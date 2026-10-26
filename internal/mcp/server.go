package mcp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"go-admin-tool/internal/audit"
	"go-admin-tool/internal/core"
	"go-admin-tool/internal/database"
	"go-admin-tool/internal/plugins"
)

const MCPProtocolVersion = "2024-11-05"

// ActionMetricCallback allows the MCP server to report action executions to the Prometheus metrics collector.
type ActionMetricCallback func(action string, outcome string, timedOut bool, duration time.Duration)

// JSONRPCRequest represents a standard JSON-RPC 2.0 request envelope used by MCP.
type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// JSONRPCError represents a standard JSON-RPC 2.0 error object.
type JSONRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// JSONRPCResponse represents a standard JSON-RPC 2.0 response envelope.
type JSONRPCResponse struct {
	JSONRPC string        `json:"jsonrpc"`
	ID      any           `json:"id,omitempty"`
	Result  any           `json:"result,omitempty"`
	Error   *JSONRPCError `json:"error,omitempty"`
	TraceID string        `json:"trace_id,omitempty"`
}

// MCPTool describes a tool exposed by the MCP server.
type MCPTool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

// MCPResource describes a readable resource exposed by the MCP server.
type MCPResource struct {
	URI         string `json:"uri"`
	Name        string `json:"name"`
	Description string `json:"description"`
	MimeType    string `json:"mimeType"`
}

// MCPPrompt describes a prompt template exposed by the MCP server.
type MCPPrompt struct {
	Name        string              `json:"name"`
	Description string              `json:"description"`
	Arguments   []map[string]any    `json:"arguments,omitempty"`
}

// MCPContentBlock represents an MCP text content block.
type MCPContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// MCPCallToolResult represents the result of an MCP tools/call invocation.
type MCPCallToolResult struct {
	Content           []MCPContentBlock `json:"content"`
	IsError           bool              `json:"isError"`
	StructuredContent any               `json:"structuredContent,omitempty"`
	TraceID           string            `json:"traceId,omitempty"`
}

// MCPTrace captures the full request/response lifecycle of an MCP interaction for auditing and debugging.
type MCPTrace struct {
	TraceID         string         `json:"trace_id"`
	SessionID       string         `json:"session_id,omitempty"`
	Timestamp       time.Time      `json:"timestamp"`
	Method          string         `json:"method"`
	ToolName        string         `json:"tool_name,omitempty"`
	Actor           string         `json:"actor"`
	Status          string         `json:"status"` // ok, error, failure
	IsError         bool           `json:"is_error"`
	DurationMs      int64          `json:"duration_ms"`
	RequestPayload  map[string]any `json:"request_payload,omitempty"`
	ResponsePayload any            `json:"response_payload,omitempty"`
	AuditEventID    string         `json:"audit_event_id,omitempty"`
}

// TraceFilter defines filters for querying stored MCP traces.
type TraceFilter struct {
	Method    string
	ToolName  string
	SessionID string
	Status    string
	Limit     int
}

// Server implements a complete Model Context Protocol (MCP) server with trace retention and audit logging.
type Server struct {
	mu             sync.RWMutex
	cfg            core.MCPConfig
	appConfig      *core.Config
	db             *database.DB
	certManager    *core.CertManager
	pluginRegistry *plugins.Registry
	auditLogger    *audit.AuditLogger
	logger         *core.Logger
	metricCallback ActionMetricCallback
	traces         []MCPTrace
}

// NewServer creates and initializes the MCP server and its trace store.
func NewServer(
	cfg core.MCPConfig,
	appConfig *core.Config,
	db *database.DB,
	certManager *core.CertManager,
	pluginRegistry *plugins.Registry,
	auditLogger *audit.AuditLogger,
	logger *core.Logger,
	metricCallback ActionMetricCallback,
) (*Server, error) {
	if cfg.ServerName == "" {
		cfg.ServerName = "api-executor-mcp"
	}
	if cfg.ServerVersion == "" {
		cfg.ServerVersion = "2.0.0"
	}
	if cfg.MaxTraces <= 0 {
		cfg.MaxTraces = 500
	}

	s := &Server{
		cfg:            cfg,
		appConfig:      appConfig,
		db:             db,
		certManager:    certManager,
		pluginRegistry: pluginRegistry,
		auditLogger:    auditLogger,
		logger:         logger,
		metricCallback: metricCallback,
		traces:         make([]MCPTrace, 0, 128),
	}

	if db != nil && !db.IsInMemory() && db.DB != nil {
		const createTracesSQL = `
		CREATE TABLE IF NOT EXISTS mcp_traces (
			trace_id TEXT NOT NULL PRIMARY KEY,
			session_id TEXT,
			timestamp DATETIME NOT NULL,
			method TEXT NOT NULL,
			tool_name TEXT,
			actor TEXT NOT NULL,
			status TEXT NOT NULL,
			is_error INTEGER NOT NULL,
			duration_ms INTEGER NOT NULL,
			request_json TEXT,
			response_json TEXT,
			audit_event_id TEXT
		);`
		if _, err := db.Exec(createTracesSQL); err != nil {
			return nil, fmt.Errorf("failed to create mcp_traces table: %w", err)
		}
	}

	return s, nil
}

func generateTraceID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "mcp_tr_" + hex.EncodeToString(b)
}

// Tools returns the list of all MCP tools exposed by this server.
func (s *Server) Tools() []MCPTool {
	return []MCPTool{
		{
			Name:        "execute_command",
			Description: "Execute a predefined system or OS-preset command with hierarchical timeout control",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"name":    map[string]any{"type": "string", "description": "Name of the predefined command to execute"},
					"timeout": map[string]any{"type": "string", "description": "Optional per-call timeout override (e.g. '10s', '500ms')"},
				},
				"required": []string{"name"},
			},
		},
		{
			Name:        "list_commands",
			Description: "List all available predefined commands and Ubuntu/RedHat OS presets with their timeouts",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"os_family": map[string]any{"type": "string", "description": "Optional filter by OS family ('ubuntu', 'redhat', 'any')"},
				},
			},
		},
		{
			Name:        "execute_plugin",
			Description: "Execute an action on a registered declarative or advanced plugin module",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"plugin_id": map[string]any{"type": "string", "description": "Plugin identifier (e.g. 'db-exposure', 'sys-diagnostics', 'ops-quick-tools')"},
					"action":    map[string]any{"type": "string", "description": "Action name within the plugin"},
					"params":    map[string]any{"type": "object", "description": "Optional key-value parameters for the plugin action"},
					"timeout":   map[string]any{"type": "string", "description": "Optional timeout override (e.g. '15s')"},
				},
				"required": []string{"plugin_id", "action"},
			},
		},
		{
			Name:        "db_query",
			Description: "Execute a strictly validated read-only SQL SELECT query via the db-exposure plugin",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"sql":      map[string]any{"type": "string", "description": "Read-only SELECT SQL query"},
					"max_rows": map[string]any{"type": "integer", "description": "Maximum number of rows to return (default 100)"},
				},
				"required": []string{"sql"},
			},
		},
		{
			Name:        "db_list_tables",
			Description: "List all database tables and row counts via the db-exposure plugin",
			InputSchema: map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
		{
			Name:        "tls_status",
			Description: "Inspect the active HTTPS/TLS certificate status, SHA-256 fingerprint, SANs, and expiration",
			InputSchema: map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
		{
			Name:        "audit_query",
			Description: "Query the tamper-evident SHA-256 hash-chained security and operational audit trail",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"category": map[string]any{"type": "string", "description": "Filter by category (command, plugin, mcp, auth, admin, tls)"},
					"status":   map[string]any{"type": "string", "description": "Filter by status (ok, error, failure, denied)"},
					"limit":    map[string]any{"type": "integer", "description": "Maximum number of events to return"},
				},
			},
		},
		{
			Name:        "audit_verify",
			Description: "Verify the cryptographic SHA-256 hash chain integrity of the entire audit log",
			InputSchema: map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
	}
}

// Resources returns the list of MCP resources exposed by this server.
func (s *Server) Resources() []MCPResource {
	return []MCPResource{
		{
			URI:         "executor://commands/catalog",
			Name:        "Predefined Commands Catalog",
			Description: "Full list of configured commands and effective timeouts",
			MimeType:    "application/json",
		},
		{
			URI:         "executor://os-presets/catalog",
			Name:        "Ubuntu & RedHat OS Preset Catalogs",
			Description: "Predefined OS administration tasks for Ubuntu and RedHat testable via Docker",
			MimeType:    "application/json",
		},
		{
			URI:         "executor://plugins/catalog",
			Name:        "Registered Plugins Catalog",
			Description: "Declarative and advanced plugin modules and their parameter schemas",
			MimeType:    "application/json",
		},
		{
			URI:         "executor://tls/info",
			Name:        "Active TLS Certificate Metadata",
			Description: "Current X.509 certificate fingerprint, validity window, and SANs",
			MimeType:    "application/json",
		},
		{
			URI:         "executor://audit/verify",
			Name:        "Audit Hash Chain Verification Status",
			Description: "Live cryptographic verification of the SHA-256 audit log chain",
			MimeType:    "application/json",
		},
	}
}

// Prompts returns the list of operational MCP prompts.
func (s *Server) Prompts() []MCPPrompt {
	return []MCPPrompt{
		{
			Name:        "diagnose-host",
			Description: "Run a structured diagnostic check across host OS presets, runtime telemetry, and disk/process status",
			Arguments: []map[string]any{
				{"name": "os_family", "description": "Target OS family ('ubuntu' or 'redhat')", "required": false},
			},
		},
		{
			Name:        "security-audit-review",
			Description: "Verify TLS certificate health and cryptographic integrity of the SHA-256 audit trail",
		},
		{
			Name:        "database-inspection",
			Description: "Inspect exposed database tables and summarize recent command execution outcomes",
		},
	}
}

// ToolAuthorizer validates whether the authenticated caller is permitted to invoke a given scope and target action.
type ToolAuthorizer func(requiredScope string, targetAction string) error

// HandleJSONRPC processes a JSON-RPC 2.0 MCP request, records a persistent trace, and writes an audit log entry.
func (s *Server) HandleJSONRPC(ctx context.Context, req JSONRPCRequest, sessionID string, actor string) JSONRPCResponse {
	return s.HandleJSONRPCWithAuthorizer(ctx, req, sessionID, actor, nil)
}

// HandleJSONRPCWithAuthorizer processes a JSON-RPC 2.0 MCP request while enforcing caller RBAC scopes and service-account action allowlists.
func (s *Server) HandleJSONRPCWithAuthorizer(ctx context.Context, req JSONRPCRequest, sessionID string, actor string, authorizer ToolAuthorizer) JSONRPCResponse {
	start := time.Now()
	traceID := generateTraceID()
	if strings.TrimSpace(actor) == "" {
		actor = "mcp_client"
	}

	var reqMap map[string]any
	if len(req.Params) > 0 {
		_ = json.Unmarshal(req.Params, &reqMap)
	}

	resp := JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		TraceID: traceID,
	}

	var toolName string
	status := "ok"
	isError := false

	switch req.Method {
	case "initialize":
		resp.Result = map[string]any{
			"protocolVersion": MCPProtocolVersion,
			"capabilities": map[string]any{
				"tools":     map[string]any{"listChanged": true},
				"resources": map[string]any{"subscribe": false, "listChanged": false},
				"prompts":   map[string]any{"listChanged": false},
				"logging":   map[string]any{},
			},
			"serverInfo": map[string]any{
				"name":    s.cfg.ServerName,
				"version": s.cfg.ServerVersion,
			},
			"traceId": traceID,
		}

	case "notifications/initialized", "ping":
		resp.Result = map[string]any{"status": "ok", "traceId": traceID}

	case "tools/list":
		resp.Result = map[string]any{
			"tools": s.Tools(),
		}

	case "tools/call":
		callRes, calledTool, callStatus, rpcErr := s.handleToolCall(ctx, req.Params, traceID, authorizer)
		toolName = calledTool
		status = callStatus
		if rpcErr != nil {
			resp.Error = rpcErr
			status = "error"
			isError = true
		} else {
			resp.Result = callRes
			isError = callRes.IsError
		}

	case "resources/list":
		resp.Result = map[string]any{
			"resources": s.Resources(),
		}

	case "resources/read":
		resContent, rpcErr := s.handleResourceRead(req.Params)
		if rpcErr != nil {
			resp.Error = rpcErr
			status = "error"
			isError = true
		} else {
			resp.Result = resContent
		}

	case "prompts/list":
		resp.Result = map[string]any{
			"prompts": s.Prompts(),
		}

	case "prompts/get":
		promptRes, rpcErr := s.handlePromptGet(req.Params)
		if rpcErr != nil {
			resp.Error = rpcErr
			status = "error"
			isError = true
		} else {
			resp.Result = promptRes
		}

	default:
		status = "error"
		isError = true
		resp.Error = &JSONRPCError{
			Code:    -32601,
			Message: fmt.Sprintf("Method not found: %s", req.Method),
		}
	}

	duration := time.Since(start)
	var auditEventID string
	if s.auditLogger != nil {
		actionLabel := req.Method
		if toolName != "" {
			actionLabel = fmt.Sprintf("%s:%s", req.Method, toolName)
		}
		ev, err := s.auditLogger.Record(audit.AuditEvent{
			TraceID:    traceID,
			Category:   "mcp",
			Action:     actionLabel,
			ActorType:  "mcp_client",
			ActorID:    actor,
			Status:     status,
			DurationMs: duration.Milliseconds(),
			Summary:    fmt.Sprintf("MCP %s (tool=%s, status=%s)", req.Method, toolName, status),
			Metadata: map[string]any{
				"session_id": sessionID,
				"method":     req.Method,
				"tool_name":  toolName,
			},
		})
		if err == nil {
			auditEventID = ev.EventID
		}
	}

	if s.cfg.RetainTraces {
		var respPayload any = resp.Result
		if resp.Error != nil {
			respPayload = resp.Error
		}
		trace := MCPTrace{
			TraceID:         traceID,
			SessionID:       sessionID,
			Timestamp:       start.UTC(),
			Method:          req.Method,
			ToolName:        toolName,
			Actor:           actor,
			Status:          status,
			IsError:         isError,
			DurationMs:      duration.Milliseconds(),
			RequestPayload:  reqMap,
			ResponsePayload: respPayload,
			AuditEventID:    auditEventID,
		}
		s.recordTrace(trace)
	}

	return resp
}

func (s *Server) handleToolCall(ctx context.Context, rawParams json.RawMessage, traceID string, authorizer ToolAuthorizer) (MCPCallToolResult, string, string, *JSONRPCError) {
	var callReq struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	}
	if err := json.Unmarshal(rawParams, &callReq); err != nil {
		return MCPCallToolResult{}, "", "error", &JSONRPCError{
			Code:    -32602,
			Message: "Invalid tools/call parameters",
		}
	}
	toolName := strings.TrimSpace(callReq.Name)
	if toolName == "" {
		return MCPCallToolResult{}, "", "error", &JSONRPCError{
			Code:    -32602,
			Message: "Tool name is required",
		}
	}

	switch toolName {
	case "execute_command":
		cmdName := ""
		if callReq.Arguments != nil {
			if v, ok := callReq.Arguments["name"]; ok {
				cmdName = strings.TrimSpace(fmt.Sprintf("%v", v))
			}
		}
		if cmdName == "" {
			return s.toolErrorResult(traceID, "missing required argument 'name'"), toolName, "error", nil
		}
		if authorizer != nil {
			if err := authorizer("commands:execute", cmdName); err != nil {
				if s.metricCallback != nil {
					s.metricCallback(cmdName, "error", false, 0)
				}
				return s.toolErrorResult(traceID, fmt.Sprintf("authorization denied for command %q: %v", cmdName, err)), toolName, "denied", nil
			}
		}

		var timeoutOverride time.Duration
		if callReq.Arguments != nil {
			if v, ok := callReq.Arguments["timeout"]; ok && strings.TrimSpace(fmt.Sprintf("%v", v)) != "" {
				d, err := core.ParseTimeoutDuration(fmt.Sprintf("%v", v))
				if err != nil {
					if s.metricCallback != nil {
						s.metricCallback(cmdName, "error", false, 0)
					}
					return s.toolErrorResult(traceID, fmt.Sprintf("invalid timeout override: %v", err)), toolName, "error", nil
				}
				timeoutOverride = d
			}
		}

		var cmdDef *core.CommandDefinition
		if s.appConfig != nil {
			for _, c := range s.appConfig.Executor.Commands {
				if c.Name == cmdName {
					cCopy := c
					cmdDef = &cCopy
					break
				}
			}
		}
		// Also check OS presets if not in primary commands list
		if cmdDef == nil {
			for _, preset := range core.GetOSPresetCommands("all") {
				if preset.Name == cmdName {
					pCopy := preset
					cmdDef = &pCopy
					break
				}
			}
		}
		if cmdDef == nil {
			if s.metricCallback != nil {
				s.metricCallback(cmdName, "error", false, 0)
			}
			return s.toolErrorResult(traceID, fmt.Sprintf("command %q not found", cmdName)), toolName, "error", nil
		}

		effTimeout := core.DefaultCommandTimeout
		if s.appConfig != nil {
			effTimeout = s.appConfig.Executor.ResolveTimeout(*cmdDef, timeoutOverride)
		} else if timeoutOverride > 0 {
			effTimeout = timeoutOverride
		}

		execStart := time.Now()
		output, err := core.ExecuteCommandWithTimeout(*cmdDef, effTimeout)
		execDur := time.Since(execStart)

		if err != nil {
			timedOut := core.IsCommandTimeout(err)
			outcome := "failure"
			if core.IsCommandSystemError(err) {
				outcome = "error"
			}
			if s.metricCallback != nil {
				s.metricCallback(cmdName, outcome, timedOut, execDur)
			}
			if s.db != nil {
				_, _ = s.db.RecordAction(cmdName, outcome, output)
			}
			return MCPCallToolResult{
				Content: []MCPContentBlock{{Type: "text", Text: fmt.Sprintf("Error: %v\nOutput: %s", err, output)}},
				IsError: true,
				StructuredContent: map[string]any{
					"command":   cmdName,
					"output":    output,
					"error":     err.Error(),
					"timed_out": timedOut,
					"timeout":   effTimeout.String(),
				},
				TraceID: traceID,
			}, toolName, outcome, nil
		}

		if s.metricCallback != nil {
			s.metricCallback(cmdName, "ok", false, execDur)
		}
		if s.db != nil {
			_, _ = s.db.RecordAction(cmdName, "success", output)
		}
		return MCPCallToolResult{
			Content: []MCPContentBlock{{Type: "text", Text: output}},
			IsError: false,
			StructuredContent: map[string]any{
				"command": cmdName,
				"output":  output,
				"timeout": effTimeout.String(),
			},
			TraceID: traceID,
		}, toolName, "ok", nil

	case "list_commands":
		osFilter := ""
		if callReq.Arguments != nil {
			if v, ok := callReq.Arguments["os_family"]; ok {
				osFilter = strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", v)))
			}
		}
		var cmds []core.CommandDefinition
		if s.appConfig != nil {
			cmds = core.MergeOSPresets(s.appConfig.Executor.Commands, "ubuntu", "redhat")
		} else {
			cmds = core.GetOSPresetCommands("ubuntu", "redhat")
		}
		var filtered []core.CommandDefinition
		for _, c := range cmds {
			if osFilter != "" && osFilter != "all" && strings.ToLower(c.OSFamily) != osFilter {
				continue
			}
			filtered = append(filtered, c)
		}
		rawJSON, _ := json.MarshalIndent(filtered, "", "  ")
		return MCPCallToolResult{
			Content:           []MCPContentBlock{{Type: "text", Text: string(rawJSON)}},
			IsError:           false,
			StructuredContent: map[string]any{"commands": filtered},
			TraceID:           traceID,
		}, toolName, "ok", nil

	case "execute_plugin":
		if s.pluginRegistry == nil {
			return s.toolErrorResult(traceID, "plugin registry is not available"), toolName, "error", nil
		}
		pluginID := ""
		action := ""
		var params map[string]any
		if callReq.Arguments != nil {
			if v, ok := callReq.Arguments["plugin_id"]; ok {
				pluginID = strings.TrimSpace(fmt.Sprintf("%v", v))
			}
			if v, ok := callReq.Arguments["action"]; ok {
				action = strings.TrimSpace(fmt.Sprintf("%v", v))
			}
			if v, ok := callReq.Arguments["params"]; ok {
				if m, okMap := v.(map[string]any); okMap {
					params = m
				}
			}
		}
		if pluginID == "" || action == "" {
			return s.toolErrorResult(traceID, "plugin_id and action are required"), toolName, "error", nil
		}
		metricLabel := fmt.Sprintf("plugin:%s:%s", pluginID, action)
		if authorizer != nil {
			if err := authorizer("plugins:execute", metricLabel); err != nil {
				if authorizer("plugins:execute", pluginID) != nil && authorizer("plugins:execute", action) != nil {
					if s.metricCallback != nil {
						s.metricCallback(metricLabel, "error", false, 0)
					}
					return s.toolErrorResult(traceID, fmt.Sprintf("authorization denied for plugin %q action %q: %v", pluginID, action, err)), toolName, "denied", nil
				}
			}
		}

		res, err := s.pluginRegistry.Execute(ctx, pluginID, action, params, 30*time.Second)
		if err != nil {
			if s.metricCallback != nil {
				s.metricCallback(metricLabel, res.Status, res.TimedOut, time.Duration(res.DurationMs)*time.Millisecond)
			}
			return MCPCallToolResult{
				Content:           []MCPContentBlock{{Type: "text", Text: fmt.Sprintf("Plugin error: %v", err)}},
				IsError:           true,
				StructuredContent: res,
				TraceID:           traceID,
			}, toolName, res.Status, nil
		}
		if s.metricCallback != nil {
			s.metricCallback(metricLabel, "ok", false, time.Duration(res.DurationMs)*time.Millisecond)
		}
		return MCPCallToolResult{
			Content:           []MCPContentBlock{{Type: "text", Text: res.Output}},
			IsError:           false,
			StructuredContent: res,
			TraceID:           traceID,
		}, toolName, "ok", nil

	case "db_query":
		if s.pluginRegistry == nil {
			return s.toolErrorResult(traceID, "plugin registry is not available"), toolName, "error", nil
		}
		if authorizer != nil {
			if err := authorizer("plugins:execute", "db-exposure"); err != nil && authorizer("plugins:execute", "plugin:db-exposure:query_readonly") != nil {
				return s.toolErrorResult(traceID, fmt.Sprintf("authorization denied for db_query: %v", err)), toolName, "denied", nil
			}
		}
		res, err := s.pluginRegistry.Execute(ctx, "db-exposure", "query_readonly", callReq.Arguments, 15*time.Second)
		if err != nil {
			return MCPCallToolResult{
				Content:           []MCPContentBlock{{Type: "text", Text: fmt.Sprintf("Database query rejected: %v", err)}},
				IsError:           true,
				StructuredContent: res,
				TraceID:           traceID,
			}, toolName, "error", nil
		}
		return MCPCallToolResult{
			Content:           []MCPContentBlock{{Type: "text", Text: res.Output}},
			IsError:           false,
			StructuredContent: res.Data,
			TraceID:           traceID,
		}, toolName, "ok", nil

	case "db_list_tables":
		if s.pluginRegistry == nil {
			return s.toolErrorResult(traceID, "plugin registry is not available"), toolName, "error", nil
		}
		if authorizer != nil {
			if err := authorizer("plugins:read", "db-exposure"); err != nil && authorizer("plugins:execute", "db-exposure") != nil {
				return s.toolErrorResult(traceID, fmt.Sprintf("authorization denied for db_list_tables: %v", err)), toolName, "denied", nil
			}
		}
		res, err := s.pluginRegistry.Execute(ctx, "db-exposure", "list_tables", nil, 10*time.Second)
		if err != nil {
			return s.toolErrorResult(traceID, err.Error()), toolName, "error", nil
		}
		return MCPCallToolResult{
			Content:           []MCPContentBlock{{Type: "text", Text: res.Output}},
			IsError:           false,
			StructuredContent: res.Data,
			TraceID:           traceID,
		}, toolName, "ok", nil

	case "tls_status":
		var info core.CertificateInfo
		if s.certManager != nil {
			info = s.certManager.Info()
		}
		raw, _ := json.MarshalIndent(info, "", "  ")
		return MCPCallToolResult{
			Content:           []MCPContentBlock{{Type: "text", Text: string(raw)}},
			IsError:           false,
			StructuredContent: info,
			TraceID:           traceID,
		}, toolName, "ok", nil

	case "audit_query":
		if s.auditLogger == nil {
			return s.toolErrorResult(traceID, "audit logger is not enabled"), toolName, "error", nil
		}
		filter := audit.AuditFilter{Limit: 50}
		if callReq.Arguments != nil {
			if v, ok := callReq.Arguments["category"]; ok {
				filter.Category = fmt.Sprintf("%v", v)
			}
			if v, ok := callReq.Arguments["status"]; ok {
				filter.Status = fmt.Sprintf("%v", v)
			}
		}
		events := s.auditLogger.Query(filter)
		raw, _ := json.MarshalIndent(events, "", "  ")
		return MCPCallToolResult{
			Content:           []MCPContentBlock{{Type: "text", Text: string(raw)}},
			IsError:           false,
			StructuredContent: map[string]any{"events": events},
			TraceID:           traceID,
		}, toolName, "ok", nil

	case "audit_verify":
		if s.auditLogger == nil {
			return s.toolErrorResult(traceID, "audit logger is not enabled"), toolName, "error", nil
		}
		v := s.auditLogger.VerifyChain()
		raw, _ := json.MarshalIndent(v, "", "  ")
		return MCPCallToolResult{
			Content:           []MCPContentBlock{{Type: "text", Text: string(raw)}},
			IsError:           !v.Valid,
			StructuredContent: v,
			TraceID:           traceID,
		}, toolName, "ok", nil

	default:
		return s.toolErrorResult(traceID, fmt.Sprintf("unknown MCP tool %q", toolName)), toolName, "error", nil
	}
}

func (s *Server) toolErrorResult(traceID, msg string) MCPCallToolResult {
	return MCPCallToolResult{
		Content:           []MCPContentBlock{{Type: "text", Text: msg}},
		IsError:           true,
		StructuredContent: map[string]any{"error": msg},
		TraceID:           traceID,
	}
}

func (s *Server) handleResourceRead(rawParams json.RawMessage) (any, *JSONRPCError) {
	var req struct {
		URI string `json:"uri"`
	}
	if err := json.Unmarshal(rawParams, &req); err != nil || strings.TrimSpace(req.URI) == "" {
		return nil, &JSONRPCError{Code: -32602, Message: "Resource URI is required"}
	}

	var payload any
	switch req.URI {
	case "executor://commands/catalog":
		if s.appConfig != nil {
			payload = s.appConfig.Executor
		}
	case "executor://os-presets/catalog":
		payload = core.AllOSPresetCatalogs()
	case "executor://plugins/catalog":
		if s.pluginRegistry != nil {
			payload = s.pluginRegistry.List()
		}
	case "executor://tls/info":
		if s.certManager != nil {
			payload = s.certManager.Info()
		}
	case "executor://audit/verify":
		if s.auditLogger != nil {
			payload = s.auditLogger.VerifyChain()
		}
	default:
		return nil, &JSONRPCError{Code: -32002, Message: fmt.Sprintf("Resource not found: %s", req.URI)}
	}

	raw, _ := json.MarshalIndent(payload, "", "  ")
	return map[string]any{
		"contents": []map[string]any{
			{
				"uri":      req.URI,
				"mimeType": "application/json",
				"text":     string(raw),
			},
		},
	}, nil
}

func (s *Server) handlePromptGet(rawParams json.RawMessage) (any, *JSONRPCError) {
	var req struct {
		Name      string            `json:"name"`
		Arguments map[string]string `json:"arguments"`
	}
	if err := json.Unmarshal(rawParams, &req); err != nil || strings.TrimSpace(req.Name) == "" {
		return nil, &JSONRPCError{Code: -32602, Message: "Prompt name is required"}
	}

	switch req.Name {
	case "diagnose-host":
		osTarget := req.Arguments["os_family"]
		if osTarget == "" {
			osTarget = core.DetectHostOSFamily()
		}
		return map[string]any{
			"description": "Guided host diagnostic workflow",
			"messages": []map[string]any{
				{
					"role": "user",
					"content": map[string]any{
						"type": "text",
						"text": fmt.Sprintf("Diagnose this %s host by calling execute_plugin (sys-diagnostics:runtime_stats) and execute_command for %s OS presets.", osTarget, osTarget),
					},
				},
			},
		}, nil
	case "security-audit-review":
		return map[string]any{
			"description": "Security & TLS audit review",
			"messages": []map[string]any{
				{
					"role": "user",
					"content": map[string]any{
						"type": "text",
						"text": "Call tls_status, audit_verify, and audit_query to verify the security posture and SHA-256 audit chain integrity.",
					},
				},
			},
		}, nil
	case "database-inspection":
		return map[string]any{
			"description": "Read-only database inspection",
			"messages": []map[string]any{
				{
					"role": "user",
					"content": map[string]any{
						"type": "text",
						"text": "Call db_list_tables and db_query with SELECT * FROM action_history ORDER BY id DESC LIMIT 10.",
					},
				},
			},
		}, nil
	default:
		return nil, &JSONRPCError{Code: -32602, Message: fmt.Sprintf("Prompt not found: %s", req.Name)}
	}
}

func (s *Server) recordTrace(tr MCPTrace) {
	s.mu.Lock()
	if len(s.traces) >= s.cfg.MaxTraces {
		s.traces = append(s.traces[1:], tr)
	} else {
		s.traces = append(s.traces, tr)
	}
	s.mu.Unlock()

	if s.cfg.TraceFilePath != "" {
		_ = os.MkdirAll(filepath.Dir(s.cfg.TraceFilePath), 0755)
		if f, err := os.OpenFile(s.cfg.TraceFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600); err == nil {
			_ = json.NewEncoder(f).Encode(tr)
			_ = f.Close()
		}
	}

	if s.db != nil && !s.db.IsInMemory() && s.db.DB != nil {
		reqBytes, _ := json.Marshal(tr.RequestPayload)
		respBytes, _ := json.Marshal(tr.ResponsePayload)
		isErrInt := 0
		if tr.IsError {
			isErrInt = 1
		}
		_, _ = s.db.Exec(
			`INSERT INTO mcp_traces(trace_id, session_id, timestamp, method, tool_name, actor, status, is_error, duration_ms, request_json, response_json, audit_event_id)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			tr.TraceID, tr.SessionID, tr.Timestamp, tr.Method, tr.ToolName, tr.Actor, tr.Status, isErrInt,
			tr.DurationMs, string(reqBytes), string(respBytes), tr.AuditEventID,
		)
	}
}

// ListTraces returns retained MCP traces matching the filter (newest first).
func (s *Server) ListTraces(filter TraceFilter) []MCPTrace {
	s.mu.RLock()
	defer s.mu.RUnlock()

	limit := filter.Limit
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	methodFilter := strings.ToLower(strings.TrimSpace(filter.Method))
	toolFilter := strings.ToLower(strings.TrimSpace(filter.ToolName))
	sessionFilter := strings.TrimSpace(filter.SessionID)
	statusFilter := strings.ToLower(strings.TrimSpace(filter.Status))

	out := make([]MCPTrace, 0, limit)
	for i := len(s.traces) - 1; i >= 0 && len(out) < limit; i-- {
		tr := s.traces[i]
		if methodFilter != "" && strings.ToLower(tr.Method) != methodFilter {
			continue
		}
		if toolFilter != "" && strings.ToLower(tr.ToolName) != toolFilter {
			continue
		}
		if sessionFilter != "" && tr.SessionID != sessionFilter {
			continue
		}
		if statusFilter != "" && strings.ToLower(tr.Status) != statusFilter {
			continue
		}
		out = append(out, tr)
	}
	return out
}

// GetTrace looks up a single MCP trace by its TraceID.
func (s *Server) GetTrace(traceID string) (MCPTrace, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for i := len(s.traces) - 1; i >= 0; i-- {
		if s.traces[i].TraceID == traceID {
			return s.traces[i], nil
		}
	}
	return MCPTrace{}, errors.New("MCP trace not found")
}

// ClearTraces clears the in-memory MCP trace buffer.
func (s *Server) ClearTraces() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := len(s.traces)
	s.traces = make([]MCPTrace, 0, 128)
	return n
}
