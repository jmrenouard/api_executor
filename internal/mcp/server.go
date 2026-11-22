package mcp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
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
	ParentTraceID   string         `json:"parent_trace_id,omitempty"`
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
	RequestSHA256   string         `json:"request_sha256,omitempty"`
	ResponseSHA256  string         `json:"response_sha256,omitempty"`
	PrevTraceHash   string         `json:"prev_trace_hash,omitempty"`
	TraceHash       string         `json:"trace_hash,omitempty"`
	AuditEventID        string  `json:"audit_event_id,omitempty"`
	AuditEntryHash      string  `json:"audit_entry_hash,omitempty"`
	GatekeeperDecision  string  `json:"gatekeeper_decision,omitempty"`
	GatekeeperRiskScore float64 `json:"gatekeeper_risk_score,omitempty"`
	GatekeeperLatencyMs float64 `json:"gatekeeper_latency_ms,omitempty"`
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
	fileMu         sync.Mutex
	traceFile      *os.File
	cfg            core.MCPConfig
	appConfig      *core.Config
	db             *database.DB
	certManager    *core.CertManager
	pluginRegistry *plugins.Registry
	auditLogger    *audit.AuditLogger
	logger         *core.Logger
	metricCallback      ActionMetricCallback
	approvalGate        ApprovalGate
	traces              []MCPTrace
	lastTraceHash       string
	firstTraceIsGenesis bool
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
		cfg:                 cfg,
		appConfig:           appConfig,
		db:                  db,
		certManager:         certManager,
		pluginRegistry:      pluginRegistry,
		auditLogger:         auditLogger,
		logger:              logger,
		metricCallback:      metricCallback,
		traces:              make([]MCPTrace, 0, 128),
		lastTraceHash:       MCPTraceGenesisHash,
		firstTraceIsGenesis: true,
	}

	if db != nil && !db.IsInMemory() && db.DB != nil {
		const createTracesSQL = `
		CREATE TABLE IF NOT EXISTS mcp_traces (
			trace_id TEXT NOT NULL PRIMARY KEY,
			parent_trace_id TEXT,
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
			request_sha256 TEXT,
			response_sha256 TEXT,
			prev_trace_hash TEXT,
			trace_hash TEXT,
			audit_event_id TEXT,
			audit_entry_hash TEXT,
			gatekeeper_decision TEXT,
			gatekeeper_risk_score REAL,
			gatekeeper_latency_ms REAL
		);`
		if _, err := db.Exec(createTracesSQL); err != nil {
			return nil, fmt.Errorf("failed to create mcp_traces table: %w", err)
		}
		if err := ensureMCPTracesColumns(db); err != nil {
			return nil, fmt.Errorf("failed to migrate mcp_traces schema: %w", err)
		}
	}

	if cfg.TraceFilePath != "" {
		if err := os.MkdirAll(filepath.Dir(cfg.TraceFilePath), 0755); err != nil {
			return nil, fmt.Errorf("failed to create MCP trace directory: %w", err)
		}
		f, err := os.OpenFile(cfg.TraceFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			return nil, fmt.Errorf("failed to open MCP trace file: %w", err)
		}
		s.traceFile = f
	}

	return s, nil
}

// Close closes the underlying persistent MCP trace file handle if one is open.
func (s *Server) Close() error {
	if s == nil {
		return nil
	}
	s.fileMu.Lock()
	defer s.fileMu.Unlock()
	if s.traceFile != nil {
		err := s.traceFile.Close()
		s.traceFile = nil
		return err
	}
	return nil
}

// HasOpenTraceFile reports whether a persistent trace file handle is currently open.
func (s *Server) HasOpenTraceFile() bool {
	if s == nil {
		return false
	}
	s.fileMu.Lock()
	defer s.fileMu.Unlock()
	return s.traceFile != nil
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
		{
			Name:        "mcp_trace_verify",
			Description: "Cryptographically verify SHA-256 hash chaining and audit cross-link continuity for MCP traces",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"trace_id": map[string]any{"type": "string", "description": "Optional specific MCP trace_id to verify (verifies full chain when omitted)"},
				},
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
		{
			URI:         CISResourceURI,
			Name:        "CIS Benchmarks Read-Only Audit Preset",
			Description: "Read-only cis.mcp.contract.v1 compliance audit preset metadata, 18 canonical targets, allowed/forbidden flags, and loaded plugin schema",
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
		{
			Name:        CISPromptName,
			Description: "Run a strictly read-only CIS compliance audit (JSON or SARIF v2.1.0) and optional dry-run remediation preview",
			Arguments: []map[string]any{
				{"name": "target", "description": "Canonical CIS target (e.g. 'rhel9', 'postgresql17', 'mysql80', 'mariadb1011', 'mongodb8', 'cassandra50')", "required": false},
				{"name": "format", "description": "Report output format ('json' or 'sarif', default 'json')", "required": false},
			},
		},
	}
}

// ToolAuthorizer validates whether the authenticated caller is permitted to invoke a given scope and target action.
type ToolAuthorizer func(requiredScope string, targetAction string) error

// ApprovalGateRequest describes an MCP tool invocation requiring HITL and/or System-1 evaluation.
type ApprovalGateRequest struct {
	ToolName    string
	Action      string
	PluginID    string
	CommandLine string
	Parameters  map[string]any
	CommandFlag bool
	ApprovalID  string
	Actor       string
}

// ApprovalGateDecision represents the outcome of a pre-execution HITL / System-1 gate check.
type ApprovalGateDecision struct {
	Allowed             bool
	Pending             bool
	ApprovalID          string
	ExpiresAt           time.Time
	PayloadSHA256       string
	Reason              string
	GatekeeperDecision  string
	GatekeeperRiskScore float64
	GatekeeperLatencyMs float64
}

// ApprovalGate enforces Human-in-the-Loop pre-execution approvals for MCP tools/call
// while keeping internal/mcp decoupled from HTTP handlers and approval persistence.
type ApprovalGate func(ctx context.Context, req ApprovalGateRequest) (ApprovalGateDecision, error)

// SetApprovalGate configures the pre-execution HITL approval gate for tools/call.
func (s *Server) SetApprovalGate(gate ApprovalGate) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.approvalGate = gate
	s.mu.Unlock()
}

// HasApprovalGate reports whether an ApprovalGate callback is configured.
func (s *Server) HasApprovalGate() bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.approvalGate != nil
}

func (s *Server) getApprovalGate() ApprovalGate {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.approvalGate
}

type gateTraceMeta struct {
	Decision  string
	RiskScore float64
	LatencyMs float64
}

func (s *Server) checkApprovalGate(ctx context.Context, req ApprovalGateRequest, traceID string) (MCPCallToolResult, string, gateTraceMeta, bool) {
	gate := s.getApprovalGate()
	if gate == nil {
		return MCPCallToolResult{}, "", gateTraceMeta{}, true
	}
	decision, err := gate(ctx, req)
	meta := gateTraceMeta{
		Decision:  decision.GatekeeperDecision,
		RiskScore: decision.GatekeeperRiskScore,
		LatencyMs: decision.GatekeeperLatencyMs,
	}
	if err != nil {
		return s.toolErrorResult(traceID, fmt.Sprintf("approval gate denied %q: %v", req.ToolName, err)), "denied", meta, false
	}
	if decision.Pending {
		msg := decision.Reason
		if strings.TrimSpace(msg) == "" {
			msg = "Human-in-the-Loop approval required before execution"
		}
		sc := map[string]any{
			"status":         "pending_approval",
			"approval_id":    decision.ApprovalID,
			"expires_at":     decision.ExpiresAt.UTC(),
			"payload_sha256": decision.PayloadSHA256,
			"message":        msg,
		}
		if meta.Decision != "" {
			sc["gatekeeper_decision"] = meta.Decision
			sc["gatekeeper_risk_score"] = meta.RiskScore
			sc["gatekeeper_latency_ms"] = meta.LatencyMs
		}
		return MCPCallToolResult{
			Content: []MCPContentBlock{{
				Type: "text",
				Text: fmt.Sprintf("%s (approval_id=%s, expires_at=%s)", msg, decision.ApprovalID, decision.ExpiresAt.UTC().Format(time.RFC3339)),
			}},
			IsError:           false,
			StructuredContent: sc,
			TraceID:           traceID,
		}, "pending_approval", meta, false
	}
	if !decision.Allowed {
		reason := decision.Reason
		if strings.TrimSpace(reason) == "" {
			reason = "execution denied by approval gate"
		}
		return s.toolErrorResult(traceID, reason), "denied", meta, false
	}
	return MCPCallToolResult{}, "", meta, true
}

func extractMCPApprovalArgs(args map[string]any) (string, map[string]any) {
	if len(args) == 0 {
		return "", nil
	}
	var approvalID string
	clean := make(map[string]any, len(args))
	for k, v := range args {
		if k == "_approval_id" {
			if v != nil {
				approvalID = strings.TrimSpace(fmt.Sprintf("%v", v))
			}
			continue
		}
		clean[k] = v
	}
	if len(clean) == 0 {
		return approvalID, nil
	}
	return approvalID, clean
}

// HandleJSONRPC processes a JSON-RPC 2.0 MCP request, records a persistent trace, and writes an audit log entry.
func (s *Server) HandleJSONRPC(ctx context.Context, req JSONRPCRequest, sessionID string, actor string) JSONRPCResponse {
	return s.HandleJSONRPCWithAuthorizer(ctx, req, sessionID, actor, nil)
}

// HandleJSONRPCWithAuthorizer processes a JSON-RPC 2.0 MCP request while enforcing caller RBAC scopes and service-account action allowlists.
func (s *Server) HandleJSONRPCWithAuthorizer(ctx context.Context, req JSONRPCRequest, sessionID string, actor string, authorizer ToolAuthorizer) JSONRPCResponse {
	return s.handleJSONRPCInternal(ctx, req, sessionID, actor, "", authorizer)
}

func (s *Server) handleJSONRPCInternal(ctx context.Context, req JSONRPCRequest, sessionID string, actor string, parentTraceID string, authorizer ToolAuthorizer) JSONRPCResponse {
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
	var gkMeta gateTraceMeta
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
		callRes, calledTool, callStatus, callMeta, rpcErr := s.handleToolCall(ctx, req.Params, traceID, actor, authorizer)
		toolName = calledTool
		status = callStatus
		gkMeta = callMeta
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
	var auditEntryHash string
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
			Metadata: func() map[string]any {
				m := map[string]any{
					"session_id": sessionID,
					"method":     req.Method,
					"tool_name":  toolName,
				}
				if gkMeta.Decision != "" {
					m["gatekeeper_decision"] = gkMeta.Decision
					m["gatekeeper_risk_score"] = gkMeta.RiskScore
					m["gatekeeper_latency_ms"] = gkMeta.LatencyMs
				}
				return m
			}(),
		})
		if err == nil {
			auditEventID = ev.EventID
			auditEntryHash = ev.EntryHash
		}
	}

	if s.cfg.RetainTraces {
		var respPayload any = resp.Result
		if resp.Error != nil {
			respPayload = resp.Error
		}
		trace := MCPTrace{
			TraceID:         traceID,
			ParentTraceID:   strings.TrimSpace(parentTraceID),
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
			AuditEventID:        auditEventID,
			AuditEntryHash:      auditEntryHash,
			GatekeeperDecision:  gkMeta.Decision,
			GatekeeperRiskScore: gkMeta.RiskScore,
			GatekeeperLatencyMs: gkMeta.LatencyMs,
		}
		s.recordTrace(trace)
	}

	return resp
}

func (s *Server) handleToolCall(ctx context.Context, rawParams json.RawMessage, traceID string, actor string, authorizer ToolAuthorizer) (MCPCallToolResult, string, string, gateTraceMeta, *JSONRPCError) {
	var callReq struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	}
	if err := json.Unmarshal(rawParams, &callReq); err != nil {
		return MCPCallToolResult{}, "", "error", gateTraceMeta{}, &JSONRPCError{
			Code:    -32602,
			Message: "Invalid tools/call parameters",
		}
	}
	toolName := strings.TrimSpace(callReq.Name)
	if toolName == "" {
		return MCPCallToolResult{}, "", "error", gateTraceMeta{}, &JSONRPCError{
			Code:    -32602,
			Message: "Tool name is required",
		}
	}
	approvalID, cleanArgs := extractMCPApprovalArgs(callReq.Arguments)
	var gateMeta gateTraceMeta

	switch toolName {
	case "execute_command":
		cmdName := ""
		if callReq.Arguments != nil {
			if v, ok := callReq.Arguments["name"]; ok {
				cmdName = strings.TrimSpace(fmt.Sprintf("%v", v))
			}
		}
		if cmdName == "" {
			return s.toolErrorResult(traceID, "missing required argument 'name'"), toolName, "error", gateMeta, nil
		}
		if authorizer != nil {
			if err := authorizer("commands:execute", cmdName); err != nil {
				if s.metricCallback != nil {
					s.metricCallback(cmdName, "error", false, 0)
				}
				return s.toolErrorResult(traceID, fmt.Sprintf("authorization denied for command %q: %v", cmdName, err)), toolName, "denied", gateMeta, nil
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
					return s.toolErrorResult(traceID, fmt.Sprintf("invalid timeout override: %v", err)), toolName, "error", gateMeta, nil
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
			return s.toolErrorResult(traceID, fmt.Sprintf("command %q not found", cmdName)), toolName, "error", gateMeta, nil
		}

		cmdLine := strings.TrimSpace(cmdDef.Command + " " + strings.Join(cmdDef.Args, " "))
		var gateRes MCPCallToolResult
		var gateStatus string
		var proceed bool
		gateRes, gateStatus, gateMeta, proceed = s.checkApprovalGate(ctx, ApprovalGateRequest{
			ToolName:    toolName,
			Action:      cmdName,
			CommandLine: cmdLine,
			Parameters:  cleanArgs,
			CommandFlag: cmdDef.RequireApproval,
			ApprovalID:  approvalID,
			Actor:       actor,
		}, traceID)
		if !proceed {
			return gateRes, toolName, gateStatus, gateMeta, nil
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
			}, toolName, outcome, gateMeta, nil
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
		}, toolName, "ok", gateMeta, nil

	case "list_commands":
		var gateRes MCPCallToolResult
		var gateStatus string
		var proceed bool
		gateRes, gateStatus, gateMeta, proceed = s.checkApprovalGate(ctx, ApprovalGateRequest{
			ToolName:   toolName,
			Action:     toolName,
			Parameters: cleanArgs,
			ApprovalID: approvalID,
			Actor:      actor,
		}, traceID)
		if !proceed {
			return gateRes, toolName, gateStatus, gateMeta, nil
		}
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
		}, toolName, "ok", gateMeta, nil

	case "execute_plugin":
		if s.pluginRegistry == nil {
			return s.toolErrorResult(traceID, "plugin registry is not available"), toolName, "error", gateMeta, nil
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
			return s.toolErrorResult(traceID, "plugin_id and action are required"), toolName, "error", gateMeta, nil
		}
		metricLabel := fmt.Sprintf("plugin:%s:%s", pluginID, action)
		if authorizer != nil {
			if err := authorizer("plugins:execute", metricLabel); err != nil {
				if authorizer("plugins:execute", pluginID) != nil && authorizer("plugins:execute", action) != nil {
					if s.metricCallback != nil {
						s.metricCallback(metricLabel, "error", false, 0)
					}
					return s.toolErrorResult(traceID, fmt.Sprintf("authorization denied for plugin %q action %q: %v", pluginID, action, err)), toolName, "denied", gateMeta, nil
				}
			}
		}

		if _, exists := s.pluginRegistry.Get(pluginID); !exists {
			if s.metricCallback != nil {
				s.metricCallback(metricLabel, "error", false, 0)
			}
			return s.toolErrorResult(traceID, fmt.Sprintf("plugin %q not found", pluginID)), toolName, "error", gateMeta, nil
		}

		var gateRes MCPCallToolResult
		var gateStatus string
		var proceed bool
		gateRes, gateStatus, gateMeta, proceed = s.checkApprovalGate(ctx, ApprovalGateRequest{
			ToolName:    toolName,
			PluginID:    pluginID,
			Action:      action,
			CommandLine: pluginID + ":" + action,
			Parameters:  params,
			ApprovalID:  approvalID,
			Actor:       actor,
		}, traceID)
		if !proceed {
			return gateRes, toolName, gateStatus, gateMeta, nil
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
			}, toolName, res.Status, gateMeta, nil
		}
		if s.metricCallback != nil {
			s.metricCallback(metricLabel, "ok", false, time.Duration(res.DurationMs)*time.Millisecond)
		}
		return MCPCallToolResult{
			Content:           []MCPContentBlock{{Type: "text", Text: res.Output}},
			IsError:           false,
			StructuredContent: res,
			TraceID:           traceID,
		}, toolName, "ok", gateMeta, nil

	case "db_query":
		if s.pluginRegistry == nil {
			return s.toolErrorResult(traceID, "plugin registry is not available"), toolName, "error", gateMeta, nil
		}
		if authorizer != nil {
			if err := authorizer("plugins:execute", "db-exposure"); err != nil && authorizer("plugins:execute", "plugin:db-exposure:query_readonly") != nil {
				return s.toolErrorResult(traceID, fmt.Sprintf("authorization denied for db_query: %v", err)), toolName, "denied", gateMeta, nil
			}
		}
		sqlStr := ""
		if cleanArgs != nil {
			if v, ok := cleanArgs["sql"]; ok && v != nil {
				sqlStr = strings.TrimSpace(fmt.Sprintf("%v", v))
			}
		}
		var gateRes MCPCallToolResult
		var gateStatus string
		var proceed bool
		gateRes, gateStatus, gateMeta, proceed = s.checkApprovalGate(ctx, ApprovalGateRequest{
			ToolName:    toolName,
			PluginID:    "db-exposure",
			Action:      "query_readonly",
			CommandLine: sqlStr,
			Parameters:  cleanArgs,
			ApprovalID:  approvalID,
			Actor:       actor,
		}, traceID)
		if !proceed {
			return gateRes, toolName, gateStatus, gateMeta, nil
		}
		res, err := s.pluginRegistry.Execute(ctx, "db-exposure", "query_readonly", cleanArgs, 15*time.Second)
		if err != nil {
			return MCPCallToolResult{
				Content:           []MCPContentBlock{{Type: "text", Text: fmt.Sprintf("Database query rejected: %v", err)}},
				IsError:           true,
				StructuredContent: res,
				TraceID:           traceID,
			}, toolName, "error", gateMeta, nil
		}
		return MCPCallToolResult{
			Content:           []MCPContentBlock{{Type: "text", Text: res.Output}},
			IsError:           false,
			StructuredContent: res.Data,
			TraceID:           traceID,
		}, toolName, "ok", gateMeta, nil

	case "db_list_tables":
		if s.pluginRegistry == nil {
			return s.toolErrorResult(traceID, "plugin registry is not available"), toolName, "error", gateMeta, nil
		}
		if authorizer != nil {
			if err := authorizer("plugins:read", "db-exposure"); err != nil && authorizer("plugins:execute", "db-exposure") != nil {
				return s.toolErrorResult(traceID, fmt.Sprintf("authorization denied for db_list_tables: %v", err)), toolName, "denied", gateMeta, nil
			}
		}
		var gateRes MCPCallToolResult
		var gateStatus string
		var proceed bool
		gateRes, gateStatus, gateMeta, proceed = s.checkApprovalGate(ctx, ApprovalGateRequest{
			ToolName:   toolName,
			PluginID:   "db-exposure",
			Action:     "list_tables",
			Parameters: cleanArgs,
			ApprovalID: approvalID,
			Actor:      actor,
		}, traceID)
		if !proceed {
			return gateRes, toolName, gateStatus, gateMeta, nil
		}
		res, err := s.pluginRegistry.Execute(ctx, "db-exposure", "list_tables", nil, 10*time.Second)
		if err != nil {
			return s.toolErrorResult(traceID, err.Error()), toolName, "error", gateMeta, nil
		}
		return MCPCallToolResult{
			Content:           []MCPContentBlock{{Type: "text", Text: res.Output}},
			IsError:           false,
			StructuredContent: res.Data,
			TraceID:           traceID,
		}, toolName, "ok", gateMeta, nil

	case "tls_status":
		var gateRes MCPCallToolResult
		var gateStatus string
		var proceed bool
		gateRes, gateStatus, gateMeta, proceed = s.checkApprovalGate(ctx, ApprovalGateRequest{
			ToolName:   toolName,
			Action:     toolName,
			Parameters: cleanArgs,
			ApprovalID: approvalID,
			Actor:      actor,
		}, traceID)
		if !proceed {
			return gateRes, toolName, gateStatus, gateMeta, nil
		}
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
		}, toolName, "ok", gateMeta, nil

	case "audit_query":
		var gateRes MCPCallToolResult
		var gateStatus string
		var proceed bool
		gateRes, gateStatus, gateMeta, proceed = s.checkApprovalGate(ctx, ApprovalGateRequest{
			ToolName:   toolName,
			Action:     toolName,
			Parameters: cleanArgs,
			ApprovalID: approvalID,
			Actor:      actor,
		}, traceID)
		if !proceed {
			return gateRes, toolName, gateStatus, gateMeta, nil
		}
		if s.auditLogger == nil {
			return s.toolErrorResult(traceID, "audit logger is not enabled"), toolName, "error", gateMeta, nil
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
		}, toolName, "ok", gateMeta, nil

	case "audit_verify":
		var gateRes MCPCallToolResult
		var gateStatus string
		var proceed bool
		gateRes, gateStatus, gateMeta, proceed = s.checkApprovalGate(ctx, ApprovalGateRequest{
			ToolName:   toolName,
			Action:     toolName,
			Parameters: cleanArgs,
			ApprovalID: approvalID,
			Actor:      actor,
		}, traceID)
		if !proceed {
			return gateRes, toolName, gateStatus, gateMeta, nil
		}
		if s.auditLogger == nil {
			return s.toolErrorResult(traceID, "audit logger is not enabled"), toolName, "error", gateMeta, nil
		}
		v := s.auditLogger.VerifyChain()
		raw, _ := json.MarshalIndent(v, "", "  ")
		return MCPCallToolResult{
			Content:           []MCPContentBlock{{Type: "text", Text: string(raw)}},
			IsError:           !v.Valid,
			StructuredContent: v,
			TraceID:           traceID,
		}, toolName, "ok", gateMeta, nil

	case "mcp_trace_verify":
		var gateRes MCPCallToolResult
		var gateStatus string
		var proceed bool
		gateRes, gateStatus, gateMeta, proceed = s.checkApprovalGate(ctx, ApprovalGateRequest{
			ToolName:   toolName,
			Action:     toolName,
			Parameters: cleanArgs,
			ApprovalID: approvalID,
			Actor:      actor,
		}, traceID)
		if !proceed {
			return gateRes, toolName, gateStatus, gateMeta, nil
		}
		targetTraceID := ""
		if cleanArgs != nil {
			if v, ok := cleanArgs["trace_id"]; ok && v != nil {
				targetTraceID = strings.TrimSpace(fmt.Sprintf("%v", v))
			}
		}
		if targetTraceID != "" {
			v, err := s.VerifyTraceIntegrity(targetTraceID)
			if err != nil {
				return s.toolErrorResult(traceID, err.Error()), toolName, "error", gateMeta, nil
			}
			raw, _ := json.MarshalIndent(v, "", "  ")
			return MCPCallToolResult{
				Content:           []MCPContentBlock{{Type: "text", Text: string(raw)}},
				IsError:           !v.Valid,
				StructuredContent: v,
				TraceID:           traceID,
			}, toolName, "ok", gateMeta, nil
		}
		v := s.VerifyTraceChain()
		raw, _ := json.MarshalIndent(v, "", "  ")
		return MCPCallToolResult{
			Content:           []MCPContentBlock{{Type: "text", Text: string(raw)}},
			IsError:           !v.Valid,
			StructuredContent: v,
			TraceID:           traceID,
		}, toolName, "ok", gateMeta, nil

	default:
		return s.toolErrorResult(traceID, fmt.Sprintf("unknown MCP tool %q", toolName)), toolName, "error", gateMeta, nil
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
	case CISResourceURI:
		payload = BuildCISBenchmarksPresetResource(s.pluginRegistry)
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
	case CISPromptName:
		target := strings.TrimSpace(req.Arguments["target"])
		if target == "" {
			target = "rhel9"
		}
		if !IsValidCISTarget(target) {
			return nil, &JSONRPCError{
				Code:    -32602,
				Message: fmt.Sprintf("Unsupported CIS benchmark target %q (must match one of the 18 canonical cis.mcp.contract.v1 targets)", target),
			}
		}
		format := strings.ToLower(strings.TrimSpace(req.Arguments["format"]))
		if format == "" {
			format = "json"
		}
		actionName := "cis_audit_json"
		switch format {
		case "json":
			actionName = "cis_audit_json"
		case "sarif":
			actionName = "cis_audit_sarif"
		default:
			return nil, &JSONRPCError{
				Code:    -32602,
				Message: fmt.Sprintf("Unsupported CIS audit format %q (allowed: 'json' or 'sarif')", format),
			}
		}
		return map[string]any{
			"description": "Guided strictly read-only CIS compliance audit workflow (cis.mcp.contract.v1)",
			"messages": []map[string]any{
				{
					"role": "user",
					"content": map[string]any{
						"type": "text",
						"text": fmt.Sprintf(
							"Perform a strictly read-only CIS compliance audit for target %q (%s format): "+
								"1) Read MCP resource %s to verify the 18-target allowlist, forbidden mutation/credential flags, and CIS_DB_PASSWORD env-only boundary; "+
								"2) Call execute_plugin with plugin_id=%q and action=%q for target=%q (never pass remediation apply flags or passwords on argv); "+
								"3) Summarize findings across the 5-state compliance taxonomy (Pass, Fail, Error, Manual, Not Applicable) and optionally call action=\"cis_remediate_dry_run\" for a zero-execution preview; "+
								"4) Verify trace and audit chain integrity via mcp_trace_verify and audit_verify.",
							target, format, CISResourceURI, CISPluginID, actionName, target,
						),
					},
				},
			},
		}, nil
	default:
		return nil, &JSONRPCError{Code: -32602, Message: fmt.Sprintf("Prompt not found: %s", req.Name)}
	}
}

func ensureMCPTracesColumns(db *database.DB) error {
	rows, err := db.Query("PRAGMA table_info(mcp_traces)")
	if err != nil {
		return err
	}
	existing := make(map[string]bool)
	for rows.Next() {
		var cid int
		var name, colType string
		var notNull int
		var dflt any
		var pk int
		if err := rows.Scan(&cid, &name, &colType, &notNull, &dflt, &pk); err != nil {
			_ = rows.Close()
			return err
		}
		existing[strings.ToLower(name)] = true
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	_ = rows.Close()

	required := []struct {
		name string
		typ  string
	}{
		{"parent_trace_id", "TEXT"},
		{"request_sha256", "TEXT"},
		{"response_sha256", "TEXT"},
		{"prev_trace_hash", "TEXT"},
		{"trace_hash", "TEXT"},
		{"audit_entry_hash", "TEXT"},
		{"gatekeeper_decision", "TEXT"},
		{"gatekeeper_risk_score", "REAL"},
		{"gatekeeper_latency_ms", "REAL"},
	}
	for _, col := range required {
		if !existing[col.name] {
			if _, err := db.Exec(fmt.Sprintf("ALTER TABLE mcp_traces ADD COLUMN %s %s", col.name, col.typ)); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Server) recordTrace(tr MCPTrace) {
	if reqDigest, err := CanonicalJSONSHA256(tr.RequestPayload); err == nil {
		tr.RequestSHA256 = reqDigest
	}
	if respDigest, err := CanonicalJSONSHA256(tr.ResponsePayload); err == nil {
		tr.ResponseSHA256 = respDigest
	}

	s.mu.Lock()
	tr.PrevTraceHash = s.lastTraceHash
	tr.TraceHash = ComputeTraceHash(tr)
	s.lastTraceHash = tr.TraceHash
	if len(s.traces) >= s.cfg.MaxTraces {
		s.traces = append(s.traces[1:], tr)
		s.firstTraceIsGenesis = false
	} else {
		s.traces = append(s.traces, tr)
	}
	s.mu.Unlock()

	if s.cfg.TraceFilePath != "" {
		s.fileMu.Lock()
		if s.traceFile != nil {
			_ = json.NewEncoder(s.traceFile).Encode(tr)
		}
		s.fileMu.Unlock()
	}

	if s.db != nil && !s.db.IsInMemory() && s.db.DB != nil {
		reqBytes, _ := json.Marshal(tr.RequestPayload)
		respBytes, _ := json.Marshal(tr.ResponsePayload)
		isErrInt := 0
		if tr.IsError {
			isErrInt = 1
		}
		_, _ = s.db.Exec(
			`INSERT INTO mcp_traces(trace_id, parent_trace_id, session_id, timestamp, method, tool_name, actor, status, is_error, duration_ms, request_json, response_json, request_sha256, response_sha256, prev_trace_hash, trace_hash, audit_event_id, audit_entry_hash, gatekeeper_decision, gatekeeper_risk_score, gatekeeper_latency_ms)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			tr.TraceID, tr.ParentTraceID, tr.SessionID, tr.Timestamp, tr.Method, tr.ToolName, tr.Actor, tr.Status, isErrInt,
			tr.DurationMs, string(reqBytes), string(respBytes), tr.RequestSHA256, tr.ResponseSHA256,
			tr.PrevTraceHash, tr.TraceHash, tr.AuditEventID, tr.AuditEntryHash,
			tr.GatekeeperDecision, tr.GatekeeperRiskScore, tr.GatekeeperLatencyMs,
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
	return MCPTrace{}, ErrTraceNotFound
}

// ClearTraces clears the in-memory MCP trace buffer and resets chain genesis tracking.
func (s *Server) ClearTraces() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := len(s.traces)
	s.traces = make([]MCPTrace, 0, 128)
	s.lastTraceHash = MCPTraceGenesisHash
	s.firstTraceIsGenesis = true
	return n
}
