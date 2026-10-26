package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"

	"go-admin-tool/internal/audit"
	"go-admin-tool/internal/core"
	"go-admin-tool/internal/mcp"
	"go-admin-tool/internal/plugins"
)

func TestMCPEndpointsAndTraceInspection(t *testing.T) {
	cfg := core.DefaultConfig()
	cfg.Server.TLS.Enabled = false

	cmdDef := core.CommandDefinition{Name: "mcp-test-cmd", Command: "sh", Args: []string{"-c", "echo mcp-http-ok"}}
	if runtime.GOOS == "windows" {
		cmdDef = core.CommandDefinition{Name: "mcp-test-cmd", Command: "cmd", Args: []string{"/C", "echo mcp-http-ok"}}
	}
	cfg.Executor.Commands = []core.CommandDefinition{cmdDef}

	auditLogger, _ := audit.NewAuditLogger(cfg.Audit, nil, nil)
	reg := plugins.NewRegistry()
	_ = reg.Register(plugins.NewSystemDiagnosticsPlugin())

	mcpServer, err := mcp.NewServer(cfg.MCP, cfg, nil, nil, reg, auditLogger, nil, RecordActionCall)
	if err != nil {
		t.Fatalf("failed to create MCPServer: %v", err)
	}

	env := &APIEnv{
		Config:         cfg,
		AuditLogger:    auditLogger,
		PluginRegistry: reg,
		MCPServer:      mcpServer,
	}
	router := NewRouter(env)

	// 1. GET /api/v1/mcp/tools returns tools, resources, and prompts
	reqTools := httptest.NewRequest(http.MethodGet, "/api/v1/mcp/tools", nil)
	recTools := httptest.NewRecorder()
	router.ServeHTTP(recTools, reqTools)
	if recTools.Code != http.StatusOK {
		t.Fatalf("expected 200 from /api/v1/mcp/tools, got %d", recTools.Code)
	}
	if !strings.Contains(recTools.Body.String(), "execute_command") {
		t.Errorf("expected execute_command in /api/v1/mcp/tools response: %s", recTools.Body.String())
	}

	// 2. POST /api/v1/mcp with tools/call -> execute_command
	rpcBody, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params": map[string]any{
			"name": "execute_command",
			"arguments": map[string]any{
				"name":    "mcp-test-cmd",
				"timeout": "5s",
			},
		},
	})
	reqRPC := httptest.NewRequest(http.MethodPost, "/api/v1/mcp", bytes.NewReader(rpcBody))
	reqRPC.Header.Set("X-MCP-Session-ID", "http-sess-1")
	recRPC := httptest.NewRecorder()
	router.ServeHTTP(recRPC, reqRPC)
	if recRPC.Code != http.StatusOK {
		t.Fatalf("expected 200 from POST /api/v1/mcp, got %d: %s", recRPC.Code, recRPC.Body.String())
	}
	traceID := recRPC.Header().Get("X-MCP-Trace-ID")
	if traceID == "" {
		t.Fatalf("expected X-MCP-Trace-ID response header")
	}
	if !strings.Contains(recRPC.Body.String(), "mcp-http-ok") {
		t.Errorf("expected mcp-http-ok in RPC output: %s", recRPC.Body.String())
	}

	// 3. GET /api/v1/mcp/traces and GET /api/v1/mcp/traces/{trace_id}
	reqTraces := httptest.NewRequest(http.MethodGet, "/api/v1/mcp/traces?session_id=http-sess-1", nil)
	recTraces := httptest.NewRecorder()
	router.ServeHTTP(recTraces, reqTraces)
	if recTraces.Code != http.StatusOK {
		t.Fatalf("expected 200 from /api/v1/mcp/traces, got %d", recTraces.Code)
	}

	reqTraceID := httptest.NewRequest(http.MethodGet, "/api/v1/mcp/traces/"+traceID, nil)
	recTraceID := httptest.NewRecorder()
	router.ServeHTTP(recTraceID, reqTraceID)
	if recTraceID.Code != http.StatusOK {
		t.Fatalf("expected 200 from /api/v1/mcp/traces/%s, got %d", traceID, recTraceID.Code)
	}

	// 4. Malformed JSON returns -32700 parse error
	reqBad := httptest.NewRequest(http.MethodPost, "/api/v1/mcp", strings.NewReader("{bad-json"))
	recBad := httptest.NewRecorder()
	router.ServeHTTP(recBad, reqBad)
	if recBad.Code != http.StatusBadRequest || !strings.Contains(recBad.Body.String(), "-32700") {
		t.Errorf("expected 400 and -32700 parse error, got %d: %s", recBad.Code, recBad.Body.String())
	}

	// 5. DELETE /api/v1/mcp/traces clears retained traces
	reqDel := httptest.NewRequest(http.MethodDelete, "/api/v1/mcp/traces", nil)
	recDel := httptest.NewRecorder()
	router.ServeHTTP(recDel, reqDel)
	if recDel.Code != http.StatusOK {
		t.Fatalf("expected 200 from DELETE /api/v1/mcp/traces, got %d", recDel.Code)
	}
}
