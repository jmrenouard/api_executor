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
	"go-admin-tool/internal/auth"
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

	// 6. Verify service account allowed_actions cannot be bypassed via POST /api/v1/mcp tools/call
	cfg.Auth.Enabled = true
	cfg.Auth.RequireAuth = true
	cmdForbidden := core.CommandDefinition{Name: "mcp-forbidden-cmd", Command: cmdDef.Command, Args: cmdDef.Args}
	cfg.Executor.Commands = []core.CommandDefinition{cmdDef, cmdForbidden}

	authMgr, err := auth.NewManager(cfg.Auth)
	if err != nil {
		t.Fatalf("failed to create auth manager: %v", err)
	}
	env.AuthManager = authMgr
	_, saKey, err := authMgr.CreateServiceAccount("mcp-sa", "MCP Bot", "Scoped to mcp-test-cmd only", nil, []string{"mcp-test-cmd"}, 0)
	if err != nil {
		t.Fatalf("failed to create service account: %v", err)
	}

	// Allowed command via MCP succeeds
	reqAllowedMCP := httptest.NewRequest(http.MethodPost, "/api/v1/mcp", bytes.NewReader(rpcBody))
	reqAllowedMCP.Header.Set("X-Service-Key", saKey)
	recAllowedMCP := httptest.NewRecorder()
	router.ServeHTTP(recAllowedMCP, reqAllowedMCP)
	if recAllowedMCP.Code != http.StatusOK || strings.Contains(recAllowedMCP.Body.String(), `"isError":true`) {
		t.Fatalf("expected allowed command to succeed via MCP for scoped service account, got %d: %s", recAllowedMCP.Code, recAllowedMCP.Body.String())
	}

	// Forbidden command via MCP must be denied (isError: true)
	forbidRPCBody, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/call",
		"params": map[string]any{
			"name": "execute_command",
			"arguments": map[string]any{
				"name": "mcp-forbidden-cmd",
			},
		},
	})
	reqForbidMCP := httptest.NewRequest(http.MethodPost, "/api/v1/mcp", bytes.NewReader(forbidRPCBody))
	reqForbidMCP.Header.Set("X-Service-Key", saKey)
	recForbidMCP := httptest.NewRecorder()
	router.ServeHTTP(recForbidMCP, reqForbidMCP)
	if !strings.Contains(recForbidMCP.Body.String(), `"isError":true`) {
		t.Fatalf("expected MCP tools/call on forbidden command to return isError=true for scoped service account, got: %s", recForbidMCP.Body.String())
	}

	// 7. GET /api/v1/mcp returns protocol metadata, non-admin DELETE /api/v1/mcp/traces returns 403
	reqMeta := httptest.NewRequest(http.MethodGet, "/api/v1/mcp", nil)
	reqMeta.Header.Set("X-Service-Key", saKey)
	recMeta := httptest.NewRecorder()
	router.ServeHTTP(recMeta, reqMeta)
	if recMeta.Code != http.StatusOK {
		t.Errorf("expected 200 from GET /api/v1/mcp, got %d", recMeta.Code)
	}

	reqDelForbid := httptest.NewRequest(http.MethodDelete, "/api/v1/mcp/traces", nil)
	reqDelForbid.Header.Set("X-Service-Key", saKey)
	recDelForbid := httptest.NewRecorder()
	router.ServeHTTP(recDelForbid, reqDelForbid)
	if recDelForbid.Code != http.StatusForbidden {
		t.Errorf("expected 403 when service account tries to DELETE /api/v1/mcp/traces, got %d", recDelForbid.Code)
	}

	// Unknown trace ID -> 404, empty trace suffix delegates to list
	reqUnkTrace := httptest.NewRequest(http.MethodGet, "/api/v1/mcp/traces/mcp_tr_missing", nil)
	reqUnkTrace.Header.Set("X-Service-Key", saKey)
	recUnkTrace := httptest.NewRecorder()
	router.ServeHTTP(recUnkTrace, reqUnkTrace)
	if recUnkTrace.Code != http.StatusNotFound {
		t.Errorf("expected 404 for unknown trace ID, got %d", recUnkTrace.Code)
	}

	reqEmptyTrace := httptest.NewRequest(http.MethodGet, "/api/v1/mcp/traces/?limit=5", nil)
	reqEmptyTrace.Header.Set("X-Service-Key", saKey)
	recEmptyTrace := httptest.NewRecorder()
	router.ServeHTTP(recEmptyTrace, reqEmptyTrace)
	if recEmptyTrace.Code != http.StatusOK {
		t.Errorf("expected 200 for /api/v1/mcp/traces/?limit=5, got %d", recEmptyTrace.Code)
	}

	// 8. MethodNotAllowed (405) and nil MCPServer (503)
	for _, tc := range []struct {
		method string
		path   string
	}{
		{http.MethodDelete, "/api/v1/mcp"},
		{http.MethodPost, "/api/v1/mcp/tools"},
		{http.MethodPut, "/api/v1/mcp/traces"},
		{http.MethodPost, "/api/v1/mcp/traces/mcp_tr_1"},
	} {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		req.Header.Set("X-Service-Key", saKey)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("expected 405 for %s %s, got %d", tc.method, tc.path, rec.Code)
		}
	}

	nilMCPRouter := NewRouter(&APIEnv{Config: cfg, AuthManager: authMgr})
	for _, path := range []string{"/api/v1/mcp", "/api/v1/mcp/tools", "/api/v1/mcp/traces", "/api/v1/mcp/traces/id1"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("X-Service-Key", saKey)
		rec := httptest.NewRecorder()
		nilMCPRouter.ServeHTTP(rec, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("expected 503 for %s when MCPServer is nil, got %d", path, rec.Code)
		}
	}
}


