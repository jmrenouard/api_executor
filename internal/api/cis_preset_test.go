package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"go-admin-tool/internal/audit"
	"go-admin-tool/internal/auth"
	"go-admin-tool/internal/core"
	"go-admin-tool/internal/mcp"
	"go-admin-tool/internal/plugins"
)

func TestCISBenchmarksPreset_ServiceAccountRBACAndFailClosedRESTAndMCP(t *testing.T) {
	cfg := core.DefaultConfig()
	cfg.Auth.Enabled = true
	cfg.Auth.RequireAuth = true
	cfg.MCP.Enabled = true
	cfg.Executor.Commands = []core.CommandDefinition{
		{Name: "list-processes", Command: "echo", Args: []string{"ok"}},
	}

	authMgr, err := auth.NewManager(cfg.Auth)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}
	_, cisSvcKey, err := authMgr.CreateServiceAccount(
		"cis-auditor-bot",
		"cis-compliance-scanner",
		"Read-only CIS Benchmarks audit service account",
		[]string{"plugins:read", "plugins:execute", "commands:execute", "mcp:access"},
		[]string{"plugin:cis-benchmarks-audit:*"},
		time.Hour,
	)
	if err != nil {
		t.Fatalf("CreateServiceAccount failed: %v", err)
	}

	reg := plugins.NewRegistry()
	pluginsDir := "plugins"
	if _, err := os.Stat(pluginsDir); err != nil && os.IsNotExist(err) {
		pluginsDir = "../../plugins"
	}
	if _, err := reg.LoadDeclarativeDirectory(pluginsDir); err != nil {
		t.Fatalf("LoadDeclarativeDirectory failed: %v", err)
	}

	auditLogger, err := audit.NewAuditLogger(core.AuditConfig{Enabled: true, MaxMemoryLog: 100}, nil, nil)
	if err != nil {
		t.Fatalf("NewAuditLogger failed: %v", err)
	}
	mcpSrv, err := mcp.NewServer(cfg.MCP, cfg, nil, nil, reg, auditLogger, nil, nil)
	if err != nil {
		t.Fatalf("mcp.NewServer failed: %v", err)
	}
	defer mcpSrv.Close()

	env := &APIEnv{
		Config:         cfg,
		AuthManager:    authMgr,
		PluginRegistry: reg,
		AuditLogger:    auditLogger,
		MCPServer:      mcpSrv,
	}
	handler := NewRouter(env)

	doPost := func(path string, body any) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+cisSvcKey)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		return rr
	}

	// 1. Scoped service account is permitted by RBAC on cis-benchmarks-audit, and forbidden flags fail closed with 400 Bad Request before subprocess spawn.
	rrCISBad := doPost("/api/v1/plugins/execute", map[string]any{
		"plugin_id": "cis-benchmarks-audit",
		"action":    "cis_audit_json",
		"params": map[string]any{
			"target": "--apply",
		},
	})
	if rrCISBad.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request (RBAC allowed, regex rejected '--apply'), got %d: %s", rrCISBad.Code, rrCISBad.Body.String())
	}

	// 2. Scoped service account is blocked (403 Forbidden) from unrelated plugins.
	rrOtherPlugin := doPost("/api/v1/plugins/execute", map[string]any{
		"plugin_id": "sys-diagnostics",
		"action":    "runtime_stats",
	})
	if rrOtherPlugin.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for unrelated plugin 'sys-diagnostics', got %d: %s", rrOtherPlugin.Code, rrOtherPlugin.Body.String())
	}

	// 3. Scoped service account is blocked (403 Forbidden) from unrelated commands.
	rrOtherCmd := doPost("/api/v1/execute", map[string]any{
		"name": "list-processes",
	})
	if rrOtherCmd.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for unrelated command 'list-processes', got %d: %s", rrOtherCmd.Code, rrOtherCmd.Body.String())
	}

	// 4. Via MCP tools/call, scoped service account is blocked from unrelated plugins and fails closed on CIS forbidden flags.
	rrMCPOther := doPost("/api/v1/mcp", map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params": map[string]any{
			"name": "execute_plugin",
			"arguments": map[string]any{
				"plugin_id": "sys-diagnostics",
				"action":    "runtime_stats",
			},
		},
	})
	if rrMCPOther.Code != http.StatusOK {
		t.Fatalf("expected 200 JSON-RPC envelope, got %d: %s", rrMCPOther.Code, rrMCPOther.Body.String())
	}
	var mcpOtherResp struct {
		Result mcp.MCPCallToolResult `json:"result"`
	}
	if err := json.Unmarshal(rrMCPOther.Body.Bytes(), &mcpOtherResp); err != nil {
		t.Fatalf("unmarshal MCP response failed: %v", err)
	}
	if !mcpOtherResp.Result.IsError {
		t.Fatalf("expected MCP authorization denial for unrelated plugin, got %+v", mcpOtherResp.Result)
	}

	rrMCPCISBad := doPost("/api/v1/mcp", map[string]any{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/call",
		"params": map[string]any{
			"name": "execute_plugin",
			"arguments": map[string]any{
				"plugin_id": "cis-benchmarks-audit",
				"action":    "cis_remediate_dry_run",
				"params": map[string]any{
					"report_path": "/tmp/../etc/passwd.json",
				},
			},
		},
	})
	if rrMCPCISBad.Code != http.StatusOK {
		t.Fatalf("expected 200 JSON-RPC envelope, got %d", rrMCPCISBad.Code)
	}
	var mcpCISResp struct {
		Result mcp.MCPCallToolResult `json:"result"`
	}
	if err := json.Unmarshal(rrMCPCISBad.Body.Bytes(), &mcpCISResp); err != nil {
		t.Fatalf("unmarshal MCP CIS response failed: %v", err)
	}
	if !mcpCISResp.Result.IsError {
		t.Fatalf("expected MCP IsError=true on path traversal in report_path, got %+v", mcpCISResp.Result)
	}
}
