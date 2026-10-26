package api

import (
	"bytes"
	"encoding/json"
	"go-admin-tool/internal/audit"
	"go-admin-tool/internal/auth"
	"go-admin-tool/internal/core"
	"go-admin-tool/internal/database"
	"go-admin-tool/internal/mcp"
	"go-admin-tool/internal/plugins"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestWebAdministrationConsoleServed(t *testing.T) {
	logger, err := core.NewLogger(core.LoggingConfig{Level: "info"})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	cfg := core.DefaultConfig()
	cfg.Server.TLS.Enabled = false
	env := &APIEnv{
		Config: cfg,
		Logger: logger,
	}
	router := NewRouter(env)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200 OK for GET /, got %d", rec.Code)
	}

	body := rec.Body.String()
	requiredSections := []string{
		"API Executor — Enterprise Remote Administration Console",
		"rel=\"icon\" type=\"image/svg+xml\"",
		"1. Command Executor",
		"2. Ubuntu & RedHat Presets",
		"3. RBAC Users & PATs",
		"4. Service Accounts",
		"5. Plugins & SQL Explorer",
		"6. MCP Server & Traces",
		"7. SHA-256 Audit & Logs",
		"8. HTTPS/TLS & Files",
		"cat.commands",
		"const pluginID = d.id || (d.plugin && d.plugin.id) || '';",
		"/api/v1/execute",
		"/api/v1/presets/activate",
		"/api/v1/auth/tokens",
		"/api/v1/auth/service-accounts",
		"/api/v1/plugins/execute",
		"/api/v1/plugins/declarative",
		"/api/v1/db/query",
		"/api/v1/mcp",
		"/api/v1/audit/verify",
		"/api/v1/logs",
		"/api/v1/history",
		"/api/v1/tls/renew",
		"this.principal = null;",
		"Deleted user ",
		"Revoked token ",
		"Deleted service account ",
		"Executed plugin ",
	}

	for _, marker := range requiredSections {
		if !strings.Contains(body, marker) {
			t.Errorf("expected web administration console HTML to contain %q", marker)
		}
	}

	// Verify the Web Console's single-family os_families payload activates ONLY Ubuntu presets (not RedHat)
	actReqBody, _ := json.Marshal(map[string]any{"os_families": []string{"ubuntu"}})
	actReq := httptest.NewRequest(http.MethodPost, "/api/v1/presets/activate", bytes.NewReader(actReqBody))
	actRec := httptest.NewRecorder()
	router.ServeHTTP(actRec, actReq)
	if actRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from POST /api/v1/presets/activate with os_families, got %d: %s", actRec.Code, actRec.Body.String())
	}
	var actResp struct {
		ActivatedFamilies []string `json:"activated_families"`
		AddedCount        int      `json:"added_count"`
		TotalCommands     int      `json:"total_commands"`
	}
	if err := json.Unmarshal(actRec.Body.Bytes(), &actResp); err != nil {
		t.Fatalf("failed to decode activate response: %v", err)
	}
	if actResp.AddedCount != 10 {
		t.Fatalf("expected exactly 10 Ubuntu preset commands added when os_families=['ubuntu'], got %d", actResp.AddedCount)
	}
}

func TestWebAdministrationConsoleEndToEndWorkflows(t *testing.T) {
	tmpDir := t.TempDir()
	logger, err := core.NewLogger(core.LoggingConfig{Level: "info"})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	cfg := core.DefaultConfig()
	cfg.Server.TLS.Enabled = true
	cfg.Server.TLS.AutoGenerate = true
	cfg.Server.TLS.CertFile = filepath.Join(tmpDir, "server.crt")
	cfg.Server.TLS.KeyFile = filepath.Join(tmpDir, "server.key")

	db, err := database.NewDB(":memory:")
	if err != nil {
		t.Fatalf("failed to create db: %v", err)
	}
	defer db.Close()
	if err := db.Init(); err != nil {
		t.Fatalf("failed to init db: %v", err)
	}

	cm, err := core.NewCertManager(cfg.Server.TLS, "localhost")
	if err != nil {
		t.Fatalf("failed to init cert manager: %v", err)
	}
	auditLogger, err := audit.NewAuditLogger(cfg.Audit, db, logger)
	if err != nil {
		t.Fatalf("failed to init audit logger: %v", err)
	}
	authMgr, err := auth.NewManager(cfg.Auth)
	if err != nil {
		t.Fatalf("failed to init auth manager: %v", err)
	}
	reg := plugins.NewRegistry()
	_ = reg.Register(plugins.NewDatabaseExposurePlugin(db, 50))
	_ = reg.Register(plugins.NewSystemDiagnosticsPlugin())

	mcpSrv, err := mcp.NewServer(cfg.MCP, cfg, db, cm, reg, auditLogger, logger, RecordActionCall)
	if err != nil {
		t.Fatalf("failed to init mcp server: %v", err)
	}

	env := &APIEnv{
		Config:         cfg,
		Logger:         logger,
		DB:             db,
		CertManager:    cm,
		AuditLogger:    auditLogger,
		AuthManager:    authMgr,
		PluginRegistry: reg,
		MCPServer:      mcpSrv,
	}
	router := NewRouter(env)

	// 1. Tab 5 workflow: Register Declarative Plugin and assert root `id` field matches Web Console binding
	declSpec := map[string]any{
		"id":          "custom-ops",
		"name":        "Custom Ops Plugin",
		"version":     "1.0.0",
		"description": "Declarative diagnostic commands",
		"actions": []map[string]any{
			{
				"name":        "hostname-check",
				"description": "Print hostname",
				"command":     "hostname",
				"args":        []string{},
				"timeout":     "5s",
			},
		},
	}
	declBytes, _ := json.Marshal(declSpec)
	declReq := httptest.NewRequest(http.MethodPost, "/api/v1/plugins/declarative", bytes.NewReader(declBytes))
	declRec := httptest.NewRecorder()
	router.ServeHTTP(declRec, declReq)
	if declRec.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created from POST /api/v1/plugins/declarative, got %d: %s", declRec.Code, declRec.Body.String())
	}
	var declResp map[string]any
	if err := json.Unmarshal(declRec.Body.Bytes(), &declResp); err != nil {
		t.Fatalf("failed to decode declarative plugin response: %v", err)
	}
	if declResp["id"] != "custom-ops" {
		t.Fatalf("expected declarative plugin response root id='custom-ops', got %v", declResp["id"])
	}

	// 2. Tab 6 workflow: MCP tools/call (audit_verify) records trace and links to SHA-256 audit log
	mcpPayload := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"audit_verify","arguments":{}}}`
	mcpReq := httptest.NewRequest(http.MethodPost, "/api/v1/mcp", strings.NewReader(mcpPayload))
	mcpReq.Header.Set("X-MCP-Session-ID", "web-admin-console")
	mcpRec := httptest.NewRecorder()
	router.ServeHTTP(mcpRec, mcpReq)
	if mcpRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from POST /api/v1/mcp, got %d: %s", mcpRec.Code, mcpRec.Body.String())
	}

	// 3. Tab 8 workflow: Rotate TLS certificate and verify audit chain integrity in Tab 7
	tlsReq := httptest.NewRequest(http.MethodPost, "/api/v1/tls/renew", nil)
	tlsRec := httptest.NewRecorder()
	router.ServeHTTP(tlsRec, tlsReq)
	if tlsRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from POST /api/v1/tls/renew, got %d: %s", tlsRec.Code, tlsRec.Body.String())
	}

	verifyReq := httptest.NewRequest(http.MethodGet, "/api/v1/audit/verify", nil)
	verifyRec := httptest.NewRecorder()
	router.ServeHTTP(verifyRec, verifyReq)
	if verifyRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from GET /api/v1/audit/verify, got %d", verifyRec.Code)
	}
	var verifyResp struct {
		Valid       bool `json:"valid"`
		TotalEvents int  `json:"total_events"`
	}
	if err := json.Unmarshal(verifyRec.Body.Bytes(), &verifyResp); err != nil {
		t.Fatalf("failed to decode audit verify response: %v", err)
	}
	if !verifyResp.Valid || verifyResp.TotalEvents < 3 {
		t.Fatalf("expected valid audit chain with >= 3 events, got valid=%v total=%d", verifyResp.Valid, verifyResp.TotalEvents)
	}
}


