package api

import (
	"bytes"
	"encoding/json"
	"go-admin-tool/internal/core"
	"net/http"
	"net/http/httptest"
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
		"1. Command Executor",
		"2. Ubuntu & RedHat Presets",
		"3. RBAC Users & PATs",
		"4. Service Accounts",
		"5. Plugins & SQL Explorer",
		"6. MCP Server & Traces",
		"7. SHA-256 Audit & Logs",
		"8. HTTPS/TLS & Files",
		"cat.commands",
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

