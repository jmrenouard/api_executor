package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"go-admin-tool/internal/audit"
	"go-admin-tool/internal/auth"
	"go-admin-tool/internal/core"
)

func TestPresetsEndpointsListAndActivate(t *testing.T) {
	cfg := core.DefaultConfig()
	cfg.Server.TLS.Enabled = false
	cfg.Executor.Enabled = true
	cfg.Executor.Commands = []core.CommandDefinition{
		{Name: "custom-cmd", Command: "echo", Args: []string{"ok"}},
	}

	auditLogger, _ := audit.NewAuditLogger(cfg.Audit, nil, nil)
	env := &APIEnv{Config: cfg, AuditLogger: auditLogger}
	router := NewRouter(env)

	// 1. GET /api/v1/presets
	reqList := httptest.NewRequest(http.MethodGet, "/api/v1/presets", nil)
	recList := httptest.NewRecorder()
	router.ServeHTTP(recList, reqList)
	if recList.Code != http.StatusOK {
		t.Fatalf("expected 200 from /api/v1/presets, got %d", recList.Code)
	}
	var listResp struct {
		DetectedOSFamily string                 `json:"detected_os_family"`
		Catalogs         []core.OSPresetCatalog `json:"catalogs"`
	}
	if err := json.Unmarshal(recList.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("failed to decode presets response: %v", err)
	}
	if len(listResp.Catalogs) < 2 {
		t.Fatalf("expected at least 2 OS preset catalogs (ubuntu, redhat), got %d", len(listResp.Catalogs))
	}

	// 2. POST /api/v1/presets/activate
	body, _ := json.Marshal(map[string]any{"families": []string{"ubuntu", "redhat"}})
	reqAct := httptest.NewRequest(http.MethodPost, "/api/v1/presets/activate", bytes.NewReader(body))
	recAct := httptest.NewRecorder()
	router.ServeHTTP(recAct, reqAct)
	if recAct.Code != http.StatusOK {
		t.Fatalf("expected 200 from /api/v1/presets/activate, got %d: %s", recAct.Code, recAct.Body.String())
	}
	var actResp struct {
		AddedCount    int `json:"added_count"`
		TotalCommands int `json:"total_commands"`
	}
	if err := json.Unmarshal(recAct.Body.Bytes(), &actResp); err != nil {
		t.Fatalf("failed to decode activate response: %v", err)
	}
	if actResp.AddedCount < 20 {
		t.Fatalf("expected at least 20 Ubuntu+RedHat preset commands added, got %d", actResp.AddedCount)
	}

	// Verify audit event recorded
	if len(auditLogger.Query(audit.AuditFilter{Action: "presets.activate"})) == 0 {
		t.Fatalf("expected presets.activate event in AuditLogger")
	}

	// 3. Enforce authentication & authorization when RequireAuth=true
	cfg.Auth.Enabled = true
	cfg.Auth.RequireAuth = true
	authMgr, _ := auth.NewManager(cfg.Auth)
	env.AuthManager = authMgr
	_, _ = authMgr.CreateUser("viewer1", "viewer-pass-123", "Viewer", "", auth.RoleViewer)
	_, _, viewerTok, _ := authMgr.AuthenticateUser("viewer1", "viewer-pass-123")

	unauthReq := httptest.NewRequest(http.MethodPost, "/api/v1/presets/activate", bytes.NewReader(body))
	unauthRec := httptest.NewRecorder()
	router.ServeHTTP(unauthRec, unauthReq)
	if unauthRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthenticated POST /api/v1/presets/activate, got %d", unauthRec.Code)
	}

	viewerReq := httptest.NewRequest(http.MethodPost, "/api/v1/presets/activate", bytes.NewReader(body))
	viewerReq.Header.Set("X-API-Token", viewerTok)
	viewerRec := httptest.NewRecorder()
	router.ServeHTTP(viewerRec, viewerReq)
	if viewerRec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for viewer POST /api/v1/presets/activate, got %d", viewerRec.Code)
	}
}
