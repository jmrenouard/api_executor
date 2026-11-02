package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sync"
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
	authMgr, err := auth.NewManager(cfg.Auth)
	if err != nil {
		t.Fatalf("failed to create auth manager: %v", err)
	}
	_, _, adminTok, err := authMgr.AuthenticateUser(cfg.Auth.BootstrapUsername, cfg.Auth.BootstrapPassword)
	if err != nil {
		t.Fatalf("failed to authenticate admin: %v", err)
	}

	env := &APIEnv{Config: cfg, AuditLogger: auditLogger, AuthManager: authMgr}
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

	// 2.1 Anonymous callers must be forbidden from activating presets
	reqActAnon := httptest.NewRequest(http.MethodPost, "/api/v1/presets/activate", bytes.NewReader(body))
	recActAnon := httptest.NewRecorder()
	router.ServeHTTP(recActAnon, reqActAnon)
	if recActAnon.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for anonymous caller on /api/v1/presets/activate, got %d", recActAnon.Code)
	}

	// 2.2 Authenticated Admin succeeds
	reqAct := httptest.NewRequest(http.MethodPost, "/api/v1/presets/activate", bytes.NewReader(body))
	reqAct.Header.Set("Authorization", "Bearer "+adminTok)
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

// TestConcurrentPresetActivationAndCommandExecution asserts that concurrent writes (activating presets)
// and concurrent reads (listing commands, looking up commands, and executing commands) produce zero data races.
func TestConcurrentPresetActivationAndCommandExecution(t *testing.T) {
	cfg := core.DefaultConfig()
	cfg.Server.TLS.Enabled = false
	cfg.Executor.Enabled = true
	echoCmd := core.CommandDefinition{
		Name:    "concurrency-echo",
		Command: "sh",
		Args:    []string{"-c", "echo concurrent-ok"},
	}
	if runtime.GOOS == "windows" {
		echoCmd = core.CommandDefinition{
			Name:    "concurrency-echo",
			Command: "cmd",
			Args:    []string{"/C", "echo concurrent-ok"},
		}
	}
	cfg.Executor.Commands = []core.CommandDefinition{echoCmd}

	auditLogger, err := audit.NewAuditLogger(cfg.Audit, nil, nil)
	if err != nil {
		t.Fatalf("failed to create audit logger: %v", err)
	}
	authMgr, err := auth.NewManager(cfg.Auth)
	if err != nil {
		t.Fatalf("failed to create auth manager: %v", err)
	}
	_, _, adminTok, err := authMgr.AuthenticateUser(cfg.Auth.BootstrapUsername, cfg.Auth.BootstrapPassword)
	if err != nil {
		t.Fatalf("failed to authenticate admin: %v", err)
	}

	env := &APIEnv{
		Config:      cfg,
		AuditLogger: auditLogger,
		AuthManager: authMgr,
	}
	router := NewRouter(env)

	const (
		concurrency = 8
		iterations  = 15
	)

	var wg sync.WaitGroup
	startSignal := make(chan struct{})

	// 1. Concurrent preset activation goroutines (write lock)
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			<-startSignal
			for j := 0; j < iterations; j++ {
				fam := "ubuntu"
				if j%2 == 1 {
					fam = "redhat"
				}
				body, _ := json.Marshal(map[string]any{"families": []string{fam}})
				req := httptest.NewRequest(http.MethodPost, "/api/v1/presets/activate", bytes.NewReader(body))
				req.Header.Set("Authorization", "Bearer "+adminTok)
				rec := httptest.NewRecorder()
				router.ServeHTTP(rec, req)
				if rec.Code != http.StatusOK {
					t.Errorf("worker %d iter %d activate failed with %d: %s", workerID, j, rec.Code, rec.Body.String())
				}
			}
		}(i)
	}

	// 2. Concurrent command listing goroutines (read lock)
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			<-startSignal
			for j := 0; j < iterations; j++ {
				req := httptest.NewRequest(http.MethodGet, "/api/v1/commands", nil)
				rec := httptest.NewRecorder()
				router.ServeHTTP(rec, req)
				if rec.Code != http.StatusOK {
					t.Errorf("worker %d iter %d list commands failed with %d", workerID, j, rec.Code)
				}
			}
		}(i)
	}

	// 3. Concurrent command execution goroutines (read lock)
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			<-startSignal
			for j := 0; j < iterations; j++ {
				body, _ := json.Marshal(map[string]any{"name": "concurrency-echo"})
				req := httptest.NewRequest(http.MethodPost, "/api/v1/execute", bytes.NewReader(body))
				rec := httptest.NewRecorder()
				router.ServeHTTP(rec, req)
				if rec.Code != http.StatusOK {
					t.Errorf("worker %d iter %d execute failed with %d: %s", workerID, j, rec.Code, rec.Body.String())
				}
			}
		}(i)
	}

	close(startSignal)
	wg.Wait()
}
