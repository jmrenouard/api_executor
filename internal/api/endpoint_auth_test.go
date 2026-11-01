package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"go-admin-tool/internal/audit"
	"go-admin-tool/internal/auth"
	"go-admin-tool/internal/core"
	"go-admin-tool/internal/database"
)

func setupProtectedEndpointsEnv(t *testing.T, requireAuth bool) (*APIEnv, http.Handler, string) {
	t.Helper()

	tmpDir := t.TempDir()
	testFilePath := filepath.Join(tmpDir, "test-doc.txt")
	if err := os.WriteFile(testFilePath, []byte("protected-file-content"), 0600); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	cfg := core.DefaultConfig()
	cfg.Server.TLS.Enabled = false
	cfg.FileServer.Enabled = true
	cfg.FileServer.SecureDir = tmpDir
	cfg.Executor.Enabled = true

	cmd := core.CommandDefinition{Name: "auth-check-cmd", Command: "sh", Args: []string{"-c", "echo auth-ok"}}
	if runtime.GOOS == "windows" {
		cmd = core.CommandDefinition{Name: "auth-check-cmd", Command: "cmd", Args: []string{"/C", "echo auth-ok"}}
	}
	cfg.Executor.Commands = []core.CommandDefinition{cmd}

	cfg.Auth.Enabled = true
	cfg.Auth.RequireAuth = requireAuth
	cfg.Auth.BootstrapUsername = "admin"
	cfg.Auth.BootstrapPassword = "admin-secret-password-123"

	logger, err := core.NewLogger(core.LoggingConfig{Level: "info"})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	db, err := database.NewDB(":memory:")
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Init(); err != nil {
		t.Fatalf("failed to initialize database schema: %v", err)
	}

	auditLogger, err := audit.NewAuditLogger(cfg.Audit, db, logger)
	if err != nil {
		t.Fatalf("failed to create audit logger: %v", err)
	}

	authMgr, err := auth.NewManager(cfg.Auth)
	if err != nil {
		t.Fatalf("failed to create auth manager: %v", err)
	}

	env := &APIEnv{
		Config:      cfg,
		Logger:      logger,
		DB:          db,
		AuditLogger: auditLogger,
		AuthManager: authMgr,
	}
	router := NewRouter(env)

	// Authenticate bootstrap admin to get a valid token
	_, _, validToken, err := authMgr.AuthenticateUser("admin", "admin-secret-password-123")
	if err != nil {
		t.Fatalf("failed to authenticate admin user: %v", err)
	}

	return env, router, validToken
}

func TestProtectedEndpoints_RequireAuth_UnauthenticatedReturns401(t *testing.T) {
	_, router, _ := setupProtectedEndpointsEnv(t, true)

	endpoints := []struct {
		name   string
		method string
		path   string
	}{
		{"ListFiles", http.MethodGet, "/api/v1/files"},
		{"DownloadFile", http.MethodGet, "/api/v1/files/test-doc.txt"},
		{"ListCommands", http.MethodGet, "/api/v1/commands"},
		{"AuditLogs", http.MethodGet, "/api/v1/audit/logs"},
		{"AuditVerify", http.MethodGet, "/api/v1/audit/verify"},
		{"SystemLogs", http.MethodGet, "/api/v1/logs"},
		{"ActionHistory", http.MethodGet, "/api/v1/history"},
	}

	for _, tc := range endpoints {
		t.Run(tc.name, func(t *testing.T) {
			// Subtest 1: Unauthenticated request without token header -> 401
			req := httptest.NewRequest(tc.method, tc.path, nil)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Errorf("expected 401 Unauthorized for unauthenticated %s %s, got %d (body: %s)",
					tc.method, tc.path, rec.Code, rec.Body.String())
			}

			// Subtest 2: Request with invalid token -> 401
			reqBadToken := httptest.NewRequest(tc.method, tc.path, nil)
			reqBadToken.Header.Set("Authorization", "Bearer invalid-or-forged-token-xyz")
			recBadToken := httptest.NewRecorder()
			router.ServeHTTP(recBadToken, reqBadToken)

			if recBadToken.Code != http.StatusUnauthorized {
				t.Errorf("expected 401 Unauthorized for invalid token on %s %s, got %d (body: %s)",
					tc.method, tc.path, recBadToken.Code, recBadToken.Body.String())
			}
		})
	}
}

func TestProtectedEndpoints_RequireAuth_AuthenticatedSucceeds200(t *testing.T) {
	_, router, validToken := setupProtectedEndpointsEnv(t, true)

	endpoints := []struct {
		name       string
		method     string
		path       string
		authHeader string
		authValue  string
	}{
		{"ListFiles_Bearer", http.MethodGet, "/api/v1/files", "Authorization", "Bearer " + validToken},
		{"ListFiles_XToken", http.MethodGet, "/api/v1/files", "X-API-Token", validToken},
		{"DownloadFile_Bearer", http.MethodGet, "/api/v1/files/test-doc.txt", "Authorization", "Bearer " + validToken},
		{"DownloadFile_XToken", http.MethodGet, "/api/v1/files/test-doc.txt", "X-API-Token", validToken},
		{"ListCommands_Bearer", http.MethodGet, "/api/v1/commands", "Authorization", "Bearer " + validToken},
		{"ListCommands_XToken", http.MethodGet, "/api/v1/commands", "X-API-Token", validToken},
		{"AuditLogs_Bearer", http.MethodGet, "/api/v1/audit/logs", "Authorization", "Bearer " + validToken},
		{"AuditLogs_XToken", http.MethodGet, "/api/v1/audit/logs", "X-API-Token", validToken},
		{"AuditVerify_Bearer", http.MethodGet, "/api/v1/audit/verify", "Authorization", "Bearer " + validToken},
		{"AuditVerify_XToken", http.MethodGet, "/api/v1/audit/verify", "X-API-Token", validToken},
		{"SystemLogs_Bearer", http.MethodGet, "/api/v1/logs", "Authorization", "Bearer " + validToken},
		{"SystemLogs_XToken", http.MethodGet, "/api/v1/logs", "X-API-Token", validToken},
		{"ActionHistory_Bearer", http.MethodGet, "/api/v1/history", "Authorization", "Bearer " + validToken},
		{"ActionHistory_XToken", http.MethodGet, "/api/v1/history", "X-API-Token", validToken},
	}

	for _, tc := range endpoints {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			req.Header.Set(tc.authHeader, tc.authValue)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("expected 200 OK for authenticated %s %s with %s, got %d (body: %s)",
					tc.method, tc.path, tc.authHeader, rec.Code, rec.Body.String())
			}

			// Validate payload integrity per endpoint
			body := rec.Body.String()
			switch {
			case strings.HasPrefix(tc.path, "/api/v1/files/test-doc.txt"):
				if body != "protected-file-content" {
					t.Errorf("unexpected file content: %s", body)
				}
			case strings.HasPrefix(tc.path, "/api/v1/files"):
				var listResp FileListResponse
				if err := json.Unmarshal(rec.Body.Bytes(), &listResp); err != nil {
					t.Errorf("failed to decode FileListResponse: %v", err)
				}
				if len(listResp.Files) != 1 || listResp.Files[0] != "test-doc.txt" {
					t.Errorf("expected ['test-doc.txt'], got %+v", listResp.Files)
				}
			case strings.HasPrefix(tc.path, "/api/v1/commands"):
				if !strings.Contains(body, "auth-check-cmd") {
					t.Errorf("expected command list to contain 'auth-check-cmd', got: %s", body)
				}
			case strings.HasPrefix(tc.path, "/api/v1/audit/verify"):
				if !strings.Contains(body, `"valid":true`) {
					t.Errorf("expected audit verify response to contain valid:true, got: %s", body)
				}
			}
		})
	}
}

func TestProtectedEndpoints_RequireAuthFalse_BackwardCompatibility(t *testing.T) {
	_, router, _ := setupProtectedEndpointsEnv(t, false)

	endpoints := []struct {
		name   string
		method string
		path   string
	}{
		{"ListFiles", http.MethodGet, "/api/v1/files"},
		{"DownloadFile", http.MethodGet, "/api/v1/files/test-doc.txt"},
		{"ListCommands", http.MethodGet, "/api/v1/commands"},
		{"AuditLogs", http.MethodGet, "/api/v1/audit/logs"},
		{"AuditVerify", http.MethodGet, "/api/v1/audit/verify"},
		{"SystemLogs", http.MethodGet, "/api/v1/logs"},
		{"ActionHistory", http.MethodGet, "/api/v1/history"},
	}

	for _, tc := range endpoints {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("expected 200 OK when RequireAuth=false for %s %s, got %d (body: %s)",
					tc.method, tc.path, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestProtectedEndpoints_RequireAuth_NilAuthManagerReturns401(t *testing.T) {
	cfg := core.DefaultConfig()
	cfg.Server.TLS.Enabled = false
	cfg.FileServer.Enabled = true
	cfg.FileServer.SecureDir = t.TempDir()
	cfg.Executor.Enabled = true
	cfg.Auth.RequireAuth = true

	env := &APIEnv{
		Config:      cfg,
		AuthManager: nil, // Nil auth manager with RequireAuth=true
	}
	router := NewRouter(env)

	for _, ep := range []string{
		"/api/v1/files",
		"/api/v1/files/any.txt",
		"/api/v1/commands",
		"/api/v1/audit/logs",
		"/api/v1/audit/verify",
		"/api/v1/logs",
		"/api/v1/history",
	} {
		req := httptest.NewRequest(http.MethodGet, ep, nil)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("expected 401 Unauthorized from %s when AuthManager is nil and RequireAuth=true, got %d", ep, rec.Code)
		}
	}
}
