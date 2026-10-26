package api

import (
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
	env := &APIEnv{
		Config: &core.Config{},
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
		"/api/v1/execute",
		"/api/v1/presets/activate",
		"/api/v1/auth/tokens",
		"/api/v1/auth/service-accounts",
		"/api/v1/plugins/execute",
		"/api/v1/db/query",
		"/api/v1/mcp",
		"/api/v1/audit/verify",
		"/api/v1/tls/renew",
	}

	for _, marker := range requiredSections {
		if !strings.Contains(body, marker) {
			t.Errorf("expected web administration console HTML to contain %q", marker)
		}
	}
}
