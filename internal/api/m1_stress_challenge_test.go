package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"go-admin-tool/internal/auth"
	"go-admin-tool/internal/core"
	"go-admin-tool/internal/database"
	"go-admin-tool/internal/plugins"
)

func TestChallenger_API_PluginsListHandler_ExtremeInputs(t *testing.T) {
	cfg := core.DefaultConfig()
	cfg.Server.TLS.Enabled = false
	cfg.Auth.Enabled = true
	cfg.Auth.RequireAuth = true

	dbPath := filepath.Join(t.TempDir(), "challenger_api_test.db")
	db, err := database.NewDB(dbPath)
	if err != nil {
		t.Fatalf("failed to create test db: %v", err)
	}
	defer db.Close()
	if err := db.Init(); err != nil {
		t.Fatalf("failed to init test db: %v", err)
	}

	authMgr, err := auth.NewManager(cfg.Auth)
	if err != nil {
		t.Fatalf("failed to init auth manager: %v", err)
	}

	reg := plugins.NewRegistry()
	if ops, err := plugins.DefaultDeclarativeOpsPlugin(); err == nil {
		_ = reg.Register(ops)
	}

	env := &APIEnv{
		Config:         cfg,
		DB:             db,
		AuthManager:    authMgr,
		PluginRegistry: reg,
	}
	router := NewRouter(env)

	// Obtain admin token via login
	loginBody, _ := json.Marshal(map[string]any{
		"username": "admin",
		"password": "admin-change-me",
	})
	reqLogin := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(loginBody))
	recLogin := httptest.NewRecorder()
	router.ServeHTTP(recLogin, reqLogin)
	if recLogin.Code != http.StatusOK {
		t.Fatalf("failed to login: %d %s", recLogin.Code, recLogin.Body.String())
	}
	var loginResp struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(recLogin.Body.Bytes(), &loginResp)
	tokenStr := loginResp.Token

	// Create service account without plugins:read permission
	saBody, _ := json.Marshal(map[string]any{
		"name":            "restricted-sa",
		"service_name":    "restricted-app",
		"allowed_actions": []string{"status"},
	})
	reqSA := httptest.NewRequest(http.MethodPost, "/api/v1/auth/service-accounts", bytes.NewReader(saBody))
	reqSA.Header.Set("Authorization", "Bearer "+tokenStr)
	recSA := httptest.NewRecorder()
	router.ServeHTTP(recSA, reqSA)
	var saResp struct {
		ServiceAccount auth.ServiceAccount `json:"service_account"`
		APIKey         string              `json:"api_key"`
	}
	_ = json.Unmarshal(recSA.Body.Bytes(), &saResp)
	restrictedToken := saResp.APIKey

	// Subtest 1: Unauthenticated request when RequireAuth=true -> must return 401
	t.Run("UnauthenticatedRequestReturns401", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/plugins", nil)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("expected 401 Unauthorized for missing token, got %d", rec.Code)
		}
	})

	// Subtest 2: Invalid Bearer token -> must return 401
	t.Run("InvalidBearerTokenReturns401", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/plugins", nil)
		req.Header.Set("Authorization", "Bearer invalid-or-forged-token-xyz")
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("expected 401 Unauthorized for forged token, got %d", rec.Code)
		}
	})

	// Subtest 3: Invalid HTTP methods (POST, PUT, DELETE) -> must return 405 Method Not Allowed
	t.Run("InvalidHTTPMethodsReturn405", func(t *testing.T) {
		methods := []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch}
		for _, m := range methods {
			req := httptest.NewRequest(m, "/api/v1/plugins", nil)
			req.Header.Set("Authorization", "Bearer "+tokenStr)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			if rec.Code != http.StatusMethodNotAllowed {
				t.Errorf("expected 405 Method Not Allowed for %s /api/v1/plugins, got %d", m, rec.Code)
			}
		}
	})

	// Subtest 4: Nil PluginRegistry on APIEnv -> must return 200 with empty list without panicking
	t.Run("NilPluginRegistryReturnsEmptyListWithoutPanic", func(t *testing.T) {
		nilEnv := &APIEnv{
			Config:         cfg,
			DB:             db,
			AuthManager:    authMgr,
			PluginRegistry: nil,
		}
		nilRouter := NewRouter(nilEnv)
		req := httptest.NewRequest(http.MethodGet, "/api/v1/plugins", nil)
		req.Header.Set("Authorization", "Bearer "+tokenStr)
		rec := httptest.NewRecorder()
		nilRouter.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK with nil registry, got %d", rec.Code)
		}
		var resp struct {
			Plugins []plugins.PluginInfo `json:"plugins"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		if len(resp.Plugins) != 0 {
			t.Errorf("expected 0 plugins for nil registry, got %d", len(resp.Plugins))
		}
	})

	// Helper function with valid admin auth
	queryAPI := func(path string) ([]plugins.PluginInfo, int) {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer "+tokenStr)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			return nil, rec.Code
		}
		var resp struct {
			Plugins []plugins.PluginInfo `json:"plugins"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		return resp.Plugins, rec.Code
	}

	// Subtest 5: Service account without plugins:read permission -> must return 403 Forbidden
	t.Run("RestrictedServiceAccountReturns403", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/plugins", nil)
		req.Header.Set("X-Service-Key", restrictedToken)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Errorf("expected 403 Forbidden for SA without plugins:read, got %d", rec.Code)
		}
	})

	// Subtest 6: Extreme query string length (20,000 characters) -> must not crash or panic
	t.Run("ExtremeQueryStringLength", func(t *testing.T) {
		bigQ := strings.Repeat("A", 20000)
		list, code := queryAPI("/api/v1/plugins?q=" + bigQ)
		if code != http.StatusOK {
			t.Fatalf("expected 200 OK for large query param, got %d", code)
		}
		if len(list) != 0 {
			t.Errorf("expected 0 matching plugins for giant junk query, got %d", len(list))
		}
	})

	// Subtest 7: SQL Injection attempt in category and q
	t.Run("SQLInjectionAttemptsInParams", func(t *testing.T) {
		list, code := queryAPI("/api/v1/plugins?category=%27%20OR%20%271%27%3D%271&q=%27%3B%20DROP%20TABLE%20plugins%3B--")
		if code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", code)
		}
		if len(list) != 0 {
			t.Errorf("expected 0 matching plugins, got %d", len(list))
		}
	})

	// Subtest 8: XSS and script payloads
	t.Run("XSSPayloadsInParams", func(t *testing.T) {
		list, code := queryAPI("/api/v1/plugins?q=%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E")
		if code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", code)
		}
		if len(list) != 0 {
			t.Errorf("expected 0 matching plugins, got %d", len(list))
		}
	})

	// Subtest 9: Regex metacharacters in query
	t.Run("RegexMetaCharactersInParams", func(t *testing.T) {
		list, code := queryAPI("/api/v1/plugins?q=.*[a-z]+(foo%7Cbar)%5C")
		if code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", code)
		}
		if len(list) != 0 {
			t.Errorf("expected 0 matching plugins, got %d", len(list))
		}
	})

	// Subtest 10: Unicode emoji and foreign alphabets
	t.Run("UnicodeEmojiAndForeignAlphabets", func(t *testing.T) {
		list, code := queryAPI("/api/v1/plugins?q=%F0%9F%9A%80&category=%E6%97%A5%E6%9C%AC%E8%AA%9E")
		if code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", code)
		}
		if len(list) != 0 {
			t.Errorf("expected 0 matching plugins, got %d", len(list))
		}
	})

	// Subtest 11: Non-existent category
	t.Run("NonExistentCategoryReturnsEmpty", func(t *testing.T) {
		list, code := queryAPI("/api/v1/plugins?category=completely_unknown_category_98765")
		if code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", code)
		}
		if len(list) != 0 {
			t.Errorf("expected 0 plugins for non-existent category, got %d", len(list))
		}
	})

	// Subtest 12: Domain fallback parameter (?domain=SysAdmin)
	t.Run("DomainParameterFallback", func(t *testing.T) {
		list, code := queryAPI("/api/v1/plugins?domain=SysAdmin")
		if code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", code)
		}
		if len(list) == 0 {
			t.Fatalf("expected at least 1 SysAdmin plugin via ?domain=, got 0")
		}
		for _, p := range list {
			if !strings.EqualFold(p.Category, "SysAdmin") {
				t.Errorf("expected SysAdmin plugin, got %s (category=%s)", p.ID, p.Category)
			}
		}
	})

	// Subtest 13: Probe invalid/unrecognized type filter in API
	t.Run("UnrecognizedTypeFilterInAPI", func(t *testing.T) {
		list, code := queryAPI("/api/v1/plugins?type=non_existent_type_foo")
		if code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", code)
		}
		// If type is invalid/unrecognized, should it return 0 plugins, or does it return all?
		// We test this empirically to expose the bug found in ListFiltered!
		t.Logf("Unrecognized type query returned %d plugins (total plugins in registry: %d)", len(list), len(reg.List()))
		if len(list) != 0 {
			t.Errorf("VULNERABILITY/BUG: invalid type filter ?type=non_existent_type_foo returned %d plugins instead of 0", len(list))
		}
	})

	// Subtest 14: PluginDeclarativeRegisterHandler response metadata completeness
	t.Run("PluginDeclarativeRegisterHandlerMetadataCompleteness", func(t *testing.T) {
		specJSON := `{
			"id": "dyn-audit-plugin",
			"name": "Dynamic Audit Plugin",
			"category": "SecOps",
			"actions": [{"name": "ping", "command": "echo"}]
		}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/plugins/declarative", strings.NewReader(specJSON))
		req.Header.Set("Authorization", "Bearer "+tokenStr)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		if rec.Code != http.StatusCreated {
			t.Fatalf("expected 201 Created, got %d: %s", rec.Code, rec.Body.String())
		}
		var registeredInfo plugins.PluginInfo
		_ = json.Unmarshal(rec.Body.Bytes(), &registeredInfo)
		t.Logf("Registered info: %+v", registeredInfo)
		if registeredInfo.Type != "declarative" {
			t.Errorf("BUG: PluginDeclarativeRegisterHandler returned empty or wrong Type: %q", registeredInfo.Type)
		}
		if registeredInfo.Category != "SecOps" {
			t.Errorf("BUG: PluginDeclarativeRegisterHandler returned empty or wrong Category: %q", registeredInfo.Category)
		}
	})

	// Subtest 15: PluginExecuteHandler RBAC and parameter validation
	t.Run("PluginExecuteRBACAndUnknownAction", func(t *testing.T) {
		// Restricted service account (only allowed "status") attempts to execute ops-quick-tools:probe-target
		execPayload, _ := json.Marshal(map[string]any{
			"plugin_id": "ops-quick-tools",
			"action":    "probe-target",
			"params":    map[string]any{"target": "127.0.0.1"},
		})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/plugins/execute", bytes.NewReader(execPayload))
		req.Header.Set("X-Service-Key", restrictedToken)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Errorf("expected 403 Forbidden for restricted service account, got %d", rec.Code)
		}

		// Admin attempts unknown plugin ID -> 404
		unknownPlugPayload, _ := json.Marshal(map[string]any{
			"plugin_id": "non-existent-plugin-id",
			"action":    "any-action",
		})
		reqUnknown := httptest.NewRequest(http.MethodPost, "/api/v1/plugins/execute", bytes.NewReader(unknownPlugPayload))
		reqUnknown.Header.Set("Authorization", "Bearer "+tokenStr)
		recUnknown := httptest.NewRecorder()
		router.ServeHTTP(recUnknown, reqUnknown)

		if recUnknown.Code != http.StatusNotFound {
			t.Errorf("expected 404 Not Found for non-existent plugin, got %d", recUnknown.Code)
		}
	})
}
