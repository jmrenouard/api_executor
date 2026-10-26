package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"

	"go-admin-tool/internal/auth"
	"go-admin-tool/internal/core"
)

func TestAuthEndpointsAndServiceAccountCommandScoping(t *testing.T) {
	cfg := core.DefaultConfig()
	cfg.Server.TLS.Enabled = false
	cfg.Auth.Enabled = true
	cfg.Auth.RequireAuth = true
	cfg.Auth.BootstrapUsername = "admin"
	cfg.Auth.BootstrapPassword = "admin-secret-password"

	cmdA := core.CommandDefinition{Name: "allowed-action", Command: "sh", Args: []string{"-c", "echo allowed"}}
	cmdB := core.CommandDefinition{Name: "forbidden-action", Command: "sh", Args: []string{"-c", "echo forbidden"}}
	if runtime.GOOS == "windows" {
		cmdA = core.CommandDefinition{Name: "allowed-action", Command: "cmd", Args: []string{"/C", "echo allowed"}}
		cmdB = core.CommandDefinition{Name: "forbidden-action", Command: "cmd", Args: []string{"/C", "echo forbidden"}}
	}
	cfg.Executor.Commands = []core.CommandDefinition{cmdA, cmdB}

	authMgr, err := auth.NewManager(cfg.Auth)
	if err != nil {
		t.Fatalf("failed to create auth manager: %v", err)
	}

	env := &APIEnv{
		Config:      cfg,
		AuthManager: authMgr,
	}
	router := NewRouter(env)

	// 1. Unauthenticated call to /api/v1/execute when RequireAuth=true must return 401
	unauthBody, _ := json.Marshal(map[string]any{"name": "allowed-action"})
	reqUnauth := httptest.NewRequest(http.MethodPost, "/api/v1/execute", bytes.NewReader(unauthBody))
	recUnauth := httptest.NewRecorder()
	router.ServeHTTP(recUnauth, reqUnauth)
	if recUnauth.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthenticated call when RequireAuth=true, got %d", recUnauth.Code)
	}

	// 2. Login via POST /api/v1/auth/login
	loginBody, _ := json.Marshal(map[string]any{"username": "admin", "password": "admin-secret-password"})
	reqLogin := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(loginBody))
	recLogin := httptest.NewRecorder()
	router.ServeHTTP(recLogin, reqLogin)
	if recLogin.Code != http.StatusOK {
		t.Fatalf("expected 200 from /api/v1/auth/login, got %d: %s", recLogin.Code, recLogin.Body.String())
	}
	var loginResp struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(recLogin.Body.Bytes(), &loginResp)
	if loginResp.Token == "" {
		t.Fatalf("expected session token from login")
	}

	// 3. Create third-party service account scoped only to "allowed-action"
	saBody, _ := json.Marshal(map[string]any{
		"name":            "prometheus-exporter-sa",
		"service_name":    "monitoring-agent",
		"allowed_actions": []string{"allowed-action"},
	})
	reqSA := httptest.NewRequest(http.MethodPost, "/api/v1/auth/service-accounts", bytes.NewReader(saBody))
	reqSA.Header.Set("Authorization", "Bearer "+loginResp.Token)
	recSA := httptest.NewRecorder()
	router.ServeHTTP(recSA, reqSA)
	if recSA.Code != http.StatusCreated {
		t.Fatalf("expected 201 from /api/v1/auth/service-accounts, got %d: %s", recSA.Code, recSA.Body.String())
	}
	var saResp struct {
		ServiceAccount auth.ServiceAccount `json:"service_account"`
		APIKey         string              `json:"api_key"`
	}
	_ = json.Unmarshal(recSA.Body.Bytes(), &saResp)

	// 4. Service account executes allowed-action -> 200 OK
	reqExecAllowed := httptest.NewRequest(http.MethodPost, "/api/v1/execute", bytes.NewReader(unauthBody))
	reqExecAllowed.Header.Set("X-Service-Key", saResp.APIKey)
	recExecAllowed := httptest.NewRecorder()
	router.ServeHTTP(recExecAllowed, reqExecAllowed)
	if recExecAllowed.Code != http.StatusOK {
		t.Fatalf("expected 200 when service account executes allowed-action, got %d: %s", recExecAllowed.Code, recExecAllowed.Body.String())
	}

	// 5. Service account attempts forbidden-action -> 403 Forbidden
	forbidBody, _ := json.Marshal(map[string]any{"name": "forbidden-action"})
	reqExecForbid := httptest.NewRequest(http.MethodPost, "/api/v1/execute", bytes.NewReader(forbidBody))
	reqExecForbid.Header.Set("X-Service-Key", saResp.APIKey)
	recExecForbid := httptest.NewRecorder()
	router.ServeHTTP(recExecForbid, reqExecForbid)
	if recExecForbid.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when service account executes forbidden-action, got %d: %s", recExecForbid.Code, recExecForbid.Body.String())
	}

	// 6. Unauthenticated rotation attempt on /api/v1/auth/service-accounts/rotate -> 401
	rotateBody, _ := json.Marshal(map[string]any{"id": saResp.ServiceAccount.ID})
	reqRotateUnauth := httptest.NewRequest(http.MethodPost, "/api/v1/auth/service-accounts/rotate", bytes.NewReader(rotateBody))
	recRotateUnauth := httptest.NewRecorder()
	router.ServeHTTP(recRotateUnauth, reqRotateUnauth)
	if recRotateUnauth.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthenticated service account rotation, got %d", recRotateUnauth.Code)
	}

	// 7. Create a non-admin operator user and verify they cannot create users or rotate service accounts (403)
	createOpBody, _ := json.Marshal(map[string]any{
		"username": "operator1",
		"password": "operator-pass-123",
		"role":     "operator",
	})
	reqCreateOp := httptest.NewRequest(http.MethodPost, "/api/v1/auth/users", bytes.NewReader(createOpBody))
	reqCreateOp.Header.Set("Authorization", "Bearer "+loginResp.Token)
	recCreateOp := httptest.NewRecorder()
	router.ServeHTTP(recCreateOp, reqCreateOp)
	if recCreateOp.Code != http.StatusCreated {
		t.Fatalf("expected 201 creating operator user, got %d: %s", recCreateOp.Code, recCreateOp.Body.String())
	}

	// Issue a PAT for operator1 via /api/v1/auth/tokens
	patBody, _ := json.Marshal(map[string]any{
		"user_id": "operator1",
		"name":    "op-pat",
		"ttl":     "1h",
	})
	reqCreatePAT := httptest.NewRequest(http.MethodPost, "/api/v1/auth/tokens", bytes.NewReader(patBody))
	reqCreatePAT.Header.Set("Authorization", "Bearer "+loginResp.Token)
	recCreatePAT := httptest.NewRecorder()
	router.ServeHTTP(recCreatePAT, reqCreatePAT)
	if recCreatePAT.Code != http.StatusCreated {
		t.Fatalf("expected 201 creating PAT, got %d: %s", recCreatePAT.Code, recCreatePAT.Body.String())
	}
	var patResp struct {
		TokenInfo auth.APIToken `json:"token_info"`
		Token     string        `json:"token"`
	}
	_ = json.Unmarshal(recCreatePAT.Body.Bytes(), &patResp)

	// Operator tries to create a user -> 403 Forbidden
	reqOpCreateUser := httptest.NewRequest(http.MethodPost, "/api/v1/auth/users", bytes.NewReader(createOpBody))
	reqOpCreateUser.Header.Set("X-API-Token", patResp.Token)
	recOpCreateUser := httptest.NewRecorder()
	router.ServeHTTP(recOpCreateUser, reqOpCreateUser)
	if recOpCreateUser.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when operator tries to create user, got %d", recOpCreateUser.Code)
	}

	// Operator tries to rotate service account key -> 403 Forbidden
	reqOpRotate := httptest.NewRequest(http.MethodPost, "/api/v1/auth/service-accounts/rotate", bytes.NewReader(rotateBody))
	reqOpRotate.Header.Set("X-API-Token", patResp.Token)
	recOpRotate := httptest.NewRecorder()
	router.ServeHTTP(recOpRotate, reqOpRotate)
	if recOpRotate.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when operator tries to rotate service account key, got %d", recOpRotate.Code)
	}

	// Admin rotates service account key -> 200 OK
	reqAdminRotate := httptest.NewRequest(http.MethodPost, "/api/v1/auth/service-accounts/rotate", bytes.NewReader(rotateBody))
	reqAdminRotate.Header.Set("Authorization", "Bearer "+loginResp.Token)
	recAdminRotate := httptest.NewRecorder()
	router.ServeHTTP(recAdminRotate, reqAdminRotate)
	if recAdminRotate.Code != http.StatusOK {
		t.Fatalf("expected 200 when admin rotates service account key, got %d: %s", recAdminRotate.Code, recAdminRotate.Body.String())
	}

	// Verify /api/v1/auth/me returns operator principal
	reqMe := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	reqMe.Header.Set("X-API-Token", patResp.Token)
	recMe := httptest.NewRecorder()
	router.ServeHTTP(recMe, reqMe)
	if recMe.Code != http.StatusOK {
		t.Fatalf("expected 200 from /api/v1/auth/me, got %d", recMe.Code)
	}

	// Revoke PAT via DELETE /api/v1/auth/tokens
	reqDelPAT := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/tokens?id="+patResp.TokenInfo.ID, nil)
	reqDelPAT.Header.Set("Authorization", "Bearer "+loginResp.Token)
	recDelPAT := httptest.NewRecorder()
	router.ServeHTTP(recDelPAT, reqDelPAT)
	if recDelPAT.Code != http.StatusOK {
		t.Fatalf("expected 200 revoking PAT, got %d", recDelPAT.Code)
	}
}

