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

func TestAuthTokensPrivilegeEscalationPrevention(t *testing.T) {
	cfg := core.DefaultConfig()
	cfg.Server.TLS.Enabled = false
	cfg.Auth.Enabled = true
	cfg.Auth.RequireAuth = true
	cfg.Auth.BootstrapUsername = "admin"
	cfg.Auth.BootstrapPassword = "admin-secret-password"

	authMgr, err := auth.NewManager(cfg.Auth)
	if err != nil {
		t.Fatalf("failed to create auth manager: %v", err)
	}
	env := &APIEnv{Config: cfg, AuthManager: authMgr}
	router := NewRouter(env)

	_, adminTokInfo, adminTok, err := authMgr.AuthenticateUser("admin", "admin-secret-password")
	if err != nil {
		t.Fatalf("admin login failed: %v", err)
	}
	_, _ = authMgr.CreateUser("operator1", "operator-pass-123", "Operator", "", auth.RoleOperator)
	_, _, opTok, err := authMgr.AuthenticateUser("operator1", "operator-pass-123")
	if err != nil {
		t.Fatalf("operator login failed: %v", err)
	}
	_, _ = authMgr.CreateUser("viewer1", "viewer-pass-123", "Viewer", "", auth.RoleViewer)
	_, _, viewerTok, err := authMgr.AuthenticateUser("viewer1", "viewer-pass-123")
	if err != nil {
		t.Fatalf("viewer login failed: %v", err)
	}
	_, saKey, err := authMgr.CreateServiceAccount("ci-probe", "CI", "probe", nil, []string{"disk-usage"}, 0)
	if err != nil {
		t.Fatalf("create SA failed: %v", err)
	}

	// 1. Operator attempting to mint a token for "admin" must be rejected with 403 Forbidden
	escBody, _ := json.Marshal(map[string]any{"user_id": "admin", "name": "escalated-admin-pat"})
	reqOpEsc := httptest.NewRequest(http.MethodPost, "/api/v1/auth/tokens", bytes.NewReader(escBody))
	reqOpEsc.Header.Set("X-API-Token", opTok)
	recOpEsc := httptest.NewRecorder()
	router.ServeHTTP(recOpEsc, reqOpEsc)
	if recOpEsc.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when operator tries to mint token for admin, got %d: %s", recOpEsc.Code, recOpEsc.Body.String())
	}

	// 2. Service account attempting to mint a PAT must be rejected with 403 Forbidden
	reqSAEsc := httptest.NewRequest(http.MethodPost, "/api/v1/auth/tokens", bytes.NewReader(escBody))
	reqSAEsc.Header.Set("X-Service-Key", saKey)
	recSAEsc := httptest.NewRecorder()
	router.ServeHTTP(recSAEsc, reqSAEsc)
	if recSAEsc.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when service account tries to mint a PAT, got %d: %s", recSAEsc.Code, recSAEsc.Body.String())
	}

	// 3. Viewer attempting to mint a PAT for admin must be rejected with 403 Forbidden
	reqViewerEsc := httptest.NewRequest(http.MethodPost, "/api/v1/auth/tokens", bytes.NewReader(escBody))
	reqViewerEsc.Header.Set("X-API-Token", viewerTok)
	recViewerEsc := httptest.NewRecorder()
	router.ServeHTTP(recViewerEsc, reqViewerEsc)
	if recViewerEsc.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when viewer tries to mint a PAT for admin, got %d: %s", recViewerEsc.Code, recViewerEsc.Body.String())
	}

	// 4. Operator attempting to revoke admin's session token must be rejected with 403 Forbidden
	reqOpRevokeAdmin := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/tokens?id="+adminTokInfo.ID, nil)
	reqOpRevokeAdmin.Header.Set("X-API-Token", opTok)
	recOpRevokeAdmin := httptest.NewRecorder()
	router.ServeHTTP(recOpRevokeAdmin, reqOpRevokeAdmin)
	if recOpRevokeAdmin.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when operator tries to revoke admin token, got %d: %s", recOpRevokeAdmin.Code, recOpRevokeAdmin.Body.String())
	}

	// 5. Operator minting a PAT for themselves ("operator1") without admin scopes succeeds (201)
	selfBody, _ := json.Marshal(map[string]any{"user_id": "operator1", "name": "op-self-pat"})
	reqOpSelf := httptest.NewRequest(http.MethodPost, "/api/v1/auth/tokens", bytes.NewReader(selfBody))
	reqOpSelf.Header.Set("X-API-Token", opTok)
	recOpSelf := httptest.NewRecorder()
	router.ServeHTTP(recOpSelf, reqOpSelf)
	if recOpSelf.Code != http.StatusCreated {
		t.Fatalf("expected 201 when operator mints token for self, got %d: %s", recOpSelf.Code, recOpSelf.Body.String())
	}

	// 6. Operator attempting to self-assign wildcard "*" admin scope must be rejected with 403 Forbidden
	wildcardBody, _ := json.Marshal(map[string]any{"user_id": "operator1", "name": "op-wildcard", "scopes": []string{"*"}})
	reqOpWildcard := httptest.NewRequest(http.MethodPost, "/api/v1/auth/tokens", bytes.NewReader(wildcardBody))
	reqOpWildcard.Header.Set("X-API-Token", opTok)
	recOpWildcard := httptest.NewRecorder()
	router.ServeHTTP(recOpWildcard, reqOpWildcard)
	if recOpWildcard.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when operator tries to self-assign '*' scope, got %d: %s", recOpWildcard.Code, recOpWildcard.Body.String())
	}

	// 7. Admin user lifecycle operations: GET /api/v1/auth/users, PATCH user, DELETE user, GET/POST/DELETE tokens & service accounts
	reqGetUsers := httptest.NewRequest(http.MethodGet, "/api/v1/auth/users", nil)
	reqGetUsers.Header.Set("X-API-Token", adminTok)
	recGetUsers := httptest.NewRecorder()
	router.ServeHTTP(recGetUsers, reqGetUsers)
	if recGetUsers.Code != http.StatusOK {
		t.Errorf("expected 200 from GET /api/v1/auth/users, got %d", recGetUsers.Code)
	}

	// Create temporary user, PATCH it, then DELETE it
	createTmpBody, _ := json.Marshal(map[string]any{"username": "tempuser", "password": "temppass123", "role": "viewer"})
	reqCreateTmp := httptest.NewRequest(http.MethodPost, "/api/v1/auth/users", bytes.NewReader(createTmpBody))
	reqCreateTmp.Header.Set("X-API-Token", adminTok)
	recCreateTmp := httptest.NewRecorder()
	router.ServeHTTP(recCreateTmp, reqCreateTmp)
	var createdUser auth.User
	_ = json.Unmarshal(recCreateTmp.Body.Bytes(), &createdUser)

	patchBody, _ := json.Marshal(map[string]any{"id": createdUser.ID, "role": "operator"})
	reqPatch := httptest.NewRequest(http.MethodPatch, "/api/v1/auth/users", bytes.NewReader(patchBody))
	reqPatch.Header.Set("X-API-Token", adminTok)
	recPatch := httptest.NewRecorder()
	router.ServeHTTP(recPatch, reqPatch)
	if recPatch.Code != http.StatusOK {
		t.Errorf("expected 200 from PATCH /api/v1/auth/users, got %d: %s", recPatch.Code, recPatch.Body.String())
	}

	reqDelUser := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/users?id="+createdUser.ID, nil)
	reqDelUser.Header.Set("X-API-Token", adminTok)
	recDelUser := httptest.NewRecorder()
	router.ServeHTTP(recDelUser, reqDelUser)
	if recDelUser.Code != http.StatusOK {
		t.Errorf("expected 200 from DELETE /api/v1/auth/users, got %d", recDelUser.Code)
	}

	// GET /api/v1/auth/tokens, POST with TTL and invalid TTL, DELETE token
	reqGetTokens := httptest.NewRequest(http.MethodGet, "/api/v1/auth/tokens", nil)
	reqGetTokens.Header.Set("X-API-Token", adminTok)
	recGetTokens := httptest.NewRecorder()
	router.ServeHTTP(recGetTokens, reqGetTokens)
	if recGetTokens.Code != http.StatusOK {
		t.Errorf("expected 200 from GET /api/v1/auth/tokens, got %d", recGetTokens.Code)
	}

	badTTLTok, _ := json.Marshal(map[string]any{"name": "bad-ttl", "ttl": "invalid"})
	reqBadTTL := httptest.NewRequest(http.MethodPost, "/api/v1/auth/tokens", bytes.NewReader(badTTLTok))
	reqBadTTL.Header.Set("X-API-Token", adminTok)
	recBadTTL := httptest.NewRecorder()
	router.ServeHTTP(recBadTTL, reqBadTTL)
	if recBadTTL.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid token TTL, got %d", recBadTTL.Code)
	}

	// GET & DELETE /api/v1/auth/service-accounts
	reqGetSA := httptest.NewRequest(http.MethodGet, "/api/v1/auth/service-accounts", nil)
	reqGetSA.Header.Set("X-API-Token", adminTok)
	recGetSA := httptest.NewRecorder()
	router.ServeHTTP(recGetSA, reqGetSA)
	if recGetSA.Code != http.StatusOK {
		t.Errorf("expected 200 from GET /api/v1/auth/service-accounts, got %d", recGetSA.Code)
	}

	badTTLSA, _ := json.Marshal(map[string]any{"name": "bad-sa", "ttl": "invalid"})
	reqBadSATTL := httptest.NewRequest(http.MethodPost, "/api/v1/auth/service-accounts", bytes.NewReader(badTTLSA))
	reqBadSATTL.Header.Set("X-API-Token", adminTok)
	recBadSATTL := httptest.NewRecorder()
	router.ServeHTTP(recBadSATTL, reqBadSATTL)
	if recBadSATTL.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid service account TTL, got %d", recBadSATTL.Code)
	}

	// MethodNotAllowed (405) and nil AuthManager (503) checks
	nilAuthRouter := NewRouter(&APIEnv{Config: cfg})
	for _, tc := range []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/api/v1/auth/login"},
		{http.MethodGet, "/api/v1/auth/users"},
		{http.MethodGet, "/api/v1/auth/tokens"},
		{http.MethodGet, "/api/v1/auth/service-accounts"},
		{http.MethodPost, "/api/v1/auth/service-accounts/rotate"},
	} {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		rec := httptest.NewRecorder()
		nilAuthRouter.ServeHTTP(rec, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("expected 503 for %s %s when AuthManager is nil, got %d", tc.method, tc.path, rec.Code)
		}
	}

	for _, tc := range []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/auth/login"},
		{http.MethodOptions, "/api/v1/auth/users"},
		{http.MethodPut, "/api/v1/auth/tokens"},
		{http.MethodPut, "/api/v1/auth/service-accounts"},
		{http.MethodGet, "/api/v1/auth/service-accounts/rotate"},
	} {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		req.Header.Set("X-API-Token", adminTok)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("expected 405 for %s %s, got %d", tc.method, tc.path, rec.Code)
		}
	}
}



