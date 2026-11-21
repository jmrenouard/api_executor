package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"go-admin-tool/internal/approval"
	"go-admin-tool/internal/audit"
	"go-admin-tool/internal/auth"
	"go-admin-tool/internal/core"
)

func newApprovalTestEnv(t *testing.T, requireAuth bool) (*APIEnv, http.Handler, map[string]string) {
	t.Helper()
	cfg := core.DefaultConfig()
	cfg.Auth.Enabled = true
	cfg.Auth.RequireAuth = requireAuth
	cfg.Approval = core.ApprovalConfig{
		Enabled:                 true,
		DefaultTTL:              "10m",
		MaxPending:              50,
		RequireDistinctApprover: true,
		CriticalCommands:        []string{"restart-*"},
	}

	authMgr, err := auth.NewManager(cfg.Auth)
	if err != nil {
		t.Fatalf("auth.NewManager failed: %v", err)
	}
	auditLogger, err := audit.NewAuditLogger(core.AuditConfig{Enabled: true, MaxMemoryLog: 500}, nil, nil)
	if err != nil {
		t.Fatalf("audit.NewAuditLogger failed: %v", err)
	}
	t.Cleanup(func() { _ = auditLogger.Close() })

	approvalStore, err := approval.NewStore(cfg.Approval, nil, auditLogger)
	if err != nil {
		t.Fatalf("approval.NewStore failed: %v", err)
	}

	// Provision distinct users and credentials
	_, adminTok, err := authMgr.CreateToken("admin", "admin-tok", nil, 0)
	if err != nil {
		t.Fatalf("CreateToken admin failed: %v", err)
	}
	admin2, err := authMgr.CreateUser("admin2", "secret123", "Second Admin", "admin2@local", auth.RoleAdmin)
	if err != nil {
		t.Fatalf("CreateUser admin2 failed: %v", err)
	}
	_, admin2Tok, err := authMgr.CreateToken(admin2.ID, "admin2-tok", nil, 0)
	if err != nil {
		t.Fatalf("CreateToken admin2 failed: %v", err)
	}
	opUser, err := authMgr.CreateUser("op1", "secret123", "Operator", "op1@local", auth.RoleOperator)
	if err != nil {
		t.Fatalf("CreateUser op1 failed: %v", err)
	}
	_, opTok, err := authMgr.CreateToken(opUser.ID, "op-tok", nil, 0)
	if err != nil {
		t.Fatalf("CreateToken op1 failed: %v", err)
	}
	viewUser, err := authMgr.CreateUser("viewer1", "secret123", "Viewer", "viewer1@local", auth.RoleViewer)
	if err != nil {
		t.Fatalf("CreateUser viewer1 failed: %v", err)
	}
	_, viewerTok, err := authMgr.CreateToken(viewUser.ID, "viewer-tok", nil, 0)
	if err != nil {
		t.Fatalf("CreateToken viewer1 failed: %v", err)
	}
	_, svcKey, err := authMgr.CreateServiceAccount("svc1", "CI Bot", "bot", nil, []string{"*"}, 0)
	if err != nil {
		t.Fatalf("CreateServiceAccount failed: %v", err)
	}

	env := &APIEnv{
		Config:        cfg,
		AuthManager:   authMgr,
		AuditLogger:   auditLogger,
		ApprovalStore: approvalStore,
	}
	tokens := map[string]string{
		"admin":    adminTok,
		"admin2":   admin2Tok,
		"operator": opTok,
		"viewer":   viewerTok,
		"service":  svcKey,
	}
	return env, NewRouter(env), tokens
}

func TestApprovalEndpoints_RBACSelfApprovalAndAuditIntegrity(t *testing.T) {
	env, router, tokens := newApprovalTestEnv(t, true)

	// Create two pending approvals (one requested by admin, one by op1)
	reqByAdmin, err := env.ApprovalStore.Create(approval.CreateParams{
		Target:        approval.Target{Channel: approval.ChannelCommand, Action: "restart-postgres"},
		RequesterID:   "admin",
		RequesterType: "user_token",
		Reason:        "upgrade",
	})
	if err != nil {
		t.Fatalf("Create reqByAdmin failed: %v", err)
	}
	reqByOp, err := env.ApprovalStore.Create(approval.CreateParams{
		Target:        approval.Target{Channel: approval.ChannelPlugin, PluginID: "db-admin", Action: "failover"},
		RequesterID:   "op1",
		RequesterType: "user_token",
	})
	if err != nil {
		t.Fatalf("Create reqByOp failed: %v", err)
	}

	// 1. Unauthenticated callers receive 401 when RequireAuth=true
	for _, ep := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/approvals"},
		{http.MethodGet, "/api/v1/approvals/" + reqByAdmin.ID},
		{http.MethodPost, "/api/v1/approvals/" + reqByAdmin.ID + "/approve"},
		{http.MethodPost, "/api/v1/approvals/" + reqByAdmin.ID + "/reject"},
	} {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(ep.method, ep.path, nil)
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("unauthenticated %s %s = %d, want 401", ep.method, ep.path, rr.Code)
		}
	}

	// 2. viewer, operator, and service_account receive 403 on approve/reject
	for _, roleName := range []string{"viewer", "operator", "service"} {
		for _, suffix := range []string{"/approve", "/reject"} {
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/"+reqByOp.ID+suffix, bytes.NewBufferString(`{"comment":"try"}`))
			req.Header.Set("Authorization", "Bearer "+tokens[roleName])
			router.ServeHTTP(rr, req)
			if rr.Code != http.StatusForbidden {
				t.Errorf("role=%s POST %s = %d, want 403", roleName, suffix, rr.Code)
			}
		}
	}

	// 3. Self-approval by admin on own request is rejected with 403 Forbidden
	{
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/"+reqByAdmin.ID+"/approve", bytes.NewBufferString(`{"comment":"self"}`))
		req.Header.Set("Authorization", "Bearer "+tokens["admin"])
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("self-approval status = %d, want 403 (body=%s)", rr.Code, rr.Body.String())
		}
	}

	// 4. Distinct admin2 approves reqByAdmin with 200 OK
	{
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/"+reqByAdmin.ID+"/approve", bytes.NewBufferString(`{"comment":"approved by admin2"}`))
		req.Header.Set("Authorization", "Bearer "+tokens["admin2"])
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("admin2 approve status = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
		}
		var out approval.Request
		if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode approve response: %v", err)
		}
		if out.Status != approval.StatusApproved || out.ApproverID != "admin2" {
			t.Fatalf("unexpected approve response: %+v", out)
		}
	}

	// 5. Re-approving an already approved request returns 409 Conflict
	{
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/"+reqByAdmin.ID+"/approve", nil)
		req.Header.Set("Authorization", "Bearer "+tokens["admin2"])
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusConflict {
			t.Fatalf("duplicate approve status = %d, want 409", rr.Code)
		}
	}

	// 6. Admin rejects reqByOp with 200 OK
	{
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/"+reqByOp.ID+"/reject", bytes.NewBufferString(`{"reason":"not in maintenance window"}`))
		req.Header.Set("Authorization", "Bearer "+tokens["admin"])
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("admin reject status = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
		}
	}

	// 7. Admin lists and gets approvals
	{
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/approvals?status=approved", nil)
		req.Header.Set("Authorization", "Bearer "+tokens["admin"])
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("GET /api/v1/approvals status = %d, want 200", rr.Code)
		}
		var listResp ApprovalListResponse
		if err := json.Unmarshal(rr.Body.Bytes(), &listResp); err != nil {
			t.Fatalf("decode list response: %v", err)
		}
		if listResp.Total != 1 || len(listResp.Approvals) != 1 || listResp.Approvals[0].ID != reqByAdmin.ID {
			t.Fatalf("unexpected list response: %+v", listResp)
		}
	}

	// 8. GET /api/v1/config exposes SanitizedApprovalConfig
	{
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("GET /api/v1/config status = %d, want 200", rr.Code)
		}
		var view core.SanitizedConfigView
		if err := json.Unmarshal(rr.Body.Bytes(), &view); err != nil {
			t.Fatalf("decode config view: %v", err)
		}
		if !view.Approval.Enabled || !view.Approval.RequireDistinctApprover || view.Approval.MaxPending != 50 {
			t.Fatalf("unexpected approval config view: %+v", view.Approval)
		}
	}

	// 9. GET /api/v1/audit/verify confirms SHA-256 audit chain integrity
	{
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/verify", nil)
		req.Header.Set("Authorization", "Bearer "+tokens["admin"])
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("GET /api/v1/audit/verify status = %d, want 200", rr.Code)
		}
		var ver audit.ChainVerificationResult
		if err := json.Unmarshal(rr.Body.Bytes(), &ver); err != nil {
			t.Fatalf("decode audit verify: %v", err)
		}
		if !ver.Valid {
			t.Fatalf("expected valid audit chain, got %+v", ver)
		}
	}
}

func TestApprovalEndpoints_AnonymousForbiddenWhenRequireAuthFalse(t *testing.T) {
	env, router, _ := newApprovalTestEnv(t, false)
	reqItem, err := env.ApprovalStore.Create(approval.CreateParams{
		Target:        approval.Target{Channel: approval.ChannelCommand, Action: "restart-db"},
		RequesterID:   "op1",
		RequesterType: "user_token",
	})
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	for _, ep := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/approvals"},
		{http.MethodGet, "/api/v1/approvals/" + reqItem.ID},
		{http.MethodPost, "/api/v1/approvals/" + reqItem.ID + "/approve"},
		{http.MethodPost, "/api/v1/approvals/" + reqItem.ID + "/reject"},
	} {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(ep.method, ep.path, nil)
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Errorf("anonymous (RequireAuth=false) %s %s = %d, want 403", ep.method, ep.path, rr.Code)
		}
	}
}

func TestNormalizeMetricPath_ApprovalRoutes(t *testing.T) {
	cases := map[string]string{
		"/api/v1/approvals":                    "/api/v1/approvals",
		"/api/v1/approvals/":                   "/api/v1/approvals",
		"/api/v1/approvals/apr_0123456789abcd": "/api/v1/approvals/:id",
		"/api/v1/approvals/apr_abc/approve":    "/api/v1/approvals/:id/approve",
		"/api/v1/approvals/apr_abc/reject":     "/api/v1/approvals/:id/reject",
		"/api/v1/approvals/apr_abc/unknown":    "other",
		"/api/v1/approvals/apr_abc/a/b":        "other",
	}
	for input, want := range cases {
		if got := normalizeMetricPath(input); got != want {
			t.Errorf("normalizeMetricPath(%q) = %q, want %q", input, got, want)
		}
	}
}
