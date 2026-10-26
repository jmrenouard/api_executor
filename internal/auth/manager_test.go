package auth

import (
	"errors"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go-admin-tool/internal/core"
)

func TestUserLifecycleAndTokenAuthentication(t *testing.T) {
	tmpDir := t.TempDir()
	mgr, err := NewManager(core.AuthConfig{
		Enabled:           true,
		RequireAuth:       true,
		BootstrapUsername: "admin",
		BootstrapPassword: "strong-admin-password",
		BootstrapToken:    "gat_pat_bootstrap_test_token_12345",
		StorePath:         filepath.Join(tmpDir, "auth_store.json"),
	})
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	// Verify bootstrap token works immediately
	pBoot, err := mgr.AuthenticateCredential("gat_pat_bootstrap_test_token_12345")
	if err != nil {
		t.Fatalf("expected bootstrap token to authenticate, got %v", err)
	}
	if pBoot.Role != RoleAdmin {
		t.Errorf("expected RoleAdmin for bootstrap token, got %q", pBoot.Role)
	}

	// Create operator user
	opUser, err := mgr.CreateUser("alice", "alice-secret-123", "Alice Operator", "alice@example.com", RoleOperator)
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}
	if opUser.PasswordHash != "" {
		t.Errorf("expected PasswordHash to be stripped in PublicUser")
	}

	// Duplicate username rejected
	if _, err := mgr.CreateUser("ALICE", "another-pass", "", "", RoleViewer); !errors.Is(err, ErrUserAlreadyExists) {
		t.Errorf("expected ErrUserAlreadyExists, got %v", err)
	}

	// Login with valid credentials
	loggedInUser, sessionTok, rawSessionTok, err := mgr.AuthenticateUser("alice", "alice-secret-123")
	if err != nil {
		t.Fatalf("AuthenticateUser failed: %v", err)
	}
	if loggedInUser.Username != "alice" || !strings.HasPrefix(rawSessionTok, "gat_pat_") || sessionTok.ID == "" {
		t.Errorf("unexpected login output: user=%+v tok=%+v raw=%q", loggedInUser, sessionTok, rawSessionTok)
	}

	// Login with wrong password fails
	if _, _, _, err := mgr.AuthenticateUser("alice", "wrong-password"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("expected ErrInvalidCredentials, got %v", err)
	}

	// Create scoped PAT for remote calls
	patMeta, rawPAT, err := mgr.CreateToken(opUser.ID, "ansible-remote-cli", []string{"commands:execute", "commands:read"}, time.Hour)
	if err != nil {
		t.Fatalf("CreateToken failed: %v", err)
	}

	principal, err := mgr.AuthenticateCredential(rawPAT)
	if err != nil {
		t.Fatalf("AuthenticateCredential for PAT failed: %v", err)
	}
	if err := Authorize(principal, "commands:execute", "list-processes"); err != nil {
		t.Errorf("expected commands:execute to be authorized: %v", err)
	}
	if err := Authorize(principal, "admin:users", ""); !errors.Is(err, ErrForbiddenScope) {
		t.Errorf("expected ErrForbiddenScope for admin:users on operator token, got %v", err)
	}

	// Revoke token and verify rejection
	if err := mgr.RevokeToken(patMeta.ID); err != nil {
		t.Fatalf("RevokeToken failed: %v", err)
	}
	if _, err := mgr.AuthenticateCredential(rawPAT); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("expected revoked token to be rejected with ErrInvalidToken, got %v", err)
	}
}

func TestThirdPartyServiceAccountScopingAndRotation(t *testing.T) {
	mgr, err := NewManager(core.AuthConfig{Enabled: true})
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	sa, rawKey, err := mgr.CreateServiceAccount(
		"prometheus-probe",
		"Prometheus Monitoring Service",
		"Third-party monitoring probe restricted to disk-usage and ubuntu-* tasks",
		[]string{"commands:execute", "commands:read"},
		[]string{"disk-usage", "ubuntu-*"},
		2*time.Hour,
	)
	if err != nil {
		t.Fatalf("CreateServiceAccount failed: %v", err)
	}
	if !strings.HasPrefix(rawKey, "gat_svc_") {
		t.Errorf("expected service account key prefix gat_svc_, got %q", rawKey)
	}

	p, err := mgr.AuthenticateCredential(rawKey)
	if err != nil {
		t.Fatalf("AuthenticateCredential for service account failed: %v", err)
	}
	if p.Type != "service_account" || p.ServiceName != "Prometheus Monitoring Service" {
		t.Errorf("unexpected principal: %+v", p)
	}

	// Permitted action exact match
	if err := Authorize(p, "commands:execute", "disk-usage"); err != nil {
		t.Errorf("expected disk-usage to be allowed for service account: %v", err)
	}
	// Permitted action wildcard match
	if err := Authorize(p, "commands:execute", "ubuntu-os-release"); err != nil {
		t.Errorf("expected ubuntu-os-release to be allowed via ubuntu-* wildcard: %v", err)
	}
	// Disallowed action rejected
	if err := Authorize(p, "commands:execute", "redhat-rpm-qa"); !errors.Is(err, ErrForbiddenAction) {
		t.Errorf("expected ErrForbiddenAction for redhat-rpm-qa, got %v", err)
	}

	// Rotate key: old key must stop working, new key must work
	_, newRawKey, err := mgr.RotateServiceAccountKey(sa.ID)
	if err != nil {
		t.Fatalf("RotateServiceAccountKey failed: %v", err)
	}
	if _, err := mgr.AuthenticateCredential(rawKey); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("expected old service account key to be invalid after rotation, got %v", err)
	}
	if _, err := mgr.AuthenticateCredential(newRawKey); err != nil {
		t.Errorf("expected new service account key to authenticate after rotation, got %v", err)
	}

	// Delete service account and verify rejection
	if len(mgr.ListServiceAccounts()) != 1 {
		t.Errorf("expected 1 service account before delete")
	}
	if err := mgr.DeleteServiceAccount(sa.ID); err != nil {
		t.Fatalf("DeleteServiceAccount failed: %v", err)
	}
	if _, err := mgr.AuthenticateCredential(newRawKey); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("expected deleted service account key to be invalid, got %v", err)
	}
}

func TestEdgeCasesEmptyInputsDisabledUserAndPersistence(t *testing.T) {
	storePath := filepath.Join(t.TempDir(), "auth_store.json")
	mgr, err := NewManager(core.AuthConfig{
		Enabled:   true,
		StorePath: storePath,
	})
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	// Empty username and short password rejected
	if _, err := mgr.CreateUser("   ", "validpass123", "", "", RoleViewer); err == nil {
		t.Errorf("expected error for empty username")
	}
	if _, err := mgr.CreateUser("bob", "short", "", "", RoleViewer); err == nil {
		t.Errorf("expected error for password shorter than 6 characters")
	}
	if _, err := mgr.AuthenticateCredential("   "); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("expected ErrInvalidToken for empty credential, got %v", err)
	}

	// Create and disable user
	bob, err := mgr.CreateUser("bob", "bob-pass-123", "Bob Viewer", "bob@example.com", RoleViewer)
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}
	_, bobPAT, err := mgr.CreateToken(bob.ID, "bob-pat", nil, 5*time.Millisecond)
	if err != nil {
		t.Fatalf("CreateToken failed: %v", err)
	}
	time.Sleep(15 * time.Millisecond)
	if _, err := mgr.AuthenticateCredential(bobPAT); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("expected ErrInvalidToken for expired PAT, got %v", err)
	}

	inactive := false
	updatedBob, err := mgr.UpdateUser(bob.ID, &inactive, RoleOperator)
	if err != nil || updatedBob.Active || updatedBob.Role != RoleOperator {
		t.Fatalf("UpdateUser failed: user=%+v err=%v", updatedBob, err)
	}
	if _, _, _, err := mgr.AuthenticateUser("bob", "bob-pass-123"); !errors.Is(err, ErrAccountDisabled) {
		t.Errorf("expected ErrAccountDisabled when logging into disabled account, got %v", err)
	}

	// Reload from persisted JSON store
	mgrReloaded, err := NewManager(core.AuthConfig{
		Enabled:   true,
		StorePath: storePath,
	})
	if err != nil {
		t.Fatalf("NewManager reload failed: %v", err)
	}
	if len(mgrReloaded.ListUsers()) < 2 {
		t.Errorf("expected persisted users to reload from %s", storePath)
	}
	if len(mgrReloaded.ListTokens()) == 0 {
		t.Errorf("expected ListTokens() to return persisted tokens")
	}
	if err := mgrReloaded.DeleteUser(bob.ID); err != nil {
		t.Errorf("DeleteUser failed: %v", err)
	}
	if err := mgrReloaded.DeleteUser("non-existent"); !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound deleting unknown user, got %v", err)
	}
	if _, err := mgrReloaded.UpdateUser("non-existent", nil, RoleViewer); !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound updating unknown user, got %v", err)
	}
	if err := mgrReloaded.RevokeToken("non-existent"); !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound revoking unknown token, got %v", err)
	}
	if err := mgrReloaded.DeleteServiceAccount("non-existent"); !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound deleting unknown service account, got %v", err)
	}
	if _, _, err := mgrReloaded.RotateServiceAccountKey("non-existent"); !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound rotating unknown service account, got %v", err)
	}
	if _, _, err := mgrReloaded.CreateServiceAccount("   ", "", "", nil, nil, 0); err == nil {
		t.Errorf("expected error creating service account with empty name")
	}

	// Test default scopes/actions on CreateServiceAccount and expired service account key
	_, expSAKey, err := mgrReloaded.CreateServiceAccount("exp-sa", "", "desc", nil, nil, 5*time.Millisecond)
	if err != nil {
		t.Fatalf("CreateServiceAccount exp-sa failed: %v", err)
	}
	time.Sleep(15 * time.Millisecond)
	if _, err := mgrReloaded.AuthenticateCredential(expSAKey); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("expected ErrInvalidToken for expired service account key, got %v", err)
	}

	// Test Authorize with nil principal and prefix wildcard scopes (e.g. commands:*)
	if err := Authorize(nil, "commands:read", ""); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("expected ErrInvalidToken on nil Principal, got %v", err)
	}
	wildcardPrincipal := &Principal{
		Type:   "user_token",
		Role:   RoleOperator,
		Scopes: []string{"commands:*"},
	}
	if err := Authorize(wildcardPrincipal, "commands:execute", ""); err != nil {
		t.Errorf("expected commands:* scope to authorize commands:execute: %v", err)
	}
}

func TestExtractTokenFromRequestHeaders(t *testing.T) {
	if tok, ok := ExtractTokenFromRequest(nil); ok || tok != "" {
		t.Errorf("expected false on nil request")
	}

	reqEmpty := httptest.NewRequest("GET", "/api/v1/commands", nil)
	if tok, ok := ExtractTokenFromRequest(reqEmpty); ok || tok != "" {
		t.Errorf("expected false on request without auth headers")
	}

	reqBearer := httptest.NewRequest("GET", "/api/v1/commands", nil)
	reqBearer.Header.Set("Authorization", "Bearer gat_pat_abc")
	if tok, ok := ExtractTokenFromRequest(reqBearer); !ok || tok != "gat_pat_abc" {
		t.Errorf("expected gat_pat_abc from Bearer header, got %q (ok=%v)", tok, ok)
	}

	reqRawAuth := httptest.NewRequest("GET", "/api/v1/commands", nil)
	reqRawAuth.Header.Set("Authorization", "gat_pat_raw")
	if tok, ok := ExtractTokenFromRequest(reqRawAuth); !ok || tok != "gat_pat_raw" {
		t.Errorf("expected gat_pat_raw from raw Authorization header, got %q (ok=%v)", tok, ok)
	}

	for _, hdr := range []string{"X-API-Token", "X-API-Key", "X-Service-Key"} {
		r := httptest.NewRequest("GET", "/api/v1/commands", nil)
		r.Header.Set(hdr, "cred_"+hdr)
		if tok, ok := ExtractTokenFromRequest(r); !ok || tok != "cred_"+hdr {
			t.Errorf("expected cred_%s from header %s, got %q (ok=%v)", hdr, hdr, tok, ok)
		}
	}
}


