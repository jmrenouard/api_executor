package api

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"go-admin-tool/internal/audit"
	"go-admin-tool/internal/auth"
	"go-admin-tool/internal/core"
)

func setupTestAPIEnvWithTLS(t *testing.T, tlsEnabled bool) (*APIEnv, *core.CertManager) {
	t.Helper()
	tmpDir := t.TempDir()

	cfg := core.DefaultConfig()
	cfg.Server.TLS.Enabled = tlsEnabled
	cfg.Server.TLS.CertFile = filepath.Join(tmpDir, "certs", "server.crt")
	cfg.Server.TLS.KeyFile = filepath.Join(tmpDir, "certs", "server.key")

	logger, err := core.NewLogger(core.LoggingConfig{Level: "error"})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}

	cm, err := core.NewCertManager(cfg.Server.TLS, "localhost")
	if err != nil {
		t.Fatalf("failed to create CertManager: %v", err)
	}

	auditLogger, _ := audit.NewAuditLogger(cfg.Audit, nil, logger)

	env := &APIEnv{
		Config:      cfg,
		Logger:      logger,
		CertManager: cm,
		AuditLogger: auditLogger,
	}
	return env, cm
}

func TestTLSInfoEndpoint(t *testing.T) {
	// Arrange
	env, _ := setupTestAPIEnvWithTLS(t, true)
	router := NewRouter(env)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tls/info", nil)
	rec := httptest.NewRecorder()

	// Act
	router.ServeHTTP(rec, req)

	// Assert
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}

	var info core.CertificateInfo
	if err := json.Unmarshal(rec.Body.Bytes(), &info); err != nil {
		t.Fatalf("failed to decode CertificateInfo: %v", err)
	}
	if !info.Enabled {
		t.Errorf("expected info.Enabled=true")
	}
	if info.FingerprintSHA256 == "" {
		t.Errorf("expected non-empty FingerprintSHA256")
	}
	if info.SerialNumber == "" {
		t.Errorf("expected non-empty SerialNumber")
	}
}

func TestTLSCertificateDownloadEndpoint(t *testing.T) {
	// Arrange
	env, _ := setupTestAPIEnvWithTLS(t, true)
	router := NewRouter(env)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tls/certificate", nil)
	rec := httptest.NewRecorder()

	// Act
	router.ServeHTTP(rec, req)

	// Assert
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}
	block, _ := pem.Decode(rec.Body.Bytes())
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("expected valid CERTIFICATE PEM block, got %q", rec.Body.String())
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		t.Fatalf("downloaded PEM is not a valid X.509 certificate: %v", err)
	}
}

func TestTLSRenewEndpoint(t *testing.T) {
	// Arrange
	env, cm := setupTestAPIEnvWithTLS(t, true)
	router := NewRouter(env)
	oldFP := cm.Info().FingerprintSHA256

	// Reject GET on /api/v1/tls/renew
	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/tls/renew", nil)
	getRec := httptest.NewRecorder()
	router.ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 Method Not Allowed for GET /api/v1/tls/renew, got %d", getRec.Code)
	}

	// Act: POST /api/v1/tls/renew
	postReq := httptest.NewRequest(http.MethodPost, "/api/v1/tls/renew", nil)
	postRec := httptest.NewRecorder()
	router.ServeHTTP(postRec, postReq)

	// Assert
	if postRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for POST /api/v1/tls/renew, got %d: %s", postRec.Code, postRec.Body.String())
	}
	var renewed core.CertificateInfo
	if err := json.Unmarshal(postRec.Body.Bytes(), &renewed); err != nil {
		t.Fatalf("failed to decode renewed CertificateInfo: %v", err)
	}
	if renewed.FingerprintSHA256 == oldFP {
		t.Errorf("expected certificate fingerprint to change after renewal, still %s", oldFP)
	}

	// Verify audit event recorded for TLS renewal
	events := env.AuditLogger.Query(audit.AuditFilter{Category: "tls"})
	if len(events) == 0 {
		t.Fatalf("expected TLS renewal to record an event in AuditLogger")
	}

	// Verify RBAC enforcement when RequireAuth=true
	env.Config.Auth.Enabled = true
	env.Config.Auth.RequireAuth = true
	authMgr, _ := auth.NewManager(env.Config.Auth)
	env.AuthManager = authMgr
	_, _ = authMgr.CreateUser("viewer1", "viewer-pass-123", "Viewer", "", auth.RoleViewer)
	_, _, viewerTok, _ := authMgr.AuthenticateUser("viewer1", "viewer-pass-123")

	unauthReq := httptest.NewRequest(http.MethodPost, "/api/v1/tls/renew", nil)
	unauthRec := httptest.NewRecorder()
	router.ServeHTTP(unauthRec, unauthReq)
	if unauthRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthenticated POST /api/v1/tls/renew when RequireAuth=true, got %d", unauthRec.Code)
	}

	viewerReq := httptest.NewRequest(http.MethodPost, "/api/v1/tls/renew", nil)
	viewerReq.Header.Set("X-API-Token", viewerTok)
	viewerRec := httptest.NewRecorder()
	router.ServeHTTP(viewerRec, viewerReq)
	if viewerRec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for viewer POST /api/v1/tls/renew, got %d", viewerRec.Code)
	}
}

func TestTLSEndpointsWhenDisabled(t *testing.T) {
	// Arrange
	env, _ := setupTestAPIEnvWithTLS(t, false)
	router := NewRouter(env)

	// Info endpoint returns enabled=false
	infoReq := httptest.NewRequest(http.MethodGet, "/api/v1/tls/info", nil)
	infoRec := httptest.NewRecorder()
	router.ServeHTTP(infoRec, infoReq)
	if infoRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on /api/v1/tls/info when TLS disabled, got %d", infoRec.Code)
	}
	var info core.CertificateInfo
	_ = json.Unmarshal(infoRec.Body.Bytes(), &info)
	if info.Enabled {
		t.Errorf("expected info.Enabled=false when TLS is disabled")
	}

	// Certificate download returns 404 when TLS disabled
	certReq := httptest.NewRequest(http.MethodGet, "/api/v1/tls/certificate", nil)
	certRec := httptest.NewRecorder()
	router.ServeHTTP(certRec, certReq)
	if certRec.Code != http.StatusNotFound {
		t.Errorf("expected 404 on /api/v1/tls/certificate when TLS disabled, got %d", certRec.Code)
	}

	// Renew returns 400 when TLS disabled
	renewReq := httptest.NewRequest(http.MethodPost, "/api/v1/tls/renew", nil)
	renewRec := httptest.NewRecorder()
	router.ServeHTTP(renewRec, renewReq)
	if renewRec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 on /api/v1/tls/renew when TLS disabled, got %d", renewRec.Code)
	}
}

func TestHTTPSServerEndToEndWithHSTSHeader(t *testing.T) {
	// Arrange
	env, cm := setupTestAPIEnvWithTLS(t, true)
	router := NewRouter(env)

	tlsCfg, err := cm.TLSConfig()
	if err != nil {
		t.Fatalf("TLSConfig() failed: %v", err)
	}

	srv := httptest.NewUnstartedServer(router)
	srv.TLS = tlsCfg
	srv.StartTLS()
	defer srv.Close()

	certPEM, err := cm.CertPEM()
	if err != nil {
		t.Fatalf("CertPEM() failed: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    pool,
				ServerName: "localhost",
			},
		},
	}

	// Act
	resp, err := client.Get(srv.URL + "/api/v1/tls/info")
	if err != nil {
		t.Fatalf("GET /api/v1/tls/info over HTTPS failed: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)

	// Assert
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", resp.StatusCode)
	}
	hsts := resp.Header.Get("Strict-Transport-Security")
	if hsts == "" {
		t.Errorf("expected Strict-Transport-Security header on HTTPS response, got empty")
	}
}
