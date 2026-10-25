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

	env := &APIEnv{
		Config:      cfg,
		Logger:      logger,
		CertManager: cm,
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
