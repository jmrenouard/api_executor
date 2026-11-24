package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"go-admin-tool/internal/auth"
	"go-admin-tool/internal/core"
	"go-admin-tool/internal/database"
	"go-admin-tool/internal/jobs"
	"go-admin-tool/internal/version"
)

// healthMockDriver is a minimal database/sql/driver used to test SQL-backed DB
// ping success and closed-DB failure independently of CGO_ENABLED.
type healthMockDriver struct{}

type healthMockConn struct{}

func (d *healthMockDriver) Open(_ string) (driver.Conn, error) {
	return &healthMockConn{}, nil
}

func (c *healthMockConn) Prepare(_ string) (driver.Stmt, error) {
	return nil, errors.New("not implemented")
}

func (c *healthMockConn) Close() error { return nil }

func (c *healthMockConn) Begin() (driver.Tx, error) {
	return nil, errors.New("not implemented")
}

var registerHealthMockDriverOnce sync.Once

func newTestSQLBackedDB(t *testing.T) *database.DB {
	t.Helper()
	registerHealthMockDriverOnce.Do(func() {
		sql.Register("health_mock_sql", &healthMockDriver{})
	})
	raw, err := sql.Open("health_mock_sql", "health_test.db")
	if err != nil {
		t.Fatalf("failed to open health_mock_sql: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	return &database.DB{DB: raw}
}

func writeShortLivedCertPair(t *testing.T, certPath, keyPath string, notAfter time.Time) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}
	now := time.Now().Add(-2 * time.Second)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    now,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("failed to marshal EC key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		t.Fatalf("failed to write cert file: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}
}

func TestHealthHandler_LivenessAndMethods(t *testing.T) {
	tmpDir := t.TempDir()
	logger, err := core.NewLogger(core.LoggingConfig{Level: "error"})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	defer logger.Close()

	for _, tlsEnabled := range []bool{false, true} {
		cfg := core.DefaultConfig()
		cfg.Server.TLS.Enabled = tlsEnabled
		cfg.Server.TLS.CertFile = filepath.Join(tmpDir, "secret-cert-path.crt")
		cfg.Server.TLS.KeyFile = filepath.Join(tmpDir, "secret-key-path.key")
		cfg.Auth.BootstrapPassword = "SuperSecretBootstrapPassword!"

		env := &APIEnv{
			Config:    cfg,
			Logger:    logger,
			StartTime: time.Now().Add(-5 * time.Second),
		}
		router := NewRouter(env)

		for _, path := range []string{"/health", "/healthz"} {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("GET %s (tls=%v): expected 200 OK, got %d: %s", path, tlsEnabled, rec.Code, rec.Body.String())
			}

			body := rec.Body.String()
			for _, forbidden := range []string{"secret-cert-path.crt", "secret-key-path.key", "SuperSecretBootstrapPassword"} {
				if strings.Contains(body, forbidden) {
					t.Errorf("GET %s leaked sensitive string %q in response: %s", path, forbidden, body)
				}
			}

			var resp HealthResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("GET %s: invalid JSON: %v", path, err)
			}
			if resp.Status != "ok" {
				t.Errorf("GET %s: expected status 'ok', got %q", path, resp.Status)
			}
			if resp.UptimeSeconds < 4.0 {
				t.Errorf("GET %s: expected uptime_seconds >= 4.0, got %v", path, resp.UptimeSeconds)
			}
			if resp.Version != version.Get().Version || resp.Version == "" {
				t.Errorf("GET %s: expected version %q, got %q", path, version.Get().Version, resp.Version)
			}
			if resp.TLSEnabled != tlsEnabled {
				t.Errorf("GET %s: expected tls_enabled=%v, got %v", path, tlsEnabled, resp.TLSEnabled)
			}

			for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
				mReq := httptest.NewRequest(method, path, nil)
				mRec := httptest.NewRecorder()
				router.ServeHTTP(mRec, mReq)

				if mRec.Code != http.StatusMethodNotAllowed {
					t.Errorf("%s %s: expected 405, got %d", method, path, mRec.Code)
				}
				if allow := mRec.Header().Get("Allow"); allow != http.MethodGet {
					t.Errorf("%s %s: expected Allow: GET, got %q", method, path, allow)
				}
			}
		}
	}
}

func TestReadinessHandler_HealthyAndMethods(t *testing.T) {
	tmpDir := t.TempDir()
	logger, err := core.NewLogger(core.LoggingConfig{Level: "error"})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	defer logger.Close()

	cfg := core.DefaultConfig()
	cfg.Server.TLS.Enabled = true
	cfg.Server.TLS.AutoGenerate = true
	cfg.Server.TLS.CertFile = filepath.Join(tmpDir, "server.crt")
	cfg.Server.TLS.KeyFile = filepath.Join(tmpDir, "server.key")

	cm, err := core.NewCertManager(cfg.Server.TLS, "localhost")
	if err != nil {
		t.Fatalf("failed to create CertManager: %v", err)
	}

	inMemDB, err := database.NewDB(":memory:")
	if err != nil {
		t.Fatalf("failed to create in-memory DB: %v", err)
	}
	defer inMemDB.Close()

	engineCfg := jobs.DefaultEngineConfig()
	engineCfg.WorkersCount = 1
	engineCfg.QueueCapacity = 4
	engine, err := jobs.NewEngine(engineCfg, nil, nil, func(_ context.Context, _ *jobs.Job, _ io.Writer) (any, error) {
		return "ok", nil
	})
	if err != nil {
		t.Fatalf("failed to create JobEngine: %v", err)
	}
	engine.Start()
	defer func() { _ = engine.Shutdown(context.Background()) }()

	env := &APIEnv{
		Config:      cfg,
		Logger:      logger,
		DB:          inMemDB,
		CertManager: cm,
		JobEngine:   engine,
		StartTime:   time.Now(),
	}
	router := NewRouter(env)

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /readyz: expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp ReadinessResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("GET /readyz: invalid JSON: %v", err)
	}
	if resp.Status != "ready" {
		t.Errorf("expected status 'ready', got %q", resp.Status)
	}
	expectedDBStatus := "ok"
	if inMemDB.IsInMemory() {
		expectedDBStatus = "in_memory"
	}
	if resp.Checks["database"] != expectedDBStatus {
		t.Errorf("expected checks[database]=%q, got %q", expectedDBStatus, resp.Checks["database"])
	}
	if resp.Checks["tls"] != "ok" {
		t.Errorf("expected checks[tls]='ok', got %q", resp.Checks["tls"])
	}
	if resp.Checks["jobs"] != "ok" {
		t.Errorf("expected checks[jobs]='ok', got %q", resp.Checks["jobs"])
	}

	// Verify SQL-backed healthy DB reports "ok"
	sqlDB := newTestSQLBackedDB(t)
	env.DB = sqlDB
	recSQL := httptest.NewRecorder()
	router.ServeHTTP(recSQL, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if recSQL.Code != http.StatusOK {
		t.Fatalf("GET /readyz (sql-backed): expected 200 OK, got %d: %s", recSQL.Code, recSQL.Body.String())
	}
	var sqlResp ReadinessResponse
	if err := json.Unmarshal(recSQL.Body.Bytes(), &sqlResp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if sqlResp.Checks["database"] != "ok" {
		t.Errorf("expected checks[database]='ok' for SQL-backed DB, got %q", sqlResp.Checks["database"])
	}

	// Verify non-GET returns 405 + Allow: GET
	postReq := httptest.NewRequest(http.MethodPost, "/readyz", nil)
	postRec := httptest.NewRecorder()
	router.ServeHTTP(postRec, postReq)
	if postRec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /readyz: expected 405, got %d", postRec.Code)
	}
	if allow := postRec.Header().Get("Allow"); allow != http.MethodGet {
		t.Errorf("POST /readyz: expected Allow: GET, got %q", allow)
	}
}

func TestReadinessHandler_Degraded503(t *testing.T) {
	t.Run("closed_sql_database", func(t *testing.T) {
		cfg := core.DefaultConfig()
		cfg.Server.TLS.Enabled = false

		sqlDB := newTestSQLBackedDB(t)
		_ = sqlDB.Close()

		env := &APIEnv{
			Config: cfg,
			DB:     sqlDB,
		}
		router := NewRouter(env)

		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))

		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("expected 503 Service Unavailable, got %d: %s", rec.Code, rec.Body.String())
		}
		var resp ReadinessResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		if resp.Status != "not_ready" {
			t.Errorf("expected status 'not_ready', got %q", resp.Status)
		}
		if resp.Checks["database"] != "error" {
			t.Errorf("expected checks[database]='error', got %q", resp.Checks["database"])
		}
	})

	t.Run("full_job_queue", func(t *testing.T) {
		cfg := core.DefaultConfig()
		cfg.Server.TLS.Enabled = false

		started := make(chan struct{})
		release := make(chan struct{})
		engineCfg := jobs.DefaultEngineConfig()
		engineCfg.WorkersCount = 1
		engineCfg.QueueCapacity = 1
		engine, err := jobs.NewEngine(engineCfg, nil, nil, func(ctx context.Context, _ *jobs.Job, _ io.Writer) (any, error) {
			select {
			case started <- struct{}{}:
			default:
			}
			select {
			case <-release:
			case <-ctx.Done():
			}
			return "done", nil
		})
		if err != nil {
			t.Fatalf("failed to create JobEngine: %v", err)
		}
		engine.Start()
		defer func() {
			close(release)
			_ = engine.Shutdown(context.Background())
		}()

		// Occupy the single worker
		if _, err := engine.Enqueue(jobs.JobRequest{Action: "blocker", TimeoutOverride: 5 * time.Second}); err != nil {
			t.Fatalf("failed to enqueue blocker job: %v", err)
		}
		<-started

		// Fill the single queue slot
		if _, err := engine.Enqueue(jobs.JobRequest{Action: "queued", TimeoutOverride: 5 * time.Second}); err != nil {
			t.Fatalf("failed to enqueue queued job: %v", err)
		}

		env := &APIEnv{
			Config:    cfg,
			JobEngine: engine,
		}
		router := NewRouter(env)

		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))

		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("expected 503 Service Unavailable when queue is full, got %d: %s", rec.Code, rec.Body.String())
		}
		var resp ReadinessResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		if resp.Status != "not_ready" {
			t.Errorf("expected status 'not_ready', got %q", resp.Status)
		}
		if resp.Checks["jobs"] != "queue_full" {
			t.Errorf("expected checks[jobs]='queue_full', got %q", resp.Checks["jobs"])
		}
	})

	t.Run("expired_tls_certificate", func(t *testing.T) {
		tmpDir := t.TempDir()
		certPath := filepath.Join(tmpDir, "short.crt")
		keyPath := filepath.Join(tmpDir, "short.key")
		// X.509 GeneralizedTime/UTCTime has 1-second resolution; align at +2s so the cert
		// is strictly valid during NewCertManager and reliably expires shortly thereafter.
		notAfter := time.Now().UTC().Truncate(time.Second).Add(2 * time.Second)
		writeShortLivedCertPair(t, certPath, keyPath, notAfter)

		cfg := core.DefaultConfig()
		cfg.Server.TLS.Enabled = true
		cfg.Server.TLS.AutoGenerate = false
		cfg.Server.TLS.CertFile = certPath
		cfg.Server.TLS.KeyFile = keyPath

		cm, err := core.NewCertManager(cfg.Server.TLS, "localhost")
		if err != nil {
			t.Fatalf("failed to create CertManager: %v", err)
		}

		// Wait until the short-lived certificate passes its NotAfter timestamp.
		if wait := time.Until(cm.Info().NotAfter) + 100*time.Millisecond; wait > 0 {
			time.Sleep(wait)
		}

		env := &APIEnv{
			Config:      cfg,
			CertManager: cm,
		}
		router := NewRouter(env)

		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))

		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("expected 503 Service Unavailable for expired TLS cert, got %d: %s", rec.Code, rec.Body.String())
		}
		var resp ReadinessResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		if resp.Status != "not_ready" {
			t.Errorf("expected status 'not_ready', got %q", resp.Status)
		}
		if resp.Checks["tls"] != "expired" {
			t.Errorf("expected checks[tls]='expired', got %q", resp.Checks["tls"])
		}
	})
}

func TestHealthAndReadinessProbes_PublicAccessWithRequireAuth(t *testing.T) {
	cfg := core.DefaultConfig()
	cfg.Server.TLS.Enabled = false
	cfg.Executor.Enabled = true
	cfg.Auth.Enabled = true
	cfg.Auth.RequireAuth = true
	cfg.Auth.BootstrapUsername = "admin"
	cfg.Auth.BootstrapPassword = "AdminSecurePassword!2026"

	authMgr, err := auth.NewManager(cfg.Auth)
	if err != nil {
		t.Fatalf("failed to create auth manager: %v", err)
	}

	db, err := database.NewDB(":memory:")
	if err != nil {
		t.Fatalf("failed to create DB: %v", err)
	}
	defer db.Close()

	env := &APIEnv{
		Config:      cfg,
		AuthManager: authMgr,
		DB:          db,
		StartTime:   time.Now(),
	}
	router := NewRouter(env)

	for _, path := range []string{"/health", "/healthz", "/readyz"} {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Errorf("unauthenticated GET %s with RequireAuth=true: expected 200 OK, got %d: %s", path, rec.Code, rec.Body.String())
		}
	}

	// Sanity check: protected endpoint still enforces 401 without credentials.
	cmdRec := httptest.NewRecorder()
	router.ServeHTTP(cmdRec, httptest.NewRequest(http.MethodGet, "/api/v1/commands", nil))
	if cmdRec.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated GET /api/v1/commands with RequireAuth=true: expected 401, got %d", cmdRec.Code)
	}
}
