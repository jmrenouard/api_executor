package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestResolveConfigPathAndInitializeServerEnv(t *testing.T) {
	// 1. Default config path when CONFIG_PATH is unset
	_ = os.Unsetenv("CONFIG_PATH")
	if got := resolveConfigPath(); got != "config.yaml" {
		t.Errorf("expected default 'config.yaml', got %q", got)
	}

	tmpDir := t.TempDir()
	customCfgPath := filepath.Join(tmpDir, "custom-config.yaml")
	t.Setenv("CONFIG_PATH", customCfgPath)
	if got := resolveConfigPath(); got != customCfgPath {
		t.Errorf("expected %q from CONFIG_PATH, got %q", customCfgPath, got)
	}

	// 2. Non-existent config path returns error
	if _, _, _, err := initializeServerEnv(filepath.Join(tmpDir, "missing.yaml")); err == nil {
		t.Errorf("expected error for missing config file")
	}

	// 3. Valid HTTPS config initializes all subsystems, creates SecureDir + dummy.txt, loads declarative plugins
	secureDir := filepath.Join(tmpDir, "secure_files")
	certFile := filepath.Join(tmpDir, "certs", "server.crt")
	keyFile := filepath.Join(tmpDir, "certs", "server.key")
	dbPath := filepath.Join(tmpDir, "history.db")
	logPath := filepath.Join(tmpDir, "app.log")
	declDir := filepath.Join(tmpDir, "plugins")
	_ = os.MkdirAll(declDir, 0755)
	declYAML := `
id: "boot-plugin"
name: "Boot Declarative Plugin"
version: "1.0.0"
actions:
  - name: "boot-echo"
    command: "whoami"
`
	_ = os.WriteFile(filepath.Join(declDir, "boot.yaml"), []byte(declYAML), 0600)

	cfgContent := fmt.Sprintf(`
server:
  port: 18443
  host: "127.0.0.1"
  tls:
    enabled: true
    auto_generate: true
    cert_file: %q
    key_file: %q
logging:
  level: "info"
  path: %q
database:
  path: %q
file_server:
  enabled: true
  secure_dir: %q
plugins:
  enabled: true
  declarative_dir: %q
  enable_db_exposure: true
  enable_sys_diag: true
command_executor:
  enabled: true
  commands:
    - name: "boot-cmd"
      command: "whoami"
`, certFile, keyFile, logPath, dbPath, secureDir, declDir)

	if err := os.WriteFile(customCfgPath, []byte(cfgContent), 0600); err != nil {
		t.Fatalf("failed to write custom config: %v", err)
	}

	env, router, cleanup, err := initializeServerEnv(customCfgPath)
	if err != nil {
		t.Fatalf("initializeServerEnv failed: %v", err)
	}
	defer cleanup()

	// Verify dummy.txt was created in secureDir
	if _, err := os.Stat(filepath.Join(secureDir, "dummy.txt")); err != nil {
		t.Errorf("expected dummy.txt to be created in SecureDir: %v", err)
	}

	// Verify buildHTTPServer with TLS enabled
	httpsSrv, err := buildHTTPServer(env, router)
	if err != nil {
		t.Fatalf("buildHTTPServer (HTTPS) failed: %v", err)
	}
	if httpsSrv.TLSConfig == nil || httpsSrv.Addr != "127.0.0.1:18443" {
		t.Errorf("expected non-nil TLSConfig and addr 127.0.0.1:18443, got %+v", httpsSrv)
	}

	// Verify router responds to /api/v1/plugins and includes boot-plugin
	req := httptest.NewRequest(http.MethodGet, "/api/v1/plugins", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 from /api/v1/plugins, got %d", rec.Code)
	}

	// Verify buildHTTPServer with TLS disabled
	env.Config.Server.TLS.Enabled = false
	httpSrv, err := buildHTTPServer(env, router)
	if err != nil {
		t.Fatalf("buildHTTPServer (HTTP) failed: %v", err)
	}
	if httpSrv.TLSConfig != nil {
		t.Errorf("expected nil TLSConfig when TLS is disabled")
	}

	// 4. Error branches in initializeServerEnv: invalid logger path, invalid TLS config
	badLogCfg := filepath.Join(tmpDir, "bad-log.yaml")
	_ = os.WriteFile(badLogCfg, []byte(fmt.Sprintf("logging:\n  path: %q\n", tmpDir)), 0600)
	if _, _, _, err := initializeServerEnv(badLogCfg); err == nil {
		t.Errorf("expected error when logging.path points to a directory")
	}

	badTLSCfg := filepath.Join(tmpDir, "bad-tls.yaml")
	_ = os.WriteFile(badTLSCfg, []byte("server:\n  tls:\n    enabled: true\n    auto_generate: false\n    cert_file: \"missing.crt\"\n    key_file: \"missing.key\"\n"), 0600)
	if _, _, _, err := initializeServerEnv(badTLSCfg); err == nil {
		t.Errorf("expected error when TLS auto_generate is false and cert files are missing")
	}

	// 5. Verify runServer with custom serveFn for HTTPS, HTTP, and error branches
	var servedTLS bool
	var servedAddr string
	err = runServer(customCfgPath, func(srv *http.Server, tlsEnabled bool) error {
		servedTLS = tlsEnabled
		servedAddr = srv.Addr
		return nil
	})
	if err != nil {
		t.Fatalf("expected runServer (HTTPS) to succeed, got %v", err)
	}
	if !servedTLS || servedAddr != "127.0.0.1:18443" {
		t.Errorf("expected servedTLS=true and addr='127.0.0.1:18443', got tls=%v addr=%q", servedTLS, servedAddr)
	}

	httpCfgPath := filepath.Join(tmpDir, "http-config.yaml")
	_ = os.WriteFile(httpCfgPath, []byte("server:\n  port: 18080\n  host: \"127.0.0.1\"\n  tls:\n    enabled: false\n"), 0600)
	err = runServer(httpCfgPath, func(srv *http.Server, tlsEnabled bool) error {
		servedTLS = tlsEnabled
		servedAddr = srv.Addr
		return nil
	})
	if err != nil {
		t.Fatalf("expected runServer (HTTP) to succeed, got %v", err)
	}
	if servedTLS || servedAddr != "127.0.0.1:18080" {
		t.Errorf("expected servedTLS=false and addr='127.0.0.1:18080', got tls=%v addr=%q", servedTLS, servedAddr)
	}

	if err := runServer(filepath.Join(tmpDir, "nonexistent.yaml"), nil); err == nil {
		t.Errorf("expected runServer to fail when config file does not exist")
	}

	err = runServer(httpCfgPath, func(srv *http.Server, tlsEnabled bool) error {
		return fmt.Errorf("simulated listen failure")
	})
	if err == nil {
		t.Errorf("expected runServer to propagate serveFn error")
	}

	err = runServer(customCfgPath, func(srv *http.Server, tlsEnabled bool) error {
		return fmt.Errorf("simulated https listen failure")
	})
	if err == nil {
		t.Errorf("expected runServer (HTTPS) to propagate serveFn error")
	}

	badAuthCfg := filepath.Join(tmpDir, "bad-auth.yaml")
	_ = os.WriteFile(badAuthCfg, []byte("server:\n  tls:\n    enabled: false\nauth:\n  enabled: true\n  bootstrap_password: \"123\"\n"), 0600)
	if _, _, _, err := initializeServerEnv(badAuthCfg); err == nil {
		t.Errorf("expected error when auth.bootstrap_password is shorter than 6 characters")
	}
}


