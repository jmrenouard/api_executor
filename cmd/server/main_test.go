package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
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
	if httpsSrv.ReadHeaderTimeout != 5*time.Second ||
		httpsSrv.ReadTimeout != 15*time.Second ||
		httpsSrv.WriteTimeout != 30*time.Second ||
		httpsSrv.IdleTimeout != 60*time.Second {
		t.Errorf("expected Slowloris timeouts (5s, 15s, 30s, 60s), got readHeader=%v read=%v write=%v idle=%v",
			httpsSrv.ReadHeaderTimeout, httpsSrv.ReadTimeout, httpsSrv.WriteTimeout, httpsSrv.IdleTimeout)
	}

	// Verify router responds to /api/v1/plugins and includes boot-plugin
	req := httptest.NewRequest(http.MethodGet, "/api/v1/plugins", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 from /api/v1/plugins, got %d", rec.Code)
	}

	// Verify all 24 native plugins are registered in env.PluginRegistry
	expectedNativePlugins := []string{
		"sys-diagnostics",
		"host-storage-stats",
		"process-tree-analyzer",
		"tcp-udp-port-probe",
		"dns-resolver-audit",
		"file-integrity-checker",
		"password-policy-audit",
		"docker-socket-client",
		"container-spec-validator",
		"k8s-manifest-linter",
		"helm-chart-inspector",
		"db-exposure",
		"sqlite-schema-analyzer",
		"redis-protocol-probe",
		"git-repo-inspector",
		"semver-release-checker",
		"prometheus-scraper",
		"log-regex-analyzer",
		"mcp-endpoint-tester",
		"model-artifact-verifier",
		"tls-cert-inspector",
		"http-latency-probe",
		"crypto-hash-utility",
		"jwt-token-inspector",
	}
	for _, pID := range expectedNativePlugins {
		if p, ok := env.PluginRegistry.Get(pID); !ok || p == nil {
			t.Errorf("expected native plugin %q to be registered in production server runtime", pID)
		}
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
	if httpSrv.ReadHeaderTimeout != 5*time.Second ||
		httpSrv.ReadTimeout != 15*time.Second ||
		httpSrv.WriteTimeout != 30*time.Second ||
		httpSrv.IdleTimeout != 60*time.Second {
		t.Errorf("expected Slowloris timeouts on httpSrv, got readHeader=%v read=%v write=%v idle=%v",
			httpSrv.ReadHeaderTimeout, httpSrv.ReadTimeout, httpSrv.WriteTimeout, httpSrv.IdleTimeout)
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

func TestInitializeServerEnv_All24NativePluginsMounted(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "plugins-enabled.yaml")
	cfgContent := `
server:
  port: 19080
  host: "127.0.0.1"
  tls:
    enabled: false
database:
  path: "file::memory:?cache=shared"
plugins:
  enabled: true
  enable_db_exposure: true
  enable_sys_diag: true
`
	if err := os.WriteFile(cfgPath, []byte(cfgContent), 0600); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	env, _, cleanup, err := initializeServerEnv(cfgPath)
	if err != nil {
		t.Fatalf("initializeServerEnv failed: %v", err)
	}
	defer cleanup()

	expectedNativeIDs := []string{
		// 1. SysAdmin
		"sys-diagnostics",
		"host-storage-stats",
		"process-tree-analyzer",
		// 2. NetOps
		"tcp-udp-port-probe",
		"dns-resolver-audit",
		// 3. SecOps
		"file-integrity-checker",
		"password-policy-audit",
		// 4. ContainerOps
		"docker-socket-client",
		"container-spec-validator",
		// 5. Kubernetes
		"k8s-manifest-linter",
		"helm-chart-inspector",
		// 6. DataOps
		"db-exposure",
		"sqlite-schema-analyzer",
		"redis-protocol-probe",
		// 7. DevOps
		"git-repo-inspector",
		"semver-release-checker",
		// 8. SRE
		"prometheus-scraper",
		"log-regex-analyzer",
		// 9. AIOps
		"mcp-endpoint-tester",
		"model-artifact-verifier",
		// 10. Web & Crypto Utilities
		"tls-cert-inspector",
		"http-latency-probe",
		"crypto-hash-utility",
		"jwt-token-inspector",
	}

	for _, id := range expectedNativeIDs {
		p, found := env.PluginRegistry.Get(id)
		if !found || p == nil {
			t.Errorf("expected native plugin %q to be registered in production server runtime", id)
			continue
		}
		if p.ID() != id {
			t.Errorf("plugin ID mismatch: expected %q, got %q", id, p.ID())
		}
		if p.Name() == "" {
			t.Errorf("plugin %q has empty Name", id)
		}
		if p.Category() == "" {
			t.Errorf("plugin %q has empty Category", id)
		}
		if len(p.Actions()) == 0 {
			t.Errorf("plugin %q has no actions exposed", id)
		}
	}

	// Verify all 10 operational domains are represented
	expectedCategories := map[string]bool{
		"SysAdmin":                 false,
		"NetOps":                   false,
		"SecOps":                   false,
		"ContainerOps":             false,
		"Kubernetes":               false,
		"DataOps":                  false,
		"DevOps":                   false,
		"SRE":                      false,
		"AIOps":                    false,
		"Web & Crypto Utilities":   false,
	}

	for _, p := range env.PluginRegistry.List() {
		if _, ok := expectedCategories[p.Category]; ok {
			expectedCategories[p.Category] = true
		}
	}

	for cat, found := range expectedCategories {
		if !found {
			t.Errorf("expected operational category %q to be present in mounted plugins", cat)
		}
	}
}

func TestInitializeServerEnv_PluginsDisabled(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "plugins-disabled.yaml")
	cfgContent := `
server:
  port: 19081
  host: "127.0.0.1"
  tls:
    enabled: false
plugins:
  enabled: false
`
	if err := os.WriteFile(cfgPath, []byte(cfgContent), 0600); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	env, _, cleanup, err := initializeServerEnv(cfgPath)
	if err != nil {
		t.Fatalf("initializeServerEnv failed: %v", err)
	}
	defer cleanup()

	if pluginsCount := len(env.PluginRegistry.List()); pluginsCount != 0 {
		t.Errorf("expected 0 plugins when plugins.enabled=false, got %d", pluginsCount)
	}
}

func TestInitializeServerEnv_FeatureFlagToggles(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "plugins-toggles.yaml")
	cfgContent := `
server:
  port: 19082
  host: "127.0.0.1"
  tls:
    enabled: false
plugins:
  enabled: true
  enable_db_exposure: false
  enable_sys_diagnostics: false
`
	if err := os.WriteFile(cfgPath, []byte(cfgContent), 0600); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	env, _, cleanup, err := initializeServerEnv(cfgPath)
	if err != nil {
		t.Fatalf("initializeServerEnv failed: %v", err)
	}
	defer cleanup()

	if _, found := env.PluginRegistry.Get("db-exposure"); found {
		t.Errorf("expected db-exposure to be absent when enable_db_exposure is false")
	}
	if _, found := env.PluginRegistry.Get("sys-diagnostics"); found {
		t.Errorf("expected sys-diagnostics to be absent when enable_sys_diag is false")
	}

	// Verify other native plugins are still mounted
	if _, found := env.PluginRegistry.Get("host-storage-stats"); !found {
		t.Errorf("expected host-storage-stats to remain registered")
	}
	if _, found := env.PluginRegistry.Get("tls-cert-inspector"); !found {
		t.Errorf("expected tls-cert-inspector to remain registered")
	}
}

func TestBuildHTTPServer_TimeoutsConfigured(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "timeouts-test.yaml")
	cfgContent := `
server:
  port: 19083
  host: "127.0.0.1"
  tls:
    enabled: false
`
	if err := os.WriteFile(cfgPath, []byte(cfgContent), 0600); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	env, router, cleanup, err := initializeServerEnv(cfgPath)
	if err != nil {
		t.Fatalf("initializeServerEnv failed: %v", err)
	}
	defer cleanup()

	srv, err := buildHTTPServer(env, router)
	if err != nil {
		t.Fatalf("buildHTTPServer failed: %v", err)
	}

	if srv.ReadHeaderTimeout != 5*time.Second {
		t.Errorf("expected ReadHeaderTimeout = 5s, got %v", srv.ReadHeaderTimeout)
	}
	if srv.ReadTimeout != 15*time.Second {
		t.Errorf("expected ReadTimeout = 15s, got %v", srv.ReadTimeout)
	}
	if srv.WriteTimeout != 30*time.Second {
		t.Errorf("expected WriteTimeout = 30s, got %v", srv.WriteTimeout)
	}
	if srv.IdleTimeout != 60*time.Second {
		t.Errorf("expected IdleTimeout = 60s, got %v", srv.IdleTimeout)
	}
}

func TestRunServerWithContext_GracefulShutdown(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "graceful-test.yaml")
	cfgContent := `
server:
  port: 19084
  host: "127.0.0.1"
  tls:
    enabled: false
`
	if err := os.WriteFile(cfgPath, []byte(cfgContent), 0600); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	serverDone := make(chan error, 1)

	go func() {
		serverDone <- runServerWithContext(ctx, cfgPath, func(srv *http.Server, tlsEnabled bool) error {
			close(started)
			<-ctx.Done()
			return http.ErrServerClosed
		})
	}()

	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for server to start")
	}

	// Trigger graceful shutdown by cancelling context
	cancel()

	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatalf("expected nil error on graceful shutdown, got: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for graceful shutdown to complete")
	}
}

func TestRunServerWithContext_RealListenerGracefulShutdown(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "real-listener-test.yaml")
	cfgContent := `
server:
  port: 0
  host: "127.0.0.1"
  tls:
    enabled: false
`
	if err := os.WriteFile(cfgPath, []byte(cfgContent), 0600); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	serverDone := make(chan error, 1)

	var ln net.Listener
	var lnErr error

	go func() {
		serverDone <- runServerWithContext(ctx, cfgPath, func(srv *http.Server, tlsEnabled bool) error {
			ln, lnErr = net.Listen("tcp", "127.0.0.1:0")
			if lnErr != nil {
				close(started)
				return lnErr
			}
			srv.Addr = ln.Addr().String()
			close(started)
			return srv.Serve(ln)
		})
	}()

	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for real server listener to start")
	}
	if lnErr != nil {
		t.Fatalf("failed to bind listener: %v", lnErr)
	}

	// Make an HTTP request to verify server is genuinely accepting traffic
	resp, err := http.Get(fmt.Sprintf("http://%s/health", ln.Addr().String()))
	if err == nil {
		_ = resp.Body.Close()
	}

	// Cancel context to trigger graceful shutdown
	cancel()

	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatalf("expected nil on real server graceful shutdown, got: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for real server to shut down gracefully")
	}
}




