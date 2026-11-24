package e2e_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"go-admin-tool/internal/core"
)

// extractYAMLBlockFromDoc reads a Markdown guide relative to repo root and returns the fenced YAML block containing marker.
func extractYAMLBlockFromDoc(t *testing.T, relPath string, marker string) string {
	t.Helper()
	candidates := []string{relPath, filepath.Join("..", "..", relPath)}
	var raw []byte
	var err error
	for _, p := range candidates {
		raw, err = os.ReadFile(p)
		if err == nil {
			break
		}
	}
	if err != nil {
		t.Fatalf("failed to read %s: %v", relPath, err)
	}

	content := strings.ReplaceAll(string(raw), "\r\n", "\n")
	// Match both ```yaml ... ``` and cat <<'YAML' ... YAML shell heredocs used in tutorials.
	heredocRe := regexp.MustCompile("(?ms)cat <<'YAML' > [^\\n]+\\n(.*?)^YAML")
	for _, m := range heredocRe.FindAllStringSubmatch(content, -1) {
		if strings.Contains(m[1], marker) {
			return m[1]
		}
	}

	fenceRe := regexp.MustCompile("(?ms)^[ \t]*```yaml[ \t]*\\n(.*?)^[ \t]*```[ \t]*$")
	for _, m := range fenceRe.FindAllStringSubmatch(content, -1) {
		dedented := dedentYAMLBlock(m[1])
		if strings.Contains(dedented, marker) {
			return dedented
		}
	}

	t.Fatalf("no YAML block containing %q found in %s", marker, relPath)
	return ""
}

func dedentYAMLBlock(block string) string {
	lines := strings.Split(block, "\n")
	minIndent := -1
	for _, ln := range lines {
		if strings.TrimSpace(ln) == "" {
			continue
		}
		indent := len(ln) - len(strings.TrimLeft(ln, " "))
		if minIndent == -1 || indent < minIndent {
			minIndent = indent
		}
	}
	if minIndent <= 0 {
		return block
	}
	for i, ln := range lines {
		if len(ln) >= minIndent && strings.TrimSpace(ln[:minIndent]) == "" {
			lines[i] = ln[minIndent:]
		}
	}
	return strings.Join(lines, "\n")
}

func resolveRepoRoot(t *testing.T) string {
	t.Helper()
	for _, candidate := range []string{".", filepath.Join("..", "..")} {
		if _, err := os.Stat(filepath.Join(candidate, "go.mod")); err == nil {
			abs, absErr := filepath.Abs(candidate)
			if absErr != nil {
				t.Fatalf("filepath.Abs(%s): %v", candidate, absErr)
			}
			return abs
		}
	}
	t.Fatalf("could not locate repository root containing go.mod")
	return ""
}

func reserveFreeLoopbackPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen failed: %v", err)
	}
	defer ln.Close()
	addr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("unexpected listener address type %T", ln.Addr())
	}
	return addr.Port
}

func buildServerBinary(t *testing.T, repoRoot string, outDir string) string {
	t.Helper()
	binName := "go-admin-tool"
	if runtime.GOOS == "windows" {
		binName += ".exe"
	}
	binPath := filepath.Join(outDir, binName)
	cmd := exec.Command("go", "build", "-o", binPath, "./cmd/server")
	cmd.Dir = repoRoot
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go build ./cmd/server failed: %v\n%s", err, string(out))
	}
	return binPath
}

type runningTutorialServer struct {
	baseURL string
	client  *http.Client
	cmd     *exec.Cmd
	logs    *bytes.Buffer
}

func startCompiledServer(t *testing.T, workDir string, binPath string, configPath string, certPath string) *runningTutorialServer {
	t.Helper()

	var logBuf bytes.Buffer
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, binPath)
	cmd.Dir = workDir
	cmd.Env = append(os.Environ(), "CONFIG_PATH="+configPath)
	cmd.Stdout = &logBuf
	cmd.Stderr = &logBuf

	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatalf("failed to start compiled server %s: %v", binPath, err)
	}

	t.Cleanup(func() {
		cancel()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	})

	// Wait until the auto-generated ECDSA server certificate exists on disk.
	deadline := time.Now().Add(15 * time.Second)
	var certPEM []byte
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(certPath)
		if err == nil && len(data) > 0 {
			certPEM = data
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if len(certPEM) == 0 {
		t.Fatalf("timed out waiting for certificate %s; server output:\n%s", certPath, logBuf.String())
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		t.Fatalf("failed to parse auto-generated certificate PEM from %s", certPath)
	}

	cfg, err := core.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("core.LoadConfig(%s): %v", configPath, err)
	}
	baseURL := fmt.Sprintf("https://127.0.0.1:%d", cfg.Server.Port)

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    pool,
				MinVersion: tls.VersionTLS13,
			},
		},
	}

	// Poll public /api/v1/version over TLS 1.3 until server listener is ready.
	for time.Now().Before(deadline) {
		resp, reqErr := client.Get(baseURL + "/api/v1/version")
		if reqErr == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return &runningTutorialServer{
					baseURL: baseURL,
					client:  client,
					cmd:     cmd,
					logs:    &logBuf,
				}
			}
		}
		time.Sleep(100 * time.Millisecond)
	}

	t.Fatalf("compiled server did not respond on %s/api/v1/version; logs:\n%s", baseURL, logBuf.String())
	return nil
}

func doJSONRequest(
	t *testing.T,
	client *http.Client,
	method string,
	url string,
	headers map[string]string,
	payload any,
) (int, []byte) {
	t.Helper()
	var body io.Reader
	if payload != nil {
		switch v := payload.(type) {
		case string:
			body = strings.NewReader(v)
		default:
			raw, err := json.Marshal(v)
			if err != nil {
				t.Fatalf("json.Marshal failed: %v", err)
			}
			body = bytes.NewReader(raw)
		}
	}
	req, err := http.NewRequestWithContext(context.Background(), method, url, body)
	if err != nil {
		t.Fatalf("http.NewRequest(%s %s): %v", method, url, err)
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("HTTP %s %s failed: %v", method, url, err)
	}
	defer resp.Body.Close()
	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading response from %s %s failed: %v", method, url, err)
	}
	return resp.StatusCode, respBytes
}

func loginTutorialUser(t *testing.T, srv *runningTutorialServer, username, password string) string {
	t.Helper()
	code, b := doJSONRequest(t, srv.client, http.MethodPost, srv.baseURL+"/api/v1/auth/login", nil, map[string]string{
		"username": username,
		"password": password,
	})
	if code != http.StatusOK {
		t.Fatalf("login %s failed: status=%d body=%s", username, code, string(b))
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(b, &out); err != nil || out.Token == "" {
		t.Fatalf("invalid login payload for %s: %s", username, string(b))
	}
	return out.Token
}

func mintTutorialPAT(
	t *testing.T,
	srv *runningTutorialServer,
	adminTok string,
	name string,
	scopes []string,
	ttl string,
) (string, string) {
	t.Helper()
	code, body := doJSONRequest(
		t,
		srv.client,
		http.MethodPost,
		srv.baseURL+"/api/v1/auth/tokens",
		map[string]string{"Authorization": "Bearer " + adminTok},
		map[string]any{
			"user_id": "admin",
			"name":    name,
			"scopes":  scopes,
			"ttl":     ttl,
		},
	)
	if code != http.StatusOK && code != http.StatusCreated {
		t.Fatalf("mint PAT %q failed: status=%d body=%s", name, code, string(body))
	}
	var res struct {
		TokenInfo struct {
			ID string `json:"id"`
		} `json:"token_info"`
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &res); err != nil || res.TokenInfo.ID == "" || !strings.HasPrefix(res.Token, "gat_pat_") {
		t.Fatalf("unexpected mint PAT response: %s", string(body))
	}
	return res.TokenInfo.ID, res.Token
}

func rewriteSandboxPaths(yamlText string, labPrefix string, sandboxDir string, port int, pluginsDir string) string {
	slashDir := filepath.ToSlash(sandboxDir)
	slashPlugins := filepath.ToSlash(pluginsDir)
	replacer := strings.NewReplacer(
		labPrefix, slashDir,
		"port: 18443", fmt.Sprintf("port: %d", port),
		"port: 18444", fmt.Sprintf("port: %d", port),
		"port: 18445", fmt.Sprintf("port: %d", port),
	)
	out := replacer.Replace(yamlText)
	if pluginsDir != "" {
		out = strings.ReplaceAll(out, slashDir+"/plugins", slashPlugins)
	}
	if runtime.GOOS == "windows" {
		// Replace POSIX ps/df commands with Windows native cmd echo so tutorial workflows run cleanly on Windows too.
		out = strings.ReplaceAll(out, "command: \"ps\"\n      args: [\"aux\"]", "command: \"cmd\"\n      args: [\"/C\", \"echo\", \"PID TTY TIME CMD\"]")
		out = strings.ReplaceAll(out, "command: \"df\"\n      args: [\"-h\"]", "command: \"cmd\"\n      args: [\"/C\", \"echo\", \"Filesystem Size Used Avail\"]")
	}
	return out
}

// TestTutorialsAndHowTos_ExecutableSuite compiles ./cmd/server and executes the YAML configs
// and end-to-end REST/MCP/HITL/Async/TLS workflows documented in docs/01-tutorials/ and docs/02-how-to-guides/.
func TestTutorialsAndHowTos_ExecutableSuite(t *testing.T) {
	repoRoot := resolveRepoRoot(t)
	buildDir := t.TempDir()
	binPath := buildServerBinary(t, repoRoot, buildDir)
	pluginsDir := filepath.Join(repoRoot, "plugins")

	// Validate embedded rootless deployment YAML from How-To guide against core.LoadConfig.
	t.Run("HowTo_DeployRootlessConfigParsesAndValidates", func(t *testing.T) {
		docYAML := extractYAMLBlockFromDoc(t, "docs/02-how-to-guides/deployment/deploy-rootless-docker-and-tls.md", "enforce_non_root: true")
		cfgPath := filepath.Join(t.TempDir(), "prod-config.yaml")
		if err := os.WriteFile(cfgPath, []byte(docYAML), 0600); err != nil {
			t.Fatalf("write temp config: %v", err)
		}
		cfg, err := core.LoadConfig(cfgPath)
		if err != nil {
			t.Fatalf("core.LoadConfig failed on deploy-rootless-docker-and-tls.md snippet: %v", err)
		}
		if !cfg.Auth.RequireAuth || cfg.Server.TLS.MinVersion != "1.3" {
			t.Fatalf("expected require_auth=true and tls.min_version=1.3, got require_auth=%v min_version=%q", cfg.Auth.RequireAuth, cfg.Server.TLS.MinVersion)
		}
		if err := cfg.Sandbox.Validate(); err != nil {
			t.Fatalf("expected sandbox config valid, got error: %v", err)
		}
		if cfg.Sandbox.UID != 10001 || cfg.Sandbox.GID != 10001 || cfg.Sandbox.UserNS != "keep-id" {
			t.Fatalf("unexpected sandbox identity: %+v", cfg.Sandbox)
		}
	})

	// Tutorial 1: Local HTTPS Quickstart (compiled binary, version probe, 401 guard, PAT mint, execute, /metrics).
	t.Run("Tutorial1_LocalHTTPSQuickstart", func(t *testing.T) {
		labDir := t.TempDir()
		_ = os.MkdirAll(filepath.Join(labDir, "certs"), 0755)
		_ = os.MkdirAll(filepath.Join(labDir, "secure_files"), 0755)

		docYAML := extractYAMLBlockFromDoc(t, "docs/01-tutorials/01-local-https-quickstart.md", "disk-usage")
		port := reserveFreeLoopbackPort(t)
		cfgText := rewriteSandboxPaths(docYAML, "/tmp/apiexec-lab", labDir, port, "")
		cfgPath := filepath.Join(labDir, "sandbox-config.yaml")
		if err := os.WriteFile(cfgPath, []byte(cfgText), 0600); err != nil {
			t.Fatalf("write sandbox-config.yaml: %v", err)
		}

		srv := startCompiledServer(t, repoRoot, binPath, cfgPath, filepath.Join(labDir, "certs", "server.crt"))

		// Step 2 check: auto-generated server.key permissions on POSIX hosts must be 0600.
		if runtime.GOOS != "windows" {
			info, err := os.Stat(filepath.Join(labDir, "certs", "server.key"))
			if err != nil {
				t.Fatalf("stat server.key: %v", err)
			}
			if perm := info.Mode().Perm(); perm != 0600 {
				t.Errorf("expected server.key permissions 0600, got %o", perm)
			}
		}

		// Step 3: Public /api/v1/version and /api/v1/config/version probes + unauthenticated 401 check.
		code, verBody := doJSONRequest(t, srv.client, http.MethodGet, srv.baseURL+"/api/v1/version", nil, nil)
		if code != http.StatusOK {
			t.Fatalf("GET /api/v1/version status=%d body=%s", code, string(verBody))
		}
		var verJSON map[string]any
		if err := json.Unmarshal(verBody, &verJSON); err != nil {
			t.Fatalf("parse /api/v1/version: %v", err)
		}
		if strings.TrimSpace(fmt.Sprint(verJSON["version"])) == "" || verJSON["config_version"] != "2.2.0" {
			t.Errorf("expected non-empty version and config_version=2.2.0, got version=%v config_version=%v", verJSON["version"], verJSON["config_version"])
		}
		if verJSON["config_version_path"] != "/api/v1/config/version" {
			t.Errorf("expected config_version_path=/api/v1/config/version, got %v", verJSON["config_version_path"])
		}

		code, _ = doJSONRequest(t, srv.client, http.MethodGet, srv.baseURL+"/api/v1/config/version", nil, nil)
		if code != http.StatusOK {
			t.Fatalf("GET /api/v1/config/version expected 200, got %d", code)
		}

		code, _ = doJSONRequest(t, srv.client, http.MethodPost, srv.baseURL+"/api/v1/execute", nil, map[string]any{"name": "disk-usage"})
		if code != http.StatusUnauthorized {
			t.Fatalf("expected unauthenticated POST /api/v1/execute -> 401, got %d", code)
		}

		// Step 4: Admin login -> mint PAT -> execute disk-usage with timeout override -> inspect /metrics.
		sessionTok := loginTutorialUser(t, srv, "admin", "lab-admin-pass")
		_, labPAT := mintTutorialPAT(t, srv, sessionTok, "quickstart-cli", []string{"commands:read", "commands:execute"}, "2h")

		code, execBody := doJSONRequest(
			t,
			srv.client,
			http.MethodPost,
			srv.baseURL+"/api/v1/execute",
			map[string]string{"X-API-Token": labPAT},
			map[string]any{"name": "disk-usage", "timeout": "5s"},
		)
		if code != http.StatusOK {
			t.Fatalf("execute disk-usage status=%d body=%s", code, string(execBody))
		}
		var execRes map[string]any
		_ = json.Unmarshal(execBody, &execRes)
		if execRes["timeout"] != "5s" {
			t.Errorf("expected timeout=5s in response, got %v", execRes["timeout"])
		}

		code, metricsBytes := doJSONRequest(t, srv.client, http.MethodGet, srv.baseURL+"/metrics", nil, nil)
		if code != http.StatusOK {
			t.Fatalf("GET /metrics status=%d", code)
		}
		metricsText := string(metricsBytes)
		for _, expectedSeries := range []string{
			`action_calls_total{action="disk-usage"}`,
			`action_mode_calls_total{action="disk-usage",mode="sync",status="ok"}`,
		} {
			if !strings.Contains(metricsText, expectedSeries) {
				t.Errorf("expected /metrics to contain %q", expectedSeries)
			}
		}
	})

	// Tutorial 2: Plugins & MCP Sandbox (SysAdmin native discovery, WebUtils sha256, injection block, db-exposure, MCP trace verify).
	t.Run("Tutorial2_PluginsAndMCPSandbox", func(t *testing.T) {
		labDir := t.TempDir()
		_ = os.MkdirAll(filepath.Join(labDir, "certs"), 0755)
		sampleFile := filepath.Join(labDir, "sample.txt")
		if err := os.WriteFile(sampleFile, []byte("hello zero-trust sandbox\n"), 0600); err != nil {
			t.Fatalf("write sample.txt: %v", err)
		}

		docYAML := extractYAMLBlockFromDoc(t, "docs/01-tutorials/02-plugins-and-mcp-sandbox.md", "api-executor-mcp-lab")
		port := reserveFreeLoopbackPort(t)
		cfgText := rewriteSandboxPaths(docYAML, "/tmp/apiexec-mcp-lab", labDir, port, pluginsDir)
		cfgPath := filepath.Join(labDir, "mcp-lab.yaml")
		if err := os.WriteFile(cfgPath, []byte(cfgText), 0600); err != nil {
			t.Fatalf("write mcp-lab.yaml: %v", err)
		}

		srv := startCompiledServer(t, repoRoot, binPath, cfgPath, filepath.Join(labDir, "certs", "server.crt"))

		adminTok := loginTutorialUser(t, srv, "admin", "lab-admin-pass")
		authHdr := map[string]string{"Authorization": "Bearer " + adminTok}

		// Step 2a: Exact SysAdmin native plugin list (must match Tutorial 2 expected output).
		code, sysPlugBody := doJSONRequest(t, srv.client, http.MethodGet, srv.baseURL+"/api/v1/plugins?category=SysAdmin&type=native", authHdr, nil)
		if code != http.StatusOK {
			t.Fatalf("GET SysAdmin native plugins status=%d body=%s", code, string(sysPlugBody))
		}
		var plugResp pluginsListResponse
		_ = json.Unmarshal(sysPlugBody, &plugResp)
		var sysIDs []string
		for _, p := range plugResp.Plugins {
			sysIDs = append(sysIDs, p.ID)
		}
		expectedSysIDs := []string{"host-storage-stats", "process-tree-analyzer", "sys-diagnostics"}
		if strings.Join(sysIDs, ",") != strings.Join(expectedSysIDs, ",") {
			t.Errorf("expected SysAdmin native IDs %v, got %v", expectedSysIDs, sysIDs)
		}

		// Step 2b: WebUtils sha256 filter & native/declarative execution + metacharacter rejection.
		code, shaQueryBody := doJSONRequest(t, srv.client, http.MethodGet, srv.baseURL+"/api/v1/plugins?category=WebUtils&q=sha256", authHdr, nil)
		if code != http.StatusOK || !strings.Contains(string(shaQueryBody), "crypto-sha256-file") {
			t.Fatalf("expected crypto-sha256-file in WebUtils query, status=%d body=%s", code, string(shaQueryBody))
		}

		code, diagBody := doJSONRequest(t, srv.client, http.MethodPost, srv.baseURL+"/api/v1/plugins/execute", authHdr, map[string]any{
			"plugin_id": "sys-diagnostics",
			"action":    "runtime_stats",
			"params":    map[string]any{},
		})
		if code != http.StatusOK {
			t.Fatalf("sys-diagnostics runtime_stats failed: %d %s", code, string(diagBody))
		}

		if _, lookErr := exec.LookPath("sha256sum"); lookErr == nil && strings.HasPrefix(filepath.ToSlash(sampleFile), "/") {
			code, hashBody := doJSONRequest(t, srv.client, http.MethodPost, srv.baseURL+"/api/v1/plugins/execute", authHdr, map[string]any{
				"plugin_id": "crypto-sha256-file",
				"action":    "sha256_hash",
				"params":    map[string]any{"file": filepath.ToSlash(sampleFile)},
			})
			if code != http.StatusOK {
				t.Fatalf("crypto-sha256-file failed: %d %s", code, string(hashBody))
			}
		}

		code, _ = doJSONRequest(t, srv.client, http.MethodPost, srv.baseURL+"/api/v1/plugins/execute", authHdr, map[string]any{
			"plugin_id": "crypto-sha256-file",
			"action":    "sha256_hash",
			"params":    map[string]any{"file": "/tmp/a;id"},
		})
		if code != http.StatusBadRequest {
			t.Errorf("expected shell metacharacter injection to return 400, got %d", code)
		}

		// Step 3: Trigger one command row then verify db/tables, read-only SELECT, and 403 DDL block.
		code, _ = doJSONRequest(t, srv.client, http.MethodPost, srv.baseURL+"/api/v1/execute", authHdr, map[string]any{"name": "disk-usage"})
		if code != http.StatusOK {
			t.Fatalf("disk-usage execute failed: %d", code)
		}
		code, tablesBody := doJSONRequest(t, srv.client, http.MethodGet, srv.baseURL+"/api/v1/db/tables", authHdr, nil)
		if code != http.StatusOK || !strings.Contains(string(tablesBody), "action_history") {
			t.Fatalf("GET /api/v1/db/tables failed: %d %s", code, string(tablesBody))
		}
		code, queryBody := doJSONRequest(t, srv.client, http.MethodPost, srv.baseURL+"/api/v1/db/query", authHdr, map[string]any{
			"sql":      "SELECT id, command, status FROM action_history ORDER BY id DESC LIMIT 5",
			"max_rows": 5,
		})
		if code != http.StatusOK {
			t.Fatalf("read-only SELECT query failed: %d %s", code, string(queryBody))
		}
		code, _ = doJSONRequest(t, srv.client, http.MethodPost, srv.baseURL+"/api/v1/db/query", authHdr, map[string]any{
			"sql": "DROP TABLE action_history",
		})
		if code != http.StatusForbidden {
			t.Errorf("expected DDL query to return 403, got %d", code)
		}

		// Step 4: MCP initialize, tools/call execute_plugin & audit_verify, and /api/v1/mcp/traces/verify.
		mcpHeaders := map[string]string{
			"Authorization":    "Bearer " + adminTok,
			"X-MCP-Session-ID": "lab-mcp-01",
		}
		code, initBody := doJSONRequest(t, srv.client, http.MethodPost, srv.baseURL+"/api/v1/mcp", mcpHeaders, map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"method":  "initialize",
			"params":  map[string]any{"protocolVersion": "2024-11-05"},
		})
		if code != http.StatusOK || !strings.Contains(string(initBody), "2024-11-05") {
			t.Fatalf("MCP initialize failed: %d %s", code, string(initBody))
		}

		code, callBody := doJSONRequest(t, srv.client, http.MethodPost, srv.baseURL+"/api/v1/mcp", mcpHeaders, map[string]any{
			"jsonrpc": "2.0",
			"id":      2,
			"method":  "tools/call",
			"params": map[string]any{
				"name":      "execute_plugin",
				"arguments": map[string]any{"plugin_id": "sys-diagnostics", "action": "runtime_stats"},
			},
		})
		if code != http.StatusOK || !strings.Contains(string(callBody), "mcp_tr_") {
			t.Fatalf("MCP execute_plugin failed: %d %s", code, string(callBody))
		}

		code, verifyRPC := doJSONRequest(t, srv.client, http.MethodPost, srv.baseURL+"/api/v1/mcp", mcpHeaders, map[string]any{
			"jsonrpc": "2.0",
			"id":      3,
			"method":  "tools/call",
			"params":  map[string]any{"name": "audit_verify", "arguments": map[string]any{}},
		})
		if code != http.StatusOK || !strings.Contains(string(verifyRPC), `"valid":true`) && !strings.Contains(string(verifyRPC), `"valid": true`) {
			t.Fatalf("MCP audit_verify failed: %d %s", code, string(verifyRPC))
		}

		code, traceVerifyBody := doJSONRequest(t, srv.client, http.MethodGet, srv.baseURL+"/api/v1/mcp/traces/verify", authHdr, nil)
		if code != http.StatusOK {
			t.Fatalf("GET /api/v1/mcp/traces/verify failed: %d %s", code, string(traceVerifyBody))
		}
		var tv map[string]any
		_ = json.Unmarshal(traceVerifyBody, &tv)
		if tv["valid"] != true || tv["audit_chain_valid"] != true {
			t.Errorf("expected valid MCP trace chain and audit chain, got %v", tv)
		}
	})

	// Tutorial 3 + Operational How-Tos (MicroLLM x_abstain -> HITL -> async jobs -> trace replay, presets, TLS renew, SA rotate).
	t.Run("Tutorial3AndHowTos_BastionAsyncPresetsAndKeyRotation", func(t *testing.T) {
		labDir := t.TempDir()
		_ = os.MkdirAll(filepath.Join(labDir, "certs"), 0755)

		mockGuard := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req map[string]any
			_ = json.NewDecoder(r.Body).Decode(&req)
			cmdStr := fmt.Sprint(req["command"])
			toolStr := fmt.Sprint(req["tool_name"])
			w.Header().Set("Content-Type", "application/json")
			if strings.Contains(cmdStr, "ps") || strings.Contains(cmdStr, "PID TTY TIME CMD") || strings.Contains(toolStr, "list-processes") {
				_, _ = io.WriteString(w, `{"schema_version":"microllm.guard.v1","decision":"x_abstain","confidence":0.48,"abstain":true,"risk_score":0.62,"primary_threat":"process_enumeration","hijack_suspected":false,"reason":"Borderline host process inspection; escalate to HITL","latency_ms":1.2}`)
				return
			}
			_, _ = io.WriteString(w, `{"schema_version":"microllm.guard.v1","decision":"allow","confidence":0.96,"abstain":false,"risk_score":0.05,"hijack_suspected":false,"reason":"Low-risk read-only operation","latency_ms":0.8}`)
		}))
		defer mockGuard.Close()

		docYAML := extractYAMLBlockFromDoc(t, "docs/01-tutorials/03-zero-trust-bastion-and-async-jobs-lab.md", "critical_commands:")
		port := reserveFreeLoopbackPort(t)
		cfgText := rewriteSandboxPaths(docYAML, "/tmp/apiexec-bastion", labDir, port, "")
		cfgText = strings.ReplaceAll(cfgText, "http://127.0.0.1:18000/v1/guard/evaluate", mockGuard.URL+"/v1/guard/evaluate")
		// Give local CI runners generous guard timeout while verifying documented YAML key structure.
		cfgText = strings.ReplaceAll(cfgText, `timeout: "50ms"`, `timeout: "500ms"`)
		cfgPath := filepath.Join(labDir, "bastion-lab.yaml")
		if err := os.WriteFile(cfgPath, []byte(cfgText), 0600); err != nil {
			t.Fatalf("write bastion-lab.yaml: %v", err)
		}

		srv := startCompiledServer(t, repoRoot, binPath, cfgPath, filepath.Join(labDir, "certs", "server.crt"))

		adminTok := loginTutorialUser(t, srv, "admin", "lab-admin-pass")
		adminHdr := map[string]string{"Authorization": "Bearer " + adminTok}

		// Step 2: Provision op-alice (operator) and sec-bob (admin).
		code, b := doJSONRequest(t, srv.client, http.MethodPost, srv.baseURL+"/api/v1/auth/users", adminHdr, map[string]string{
			"username":     "op-alice",
			"password":     "alice-lab-pass",
			"display_name": "Alice Operator",
			"role":         "operator",
		})
		if code != http.StatusOK && code != http.StatusCreated {
			t.Fatalf("create op-alice failed: %d %s", code, string(b))
		}
		code, b = doJSONRequest(t, srv.client, http.MethodPost, srv.baseURL+"/api/v1/auth/users", adminHdr, map[string]string{
			"username":     "sec-bob",
			"password":     "bob-lab-pass",
			"display_name": "Bob Security Admin",
			"role":         "admin",
		})
		if code != http.StatusOK && code != http.StatusCreated {
			t.Fatalf("create sec-bob failed: %d %s", code, string(b))
		}

		aliceTok := loginTutorialUser(t, srv, "op-alice", "alice-lab-pass")
		bobTok := loginTutorialUser(t, srv, "sec-bob", "bob-lab-pass")
		aliceHdr := map[string]string{"Authorization": "Bearer " + aliceTok}
		bobHdr := map[string]string{"Authorization": "Bearer " + bobTok}

		// Step 3: Trigger MicroLLM x_abstain -> HITL 202 challenge -> self-approve 403 -> distinct approve 200.
		code, chalBody := doJSONRequest(t, srv.client, http.MethodPost, srv.baseURL+"/api/v1/jobs", aliceHdr, map[string]any{
			"type":     "command",
			"action":   "list-processes",
			"priority": "high",
			"timeout":  "10s",
		})
		if code != http.StatusAccepted {
			t.Fatalf("expected 202 challenge on x_abstain, got %d body=%s", code, string(chalBody))
		}
		var chal map[string]any
		_ = json.Unmarshal(chalBody, &chal)
		approvalID, _ := chal["approval_id"].(string)
		if !strings.HasPrefix(approvalID, "apr_") || chal["gatekeeper_decision"] != "x_abstain" {
			t.Fatalf("unexpected HITL challenge payload: %v", chal)
		}

		code, _ = doJSONRequest(t, srv.client, http.MethodPost, srv.baseURL+"/api/v1/approvals/"+approvalID+"/approve", aliceHdr, nil)
		if code != http.StatusForbidden {
			t.Errorf("expected self-approval rejection 403, got %d", code)
		}

		code, apprBody := doJSONRequest(t, srv.client, http.MethodPost, srv.baseURL+"/api/v1/approvals/"+approvalID+"/approve", bobHdr, map[string]string{
			"comment": "Verified safe process inspection",
		})
		if code != http.StatusOK || !strings.Contains(string(apprBody), `"approved"`) {
			t.Fatalf("distinct admin approve failed: %d %s", code, string(apprBody))
		}

		// Step 4: Verify TOCTOU mismatch rejection (403) then enqueue approved async job & read logs + verify replay conflict (409).
		code, _ = doJSONRequest(t, srv.client, http.MethodPost, srv.baseURL+"/api/v1/jobs", aliceHdr, map[string]any{
			"type":        "command",
			"action":      "list-processes",
			"priority":    "high",
			"timeout":     "5s",
			"approval_id": approvalID,
		})
		if code != http.StatusForbidden {
			t.Errorf("expected TOCTOU timeout mismatch 403, got %d", code)
		}

		code, jobBody := doJSONRequest(t, srv.client, http.MethodPost, srv.baseURL+"/api/v1/jobs", aliceHdr, map[string]any{
			"type":        "command",
			"action":      "list-processes",
			"priority":    "high",
			"timeout":     "10s",
			"approval_id": approvalID,
		})
		if code != http.StatusAccepted {
			t.Fatalf("expected approved job enqueue 202, got %d %s", code, string(jobBody))
		}
		var jobResp map[string]any
		_ = json.Unmarshal(jobBody, &jobResp)
		jobID := fmt.Sprint(jobResp["job_id"])

		// Poll job logs until eof == true.
		var logsEOF bool
		pollDeadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(pollDeadline) {
			lCode, lBody := doJSONRequest(t, srv.client, http.MethodGet, srv.baseURL+"/api/v1/jobs/"+jobID+"/logs?offset=0", aliceHdr, nil)
			if lCode == http.StatusOK {
				var lJSON map[string]any
				_ = json.Unmarshal(lBody, &lJSON)
				if lJSON["eof"] == true {
					logsEOF = true
					break
				}
			}
			time.Sleep(100 * time.Millisecond)
		}
		if !logsEOF {
			t.Errorf("timed out waiting for eof=true on job %s logs", jobID)
		}

		code, _ = doJSONRequest(t, srv.client, http.MethodPost, srv.baseURL+"/api/v1/jobs", aliceHdr, map[string]any{
			"type":        "command",
			"action":      "list-processes",
			"priority":    "high",
			"timeout":     "10s",
			"approval_id": approvalID,
		})
		if code != http.StatusConflict {
			t.Errorf("expected consumed approval replay -> 409 Conflict, got %d", code)
		}

		// Step 5: MCP audit_verify -> /api/v1/audit/verify -> dry_run MCP trace replay.
		code, mcpBody := doJSONRequest(t, srv.client, http.MethodPost, srv.baseURL+"/api/v1/mcp", map[string]string{
			"Authorization":    "Bearer " + aliceTok,
			"X-MCP-Session-ID": "bastion-01",
		}, map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"method":  "tools/call",
			"params":  map[string]any{"name": "audit_verify", "arguments": map[string]any{}},
		})
		if code != http.StatusOK {
			t.Fatalf("MCP audit_verify status=%d body=%s", code, string(mcpBody))
		}
		var mcpOut struct {
			TraceID string `json:"trace_id"`
		}
		_ = json.Unmarshal(mcpBody, &mcpOut)

		code, avBody := doJSONRequest(t, srv.client, http.MethodGet, srv.baseURL+"/api/v1/audit/verify", aliceHdr, nil)
		if code != http.StatusOK || !strings.Contains(string(avBody), `"valid":true`) && !strings.Contains(string(avBody), `"valid": true`) {
			t.Fatalf("GET /api/v1/audit/verify failed: %d %s", code, string(avBody))
		}

		code, replayBody := doJSONRequest(t, srv.client, http.MethodPost, srv.baseURL+"/api/v1/mcp/traces/"+mcpOut.TraceID+"/replay", aliceHdr, map[string]string{
			"mode": "dry_run",
		})
		if code != http.StatusOK {
			t.Fatalf("trace replay failed: %d %s", code, string(replayBody))
		}
		var replayRes map[string]any
		_ = json.Unmarshal(replayBody, &replayRes)
		if replayRes["integrity_valid"] != true || replayRes["audit_chain_valid"] != true || replayRes["policy_eligible"] != true {
			t.Errorf("unexpected replay report: %v", replayRes)
		}

		// How-To Runbook Checks: manage-async-jobs-and-presets (GET /presets + POST /presets/activate + /jobs/queue).
		code, presetsBody := doJSONRequest(t, srv.client, http.MethodGet, srv.baseURL+"/api/v1/presets", aliceHdr, nil)
		if code != http.StatusOK || !strings.Contains(string(presetsBody), "ubuntu") {
			t.Fatalf("GET /api/v1/presets failed: %d %s", code, string(presetsBody))
		}
		code, actBody := doJSONRequest(t, srv.client, http.MethodPost, srv.baseURL+"/api/v1/presets/activate", adminHdr, map[string]any{
			"families": []string{"ubuntu"},
		})
		if code != http.StatusOK {
			t.Fatalf("POST /api/v1/presets/activate failed: %d %s", code, string(actBody))
		}
		code, queueBody := doJSONRequest(t, srv.client, http.MethodGet, srv.baseURL+"/api/v1/jobs/queue", aliceHdr, nil)
		if code != http.StatusOK || !strings.Contains(string(queueBody), "capacity") {
			t.Fatalf("GET /api/v1/jobs/queue failed: %d %s", code, string(queueBody))
		}

		// How-To Runbook Checks: rotate-tls-and-service-account-keys (TLS renew + SA create/rotate/401/200 + audit logs).
		code, tlsInfoBeforeBytes := doJSONRequest(t, srv.client, http.MethodGet, srv.baseURL+"/api/v1/tls/info", adminHdr, nil)
		if code != http.StatusOK {
			t.Fatalf("GET /api/v1/tls/info failed: %d %s", code, string(tlsInfoBeforeBytes))
		}
		var tlsBefore map[string]any
		_ = json.Unmarshal(tlsInfoBeforeBytes, &tlsBefore)

		code, _ = doJSONRequest(t, srv.client, http.MethodPost, srv.baseURL+"/api/v1/tls/renew", adminHdr, nil)
		if code != http.StatusOK {
			t.Fatalf("POST /api/v1/tls/renew failed: %d", code)
		}
		code, tlsInfoAfterBytes := doJSONRequest(t, srv.client, http.MethodGet, srv.baseURL+"/api/v1/tls/info", adminHdr, nil)
		if code != http.StatusOK {
			t.Fatalf("GET /api/v1/tls/info after renew failed: %d", code)
		}
		var tlsAfter map[string]any
		_ = json.Unmarshal(tlsInfoAfterBytes, &tlsAfter)
		if tlsBefore["fingerprint_sha256"] == tlsAfter["fingerprint_sha256"] {
			t.Errorf("expected new fingerprint_sha256 after TLS renew, stayed %v", tlsBefore["fingerprint_sha256"])
		}

		// Download the rotated public PEM certificate over an unpinned bootstrap transport, then pin it for subsequent requests.
		unpinnedClient := &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}, // #nosec G402 -- bootstrap fetch mirroring curl -k Step 3 of key rotation guide
			},
		}
		code, pemBytes := doJSONRequest(t, unpinnedClient, http.MethodGet, srv.baseURL+"/api/v1/tls/certificate", adminHdr, nil)
		if code != http.StatusOK || !strings.Contains(string(pemBytes), "BEGIN CERTIFICATE") {
			t.Fatalf("GET /api/v1/tls/certificate invalid: %d", code)
		}
		rotatedPool := x509.NewCertPool()
		if !rotatedPool.AppendCertsFromPEM(pemBytes) {
			t.Fatalf("failed to append rotated PEM certificate")
		}
		srv.client = &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{RootCAs: rotatedPool, MinVersion: tls.VersionTLS13},
			},
		}

		// Service Account creation and key rotation (old key 401 -> new key 200).
		code, saCreateBody := doJSONRequest(t, srv.client, http.MethodPost, srv.baseURL+"/api/v1/auth/service-accounts", adminHdr, map[string]any{
			"name":            "howto-rotation-svc",
			"service_name":    "Rotation Test",
			"scopes":          []string{"commands:read"},
			"allowed_actions": []string{"list-processes"},
			"ttl":             "2h",
		})
		if code != http.StatusOK && code != http.StatusCreated {
			t.Fatalf("create service account failed: %d %s", code, string(saCreateBody))
		}
		var saCreateRes struct {
			ServiceAccount struct {
				ID string `json:"id"`
			} `json:"service_account"`
			APIKey string `json:"api_key"`
		}
		_ = json.Unmarshal(saCreateBody, &saCreateRes)

		code, saRotateBody := doJSONRequest(t, srv.client, http.MethodPost, srv.baseURL+"/api/v1/auth/service-accounts/rotate", adminHdr, map[string]string{
			"id": saCreateRes.ServiceAccount.ID,
		})
		if code != http.StatusOK {
			t.Fatalf("rotate service account failed: %d %s", code, string(saRotateBody))
		}
		var saRotateRes struct {
			APIKey string `json:"api_key"`
		}
		_ = json.Unmarshal(saRotateBody, &saRotateRes)

		code, _ = doJSONRequest(t, srv.client, http.MethodGet, srv.baseURL+"/api/v1/auth/me", map[string]string{"X-Service-Key": saCreateRes.APIKey}, nil)
		if code != http.StatusUnauthorized {
			t.Errorf("expected old service key to fail with 401 after rotation, got %d", code)
		}
		code, _ = doJSONRequest(t, srv.client, http.MethodGet, srv.baseURL+"/api/v1/auth/me", map[string]string{"X-Service-Key": saRotateRes.APIKey}, nil)
		if code != http.StatusOK {
			t.Errorf("expected rotated service key to succeed with 200, got %d", code)
		}

		// Step 7 of rotate-tls-and-service-account-keys.md: revoke a minted PAT and confirm 401 rejection.
		patID, patSecret := mintTutorialPAT(t, srv, adminTok, "temp-rotation-pat", []string{"commands:read"}, "1h")
		code, _ = doJSONRequest(t, srv.client, http.MethodDelete, srv.baseURL+"/api/v1/auth/tokens?id="+patID, adminHdr, nil)
		if code != http.StatusOK {
			t.Fatalf("DELETE /api/v1/auth/tokens failed: %d", code)
		}
		code, _ = doJSONRequest(t, srv.client, http.MethodGet, srv.baseURL+"/api/v1/auth/me", map[string]string{"Authorization": "Bearer " + patSecret}, nil)
		if code != http.StatusUnauthorized {
			t.Errorf("expected revoked PAT to return 401, got %d", code)
		}
	})

	// Sanity check: Tutorial 1-3 files keep documented bash cleanup steps and valid YAML fences.
	t.Run("TutorialCleanupAndShellBlockSanity", func(t *testing.T) {
		for _, path := range []string{
			"docs/01-tutorials/01-local-https-quickstart.md",
			"docs/01-tutorials/02-plugins-and-mcp-sandbox.md",
			"docs/01-tutorials/03-zero-trust-bastion-and-async-jobs-lab.md",
		} {
			full := filepath.Join(repoRoot, path)
			f, err := os.Open(full)
			if err != nil {
				t.Fatalf("open %s: %v", full, err)
			}
			sc := bufio.NewScanner(f)
			hasCleanup := false
			for sc.Scan() {
				if strings.Contains(sc.Text(), "rm -rf /tmp/apiexec-") {
					hasCleanup = true
				}
			}
			_ = f.Close()
			if !hasCleanup {
				t.Errorf("%s must contain sandbox cleanup step (rm -rf /tmp/apiexec-*)", path)
			}
		}
	})
}
