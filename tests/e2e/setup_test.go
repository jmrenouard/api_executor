package e2e_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"go-admin-tool/internal/api"
	"go-admin-tool/internal/audit"
	"go-admin-tool/internal/auth"
	"go-admin-tool/internal/core"
	"go-admin-tool/internal/database"
	"go-admin-tool/internal/jobs"
	"go-admin-tool/internal/mcp"
	"go-admin-tool/internal/plugins"
)

// e2eTestServer encapsulates a live HTTP test server and authenticated principals.
type e2eTestServer struct {
	ts           *httptest.Server
	baseURL      string
	client       *http.Client
	db           *database.DB
	auditLogger  *audit.AuditLogger
	authMgr      *auth.Manager
	pluginReg    *plugins.Registry
	jobEngine    *jobs.Engine
	adminPAT     string
	operatorPAT  string
	viewerPAT    string
	scopedSvcPAT string
}

func (s *e2eTestServer) Close() {
	if s.jobEngine != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_ = s.jobEngine.Shutdown(ctx)
		cancel()
	}
	if s.ts != nil {
		s.ts.Close()
	}
	if s.db != nil {
		s.db.Close()
	}
}

// setupE2ETestServer initializes an ephemeral, opaque HTTP server with default engine config.
func setupE2ETestServer(t *testing.T) *e2eTestServer {
	return setupCustomE2ETestServer(t, jobs.DefaultEngineConfig())
}

// setupCustomE2ETestServer initializes an ephemeral HTTP server with customized engine config.
func setupCustomE2ETestServer(t *testing.T, engineCfg jobs.EngineConfig) *e2eTestServer {
	t.Helper()

	api.ResetActionMetrics()

	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "e2e_test.db")
	db, err := database.NewDB(dbPath)
	if err != nil {
		t.Fatalf("setupE2ETestServer: failed to create SQLite db: %v", err)
	}
	if err := db.Init(); err != nil {
		t.Fatalf("setupE2ETestServer: failed to initialize SQLite db: %v", err)
	}

	appCfg := core.DefaultConfig()
	appCfg.Server.TLS.Enabled = false
	appCfg.Audit.Enabled = true
	appCfg.Audit.MaxMemoryLog = 1000
	appCfg.Auth.Enabled = true
	appCfg.Auth.StorePath = filepath.Join(tempDir, "auth.json")
	appCfg.Auth.BootstrapUsername = "e2e_admin"
	appCfg.Auth.BootstrapPassword = "AdminSecurePassword123!"
	appCfg.Executor.Enabled = true
	appCfg.Executor.MaxTimeoutSeconds = 60

	// Register cross-platform test commands
	cmdEchoName, baseEchoArgs := crossPlatformEcho()
	fastCmdArgs := append(append([]string{}, baseEchoArgs...), "hello-async")
	cmdEcho2Args := append(append([]string{}, baseEchoArgs...), "e2e-async-output")

	blockCmd := "sleep"
	blockArgs := []string{"2"}
	slowCmd := "sleep"
	slowArgs := []string{"5"}
	slowDiagCmd := "sleep"
	slowDiagArgs := []string{"10"}

	if runtime.GOOS == "windows" {
		blockCmd = "cmd"
		blockArgs = []string{"/C", "ping", "-n", "3", "127.0.0.1"}
		slowCmd = "cmd"
		slowArgs = []string{"/C", "ping", "-n", "6", "127.0.0.1"}
		slowDiagCmd = "cmd"
		slowDiagArgs = []string{"/C", "ping", "-n", "10", "127.0.0.1"}
	}

	appCfg.Executor.Commands = []core.CommandDefinition{
		{Name: "test-echo", Command: cmdEchoName, Args: fastCmdArgs},
		{Name: "echo-cmd", Command: cmdEchoName, Args: cmdEcho2Args},
		{Name: "test-block", Command: blockCmd, Args: blockArgs},
		{Name: "slow-cmd", Command: slowCmd, Args: slowArgs},
		{Name: "slow-diag-cmd", Command: slowDiagCmd, Args: slowDiagArgs},
	}

	logger, err := core.NewLogger(appCfg.Logging)
	if err != nil {
		t.Fatalf("setupE2ETestServer: failed to initialize logger: %v", err)
	}

	auditLogger, err := audit.NewAuditLogger(appCfg.Audit, db, logger)
	if err != nil {
		t.Fatalf("setupE2ETestServer: failed to initialize audit logger: %v", err)
	}

	authMgr, err := auth.NewManager(appCfg.Auth)
	if err != nil {
		t.Fatalf("setupE2ETestServer: failed to initialize auth manager: %v", err)
	}

	// Create human users
	adminUser, err := authMgr.CreateUser("e2e_admin_user", "Admin1234!", "E2E Administrator", "admin@e2e.test", auth.RoleAdmin)
	if err != nil && !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("setupE2ETestServer: failed to create admin user: %v", err)
	}
	operatorUser, err := authMgr.CreateUser("e2e_operator", "Operator1234!", "E2E Operator", "op@e2e.test", auth.RoleOperator)
	if err != nil && !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("setupE2ETestServer: failed to create operator user: %v", err)
	}
	viewerUser, err := authMgr.CreateUser("e2e_viewer", "Viewer1234!", "E2E Viewer", "viewer@e2e.test", auth.RoleViewer)
	if err != nil && !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("setupE2ETestServer: failed to create viewer user: %v", err)
	}

	// Issue PATs with async scopes
	_, adminPAT, err := authMgr.CreateToken(adminUser.ID, "admin-pat", []string{"*"}, 24*time.Hour)
	if err != nil {
		t.Fatalf("setupE2ETestServer: failed to create admin token: %v", err)
	}
	_, operatorPAT, err := authMgr.CreateToken(operatorUser.ID, "operator-pat", []string{
		"commands:execute", "plugins:read", "plugins:execute", "jobs:submit", "jobs:read", "jobs:cancel",
	}, 24*time.Hour)
	if err != nil {
		t.Fatalf("setupE2ETestServer: failed to create operator token: %v", err)
	}
	_, viewerPAT, err := authMgr.CreateToken(viewerUser.ID, "viewer-pat", []string{
		"commands:read", "plugins:read", "audit:read", "jobs:read",
	}, 24*time.Hour)
	if err != nil {
		t.Fatalf("setupE2ETestServer: failed to create viewer token: %v", err)
	}

	// Issue Scoped Service Account (allowed only for sys-diagnostics actions)
	_, scopedSvcPAT, err := authMgr.CreateServiceAccount(
		"sys-diagnostics-svc",
		"SysOps Service",
		"Scoped service account for system diagnostics only",
		[]string{"plugins:execute", "plugins:read", "jobs:submit", "jobs:read"},
		[]string{"plugin:sys-diagnostics:*", "sys-diagnostics"},
		24*time.Hour,
	)
	if err != nil {
		t.Fatalf("setupE2ETestServer: failed to create scoped service account: %v", err)
	}

	// Initialize plugin registry
	pluginReg := plugins.NewRegistry()
	_ = pluginReg.Register(plugins.NewSystemDiagnosticsPlugin())
	_ = pluginReg.Register(plugins.NewDatabaseExposurePlugin(db, 200))
	if opsPlugin, err := plugins.DefaultDeclarativeOpsPlugin(); err == nil {
		_ = pluginReg.Register(opsPlugin)
	}

	// Discover and load plugins from filesystem if available (visiting each manifest directory once)
	visitedDirs := make(map[string]bool)
	for _, candidate := range []string{"plugins", "../../plugins", "../plugins"} {
		if fi, err := os.Stat(candidate); err == nil && fi.IsDir() {
			_ = filepath.WalkDir(candidate, func(path string, d os.DirEntry, walkErr error) error {
				if walkErr != nil || d.IsDir() {
					return nil
				}
				ext := strings.ToLower(filepath.Ext(d.Name()))
				if ext == ".yaml" || ext == ".yml" || ext == ".json" {
					dir := filepath.Dir(path)
					if !visitedDirs[dir] {
						visitedDirs[dir] = true
						_, _ = pluginReg.LoadDeclarativeDirectory(dir)
					}
				}
				return nil
			})
			break
		}
	}

	// Populate synthetic domain catalog for scaling verification (up to 300 plugins across 10 domains)
	populateDomainCatalogFixtures(pluginReg)

	mcpServer, err := mcp.NewServer(
		appCfg.MCP,
		appCfg,
		db,
		nil,
		pluginReg,
		auditLogger,
		logger,
		api.RecordActionCall,
	)
	if err != nil {
		t.Fatalf("setupE2ETestServer: failed to initialize MCP server: %v", err)
	}

	var env *api.APIEnv

	// Real subprocess and plugin executor for async jobs
	jobExecutor := func(ctx context.Context, job *jobs.Job, logWriter io.Writer) (any, error) {
		switch job.Type {
		case jobs.TypeCommand:
			cmdCopy, found := env.FindCommand(job.Action)
			if !found {
				return nil, fmt.Errorf("command %q not found", job.Action)
			}
			timeout := job.Timeout
			if timeout <= 0 {
				timeout = cmdCopy.EffectiveTimeout(core.DefaultCommandTimeout)
			}
			output, execErr := core.ExecuteCommandWithContext(ctx, cmdCopy, timeout, logWriter)
			return map[string]any{"output": output}, execErr
		case jobs.TypePlugin:
			if pluginReg == nil {
				return nil, errors.New("plugin registry is not initialized")
			}
			res, execErr := pluginReg.Execute(ctx, job.PluginID, job.Action, job.Params, job.Timeout)
			if logWriter != nil && res.Output != "" {
				_, _ = logWriter.Write([]byte(res.Output))
			}
			return res, execErr
		default:
			return nil, fmt.Errorf("unsupported job type: %s", job.Type)
		}
	}

	jobStore, err := jobs.NewJobStore(db)
	if err != nil {
		jobStore = jobs.NewMemoryJobStore()
	}

	jobEngine, err := jobs.NewEngine(engineCfg, jobStore, auditLogger, jobExecutor)
	if err != nil {
		t.Fatalf("setupE2ETestServer: failed to initialize async job engine: %v", err)
	}
	jobEngine.SetMetricsReporter(api.NewJobMetricsReporter())
	if err := jobEngine.Start(); err != nil {
		t.Fatalf("setupE2ETestServer: failed to start async job engine: %v", err)
	}

	env = &api.APIEnv{
		Config:         appCfg,
		Logger:         logger,
		DB:             db,
		AuditLogger:    auditLogger,
		AuthManager:    authMgr,
		PluginRegistry: pluginReg,
		MCPServer:      mcpServer,
		JobEngine:      jobEngine,
	}

	router := api.NewRouter(env)
	ts := httptest.NewServer(router)

	client := &http.Client{
		Timeout: 15 * time.Second,
	}

	srv := &e2eTestServer{
		ts:           ts,
		baseURL:      ts.URL,
		client:       client,
		db:           db,
		auditLogger:  auditLogger,
		authMgr:      authMgr,
		pluginReg:    pluginReg,
		jobEngine:    jobEngine,
		adminPAT:     adminPAT,
		operatorPAT:  operatorPAT,
		viewerPAT:    viewerPAT,
		scopedSvcPAT: scopedSvcPAT,
	}

	t.Cleanup(func() {
		srv.Close()
	})

	return srv
}

// 10 operational domains defined in ORIGINAL_REQUEST.md & PROJECT.md
var operationalDomains = []string{
	"SysAdmin",
	"NetOps",
	"SecOps",
	"ContainerOps",
	"Kubernetes",
	"DataOps",
	"DevOps",
	"SRE",
	"AIOps",
	"WebUtils",
}

func crossPlatformEcho() (string, []string) {
	if runtime.GOOS == "windows" {
		return "cmd", []string{"/C", "echo"}
	}
	return "echo", []string{}
}

// populateDomainCatalogFixtures guarantees at least 300 registered plugins across 10 domains
// so that Tier 1-4 tests can verify catalog scaling and multi-domain operations reliably.
func populateDomainCatalogFixtures(reg *plugins.Registry) {
	currentList := reg.List()
	existingCount := len(currentList)
	if existingCount >= 300 {
		return
	}

	targetTotal := 305
	needed := targetTotal - existingCount
	pluginsPerDomain := (needed / len(operationalDomains)) + 1

	cmd, baseArgs := crossPlatformEcho()

	for _, domain := range operationalDomains {
		prefix := strings.ToLower(domain)
		for i := 1; i <= pluginsPerDomain; i++ {
			pluginID := fmt.Sprintf("%s-check-%03d", prefix, i)
			if _, exists := reg.Get(pluginID); exists {
				continue
			}
			runArgs := append([]string{}, baseArgs...)
			runArgs = append(runArgs, "status=healthy", "domain="+domain, "probe={{probe_id}}")

			statusArgs := append([]string{}, baseArgs...)
			statusArgs = append(statusArgs, "ok")

			spec := plugins.DeclarativeModuleSpec{
				ID:          pluginID,
				Name:        fmt.Sprintf("%s Automated Diagnostic %03d", domain, i),
				Version:     "1.0.0",
				Description: fmt.Sprintf("Production telemetry probe for %s domain operations (%03d)", domain, i),
				Actions: []plugins.DeclarativeActionSpec{
					{
						Name:        "run-check",
						Description: fmt.Sprintf("Execute operational probe for %s", pluginID),
						Command:     cmd,
						Args:        runArgs,
						Timeout:     "5s",
						Parameters: []plugins.ActionParameter{
							{
								Name:        "probe_id",
								Type:        "string",
								Required:    false,
								Default:     "default-probe",
								Pattern:     `^[a-zA-Z0-9._-]+$`,
								Description: "Target probe identifier",
							},
						},
					},
					{
						Name:        "get-status",
						Description: fmt.Sprintf("Retrieve current telemetry status for %s", pluginID),
						Command:     cmd,
						Args:        statusArgs,
						Timeout:     "3s",
					},
				},
			}
			_, _ = reg.RegisterDeclarativeModule(spec)
			if len(reg.List()) >= targetTotal {
				return
			}
		}
	}
}

// HTTP Helper Functions for Opaque-Box Endpoint Testing

// E2EPluginInfo represents the wire JSON schema of a plugin returned by the REST API and MCP.
type E2EPluginInfo struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Version     string                 `json:"version"`
	Kind        string                 `json:"kind"`
	Type        string                 `json:"type"`
	Category    string                 `json:"category"`
	Description string                 `json:"description"`
	Actions     []plugins.PluginAction `json:"actions"`
}

type pluginsListResponse struct {
	Plugins []E2EPluginInfo `json:"plugins"`
	Error   string          `json:"error,omitempty"`
}

func httpGetPlugins(t *testing.T, srv *e2eTestServer, token string, query string) (int, pluginsListResponse) {
	t.Helper()
	url := srv.baseURL + "/api/v1/plugins"
	if query != "" {
		if !strings.HasPrefix(query, "?") {
			query = "?" + query
		}
		url += query
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("httpGetPlugins: failed to create request: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := srv.client.Do(req)
	if err != nil {
		t.Fatalf("httpGetPlugins: network error calling %s: %v", url, err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("httpGetPlugins: failed to read response body: %v", err)
	}

	var res pluginsListResponse
	_ = json.Unmarshal(bodyBytes, &res)
	if resp.StatusCode != http.StatusOK && res.Error == "" {
		var errObj struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(bodyBytes, &errObj) == nil && errObj.Error != "" {
			res.Error = errObj.Error
		} else {
			res.Error = string(bodyBytes)
		}
	}
	return resp.StatusCode, res
}

func httpExecutePlugin(t *testing.T, srv *e2eTestServer, token string, payload any) (int, plugins.PluginResult, string) {
	t.Helper()
	var bodyReader io.Reader
	if rawStr, ok := payload.(string); ok {
		bodyReader = strings.NewReader(rawStr)
	} else if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("httpExecutePlugin: failed to marshal payload: %v", err)
		}
		bodyReader = bytes.NewReader(b)
	}

	url := srv.baseURL + "/api/v1/plugins/execute"
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, bodyReader)
	if err != nil {
		t.Fatalf("httpExecutePlugin: failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := srv.client.Do(req)
	if err != nil {
		t.Fatalf("httpExecutePlugin: network error calling %s: %v", url, err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("httpExecutePlugin: failed to read response body: %v", err)
	}

	var res plugins.PluginResult
	_ = json.Unmarshal(bodyBytes, &res)
	return resp.StatusCode, res, string(bodyBytes)
}

func httpRegisterDeclarativePlugin(t *testing.T, srv *e2eTestServer, token string, spec any) (int, E2EPluginInfo, string) {
	t.Helper()
	var bodyReader io.Reader
	if rawStr, ok := spec.(string); ok {
		bodyReader = strings.NewReader(rawStr)
	} else if spec != nil {
		b, err := json.Marshal(spec)
		if err != nil {
			t.Fatalf("httpRegisterDeclarativePlugin: failed to marshal spec: %v", err)
		}
		bodyReader = bytes.NewReader(b)
	}

	url := srv.baseURL + "/api/v1/plugins/declarative"
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, bodyReader)
	if err != nil {
		t.Fatalf("httpRegisterDeclarativePlugin: failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := srv.client.Do(req)
	if err != nil {
		t.Fatalf("httpRegisterDeclarativePlugin: network error: %v", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("httpRegisterDeclarativePlugin: failed to read body: %v", err)
	}

	var info E2EPluginInfo
	_ = json.Unmarshal(bodyBytes, &info)
	return resp.StatusCode, info, string(bodyBytes)
}

func httpMCPCall(t *testing.T, srv *e2eTestServer, token string, rpcReq mcp.JSONRPCRequest) (int, mcp.JSONRPCResponse, string) {
	t.Helper()
	b, err := json.Marshal(rpcReq)
	if err != nil {
		t.Fatalf("httpMCPCall: failed to marshal JSON-RPC request: %v", err)
	}

	url := srv.baseURL + "/api/v1/mcp"
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		t.Fatalf("httpMCPCall: failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := srv.client.Do(req)
	if err != nil {
		t.Fatalf("httpMCPCall: network error: %v", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("httpMCPCall: failed to read response body: %v", err)
	}

	var rpcResp mcp.JSONRPCResponse
	_ = json.Unmarshal(bodyBytes, &rpcResp)
	return resp.StatusCode, rpcResp, string(bodyBytes)
}

func httpGetAuditLogs(t *testing.T, srv *e2eTestServer, token string, query string) (int, []audit.AuditEvent) {
	t.Helper()
	url := srv.baseURL + "/api/v1/audit/logs"
	if query != "" {
		if !strings.HasPrefix(query, "?") {
			query = "?" + query
		}
		url += query
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("httpGetAuditLogs: failed to create request: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := srv.client.Do(req)
	if err != nil {
		t.Fatalf("httpGetAuditLogs: network error: %v", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("httpGetAuditLogs: failed to read response: %v", err)
	}

	var res struct {
		Events []audit.AuditEvent `json:"events"`
	}
	_ = json.Unmarshal(bodyBytes, &res)
	return resp.StatusCode, res.Events
}

func httpVerifyAuditChain(t *testing.T, srv *e2eTestServer, token string) (int, audit.ChainVerificationResult) {
	t.Helper()
	url := srv.baseURL + "/api/v1/audit/verify"
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("httpVerifyAuditChain: failed to create request: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := srv.client.Do(req)
	if err != nil {
		t.Fatalf("httpVerifyAuditChain: network error: %v", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("httpVerifyAuditChain: failed to read response: %v", err)
	}

	var res audit.ChainVerificationResult
	_ = json.Unmarshal(bodyBytes, &res)
	return resp.StatusCode, res
}

func httpGetMetrics(t *testing.T, srv *e2eTestServer) (int, string) {
	t.Helper()
	url := srv.baseURL + "/metrics"
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("httpGetMetrics: failed to create request: %v", err)
	}

	resp, err := srv.client.Do(req)
	if err != nil {
		t.Fatalf("httpGetMetrics: network error: %v", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("httpGetMetrics: failed to read metrics body: %v", err)
	}
	return resp.StatusCode, string(bodyBytes)
}

func TestE2ESetup_PluginDirectorySinglePassLoading(t *testing.T) {
	srv := setupE2ETestServer(t)
	if srv == nil {
		t.Fatalf("expected non-nil e2eTestServer")
	}

	plugins := srv.pluginReg.List()
	if len(plugins) < 300 {
		t.Fatalf("expected at least 300 registered plugins, got %d", len(plugins))
	}

	status, res := httpGetPlugins(t, srv, srv.adminPAT, "")
	if status != http.StatusOK {
		t.Fatalf("expected 200 OK from httpGetPlugins, got %d: %s", status, res.Error)
	}
	if len(res.Plugins) < 300 {
		t.Fatalf("expected at least 300 plugins returned via REST API, got %d", len(res.Plugins))
	}
}

// Asynchronous Job HTTP Client Helpers

func httpSubmitJob(t *testing.T, srv *e2eTestServer, token string, payload any, extraHeaders ...map[string]string) (int, api.SubmitJobResponse, string) {
	t.Helper()
	var bodyReader io.Reader
	if rawStr, ok := payload.(string); ok {
		bodyReader = strings.NewReader(rawStr)
	} else if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("httpSubmitJob: failed to marshal payload: %v", err)
		}
		bodyReader = bytes.NewReader(b)
	}

	url := srv.baseURL + "/api/v1/jobs"
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, bodyReader)
	if err != nil {
		t.Fatalf("httpSubmitJob: failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for _, m := range extraHeaders {
		for k, v := range m {
			req.Header.Set(k, v)
		}
	}

	resp, err := srv.client.Do(req)
	if err != nil {
		t.Fatalf("httpSubmitJob: network error: %v", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("httpSubmitJob: failed to read body: %v", err)
	}

	var res api.SubmitJobResponse
	_ = json.Unmarshal(bodyBytes, &res)
	return resp.StatusCode, res, string(bodyBytes)
}

func httpGetJob(t *testing.T, srv *e2eTestServer, token string, jobID string, extraHeaders ...map[string]string) (int, *jobs.Job, string) {
	t.Helper()
	url := fmt.Sprintf("%s/api/v1/jobs/%s", srv.baseURL, jobID)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("httpGetJob: failed to create request: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for _, m := range extraHeaders {
		for k, v := range m {
			req.Header.Set(k, v)
		}
	}

	resp, err := srv.client.Do(req)
	if err != nil {
		t.Fatalf("httpGetJob: network error: %v", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("httpGetJob: failed to read body: %v", err)
	}

	var res jobs.Job
	if err := json.Unmarshal(bodyBytes, &res); err != nil {
		return resp.StatusCode, nil, string(bodyBytes)
	}
	return resp.StatusCode, &res, string(bodyBytes)
}

func httpListJobs(t *testing.T, srv *e2eTestServer, token string, query string, extraHeaders ...map[string]string) (int, api.JobListResponse, string) {
	t.Helper()
	url := srv.baseURL + "/api/v1/jobs"
	if query != "" {
		if !strings.HasPrefix(query, "?") {
			query = "?" + query
		}
		url += query
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("httpListJobs: failed to create request: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for _, m := range extraHeaders {
		for k, v := range m {
			req.Header.Set(k, v)
		}
	}

	resp, err := srv.client.Do(req)
	if err != nil {
		t.Fatalf("httpListJobs: network error: %v", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("httpListJobs: failed to read body: %v", err)
	}

	var res api.JobListResponse
	_ = json.Unmarshal(bodyBytes, &res)
	return resp.StatusCode, res, string(bodyBytes)
}

func httpGetJobLogs(t *testing.T, srv *e2eTestServer, token string, jobID string, offset int, extraHeaders ...map[string]string) (int, api.JobLogsResponse, string) {
	t.Helper()
	url := fmt.Sprintf("%s/api/v1/jobs/%s/logs?offset=%d", srv.baseURL, jobID, offset)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("httpGetJobLogs: failed to create request: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for _, m := range extraHeaders {
		for k, v := range m {
			req.Header.Set(k, v)
		}
	}

	resp, err := srv.client.Do(req)
	if err != nil {
		t.Fatalf("httpGetJobLogs: network error: %v", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("httpGetJobLogs: failed to read body: %v", err)
	}

	var res api.JobLogsResponse
	_ = json.Unmarshal(bodyBytes, &res)
	return resp.StatusCode, res, string(bodyBytes)
}

func httpCancelJob(t *testing.T, srv *e2eTestServer, token string, jobID string, extraHeaders ...map[string]string) (int, api.CancelJobResponse, string) {
	t.Helper()
	url := fmt.Sprintf("%s/api/v1/jobs/%s/cancel", srv.baseURL, jobID)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, nil)
	if err != nil {
		t.Fatalf("httpCancelJob: failed to create request: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for _, m := range extraHeaders {
		for k, v := range m {
			req.Header.Set(k, v)
		}
	}

	resp, err := srv.client.Do(req)
	if err != nil {
		t.Fatalf("httpCancelJob: network error: %v", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("httpCancelJob: failed to read body: %v", err)
	}

	var res api.CancelJobResponse
	_ = json.Unmarshal(bodyBytes, &res)
	return resp.StatusCode, res, string(bodyBytes)
}

func httpGetJobQueue(t *testing.T, srv *e2eTestServer, token string, extraHeaders ...map[string]string) (int, api.QueueStatsResponse, string) {
	t.Helper()
	url := srv.baseURL + "/api/v1/jobs/queue"
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("httpGetJobQueue: failed to create request: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for _, m := range extraHeaders {
		for k, v := range m {
			req.Header.Set(k, v)
		}
	}

	resp, err := srv.client.Do(req)
	if err != nil {
		t.Fatalf("httpGetJobQueue: network error: %v", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("httpGetJobQueue: failed to read body: %v", err)
	}

	var res api.QueueStatsResponse
	_ = json.Unmarshal(bodyBytes, &res)
	return resp.StatusCode, res, string(bodyBytes)
}

func httpGetQueueStats(t *testing.T, srv *e2eTestServer, token string, extraHeaders ...map[string]string) (int, api.QueueStatsResponse, string) {
	t.Helper()
	return httpGetJobQueue(t, srv, token, extraHeaders...)
}

func pollJobTerminal(t *testing.T, srv *e2eTestServer, token, jobID string, timeout time.Duration) *jobs.Job {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		code, job, _ := httpGetJob(t, srv, token, jobID)
		if code == http.StatusOK && job != nil && job.Status.IsTerminal() {
			return job
		}
		time.Sleep(30 * time.Millisecond)
	}
	t.Fatalf("pollJobTerminal: job %s did not reach terminal status within %s", jobID, timeout)
	return nil
}

func waitForJobTerminal(t *testing.T, srv *e2eTestServer, token, jobID string, timeout time.Duration) *jobs.Job {
	t.Helper()
	return pollJobTerminal(t, srv, token, jobID, timeout)
}

func pollJobLogsUntilEOF(t *testing.T, srv *e2eTestServer, token, jobID string, timeout time.Duration) string {
	t.Helper()
	var logs strings.Builder
	offset := 0
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		code, resp, _ := httpGetJobLogs(t, srv, token, jobID, offset)
		if code == http.StatusOK {
			logs.WriteString(resp.Logs)
			offset = resp.NextOffset
			if resp.EOF {
				return logs.String()
			}
		}
		time.Sleep(30 * time.Millisecond)
	}
	t.Fatalf("pollJobLogsUntilEOF: job %s logs did not reach EOF within %s (logs collected: %q)", jobID, timeout, logs.String())
	return logs.String()
}

