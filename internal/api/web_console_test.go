package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go-admin-tool/internal/audit"
	"go-admin-tool/internal/auth"
	"go-admin-tool/internal/core"
	"go-admin-tool/internal/database"
	"go-admin-tool/internal/mcp"
	"go-admin-tool/internal/plugins"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWebAdministrationConsoleServed(t *testing.T) {
	logger, err := core.NewLogger(core.LoggingConfig{Level: "info"})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	cfg := core.DefaultConfig()
	cfg.Server.TLS.Enabled = false
	authMgr, err := auth.NewManager(cfg.Auth)
	if err != nil {
		t.Fatalf("failed to create auth manager: %v", err)
	}
	_, _, adminTok, err := authMgr.AuthenticateUser(cfg.Auth.BootstrapUsername, cfg.Auth.BootstrapPassword)
	if err != nil {
		t.Fatalf("failed to authenticate admin: %v", err)
	}
	env := &APIEnv{
		Config:      cfg,
		Logger:      logger,
		AuthManager: authMgr,
	}
	router := NewRouter(env)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200 OK for GET /, got %d", rec.Code)
	}

	body := rec.Body.String()
	requiredSections := []string{
		"API Executor — Enterprise Remote Administration Console",
		"rel=\"icon\" type=\"image/svg+xml\"",
		"1. Command Executor",
		"2. Ubuntu & RedHat Presets",
		"3. RBAC Users & PATs",
		"4. Service Accounts",
		"5. Plugins & SQL Explorer",
		"6. MCP Server & Traces",
		"7. SHA-256 Audit & Logs",
		"8. HTTPS/TLS & Files",
		"9. Async Jobs & Queue",
		"cat.commands",
		"const pluginID = d.id || (d.plugin && d.plugin.id) || '';",
		"/api/v1/execute",
		"/api/v1/jobs",
		"/api/v1/jobs/queue",
		"/api/v1/presets/activate",
		"/api/v1/auth/tokens",
		"/api/v1/auth/service-accounts",
		"/api/v1/plugins/execute",
		"/api/v1/plugins/declarative",
		"/api/v1/db/query",
		"/api/v1/mcp",
		"/api/v1/audit/verify",
		"/api/v1/logs",
		"/api/v1/history",
		"/api/v1/tls/renew",
		"this.principal = null;",
		"Deleted user ",
		"Revoked token ",
		"Deleted service account ",
		"Executed plugin ",
	}

	for _, marker := range requiredSections {
		if !strings.Contains(body, marker) {
			t.Errorf("expected web administration console HTML to contain %q", marker)
		}
	}

	// Verify the Web Console's single-family os_families payload activates ONLY Ubuntu presets (not RedHat)
	actReqBody, _ := json.Marshal(map[string]any{"os_families": []string{"ubuntu"}})
	actReq := httptest.NewRequest(http.MethodPost, "/api/v1/presets/activate", bytes.NewReader(actReqBody))
	actReq.Header.Set("Authorization", "Bearer "+adminTok)
	actRec := httptest.NewRecorder()
	router.ServeHTTP(actRec, actReq)
	if actRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from POST /api/v1/presets/activate with os_families, got %d: %s", actRec.Code, actRec.Body.String())
	}
	var actResp struct {
		ActivatedFamilies []string `json:"activated_families"`
		AddedCount        int      `json:"added_count"`
		TotalCommands     int      `json:"total_commands"`
	}
	if err := json.Unmarshal(actRec.Body.Bytes(), &actResp); err != nil {
		t.Fatalf("failed to decode activate response: %v", err)
	}
	if actResp.AddedCount != 10 {
		t.Fatalf("expected exactly 10 Ubuntu preset commands added when os_families=['ubuntu'], got %d", actResp.AddedCount)
	}
}

func TestWebAdministrationConsoleEndToEndWorkflows(t *testing.T) {
	tmpDir := t.TempDir()
	logger, err := core.NewLogger(core.LoggingConfig{Level: "info"})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	cfg := core.DefaultConfig()
	cfg.Server.TLS.Enabled = true
	cfg.Server.TLS.AutoGenerate = true
	cfg.Server.TLS.CertFile = filepath.Join(tmpDir, "server.crt")
	cfg.Server.TLS.KeyFile = filepath.Join(tmpDir, "server.key")

	db, err := database.NewDB(":memory:")
	if err != nil {
		t.Fatalf("failed to create db: %v", err)
	}
	defer db.Close()
	if err := db.Init(); err != nil {
		t.Fatalf("failed to init db: %v", err)
	}

	cm, err := core.NewCertManager(cfg.Server.TLS, "localhost")
	if err != nil {
		t.Fatalf("failed to init cert manager: %v", err)
	}
	auditLogger, err := audit.NewAuditLogger(cfg.Audit, db, logger)
	if err != nil {
		t.Fatalf("failed to init audit logger: %v", err)
	}
	authMgr, err := auth.NewManager(cfg.Auth)
	if err != nil {
		t.Fatalf("failed to init auth manager: %v", err)
	}
	_, _, adminTok, err := authMgr.AuthenticateUser(cfg.Auth.BootstrapUsername, cfg.Auth.BootstrapPassword)
	if err != nil {
		t.Fatalf("failed to authenticate admin: %v", err)
	}
	reg := plugins.NewRegistry()
	_ = reg.Register(plugins.NewDatabaseExposurePlugin(db, 50))
	_ = reg.Register(plugins.NewSystemDiagnosticsPlugin())

	mcpSrv, err := mcp.NewServer(cfg.MCP, cfg, db, cm, reg, auditLogger, logger, RecordActionCall)
	if err != nil {
		t.Fatalf("failed to init mcp server: %v", err)
	}

	env := &APIEnv{
		Config:         cfg,
		Logger:         logger,
		DB:             db,
		CertManager:    cm,
		AuditLogger:    auditLogger,
		AuthManager:    authMgr,
		PluginRegistry: reg,
		MCPServer:      mcpSrv,
	}
	router := NewRouter(env)

	// 1. Tab 5 workflow: Register Declarative Plugin and assert root `id` field matches Web Console binding
	declSpec := map[string]any{
		"id":          "custom-ops",
		"name":        "Custom Ops Plugin",
		"version":     "1.0.0",
		"description": "Declarative diagnostic commands",
		"actions": []map[string]any{
			{
				"name":        "hostname-check",
				"description": "Print hostname",
				"command":     "hostname",
				"args":        []string{},
				"timeout":     "5s",
			},
		},
	}
	declBytes, _ := json.Marshal(declSpec)
	declReq := httptest.NewRequest(http.MethodPost, "/api/v1/plugins/declarative", bytes.NewReader(declBytes))
	declReq.Header.Set("Authorization", "Bearer "+adminTok)
	declRec := httptest.NewRecorder()
	router.ServeHTTP(declRec, declReq)
	if declRec.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created from POST /api/v1/plugins/declarative, got %d: %s", declRec.Code, declRec.Body.String())
	}
	var declResp map[string]any
	if err := json.Unmarshal(declRec.Body.Bytes(), &declResp); err != nil {
		t.Fatalf("failed to decode declarative plugin response: %v", err)
	}
	if declResp["id"] != "custom-ops" {
		t.Fatalf("expected declarative plugin response root id='custom-ops', got %v", declResp["id"])
	}

	// 2. Tab 6 workflow: MCP tools/call (audit_verify) records trace and links to SHA-256 audit log
	mcpPayload := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"audit_verify","arguments":{}}}`
	mcpReq := httptest.NewRequest(http.MethodPost, "/api/v1/mcp", strings.NewReader(mcpPayload))
	mcpReq.Header.Set("X-MCP-Session-ID", "web-admin-console")
	mcpRec := httptest.NewRecorder()
	router.ServeHTTP(mcpRec, mcpReq)
	if mcpRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from POST /api/v1/mcp, got %d: %s", mcpRec.Code, mcpRec.Body.String())
	}

	// 3. Tab 8 workflow: Rotate TLS certificate and verify audit chain integrity in Tab 7
	tlsReq := httptest.NewRequest(http.MethodPost, "/api/v1/tls/renew", nil)
	tlsReq.Header.Set("Authorization", "Bearer "+adminTok)
	tlsRec := httptest.NewRecorder()
	router.ServeHTTP(tlsRec, tlsReq)
	if tlsRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from POST /api/v1/tls/renew, got %d: %s", tlsRec.Code, tlsRec.Body.String())
	}

	verifyReq := httptest.NewRequest(http.MethodGet, "/api/v1/audit/verify", nil)
	verifyRec := httptest.NewRecorder()
	router.ServeHTTP(verifyRec, verifyReq)
	if verifyRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from GET /api/v1/audit/verify, got %d", verifyRec.Code)
	}
	var verifyResp struct {
		Valid       bool `json:"valid"`
		TotalEvents int  `json:"total_events"`
	}
	if err := json.Unmarshal(verifyRec.Body.Bytes(), &verifyResp); err != nil {
		t.Fatalf("failed to decode audit verify response: %v", err)
	}
	if !verifyResp.Valid || verifyResp.TotalEvents < 3 {
		t.Fatalf("expected valid audit chain with >= 3 events, got valid=%v total=%d", verifyResp.Valid, verifyResp.TotalEvents)
	}
}

func TestWebAdministrationConsole_Tab5_CatalogSearchFilteringPaginationAndForms(t *testing.T) {
	logger, err := core.NewLogger(core.LoggingConfig{Level: "info"})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	cfg := core.DefaultConfig()
	cfg.Server.TLS.Enabled = false

	db, err := database.NewDB(filepath.Join(t.TempDir(), "web_tab5_test.db"))
	if err != nil {
		t.Fatalf("failed to create db: %v", err)
	}
	defer db.Close()
	_ = db.Init()

	auditLogger, err := audit.NewAuditLogger(cfg.Audit, db, logger)
	if err != nil {
		t.Fatalf("failed to init audit logger: %v", err)
	}
	authMgr, err := auth.NewManager(cfg.Auth)
	if err != nil {
		t.Fatalf("failed to init auth manager: %v", err)
	}
	reg := plugins.NewRegistry()
	_ = reg.Register(plugins.NewDatabaseExposurePlugin(db, 50))

	env := &APIEnv{
		Config:         cfg,
		Logger:         logger,
		DB:             db,
		AuditLogger:    auditLogger,
		AuthManager:    authMgr,
		PluginRegistry: reg,
	}
	router := NewRouter(env)

	// 1. Fetch web console HTML
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for GET /, got %d", rec.Code)
	}
	body := rec.Body.String()

	// 2. Validate all Tab 5 reactive state bindings and layout markers
	expectedMarkers := []string{
		"300+ Modular Plugins &amp; SQL Explorer",
		"pluginSearchQuery",
		"pluginCategoryFilter",
		"pluginTypeFilter",
		"pluginPage",
		"pluginPageSize",
		"pluginSubTab",
		"paramInputMode",
		"actionParamValues",
		"pluginExecuting",
		"pluginExecResult",
		"filteredPlugins",
		"paginatedPlugins",
		"categoryCount",
		"totalPluginPages",
		"paginationSummary",
		"currentActionParameters",
		"toggleParamMode",
		"Execute Plugin Action",
		"All 10 Domains",
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
		"db-exposure",
		"Register Declarative Spec",
		"x-model=\"pluginSearchQuery\"",
		"x-model=\"actionParamValues[param.name]\"",
		"x-model=\"dbSQLQuery\"",
		"x-model=\"declarativeSpecJSON\"",
	}

	for _, marker := range expectedMarkers {
		if !strings.Contains(body, marker) {
			t.Errorf("expected web administration console to contain Tab 5 marker %q", marker)
		}
	}

	// 3. Test plugin execution API endpoint used by Tab 5 Execute button
	_, token, err := authMgr.CreateToken("admin", "web-tab5-tester", []string{"*"}, time.Hour)
	if err != nil {
		t.Fatalf("failed to create PAT: %v", err)
	}

	execBody, _ := json.Marshal(map[string]any{
		"plugin_id": "sys-diagnostics",
		"action":    "runtime_stats",
		"params":    map[string]any{},
	})
	execReq := httptest.NewRequest(http.MethodPost, "/api/v1/plugins/execute", bytes.NewReader(execBody))
	execReq.Header.Set("Authorization", "Bearer "+token)
	execReq.Header.Set("Content-Type", "application/json")
	execRec := httptest.NewRecorder()
	router.ServeHTTP(execRec, execReq)

	if execRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from plugin execution, got %d: %s", execRec.Code, execRec.Body.String())
	}

	var execResp struct {
		PluginID   string `json:"plugin_id"`
		Action     string `json:"action"`
		Status     string `json:"status"`
		Output     string `json:"output"`
		DurationMs int64  `json:"duration_ms"`
	}
	if err := json.Unmarshal(execRec.Body.Bytes(), &execResp); err != nil {
		t.Fatalf("failed to decode plugin execute response: %v", err)
	}
	if execResp.PluginID != "sys-diagnostics" || execResp.Action != "runtime_stats" || execResp.Status != "ok" {
		t.Fatalf("unexpected plugin execution result: %+v", execResp)
	}
	if !strings.Contains(execResp.Output, "num_goroutine") {
		t.Errorf("expected runtime stats output to contain telemetry data, got %q", execResp.Output)
	}
}

func TestWebAdministrationConsole_ResilienceGuarantees(t *testing.T) {
	logger, err := core.NewLogger(core.LoggingConfig{Level: "info"})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	cfg := core.DefaultConfig()
	cfg.Server.TLS.Enabled = false
	authMgr, err := auth.NewManager(cfg.Auth)
	if err != nil {
		t.Fatalf("failed to create auth manager: %v", err)
	}
	env := &APIEnv{
		Config:      cfg,
		Logger:      logger,
		AuthManager: authMgr,
	}
	router := NewRouter(env)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200 OK for GET /, got %d", rec.Code)
	}

	body := rec.Body.String()

	// 1. Authorization header format in curlSnippet() must match headers() (Bearer token, not deprecated X-API-Token)
	expectedCurlAuth := `-H "Authorization: Bearer ${this.authToken || 'gat_pat_<your_token>'}"`
	if !strings.Contains(body, expectedCurlAuth) {
		t.Errorf("expected curlSnippet() to generate Authorization: Bearer header %q", expectedCurlAuth)
	}
	if strings.Contains(body, `X-API-Token: ${this.authToken`) {
		t.Errorf("curlSnippet() must not contain deprecated X-API-Token header")
	}

	// 2. Initial page load without token must suppress statusBanner error
	if !strings.Contains(body, "if (this.authToken)") {
		t.Errorf("expected loadPrincipal() to guard statusBanner with 'if (this.authToken)'")
	}

	// 3. Coordination of refreshAll() via Promise.allSettled()
	if !strings.Contains(body, "Promise.allSettled") {
		t.Errorf("expected refreshAll() to coordinate concurrent requests with Promise.allSettled()")
	}

	// 4. Defensive try...catch blocks on action methods
	defensiveMarkers := []string{
		"Failed to activate presets: ' + e",
		"Authentication failed: ' + e",
		"Failed to create user: ' + e",
		"Failed to delete user: ' + e",
		"Failed to issue token: ' + e",
		"Failed to revoke token: ' + e",
		"Failed to create service account: ' + e",
		"Failed to rotate service account key: ' + e",
		"Failed to delete service account: ' + e",
		"Failed to register declarative plugin: ' + e",
		"Failed to load tables: ' + e",
		"Database query failed: ' + e",
		"MCP request failed: ' + e",
		"Failed to rotate TLS certificate: ' + e",
	}

	for _, marker := range defensiveMarkers {
		if !strings.Contains(body, marker) {
			t.Errorf("expected web console to contain defensive error handling marker %q", marker)
		}
	}
}

func TestWebAdministrationConsole_Tab9_JobsQueueStructure(t *testing.T) {
	logger, err := core.NewLogger(core.LoggingConfig{Level: "info"})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	cfg := core.DefaultConfig()
	cfg.Server.TLS.Enabled = false

	db, err := database.NewDB(filepath.Join(t.TempDir(), "web_tab9_test.db"))
	if err != nil {
		t.Fatalf("failed to create db: %v", err)
	}
	defer db.Close()
	_ = db.Init()

	auditLogger, err := audit.NewAuditLogger(cfg.Audit, db, logger)
	if err != nil {
		t.Fatalf("failed to init audit logger: %v", err)
	}
	authMgr, err := auth.NewManager(cfg.Auth)
	if err != nil {
		t.Fatalf("failed to init auth manager: %v", err)
	}

	env := &APIEnv{
		Config:      cfg,
		Logger:      logger,
		DB:          db,
		AuditLogger: auditLogger,
		AuthManager: authMgr,
	}
	router := NewRouter(env)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for GET /, got %d", rec.Code)
	}
	body := rec.Body.String()

	// Validate Tab 9 navigation, layout containers, form controls, table headers, and modal dialog
	expectedTab9Markers := []string{
		// 1. Navigation tab item
		"9. Async Jobs &amp; Queue",
		"id: 'jobs'",
		"data-tab=\"jobs\"",

		// 2. Main section container
		"id=\"tab-jobs\"",
		"x-show=\"activeTab === 'jobs'\"",
		"Asynchronous Execution Engine",
		"Async Jobs &amp; Queue Management",

		// 3. Queue Telemetry Cards
		"id=\"queue-depth-metric\"",
		"id=\"workers-active-metric\"",
		"id=\"workers-total-metric\"",
		"id=\"queue-capacity-metric\"",
		"Queued Jobs",
		"Active Workers",
		"Total Workers",
		"Queue Capacity",
		"fetchQueueTelemetry",

		// 4. Async Job Submission Form
		"x-model=\"jobForm.type\"",
		"x-model=\"jobForm.action\"",
		"x-model=\"jobForm.plugin_id\"",
		"x-model=\"jobForm.paramsJSON\"",
		"x-model=\"jobForm.priority\"",
		"x-model=\"jobForm.timeout\"",
		"Launch Async Job",
		"submitAsyncJob",

		// 5. Jobs History Table & Filters
		"Job ID",
		"Priority",
		"Status",
		"Created At",
		"Duration",
		"Actions",
		"jobsFilterStatus",
		"loadJobsHistory",
		"openLogModal",
		"cancelJob",
		"View Logs",

		// 6. Live Log Modal Dialog
		"id=\"job-log-modal\"",
		"logModalOpen",
		"id=\"log-terminal-output\"",
		"id=\"log-autoscroll\"",
		"logAutoScroll",
		"copyLogOutput",
		"Copy Logs",
		"closeLogModal",
	}

	for _, marker := range expectedTab9Markers {
		if !strings.Contains(body, marker) {
			t.Errorf("expected web administration console to contain Tab 9 marker %q", marker)
		}
	}
}

func TestWebAdministrationConsole_Tab9_FormControlsAndEndpoints(t *testing.T) {
	// Initialize full API environment with active JobEngine and router
	_, router, _ := setupTestJobAPIEnv(t)

	// Step 1: Verify that embedded JavaScript code references required endpoints and HTTP status codes
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for GET /, got %d", rec.Code)
	}
	body := rec.Body.String()

	requiredJSEndpointsAndStatuses := []string{
		// Endpoints
		"/api/v1/jobs/queue",
		"/api/v1/jobs",
		"/api/v1/jobs/",
		"/cancel",
		"/logs",
		"next_offset",
		"eof",
		"truncated",

		// Status codes handled in JS
		"200",
		"202",
		"400",
		"403",
		"404",
		"409",
		"429",

		// Defensive error handlers
		"Failed to submit job",
		"Failed to load job history",
		"Failed to cancel job",
	}

	for _, marker := range requiredJSEndpointsAndStatuses {
		if !strings.Contains(body, marker) {
			t.Errorf("expected web console JS to reference endpoint/status %q", marker)
		}
	}

	// Step 2: Live end-to-end HTTP integration verification matching Tab 9 UI actions
	// A. Queue Telemetry Endpoint: GET /api/v1/jobs/queue
	telemetryReq := httptest.NewRequest(http.MethodGet, "/api/v1/jobs/queue", nil)
	telemetryRec := httptest.NewRecorder()
	router.ServeHTTP(telemetryRec, telemetryReq)
	if telemetryRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from GET /api/v1/jobs/queue, got %d: %s", telemetryRec.Code, telemetryRec.Body.String())
	}
	var qStats struct {
		QueuedJobs    int `json:"queued_jobs"`
		WorkersTotal  int `json:"workers_total"`
		WorkersActive int `json:"workers_active"`
		Capacity      int `json:"capacity"`
	}
	if err := json.Unmarshal(telemetryRec.Body.Bytes(), &qStats); err != nil {
		t.Fatalf("failed to decode queue stats response: %v", err)
	}
	if qStats.Capacity <= 0 {
		t.Fatalf("expected positive queue capacity, got %d", qStats.Capacity)
	}

	// B. Async Job Submission: POST /api/v1/jobs (Launch Async Job)
	submitPayload := map[string]any{
		"type":     "command",
		"action":   "echo-cmd",
		"priority": "normal",
	}
	submitBytes, _ := json.Marshal(submitPayload)
	submitReq := httptest.NewRequest(http.MethodPost, "/api/v1/jobs", bytes.NewReader(submitBytes))
	submitReq.Header.Set("Content-Type", "application/json")
	submitRec := httptest.NewRecorder()
	router.ServeHTTP(submitRec, submitReq)
	if submitRec.Code != http.StatusAccepted {
		t.Fatalf("expected 202 Accepted from POST /api/v1/jobs, got %d: %s", submitRec.Code, submitRec.Body.String())
	}
	var submitResp struct {
		JobID   string `json:"job_id"`
		Status  string `json:"status"`
		PollURL string `json:"poll_url"`
		LogsURL string `json:"logs_url"`
	}
	if err := json.Unmarshal(submitRec.Body.Bytes(), &submitResp); err != nil {
		t.Fatalf("failed to decode submit response: %v", err)
	}
	if submitResp.JobID == "" || submitResp.Status != "queued" {
		t.Fatalf("unexpected submit response fields: %+v", submitResp)
	}

	// C. History Listing: GET /api/v1/jobs (Job Execution History)
	historyReq := httptest.NewRequest(http.MethodGet, "/api/v1/jobs?limit=10&offset=0", nil)
	historyRec := httptest.NewRecorder()
	router.ServeHTTP(historyRec, historyReq)
	if historyRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from GET /api/v1/jobs, got %d: %s", historyRec.Code, historyRec.Body.String())
	}
	var historyResp struct {
		Jobs  []map[string]any `json:"jobs"`
		Total int              `json:"total"`
	}
	if err := json.Unmarshal(historyRec.Body.Bytes(), &historyResp); err != nil {
		t.Fatalf("failed to decode history response: %v", err)
	}
	if len(historyResp.Jobs) == 0 {
		t.Fatalf("expected history to contain at least 1 job, got %d", len(historyResp.Jobs))
	}

	// D. Chunked Log Stream: GET /api/v1/jobs/{id}/logs?offset=0 (Live Log Modal)
	logsReq := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/jobs/%s/logs?offset=0", submitResp.JobID), nil)
	logsRec := httptest.NewRecorder()
	router.ServeHTTP(logsRec, logsReq)
	if logsRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from GET /api/v1/jobs/{id}/logs, got %d: %s", logsRec.Code, logsRec.Body.String())
	}
	var logsResp struct {
		JobID      string `json:"job_id"`
		Status     string `json:"status"`
		Logs       string `json:"logs"`
		Offset     int    `json:"offset"`
		NextOffset int    `json:"next_offset"`
		EOF        bool   `json:"eof"`
	}
	if err := json.Unmarshal(logsRec.Body.Bytes(), &logsResp); err != nil {
		t.Fatalf("failed to decode logs response: %v", err)
	}
	if logsResp.JobID != submitResp.JobID {
		t.Fatalf("expected log response for job %s, got %s", submitResp.JobID, logsResp.JobID)
	}

	// E. Job Cancellation: POST /api/v1/jobs/{id}/cancel
	cancelReq := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/v1/jobs/%s/cancel", submitResp.JobID), nil)
	cancelRec := httptest.NewRecorder()
	router.ServeHTTP(cancelRec, cancelReq)
	if cancelRec.Code != http.StatusOK && cancelRec.Code != http.StatusConflict {
		t.Fatalf("expected 200 OK or 409 Conflict from POST /api/v1/jobs/{id}/cancel, got %d: %s", cancelRec.Code, cancelRec.Body.String())
	}

	// F. Validation Failure (HTTP 400 Bad Request)
	badReq := httptest.NewRequest(http.MethodPost, "/api/v1/jobs", bytes.NewReader([]byte(`{"type":"invalid_type"}`)))
	badReq.Header.Set("Content-Type", "application/json")
	badRec := httptest.NewRecorder()
	router.ServeHTTP(badRec, badReq)
	if badRec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request for invalid job submission, got %d", badRec.Code)
	}
}



