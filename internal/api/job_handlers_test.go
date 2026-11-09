package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
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
	"go-admin-tool/internal/plugins"
)

func setupTestJobAPIEnv(t *testing.T, customEngineCfg ...jobs.EngineConfig) (*APIEnv, http.Handler, *jobs.Engine) {
	t.Helper()

	cfg := core.DefaultConfig()
	cfg.Server.TLS.Enabled = false
	cfg.Executor.Enabled = true
	cfg.Executor.MaxTimeoutSeconds = 60

	cmdA := core.CommandDefinition{Name: "echo-cmd", Command: "echo", Args: []string{"hello-async"}}
	cmdAllowed := core.CommandDefinition{Name: "allowed-cmd", Command: "echo", Args: []string{"allowed"}}
	cmdForbidden := core.CommandDefinition{Name: "forbidden-cmd", Command: "echo", Args: []string{"forbidden"}}
	cmdBlock := core.CommandDefinition{Name: "block-cmd", Command: "echo", Args: []string{"blocking"}}
	if runtime.GOOS == "windows" {
		cmdA = core.CommandDefinition{Name: "echo-cmd", Command: "cmd", Args: []string{"/C", "echo hello-async"}}
		cmdAllowed = core.CommandDefinition{Name: "allowed-cmd", Command: "cmd", Args: []string{"/C", "echo allowed"}}
		cmdForbidden = core.CommandDefinition{Name: "forbidden-cmd", Command: "cmd", Args: []string{"/C", "echo forbidden"}}
		cmdBlock = core.CommandDefinition{Name: "block-cmd", Command: "cmd", Args: []string{"/C", "echo blocking"}}
	}
	cfg.Executor.Commands = []core.CommandDefinition{cmdA, cmdAllowed, cmdForbidden, cmdBlock}

	logger, err := core.NewLogger(core.LoggingConfig{Level: "error"})
	if err != nil {
		t.Fatalf("failed to create test logger: %v", err)
	}

	dbPath := filepath.Join(t.TempDir(), fmt.Sprintf("job_test_%d.db", time.Now().UnixNano()))
	db, err := database.NewDB(dbPath)
	if err != nil {
		t.Fatalf("failed to create DB: %v", err)
	}
	if err := db.Init(); err != nil {
		t.Fatalf("db.Init failed: %v", err)
	}

	auditLogger, err := audit.NewAuditLogger(core.AuditConfig{
		Enabled:      true,
		MaxMemoryLog: 100,
	}, db, logger)
	if err != nil {
		t.Fatalf("failed to create audit logger: %v", err)
	}

	authMgr, err := auth.NewManager(core.AuthConfig{
		Enabled:           true,
		RequireAuth:       false,
		BootstrapUsername: "admin",
		BootstrapPassword: "admin-password-123",
	})
	if err != nil {
		t.Fatalf("failed to create auth manager: %v", err)
	}

	reg := plugins.NewRegistry()
	if ops, err := plugins.DefaultDeclarativeOpsPlugin(); err == nil {
		_ = reg.Register(ops)
	}

	engineCfg := jobs.DefaultEngineConfig()
	engineCfg.WorkersCount = 2
	engineCfg.QueueCapacity = 100
	if len(customEngineCfg) > 0 {
		engineCfg = customEngineCfg[0]
	}

	store, err := jobs.NewJobStore(db)
	if err != nil {
		store = jobs.NewMemoryJobStore()
	}

	var apiEnv *APIEnv
	jobExecutor := func(ctx context.Context, job *jobs.Job, logWriter io.Writer) (any, error) {
		switch job.Type {
		case jobs.TypeCommand:
			if job.Action == "block-cmd" {
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(2 * time.Second):
					return map[string]any{"output": "unblocked"}, nil
				}
			}
			cmdCopy, found := apiEnv.FindCommand(job.Action)
			if !found {
				return nil, fmt.Errorf("command %q not found", job.Action)
			}
			out, execErr := core.ExecuteCommandWithContext(ctx, cmdCopy, job.Timeout, logWriter)
			return map[string]any{"output": out}, execErr
		case jobs.TypePlugin:
			if reg == nil {
				return nil, errors.New("plugin registry is not initialized")
			}
			res, execErr := reg.Execute(ctx, job.PluginID, job.Action, job.Params, job.Timeout)
			if logWriter != nil && res.Output != "" {
				_, _ = logWriter.Write([]byte(res.Output))
			}
			return res, execErr
		default:
			return nil, fmt.Errorf("unsupported job type: %s", job.Type)
		}
	}

	engine, err := jobs.NewEngine(engineCfg, store, auditLogger, jobExecutor)
	if err != nil {
		t.Fatalf("failed to create job engine: %v", err)
	}
	engine.SetMetricsReporter(NewJobMetricsReporter())
	if err := engine.Start(); err != nil {
		t.Fatalf("failed to start job engine: %v", err)
	}

	t.Cleanup(func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = engine.Shutdown(shutdownCtx)
		cancel()
		_ = auditLogger.Close()
		_ = db.Close()
	})

	apiEnv = &APIEnv{
		Config:         cfg,
		Logger:         logger,
		DB:             db,
		AuditLogger:    auditLogger,
		AuthManager:    authMgr,
		PluginRegistry: reg,
		JobEngine:      engine,
	}

	router := NewRouter(apiEnv)
	return apiEnv, router, engine
}

func TestSubmitJobHandler_CommandSuccess(t *testing.T) {
	_, router, _ := setupTestJobAPIEnv(t)

	payload := map[string]any{
		"type":   "command",
		"action": "echo-cmd",
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/jobs", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202 Accepted, got %d: %s", rec.Code, rec.Body.String())
	}

	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "/api/v1/jobs/") {
		t.Errorf("expected Location header to start with '/api/v1/jobs/', got %q", loc)
	}

	var resp SubmitJobResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.JobID == "" {
		t.Errorf("expected non-empty job_id")
	}
	if resp.Status != jobs.StatusQueued && resp.Status != jobs.StatusRunning && resp.Status != jobs.StatusCompleted {
		t.Errorf("unexpected job status: %s", resp.Status)
	}
	if resp.Action != "echo-cmd" {
		t.Errorf("expected action 'echo-cmd', got %q", resp.Action)
	}
	if resp.PollURL != fmt.Sprintf("/api/v1/jobs/%s", resp.JobID) {
		t.Errorf("expected PollURL %q, got %q", fmt.Sprintf("/api/v1/jobs/%s", resp.JobID), resp.PollURL)
	}
	if resp.LogsURL != fmt.Sprintf("/api/v1/jobs/%s/logs", resp.JobID) {
		t.Errorf("expected LogsURL %q, got %q", fmt.Sprintf("/api/v1/jobs/%s/logs", resp.JobID), resp.LogsURL)
	}
}

func TestSubmitJobHandler_PluginSuccess(t *testing.T) {
	_, router, _ := setupTestJobAPIEnv(t)

	payload := map[string]any{
		"type":      "plugin",
		"plugin_id": "ops-quick-tools",
		"action":    "probe-target",
		"params":    map[string]any{"target": "localhost"},
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/jobs", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202 Accepted, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp SubmitJobResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.JobID == "" {
		t.Errorf("expected non-empty job_id")
	}
	if resp.Type != jobs.TypePlugin {
		t.Errorf("expected type 'plugin', got %q", resp.Type)
	}
}

func TestSubmitJobHandler_PriorityAndTimeout(t *testing.T) {
	_, router, engine := setupTestJobAPIEnv(t)

	payload := map[string]any{
		"type":     "command",
		"action":   "echo-cmd",
		"priority": "high",
		"timeout":  "45s",
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/jobs", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202 Accepted, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp SubmitJobResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Priority != jobs.PriorityHigh {
		t.Errorf("expected priority 'high', got %q", resp.Priority)
	}

	job, found := engine.GetJob(resp.JobID)
	if !found || job == nil {
		t.Fatalf("job %s not found in engine store", resp.JobID)
	}
	if job.Timeout != 45*time.Second {
		t.Errorf("expected timeout 45s, got %s", job.Timeout)
	}
}

func TestSubmitJobHandler_ValidationErrors(t *testing.T) {
	env, router, _ := setupTestJobAPIEnv(t)

	// 1. Invalid JSON body -> 400
	req := httptest.NewRequest(http.MethodPost, "/api/v1/jobs", strings.NewReader("{invalid-json"))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid JSON, got %d", rec.Code)
	}

	// 2. Empty action -> 400
	body, _ := json.Marshal(map[string]any{"type": "command", "action": "   "})
	req = httptest.NewRequest(http.MethodPost, "/api/v1/jobs", bytes.NewReader(body))
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for empty action, got %d", rec.Code)
	}

	// 3. Unsupported job type -> 400
	body, _ = json.Marshal(map[string]any{"type": "invalid_type", "action": "echo-cmd"})
	req = httptest.NewRequest(http.MethodPost, "/api/v1/jobs", bytes.NewReader(body))
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for unsupported job type, got %d", rec.Code)
	}

	// 4. Plugin job missing plugin_id -> 400
	body, _ = json.Marshal(map[string]any{"type": "plugin", "action": "echo"})
	req = httptest.NewRequest(http.MethodPost, "/api/v1/jobs", bytes.NewReader(body))
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing plugin_id on plugin job, got %d", rec.Code)
	}

	// 5. Invalid timeout format -> 400
	body, _ = json.Marshal(map[string]any{"action": "echo-cmd", "timeout": "not-a-duration"})
	req = httptest.NewRequest(http.MethodPost, "/api/v1/jobs", bytes.NewReader(body))
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid timeout format, got %d", rec.Code)
	}

	// 6. Timeout exceeding MaxTimeoutSeconds (60s in test config) -> 400
	body, _ = json.Marshal(map[string]any{"action": "echo-cmd", "timeout": "120s"})
	req = httptest.NewRequest(http.MethodPost, "/api/v1/jobs", bytes.NewReader(body))
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for timeout exceeding maximum, got %d", rec.Code)
	}

	// 7. Engine not initialized -> 503
	savedEngine := env.JobEngine
	env.JobEngine = nil
	body, _ = json.Marshal(map[string]any{"action": "echo-cmd"})
	req = httptest.NewRequest(http.MethodPost, "/api/v1/jobs", bytes.NewReader(body))
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 when engine is nil, got %d", rec.Code)
	}
	env.JobEngine = savedEngine
}

func TestSubmitJobHandler_CommandNotFound(t *testing.T) {
	_, router, _ := setupTestJobAPIEnv(t)

	body, _ := json.Marshal(map[string]any{"type": "command", "action": "nonexistent-cmd"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/jobs", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 for unknown command, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestSubmitJobHandler_PluginNotFound(t *testing.T) {
	_, router, _ := setupTestJobAPIEnv(t)

	body, _ := json.Marshal(map[string]any{"type": "plugin", "plugin_id": "nonexistent-plugin", "action": "echo"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/jobs", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 for unknown plugin, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestSubmitJobHandler_ExecutorDisabled(t *testing.T) {
	env, router, _ := setupTestJobAPIEnv(t)
	env.Config.Executor.Enabled = false

	body, _ := json.Marshal(map[string]any{"type": "command", "action": "echo-cmd"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/jobs", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 when executor is disabled, got %d", rec.Code)
	}
}

func TestSubmitJobHandler_QueueFullBackpressure(t *testing.T) {
	customCfg := jobs.DefaultEngineConfig()
	customCfg.QueueCapacity = 1
	customCfg.WorkersCount = 1
	_, router, _ := setupTestJobAPIEnv(t, customCfg)

	// First job is consumed by the single worker and blocks
	body1, _ := json.Marshal(map[string]any{"action": "block-cmd"})
	req1 := httptest.NewRequest(http.MethodPost, "/api/v1/jobs", bytes.NewReader(body1))
	rec1 := httptest.NewRecorder()
	router.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusAccepted {
		t.Fatalf("first enqueue failed: %d", rec1.Code)
	}

	// Give the worker goroutine a few milliseconds to pull job1 from the queue
	time.Sleep(30 * time.Millisecond)

	// Second job fills the queue (capacity 1)
	body2, _ := json.Marshal(map[string]any{"action": "echo-cmd"})
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/jobs", bytes.NewReader(body2))
	rec2 := httptest.NewRecorder()
	router.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusAccepted {
		t.Fatalf("second enqueue failed: %d", rec2.Code)
	}

	// Third job overflows queue capacity -> 429 Too Many Requests
	body3, _ := json.Marshal(map[string]any{"action": "echo-cmd"})
	req3 := httptest.NewRequest(http.MethodPost, "/api/v1/jobs", bytes.NewReader(body3))
	rec3 := httptest.NewRecorder()
	router.ServeHTTP(rec3, req3)

	if rec3.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429 Too Many Requests on queue full, got %d: %s", rec3.Code, rec3.Body.String())
	}
}

func TestSubmitJobHandler_RBAC_Unauthorized(t *testing.T) {
	env, router, _ := setupTestJobAPIEnv(t)
	env.Config.Auth.RequireAuth = true

	body, _ := json.Marshal(map[string]any{"action": "echo-cmd"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/jobs", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 when unauthenticated and RequireAuth=true, got %d", rec.Code)
	}
}

func TestSubmitJobHandler_RBAC_ForbiddenAndAudit(t *testing.T) {
	env, router, _ := setupTestJobAPIEnv(t)
	env.Config.Auth.RequireAuth = true

	// Create user with Viewer role (has jobs:read, lacks jobs:submit)
	viewer, err := env.AuthManager.CreateUser("viewer-user", "Viewer User", "viewer-user@example.com", auth.RoleViewer, "viewer-password-123")
	if err != nil {
		t.Fatalf("failed to create viewer user: %v", err)
	}
	_, rawViewerToken, err := env.AuthManager.CreateToken(viewer.ID, "Viewer PAT", []string{auth.ScopeJobsRead}, 1*time.Hour)
	if err != nil {
		t.Fatalf("failed to generate viewer token: %v", err)
	}

	body, _ := json.Marshal(map[string]any{"action": "echo-cmd"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/jobs", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+rawViewerToken)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for viewer token submitting job, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify that a denied audit event was recorded
	events := env.AuditLogger.Query(audit.AuditFilter{
		Category: "job",
		Status:   "denied",
	})
	if len(events) == 0 {
		t.Errorf("expected audit denial event to be logged under category 'job', got total %d", len(events))
	}
}

func TestSubmitJobHandler_ServiceAccountAllowedActions(t *testing.T) {
	env, router, _ := setupTestJobAPIEnv(t)
	env.Config.Auth.RequireAuth = true

	// Service account allowed only "allowed-cmd"
	sa, rawKey, err := env.AuthManager.CreateServiceAccount(
		"limited-sa",
		"limited-sa",
		"Limited Automation SA",
		[]string{auth.ScopeJobsSubmit, "commands:execute"},
		[]string{"allowed-cmd"},
		24*time.Hour,
	)
	if err != nil {
		t.Fatalf("failed to create service account: %v", err)
	}
	_ = sa

	// 1. Submit allowed action -> 202 Accepted
	body1, _ := json.Marshal(map[string]any{"action": "allowed-cmd"})
	req1 := httptest.NewRequest(http.MethodPost, "/api/v1/jobs", bytes.NewReader(body1))
	req1.Header.Set("X-Service-Key", rawKey)
	rec1 := httptest.NewRecorder()
	router.ServeHTTP(rec1, req1)

	if rec1.Code != http.StatusAccepted {
		t.Fatalf("expected 202 Accepted for allowed action, got %d: %s", rec1.Code, rec1.Body.String())
	}

	// 2. Submit forbidden action -> 403 Forbidden
	body2, _ := json.Marshal(map[string]any{"action": "forbidden-cmd"})
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/jobs", bytes.NewReader(body2))
	req2.Header.Set("X-Service-Key", rawKey)
	rec2 := httptest.NewRecorder()
	router.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for forbidden action, got %d: %s", rec2.Code, rec2.Body.String())
	}
}

func TestListJobsHandler_FilteringAndPagination(t *testing.T) {
	_, router, engine := setupTestJobAPIEnv(t)

	// Enqueue 4 jobs with different attributes
	_, _ = engine.Enqueue(jobs.JobRequest{Type: jobs.TypeCommand, Action: "echo-cmd", Priority: jobs.PriorityHigh, ActorID: "alice"})
	_, _ = engine.Enqueue(jobs.JobRequest{Type: jobs.TypeCommand, Action: "echo-cmd", Priority: jobs.PriorityNormal, ActorID: "bob"})
	_, _ = engine.Enqueue(jobs.JobRequest{Type: jobs.TypePlugin, Action: "echo", PluginID: "ops", Priority: jobs.PriorityLow, ActorID: "alice"})
	_, _ = engine.Enqueue(jobs.JobRequest{Type: jobs.TypeCommand, Action: "allowed-cmd", Priority: jobs.PriorityNormal, ActorID: "charlie"})

	// 1. List all jobs
	req := httptest.NewRequest(http.MethodGet, "/api/v1/jobs", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var resp JobListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode: %v", err)
	}
	if resp.Total < 4 {
		t.Errorf("expected at least 4 jobs, got %d", resp.Total)
	}

	// 2. Pagination ?limit=2&offset=1
	req = httptest.NewRequest(http.MethodGet, "/api/v1/jobs?limit=2&offset=1", nil)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	var pageResp JobListResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &pageResp)
	if len(pageResp.Jobs) != 2 {
		t.Errorf("expected 2 jobs on page, got %d", len(pageResp.Jobs))
	}
	if pageResp.Limit != 2 || pageResp.Offset != 1 {
		t.Errorf("unexpected pagination metadata: limit=%d, offset=%d", pageResp.Limit, pageResp.Offset)
	}

	// 3. Filter by action
	req = httptest.NewRequest(http.MethodGet, "/api/v1/jobs?action=allowed-cmd", nil)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	var actionResp JobListResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &actionResp)
	for _, j := range actionResp.Jobs {
		if j.Action != "allowed-cmd" {
			t.Errorf("filter by action returned non-matching job: %s", j.Action)
		}
	}

	// 4. Filter by actor_id
	req = httptest.NewRequest(http.MethodGet, "/api/v1/jobs?actor_id=alice", nil)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	var actorResp JobListResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &actorResp)
	for _, j := range actorResp.Jobs {
		if j.ActorID != "alice" {
			t.Errorf("filter by actor_id returned non-matching job: %s", j.ActorID)
		}
	}
}

func TestGetJobHandler_SuccessAndNotFound(t *testing.T) {
	_, router, engine := setupTestJobAPIEnv(t)

	// 1. Submit a job
	job, err := engine.Enqueue(jobs.JobRequest{Type: jobs.TypeCommand, Action: "echo-cmd"})
	if err != nil {
		t.Fatalf("failed to enqueue: %v", err)
	}

	// 2. GET /api/v1/jobs/{id} -> 200
	req := httptest.NewRequest(http.MethodGet, "/api/v1/jobs/"+job.ID, nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var fetched jobs.Job
	if err := json.Unmarshal(rec.Body.Bytes(), &fetched); err != nil {
		t.Fatalf("failed to decode job: %v", err)
	}
	if fetched.ID != job.ID {
		t.Errorf("expected ID %s, got %s", job.ID, fetched.ID)
	}
	if fetched.Action != "echo-cmd" {
		t.Errorf("expected action 'echo-cmd', got %s", fetched.Action)
	}

	// 3. GET /api/v1/jobs/unknown-id -> 404
	req404 := httptest.NewRequest(http.MethodGet, "/api/v1/jobs/nonexistent-job-uuid", nil)
	rec404 := httptest.NewRecorder()
	router.ServeHTTP(rec404, req404)

	if rec404.Code != http.StatusNotFound {
		t.Errorf("expected 404 for unknown job, got %d", rec404.Code)
	}
}

func TestGetJobLogsHandler_ChunkedStreaming(t *testing.T) {
	_, router, engine := setupTestJobAPIEnv(t)

	job, err := engine.Enqueue(jobs.JobRequest{Type: jobs.TypeCommand, Action: "echo-cmd"})
	if err != nil {
		t.Fatalf("failed to enqueue: %v", err)
	}

	buf := job.LogBuffer()
	if buf == nil {
		t.Fatalf("expected non-nil LogBuffer on job")
	}

	// Write first log chunk
	_, _ = buf.Write([]byte("chunk-1\n"))

	// 1. Read offset=0
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/jobs/%s/logs?offset=0", job.ID), nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for logs, got %d", rec.Code)
	}

	var resp1 JobLogsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp1); err != nil {
		t.Fatalf("failed to decode logs response: %v", err)
	}

	if resp1.Logs != "chunk-1\n" {
		t.Errorf("expected logs 'chunk-1\\n', got %q", resp1.Logs)
	}
	if resp1.NextOffset != len("chunk-1\n") {
		t.Errorf("expected NextOffset %d, got %d", len("chunk-1\n"), resp1.NextOffset)
	}
	if resp1.EOF {
		t.Errorf("expected EOF=false while active")
	}

	// Write second log chunk and mark EOF
	_, _ = buf.Write([]byte("chunk-2\n"))
	buf.SetEOF()

	// 2. Read from next_offset
	req2 := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/jobs/%s/logs?offset=%d", job.ID, resp1.NextOffset), nil)
	rec2 := httptest.NewRecorder()
	router.ServeHTTP(rec2, req2)

	var resp2 JobLogsResponse
	_ = json.Unmarshal(rec2.Body.Bytes(), &resp2)

	if resp2.Logs != "chunk-2\n" {
		t.Errorf("expected logs 'chunk-2\\n', got %q", resp2.Logs)
	}
	if !resp2.EOF {
		t.Errorf("expected EOF=true after SetEOF")
	}

	// 3. Test 404 on nonexistent job logs
	req404 := httptest.NewRequest(http.MethodGet, "/api/v1/jobs/nonexistent-id/logs", nil)
	rec404 := httptest.NewRecorder()
	router.ServeHTTP(rec404, req404)
	if rec404.Code != http.StatusNotFound {
		t.Errorf("expected 404 for unknown job logs, got %d", rec404.Code)
	}
}

func TestCancelJobHandler_QueuedJobAndConflict(t *testing.T) {
	customCfg := jobs.DefaultEngineConfig()
	customCfg.WorkersCount = 0 // pause workers so job stays queued
	_, router, engine := setupTestJobAPIEnv(t, customCfg)

	job, err := engine.Enqueue(jobs.JobRequest{Type: jobs.TypeCommand, Action: "echo-cmd"})
	if err != nil {
		t.Fatalf("failed to enqueue: %v", err)
	}

	// 1. Cancel queued job -> 200 OK
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/v1/jobs/%s/cancel", job.ID), nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on cancel, got %d: %s", rec.Code, rec.Body.String())
	}

	var cancelResp CancelJobResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &cancelResp); err != nil {
		t.Fatalf("failed to decode cancel response: %v", err)
	}
	if cancelResp.Status != jobs.StatusCancelled {
		t.Errorf("expected status 'cancelled', got %s", cancelResp.Status)
	}

	// 2. Wait until job is in terminal state in store
	for i := 0; i < 50; i++ {
		j, found := engine.GetJob(job.ID)
		if found && j != nil && j.Status.IsTerminal() {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Second cancel attempt on already finished job -> 409 Conflict
	reqConflict := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/v1/jobs/%s/cancel", job.ID), nil)
	recConflict := httptest.NewRecorder()
	router.ServeHTTP(recConflict, reqConflict)

	if recConflict.Code != http.StatusConflict {
		t.Errorf("expected 409 Conflict for already finished job, got %d", recConflict.Code)
	}

	// 3. Cancel non-existent job -> 404 Not Found
	req404 := httptest.NewRequest(http.MethodPost, "/api/v1/jobs/nonexistent-job-uuid/cancel", nil)
	rec404 := httptest.NewRecorder()
	router.ServeHTTP(rec404, req404)

	if rec404.Code != http.StatusNotFound {
		t.Errorf("expected 404 for non-existent job cancel, got %d", rec404.Code)
	}
}

func TestCancelJobHandler_RBAC(t *testing.T) {
	env, router, engine := setupTestJobAPIEnv(t)
	env.Config.Auth.RequireAuth = true

	// Create Viewer token (lacks jobs:cancel)
	viewer, err := env.AuthManager.CreateUser("viewer-user2", "Viewer User", "viewer2@example.com", auth.RoleViewer, "viewer-password-123")
	if err != nil {
		t.Fatalf("failed to create viewer user: %v", err)
	}
	_, rawViewerToken, err := env.AuthManager.CreateToken(viewer.ID, "Viewer PAT", []string{auth.ScopeJobsRead}, 1*time.Hour)
	if err != nil {
		t.Fatalf("failed to generate viewer token: %v", err)
	}

	job, err := engine.Enqueue(jobs.JobRequest{Type: jobs.TypeCommand, Action: "echo-cmd"})
	if err != nil {
		t.Fatalf("failed to enqueue: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/v1/jobs/%s/cancel", job.ID), nil)
	req.Header.Set("Authorization", "Bearer "+rawViewerToken)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for viewer attempting cancel, got %d", rec.Code)
	}
}

func TestJobQueueStatsHandler(t *testing.T) {
	_, router, _ := setupTestJobAPIEnv(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/jobs/queue", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for queue stats, got %d: %s", rec.Code, rec.Body.String())
	}

	var stats QueueStatsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &stats); err != nil {
		t.Fatalf("failed to decode queue stats: %v", err)
	}

	if stats.WorkersTotal != 2 {
		t.Errorf("expected workers_total=2, got %d", stats.WorkersTotal)
	}
	if stats.Capacity != 100 {
		t.Errorf("expected capacity=100, got %d", stats.Capacity)
	}
}

func TestJobMetricsTelemetryIntegration(t *testing.T) {
	ResetJobMetrics()
	_, router, _ := setupTestJobAPIEnv(t)

	// Record manual executions and updates
	RecordJobExecution("echo-cmd", "completed", 150*time.Millisecond)
	RecordJobExecution("echo-cmd", "completed", 200*time.Millisecond)
	RecordJobExecution("echo-cmd", "failed", 50*time.Millisecond)
	UpdateJobQueueMetrics(5, 2)
	UpdateJobWorkersTotal(4)

	if count := GetJobExecutionCount("completed", "echo-cmd"); count != 2 {
		t.Errorf("expected completed execution count 2, got %v", count)
	}
	if count := GetJobExecutionCount("failed", "echo-cmd"); count != 1 {
		t.Errorf("expected failed execution count 1, got %v", count)
	}
	if depth := GetJobQueueDepth(); depth != 5 {
		t.Errorf("expected queue depth 5, got %v", depth)
	}
	if active := GetJobWorkersActive(); active != 2 {
		t.Errorf("expected active workers 2, got %v", active)
	}
	if total := GetJobWorkersTotal(); total != 4 {
		t.Errorf("expected total workers 4, got %v", total)
	}

	// Scrape /metrics and verify all 5 job metrics exist in Prometheus output
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from /metrics, got %d", rec.Code)
	}

	metricsOutput := rec.Body.String()
	expectedMetrics := []string{
		"job_queue_depth",
		"job_workers_active",
		"job_workers_total",
		"job_executions_total",
		"job_execution_duration_seconds",
	}
	for _, m := range expectedMetrics {
		if !strings.Contains(metricsOutput, m) {
			t.Errorf("expected Prometheus /metrics output to contain %q", m)
		}
	}
}
