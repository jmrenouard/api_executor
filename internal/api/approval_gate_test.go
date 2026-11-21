package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
	"time"

	"go-admin-tool/internal/approval"
	"go-admin-tool/internal/audit"
	"go-admin-tool/internal/auth"
	"go-admin-tool/internal/core"
	"go-admin-tool/internal/jobs"
	"go-admin-tool/internal/mcp"
	"go-admin-tool/internal/plugins"
)

func crossPlatformEchoCmd(name string, requireApproval bool) core.CommandDefinition {
	if runtime.GOOS == "windows" {
		return core.CommandDefinition{
			Name:            name,
			Command:         "cmd",
			Args:            []string{"/C", "echo", "executed-" + name},
			Timeout:         "5s",
			RequireApproval: requireApproval,
		}
	}
	return core.CommandDefinition{
		Name:            name,
		Command:         "echo",
		Args:            []string{"executed-" + name},
		Timeout:         "5s",
		RequireApproval: requireApproval,
	}
}

func newHITLGateTestEnv(t *testing.T, enabled bool) (*APIEnv, http.Handler, map[string]string) {
	t.Helper()
	cfg := core.DefaultConfig()
	cfg.Auth.Enabled = true
	cfg.Auth.RequireAuth = true
	cfg.Executor.Enabled = true
	cfg.Executor.Commands = []core.CommandDefinition{
		crossPlatformEchoCmd("safe-cmd", false),
		crossPlatformEchoCmd("crit-flag-cmd", true),
		crossPlatformEchoCmd("restart-postgres", false),
	}
	cfg.Approval = core.ApprovalConfig{
		Enabled:                 enabled,
		DefaultTTL:              "10m",
		MaxPending:              50,
		RequireDistinctApprover: true,
		CriticalCommands:        []string{"restart-*"},
		CriticalPlugins:         []string{"plugin:sys-diagnostics:runtime_stats"},
		CriticalMCPTools:        []string{"tls_status"},
	}

	authMgr, err := auth.NewManager(cfg.Auth)
	if err != nil {
		t.Fatalf("auth.NewManager: %v", err)
	}
	auditLogger, err := audit.NewAuditLogger(core.AuditConfig{Enabled: true, MaxMemoryLog: 500}, nil, nil)
	if err != nil {
		t.Fatalf("audit.NewAuditLogger: %v", err)
	}
	t.Cleanup(func() { _ = auditLogger.Close() })

	approvalStore, err := approval.NewStore(cfg.Approval, nil, auditLogger)
	if err != nil {
		t.Fatalf("approval.NewStore: %v", err)
	}

	reg := plugins.NewEmptyRegistry()
	_ = reg.Register(plugins.NewSystemDiagnosticsPlugin())

	mcpSrv, err := mcp.NewServer(cfg.MCP, cfg, nil, nil, reg, auditLogger, nil, RecordActionCall)
	if err != nil {
		t.Fatalf("mcp.NewServer: %v", err)
	}
	t.Cleanup(func() { _ = mcpSrv.Close() })

	var env *APIEnv
	jobEngine, err := jobs.NewEngine(jobs.DefaultEngineConfig(), jobs.NewMemoryJobStore(), auditLogger, func(ctx context.Context, j *jobs.Job, _ io.Writer) (any, error) {
		if j.Type == jobs.TypeCommand {
			cmd, _ := env.FindCommand(j.Action)
			out, err := core.ExecuteCommandWithContext(ctx, cmd, j.Timeout, nil)
			return map[string]any{"output": out}, err
		}
		return reg.Execute(ctx, j.PluginID, j.Action, j.Params, j.Timeout)
	})
	if err != nil {
		t.Fatalf("jobs.NewEngine: %v", err)
	}
	if err := jobEngine.Start(); err != nil {
		t.Fatalf("jobEngine.Start: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = jobEngine.Shutdown(ctx)
	})

	_, adminTok, _ := authMgr.CreateToken("admin", "admin-tok", nil, 0)
	admin2, _ := authMgr.CreateUser("admin2", "secret123", "Admin2", "a2@local", auth.RoleAdmin)
	_, admin2Tok, _ := authMgr.CreateToken(admin2.ID, "admin2-tok", nil, 0)
	opUser, _ := authMgr.CreateUser("op1", "secret123", "Op1", "op1@local", auth.RoleOperator)
	_, opTok, _ := authMgr.CreateToken(opUser.ID, "op-tok", nil, 0)
	viewUser, _ := authMgr.CreateUser("viewer1", "secret123", "Viewer1", "v1@local", auth.RoleViewer)
	_, viewerTok, _ := authMgr.CreateToken(viewUser.ID, "v-tok", nil, 0)

	env = &APIEnv{
		Config:         cfg,
		AuthManager:    authMgr,
		AuditLogger:    auditLogger,
		ApprovalStore:  approvalStore,
		PluginRegistry: reg,
		MCPServer:      mcpSrv,
		JobEngine:      jobEngine,
	}
	router := NewRouter(env)
	return env, router, map[string]string{
		"admin":    adminTok,
		"admin2":   admin2Tok,
		"operator": opTok,
		"viewer":   viewerTok,
	}
}

func approveViaAPI(t *testing.T, router http.Handler, approverToken, approvalID string) int {
	t.Helper()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/"+approvalID+"/approve", bytes.NewBufferString(`{"comment":"approved"}`))
	req.Header.Set("Authorization", "Bearer "+approverToken)
	router.ServeHTTP(rr, req)
	return rr.Code
}

func TestHITLPreExecutionGate_CommandPluginJobAndMCP(t *testing.T) {
	env, router, tokens := newHITLGateTestEnv(t, true)

	// 1. Non-critical command executes directly without approval
	{
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/execute", bytes.NewBufferString(`{"name":"safe-cmd"}`))
		req.Header.Set("Authorization", "Bearer "+tokens["operator"])
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("non-critical command status = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
		}
	}

	// 2. RBAC runs BEFORE HITL: viewer gets 403 and creates zero pending approval records
	{
		before := env.ApprovalStore.PendingCount()
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/execute", bytes.NewBufferString(`{"name":"crit-flag-cmd"}`))
		req.Header.Set("Authorization", "Bearer "+tokens["viewer"])
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("viewer critical command status = %d, want 403", rr.Code)
		}
		if env.ApprovalStore.PendingCount() != before {
			t.Fatalf("RBAC-denied request must not create pending approval records")
		}
	}

	// 3. Command HITL flow: challenge -> pending reject -> approve -> tamper 403 -> consume 200 -> replay 409
	{
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/execute", bytes.NewBufferString(`{"name":"crit-flag-cmd","timeout":"3s"}`))
		req.Header.Set("Authorization", "Bearer "+tokens["operator"])
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusAccepted {
			t.Fatalf("critical command initial status = %d, want 202 (body=%s)", rr.Code, rr.Body.String())
		}
		var challenge ApprovalChallengeResponse
		if err := json.Unmarshal(rr.Body.Bytes(), &challenge); err != nil {
			t.Fatalf("decode challenge: %v", err)
		}
		if challenge.Status != "pending_approval" || challenge.ApprovalID == "" {
			t.Fatalf("unexpected challenge: %+v", challenge)
		}

		// Re-submitting while still pending fails closed (409)
		rrPend := httptest.NewRecorder()
		reqPend := httptest.NewRequest(http.MethodPost, "/api/v1/execute", bytes.NewBufferString(`{"name":"crit-flag-cmd","timeout":"3s","approval_id":"`+challenge.ApprovalID+`"}`))
		reqPend.Header.Set("Authorization", "Bearer "+tokens["operator"])
		router.ServeHTTP(rrPend, reqPend)
		if rrPend.Code != http.StatusConflict {
			t.Fatalf("pending approval_id status = %d, want 409", rrPend.Code)
		}

		// Approve by distinct admin
		if code := approveViaAPI(t, router, tokens["admin"], challenge.ApprovalID); code != http.StatusOK {
			t.Fatalf("approve status = %d, want 200", code)
		}

		// Tampered timeout fails closed (403 Forbidden)
		rrTamper := httptest.NewRecorder()
		reqTamper := httptest.NewRequest(http.MethodPost, "/api/v1/execute", bytes.NewBufferString(`{"name":"crit-flag-cmd","timeout":"4s"}`))
		reqTamper.Header.Set("Authorization", "Bearer "+tokens["operator"])
		reqTamper.Header.Set("X-Approval-ID", challenge.ApprovalID)
		router.ServeHTTP(rrTamper, reqTamper)
		if rrTamper.Code != http.StatusForbidden {
			t.Fatalf("tampered payload status = %d, want 403 (body=%s)", rrTamper.Code, rrTamper.Body.String())
		}

		// Exact payload executes once (200 OK)
		rrExec := httptest.NewRecorder()
		reqExec := httptest.NewRequest(http.MethodPost, "/api/v1/execute", bytes.NewBufferString(`{"name":"crit-flag-cmd","timeout":"3s"}`))
		reqExec.Header.Set("Authorization", "Bearer "+tokens["operator"])
		reqExec.Header.Set("X-Approval-ID", challenge.ApprovalID)
		router.ServeHTTP(rrExec, reqExec)
		if rrExec.Code != http.StatusOK {
			t.Fatalf("approved command status = %d, want 200 (body=%s)", rrExec.Code, rrExec.Body.String())
		}

		// Replaying consumed approval_id fails closed (409 Conflict)
		rrReplay := httptest.NewRecorder()
		reqReplay := httptest.NewRequest(http.MethodPost, "/api/v1/execute", bytes.NewBufferString(`{"name":"crit-flag-cmd","timeout":"3s","approval_id":"`+challenge.ApprovalID+`"}`))
		reqReplay.Header.Set("Authorization", "Bearer "+tokens["operator"])
		router.ServeHTTP(rrReplay, reqReplay)
		if rrReplay.Code != http.StatusConflict {
			t.Fatalf("replayed approval_id status = %d, want 409", rrReplay.Code)
		}
	}

	// 4. Plugin HITL flow: challenge -> approve -> tamper 403 -> consume 200
	{
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/plugins/execute", bytes.NewBufferString(`{"plugin_id":"sys-diagnostics","action":"runtime_stats","params":{"k":"v1"}}`))
		req.Header.Set("Authorization", "Bearer "+tokens["operator"])
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusAccepted {
			t.Fatalf("critical plugin status = %d, want 202 (body=%s)", rr.Code, rr.Body.String())
		}
		var ch ApprovalChallengeResponse
		_ = json.Unmarshal(rr.Body.Bytes(), &ch)
		if code := approveViaAPI(t, router, tokens["admin"], ch.ApprovalID); code != http.StatusOK {
			t.Fatalf("approve plugin status = %d, want 200", code)
		}
		// Tampered params -> 403
		rrBad := httptest.NewRecorder()
		reqBad := httptest.NewRequest(http.MethodPost, "/api/v1/plugins/execute", bytes.NewBufferString(`{"plugin_id":"sys-diagnostics","action":"runtime_stats","params":{"k":"v2"},"approval_id":"`+ch.ApprovalID+`"}`))
		reqBad.Header.Set("Authorization", "Bearer "+tokens["operator"])
		router.ServeHTTP(rrBad, reqBad)
		if rrBad.Code != http.StatusForbidden {
			t.Fatalf("tampered plugin params status = %d, want 403", rrBad.Code)
		}
		// Exact params -> 200
		rrOK := httptest.NewRecorder()
		reqOK := httptest.NewRequest(http.MethodPost, "/api/v1/plugins/execute", bytes.NewBufferString(`{"plugin_id":"sys-diagnostics","action":"runtime_stats","params":{"k":"v1"},"approval_id":"`+ch.ApprovalID+`"}`))
		reqOK.Header.Set("Authorization", "Bearer "+tokens["operator"])
		router.ServeHTTP(rrOK, reqOK)
		if rrOK.Code != http.StatusOK {
			t.Fatalf("approved plugin status = %d, want 200 (body=%s)", rrOK.Code, rrOK.Body.String())
		}
	}

	// 5. Async Job HITL flow: challenge (not enqueued) -> approve -> enqueue (202 queued)
	{
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/jobs", bytes.NewBufferString(`{"type":"command","action":"restart-postgres"}`))
		req.Header.Set("Authorization", "Bearer "+tokens["operator"])
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusAccepted {
			t.Fatalf("critical job initial status = %d, want 202", rr.Code)
		}
		var ch ApprovalChallengeResponse
		_ = json.Unmarshal(rr.Body.Bytes(), &ch)
		if ch.Status != "pending_approval" || ch.ApprovalID == "" {
			t.Fatalf("expected pending_approval challenge for job, got %+v", ch)
		}
		if _, total := env.JobEngine.ListJobs(jobs.JobFilter{}); total != 0 {
			t.Fatalf("expected 0 jobs enqueued before approval, got %d", total)
		}
		if code := approveViaAPI(t, router, tokens["admin"], ch.ApprovalID); code != http.StatusOK {
			t.Fatalf("approve job status = %d, want 200", code)
		}
		rrRun := httptest.NewRecorder()
		reqRun := httptest.NewRequest(http.MethodPost, "/api/v1/jobs", bytes.NewBufferString(`{"type":"command","action":"restart-postgres","approval_id":"`+ch.ApprovalID+`"}`))
		reqRun.Header.Set("Authorization", "Bearer "+tokens["operator"])
		router.ServeHTTP(rrRun, reqRun)
		if rrRun.Code != http.StatusAccepted {
			t.Fatalf("approved job submit status = %d, want 202 (body=%s)", rrRun.Code, rrRun.Body.String())
		}
		var jobResp SubmitJobResponse
		_ = json.Unmarshal(rrRun.Body.Bytes(), &jobResp)
		if jobResp.JobID == "" || jobResp.Status != jobs.StatusQueued {
			t.Fatalf("expected queued job response, got %+v", jobResp)
		}
	}

	// 6. MCP tools/call HITL flow (including admin distinct-approver check across MCP->REST)
	{
		rpcPayload := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"execute_command","arguments":{"name":"restart-postgres"}}}`
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/mcp", bytes.NewBufferString(rpcPayload))
		req.Header.Set("Authorization", "Bearer "+tokens["admin"])
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("MCP tools/call status = %d, want 200", rr.Code)
		}
		var rpcResp struct {
			Result struct {
				IsError           bool           `json:"isError"`
				StructuredContent map[string]any `json:"structuredContent"`
			} `json:"result"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &rpcResp); err != nil {
			t.Fatalf("decode MCP response: %v", err)
		}
		if rpcResp.Result.IsError || rpcResp.Result.StructuredContent["status"] != "pending_approval" {
			t.Fatalf("expected pending_approval MCP challenge, got %+v", rpcResp)
		}
		approvalID, _ := rpcResp.Result.StructuredContent["approval_id"].(string)
		if approvalID == "" {
			t.Fatalf("expected non-empty approval_id in MCP structuredContent")
		}

		// Admin who requested via MCP MUST NOT be able to self-approve!
		if code := approveViaAPI(t, router, tokens["admin"], approvalID); code != http.StatusForbidden {
			t.Fatalf("admin self-approval of own MCP request = %d, want 403", code)
		}
		// Distinct admin2 approves
		if code := approveViaAPI(t, router, tokens["admin2"], approvalID); code != http.StatusOK {
			t.Fatalf("admin2 approve MCP request = %d, want 200", code)
		}

		// Tampered MCP arguments fail closed (isError: true)
		tamperRPC := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"execute_command","arguments":{"name":"restart-postgres","timeout":"2s","_approval_id":"` + approvalID + `"}}}`
		rrTamper := httptest.NewRecorder()
		reqTamper := httptest.NewRequest(http.MethodPost, "/api/v1/mcp", bytes.NewBufferString(tamperRPC))
		reqTamper.Header.Set("Authorization", "Bearer "+tokens["admin"])
		router.ServeHTTP(rrTamper, reqTamper)
		var tamperResp struct {
			Result struct {
				IsError bool `json:"isError"`
			} `json:"result"`
		}
		_ = json.Unmarshal(rrTamper.Body.Bytes(), &tamperResp)
		if !tamperResp.Result.IsError {
			t.Fatalf("expected tampered MCP call to fail closed with isError=true")
		}

		// Exact MCP arguments with _approval_id execute once and consume approval
		okRPC := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"execute_command","arguments":{"name":"restart-postgres","_approval_id":"` + approvalID + `"}}}`
		rrOK := httptest.NewRecorder()
		reqOK := httptest.NewRequest(http.MethodPost, "/api/v1/mcp", bytes.NewBufferString(okRPC))
		reqOK.Header.Set("Authorization", "Bearer "+tokens["admin"])
		router.ServeHTTP(rrOK, reqOK)
		var okResp struct {
			Result struct {
				IsError bool `json:"isError"`
			} `json:"result"`
		}
		_ = json.Unmarshal(rrOK.Body.Bytes(), &okResp)
		if okResp.Result.IsError {
			t.Fatalf("expected approved MCP call to succeed, body=%s", rrOK.Body.String())
		}

		// Replay fails closed
		rrReplay := httptest.NewRecorder()
		reqReplay := httptest.NewRequest(http.MethodPost, "/api/v1/mcp", bytes.NewBufferString(okRPC))
		reqReplay.Header.Set("Authorization", "Bearer "+tokens["admin"])
		router.ServeHTTP(rrReplay, reqReplay)
		var replayResp struct {
			Result struct {
				IsError bool `json:"isError"`
			} `json:"result"`
		}
		_ = json.Unmarshal(rrReplay.Body.Bytes(), &replayResp)
		if !replayResp.Result.IsError {
			t.Fatalf("expected replayed MCP approval_id to fail closed")
		}
	}

	// 7. SHA-256 audit chain remains valid
	if ver := env.AuditLogger.VerifyChain(); !ver.Valid {
		t.Fatalf("expected valid SHA-256 audit chain, got %+v", ver)
	}
}

func TestHITLPreExecutionGate_DisabledBackwardCompatibility(t *testing.T) {
	_, router, tokens := newHITLGateTestEnv(t, false)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/execute", bytes.NewBufferString(`{"name":"crit-flag-cmd"}`))
	req.Header.Set("Authorization", "Bearer "+tokens["operator"])
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK when approval.enabled=false, got %d (body=%s)", rr.Code, rr.Body.String())
	}
}
