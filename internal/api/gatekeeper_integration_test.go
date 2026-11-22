package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"go-admin-tool/internal/audit"
	"go-admin-tool/internal/core"
	"go-admin-tool/internal/gatekeeper"
)

func newSystem1BastionTestEnv(t *testing.T, hitlEnabled bool) (*APIEnv, http.Handler, map[string]string, func(resp string), *atomic.Int64) {
	t.Helper()
	var mu sync.Mutex
	var mockResp = `{"schema_version":"microllm.guard.v1","decision":"allow","confidence":0.95,"abstain":false,"reason":"safe","risk_score":0.05}`
	var callCount atomic.Int64

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		callCount.Add(1)
		mu.Lock()
		body := mockResp
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(ts.Close)

	env, _, tokens := newHITLGateTestEnv(t, hitlEnabled)
	env.Config.Gatekeeper = core.GatekeeperConfig{
		Enabled:       true,
		Mode:          "http",
		Endpoint:      ts.URL + "/v1/guard/evaluate",
		Timeout:       "100ms",
		MinConfidence: 0.70,
		FailMode:      "escalate_hitl",
		Environment:   "production",
	}
	gk, err := gatekeeper.NewFromConfig(env.Config.Gatekeeper, env.Config.Sandbox)
	if err != nil {
		t.Fatalf("gatekeeper.NewFromConfig: %v", err)
	}
	t.Cleanup(func() { _ = gk.Close() })

	env.Gatekeeper = gk
	env.MCPServer.SetApprovalGate(env.NewMCPApprovalGate())
	router := NewRouter(env)

	setResp := func(r string) {
		mu.Lock()
		mockResp = r
		mu.Unlock()
	}
	return env, router, tokens, setResp, &callCount
}

func TestSystem1Gatekeeper_AllowDenyAbstainAndHITLPrecedence(t *testing.T) {
	ResetGatekeeperMetrics()
	env, router, tokens, setResp, gkCalls := newSystem1BastionTestEnv(t, true)

	// 1. System-1 allow -> executes command, plugin, and MCP normally with gatekeeper.allow audit + MCPTrace metadata
	{
		setResp(`{"schema_version":"microllm.guard.v1","decision":"allow","confidence":0.96,"abstain":false,"reason":"read-only","risk_score":0.04}`)
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/execute", bytes.NewBufferString(`{"name":"safe-cmd"}`))
		req.Header.Set("Authorization", "Bearer "+tokens["operator"])
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("allow command status = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
		}

		// MCP execute_command allow attaches gatekeeper_decision to MCPTrace
		rrMCP := httptest.NewRecorder()
		reqMCP := httptest.NewRequest(http.MethodPost, "/api/v1/mcp", bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"execute_command","arguments":{"name":"safe-cmd"}}}`))
		reqMCP.Header.Set("Authorization", "Bearer "+tokens["operator"])
		router.ServeHTTP(rrMCP, reqMCP)
		if rrMCP.Code != http.StatusOK {
			t.Fatalf("allow MCP status = %d, want 200", rrMCP.Code)
		}
		traceID := rrMCP.Header().Get("X-MCP-Trace-ID")
		tr, err := env.MCPServer.GetTrace(traceID)
		if err != nil || tr.GatekeeperDecision != "allow" {
			t.Fatalf("expected MCPTrace.GatekeeperDecision='allow', got %+v err=%v", tr, err)
		}
		if GetGatekeeperDecisionCount("allow", "command") < 1 || GetGatekeeperDecisionCount("allow", "mcp") < 1 {
			t.Fatalf("expected gatekeeper_decisions_total allow counters incremented")
		}
	}

	// 2. System-1 allow NEVER bypasses RBAC denial (viewer -> 403, gatekeeper not invoked)
	{
		before := gkCalls.Load()
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/execute", bytes.NewBufferString(`{"name":"safe-cmd"}`))
		req.Header.Set("Authorization", "Bearer "+tokens["viewer"])
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("viewer status = %d, want 403", rr.Code)
		}
		if gkCalls.Load() != before {
			t.Fatalf("gatekeeper must not run when RBAC denies")
		}
	}

	// 3. System-1 allow NEVER bypasses static RequireApproval: true command
	{
		before := gkCalls.Load()
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/execute", bytes.NewBufferString(`{"name":"crit-flag-cmd"}`))
		req.Header.Set("Authorization", "Bearer "+tokens["operator"])
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusAccepted {
			t.Fatalf("static RequireApproval command status = %d, want 202 (body=%s)", rr.Code, rr.Body.String())
		}
		if gkCalls.Load() != before {
			t.Fatalf("static HITL policy must pause before System-1 allow can bypass it")
		}
	}

	// 4. System-1 deny (MicroLLM "block") blocks REST command, job, and MCP with 403 / MCP isError
	{
		setResp(`{"schema_version":"microllm.guard.v1","decision":"block","confidence":0.99,"abstain":false,"reason":"destructive","risk_score":0.98,"primary_threat":"destruction"}`)

		rrCmd := httptest.NewRecorder()
		reqCmd := httptest.NewRequest(http.MethodPost, "/api/v1/execute", bytes.NewBufferString(`{"name":"safe-cmd"}`))
		reqCmd.Header.Set("Authorization", "Bearer "+tokens["operator"])
		router.ServeHTTP(rrCmd, reqCmd)
		if rrCmd.Code != http.StatusForbidden {
			t.Fatalf("deny command status = %d, want 403", rrCmd.Code)
		}

		rrJob := httptest.NewRecorder()
		reqJob := httptest.NewRequest(http.MethodPost, "/api/v1/jobs", bytes.NewBufferString(`{"type":"command","action":"safe-cmd"}`))
		reqJob.Header.Set("Authorization", "Bearer "+tokens["operator"])
		router.ServeHTTP(rrJob, reqJob)
		if rrJob.Code != http.StatusForbidden {
			t.Fatalf("deny job status = %d, want 403", rrJob.Code)
		}

		rrMCP := httptest.NewRecorder()
		reqMCP := httptest.NewRequest(http.MethodPost, "/api/v1/mcp", bytes.NewBufferString(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"execute_command","arguments":{"name":"safe-cmd"}}}`))
		reqMCP.Header.Set("Authorization", "Bearer "+tokens["operator"])
		router.ServeHTTP(rrMCP, reqMCP)
		var mcpOut struct {
			Result struct {
				IsError bool `json:"isError"`
			} `json:"result"`
		}
		_ = json.Unmarshal(rrMCP.Body.Bytes(), &mcpOut)
		if !mcpOut.Result.IsError {
			t.Fatalf("expected MCP isError=true on System-1 deny, body=%s", rrMCP.Body.String())
		}
	}

	// 5. System-1 x_abstain (MicroLLM "escalate") escalates to HITL -> admin approves -> re-submit executes once!
	{
		setResp(`{"schema_version":"microllm.guard.v1","decision":"escalate","confidence":0.52,"abstain":true,"reason":"uncertain side effects","risk_score":0.55}`)

		// 5a. REST command escalation -> approve -> execute -> replay blocked
		rrEsc := httptest.NewRecorder()
		reqEsc := httptest.NewRequest(http.MethodPost, "/api/v1/execute", bytes.NewBufferString(`{"name":"safe-cmd"}`))
		reqEsc.Header.Set("Authorization", "Bearer "+tokens["operator"])
		router.ServeHTTP(rrEsc, reqEsc)
		if rrEsc.Code != http.StatusAccepted {
			t.Fatalf("x_abstain REST command status = %d, want 202 (body=%s)", rrEsc.Code, rrEsc.Body.String())
		}
		var ch ApprovalChallengeResponse
		if err := json.Unmarshal(rrEsc.Body.Bytes(), &ch); err != nil {
			t.Fatalf("decode challenge: %v", err)
		}
		if ch.Status != "pending_approval" || ch.ApprovalID == "" || ch.GatekeeperDecision != "x_abstain" {
			t.Fatalf("unexpected x_abstain challenge: %+v", ch)
		}

		// Approve by admin
		if code := approveViaAPI(t, router, tokens["admin"], ch.ApprovalID); code != http.StatusOK {
			t.Fatalf("admin approve escalated request = %d, want 200", code)
		}

		// Re-submit with approval_id executes once even though System-1 still returns escalate!
		rrExec := httptest.NewRecorder()
		reqExec := httptest.NewRequest(http.MethodPost, "/api/v1/execute", bytes.NewBufferString(`{"name":"safe-cmd","approval_id":"`+ch.ApprovalID+`"}`))
		reqExec.Header.Set("Authorization", "Bearer "+tokens["operator"])
		router.ServeHTTP(rrExec, reqExec)
		if rrExec.Code != http.StatusOK {
			t.Fatalf("approved escalated command status = %d, want 200 (body=%s)", rrExec.Code, rrExec.Body.String())
		}

		// Replay of consumed approval_id fails closed (409)
		rrReplay := httptest.NewRecorder()
		reqReplay := httptest.NewRequest(http.MethodPost, "/api/v1/execute", bytes.NewBufferString(`{"name":"safe-cmd","approval_id":"`+ch.ApprovalID+`"}`))
		reqReplay.Header.Set("Authorization", "Bearer "+tokens["operator"])
		router.ServeHTTP(rrReplay, reqReplay)
		if rrReplay.Code != http.StatusConflict {
			t.Fatalf("replayed approval status = %d, want 409", rrReplay.Code)
		}

		// 5b. MCP escalation -> admin approve -> MCP re-submit executes once
		rrMCPEsc := httptest.NewRecorder()
		reqMCPEsc := httptest.NewRequest(http.MethodPost, "/api/v1/mcp", bytes.NewBufferString(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"execute_command","arguments":{"name":"safe-cmd"}}}`))
		reqMCPEsc.Header.Set("Authorization", "Bearer "+tokens["operator"])
		router.ServeHTTP(rrMCPEsc, reqMCPEsc)
		var mcpEsc struct {
			Result struct {
				IsError           bool           `json:"isError"`
				StructuredContent map[string]any `json:"structuredContent"`
			} `json:"result"`
		}
		_ = json.Unmarshal(rrMCPEsc.Body.Bytes(), &mcpEsc)
		mcpApprID, _ := mcpEsc.Result.StructuredContent["approval_id"].(string)
		if mcpEsc.Result.IsError || mcpEsc.Result.StructuredContent["status"] != "pending_approval" || mcpApprID == "" {
			t.Fatalf("expected MCP pending_approval escalation, got %+v", mcpEsc)
		}
		if code := approveViaAPI(t, router, tokens["admin"], mcpApprID); code != http.StatusOK {
			t.Fatalf("approve MCP escalation = %d, want 200", code)
		}
		rrMCPOk := httptest.NewRecorder()
		reqMCPOk := httptest.NewRequest(http.MethodPost, "/api/v1/mcp", bytes.NewBufferString(`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"execute_command","arguments":{"name":"safe-cmd","_approval_id":"`+mcpApprID+`"}}}`))
		reqMCPOk.Header.Set("Authorization", "Bearer "+tokens["operator"])
		router.ServeHTTP(rrMCPOk, reqMCPOk)
		var mcpOk struct {
			Result struct {
				IsError bool `json:"isError"`
			} `json:"result"`
		}
		_ = json.Unmarshal(rrMCPOk.Body.Bytes(), &mcpOk)
		if mcpOk.Result.IsError {
			t.Fatalf("expected approved MCP call to succeed, body=%s", rrMCPOk.Body.String())
		}
	}

	// 6. Both SHA-256 audit chain and MCP trace chain remain valid
	if v := env.AuditLogger.VerifyChain(); !v.Valid {
		t.Fatalf("audit chain invalid: %+v", v)
	}
	if v := env.MCPServer.VerifyTraceChain(); !v.Valid {
		t.Fatalf("MCP trace chain invalid: %+v", v)
	}
	gkAudit := env.AuditLogger.Query(audit.AuditFilter{Category: "gatekeeper", Limit: 50})
	if len(gkAudit) < 4 {
		t.Fatalf("expected >= 4 gatekeeper audit events, got %d", len(gkAudit))
	}
}

func TestSystem1Gatekeeper_AbstainFailsClosedWhenHITLDisabled(t *testing.T) {
	_, router, tokens, setResp, _ := newSystem1BastionTestEnv(t, false)
	setResp(`{"schema_version":"microllm.guard.v1","decision":"escalate","confidence":0.45,"abstain":true,"reason":"ambiguous"}`)

	// REST command fails closed 403 (never falls through to execution!)
	rrCmd := httptest.NewRecorder()
	reqCmd := httptest.NewRequest(http.MethodPost, "/api/v1/execute", bytes.NewBufferString(`{"name":"safe-cmd"}`))
	reqCmd.Header.Set("Authorization", "Bearer "+tokens["operator"])
	router.ServeHTTP(rrCmd, reqCmd)
	if rrCmd.Code != http.StatusForbidden {
		t.Fatalf("x_abstain with HITL disabled (REST) = %d, want 403 (body=%s)", rrCmd.Code, rrCmd.Body.String())
	}

	// MCP tool fails closed with isError=true
	rrMCP := httptest.NewRecorder()
	reqMCP := httptest.NewRequest(http.MethodPost, "/api/v1/mcp", bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"execute_command","arguments":{"name":"safe-cmd"}}}`))
	reqMCP.Header.Set("Authorization", "Bearer "+tokens["operator"])
	router.ServeHTTP(rrMCP, reqMCP)
	var mcpOut struct {
		Result struct {
			IsError bool `json:"isError"`
		} `json:"result"`
	}
	_ = json.Unmarshal(rrMCP.Body.Bytes(), &mcpOut)
	if !mcpOut.Result.IsError {
		t.Fatalf("expected MCP isError=true when x_abstain occurs with HITL disabled, body=%s", rrMCP.Body.String())
	}
}
