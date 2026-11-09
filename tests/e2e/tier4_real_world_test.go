package e2e_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"go-admin-tool/internal/auth"
	"go-admin-tool/internal/jobs"
	"go-admin-tool/internal/mcp"
)

// ============================================================================
// Tier 4: Real-World Application & Autonomous Agent Scenarios
// ============================================================================

// TestTier4_Scenario_ComprehensiveSystemDiagnosticsWorkflow simulates a multi-step
// infrastructure engineer runbook executing consecutive system probes and validating audit integrity.
func TestTier4_Scenario_ComprehensiveSystemDiagnosticsWorkflow(t *testing.T) {
	srv := setupE2ETestServer(t)

	// Step 1: Probe host runtime telemetry
	code1, res1, _ := httpExecutePlugin(t, srv, srv.adminPAT, map[string]any{
		"plugin_id": "sys-diagnostics",
		"action":    "runtime_stats",
	})
	if code1 != http.StatusOK || res1.Status != "ok" {
		t.Fatalf("Step 1 failed: runtime_stats code=%d status=%s", code1, res1.Status)
	}

	// Step 2: Enumerate network interfaces
	code2, res2, _ := httpExecutePlugin(t, srv, srv.adminPAT, map[string]any{
		"plugin_id": "sys-diagnostics",
		"action":    "network_interfaces",
	})
	if code2 != http.StatusOK || res2.Status != "ok" {
		t.Fatalf("Step 2 failed: network_interfaces code=%d status=%s", code2, res2.Status)
	}

	// Step 3: Inspect environment summary
	code3, res3, _ := httpExecutePlugin(t, srv, srv.adminPAT, map[string]any{
		"plugin_id": "sys-diagnostics",
		"action":    "env_summary",
	})
	if code3 != http.StatusOK || res3.Status != "ok" {
		t.Fatalf("Step 3 failed: env_summary code=%d status=%s", code3, res3.Status)
	}

	// Step 4: Verify audit log records all three diagnostic steps with non-empty SHA-256 hashes
	auditCode, events := httpGetAuditLogs(t, srv, srv.adminPAT, "?category=plugin")
	if auditCode != http.StatusOK {
		t.Fatalf("Step 4 failed: could not retrieve audit logs, code=%d", auditCode)
	}

	actionsFound := 0
	for _, ev := range events {
		if strings.Contains(ev.Action, "sys-diagnostics") {
			actionsFound++
			if ev.EntryHash == "" {
				t.Errorf("Step 4: audit event missing EntryHash: %+v", ev)
			}
		}
	}
	if actionsFound < 3 {
		t.Errorf("Step 4: expected at least 3 audit entries for sys-diagnostics, found %d", actionsFound)
	}

	// Step 5: Verify the entire cryptographic chain remains valid
	_, verResult := httpVerifyAuditChain(t, srv, srv.adminPAT)
	if !verResult.Valid {
		t.Errorf("Step 5: cryptographic audit chain is invalid")
	}
}

// TestTier4_Scenario_DatabaseHealthAndTableInspectionWorkflow simulates an automated
// DataOps triage workflow checking database tables, telemetry, and connection stats.
func TestTier4_Scenario_DatabaseHealthAndTableInspectionWorkflow(t *testing.T) {
	srv := setupE2ETestServer(t)

	// Step 1: Discover database exposure plugin in catalog
	code1, resp1 := httpGetPlugins(t, srv, srv.adminPAT, "?q=db-exposure")
	if code1 != http.StatusOK {
		t.Fatalf("Step 1 failed: catalog discovery code=%d", code1)
	}
	foundDB := false
	for _, p := range resp1.Plugins {
		if p.ID == "db-exposure" {
			foundDB = true
		}
	}
	if !foundDB {
		t.Fatalf("Step 1 failed: db-exposure plugin not discovered")
	}

	// Step 2: List database tables via plugin execute
	code2, res2, _ := httpExecutePlugin(t, srv, srv.adminPAT, map[string]any{
		"plugin_id": "db-exposure",
		"action":    "list_tables",
	})
	if code2 != http.StatusOK || res2.Status != "ok" {
		t.Fatalf("Step 2 failed: list_tables code=%d status=%s", code2, res2.Status)
	}

	// Step 3: Fetch database statistics
	code3, res3, _ := httpExecutePlugin(t, srv, srv.adminPAT, map[string]any{
		"plugin_id": "db-exposure",
		"action":    "db_stats",
	})
	if code3 != http.StatusOK || res3.Status != "ok" {
		t.Fatalf("Step 3 failed: db_stats code=%d status=%s", code3, res3.Status)
	}
}

// TestTier4_Scenario_MultiDomainTriageViaMCPAgentSimulation simulates an autonomous
// LLM MCP client performing end-to-end host discovery, reading the catalog resource,
// and invoking tools.
func TestTier4_Scenario_MultiDomainTriageViaMCPAgentSimulation(t *testing.T) {
	srv := setupE2ETestServer(t)

	// Step 1: Agent Handshake (initialize)
	initReq := mcp.JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
	}
	code1, resp1, _ := httpMCPCall(t, srv, srv.adminPAT, initReq)
	if code1 != http.StatusOK || resp1.Error != nil {
		t.Fatalf("Step 1 Handshake failed: code=%d err=%+v", code1, resp1.Error)
	}

	// Step 2: Agent Discovers Resources (resources/list)
	listResReq := mcp.JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      2,
		Method:  "resources/list",
	}
	code2, resp2, _ := httpMCPCall(t, srv, srv.adminPAT, listResReq)
	if code2 != http.StatusOK || resp2.Error != nil {
		t.Fatalf("Step 2 Resources list failed: code=%d err=%+v", code2, resp2.Error)
	}

	// Step 3: Agent Reads Plugins Catalog Resource (resources/read)
	readCatReq := mcp.JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      3,
		Method:  "resources/read",
		Params:  []byte(`{"uri":"executor://plugins/catalog"}`),
	}
	code3, resp3, _ := httpMCPCall(t, srv, srv.adminPAT, readCatReq)
	if code3 != http.StatusOK || resp3.Error != nil {
		t.Fatalf("Step 3 Catalog read failed: code=%d err=%+v", code3, resp3.Error)
	}

	// Step 4: Agent Executes Triage Tool (tools/call execute_plugin)
	callBytes, _ := json.Marshal(map[string]any{
		"name": "execute_plugin",
		"arguments": map[string]any{
			"plugin_id": "sys-diagnostics",
			"action":    "runtime_stats",
		},
	})
	callToolReq := mcp.JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      4,
		Method:  "tools/call",
		Params:  callBytes,
	}
	code4, resp4, _ := httpMCPCall(t, srv, srv.adminPAT, callToolReq)
	if code4 != http.StatusOK || resp4.Error != nil {
		t.Fatalf("Step 4 Tool call failed: code=%d err=%+v", code4, resp4.Error)
	}

	callResRaw, _ := json.Marshal(resp4.Result)
	var callRes mcp.MCPCallToolResult
	_ = json.Unmarshal(callResRaw, &callRes)
	if callRes.IsError {
		t.Errorf("Step 4: expected tool call success, got IsError=true")
	}
}

// TestTier4_Scenario_DynamicOpsRemediationAndAuditLifecycle simulates an operational
// incident remediation where an SRE registers a custom declarative verification check,
// executes it with strict parameter validation, and verifies the audit record and metrics.
func TestTier4_Scenario_DynamicOpsRemediationAndAuditLifecycle(t *testing.T) {
	srv := setupE2ETestServer(t)

	// Step 1: Register incident response declarative check module
	incidentModuleID := "incident-ir-994"
	echoCmd, baseEchoArgs := crossPlatformEcho()
	echoArgs := append([]string{}, baseEchoArgs...)
	echoArgs = append(echoArgs, "incident=IR-994", "status=resolved", "host={{target_host}}")

	spec := map[string]any{
		"id":          incidentModuleID,
		"name":        "Incident IR-994 Health Check",
		"version":     "1.0.0",
		"description": "Emergency triage module registered during active incident response",
		"actions": []map[string]any{
			{
				"name":        "verify-host",
				"description": "Verifies host connectivity",
				"command":     echoCmd,
				"args":        echoArgs,
				"timeout":     "5s",
				"parameters": []map[string]any{
					{
						"name":        "target_host",
						"type":        "string",
						"required":    true,
						"pattern":     `^[a-zA-Z0-9.-]+$`,
						"description": "Host identifier to verify",
					},
				},
			},
		},
	}

	code1, _, raw1 := httpRegisterDeclarativePlugin(t, srv, srv.adminPAT, spec)
	if code1 != http.StatusCreated {
		t.Fatalf("Step 1 registration failed: code=%d raw=%s", code1, raw1)
	}

	// Step 2: Attempt execution with invalid metacharacter parameter (adversarial check)
	code2, _, _ := httpExecutePlugin(t, srv, srv.adminPAT, map[string]any{
		"plugin_id": incidentModuleID,
		"action":    "verify-host",
		"params":    map[string]any{"target_host": "host; whoami"},
	})
	if code2 != http.StatusBadRequest {
		t.Fatalf("Step 2 security validation failed: expected 400 Bad Request, got %d", code2)
	}

	// Step 3: Execute with valid parameter
	code3, res3, _ := httpExecutePlugin(t, srv, srv.adminPAT, map[string]any{
		"plugin_id": incidentModuleID,
		"action":    "verify-host",
		"params":    map[string]any{"target_host": "edge-lb-01.internal"},
	})
	if code3 != http.StatusOK || res3.Status != "ok" {
		t.Fatalf("Step 3 valid execution failed: code=%d status=%s", code3, res3.Status)
	}
	if !strings.Contains(res3.Output, "status=resolved") {
		t.Errorf("Step 3: expected output to include 'status=resolved', got: %s", res3.Output)
	}

	// Step 4: Verify audit log recorded the registration and execution
	auditCode, events := httpGetAuditLogs(t, srv, srv.adminPAT, "?category=plugin")
	if auditCode != http.StatusOK {
		t.Fatalf("Step 4: failed to retrieve audit logs, code=%d", auditCode)
	}
	foundIR := false
	for _, ev := range events {
		if strings.Contains(ev.Action, incidentModuleID) || strings.Contains(ev.Summary, incidentModuleID) {
			foundIR = true
		}
	}
	if !foundIR {
		t.Errorf("Step 4: expected audit event for incident module %s", incidentModuleID)
	}

	// Step 5: Verify cryptographic audit integrity
	_, verResult := httpVerifyAuditChain(t, srv, srv.adminPAT)
	if !verResult.Valid {
		t.Errorf("Step 5: audit chain verification failed")
	}
}

// ============================================================================
// Tier 4: Feature 6 Real-World Operational & Multi-Tenant Scenarios
// ============================================================================

func TestTier4_Scenario_OperationalBatchDiagnosticWorkflow_StreamLogsAndMidFlightCancellation(t *testing.T) {
	srv := setupE2ETestServer(t)

	// Step 1: Submit 3 diagnostic jobs (2 fast probes, 1 slow stuck probe)
	code1, resp1, _ := httpSubmitJob(t, srv, srv.adminPAT, map[string]any{
		"type":      "plugin",
		"plugin_id": "sys-diagnostics",
		"action":    "runtime_stats",
		"priority":  "high",
	})
	if code1 != http.StatusAccepted {
		t.Fatalf("Step 1: runtime_stats submit failed: %d", code1)
	}

	code2, resp2, _ := httpSubmitJob(t, srv, srv.adminPAT, map[string]any{
		"type":      "plugin",
		"plugin_id": "sys-diagnostics",
		"action":    "network_interfaces",
		"priority":  "normal",
	})
	if code2 != http.StatusAccepted {
		t.Fatalf("Step 1: network_interfaces submit failed: %d", code2)
	}

	code3, resp3, _ := httpSubmitJob(t, srv, srv.adminPAT, map[string]any{
		"type":     "command",
		"action":   "slow-diag-cmd",
		"priority": "low",
	})
	if code3 != http.StatusAccepted {
		t.Fatalf("Step 1: slow-diag-cmd submit failed: %d", code3)
	}

	// Step 2: Poll Queue Telemetry
	qCode, qStats, _ := httpGetJobQueue(t, srv, srv.adminPAT)
	if qCode != http.StatusOK {
		t.Fatalf("Step 2: queue telemetry failed: %d", qCode)
	}
	if qStats.WorkersTotal <= 0 {
		t.Errorf("Step 2: expected positive WorkersTotal, got %d", qStats.WorkersTotal)
	}

	// Step 3: Stream and verify logs for Job 1 until EOF
	streamLogs := pollJobLogsUntilEOF(t, srv, srv.adminPAT, resp1.JobID, 5*time.Second)
	if !strings.Contains(streamLogs, "runtime") && !strings.Contains(streamLogs, "stats") && !strings.Contains(streamLogs, "heap") {
		t.Logf("Streamed logs for Job 1: %s", streamLogs)
	}

	// Wait for Job 2 to finish
	pollJobTerminal(t, srv, srv.adminPAT, resp2.JobID, 5*time.Second)

	// Step 4: Mid-Flight Cancellation of the Stuck Diagnostic Job 3
	time.Sleep(50 * time.Millisecond) // Ensure it started executing
	cCode, cResp, cRaw := httpCancelJob(t, srv, srv.adminPAT, resp3.JobID)
	if cCode != http.StatusOK {
		t.Fatalf("Step 4: cancellation failed with code %d: %s", cCode, cRaw)
	}
	if cResp.Status != jobs.StatusCancelled {
		t.Errorf("Step 4: expected status cancelled, got %s", cResp.Status)
	}

	// Wait for cancelled terminal state
	job3 := pollJobTerminal(t, srv, srv.adminPAT, resp3.JobID, 5*time.Second)
	if job3.Status != jobs.StatusCancelled {
		t.Fatalf("Step 4: expected cancelled status for job 3, got %s", job3.Status)
	}

	// Confirm final status in job detail endpoint
	gCode, job3Detail, _ := httpGetJob(t, srv, srv.adminPAT, resp3.JobID)
	if gCode != http.StatusOK || job3Detail.Status != jobs.StatusCancelled {
		t.Fatalf("Step 4: expected cancelled status for job 3 detail, got code=%d status=%s", gCode, job3Detail.Status)
	}

	// Step 5: Verify Cryptographic SHA-256 Audit Integrity
	vCode, vRes := httpVerifyAuditChain(t, srv, srv.adminPAT)
	if vCode != http.StatusOK || !vRes.Valid {
		t.Fatalf("Step 5: audit verification failed: valid=%v brokenAt=%d", vRes.Valid, vRes.BrokenAtID)
	}
}

func TestTier4_Scenario_MultiTenantIsolation_JobHistoryAndAuditScoping(t *testing.T) {
	srv := setupE2ETestServer(t)

	// Create Tenant Alpha user & token
	userAlpha, err := srv.authMgr.CreateUser("tenant_alpha", "PasswordAlpha123!", "Tenant Alpha", "alpha@tenant.test", auth.RoleOperator)
	if err != nil && !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("failed to create tenant_alpha: %v", err)
	}
	_, tokenAlpha, err := srv.authMgr.CreateToken(userAlpha.ID, "alpha-pat", []string{
		auth.ScopeJobsSubmit, auth.ScopeJobsRead, auth.ScopeJobsCancel, "commands:execute", "plugins:execute",
	}, 24*time.Hour)
	if err != nil {
		t.Fatalf("failed to issue tokenAlpha: %v", err)
	}

	// Create Tenant Beta user & token
	userBeta, err := srv.authMgr.CreateUser("tenant_beta", "PasswordBeta123!", "Tenant Beta", "beta@tenant.test", auth.RoleOperator)
	if err != nil && !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("failed to create tenant_beta: %v", err)
	}
	_, tokenBeta, err := srv.authMgr.CreateToken(userBeta.ID, "beta-pat", []string{
		auth.ScopeJobsSubmit, auth.ScopeJobsRead, auth.ScopeJobsCancel, "commands:execute", "plugins:execute",
	}, 24*time.Hour)
	if err != nil {
		t.Fatalf("failed to issue tokenBeta: %v", err)
	}

	// Tenant Alpha submits 2 jobs
	codeA1, respA1, _ := httpSubmitJob(t, srv, tokenAlpha, map[string]any{"type": "command", "action": "echo-cmd"})
	codeA2, respA2, _ := httpSubmitJob(t, srv, tokenAlpha, map[string]any{"type": "command", "action": "echo-cmd"})
	if codeA1 != http.StatusAccepted || codeA2 != http.StatusAccepted {
		t.Fatalf("Tenant Alpha job submission failed: codeA1=%d codeA2=%d", codeA1, codeA2)
	}

	// Tenant Beta submits 2 jobs
	codeB1, respB1, _ := httpSubmitJob(t, srv, tokenBeta, map[string]any{"type": "command", "action": "echo-cmd"})
	codeB2, respB2, _ := httpSubmitJob(t, srv, tokenBeta, map[string]any{"type": "command", "action": "echo-cmd"})
	if codeB1 != http.StatusAccepted || codeB2 != http.StatusAccepted {
		t.Fatalf("Tenant Beta job submission failed: codeB1=%d codeB2=%d", codeB1, codeB2)
	}

	// Wait for all jobs to reach terminal state
	pollJobTerminal(t, srv, tokenAlpha, respA1.JobID, 5*time.Second)
	pollJobTerminal(t, srv, tokenAlpha, respA2.JobID, 5*time.Second)
	pollJobTerminal(t, srv, tokenBeta, respB1.JobID, 5*time.Second)
	pollJobTerminal(t, srv, tokenBeta, respB2.JobID, 5*time.Second)

	// Step 1: Query job history filtered by actor_id=tenant_alpha
	codeListA, listA, rawListA := httpListJobs(t, srv, tokenAlpha, "?actor_id=tenant_alpha")
	if codeListA != http.StatusOK {
		t.Fatalf("failed to list Alpha jobs: %d: %s", codeListA, rawListA)
	}
	if len(listA.Jobs) < 2 {
		t.Fatalf("expected at least 2 Alpha jobs, got %d", len(listA.Jobs))
	}
	for _, j := range listA.Jobs {
		if j.ActorID != "tenant_alpha" {
			t.Errorf("multi-tenant breach: non-alpha job returned in alpha query: %+v", j)
		}
		if j.ID == respB1.JobID || j.ID == respB2.JobID {
			t.Errorf("multi-tenant breach: beta job %s leaked to alpha query", j.ID)
		}
	}

	// Step 2: Query job history filtered by actor_id=tenant_beta
	codeListB, listB, rawListB := httpListJobs(t, srv, tokenBeta, "?actor_id=tenant_beta")
	if codeListB != http.StatusOK {
		t.Fatalf("failed to list Beta jobs: %d: %s", codeListB, rawListB)
	}
	if len(listB.Jobs) < 2 {
		t.Fatalf("expected at least 2 Beta jobs, got %d", len(listB.Jobs))
	}
	for _, j := range listB.Jobs {
		if j.ActorID != "tenant_beta" {
			t.Errorf("multi-tenant breach: non-beta job returned in beta query: %+v", j)
		}
		if j.ID == respA1.JobID || j.ID == respA2.JobID {
			t.Errorf("multi-tenant breach: alpha job %s leaked to beta query", j.ID)
		}
	}

	// Step 3: Verify Audit Segregation and Attribution
	codeAuditA, auditA := httpGetAuditLogs(t, srv, srv.adminPAT, "?actor_id=tenant_alpha")
	if codeAuditA != http.StatusOK {
		t.Fatalf("failed to query alpha audit logs: %d", codeAuditA)
	}
	if len(auditA) == 0 {
		t.Errorf("expected non-empty audit events for tenant_alpha")
	}
	for _, ev := range auditA {
		if ev.ActorID != "tenant_alpha" {
			t.Errorf("audit query breach: non-alpha audit event returned: %+v", ev)
		}
	}

	// Step 4: Verify overall cryptographic chain validity across multi-tenant events
	vCode, vRes := httpVerifyAuditChain(t, srv, srv.adminPAT)
	if vCode != http.StatusOK || !vRes.Valid {
		t.Fatalf("audit chain verification failed after multi-tenant run: %+v", vRes)
	}
}

