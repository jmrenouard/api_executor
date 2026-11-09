package e2e_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"go-admin-tool/internal/api"
	"go-admin-tool/internal/auth"
	"go-admin-tool/internal/jobs"
	"go-admin-tool/internal/mcp"
)

// ============================================================================
// Tier 3: Cross-Feature Combinations & Subsystem Integrations
// ============================================================================

func TestTier3_Combination_APIFilterAndExecuteWorkflow(t *testing.T) {
	srv := setupE2ETestServer(t)

	// Step 1: Query plugins catalog
	code, resp := httpGetPlugins(t, srv, srv.adminPAT, "?q=diagnostics")
	if code != http.StatusOK || len(resp.Plugins) == 0 {
		t.Fatalf("expected 200 with non-empty plugins, got code=%d len=%d", code, len(resp.Plugins))
	}

	// Step 2: Pick the first discovered plugin and action
	targetPlugin := resp.Plugins[0]
	targetAction := targetPlugin.Actions[0]

	// Step 3: Execute the discovered action
	execReq := map[string]any{
		"plugin_id": targetPlugin.ID,
		"action":    targetAction.Name,
	}
	execCode, execRes, _ := httpExecutePlugin(t, srv, srv.adminPAT, execReq)
	if execCode != http.StatusOK {
		t.Fatalf("expected 200 OK executing discovered plugin %s:%s, got %d (error: %s)",
			targetPlugin.ID, targetAction.Name, execCode, execRes.Error)
	}
	if execRes.Status != "ok" {
		t.Errorf("expected status 'ok', got %s", execRes.Status)
	}
}

func TestTier3_Combination_MCPExecution_WithSHA256AuditLoggingAndChainVerification(t *testing.T) {
	srv := setupE2ETestServer(t)

	// Step 1: Execute sys-diagnostics:runtime_stats via MCP tools/call
	paramsBytes, _ := json.Marshal(map[string]any{
		"name": "execute_plugin",
		"arguments": map[string]any{
			"plugin_id": "sys-diagnostics",
			"action":    "runtime_stats",
		},
	})
	rpcReq := mcp.JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      101,
		Method:  "tools/call",
		Params:  paramsBytes,
	}

	mcpCode, rpcResp, _ := httpMCPCall(t, srv, srv.adminPAT, rpcReq)
	if mcpCode != http.StatusOK {
		t.Fatalf("expected 200 OK from MCP call, got %d", mcpCode)
	}
	if rpcResp.Error != nil {
		t.Fatalf("unexpected RPC error: %+v", rpcResp.Error)
	}

	// Step 2: Check audit trail via GET /api/v1/audit/logs
	auditCode, events := httpGetAuditLogs(t, srv, srv.adminPAT, "?category=mcp")
	if auditCode != http.StatusOK {
		t.Fatalf("expected 200 OK retrieving audit logs, got %d", auditCode)
	}

	foundAudit := false
	for _, ev := range events {
		if strings.Contains(ev.Action, "execute_plugin") || strings.Contains(ev.Summary, "sys-diagnostics") {
			foundAudit = true
			if ev.EntryHash == "" {
				t.Errorf("audit event missing SHA-256 EntryHash")
			}
		}
	}
	if !foundAudit {
		t.Errorf("expected MCP execute_plugin audit event in audit trail")
	}

	// Step 3: Cryptographically verify the SHA-256 audit log chain
	verifyCode, verResult := httpVerifyAuditChain(t, srv, srv.adminPAT)
	if verifyCode != http.StatusOK {
		t.Fatalf("expected 200 from audit verify, got %d", verifyCode)
	}
	if !verResult.Valid {
		t.Errorf("cryptographic audit chain validation failed: %+v", verResult)
	}
}

func TestTier3_Combination_RESTExecution_WithSHA256AuditLoggingAndChainVerification(t *testing.T) {
	srv := setupE2ETestServer(t)

	// Step 1: Execute native plugin via REST API
	execReq := map[string]any{
		"plugin_id": "sys-diagnostics",
		"action":    "network_interfaces",
	}
	code, res, _ := httpExecutePlugin(t, srv, srv.adminPAT, execReq)
	if code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d (error: %s)", code, res.Error)
	}

	// Step 2: Inspect audit logs
	auditCode, events := httpGetAuditLogs(t, srv, srv.adminPAT, "?category=plugin")
	if auditCode != http.StatusOK {
		t.Fatalf("expected 200 OK from audit logs, got %d", auditCode)
	}

	foundPluginAudit := false
	for _, ev := range events {
		if strings.Contains(ev.Action, "plugin:sys-diagnostics:network_interfaces") {
			foundPluginAudit = true
			if ev.Status != "ok" {
				t.Errorf("expected audit event status 'ok', got %s", ev.Status)
			}
		}
	}
	if !foundPluginAudit {
		t.Errorf("expected audit event for plugin:sys-diagnostics:network_interfaces")
	}

	// Step 3: Verify chain integrity
	_, verResult := httpVerifyAuditChain(t, srv, srv.adminPAT)
	if !verResult.Valid {
		t.Errorf("audit chain verification failed after REST execution")
	}
}

func TestTier3_Combination_RBAC_AdminAllowed_ViewerForbidden(t *testing.T) {
	srv := setupE2ETestServer(t)

	execReq := map[string]any{
		"plugin_id": "sys-diagnostics",
		"action":    "runtime_stats",
	}

	// 1. Admin PAT succeeds (200 OK)
	adminCode, adminRes, _ := httpExecutePlugin(t, srv, srv.adminPAT, execReq)
	if adminCode != http.StatusOK {
		t.Fatalf("expected admin PAT to execute plugin with 200 OK, got %d: %s", adminCode, adminRes.Error)
	}

	// 2. Viewer PAT is denied execution with 403 Forbidden
	viewerCode, _, rawViewer := httpExecutePlugin(t, srv, srv.viewerPAT, execReq)
	if viewerCode != http.StatusForbidden {
		t.Fatalf("expected viewer PAT to receive 403 Forbidden on execution, got %d: %s", viewerCode, rawViewer)
	}

	// 3. Viewer PAT is permitted to list plugins with 200 OK
	listCode, listResp := httpGetPlugins(t, srv, srv.viewerPAT, "")
	if listCode != http.StatusOK {
		t.Fatalf("expected viewer PAT to read plugins list with 200 OK, got %d: %s", listCode, listResp.Error)
	}
}

func TestTier3_Combination_ScopedServiceAccount_AllowedActionsEnforcement(t *testing.T) {
	srv := setupE2ETestServer(t)

	// Scoped Service Account is authorized ONLY for sys-diagnostics actions

	// 1. Permitted action: sys-diagnostics:runtime_stats -> 200 OK
	allowedReq := map[string]any{
		"plugin_id": "sys-diagnostics",
		"action":    "runtime_stats",
	}
	allowedCode, allowedRes, _ := httpExecutePlugin(t, srv, srv.scopedSvcPAT, allowedReq)
	if allowedCode != http.StatusOK {
		t.Fatalf("expected scoped service account to execute sys-diagnostics, got %d: %s", allowedCode, allowedRes.Error)
	}

	// 2. Denied action: ops-quick-tools:probe-target -> 403 Forbidden
	deniedReq := map[string]any{
		"plugin_id": "ops-quick-tools",
		"action":    "probe-target",
	}
	deniedCode, _, rawDenied := httpExecutePlugin(t, srv, srv.scopedSvcPAT, deniedReq)
	if deniedCode != http.StatusForbidden {
		t.Fatalf("expected scoped service account to receive 403 Forbidden on out-of-scope plugin, got %d: %s",
			deniedCode, rawDenied)
	}
}

func TestTier3_Combination_PrometheusMetricCorrelation_OnPluginAction(t *testing.T) {
	srv := setupE2ETestServer(t)

	// Execute action
	execReq := map[string]any{
		"plugin_id": "sys-diagnostics",
		"action":    "runtime_stats",
	}
	code, _, _ := httpExecutePlugin(t, srv, srv.adminPAT, execReq)
	if code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", code)
	}

	// Scrape /metrics endpoint
	metricsCode, metricsBody := httpGetMetrics(t, srv)
	if metricsCode != http.StatusOK {
		t.Fatalf("expected 200 OK from /metrics, got %d", metricsCode)
	}

	expectedMetricKey := `action_calls_total{action="plugin:sys-diagnostics:runtime_stats"}`
	if !strings.Contains(metricsBody, expectedMetricKey) {
		t.Errorf("expected /metrics to include %s, metrics output was:\n%s", expectedMetricKey, metricsBody)
	}
}

func TestTier3_Combination_DynamicDeclarativeRegistration_MCPAvailability(t *testing.T) {
	srv := setupE2ETestServer(t)

	newID := fmt.Sprintf("tier3-dyn-%d", 1234)
	spec := map[string]any{
		"id":          newID,
		"name":        "Tier 3 Dynamic Module",
		"version":     "1.0.0",
		"description": "Module registered via REST and consumed via MCP",
		"actions": []map[string]any{
			{
				"name":        "mcp-probe",
				"description": "Probe action",
				"command":     "echo",
				"args":        []string{"mcp-ok"},
				"timeout":     "5s",
			},
		},
	}

	regCode, _, regRaw := httpRegisterDeclarativePlugin(t, srv, srv.adminPAT, spec)
	if regCode != http.StatusCreated {
		t.Fatalf("failed to register plugin via REST: %d: %s", regCode, regRaw)
	}

	// Verify availability in MCP catalog resource
	resBytes, _ := json.Marshal(map[string]any{"uri": "executor://plugins/catalog"})
	rpcRead := mcp.JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      201,
		Method:  "resources/read",
		Params:  resBytes,
	}
	readCode, readResp, _ := httpMCPCall(t, srv, srv.adminPAT, rpcRead)
	if readCode != http.StatusOK || readResp.Error != nil {
		t.Fatalf("failed to read MCP catalog resource: code=%d err=%+v", readCode, readResp.Error)
	}

	// Execute via MCP tools/call
	callBytes, _ := json.Marshal(map[string]any{
		"name": "execute_plugin",
		"arguments": map[string]any{
			"plugin_id": newID,
			"action":    "mcp-probe",
		},
	})
	rpcCall := mcp.JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      202,
		Method:  "tools/call",
		Params:  callBytes,
	}
	callCode, callResp, _ := httpMCPCall(t, srv, srv.adminPAT, rpcCall)
	if callCode != http.StatusOK || callResp.Error != nil {
		t.Fatalf("failed to execute dynamic plugin via MCP: code=%d err=%+v", callCode, callResp.Error)
	}
}

// ============================================================================
// Tier 3: Feature 6 Cross-Feature Combinations (RBAC, Audit, Prometheus, Race)
// ============================================================================

func TestTier3_Combination_TwoTierRBAC_ScopeAndActionEnforcement(t *testing.T) {
	srv := setupE2ETestServer(t)

	// 1. Submit-only token with jobs:submit, lacking commands:execute
	_, submitNoExecPAT, err := srv.authMgr.CreateToken("e2e_operator", "sub-no-exec", []string{auth.ScopeJobsSubmit}, 24*time.Hour)
	if err != nil {
		t.Fatalf("failed to create submit-only token: %v", err)
	}
	// 2. Read-only token with jobs:read, lacking jobs:submit and jobs:cancel
	_, readOnlyPAT, err := srv.authMgr.CreateToken("e2e_viewer", "read-only-pat", []string{auth.ScopeJobsRead}, 24*time.Hour)
	if err != nil {
		t.Fatalf("failed to create read-only token: %v", err)
	}
	// 3. Service account with X-Service-Key allowed ONLY for sys-diagnostics
	_, svcKey, err := srv.authMgr.CreateServiceAccount(
		"tier3-rbac-svc", "Tier3 Service", "Restricted to sys-diagnostics",
		[]string{auth.ScopeJobsSubmit, auth.ScopeJobsRead, "plugins:execute"},
		[]string{"plugin:sys-diagnostics:*", "sys-diagnostics"},
		24*time.Hour,
	)
	if err != nil {
		t.Fatalf("failed to create service account: %v", err)
	}

	// Case A: Token missing jobs:submit receives 403 Forbidden
	codeA, _, rawA := httpSubmitJob(t, srv, readOnlyPAT, map[string]any{
		"type":   "command",
		"action": "echo-cmd",
	})
	if codeA != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden when jobs:submit is missing, got %d: %s", codeA, rawA)
	}

	// Case B: Token with jobs:submit but missing commands:execute receives 403 Forbidden
	codeB, _, rawB := httpSubmitJob(t, srv, submitNoExecPAT, map[string]any{
		"type":   "command",
		"action": "echo-cmd",
	})
	if codeB != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden when commands:execute is missing, got %d: %s", codeB, rawB)
	}

	// Case C: Service account using X-Service-Key attempting out-of-scope plugin receives 403 Forbidden
	codeC, _, rawC := httpSubmitJob(t, srv, "", map[string]any{
		"type":      "plugin",
		"plugin_id": "ops-quick-tools",
		"action":    "probe-target",
	}, map[string]string{"X-Service-Key": svcKey})
	if codeC != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for out-of-scope action via X-Service-Key, got %d: %s", codeC, rawC)
	}

	// Case D: Service account using X-Service-Key for allowed plugin succeeds (202 Accepted)
	codeD, respD, rawD := httpSubmitJob(t, srv, "", map[string]any{
		"type":      "plugin",
		"plugin_id": "sys-diagnostics",
		"action":    "runtime_stats",
	}, map[string]string{"X-Service-Key": svcKey})
	if codeD != http.StatusAccepted {
		t.Fatalf("expected 202 Accepted for in-scope action via X-Service-Key, got %d: %s", codeD, rawD)
	}
	if respD.JobID == "" {
		t.Errorf("expected non-empty JobID in 202 response")
	}

	// Case E: Scope-restricted cancellation (token without jobs:cancel receives 403)
	// Submit a slow running job to attempt unauthorized cancellation while active
	codeSlowE, respSlowE, _ := httpSubmitJob(t, srv, srv.adminPAT, map[string]any{
		"type":     "command",
		"action":   "slow-diag-cmd",
		"priority": "low",
	})
	if codeSlowE != http.StatusAccepted {
		t.Fatalf("failed to submit slow job for cancellation test: %d", codeSlowE)
	}
	time.Sleep(50 * time.Millisecond)

	codeE, _, rawE := httpCancelJob(t, srv, readOnlyPAT, respSlowE.JobID)
	if codeE != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden when jobs:cancel is missing, got %d: %s", codeE, rawE)
	}

	// Clean up by cancelling with admin PAT
	_, _, _ = httpCancelJob(t, srv, srv.adminPAT, respSlowE.JobID)

	// Case F: Admin PAT with full wildcard (*) succeeds
	codeF, _, _ := httpGetJob(t, srv, srv.adminPAT, respD.JobID)
	if codeF != http.StatusOK {
		t.Fatalf("expected 200 OK from admin PAT, got %d", codeF)
	}
}

func TestTier3_Combination_CryptographicAuditTrail_FullJobLifecycleChain(t *testing.T) {
	srv := setupE2ETestServer(t)

	// Step 1: Submit normal completed job
	code1, resp1, _ := httpSubmitJob(t, srv, srv.adminPAT, map[string]any{
		"type":      "plugin",
		"plugin_id": "sys-diagnostics",
		"action":    "network_interfaces",
		"priority":  "high",
	})
	if code1 != http.StatusAccepted {
		t.Fatalf("Step 1 failed: expected 202 Accepted, got %d", code1)
	}

	finalJob1 := pollJobTerminal(t, srv, srv.adminPAT, resp1.JobID, 5*time.Second)
	if finalJob1.Status != jobs.StatusCompleted {
		t.Fatalf("Step 1 failed: expected completed job, got %s", finalJob1.Status)
	}

	// Step 2: Submit and cancel slow job
	code2, resp2, _ := httpSubmitJob(t, srv, srv.adminPAT, map[string]any{
		"type":     "command",
		"action":   "slow-diag-cmd",
		"priority": "low",
	})
	if code2 != http.StatusAccepted {
		t.Fatalf("Step 2 failed: expected 202, got %d", code2)
	}
	time.Sleep(50 * time.Millisecond)

	codeCancel, _, _ := httpCancelJob(t, srv, srv.adminPAT, resp2.JobID)
	if codeCancel != http.StatusOK {
		t.Fatalf("Step 2 cancel failed: expected 200, got %d", codeCancel)
	}

	// Wait until cancelled job reaches terminal state and records audit log
	cancelledJob := pollJobTerminal(t, srv, srv.adminPAT, resp2.JobID, 5*time.Second)
	if cancelledJob.Status != jobs.StatusCancelled {
		t.Fatalf("expected job 2 status cancelled, got %s", cancelledJob.Status)
	}

	// Step 3: Inspect Audit Logs
	auditCode, events := httpGetAuditLogs(t, srv, srv.adminPAT, "?category=job")
	if auditCode != http.StatusOK {
		t.Fatalf("failed to retrieve audit logs: %d", auditCode)
	}

	enqueuedFound := false
	startedFound := false
	completedFound := false
	cancelledFound := false

	for _, ev := range events {
		if ev.EntryHash == "" || ev.PrevHash == "" {
			t.Errorf("audit event %d missing SHA-256 hash or prev_hash: %+v", ev.ID, ev)
		}
		if ev.Action == "job.enqueued" {
			enqueuedFound = true
		}
		if ev.Action == "job.started" {
			startedFound = true
		}
		if ev.Action == "job.completed" {
			completedFound = true
		}
		if ev.Action == "job.cancelled" {
			cancelledFound = true
		}
	}

	if !enqueuedFound || !startedFound || !completedFound || !cancelledFound {
		t.Errorf("missing expected lifecycle transitions: enqueued=%v started=%v completed=%v cancelled=%v",
			enqueuedFound, startedFound, completedFound, cancelledFound)
	}

	// Step 4: Verify complete cryptographic chain integrity
	verifyCode, verResult := httpVerifyAuditChain(t, srv, srv.adminPAT)
	if verifyCode != http.StatusOK {
		t.Fatalf("audit verify returned HTTP %d", verifyCode)
	}
	if !verResult.Valid {
		t.Fatalf("cryptographic SHA-256 audit chain verification failed: %+v", verResult)
	}
	if verResult.TotalEvents < 4 {
		t.Errorf("expected at least 4 audit events in chain, got %d", verResult.TotalEvents)
	}
}

func TestTier3_Combination_PrometheusTelemetryInvariants_AcrossJobLifecycle(t *testing.T) {
	srv := setupE2ETestServer(t)
	api.ResetJobMetrics()
	api.ResetHTTPMetrics()

	// 1. Submit and wait for 3 fast jobs
	for i := 0; i < 3; i++ {
		code, resp, _ := httpSubmitJob(t, srv, srv.adminPAT, map[string]any{
			"type":   "command",
			"action": "echo-cmd",
		})
		if code != http.StatusAccepted {
			t.Fatalf("failed to submit job %d: code=%d", i, code)
		}
		pollJobTerminal(t, srv, srv.adminPAT, resp.JobID, 5*time.Second)
		_, _, _ = httpGetJobLogs(t, srv, srv.adminPAT, resp.JobID, 0)
	}

	// 2. Scrape /metrics
	mCode, mBody := httpGetMetrics(t, srv)
	if mCode != http.StatusOK {
		t.Fatalf("expected 200 OK from /metrics, got %d", mCode)
	}

	// Verify Prometheus counters & gauges
	if !strings.Contains(mBody, `job_executions_total{action="echo-cmd",status="completed"}`) {
		t.Errorf("expected job_executions_total metric for echo-cmd in /metrics:\n%s", mBody)
	}
	if !strings.Contains(mBody, "job_queue_depth") {
		t.Errorf("expected job_queue_depth gauge in /metrics")
	}
	if !strings.Contains(mBody, "job_workers_active") {
		t.Errorf("expected job_workers_active gauge in /metrics")
	}

	// Verify route normalization (no unbounded cardinality from dynamic job IDs)
	if !strings.Contains(mBody, `path="/api/v1/jobs/:id/logs"`) {
		t.Errorf("expected normalized route path '/api/v1/jobs/:id/logs' in http_requests_total")
	}
	if strings.Contains(mBody, `path="/api/v1/jobs/job_`) {
		t.Errorf("detected unnormalized dynamic job ID in Prometheus path labels")
	}
}

func TestTier3_Combination_HighConcurrency_JobSubmissionRaceAndPriorityHeapOrdering(t *testing.T) {
	srv := setupE2ETestServer(t)

	// Block workers with a slow job to let concurrent submissions queue up
	codeSlow, respSlow, _ := httpSubmitJob(t, srv, srv.adminPAT, map[string]any{
		"type":     "command",
		"action":   "slow-diag-cmd",
		"priority": "low",
	})
	if codeSlow != http.StatusAccepted {
		t.Fatalf("failed to submit blocker job: %d", codeSlow)
	}

	const totalJobs = 30
	priorities := []string{"low", "normal", "high"}
	var wg sync.WaitGroup
	results := make(chan api.SubmitJobResponse, totalJobs)
	errorsChan := make(chan error, totalJobs)

	// Fire 30 concurrent submissions across 3 priority tiers
	for i := 0; i < totalJobs; i++ {
		p := priorities[i%len(priorities)]
		wg.Add(1)
		go func(priority string) {
			defer wg.Done()
			code, resp, raw := httpSubmitJob(t, srv, srv.adminPAT, map[string]any{
				"type":     "command",
				"action":   "echo-cmd",
				"priority": priority,
			})
			if code != http.StatusAccepted {
				errorsChan <- fmt.Errorf("unexpected status %d: %s", code, raw)
				return
			}
			results <- resp
		}(p)
	}
	wg.Wait()
	close(results)
	close(errorsChan)

	for err := range errorsChan {
		t.Fatalf("concurrent submission error: %v", err)
	}

	submittedIDs := make(map[string]bool)
	for r := range results {
		if r.JobID == "" {
			t.Errorf("received empty JobID in concurrent response")
		}
		if submittedIDs[r.JobID] {
			t.Errorf("duplicate JobID detected under concurrency: %s", r.JobID)
		}
		submittedIDs[r.JobID] = true
	}
	if len(submittedIDs) != totalJobs {
		t.Fatalf("expected %d unique jobs submitted, got %d", totalJobs, len(submittedIDs))
	}

	// Cancel the initial blocker job
	_, _, _ = httpCancelJob(t, srv, srv.adminPAT, respSlow.JobID)

	// Wait for queue to drain
	timeout := time.After(15 * time.Second)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			t.Fatalf("timed out waiting for concurrent jobs to complete")
		case <-ticker.C:
			code, stats, _ := httpGetJobQueue(t, srv, srv.adminPAT)
			if code == http.StatusOK && stats.QueuedJobs == 0 && stats.WorkersActive == 0 {
				return // Success
			}
		}
	}
}

func TestTier3_Combination_AsyncJob_CancellationAndProcessTermination(t *testing.T) {
	srv := setupE2ETestServer(t)

	// Submit slow command job
	code, resp, raw := httpSubmitJob(t, srv, srv.adminPAT, map[string]any{
		"type":     "command",
		"action":   "slow-diag-cmd",
		"priority": "normal",
	})
	if code != http.StatusAccepted {
		t.Fatalf("expected 202 Accepted, got %d: %s", code, raw)
	}

	// Give it a brief moment to start running
	time.Sleep(100 * time.Millisecond)

	// Cancel the running job
	cancelCode, cancelResp, cancelRaw := httpCancelJob(t, srv, srv.adminPAT, resp.JobID)
	if cancelCode != http.StatusOK {
		t.Fatalf("expected 200 OK on job cancel, got %d: %s", cancelCode, cancelRaw)
	}
	if cancelResp.Status != jobs.StatusCancelled {
		t.Errorf("expected status cancelled in response, got %s", cancelResp.Status)
	}

	// Verify terminal state in job store
	terminalJob := pollJobTerminal(t, srv, srv.adminPAT, resp.JobID, 5*time.Second)
	if terminalJob.Status != jobs.StatusCancelled {
		t.Fatalf("expected terminal status cancelled, got %s", terminalJob.Status)
	}

	// Verify audit log has job.cancelled
	auditCode, events := httpGetAuditLogs(t, srv, srv.adminPAT, "?category=job")
	if auditCode != http.StatusOK {
		t.Fatalf("failed to retrieve audit logs: %d", auditCode)
	}
	foundCancelled := false
	for _, ev := range events {
		if ev.Action == "job.cancelled" {
			foundCancelled = true
			break
		}
	}
	if !foundCancelled {
		t.Errorf("expected job.cancelled event in audit log")
	}
}

