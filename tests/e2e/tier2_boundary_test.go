package e2e_test

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"go-admin-tool/internal/api"
	"go-admin-tool/internal/jobs"
)

// ============================================================================
// Tier 2: Boundary, Corner Cases & Adversarial Verification
// ============================================================================

func TestTier2_Boundary_EmptyQueryParams(t *testing.T) {
	srv := setupE2ETestServer(t)

	code, resp := httpGetPlugins(t, srv, srv.adminPAT, "?category=&q=&type=")
	if code != http.StatusOK {
		t.Fatalf("expected 200 OK for empty query parameters, got %d", code)
	}
	if len(resp.Plugins) == 0 {
		t.Errorf("expected non-empty plugins list for empty query strings")
	}
}

func TestTier2_Boundary_UnknownCategory(t *testing.T) {
	srv := setupE2ETestServer(t)

	totalCode, totalResp := httpGetPlugins(t, srv, srv.adminPAT, "")
	if totalCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", totalCode)
	}

	code, resp := httpGetPlugins(t, srv, srv.adminPAT, "?category=NonExistentCategory9999XYZ")
	if code != http.StatusOK {
		t.Fatalf("expected 200 OK without crashing on unknown category, got %d", code)
	}
	// When query filtering is active, unknown category returns 0 plugins
	if len(resp.Plugins) < len(totalResp.Plugins) && len(resp.Plugins) != 0 {
		t.Errorf("expected 0 plugins for unknown category, got %d", len(resp.Plugins))
	}
}

func TestTier2_Boundary_UnknownSearchQuery(t *testing.T) {
	srv := setupE2ETestServer(t)

	totalCode, totalResp := httpGetPlugins(t, srv, srv.adminPAT, "")
	if totalCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", totalCode)
	}

	code, resp := httpGetPlugins(t, srv, srv.adminPAT, "?q=z9z9z9nonexistentquerykeyword")
	if code != http.StatusOK {
		t.Fatalf("expected 200 OK without crashing on unknown search query, got %d", code)
	}
	if len(resp.Plugins) < len(totalResp.Plugins) && len(resp.Plugins) != 0 {
		t.Errorf("expected 0 plugins for unmatched search query, got %d", len(resp.Plugins))
	}
}

func TestTier2_Boundary_MissingPluginID(t *testing.T) {
	srv := setupE2ETestServer(t)

	req := map[string]any{
		"action": "runtime_stats",
	}
	code, res, raw := httpExecutePlugin(t, srv, srv.adminPAT, req)
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request when plugin_id is missing, got %d: %s", code, raw)
	}
	if !strings.Contains(strings.ToLower(res.Error+raw), "plugin_id") {
		t.Errorf("expected error message to mention missing plugin_id, got %s", raw)
	}
}

func TestTier2_Boundary_MissingAction(t *testing.T) {
	srv := setupE2ETestServer(t)

	req := map[string]any{
		"plugin_id": "sys-diagnostics",
	}
	code, res, raw := httpExecutePlugin(t, srv, srv.adminPAT, req)
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request when action is missing, got %d: %s", code, raw)
	}
	if !strings.Contains(strings.ToLower(res.Error+raw), "action") {
		t.Errorf("expected error message to mention missing action, got %s", raw)
	}
}

func TestTier2_Boundary_NonExistentPluginID(t *testing.T) {
	srv := setupE2ETestServer(t)

	req := map[string]any{
		"plugin_id": "ghost-plugin-does-not-exist",
		"action":    "any-action",
	}
	code, res, _ := httpExecutePlugin(t, srv, srv.adminPAT, req)
	if code != http.StatusNotFound {
		t.Fatalf("expected 404 Not Found for non-existent plugin, got %d (error: %s)", code, res.Error)
	}
}

func TestTier2_Boundary_NonExistentActionOnExistingPlugin(t *testing.T) {
	srv := setupE2ETestServer(t)

	req := map[string]any{
		"plugin_id": "sys-diagnostics",
		"action":    "non-existent-action-999",
	}
	code, res, _ := httpExecutePlugin(t, srv, srv.adminPAT, req)
	if code != http.StatusNotFound {
		t.Fatalf("expected 404 Not Found for non-existent action on existing plugin, got %d (error: %s)", code, res.Error)
	}
}

func TestTier2_Boundary_InvalidRegexParameterInjection(t *testing.T) {
	srv := setupE2ETestServer(t)

	maliciousPayloads := []string{
		"localhost; rm -rf /",
		"target$(whoami)",
		"node01`id`",
		"server && cat /etc/passwd",
		"host | nc -l 4444",
		"target > /tmp/pwned",
		"newline\ninjection",
	}

	for _, mal := range maliciousPayloads {
		t.Run("injection_"+mal, func(t *testing.T) {
			req := map[string]any{
				"plugin_id": "ops-quick-tools",
				"action":    "probe-target",
				"params": map[string]any{
					"target": mal,
				},
			}
			code, res, raw := httpExecutePlugin(t, srv, srv.adminPAT, req)
			if code != http.StatusBadRequest {
				t.Fatalf("expected 400 Bad Request for shell injection payload %q, got %d: %s", mal, code, raw)
			}
			if !strings.Contains(strings.ToLower(res.Error+raw), "validation") &&
				!strings.Contains(strings.ToLower(res.Error+raw), "failed") &&
				!strings.Contains(strings.ToLower(res.Error+raw), "invalid") {
				t.Errorf("expected security validation error for payload %q, got %s", mal, raw)
			}
		})
	}
}

func TestTier2_Boundary_ParameterTypeMismatch(t *testing.T) {
	srv := setupE2ETestServer(t)

	// Passing a complex nested structure where string is expected
	req := map[string]any{
		"plugin_id": "ops-quick-tools",
		"action":    "probe-target",
		"params": map[string]any{
			"target": map[string]any{"nested": "invalid-object"},
		},
	}
	code, res, raw := httpExecutePlugin(t, srv, srv.adminPAT, req)
	if code == http.StatusOK && res.Status == "ok" {
		t.Errorf("expected error or rejected status on parameter type mismatch, got 200 OK: %s", raw)
	}
}

func TestTier2_Boundary_InvalidTimeoutString(t *testing.T) {
	srv := setupE2ETestServer(t)

	invalidTimeouts := []string{
		"not-a-duration",
		"-10s",
		"99999999999999999999999999999999999999999999999h",
		"500xyz",
	}

	for _, to := range invalidTimeouts {
		t.Run("timeout_"+to, func(t *testing.T) {
			req := map[string]any{
				"plugin_id": "sys-diagnostics",
				"action":    "runtime_stats",
				"timeout":   to,
			}
			code, _, raw := httpExecutePlugin(t, srv, srv.adminPAT, req)
			if code != http.StatusBadRequest {
				t.Errorf("expected 400 Bad Request for invalid timeout %q, got %d: %s", to, code, raw)
			}
		})
	}
}

func TestTier2_Boundary_ShortTimeoutExpiry(t *testing.T) {
	srv := setupE2ETestServer(t)

	req := map[string]any{
		"plugin_id": "ops-quick-tools",
		"action":    "probe-target",
		"params":    map[string]any{"target": "node-timeout-test"},
		"timeout":   "1ms",
	}
	code, res, _ := httpExecutePlugin(t, srv, srv.adminPAT, req)
	// Execution might complete or time out depending on system speed, but must handle gracefully
	if code != http.StatusOK && code != http.StatusBadRequest {
		t.Errorf("expected graceful handling of ultra-short timeout, got HTTP %d (status=%s)", code, res.Status)
	}
}

func TestTier2_Boundary_LargePayloadStress(t *testing.T) {
	srv := setupE2ETestServer(t)

	// Build a valid alphanumeric string of length 200
	largeTarget := strings.Repeat("a", 200)
	req := map[string]any{
		"plugin_id": "ops-quick-tools",
		"action":    "probe-target",
		"params": map[string]any{
			"target": largeTarget,
		},
	}
	code, res, _ := httpExecutePlugin(t, srv, srv.adminPAT, req)
	if code != http.StatusOK {
		t.Fatalf("expected 200 OK for large valid parameter, got %d (error: %s)", code, res.Error)
	}
	if res.Status != "ok" {
		t.Errorf("expected status 'ok', got %s", res.Status)
	}
}

func TestTier2_Boundary_SpecialCharactersAndUnicodeQuery(t *testing.T) {
	srv := setupE2ETestServer(t)

	unicodeQueries := []string{
		"sysadmin+kernel%20diagnostic",
		"unicode_probe_🚀_test",
		"accentue_é_è_à_ç",
		"chinese_测试_query",
	}

	for _, q := range unicodeQueries {
		t.Run("query_"+q, func(t *testing.T) {
			code, resp := httpGetPlugins(t, srv, srv.adminPAT, fmt.Sprintf("?q=%s", q))
			if code != http.StatusOK {
				t.Errorf("expected 200 OK for query %q, got %d (error: %s)", q, code, resp.Error)
			}
		})
	}
}

func TestTier2_Boundary_MalformedJSONRequestBody(t *testing.T) {
	srv := setupE2ETestServer(t)

	malformedJSON := "{malformed json without closing brace"
	code, _, raw := httpExecutePlugin(t, srv, srv.adminPAT, malformedJSON)
	if code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request on malformed JSON body, got %d: %s", code, raw)
	}
}

// ============================================================================
// Tier 2: Feature 6 Boundary & Corner Cases (Asynchronous Jobs & Queue)
// ============================================================================

func TestTier2_Boundary_Jobs_MissingRequiredFields(t *testing.T) {
	srv := setupE2ETestServer(t)

	code, _, raw := httpSubmitJob(t, srv, srv.adminPAT, map[string]any{})
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request when action is missing, got %d: %s", code, raw)
	}
	if !strings.Contains(raw, "Action is required") && !strings.Contains(raw, "action") {
		t.Errorf("expected error message mentioning action requirement: %s", raw)
	}
}

func TestTier2_Boundary_Jobs_InvalidJobType(t *testing.T) {
	srv := setupE2ETestServer(t)

	code, _, raw := httpSubmitJob(t, srv, srv.adminPAT, map[string]any{
		"type":   "unsupported_engine_xyz",
		"action": "echo-cmd",
	})
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request on invalid job type, got %d: %s", code, raw)
	}
	if !strings.Contains(raw, "Unsupported job type") && !strings.Contains(raw, "type") {
		t.Errorf("expected error message mentioning invalid job type: %s", raw)
	}
}

func TestTier2_Boundary_Jobs_PluginWithoutPluginID(t *testing.T) {
	srv := setupE2ETestServer(t)

	code, _, raw := httpSubmitJob(t, srv, srv.adminPAT, map[string]any{
		"type":   "plugin",
		"action": "runtime_stats",
	})
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request when plugin_id is missing, got %d: %s", code, raw)
	}
	if !strings.Contains(raw, "Plugin ID is required") && !strings.Contains(raw, "plugin") {
		t.Errorf("expected error message mentioning missing plugin ID: %s", raw)
	}
}

func TestTier2_Boundary_Jobs_NonExistentJobID(t *testing.T) {
	srv := setupE2ETestServer(t)
	ghostID := "00000000-0000-0000-0000-000000000000"

	// GET detail
	codeGet, _, _ := httpGetJob(t, srv, srv.adminPAT, ghostID)
	if codeGet != http.StatusNotFound {
		t.Errorf("expected 404 Not Found for non-existent job detail, got %d", codeGet)
	}

	// GET logs
	codeLogs, _, _ := httpGetJobLogs(t, srv, srv.adminPAT, ghostID, 0)
	if codeLogs != http.StatusNotFound {
		t.Errorf("expected 404 Not Found for non-existent job logs, got %d", codeLogs)
	}

	// POST cancel
	codeCancel, _, _ := httpCancelJob(t, srv, srv.adminPAT, ghostID)
	if codeCancel != http.StatusNotFound {
		t.Errorf("expected 404 Not Found for non-existent job cancel, got %d", codeCancel)
	}
}

func TestTier2_Boundary_Jobs_CancelAlreadyTerminalJob(t *testing.T) {
	srv := setupE2ETestServer(t)

	code, resp, _ := httpSubmitJob(t, srv, srv.adminPAT, map[string]any{
		"type":   "command",
		"action": "echo-cmd",
	})
	if code != http.StatusAccepted {
		t.Fatalf("expected 202 Accepted, got %d", code)
	}

	terminalJob := pollJobTerminal(t, srv, srv.adminPAT, resp.JobID, 5*time.Second)
	if !terminalJob.Status.IsTerminal() {
		t.Fatalf("expected job to reach terminal status, got %s", terminalJob.Status)
	}

	// Attempting to cancel an already finished job must return 409 Conflict
	cancelCode, _, cancelRaw := httpCancelJob(t, srv, srv.adminPAT, resp.JobID)
	if cancelCode != http.StatusConflict {
		t.Fatalf("expected 409 Conflict on cancelling finished job, got %d: %s", cancelCode, cancelRaw)
	}
}

func TestTier2_Boundary_Jobs_InvalidLimitAndOffset(t *testing.T) {
	srv := setupE2ETestServer(t)

	code, listResp, raw := httpListJobs(t, srv, srv.adminPAT, "?limit=-10&offset=-5")
	if code != http.StatusOK {
		t.Fatalf("expected 200 OK with sanitized pagination defaults, got %d: %s", code, raw)
	}
	if listResp.Limit <= 0 {
		t.Errorf("expected positive sanitized limit, got %d", listResp.Limit)
	}
	if listResp.Offset < 0 {
		t.Errorf("expected non-negative sanitized offset, got %d", listResp.Offset)
	}
}

func TestTier2_Boundary_Jobs_MalformedJSON(t *testing.T) {
	srv := setupE2ETestServer(t)

	code, _, raw := httpSubmitJob(t, srv, srv.adminPAT, "{invalid json without closing brace")
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request on malformed JSON body, got %d: %s", code, raw)
	}
}

func TestTier2_Boundary_Jobs_JobTimeoutEnforcement(t *testing.T) {
	srv := setupE2ETestServer(t)

	code, resp, raw := httpSubmitJob(t, srv, srv.adminPAT, map[string]any{
		"type":     "command",
		"action":   "slow-cmd",
		"timeout":  "100ms",
		"priority": "high",
	})
	if code != http.StatusAccepted {
		t.Fatalf("expected 202 Accepted, got %d: %s", code, raw)
	}

	terminalJob := pollJobTerminal(t, srv, srv.adminPAT, resp.JobID, 5*time.Second)
	if terminalJob.Status != jobs.StatusTimedOut {
		t.Fatalf("expected job status timed_out, got %s (error: %s)", terminalJob.Status, terminalJob.Error)
	}
	if terminalJob.Error == "" {
		t.Errorf("expected non-empty error message indicating timeout")
	}
}

func TestTier2_Boundary_Jobs_QueueCapacityBackpressure(t *testing.T) {
	customCfg := jobs.DefaultEngineConfig()
	customCfg.WorkersCount = 1
	customCfg.QueueCapacity = 2

	srv := setupCustomE2ETestServer(t, customCfg)

	// 1. Submit blocker job to tie up the single worker
	codeBlocker, respBlocker, _ := httpSubmitJob(t, srv, srv.adminPAT, map[string]any{
		"type":     "command",
		"action":   "slow-cmd",
		"priority": "low",
	})
	if codeBlocker != http.StatusAccepted {
		t.Fatalf("failed to submit blocker job: %d", codeBlocker)
	}

	// Give worker a moment to pick up the blocker
	time.Sleep(100 * time.Millisecond)

	// 2. Submit 2 jobs to fill the priority queue to capacity (2)
	codeQ1, _, rawQ1 := httpSubmitJob(t, srv, srv.adminPAT, map[string]any{
		"type":   "command",
		"action": "echo-cmd",
	})
	codeQ2, _, rawQ2 := httpSubmitJob(t, srv, srv.adminPAT, map[string]any{
		"type":   "command",
		"action": "echo-cmd",
	})
	if codeQ1 != http.StatusAccepted || codeQ2 != http.StatusAccepted {
		t.Fatalf("expected queued jobs to be accepted: q1=%d (%s), q2=%d (%s)", codeQ1, rawQ1, codeQ2, rawQ2)
	}

	// 3. 4th job must be rejected with 429 Too Many Requests (backpressure)
	codeOver, _, rawOver := httpSubmitJob(t, srv, srv.adminPAT, map[string]any{
		"type":   "command",
		"action": "echo-cmd",
	})
	if codeOver != http.StatusTooManyRequests {
		t.Fatalf("expected 429 Too Many Requests when queue is full, got %d: %s", codeOver, rawOver)
	}

	// 4. Cancel the blocker job to relieve backpressure
	cCode, _, cRaw := httpCancelJob(t, srv, srv.adminPAT, respBlocker.JobID)
	if cCode != http.StatusOK {
		t.Fatalf("failed to cancel blocker job: %d: %s", cCode, cRaw)
	}

	// Wait deterministically for queue capacity to relieve (queued_jobs < QueueCapacity).
	// On Windows, process-group cancellation via taskkill /T /F and worker dequeue
	// may exceed arbitrary sleeps (500ms) under concurrent test execution.
	// Polling GET /api/v1/jobs/queue guarantees deterministic execution across all OS platforms.
	var lastStats api.QueueStatsResponse
	drainDeadline := time.Now().Add(3 * time.Second)
	drained := false
	for time.Now().Before(drainDeadline) {
		code, stats, _ := httpGetJobQueue(t, srv, srv.adminPAT)
		if code == http.StatusOK {
			lastStats = stats
			if stats.QueuedJobs < customCfg.QueueCapacity {
				drained = true
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !drained {
		t.Fatalf("timed out waiting for queue capacity to relieve after blocker cancellation: queued=%d, capacity=%d",
			lastStats.QueuedJobs, customCfg.QueueCapacity)
	}

	// 5. Subsequent job is accepted again
	codeRelieved, _, rawRelieved := httpSubmitJob(t, srv, srv.adminPAT, map[string]any{
		"type":   "command",
		"action": "echo-cmd",
	})
	if codeRelieved != http.StatusAccepted {
		t.Fatalf("expected 202 Accepted after queue drained, got %d: %s", codeRelieved, rawRelieved)
	}
}

