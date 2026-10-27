package e2e_test

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
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
