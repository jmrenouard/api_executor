package e2e_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

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
