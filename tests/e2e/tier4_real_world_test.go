package e2e_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

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
