package e2e_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"go-admin-tool/internal/jobs"
	"go-admin-tool/internal/mcp"
	"go-admin-tool/internal/plugins"
)

// ============================================================================
// Tier 1 - Feature 1: Plugin Catalog Discovery (GET /api/v1/plugins)
// ============================================================================

func TestTier1_F1_CatalogDiscovery_HappyPath(t *testing.T) {
	srv := setupE2ETestServer(t)

	code, resp := httpGetPlugins(t, srv, srv.adminPAT, "")
	if code != http.StatusOK {
		t.Fatalf("expected HTTP 200 OK, got %d (error: %s)", code, resp.Error)
	}
	if len(resp.Plugins) < 300 {
		t.Fatalf("expected at least 300 plugins in catalog, got %d", len(resp.Plugins))
	}
}

func TestTier1_F1_PluginMetadataSchema_Validation(t *testing.T) {
	srv := setupE2ETestServer(t)

	code, resp := httpGetPlugins(t, srv, srv.adminPAT, "")
	if code != http.StatusOK {
		t.Fatalf("expected HTTP 200 OK, got %d", code)
	}

	for _, p := range resp.Plugins {
		if strings.TrimSpace(p.ID) == "" {
			t.Errorf("plugin missing ID: %+v", p)
		}
		if strings.TrimSpace(p.Name) == "" {
			t.Errorf("plugin %s missing Name", p.ID)
		}
		if strings.TrimSpace(p.Version) == "" {
			t.Errorf("plugin %s missing Version", p.ID)
		}
		if len(p.Actions) == 0 {
			t.Errorf("plugin %s has no defined actions", p.ID)
		}
		for _, a := range p.Actions {
			if strings.TrimSpace(a.Name) == "" {
				t.Errorf("plugin %s has action with empty name", p.ID)
			}
		}
	}
}

func TestTier1_F1_NativePlugins_Presence(t *testing.T) {
	srv := setupE2ETestServer(t)

	code, resp := httpGetPlugins(t, srv, srv.adminPAT, "")
	if code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d", code)
	}

	foundSysDiag := false
	foundDBExp := false
	for _, p := range resp.Plugins {
		if p.ID == "sys-diagnostics" {
			foundSysDiag = true
			if len(p.Actions) < 3 {
				t.Errorf("expected sys-diagnostics to have >= 3 actions, got %d", len(p.Actions))
			}
		}
		if p.ID == "db-exposure" {
			foundDBExp = true
			if len(p.Actions) < 3 {
				t.Errorf("expected db-exposure to have >= 3 actions, got %d", len(p.Actions))
			}
		}
	}

	if !foundSysDiag {
		t.Errorf("expected native plugin 'sys-diagnostics' in catalog")
	}
	if !foundDBExp {
		t.Errorf("expected native plugin 'db-exposure' in catalog")
	}
}

func TestTier1_F1_DeclarativePlugins_Presence(t *testing.T) {
	srv := setupE2ETestServer(t)

	code, resp := httpGetPlugins(t, srv, srv.adminPAT, "")
	if code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d", code)
	}

	foundOps := false
	for _, p := range resp.Plugins {
		if p.ID == "ops-quick-tools" {
			foundOps = true
			if len(p.Actions) < 2 {
				t.Errorf("expected ops-quick-tools to have >= 2 actions, got %d", len(p.Actions))
			}
			foundProbe := false
			for _, a := range p.Actions {
				if a.Name == "probe-target" {
					foundProbe = true
					if len(a.Parameters) == 0 {
						t.Errorf("expected probe-target to declare parameters")
					}
				}
			}
			if !foundProbe {
				t.Errorf("expected action probe-target in ops-quick-tools")
			}
		}
	}

	if !foundOps {
		t.Errorf("expected declarative plugin 'ops-quick-tools' in catalog")
	}
}

func TestTier1_F1_PluginUniquenessAndSorting(t *testing.T) {
	srv := setupE2ETestServer(t)

	code, resp := httpGetPlugins(t, srv, srv.adminPAT, "")
	if code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d", code)
	}

	seenIDs := make(map[string]bool)
	for i, p := range resp.Plugins {
		if seenIDs[p.ID] {
			t.Fatalf("duplicate plugin ID found: %s", p.ID)
		}
		seenIDs[p.ID] = true

		if i > 0 && resp.Plugins[i-1].ID > p.ID {
			t.Errorf("plugins not sorted alphabetically: %s appeared after %s", p.ID, resp.Plugins[i-1].ID)
		}
	}
}

// ============================================================================
// Tier 1 - Feature 2: Catalog Filtering (GET /api/v1/plugins?category=...&q=...&type=...)
// ============================================================================

func TestTier1_F2_FilterByCategory(t *testing.T) {
	srv := setupE2ETestServer(t)

	totalCode, totalResp := httpGetPlugins(t, srv, srv.adminPAT, "")
	if totalCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", totalCode)
	}

	code, filteredResp := httpGetPlugins(t, srv, srv.adminPAT, "?category=SysAdmin")
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}

	if len(filteredResp.Plugins) < len(totalResp.Plugins) {
		for _, p := range filteredResp.Plugins {
			if !strings.EqualFold(p.Category, "SysAdmin") {
				t.Errorf("expected category SysAdmin, got %s (plugin %s)", p.Category, p.ID)
			}
		}
	}
}

func TestTier1_F2_FilterByKeywordQuery(t *testing.T) {
	srv := setupE2ETestServer(t)

	totalCode, totalResp := httpGetPlugins(t, srv, srv.adminPAT, "")
	if totalCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", totalCode)
	}

	code, filteredResp := httpGetPlugins(t, srv, srv.adminPAT, "?q=diagnostics")
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}

	if len(filteredResp.Plugins) < len(totalResp.Plugins) {
		for _, p := range filteredResp.Plugins {
			matched := strings.Contains(strings.ToLower(p.ID), "diagnostics") ||
				strings.Contains(strings.ToLower(p.Name), "diagnostics") ||
				strings.Contains(strings.ToLower(p.Description), "diagnostics")
			if !matched {
				t.Errorf("plugin %s does not contain search keyword 'diagnostics'", p.ID)
			}
		}
	}
}

func TestTier1_F2_FilterByType(t *testing.T) {
	srv := setupE2ETestServer(t)

	totalCode, totalResp := httpGetPlugins(t, srv, srv.adminPAT, "")
	if totalCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", totalCode)
	}

	code, filteredResp := httpGetPlugins(t, srv, srv.adminPAT, "?type=native")
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}

	if len(filteredResp.Plugins) < len(totalResp.Plugins) {
		for _, p := range filteredResp.Plugins {
			if p.Type != "native" && p.Kind != string(plugins.KindAdvanced) {
				t.Errorf("expected native plugin, got type=%s kind=%s (id=%s)", p.Type, p.Kind, p.ID)
			}
		}
	}
}

func TestTier1_F2_CombinedFilter_CategoryAndTypeAndQuery(t *testing.T) {
	srv := setupE2ETestServer(t)

	code, resp := httpGetPlugins(t, srv, srv.adminPAT, "?category=SysAdmin&type=declarative&q=check")
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}
	if resp.Error != "" {
		t.Fatalf("unexpected error response: %s", resp.Error)
	}
}

func TestTier1_F2_CaseInsensitiveFilter(t *testing.T) {
	srv := setupE2ETestServer(t)

	codeLower, respLower := httpGetPlugins(t, srv, srv.adminPAT, "?category=sysadmin")
	codeUpper, respUpper := httpGetPlugins(t, srv, srv.adminPAT, "?category=SYSADMIN")

	if codeLower != http.StatusOK || codeUpper != http.StatusOK {
		t.Fatalf("expected 200 for both casing queries, got lower=%d upper=%d", codeLower, codeUpper)
	}
	if len(respLower.Plugins) != len(respUpper.Plugins) {
		t.Errorf("case mismatch count: lower=%d upper=%d", len(respLower.Plugins), len(respUpper.Plugins))
	}
}

// ============================================================================
// Tier 1 - Feature 3: Native Plugin Execution (POST /api/v1/plugins/execute)
// ============================================================================

func TestTier1_F3_NativePlugin_SysDiagnostics_RuntimeStats(t *testing.T) {
	srv := setupE2ETestServer(t)

	req := map[string]any{
		"plugin_id": "sys-diagnostics",
		"action":    "runtime_stats",
	}
	code, res, _ := httpExecutePlugin(t, srv, srv.adminPAT, req)
	if code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d (error: %s)", code, res.Error)
	}
	if res.Status != "ok" {
		t.Errorf("expected status 'ok', got %q", res.Status)
	}
	if res.DurationMs < 0 {
		t.Errorf("invalid duration_ms: %d", res.DurationMs)
	}
	if dataMap, ok := res.Data.(map[string]any); !ok || dataMap["num_goroutine"] == nil {
		t.Errorf("expected num_goroutine in runtime_stats Data, got: %+v", res.Data)
	}
}

func TestTier1_F3_NativePlugin_SysDiagnostics_NetworkInterfaces(t *testing.T) {
	srv := setupE2ETestServer(t)

	req := map[string]any{
		"plugin_id": "sys-diagnostics",
		"action":    "network_interfaces",
	}
	code, res, _ := httpExecutePlugin(t, srv, srv.adminPAT, req)
	if code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", code)
	}
	if res.Status != "ok" {
		t.Errorf("expected status 'ok', got %q", res.Status)
	}
}

func TestTier1_F3_NativePlugin_SysDiagnostics_EnvSummary(t *testing.T) {
	srv := setupE2ETestServer(t)

	req := map[string]any{
		"plugin_id": "sys-diagnostics",
		"action":    "env_summary",
	}
	code, res, _ := httpExecutePlugin(t, srv, srv.adminPAT, req)
	if code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", code)
	}
	if res.Status != "ok" {
		t.Errorf("expected status 'ok', got %q", res.Status)
	}
	if dataMap, ok := res.Data.(map[string]any); !ok || dataMap["environment"] == nil {
		t.Errorf("expected environment in env_summary Data, got: %+v", res.Data)
	}
}

func TestTier1_F3_NativePlugin_DBExposure_ListTables(t *testing.T) {
	srv := setupE2ETestServer(t)

	req := map[string]any{
		"plugin_id": "db-exposure",
		"action":    "list_tables",
	}
	code, res, _ := httpExecutePlugin(t, srv, srv.adminPAT, req)
	if code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", code)
	}
	if res.Status != "ok" {
		t.Errorf("expected status 'ok', got %q", res.Status)
	}
}

func TestTier1_F3_NativePlugin_DBExposure_DBStats(t *testing.T) {
	srv := setupE2ETestServer(t)

	req := map[string]any{
		"plugin_id": "db-exposure",
		"action":    "db_stats",
	}
	code, res, _ := httpExecutePlugin(t, srv, srv.adminPAT, req)
	if code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", code)
	}
	if res.Status != "ok" {
		t.Errorf("expected status 'ok', got %q", res.Status)
	}
}

// ============================================================================
// Tier 1 - Feature 4: Declarative Plugin Execution (POST /api/v1/plugins/execute)
// ============================================================================

func TestTier1_F4_DeclarativePlugin_ProbeTarget_ValidParam(t *testing.T) {
	srv := setupE2ETestServer(t)

	req := map[string]any{
		"plugin_id": "ops-quick-tools",
		"action":    "probe-target",
		"params": map[string]any{
			"target": "server-01.production.net",
		},
		"timeout": "5s",
	}
	code, res, _ := httpExecutePlugin(t, srv, srv.adminPAT, req)
	if code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d (error: %s)", code, res.Error)
	}
	if res.Status != "ok" {
		t.Errorf("expected status 'ok', got %q", res.Status)
	}
	if !strings.Contains(res.Output, "server-01.production.net") {
		t.Errorf("expected output to contain target value, got: %s", res.Output)
	}
}

func TestTier1_F4_DeclarativePlugin_DefaultParameterFallback(t *testing.T) {
	srv := setupE2ETestServer(t)

	// Omit 'target' parameter, expecting fallback to default value 'localhost'
	req := map[string]any{
		"plugin_id": "ops-quick-tools",
		"action":    "probe-target",
	}
	code, res, _ := httpExecutePlugin(t, srv, srv.adminPAT, req)
	if code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", code)
	}
	if res.Status != "ok" {
		t.Errorf("expected status 'ok', got %q", res.Status)
	}
	if !strings.Contains(res.Output, "localhost") {
		t.Errorf("expected output to use default value 'localhost', got: %s", res.Output)
	}
}

func TestTier1_F4_DeclarativePlugin_CustomTimeoutOverride(t *testing.T) {
	srv := setupE2ETestServer(t)

	req := map[string]any{
		"plugin_id": "ops-quick-tools",
		"action":    "probe-target",
		"params":    map[string]any{"target": "node-10"},
		"timeout":   "8s",
	}
	code, res, _ := httpExecutePlugin(t, srv, srv.adminPAT, req)
	if code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", code)
	}
	if res.Status != "ok" {
		t.Errorf("expected status 'ok', got %q", res.Status)
	}
}

func TestTier1_F4_DeclarativePlugin_DynamicRegistrationAndExecution(t *testing.T) {
	srv := setupE2ETestServer(t)

	echoCmd, baseEchoArgs := crossPlatformEcho()
	echoArgs := append([]string{}, baseEchoArgs...)
	echoArgs = append(echoArgs, "hello={{msg}}")

	spec := map[string]any{
		"id":          "dynamic-tier1-plugin",
		"name":        "Dynamic Tier 1 Plugin",
		"version":     "1.0.0",
		"description": "Dynamically registered declarative plugin for E2E Tier 1 testing",
		"actions": []map[string]any{
			{
				"name":        "echo-message",
				"description": "Echoes back test payload",
				"command":     echoCmd,
				"args":        echoArgs,
				"timeout":     "5s",
				"parameters": []map[string]any{
					{
						"name":        "msg",
						"type":        "string",
						"required":    false,
						"default":     "world",
						"pattern":     `^[a-zA-Z0-9._-]+$`,
						"description": "Message string",
					},
				},
			},
		},
	}

	regCode, info, regRaw := httpRegisterDeclarativePlugin(t, srv, srv.adminPAT, spec)
	if regCode != http.StatusCreated {
		t.Fatalf("expected 201 Created from registration, got %d: %s", regCode, regRaw)
	}
	if info.ID != "dynamic-tier1-plugin" {
		t.Errorf("expected registered plugin ID 'dynamic-tier1-plugin', got %s", info.ID)
	}

	// Immediately execute the registered action
	execReq := map[string]any{
		"plugin_id": "dynamic-tier1-plugin",
		"action":    "echo-message",
		"params":    map[string]any{"msg": "e2e-success"},
	}
	execCode, execRes, _ := httpExecutePlugin(t, srv, srv.adminPAT, execReq)
	if execCode != http.StatusOK {
		t.Fatalf("expected 200 OK executing dynamically registered plugin, got %d", execCode)
	}
	if execRes.Status != "ok" {
		t.Errorf("expected status 'ok', got %q", execRes.Status)
	}
	if !strings.Contains(execRes.Output, "e2e-success") {
		t.Errorf("expected output to contain 'e2e-success', got: %s", execRes.Output)
	}
}

func TestTier1_F4_DeclarativePlugin_CommandOutputAndExitStatus(t *testing.T) {
	srv := setupE2ETestServer(t)

	req := map[string]any{
		"plugin_id": "ops-quick-tools",
		"action":    "process-identity",
	}
	code, res, _ := httpExecutePlugin(t, srv, srv.adminPAT, req)
	if code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", code)
	}
	if res.Status != "ok" {
		t.Errorf("expected status 'ok', got %q", res.Status)
	}
	if strings.TrimSpace(res.Output) == "" {
		t.Errorf("expected non-empty output from process-identity")
	}
}

// ============================================================================
// Tier 1 - Feature 5: Model Context Protocol (MCP) Integration (POST /api/v1/mcp)
// ============================================================================

func TestTier1_F5_MCP_InitializeProtocol(t *testing.T) {
	srv := setupE2ETestServer(t)

	rpcReq := mcp.JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
	}
	code, rpcResp, _ := httpMCPCall(t, srv, srv.adminPAT, rpcReq)
	if code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", code)
	}
	if rpcResp.Error != nil {
		t.Fatalf("unexpected RPC error: %+v", rpcResp.Error)
	}

	resultMap, ok := rpcResp.Result.(map[string]any)
	if !ok {
		t.Fatalf("expected result object in initialize response")
	}
	if resultMap["protocolVersion"] != mcp.MCPProtocolVersion {
		t.Errorf("expected protocolVersion %s, got %v", mcp.MCPProtocolVersion, resultMap["protocolVersion"])
	}
}

func TestTier1_F5_MCP_ToolsList_ExecutePluginPresent(t *testing.T) {
	srv := setupE2ETestServer(t)

	rpcReq := mcp.JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      2,
		Method:  "tools/list",
	}
	code, rpcResp, _ := httpMCPCall(t, srv, srv.adminPAT, rpcReq)
	if code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", code)
	}
	if rpcResp.Error != nil {
		t.Fatalf("unexpected RPC error: %+v", rpcResp.Error)
	}

	resultMap, ok := rpcResp.Result.(map[string]any)
	if !ok {
		t.Fatalf("expected result object")
	}
	toolsRaw, _ := json.Marshal(resultMap["tools"])
	var tools []mcp.MCPTool
	_ = json.Unmarshal(toolsRaw, &tools)

	found := false
	for _, tool := range tools {
		if tool.Name == "execute_plugin" {
			found = true
			if tool.InputSchema == nil {
				t.Errorf("expected inputSchema for execute_plugin")
			}
		}
	}
	if !found {
		t.Errorf("expected 'execute_plugin' tool in tools/list response")
	}
}

func TestTier1_F5_MCP_ToolsCall_ExecutePlugin_Native(t *testing.T) {
	srv := setupE2ETestServer(t)

	paramsBytes, _ := json.Marshal(map[string]any{
		"name": "execute_plugin",
		"arguments": map[string]any{
			"plugin_id": "sys-diagnostics",
			"action":    "runtime_stats",
		},
	})

	rpcReq := mcp.JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      3,
		Method:  "tools/call",
		Params:  paramsBytes,
	}
	code, rpcResp, _ := httpMCPCall(t, srv, srv.adminPAT, rpcReq)
	if code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", code)
	}
	if rpcResp.Error != nil {
		t.Fatalf("unexpected RPC error: %+v", rpcResp.Error)
	}

	callResRaw, _ := json.Marshal(rpcResp.Result)
	var callRes mcp.MCPCallToolResult
	_ = json.Unmarshal(callResRaw, &callRes)

	if callRes.IsError {
		t.Errorf("expected successful tool call, got IsError=true (content: %+v)", callRes.Content)
	}
	if len(callRes.Content) == 0 {
		t.Errorf("expected non-empty content in tool result")
	}
}

func TestTier1_F5_MCP_ToolsCall_ExecutePlugin_Declarative(t *testing.T) {
	srv := setupE2ETestServer(t)

	paramsBytes, _ := json.Marshal(map[string]any{
		"name": "execute_plugin",
		"arguments": map[string]any{
			"plugin_id": "ops-quick-tools",
			"action":    "probe-target",
			"params": map[string]any{
				"target": "mcp-node-01",
			},
		},
	})

	rpcReq := mcp.JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      4,
		Method:  "tools/call",
		Params:  paramsBytes,
	}
	code, rpcResp, _ := httpMCPCall(t, srv, srv.adminPAT, rpcReq)
	if code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", code)
	}
	if rpcResp.Error != nil {
		t.Fatalf("unexpected RPC error: %+v", rpcResp.Error)
	}

	callResRaw, _ := json.Marshal(rpcResp.Result)
	var callRes mcp.MCPCallToolResult
	_ = json.Unmarshal(callResRaw, &callRes)

	if callRes.IsError {
		t.Errorf("expected successful tool call, got IsError=true")
	}
	foundMatch := false
	for _, c := range callRes.Content {
		if strings.Contains(c.Text, "mcp-node-01") {
			foundMatch = true
		}
	}
	if !foundMatch {
		t.Errorf("expected tool output to contain 'mcp-node-01', got: %+v", callRes.Content)
	}
}

func TestTier1_F5_MCP_ResourcesRead_PluginsCatalog(t *testing.T) {
	srv := setupE2ETestServer(t)

	paramsBytes, _ := json.Marshal(map[string]any{
		"uri": "executor://plugins/catalog",
	})

	rpcReq := mcp.JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      5,
		Method:  "resources/read",
		Params:  paramsBytes,
	}
	code, rpcResp, _ := httpMCPCall(t, srv, srv.adminPAT, rpcReq)
	if code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", code)
	}
	if rpcResp.Error != nil {
		t.Fatalf("unexpected RPC error: %+v", rpcResp.Error)
	}

	resMap, ok := rpcResp.Result.(map[string]any)
	if !ok || resMap["contents"] == nil {
		t.Fatalf("expected contents array in resources/read response, got: %+v", rpcResp.Result)
	}
	contentsList, okList := resMap["contents"].([]any)
	if !okList || len(contentsList) == 0 {
		t.Fatalf("expected non-empty contents in resources/read")
	}
}

// ============================================================================
// Tier 1 - Feature 6: Asynchronous Jobs, Queue & Live Logs (POST /api/v1/jobs)
// ============================================================================

func TestTier1_F6_AsyncJob_SubmitCommand_HappyPath(t *testing.T) {
	srv := setupE2ETestServer(t)

	code, resp, raw := httpSubmitJob(t, srv, srv.adminPAT, map[string]any{
		"type":     "command",
		"action":   "echo-cmd",
		"priority": "normal",
	})
	if code != http.StatusAccepted {
		t.Fatalf("expected HTTP 202 Accepted, got %d: %s", code, raw)
	}
	if resp.JobID == "" {
		t.Fatalf("expected non-empty JobID")
	}
	if resp.Status != jobs.StatusQueued {
		t.Errorf("expected status queued, got %s", resp.Status)
	}
	if !strings.Contains(resp.PollURL, resp.JobID) {
		t.Errorf("expected poll_url to reference jobID %s: %s", resp.JobID, resp.PollURL)
	}
	if !strings.Contains(resp.LogsURL, resp.JobID) {
		t.Errorf("expected logs_url to reference jobID %s: %s", resp.JobID, resp.LogsURL)
	}

	terminalJob := pollJobTerminal(t, srv, srv.adminPAT, resp.JobID, 5*time.Second)
	if terminalJob.Status != jobs.StatusCompleted {
		t.Fatalf("expected terminal status completed, got %s (error: %s)", terminalJob.Status, terminalJob.Error)
	}
	if terminalJob.StartedAt == nil || terminalJob.CompletedAt == nil {
		t.Errorf("expected non-nil StartedAt and CompletedAt timestamps")
	}
	if terminalJob.DurationMs < 0 {
		t.Errorf("expected non-negative duration_ms, got %d", terminalJob.DurationMs)
	}
}

func TestTier1_F6_AsyncJob_SubmitPlugin_Native_HappyPath(t *testing.T) {
	srv := setupE2ETestServer(t)

	code, resp, raw := httpSubmitJob(t, srv, srv.adminPAT, map[string]any{
		"type":      "plugin",
		"plugin_id": "sys-diagnostics",
		"action":    "runtime_stats",
		"priority":  "high",
	})
	if code != http.StatusAccepted {
		t.Fatalf("expected HTTP 202 Accepted, got %d: %s", code, raw)
	}
	if resp.JobID == "" {
		t.Fatalf("expected non-empty JobID")
	}

	terminalJob := pollJobTerminal(t, srv, srv.adminPAT, resp.JobID, 5*time.Second)
	if terminalJob.Status != jobs.StatusCompleted {
		t.Fatalf("expected terminal status completed, got %s (error: %s)", terminalJob.Status, terminalJob.Error)
	}
	if terminalJob.PluginID != "sys-diagnostics" {
		t.Errorf("expected PluginID sys-diagnostics, got %s", terminalJob.PluginID)
	}
}

func TestTier1_F6_AsyncJob_GetJob_StatusTransition(t *testing.T) {
	srv := setupE2ETestServer(t)

	code, resp, raw := httpSubmitJob(t, srv, srv.adminPAT, map[string]any{
		"type":   "command",
		"action": "test-echo",
	})
	if code != http.StatusAccepted {
		t.Fatalf("expected 202 Accepted, got %d: %s", code, raw)
	}

	terminalJob := pollJobTerminal(t, srv, srv.adminPAT, resp.JobID, 5*time.Second)
	if terminalJob.Status != jobs.StatusCompleted {
		t.Fatalf("expected job to complete, got %s", terminalJob.Status)
	}

	statusCode, detail, detailRaw := httpGetJob(t, srv, srv.adminPAT, resp.JobID)
	if statusCode != http.StatusOK {
		t.Fatalf("expected HTTP 200 OK from GET /api/v1/jobs/{id}, got %d: %s", statusCode, detailRaw)
	}
	if detail.ID != resp.JobID {
		t.Errorf("expected ID %s, got %s", resp.JobID, detail.ID)
	}
	if detail.ActorID != "e2e_admin_user" {
		t.Errorf("expected ActorID e2e_admin_user, got %s", detail.ActorID)
	}
	if detail.ActorType != "user_token" && detail.ActorType != "user" {
		t.Errorf("expected ActorType user_token or user, got %s", detail.ActorType)
	}
}

func TestTier1_F6_AsyncJob_ListJobs_FilteringAndPagination(t *testing.T) {
	srv := setupE2ETestServer(t)

	// Submit 3 jobs
	for i := 0; i < 3; i++ {
		code, _, _ := httpSubmitJob(t, srv, srv.adminPAT, map[string]any{
			"type":   "command",
			"action": "echo-cmd",
		})
		if code != http.StatusAccepted {
			t.Fatalf("failed to submit job %d", i)
		}
	}

	// Give workers a moment to process
	time.Sleep(200 * time.Millisecond)

	// Pagination: page 1 with limit 2, offset 0
	code1, list1, raw1 := httpListJobs(t, srv, srv.adminPAT, "?limit=2&offset=0")
	if code1 != http.StatusOK {
		t.Fatalf("expected HTTP 200 OK, got %d: %s", code1, raw1)
	}
	if len(list1.Jobs) != 2 {
		t.Fatalf("expected 2 jobs on page 1, got %d", len(list1.Jobs))
	}
	if list1.Total < 3 {
		t.Errorf("expected total >= 3, got %d", list1.Total)
	}

	// Pagination: page 2 with limit 2, offset 2
	code2, list2, raw2 := httpListJobs(t, srv, srv.adminPAT, "?limit=2&offset=2")
	if code2 != http.StatusOK {
		t.Fatalf("expected HTTP 200 OK, got %d: %s", code2, raw2)
	}
	if len(list2.Jobs) < 1 {
		t.Fatalf("expected at least 1 job on page 2, got %d", len(list2.Jobs))
	}
	if list1.Jobs[0].ID == list2.Jobs[0].ID {
		t.Errorf("expected different jobs on page 1 and page 2")
	}

	// Filter by status=completed
	codeFilter, listFilter, _ := httpListJobs(t, srv, srv.adminPAT, "?status=completed")
	if codeFilter != http.StatusOK {
		t.Fatalf("expected 200 OK on filtered list, got %d", codeFilter)
	}
	for _, j := range listFilter.Jobs {
		if j.Status != jobs.StatusCompleted {
			t.Errorf("expected status completed, got %s", j.Status)
		}
	}
}

func TestTier1_F6_AsyncJob_QueueStats_Telemetry(t *testing.T) {
	srv := setupE2ETestServer(t)

	code, stats, raw := httpGetQueueStats(t, srv, srv.adminPAT)
	if code != http.StatusOK {
		t.Fatalf("expected HTTP 200 OK from /api/v1/jobs/queue, got %d: %s", code, raw)
	}
	if stats.WorkersTotal <= 0 {
		t.Errorf("expected positive WorkersTotal, got %d", stats.WorkersTotal)
	}
	if stats.Capacity <= 0 {
		t.Errorf("expected positive Capacity, got %d", stats.Capacity)
	}
	if stats.QueuedJobs < 0 {
		t.Errorf("expected non-negative QueuedJobs, got %d", stats.QueuedJobs)
	}
	if stats.WorkersActive < 0 {
		t.Errorf("expected non-negative WorkersActive, got %d", stats.WorkersActive)
	}
}

func TestTier1_F6_AsyncJob_ChunkedLogStreaming(t *testing.T) {
	srv := setupE2ETestServer(t)

	code, resp, raw := httpSubmitJob(t, srv, srv.adminPAT, map[string]any{
		"type":   "command",
		"action": "echo-cmd",
	})
	if code != http.StatusAccepted {
		t.Fatalf("expected 202 Accepted, got %d: %s", code, raw)
	}

	pollJobTerminal(t, srv, srv.adminPAT, resp.JobID, 5*time.Second)

	// Fetch logs from offset 0
	logCode, logResp, logRaw := httpGetJobLogs(t, srv, srv.adminPAT, resp.JobID, 0)
	if logCode != http.StatusOK {
		t.Fatalf("expected 200 OK from /logs, got %d: %s", logCode, logRaw)
	}
	if !strings.Contains(logResp.Logs, "e2e-async-output") {
		t.Errorf("expected logs to contain 'e2e-async-output', got: %q", logResp.Logs)
	}
	if logResp.NextOffset <= 0 {
		t.Errorf("expected NextOffset > 0, got %d", logResp.NextOffset)
	}
	if logResp.Truncated {
		t.Errorf("expected truncated to be false")
	}

	// Fetch logs from next offset (should be empty with EOF)
	logCode2, logResp2, _ := httpGetJobLogs(t, srv, srv.adminPAT, resp.JobID, logResp.NextOffset)
	if logCode2 != http.StatusOK {
		t.Fatalf("expected 200 OK from /logs next offset, got %d", logCode2)
	}
	if logResp2.Logs != "" {
		t.Errorf("expected empty logs at EOF, got %q", logResp2.Logs)
	}
	if !logResp2.EOF {
		t.Errorf("expected EOF to be true at stream end")
	}
}

