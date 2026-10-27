package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"go-admin-tool/internal/audit"
	"go-admin-tool/internal/core"
	"go-admin-tool/internal/database"
	"go-admin-tool/internal/plugins"
)

func TestMCPServerFullLifecycleAndTraceRetention(t *testing.T) {
	tmpDir := t.TempDir()

	var echoCmd core.CommandDefinition
	if runtime.GOOS == "windows" {
		echoCmd = core.CommandDefinition{
			Name:    "mcp-hello",
			Command: "cmd",
			Args:    []string{"/C", "echo mcp-execution-ok"},
		}
	} else {
		echoCmd = core.CommandDefinition{
			Name:    "mcp-hello",
			Command: "sh",
			Args:    []string{"-c", "echo mcp-execution-ok"},
		}
	}

	appCfg := core.DefaultConfig()
	appCfg.Executor.Commands = []core.CommandDefinition{echoCmd}

	db, err := database.NewDB(filepath.Join(tmpDir, "mcp_test.db"))
	if err != nil {
		t.Fatalf("NewDB failed: %v", err)
	}
	defer db.Close()
	_ = db.Init()

	auditLogger, err := audit.NewAuditLogger(core.AuditConfig{Enabled: true, MaxMemoryLog: 100}, db, nil)
	if err != nil {
		t.Fatalf("NewAuditLogger failed: %v", err)
	}

	reg := plugins.NewRegistry()
	_ = reg.Register(plugins.NewDatabaseExposurePlugin(db, 100))
	_ = reg.Register(plugins.NewSystemDiagnosticsPlugin())

	var recordedActions []string
	srv, err := NewServer(
		core.MCPConfig{
			Enabled:       true,
			ServerName:    "api-executor-mcp",
			ServerVersion: "2.0.0",
			RetainTraces:  true,
			MaxTraces:     100,
			TraceFilePath: filepath.Join(tmpDir, "mcp_traces.jsonl"),
		},
		appCfg,
		db,
		nil,
		reg,
		auditLogger,
		nil,
		func(action, outcome string, _ bool, _ time.Duration) {
			recordedActions = append(recordedActions, action+":"+outcome)
		},
	)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	// 1. initialize
	initResp := srv.HandleJSONRPC(context.Background(), JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
	}, "sess-01", "claude-agent")
	if initResp.Error != nil {
		t.Fatalf("initialize returned error: %+v", initResp.Error)
	}

	// 2. tools/list
	toolsResp := srv.HandleJSONRPC(context.Background(), JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      2,
		Method:  "tools/list",
	}, "sess-01", "claude-agent")
	if toolsResp.Error != nil {
		t.Fatalf("tools/list returned error: %+v", toolsResp.Error)
	}

	// 3. tools/call -> execute_command
	callParams, _ := json.Marshal(map[string]any{
		"name": "execute_command",
		"arguments": map[string]any{
			"name":    "mcp-hello",
			"timeout": "5s",
		},
	})
	callResp := srv.HandleJSONRPC(context.Background(), JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      3,
		Method:  "tools/call",
		Params:  callParams,
	}, "sess-01", "claude-agent")
	if callResp.Error != nil {
		t.Fatalf("tools/call execute_command returned RPC error: %+v", callResp.Error)
	}
	resObj, ok := callResp.Result.(MCPCallToolResult)
	if !ok || resObj.IsError || !strings.Contains(resObj.Content[0].Text, "mcp-execution-ok") {
		t.Errorf("unexpected execute_command tool result: %+v", callResp.Result)
	}

	// 4. tools/call -> db_query (via db-exposure plugin)
	dbParams, _ := json.Marshal(map[string]any{
		"name": "db_query",
		"arguments": map[string]any{
			"sql": "SELECT command, status FROM action_history",
		},
	})
	dbResp := srv.HandleJSONRPC(context.Background(), JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      4,
		Method:  "tools/call",
		Params:  dbParams,
	}, "sess-01", "claude-agent")
	if dbResp.Error != nil {
		t.Fatalf("tools/call db_query failed: %+v", dbResp.Error)
	}

	// 5. resources/read -> executor://os-presets/catalog
	resReadParams, _ := json.Marshal(map[string]any{
		"uri": "executor://os-presets/catalog",
	})
	resReadResp := srv.HandleJSONRPC(context.Background(), JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      5,
		Method:  "resources/read",
		Params:  resReadParams,
	}, "sess-01", "claude-agent")
	if resReadResp.Error != nil {
		t.Fatalf("resources/read failed: %+v", resReadResp.Error)
	}

	// 6. Verify trace retention and linked audit events
	traces := srv.ListTraces(TraceFilter{SessionID: "sess-01"})
	if len(traces) != 5 {
		t.Fatalf("expected 5 retained MCP traces for sess-01, got %d", len(traces))
	}
	foundTrace, err := srv.GetTrace(callResp.TraceID)
	if err != nil {
		t.Fatalf("GetTrace(%s) failed: %v", callResp.TraceID, err)
	}
	if foundTrace.ToolName != "execute_command" || foundTrace.AuditEventID == "" {
		t.Errorf("expected tool_name='execute_command' and linked AuditEventID, got %+v", foundTrace)
	}

	// Verify audit chain remains 100% valid
	chainVerify := auditLogger.VerifyChain()
	if !chainVerify.Valid || chainVerify.TotalEvents < 5 {
		t.Errorf("expected valid audit chain with >= 5 events, got %+v", chainVerify)
	}

	// 7. Test resources/list, prompts/list, prompts/get, ping, and additional tools/call
	for _, method := range []string{"resources/list", "prompts/list", "ping"} {
		r := srv.HandleJSONRPC(context.Background(), JSONRPCRequest{
			JSONRPC: "2.0",
			ID:      10,
			Method:  method,
		}, "sess-02", "agent-2")
		if r.Error != nil {
			t.Errorf("expected %s to succeed, got %+v", method, r.Error)
		}
	}

	for _, promptName := range []string{"diagnose-host", "security-audit-review", "database-inspection"} {
		pParams, _ := json.Marshal(map[string]any{"name": promptName})
		pResp := srv.HandleJSONRPC(context.Background(), JSONRPCRequest{
			JSONRPC: "2.0",
			ID:      11,
			Method:  "prompts/get",
			Params:  pParams,
		}, "sess-02", "agent-2")
		if pResp.Error != nil {
			t.Errorf("expected prompts/get(%s) to succeed, got %+v", promptName, pResp.Error)
		}
	}

	for _, toolName := range []string{"list_commands", "db_list_tables", "audit_verify", "audit_query", "tls_status"} {
		tParams, _ := json.Marshal(map[string]any{"name": toolName, "arguments": map[string]any{}})
		tResp := srv.HandleJSONRPC(context.Background(), JSONRPCRequest{
			JSONRPC: "2.0",
			ID:      12,
			Method:  "tools/call",
			Params:  tParams,
		}, "sess-02", "agent-2")
		if tResp.Error != nil {
			t.Errorf("expected tools/call(%s) to succeed, got %+v", toolName, tResp.Error)
		}
	}

	// Unknown method returns -32601
	unkResp := srv.HandleJSONRPC(context.Background(), JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      99,
		Method:  "unknown/method",
	}, "sess-02", "agent-2")
	if unkResp.Error == nil || unkResp.Error.Code != -32601 {
		t.Errorf("expected -32601 for unknown method, got %+v", unkResp.Error)
	}

	// ClearTraces
	cleared := srv.ClearTraces()
	if cleared == 0 || len(srv.ListTraces(TraceFilter{})) != 0 {
		t.Errorf("expected ClearTraces to empty trace buffer")
	}
}

func TestMCPServerToolsResourcesPromptsAndErrorBranches(t *testing.T) {
	tmpDir := t.TempDir()
	db, _ := database.NewDB(filepath.Join(tmpDir, "mcp_err.db"))
	defer db.Close()
	_ = db.Init()

	certMgr, err := core.NewCertManager(core.TLSConfig{
		Enabled:      true,
		AutoGenerate: true,
		CertFile:     filepath.Join(tmpDir, "server.crt"),
		KeyFile:      filepath.Join(tmpDir, "server.key"),
	}, "localhost")
	if err != nil {
		t.Fatalf("NewCertManager failed: %v", err)
	}

	auditLogger, _ := audit.NewAuditLogger(core.AuditConfig{Enabled: true}, db, nil)
	reg := plugins.NewRegistry()
	_ = reg.Register(plugins.NewDatabaseExposurePlugin(db, 50))
	_ = reg.Register(plugins.NewSystemDiagnosticsPlugin())

	appCfg := core.DefaultConfig()
	appCfg.Executor.Commands = []core.CommandDefinition{
		{
			Name:    "fail-bin",
			Command: "nonexistent_mcp_binary_xyz",
		},
	}

	var metricsCount int
	srv, err := NewServer(
		core.MCPConfig{
			Enabled:      true,
			RetainTraces: true,
			MaxTraces:    3, // small cap to test ring buffer eviction
		},
		appCfg,
		db,
		certMgr,
		reg,
		auditLogger,
		nil,
		func(_ string, _ string, _ bool, _ time.Duration) {
			metricsCount++
		},
	)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	callTool := func(name string, args map[string]any, authFn ToolAuthorizer) JSONRPCResponse {
		p, _ := json.Marshal(map[string]any{"name": name, "arguments": args})
		return srv.HandleJSONRPCWithAuthorizer(context.Background(), JSONRPCRequest{
			JSONRPC: "2.0",
			ID:      1,
			Method:  "tools/call",
			Params:  p,
		}, "sess-edge", "", authFn)
	}

	// 1. Invalid JSON-RPC params and empty tool name on tools/call
	badParamResp := srv.HandleJSONRPC(context.Background(), JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
		Params:  json.RawMessage(`"not-an-object"`),
	}, "s", "")
	if badParamResp.Error == nil || badParamResp.Error.Code != -32602 {
		t.Errorf("expected -32602 for invalid tools/call params, got %+v", badParamResp.Error)
	}
	emptyNameResp := callTool("   ", nil, nil)
	if emptyNameResp.Error == nil || emptyNameResp.Error.Code != -32602 {
		t.Errorf("expected -32602 for empty tool name, got %+v", emptyNameResp.Error)
	}

	// 2. execute_command edge cases: missing name, denied by authorizer, bad timeout, not found, failing binary
	for _, tc := range []struct {
		args   map[string]any
		authFn ToolAuthorizer
	}{
		{args: map[string]any{}, authFn: nil},
		{args: map[string]any{"name": "fail-bin"}, authFn: func(_, _ string) error { return plugins.ErrForbiddenSQL }},
		{args: map[string]any{"name": "fail-bin", "timeout": "invalid-dur"}, authFn: nil},
		{args: map[string]any{"name": "unknown-cmd"}, authFn: nil},
		{args: map[string]any{"name": "fail-bin"}, authFn: nil},
	} {
		resp := callTool("execute_command", tc.args, tc.authFn)
		res, ok := resp.Result.(MCPCallToolResult)
		if !ok || !res.IsError {
			t.Errorf("expected IsError=true for execute_command(%v), got %+v", tc.args, resp)
		}
	}

	// 3. list_commands with os_family filter
	listResp := callTool("list_commands", map[string]any{"os_family": "ubuntu"}, nil)
	if res, ok := listResp.Result.(MCPCallToolResult); !ok || res.IsError {
		t.Errorf("expected list_commands(ubuntu) to succeed, got %+v", listResp)
	}

	// 4. execute_plugin: missing args, denied by authorizer, valid execution, failing execution
	if res := callTool("execute_plugin", map[string]any{"plugin_id": "sys-diagnostics"}, nil).Result.(MCPCallToolResult); !res.IsError {
		t.Errorf("expected IsError when action is missing in execute_plugin")
	}
	if res := callTool("execute_plugin", map[string]any{"plugin_id": "sys-diagnostics", "action": "runtime_stats"}, func(_, _ string) error {
		return plugins.ErrForbiddenSQL
	}).Result.(MCPCallToolResult); !res.IsError {
		t.Errorf("expected IsError when authorizer denies execute_plugin")
	}
	if res := callTool("execute_plugin", map[string]any{
		"plugin_id": "sys-diagnostics",
		"action":    "runtime_stats",
		"params":    map[string]any{"detail": true},
	}, nil).Result.(MCPCallToolResult); res.IsError {
		t.Errorf("expected execute_plugin(sys-diagnostics:runtime_stats) to succeed, got %+v", res)
	}
	if res := callTool("execute_plugin", map[string]any{
		"plugin_id": "sys-diagnostics",
		"action":    "non-existent-action",
	}, nil).Result.(MCPCallToolResult); !res.IsError {
		t.Errorf("expected IsError for unknown plugin action")
	}

	// 5. db_query & db_list_tables: denied by authorizer and forbidden SQL
	denyFn := func(_, _ string) error { return plugins.ErrForbiddenSQL }
	if res := callTool("db_query", map[string]any{"sql": "SELECT 1"}, denyFn).Result.(MCPCallToolResult); !res.IsError {
		t.Errorf("expected db_query denial to return IsError")
	}
	if res := callTool("db_query", map[string]any{"sql": "DROP TABLE action_history"}, nil).Result.(MCPCallToolResult); !res.IsError {
		t.Errorf("expected forbidden SQL in db_query to return IsError")
	}
	if res := callTool("db_list_tables", nil, denyFn).Result.(MCPCallToolResult); !res.IsError {
		t.Errorf("expected db_list_tables denial to return IsError")
	}

	// 6. audit_query with filters and unknown tool
	if res := callTool("audit_query", map[string]any{"category": "mcp", "status": "ok"}, nil).Result.(MCPCallToolResult); res.IsError {
		t.Errorf("expected audit_query with filters to succeed")
	}
	if res := callTool("unknown_tool_xyz", nil, nil).Result.(MCPCallToolResult); !res.IsError {
		t.Errorf("expected unknown tool to return IsError")
	}

	// 7. resources/read for all URIs + invalid/unknown URI
	for _, uri := range []string{
		"executor://commands/catalog",
		"executor://os-presets/catalog",
		"executor://plugins/catalog",
		"executor://tls/info",
		"executor://audit/verify",
	} {
		raw, _ := json.Marshal(map[string]any{"uri": uri})
		r := srv.HandleJSONRPC(context.Background(), JSONRPCRequest{JSONRPC: "2.0", ID: 20, Method: "resources/read", Params: raw}, "s", "a")
		if r.Error != nil {
			t.Errorf("expected resources/read(%s) to succeed, got %+v", uri, r.Error)
		}
	}
	emptyURI, _ := json.Marshal(map[string]any{"uri": ""})
	if r := srv.HandleJSONRPC(context.Background(), JSONRPCRequest{JSONRPC: "2.0", ID: 21, Method: "resources/read", Params: emptyURI}, "s", "a"); r.Error == nil {
		t.Errorf("expected error for empty resource URI")
	}
	unknownURI, _ := json.Marshal(map[string]any{"uri": "executor://unknown/uri"})
	if r := srv.HandleJSONRPC(context.Background(), JSONRPCRequest{JSONRPC: "2.0", ID: 22, Method: "resources/read", Params: unknownURI}, "s", "a"); r.Error == nil || r.Error.Code != -32002 {
		t.Errorf("expected -32002 for unknown resource URI, got %+v", r.Error)
	}

	// 8. prompts/get with explicit arguments, empty name, and unknown prompt
	diagArgs, _ := json.Marshal(map[string]any{"name": "diagnose-host", "arguments": map[string]string{"os_family": "redhat"}})
	if r := srv.HandleJSONRPC(context.Background(), JSONRPCRequest{JSONRPC: "2.0", ID: 30, Method: "prompts/get", Params: diagArgs}, "s", "a"); r.Error != nil {
		t.Errorf("expected diagnose-host(redhat) to succeed, got %+v", r.Error)
	}
	if r := srv.HandleJSONRPC(context.Background(), JSONRPCRequest{JSONRPC: "2.0", ID: 31, Method: "prompts/get", Params: json.RawMessage(`{}`)}, "s", "a"); r.Error == nil {
		t.Errorf("expected error for empty prompt name")
	}
	unkPrompt, _ := json.Marshal(map[string]any{"name": "unknown-prompt"})
	if r := srv.HandleJSONRPC(context.Background(), JSONRPCRequest{JSONRPC: "2.0", ID: 32, Method: "prompts/get", Params: unkPrompt}, "s", "a"); r.Error == nil {
		t.Errorf("expected error for unknown prompt")
	}

	// 9. ListTraces filtering and GetTrace not-found
	_ = srv.ListTraces(TraceFilter{Method: "tools/call", ToolName: "unknown_tool_xyz", Status: "error", Limit: 0})
	if _, err := srv.GetTrace("mcp_tr_nonexistent"); err == nil {
		t.Errorf("expected error for non-existent trace ID")
	}

	// 10. Server with nil dependencies (nil pluginRegistry, nil auditLogger, nil appConfig)
	bareSrv, _ := NewServer(core.MCPConfig{}, nil, nil, nil, nil, nil, nil, nil)
	for _, tool := range []string{"execute_plugin", "db_query", "db_list_tables", "audit_query", "audit_verify"} {
		p, _ := json.Marshal(map[string]any{"name": tool})
		r := bareSrv.HandleJSONRPC(context.Background(), JSONRPCRequest{JSONRPC: "2.0", ID: 40, Method: "tools/call", Params: p}, "s", "a")
		if res, ok := r.Result.(MCPCallToolResult); !ok || !res.IsError {
			t.Errorf("expected IsError=true on bare server for tool %s, got %+v", tool, r)
		}
	}
}

func TestMCPServer_ResourcePluginsCatalog_300PlusPlugins(t *testing.T) {
	pluginsDir := "plugins"
	if _, err := os.Stat(pluginsDir); err != nil && os.IsNotExist(err) {
		pluginsDir = "../../plugins"
	}

	reg := plugins.NewRegistry()
	loaded, err := reg.LoadDeclarativeDirectory(pluginsDir)
	if err != nil {
		t.Fatalf("failed to load declarative plugins from %s: %v", pluginsDir, err)
	}
	if loaded < 280 {
		t.Fatalf("expected at least 280 declarative plugins, loaded %d", loaded)
	}

	allPlugins := reg.List()
	if len(allPlugins) < 300 {
		t.Fatalf("expected at least 300 total plugins in registry, got %d", len(allPlugins))
	}

	tmpDir := t.TempDir()
	db, err := database.NewDB(filepath.Join(tmpDir, "mcp_300_test.db"))
	if err != nil {
		t.Fatalf("NewDB failed: %v", err)
	}
	defer db.Close()
	_ = db.Init()
	_ = reg.Register(plugins.NewDatabaseExposurePlugin(db, 100))

	auditLogger, err := audit.NewAuditLogger(core.AuditConfig{Enabled: true, MaxMemoryLog: 100}, db, nil)
	if err != nil {
		t.Fatalf("NewAuditLogger failed: %v", err)
	}

	var recordedActions []string
	srv, err := NewServer(
		core.MCPConfig{
			Enabled:       true,
			ServerName:    "api-executor-mcp",
			ServerVersion: "2.0.0",
			RetainTraces:  true,
			MaxTraces:     100,
		},
		core.DefaultConfig(),
		db,
		nil,
		reg,
		auditLogger,
		nil,
		func(action, outcome string, _ bool, _ time.Duration) {
			recordedActions = append(recordedActions, action+":"+outcome)
		},
	)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	// 1. Verify executor://plugins/catalog is declared in Resources()
	resList := srv.Resources()
	foundCatalogResource := false
	for _, r := range resList {
		if r.URI == "executor://plugins/catalog" {
			foundCatalogResource = true
			if r.MimeType != "application/json" {
				t.Errorf("expected application/json mimeType, got %s", r.MimeType)
			}
			break
		}
	}
	if !foundCatalogResource {
		t.Fatalf("executor://plugins/catalog resource not found in MCP server resources")
	}

	// 2. Read executor://plugins/catalog resource via JSON-RPC
	readReq, _ := json.Marshal(map[string]any{"uri": "executor://plugins/catalog"})
	readResp := srv.HandleJSONRPC(context.Background(), JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      100,
		Method:  "resources/read",
		Params:  readReq,
	}, "sess-catalog", "llm-agent")
	if readResp.Error != nil {
		t.Fatalf("resources/read returned error: %+v", readResp.Error)
	}

	resultMap, ok := readResp.Result.(map[string]any)
	if !ok {
		t.Fatalf("unexpected result structure: %+v", readResp.Result)
	}
	contentsList, ok := resultMap["contents"].([]map[string]any)
	if !ok || len(contentsList) == 0 {
		t.Fatalf("missing contents in resources/read response: %+v", resultMap)
	}
	catalogJSON, ok := contentsList[0]["text"].(string)
	if !ok || len(catalogJSON) == 0 {
		t.Fatalf("empty catalog text in resources/read")
	}

	var catalog []plugins.PluginInfo
	if err := json.Unmarshal([]byte(catalogJSON), &catalog); err != nil {
		t.Fatalf("failed to unmarshal catalog JSON: %v", err)
	}
	if len(catalog) < 300 {
		t.Fatalf("expected >= 300 plugins in MCP resource catalog, got %d", len(catalog))
	}

	// Verify all 10 domain categories are present with at least 28 plugins each
	requiredCategories := []string{
		"SysAdmin", "NetOps", "SecOps", "ContainerOps", "Kubernetes",
		"DataOps", "DevOps", "SRE", "AIOps", "WebUtils",
	}
	catCounts := make(map[string]int)
	for _, p := range catalog {
		catCounts[p.Category]++
	}
	for _, reqCat := range requiredCategories {
		count := catCounts[reqCat]
		if count < 28 {
			t.Errorf("category %q has %d plugins in MCP catalog, expected >= 28", reqCat, count)
		}
	}

	// 3. Test execute_plugin meta-tool on Native Go plugin (sys-diagnostics:runtime_stats)
	nativeExecReq, _ := json.Marshal(map[string]any{
		"name": "execute_plugin",
		"arguments": map[string]any{
			"plugin_id": "sys-diagnostics",
			"action":    "runtime_stats",
		},
	})
	nativeExecResp := srv.HandleJSONRPC(context.Background(), JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      101,
		Method:  "tools/call",
		Params:  nativeExecReq,
	}, "sess-exec", "llm-agent")
	if nativeExecResp.Error != nil {
		t.Fatalf("execute_plugin native returned JSON-RPC error: %+v", nativeExecResp.Error)
	}
	nativeCallRes, ok := nativeExecResp.Result.(MCPCallToolResult)
	if !ok {
		t.Fatalf("unexpected call result type: %+v", nativeExecResp.Result)
	}
	if nativeCallRes.IsError {
		t.Errorf("expected native plugin execution to succeed, got error result: %+v", nativeCallRes)
	}
	if len(nativeCallRes.Content) == 0 || len(nativeCallRes.Content[0].Text) == 0 {
		t.Errorf("expected non-empty output text from sys-diagnostics:runtime_stats")
	}

	// 4. Test execute_plugin meta-tool on db-exposure (list_tables)
	dbExecReq, _ := json.Marshal(map[string]any{
		"name": "execute_plugin",
		"arguments": map[string]any{
			"plugin_id": "db-exposure",
			"action":    "list_tables",
		},
	})
	dbExecResp := srv.HandleJSONRPC(context.Background(), JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      102,
		Method:  "tools/call",
		Params:  dbExecReq,
	}, "sess-exec", "llm-agent")
	if dbExecResp.Error != nil {
		t.Fatalf("execute_plugin db-exposure returned error: %+v", dbExecResp.Error)
	}
	dbCallRes := dbExecResp.Result.(MCPCallToolResult)
	if dbCallRes.IsError {
		t.Errorf("expected db-exposure:list_tables to succeed, got error: %+v", dbCallRes)
	}

	// 5. Test execute_plugin error paths
	// 5a. Missing plugin_id
	badArgs1, _ := json.Marshal(map[string]any{
		"name":      "execute_plugin",
		"arguments": map[string]any{"action": "test"},
	})
	badResp1 := srv.HandleJSONRPC(context.Background(), JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      103,
		Method:  "tools/call",
		Params:  badArgs1,
	}, "sess-err", "llm-agent")
	if res, ok := badResp1.Result.(MCPCallToolResult); !ok || !res.IsError {
		t.Errorf("expected IsError=true for missing plugin_id")
	}

	// 5b. Non-existent plugin ID
	badArgs2, _ := json.Marshal(map[string]any{
		"name": "execute_plugin",
		"arguments": map[string]any{
			"plugin_id": "nonexistent-plugin-xyz",
			"action":    "some_action",
		},
	})
	badResp2 := srv.HandleJSONRPC(context.Background(), JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      104,
		Method:  "tools/call",
		Params:  badArgs2,
	}, "sess-err", "llm-agent")
	if res, ok := badResp2.Result.(MCPCallToolResult); !ok || !res.IsError {
		t.Errorf("expected IsError=true for nonexistent plugin ID")
	}

	// 6. Test RBAC denial with authorizer
	denyAuthorizer := func(scope, action string) error {
		return errors.New("insufficient permission")
	}
	denyResp := srv.HandleJSONRPCWithAuthorizer(context.Background(), JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      105,
		Method:  "tools/call",
		Params:  nativeExecReq,
	}, "sess-deny", "restricted-agent", denyAuthorizer)
	if res, ok := denyResp.Result.(MCPCallToolResult); !ok || !res.IsError {
		t.Errorf("expected IsError=true when authorizer denies execute_plugin")
	}
}



