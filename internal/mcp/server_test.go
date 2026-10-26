package mcp

import (
	"context"
	"encoding/json"
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

