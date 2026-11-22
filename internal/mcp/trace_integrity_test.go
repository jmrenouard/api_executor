package mcp

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"go-admin-tool/internal/audit"
	"go-admin-tool/internal/core"
	"go-admin-tool/internal/database"
	"go-admin-tool/internal/plugins"
)

func TestCanonicalJSONSHA256_DeterminismAcrossStructAndMap(t *testing.T) {
	structVal := MCPCallToolResult{
		Content:           []MCPContentBlock{{Type: "text", Text: "ok"}},
		IsError:           false,
		StructuredContent: map[string]any{"b": 2, "a": "x"},
		TraceID:           "mcp_tr_1234",
	}
	mapVal := map[string]any{
		"traceId":           "mcp_tr_1234",
		"structuredContent": map[string]any{"a": "x", "b": 2},
		"isError":           false,
		"content":           []any{map[string]any{"text": "ok", "type": "text"}},
	}

	d1, err := CanonicalJSONSHA256(structVal)
	if err != nil {
		t.Fatalf("CanonicalJSONSHA256(struct): %v", err)
	}
	d2, err := CanonicalJSONSHA256(mapVal)
	if err != nil {
		t.Fatalf("CanonicalJSONSHA256(map): %v", err)
	}
	if len(d1) != 64 || d1 != d2 {
		t.Fatalf("expected identical 64-hex digests, got %s vs %s", d1, d2)
	}
}

func TestMCPTraceHashChainAndTamperDetection(t *testing.T) {
	cfg := core.DefaultConfig()
	cfg.MCP.RetainTraces = true
	cfg.MCP.MaxTraces = 50
	traceFile := filepath.Join(t.TempDir(), "traces.jsonl")
	cfg.MCP.TraceFilePath = traceFile

	auditLogger, err := audit.NewAuditLogger(core.AuditConfig{Enabled: true, MaxMemoryLog: 200}, nil, nil)
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	defer auditLogger.Close()

	reg := plugins.NewEmptyRegistry()
	_ = reg.Register(plugins.NewSystemDiagnosticsPlugin())

	srv, err := NewServer(cfg.MCP, cfg, nil, nil, reg, auditLogger, nil, nil)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer srv.Close()

	// 1. Execute 3 MCP requests
	r1 := srv.HandleJSONRPC(context.Background(), JSONRPCRequest{JSONRPC: "2.0", ID: 1, Method: "ping"}, "s1", "alice")
	r2 := srv.HandleJSONRPC(context.Background(), JSONRPCRequest{JSONRPC: "2.0", ID: 2, Method: "tools/list"}, "s1", "alice")
	rawVerifyParams, _ := json.Marshal(map[string]any{"name": "mcp_trace_verify", "arguments": map[string]any{"trace_id": r1.TraceID}})
	r3 := srv.HandleJSONRPC(context.Background(), JSONRPCRequest{JSONRPC: "2.0", ID: 3, Method: "tools/call", Params: rawVerifyParams}, "s1", "alice")

	// Verify mcp_trace_verify tool call succeeded
	if toolRes, ok := r3.Result.(MCPCallToolResult); !ok || toolRes.IsError {
		t.Fatalf("expected mcp_trace_verify tool call to succeed, got %+v", r3)
	}

	// 2. Inspect stored traces for 64-hex digests and chain linkage
	t1, err := srv.GetTrace(r1.TraceID)
	if err != nil {
		t.Fatalf("GetTrace(r1): %v", err)
	}
	t2, err := srv.GetTrace(r2.TraceID)
	if err != nil {
		t.Fatalf("GetTrace(r2): %v", err)
	}
	if len(t1.RequestSHA256) != 64 || len(t1.ResponseSHA256) != 64 || len(t1.TraceHash) != 64 || len(t1.AuditEntryHash) != 64 {
		t.Fatalf("expected valid 64-hex digests on trace 1, got %+v", t1)
	}
	if t1.PrevTraceHash != MCPTraceGenesisHash {
		t.Fatalf("expected genesis prev_trace_hash on trace 1, got %q", t1.PrevTraceHash)
	}
	if t2.PrevTraceHash != t1.TraceHash {
		t.Fatalf("expected trace 2 prev_trace_hash=%s, got %s", t1.TraceHash, t2.PrevTraceHash)
	}

	// 3. Verify chain and single trace integrity
	chainVer := srv.VerifyTraceChain()
	if !chainVer.Valid || chainVer.TotalTraces != 3 || !chainVer.AuditChainValid {
		t.Fatalf("expected valid trace chain of 3, got %+v", chainVer)
	}
	singleVer, err := srv.VerifyTraceIntegrity(r2.TraceID)
	if err != nil || !singleVer.Valid || !singleVer.AuditLinkValid || !singleVer.ChainLinkValid {
		t.Fatalf("expected valid single trace integrity, got %+v err=%v", singleVer, err)
	}

	// 4. Tamper with RequestPayload -> VerifyTraceChain and VerifyTraceIntegrity must detect it
	srv.mu.Lock()
	origReq := srv.traces[1].RequestPayload
	srv.traces[1].RequestPayload = map[string]any{"tampered": true}
	srv.mu.Unlock()

	tamperedChain := srv.VerifyTraceChain()
	if tamperedChain.Valid || tamperedChain.BrokenAtTraceID != r2.TraceID {
		t.Fatalf("expected VerifyTraceChain to catch request tampering at %s, got %+v", r2.TraceID, tamperedChain)
	}
	tamperedSingle, _ := srv.VerifyTraceIntegrity(r2.TraceID)
	if tamperedSingle.Valid || tamperedSingle.RequestDigestValid {
		t.Fatalf("expected VerifyTraceIntegrity to flag request_digest_valid=false, got %+v", tamperedSingle)
	}

	// Restore RequestPayload, tamper with PrevTraceHash -> broken chain link detected
	srv.mu.Lock()
	srv.traces[1].RequestPayload = origReq
	origPrev := srv.traces[1].PrevTraceHash
	srv.traces[1].PrevTraceHash = "0000000000000000000000000000000000000000000000000000000000000000"
	srv.mu.Unlock()

	brokenChain := srv.VerifyTraceChain()
	if brokenChain.Valid || brokenChain.BrokenAtTraceID != r2.TraceID {
		t.Fatalf("expected broken chain at %s, got %+v", r2.TraceID, brokenChain)
	}

	// Restore and verify ClearTraces resets genesis cleanly
	srv.mu.Lock()
	srv.traces[1].PrevTraceHash = origPrev
	srv.mu.Unlock()
	if cleared := srv.ClearTraces(); cleared != 3 {
		t.Fatalf("expected ClearTraces()=3, got %d", cleared)
	}
	srv.HandleJSONRPC(context.Background(), JSONRPCRequest{JSONRPC: "2.0", ID: 4, Method: "ping"}, "s2", "bob")
	if v := srv.VerifyTraceChain(); !v.Valid || v.TotalTraces != 1 {
		t.Fatalf("expected valid trace chain after ClearTraces, got %+v", v)
	}
}

func TestMCPTraceRingBufferEvictionAndSQLiteMigration(t *testing.T) {
	// 1. Ring buffer eviction maintains valid chain verification
	cfg := core.DefaultConfig()
	cfg.MCP.RetainTraces = true
	cfg.MCP.MaxTraces = 2
	auditLogger, _ := audit.NewAuditLogger(core.AuditConfig{Enabled: true, MaxMemoryLog: 50}, nil, nil)
	defer auditLogger.Close()

	srv, err := NewServer(cfg.MCP, cfg, nil, nil, nil, auditLogger, nil, nil)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer srv.Close()

	for i := 0; i < 4; i++ {
		srv.HandleJSONRPC(context.Background(), JSONRPCRequest{JSONRPC: "2.0", ID: i, Method: "ping"}, "s", "alice")
	}
	ver := srv.VerifyTraceChain()
	if !ver.Valid || ver.TotalTraces != 2 {
		t.Fatalf("expected valid trace chain after ring buffer eviction, got %+v", ver)
	}

	// 2. Existing legacy SQLite table upgrades idempotently without data loss
	dbPath := filepath.Join(t.TempDir(), "legacy_traces.db")
	db, err := database.NewDB(dbPath)
	if err != nil {
		t.Fatalf("database.NewDB: %v", err)
	}
	defer db.Close()
	if err := db.Init(); err != nil {
		t.Fatalf("db.Init: %v", err)
	}

	if !db.IsInMemory() && db.DB != nil {
		legacyDDL := `
		CREATE TABLE IF NOT EXISTS mcp_traces (
			trace_id TEXT NOT NULL PRIMARY KEY,
			session_id TEXT,
			timestamp DATETIME NOT NULL,
			method TEXT NOT NULL,
			tool_name TEXT,
			actor TEXT NOT NULL,
			status TEXT NOT NULL,
			is_error INTEGER NOT NULL,
			duration_ms INTEGER NOT NULL,
			request_json TEXT,
			response_json TEXT,
			audit_event_id TEXT
		);`
		if _, err := db.Exec(legacyDDL); err != nil {
			t.Fatalf("create legacy table: %v", err)
		}
		if _, err := db.Exec(`INSERT INTO mcp_traces(trace_id, session_id, timestamp, method, tool_name, actor, status, is_error, duration_ms) VALUES ('mcp_tr_legacy', 's0', CURRENT_TIMESTAMP, 'ping', '', 'legacy', 'ok', 0, 1)`); err != nil {
			t.Fatalf("insert legacy row: %v", err)
		}
	}

	sqlSrv, err := NewServer(cfg.MCP, cfg, db, nil, nil, auditLogger, nil, nil)
	if err != nil {
		t.Fatalf("NewServer on legacy DB failed: %v", err)
	}
	defer sqlSrv.Close()

	resp := sqlSrv.HandleJSONRPC(context.Background(), JSONRPCRequest{JSONRPC: "2.0", ID: 10, Method: "ping"}, "s-mig", "alice")
	if !db.IsInMemory() && db.DB != nil {
		var count int
		if err := db.QueryRow("SELECT COUNT(*) FROM mcp_traces").Scan(&count); err != nil || count != 2 {
			t.Fatalf("expected 2 rows (1 legacy + 1 new) after migration, got count=%d err=%v", count, err)
		}
		var traceHash string
		if err := db.QueryRow("SELECT trace_hash FROM mcp_traces WHERE trace_id = ?", resp.TraceID).Scan(&traceHash); err != nil || len(traceHash) != 64 {
			t.Fatalf("expected persisted 64-hex trace_hash for new trace, got %q err=%v", traceHash, err)
		}
	}
}
