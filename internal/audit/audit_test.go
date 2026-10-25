package audit

import (
	"path/filepath"
	"testing"

	"go-admin-tool/internal/core"
)

func TestAuditLoggerHashChainAndQuery(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := core.AuditConfig{
		Enabled:      true,
		FilePath:     filepath.Join(tmpDir, "audit.jsonl"),
		MaxMemoryLog: 50,
	}

	al, err := NewAuditLogger(cfg, nil, nil)
	if err != nil {
		t.Fatalf("NewAuditLogger failed: %v", err)
	}

	ev1, err := al.Record(AuditEvent{
		TraceID:   "trace-001",
		Category:  "auth",
		Action:    "user.login",
		ActorType: "user",
		ActorID:   "admin",
		Status:    "ok",
		Summary:   "Admin logged in",
	})
	if err != nil {
		t.Fatalf("Record ev1 failed: %v", err)
	}
	if ev1.PrevHash != GenesisHash {
		t.Errorf("expected first event PrevHash=%s, got %s", GenesisHash, ev1.PrevHash)
	}
	if ev1.EntryHash == "" {
		t.Errorf("expected non-empty EntryHash")
	}

	ev2, err := al.Record(AuditEvent{
		TraceID:   "trace-002",
		Category:  "command",
		Action:    "list-processes",
		ActorType: "service_account",
		ActorID:   "svc-prometheus",
		Status:    "ok",
		Summary:   "Executed list-processes",
	})
	if err != nil {
		t.Fatalf("Record ev2 failed: %v", err)
	}
	if ev2.PrevHash != ev1.EntryHash {
		t.Errorf("expected ev2.PrevHash (%s) == ev1.EntryHash (%s)", ev2.PrevHash, ev1.EntryHash)
	}

	verify := al.VerifyChain()
	if !verify.Valid || verify.TotalEvents != 2 {
		t.Errorf("expected valid chain with 2 events, got %+v", verify)
	}

	// Query by category
	cmdEvents := al.Query(AuditFilter{Category: "command"})
	if len(cmdEvents) != 1 || cmdEvents[0].Action != "list-processes" {
		t.Errorf("unexpected query result for category=command: %+v", cmdEvents)
	}

	// Query by trace_id
	traceEvents := al.Query(AuditFilter{TraceID: "trace-001"})
	if len(traceEvents) != 1 || traceEvents[0].ActorID != "admin" {
		t.Errorf("unexpected query result for trace_id=trace-001: %+v", traceEvents)
	}

	// Tamper detection test: mutate an event in memory and verify VerifyChain detects it
	al.mu.Lock()
	al.events[0].Summary = "Tampered summary"
	al.mu.Unlock()

	tamperedVerify := al.VerifyChain()
	if tamperedVerify.Valid {
		t.Errorf("expected VerifyChain to detect tampered event, got Valid=true")
	}
	if tamperedVerify.BrokenAtID != 1 {
		t.Errorf("expected BrokenAtID=1, got %d", tamperedVerify.BrokenAtID)
	}
}
