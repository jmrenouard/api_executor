package audit

import (
	"path/filepath"
	"testing"
	"time"

	"go-admin-tool/internal/core"
)

func TestAuditLoggerHashChainAndQuery(t *testing.T) {
	// 1. Verify nil receiver safety
	var nilAL *AuditLogger
	if _, err := nilAL.Record(AuditEvent{Action: "noop"}); err != nil {
		t.Errorf("expected nil error on nil AuditLogger.Record, got %v", err)
	}
	if q := nilAL.Query(AuditFilter{}); q != nil {
		t.Errorf("expected nil Query result on nil AuditLogger, got %+v", q)
	}
	if v := nilAL.VerifyChain(); !v.Valid || v.TotalEvents != 0 || v.LastHash != GenesisHash {
		t.Errorf("unexpected VerifyChain on nil AuditLogger: %+v", v)
	}
	if c := nilAL.Count(); c != 0 {
		t.Errorf("expected Count()=0 on nil AuditLogger, got %d", c)
	}

	tmpDir := t.TempDir()
	logger, err := core.NewLogger(core.LoggingConfig{Level: "info"})
	if err != nil {
		t.Fatalf("NewLogger failed: %v", err)
	}
	defer logger.Close()

	cfg := core.AuditConfig{
		Enabled:      true,
		FilePath:     filepath.Join(tmpDir, "nested", "audit.jsonl"),
		MaxMemoryLog: 0, // should default to 1000
	}

	al, err := NewAuditLogger(cfg, nil, logger)
	if err != nil {
		t.Fatalf("NewAuditLogger failed: %v", err)
	}

	// Empty chain verification
	emptyVerify := al.VerifyChain()
	if !emptyVerify.Valid || emptyVerify.TotalEvents != 0 {
		t.Errorf("expected empty chain to be valid with 0 events, got %+v", emptyVerify)
	}

	// Record event with explicit Timestamp and defaults for empty Category/ActorType/ActorID/Status
	fixedTime := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	ev1, err := al.Record(AuditEvent{
		Timestamp: fixedTime,
		TraceID:   "trace-001",
		Action:    "user.login",
		Summary:   "Default fields populated",
	})
	if err != nil {
		t.Fatalf("Record ev1 failed: %v", err)
	}
	if ev1.PrevHash != GenesisHash {
		t.Errorf("expected first event PrevHash=%s, got %s", GenesisHash, ev1.PrevHash)
	}
	if ev1.Category != "system" || ev1.ActorType != "anonymous" || ev1.ActorID != "anonymous" || ev1.Status != "ok" {
		t.Errorf("expected default category/actor/status fields, got %+v", ev1)
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
		Status:    "failure",
		Summary:   "Executed list-processes",
	})
	if err != nil {
		t.Fatalf("Record ev2 failed: %v", err)
	}
	if ev2.PrevHash != ev1.EntryHash {
		t.Errorf("expected ev2.PrevHash (%s) == ev1.EntryHash (%s)", ev2.PrevHash, ev1.EntryHash)
	}

	if al.Count() != 2 {
		t.Errorf("expected Count()=2, got %d", al.Count())
	}

	verify := al.VerifyChain()
	if !verify.Valid || verify.TotalEvents != 2 {
		t.Errorf("expected valid chain with 2 events, got %+v", verify)
	}

	// Query by Category, Action, ActorID, Status, TraceID
	cmdEvents := al.Query(AuditFilter{Category: "command", Action: "list", ActorID: "svc-prometheus", Status: "failure", Limit: 10})
	if len(cmdEvents) != 1 || cmdEvents[0].Action != "list-processes" {
		t.Errorf("unexpected query result for combined filter: %+v", cmdEvents)
	}

	// Query with non-matching filters
	if len(al.Query(AuditFilter{Action: "non-existent"})) != 0 {
		t.Errorf("expected 0 events for non-matching action")
	}
	if len(al.Query(AuditFilter{ActorID: "nobody"})) != 0 {
		t.Errorf("expected 0 events for non-matching actor_id")
	}
	if len(al.Query(AuditFilter{Status: "denied"})) != 0 {
		t.Errorf("expected 0 events for non-matching status")
	}

	// Query by trace_id
	traceEvents := al.Query(AuditFilter{TraceID: "trace-001"})
	if len(traceEvents) != 1 || traceEvents[0].ActorID != "anonymous" {
		t.Errorf("unexpected query result for trace_id=trace-001: %+v", traceEvents)
	}

	// Tamper detection 1: mutate an event summary in memory
	al.mu.Lock()
	origSummary := al.events[0].Summary
	al.events[0].Summary = "Tampered summary"
	al.mu.Unlock()

	tamperedVerify := al.VerifyChain()
	if tamperedVerify.Valid || tamperedVerify.BrokenAtID != 1 {
		t.Errorf("expected VerifyChain to detect tampered event at ID 1, got %+v", tamperedVerify)
	}

	// Tamper detection 2: corrupt genesis PrevHash while recomputing EntryHash
	al.mu.Lock()
	al.events[0].Summary = origSummary
	al.events[0].PrevHash = "FORGED_GENESIS"
	al.events[0].EntryHash = computeEntryHash(al.events[0])
	al.mu.Unlock()

	genesisTamper := al.VerifyChain()
	if genesisTamper.Valid || genesisTamper.BrokenAtID != 1 {
		t.Errorf("expected VerifyChain to detect forged genesis prev_hash at ID 1, got %+v", genesisTamper)
	}

	// Tamper detection 3: restore event 1, break chain link on event 2 while recomputing event 2's EntryHash
	al.mu.Lock()
	al.events[0].PrevHash = GenesisHash
	al.events[0].EntryHash = computeEntryHash(al.events[0])
	al.events[1].PrevHash = "BROKEN_LINK_HASH"
	al.events[1].EntryHash = computeEntryHash(al.events[1])
	al.mu.Unlock()

	linkTamper := al.VerifyChain()
	if linkTamper.Valid || linkTamper.BrokenAtID != 2 {
		t.Errorf("expected VerifyChain to detect broken chain link at ID 2, got %+v", linkTamper)
	}

	// Sliding window eviction test
	smallAL, err := NewAuditLogger(core.AuditConfig{Enabled: true, MaxMemoryLog: 2}, nil, nil)
	if err != nil {
		t.Fatalf("NewAuditLogger small failed: %v", err)
	}
	_, _ = smallAL.Record(AuditEvent{Action: "a1"})
	_, _ = smallAL.Record(AuditEvent{Action: "a2"})
	_, _ = smallAL.Record(AuditEvent{Action: "a3"})
	if smallAL.Count() != 2 {
		t.Errorf("expected sliding window of 2 events, got %d", smallAL.Count())
	}
	if v := smallAL.VerifyChain(); !v.Valid {
		t.Errorf("expected sliding window chain to remain valid, got %+v", v)
	}
}
