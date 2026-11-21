package approval

import (
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go-admin-tool/internal/audit"
	"go-admin-tool/internal/core"
	"go-admin-tool/internal/database"
)

func TestApprovalPolicyAndCanonicalDigest(t *testing.T) {
	// 1. Canonical SHA-256 digest determinism across key orders and nil/empty params
	d1, err := ComputePayloadSHA256(Target{
		Channel:    ChannelPlugin,
		PluginID:   "db-admin",
		Action:     "vacuum",
		Parameters: map[string]any{"b": 2, "a": "hello"},
	})
	if err != nil {
		t.Fatalf("ComputePayloadSHA256 failed: %v", err)
	}
	d2, err := ComputePayloadSHA256(Target{
		Channel:    " PLUGIN ",
		PluginID:   "db-admin",
		Action:     "vacuum",
		Parameters: map[string]any{"a": "hello", "b": 2},
	})
	if err != nil {
		t.Fatalf("ComputePayloadSHA256 failed: %v", err)
	}
	if !ConstantTimeDigestEqual(d1, d2) {
		t.Fatalf("expected identical canonical digests, got %s vs %s", d1, d2)
	}
	dEmpty1, _ := ComputePayloadSHA256(Target{Channel: ChannelCommand, Action: "restart-db"})
	dEmpty2, _ := ComputePayloadSHA256(Target{Channel: ChannelCommand, Action: "restart-db", Parameters: map[string]any{}})
	if !ConstantTimeDigestEqual(dEmpty1, dEmpty2) {
		t.Fatalf("expected nil and empty parameters to yield identical digests")
	}
	if ConstantTimeDigestEqual(d1, "short") {
		t.Fatalf("expected short digest comparison to fail")
	}

	// 2. Disabled policy always returns false
	disabled := NewPolicy(core.DefaultApprovalConfig())
	if disabled.Enabled() {
		t.Fatalf("expected default approval policy to be disabled")
	}
	if disabled.RequiresApproval(Target{Channel: ChannelCommand, Action: "drop-db"}, true) {
		t.Fatalf("expected disabled policy to return false even when commandFlag=true")
	}

	// 3. Enabled policy matches commandFlag, wildcards, plugins, jobs, and MCP tools
	pol := NewPolicy(core.ApprovalConfig{
		Enabled:          true,
		CriticalCommands: []string{"restart-*", "drop-table"},
		CriticalPlugins:  []string{"plugin:db-admin:*", "k8s-drain"},
		CriticalMCPTools: []string{"dangerous_tool"},
	})

	cases := []struct {
		name        string
		target      Target
		commandFlag bool
		want        bool
	}{
		{"command_flag", Target{Channel: ChannelCommand, Action: "safe-cmd"}, true, true},
		{"command_prefix", Target{Channel: ChannelCommand, Action: "restart-postgres"}, false, true},
		{"command_safe", Target{Channel: ChannelCommand, Action: "disk-usage"}, false, false},
		{"plugin_wildcard", Target{Channel: ChannelPlugin, PluginID: "db-admin", Action: "failover"}, false, true},
		{"plugin_id_match", Target{Channel: ChannelPlugin, PluginID: "k8s-drain", Action: "node"}, false, true},
		{"plugin_safe", Target{Channel: ChannelPlugin, PluginID: "sys-diagnostics", Action: "runtime_stats"}, false, false},
		{"job_command", Target{Channel: ChannelJob, Action: "drop-table"}, false, true},
		{"job_plugin", Target{Channel: ChannelJob, PluginID: "db-admin", Action: "promote"}, false, true},
		{"mcp_tool_direct", Target{Channel: ChannelMCP, ToolName: "dangerous_tool"}, false, true},
		{"mcp_execute_command", Target{Channel: ChannelMCP, ToolName: "execute_command", Action: "restart-mysql"}, false, true},
		{"mcp_execute_plugin", Target{Channel: ChannelMCP, ToolName: "execute_plugin", PluginID: "db-admin", Action: "reset"}, false, true},
		{"mcp_safe_tool", Target{Channel: ChannelMCP, ToolName: "list_commands"}, false, false},
	}

	for _, tc := range cases {
		if got := pol.RequiresApproval(tc.target, tc.commandFlag); got != tc.want {
			t.Errorf("%s: RequiresApproval() = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func runStoreLifecycleSuite(t *testing.T, db *database.DB) {
	t.Helper()
	auditLogger, err := audit.NewAuditLogger(core.AuditConfig{Enabled: true, MaxMemoryLog: 200}, db, nil)
	if err != nil {
		t.Fatalf("failed to create audit logger: %v", err)
	}
	defer auditLogger.Close()

	cfg := core.ApprovalConfig{
		Enabled:                 true,
		DefaultTTL:              "10m",
		MaxPending:              2,
		RequireDistinctApprover: true,
		CriticalCommands:        []string{"restart-*"},
	}

	store, err := NewStore(cfg, db, auditLogger)
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}

	now := time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)
	store.SetNowFunc(func() time.Time { return now })

	target := Target{
		Channel:    ChannelCommand,
		Action:     "restart-postgres",
		Parameters: map[string]any{"timeout": "15s"},
	}

	// 1. Create pending approval
	req1, err := store.Create(CreateParams{
		Target:        target,
		RequesterID:   "alice",
		RequesterType: "user_token",
		SourceIP:      "127.0.0.1",
		Reason:        "planned maintenance",
	})
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	if req1.Status != StatusPending || len(req1.PayloadSHA256) != 64 {
		t.Fatalf("unexpected created request: %+v", req1)
	}

	// 2. Self-approval rejected when RequireDistinctApprover=true
	if _, err := store.Approve(req1.ID, "alice", "user_token", "127.0.0.1", "self"); !errors.Is(err, ErrSelfApprovalForbidden) {
		t.Fatalf("expected ErrSelfApprovalForbidden, got %v", err)
	}

	// 3. Cannot consume while still pending
	if _, err := store.Consume(req1.ID, req1.PayloadSHA256, "alice", "user_token", "127.0.0.1"); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("expected ErrInvalidTransition on pending consume, got %v", err)
	}

	// 4. Distinct admin approves
	approved, err := store.Approve(req1.ID, "bob-admin", "user_token", "127.0.0.1", "verified change ticket")
	if err != nil {
		t.Fatalf("Approve failed: %v", err)
	}
	if approved.Status != StatusApproved || approved.ApproverID != "bob-admin" || approved.DecidedAt == nil {
		t.Fatalf("unexpected approved request: %+v", approved)
	}

	// 5. Tampered payload fails closed
	badDigest, _ := ComputePayloadSHA256(Target{Channel: ChannelCommand, Action: "restart-postgres", Parameters: map[string]any{"timeout": "99s"}})
	if _, err := store.Consume(req1.ID, badDigest, "alice", "user_token", "127.0.0.1"); !errors.Is(err, ErrPayloadMismatch) {
		t.Fatalf("expected ErrPayloadMismatch, got %v", err)
	}

	// 6. Exact payload consumes atomically once, second consume fails with ErrAlreadyConsumed
	consumed, err := store.Consume(req1.ID, req1.PayloadSHA256, "alice", "user_token", "127.0.0.1")
	if err != nil {
		t.Fatalf("Consume failed: %v", err)
	}
	if consumed.Status != StatusConsumed || consumed.ConsumedAt == nil {
		t.Fatalf("unexpected consumed request: %+v", consumed)
	}
	if _, err := store.Consume(req1.ID, req1.PayloadSHA256, "alice", "user_token", "127.0.0.1"); !errors.Is(err, ErrAlreadyConsumed) {
		t.Fatalf("expected ErrAlreadyConsumed on replay, got %v", err)
	}

	// 7. MaxPending cap and TTL expiration pruning
	req2, err := store.Create(CreateParams{Target: target, RequesterID: "alice", RequesterType: "user_token", TTL: 5 * time.Minute})
	if err != nil {
		t.Fatalf("Create req2 failed: %v", err)
	}
	req3, err := store.Create(CreateParams{Target: target, RequesterID: "charlie", RequesterType: "user_token", TTL: 5 * time.Minute})
	if err != nil {
		t.Fatalf("Create req3 failed: %v", err)
	}
	if _, err := store.Create(CreateParams{Target: target, RequesterID: "dave", RequesterType: "user_token"}); !errors.Is(err, ErrMaxPendingReached) {
		t.Fatalf("expected ErrMaxPendingReached, got %v", err)
	}

	// Reject req3
	if _, err := store.Reject(req3.ID, "bob-admin", "user_token", "127.0.0.1", "denied"); err != nil {
		t.Fatalf("Reject req3 failed: %v", err)
	}

	// Advance clock past TTL to expire req2
	now = now.Add(6 * time.Minute)
	got2, err := store.Get(req2.ID)
	if err != nil {
		t.Fatalf("Get req2 failed: %v", err)
	}
	if got2.Status != StatusExpired {
		t.Fatalf("expected req2 to be expired, got %s", got2.Status)
	}
	if _, err := store.Approve(req2.ID, "bob-admin", "user_token", "127.0.0.1", "late"); !errors.Is(err, ErrExpired) {
		t.Fatalf("expected ErrExpired approving stale request, got %v", err)
	}

	// List filtering
	items, total := store.List(Filter{Status: StatusRejected})
	if total != 1 || len(items) != 1 || items[0].ID != req3.ID {
		t.Fatalf("expected 1 rejected approval (%s), got total=%d len=%d", req3.ID, total, len(items))
	}

	// Verify SQLite persistence across reload when not in-memory
	if !store.IsInMemory() {
		reloaded, err := NewStore(cfg, db, auditLogger)
		if err != nil {
			t.Fatalf("reloaded NewStore failed: %v", err)
		}
		reloadedReq, err := reloaded.Get(req1.ID)
		if err != nil || reloadedReq.Status != StatusConsumed {
			t.Fatalf("expected reloaded req1 to be consumed, got %+v err=%v", reloadedReq, err)
		}
	}

	// Verify SHA-256 audit chain integrity
	ver := auditLogger.VerifyChain()
	if !ver.Valid || ver.TotalEvents < 5 {
		t.Fatalf("expected valid audit chain with >= 5 events, got %+v", ver)
	}
}

func TestApprovalStoreLifecycle_InMemoryAndSQLite(t *testing.T) {
	t.Run("pure_go_in_memory", func(t *testing.T) {
		runStoreLifecycleSuite(t, nil)
	})

	t.Run("database_backed", func(t *testing.T) {
		dbPath := filepath.Join(t.TempDir(), "approvals.db")
		db, err := database.NewDB(dbPath)
		if err != nil {
			t.Fatalf("database.NewDB failed: %v", err)
		}
		defer db.Close()
		if err := db.Init(); err != nil {
			t.Fatalf("db.Init failed: %v", err)
		}
		runStoreLifecycleSuite(t, db)
	})
}

func TestApprovalStoreConcurrentSingleUseConsume(t *testing.T) {
	store, err := NewStore(core.ApprovalConfig{
		Enabled:                 true,
		DefaultTTL:              "5m",
		MaxPending:              100,
		RequireDistinctApprover: true,
	}, nil, nil)
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}

	req, err := store.Create(CreateParams{
		Target:        Target{Channel: ChannelCommand, Action: "restart-db"},
		RequesterID:   "operator1",
		RequesterType: "user_token",
	})
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	if _, err := store.Approve(req.ID, "admin1", "user_token", "127.0.0.1", "ok"); err != nil {
		t.Fatalf("Approve failed: %v", err)
	}

	const workers = 16
	var succeeded atomic.Int32
	var alreadyConsumed atomic.Int32
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			_, cErr := store.Consume(req.ID, req.PayloadSHA256, "operator1", "user_token", "127.0.0.1")
			if cErr == nil {
				succeeded.Add(1)
			} else if errors.Is(cErr, ErrAlreadyConsumed) {
				alreadyConsumed.Add(1)
			}
		}()
	}
	wg.Wait()

	if succeeded.Load() != 1 || alreadyConsumed.Load() != workers-1 {
		t.Fatalf("expected exactly 1 consume and %d ErrAlreadyConsumed, got %d and %d",
			workers-1, succeeded.Load(), alreadyConsumed.Load())
	}
}
