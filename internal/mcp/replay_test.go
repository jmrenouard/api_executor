package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"go-admin-tool/internal/audit"
	"go-admin-tool/internal/core"
	"go-admin-tool/internal/plugins"
)

type counterPlugin struct {
	calls atomic.Int64
}

func (p *counterPlugin) ID() string          { return "replay-counter" }
func (p *counterPlugin) Name() string        { return "Replay Counter" }
func (p *counterPlugin) Version() string     { return "1.0.0" }
func (p *counterPlugin) Kind() plugins.PluginKind { return plugins.KindAdvanced }
func (p *counterPlugin) Type() string             { return "native" }
func (p *counterPlugin) Category() string    { return "SRE" }
func (p *counterPlugin) Description() string { return "Test plugin returning incrementing count" }
func (p *counterPlugin) Actions() []plugins.PluginAction {
	return []plugins.PluginAction{{Name: "next", Description: "Increment counter"}}
}
func (p *counterPlugin) Execute(_ context.Context, action string, _ map[string]any, _ time.Duration) (plugins.PluginResult, error) {
	if action != "next" {
		return plugins.PluginResult{Status: "error"}, plugins.ErrActionNotFound
	}
	n := p.calls.Add(1)
	return plugins.PluginResult{
		PluginID: p.ID(),
		Action:   action,
		Status:   "ok",
		Output:   fmt.Sprintf("count=%d", n),
		Data:     map[string]any{"count": n},
	}, nil
}

func echoCmdDef(name string) core.CommandDefinition {
	if runtime.GOOS == "windows" {
		return core.CommandDefinition{Name: name, Command: "cmd", Args: []string{"/C", "echo", "deterministic-ok"}, Timeout: "5s"}
	}
	return core.CommandDefinition{Name: name, Command: "echo", Args: []string{"deterministic-ok"}, Timeout: "5s"}
}

func TestMCPTraceReplay_DryRunLiveDeterminismAndTamperFailClosed(t *testing.T) {
	cfg := core.DefaultConfig()
	cfg.MCP.RetainTraces = true
	cfg.MCP.MaxTraces = 50
	cfg.Executor.Commands = []core.CommandDefinition{echoCmdDef("echo-det")}

	auditLogger, err := audit.NewAuditLogger(core.AuditConfig{Enabled: true, MaxMemoryLog: 200}, nil, nil)
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	defer auditLogger.Close()

	counter := &counterPlugin{}
	reg := plugins.NewEmptyRegistry()
	_ = reg.Register(counter)

	srv, err := NewServer(cfg.MCP, cfg, nil, nil, reg, auditLogger, nil, nil)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer srv.Close()

	// 1. Record deterministic execute_command trace
	cmdParams, _ := json.Marshal(map[string]any{"name": "execute_command", "arguments": map[string]any{"name": "echo-det"}})
	origResp := srv.HandleJSONRPC(context.Background(), JSONRPCRequest{JSONRPC: "2.0", ID: 1, Method: "tools/call", Params: cmdParams}, "s1", "alice")
	origTrace, err := srv.GetTrace(origResp.TraceID)
	if err != nil {
		t.Fatalf("GetTrace: %v", err)
	}

	// 2. Default dry_run verifies integrity without creating a new trace
	beforeCount := len(srv.ListTraces(TraceFilter{Limit: 100}))
	dryReport, err := srv.ReplayTrace(context.Background(), origTrace.TraceID, ReplayOptions{Actor: "admin"}, nil)
	if err != nil {
		t.Fatalf("dry_run ReplayTrace failed: %v", err)
	}
	if dryReport.Mode != ReplayModeDryRun || !dryReport.IntegrityValid || !dryReport.AuditChainValid || !dryReport.PolicyEligible || dryReport.ReplayTraceID != "" {
		t.Fatalf("unexpected dry_run report: %+v", dryReport)
	}
	if afterCount := len(srv.ListTraces(TraceFilter{Limit: 100})); afterCount != beforeCount {
		t.Fatalf("dry_run must not append new traces (before=%d, after=%d)", beforeCount, afterCount)
	}

	// 3. Live replay of deterministic command yields deterministic_match=true and linked child trace
	liveReport, err := srv.ReplayTrace(context.Background(), origTrace.TraceID, ReplayOptions{Mode: ReplayModeLive, Actor: "admin"}, nil)
	if err != nil {
		t.Fatalf("live ReplayTrace failed: %v", err)
	}
	if !liveReport.IntegrityValid || !liveReport.AuditChainValid || !liveReport.StatusMatch || !liveReport.DeterministicMatch {
		t.Fatalf("expected deterministic live replay match, got %+v", liveReport)
	}
	if liveReport.ReplayTraceID == "" || liveReport.ReplayTraceID == origTrace.TraceID {
		t.Fatalf("expected distinct replay_trace_id, got %q", liveReport.ReplayTraceID)
	}
	childTrace, err := srv.GetTrace(liveReport.ReplayTraceID)
	if err != nil {
		t.Fatalf("GetTrace(replay): %v", err)
	}
	if childTrace.ParentTraceID != origTrace.TraceID {
		t.Fatalf("expected parent_trace_id=%q, got %q", origTrace.TraceID, childTrace.ParentTraceID)
	}
	// Original trace remains completely unchanged
	origAfter, _ := srv.GetTrace(origTrace.TraceID)
	if origAfter.TraceHash != origTrace.TraceHash || origAfter.ParentTraceID != "" {
		t.Fatalf("original trace was unexpectedly mutated")
	}

	// 4. Non-deterministic plugin output reports deterministic_match=false with divergence
	plugParams, _ := json.Marshal(map[string]any{"name": "execute_plugin", "arguments": map[string]any{"plugin_id": "replay-counter", "action": "next"}})
	plugResp := srv.HandleJSONRPC(context.Background(), JSONRPCRequest{JSONRPC: "2.0", ID: 2, Method: "tools/call", Params: plugParams}, "s1", "alice")
	divReport, err := srv.ReplayTrace(context.Background(), plugResp.TraceID, ReplayOptions{Mode: ReplayModeLive, Actor: "admin"}, nil)
	if err != nil {
		t.Fatalf("live ReplayTrace (counter) failed: %v", err)
	}
	if !divReport.StatusMatch || divReport.DeterministicMatch || len(divReport.Divergences) == 0 {
		t.Fatalf("expected status_match=true and deterministic_match=false with divergence, got %+v", divReport)
	}

	// 5. HITL ApprovalGate is still enforced during live replay
	gateCalled := false
	srv.SetApprovalGate(func(_ context.Context, req ApprovalGateRequest) (ApprovalGateDecision, error) {
		gateCalled = true
		if req.ApprovalID == "" {
			return ApprovalGateDecision{Pending: true, ApprovalID: "apr_replay_1", ExpiresAt: time.Now().UTC().Add(5 * time.Minute)}, nil
		}
		return ApprovalGateDecision{Allowed: true, ApprovalID: req.ApprovalID}, nil
	})
	gatedReport, err := srv.ReplayTrace(context.Background(), origTrace.TraceID, ReplayOptions{Mode: ReplayModeLive, Actor: "admin"}, nil)
	if err != nil {
		t.Fatalf("gated live replay returned error: %v", err)
	}
	if !gateCalled || gatedReport.ReplayedStatus != "pending_approval" {
		t.Fatalf("expected ApprovalGate to pause live replay, gateCalled=%v report=%+v", gateCalled, gatedReport)
	}
	srv.SetApprovalGate(nil)

	// 6. Both chains remain valid before tampering
	if v := srv.VerifyTraceChain(); !v.Valid {
		t.Fatalf("expected valid trace chain after replays, got %+v", v)
	}
	if v := auditLogger.VerifyChain(); !v.Valid {
		t.Fatalf("expected valid audit chain after replays, got %+v", v)
	}

	// 7. Tampered retained trace fails closed BEFORE any live execution
	callsBefore := counter.calls.Load()
	srv.mu.Lock()
	for i := range srv.traces {
		if srv.traces[i].TraceID == plugResp.TraceID {
			srv.traces[i].RequestPayload = map[string]any{"tampered": true}
		}
	}
	srv.mu.Unlock()

	tamperReport, tamperErr := srv.ReplayTrace(context.Background(), plugResp.TraceID, ReplayOptions{Mode: ReplayModeLive, Actor: "admin"}, nil)
	if !errors.Is(tamperErr, ErrIntegrityFailed) {
		t.Fatalf("expected ErrIntegrityFailed on tampered trace, got %v", tamperErr)
	}
	if tamperReport.IntegrityValid || tamperReport.ReplayTraceID != "" || len(tamperReport.Divergences) == 0 {
		t.Fatalf("expected fail-closed tamper report with divergences, got %+v", tamperReport)
	}
	if counter.calls.Load() != callsBefore {
		t.Fatalf("tampered trace must never execute live subprocess/plugin")
	}
}
