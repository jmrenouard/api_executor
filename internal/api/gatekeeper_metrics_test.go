package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go-admin-tool/internal/core"
)

func TestGatekeeperMetrics_ZeroAllocAndBoundedLabels(t *testing.T) {
	ResetGatekeeperMetrics()

	// Warm up metric label sets
	RecordGatekeeperEvaluation("http", "mcp", "allow", 2*time.Millisecond)
	RecordGatekeeperEvaluation("cli", "command", "deny", 3*time.Millisecond)
	RecordGatekeeperEvaluation("http", "plugin", "x_abstain", 4*time.Millisecond)

	allocs := testing.AllocsPerRun(100, func() {
		RecordGatekeeperEvaluation("http", "mcp", "allow", 2*time.Millisecond)
		RecordGatekeeperEvaluation("HTTP", "COMMAND", "block", 3*time.Millisecond)
		RecordGatekeeperEvaluation("unknown-mode", "arbitrary-channel", "escalate", time.Millisecond)
	})
	if allocs != 0 {
		t.Fatalf("expected 0 allocs/op on steady-state RecordGatekeeperEvaluation, got %.2f", allocs)
	}

	if got := GetGatekeeperDecisionCount("allow", "mcp"); got < 101 {
		t.Fatalf("expected allow/mcp count >= 101, got %v", got)
	}
	if got := GetGatekeeperDecisionCount("deny", "command"); got < 101 {
		t.Fatalf("expected deny/command count >= 101, got %v", got)
	}
	if got := GetGatekeeperDecisionCount("x_abstain", "other"); got < 100 {
		t.Fatalf("expected x_abstain/other count >= 100, got %v", got)
	}
}

func TestConfigEndpoint_SanitizedGatekeeperHeaderRedaction(t *testing.T) {
	cfg := core.DefaultConfig()
	cfg.Gatekeeper = core.GatekeeperConfig{
		Enabled:       true,
		Mode:          "http",
		Endpoint:      "http://127.0.0.1:8000/v1/guard/evaluate",
		Timeout:       "5ms",
		MinConfidence: 0.80,
		FailMode:      "escalate_hitl",
		Headers: map[string]string{
			"Authorization": "Bearer super-secret-microllm-key",
			"X-API-Key":     "top-secret",
		},
	}

	env := &APIEnv{Config: cfg}
	router := NewRouter(env)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/config", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/config = %d, want 200", rr.Code)
	}

	var view core.SanitizedConfigView
	if err := json.Unmarshal(rr.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode SanitizedConfigView: %v", err)
	}
	if !view.Gatekeeper.Enabled || view.Gatekeeper.Mode != "http" || view.Gatekeeper.Timeout != "5ms" {
		t.Fatalf("unexpected sanitized gatekeeper config: %+v", view.Gatekeeper)
	}
	for k, v := range view.Gatekeeper.Headers {
		if v != "[REDACTED]" {
			t.Errorf("expected Gatekeeper.Headers[%q] to be '[REDACTED]', got %q", k, v)
		}
	}
	if len(view.Gatekeeper.Headers) != 2 {
		t.Fatalf("expected 2 redacted headers, got %d", len(view.Gatekeeper.Headers))
	}
}
