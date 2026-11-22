package gatekeeper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"go-admin-tool/internal/core"
)

// TestHelperProcess_MicroLLMCLI acts as a cross-platform mock microllm-guard CLI binary
// invoked via os.Args[0] with GO_WANT_GATEKEEPER_HELPER=1 (zero shell, works on Windows & Linux).
func TestHelperProcess_MicroLLMCLI(t *testing.T) {
	if os.Getenv("GO_WANT_GATEKEEPER_HELPER") != "1" {
		return
	}
	mode := os.Getenv("GATEKEEPER_HELPER_MODE")
	rawIn, _ := io.ReadAll(os.Stdin)
	var req map[string]any
	if err := json.Unmarshal(rawIn, &req); err != nil {
		fmt.Fprintln(os.Stdout, `{"schema_version":"microllm.guard.v1","error":"invalid stdin json"}`)
		os.Exit(1)
	}
	if _, ok := req["tool_name"]; !ok {
		fmt.Fprintln(os.Stdout, `{"schema_version":"microllm.guard.v1","error":"missing tool_name"}`)
		os.Exit(1)
	}

	switch mode {
	case "allow":
		fmt.Fprintln(os.Stdout, `{"schema_version":"microllm.guard.v1","decision":"allow","confidence":0.96,"abstain":false,"reason":"safe command","risk_score":0.05}`)
		os.Exit(0)
	case "block":
		fmt.Fprintln(os.Stdout, `{"schema_version":"microllm.guard.v1","decision":"block","confidence":0.98,"abstain":false,"reason":"destructive command","risk_score":0.95,"primary_threat":"data_destruction"}`)
		os.Exit(2)
	case "escalate":
		fmt.Fprintln(os.Stdout, `{"schema_version":"microllm.guard.v1","decision":"escalate","confidence":0.55,"abstain":true,"reason":"uncertain risk","risk_score":0.48}`)
		os.Exit(3)
	case "contradict_block":
		fmt.Fprintln(os.Stdout, `{"schema_version":"microllm.guard.v1","decision":"allow","confidence":0.99,"abstain":false,"reason":"spoofed allow"}`)
		os.Exit(2)
	case "oversized":
		fmt.Fprintln(os.Stdout, strings.Repeat("a", MaxResponseBytes+2048))
		os.Exit(0)
	case "sleep":
		time.Sleep(500 * time.Millisecond)
		fmt.Fprintln(os.Stdout, `{"schema_version":"microllm.guard.v1","decision":"allow","confidence":0.99,"abstain":false,"reason":"late"}`)
		os.Exit(0)
	default:
		fmt.Fprintln(os.Stderr, "simulated cli error")
		os.Exit(1)
	}
}

func TestHTTPGatekeeper_MicroLLMContractV1AndFailClosed(t *testing.T) {
	allowedWireKeys := map[string]bool{
		"tool_name":         true,
		"command":           true,
		"arguments":         true,
		"context":           true,
		"environment":       true,
		"threshold":         true,
		"abstain_policy":    true,
		"policy_boundaries": true,
		"custom_rubrics":    true,
	}

	var mu sync.Mutex
	var handlerResp string
	var handlerStatus int
	var handlerDelay time.Duration
	var sawAuthHeader string

	setMock := func(status int, body string, delay time.Duration) {
		mu.Lock()
		handlerStatus = status
		handlerResp = body
		handlerDelay = delay
		mu.Unlock()
	}
	getAuthHeader := func() string {
		mu.Lock()
		defer mu.Unlock()
		return sawAuthHeader
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/guard/evaluate" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		mu.Lock()
		sawAuthHeader = r.Header.Get("Authorization")
		status := handlerStatus
		respBody := handlerResp
		delay := handlerDelay
		mu.Unlock()

		body, _ := io.ReadAll(r.Body)
		var decoded map[string]any
		if err := json.Unmarshal(body, &decoded); err != nil {
			http.Error(w, "bad json", http.StatusUnprocessableEntity)
			return
		}
		// Enforce MicroLLM extra="forbid" contract strictly
		for k := range decoded {
			if !allowedWireKeys[k] {
				http.Error(w, "extra forbidden field: "+k, http.StatusUnprocessableEntity)
				return
			}
		}
		if delay > 0 {
			select {
			case <-time.After(delay):
			case <-r.Context().Done():
				return
			}
		}
		if status == http.StatusFound {
			http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(respBody))
	}))
	defer ts.Close()

	cfg := core.GatekeeperConfig{
		Enabled:       true,
		Mode:          "http",
		Endpoint:      ts.URL + "/v1/guard/evaluate",
		Timeout:       "100ms",
		MinConfidence: 0.75,
		FailMode:      "escalate_hitl",
		Environment:   "production",
		Headers:       map[string]string{"Authorization": "Bearer secret-key"},
	}

	gk, err := NewFromConfig(cfg, core.DefaultSandboxConfig())
	if err != nil {
		t.Fatalf("NewFromConfig: %v", err)
	}
	defer gk.Close()

	evalReq := EvalRequest{
		Channel:   "mcp",
		ToolName:  "execute_command",
		Command:   "df -h",
		Arguments: map[string]any{"name": "disk-usage"},
		Context:   "routine check",
	}

	// 1. Allow above threshold
	setMock(http.StatusOK, `{"schema_version":"microllm.guard.v1","decision":"allow","confidence":0.95,"abstain":false,"reason":"read-only check","risk_score":0.02,"latency_ms":1.2}`, 0)
	res := gk.Evaluate(context.Background(), evalReq)
	if res.Decision != DecisionAllow || res.FailClosed || getAuthHeader() != "Bearer secret-key" {
		t.Fatalf("expected allow with forwarded auth header, got %+v auth=%q", res, getAuthHeader())
	}

	// 2. MicroLLM "block" maps cleanly to DecisionDeny
	setMock(http.StatusOK, `{"schema_version":"microllm.guard.v1","decision":"block","confidence":0.97,"abstain":false,"reason":"drop database","risk_score":0.99,"primary_threat":"sql_destructive"}`, 0)
	res = gk.Evaluate(context.Background(), evalReq)
	if res.Decision != DecisionDeny || res.PrimaryThreat != "sql_destructive" {
		t.Fatalf("expected deny for block, got %+v", res)
	}

	// 3. MicroLLM "escalate" maps to DecisionAbstain
	setMock(http.StatusOK, `{"schema_version":"microllm.guard.v1","decision":"escalate","confidence":0.62,"abstain":true,"reason":"ambiguous target","risk_score":0.52}`, 0)
	res = gk.Evaluate(context.Background(), evalReq)
	if res.Decision != DecisionAbstain || !res.Abstain {
		t.Fatalf("expected x_abstain for escalate, got %+v", res)
	}

	// 4. Low confidence (< 0.75) on "allow" fails closed to x_abstain
	setMock(http.StatusOK, `{"schema_version":"microllm.guard.v1","decision":"allow","confidence":0.60,"abstain":false,"reason":"low conf"}`, 0)
	res = gk.Evaluate(context.Background(), evalReq)
	if res.Decision != DecisionAbstain || !res.FailClosed {
		t.Fatalf("expected low confidence allow to fail closed to x_abstain, got %+v", res)
	}

	// 5. Malformed JSON, non-200, redirect (SSRF), oversized (> 64 KiB), unknown decision, timeout -> all fail closed!
	failCases := []struct {
		name   string
		status int
		body   string
		delay  time.Duration
	}{
		{"malformed_json", http.StatusOK, `{not-json`, 0},
		{"http_500", http.StatusInternalServerError, `{"error":"boom"}`, 0},
		{"http_422", http.StatusUnprocessableEntity, `{"detail":"bad"}`, 0},
		{"redirect_blocked", http.StatusFound, "", 0},
		{"oversized_payload", http.StatusOK, strings.Repeat("x", MaxResponseBytes+1024), 0},
		{"unknown_decision", http.StatusOK, `{"schema_version":"microllm.guard.v1","decision":"maybe","confidence":0.9,"abstain":false}`, 0},
		{"missing_confidence", http.StatusOK, `{"schema_version":"microllm.guard.v1","decision":"allow","abstain":false}`, 0},
		{"hijack_suspected_on_allow", http.StatusOK, `{"schema_version":"microllm.guard.v1","decision":"allow","confidence":0.99,"abstain":false,"hijack_suspected":true}`, 0},
		{"timeout", http.StatusOK, `{"schema_version":"microllm.guard.v1","decision":"allow","confidence":0.99,"abstain":false}`, 250 * time.Millisecond},
	}
	for _, tc := range failCases {
		t.Run(tc.name, func(t *testing.T) {
			setMock(tc.status, tc.body, tc.delay)
			r := gk.Evaluate(context.Background(), evalReq)
			if r.Decision != DecisionAbstain || !r.FailClosed {
				t.Errorf("%s: expected fail-closed x_abstain, got %+v", tc.name, r)
			}
		})
	}

	// 6. FailMode="deny" maps failures and escalations to DecisionDeny
	cfgDeny := cfg
	cfgDeny.FailMode = "deny"
	gkDeny, err := NewHTTPGatekeeper(cfgDeny)
	if err != nil {
		t.Fatalf("NewHTTPGatekeeper(deny): %v", err)
	}
	defer gkDeny.Close()
	setMock(http.StatusOK, `{"schema_version":"microllm.guard.v1","decision":"escalate","confidence":0.5,"abstain":true,"reason":"escalate"}`, 0)
	if r := gkDeny.Evaluate(context.Background(), evalReq); r.Decision != DecisionDeny {
		t.Fatalf("expected deny under fail_mode=deny, got %+v", r)
	}
}

func TestHTTPGatekeeper_SSRFConfinement(t *testing.T) {
	if _, err := NewHTTPGatekeeper(core.GatekeeperConfig{
		Enabled:  true,
		Mode:     "http",
		Endpoint: "https://remote.example.com/v1/guard/evaluate",
	}); !errors.Is(err, ErrRemoteEndpointForbidden) {
		t.Fatalf("expected ErrRemoteEndpointForbidden for remote host, got %v", err)
	}

	gkRemote, err := NewHTTPGatekeeper(core.GatekeeperConfig{
		Enabled:             true,
		Mode:                "http",
		Endpoint:            "https://remote.example.com/v1/guard/evaluate",
		AllowRemoteEndpoint: true,
	})
	if err != nil {
		t.Fatalf("expected remote host allowed when allow_remote_endpoint=true, got %v", err)
	}
	_ = gkRemote.Close()

	if _, err := NewHTTPGatekeeper(core.GatekeeperConfig{
		Enabled:  true,
		Mode:     "http",
		Endpoint: "file:///etc/passwd",
	}); !errors.Is(err, ErrInvalidEndpoint) {
		t.Fatalf("expected ErrInvalidEndpoint for file:// scheme, got %v", err)
	}
}

func TestCLIGatekeeper_DirectArgvExitCodesAndSandbox(t *testing.T) {
	// 1. Rejects UID 0 sandbox configuration
	badSandbox := core.DefaultSandboxConfig()
	badSandbox.UID = 0
	if _, err := NewCLIGatekeeper(core.GatekeeperConfig{
		Enabled: true,
		Mode:    "cli",
		CLIPath: os.Args[0],
	}, badSandbox); !errors.Is(err, core.ErrRootExecutionForbidden) {
		t.Fatalf("expected ErrRootExecutionForbidden for UID 0, got %v", err)
	}

	runHelper := func(helperMode string, timeout string) EvalResponse {
		t.Setenv("GO_WANT_GATEKEEPER_HELPER", "1")
		t.Setenv("GATEKEEPER_HELPER_MODE", helperMode)
		cliGK, err := NewCLIGatekeeper(core.GatekeeperConfig{
			Enabled:       true,
			Mode:          "cli",
			CLIPath:       os.Args[0],
			CLIArgs:       []string{"-test.run=TestHelperProcess_MicroLLMCLI"},
			Timeout:       timeout,
			MinConfidence: 0.70,
			FailMode:      "escalate_hitl",
		}, core.DefaultSandboxConfig())
		if err != nil {
			t.Fatalf("NewCLIGatekeeper: %v", err)
		}
		return cliGK.Evaluate(context.Background(), EvalRequest{
			Channel:  "command",
			ToolName: "execute_command",
			Command:  "ps aux",
		})
	}

	if r := runHelper("allow", "5s"); r.Decision != DecisionAllow || r.FailClosed {
		t.Errorf("CLI allow: got %+v", r)
	}
	if r := runHelper("block", "5s"); r.Decision != DecisionDeny || r.PrimaryThreat != "data_destruction" {
		t.Errorf("CLI block (exit 2): got %+v", r)
	}
	if r := runHelper("escalate", "5s"); r.Decision != DecisionAbstain || !r.Abstain {
		t.Errorf("CLI escalate (exit 3): got %+v", r)
	}
	if r := runHelper("contradict_block", "5s"); r.Decision != DecisionDeny || !r.FailClosed {
		t.Errorf("CLI contradict exit 2 vs allow: expected fail-closed deny, got %+v", r)
	}
	if r := runHelper("error", "5s"); r.Decision != DecisionAbstain || !r.FailClosed {
		t.Errorf("CLI error (exit 1): expected fail-closed x_abstain, got %+v", r)
	}
	if r := runHelper("oversized", "5s"); r.Decision != DecisionAbstain || !r.FailClosed {
		t.Errorf("CLI oversized stdout: expected fail-closed x_abstain, got %+v", r)
	}
	if r := runHelper("sleep", "50ms"); r.Decision != DecisionAbstain || !r.FailClosed {
		t.Errorf("CLI timeout: expected fail-closed x_abstain, got %+v", r)
	}
}

func BenchmarkHTTPGatekeeper_LocalhostLatency(b *testing.B) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"schema_version":"microllm.guard.v1","decision":"allow","confidence":0.99,"abstain":false,"reason":"ok","risk_score":0.01}`))
	}))
	defer ts.Close()

	gk, err := NewHTTPGatekeeper(core.GatekeeperConfig{
		Enabled:       true,
		Mode:          "http",
		Endpoint:      ts.URL + "/v1/guard/evaluate",
		Timeout:       "50ms",
		MinConfidence: 0.70,
		FailMode:      "escalate_hitl",
	})
	if err != nil {
		b.Fatalf("NewHTTPGatekeeper: %v", err)
	}
	defer gk.Close()

	req := EvalRequest{Channel: "mcp", ToolName: "execute_command", Command: "df -h"}
	// Warm up keep-alive pool
	if warm := gk.Evaluate(context.Background(), req); warm.Decision != DecisionAllow {
		b.Fatalf("warmup failed: %+v", warm)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res := gk.Evaluate(context.Background(), req)
		if res.Decision != DecisionAllow {
			b.Fatalf("unexpected verdict: %+v", res)
		}
	}
}
