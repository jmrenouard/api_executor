package gatekeeper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"

	"go-admin-tool/internal/core"
)

const (
	// SchemaVersionV1 is the finalized MicroLLM gatekeeper wire contract version.
	SchemaVersionV1 = "microllm.guard.v1"
	// MaxResponseBytes bounds HTTP and CLI gatekeeper responses to prevent memory exhaustion (IMP-008).
	MaxResponseBytes = 64 * 1024
)

var (
	ErrRemoteEndpointForbidden = errors.New("non-loopback gatekeeper endpoint forbidden unless allow_remote_endpoint is true")
	ErrInvalidEndpoint         = errors.New("invalid gatekeeper endpoint URL")
	ErrInvalidCLIPath          = errors.New("gatekeeper cli_path is required when mode is cli")
)

// Decision represents the canonical System-1 Bastion gatekeeper outcome.
type Decision string

const (
	DecisionAllow   Decision = "allow"
	DecisionDeny    Decision = "deny"
	DecisionAbstain Decision = "x_abstain"
)

// PolicyBoundaries mirrors MicroLLM microllm.guard.v1 policy_boundaries.
type PolicyBoundaries struct {
	Allowed   []string `json:"allowed,omitempty"`
	Forbidden []string `json:"forbidden,omitempty"`
}

// EvalRequest describes a command, plugin, job, or MCP invocation evaluated by System-1.
type EvalRequest struct {
	Channel          string            `json:"channel,omitempty"`
	ToolName         string            `json:"tool_name"`
	Command          string            `json:"command,omitempty"`
	Arguments        map[string]any    `json:"arguments,omitempty"`
	Context          string            `json:"context,omitempty"`
	Environment      string            `json:"environment,omitempty"`
	Actor            string            `json:"actor,omitempty"`
	PolicyBoundaries *PolicyBoundaries `json:"policy_boundaries,omitempty"`
	CustomRubrics    map[string]string `json:"custom_rubrics,omitempty"`
}

// EvalResponse represents the normalized, fail-closed System-1 verdict.
type EvalResponse struct {
	SchemaVersion   string   `json:"schema_version"`
	Decision        Decision `json:"decision"`
	RawDecision     string   `json:"raw_decision,omitempty"`
	Confidence      float64  `json:"confidence"`
	Abstain         bool     `json:"abstain"`
	RiskScore       float64  `json:"risk_score,omitempty"`
	PrimaryThreat   string   `json:"primary_threat,omitempty"`
	HijackSuspected bool     `json:"hijack_suspected,omitempty"`
	Reason          string   `json:"reason"`
	LatencyMs       float64  `json:"latency_ms"`
	FailClosed      bool     `json:"fail_closed,omitempty"`
}

// guardWireRequest strictly conforms to microllm.guard.v1 (extra="forbid").
type guardWireRequest struct {
	ToolName         string            `json:"tool_name"`
	Command          string            `json:"command,omitempty"`
	Arguments        map[string]any    `json:"arguments,omitempty"`
	Context          string            `json:"context,omitempty"`
	Environment      string            `json:"environment,omitempty"`
	Threshold        float64           `json:"threshold,omitempty"`
	AbstainPolicy    string            `json:"abstain_policy,omitempty"`
	PolicyBoundaries *PolicyBoundaries `json:"policy_boundaries,omitempty"`
	CustomRubrics    map[string]string `json:"custom_rubrics,omitempty"`
}

// guardWireResponse decodes MicroLLM microllm.guard.v1 JSON responses.
type guardWireResponse struct {
	SchemaVersion   string   `json:"schema_version"`
	Decision        string   `json:"decision"`
	Confidence      *float64 `json:"confidence"`
	Abstain         bool     `json:"abstain"`
	Reason          string   `json:"reason"`
	RiskScore       float64  `json:"risk_score"`
	PrimaryThreat   string   `json:"primary_threat"`
	HijackSuspected bool     `json:"hijack_suspected"`
	LatencyMs       float64  `json:"latency_ms"`
	Error           string   `json:"error"`
}

// Gatekeeper evaluates pre-execution safety using a local System-1 engine (e.g., MicroLLM).
type Gatekeeper interface {
	Evaluate(ctx context.Context, req EvalRequest) EvalResponse
	Mode() string
	Close() error
}

// NoopGatekeeper allows all invocations when System-1 gating is disabled.
type NoopGatekeeper struct{}

func (NoopGatekeeper) Evaluate(_ context.Context, _ EvalRequest) EvalResponse {
	return EvalResponse{
		SchemaVersion: SchemaVersionV1,
		Decision:      DecisionAllow,
		RawDecision:   "allow",
		Confidence:    1.0,
		Reason:        "gatekeeper disabled (noop)",
	}
}

func (NoopGatekeeper) Mode() string { return "noop" }
func (NoopGatekeeper) Close() error { return nil }

// NewFromConfig constructs the configured Gatekeeper adapter (http, cli, or noop).
func NewFromConfig(cfg core.GatekeeperConfig, sandbox core.SandboxConfig) (Gatekeeper, error) {
	if !cfg.Enabled {
		return NoopGatekeeper{}, nil
	}
	switch cfg.EffectiveMode() {
	case "noop":
		return NoopGatekeeper{}, nil
	case "cli":
		return NewCLIGatekeeper(cfg, sandbox)
	case "http":
		return NewHTTPGatekeeper(cfg)
	default:
		return nil, fmt.Errorf("unsupported gatekeeper mode %q", cfg.Mode)
	}
}

func buildWireRequest(req EvalRequest, cfg core.GatekeeperConfig) ([]byte, error) {
	toolName := strings.TrimSpace(req.ToolName)
	if toolName == "" {
		toolName = "execute_command"
	}
	env := strings.ToLower(strings.TrimSpace(req.Environment))
	switch env {
	case "production", "prod":
		env = "production"
	case "staging", "stage":
		env = "staging"
	case "development", "dev":
		env = "development"
	default:
		env = cfg.EffectiveEnvironment()
	}

	abstainPolicy := "escalate"
	if cfg.EffectiveFailMode() == "deny" {
		abstainPolicy = "block"
	}

	threshold := cfg.EffectiveMinConfidence()
	if threshold < 0.10 || threshold > 0.99 {
		threshold = 0.70
	}

	wire := guardWireRequest{
		ToolName:         toolName,
		Command:          strings.TrimSpace(req.Command),
		Arguments:        req.Arguments,
		Context:          strings.TrimSpace(req.Context),
		Environment:      env,
		Threshold:        threshold,
		AbstainPolicy:    abstainPolicy,
		PolicyBoundaries: req.PolicyBoundaries,
		CustomRubrics:    req.CustomRubrics,
	}
	return json.Marshal(wire)
}

func failClosedDecision(failMode string) Decision {
	if strings.EqualFold(strings.TrimSpace(failMode), "deny") || strings.EqualFold(strings.TrimSpace(failMode), "block") {
		return DecisionDeny
	}
	return DecisionAbstain
}

func failClosedResponse(failMode, reason string, latencyMs float64) EvalResponse {
	dec := failClosedDecision(failMode)
	return EvalResponse{
		SchemaVersion: SchemaVersionV1,
		Decision:      dec,
		Confidence:    0,
		Abstain:       dec == DecisionAbstain,
		Reason:        reason,
		LatencyMs:     latencyMs,
		FailClosed:    true,
	}
}

// NormalizeWireResponse validates and maps a raw microllm.guard.v1 JSON payload into a fail-closed EvalResponse.
func NormalizeWireResponse(raw []byte, minConfidence float64, failMode string, measuredLatencyMs float64) EvalResponse {
	if len(raw) == 0 {
		return failClosedResponse(failMode, "empty gatekeeper response", measuredLatencyMs)
	}
	if len(raw) > MaxResponseBytes {
		return failClosedResponse(failMode, "gatekeeper response exceeded 64 KiB cap", measuredLatencyMs)
	}

	var wire guardWireResponse
	if err := json.Unmarshal(raw, &wire); err != nil {
		return failClosedResponse(failMode, fmt.Sprintf("malformed gatekeeper JSON: %v", err), measuredLatencyMs)
	}
	if strings.TrimSpace(wire.Error) != "" {
		return failClosedResponse(failMode, fmt.Sprintf("gatekeeper returned error: %s", strings.TrimSpace(wire.Error)), measuredLatencyMs)
	}
	if sv := strings.TrimSpace(wire.SchemaVersion); sv != "" && sv != SchemaVersionV1 {
		return failClosedResponse(failMode, fmt.Sprintf("unsupported gatekeeper schema_version %q", sv), measuredLatencyMs)
	}
	if wire.Confidence == nil || math.IsNaN(*wire.Confidence) || math.IsInf(*wire.Confidence, 0) || *wire.Confidence < 0 || *wire.Confidence > 1 {
		return failClosedResponse(failMode, "missing or out-of-range gatekeeper confidence", measuredLatencyMs)
	}
	conf := *wire.Confidence

	risk := wire.RiskScore
	if math.IsNaN(risk) || math.IsInf(risk, 0) || risk < 0 {
		risk = 0
	}

	rawDec := strings.ToLower(strings.TrimSpace(wire.Decision))
	reason := strings.TrimSpace(wire.Reason)
	out := EvalResponse{
		SchemaVersion:   SchemaVersionV1,
		RawDecision:     rawDec,
		Confidence:      conf,
		Abstain:         wire.Abstain,
		RiskScore:       risk,
		PrimaryThreat:   strings.TrimSpace(wire.PrimaryThreat),
		HijackSuspected: wire.HijackSuspected,
		Reason:          reason,
		LatencyMs:       measuredLatencyMs,
	}

	switch rawDec {
	case "allow":
		if wire.Abstain {
			dec := failClosedDecision(failMode)
			out.Decision = dec
			out.Abstain = dec == DecisionAbstain
			out.FailClosed = true
			if out.Reason == "" {
				out.Reason = "gatekeeper abstained on allow verdict"
			}
			return out
		}
		if conf < minConfidence {
			dec := failClosedDecision(failMode)
			out.Decision = dec
			out.Abstain = dec == DecisionAbstain
			out.FailClosed = true
			out.Reason = fmt.Sprintf("gatekeeper confidence %.3f below min_confidence %.3f", conf, minConfidence)
			return out
		}
		out.Decision = DecisionAllow
		if out.Reason == "" {
			out.Reason = "allowed by System-1 gatekeeper"
		}
		return out

	case "block", "deny":
		out.Decision = DecisionDeny
		out.Abstain = false
		if out.Reason == "" {
			out.Reason = "blocked by System-1 gatekeeper"
		}
		return out

	case "escalate", "x_abstain", "abstain":
		dec := failClosedDecision(failMode)
		out.Decision = dec
		out.Abstain = dec == DecisionAbstain
		if out.Reason == "" {
			out.Reason = "escalated to HITL by System-1 gatekeeper"
		}
		return out

	default:
		return failClosedResponse(failMode, fmt.Sprintf("unrecognized gatekeeper decision %q", wire.Decision), measuredLatencyMs)
	}
}
