package gatekeeper

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"go-admin-tool/internal/core"
)

// CLIGatekeeper invokes a pinned local MicroLLM CLI binary directly via exec.CommandContext
// (zero shell interpolation) with non-root SandboxConfig enforcement and bounded 64 KiB output.
type CLIGatekeeper struct {
	cfg           core.GatekeeperConfig
	sandbox       core.SandboxConfig
	cliPath       string
	cliArgs       []string
	timeout       time.Duration
	minConfidence float64
	failMode      string
}

type boundedBuffer struct {
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if b.buf.Len() >= b.limit {
		b.truncated = true
		return len(p), nil
	}
	rem := b.limit - b.buf.Len()
	if len(p) > rem {
		_, _ = b.buf.Write(p[:rem])
		b.truncated = true
		return len(p), nil
	}
	return b.buf.Write(p)
}

// NewCLIGatekeeper validates CLI path and non-root SandboxConfig before constructing the adapter.
func NewCLIGatekeeper(cfg core.GatekeeperConfig, sandbox core.SandboxConfig) (*CLIGatekeeper, error) {
	cliPath := strings.TrimSpace(cfg.CLIPath)
	if cliPath == "" {
		return nil, ErrInvalidCLIPath
	}
	if err := sandbox.Validate(); err != nil {
		return nil, fmt.Errorf("gatekeeper CLI sandbox validation failed: %w", err)
	}

	args := append([]string(nil), cfg.CLIArgs...)
	if len(args) == 0 {
		args = []string{"--stdin", "--json"}
	}

	return &CLIGatekeeper{
		cfg:           cfg,
		sandbox:       sandbox,
		cliPath:       cliPath,
		cliArgs:       args,
		timeout:       cfg.EffectiveTimeout(),
		minConfidence: cfg.EffectiveMinConfidence(),
		failMode:      cfg.EffectiveFailMode(),
	}, nil
}

// Mode returns "cli".
func (c *CLIGatekeeper) Mode() string { return "cli" }

// Close is a no-op for the per-call CLI adapter.
func (c *CLIGatekeeper) Close() error { return nil }

// Evaluate writes microllm.guard.v1 JSON to stdin, parses bounded stdout JSON, and enforces
// MicroLLM CLI exit codes (0=allow, 2=block, 3=escalate, 1=error) fail-closed.
func (c *CLIGatekeeper) Evaluate(ctx context.Context, req EvalRequest) EvalResponse {
	start := time.Now()
	payload, err := buildWireRequest(req, c.cfg)
	if err != nil {
		return failClosedResponse(c.failMode, fmt.Sprintf("failed to encode gatekeeper CLI request: %v", err), elapsedMs(start))
	}

	execCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	cmd := exec.CommandContext(execCtx, c.cliPath, c.cliArgs...)
	cmd.WaitDelay = 500 * time.Millisecond
	if err := core.ConfigureCommandProcessGroupAndSandbox(cmd, c.sandbox); err != nil {
		return failClosedResponse(c.failMode, fmt.Sprintf("gatekeeper CLI sandbox error: %v", err), elapsedMs(start))
	}

	cmd.Stdin = bytes.NewReader(payload)
	stdout := &boundedBuffer{limit: MaxResponseBytes + 1}
	stderr := &boundedBuffer{limit: 4096}
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	runErr := cmd.Run()
	lat := elapsedMs(start)

	if execCtx.Err() != nil {
		return failClosedResponse(c.failMode, fmt.Sprintf("gatekeeper CLI timed out after %s", c.timeout), lat)
	}

	exitCode := 0
	if runErr != nil {
		var exitErr *exec.ExitError
		if !errors.As(runErr, &exitErr) {
			return failClosedResponse(c.failMode, fmt.Sprintf("gatekeeper CLI spawn failed: %v", runErr), lat)
		}
		exitCode = exitErr.ExitCode()
	}

	// MicroLLM CLI exit contract: 0=allow, 2=block, 3=escalate, 1=error/invalid input.
	if exitCode != 0 && exitCode != 2 && exitCode != 3 {
		errDetail := strings.TrimSpace(stderr.buf.String())
		if errDetail == "" {
			errDetail = fmt.Sprintf("exit code %d", exitCode)
		}
		return failClosedResponse(c.failMode, fmt.Sprintf("gatekeeper CLI failed (%s)", errDetail), lat)
	}

	if stdout.truncated || stdout.buf.Len() > MaxResponseBytes {
		return failClosedResponse(c.failMode, "gatekeeper CLI output exceeded 64 KiB cap", lat)
	}

	res := NormalizeWireResponse(bytes.TrimSpace(stdout.buf.Bytes()), c.minConfidence, c.failMode, lat)

	// Cross-check CLI exit code against parsed JSON decision (fail closed on contradictions).
	if exitCode == 2 && res.Decision == DecisionAllow {
		res.Decision = DecisionDeny
		res.Abstain = false
		res.FailClosed = true
		res.Reason = "gatekeeper CLI exit code 2 (block) contradicted JSON allow"
	} else if exitCode == 3 && res.Decision == DecisionAllow {
		dec := failClosedDecision(c.failMode)
		res.Decision = dec
		res.Abstain = dec == DecisionAbstain
		res.FailClosed = true
		res.Reason = "gatekeeper CLI exit code 3 (escalate) contradicted JSON allow"
	}

	return res
}
