package core

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func helperEchoCommand(name, text string) CommandDefinition {
	if runtime.GOOS == "windows" {
		return CommandDefinition{
			Name:    name,
			Command: "cmd",
			Args:    []string{"/C", "echo " + text},
		}
	}
	return CommandDefinition{
		Name:    name,
		Command: "sh",
		Args:    []string{"-c", "echo " + text},
	}
}

func helperExitCodeCommand(name string, code int) CommandDefinition {
	if runtime.GOOS == "windows" {
		return CommandDefinition{
			Name:    name,
			Command: "cmd",
			Args:    []string{"/C", "exit /B 1"},
		}
	}
	return CommandDefinition{
		Name:    name,
		Command: "sh",
		Args:    []string{"-c", "exit 1"},
	}
}

func helperSleepCommand(name string) CommandDefinition {
	if runtime.GOOS == "windows" {
		return CommandDefinition{
			Name:    name,
			Command: "powershell",
			Args:    []string{"-NoProfile", "-Command", "Start-Sleep -Seconds 5"},
		}
	}
	return CommandDefinition{
		Name:    name,
		Command: "sh",
		Args:    []string{"-c", "sleep 5"},
	}
}

func TestDefaultCommandTimeoutConstant(t *testing.T) {
	if DefaultCommandTimeout != 30*time.Second {
		t.Errorf("expected DefaultCommandTimeout to be 30s, got %v", DefaultCommandTimeout)
	}
	cfg := DefaultConfig()
	if cfg.Executor.EffectiveDefaultTimeout() != 30*time.Second {
		t.Errorf("expected EffectiveDefaultTimeout() to be 30s, got %v", cfg.Executor.EffectiveDefaultTimeout())
	}
}

func TestParseTimeoutDuration(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    time.Duration
		wantErr bool
	}{
		{name: "standard duration seconds", raw: "15s", want: 15 * time.Second, wantErr: false},
		{name: "standard duration milliseconds", raw: "250ms", want: 250 * time.Millisecond, wantErr: false},
		{name: "numeric seconds integer", raw: "10", want: 10 * time.Second, wantErr: false},
		{name: "numeric seconds float", raw: "0.5", want: 500 * time.Millisecond, wantErr: false},
		{name: "empty string returns zero without error", raw: "", want: 0, wantErr: false},
		{name: "whitespace string returns zero without error", raw: "   ", want: 0, wantErr: false},
		{name: "zero duration rejected", raw: "0s", want: 0, wantErr: true},
		{name: "zero numeric rejected", raw: "0", want: 0, wantErr: true},
		{name: "negative duration rejected", raw: "-5s", want: 0, wantErr: true},
		{name: "negative numeric rejected", raw: "-3", want: 0, wantErr: true},
		{name: "invalid string rejected", raw: "not-a-timeout", want: 0, wantErr: true},
		{name: "NaN rejected", raw: "NaN", want: 0, wantErr: true},
		{name: "+Inf rejected", raw: "+Inf", want: 0, wantErr: true},
		{name: "-Inf rejected", raw: "-Inf", want: 0, wantErr: true},
		{name: "huge overflow float rejected", raw: "1e100", want: 0, wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseTimeoutDuration(tc.raw)
			if tc.wantErr && err == nil {
				t.Errorf("ParseTimeoutDuration(%q) expected error, got nil (duration=%v)", tc.raw, got)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("ParseTimeoutDuration(%q) unexpected error: %v", tc.raw, err)
			}
			if !tc.wantErr && got != tc.want {
				t.Errorf("ParseTimeoutDuration(%q) = %v, want %v", tc.raw, got, tc.want)
			}
		})
	}
}

func TestResolveCommandTimeoutHierarchy(t *testing.T) {
	execCfg := ExecutorConfig{
		Enabled:               true,
		DefaultTimeoutSeconds: 45,
	}
	cmdNoTimeout := CommandDefinition{
		Name:    "cmd-default",
		Command: "echo",
	}
	cmdWithTimeout := CommandDefinition{
		Name:           "cmd-custom",
		Command:        "echo",
		TimeoutSeconds: 12,
	}
	cmdWithDurationString := CommandDefinition{
		Name:    "cmd-str",
		Command: "echo",
		Timeout: "8s",
	}

	// 1. Falls back to executor default (45s) when neither call override nor command timeout is set
	if got := execCfg.ResolveTimeout(cmdNoTimeout, 0); got != 45*time.Second {
		t.Errorf("expected 45s from executor default, got %v", got)
	}

	// 2. Command timeout (12s / 8s) overrides executor default (45s)
	if got := execCfg.ResolveTimeout(cmdWithTimeout, 0); got != 12*time.Second {
		t.Errorf("expected 12s from command config, got %v", got)
	}
	if got := execCfg.ResolveTimeout(cmdWithDurationString, 0); got != 8*time.Second {
		t.Errorf("expected 8s from command duration string config, got %v", got)
	}

	// 3. Per-call override (3s) overrides both command timeout (12s) and executor default (45s)
	if got := execCfg.ResolveTimeout(cmdWithTimeout, 3*time.Second); got != 3*time.Second {
		t.Errorf("expected 3s from per-call override, got %v", got)
	}

	// 4. Empty ExecutorConfig falls back to global DefaultCommandTimeout (30s)
	emptyExecCfg := ExecutorConfig{Enabled: true}
	if got := emptyExecCfg.ResolveTimeout(cmdNoTimeout, 0); got != DefaultCommandTimeout {
		t.Errorf("expected global default %v, got %v", DefaultCommandTimeout, got)
	}

	// 5. Mutating DefaultTimeoutSeconds on DefaultConfig() is honored even when DefaultTimeout is still "30s"
	defCfg := DefaultConfig()
	defCfg.Executor.DefaultTimeoutSeconds = 45
	if got := defCfg.Executor.EffectiveDefaultTimeout(); got != 45*time.Second {
		t.Errorf("expected 45s when DefaultTimeoutSeconds is updated on DefaultConfig(), got %v", got)
	}
}

func TestLoadConfigTimeoutDefaultsAndOverrides(t *testing.T) {
	tmpDir := t.TempDir()

	// Case 1: Omitted timeout fields in YAML -> defaults to 30s
	cfgPath1 := filepath.Join(tmpDir, "config1.yaml")
	if err := os.WriteFile(cfgPath1, []byte(`
command_executor:
  enabled: true
  commands:
    - name: "test-cmd"
      command: "echo"
`), 0600); err != nil {
		t.Fatalf("failed to write config1: %v", err)
	}
	cfg1, err := LoadConfig(cfgPath1)
	if err != nil {
		t.Fatalf("LoadConfig(config1) failed: %v", err)
	}
	if cfg1.Executor.EffectiveDefaultTimeout() != 30*time.Second || cfg1.Executor.DefaultTimeoutSeconds != 30 {
		t.Errorf("expected default timeout 30s, got %v (%ds)", cfg1.Executor.EffectiveDefaultTimeout(), cfg1.Executor.DefaultTimeoutSeconds)
	}

	// Case 2: Explicit default_timeout string in YAML -> 45s
	cfgPath2 := filepath.Join(tmpDir, "config2.yaml")
	if err := os.WriteFile(cfgPath2, []byte(`
command_executor:
  enabled: true
  default_timeout: "45s"
  commands:
    - name: "test-cmd"
      command: "echo"
      timeout: "10s"
`), 0600); err != nil {
		t.Fatalf("failed to write config2: %v", err)
	}
	cfg2, err := LoadConfig(cfgPath2)
	if err != nil {
		t.Fatalf("LoadConfig(config2) failed: %v", err)
	}
	if cfg2.Executor.EffectiveDefaultTimeout() != 45*time.Second || cfg2.Executor.DefaultTimeoutSeconds != 45 {
		t.Errorf("expected configured default timeout 45s, got %v (%ds)", cfg2.Executor.EffectiveDefaultTimeout(), cfg2.Executor.DefaultTimeoutSeconds)
	}
	if got := cfg2.Executor.ResolveTimeout(cfg2.Executor.Commands[0], 0); got != 10*time.Second {
		t.Errorf("expected command timeout 10s, got %v", got)
	}

	// Case 3: Invalid default_timeout string in YAML is normalized to fallback "30s"
	cfgPath3 := filepath.Join(tmpDir, "config3.yaml")
	if err := os.WriteFile(cfgPath3, []byte(`
command_executor:
  enabled: true
  default_timeout: "invalid-duration"
`), 0600); err != nil {
		t.Fatalf("failed to write config3: %v", err)
	}
	cfg3, err := LoadConfig(cfgPath3)
	if err != nil {
		t.Fatalf("LoadConfig(config3) failed: %v", err)
	}
	if cfg3.Executor.DefaultTimeout != "30s" || cfg3.Executor.EffectiveDefaultTimeout() != 30*time.Second {
		t.Errorf("expected normalized DefaultTimeout='30s', got %q (%v)", cfg3.Executor.DefaultTimeout, cfg3.Executor.EffectiveDefaultTimeout())
	}
}

func TestExecuteCommandSuccess(t *testing.T) {
	cmd := helperEchoCommand("hello-action", "hello-world")
	output, err := ExecuteCommand(cmd)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if output == "" {
		t.Errorf("expected non-empty output")
	}
}

func TestExecuteCommandTimeoutOverride(t *testing.T) {
	cmd := helperSleepCommand("slow-action")

	start := time.Now()
	_, err := ExecuteCommand(cmd, 150*time.Millisecond)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatalf("expected timeout error for slow command, got nil")
	}
	if !errors.Is(err, ErrCommandTimeout) {
		t.Errorf("expected errors.Is(err, ErrCommandTimeout) to be true, got %v", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected errors.Is(err, context.DeadlineExceeded) to be true, got %v", err)
	}
	if elapsed > 4*time.Second {
		t.Errorf("expected command to abort near 150ms timeout, took %v", elapsed)
	}
}

func TestExecuteCommandGrandchildProcessGroupTimeout(t *testing.T) {
	var grandchildCmd CommandDefinition
	if runtime.GOOS == "windows" {
		grandchildCmd = CommandDefinition{
			Name:    "grandchild-sleep",
			Command: "cmd",
			Args:    []string{"/C", "powershell -NoProfile -Command \"Start-Sleep -Seconds 6\""},
		}
	} else {
		grandchildCmd = CommandDefinition{
			Name:    "grandchild-sleep",
			Command: "sh",
			Args:    []string{"-c", "sh -c 'sleep 6'"},
		}
	}

	start := time.Now()
	_, err := ExecuteCommand(grandchildCmd, 150*time.Millisecond)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatalf("expected timeout error for grandchild sleep command, got nil")
	}
	if !IsCommandTimeout(err) {
		t.Errorf("expected IsCommandTimeout(err)=true, got false (err=%v)", err)
	}
	if elapsed > 4500*time.Millisecond {
		t.Errorf("expected grandchild tree termination well before 6s sleep, took %v", elapsed)
	}
}

func TestExecuteCommandFailureVsSystemError(t *testing.T) {
	// Non-zero exit code is a command failure (appel en échec)
	failCmd := helperExitCodeCommand("exit-fail", 1)
	_, err := ExecuteCommand(failCmd)
	if err == nil {
		t.Fatalf("expected error for non-zero exit command")
	}
	if !IsCommandFailure(err) {
		t.Errorf("expected IsCommandFailure(err)=true for exit code 1, got false (err=%v)", err)
	}
	if IsCommandSystemError(err) {
		t.Errorf("expected IsCommandSystemError(err)=false for exit code 1")
	}

	// Non-existent binary is a system/invocation error (appel en erreur)
	badBinCmd := CommandDefinition{
		Name:    "missing-binary",
		Command: "definitely_nonexistent_executable_xyz_98765",
	}
	_, err = ExecuteCommand(badBinCmd)
	if err == nil {
		t.Fatalf("expected error for nonexistent binary")
	}
	if !IsCommandSystemError(err) {
		t.Errorf("expected IsCommandSystemError(err)=true for missing binary, got false (err=%v)", err)
	}
}

func TestLimitedOutputBufferAndMaxCommandOutputBytes(t *testing.T) {
	if MaxCommandOutputBytes != 1<<20 {
		t.Fatalf("expected MaxCommandOutputBytes == 1048576, got %d", MaxCommandOutputBytes)
	}

	buf := newLimitedOutputBuffer(64)
	chunk := strings.Repeat("A", 40)
	if n, err := buf.Write([]byte(chunk)); err != nil || n != 40 {
		t.Fatalf("unexpected first Write result: n=%d err=%v", n, err)
	}
	if buf.Truncated() {
		t.Errorf("expected Truncated() == false after 40/64 bytes")
	}

	// Second write exceeds the 64-byte cap; Write must still report full len(p) to avoid broken-pipe errors in os/exec
	if n, err := buf.Write([]byte(chunk)); err != nil || n != 40 {
		t.Fatalf("unexpected second Write result: n=%d err=%v", n, err)
	}
	if !buf.Truncated() {
		t.Errorf("expected Truncated() == true after 80/64 bytes")
	}
	out := buf.String()
	if !strings.HasPrefix(out, strings.Repeat("A", 64)) {
		t.Errorf("expected prefix of 64 'A' chars, got %q", out)
	}
	if !strings.Contains(out, "[output truncated: exceeded 64 bytes limit]") {
		t.Errorf("expected truncation suffix in output, got %q", out)
	}
}

func TestExecuteCommandWithContext_Success(t *testing.T) {
	cmd := helperEchoCommand("ctx-echo", "hello-context")
	out, err := ExecuteCommandWithContext(context.Background(), cmd, 5*time.Second, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "hello-context") {
		t.Errorf("expected output to contain 'hello-context', got %q", out)
	}
}

func TestExecuteCommandWithContext_LiveWriter(t *testing.T) {
	cmd := helperEchoCommand("live-echo", "live-stream-data")
	var liveBuf strings.Builder
	out, err := ExecuteCommandWithContext(context.Background(), cmd, 5*time.Second, &liveBuf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "live-stream-data") {
		t.Errorf("expected return output to contain 'live-stream-data', got %q", out)
	}
	if !strings.Contains(liveBuf.String(), "live-stream-data") {
		t.Errorf("expected liveBuf to contain 'live-stream-data', got %q", liveBuf.String())
	}
}

func TestExecuteCommandWithContext_Cancellation(t *testing.T) {
	cmd := helperSleepCommand("cancel-cmd")
	ctx, cancel := context.WithCancel(context.Background())

	time.AfterFunc(100*time.Millisecond, cancel)

	_, err := ExecuteCommandWithContext(ctx, cmd, 10*time.Second, nil)
	if err == nil {
		t.Fatalf("expected cancellation error, got nil")
	}
	if !IsCommandCancelled(err) {
		t.Errorf("expected IsCommandCancelled(err) == true, got false (err=%v)", err)
	}
	if !IsCommandFailure(err) {
		t.Errorf("expected IsCommandFailure(err) == true for cancelled command, got false")
	}
}

func TestIsCommandCancelled(t *testing.T) {
	if IsCommandCancelled(nil) {
		t.Errorf("expected IsCommandCancelled(nil) == false")
	}
	if !IsCommandCancelled(ErrCommandCancelled) {
		t.Errorf("expected IsCommandCancelled(ErrCommandCancelled) == true")
	}
	if !IsCommandCancelled(context.Canceled) {
		t.Errorf("expected IsCommandCancelled(context.Canceled) == true")
	}
	wrapped := fmt.Errorf("wrapped: %w", ErrCommandCancelled)
	if !IsCommandCancelled(wrapped) {
		t.Errorf("expected IsCommandCancelled(wrapped) == true")
	}
	unrelated := errors.New("unrelated error")
	if IsCommandCancelled(unrelated) {
		t.Errorf("expected IsCommandCancelled(unrelated) == false")
	}
}

func TestExecutor_RejectRootPrivilegeEscalation(t *testing.T) {
	rootSandbox := SandboxConfig{
		Enabled:        true,
		EnforceNonRoot: true,
		UID:            0,
		GID:            0,
		UserNS:         "keep-id",
	}
	cmd := helperEchoCommand("root-escalation-attempt", "evil")
	cmd.Sandbox = &rootSandbox

	_, err := ExecuteCommand(cmd)
	if err == nil {
		t.Fatalf("expected error when command specifies UID 0 with sandbox enabled")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "root") && !strings.Contains(strings.ToLower(err.Error()), "sandbox") {
		t.Errorf("expected error indicating root/sandbox rejection, got %v", err)
	}
	if !errors.Is(err, ErrRootExecutionForbidden) {
		t.Errorf("expected errors.Is(err, ErrRootExecutionForbidden) to be true, got %v", err)
	}
}

func TestExecutor_ConfigureCommandProcessGroupAndSandbox(t *testing.T) {
	sandbox := DefaultSandboxConfig()
	cmd := exec.Command("echo", "test")
	err := ConfigureCommandProcessGroupAndSandbox(cmd, sandbox)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cmd.Cancel == nil {
		t.Errorf("expected cmd.Cancel cleanup handler to be initialized")
	}
}

func TestWrapContainerSandboxCommand_Podman(t *testing.T) {
	sandbox := DefaultSandboxConfig()
	sandbox.ContainerRuntime = "podman"

	cmdDef := CommandDefinition{
		Name:    "echo-test",
		Command: "echo",
		Args:    []string{"hello"},
	}

	wrapped, err := WrapContainerSandboxCommand(cmdDef, sandbox)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if wrapped.Command != "podman" {
		t.Errorf("expected command 'podman', got %q", wrapped.Command)
	}
	foundUserNS := false
	foundUser := false
	for _, arg := range wrapped.Args {
		if strings.Contains(arg, "--userns=keep-id") {
			foundUserNS = true
		}
		if strings.Contains(arg, "--user=10001:10001") {
			foundUser = true
		}
	}
	if !foundUserNS {
		t.Errorf("expected wrapped args to contain '--userns=keep-id', got %v", wrapped.Args)
	}
	if !foundUser {
		t.Errorf("expected wrapped args to contain '--user=10001:10001', got %v", wrapped.Args)
	}
}

func TestWrapContainerSandboxCommand_Docker(t *testing.T) {
	sandbox := DefaultSandboxConfig()
	sandbox.ContainerRuntime = "docker"

	cmdDef := CommandDefinition{
		Name:    "echo-test",
		Command: "echo",
		Args:    []string{"hello"},
	}

	wrapped, err := WrapContainerSandboxCommand(cmdDef, sandbox)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if wrapped.Command != "docker" {
		t.Errorf("expected command 'docker', got %q", wrapped.Command)
	}
	foundUser := false
	for _, arg := range wrapped.Args {
		if strings.Contains(arg, "--user=10001:10001") {
			foundUser = true
		}
	}
	if !foundUser {
		t.Errorf("expected wrapped args to contain '--user=10001:10001', got %v", wrapped.Args)
	}
}

func TestWrapContainerSandboxCommand_RootRejected(t *testing.T) {
	sandbox := SandboxConfig{
		Enabled:          true,
		EnforceNonRoot:   true,
		UID:              0,
		GID:              0,
		ContainerRuntime: "podman",
	}

	cmdDef := CommandDefinition{
		Name:    "echo-test",
		Command: "echo",
		Args:    []string{"hello"},
	}

	_, err := WrapContainerSandboxCommand(cmdDef, sandbox)
	if err == nil {
		t.Fatalf("expected error rejecting UID 0, got nil")
	}
	if !errors.Is(err, ErrRootExecutionForbidden) {
		t.Errorf("expected ErrRootExecutionForbidden, got %v", err)
	}
}
