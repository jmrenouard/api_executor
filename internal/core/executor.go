package core

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sync"
	"time"
)

// MaxCommandOutputBytes caps the maximum combined stdout/stderr bytes captured in memory per command execution (1 MiB).
const MaxCommandOutputBytes = 1 << 20

// ErrCommandTimeout is returned when a command execution exceeds its configured or overridden timeout.
var ErrCommandTimeout = errors.New("command execution timed out")

// ErrCommandCancelled is returned when a command execution is cancelled via context cancellation.
var ErrCommandCancelled = errors.New("command execution cancelled")

// limitedOutputBuffer is a concurrency-safe io.Writer that captures up to maxBytes of subprocess output
// and drains any excess bytes without blocking subprocess stdout/stderr pipes.
type limitedOutputBuffer struct {
	mu        sync.Mutex
	buf       bytes.Buffer
	maxBytes  int
	truncated bool
}

func newLimitedOutputBuffer(maxBytes int) *limitedOutputBuffer {
	if maxBytes <= 0 {
		maxBytes = MaxCommandOutputBytes
	}
	return &limitedOutputBuffer{maxBytes: maxBytes}
}

func (b *limitedOutputBuffer) Write(p []byte) (int, error) {
	totalLen := len(p)
	if totalLen == 0 {
		return 0, nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	remaining := b.maxBytes - b.buf.Len()
	if remaining <= 0 {
		b.truncated = true
		return totalLen, nil
	}
	if totalLen > remaining {
		_, _ = b.buf.Write(p[:remaining])
		b.truncated = true
		return totalLen, nil
	}
	_, _ = b.buf.Write(p)
	return totalLen, nil
}

func (b *limitedOutputBuffer) Truncated() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.truncated
}

func (b *limitedOutputBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.truncated {
		return fmt.Sprintf("%s\n[output truncated: exceeded %d bytes limit]", b.buf.String(), b.maxBytes)
	}
	return b.buf.String()
}

// ExecuteCommand runs a predefined command and returns its combined stdout/stderr output.
// If an optional timeoutOverride (> 0) is provided, it overrides the command's configured/default timeout.
func ExecuteCommand(commandDef CommandDefinition, timeoutOverride ...time.Duration) (string, error) {
	var override time.Duration
	if len(timeoutOverride) > 0 {
		override = timeoutOverride[0]
	}
	timeout := commandDef.EffectiveTimeout(DefaultCommandTimeout)
	if override > 0 {
		timeout = override
	}
	return ExecuteCommandWithContext(context.Background(), commandDef, timeout, nil)
}

// ExecuteCommandWithTimeout runs a predefined command with the specified timeout duration.
// If timeout <= 0, the command's configured timeout or DefaultCommandTimeout (30s) is used.
func ExecuteCommandWithTimeout(commandDef CommandDefinition, timeout time.Duration) (string, error) {
	return ExecuteCommandWithContext(context.Background(), commandDef, timeout, nil)
}

// ExecuteCommandWithContext runs a predefined command with the provided context, timeout duration,
// and an optional liveWriter (e.g., JobLogBuffer) that receives stdout/stderr streams in real time.
// It guarantees that if the context is cancelled or times out, the entire subprocess tree is terminated
// via configureCommandProcessGroup on both Windows and Unix, and WaitDelay ensures open pipes do not hang.
func ExecuteCommandWithContext(ctx context.Context, commandDef CommandDefinition, timeout time.Duration, liveWriter io.Writer) (string, error) {
	if timeout <= 0 {
		timeout = commandDef.EffectiveTimeout(DefaultCommandTimeout)
	}
	if ctx == nil {
		ctx = context.Background()
	}

	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(execCtx, commandDef.Command, commandDef.Args...)
	configureCommandProcessGroup(cmd)
	// Ensure child processes holding open stdout/stderr descriptors do not block Wait indefinitely after kill.
	cmd.WaitDelay = 200 * time.Millisecond

	outBuf := newLimitedOutputBuffer(MaxCommandOutputBytes)
	if liveWriter != nil {
		multi := io.MultiWriter(outBuf, liveWriter)
		cmd.Stdout = multi
		cmd.Stderr = multi
	} else {
		cmd.Stdout = outBuf
		cmd.Stderr = outBuf
	}

	err := cmd.Run()
	outputStr := outBuf.String()
	if err != nil {
		// If the executable itself could not be found/started, classify as a system error rather than timeout/cancel
		var execErr *exec.Error
		if !errors.As(err, &execErr) {
			if errors.Is(execCtx.Err(), context.DeadlineExceeded) {
				return outputStr, fmt.Errorf("command '%s' timed out after %s: %w (%w)", commandDef.Name, timeout, ErrCommandTimeout, context.DeadlineExceeded)
			}
			if errors.Is(execCtx.Err(), context.Canceled) {
				return outputStr, fmt.Errorf("command '%s' was cancelled: %w (%w)", commandDef.Name, ErrCommandCancelled, context.Canceled)
			}
		}
		// If the command fails, return the output (which might contain error details) and the error.
		return outputStr, fmt.Errorf("command '%s' failed: %w", commandDef.Name, err)
	}

	return outputStr, nil
}

// IsCommandTimeout reports whether err represents a command timeout.
func IsCommandTimeout(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, ErrCommandTimeout) || errors.Is(err, context.DeadlineExceeded)
}

// IsCommandCancelled reports whether err represents a command cancellation via context.
func IsCommandCancelled(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, ErrCommandCancelled) || errors.Is(err, context.Canceled)
}

// IsCommandFailure reports whether err represents a command execution failure ("appel en échec"),
// i.e., the command process ran and exited with a non-zero exit code, timed out, or was cancelled.
func IsCommandFailure(err error) bool {
	if err == nil {
		return false
	}
	if IsCommandTimeout(err) || IsCommandCancelled(err) {
		return true
	}
	var exitErr *exec.ExitError
	return errors.As(err, &exitErr)
}

// IsCommandSystemError reports whether err represents a technical/invocation error ("appel en erreur"),
// such as the executable binary not existing on the host or failing to spawn.
func IsCommandSystemError(err error) bool {
	if err == nil {
		return false
	}
	return !IsCommandFailure(err)
}
