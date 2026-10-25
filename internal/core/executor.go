package core

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"time"
)

// ErrCommandTimeout is returned when a command execution exceeds its configured or overridden timeout.
var ErrCommandTimeout = errors.New("command execution timed out")

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
	return ExecuteCommandWithTimeout(commandDef, timeout)
}

// ExecuteCommandWithTimeout runs a predefined command with the specified timeout duration.
// If timeout <= 0, the command's configured timeout or DefaultCommandTimeout (30s) is used.
func ExecuteCommandWithTimeout(commandDef CommandDefinition, timeout time.Duration) (string, error) {
	if timeout <= 0 {
		timeout = commandDef.EffectiveTimeout(DefaultCommandTimeout)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, commandDef.Command, commandDef.Args...)
	configureCommandProcessGroup(cmd)
	// Ensure child processes holding open stdout/stderr descriptors do not block Wait indefinitely after kill.
	cmd.WaitDelay = 200 * time.Millisecond

	output, err := cmd.CombinedOutput()
	if err != nil {
		// If the executable itself could not be found/started, classify as a system error rather than timeout
		var execErr *exec.Error
		if !errors.As(err, &execErr) && errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return string(output), fmt.Errorf("command '%s' timed out after %s: %w (%w)", commandDef.Name, timeout, ErrCommandTimeout, context.DeadlineExceeded)
		}
		// If the command fails, return the output (which might contain error details) and the error.
		return string(output), fmt.Errorf("command '%s' failed: %w", commandDef.Name, err)
	}

	return string(output), nil
}

// IsCommandTimeout reports whether err represents a command timeout.
func IsCommandTimeout(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, ErrCommandTimeout) || errors.Is(err, context.DeadlineExceeded)
}

// IsCommandFailure reports whether err represents a command execution failure ("appel en échec"),
// i.e., the command process ran and exited with a non-zero exit code or timed out.
func IsCommandFailure(err error) bool {
	if err == nil {
		return false
	}
	if IsCommandTimeout(err) {
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
