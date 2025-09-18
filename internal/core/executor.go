package core

import (
	"context"
	"fmt"
	"os/exec"
	"time"
)

// ExecuteCommand runs a predefined command and returns its output.
// It uses a context for timeout/cancellation.
func ExecuteCommand(commandDef CommandDefinition) (string, error) {
	// A simple timeout to prevent commands from running indefinitely.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, commandDef.Command, commandDef.Args...)

	output, err := cmd.CombinedOutput()
	if err != nil {
		// If the command fails, return the output (which might contain error details) and the error.
		return string(output), fmt.Errorf("command '%s' failed: %w", commandDef.Name, err)
	}

	return string(output), nil
}
