//go:build windows

package core

import (
	"os/exec"
	"strconv"
)

// ConfigureCommandProcessGroupAndSandbox configures cmd on Windows to terminate
// child process trees on cancellation and enforces sandbox validation.
func ConfigureCommandProcessGroupAndSandbox(cmd *exec.Cmd, sandbox SandboxConfig) error {
	if err := sandbox.Validate(); err != nil {
		return err
	}

	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		pid := strconv.Itoa(cmd.Process.Pid)
		// Kill the process and all child processes it spawned (/T /F).
		_ = exec.Command("taskkill", "/T", "/F", "/PID", pid).Run()
		return cmd.Process.Kill()
	}
	return nil
}

// configureCommandProcessGroup configures cmd so that when its context is canceled on timeout,
// the entire child process tree spawned by the command is terminated.
func configureCommandProcessGroup(cmd *exec.Cmd) {
	_ = ConfigureCommandProcessGroupAndSandbox(cmd, DefaultSandboxConfig())
}
