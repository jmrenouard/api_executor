//go:build !windows

package core

import (
	"os/exec"
	"syscall"
)

// configureCommandProcessGroup places cmd in its own process group so that when its context
// is canceled on timeout, the entire process group (including child/grandchild processes) is killed.
func configureCommandProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err == nil {
			return nil
		}
		return cmd.Process.Kill()
	}
}
