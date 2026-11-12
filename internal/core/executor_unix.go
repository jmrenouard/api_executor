//go:build !windows

package core

import (
	"os"
	"os/exec"
	"syscall"
)

// ConfigureCommandProcessGroupAndSandbox configures cmd with process group isolation,
// context cancellation cleanup, and drops root credentials to non-root UID/GID when running as root.
func ConfigureCommandProcessGroupAndSandbox(cmd *exec.Cmd, sandbox SandboxConfig) error {
	if err := sandbox.Validate(); err != nil {
		return err
	}

	sysProc := &syscall.SysProcAttr{Setpgid: true}

	if sandbox.Enabled && sandbox.DropPrivileges {
		// If running as root (euid 0), drop credentials to sandbox UID/GID
		if os.Geteuid() == 0 {
			uid := sandbox.EffectiveUID()
			gid := sandbox.EffectiveGID()
			if uid == 0 || gid == 0 {
				return ErrRootExecutionForbidden
			}
			sysProc.Credential = &syscall.Credential{
				Uid:         uid,
				Gid:         gid,
				NoSetGroups: true,
			}
		}
	}

	cmd.SysProcAttr = sysProc
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err == nil {
			return nil
		}
		return cmd.Process.Kill()
	}
	return nil
}

// configureCommandProcessGroup places cmd in its own process group so that when its context
// is canceled on timeout, the entire process group (including child/grandchild processes) is killed.
func configureCommandProcessGroup(cmd *exec.Cmd) {
	_ = ConfigureCommandProcessGroupAndSandbox(cmd, DefaultSandboxConfig())
}
