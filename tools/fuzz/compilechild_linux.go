//go:build linux

package fuzz

import (
	"os/exec"
	"syscall"
)

// setChildDeathSignal has the kernel kill the compile child when the worker
// that started it dies — killed by Go's fuzz engine as hung, or by ^C — so a
// child in the middle of a long compile does not outlive it. The signal is
// tied to the THREAD that started the child; Go ends a thread only when a
// goroutine locked to it exits, which nothing here does, and the child also
// watches its parent's pid (serveCompileChild).
func setChildDeathSignal(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
}
