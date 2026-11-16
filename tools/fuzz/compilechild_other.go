//go:build !linux

package fuzz

import "os/exec"

// setChildDeathSignal: there is no parent-death signal outside Linux; the
// child watches its parent's pid instead (serveCompileChild).
func setChildDeathSignal(*exec.Cmd) {}
