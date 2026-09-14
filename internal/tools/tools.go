// Package tools resolves the external binaries regexped shells out to —
// wasm-merge, wasm-tools and wac — from their config keys, and runs them.
package tools

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
)

// Resolve returns the executable for one external tool.
//
// path is the key's value as resolved when the config was loaded — absolute,
// `~` expanded, a relative value joined to the config file's directory — and
// asWritten is the same value as the user wrote it, kept for messages. With
// both empty the key was omitted, and the fixed toolName is looked up in $PATH.
// Otherwise path is stat'ed, following symlinks: a regular file IS the
// executable, which is how a tool installed under another name is used, and a
// directory gets toolName appended.
//
// There is no environment variable. The key and $PATH are the only two places
// a tool is looked for.
//
// Every error is specific: it names the key, the value as written, what it
// resolved to when that differs, and the EXACT path tried — for a directory the
// joined path, not just the directory.
func Resolve(key, asWritten, path, toolName string) (string, error) {
	if path == "" && asWritten == "" {
		p, err := exec.LookPath(toolName)
		if err != nil {
			return "", fmt.Errorf("`%s` not found in $PATH (set %s to its location)", toolName, key)
		}
		return p, nil
	}
	if path == "" {
		path = asWritten
	}
	if asWritten == "" {
		asWritten = path
	}
	prefix := fmt.Sprintf("%s = `%s`", key, asWritten)
	if asWritten != path {
		prefix += fmt.Sprintf(" (resolved to %s)", path)
	}

	info, err := os.Stat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "", fmt.Errorf("%s: no such file or directory", prefix)
	case err != nil:
		return "", fmt.Errorf("%s: cannot access %s: %v", prefix, path, err)
	}
	if info.IsDir() {
		joined := filepath.Join(path, toolName)
		ji, err := os.Stat(joined)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			return "", fmt.Errorf("%s: is a directory, but %s does not exist", prefix, joined)
		case err != nil:
			return "", fmt.Errorf("%s: cannot access %s: %v", prefix, joined, err)
		case !ji.Mode().IsRegular():
			return "", fmt.Errorf("%s: %s is not a regular file", prefix, joined)
		case ji.Mode()&0o111 == 0:
			return "", fmt.Errorf("%s: %s is not executable", prefix, joined)
		}
		return joined, nil
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s: %s is not a regular file", prefix, path)
	}
	if info.Mode()&0o111 == 0 {
		return "", fmt.Errorf("%s: %s is not executable", prefix, path)
	}
	return path, nil
}

// Run executes one tool with its output on regexped's own stdout and stderr, in
// dir (the current directory when empty), with extraEnv appended to the
// environment. merge/ and component/ each carried an identical copy of this.
func Run(name string, args []string, dir string, extraEnv []string) error {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if len(extraEnv) > 0 {
		cmd.Env = append(os.Environ(), extraEnv...)
	}
	return cmd.Run()
}
