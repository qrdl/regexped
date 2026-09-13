package tools

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeExec(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}

// mustErr requires an error whose message contains every part: the key, the
// value as written, the resolved path and the exact path tried are the content
// every resolver error is required to carry.
func mustErr(t *testing.T, err error, parts ...string) {
	t.Helper()
	if err == nil {
		t.Fatalf("got no error, want one containing %q", parts)
	}
	for _, p := range parts {
		if !strings.Contains(err.Error(), p) {
			t.Errorf("error %q does not contain %q", err, p)
		}
	}
}

// An omitted key means the fixed tool name, looked up in $PATH.
func TestResolveOmittedKeyLooksInPATH(t *testing.T) {
	dir := t.TempDir()
	writeExec(t, filepath.Join(dir, "faketool"))
	t.Setenv("PATH", dir)
	if got, err := Resolve("fake_path", "", "", "faketool"); err != nil || got != filepath.Join(dir, "faketool") {
		t.Fatalf("Resolve = %q, %v; want the tool found in $PATH", got, err)
	}
	t.Setenv("PATH", t.TempDir())
	_, err := Resolve("fake_path", "", "", "faketool")
	mustErr(t, err, "faketool", "$PATH", "fake_path")
}

// A DIRECTORY gets the fixed tool name appended, and every failure prints the
// joined path it tried rather than just the directory.
func TestResolveDirectory(t *testing.T) {
	dir := t.TempDir()
	writeExec(t, filepath.Join(dir, "faketool"))
	if got, err := Resolve("fake_path", "tools", dir, "faketool"); err != nil || got != filepath.Join(dir, "faketool") {
		t.Fatalf("Resolve(directory) = %q, %v", got, err)
	}

	empty := t.TempDir()
	_, err := Resolve("fake_path", "tools", empty, "faketool")
	mustErr(t, err, "fake_path", "`tools`", empty, filepath.Join(empty, "faketool"))

	isDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(isDir, "faketool"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err = Resolve("fake_path", isDir, isDir, "faketool")
	mustErr(t, err, filepath.Join(isDir, "faketool"), "not a regular file")

	notExec := t.TempDir()
	if err := os.WriteFile(filepath.Join(notExec, "faketool"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = Resolve("fake_path", notExec, notExec, "faketool")
	mustErr(t, err, filepath.Join(notExec, "faketool"), "not executable")
}

// A FILE is the executable itself, so a tool installed under another name can
// be pointed at directly.
func TestResolveFile(t *testing.T) {
	dir := t.TempDir()
	other := filepath.Join(dir, "faketool-118")
	writeExec(t, other)
	if got, err := Resolve("fake_path", other, other, "faketool"); err != nil || got != other {
		t.Fatalf("Resolve(file) = %q, %v; want the file itself", got, err)
	}
	plain := filepath.Join(dir, "plain")
	if err := os.WriteFile(plain, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Resolve("fake_path", plain, plain, "faketool")
	mustErr(t, err, "fake_path", plain, "not executable")
}

// Symlinks are followed: to a file it is the executable, to a directory the tool
// name is appended.
func TestResolveSymlinks(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	writeExec(t, real)
	linkFile := filepath.Join(dir, "link-file")
	if err := os.Symlink(real, linkFile); err != nil {
		t.Skip("symlinks unsupported:", err)
	}
	if got, err := Resolve("fake_path", linkFile, linkFile, "faketool"); err != nil || got != linkFile {
		t.Errorf("Resolve(symlink to file) = %q, %v", got, err)
	}
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	writeExec(t, filepath.Join(sub, "faketool"))
	linkDir := filepath.Join(dir, "link-dir")
	if err := os.Symlink(sub, linkDir); err != nil {
		t.Fatal(err)
	}
	if got, err := Resolve("fake_path", linkDir, linkDir, "faketool"); err != nil || got != filepath.Join(linkDir, "faketool") {
		t.Errorf("Resolve(symlink to directory) = %q, %v", got, err)
	}
}

// A path that does not exist names the key, the value as written and what it
// resolved to.
func TestResolveMissingPath(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope")
	_, err := Resolve("fake_path", "nope", missing, "faketool")
	mustErr(t, err, "fake_path", "`nope`", missing)
}

func TestRun(t *testing.T) {
	if err := Run("/bin/true", nil, "", nil); err != nil {
		t.Errorf("Run(/bin/true): %v", err)
	}
	if err := Run("/bin/false", nil, "", nil); err == nil {
		t.Error("Run(/bin/false): want an error")
	}
	dir := t.TempDir()
	marker := filepath.Join(dir, "ran")
	if err := Run("/bin/sh", []string{"-c", `test "$REGEXPED_TEST" = 1 && touch ran`}, dir, []string{"REGEXPED_TEST=1"}); err != nil {
		t.Fatalf("Run with dir and extra env: %v", err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Error("Run ignored its directory or its extra environment")
	}
}

// Either half of the key's value may arrive alone: a caller that resolved no
// path passes only what was written, and one with nothing written to quote passes
// only the path. Each fills in the other, and a message with no difference
// between the two does not print a "resolved to" that says nothing.
func TestResolveFillsTheMissingHalf(t *testing.T) {
	dir := t.TempDir()
	tool := filepath.Join(dir, "faketool")
	writeExec(t, tool)
	if got, err := Resolve("fake_path", tool, "", "faketool"); err != nil || got != tool {
		t.Errorf("Resolve(written only) = %q, %v; want %q", got, err, tool)
	}
	if got, err := Resolve("fake_path", "", tool, "faketool"); err != nil || got != tool {
		t.Errorf("Resolve(path only) = %q, %v; want %q", got, err, tool)
	}
	missing := filepath.Join(dir, "nope")
	_, err := Resolve("fake_path", "", missing, "faketool")
	mustErr(t, err, "fake_path = `"+missing+"`", "no such file or directory")
	if strings.Contains(err.Error(), "resolved to") {
		t.Errorf("error %q prints a resolved path identical to the written one", err)
	}
}

// A stat failure that is not "does not exist" is reported as what it is, with
// the exact path that failed: a symlink loop is the portable way to get one, both
// at the key's own path and at the tool name joined under a directory.
func TestResolveReportsOtherStatFailures(t *testing.T) {
	dir := t.TempDir()
	loop := filepath.Join(dir, "loop")
	if err := os.Symlink(loop, loop); err != nil {
		t.Skip("symlinks unsupported:", err)
	}
	_, err := Resolve("fake_path", loop, loop, "faketool")
	mustErr(t, err, "fake_path", "cannot access "+loop)

	sub := t.TempDir()
	joined := filepath.Join(sub, "faketool")
	if err := os.Symlink(joined, joined); err != nil {
		t.Fatal(err)
	}
	_, err = Resolve("fake_path", sub, sub, "faketool")
	mustErr(t, err, "fake_path", "cannot access "+joined)
}

// A path that exists but is neither a directory nor a regular file — a device —
// is refused rather than executed.
func TestResolveRefusesANonRegularFile(t *testing.T) {
	info, err := os.Stat(os.DevNull)
	if err != nil || info.IsDir() || info.Mode().IsRegular() {
		t.Skipf("%s is not a device here", os.DevNull)
	}
	_, err = Resolve("fake_path", os.DevNull, os.DevNull, "faketool")
	mustErr(t, err, "fake_path", os.DevNull, "not a regular file")
}
