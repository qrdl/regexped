// Package ownership hands a root process's outputs to the user who owns the
// directory they land in.
//
// It exists for the Docker image. A bind-mounted project directory belongs to
// the host user, and the kernel enforces that ownership inside the container:
// a non-root container cannot write into it at all, so the image runs as root.
// Root writes succeed, but every file it produces is then owned by root on the
// HOST — stubs the user cannot edit and outputs the user cannot delete without
// sudo. Handing each output to the owner of its own directory is what lets
// `docker run -v $(pwd):/work -w /work qrdl/regexped …` work with no --user
// flag, which is the whole point.
//
// Everything here is a NO-OP unless the process is root, so an ordinary
// `regexped` run — and a container run with an explicit --user — behaves
// exactly as it did before this package existed.
//
// FAILURE IS A WARNING, NEVER AN ERROR. Docker Desktop's macOS and Windows
// mounts synthesise ownership and ignore or refuse chown, some network
// filesystems refuse it, and under rootless Docker the mapped root may not hold
// CAP_CHOWN over the file. In each of those the output itself is fine, and a
// build must not fail over a cosmetic correction.
package ownership

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// Test seams, in the style component/ already uses. Each guards a branch that
// only a ROOT process reaches, and a test binary is not one: without these, the
// half of this package that does the actual work would be exercised by nothing
// and the correction could break silently in the only environment it runs in.
//
// chownFile and dirOwner are separate from the root check because what is worth
// asserting is the DECISION — which path, handed to which uid and gid — and not
// whether the kernel can perform a chown, which it demonstrably can. dirOwner in
// particular is the whole input to that decision, and off-root every file shares
// its directory's owner, so without the seam the correction is always skipped as
// already-correct and never runs at all.
var (
	isRootProcess = func() bool { return os.Getuid() == 0 }
	chownFile     = os.Chown
	dirOwner      = ownerOf
)

// enabled reports whether ownership correction applies at all. os.Getuid
// returns -1 on Windows, so the package disables itself there without needing a
// build tag of its own.
func enabled() bool { return isRootProcess() }

// Fix gives path the ownership of the directory it sits in.
//
// Call it on the FINAL path, once the bytes are in place — after a rename, or
// after the subprocess that wrote the file has returned. Both matter here: a
// rename replaces the inode, so a staged file renamed over one the user already
// owned still yields a root-owned file; and `wasm-merge`, `wac` and
// `wasm-tools` write their own output as children of this root process.
//
// "-" is the stdout sentinel the commands accept, and it owns nothing.
func Fix(path string) {
	if !enabled() || path == "" || path == "-" {
		return
	}
	uid, gid, ok := dirOwner(filepath.Dir(path))
	if !ok {
		return
	}
	chown(path, uid, gid)
}

// MkdirAll is os.MkdirAll, plus the ownership of every level it creates.
//
// The levels are collected BEFORE the directories exist, because afterwards
// nothing distinguishes one this call made from one that was already there —
// and a directory the user made is not ours to re-own. They all take the owner
// of the nearest pre-existing ancestor, which is also the answer to the
// circularity in "the owner of the output directory": when the output directory
// is one being created right now, root owns it, and asking it who its files
// should belong to would answer root.
func MkdirAll(dir string, perm os.FileMode) error {
	var created []string
	if enabled() {
		created = missingLevels(dir)
	}
	if err := os.MkdirAll(dir, perm); err != nil {
		return err
	}
	if len(created) == 0 {
		return nil
	}
	// created[0] is the outermost level that did not exist, so its parent is
	// the nearest ancestor that did.
	uid, gid, ok := dirOwner(filepath.Dir(created[0]))
	if !ok {
		return nil
	}
	for _, d := range created {
		chown(d, uid, gid)
	}
	return nil
}

// missingLevels returns the directories os.MkdirAll would have to create for
// dir to exist, OUTERMOST FIRST. Empty when dir already exists, which is the
// everyday case and the one that must do nothing at all.
func missingLevels(dir string) []string {
	if dir == "" {
		return nil
	}
	// The walk is bounded by the number of levels in the path rather than by a
	// parent == p test. filepath.Dir is idempotent at the top ("/" and "." are
	// their own parents), so the test form needs a guard against spinning there
	// — and that guard is unreachable, since both of those always exist: "/"
	// permanently, and "." for as long as the process holds it, even after the
	// directory is unlinked. A bound that comes from the path itself cannot spin
	// and leaves no branch that nothing reaches.
	//
	// n separators means n+1 levels to consider: the path, and each ancestor up
	// to but not including the top. The top is never reported, which is right —
	// "/" and "." are not creatable and never missing.
	p := filepath.Clean(dir)
	var missing []string
	for range strings.Count(p, string(filepath.Separator)) + 1 {
		if _, err := os.Stat(p); err == nil {
			break
		}
		missing = append(missing, p)
		p = filepath.Dir(p)
	}
	// Collected innermost-first; reverse, so callers see creation order.
	for i, j := 0, len(missing)-1; i < j; i, j = i+1, j-1 {
		missing[i], missing[j] = missing[j], missing[i]
	}
	return missing
}

// ownerOf reports the uid and gid owning p, and whether they could be read at
// all — a platform without Unix ownership answers false, and every caller then
// leaves the path alone.
func ownerOf(p string) (uid, gid int, ok bool) {
	info, err := os.Stat(p)
	if err != nil {
		slog.Debug("ownership: cannot stat directory", "path", p, "err", err)
		return 0, 0, false
	}
	return statOwner(info)
}

// chown applies the ownership, skipping the syscall when it would change
// nothing. That skip is what keeps the warnings honest on mounts which
// synthesise ownership and then refuse the call: there every output already
// reads as correctly owned, and without the check each one would warn about a
// correction it never needed.
//
// os.Chown and not os.Lchown: a stub path that is a symlink was written THROUGH
// by os.WriteFile, so the file whose ownership is wrong is the target.
func chown(path string, uid, gid int) {
	info, err := os.Stat(path)
	if err != nil {
		slog.Warn("ownership: cannot stat output", "path", path, "err", err)
		return
	}
	if curUID, curGID, ok := statOwner(info); ok && curUID == uid && curGID == gid {
		return
	}
	if err := chownFile(path, uid, gid); err != nil {
		slog.Warn("ownership: cannot hand output to the owner of its directory",
			"path", path, "uid", uid, "gid", gid, "err", err)
	}
}
