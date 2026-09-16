package ownership

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// The ownership correction itself only happens as root, and the test binary
// almost never is. What CAN be pinned without root is the half that decides
// WHICH paths get touched — and that half is where the damage would be, since
// re-owning a directory the user created is worse than leaving one alone.

func TestMissingLevelsIsEmptyForAnExistingDirectory(t *testing.T) {
	dir := t.TempDir()
	if got := missingLevels(dir); len(got) != 0 {
		t.Fatalf("existing directory reported as missing: %v", got)
	}
}

func TestMissingLevelsIsOutermostFirst(t *testing.T) {
	root := t.TempDir()
	deep := filepath.Join(root, "wit", "deps", "pkg")

	want := []string{
		filepath.Join(root, "wit"),
		filepath.Join(root, "wit", "deps"),
		deep,
	}
	got := missingLevels(deep)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("missingLevels(%q):\n got %v\nwant %v", deep, got, want)
	}

	// The order is the contract: created[0]'s PARENT is the nearest
	// pre-existing ancestor, and that is the directory whose owner every
	// created level inherits. Reversed, the inherited owner would be read off a
	// directory this process had just created — which is root, the very answer
	// the package exists to avoid.
	if parent := filepath.Dir(got[0]); parent != root {
		t.Fatalf("parent of the outermost missing level = %q, want the pre-existing %q", parent, root)
	}
}

func TestMissingLevelsStopsAtAnExistingAncestor(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	got := missingLevels(filepath.Join(root, "src", "generated"))
	want := []string{filepath.Join(root, "src", "generated")}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestMissingLevelsToleratesAnEmptyPath(t *testing.T) {
	if got := missingLevels(""); got != nil {
		t.Fatalf("got %v, want nil", got)
	}
}

// MkdirAll must remain a drop-in for os.MkdirAll: the ownership pass is an
// addition, never a change to what ends up on disk.
func TestMkdirAllCreatesTheTreeAndIsIdempotent(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "a", "b", "c")
	for i := range 2 {
		if err := MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
		info, err := os.Stat(dir)
		if err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
		if !info.IsDir() {
			t.Fatalf("call %d: not a directory", i)
		}
	}
}

func TestMkdirAllReportsFailure(t *testing.T) {
	file := filepath.Join(t.TempDir(), "notadir")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := MkdirAll(filepath.Join(file, "child"), 0o755); err == nil {
		t.Fatal("reported success for a directory under a regular file")
	}
}

// The stdout sentinel and the empty path name nothing on disk. Fix must not
// stat them, let alone warn about them.
func TestFixIgnoresPathsThatOwnNothing(t *testing.T) {
	Fix("-")
	Fix("")
}

func TestFixIsHarmlessForAMissingPath(t *testing.T) {
	Fix(filepath.Join(t.TempDir(), "never-written"))
}

// Below root, every entry point must leave the filesystem exactly as it found
// it — this is what makes an ordinary `regexped` run, and a container run with
// an explicit --user, byte-for-byte the behaviour it had before the package
// existed.
func TestNothingIsTouchedWhenNotRoot(t *testing.T) {
	if enabled() {
		t.Skip("running as root; this test pins the non-root no-op")
	}
	dir := t.TempDir()
	file := filepath.Join(dir, "out.wasm")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	beforeUID, beforeGID, ok := statOwner(before)
	if !ok {
		t.Skip("no Unix ownership on this platform")
	}

	Fix(file)

	after, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	afterUID, afterGID, _ := statOwner(after)
	if beforeUID != afterUID || beforeGID != afterGID {
		t.Fatalf("ownership changed while not root: %d:%d -> %d:%d",
			beforeUID, beforeGID, afterUID, afterGID)
	}
}

// The root path, for the rare run that has it — a container, or a CI job that
// happens to be uid 0. It is the only check that the correction WORKS rather
// than merely that it is skipped.
func TestRootHandsOutputToTheOwnerOfItsDirectory(t *testing.T) {
	if !enabled() {
		t.Skip("not root; the correction only applies to a root process")
	}
	dir := t.TempDir()
	// A uid that is certainly not root, so "unchanged" cannot pass for
	// "corrected".
	const wantUID, wantGID = 65534, 65534
	if err := os.Chown(dir, wantUID, wantGID); err != nil {
		t.Skipf("cannot set up a non-root directory owner: %v", err)
	}

	file := filepath.Join(dir, "out.wasm")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	Fix(file)

	info, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	uid, gid, ok := statOwner(info)
	if !ok {
		t.Skip("no Unix ownership on this platform")
	}
	if uid != wantUID || gid != wantGID {
		t.Fatalf("output owned by %d:%d, want the directory's %d:%d", uid, gid, wantUID, wantGID)
	}
}

func TestRootGivesCreatedDirectoriesTheAncestorsOwner(t *testing.T) {
	if !enabled() {
		t.Skip("not root; the correction only applies to a root process")
	}
	root := t.TempDir()
	const wantUID, wantGID = 65534, 65534
	if err := os.Chown(root, wantUID, wantGID); err != nil {
		t.Skipf("cannot set up a non-root directory owner: %v", err)
	}

	deep := filepath.Join(root, "wit", "deps")
	if err := MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{filepath.Join(root, "wit"), deep} {
		info, err := os.Stat(d)
		if err != nil {
			t.Fatal(err)
		}
		uid, gid, ok := statOwner(info)
		if !ok {
			t.Skip("no Unix ownership on this platform")
		}
		if uid != wantUID || gid != wantGID {
			t.Fatalf("%s owned by %d:%d, want the ancestor's %d:%d", d, uid, gid, wantUID, wantGID)
		}
	}
}

// ---------------------------------------------------------------------------
// The root half, through the seams. These pin the DECISION — which paths get
// corrected, and to whose uid and gid — which is the part that can be wrong.
// TestRootHandsOutputToTheOwnerOfItsDirectory above still drives the real
// syscall whenever the suite genuinely runs as uid 0.

type chownCall struct {
	path     string
	uid, gid int
}

// The uid/gid the stubbed directory owner reports. Neither is the test user, so
// "corrected" cannot be confused with "left alone".
const stubUID, stubGID = 4242, 4343

// asRoot makes the package believe it is root, gives every directory a known
// owner, and captures the chowns that result, in order.
func asRoot(t *testing.T) *[]chownCall {
	t.Helper()
	var calls []chownCall
	oldRoot, oldChown, oldOwner := isRootProcess, chownFile, dirOwner
	isRootProcess = func() bool { return true }
	dirOwner = func(string) (int, int, bool) { return stubUID, stubGID, true }
	chownFile = func(path string, uid, gid int) error {
		calls = append(calls, chownCall{path, uid, gid})
		return nil
	}
	t.Cleanup(func() { isRootProcess, chownFile, dirOwner = oldRoot, oldChown, oldOwner })
	return &calls
}

func TestFixHandsTheOutputToTheOwnerOfItsDirectory(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "out.wasm")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	calls := asRoot(t)

	Fix(file)

	want := []chownCall{{file, stubUID, stubGID}}
	if !reflect.DeepEqual(*calls, want) {
		t.Fatalf("got %v, want %v", *calls, want)
	}
}

// The syscall is skipped when it would change nothing. That skip is what keeps
// the warnings honest on mounts which synthesise ownership and then refuse the
// call: there every output already reads as correctly owned.
func TestFixSkipsAFileThatIsAlreadyCorrectlyOwned(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "out.wasm")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	uid, gid, ok := statOwner(info)
	if !ok {
		t.Skip("no Unix ownership on this platform")
	}

	calls := asRoot(t)
	dirOwner = func(string) (int, int, bool) { return uid, gid, true } // already ours

	Fix(file)

	if len(*calls) != 0 {
		t.Fatalf("chowned a file that was already correctly owned: %v", *calls)
	}
}

func TestMkdirAllCorrectsEveryLevelItCreated(t *testing.T) {
	root := t.TempDir()
	calls := asRoot(t)

	deep := filepath.Join(root, "wit", "deps")
	if err := MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}

	// Both created levels, outermost first, each handed the PRE-EXISTING
	// ancestor's owner — never that of a directory this call had just made.
	want := []chownCall{
		{filepath.Join(root, "wit"), stubUID, stubGID},
		{deep, stubUID, stubGID},
	}
	if !reflect.DeepEqual(*calls, want) {
		t.Fatalf("got %v, want %v", *calls, want)
	}
}

func TestMkdirAllLeavesAPreExistingDirectoryAlone(t *testing.T) {
	dir := t.TempDir()
	calls := asRoot(t)

	if err := MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 0 {
		t.Fatalf("re-owned a directory it did not create: %v", *calls)
	}
}

// A chown that cannot be performed is warned about and survived: the output is
// correct, and a build must not fail over the ownership bit.
func TestAFailedChownIsNotFatal(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "out.wasm")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	asRoot(t)
	chownFile = func(string, int, int) error { return os.ErrPermission }

	Fix(file) // must return, not panic and not propagate
}

// A directory whose owner cannot be read leaves the output alone rather than
// inventing one.
func TestAnUnreadableDirectoryLeavesTheOutputAlone(t *testing.T) {
	calls := asRoot(t)
	dirOwner = func(string) (int, int, bool) { return 0, 0, false }

	Fix(filepath.Join(t.TempDir(), "out.wasm"))

	if len(*calls) != 0 {
		t.Fatalf("chowned without knowing the directory's owner: %v", *calls)
	}
}

// Fix stats the path itself before deciding, so a path that is not there warns
// and stops rather than chowning something that does not exist.
func TestFixOnAMissingFileDoesNotChown(t *testing.T) {
	calls := asRoot(t)

	Fix(filepath.Join(t.TempDir(), "never-written"))

	if len(*calls) != 0 {
		t.Fatalf("chowned a file that was never written: %v", *calls)
	}
}

// ownerOf is what dirOwner stands in for everywhere above; this is the one test
// that exercises the real thing.
func TestOwnerOfReadsARealDirectory(t *testing.T) {
	dir := t.TempDir()
	uid, gid, ok := ownerOf(dir)
	if !ok {
		t.Skip("no Unix ownership on this platform")
	}
	if uid != os.Getuid() || gid != os.Getgid() {
		t.Fatalf("t.TempDir() owned by %d:%d, want this process's %d:%d",
			uid, gid, os.Getuid(), os.Getgid())
	}
	if _, _, ok := ownerOf(filepath.Join(dir, "absent")); ok {
		t.Fatal("reported an owner for a path that does not exist")
	}
}

// The directories still get made when their owner cannot be read: the tree is
// the job, the ownership is the correction, and losing the second must never
// cost the first.
func TestMkdirAllStillCreatesTheTreeWhenTheOwnerIsUnreadable(t *testing.T) {
	root := t.TempDir()
	calls := asRoot(t)
	dirOwner = func(string) (int, int, bool) { return 0, 0, false }

	deep := filepath.Join(root, "wit", "deps")
	if err := MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(deep); err != nil || !info.IsDir() {
		t.Fatalf("directory not created: %v", err)
	}
	if len(*calls) != 0 {
		t.Fatalf("chowned without knowing the ancestor's owner: %v", *calls)
	}
}

// ---------------------------------------------------------------------------
// The two defensive branches. Neither is reached by any ordinary call, which is
// precisely why they need pinning: an unreached branch is one nothing would
// notice breaking.

// fileInfoWithoutOwnership is what a FileInfo looks like on a filesystem that
// carries no Unix uid/gid. os.Stat never produces one on Linux, so the branch
// that handles it has to be driven directly.
type fileInfoWithoutOwnership struct{ os.FileInfo }

func (fileInfoWithoutOwnership) Sys() any { return nil }

func TestStatOwnerRefusesAFileInfoWithoutUnixOwnership(t *testing.T) {
	real, err := os.Stat(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ok := statOwner(real); !ok {
		t.Skip("no Unix ownership on this platform")
	}

	uid, gid, ok := statOwner(fileInfoWithoutOwnership{real})
	if ok {
		t.Fatalf("claimed ownership %d:%d from a FileInfo that carries none", uid, gid)
	}
	if uid != 0 || gid != 0 {
		t.Fatalf("returned %d:%d alongside ok=false, want the zero pair", uid, gid)
	}
}

// The walk is bounded by the path's own depth, so it terminates on any input
// without needing a same-parent guard. These pin that bound, including the two
// idempotent tops it must not spin on and must not report.
func TestMissingLevelsTerminatesOnTopLevelPaths(t *testing.T) {
	for _, dir := range []string{"/", ".", string(filepath.Separator)} {
		if got := missingLevels(dir); len(got) != 0 {
			t.Fatalf("missingLevels(%q) = %v, want none — a top level is never creatable", dir, got)
		}
	}
}

func TestMissingLevelsNeverReportsTheTop(t *testing.T) {
	// An absolute path whose every named level is absent still stops at "/",
	// and a relative one stops before ".": neither is a directory MkdirAll
	// could create, so neither belongs in the list.
	abs := missingLevels("/nonexistent-abcdef/wit/deps")
	want := []string{"/nonexistent-abcdef", "/nonexistent-abcdef/wit", "/nonexistent-abcdef/wit/deps"}
	if !reflect.DeepEqual(abs, want) {
		t.Fatalf("absolute: got %v, want %v", abs, want)
	}

	t.Chdir(t.TempDir())
	rel := missingLevels(filepath.Join("wit", "deps"))
	wantRel := []string{"wit", filepath.Join("wit", "deps")}
	if !reflect.DeepEqual(rel, wantRel) {
		t.Fatalf("relative: got %v, want %v", rel, wantRel)
	}
}
