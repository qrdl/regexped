//go:build unix

package ownership

import (
	"os"
	"syscall"
)

// statOwner reads the uid and gid out of a FileInfo. syscall.Stat_t is the
// Unix-only shape, which is why this sits behind a build tag rather than in
// ownership.go — the type does not exist on Windows and its absence is a
// COMPILE error there, not a runtime one.
func statOwner(info os.FileInfo) (uid, gid int, ok bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return int(st.Uid), int(st.Gid), true
}
