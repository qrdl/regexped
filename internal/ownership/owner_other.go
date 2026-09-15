//go:build !unix

package ownership

import "os"

// statOwner has no answer where files carry no Unix uid/gid. Unreachable in
// practice — enabled() is already false wherever os.Getuid returns -1 — but it
// is what keeps the package compiling for every GOOS.
func statOwner(os.FileInfo) (uid, gid int, ok bool) { return 0, 0, false }
