//go:build !linux

package port49d

import "io/fs"

// ownerOf has no owner to read off Linux; the tests then skip the owner checks.
func ownerOf(fs.FileInfo) (uid, gid int, ok bool) { return 0, 0, false }
