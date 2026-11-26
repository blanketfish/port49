package port49d

import (
	"io/fs"
	"syscall"
)

// ownerOf is the uid and gid owning what fi describes.
func ownerOf(fi fs.FileInfo) (uid, gid int, ok bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return int(st.Uid), int(st.Gid), true
}
