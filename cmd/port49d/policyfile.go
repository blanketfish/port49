package main

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// geteuid is os.Geteuid, swapped in tests: CI has no second uid to own a file.
var geteuid = os.Geteuid

// readPolicyFile reads broker.policy_file, refusing a file anyone but the user
// port49d runs as, or root, could have written (spec §5.1.3). port49d reloads
// the file live (plan 4b), so whoever can write it decides every operator's
// access within seconds: the file must not be group- or world-writable, nor
// its directory, and the file must be owned by port49d's user or by root. It
// is keyfile's rule for a private key, for writing rather than reading.
//
// A symlink is followed, unlike keyfile's: a Kubernetes ConfigMap mounts the
// policy as a chain of them. What is checked is what is read — the final
// target, opened without following a link planted after the path was
// resolved, and the directory holding it, which is what decides who could
// replace it. The directories above that are not walked; keep the policy
// where only root can rename its directory.
//
// It is opened non-blocking, so a named pipe is refused rather than hanging a
// start or a reload until something writes to it.
func readPolicyFile(path string) ([]byte, error) {
	target, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(target, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", target)
	}
	if err := writableByUsAlone("the file "+target, fi); err != nil {
		return nil, err
	}
	dir := filepath.Dir(target)
	di, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	if err := writableByUsAlone("the directory "+dir, di); err != nil {
		return nil, err
	}
	return io.ReadAll(f)
}

// writableByUsAlone refuses what port49d's user or root is not the only one
// able to write.
func writableByUsAlone(what string, fi fs.FileInfo) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%s: cannot read its owner", what)
	}
	if euid := geteuid(); st.Uid != uint32(euid) && st.Uid != 0 {
		return fmt.Errorf("%s is owned by uid %d; whoever can write the policy decides every operator's access, "+
			"so it must belong to the user port49d runs as (uid %d) or to root - chown it", what, st.Uid, euid)
	}
	if perm := fi.Mode().Perm(); perm&0o022 != 0 {
		return fmt.Errorf("%s is mode %v, writable by others than its owner; whoever can write the policy "+
			"decides every operator's access - chmod go-w it", what, perm)
	}
	return nil
}
