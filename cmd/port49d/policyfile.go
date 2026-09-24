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

// fileOwner is the uid owning what fi describes, swapped in tests for the same
// reason: no second uid exists to own a directory holding a file we own.
var fileOwner = func(fi fs.FileInfo) (uint32, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Uid, true
}

// readPolicyFile reads broker.policy_file, refusing a file anyone but the user
// port49d runs as, or root, could have written (spec §5.1.3). port49d reloads
// the file live (plan 4b), so whoever can write it decides every operator's
// access within seconds: neither the file nor its directory may be group- or
// world-writable, and both must be owned by port49d's user or by root — the
// directory's owner could chmod it and replace the file. It is keyfile's rule
// for a private key, for writing rather than reading.
//
// A symlink is followed, unlike keyfile's: a Kubernetes ConfigMap mounts the
// policy as a chain of them. What is checked is what is read. The directory
// holding the final target is opened, without following a link in its place,
// and the file is opened relative to that descriptor, without following one
// either; both checks are fstats of the descriptors, and the bytes come from
// the file descriptor checked. A rename after the checks changes nothing that
// was checked or read. The directories above that one are not walked; keep
// the policy where only root can rename its directory.
//
// It is opened non-blocking, so a named pipe is refused rather than hanging a
// start or a reload until something writes to it.
func readPolicyFile(path string) ([]byte, error) {
	target, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, err
	}
	dir, base := filepath.Dir(target), filepath.Base(target)
	d, err := os.OpenFile(dir, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer d.Close()
	di, err := d.Stat()
	if err != nil {
		return nil, err
	}
	fd, err := syscall.Openat(int(d.Fd()), base, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: target, Err: err}
	}
	f := os.NewFile(uintptr(fd), target)
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
	if err := writableByUsAlone("the directory "+dir, di); err != nil {
		return nil, err
	}
	return io.ReadAll(f)
}

// writableByUsAlone refuses what port49d's user or root is not the only one
// able to write.
func writableByUsAlone(what string, fi fs.FileInfo) error {
	uid, ok := fileOwner(fi)
	if !ok {
		return fmt.Errorf("%s: cannot read its owner", what)
	}
	if euid := geteuid(); uid != uint32(euid) && uid != 0 {
		return fmt.Errorf("%s is owned by uid %d; whoever can write the policy decides every operator's access, "+
			"so it must belong to the user port49d runs as (uid %d) or to root - chown it", what, uid, euid)
	}
	if perm := fi.Mode().Perm(); perm&0o022 != 0 {
		return fmt.Errorf("%s is mode %v, writable by others than its owner; whoever can write the policy "+
			"decides every operator's access - chmod go-w it", what, perm)
	}
	return nil
}
