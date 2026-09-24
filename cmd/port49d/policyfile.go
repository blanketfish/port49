//go:build linux

package main

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// maxPolicySize bounds the read, as keyfile's is bounded: a policy file is
// kilobytes, and a link aimed at a multi-gigabyte file must not be read into
// memory at every poll.
const maxPolicySize = 1 << 20

// maxLinks is how many symbolic links the path may pass through, Linux's own
// limit for a path lookup: a ConfigMap uses two.
const maxLinks = 40

// oPath is Linux's O_PATH, which package syscall does not name: a directory
// opened with it can be fstatted and opened relative to with no read
// permission on it, only search, as a plain open of the file needs.
const oPath = 0x200000

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
// policy as a chain of them. Whoever can write the directory holding a link
// can re-point it at any file that passes — a root-owned policy.yaml.bak from
// before a grant was withdrawn — so the directory holding every link the path
// passes through, the configured name's own and any standing for a directory
// included, is held to the same rule (resolvePolicyPath). The directory
// holding the final target is then opened, without following a link in its
// place, and the file is opened relative to that descriptor, without following
// one either; both checks are fstats of the descriptors, and the bytes come
// from the file descriptor checked. A rename after the checks changes nothing
// that was checked or read. Directories above those are not walked; keep the
// policy where only root can rename its directory.
//
// It is opened non-blocking, so a named pipe is refused rather than hanging a
// start or a reload until something writes to it, and read to at most
// maxPolicySize.
func readPolicyFile(path string) ([]byte, error) {
	target, err := resolvePolicyPath(path)
	if err != nil {
		return nil, err
	}
	dir, base := filepath.Dir(target), filepath.Base(target)
	d, di, err := openDir(dir)
	if err != nil {
		return nil, err
	}
	defer d.Close()
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
	raw, err := io.ReadAll(io.LimitReader(f, maxPolicySize+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxPolicySize {
		return nil, fmt.Errorf("%s is larger than %d bytes; it is not a policy file", target, maxPolicySize)
	}
	return raw, nil
}

// resolvePolicyPath follows path one component at a time to the name with no
// link left in it, and refuses it if the directory holding any link on the way
// is not writableByUsAlone. A link standing for a directory counts: its
// directory's owner can re-point it as surely as a link to the file.
func resolvePolicyPath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	pending := strings.Split(abs, "/")
	resolved := "/"
	links := 0
	checked := map[string]bool{}
	for len(pending) > 0 {
		comp := pending[0]
		pending = pending[1:]
		switch comp {
		case "", ".":
			continue
		case "..":
			resolved = filepath.Dir(resolved) // resolved holds no link, so this is its parent
			continue
		}
		next := filepath.Join(resolved, comp)
		fi, err := os.Lstat(next)
		if err != nil {
			return "", err
		}
		if fi.Mode()&fs.ModeSymlink == 0 {
			resolved = next
			continue
		}
		if links++; links > maxLinks {
			return "", fmt.Errorf("%s passes through more than %d symbolic links", path, maxLinks)
		}
		if !checked[resolved] {
			d, di, err := openDir(resolved)
			if err != nil {
				return "", err
			}
			d.Close()
			if err := writableByUsAlone("the directory "+resolved+", holding the symbolic link "+next, di); err != nil {
				return "", err
			}
			checked[resolved] = true
		}
		target, err := os.Readlink(next)
		if err != nil {
			return "", err
		}
		if filepath.IsAbs(target) {
			resolved = "/"
		}
		pending = append(strings.Split(target, "/"), pending...)
	}
	return resolved, nil
}

// openDir opens dir for fstat and openat alone, without following a link in
// its place, and returns what the descriptor says of it.
func openDir(dir string) (*os.File, fs.FileInfo, error) {
	d, err := os.OpenFile(dir, oPath|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	di, err := d.Stat()
	if err != nil {
		d.Close()
		return nil, nil, err
	}
	return d, di, nil
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
