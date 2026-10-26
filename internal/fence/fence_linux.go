//go:build linux

// Package fence reads a file that decides access within seconds of an edit —
// the policy file, the inventory file, the inventory service's file source,
// port49d's persisted bundle — only when nobody but the user port49 runs as,
// or root, could have written it (spec §5.1.3, §10). Read is port49d's policy
// file fence of plan 4b, moved here unchanged so both binaries read through it.
package fence

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// maxLinks is how many symbolic links the path may pass through, Linux's own
// limit for a path lookup: a ConfigMap uses two.
const maxLinks = 40

// oPath is Linux's O_PATH, which package syscall does not name: a directory
// opened with it can be fstatted and opened relative to with no read
// permission on it, only search, as a plain open of the file needs.
const oPath = 0x200000

// Geteuid is os.Geteuid, swapped in tests: CI has no second uid to own a file.
var Geteuid = os.Geteuid

// FileOwner is the uid owning what fi describes, swapped in tests for the same
// reason: no second uid exists to own a directory holding a file we own.
var FileOwner = func(fi fs.FileInfo) (uint32, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Uid, true
}

// stRdonly is ST_RDONLY in statfs's flags, which package syscall does not
// name.
const stRdonly = 0x1

// ReadOnlyFS reports whether the filesystem holding the open file f is
// mounted read-only, from fstatfs on the descriptor, never a path. Swapped in
// tests: CI has no read-only mount to hand.
var ReadOnlyFS = func(f *os.File) (bool, error) {
	var st syscall.Statfs_t
	if err := syscall.Fstatfs(int(f.Fd()), &st); err != nil {
		return false, err
	}
	return st.Flags&stRdonly != 0, nil
}

// Read reads path, refusing a file anyone but the user this process runs as,
// or root, could have written (spec §5.1.3). The file is reloaded live, so
// whoever can write it decides access within seconds: neither the file nor
// its directory may be group- or world-writable, and both must be owned by
// this process's user or by root — the directory's owner could chmod it and
// replace the file. It is keyfile's rule for a private key, for writing
// rather than reading.
//
// A symlink is followed, unlike keyfile's: a Kubernetes ConfigMap mounts the
// policy as a chain of them. Whoever can write the directory holding a link
// can re-point it at any file that passes — a root-owned policy.yaml.bak from
// before a grant was withdrawn — so the directory holding every link the path
// passes through, the configured name's own and any standing for a directory
// included, is held to the same rule (resolvePolicyPath). A link's directory
// has its mode excused on a read-only mount, which is how a ConfigMap passes
// (dirWritableByUsAlone); the directory holding the file never does. The
// directory holding the final target is then opened, without following a link
// in its place, and the file is opened relative to that descriptor, without
// following one either; both checks are fstats of the descriptors, and the
// bytes come from the file descriptor checked. A rename after the checks
// changes nothing that was checked or read. Directories above those are not
// walked; keep the file where only root can rename its directory.
//
// It is opened non-blocking, so a named pipe is refused rather than hanging a
// start or a reload until something writes to it, and read to at most max
// bytes, what naming the file in the size refusal.
func Read(path string, max int64, what string) ([]byte, error) {
	target, err := resolvePolicyPath(path)
	if err != nil {
		return nil, err
	}
	return readIn(filepath.Dir(target), filepath.Base(target), max, what)
}

// ReadSecret reads a secret file a `file:` reference names (spec §13
// decision 53 rulings 1 and 12). It is Read's fence with a reader's rule for
// the file. A link is followed, as a ConfigMap's is, and the file it comes to
// must lie inside within: a Kubernetes Secret or CSI volume's
// name -> ..data/name chain does, and a link to the TLS key or the keytab,
// outside the directory, is refused. Only the final, fully resolved target is
// tested against within; a chain that leaves the directory and comes back is
// read, which is safe because the directory holding every link on the way is
// held to the fence's rule by resolvePolicyPath (a writer who could plant the
// middle link is refused there). The ancestors of those directories are
// walked from Task 15 of plan 12a (decision 53 ruling 11), not by this
// function alone; until then keep the key directory where only root can
// rename its parents. The directory holding the file is held to Read's rule,
// never excused by a read-only mount, except for a sticky directory we or
// root own (secretDirWritableByUsAlone). within must be absolute, clean and
// not "/". The file must be owned by this process's user or root, writable by
// its owner alone, and carry no world bit: group-read is allowed, which
// fsGroup and an agent's perms = "0440" give. No error carries the file's
// bytes.
func ReadSecret(path, within string, max int64) ([]byte, error) {
	if !filepath.IsAbs(within) || filepath.Clean(within) != within {
		return nil, fmt.Errorf("%s: the directory a secret file must stay inside is not an absolute, clean path", path)
	}
	if within == "/" {
		return nil, fmt.Errorf("%s is outside the allowed directory: a secret file is kept in a directory of its "+
			"own, never directly under /", path)
	}
	target, err := resolvePolicyPath(path)
	if err != nil {
		return nil, err
	}
	w, err := resolvePolicyPath(within)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(target, w+"/") {
		return nil, fmt.Errorf("%s resolves to %s, outside %s: a secret file, and every link to it, stays "+
			"inside that directory", path, target, w)
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
	return readChecked(f, target, max, "secret file", func(fi fs.FileInfo) error {
		if err := ownedByUsOrRoot("the secret file "+target, fi); err != nil {
			return err
		}
		if perm := fi.Mode().Perm(); perm&0o027 != 0 {
			return fmt.Errorf("%s is mode %v: a secret file may be group-readable, never world-readable or "+
				"writable by anyone but its owner - chmod 0440 or 0600 it, or, on a mounted volume, set the "+
				"mode where it is rendered (Kubernetes defaultMode and fsGroup, Vault Agent's perms)", target, perm)
		}
		return secretDirWritableByUsAlone("the directory "+dir, di)
	})
}

// secretDirWritableByUsAlone is writableByUsAlone for the directory holding a
// secret file, with ruling 11's sticky excuse for a directory we or root own:
// the Vault Agent injector renders into a tmpfs emptyDir that is 01777. It is
// sound because the file itself must be owned by us or root, and under the
// sticky bit only the file's owner, the directory's owner or root can rename
// or unlink it; others can squat a name before the first render, which the
// file's owner check then refuses, never substitutes. The sticky bit is the
// inode's own mode, so the host sees it too, unlike a read-only bind, whose
// excuse is never extended here.
func secretDirWritableByUsAlone(what string, fi fs.FileInfo) error {
	if err := ownedByUsOrRoot(what, fi); err != nil {
		return err
	}
	if fi.Mode()&fs.ModeSticky != 0 {
		return nil
	}
	return notWritableByOthers(what, fi)
}

// ReadNoLink is Read for a file this process writes itself, whose own name is
// never a link: the inventory service's state, the trust anchor for its
// sequence. A link in its place is refused, not followed, so nobody can point
// published.json at an older, validly signed document elsewhere; links on the
// way to its directory are followed and fenced as Read's are.
func ReadNoLink(path string, max int64, what string) ([]byte, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	dir, err := resolvePolicyPath(filepath.Dir(abs))
	if err != nil {
		return nil, err
	}
	raw, err := readIn(dir, filepath.Base(abs), max, what)
	if errors.Is(err, syscall.ELOOP) {
		return nil, linkRefused(filepath.Join(dir, filepath.Base(abs)), what, err)
	}
	return raw, err
}

// CheckDir asks Read's question of the directory that holds, or will hold,
// path: it exists, every link on the way to it passes the fence, and it is
// writable by this process's user or root alone. It is asked whether or not
// the file is there, so a missing file in a directory others can write is
// refused rather than read as "nothing yet" (plan 7a, pre-flight C1).
func CheckDir(path, what string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	dir, err := resolvePolicyPath(filepath.Dir(abs))
	if err != nil {
		return err
	}
	d, di, err := openDir(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return writableByUsAlone("the directory "+dir+", holding the "+what, di)
}

// linkRefused is the refusal of a link in a file's own name, wrapping err so
// errors.Is(err, syscall.ELOOP) still holds.
func linkRefused(path, what string, err error) error {
	return fmt.Errorf("%s is a symbolic link; a%s %s is read only as a file of its own: %w", path, article(what),
		what, err)
}

// ReadSigned reads a file whose bytes a signature vouches for, from a shared
// mount the fence cannot hold to its owner rule: the inventory service's
// mirror. Only the shape is checked: its name is not a link (O_NOFOLLOW), it
// is a regular file, opened non-blocking, and at most max bytes are read.
func ReadSigned(path string, max int64, what string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if errors.Is(err, syscall.ELOOP) {
		return nil, linkRefused(path, what, err)
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readChecked(f, path, max, what, nil)
}

// readIn opens base in dir, following a link in neither place, and reads it
// if Read's rule holds of it and of dir.
func readIn(dir, base string, max int64, what string) ([]byte, error) {
	target := filepath.Join(dir, base)
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
	return readChecked(f, target, max, what, func(fi fs.FileInfo) error {
		if err := writableByUsAlone("the file "+target, fi); err != nil {
			return err
		}
		// The directory holding the file is never excused by a read-only
		// mount (dirWritableByUsAlone is for a link's directory alone): a
		// read-only bind of a host directory others can write is writable on
		// the host.
		return writableByUsAlone("the directory "+dir, di)
	})
}

// readChecked reads the open file f, named target, if it is a regular file
// that check (when set) passes, to at most max bytes.
func readChecked(f *os.File, target string, max int64, what string, check func(fs.FileInfo) error) ([]byte, error) {
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", target)
	}
	if check != nil {
		if err := check(fi); err != nil {
			return nil, err
		}
	}
	raw, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > max {
		return nil, fmt.Errorf("%s is larger than %d bytes; it is not a%s %s", target, max, article(what), what)
	}
	return raw, nil
}

// article is "n" before a word starting with a vowel, else "".
func article(word string) string {
	if word != "" && strings.ContainsRune("aeiou", rune(word[0])) {
		return "n"
	}
	return ""
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
			err = dirWritableByUsAlone("the directory "+resolved+", holding the symbolic link "+next, d, di)
			d.Close()
			if err != nil {
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

// writableByUsAlone refuses what this process's user or root is not the only one
// able to write.
func writableByUsAlone(what string, fi fs.FileInfo) error {
	if err := ownedByUsOrRoot(what, fi); err != nil {
		return err
	}
	return notWritableByOthers(what, fi)
}

// dirWritableByUsAlone is writableByUsAlone for a directory holding a link in
// the chain, open as d, whose mode is excused on a read-only mount. A
// Kubernetes ConfigMap or Secret volume's root holds the policy's two links at
// mode 0777 (01777, 02777 with fsGroup) and is mounted read-only: nobody in
// the pod, root included, can write it (tests/lab/results/configmap-mounts.md).
// The excuse trusts whoever writes the mount's source — the kubelet, for a
// ConfigMap — so it is never extended to the directory holding the file,
// where a read-only bind of a host directory others can write would let them
// rename a stale policy over it. Read-only is asked of the descriptor opened,
// not a path, and the owner is still checked.
func dirWritableByUsAlone(what string, d *os.File, fi fs.FileInfo) error {
	if err := ownedByUsOrRoot(what, fi); err != nil {
		return err
	}
	if err := notWritableByOthers(what, fi); err == nil {
		return nil
	} else if ro, rerr := ReadOnlyFS(d); rerr != nil || !ro {
		return err
	}
	return nil
}

func ownedByUsOrRoot(what string, fi fs.FileInfo) error {
	uid, ok := FileOwner(fi)
	if !ok {
		return fmt.Errorf("%s: cannot read its owner", what)
	}
	if euid := Geteuid(); uid != uint32(euid) && uid != 0 {
		return fmt.Errorf("%s is owned by uid %d; whoever can write it decides who gets access, "+
			"so it must belong to the user this process runs as (uid %d) or to root - chown it", what, uid, euid)
	}
	return nil
}

func notWritableByOthers(what string, fi fs.FileInfo) error {
	if perm := fi.Mode().Perm(); perm&0o022 != 0 {
		return fmt.Errorf("%s is mode %v, writable by others than its owner; whoever can write it "+
			"decides who gets access - chmod go-w it", what, perm)
	}
	return nil
}
