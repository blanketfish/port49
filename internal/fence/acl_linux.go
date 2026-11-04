package fence

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

// A POSIX ACL changes what a file's mode says. With one, the mode's group bits are the ACL mask,
// not the owning group's permission, so the mode alone neither shows a named user who can read
// the file nor an owning group that cannot. ReadSecret therefore reads system.posix_acl_access
// (the Linux xattr: a u32 version 2, then 8-byte entries of u16 tag, u16 perm, u32 id, little
// endian) and decides from the entries themselves.
const (
	aclXattr = "system.posix_acl_access"

	aclUserObj  = 0x01
	aclUser     = 0x02
	aclGroupObj = 0x04
	aclGroup    = 0x08
	aclMask     = 0x10
	aclOther    = 0x20

	aclRead  = 4
	aclWrite = 2

	aclVersion = 2
)

type aclEntry struct {
	tag, perm uint16
	id        uint32
}

// parsePOSIXACL decodes the xattr. A wrong version, a length that is not whole entries, an
// unknown tag, a permission past rwx or a missing base entry is an error: an ACL this does not understand is refused,
// never read as empty.
func parsePOSIXACL(b []byte) ([]aclEntry, error) {
	if len(b) < 4 || binary.LittleEndian.Uint32(b) != aclVersion {
		return nil, errors.New("not a version 2 POSIX ACL")
	}
	b = b[4:]
	if len(b)%8 != 0 {
		return nil, errors.New("truncated POSIX ACL")
	}
	var es []aclEntry
	for ; len(b) > 0; b = b[8:] {
		e := aclEntry{binary.LittleEndian.Uint16(b), binary.LittleEndian.Uint16(b[2:]), binary.LittleEndian.Uint32(b[4:])}
		switch e.tag {
		case aclUserObj, aclUser, aclGroupObj, aclGroup, aclMask, aclOther:
		default:
			return nil, fmt.Errorf("unknown POSIX ACL tag %#x", e.tag)
		}
		if e.perm > 7 {
			return nil, fmt.Errorf("POSIX ACL permission %#x past rwx", e.perm)
		}
		es = append(es, e)
	}
	var obj, gobj, other, mask, named int
	for _, e := range es {
		switch e.tag {
		case aclUserObj:
			obj++
		case aclGroupObj:
			gobj++
		case aclOther:
			other++
		case aclMask:
			mask++
		default:
			named++
		}
	}
	if obj != 1 || gobj != 1 || other != 1 || mask > 1 || (named > 0 && mask != 1) {
		return nil, errors.New("POSIX ACL missing a required entry (user::, group::, other::, or mask:: beside named entries)")
	}
	return es, nil
}

func aclPerm(p uint16) string {
	s := []byte("---")
	for i, bit := range []uint16{aclRead, aclWrite, 1} {
		if p&bit != 0 {
			s[i] = "rwx"[i]
		}
	}
	return string(s)
}

// secretACLRefusal applies the secret file's rule to its ACL: only the process's user (euid) and
// root may be named, only groups it is in, nobody may write, and other has nothing; the owning
// group's own entry may read only if owningGroup is one of ours. The error names the entry by
// numeric id and the setfacl that removes it.
func secretACLRefusal(entries []aclEntry, euid, owningGroup uint32, groupOurs func(uint32) bool) error {
	for _, e := range entries {
		var name, remove string
		switch e.tag {
		case aclUser:
			name, remove = "user:"+strconv.Itoa(int(e.id)), "setfacl -x u:"+strconv.Itoa(int(e.id))
		case aclGroup:
			name, remove = "group:"+strconv.Itoa(int(e.id)), "setfacl -x g:"+strconv.Itoa(int(e.id))
		case aclGroupObj:
			name, remove = "group::", "setfacl -m g::-"
		case aclOther:
			name, remove = "other::", "setfacl -m o::-"
		default:
			continue
		}
		entry := fmt.Sprintf("%s:%s", name, aclPerm(e.perm))
		if e.perm&aclWrite != 0 {
			return fmt.Errorf("carries the ACL entry %s: write on a secret is for its owner alone - remove it with %s on the file (setfacl -b clears every extended entry)", entry, remove)
		}
		if e.perm == 0 {
			continue
		}
		switch e.tag {
		case aclUser:
			if e.id != euid && e.id != 0 {
				return fmt.Errorf("carries the ACL entry %s, a user that is neither this process's (uid %d) nor root; it could read the secret too - remove it with %s on the file (setfacl -b clears every extended entry)", entry, euid, remove)
			}
		case aclGroup:
			if !groupOurs(e.id) {
				return fmt.Errorf("carries the ACL entry %s, a group this process is not in; its members could read the secret too - remove it with %s on the file (setfacl -b clears every extended entry)", entry, remove)
			}
		case aclGroupObj:
			if e.perm&aclRead != 0 && !groupOurs(owningGroup) {
				return fmt.Errorf("carries the ACL entry %s, and its owning group (gid %d) is not one this process is in; its members could read the secret too - chgrp the file to the service's group, or remove it with %s on the file (setfacl -b clears every extended entry)", entry, owningGroup, remove)
			}
		case aclOther:
			return fmt.Errorf("carries the ACL entry %s: a secret is for no one but the service - remove it with %s on the file (setfacl -b clears every extended entry)", entry, remove)
		}
	}
	return nil
}

// dirACLRefusal is the directory's. Read entries are not its business, only write; an entry masked
// out of effect is refused too (the mask is the mode's group bits, which the mode rule judges
// separately), and the rule runs before ruling 11's sticky excuse, so a sticky directory whose extra
// writers come from ACL entries is refused. Whoever could change the directory decides who gets
// the file, so an entry granting write to anyone but the process's user or root is refused.
func dirACLRefusal(entries []aclEntry, euid uint32) error {
	for _, e := range entries {
		if e.perm&aclWrite == 0 {
			continue
		}
		var name, remove string
		switch e.tag {
		case aclUser:
			if e.id == euid || e.id == 0 {
				continue
			}
			name, remove = "user:"+strconv.Itoa(int(e.id)), "setfacl -x u:"+strconv.Itoa(int(e.id))
		case aclGroup:
			name, remove = "group:"+strconv.Itoa(int(e.id)), "setfacl -x g:"+strconv.Itoa(int(e.id))
		case aclGroupObj:
			name, remove = "group::", "setfacl -m g::-"
		case aclOther:
			name, remove = "other::", "setfacl -m o::-"
		default:
			continue
		}
		return fmt.Errorf("carries the ACL entry %s:%s, which lets others than its owner write it; whoever can write it decides who gets access - remove it with %s on the directory (setfacl -b clears every extended entry)", name, aclPerm(e.perm), remove)
	}
	return nil
}

// fetchACL asks get (an fgetxattr or getxattr) for the access ACL and parses it. No ACL, or a
// filesystem with none, is (nil, false, nil); any other failure, and an ACL that does not parse,
// is an error, since the file's mode alone is then not known to be the whole story.
func fetchACL(get func(dest []byte) (int, error)) ([]aclEntry, bool, error) {
	for range 3 {
		n, err := get(nil)
		if err != nil {
			if errors.Is(err, unix.ENODATA) || errors.Is(err, unix.ENOTSUP) {
				return nil, false, nil
			}
			return nil, false, fmt.Errorf("reading its POSIX ACL: %w", err)
		}
		buf := make([]byte, n)
		n, err = get(buf)
		if errors.Is(err, unix.ERANGE) || (err == nil && n > len(buf)) {
			continue // the ACL grew between the two calls
		}
		if err != nil {
			if errors.Is(err, unix.ENODATA) {
				return nil, false, nil
			}
			return nil, false, fmt.Errorf("reading its POSIX ACL: %w", err)
		}
		es, err := parsePOSIXACL(buf[:n])
		if err != nil {
			return nil, false, fmt.Errorf("its POSIX ACL is unreadable (%v), so what it grants is unknown", err)
		}
		return es, true, nil
	}
	return nil, false, errors.New("its POSIX ACL kept changing while it was read")
}

// readACL reads the open file f's access ACL, by its descriptor.
func readACL(f *os.File) ([]aclEntry, bool, error) {
	rc, err := f.SyscallConn()
	if err != nil {
		return nil, false, err
	}
	var es []aclEntry
	var has bool
	var ferr error
	if err := rc.Control(func(fd uintptr) {
		es, has, ferr = fetchACL(func(dest []byte) (int, error) { return unix.Fgetxattr(int(fd), aclXattr, dest) })
	}); err != nil {
		return nil, false, err
	}
	return es, has, ferr
}

// procSelfFd is where a descriptor's magic link lives, swapped in tests. It is the fallback only:
// a directory port49d may search but not read cannot be reopened, and then without /proc (a chroot,
// or RootDirectory= without API VFS) its ACL cannot be read and the secret is refused.
var procSelfFd = "/proc/self/fd"

// reopenDir opens the directory held as the O_PATH descriptor d for reading, relative to d itself
// ("." names the same inode whatever is renamed), without following a link. Swapped in tests.
var reopenDir = func(d *os.File) (*os.File, error) {
	fd, err := syscall.Openat(int(d.Fd()), ".", os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), d.Name()), nil
}

// readDirACL is readACL for a directory held open with O_PATH, which fgetxattr refuses. It reopens
// the directory with fgetxattr's kind of descriptor, and only when that is denied (EACCES: search
// without read) asks for the descriptor's /proc/self/fd entry. If both fail it refuses, naming why.
func readDirACL(d *os.File, di fs.FileInfo) ([]aclEntry, bool, error) {
	f, err := reopenDir(d)
	if err == nil {
		defer f.Close()
		fi, serr := f.Stat()
		if serr != nil {
			return nil, false, serr
		}
		a, ok1 := fi.Sys().(*syscall.Stat_t)
		b, ok2 := di.Sys().(*syscall.Stat_t)
		if !ok1 || !ok2 || a.Dev != b.Dev || a.Ino != b.Ino {
			return nil, false, errors.New("reopened as not the directory that was walked, so its POSIX ACL is not trusted")
		}
		return readACL(f)
	}
	if !errors.Is(err, syscall.EACCES) {
		return nil, false, fmt.Errorf("cannot be reopened to read its POSIX ACL: %w", err)
	}
	path := procSelfFd + "/" + strconv.Itoa(int(d.Fd()))
	es, has, perr := fetchACL(func(dest []byte) (int, error) { return unix.Getxattr(path, aclXattr, dest) })
	if perr != nil && errors.Is(perr, syscall.ENOENT) {
		perr = fmt.Errorf("it is searchable but not readable (%v), so its POSIX ACL is read through /proc, which is not mounted: %w", err, perr)
	}
	return es, has, perr
}
