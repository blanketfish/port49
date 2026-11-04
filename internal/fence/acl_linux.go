package fence

import (
	"encoding/binary"
	"errors"
	"fmt"
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
// unknown tag or a permission past rwx is an error: an ACL this does not understand is refused,
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
			name, remove = "user:"+strconv.Itoa(int(e.id)), "u:"+strconv.Itoa(int(e.id))
		case aclGroup:
			name, remove = "group:"+strconv.Itoa(int(e.id)), "g:"+strconv.Itoa(int(e.id))
		case aclGroupObj:
			name, remove = "group::", "g::"
		case aclOther:
			name, remove = "other::", "o::"
		default:
			continue
		}
		entry := fmt.Sprintf("%s:%s", name, aclPerm(e.perm))
		if e.perm&aclWrite != 0 {
			return fmt.Errorf("carries the ACL entry %s: write on a secret is for its owner alone - remove it with setfacl -x %s on the file", entry, remove)
		}
		if e.perm == 0 {
			continue
		}
		switch e.tag {
		case aclUser:
			if e.id != euid && e.id != 0 {
				return fmt.Errorf("carries the ACL entry %s, a user that is neither this process's (uid %d) nor root; it could read the secret too - remove it with setfacl -x %s on the file", entry, euid, remove)
			}
		case aclGroup:
			if !groupOurs(e.id) {
				return fmt.Errorf("carries the ACL entry %s, a group this process is not in; its members could read the secret too - remove it with setfacl -x %s on the file", entry, remove)
			}
		case aclGroupObj:
			if e.perm&aclRead != 0 && !groupOurs(owningGroup) {
				return fmt.Errorf("carries the ACL entry %s, and its owning group (gid %d) is not one this process is in; its members could read the secret too - chgrp the file to the service's group, or remove it with setfacl -x %s on the file", entry, owningGroup, remove)
			}
		case aclOther:
			return fmt.Errorf("carries the ACL entry %s: a secret is for no one but the service - remove it with setfacl -x %s on the file", entry, remove)
		}
	}
	return nil
}

// dirACLRefusal is the directory's: who could change the directory decides who gets the file, so
// an entry granting write to anyone but the process's user or root is refused.
func dirACLRefusal(entries []aclEntry, euid uint32, groupOurs func(uint32) bool) error {
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
			name, remove = "user:"+strconv.Itoa(int(e.id)), "u:"+strconv.Itoa(int(e.id))
		case aclGroup:
			name, remove = "group:"+strconv.Itoa(int(e.id)), "g:"+strconv.Itoa(int(e.id))
		case aclGroupObj:
			name, remove = "group::", "g::"
		case aclOther:
			name, remove = "other::", "o::"
		default:
			continue
		}
		return fmt.Errorf("carries the ACL entry %s:%s, which lets others than its owner write it; whoever can write it decides who gets access - remove it with setfacl -x %s on the directory", name, aclPerm(e.perm), remove)
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
		if errors.Is(err, unix.ERANGE) {
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

// readDirACL is readACL for a directory held open with O_PATH, which fgetxattr refuses: it asks
// for the descriptor's own /proc/self/fd entry, which names the same inode whatever is renamed.
func readDirACL(d *os.File) ([]aclEntry, bool, error) {
	path := "/proc/self/fd/" + strconv.Itoa(int(d.Fd()))
	es, has, err := fetchACL(func(dest []byte) (int, error) { return unix.Getxattr(path, aclXattr, dest) })
	if err != nil && errors.Is(err, syscall.ENOENT) {
		err = fmt.Errorf("%w (is /proc mounted?)", err)
	}
	return es, has, err
}
