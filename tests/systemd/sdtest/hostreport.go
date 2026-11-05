package sdtest

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// Rendered reports whether the probe script's output (l84's cred_dir= and cred_file= lines) shows
// that systemd gave the unit both a credentials directory and the credential's file.
func Rendered(out string) bool {
	return strings.Contains(out, "cred_dir=yes") && strings.Contains(out, "cred_file=yes")
}

// UnitProperties is each key=value line of a unit file's [Service] section that a transient unit
// may take as -p, without the commands (Exec*), the restart policy (Restart*) and Type=: the
// shipped unit's shape, with the command replaced.
func UnitProperties(unit string) []string {
	var out []string
	in := false
	for _, l := range strings.Split(unit, "\n") {
		l = strings.TrimSpace(l)
		switch {
		case l == "" || strings.HasPrefix(l, "#"):
		case strings.HasPrefix(l, "["):
			in = l == "[Service]"
		case in:
			k, _, ok := strings.Cut(l, "=")
			if ok && !strings.HasPrefix(k, "Exec") && !strings.HasPrefix(k, "Restart") && k != "Type" {
				out = append(out, l)
			}
		}
	}
	return out
}

// Category is the harness's name for a refusal, from the product's own words in msg; "other" when
// msg holds none. Only the category is recorded, never msg.
func Category(msg string) string {
	low := strings.ToLower(msg)
	for _, r := range Refusals {
		if r.Also == "" && strings.Contains(low, strings.ToLower(r.Phrase)) {
			return r.Category
		}
	}
	return "other"
}

// Report is what the host cell records about the credentials directory and file name: whether
// read (fence.ReadSecret in port49d's own call shape, within = the directory) accepts it, and each
// one's numeric owner:group, mode and whether it carries a POSIX ACL. It never holds the bytes.
func Report(dir, name string, read func(path, within string, max int64) ([]byte, error)) []string {
	out := []string{"CREDENTIALS_DIRECTORY=" + dir, fmt.Sprintf("process: uid=%d gid=%d", os.Getuid(), os.Getgid())}
	if _, err := read(filepath.Join(dir, name), dir, 4096); err != nil {
		out = append(out, "read: "+Category(err.Error()))
	} else {
		out = append(out, "read: ok")
	}
	for _, p := range []struct{ what, path string }{{"dir", dir}, {"file", filepath.Join(dir, name)}} {
		fi, err := os.Stat(p.path)
		if err != nil {
			out = append(out, p.what+": absent")
			continue
		}
		out = append(out, fmt.Sprintf("%s: %s", p.what, describe(fi, p.path)))
	}
	return out
}

func describe(fi fs.FileInfo, path string) string {
	owner := "?:?"
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		owner = fmt.Sprintf("%d:%d", st.Uid, st.Gid)
	}
	return fmt.Sprintf("owner %s mode %s acl=%s", owner, fi.Mode().String(), aclText(path))
}

// aclText is path's POSIX access ACL as FormatACL writes it, "none" when it has none and "unreadable"
// when the xattr is there and not understood. Only the entries are read, never the file.
func aclText(path string) string {
	raw, ok := accessACL(path)
	if !ok {
		return "none"
	}
	text, err := FormatACL(raw)
	if err != nil {
		return "unreadable (" + err.Error() + ")"
	}
	return text
}

// FormatACL writes the system.posix_acl_access xattr (a u32 version 2, then 8-byte little-endian
// entries of u16 tag, u16 perm, u32 id) as tag:id:perms with numeric ids, e.g.
// "user::r--, user:999:r--, group::---, mask::r--, other::---". The owner entries and mask carry no id.
func FormatACL(b []byte) (string, error) {
	if len(b) < 4 || binary.LittleEndian.Uint32(b) != 2 {
		return "", errors.New("not a version 2 POSIX ACL")
	}
	b = b[4:]
	if len(b)%8 != 0 {
		return "", errors.New("truncated POSIX ACL")
	}
	var out []string
	for ; len(b) > 0; b = b[8:] {
		tag, perm, id := binary.LittleEndian.Uint16(b), binary.LittleEndian.Uint16(b[2:]), binary.LittleEndian.Uint32(b[4:])
		name, named := map[uint16]string{1: "user", 2: "user", 4: "group", 8: "group", 0x10: "mask", 0x20: "other"}[tag], tag == 2 || tag == 8
		if name == "" || perm > 7 {
			return "", fmt.Errorf("unknown POSIX ACL entry (tag %#x, perm %#x)", tag, perm)
		}
		who := ""
		if named {
			who = strconv.FormatUint(uint64(id), 10)
		}
		p := []byte("---")
		for i, bit := range []uint16{4, 2, 1} {
			if perm&bit != 0 {
				p[i] = "rwx"[i]
			}
		}
		out = append(out, name+":"+who+":"+string(p))
	}
	return strings.Join(out, ", "), nil
}

// HostedRunner reports whether getenv describes a GitHub-hosted runner, the only machine
// TestL84Host may run on: it creates a system user, writes keys under /etc and installs units.
func HostedRunner(getenv func(string) string) bool {
	return getenv("GITHUB_ACTIONS") == "true" && getenv("RUNNER_ENVIRONMENT") == "github-hosted"
}
