package sdtest

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
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
	acl := "no"
	if hasACL(path) {
		acl = "yes"
	}
	return fmt.Sprintf("owner %s mode %s acl=%s", owner, fi.Mode().String(), acl)
}
