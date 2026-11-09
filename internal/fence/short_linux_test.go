//go:build linux

package fence

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

const (
	bigUID  = 4294967295                        // the longest uid a refusal names, as an owner
	ourUID  = 4294967294                        // and as this process's
	longest = "broker.directory.bind.krb5_conf" // the longest what a caller passes (internal/directory/conn.go)
	pathLen = 260                               // the issue's long path (#60)
)

// deepDir makes a directory, mode 0755, such that name inside it is a path of
// exactly n bytes, built from components of at most 50 bytes so its parents
// are long too.
func deepDir(t *testing.T, n int, name string) string {
	t.Helper()
	dir := safeDir(t)
	for {
		rest := n - len(dir) - 1 - len(name) // bytes still to add, each component with its slash
		if rest == 0 {
			return dir
		}
		if rest < 2 {
			t.Fatalf("TMPDIR %s is too long for a %d-byte path", os.TempDir(), n)
		}
		k := min(rest-1, 50)
		if rest-1-k == 1 {
			k-- // never leave one byte, which no component can fill
		}
		dir = filepath.Join(dir, strings.Repeat("d", k))
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

// ownedBy makes the fence see this process as ourUID, every inode as
// ourUID's, and the inode at path as bigUID's: an owner refusal with the
// longest values, as root or not.
func ownedBy(t *testing.T, path string) {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	ino := fi.Sys().(*syscall.Stat_t).Ino
	owner, euid := FileOwner, Geteuid
	t.Cleanup(func() { FileOwner, Geteuid = owner, euid })
	Geteuid = func() int { return ourUID }
	FileOwner = func(fi fs.FileInfo) (uint32, bool) {
		if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Ino == ino {
			return bigUID, true
		}
		return ourUID, true
	}
}

func chmodT(t *testing.T, p string, m fs.FileMode) {
	t.Helper()
	if err := os.Chmod(p, m); err != nil {
		t.Fatal(err)
	}
}

// policyFile writes minimalPolicy at p and gives it perm, whatever the umask.
func policyFile(t *testing.T, p string, perm fs.FileMode) string {
	t.Helper()
	if err := os.WriteFile(p, []byte(minimalPolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	chmodT(t, p, perm)
	return p
}

func symlinkT(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

// Every refusal the fence words itself has a Short that keeps the check that
// failed, the value seen and the one wanted, the remedy and each path's tail,
// within shortMax, at a 260-byte path with the longest uids and names a
// caller gives. Its Error still names each path whole, and errors.Is and
// errors.As see through it as before: only the link refusal wraps an error
// (#60).
func TestEveryFenceRefusalHasAShortFormThatKeepsItsCause(t *testing.T) {
	defer func(f func(*os.File) (bool, error)) { ReadOnlyFS = f }(ReadOnlyFS)
	ReadOnlyFS = func(*os.File) (bool, error) { return false, nil }
	deepFile := func(t *testing.T, name string) string { return filepath.Join(deepDir(t, pathLen, name), name) }
	const linkCase = "a link in the file's own name"
	for _, c := range []struct {
		name  string
		build func(t *testing.T) ([]string, error)
		wants []string
	}{
		{"file owner", func(t *testing.T) ([]string, error) {
			p := policyFile(t, deepFile(t, "policy.yaml"), 0o600)
			ownedBy(t, p)
			_, err := Read(p, maxPolicySize, "policy file")
			return []string{p}, err
		}, []string{"the file …", ": owner uid 4294967295, wants uid 4294967294 or root - chown it"}},
		{"file mode", func(t *testing.T) ([]string, error) {
			p := policyFile(t, deepFile(t, "policy.yaml"), 0o666)
			_, err := Read(p, maxPolicySize, "policy file")
			return []string{p}, err
		}, []string{"the file …", ": mode -rw-rw-rw-, wants no group or other write - chmod go-w it"}},
		{"directory mode", func(t *testing.T) ([]string, error) {
			p := policyFile(t, deepFile(t, "policy.yaml"), 0o600)
			chmodT(t, filepath.Dir(p), 0o777|fs.ModeSticky) // sticky (os.Chmod ignores a literal 0o1000): the ancestor walk excuses it, the holding directory's rule does not
			_, err := Read(p, maxPolicySize, "policy file")
			return []string{filepath.Dir(p)}, err
		}, []string{"the directory …", ": mode drwxrwxrwx (sticky), wants no group or other write - chmod go-w it"}},
		{"directory, asked by CheckDir", func(t *testing.T) ([]string, error) {
			p := policyFile(t, deepFile(t, "policy.yaml"), 0o600)
			chmodT(t, filepath.Dir(p), 0o777|fs.ModeSticky)
			return []string{filepath.Dir(p)}, CheckDir(p, "revocations file")
		}, []string{"the directory …", ", holding the revocations file: mode drwxrwxrwx (sticky), wants no group or other write - chmod go-w it"}},
		{"ancestor mode", func(t *testing.T) ([]string, error) {
			p := policyFile(t, deepFile(t, "policy.yaml"), 0o600)
			mid := filepath.Dir(filepath.Dir(p))
			chmodT(t, mid, 0o777)
			_, err := Read(p, maxPolicySize, "policy file")
			return []string{mid, p}, err
		}, []string{"the directory …", " above …", ": mode drwxrwxrwx, wants no group or other write - chmod go-w it, or move the file out from under it"}},
		{"ancestor owner", func(t *testing.T) ([]string, error) {
			p := policyFile(t, deepFile(t, "policy.yaml"), 0o600)
			mid := filepath.Dir(filepath.Dir(p))
			ownedBy(t, mid)
			_, err := Read(p, maxPolicySize, "policy file")
			return []string{mid, p}, err
		}, []string{"the directory …", " above …", ": owner uid 4294967295, wants uid 4294967294 or root - chown it"}},
		{"directory holding a link, mode", func(t *testing.T) ([]string, error) {
			real := policyFile(t, filepath.Join(safeDir(t), "policy.yaml"), 0o600)
			open := deepDir(t, pathLen-len("/policy.yaml"), "etc")
			symlinkT(t, filepath.Dir(real), filepath.Join(open, "etc"))
			chmodT(t, open, 0o777|fs.ModeSticky) // a link's directory is never excused by the sticky bit
			_, err := Read(filepath.Join(open, "etc", "policy.yaml"), maxPolicySize, "policy file")
			return []string{open, filepath.Join(open, "etc")}, err
		}, []string{"the directory …", " holding the link …", ": mode drwxrwxrwx (sticky), wants no group or other write - chmod go-w it"}},
		{"directory holding a link, owner", func(t *testing.T) ([]string, error) {
			real := policyFile(t, filepath.Join(safeDir(t), "policy.yaml"), 0o600)
			open := deepDir(t, pathLen-len("/policy.yaml"), "etc")
			symlinkT(t, filepath.Dir(real), filepath.Join(open, "etc"))
			ownedBy(t, open)
			_, err := Read(filepath.Join(open, "etc", "policy.yaml"), maxPolicySize, "policy file")
			return []string{open, filepath.Join(open, "etc")}, err
		}, []string{" holding the link …", ": owner uid 4294967295, wants uid 4294967294 or root - chown it"}},
		{"more than 40 links", func(t *testing.T) ([]string, error) {
			dir := deepDir(t, pathLen, "l0")
			policyFile(t, filepath.Join(dir, "policy.yaml"), 0o600)
			for i := 0; i <= maxLinks; i++ { // l0 -> l1 -> ... -> l40 -> policy.yaml: 41 links
				target := "l" + strconv.Itoa(i+1)
				if i == maxLinks {
					target = "policy.yaml"
				}
				symlinkT(t, target, filepath.Join(dir, "l"+strconv.Itoa(i)))
			}
			p := filepath.Join(dir, "l0")
			_, err := Read(p, maxPolicySize, "policy file")
			return []string{p}, err
		}, []string{"the path …", ": more than 40 symbolic links, wants at most 40 - shorten the chain"}},
		{"not a regular file", func(t *testing.T) ([]string, error) {
			p := deepFile(t, "policy.yaml")
			if err := syscall.Mkfifo(p, 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := Read(p, maxPolicySize, longest)
			return []string{p}, err
		}, []string{"the path …", ": a named pipe, wants a regular file - put the " + longest + " itself there"}},
		{"over the size bound", func(t *testing.T) ([]string, error) {
			p := policyFile(t, deepFile(t, "policy.yaml"), 0o600)
			if err := os.Truncate(p, maxInventorySize+1); err != nil {
				t.Fatal(err)
			}
			_, err := Read(p, maxInventorySize, longest)
			return []string{p}, err
		}, []string{"the file …", ": larger than 67108864 bytes, the most a " + longest + " may be - restore it"}},
		{linkCase, func(t *testing.T) ([]string, error) {
			real := policyFile(t, filepath.Join(safeDir(t), "policy.yaml"), 0o600)
			p := deepFile(t, "policy.yaml")
			symlinkT(t, real, p)
			_, err := ReadNoLink(p, maxPolicySize, longest)
			return []string{p}, err
		}, []string{"the file …", ": a symbolic link, wants the " + longest + " itself - put the file in place of the link"}},
		{"secret file owner", func(t *testing.T) ([]string, error) {
			p := policyFile(t, deepFile(t, "k1"), 0o600)
			ownedBy(t, p)
			_, err := ReadSecret(p, filepath.Dir(p), 1<<10)
			return []string{p}, err
		}, []string{"the secret file …", ": owner uid 4294967295, wants uid 4294967294 or root - chown it"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			paths, err := c.build(t)
			var r *Refusal
			if !errors.As(err, &r) {
				t.Fatalf("not a Refusal: %v", err)
			}
			short := Brief(err)
			if short != r.Short() {
				t.Errorf("Brief of a bare refusal is not its Short: %q", short)
			}
			if len(short) > shortMax {
				t.Errorf("%d bytes, past %d: %s", len(short), shortMax, short)
			}
			for _, w := range c.wants {
				if !strings.Contains(short, w) {
					t.Errorf("want %q: %s", w, short)
				}
			}
			for _, p := range paths {
				if len(p) <= 2*shortPathMax {
					t.Fatalf("the case's path is short: %s", p)
				}
				if !strings.Contains(err.Error(), p) {
					t.Errorf("the full text does not name %s whole: %v", p, err)
				}
				if !strings.Contains(short, "…"+p[len(p)-shortPathMax:]) {
					t.Errorf("%s is not named by its tail: %s", p, short)
				}
			}
			var pe *fs.PathError
			if link := c.name == linkCase; errors.Is(err, syscall.ELOOP) != link || errors.As(err, &pe) != link {
				t.Errorf("errors.Is ELOOP %v, errors.As PathError %v, want both %v", errors.Is(err, syscall.ELOOP),
					errors.As(err, &pe), link)
			}
		})
	}
}

// A start error and a log line still name every path whole, in the words
// they had (#60).
func TestTheFullTextOfARefusalIsUnchanged(t *testing.T) {
	p := policyAt(t, 0o666, 0o700)
	_, err := Read(p, maxPolicySize, "policy file")
	if want := "the file " + p + " is mode -rw-rw-rw-, writable by others than its owner; whoever can write it " +
		"decides who gets access - chmod go-w it"; err == nil || err.Error() != want {
		t.Errorf("mode: %v\nwant %s", err, want)
	}
	chmodT(t, p, 0o600)
	ownedBy(t, p)
	_, err = Read(p, maxPolicySize, "policy file")
	if want := fmt.Sprintf("the file %s is owned by uid %d; whoever can write it decides who gets access, so it "+
		"must belong to the user this process runs as (uid %d) or to root - chown it", p, bigUID, ourUID); err == nil ||
		err.Error() != want {
		t.Errorf("owner: %v\nwant %s", err, want)
	}
}

// The rest of the fence's own texts, byte for byte, in the words they had
// before a Refusal carried them (#60).
func TestTheFullTextOfEveryOtherRefusalIsUnchanged(t *testing.T) {
	defer func(f func(*os.File) (bool, error)) { ReadOnlyFS = f }(ReadOnlyFS)
	ReadOnlyFS = func(*os.File) (bool, error) { return false, nil }
	modeText := func(what, mode, advice string) string {
		return what + " is mode " + mode + ", writable by others than its owner; whoever can write it " +
			"decides who gets access - " + advice
	}
	ownerText := func(what string) string {
		return fmt.Sprintf("%s is owned by uid %d; whoever can write it decides who gets access, so it "+
			"must belong to the user this process runs as (uid %d) or to root - chown it", what, bigUID, ourUID)
	}
	check := func(t *testing.T, err error, want string) {
		t.Helper()
		if err == nil || err.Error() != want {
			t.Errorf("got  %v\nwant %s", err, want)
		}
	}
	t.Run("directory mode", func(t *testing.T) {
		p := policyAt(t, 0o600, 0o700)
		chmodT(t, filepath.Dir(p), 0o777|fs.ModeSticky)
		_, err := Read(p, maxPolicySize, "policy file")
		check(t, err, modeText("the directory "+filepath.Dir(p), "drwxrwxrwx (sticky)", "chmod go-w it"))
	})
	t.Run("CheckDir", func(t *testing.T) {
		p := policyAt(t, 0o600, 0o700)
		chmodT(t, filepath.Dir(p), 0o777)
		check(t, CheckDir(p, "revocations file"),
			modeText("the directory "+filepath.Dir(p)+", holding the revocations file", "drwxrwxrwx", "chmod go-w it"))
	})
	t.Run("ancestor mode", func(t *testing.T) {
		p := policyAt(t, 0o600, 0o700)
		mid := filepath.Dir(filepath.Dir(p))
		chmodT(t, mid, 0o777)
		_, err := Read(p, maxPolicySize, "policy file")
		check(t, err, modeText("the directory "+mid+" (above "+p+")", "drwxrwxrwx", fmt.Sprintf("chmod go-w it, or, if "+
			"others share it, move the file under directories only root or uid %d can write", Geteuid())))
	})
	t.Run("ancestor owner", func(t *testing.T) {
		p := policyAt(t, 0o600, 0o700)
		mid := filepath.Dir(filepath.Dir(p))
		ownedBy(t, mid)
		_, err := Read(p, maxPolicySize, "policy file")
		check(t, err, ownerText("the directory "+mid+" (above "+p+")"))
	})
	t.Run("directory holding a link", func(t *testing.T) {
		real := policyFile(t, filepath.Join(safeDir(t), "policy.yaml"), 0o600)
		open := safeDir(t)
		symlinkT(t, filepath.Dir(real), filepath.Join(open, "etc"))
		chmodT(t, open, 0o777)
		_, err := Read(filepath.Join(open, "etc", "policy.yaml"), maxPolicySize, "policy file")
		check(t, err, modeText("the directory "+open+", holding the symbolic link "+filepath.Join(open, "etc"),
			"drwxrwxrwx", "chmod go-w it"))
		chmodT(t, open, 0o755)
		ownedBy(t, open)
		_, err = Read(filepath.Join(open, "etc", "policy.yaml"), maxPolicySize, "policy file")
		check(t, err, ownerText("the directory "+open+", holding the symbolic link "+filepath.Join(open, "etc")))
	})
	t.Run("more than 40 links", func(t *testing.T) {
		dir := safeDir(t)
		policyFile(t, filepath.Join(dir, "policy.yaml"), 0o600)
		for i := 0; i <= maxLinks; i++ {
			target := "l" + strconv.Itoa(i+1)
			if i == maxLinks {
				target = "policy.yaml"
			}
			symlinkT(t, target, filepath.Join(dir, "l"+strconv.Itoa(i)))
		}
		p := filepath.Join(dir, "l0")
		_, err := Read(p, maxPolicySize, "policy file")
		check(t, err, fmt.Sprintf("%s passes through more than %d symbolic links", p, maxLinks))
	})
	t.Run("not a regular file", func(t *testing.T) {
		p := filepath.Join(safeDir(t), "pipe")
		if err := syscall.Mkfifo(p, 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := Read(p, maxPolicySize, "policy file")
		check(t, err, p+" is not a regular file")
	})
	t.Run("over the size bound", func(t *testing.T) {
		p := policyAt(t, 0o600, 0o700)
		_, err := Read(p, 3, "inventory file")
		check(t, err, fmt.Sprintf("%s is larger than 3 bytes; it is not an inventory file", p))
		_, err = Read(p, 3, "policy file")
		check(t, err, fmt.Sprintf("%s is larger than 3 bytes; it is not a policy file", p))
	})
	t.Run("a link in the file's own name", func(t *testing.T) {
		real := policyFile(t, filepath.Join(safeDir(t), "policy.yaml"), 0o600)
		dir := safeDir(t)
		p := filepath.Join(dir, "policy.yaml")
		symlinkT(t, real, p)
		_, err := ReadNoLink(p, maxPolicySize, "inventory file")
		if want := p + " is a symbolic link; an inventory file is read only as a file of its own: open " + p +
			": too many levels of symbolic links"; err == nil || err.Error() != want {
			t.Errorf("got  %v\nwant %s", err, want)
		}
	})
	t.Run("secret file owner", func(t *testing.T) {
		p := policyFile(t, filepath.Join(safeDir(t), "k1"), 0o600)
		ownedBy(t, p)
		_, err := ReadSecret(p, filepath.Dir(p), 1<<10)
		check(t, err, ownerText("the secret file "+p))
	})
	t.Run("no owner", func(t *testing.T) {
		p := policyAt(t, 0o600, 0o700)
		defer func(f func(fs.FileInfo) (uint32, bool)) { FileOwner = f }(FileOwner)
		FileOwner = func(fi fs.FileInfo) (uint32, bool) { return 0, !fi.Mode().IsRegular() }
		_, err := Read(p, maxPolicySize, "policy file")
		check(t, err, "the file "+p+": cannot read its owner")
	})
}
