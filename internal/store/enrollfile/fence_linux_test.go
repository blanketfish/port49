//go:build linux

package enrollfile

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/blanketfish/port49/internal/fence"
	"github.com/blanketfish/port49/internal/printsafe"
	"github.com/blanketfish/port49/internal/store"
)

// deepStoreDir makes a private directory such that name inside it is a path
// of exactly n bytes, built from components of at most 50 bytes so its
// parents are long too.
func deepStoreDir(t *testing.T, n int, name string) string {
	t.Helper()
	dir := dirFor(t)
	for {
		rest := n - len(dir) - 1 - len(name)
		if rest == 0 {
			return dir
		}
		if rest < 2 {
			t.Fatalf("TMPDIR %s is too long for a %d-byte path", os.TempDir(), n)
		}
		k := min(rest-1, 50)
		if rest-1-k == 1 {
			k--
		}
		dir = filepath.Join(dir, strings.Repeat("d", k))
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
}

// fenceSees makes the fence see this process as uid 4294967294, every inode
// as its, and the inode at path as uid 4294967295's: an owner refusal with
// the longest values, as root or not.
func fenceSees(t *testing.T, path string) {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	ino := fi.Sys().(*syscall.Stat_t).Ino
	owner, euid := fence.FileOwner, fence.Geteuid
	t.Cleanup(func() { fence.FileOwner, fence.Geteuid = owner, euid })
	fence.Geteuid = func() int { return 4294967294 }
	fence.FileOwner = func(fi fs.FileInfo) (uint32, bool) {
		if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Ino == ino {
			return 4294967295, true
		}
		return 4294967294, true
	}
}

func chmodStore(t *testing.T, p string, m fs.FileMode) {
	t.Helper()
	if err := os.Chmod(p, m); err != nil {
		t.Fatal(err)
	}
}

// Every refusal the fence words itself reaches the broker's 300-byte cut
// whole, with the store's own words around it, at a 260-byte path and the
// longest uids. The reason keeps the check that failed, the value seen and
// the one wanted, and the remedy, and names the path once (#60). The late
// reason is the longest, so each case is found by a running handle. The
// file owner, the likeliest after a restore, is also found at start.
func TestAFenceRefusalReachesTheBrokersCutWhole(t *testing.T) {
	ctx := context.Background()
	cut := func(t *testing.T, err error, wants ...string) {
		t.Helper()
		if !errors.Is(err, store.ErrEnrollmentStoreLost) {
			t.Fatalf("not lost: %v", err)
		}
		said := printsafe.Line(err.Error(), 300) // as Broker.CheckEnrollmentStore cuts it
		if said != err.Error() {
			t.Errorf("%d bytes, cut: %s", len(err.Error()), said)
		}
		for _, w := range wants {
			if !strings.Contains(said, w) {
				t.Errorf("want %q: %s", w, said)
			}
		}
		if strings.Count(said, "enrollments.json") > 1 || strings.Contains(said, "cannot be read") {
			t.Errorf("the path twice, or the generic words: %s", said)
		}
	}
	const late = "; this broker looks again at its next recheck, with no restart"
	for _, c := range []struct {
		name  string
		after func(t *testing.T, path string) // makes the refusal once the handle is open
		wants []string
	}{
		{"file owner", func(t *testing.T, path string) { written(t, path, keys()); fenceSees(t, path) },
			[]string{"lost: the file …", "/enrollments.json: owner uid 4294967295, wants uid 4294967294 or root - chown it" + late}},
		{"file mode", func(t *testing.T, path string) { written(t, path, keys()); chmodStore(t, path, 0o666) },
			[]string{"lost: the file …", ": mode -rw-rw-rw-, wants no group or other write - chmod go-w it" + late}},
		{"directory mode", func(t *testing.T, path string) {
			written(t, path, keys())
			chmodStore(t, filepath.Dir(path), fs.ModeSticky|0o777)
		}, []string{"lost: the directory …", ": mode drwxrwxrwx (sticky), wants no group or other write - chmod go-w it" + late}},
		{"directory owner", func(t *testing.T, path string) {
			written(t, path, keys())
			fenceSees(t, filepath.Dir(path))
		}, []string{"lost: the directory …", ": owner uid 4294967295, wants uid 4294967294 or root - chown it" + late}},
		{"ancestor mode", func(t *testing.T, path string) {
			written(t, path, keys())
			chmodStore(t, filepath.Dir(filepath.Dir(path)), 0o777)
		}, []string{"lost: the directory …", " above …", ": mode drwxrwxrwx, wants no group or other write - chmod go-w it, " +
			"or move the file out from under it" + late}},
		{"ancestor owner", func(t *testing.T, path string) {
			written(t, path, keys())
			fenceSees(t, filepath.Dir(filepath.Dir(path)))
		}, []string{" above …", ": owner uid 4294967295, wants uid 4294967294 or root - chown it" + late}},
		{"not a regular file", func(t *testing.T, path string) {
			if err := syscall.Mkfifo(path, 0o600); err != nil {
				t.Fatal(err)
			}
		}, []string{"lost: the path …", ": a named pipe, wants a regular file - put the enrollments file itself there" + late}},
		{"over maxFile", func(t *testing.T, path string) {
			written(t, path, keys())
			if err := os.Truncate(path, maxFile+1); err != nil {
				t.Fatal(err)
			}
		}, []string{"lost: the file …", ": larger than 67108864 bytes, the most an enrollments file may be - restore it" + late}},
	} {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(deepStoreDir(t, 260, "enrollments.json"), "enrollments.json")
			running := openAt(t, path, keys())
			c.after(t, path)
			_, err := running.GetEnrollmentMark(ctx)
			cut(t, err, c.wants...)
		})
	}
	t.Run("file owner at start", func(t *testing.T) {
		path := filepath.Join(deepStoreDir(t, 260, "enrollments.json"), "enrollments.json")
		written(t, path, keys())
		fenceSees(t, path)
		_, err := openAt(t, path, keys()).GetEnrollmentMark(ctx)
		cut(t, err, "store: the enrollment store is lost: the file …",
			"/enrollments.json: owner uid 4294967295, wants uid 4294967294 or root - chown it")
		if strings.HasSuffix(err.Error(), late) {
			t.Errorf("a start reason says it looks again: %v", err)
		}
	})
}
