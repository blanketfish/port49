//go:build linux

package port49d

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/blanketfish/port49/internal/printsafe"
	"github.com/blanketfish/port49/internal/store"
)

// deepEnrollDir makes a private directory such that name inside it is a path
// of exactly n bytes, in components of at most 50 bytes.
func deepEnrollDir(t *testing.T, n int, name string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
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

// A fence refusal at Open is lost in the fence's short words, which the
// broker's 300-byte cut leaves whole at a 260-byte path (#60). The cases are
// the store's directory, a link at its path, and more than 40 links on the
// way to it.
func TestAnEnrollmentFileRefusedAtOpenIsLostWithinTheCut(t *testing.T) {
	for _, c := range []struct {
		name  string
		path  func(t *testing.T) string
		wants []string
	}{
		{"its directory", func(t *testing.T) string {
			dir := deepEnrollDir(t, 260, "enrollments.json")
			if err := os.Chmod(dir, os.ModeSticky|0o777); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(dir, "enrollments.json")
		}, []string{"the directory …", ", holding the enrollments file: mode drwxrwxrwx (sticky), wants no group or other write - chmod go-w it"}},
		{"a link at its path", func(t *testing.T) string {
			dir := deepEnrollDir(t, 260, "enrollments.json")
			real := filepath.Join(dir, "real.json")
			if err := os.WriteFile(real, []byte("{}"), 0o600); err != nil {
				t.Fatal(err)
			}
			p := filepath.Join(dir, "enrollments.json")
			if err := os.Symlink(real, p); err != nil {
				t.Fatal(err)
			}
			return p
		}, []string{"the file …", "/enrollments.json: a symbolic link, wants the enrollments file itself - put the file in place of the link"}},
		{"more than 40 links on the way", func(t *testing.T) string {
			dir := deepEnrollDir(t, 260-len("/enrollments.json"), "l0")
			if err := os.Mkdir(filepath.Join(dir, "real"), 0o700); err != nil {
				t.Fatal(err)
			}
			for i := 0; i <= 40; i++ { // l0 -> ... -> l40 -> real: 41 links
				target := "l" + strconv.Itoa(i+1)
				if i == 40 {
					target = "real"
				}
				if err := os.Symlink(target, filepath.Join(dir, "l"+strconv.Itoa(i))); err != nil {
					t.Fatal(err)
				}
			}
			return filepath.Join(dir, "l0", "enrollments.json")
		}, []string{"the path …", ": more than 40 symbolic links, wants at most 40 - shorten the chain"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := openEnrollmentFile(c.path(t), signInTestKeys, nil)
			if !errors.Is(err, store.ErrEnrollmentStoreLost) {
				t.Fatalf("not lost: %v", err)
			}
			said := printsafe.Line(err.Error(), 300) // as Broker.CheckEnrollmentStore cuts it
			if said != err.Error() {
				t.Errorf("%d bytes, cut: %s", len(err.Error()), said)
			}
			if strings.Count(said, "enrollments.json") > 1 {
				t.Errorf("the path twice: %s", said)
			}
			for _, w := range c.wants {
				if !strings.Contains(said, w) {
					t.Errorf("want %q: %s", w, said)
				}
			}
		})
	}
}
