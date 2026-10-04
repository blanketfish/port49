//go:build linux

package port49d

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rhwendt/port49/internal/fence"
)

// init runs as the revocations directory's owner, port49d's user, or not
// at all: a root-run init would leave 0600 files port49d cannot read, and
// the first start would fail on "permission denied" (pre-flight I5). The
// refusal names the owner and the sudo line, and nothing is written; it
// never chowns. It is asked before the fence, whose own refusal would say
// "chown it".
func TestInitRevocationsRunsAsTheDirectorysOwner(t *testing.T) {
	path := filepath.Join(safeDir(t), "revocations.json")
	defer func(f func() int) { fence.Geteuid = f }(fence.Geteuid)
	fence.Geteuid = func() int { return os.Geteuid() + 1 }
	_, err := initRevocations(path, testInitConfig)
	if err == nil || !strings.Contains(err.Error(), "e.g. sudo -u ") ||
		!strings.Contains(err.Error(), " port49d init-revocations --config "+testInitConfig) ||
		strings.Contains(err.Error(), "chown") {
		t.Fatalf("%v", err)
	}
	for _, p := range []string{path, markerOf(path)} {
		if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("a refused init wrote %s", p)
		}
	}
}

// A directory root owns, asked by another user, is most often a bare mount
// point whose volume did not mount, and never one a port49d not running as
// root can keep the file in: the refusal names the mount and the owner the
// directory needs, never "sudo -u root", and writes nothing (task 2 review
// I1).
func TestInitRevocationsOverARootOwnedDirectoryNamesTheMount(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("needs a uid other than root to ask as")
	}
	path := filepath.Join(safeDir(t), "revocations.json")
	defer func(f func(fs.FileInfo) (uint32, bool)) { fence.FileOwner = f }(fence.FileOwner)
	fence.FileOwner = func(fs.FileInfo) (uint32, bool) { return 0, true }
	_, err := initRevocations(path, testInitConfig)
	if err == nil || !strings.Contains(err.Error(), "belongs to root") ||
		!strings.Contains(err.Error(), "if a volume should be mounted there, it is not; mount it") ||
		!strings.Contains(err.Error(), "must belong to the user port49d runs as") ||
		!strings.Contains(err.Error(), "--config "+testInitConfig) ||
		strings.Contains(err.Error(), "sudo -u root") || strings.Contains(err.Error(), "chown") {
		t.Fatalf("%v", err)
	}
	for _, p := range []string{path, markerOf(path)} {
		if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("a refused init wrote %s", p)
		}
	}
}
