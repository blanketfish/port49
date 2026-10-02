//go:build linux

package main

import (
	"errors"
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
	_, err := initRevocations(path)
	if err == nil || !strings.Contains(err.Error(), "e.g. sudo -u ") ||
		!strings.Contains(err.Error(), " port49d init-revocations") || strings.Contains(err.Error(), "chown") {
		t.Fatalf("%v", err)
	}
	for _, p := range []string{path, markerOf(path)} {
		if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("a refused init wrote %s", p)
		}
	}
}
