//go:build linux

package fence

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The package's seams are variables a test swaps. Production code never assigns one: only a _test.go
// file may, so a running binary has no path that loosens a check.
func TestNoProductionCodeAssignsASeam(t *testing.T) {
	assign := regexp.MustCompile(`\bfence\.(FileOwner|FileGroup|ReadOnlyFS|Geteuid|AfterResolve)\s*=[^=]`)
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	scanned := 0
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == ".worktrees" || d.Name() == "logs" || d.Name() == "node_modules") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		scanned++
		if m := assign.Find(b); m != nil {
			rel, _ := filepath.Rel(root, p)
			t.Errorf("%s assigns a test seam: %s", rel, m)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if scanned < 100 {
		t.Fatalf("scanned only %d Go files under %s", scanned, root)
	}
}
