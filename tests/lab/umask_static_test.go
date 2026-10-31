package lab

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The daemons the lab starts read their trust files through the fence (decision 54 ruling 16), which
// refuses a directory others can write; t.TempDir takes the process umask, so on a lab host at 002 every
// daemon input is group-writable and the start is refused. Every package under tests/ with a lab-tagged
// test file therefore pins umask 022 in an init of its own (not an assumption about the host).
func TestEveryLabTaggedPackagePinsUmask022(t *testing.T) {
	const needle = "syscall.Umask(0o0" + "22)"
	tag := regexp.MustCompile(`(?m)^//go:build .*\blab\b`)
	labDirs := map[string]bool{}
	pinned := map[string]bool{}
	err := filepath.WalkDir("..", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if n := d.Name(); n == "logs" || n == "results" || n == "evidence" || n == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		dir := filepath.Dir(p)
		if tag.Match(b) {
			labDirs[dir] = true
		}
		if strings.Contains(string(b), needle) && !strings.HasSuffix(p, "umask_static_test.go") {
			pinned[dir] = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(labDirs) < 2 {
		t.Fatalf("found %d lab-tagged packages, want at least 2: the scan is broken", len(labDirs))
	}
	for dir := range labDirs {
		if !pinned[dir] {
			t.Errorf("%s has lab-tagged tests and no `syscall.Umask(0o022)` in an init of a _test.go file", dir)
		}
	}
}
