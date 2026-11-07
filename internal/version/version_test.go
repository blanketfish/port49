package version_test

import (
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/blanketfish/port49/internal/version"
)

const stamp = "v0.0.0-test"

func TestLineNamesTheBinaryAndTheVersion(t *testing.T) {
	if got, want := version.Line("port49d"), "port49d "+version.Version; got != want {
		t.Errorf("Line = %q, want %q", got, want)
	}
	if version.Version == "" {
		t.Error("Version is empty; an unstamped build says dev")
	}
}

// Every shipped binary, built the way the release and the Makefile build it, answers --version
// with its name and the stamped version, exit 0, before it reads any config.
func TestEveryBinaryPrintsItsVersion(t *testing.T) {
	if testing.Short() {
		t.Skip("builds five binaries")
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	ld := "-X github.com/blanketfish/port49/internal/version.Version=" + stamp
	dir := t.TempDir()
	type build struct {
		name, cmd string
		tags      []string
		args      [][]string
	}
	builds := []build{
		{"port49d", "port49d", nil, [][]string{{"--version"}}},
		{"port49-broker", "port49-broker", nil, [][]string{{"--version"}}},
		{"port49-inventory", "port49-inventory", nil, [][]string{{"--version"}}},
		{"port49", "port49", nil, [][]string{{"--version"}, {"version"}}},
		{"port49", "port49", []string{"-tags", "hwkey_dlopen"}, [][]string{{"--version"}, {"version"}}},
	}
	for i, b := range builds {
		bin := filepath.Join(dir, b.name+string(rune('a'+i)))
		args := append([]string{"build", "-ldflags", ld}, b.tags...)
		args = append(args, "-o", bin, "./cmd/"+b.cmd)
		cmd := exec.Command("go", args...)
		cmd.Dir = root
		cmd.Env = append(cmd.Environ(), "CGO_ENABLED=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build %s %v: %v\n%s", b.cmd, b.tags, err, out)
		}
		for _, a := range b.args {
			// Run from an empty directory with no config: the flag must not read one.
			run := exec.Command(bin, a...)
			run.Dir = t.TempDir()
			var stderr []byte
			out, err := run.Output()
			if ee, ok := err.(*exec.ExitError); ok {
				stderr = ee.Stderr
			}
			if err != nil {
				t.Errorf("%s %v %v: %v\n%s", b.name, b.tags, a, err, stderr)
				continue
			}
			if want := b.name + " " + stamp + "\n"; string(out) != want {
				t.Errorf("%s %v %v printed %q, want %q", b.name, b.tags, a, out, want)
			}
		}
	}
}
