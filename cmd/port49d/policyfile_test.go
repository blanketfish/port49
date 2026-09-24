package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// policyAt writes a policy file with mode perm in a fresh directory of mode
// dirPerm, and returns its path.
func policyAt(t *testing.T, perm, dirPerm os.FileMode) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "etc")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(minimalPolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	// Chmod, not the create mode: the umask would narrow that.
	if err := os.Chmod(path, perm); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, dirPerm); err != nil {
		t.Fatal(err)
	}
	return path
}

// Whoever can write the policy decides every operator's access (spec
// §5.1.3), so a file or a directory anyone but port49d's user could write is
// refused, naming what to fix.
func TestAPolicyFileOthersCouldWriteIsRefused(t *testing.T) {
	for name, c := range map[string]struct {
		perm, dirPerm os.FileMode
		want          string
	}{
		"group-writable file":      {0o620, 0o755, "the file"},
		"world-writable file":      {0o602, 0o755, "the file"},
		"group-writable directory": {0o644, 0o775, "the directory"},
		"world-writable directory": {0o644, 0o1777, "the directory"},
	} {
		path := policyAt(t, c.perm, c.dirPerm)
		if _, err := readPolicyFile(path); err == nil || !strings.Contains(err.Error(), c.want) ||
			!strings.Contains(err.Error(), "chmod go-w") {
			t.Errorf("%s: %v", name, err)
		}
	}
	if raw, err := readPolicyFile(policyAt(t, 0o644, 0o755)); err != nil || string(raw) != minimalPolicy {
		t.Fatalf("a file only its owner can write is read: %v", err)
	}
}

// A file owned by neither port49d's user nor root is refused.
func TestAPolicyFileAnotherUserOwnsIsRefused(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("as root every file is owned by an accepted uid")
	}
	defer func(f func() int) { geteuid = f }(geteuid)
	geteuid = func() int { return os.Geteuid() + 1 }
	if _, err := readPolicyFile(policyAt(t, 0o600, 0o700)); err == nil || !strings.Contains(err.Error(), "chown it") {
		t.Fatalf("%v", err)
	}
}

// A symlink is followed, and the target and its directory are what is
// checked: a ConfigMap's chain of links to a safe file passes, and a link to
// a file others could write does not.
func TestAPolicySymlinkIsJudgedByItsTarget(t *testing.T) {
	link := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.Symlink(policyAt(t, 0o644, 0o755), link); err != nil {
		t.Fatal(err)
	}
	if _, err := readPolicyFile(link); err != nil {
		t.Fatalf("a link to a safe file is read: %v", err)
	}
	unsafe := filepath.Join(t.TempDir(), "policy.yaml")
	target := policyAt(t, 0o666, 0o755)
	if err := os.Symlink(target, unsafe); err != nil {
		t.Fatal(err)
	}
	if _, err := readPolicyFile(unsafe); err == nil || !strings.Contains(err.Error(), target) {
		t.Fatalf("a link to a world-writable file names the target: %v", err)
	}
}

// At start an unsafe policy file refuses the start, as a policy that does not
// load does, naming the config key and the file.
func TestAnUnsafePolicyFileRefusesTheStart(t *testing.T) {
	cfg := brokerConfig(t, minimalPolicy)
	if err := os.Chmod(cfg.Broker.PolicyFile, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := buildWith(cfg); err == nil || !strings.Contains(err.Error(), "broker.policy_file "+cfg.Broker.PolicyFile) ||
		!strings.Contains(err.Error(), "writable by others") {
		t.Fatalf("%v", err)
	}
}

// A directory owned by neither port49d's user nor root is refused even when
// the file in it is safe: its owner can chmod it and replace the file. No
// second uid exists to own one in a test, so the owner lookup is swapped for
// directories alone.
func TestAPolicyDirectoryAnotherUserOwnsIsRefused(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("as root every file is owned by an accepted uid")
	}
	defer func(f func(fs.FileInfo) (uint32, bool)) { fileOwner = f }(fileOwner)
	real := fileOwner
	fileOwner = func(fi fs.FileInfo) (uint32, bool) {
		if fi.IsDir() {
			return uint32(os.Geteuid() + 1), true
		}
		return real(fi)
	}
	path := policyAt(t, 0o600, 0o700)
	if _, err := readPolicyFile(path); err == nil || !strings.Contains(err.Error(), "the directory "+filepath.Dir(path)) ||
		!strings.Contains(err.Error(), "chown it") {
		t.Fatalf("%v", err)
	}
}
