//go:build linux

package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
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
	path := policyAt(t, 0o600, 0o700)
	if _, err := readPolicyFile(path); err == nil || !strings.Contains(err.Error(), "the file "+path) ||
		!strings.Contains(err.Error(), "chown it") {
		t.Fatalf("the refusal names the file: %v", err)
	}
}

// configMap lays a policy out as a Kubernetes ConfigMap volume does:
// dir/policy.yaml -> ..data/policy.yaml, ..data -> ..2026_09_24, and the
// file in that timestamped directory; directories 0755, the file 0644. It
// returns dir.
func configMap(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "policy")
	stamped := filepath.Join(dir, "..2026_09_24_07_00_00.123456789")
	if err := os.MkdirAll(stamped, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stamped, "policy.yaml"), []byte(minimalPolicy), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{dir, stamped} {
		if err := os.Chmod(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Base(stamped), filepath.Join(dir, "..data")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("..data/policy.yaml", filepath.Join(dir, "policy.yaml")); err != nil {
		t.Fatal(err)
	}
	return dir
}

// A ConfigMap's chain of links is followed, and every directory holding a
// link in it, or the file, passes when only its owner can write it.
func TestAConfigMapPolicyIsRead(t *testing.T) {
	raw, err := readPolicyFile(filepath.Join(configMap(t), "policy.yaml"))
	if err != nil || string(raw) != minimalPolicy {
		t.Fatalf("a ConfigMap layout is read: %v", err)
	}
}

// The directory holding every link in the chain is checked, not only the
// final target's: whoever can write a link's directory can re-point it at
// any file that passes, a root-owned policy.yaml.bak granting more included
// (final review I2). Here the configured link, a link half-way along, and a
// link standing for a directory each sit in a directory others can write.
func TestALinkInADirectoryOthersCanWriteIsRefused(t *testing.T) {
	open := func() string {
		d := filepath.Join(t.TempDir(), "open")
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(d, 0o777); err != nil {
			t.Fatal(err)
		}
		return d
	}
	safe := policyAt(t, 0o644, 0o755)

	configured := open()
	if err := os.Symlink(safe, filepath.Join(configured, "policy.yaml")); err != nil {
		t.Fatal(err)
	}

	midway := open()
	if err := os.Symlink(safe, filepath.Join(midway, "hop")); err != nil {
		t.Fatal(err)
	}
	first := filepath.Join(policyAt(t, 0o644, 0o755)+".d", "policy.yaml")
	if err := os.Mkdir(filepath.Dir(first), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(midway, "hop"), first); err != nil {
		t.Fatal(err)
	}

	dirLink := open()
	if err := os.Symlink(filepath.Dir(safe), filepath.Join(dirLink, "etc")); err != nil {
		t.Fatal(err)
	}

	for name, c := range map[string]struct{ path, dir string }{
		"the configured link":       {filepath.Join(configured, "policy.yaml"), configured},
		"a link half-way":           {first, midway},
		"a link standing for a dir": {filepath.Join(dirLink, "etc", "policy.yaml"), dirLink},
	} {
		if _, err := readPolicyFile(c.path); err == nil || !strings.Contains(err.Error(), "the directory "+c.dir) ||
			!strings.Contains(err.Error(), "chmod go-w") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A real ConfigMap or Secret mount root holds both links at mode 0777 (01777,
// 02777 with fsGroup) and is mounted read-only, so nobody in the pod can
// write it (tests/lab/results/configmap-mounts.md). A directory others could
// write by its mode is accepted when its filesystem is read-only, and only
// then; its owner must still be port49d's user or root.
func TestAWritableDirectoryOnAReadOnlyMountIsAccepted(t *testing.T) {
	dir := configMap(t) // the timestamped directory holding the file stays 0755, as measured
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "policy.yaml")
	defer func(f func(*os.File) (bool, error)) { readOnlyFS = f }(readOnlyFS)

	readOnlyFS = func(*os.File) (bool, error) { return false, nil }
	if _, err := readPolicyFile(path); err == nil || !strings.Contains(err.Error(), "chmod go-w") {
		t.Fatalf("a 0777 directory on a writable mount is refused: %v", err)
	}

	readOnlyFS = func(*os.File) (bool, error) { return true, nil }
	if raw, err := readPolicyFile(path); err != nil || string(raw) != minimalPolicy {
		t.Fatalf("a 0777 directory on a read-only mount is accepted: %v", err)
	}

	if os.Geteuid() != 0 {
		defer func(f func(fs.FileInfo) (uint32, bool)) { fileOwner = f }(fileOwner)
		real := fileOwner
		fileOwner = func(fi fs.FileInfo) (uint32, bool) {
			if fi.IsDir() {
				return uint32(os.Geteuid() + 1), true
			}
			return real(fi)
		}
		if _, err := readPolicyFile(path); err == nil || !strings.Contains(err.Error(), "chown it") {
			t.Fatalf("a read-only mount does not excuse another owner: %v", err)
		}
	}
}

// The directory holding the file itself is never excused, read-only or not.
// A read-only bind of a host directory others can write lets them rename a
// stale root-owned policy over the file on the host, which a read-only mount
// does not stop (re-review N1). A ConfigMap's file directory is root's 0755
// in every case measured, so it needs no excuse. Here a ConfigMap layout
// whose timestamped directory is 0777, and a plain bind of a 0777 directory,
// are both refused on a read-only mount.
func TestTheFilesOwnDirectoryIsNotExcusedByAReadOnlyMount(t *testing.T) {
	defer func(f func(*os.File) (bool, error)) { readOnlyFS = f }(readOnlyFS)
	readOnlyFS = func(*os.File) (bool, error) { return true, nil }

	dir := configMap(t)
	stamped := filepath.Join(dir, "..2026_09_24_07_00_00.123456789")
	for _, p := range []string{dir, stamped} {
		if err := os.Chmod(p, 0o777); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := readPolicyFile(filepath.Join(dir, "policy.yaml")); err == nil ||
		!strings.Contains(err.Error(), "the directory "+stamped) || !strings.Contains(err.Error(), "chmod go-w") {
		t.Fatalf("a ConfigMap whose file directory is 0777: %v", err)
	}

	bind := policyAt(t, 0o644, 0o777)
	if _, err := readPolicyFile(bind); err == nil || !strings.Contains(err.Error(), "the directory "+filepath.Dir(bind)) {
		t.Fatalf("a read-only bind of a 0777 host directory: %v", err)
	}
}

// A file others could write is refused even on a read-only mount: only a
// directory's mode is excused, and a ConfigMap's file is 0644 or narrower.
func TestAWritableFileOnAReadOnlyMountIsRefused(t *testing.T) {
	defer func(f func(*os.File) (bool, error)) { readOnlyFS = f }(readOnlyFS)
	readOnlyFS = func(*os.File) (bool, error) { return true, nil }
	if _, err := readPolicyFile(policyAt(t, 0o666, 0o755)); err == nil || !strings.Contains(err.Error(), "the file") {
		t.Fatalf("%v", err)
	}
}

// A chain of links that never ends is refused, not followed forever.
func TestALinkLoopIsRefused(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "etc")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("b", filepath.Join(dir, "a")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("a", filepath.Join(dir, "b")); err != nil {
		t.Fatal(err)
	}
	if _, err := readPolicyFile(filepath.Join(dir, "a")); err == nil || !strings.Contains(err.Error(), "links") {
		t.Fatalf("%v", err)
	}
}

// The read is capped, as keyfile's is: a link aimed at a multi-gigabyte file
// is not read into memory at every poll.
func TestAPolicyFileOverAMebibyteIsRefused(t *testing.T) {
	path := policyAt(t, 0o644, 0o755)
	if err := os.WriteFile(path, make([]byte, maxPolicySize+1), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readPolicyFile(path); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("%v", err)
	}
	if err := os.Truncate(path, maxPolicySize); err != nil {
		t.Fatal(err)
	}
	if raw, err := readPolicyFile(path); err != nil || len(raw) != maxPolicySize {
		t.Fatalf("a file of exactly the cap is read: %v", err)
	}
}

// A named pipe is refused at once, not waited on: a start or a reload that
// hung on one would hang until something wrote to it.
func TestANamedPipeIsRefused(t *testing.T) {
	path := policyAt(t, 0o644, 0o755)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readPolicyFile(path); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("%v", err)
	}
}

// Reading the file needs only search permission on its directory, as a plain
// open does: a non-root port49d with its policy in a directory it may search
// but not list is not refused "permission denied" on the directory.
func TestAPolicyInASearchOnlyDirectoryIsRead(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads every directory")
	}
	path := policyAt(t, 0o644, 0o111)
	t.Cleanup(func() { os.Chmod(filepath.Dir(path), 0o700) })
	if raw, err := readPolicyFile(path); err != nil || string(raw) != minimalPolicy {
		t.Fatalf("%v", err)
	}
}

// A refusal quotes what it found, and a policy file can hold anything a link
// aimed it at: every quoted value on the line is cut to 64 characters.
func TestARefusalQuotesAtMost64Characters(t *testing.T) {
	cfg := brokerConfig(t, minimalPolicy)
	long := strings.Repeat("x", 200)
	_, err := parseBundle(cfg, []byte(strings.Replace(minimalPolicy, "roles: [r]", "roles: ["+long+"]", 1)), cfg.Inventory)
	if err == nil {
		t.Fatal("a grant naming no role must not load")
	}
	if strings.Contains(err.Error(), strings.Repeat("x", 65)) || !strings.Contains(err.Error(), strings.Repeat("x", 64)) {
		t.Fatalf("the quoted role name is cut to 64 characters: %v", err)
	}
}

// A symlink is followed, and the target and its directory are what is
// checked: a link to a safe file, in a directory only its owner can write,
// passes, and a link to a file others could write does not.
func TestAPolicySymlinkIsJudgedByItsTarget(t *testing.T) {
	link := filepath.Join(safeDir(t), "policy.yaml")
	if err := os.Symlink(policyAt(t, 0o644, 0o755), link); err != nil {
		t.Fatal(err)
	}
	if _, err := readPolicyFile(link); err != nil {
		t.Fatalf("a link to a safe file is read: %v", err)
	}
	unsafe := filepath.Join(safeDir(t), "policy.yaml")
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

// C2: the inventory file is read behind the policy file's fence, with its
// own size bound.
func TestTheInventoryFileIsFenced(t *testing.T) {
	dir := safeDir(t)
	path := filepath.Join(dir, "inventory.yaml")
	if err := os.WriteFile(path, []byte("devices: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if raw, err := readInventoryFile(path); err != nil || string(raw) != "devices: []\n" {
		t.Fatalf("a private file: %q, %v", raw, err)
	}
	if err := os.Chmod(path, 0o664); err != nil {
		t.Fatal(err)
	}
	if _, err := readInventoryFile(path); err == nil || !strings.Contains(err.Error(), "the file "+path) {
		t.Fatalf("a group-writable file: %v", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(path, maxInventorySize+1); err != nil {
		t.Fatal(err)
	}
	if _, err := readInventoryFile(path); err == nil || !strings.Contains(err.Error(), "not an inventory file") {
		t.Fatalf("an oversized file: %v", err)
	}
}

// inventoryAt writes an inventory file with mode perm in a fresh directory
// of mode dirPerm, and returns its path.
func inventoryAt(t *testing.T, perm, dirPerm os.FileMode) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "etc")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "inventory.yaml")
	if err := os.WriteFile(path, []byte("devices: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, perm); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, dirPerm); err != nil {
		t.Fatal(err)
	}
	return path
}

// Every refusal the policy file has, the inventory file has: whoever can
// write it decides scope membership, capture addresses and key pins.
func TestAnInventoryFileOthersCouldWriteIsRefused(t *testing.T) {
	for name, c := range map[string]struct {
		perm, dirPerm os.FileMode
		want          string
	}{
		"world-writable file":      {0o602, 0o755, "the file"},
		"group-writable directory": {0o644, 0o775, "the directory"},
		"world-writable directory": {0o644, 0o1777, "the directory"},
	} {
		path := inventoryAt(t, c.perm, c.dirPerm)
		if _, err := readInventoryFile(path); err == nil || !strings.Contains(err.Error(), c.want) ||
			!strings.Contains(err.Error(), "chmod go-w") {
			t.Errorf("%s: %v", name, err)
		}
	}
	if raw, err := readInventoryFile(inventoryAt(t, 0o644, 0o755)); err != nil || string(raw) != "devices: []\n" {
		t.Fatalf("a file only its owner can write is read: %v", err)
	}
}

// A file or directory another user owns is refused. No second uid exists in
// a test, so the owner lookup is swapped: for the file, then for directories.
func TestAnInventoryFileAnotherUserOwnsIsRefused(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("as root every file is owned by an accepted uid")
	}
	real := fileOwner
	defer func() { fileOwner = real }()
	for name, other := range map[string]func(fs.FileInfo) bool{
		"the file":      func(fi fs.FileInfo) bool { return !fi.IsDir() },
		"the directory": func(fi fs.FileInfo) bool { return fi.IsDir() },
	} {
		fileOwner = func(fi fs.FileInfo) (uint32, bool) {
			if other(fi) {
				return uint32(os.Geteuid() + 1), true
			}
			return real(fi)
		}
		if _, err := readInventoryFile(inventoryAt(t, 0o600, 0o700)); err == nil ||
			!strings.Contains(err.Error(), name) || !strings.Contains(err.Error(), "chown it") {
			t.Errorf("%s owned by another uid: %v", name, err)
		}
	}
}

// A link is judged by its target, and a link whose own directory others can
// write is refused: they could re-point it at any file that passes.
func TestAnInventorySymlinkIsFenced(t *testing.T) {
	good := inventoryAt(t, 0o600, 0o700)
	link := filepath.Join(safeDir(t), "inventory.yaml")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	if raw, err := readInventoryFile(link); err != nil || string(raw) != "devices: []\n" {
		t.Fatalf("a link to a safe file is read: %q, %v", raw, err)
	}

	// A link to a file in a directory others can write.
	writable := inventoryAt(t, 0o644, 0o777)
	toWritable := filepath.Join(safeDir(t), "inventory.yaml")
	if err := os.Symlink(writable, toWritable); err != nil {
		t.Fatal(err)
	}
	if _, err := readInventoryFile(toWritable); err == nil ||
		!strings.Contains(err.Error(), "the directory "+filepath.Dir(writable)) {
		t.Fatalf("a link into a writable directory: %v", err)
	}

	// A safe target behind a link in a directory others can write: the link
	// can be swapped.
	swappable := t.TempDir()
	if err := os.Chmod(swappable, 0o777); err != nil {
		t.Fatal(err)
	}
	inSwappable := filepath.Join(swappable, "inventory.yaml")
	if err := os.Symlink(good, inSwappable); err != nil {
		t.Fatal(err)
	}
	if _, err := readInventoryFile(inSwappable); err == nil ||
		!strings.Contains(err.Error(), "holding the symbolic link "+inSwappable) {
		t.Fatalf("a link others could re-point: %v", err)
	}
}

// A named pipe is refused rather than hanging a start or a reload.
func TestAnInventoryFIFOIsRefused(t *testing.T) {
	path := filepath.Join(safeDir(t), "inventory.yaml")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readInventoryFile(path); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("%v", err)
	}
}

// With a broker nothing reads the inventory before the fence: a FIFO at its
// path is refused with the fence's words, and the start returns rather than
// hanging in a plain read (runExpectingRefusal's deadline).
func TestRunRefusesAnInventoryFIFOWithoutHanging(t *testing.T) {
	cfgPath := writeRunConfig(t, brokerConfig(t, minimalPolicy).Broker)
	inv := filepath.Join(filepath.Dir(cfgPath), "inventory.yaml")
	if err := os.Remove(inv); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(inv, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := runExpectingRefusal(t, cfgPath); err == nil || !strings.Contains(err.Error(), "inventory_file "+inv) ||
		!strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("run: %v", err)
	}
}
