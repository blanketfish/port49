//go:build linux

package fence

import (
	"crypto/ed25519"
	"crypto/rand"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/rhwendt/port49/internal/keyfile"
)

// maxPolicySize and maxInventorySize are port49d's bounds for its two files
// (internal/port49d/policyfile.go), which these tests read as port49d does.
const (
	maxPolicySize    = 1 << 20
	maxInventorySize = 64 << 20
)

// minimalPolicy is port49d's smallest policy file; the fence reads it as
// bytes.
const minimalPolicy = `
scopes: [{name: all_devices, match: {}}]
roles: [{name: r, privilege: admin, permit: ["**"]}]
subjects: [{name: s, identity: ["user:alice@example.com"], username: alice, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [r]}]
`

// safeDir is a fresh directory only its owner can write, whatever the umask.
func safeDir(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	if err := os.Chmod(d, 0o755); err != nil {
		t.Fatal(err)
	}
	return d
}

// policyAt writes a policy file with mode perm in a fresh directory of mode
// dirPerm, and returns its path.
func policyAt(t *testing.T, perm, dirPerm os.FileMode) string {
	t.Helper()
	dir := filepath.Join(safeDir(t), "etc")
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
// §5.1.3), so a file or a directory anyone but the user this process runs as
// could write is refused, naming what to fix.
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
		if _, err := Read(path, maxPolicySize, "policy file"); err == nil || !strings.Contains(err.Error(), c.want) ||
			!strings.Contains(err.Error(), "chmod go-w") {
			t.Errorf("%s: %v", name, err)
		}
	}
	if raw, err := Read(policyAt(t, 0o644, 0o755), maxPolicySize, "policy file"); err != nil || string(raw) != minimalPolicy {
		t.Fatalf("a file only its owner can write is read: %v", err)
	}
}

// A file owned by neither the user this process runs as nor root is refused.
func TestAPolicyFileAnotherUserOwnsIsRefused(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("as root every file is owned by an accepted uid")
	}
	defer func(f func(fs.FileInfo) (uint32, bool)) { FileOwner = f }(FileOwner)
	real := FileOwner
	FileOwner = func(fi fs.FileInfo) (uint32, bool) {
		if !fi.IsDir() {
			return uint32(os.Geteuid() + 1), true // the file alone; every directory is ours
		}
		return real(fi)
	}
	path := policyAt(t, 0o600, 0o700)
	if _, err := Read(path, maxPolicySize, "policy file"); err == nil || !strings.Contains(err.Error(), "the file "+path) ||
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
	dir := filepath.Join(safeDir(t), "policy")
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
	raw, err := Read(filepath.Join(configMap(t), "policy.yaml"), maxPolicySize, "policy file")
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
		d := filepath.Join(safeDir(t), "open")
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
		if _, err := Read(c.path, maxPolicySize, "policy file"); err == nil || !strings.Contains(err.Error(), "the directory "+c.dir) ||
			!strings.Contains(err.Error(), "chmod go-w") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A real ConfigMap or Secret mount root holds both links at mode 0777 (01777,
// 02777 with fsGroup) and is mounted read-only, so nobody in the pod can
// write it (tests/lab/results/configmap-mounts.md). A directory others could
// write by its mode is accepted when its filesystem is read-only, and only
// then; its owner must still be the user this process runs as, or root.
func TestAWritableDirectoryOnAReadOnlyMountIsAccepted(t *testing.T) {
	dir := configMap(t) // the timestamped directory holding the file stays 0755, as measured
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "policy.yaml")
	defer func(f func(*os.File) (bool, error)) { ReadOnlyFS = f }(ReadOnlyFS)

	ReadOnlyFS = func(*os.File) (bool, error) { return false, nil }
	if _, err := Read(path, maxPolicySize, "policy file"); err == nil || !strings.Contains(err.Error(), "chmod go-w") {
		t.Fatalf("a 0777 directory on a writable mount is refused: %v", err)
	}

	ReadOnlyFS = func(*os.File) (bool, error) { return true, nil }
	if raw, err := Read(path, maxPolicySize, "policy file"); err != nil || string(raw) != minimalPolicy {
		t.Fatalf("a 0777 directory on a read-only mount is accepted: %v", err)
	}

	if os.Geteuid() != 0 {
		defer func(f func(fs.FileInfo) (uint32, bool)) { FileOwner = f }(FileOwner)
		real := FileOwner
		FileOwner = func(fi fs.FileInfo) (uint32, bool) {
			if fi.IsDir() {
				return uint32(os.Geteuid() + 1), true
			}
			return real(fi)
		}
		if _, err := Read(path, maxPolicySize, "policy file"); err == nil || !strings.Contains(err.Error(), "chown it") {
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
	defer func(f func(*os.File) (bool, error)) { ReadOnlyFS = f }(ReadOnlyFS)
	ReadOnlyFS = func(*os.File) (bool, error) { return true, nil }

	dir := configMap(t)
	stamped := filepath.Join(dir, "..2026_09_24_07_00_00.123456789")
	for _, p := range []string{dir, stamped} {
		if err := os.Chmod(p, 0o777); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Read(filepath.Join(dir, "policy.yaml"), maxPolicySize, "policy file"); err == nil ||
		!strings.Contains(err.Error(), "the directory "+stamped) || !strings.Contains(err.Error(), "chmod go-w") {
		t.Fatalf("a ConfigMap whose file directory is 0777: %v", err)
	}

	bind := policyAt(t, 0o644, 0o777)
	if _, err := Read(bind, maxPolicySize, "policy file"); err == nil || !strings.Contains(err.Error(), "the directory "+filepath.Dir(bind)) {
		t.Fatalf("a read-only bind of a 0777 host directory: %v", err)
	}
}

// A file others could write is refused even on a read-only mount: only a
// directory's mode is excused, and a ConfigMap's file is 0644 or narrower.
func TestAWritableFileOnAReadOnlyMountIsRefused(t *testing.T) {
	defer func(f func(*os.File) (bool, error)) { ReadOnlyFS = f }(ReadOnlyFS)
	ReadOnlyFS = func(*os.File) (bool, error) { return true, nil }
	if _, err := Read(policyAt(t, 0o666, 0o755), maxPolicySize, "policy file"); err == nil || !strings.Contains(err.Error(), "the file") {
		t.Fatalf("%v", err)
	}
}

// A chain of links that never ends is refused, not followed forever.
func TestALinkLoopIsRefused(t *testing.T) {
	dir := filepath.Join(safeDir(t), "etc")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("b", filepath.Join(dir, "a")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("a", filepath.Join(dir, "b")); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(filepath.Join(dir, "a"), maxPolicySize, "policy file"); err == nil || !strings.Contains(err.Error(), "links") {
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
	if _, err := Read(path, maxPolicySize, "policy file"); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("%v", err)
	}
	if err := os.Truncate(path, maxPolicySize); err != nil {
		t.Fatal(err)
	}
	if raw, err := Read(path, maxPolicySize, "policy file"); err != nil || len(raw) != maxPolicySize {
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
	if _, err := Read(path, maxPolicySize, "policy file"); err == nil || !strings.Contains(err.Error(), "not a regular file") {
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
	if raw, err := Read(path, maxPolicySize, "policy file"); err != nil || string(raw) != minimalPolicy {
		t.Fatalf("%v", err)
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
	if _, err := Read(link, maxPolicySize, "policy file"); err != nil {
		t.Fatalf("a link to a safe file is read: %v", err)
	}
	unsafe := filepath.Join(safeDir(t), "policy.yaml")
	target := policyAt(t, 0o666, 0o755)
	if err := os.Symlink(target, unsafe); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(unsafe, maxPolicySize, "policy file"); err == nil || !strings.Contains(err.Error(), target) {
		t.Fatalf("a link to a world-writable file names the target: %v", err)
	}
}

// A directory owned by neither the user this process runs as nor root is refused even when
// the file in it is safe: its owner can chmod it and replace the file. No
// second uid exists to own one in a test, so the owner lookup is swapped for
// directories alone.
func TestAPolicyDirectoryAnotherUserOwnsIsRefused(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("as root every file is owned by an accepted uid")
	}
	defer func(f func(fs.FileInfo) (uint32, bool)) { FileOwner = f }(FileOwner)
	real := FileOwner
	path := policyAt(t, 0o600, 0o700)
	hi, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	holdingIno := hi.Sys().(*syscall.Stat_t).Ino
	FileOwner = func(fi fs.FileInfo) (uint32, bool) {
		if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Ino == holdingIno {
			return uint32(os.Geteuid() + 1), true
		}
		return real(fi)
	}
	if _, err := Read(path, maxPolicySize, "policy file"); err == nil || !strings.Contains(err.Error(), "the directory "+filepath.Dir(path)) ||
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
	if raw, err := Read(path, maxInventorySize, "inventory file"); err != nil || string(raw) != "devices: []\n" {
		t.Fatalf("a private file: %q, %v", raw, err)
	}
	if err := os.Chmod(path, 0o664); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(path, maxInventorySize, "inventory file"); err == nil || !strings.Contains(err.Error(), "the file "+path) {
		t.Fatalf("a group-writable file: %v", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(path, maxInventorySize+1); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(path, maxInventorySize, "inventory file"); err == nil || !strings.Contains(err.Error(), "not an inventory file") {
		t.Fatalf("an oversized file: %v", err)
	}
}

// inventoryAt writes an inventory file with mode perm in a fresh directory
// of mode dirPerm, and returns its path.
func inventoryAt(t *testing.T, perm, dirPerm os.FileMode) string {
	t.Helper()
	dir := filepath.Join(safeDir(t), "etc")
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
		if _, err := Read(path, maxInventorySize, "inventory file"); err == nil || !strings.Contains(err.Error(), c.want) ||
			!strings.Contains(err.Error(), "chmod go-w") {
			t.Errorf("%s: %v", name, err)
		}
	}
	if raw, err := Read(inventoryAt(t, 0o644, 0o755), maxInventorySize, "inventory file"); err != nil || string(raw) != "devices: []\n" {
		t.Fatalf("a file only its owner can write is read: %v", err)
	}
}

// A file or directory another user owns is refused. No second uid exists in
// a test, so the owner lookup is swapped: for the file, then for directories.
func TestAnInventoryFileAnotherUserOwnsIsRefused(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("as root every file is owned by an accepted uid")
	}
	real := FileOwner
	defer func() { FileOwner = real }()
	for name, other := range map[string]func(fs.FileInfo) bool{
		"the file":      func(fi fs.FileInfo) bool { return !fi.IsDir() },
		"the directory": func(fi fs.FileInfo) bool { return fi.IsDir() },
	} {
		FileOwner = func(fi fs.FileInfo) (uint32, bool) {
			if other(fi) {
				return uint32(os.Geteuid() + 1), true
			}
			return real(fi)
		}
		if _, err := Read(inventoryAt(t, 0o600, 0o700), maxInventorySize, "inventory file"); err == nil ||
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
	if raw, err := Read(link, maxInventorySize, "inventory file"); err != nil || string(raw) != "devices: []\n" {
		t.Fatalf("a link to a safe file is read: %q, %v", raw, err)
	}

	// A link to a file in a directory others can write.
	writable := inventoryAt(t, 0o644, 0o777)
	toWritable := filepath.Join(safeDir(t), "inventory.yaml")
	if err := os.Symlink(writable, toWritable); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(toWritable, maxInventorySize, "inventory file"); err == nil ||
		!strings.Contains(err.Error(), "the directory "+filepath.Dir(writable)) {
		t.Fatalf("a link into a writable directory: %v", err)
	}

	// A safe target behind a link in a directory others can write: the link
	// can be swapped.
	swappable := safeDir(t)
	if err := os.Chmod(swappable, 0o777); err != nil {
		t.Fatal(err)
	}
	inSwappable := filepath.Join(swappable, "inventory.yaml")
	if err := os.Symlink(good, inSwappable); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(inSwappable, maxInventorySize, "inventory file"); err == nil ||
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
	if _, err := Read(path, maxInventorySize, "inventory file"); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("%v", err)
	}
}

// verifyKeyAt writes an ed25519 public key PEM with mode perm in dir and
// returns its path.
func verifyKeyAt(t *testing.T, dir, name string, perm os.FileMode) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, pubPEM, err := keyfile.EncodeEd25519(priv)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, pubPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	// Chmod, not the create mode: the umask would narrow that.
	if err := os.Chmod(p, perm); err != nil {
		t.Fatal(err)
	}
	return p
}

// Pre-flight M3: a verify key others could write is refused, as a policy
// file is.
func TestAVerifyKeyOthersCouldWriteIsRefused(t *testing.T) {
	p := verifyKeyAt(t, safeDir(t), "signing.pub", 0o664)
	if _, err := ReadVerifyKeys("verify_key_files", []string{p}); err == nil ||
		!strings.Contains(err.Error(), "verify_key_files[0]") || !strings.Contains(err.Error(), "writable by others") {
		t.Fatalf("got %v", err)
	}
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	if keys, err := ReadVerifyKeys("verify_key_files", []string{p}); err != nil || len(keys) != 1 {
		t.Fatalf("%v %v", keys, err)
	}
}

// A verify key that does not parse is refused naming its index and file,
// never quoting what the file holds; the bad key's index is its own, not the
// first.
func TestAVerifyKeyThatDoesNotParseNamesItsIndexNotItsBytes(t *testing.T) {
	dir := safeDir(t)
	good := verifyKeyAt(t, dir, "good.pub", 0o644)
	bad := filepath.Join(dir, "bad.pub")
	const junk = "not-a-key-c29tZSBieXRlcw"
	if err := os.WriteFile(bad, []byte(junk+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := ReadVerifyKeys("verify_key_files", []string{good, bad})
	if err == nil || !strings.Contains(err.Error(), "verify_key_files[1]") || !strings.Contains(err.Error(), bad) ||
		strings.Contains(err.Error(), junk) {
		t.Fatalf("got %v", err)
	}
}

// An empty list reads nothing and refuses nothing: refusing a bundle source
// with no verify key is the caller's (Tasks 11, 13).
func TestNoVerifyKeysIsAnEmptyList(t *testing.T) {
	if keys, err := ReadVerifyKeys("verify_key_files", nil); err != nil || len(keys) != 0 {
		t.Fatalf("%v %v", keys, err)
	}
}

// CheckDir asks the directory's question whether or not the file is there:
// a missing file must not skip it (plan 7a, pre-flight C1).
func TestCheckDirAsksOfTheDirectoryAlone(t *testing.T) {
	dir := safeDir(t) // t.TempDir() is group-writable under a 002 umask
	if err := CheckDir(filepath.Join(dir, "absent.json"), "revocations file"); err != nil {
		t.Fatalf("a private directory with no file yet: %v", err)
	}
	if err := CheckDir(filepath.Join(dir, "missing", "absent.json"), "revocations file"); err == nil {
		t.Fatal("a missing directory passed")
	}
	open := filepath.Join(dir, "open")
	if err := os.Mkdir(open, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := CheckDir(filepath.Join(open, "absent.json"), "revocations file"); err == nil ||
		!strings.Contains(err.Error(), "writable by others") {
		t.Fatalf("a directory others can write: %v", err)
	}
}

// secretVolume lays a secret out as a Kubernetes Secret or CSI volume does,
// in the configMap layout: dir/k -> ..data/k, ..data -> ..2026_…, the file
// 0440 in the timestamped directory. It returns dir.
func secretVolume(t *testing.T) string {
	t.Helper()
	dir := configMap(t) // policy.yaml in it stands for any file
	stamped, _ := filepath.EvalSymlinks(filepath.Join(dir, "..data"))
	if err := os.WriteFile(filepath.Join(stamped, "k"), []byte("s3cret\n"), 0o440); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("..data/k", filepath.Join(dir, "k")); err != nil {
		t.Fatal(err)
	}
	return dir
}

// A secret volume's chain of links is followed while it stays inside the
// directory, so a key added to a whole-volume mount is read with no restart
// (decision 53 ruling 1).
func TestASecretLinkInsideTheDirectoryIsFollowed(t *testing.T) {
	dir := secretVolume(t)
	if raw, err := ReadSecret(filepath.Join(dir, "k"), dir, 1<<20); err != nil || len(raw) != 7 {
		t.Fatalf("%d bytes, %v", len(raw), err)
	}
}

// A link that leaves the directory is refused, naming both paths: a policy
// writer who can place a link must not reach the host's other secrets
// (Review Focus 2; decision 53 ruling 12).
func TestALinkOutOfTheDirectoryIsRefused(t *testing.T) {
	dir := secretVolume(t)
	other := filepath.Join(safeDir(t), "tls-key.pem")
	if err := os.WriteFile(other, []byte("hunter2-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, filepath.Join(dir, "out")); err != nil {
		t.Fatal(err)
	}
	_, err := ReadSecret(filepath.Join(dir, "out"), dir, 1<<20)
	if err != nil && strings.Contains(err.Error(), "hunter2") {
		t.Fatal("the refusal carries the target's content")
	}
	if err == nil || !strings.Contains(err.Error(), other) || !strings.Contains(err.Error(), "outside "+dir) {
		t.Fatalf("%v", err)
	}
	if _, err := ReadSecret(other, dir, 1<<20); err == nil {
		t.Fatal("a file outside the directory was read")
	}
}

// The file is held to a reader's rule: owned by us or root, written by its
// owner alone, no world bit; another owner is refused.
func TestASecretFileOfAnotherOwnerIsRefused(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root owns every file it writes")
	}
	dir := secretVolume(t)
	defer func(f func(fs.FileInfo) (uint32, bool)) { FileOwner = f }(FileOwner)
	real := FileOwner
	FileOwner = func(fi fs.FileInfo) (uint32, bool) {
		if fi.Mode().IsRegular() {
			return uint32(os.Geteuid() + 1), true // the Vault Agent injector's uid 100, say
		}
		return real(fi)
	}
	if _, err := ReadSecret(filepath.Join(dir, "k"), dir, 1<<20); err == nil || !strings.Contains(err.Error(), "chown it") {
		t.Fatalf("%v", err)
	}
}

// plainSecretDir is a directory holding one 0440 secret file "k", the
// directory at mode: the Vault Agent injector renders into a tmpfs emptyDir
// that is 01777.
func plainSecretDir(t *testing.T, mode fs.FileMode) (dir, file string) {
	t.Helper()
	dir = filepath.Join(safeDir(t), "keys")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	file = filepath.Join(dir, "k")
	if err := os.WriteFile(file, []byte("s3cret\n"), 0o440); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, mode); err != nil {
		t.Fatal(err)
	}
	return dir, file
}

// The directory holding the secret is held to Read's rule: one others can
// write could have its file swapped, so group- and world-write are refused,
// with or without a read-only mount's excuse (which this directory never
// gets). Only the sticky bit excuses it, below.
func TestASecretInADirectoryOthersCanWriteIsRefused(t *testing.T) {
	for _, mode := range []fs.FileMode{0o775, 0o757, 0o777} {
		dir, file := plainSecretDir(t, mode)
		if _, err := ReadSecret(file, dir, 1<<20); err == nil || !strings.Contains(err.Error(), "chmod go-w") {
			t.Errorf("directory mode %v: %v", mode, err)
		}
	}
}

// A sticky directory we or root own passes: under the sticky bit only the
// file's owner, the directory's owner or root can rename or unlink the file,
// and the file itself must be ours or root's, so a name squatted before the
// first render is refused (denial of service) and never substituted. This is
// the Vault Agent injector's tmpfs (01777), and ruling 11's ancestor excuse.
func TestASecretInAStickyDirectoryIsRead(t *testing.T) {
	dir, file := plainSecretDir(t, 0o777|fs.ModeSticky)
	if raw, err := ReadSecret(file, dir, 1<<20); err != nil || len(raw) != 7 {
		t.Fatalf("%d bytes, %v", len(raw), err)
	}
}

// The sticky excuse is for a directory we or root own, not any sticky one.
func TestAStickyDirectoryOfAnotherOwnerIsRefused(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root owns every directory it makes")
	}
	dir, file := plainSecretDir(t, 0o777|fs.ModeSticky)
	defer func(f func(fs.FileInfo) (uint32, bool)) { FileOwner = f }(FileOwner)
	real := FileOwner
	FileOwner = func(fi fs.FileInfo) (uint32, bool) {
		if fi.IsDir() {
			return uint32(os.Geteuid() + 1), true
		}
		return real(fi)
	}
	if _, err := ReadSecret(file, dir, 1<<20); err == nil || !strings.Contains(err.Error(), "chown it") {
		t.Fatalf("%v", err)
	}
}

// within is a directory: absolute and clean, or the working directory would
// stand in for it, and "/" would bound nothing.
func TestAWithinThatBoundsNothingIsRefused(t *testing.T) {
	dir, file := plainSecretDir(t, 0o700)
	for _, within := range []string{"", "keys", dir + "/../keys", "/"} {
		if _, err := ReadSecret(file, within, 1<<20); err == nil {
			t.Errorf("within %q was accepted", within)
		}
	}
	if _, err := ReadSecret("/k", "/", 1<<20); err == nil || !strings.Contains(err.Error(), "outside the allowed directory") {
		t.Errorf("a file under /: %v", err)
	}
}

// Under the sticky excuse a secret file has one name: another user who can
// write the directory could have created the name as a hard link to a file of
// ours or root's elsewhere. In a directory only its owner can write, a second
// name is the owner's own doing and is not refused.
func TestAHardLinkedSecretInAStickyDirectoryIsRefused(t *testing.T) {
	dir, file := plainSecretDir(t, 0o777|fs.ModeSticky)
	other := filepath.Join(dir, "l")
	if err := os.Link(file, other); err != nil {
		t.Skipf("no hard links here: %v", err)
	}
	_, err := ReadSecret(other, dir, 1<<20)
	if err == nil || !strings.Contains(err.Error(), "more than one hard link") || strings.Contains(err.Error(), "s3cret") {
		t.Fatalf("%v", err)
	}
	tight, tfile := plainSecretDir(t, 0o700)
	if err := os.Link(tfile, filepath.Join(tight, "l")); err != nil {
		t.Fatal(err)
	}
	if raw, err := ReadSecret(tfile, tight, 1<<20); err != nil || len(raw) != 7 {
		t.Fatalf("a second name in a private directory: %d bytes, %v", len(raw), err)
	}
}

// A directory above the file that others can write could rename the file's
// directory and put another in its place: refused, unless its sticky bit
// keeps others from renaming what is below it (decision 53 ruling 11).
func TestAnAncestorOthersCanWriteIsRefused(t *testing.T) {
	top := safeDir(t)
	mid := filepath.Join(top, "shared")
	dir := filepath.Join(mid, "port49")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(p, []byte(minimalPolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(mid, 0o777); err != nil {
		t.Fatal(err)
	}
	// The refusal names the ancestor, the file read, the directory's mode as
	// a directory's, and a way out that does not need chmod on a shared one.
	if _, err := Read(p, maxPolicySize, "policy file"); err == nil || !strings.Contains(err.Error(), "the directory "+mid+", above "+p+", is mode drwxrwxrwx") ||
		!strings.Contains(err.Error(), "chmod go-w") || !strings.Contains(err.Error(), "move the file under directories only root or uid") {
		t.Fatalf("an others-writable ancestor: %v", err)
	}
	// The same walk guards the other entry points.
	if _, err := ReadNoLink(p, maxPolicySize, "state file"); err == nil || !strings.Contains(err.Error(), mid) {
		t.Fatalf("ReadNoLink under an others-writable ancestor: %v", err)
	}
	if err := CheckDir(p, "policy file"); err == nil || !strings.Contains(err.Error(), mid) {
		t.Fatalf("CheckDir under an others-writable ancestor: %v", err)
	}
	if err := os.Chmod(mid, 0o777|fs.ModeSticky); err != nil {
		t.Fatal(err)
	}
	if raw, err := Read(p, maxPolicySize, "policy file"); err != nil || string(raw) != minimalPolicy {
		t.Fatalf("a sticky ancestor, as /tmp is: %v", err)
	}
	// A group-writable ancestor is refused too, and the refusal names the
	// ancestor, never the file's bytes.
	if err := os.Chmod(mid, 0o770); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(p, maxPolicySize, "policy file"); err == nil || !strings.Contains(err.Error(), mid) ||
		strings.Contains(err.Error(), "scopes:") {
		t.Fatalf("a group-writable ancestor: %v", err)
	}
}

// A sticky ancestor is excused only when we or root own it: another user's
// sticky directory is theirs to rename within.
func TestAStickyAncestorOfAnotherOwnerIsRefused(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root owns the swapped uid's directory anyway")
	}
	top := safeDir(t)
	mid := filepath.Join(top, "shared")
	dir := filepath.Join(mid, "port49")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(p, []byte(minimalPolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(mid, 0o777|fs.ModeSticky); err != nil {
		t.Fatal(err)
	}
	mi, err := os.Stat(mid)
	if err != nil {
		t.Fatal(err)
	}
	midIno := mi.Sys().(*syscall.Stat_t).Ino
	defer func(f func(fs.FileInfo) (uint32, bool)) { FileOwner = f }(FileOwner)
	real := FileOwner
	FileOwner = func(fi fs.FileInfo) (uint32, bool) {
		if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Ino == midIno {
			return uint32(os.Geteuid() + 1), true
		}
		return real(fi)
	}
	if _, err := Read(p, maxPolicySize, "policy file"); err == nil || !strings.Contains(err.Error(), mid) ||
		!strings.Contains(err.Error(), "chown it") {
		t.Fatalf("a sticky ancestor of another owner: %v", err)
	}
}

// An ancestor on a read-only mount is excused, as a link's directory is.
func TestAWritableAncestorOnAReadOnlyMountIsAccepted(t *testing.T) {
	top := safeDir(t)
	mid := filepath.Join(top, "shared")
	dir := filepath.Join(mid, "port49")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(p, []byte(minimalPolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(mid, 0o777); err != nil {
		t.Fatal(err)
	}
	defer func(f func(*os.File) (bool, error)) { ReadOnlyFS = f }(ReadOnlyFS)
	ReadOnlyFS = func(*os.File) (bool, error) { return false, nil }
	if _, err := Read(p, maxPolicySize, "policy file"); err == nil || !strings.Contains(err.Error(), mid) {
		t.Fatalf("a 0777 ancestor on a writable mount is refused: %v", err)
	}
	ReadOnlyFS = func(*os.File) (bool, error) { return true, nil }
	if raw, err := Read(p, maxPolicySize, "policy file"); err != nil || string(raw) != minimalPolicy {
		t.Fatalf("a 0777 ancestor on a read-only mount is accepted: %v", err)
	}
}

// A secret file's key directory is walked too: an others-writable parent
// could rename the whole key directory, so ReadSecret refuses it.
func TestASecretUnderAnAncestorOthersCanWriteIsRefused(t *testing.T) {
	top := safeDir(t)
	mid := filepath.Join(top, "shared")
	keys := filepath.Join(mid, "keys")
	if err := os.MkdirAll(keys, 0o700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(keys, "k1")
	if err := os.WriteFile(p, []byte("not-a-real-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(mid, 0o777); err != nil {
		t.Fatal(err)
	}
	_, err := ReadSecret(p, keys, 1<<10)
	if err == nil || !strings.Contains(err.Error(), "the directory "+mid) || strings.Contains(err.Error(), "not-a-real-secret") {
		t.Fatalf("a secret under an others-writable ancestor: %v", err)
	}
	if err := os.Chmod(mid, 0o755); err != nil {
		t.Fatal(err)
	}
	if raw, err := ReadSecret(p, keys, 1<<10); err != nil || string(raw) != "not-a-real-secret\n" {
		t.Fatalf("the same secret under a private ancestor: %v", err)
	}
}

// A POSIX ACL granting another user write shows in the mode's group bits
// (the ACL mask), so the mode check already refuses it.
func TestAnACLGrantingWriteIsRefused(t *testing.T) {
	setfacl, err := exec.LookPath("setfacl")
	if err != nil {
		t.Skip("setfacl is not installed")
	}
	dir := safeDir(t)
	p := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(p, []byte(minimalPolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(setfacl, "-m", "u:nobody:rw", p).CombinedOutput(); err != nil {
		t.Skipf("this filesystem takes no ACL: %v %s", err, out)
	}
	if _, err := Read(p, maxPolicySize, "policy file"); err == nil || !strings.Contains(err.Error(), "writable by others") {
		t.Fatalf("an ACL granting write: %v", err)
	}
}

// A plain ancestor another user owns is refused even at 0755, and a read-only
// mount never excuses its owner: its owner can rename the directory below it
// and put another tree in its place (/home/bob above the file).
func TestAnAncestorOfAnotherOwnerIsRefused(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root owns the swapped uid's directory anyway")
	}
	top := safeDir(t)
	mid := filepath.Join(top, "bob")
	dir := filepath.Join(mid, "port49")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(mid, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(p, []byte(minimalPolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	mi, err := os.Stat(mid)
	if err != nil {
		t.Fatal(err)
	}
	midIno := mi.Sys().(*syscall.Stat_t).Ino
	defer func(f func(fs.FileInfo) (uint32, bool)) { FileOwner = f }(FileOwner)
	real := FileOwner
	FileOwner = func(fi fs.FileInfo) (uint32, bool) {
		if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Ino == midIno {
			return uint32(os.Geteuid() + 1), true
		}
		return real(fi)
	}
	for _, ro := range []bool{false, true} {
		func() {
			defer func(f func(*os.File) (bool, error)) { ReadOnlyFS = f }(ReadOnlyFS)
			ReadOnlyFS = func(*os.File) (bool, error) { return ro, nil }
			_, err := Read(p, maxPolicySize, "policy file")
			if err == nil || !strings.Contains(err.Error(), "the directory "+mid) || !strings.Contains(err.Error(), "chown it") {
				t.Fatalf("an ancestor of another owner (read-only mount %v): %v", ro, err)
			}
		}()
	}
}
