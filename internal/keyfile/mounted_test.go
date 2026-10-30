//go:build linux

package keyfile

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/fence"
	"github.com/rhwendt/port49/internal/testpki"
)

// labPair is a certificate and its key as bytes, from the lab PKI.
func labPair(t *testing.T) (cert, key []byte) {
	t.Helper()
	d := t.TempDir()
	if err := testpki.WriteLab(d, "alice@example.com", time.Now()); err != nil {
		t.Fatal(err)
	}
	cert, err := os.ReadFile(filepath.Join(d, testpki.LabClientCert))
	if err != nil {
		t.Fatal(err)
	}
	key, err = os.ReadFile(filepath.Join(d, testpki.LabClientKey))
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

// generation writes one generation of a Kubernetes Secret volume's atomic writer into dir: a
// directory ..name holding the files, mode 2755 as measured (tests/lab/results/configmap-mounts.md),
// each file mode 0440.
func generation(t *testing.T, dir, name string, files map[string][]byte) {
	t.Helper()
	g := filepath.Join(dir, name)
	if err := os.Mkdir(g, 0o755); err != nil {
		t.Fatal(err)
	}
	for f, b := range files {
		if err := os.WriteFile(filepath.Join(g, f), b, 0o440); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(g, 0o755|fs.ModeSetgid|fs.ModeDir); err != nil {
		t.Fatal(err)
	}
}

// publish points ..data at generation name, as the atomic writer does: a new link renamed over it.
func publish(t *testing.T, dir, name string) {
	t.Helper()
	tmp := filepath.Join(dir, "..data_tmp")
	if err := os.Symlink(name, tmp); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, filepath.Join(dir, "..data")); err != nil {
		t.Fatal(err)
	}
}

// secretVolume is a mounted Secret volume as the kubelet lays it out: the volume root mode 3777 on
// a read-only mount, name -> ..data/name for each file, ..data -> the current generation. The mount
// is read-only to us, which the fence is told through its test seam.
func secretVolume(t *testing.T, files map[string][]byte) string {
	t.Helper()
	dir := t.TempDir()
	generation(t, dir, "..2026_a", files)
	publish(t, dir, "..2026_a")
	for f := range files {
		if err := os.Symlink(filepath.Join("..data", f), filepath.Join(dir, f)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(dir, 0o777|fs.ModeSticky); err != nil {
		t.Fatal(err)
	}
	old := fence.ReadOnlyFS
	fence.ReadOnlyFS = func(*os.File) (bool, error) { return true, nil }
	t.Cleanup(func() { fence.ReadOnlyFS = old })
	return dir
}

// The layout the kubelet measured: a key at 0440 behind two links, in a 3777 read-only volume root.
// A broker's server key, an etcd client key and a keytab all arrive this way, so all three load.
func TestAKeyInAMountedSecretVolumeLoads(t *testing.T) {
	cert, key := labPair(t)
	dir := secretVolume(t, map[string][]byte{"tls.crt": cert, "tls.key": key, "svc.keytab": []byte("keytab")})
	if _, err := LoadX509KeyPair(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")); err != nil {
		t.Fatalf("a mounted key pair: %v", err)
	}
	if b, err := ReadSecret(filepath.Join(dir, "svc.keytab")); err != nil || string(b) != "keytab" {
		t.Fatalf("a mounted keytab: %q %v", b, err)
	}
}

// A regular file, 0600 (systemd) or 0440 (a group the process is in), loads.
func TestARegularKeyFileAt0600Or0440Loads(t *testing.T) {
	cert, key := labPair(t)
	for _, mode := range []os.FileMode{0o600, 0o440} {
		dir := t.TempDir()
		if err := os.Chmod(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		c, k := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
		if err := os.WriteFile(c, cert, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(k, key, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(k, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadX509KeyPair(c, k); err != nil {
			t.Errorf("a %v key: %v", mode, err)
		}
	}
}

// A link in the volume that points out of it is refused, whatever its target is: whoever can plant it
// decides what port49 loads.
func TestAKeyLinkedFromOutsideTheVolumeIsRefused(t *testing.T) {
	cert, key := labPair(t)
	elsewhere := t.TempDir()
	if err := os.Chmod(elsewhere, 0o755); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(elsewhere, "key.pem")
	if err := os.WriteFile(outside, key, 0o600); err != nil {
		t.Fatal(err)
	}
	dir := secretVolume(t, map[string][]byte{"tls.crt": cert, "tls.key": key})
	if err := os.Remove(filepath.Join(dir, "tls.key")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "tls.key")); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadX509KeyPair(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")); err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("a key linked from outside the volume: %v", err)
	}
	// ..data re-pointed out of the volume, through the parent.
	dir = secretVolume(t, map[string][]byte{"tls.crt": cert, "tls.key": key})
	sibling := filepath.Join(filepath.Dir(dir), filepath.Base(dir)+"-elsewhere")
	if err := os.Mkdir(sibling, 0o755); err != nil {
		t.Fatal(err)
	}
	for f, b := range map[string][]byte{"tls.crt": cert, "tls.key": key} {
		if err := os.WriteFile(filepath.Join(sibling, f), b, 0o440); err != nil {
			t.Fatal(err)
		}
	}
	publish(t, dir, "../"+filepath.Base(sibling))
	if _, err := LoadX509KeyPair(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")); err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("..data pointed out through the parent: %v", err)
	}
}

// A link in a directory others can write, on a mount that is not read-only, could be re-pointed by
// them: refused.
func TestALinkInAWritableDirectoryIsRefused(t *testing.T) {
	cert, key := labPair(t)
	dir := secretVolume(t, map[string][]byte{"tls.crt": cert, "tls.key": key})
	fence.ReadOnlyFS = func(*os.File) (bool, error) { return false, nil }
	if err := os.Chmod(dir, 0o777); err != nil { // writable by others, not sticky
		t.Fatal(err)
	}
	if _, err := LoadX509KeyPair(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")); err == nil {
		t.Fatal("a key behind a link in a world-writable directory was loaded")
	}
}

// Modes the fence refuses: world-readable (0444), group-writable (0460), and group-readable by a
// group the process is not in.
func TestAKeyWithTheWrongModeOrGroupIsRefused(t *testing.T) {
	cert, key := labPair(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	c, k := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	if err := os.WriteFile(c, cert, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(k, key, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []os.FileMode{0o444, 0o460} {
		if err := os.Chmod(k, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadX509KeyPair(c, k); err == nil {
			t.Errorf("a %v key was loaded", mode)
		}
	}
	if err := os.Chmod(k, 0o440); err != nil {
		t.Fatal(err)
	}
	defer func(f func(fs.FileInfo) (uint32, bool)) { fence.FileGroup = f }(fence.FileGroup)
	fence.FileGroup = func(fs.FileInfo) (uint32, bool) { return 4242, true }
	if _, err := LoadX509KeyPair(c, k); err == nil || !strings.Contains(err.Error(), "gid 4242") {
		t.Errorf("a 0440 key of a foreign group: %v", err)
	}
	// A key owned by another user is refused too.
	defer func(f func(fs.FileInfo) (uint32, bool)) { fence.FileOwner = f }(fence.FileOwner)
	fence.FileGroup = func(fi fs.FileInfo) (uint32, bool) { return uint32(os.Getegid()), true }
	fence.FileOwner = func(fs.FileInfo) (uint32, bool) { return uint32(os.Geteuid()) + 1, true }
	if _, err := LoadX509KeyPair(c, k); err == nil || !strings.Contains(err.Error(), "chown it") {
		t.Errorf("a key owned by another uid: %v", err)
	}
}

// A named pipe as the key is refused without blocking.
func TestAMountedKeyThatIsAPipeIsRefusedWithoutBlocking(t *testing.T) {
	cert, _ := labPair(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	c, k := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	if err := os.WriteFile(c, cert, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(k, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := LoadX509KeyPair(c, k); done <- err }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("a pipe as the key: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a pipe as the key blocked the open")
	}
}

// A files port49 writes itself keeps ssh's rule: no link, owner-only, ours or root's.
func TestReadOwnKeepsTheStrictRule(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "issuing-ca.key")
	if err := os.WriteFile(key, []byte("not-a-real-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, err := ReadOwn(key); err != nil || string(b) != "not-a-real-key" {
		t.Fatalf("a 0600 key: %q %v", b, err)
	}
	link := filepath.Join(dir, "link.key")
	if err := os.Symlink(key, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadOwn(link); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Errorf("a link: %v", err)
	}
	for _, mode := range []os.FileMode{0o640, 0o440} {
		if err := os.Chmod(key, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadOwn(key); err == nil || !strings.Contains(err.Error(), "chmod 600") {
			t.Errorf("a %v key: %v", mode, err)
		}
	}
}

// The files port49 writes itself read through ReadOwn and nothing looser: a 0440 issuing CA key is
// never accepted. This pins the call sites, so a later edit cannot move one to the mounted rule.
func TestTheFilesPort49WritesAreReadStrictly(t *testing.T) {
	for _, c := range []struct{ file, want, not string }{
		{"../port49d/issuer.go", "keyfile.ReadOwn(", "keyfile.ReadSecret("},
		{"../hwkey/tpm/tpm.go", "keyfile.ReadOwn(", "keyfile.ReadSecret("},
		{"../clientkey/open_dlopen.go", "keyfile.ReadOwn(", "keyfile.ReadSecret("},
		{"../clientkey/clientkey.go", "keyfile.LoadOwnX509KeyPair(", "keyfile.LoadX509KeyPair("},
	} {
		b, err := os.ReadFile(c.file)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), c.want) || strings.Contains(string(b), c.not) {
			t.Errorf("%s must call %s and not %s", c.file, c.want, c.not)
		}
	}
}

// A key the operator provisions is read under the secret-file rule at every site that loads one: the
// listener's key_file, once read with config.ReadRegular, which checks no owner, mode or link.
func TestTheMountedKeysAreReadUnderTheSecretFileRule(t *testing.T) {
	for _, c := range []struct{ file, want string }{
		{"../port49d/tlslistener.go", "keyfile.ReadSecret("},
		{"../port49d/store.go", "keyfile.LoadX509KeyPair("},
		{"../port49d/main.go", "keyfile.LoadX509KeyPair("},
		{"../broker/server.go", "keyfile.LoadX509KeyPair("},
		{"../directory/conn.go", "keyfile.ReadSecret("},
	} {
		b, err := os.ReadFile(c.file)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), c.want) {
			t.Errorf("%s must call %s", c.file, c.want)
		}
	}
}

// The atomic writer swaps ..data and removes the old generation: a read that raced it finds its
// target gone once. It re-resolves and reads the new generation.
func TestAReadThatRacesTheAtomicWriterRetriesOnce(t *testing.T) {
	cert, key := labPair(t)
	dir := secretVolume(t, map[string][]byte{"tls.crt": cert, "tls.key": key})
	swapped := false
	defer func(h func()) { fence.AfterResolve = h }(fence.AfterResolve)
	fence.AfterResolve = func() {
		if swapped {
			return
		}
		swapped = true
		generation(t, dir, "..2026_b", map[string][]byte{"tls.crt": cert, "tls.key": key})
		publish(t, dir, "..2026_b")
		os.RemoveAll(filepath.Join(dir, "..2026_a"))
	}
	if _, err := LoadX509KeyPair(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")); err != nil {
		t.Fatalf("a key read across a swap: %v", err)
	}
	if !swapped {
		t.Fatal("the hook never ran")
	}
}

// A rotation between the certificate's read and the key's gives a cert of one generation and a key of
// the other, which tls refuses as a mismatch: the pair is read again and comes from one generation.
func TestACertAndKeyReadAcrossASwapComeFromOneGeneration(t *testing.T) {
	cert1, key1 := labPair(t)
	cert2, key2 := labPair(t)
	dir := secretVolume(t, map[string][]byte{"tls.crt": cert1, "tls.key": key1})
	swapped := false
	defer func(h func()) { afterCert = h }(afterCert)
	afterCert = func() {
		if swapped {
			return
		}
		swapped = true
		generation(t, dir, "..2026_b", map[string][]byte{"tls.crt": cert2, "tls.key": key2})
		publish(t, dir, "..2026_b")
		os.RemoveAll(filepath.Join(dir, "..2026_a"))
	}
	pair, err := LoadX509KeyPair(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"))
	if err != nil {
		t.Fatalf("a pair read across a swap: %v", err)
	}
	if string(pair.Certificate[0]) == "" || !swapped {
		t.Fatal("no pair, or the hook never ran")
	}
}

// The atomic writer removes the old generation under a read of the certificate too: it is read again
// once, as the key is, and a certificate that is truly absent still fails.
func TestACertReadThatRacesTheAtomicWriterRetriesOnce(t *testing.T) {
	cert, key := labPair(t)
	dir := secretVolume(t, map[string][]byte{"tls.crt": cert, "tls.key": key})
	real := readCert
	defer func() { readCert = real }()
	calls := 0
	readCert = func(p string) ([]byte, error) {
		calls++
		if calls == 1 {
			return nil, &fs.PathError{Op: "open", Path: p, Err: fs.ErrNotExist}
		}
		return real(p)
	}
	if _, err := LoadX509KeyPair(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")); err != nil || calls != 2 {
		t.Fatalf("a certificate read across a swap: %v after %d reads", err, calls)
	}
	readCert = func(p string) ([]byte, error) { return nil, &fs.PathError{Op: "open", Path: p, Err: fs.ErrNotExist} }
	if _, err := LoadX509KeyPair(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("an absent certificate: %v", err)
	}
}
