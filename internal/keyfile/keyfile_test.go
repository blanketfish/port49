package keyfile

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/testpki"
)

// A private key is loaded only from a regular file its owner alone can read,
// and never through a symlink: ssh's rule for a key, and the seed-token file's
// rule for a credential (internal/port49d, O_NOFOLLOW).
func TestAPrivateKeyMustBeItsOwnersAlone(t *testing.T) {
	dir := t.TempDir()
	if err := testpki.WriteLab(dir, "alice@example.com", time.Now()); err != nil {
		t.Fatal(err)
	}
	cert, key := filepath.Join(dir, testpki.LabClientCert), filepath.Join(dir, testpki.LabClientKey)
	if _, err := LoadOwnX509KeyPair(cert, key); err != nil {
		t.Fatalf("a 0600 key: %v", err)
	}
	link := filepath.Join(dir, "link.pem")
	if err := os.Symlink(key, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOwnX509KeyPair(cert, link); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("a key through a symlink: %v", err)
	}
	// A missing key says so, and does not blame a symlink that is not there.
	if _, err := LoadOwnX509KeyPair(cert, filepath.Join(dir, "absent.pem")); !errors.Is(err, os.ErrNotExist) ||
		strings.Contains(err.Error(), "symlink") {
		t.Fatalf("a missing key: %v", err)
	}
	if err := os.Chmod(key, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOwnX509KeyPair(cert, key); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("a group-readable key: %v", err)
	}
}

// A named pipe would block the open or feed whatever its writer chooses; a
// key is a regular file or nothing.
func TestAKeyThatIsNotARegularFileIsRefused(t *testing.T) {
	dir := t.TempDir()
	if err := testpki.WriteLab(dir, "alice@example.com", time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOwnX509KeyPair(filepath.Join(dir, testpki.LabClientCert), dir); err == nil ||
		!strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("a directory as the key: %v", err)
	}
	fifo := filepath.Join(dir, "fifo.pem")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := LoadOwnX509KeyPair(filepath.Join(dir, testpki.LabClientCert), fifo)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("a named pipe as the key: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a named pipe as the key blocked the open")
	}
}

// ssh's rule for the owner: the key belongs to the user port49 runs as, or to
// root. Mode bits alone would let root load a 0600 key another user renamed
// into a writable directory. There is no second uid in CI, so the effective
// uid is swapped instead.
func TestAKeyMustBeOwnedByItsUserOrRoot(t *testing.T) {
	dir := t.TempDir()
	if err := testpki.WriteLab(dir, "alice@example.com", time.Now()); err != nil {
		t.Fatal(err)
	}
	cert, key := filepath.Join(dir, testpki.LabClientCert), filepath.Join(dir, testpki.LabClientKey)
	me := uint32(os.Geteuid())
	defer func(g func() int) { geteuid = g }(geteuid)

	geteuid = func() int { return int(me) + 1 }
	if me != 0 {
		if _, err := LoadOwnX509KeyPair(cert, key); err == nil || !strings.Contains(err.Error(), "chown") {
			t.Fatalf("a key owned by another user: %v", err)
		}
		// Root running port49 does not take a key another user owns either.
		geteuid = func() int { return 0 }
		if _, err := LoadOwnX509KeyPair(cert, key); err == nil || !strings.Contains(err.Error(), "chown") {
			t.Fatalf("root loading a user's key: %v", err)
		}
	}

	// A root-owned file passes the owner check whatever the effective uid:
	// /etc/passwd is refused for its mode, not its owner.
	var st syscall.Stat_t
	if err := syscall.Stat("/etc/passwd", &st); err != nil || st.Uid != 0 || st.Mode&0o077 == 0 {
		t.Skip("no root-owned, group-readable /etc/passwd to probe")
	}
	geteuid = func() int { return int(me) + 1 }
	if _, err := LoadOwnX509KeyPair(cert, "/etc/passwd"); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("a root-owned key: %v", err)
	}
}

// The path is the operator's to choose; a key is a few hundred bytes, and a
// mistyped path to something huge is refused rather than read into memory.
func TestAnOversizedKeyIsRefused(t *testing.T) {
	dir := t.TempDir()
	if err := testpki.WriteLab(dir, "alice@example.com", time.Now()); err != nil {
		t.Fatal(err)
	}
	big := filepath.Join(dir, "big.pem")
	if err := os.WriteFile(big, make([]byte, maxKeySize+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOwnX509KeyPair(filepath.Join(dir, testpki.LabClientCert), big); err == nil ||
		!strings.Contains(err.Error(), "larger than") {
		t.Fatalf("an oversized key: %v", err)
	}
}

// ReadOwn is the owner-only rule for a file that is not a key pair: a TPM blob.
func TestReadOwnRefusesAGroupReadableFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "svc.keytab")
	if err := os.WriteFile(path, []byte("keytab"), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, err := ReadOwn(path); err != nil || string(b) != "keytab" {
		t.Fatalf("a 0600 file: %q %v", b, err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadOwn(path); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("a group-readable file: %v", err)
	}
}
