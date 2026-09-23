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
// rule for a credential (cmd/port49d, O_NOFOLLOW).
func TestAPrivateKeyMustBeItsOwnersAlone(t *testing.T) {
	dir := t.TempDir()
	if err := testpki.WriteLab(dir, "alice@example.com", time.Now()); err != nil {
		t.Fatal(err)
	}
	cert, key := filepath.Join(dir, testpki.LabClientCert), filepath.Join(dir, testpki.LabClientKey)
	if _, err := LoadX509KeyPair(cert, key); err != nil {
		t.Fatalf("a 0600 key: %v", err)
	}
	link := filepath.Join(dir, "link.pem")
	if err := os.Symlink(key, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadX509KeyPair(cert, link); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("a key through a symlink: %v", err)
	}
	// A missing key says so, and does not blame a symlink that is not there.
	if _, err := LoadX509KeyPair(cert, filepath.Join(dir, "absent.pem")); !errors.Is(err, os.ErrNotExist) ||
		strings.Contains(err.Error(), "symlink") {
		t.Fatalf("a missing key: %v", err)
	}
	if err := os.Chmod(key, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadX509KeyPair(cert, key); err == nil || !strings.Contains(err.Error(), "chmod 600") {
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
	if _, err := LoadX509KeyPair(filepath.Join(dir, testpki.LabClientCert), dir); err == nil ||
		!strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("a directory as the key: %v", err)
	}
	fifo := filepath.Join(dir, "fifo.pem")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := LoadX509KeyPair(filepath.Join(dir, testpki.LabClientCert), fifo)
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
