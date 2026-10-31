//go:build linux

package keyfile

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A named pipe where a cert_file should be would block the open of os.ReadFile for good, with no
// message; port49d's inventory client loads its pair on every connection. Both loaders refuse it,
// naming the file, within 2 s. A hung load fails the test instead of the suite.
func TestACertThatIsAPipeIsRefusedNotWaitedOn(t *testing.T) {
	_, key := labPair(t)
	for name, load := range map[string]func(c, k string) error{
		"LoadX509KeyPair":    func(c, k string) error { _, err := LoadX509KeyPair(c, k); return err },
		"LoadOwnX509KeyPair": func(c, k string) error { _, err := LoadOwnX509KeyPair(c, k); return err },
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "key.pem"), key, 0o600); err != nil {
				t.Fatal(err)
			}
			fifo := filepath.Join(dir, "cert.pem")
			if err := syscall.Mkfifo(fifo, 0o600); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { // release a reader a regression left blocked
				if f, err := os.OpenFile(fifo, os.O_RDWR, 0); err == nil {
					f.Close()
				}
			})
			done := make(chan error, 1)
			go func() { done <- load(fifo, filepath.Join(dir, "key.pem")) }()
			select {
			case err := <-done:
				if err == nil || !strings.Contains(err.Error(), "not a regular file") || !strings.Contains(err.Error(), fifo) {
					t.Fatalf("a pipe as the certificate: %v", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("a pipe as the certificate blocked the load")
			}
		})
	}
}

// The certificate is public, so neither a mode nor an owner is checked, but it is bounded, and the
// own-key loader, which refuses a link for the key, refuses one for the certificate too.
func TestACertIsBoundedAndTheOwnLoaderFollowsNoLink(t *testing.T) {
	cert, key := labPair(t)
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(keyFile, key, 0o600); err != nil {
		t.Fatal(err)
	}
	big := filepath.Join(dir, "big.pem")
	if err := os.WriteFile(big, append(cert, make([]byte, 1<<20+1)...), 0o644); err != nil {
		t.Fatal(err)
	}
	for name, load := range map[string]func(c, k string) error{
		"LoadX509KeyPair":    func(c, k string) error { _, err := LoadX509KeyPair(c, k); return err },
		"LoadOwnX509KeyPair": func(c, k string) error { _, err := LoadOwnX509KeyPair(c, k); return err },
	} {
		if err := load(big, keyFile); err == nil || !strings.Contains(err.Error(), "larger than") || !strings.Contains(err.Error(), big) {
			t.Errorf("%s: an oversized certificate: %v", name, err)
		}
	}
	good := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(good, cert, 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.pem")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOwnX509KeyPair(link, keyFile); err == nil || !strings.Contains(err.Error(), link) {
		t.Errorf("LoadOwnX509KeyPair followed a link to the certificate: %v", err)
	}
	if _, err := LoadOwnX509KeyPair(good, keyFile); err != nil {
		t.Errorf("LoadOwnX509KeyPair, a regular 0644 certificate: %v", err)
	}
}
