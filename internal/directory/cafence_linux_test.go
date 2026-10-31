//go:build linux

package directory

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/testpki"
)

// broker.directory.ca_file names what the broker trusts to be the directory (a fake one would see every
// person's password), so it is read through the policy-file fence at each dial (decision 54 ruling 16): a
// directory others can write, a link out of its directory and a named pipe are each refused.
func TestTheDirectoryCAFileIsReadThroughTheFence(t *testing.T) {
	pki, err := testpki.NewCA("lab directory CA", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	srv := Server{URI: "ldaps://dc-01.corp.example.com:636"}
	mk := func(name string, mode os.FileMode) string { // a directory of the mode, holding the CA
		d := t.TempDir()
		if err := os.Chmod(d, mode); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(d, name)
		if err := os.WriteFile(p, pki.PEM(), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if _, err := tlsConfig(Config{CAFile: mk("ca.pem", 0o755)}, srv, &Credentials{mech: "simple"}); err != nil {
		t.Fatalf("the control, a good file in a safe directory, was refused: %v", err)
	}
	out := mk("ca.pem", 0o777)
	link := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.Symlink(out, link); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(t.TempDir(), "ca.pem")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string]string{
		"a world-writable directory": out,
		"a group-writable directory": mk("ca.pem", 0o775),
		"a link out to such a place": link,
		"a named pipe":               fifo,
	} {
		done := make(chan error, 1)
		go func() { _, err := tlsConfig(Config{CAFile: p}, srv, &Credentials{mech: "simple"}); done <- err }()
		select {
		case err := <-done:
			if err == nil {
				t.Errorf("%s: an unsafe ca_file was read", name)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: the read hung", name)
		}
	}
}
