//go:build linux

package sot

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/testpki"
)

// ca_file names what the client trusts to be the server (a fake one would see a bearer token), so it is read
// through the policy-file fence (decision 54 ruling 16): a directory others can write, a link out of its
// directory and a named pipe are each refused, with an error that names the field.
func TestTheCAFileIsReadThroughTheFence(t *testing.T) {
	ca, err := testpki.NewCA("lab CA", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	mk := func(mode os.FileMode) string { // a directory of the mode, holding the CA
		d := t.TempDir()
		if err := os.Chmod(d, mode); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(d, "ca.pem")
		if err := os.WriteFile(p, ca.PEM(), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if _, err := readCA(mk(0o755)); err != nil {
		t.Fatalf("the control, a good file in a safe directory, was refused: %v", err)
	}
	out := mk(0o777)
	link := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.Symlink(out, link); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(t.TempDir(), "ca.pem")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{
		"a group-writable directory": mk(0o775),
		"a world-writable directory": out,
		"a link out to such a place": link,
		"a named pipe":               fifo,
	} {
		done := make(chan error, 1)
		go func() { _, err := readCA(path); done <- err }()
		select {
		case err := <-done:
			if err == nil || !strings.Contains(err.Error(), "ca_file") {
				t.Errorf("%s: want a refusal naming ca_file, got %v", name, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: the read hung", name)
		}
	}
}
