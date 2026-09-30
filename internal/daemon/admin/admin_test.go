package admin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/keyring"
)

func TestAnswerRefusesAnUnknownOpAndAnUnheldDevice(t *testing.T) {
	s := &Server{Held: &keyring.Held{}, Keys: map[string]keyring.Set{}, Now: time.Now}
	if r := s.answer(Request{Op: "keys_show", Device: "x"}); !strings.Contains(r.Error, "unknown op") {
		t.Fatalf("%+v", r)
	}
	if r := s.answer(Request{Op: "keys_diagnose", Device: "x"}); !strings.Contains(r.Error, "holds no unvalidated packet") {
		t.Fatalf("%+v", r)
	}
}

func TestListenRefusesAPathThatIsNotASocket(t *testing.T) {
	p := filepath.Join(t.TempDir(), "port49d.sock")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(p); err == nil || !strings.Contains(err.Error(), "not a socket") {
		t.Fatalf("%v", err)
	}
}

// A symlink at the path is refused and never followed: its target keeps its
// mode and its contents.
func TestListenRefusesASymlinkAndLeavesItsTarget(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "port49d.sock")
	if err := os.Symlink(target, p); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(p); err == nil || !strings.Contains(err.Error(), "not a socket") {
		t.Fatalf("%v", err)
	}
	fi, err := os.Stat(target)
	if err != nil || fi.Mode().Perm() != 0o644 {
		t.Fatalf("target mode %v, %v", fi.Mode(), err)
	}
	if fi, err := os.Lstat(p); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("the link was removed or replaced: %v, %v", fi, err)
	}
}

// The uid rule itself: port49d's own and root, and no other.
func TestUIDAllowedIsOwnAndRootOnly(t *testing.T) {
	const own = 1000
	if err := uidAllowed(own, own); err != nil {
		t.Fatal(err)
	}
	if err := uidAllowed(0, own); err != nil {
		t.Fatal(err)
	}
	if err := uidAllowed(1001, own); err == nil || !strings.Contains(err.Error(), "neither port49d's") {
		t.Fatalf("another uid: %v", err)
	}
}

// A request that is not one JSON object is refused without echoing it.
func TestAnswerNeverEchoesAMalformedRequest(t *testing.T) {
	s := &Server{Held: &keyring.Held{}, Keys: map[string]keyring.Set{}, Now: time.Now}
	r := s.answer(Request{Op: "keys_diagnose\x00secret", Device: "x"})
	if !strings.Contains(r.Error, "unknown op") || strings.Contains(r.Error, "secret") {
		t.Fatalf("%+v", r)
	}
}
