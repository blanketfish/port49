package admin

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/keyring"
)

func TestAnswerRefusesAnUnknownOpAndAnUnheldDevice(t *testing.T) {
	s := &Server{Held: &keyring.Held{}, Keys: map[string]keyring.Set{}, Now: time.Now}
	if r := s.answer(context.Background(), Request{Op: "keys_show", Device: "x"}, 0); r.Error != "unknown op; the ops are keys_diagnose, revoke and revocations" {
		t.Fatalf("%+v", r)
	}
	if r := s.answer(context.Background(), Request{Op: "keys_diagnose", Device: "x"}, 0); !strings.Contains(r.Error, "holds no unvalidated packet") {
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
	r := s.answer(context.Background(), Request{Op: "keys_diagnose\x00secret", Device: "x"}, 0)
	if !strings.Contains(r.Error, "unknown op") || strings.Contains(r.Error, "secret") {
		t.Fatalf("%+v", r)
	}
}

// revoke and revocations reach the funcs port49d gives, with the uid that
// asked; without a broker they are refused, saying why.
func TestRevokeOpsReachTheBroker(t *testing.T) {
	ctx := context.Background()
	var got RevokeOp
	s := &Server{Held: &keyring.Held{}, Now: time.Now,
		Revoke: func(_ context.Context, op RevokeOp) (string, bool, error) {
			got = op
			return "revoked it", op.Lift, nil
		},
		Revocations: func(context.Context) (string, error) { return "no revocation is in force", nil }}
	r := s.answer(ctx, Request{Op: "revoke", Principal: "user:alice@example.com"}, 1000)
	if r.Text != "revoked it" || got.Principal != "user:alice@example.com" || got.UID != 1000 || got.Lift {
		t.Fatalf("%+v %+v", r, got)
	}
	if r := s.answer(ctx, Request{Op: "revoke", CertIssuer: "CN=Corp CA", CertSerial: "3f9a01", Lift: true}, 0); !r.Partial {
		t.Fatalf("a partial answer must say so: %+v", r)
	}
	if got.Issuer != "CN=Corp CA" || got.Serial != "3f9a01" || !got.Lift {
		t.Fatalf("%+v", got)
	}
	// A panic behind an op answers an error and leaves port49d running (M12).
	boom := &Server{Held: &keyring.Held{}, Now: time.Now,
		Revoke:      func(context.Context, RevokeOp) (string, bool, error) { panic("boom") },
		Revocations: func(context.Context) (string, error) { return "", nil }}
	if r := boom.answer(ctx, Request{Op: "revoke", Principal: "user:a@b"}, 0); !strings.Contains(r.Error, "internal error") {
		t.Fatalf("%+v", r)
	}
	if r := s.answer(ctx, Request{Op: "revocations"}, 0); r.Text != "no revocation is in force" {
		t.Fatalf("%+v", r)
	}
	none := &Server{Held: &keyring.Held{}, Now: time.Now}
	if r := none.answer(ctx, Request{Op: "revoke", Principal: "user:a@b"}, 0); !strings.Contains(r.Error, "runs no broker") {
		t.Fatalf("%+v", r)
	}
}
