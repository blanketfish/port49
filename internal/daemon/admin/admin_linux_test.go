//go:build linux

package admin

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/keyring"
)

// The socket is 0600 and answers its owner (SO_PEERCRED, plan 6a owner
// decision 2).
func TestTheSocketIsPrivateAndAnswersItsOwner(t *testing.T) {
	p := filepath.Join(t.TempDir(), "port49d.sock")
	ln, err := Listen(p)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v, %v", fi.Mode(), err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &Server{Held: &keyring.Held{}, Keys: map[string]keyring.Set{}, Now: time.Now}
	go s.Serve(ctx, ln)
	c, err := net.Dial("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	json.NewEncoder(c).Encode(Request{Op: "keys_diagnose", Device: "leaf-19"})
	var r Response
	// The answer is the diagnosis's own ("holds no unvalidated packet"),
	// never "refused: ...": the peer check ran and let our uid through.
	if err := json.NewDecoder(c).Decode(&r); err != nil || !strings.Contains(r.Error, "holds no unvalidated packet") {
		t.Fatalf("%+v, %v", r, err)
	}
	if _, err := Listen(p); err == nil || !strings.Contains(err.Error(), "another process answers") {
		t.Fatalf("a second Listen on a live socket: %v", err)
	}
}

// A socket file nothing answers on, left by a port49d that died, is
// replaced; the new one is 0600 whatever the process umask would give.
func TestListenReplacesAStaleSocket(t *testing.T) {
	p := filepath.Join(t.TempDir(), "port49d.sock")
	old, err := net.Listen("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	old.(*net.UnixListener).SetUnlinkOnClose(false)
	old.Close()
	if err := os.Chmod(p, 0o777); err != nil {
		t.Fatal(err)
	}
	ln, err := Listen(p)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if fi, err := os.Lstat(p); err != nil || fi.Mode()&os.ModeSocket == 0 || fi.Mode().Perm() != 0o600 {
		t.Fatalf("%v, %v", fi.Mode(), err)
	}
}

// Closing the listener removes the socket file, so a clean stop leaves
// nothing for the next start to judge.
func TestClosingTheListenerRemovesTheSocket(t *testing.T) {
	p := filepath.Join(t.TempDir(), "port49d.sock")
	ln, err := Listen(p)
	if err != nil {
		t.Fatal(err)
	}
	ln.Close()
	if _, err := os.Lstat(p); !os.IsNotExist(err) {
		t.Fatalf("%v", err)
	}
}

// A peer that is neither port49d's uid nor root is refused by SO_PEERCRED
// even with the mode fence down. Setting another uid on a child needs root;
// as any other user this skips, and TestUIDAllowedIsOwnAndRootOnly carries
// the rule.
func TestAnotherUIDIsRefused(t *testing.T) {
	if p := os.Getenv("PORT49_ADMIN_TEST_DIAL"); p != "" {
		c, err := net.Dial("unix", p)
		if err != nil {
			os.Exit(3)
		}
		json.NewEncoder(c).Encode(Request{Op: "keys_diagnose", Device: "leaf-19"})
		var r Response
		json.NewDecoder(c).Decode(&r)
		os.Stdout.WriteString(r.Error)
		os.Exit(0)
	}
	if os.Geteuid() != 0 {
		t.Skip("setting another uid on the client needs root")
	}
	// The child runs as nobody, so the socket and the binary it runs sit in a
	// directory it can traverse; t.TempDir's parent is 0700.
	dir, err := os.MkdirTemp("", "port49-admin")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	bin, err := os.ReadFile(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	self := filepath.Join(dir, "admin.test")
	if err := os.WriteFile(self, bin, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "port49d.sock")
	ln, err := Listen(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o666); err != nil { // the fence down, to reach the check
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &Server{Held: &keyring.Held{}, Keys: map[string]keyring.Set{}, Now: time.Now}
	go s.Serve(ctx, ln)
	cmd := exec.Command(self, "-test.run=^TestAnotherUIDIsRefused$")
	cmd.Env = append(os.Environ(), "PORT49_ADMIN_TEST_DIAL="+p)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
	out, err := cmd.Output()
	if err != nil || !strings.HasPrefix(string(out), "refused: uid 65534") {
		t.Fatalf("%q, %v", out, err)
	}
}

// Only a refused dial marks a socket stale (final review m4). One this uid
// cannot dial — another uid's port49d's 0600 socket, say — is refused by
// name and left in place, never unlinked and taken over.
func TestListenLeavesASocketItCannotDial(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root dials a 0000 socket; TestOnlyARefusedDialIsStale carries the rule")
	}
	p := filepath.Join(t.TempDir(), "port49d.sock")
	live, err := net.Listen("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	defer live.Close()
	if err := os.Chmod(p, 0); err != nil {
		t.Fatal(err)
	}
	ln, err := Listen(p)
	if err == nil {
		ln.Close()
		t.Fatal("a socket this uid cannot dial was taken over")
	}
	if !strings.Contains(err.Error(), p) || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("the refusal does not name the path and why: %v", err)
	}
	if fi, err := os.Lstat(p); err != nil || fi.Mode()&os.ModeSocket == 0 {
		t.Fatalf("the socket was removed: %v", err)
	}
}

func TestOnlyARefusedDialIsStale(t *testing.T) {
	op := func(errno syscall.Errno) error {
		return &net.OpError{Op: "dial", Net: "unix", Err: os.NewSyscallError("connect", errno)}
	}
	if !stale(op(syscall.ECONNREFUSED)) {
		t.Fatal("ECONNREFUSED is a socket nothing answers on")
	}
	for _, e := range []syscall.Errno{syscall.EACCES, syscall.EPERM, syscall.EAGAIN, syscall.ETIMEDOUT} {
		if stale(op(e)) {
			t.Fatalf("%v read as stale", e)
		}
	}
}
