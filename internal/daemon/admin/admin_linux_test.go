//go:build linux

package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/config"
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

// serve starts s on a socket in a fresh directory and returns its path.
func serve(t *testing.T, s *Server) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "port49d.sock")
	ln, err := Listen(p)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go s.Serve(ctx, ln)
	return p
}

// Only root or port49d's own uid may revoke, lift or list (spec §13
// decision 32 ruling 9). Another uid is refused before its request is read,
// and nothing is revoked. Without root to run a client as another uid, the
// socket's idea of its own uid is moved instead, so the test's uid is the
// other one; TestAnotherUIDIsRefused runs a real other uid as root.
func TestAnotherUIDCannotRevokeLiftOrList(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root is always answered")
	}
	called := make(chan string, 4)
	p := serve(t, &Server{Held: &keyring.Held{}, Now: time.Now,
		ownUID: func() uint32 { return uint32(os.Geteuid()) + 1 },
		Revoke: func(_ context.Context, op RevokeOp) (string, bool, error) {
			called <- "revoke"
			return "revoked", false, nil
		},
		Revocations: func(context.Context) (string, error) { called <- "revocations"; return "", nil }})
	for _, req := range []Request{{Op: "revoke", Principal: "user:alice@example.com"},
		{Op: "revoke", Principal: "user:alice@example.com", Lift: true}, {Op: "revocations"}} {
		c, err := net.Dial("unix", p)
		if err != nil {
			t.Fatal(err)
		}
		json.NewEncoder(c).Encode(req)
		var r Response
		err = json.NewDecoder(c).Decode(&r)
		c.Close()
		if err != nil || !strings.HasPrefix(r.Error, fmt.Sprintf("refused: uid %d is neither port49d's", os.Geteuid())) ||
			r.Text != "" {
			t.Fatalf("%+v: %+v, %v", req, r, err)
		}
	}
	select {
	case op := <-called:
		t.Fatalf("a refused caller reached %s", op)
	default:
	}
}

// directory_forget answers the same peers as a revoke: another uid is
// refused before its request is read, and nothing is forgotten.
func TestAnotherUIDCannotForget(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root is always answered")
	}
	called := make(chan string, 1)
	p := serve(t, &Server{Held: &keyring.Held{}, Now: time.Now,
		ownUID: func() uint32 { return uint32(os.Geteuid()) + 1 },
		Forget: func(_ context.Context, principal string, _ uint32) (string, error) {
			called <- principal
			return "forgot", nil
		}})
	c, err := net.Dial("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	json.NewEncoder(c).Encode(Request{Op: "directory_forget", Principal: "user:alice@example.com"})
	var r Response
	if err := json.NewDecoder(c).Decode(&r); err != nil ||
		!strings.HasPrefix(r.Error, fmt.Sprintf("refused: uid %d is neither port49d's", os.Geteuid())) || r.Text != "" {
		t.Fatalf("%+v, %v", r, err)
	}
	select {
	case p := <-called:
		t.Fatalf("a refused caller forgot %s", p)
	default:
	}
}

// A revocation that cannot finish gives up at the server's deadline, and
// the caller is told so, not left waiting.
func TestARevocationGivesUpAtTheDeadlineAndSaysSo(t *testing.T) {
	p := serve(t, &Server{Held: &keyring.Held{}, Now: time.Now, OpTimeout: 100 * time.Millisecond,
		Revoke: func(ctx context.Context, op RevokeOp) (string, bool, error) {
			<-ctx.Done() // a hung store gives up only with its ctx
			return "", false, fmt.Errorf("broker: the revocation may not have been recorded (%w)", ctx.Err())
		},
		Revocations: func(context.Context) (string, error) { return "", nil }})
	c, err := net.Dial("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	start := time.Now()
	json.NewEncoder(c).Encode(Request{Op: "revoke", Principal: "user:alice@example.com"})
	var r Response
	if err := json.NewDecoder(c).Decode(&r); err != nil || !strings.Contains(r.Error, "deadline exceeded") {
		t.Fatalf("%+v, %v", r, err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("answered after %v", d)
	}
}

// A caller that hangs up mid-revocation ends the op's ctx: nothing goes on
// waiting on its behalf.
func TestACallerThatHangsUpEndsItsOp(t *testing.T) {
	entered, ended := make(chan struct{}), make(chan error, 1)
	p := serve(t, &Server{Held: &keyring.Held{}, Now: time.Now,
		Revoke: func(ctx context.Context, op RevokeOp) (string, bool, error) {
			close(entered)
			<-ctx.Done()
			ended <- ctx.Err()
			return "", false, ctx.Err()
		},
		Revocations: func(context.Context) (string, error) { return "", nil }})
	c, err := net.Dial("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	json.NewEncoder(c).Encode(Request{Op: "revoke", Principal: "user:alice@example.com"})
	<-entered
	c.Close()
	select {
	case err := <-ended:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("the op ended by %v, not the hang-up", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the op went on after its caller hung up")
	}
}

// A misspelt key is refused, not dropped: "lifted" for "lift" would
// otherwise revoke what the operator meant to lift. Nothing reaches the
// broker, and the answer does not echo the request.
func TestAnUnknownKeyIsRefused(t *testing.T) {
	called := make(chan RevokeOp, 1)
	p := serve(t, &Server{Held: &keyring.Held{}, Now: time.Now,
		Revoke:      func(_ context.Context, op RevokeOp) (string, bool, error) { called <- op; return "", false, nil },
		Revocations: func(context.Context) (string, error) { return "", nil }})
	c, err := net.Dial("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte(`{"op":"revoke","principal":"user:alice@example.com","lifted":true}` + "\n"))
	var r Response
	if err := json.NewDecoder(c).Decode(&r); err != nil || r.Error != "a request is one JSON object with known keys" {
		t.Fatalf("%+v, %v", r, err)
	}
	select {
	case op := <-called:
		t.Fatalf("a request with an unknown key reached the broker: %+v", op)
	default:
	}
}

// An import's body follows its request line on the connection, to the
// client's half-close, whole across the decoder's read-ahead and the socket's
// buffers; an export's comes back whole in the answer (plan 9e, I14).
// An export of exactly 64 MiB, which the CLI sends, is taken: the newline that
// ends the request line is not part of the bound.
func TestAnImportOfExactlyTheLimitIsTaken(t *testing.T) {
	body := bytes.Repeat([]byte("x"), maxImport)
	got := make(chan int, 1)
	p := serve(t, &Server{Held: &keyring.Held{}, Now: time.Now,
		EnrollmentsImport: func(_ context.Context, sealed []byte, _ bool, _ uint32) (string, error) {
			got <- len(sealed)
			return "imported", nil
		}})
	c, err := net.Dial("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := json.NewEncoder(c).Encode(Request{Op: "enrollments_import"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := c.(*net.UnixConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	var r Response
	if err := json.NewDecoder(c).Decode(&r); err != nil || r.Text != "imported" || r.Error != "" {
		t.Fatalf("%+v, %v", r, err)
	}
	if n := <-got; n != maxImport {
		t.Fatalf("the body arrived as %d bytes, want %d", n, maxImport)
	}
}

func TestAnImportBodyFollowsItsRequestLineAndAnExportComesBack(t *testing.T) {
	body := make([]byte, 3<<20+17)
	for i := range body {
		body[i] = byte('a' + i%26)
	}
	got := make(chan []byte, 1)
	p := serve(t, &Server{Held: &keyring.Held{}, Now: time.Now,
		EnrollmentsImport: func(_ context.Context, sealed []byte, replace bool, _ uint32) (string, error) {
			got <- sealed
			return fmt.Sprintf("imported (replace %v)", replace), nil
		},
		EnrollmentsExport: func(context.Context, uint32) ([]byte, error) { return body, nil }})

	c, err := net.Dial("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := json.NewEncoder(c).Encode(Request{Op: "enrollments_import", Replace: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := c.(*net.UnixConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	var r Response
	if err := json.NewDecoder(c).Decode(&r); err != nil || r.Text != "imported (replace true)" {
		t.Fatalf("%+v, %v", r, err)
	}
	if sealed := <-got; !bytes.Equal(sealed, body) {
		t.Fatalf("the body arrived as %d bytes, want %d, or changed", len(sealed), len(body))
	}

	e, err := net.Dial("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	json.NewEncoder(e).Encode(Request{Op: "enrollments_export"})
	var x Response
	if err := json.NewDecoder(e).Decode(&x); err != nil || !bytes.Equal(x.Sealed, body) {
		t.Fatalf("the export came back as %d bytes: %v", len(x.Sealed), err)
	}
}

// A store_status that takes longer than the connection's first 5s is still
// answered: it gets its own deadline, StatusWait (plan 11a, R21).
func TestStoreStatusOutlastsTheFirstDeadline(t *testing.T) {
	p := serve(t, &Server{Now: time.Now, StoreStatus: func(context.Context) (string, bool, error) {
		time.Sleep(5500 * time.Millisecond)
		return "directory  etcd    ?/? members  unreachable", true, nil
	}})
	c, err := net.Dial("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(StatusWait))
	fmt.Fprintln(c, `{"op":"store_status"}`)
	var r Response
	if err := json.NewDecoder(c).Decode(&r); err != nil || !r.Degraded || r.Text == "" {
		t.Fatalf("%+v %v", r, err)
	}
}

// A caller that hangs up cancels the reads behind its store_status.
func TestStoreStatusStopsWhenTheCallerHangsUp(t *testing.T) {
	started, ended := make(chan struct{}), make(chan struct{})
	p := serve(t, &Server{Now: time.Now, StoreStatus: func(ctx context.Context) (string, bool, error) {
		close(started)
		<-ctx.Done()
		close(ended)
		return "", false, ctx.Err()
	}})
	c, err := net.Dial("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintln(c, `{"op":"store_status"}`)
	<-started
	c.Close()
	select {
	case <-ended:
	case <-time.After(3 * time.Second):
		t.Fatal("the reads went on after the caller hung up")
	}
}

// The wait covers two sequential call_timeouts at their 5s maximum.
func TestStatusWaitCoversTheLargestCallTimeout(t *testing.T) {
	if StatusOpTimeout != 2*config.MaxCallTimeout || StatusWait <= StatusOpTimeout {
		t.Fatalf("StatusOpTimeout %v, StatusWait %v", StatusOpTimeout, StatusWait)
	}
}
