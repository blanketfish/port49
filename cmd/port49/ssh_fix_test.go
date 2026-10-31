package main

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// OpenSSH lowercases the HostKeyAlias it puts in a prompt and keeps the
// username's case, so the device compares folded and the username exact (task
// 6 review I-1).
func TestOwnPromptFoldsTheDevicesCaseNotTheUsers(t *testing.T) {
	for _, c := range []struct {
		prompt, username, device string
		own                      bool
	}{
		{"alice@leaf1's password: ", "alice", "Leaf1", true},
		{"(alice@leaf1) Password: ", "alice", "Leaf1", true},
		{"alice@nyc-core-01's password: ", "alice", "NYC-CORE-01", true},
		{"Alice@leaf1's password: ", "alice", "Leaf1", false},
		{"Alice.X@leaf1's password: ", "Alice.X", "Leaf1", true},
		{"alice@leaf10's password: ", "alice", "Leaf1", false},
		{"alice@Leaf1's password: ", "alice", "Leaf1", false}, // ssh never prints the alias unfolded
	} {
		if ownPrompt(c.prompt, c.username, c.device) != c.own {
			t.Errorf("ownPrompt(%q, %q, %q) = %v", c.prompt, c.username, c.device, !c.own)
		}
	}
}

// A device whose inventory name has a capital is logged in to: the token
// reaches its own prompt by either method (task 6 review I-1).
func TestPortSSHLogsInToADeviceNamedWithCapitals(t *testing.T) {
	for _, method := range []string{"keyboard-interactive", "password"} {
		dev := startDeviceSSH(t, []string{method}, "LOGINTOKEN", 0)
		item := sshPermit
		item.Device = "Leaf1"
		r := newSSHRig(t, dev, item, 0, nil)
		// Under Leaf1, the case a fold must match.
		if err := os.WriteFile(r.known, []byte("Leaf1 "+string(ssh.MarshalAuthorizedKey(dev.key))), 0o600); err != nil {
			t.Fatal(err)
		}
		code, out, errb := r.run(t, "Leaf1", "--", "show", "version")
		if code != 0 || out != "ran: show version\n" || strings.Join(dev.attempts(), ",") != "LOGINTOKEN" {
			t.Errorf("%s: code %d stdout %q stderr %q attempts %q", method, code, out, errb, dev.attempts())
		}
		tokenNowhere(t, out, errb)
	}
}

// ssh sets SSH_ASKPASS_PROMPT only when it has a hint, so one inherited from
// the operator's environment reaches the askpass for the device's own prompt.
// It is stripped; otherwise the askpass takes the prompt for a notification,
// answers nothing, and ssh sends the device an empty password (task 6 review
// M-2).
func TestAnInheritedAskpassPromptHintDoesNotSwallowTheToken(t *testing.T) {
	t.Setenv("SSH_ASKPASS_PROMPT", "none")
	for _, method := range []string{"keyboard-interactive", "password"} {
		dev := startDeviceSSH(t, []string{method}, "LOGINTOKEN", 0)
		r := newSSHRig(t, dev, sshPermit, 0, dev.key)
		code, out, errb := r.run(t, "leaf1", "--", "show", "version")
		if code != 0 || out != "ran: show version\n" || strings.Join(dev.attempts(), ",") != "LOGINTOKEN" {
			t.Errorf("%s: code %d stdout %q stderr %q attempts %q", method, code, out, errb, dev.attempts())
		}
		tokenNowhere(t, out, errb)
	}
}

// The askpass socket is made only in a directory that is 0700 and this user's,
// whatever the order its caller runs in (task 6 review I-3).
func TestTheAskpassSocketIsNeverMadeInAnOpenDirectory(t *testing.T) {
	// A short path: a Unix socket's is limited, and the test's name is long.
	base, err := os.MkdirTemp("", "p49o")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	open := filepath.Join(base, "open")
	if err := os.Mkdir(open, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o755); err != nil {
		t.Fatal(err)
	}
	if ln, _, err := listenAskpass(filepath.Join(open, "agent.sock")); err == nil {
		ln.Close()
		t.Fatal("an askpass socket was made in a 0755 directory")
	}
	if left, _ := filepath.Glob(filepath.Join(open, "askpass-*")); len(left) != 0 {
		t.Fatalf("left in the open directory: %v", left)
	}
	ln, path, err := listenAskpass(filepath.Join(privateDir(t), "agent.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if fi, err := os.Lstat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("the socket: %v %v", fi, err)
	}
}

// rawAsk sends line to the askpass socket as the askpass would and returns
// what came back until the server closed.
func rawAsk(t *testing.T, sock, line string) string {
	t.Helper()
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(c, line); err != nil {
		t.Fatal(err)
	}
	_ = c.(*net.UnixConn).CloseWrite()
	b, _ := io.ReadAll(c)
	return string(b)
}

// A prompt the server cannot read, parse or fit is answered with ssh ended,
// not with silence that OpenSSH turns into an empty password (task 6 review
// M-1).
func TestAnUnreadablePromptEndsSSH(t *testing.T) {
	dir, err := os.MkdirTemp("", "p49a")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "a.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var killed atomic.Int32
	srv := &askpassServer{ln: ln, token: "LOGINTOKEN", username: "alice", device: "leaf1"}
	srv.setKill(func() { killed.Add(1) })
	go srv.serve()
	for name, line := range map[string]string{
		"not quoted": "alice@leaf1's password: \n",
		"too long":   strconv.Quote(strings.Repeat("a", 2*maxPrompt)) + "\n",
		"no newline": strconv.Quote("alice@leaf1's password: "),
	} {
		before := killed.Load()
		if got := rawAsk(t, sock, line); strings.Contains(got, "LOGINTOKEN") || killed.Load() != before+1 {
			t.Errorf("%s: reply %v, killed %d times", name, strings.Contains(got, "LOGINTOKEN"), killed.Load()-before)
		}
	}
}

// An askpass that cannot reach port49 ssh ends its parent ssh before it exits
// non-zero; ssh would otherwise send an empty password. Only under the askpass
// environment (task 6 review M-1).
func TestAnAskpassThatCannotDialEndsSSH(t *testing.T) {
	var ended atomic.Int32
	prev := terminateSSH
	terminateSSH = func(sshParent) { ended.Add(1) }
	t.Cleanup(func() { terminateSSH = prev })
	sock := filepath.Join(t.TempDir(), "gone.sock")
	t.Setenv("SSH_ASKPASS_REQUIRE", "force")
	if code := askpassMain(sock, []string{"alice@leaf1's password: "}, io.Discard, io.Discard); code != 1 || ended.Load() != 1 {
		t.Fatalf("code %d, ssh ended %d times", code, ended.Load())
	}
	t.Setenv("SSH_ASKPASS_REQUIRE", "")
	if code := askpassMain(sock, []string{"alice@leaf1's password: "}, io.Discard, io.Discard); code != 1 || ended.Load() != 1 {
		t.Fatalf("outside the askpass environment: code %d, ssh ended %d times", code, ended.Load())
	}
}

// A socket a killed port49 ssh left, with no listener, is removed at the next
// run; one with a listener is not (task 6 review M-3).
func TestStaleAskpassSocketsAreSwept(t *testing.T) {
	dir := privateDir(t)
	stale := filepath.Join(dir, "askpass-0000000000000001.sock")
	ln, err := net.Listen("unix", stale)
	if err != nil {
		t.Fatal(err)
	}
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	ln.Close()
	old := time.Now().Add(-time.Minute)
	if err := os.Chtimes(stale, old, old); err != nil {
		t.Fatal(err)
	}
	live := filepath.Join(dir, "askpass-0000000000000002.sock")
	lv, err := net.Listen("unix", live)
	if err != nil {
		t.Fatal(err)
	}
	defer lv.Close()
	other := filepath.Join(dir, "agent.sock")
	if err := os.WriteFile(other, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	mine, _, err := listenAskpass(other)
	if err != nil {
		t.Fatal(err)
	}
	defer mine.Close()
	if _, err := os.Lstat(stale); err == nil {
		t.Error("the stale socket was kept")
	}
	for _, p := range []string{live, other} {
		if _, err := os.Lstat(p); err != nil {
			t.Errorf("%s was removed: %v", p, err)
		}
	}
}

// A jump host's prompt is the server's text: its control characters are not
// sent to the operator's terminal, its newlines are kept (task 6 review M-4).
func TestTerminalPromptHoldsNoControlCharacters(t *testing.T) {
	if got, want := terminalPrompt("Pass\x1b[2Jword\a:\nDo you? (yes/no) \r"), "Pass?[2Jword?:\nDo you? (yes/no) ?"; got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

// A ssh that names no OpenSSH version is pointed at `port49 token` (task 6
// review M-5).
func TestANonOpenSSHIsPointedAtPort49Token(t *testing.T) {
	dev := startDeviceSSH(t, []string{"password"}, "LOGINTOKEN", 0)
	r := newSSHRig(t, dev, sshPermit, 0, dev.key)
	fake := filepath.Join(t.TempDir(), "ssh")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\necho 'dropbear v2022.83' >&2\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	r.flags[1] = fake
	code, _, errb := r.run(t, "leaf1")
	if code != 1 || r.mints.Load() != 0 || !strings.Contains(errb, "port49 token leaf1") {
		t.Fatalf("code %d mints %d stderr %q", code, r.mints.Load(), errb)
	}
}

// Exit 255 for a reason that is not the host key says the host key hint
// conditionally, on ssh's own message above it: ssh's stderr goes straight to
// the caller's, so port49 ssh cannot tell (task 6 review M-5, re-review N-3).
func TestTheHostKeyHintIsConditionalOnSSHsMessage(t *testing.T) {
	dev := startDeviceSSH(t, []string{"password"}, "LOGINTOKEN", 0)
	r := newSSHRig(t, dev, sshPermit, 0, dev.key)
	fake := filepath.Join(t.TempDir(), "ssh")
	script := fakeSSHHead(r.known) + "echo 'remote username contains invalid characters' >&2\nexit 255\n"
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	r.flags[1] = fake
	code, _, errb := r.run(t, "leaf1")
	if code != 255 || !strings.Contains(errb, "so it was never sent") ||
		!strings.Contains(errb, "If it says Host key verification failed") ||
		!strings.Contains(errb, "run ssh-keygen -f "+r.known+" -R leaf1 and") || strings.Contains(errb, "devices trust") {
		t.Fatalf("code %d stderr %q", code, errb)
	}
}

// ssh's stderr is the caller's own, not a pipe port49 ssh holds: ssh's
// behaviour that depends on a terminal stays, and a descendant holding it
// cannot keep port49 ssh from returning (task 6 re-review N-3).
func TestSSHsStderrIsTheCallersOwn(t *testing.T) {
	dev := startDeviceSSH(t, []string{"password"}, "LOGINTOKEN", 0)
	r := newSSHRig(t, dev, sshPermit, 0, dev.key)
	fake := filepath.Join(t.TempDir(), "ssh")
	script := fakeSSHHead(r.known) + "sleep 3 >&2 &\nexit 0\n"
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	r.flags[1] = fake
	f, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	start := time.Now()
	var out lockedBuffer
	t.Setenv("PORT49_TEST_AGENT_SOCKET", r.sock)
	code := run(append(append([]string{"ssh"}, r.flags...), "leaf1"), &out, f)
	if code != 0 || time.Since(start) > 2*time.Second {
		t.Fatalf("code %d after %v: a descendant holding ssh's stderr held port49 ssh", code, time.Since(start))
	}
}
