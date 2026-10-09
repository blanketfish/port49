package main

import (
	"bytes"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// A connection that closes having sent nothing is not a prompt: it is another
// run's sweep dialling this socket, and it must not end this session (task 6
// re-review N-1).
func TestAConnectionThatSendsNothingIsNotAPrompt(t *testing.T) {
	dir, err := os.MkdirTemp("", "p49n")
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
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	// The server answers the next connection only after it is done with the
	// first, so a real ask that comes back proves the empty one is over.
	if got := rawAsk(t, sock, "\"bob@jump's password: \"\n"); got != "N\n" {
		t.Fatalf("the next ask got %q", got)
	}
	if killed.Load() != 0 {
		t.Fatalf("an empty connection ended ssh %d times", killed.Load())
	}
}

// A live session survives another port49 ssh's sweep of the askpass sockets
// (task 6 re-review N-1).
func TestALiveSessionSurvivesAnotherRunsSweep(t *testing.T) {
	prev := staleAge
	staleAge = 0
	t.Cleanup(func() { staleAge = prev })
	dev := startDeviceSSH(t, []string{"password"}, "LOGINTOKEN", 3*time.Second)
	r := newSSHRig(t, dev, sshPermit, 0, dev.key)
	type result struct {
		code      int
		out, errb string
	}
	done := make(chan result, 1)
	go func() {
		code, out, errb := r.run(t, "leaf1", "--", "show", "version")
		done <- result{code, out, errb}
	}()
	deadline := time.Now().Add(10 * time.Second)
	for len(dev.attempts()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the device was never sent the token")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if socks, _ := filepath.Glob(filepath.Join(filepath.Dir(r.sock), "askpass-*.sock")); len(socks) != 1 {
		t.Fatalf("expected the session's one askpass socket, got %v", socks)
	}
	removeStaleAskpassSockets(filepath.Dir(r.sock))
	res := <-done
	if res.code != 0 || res.out != "ran: show version\n" {
		t.Fatalf("the sweep ended a live session: code %d stdout %q stderr %q", res.code, res.out, res.errb)
	}
	tokenNowhere(t, res.out, res.errb)
}

// ssh runs the askpass by the path it was given, and port49 may be gone from
// that path by the time the device asks: a failed exec makes OpenSSH send the
// device an empty password. On Linux the askpass is the running image itself
// (task 6 re-review M-1).
func TestAskpassSurvivesPort49BeingDeletedMidSession(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the /proc/<pid>/exe askpass is Linux's")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	copyDir := t.TempDir()
	copyBin := filepath.Join(copyDir, "port49")
	b, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(copyBin, b, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{"keyboard-interactive", "password"} {
		dev := startDeviceSSH(t, []string{method}, "LOGINTOKEN", 0)
		r := newSSHRig(t, dev, sshPermit, 0, dev.key)
		// An ssh that removes port49 before it connects, then is the real one.
		wrap := filepath.Join(t.TempDir(), "ssh")
		script := "#!/bin/sh\nif [ \"$1\" = -V ]; then exec " + r.flags[3] + " -V; fi\nrm -f " + copyBin +
			"\nexec " + r.flags[3] + " \"$@\"\n"
		if err := os.WriteFile(wrap, []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
		r.flags[3] = wrap
		if err := os.WriteFile(copyBin, b, 0o755); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(copyBin, append(append([]string{"ssh"}, r.flags...), "leaf1", "--", "show", "version")...)
		cmd.Env = append(os.Environ(), runCLIEnv+"=1")
		var out, errb bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errb
		if err := cmd.Run(); err != nil || out.String() != "ran: show version\n" ||
			strings.Join(dev.attempts(), ",") != "LOGINTOKEN" {
			t.Errorf("%s: %v stdout %q stderr %q attempts %q", method, err, out.String(), errb.String(), dev.attempts())
		}
		tokenNowhere(t, out.String(), errb.String())
		if _, err := os.Stat(copyBin); err == nil {
			t.Errorf("%s: the copy was not deleted, so the test proved nothing", method)
		}
	}
}

// Only a socket that is both refused and older than staleAge is swept: a run
// that is between Listen and its first Accept is neither (task 6 re-review
// N-4).
func TestOnlyOldRefusedSocketsAreSwept(t *testing.T) {
	dir := privateDir(t)
	mk := func(name string, age time.Duration) string {
		p := filepath.Join(dir, name)
		ln, err := net.Listen("unix", p)
		if err != nil {
			t.Fatal(err)
		}
		ln.(*net.UnixListener).SetUnlinkOnClose(false)
		ln.Close()
		when := time.Now().Add(-age)
		if err := os.Chtimes(p, when, when); err != nil {
			t.Fatal(err)
		}
		return p
	}
	fresh := mk("askpass-0000000000000001.sock", time.Second)
	old := mk("askpass-0000000000000002.sock", time.Minute)
	removeStaleAskpassSockets(dir)
	if _, err := os.Lstat(fresh); err != nil {
		t.Errorf("a socket one second old was swept: %v", err)
	}
	if _, err := os.Lstat(old); err == nil {
		t.Error("a refused socket a minute old was kept")
	}
}
