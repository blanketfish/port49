//go:build linux

package main

import (
	"bytes"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

// stopAgentAt sends SIGTERM to whatever process listens on sock, found by
// the socket's peer credentials rather than by anything the test parsed,
// and waits for it to remove the socket. The test binary itself is never
// signalled.
func stopAgentAt(sock string) {
	c, err := net.Dial("unix", sock)
	if err != nil {
		return
	}
	var cred *syscall.Ucred
	if raw, err := c.(*net.UnixConn).SyscallConn(); err == nil {
		_ = raw.Control(func(fd uintptr) {
			cred, _ = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		})
	}
	c.Close()
	if cred == nil || int(cred.Pid) == os.Getpid() || cred.Pid <= 0 {
		return
	}
	_ = syscall.Kill(int(cred.Pid), syscall.SIGTERM)
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if _, err := os.Stat(sock); err != nil {
			return
		}
	}
}

// The real path: port49 login starts the agent, which logs in to a real
// broker, and refreshes at once, extending the device session the last
// login left; a second login finds the agent, names its broker, and
// refreshes it again.
func TestLoginStartsAnAgentAndRefreshes(t *testing.T) {
	l := newLabBroker(t, time.Hour)
	sock := privateSocket(t)
	// Registered before the login, so an agent that started is stopped
	// whatever the login printed.
	t.Cleanup(func() { stopAgentAt(sock) })
	t.Setenv(runCLIEnv, "1")
	var out, errb bytes.Buffer
	if code := run(append([]string{"login"}, l.flags(sock)...), &out, &errb); code != 0 ||
		!strings.Contains(out.String(), "port49: logged in to "+l.url) ||
		!strings.Contains(out.String(), "\nrefreshed at ") || !strings.Contains(out.String(), "  leaf1 (alice)  extended to ") {
		t.Fatalf("code %d stdout %q stderr %q", code, out.String(), errb.String())
	}
	l.step(11 * time.Second) // past the connection's refresh pacing
	out.Reset()
	if code := run(append([]string{"login"}, l.flags(sock)...), &out, &errb); code != 0 ||
		!strings.HasPrefix(out.String(), "port49: already logged in to "+l.url+"; refreshing\nrefreshed at ") ||
		!strings.Contains(out.String(), "  leaf1 (alice)  extended to ") {
		t.Fatalf("a second login: code %d stdout %q stderr %q", code, out.String(), errb.String())
	}
}
