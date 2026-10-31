//go:build linux

package main

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/testpki"
	"github.com/rhwendt/port49/internal/userconfig"
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

// A broker that sends a CA bundle: the agent the login starts keeps it in
// ~/.port49/broker_ca/, 0600, and logs it by fingerprint. A later login
// whose broker_ca is only the next CA still reaches the broker, through the
// kept bundle: the rotation's first half, with nothing asked of the user
// (decision 43 ruling 25).
func TestTheAgentKeepsTheBrokersCABundle(t *testing.T) {
	l := newLabBroker(t, time.Hour)
	next, err := testpki.NewCA("port49 lab next CA", time.Now().Add(-time.Hour), time.Now().Add(48*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	cur, err := os.ReadFile(filepath.Join(l.dir, testpki.LabCA))
	if err != nil {
		t.Fatal(err)
	}
	l.b.CABundle = append(append([]byte{}, cur...), next.PEM()...)
	t.Setenv("HOME", privateDir(t))
	sock := privateSocket(t)
	t.Cleanup(func() { stopAgentAt(sock) })
	t.Setenv(runCLIEnv, "1")
	var out, errb bytes.Buffer
	if code := run(append([]string{"login"}, l.flags(t, sock)...), &out, &errb); code != 0 {
		t.Fatalf("code %d stdout %q stderr %q", code, out.String(), errb.String())
	}
	path, err := userconfig.CABundlePath(l.url)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(raw, l.b.CABundle) {
		t.Fatalf("%v %q", err, raw)
	}
	certs, _ := api.ParseCABundle(raw)
	if log, _ := os.ReadFile(filepath.Join(filepath.Dir(sock), "agent.log")); !strings.Contains(string(log),
		"kept the broker's CA bundle in "+path+": "+api.CAFingerprints(certs)) {
		t.Fatalf("the agent's log: %q", log)
	}
	stopAgentAt(sock)
	nextOnly := filepath.Join(privateDir(t), "next.pem")
	if err := os.WriteFile(nextOnly, next.PEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	flags := l.flags(t, sock)
	for i := range flags {
		if flags[i] == "--broker-ca" {
			flags[i+1] = nextOnly
		}
	}
	out.Reset()
	if code := run(append([]string{"login"}, flags...), &out, &errb); code != 0 ||
		!strings.Contains(out.String(), "port49: logged in to "+l.url) {
		t.Fatalf("a login on the next CA alone: code %d stdout %q stderr %q", code, out.String(), errb.String())
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
	if code := run(append([]string{"login"}, l.flags(t, sock)...), &out, &errb); code != 0 ||
		!strings.Contains(out.String(), "port49: logged in to "+l.url) ||
		!strings.Contains(out.String(), "\nrefreshed at ") || !strings.Contains(out.String(), "  leaf1 (alice)  extended to ") {
		t.Fatalf("code %d stdout %q stderr %q", code, out.String(), errb.String())
	}
	l.step(11 * time.Second) // past the connection's refresh pacing
	out.Reset()
	if code := run(append([]string{"login"}, l.flags(t, sock)...), &out, &errb); code != 0 ||
		!strings.HasPrefix(out.String(), "port49: already logged in to "+l.url+"; refreshing\nrefreshed at ") ||
		!strings.Contains(out.String(), "  leaf1 (alice)  extended to ") {
		t.Fatalf("a second login: code %d stdout %q stderr %q", code, out.String(), errb.String())
	}
}
