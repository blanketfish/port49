package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/agent"
	"github.com/rhwendt/port49/internal/testpki"
)

// The agent child trusts the CA bytes the login read and passed on its
// --broker-ca-fd, not whatever the --broker-ca path holds by then: here the
// path names another CA, as if the file had been swapped after the login read
// it, and the agent still reaches the broker.
func TestTheAgentTrustsTheCABytesItIsHanded(t *testing.T) {
	l := newLabBroker(t, time.Hour)
	real, err := os.ReadFile(filepath.Join(l.dir, testpki.LabCA))
	if err != nil {
		t.Fatal(err)
	}
	other, err := testpki.NewCA("someone else", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	swapped := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(swapped, other.PEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	flags := func(sock string) []string {
		t.Setenv("PORT49_TEST_AGENT_SOCKET", sock)
		return []string{"--broker", l.url, "--cert", filepath.Join(l.dir, testpki.LabClientCert),
			"--key", filepath.Join(l.dir, testpki.LabClientKey), "--broker-ca", swapped}
	}

	// Without the fd the swapped file is what the agent trusts, and it refuses.
	var log lockedBuffer
	if code := run(append([]string{"agent"}, flags(privateSocket(t))...), io.Discard, &log); code == 0 {
		t.Fatalf("an agent trusted a CA that did not issue the broker's certificate: %s", log.String())
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := w.Write(real); err != nil {
		t.Fatal(err)
	}
	w.Close()
	// The agent owns the descriptor it is handed: config() wraps it and closes
	// it. It is given a dup, so the close above and the agent's close are of
	// two descriptors, not one number closed twice.
	handed, err := syscall.Dup(int(r.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	sock := privateSocket(t)
	t.Cleanup(func() { stopAgentAt(sock) })
	var log2 lockedBuffer
	exited := make(chan int, 1)
	go func() {
		exited <- run(append(append([]string{"agent"}, flags(sock)...), "--broker-ca-fd", strconv.Itoa(handed)),
			io.Discard, &log2)
	}()
	c := agent.NewClient(sock)
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		if _, err := c.Status(context.Background()); err == nil {
			return
		}
		select {
		case code := <-exited:
			t.Fatalf("the agent exited %d: %s", code, log2.String())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("the agent never answered: %s", log2.String())
		}
	}
}

// Bytes the login passed that hold no certificate are reported as the login's,
// not as the --broker-ca path, which was not read.
func TestACAFromTheLoginThatHoldsNoCertificateNamesItsSource(t *testing.T) {
	l := newLabBroker(t, time.Hour)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := w.WriteString("not a certificate\n"); err != nil {
		t.Fatal(err)
	}
	w.Close()
	handed, err := syscall.Dup(int(r.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	var log lockedBuffer
	t.Setenv("PORT49_TEST_AGENT_SOCKET", privateSocket(t))
	code := run([]string{"agent", "--broker", l.url, "--cert", filepath.Join(l.dir, testpki.LabClientCert),
		"--key", filepath.Join(l.dir, testpki.LabClientKey), "--broker-ca", "/etc/port49/ca.pem", "--broker-ca-fd", strconv.Itoa(handed)}, io.Discard, &log)
	if code == 0 || !strings.Contains(log.String(), "the broker CA the login passed (from /etc/port49/ca.pem) holds no PEM certificate") {
		t.Fatalf("code %d: %s", code, log.String())
	}
}
