package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strconv"
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
		return []string{"--broker", l.url, "--cert", filepath.Join(l.dir, testpki.LabClientCert),
			"--key", filepath.Join(l.dir, testpki.LabClientKey), "--broker-ca", swapped, "--socket", sock}
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
	sock := privateSocket(t)
	t.Cleanup(func() { stopAgentAt(sock) })
	var log2 lockedBuffer
	exited := make(chan int, 1)
	go func() {
		exited <- run(append(append([]string{"agent"}, flags(sock)...), "--broker-ca-fd", strconv.Itoa(int(r.Fd()))),
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
