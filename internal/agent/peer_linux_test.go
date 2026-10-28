package agent

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
)

// A connection to the agent's socket is attributed to the process that made it
// (SO_PEERCRED), not to the agent.
func TestConnContextNamesTheConnectingPeer(t *testing.T) {
	dir, err := os.MkdirTemp("", "p49peer")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	ln, err := net.Listen("unix", filepath.Join(dir, "s"))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan net.Conn, 1)
	go func() { c, _ := ln.Accept(); done <- c }()
	cl, err := net.Dial("unix", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	srv := <-done
	if srv == nil {
		t.Fatal("no accepted connection")
	}
	defer srv.Close()
	got := peerText(ConnContext(context.Background(), srv))
	if want := fmt.Sprintf(" peer_pid=%d peer_uid=%d", os.Getpid(), os.Getuid()); got != want {
		t.Fatalf("peer %q, want %q", got, want)
	}
	// A connection that is not a Unix socket records nothing.
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if got := peerText(ConnContext(context.Background(), a)); got != "" {
		t.Fatalf("a pipe has a peer: %q", got)
	}
}
