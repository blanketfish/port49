package main

import (
	"bytes"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rhwendt/port49/internal/agent"
	"github.com/rhwendt/port49/internal/broker/api"
)

// A key that is out is said as the agent said it, without the "agent: "
// prefix, and the command fails. The error is the one the CLI really receives:
// the client's rebuild from the socket's key_absent answer.
func TestMintFailedSaysAnAbsentKeyAsTheAgentDid(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "a.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`{"error":"key_absent","detail":"agent: insert your key; your session goes on until 2026-10-13T09:00:00Z"}`))
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	_, err = agent.NewClient(sock).Token(t.Context(), agent.TokenRequest{Device: "leaf1"})
	if err == nil {
		t.Fatal("the agent's key_absent answer was not an error")
	}
	var stderr bytes.Buffer
	if !mintFailed("port49 token", "/s", "leaf1", api.MintItem{}, err, &stderr) {
		t.Fatal("mintFailed returned false for an absent key")
	}
	want := "port49 token: insert your key; your session goes on until 2026-10-13T09:00:00Z"
	if !strings.HasPrefix(stderr.String(), want) || strings.Contains(stderr.String(), "agent:") {
		t.Fatalf("stderr = %q, want it to start %q", stderr.String(), want)
	}
}
