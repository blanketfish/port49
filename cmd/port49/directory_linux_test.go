//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/daemon/admin"
	"github.com/rhwendt/port49/internal/keyring"
)

// port49 directory forget sends one directory_forget op naming the
// principal and prints the answer; a refusal exits 1 on stderr; a missing
// or extra argument is a usage error (plan 7g, Ruling 3's escape).
func TestDirectoryForgetAsksTheAdminSocket(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "port49-broker.sock")
	ln, err := admin.Listen(socket)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var mu sync.Mutex
	var got []string
	srv := &admin.Server{Held: &keyring.Held{}, Now: time.Now,
		Forget: func(_ context.Context, principal string, _ uint32) (string, error) {
			mu.Lock()
			defer mu.Unlock()
			got = append(got, principal)
			if principal == "app:ci" {
				return "", errors.New("broker: \"app:ci\" is not a user: principal")
			}
			return "forgot " + principal, nil
		}}
	go srv.Serve(ctx, ln)

	var out, errb bytes.Buffer
	if code := run([]string{"directory", "forget", "--socket", socket, "user:alice@example.com"}, &out, &errb); code != 0 ||
		strings.TrimSpace(out.String()) != "forgot user:alice@example.com" {
		t.Fatalf("exit %d: %q %q", code, out.String(), errb.String())
	}
	out.Reset()
	if code := run([]string{"directory", "forget", "--socket", socket, "app:ci"}, &out, &errb); code != 1 ||
		!strings.Contains(errb.String(), "not a user: principal") {
		t.Fatalf("exit %d: %q", code, errb.String())
	}
	for _, args := range [][]string{{"directory", "forget", "--socket", socket}, {"directory", "forget", "--socket",
		socket, "user:a@b", "user:c@d"}, {"directory"}, {"directory", "remember", "user:a@b"}} {
		if code := run(args, &out, &errb); code != 2 {
			t.Fatalf("%v: exit %d, want 2", args, code)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 2 {
		t.Fatalf("the broker was asked %d times, want 2: %v", len(got), got)
	}
}
