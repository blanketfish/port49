//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
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

// `port49 directory reset-second-factor [--all]`, `unlock`,
// `init-enrollments`, `export` and `import [--replace]` over the socket: no
// secret on stdout's text; export to a terminal is refused ("redirect it to a
// file"); import without --replace over a later enrollment exits 1 naming
// --replace.
func TestDirectorySignInCommands(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "port49-broker.sock")
	ln, err := admin.Listen(socket)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sealed := []byte(`{"port49_enrollments":1,"key_id":"k","sealed":"c2VhbGVk"}`)
	var mu sync.Mutex
	var got []string
	note := func(s string, a ...any) { mu.Lock(); got = append(got, fmt.Sprintf(s, a...)); mu.Unlock() }
	srv := &admin.Server{Held: &keyring.Held{}, Now: time.Now,
		SecondFactorReset: func(_ context.Context, p string, all bool, _ uint32) (string, error) {
			note("reset %q all=%v", p, all)
			return "reset " + p + " (enrolled 2026-01-02T03:04:05Z from 192.0.2.0/32)", nil
		},
		SignInUnlock: func(_ context.Context, p string, _ uint32) (string, error) {
			note("unlock %q", p)
			return "cleared 3 failed sign-ins for " + p, nil
		},
		EnrollmentsInit: func(context.Context, uint32) (string, error) {
			note("init")
			return "", errors.New("broker: the enrollment store is already there: import or reset-second-factor --all")
		},
		EnrollmentsExport: func(context.Context, uint32) ([]byte, error) { note("export"); return sealed, nil },
		EnrollmentsImport: func(_ context.Context, body []byte, replace bool, _ uint32) (string, error) {
			note("import %d bytes replace=%v", len(body), replace)
			if !replace {
				return "", errors.New("broker: the store holds a second factor enrolled after this export: run it with --replace")
			}
			return "imported 1 second factors exported at 2026-01-02T03:04:05Z", nil
		}}
	go srv.Serve(ctx, ln)
	in := func(s string) { directoryStdin = strings.NewReader(s) }
	defer func(r io.Reader) { directoryStdin = r }(directoryStdin)

	do := func(args ...string) (int, string, string) {
		var out, errb bytes.Buffer
		code := run(append([]string{"directory"}, append(args[:1:1], append([]string{"--socket", socket}, args[1:]...)...)...),
			&out, &errb)
		return code, out.String(), errb.String()
	}
	if code, out, errb := do("reset-second-factor", "USER:Alice@Example.com"); code != 0 || !strings.Contains(out, "enrolled") || errb != "" {
		t.Fatalf("reset: %d %q %q", code, out, errb)
	}
	if code, out, errb := do("reset-second-factor", "--all"); code != 0 || !strings.Contains(out, "reset ") || errb != "" {
		t.Fatalf("reset --all: %d %q %q", code, out, errb)
	}
	if code, out, _ := do("unlock", "user:alice@example.com"); code != 0 || strings.TrimSpace(out) != "cleared 3 failed sign-ins for user:alice@example.com" {
		t.Fatalf("unlock: %d %q", code, out)
	}
	if code, out, errb := do("init-enrollments"); code != 1 || out != "" || !strings.Contains(errb, "already there") {
		t.Fatalf("init: %d %q %q", code, out, errb)
	}
	if code, out, errb := do("export"); code != 0 || out != string(sealed) || strings.Contains(errb, "c2VhbGVk") ||
		!strings.Contains(errb, "exported 57 bytes") {
		t.Fatalf("export: %d %q %q", code, out, errb)
	}
	in(string(sealed))
	if code, out, errb := do("import"); code != 1 || out != "" || !strings.Contains(errb, "--replace") {
		t.Fatalf("import over a later enrollment: %d %q %q", code, out, errb)
	}
	in(string(sealed))
	if code, out, errb := do("import", "--replace"); code != 0 || !strings.HasPrefix(out, "imported 1 second factors") || errb != "" {
		t.Fatalf("import --replace: %d %q %q", code, out, errb)
	}
	in("")
	if code, _, errb := do("import"); code != 1 || !strings.Contains(errb, "no export on standard input") {
		t.Fatalf("an empty import: %d %q", code, errb)
	}

	// The terminal refuses an export before the broker is asked.
	_, slave := openPty(t)
	mu.Lock()
	got = nil
	mu.Unlock()
	var errb bytes.Buffer
	if code := run([]string{"directory", "export", "--socket", socket}, slave, &errb); code != 1 ||
		!strings.Contains(errb.String(), "redirect it to a file") {
		t.Fatalf("export to a terminal: %d %q", code, errb.String())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 0 {
		t.Fatalf("an export to a terminal reached the broker: %v", got)
	}
}

// reset-second-factor takes a principal or --all, one of them; the others take
// what their usage says: a wrong argument count is usage, exit 2.
func TestDirectorySignInCommandsTakeTheirArguments(t *testing.T) {
	for _, args := range [][]string{{"directory", "reset-second-factor"},
		{"directory", "reset-second-factor", "--all", "user:a@b"},
		{"directory", "reset-second-factor", "user:a@b", "user:c@d"},
		{"directory", "unlock"}, {"directory", "init-enrollments", "extra"}, {"directory", "export", "extra"},
		{"directory", "import", "extra"}, {"directory", "export", "--all"}} {
		var out, errb bytes.Buffer
		if code := run(args, &out, &errb); code != 2 {
			t.Errorf("%v: exit %d %q", args, code, errb.String())
		}
	}
}
