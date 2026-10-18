package main

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/daemon/admin"
)

// serveStatus serves a store_status of text and degraded on a socket of the
// test's own, and returns its path.
func serveStatus(t *testing.T, text string, degraded bool) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "p.sock")
	ln, err := admin.Listen(p)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	srv := &admin.Server{Now: time.Now, StoreStatus: func(context.Context) (string, bool, error) {
		return text, degraded, nil
	}}
	go srv.Serve(ctx, ln)
	return p
}

// A process that reports no stores answers an error: exit 1 and the reason.
func TestStoreStatusExitsOneOnAnErrorAnswer(t *testing.T) {
	p := filepath.Join(t.TempDir(), "p.sock")
	ln, err := admin.Listen(p)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go (&admin.Server{Now: time.Now}).Serve(ctx, ln)
	var out, errb bytes.Buffer
	if code := run([]string{"store", "status", "--socket", p}, &out, &errb); code != 1 ||
		!strings.Contains(errb.String(), "this process reports no stores") || out.Len() != 0 {
		t.Fatalf("exit %d, out %q, err %q", code, out.String(), errb.String())
	}
}

func TestStoreStatusExitsByWhatItFound(t *testing.T) {
	ok := "directory  etcd    3/3 members  reachable  cache 0.4s\nsession    shares the directory store"
	var out, errb bytes.Buffer
	if code := run([]string{"store", "status", "--socket", serveStatus(t, ok, false)}, &out, &errb); code != 0 ||
		!strings.Contains(out.String(), "3/3 members  reachable") {
		t.Fatalf("exit %d, out %q, err %q", code, out.String(), errb.String())
	}
	out.Reset()
	if code := run([]string{"store", "status", "--socket", serveStatus(t, "directory  etcd    ?/3 members  unreachable", true)},
		&out, &errb); code != 3 {
		t.Fatalf("a store that does not answer exits %d, want 3", code)
	}
	if code := run([]string{"store", "status", "--socket", filepath.Join(t.TempDir(), "none.sock")}, &out, &errb); code != 1 {
		t.Fatalf("no socket exits %d, want 1", code)
	}
}
