package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/rhwendt/port49/internal/broker"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/session"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/memory"
)

func newMetrics() *metrics.Metrics { return metrics.New(prometheus.NewRegistry()) }

// A mark put in force before a restart is in force after it: the file is
// what a restart reads back (spec §13 decision 32).
func TestRevocationsSurviveARestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(safeDir(t), "revocations.json")
	if _, created, err := restoreRevocations(ctx, memory.New(time.Now), path, newMetrics()); err != nil || !created {
		t.Fatalf("first start: %v %v", created, err)
	}
	at := time.Date(2026, 10, 2, 3, 12, 9, 0, time.UTC)
	before := memory.New(time.Now)
	for _, r := range []store.Revocation{
		{Kind: store.RevocationPrincipal, Key: "user:alice@example.com", At: at, Origin: "admin_socket uid 0"},
		{Kind: store.RevocationCert, Key: store.CertKey("CN=Corp CA,O=Example", "3f9a01"), At: at, Origin: "admin_socket uid 0"},
	} {
		if err := before.PutRevocation(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	if err := persister(before, path, newMetrics())(ctx); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("the file: %v %v", fi, err)
	}
	after := memory.New(time.Now)
	m := newMetrics()
	rs, created, err := restoreRevocations(ctx, after, path, m)
	if err != nil || created || len(rs) != 2 {
		t.Fatalf("%d %v %v", len(rs), created, err)
	}
	got, err := after.GetRevocation(ctx, store.RevocationPrincipal, "user:alice@example.com")
	if err != nil || !got.At.Equal(at) || got.Origin != "admin_socket uid 0" {
		t.Fatalf("%+v %v", got, err)
	}
	if testutil.ToFloat64(m.RevocationsInForce.WithLabelValues("cert")) != 1 {
		t.Fatal("port49_revocations_in_force{by=cert}")
	}
}

// The first start writes the marker, then an empty file, and says so; a
// later start that finds the file gone refuses, because "never written" and
// "deleted" are no longer the same thing (pre-flight C1).
func TestTheFirstStartCreatesTheFileAndALaterMissingOneRefuses(t *testing.T) {
	path := filepath.Join(safeDir(t), "revocations.json")
	rs, created, err := loadRevocations(path)
	if err != nil || !created || len(rs) != 0 {
		t.Fatalf("first start: %v %v %v", rs, created, err)
	}
	for _, p := range []string{path, path + ".created"} {
		if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", p, fi, err)
		}
	}
	if _, created, err := loadRevocations(path); err != nil || created {
		t.Fatalf("second start: %v %v", created, err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadRevocations(path); err == nil || !strings.Contains(err.Error(), "is missing") {
		t.Fatalf("a deleted file after the first start: %v", err)
	}
}

// The directory is fenced whether or not the file exists: a missing
// directory, or one others can write, refuses the start before "missing"
// can mean anything (pre-flight C1).
func TestTheDirectoryIsFencedWithOrWithoutTheFile(t *testing.T) {
	if _, _, err := loadRevocations(filepath.Join(safeDir(t), "missing", "revocations.json")); err == nil {
		t.Fatal("a missing directory read as no revocations")
	}
	open := safeDir(t)
	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadRevocations(filepath.Join(open, "revocations.json")); err == nil {
		t.Fatal("a missing file in a directory others can write read as no revocations")
	}
	if _, err := os.Lstat(filepath.Join(open, "revocations.json.created")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a refused directory was written: %v", err)
	}
}

// A file port49d cannot read whole refuses the start: a port49d that
// forgot a revocation would mint for a stolen certificate again.
func TestARevocationsFileThatDoesNotLoadRefusesTheStart(t *testing.T) {
	for name, body := range map[string]string{
		"not json":      "{",
		"unknown field": `{"revocations":[],"extra":1}`,
		"unknown kind":  `{"revocations":[{"kind":"sid","key":"x","at":"2026-10-02T03:12:09Z","origin":"o"}]}`,
		"empty key":     `{"revocations":[{"kind":"principal","key":"","at":"2026-10-02T03:12:09Z","origin":"o"}]}`,
		"bad time":      `{"revocations":[{"kind":"principal","key":"user:a@b","at":"yesterday","origin":"o"}]}`,
		"control char":  `{"revocations":[{"kind":"principal","key":"user:a\n@b","at":"2026-10-02T03:12:09Z","origin":"o"}]}`,
	} {
		path := filepath.Join(safeDir(t), "revocations.json")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := loadRevocations(path); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
}

// A mark the file holds but the store refuses (a certificate key with no
// issuer) refuses the start too, named by its index: it never loads as a
// mark that matches nothing (Task 5 review).
func TestAMarkTheStoreRefusesRefusesTheStart(t *testing.T) {
	path := filepath.Join(safeDir(t), "revocations.json")
	if err := os.WriteFile(path, []byte(`{"revocations":[{"kind":"cert","key":"3f9a01",`+
		`"at":"2026-10-02T03:12:09Z","origin":"o"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := restoreRevocations(context.Background(), memory.New(time.Now), path, newMetrics()); err == nil ||
		!strings.Contains(err.Error(), "revocation 0") {
		t.Fatalf("a certificate mark with no issuer: %v", err)
	}
}

// The file decides who is refused, so it is read behind the fence: one
// another user could write is refused, and so is a link in its name.
func TestARevocationsFileOthersCouldWriteIsRefused(t *testing.T) {
	dir := safeDir(t)
	path := filepath.Join(dir, "revocations.json")
	if err := os.WriteFile(path, []byte(`{"revocations":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o622); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadRevocations(path); err == nil {
		t.Fatal("a world-writable revocations file loaded")
	}
	link := filepath.Join(dir, "linked.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadRevocations(link); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("a link: %v", err)
	}
}

// A write that fails raises port49_revocations_file_failed; the next that
// succeeds lowers it.
func TestAFailedWriteIsAlarmed(t *testing.T) {
	m := newMetrics()
	st := memory.New(time.Now)
	if err := persister(st, filepath.Join(safeDir(t), "missing", "revocations.json"), m)(context.Background()); err == nil {
		t.Fatal("a write into a missing directory succeeded")
	}
	if testutil.ToFloat64(m.RevocationsFileFailed) != 1 {
		t.Fatal("not alarmed")
	}
	if err := persister(st, filepath.Join(safeDir(t), "revocations.json"), m)(context.Background()); err != nil {
		t.Fatal(err)
	}
	if testutil.ToFloat64(m.RevocationsFileFailed) != 0 {
		t.Fatal("not cleared")
	}
}

// hangWrites makes every revocations file write block until the returned
// release is called, and shortens persistDeadline to d.
func hangWrites(t *testing.T, d time.Duration) (release func()) {
	t.Helper()
	gate := make(chan struct{})
	w, pd := writeRevocations, persistDeadline
	writeRevocations = func(path string, rs []store.Revocation) error {
		<-gate
		return saveRevocations(path, rs)
	}
	persistDeadline = d
	var once bool
	release = func() {
		if !once {
			once = true
			close(gate)
		}
	}
	t.Cleanup(func() {
		release()
		writeRevocations, persistDeadline = w, pd
	})
	return release
}

// A write to a hung mount does not hang Persist: it gives up at its
// deadline, unsaved and alarmed. A later call waits behind the hung write
// under its own deadline rather than writing beside it, so the abandoned
// write can never land after a newer one and drop a mark; once the hung
// write returns, the next call writes every mark (Task 8 review).
func TestAHungWriteGivesUpAtItsDeadline(t *testing.T) {
	ctx := context.Background()
	m := newMetrics()
	st := memory.New(time.Now)
	path := filepath.Join(safeDir(t), "revocations.json")
	persist := persister(st, path, m)
	release := hangWrites(t, 50*time.Millisecond)
	put := func(key string) {
		if err := st.PutRevocation(ctx, store.Revocation{Kind: store.RevocationPrincipal, Key: key, At: time.Now(),
			Origin: "test"}); err != nil {
			t.Fatal(err)
		}
	}
	put("user:alice@example.com")
	for i, want := range []string{"the write did not return", "an earlier write has not returned"} {
		start := time.Now()
		err := persist(ctx)
		if err == nil || !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), want) ||
			!strings.Contains(err.Error(), path) {
			t.Fatalf("call %d: %v", i, err)
		}
		if took := time.Since(start); took > 2*time.Second {
			t.Fatalf("call %d took %s", i, took)
		}
		if testutil.ToFloat64(m.RevocationsFileFailed) != 1 {
			t.Fatalf("call %d: not alarmed", i)
		}
		put("user:bob@example.com")
	}
	release()
	persistDeadline = 5 * time.Second
	if err := persist(ctx); err != nil {
		t.Fatal(err)
	}
	rs, _, err := loadRevocations(path)
	if err != nil || len(rs) != 2 {
		t.Fatalf("after the hung write returned: %v %v", rs, err)
	}
	if testutil.ToFloat64(m.RevocationsFileFailed) != 0 {
		t.Fatal("not cleared")
	}
}

// A revocation behind a hung write is not held by it: Revoke, as port49d
// wires it, returns unsaved within the deadline, the mark standing in the
// store, so its token and context passes run (Task 8 review).
func TestARevocationBehindAHungWriteIsReportedUnsaved(t *testing.T) {
	cfg := brokerConfig(t, minimalPolicy)
	st := memory.New(time.Now)
	m := newMetrics()
	_, brk, err := buildBroker(cfg, "inventory_file "+cfg.InventoryFile, st, seedMinter(),
		decision.NewJSONLines(io.Discard), m)
	if err != nil {
		t.Fatal(err)
	}
	brk.Sessions = session.New(st, time.Now, time.Hour, time.Hour)
	brk.Persist = persister(st, filepath.Join(safeDir(t), "revocations.json"), m)
	hangWrites(t, 50*time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rep, err := brk.Revoke(ctx, broker.RevokeRequest{Principal: "user:alice@example.com", Origin: "test"})
	if err != nil || rep.Saved || rep.SaveErr == nil || !errors.Is(rep.SaveErr, context.DeadlineExceeded) {
		t.Fatalf("%+v %v", rep, err)
	}
	if _, err := st.GetRevocation(ctx, store.RevocationPrincipal, "user:alice@example.com"); err != nil {
		t.Fatalf("the mark: %v", err)
	}
	if ctx.Err() != nil {
		t.Fatal("Revoke waited out the caller's deadline")
	}
}
