package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"io/fs"
	"net"
	"net/http"
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
	"github.com/rhwendt/port49/internal/token"
)

func newMetrics() *metrics.Metrics { return metrics.New(prometheus.NewRegistry()) }

// testInitConfig is the config path initRevocations is told it read, for
// the line its refusals give to run.
const testInitConfig = "/etc/port49/port49d.yaml"

// A mark put in force before a restart is in force after it: the file is
// what a restart reads back (spec §13 decision 32).
func TestRevocationsSurviveARestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(safeDir(t), "revocations.json")
	if created, err := initRevocations(path, testInitConfig); err != nil || !created {
		t.Fatalf("init: %v %v", created, err)
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
	if err := persister(before, path, nil, nil, newMetrics())(ctx); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("the file: %v %v", fi, err)
	}
	after := memory.New(time.Now)
	rs, err := restoreRevocations(ctx, after, path)
	if err != nil || len(rs) != 2 {
		t.Fatalf("%d %v", len(rs), err)
	}
	got, err := after.GetRevocation(ctx, store.RevocationPrincipal, "user:alice@example.com")
	if err != nil || !got.At.Equal(at) || got.Origin != "admin_socket uid 0" {
		t.Fatalf("%+v %v", got, err)
	}
}

// Between an etcd restore that lost a mark and the marks feed's reload, a
// persist on this process keeps the mark in the file while this process
// enforces it, so the reload's put-back still finds it; a mark this
// process lifted, or saw lifted, is dropped (final review 7e-1 C-1). The
// put-back puts back only the file's marks this process enforces and the
// store lacks, and says how many.
func TestAPersistBeforeTheReloadKeepsAMarkARestoreLost(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(safeDir(t), "revocations.json")
	if _, err := initRevocations(path, testInitConfig); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 3, 3, 0, 0, 0, time.UTC)
	lost := store.Revocation{Kind: store.RevocationPrincipal, Key: "user:alice@example.com", At: at, Origin: "admin_socket uid 0"}
	lifted := store.Revocation{Kind: store.RevocationPrincipal, Key: "user:carol@example.com", At: at, Origin: "admin_socket uid 0"}
	kept := store.Revocation{Kind: store.RevocationCert, Key: store.CertKey("CN=Corp CA,O=Example", "3f9a01"), At: at,
		Origin: "admin_socket uid 0"}
	held := []store.Revocation{kept, lost, lifted}
	if err := saveRevocations(path, held); err != nil {
		t.Fatal(err)
	}
	enforced := store.NewMarks()
	for _, r := range held {
		enforced.Set(r, true)
	}
	enforced.Set(lifted, false) // its lift, made here or brought by the feed
	// A reload before any persist since the lift: the file still holds it.
	empty := memory.New(time.Now)
	if n, err := putBackFileMarks(ctx, empty, path, enforced); err != nil || n != 2 {
		t.Fatalf("put back %d: %v", n, err)
	}
	if _, err := empty.GetRevocation(ctx, lifted.Kind, lifted.Key); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a mark this process saw lifted was put back: %v", err)
	}
	st := memory.New(time.Now) // the restored store: it holds only kept
	if err := st.PutRevocation(ctx, kept); err != nil {
		t.Fatal(err)
	}
	if err := persister(st, path, held, enforced, newMetrics())(ctx); err != nil {
		t.Fatal(err)
	}
	rs, err := readRevocations(path)
	if err != nil || len(rs) != 2 || rs[0].Key != kept.Key || rs[1].Key != lost.Key || !rs[1].At.Equal(at) {
		t.Fatalf("the file after a persist in the window: %+v %v", rs, err)
	}

	n, err := putBackFileMarks(ctx, st, path, enforced)
	if err != nil || n != 1 {
		t.Fatalf("put back %d: %v", n, err)
	}
	if got, err := st.GetRevocation(ctx, lost.Kind, lost.Key); err != nil || !got.At.Equal(at) {
		t.Fatalf("the lost mark is not back in the store: %+v %v", got, err)
	}
	if _, err := st.GetRevocation(ctx, lifted.Kind, lifted.Key); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a lifted mark was put back: %v", err)
	}
	if n, err := putBackFileMarks(ctx, st, path, enforced); err != nil || n != 0 {
		t.Fatalf("a second put-back: %d %v", n, err)
	}

	// Lifted here: the next persist drops it, and a reload puts nothing back.
	enforced.Set(lost, false)
	if err := st.DeleteRevocation(ctx, lost.Kind, lost.Key); err != nil {
		t.Fatal(err)
	}
	if err := persister(st, path, rs, enforced, newMetrics())(ctx); err != nil {
		t.Fatal(err)
	}
	if rs, err := readRevocations(path); err != nil || len(rs) != 1 || rs[0].Key != kept.Key {
		t.Fatalf("the file after a lift: %+v %v", rs, err)
	}
	if n, err := putBackFileMarks(ctx, st, path, enforced); err != nil || n != 0 {
		t.Fatalf("a put-back after a lift: %d %v", n, err)
	}
}

// A start never creates the file (spec §13 decision 32, amended
// 2026-10-02): a fresh directory, or a mounted volume left empty, refuses
// every start and writes nothing. The refusal leads with the upgrade case,
// so an operator whose volume did not mount mounts it rather than running
// the first-install init on an empty mount point (pre-flight M13).
func TestAStartNeverCreatesTheFile(t *testing.T) {
	path := filepath.Join(safeDir(t), "revocations.json")
	for i := 0; i < 2; i++ {
		_, err := loadRevocations(path)
		if err == nil || !strings.HasPrefix(err.Error(), "does not exist: if port49d has run here before, the "+
			"volume holding it is missing or empty") || !strings.Contains(err.Error(), "port49d init-revocations") {
			t.Fatalf("start %d on an empty directory: %v", i, err)
		}
	}
	for _, p := range []string{path, markerOf(path)} {
		if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("a start wrote %s: %v", p, err)
		}
	}
}

// init writes the marker and an empty file, 0600, and a start loads them.
// Run again over a file that loads, it writes nothing and says so, so a
// provisioning step may run it twice (pre-flight I6). Over a file that does
// not load it refuses and leaves it. Over a lost file (the marker still
// there) it refuses, so it never papers over revocations that were lost; a
// start then says they were lost.
func TestInitRevocationsCreatesOnceAndNeverOverALoss(t *testing.T) {
	path := filepath.Join(safeDir(t), "revocations.json")
	if created, err := initRevocations(path, testInitConfig); err != nil || !created {
		t.Fatalf("the first init: %v %v", created, err)
	}
	for _, p := range []string{path, markerOf(path)} {
		if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", p, fi, err)
		}
	}
	if rs, err := loadRevocations(path); err != nil || len(rs) != 0 {
		t.Fatalf("the start after init: %v %v", rs, err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if created, err := initRevocations(path, testInitConfig); err != nil || created {
		t.Fatalf("a second init over a file that loads: %v %v", created, err)
	}
	if after, err := os.ReadFile(path); err != nil || !bytes.Equal(before, after) {
		t.Fatalf("a second init wrote the file: %q %v", after, err)
	}
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := initRevocations(path, testInitConfig); err == nil || !strings.Contains(err.Error(), "does not load") {
		t.Fatalf("an init over a file that does not load: %v", err)
	}
	if got, _ := os.ReadFile(path); string(got) != "{" {
		t.Fatalf("init replaced a file that does not load: %q", got)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := initRevocations(path, testInitConfig); err == nil || !strings.Contains(err.Error(), "never re-creates a lost file") {
		t.Fatalf("an init over a lost file: %v", err)
	}
	if _, err := loadRevocations(path); err == nil || !strings.Contains(err.Error(), "its marker says") {
		t.Fatalf("a start after the loss: %v", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a refused init or start wrote the file: %v", err)
	}
}

// A file laid down by hand loads, and the start writes the marker beside
// it, as 7a's start did (spec §13 decision 32; pre-flight M12): that
// creates no revocations file, and the file's later loss then refuses the
// start as a loss, never as a first install.
func TestAHandLaidFileLoadsAndGetsAMarker(t *testing.T) {
	path := filepath.Join(safeDir(t), "revocations.json")
	if err := os.WriteFile(path, []byte(`{"revocations": []}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if rs, err := loadRevocations(path); err != nil || len(rs) != 0 {
		t.Fatalf("%v %v", rs, err)
	}
	if _, err := os.Lstat(markerOf(path)); err != nil {
		t.Fatalf("no marker beside a file that loaded: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := loadRevocations(path); err == nil || !strings.Contains(err.Error(), "its marker says") {
		t.Fatalf("a start after a hand-laid file was lost: %v", err)
	}
}

// init is fenced as a start is: a directory others can write is refused
// and nothing is written.
func TestInitRevocationsIsFenced(t *testing.T) {
	open := safeDir(t)
	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(open, "revocations.json")
	if _, err := initRevocations(path, testInitConfig); err == nil {
		t.Fatal("init wrote into a directory others can write")
	}
	for _, p := range []string{path, markerOf(path)} {
		if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("a refused init wrote %s", p)
		}
	}
}

// A file that appears between init's look and its write is never
// replaced: the create is a link, which fails on an existing name
// (pre-flight M10).
func TestCreateExclusiveNeverReplaces(t *testing.T) {
	path := filepath.Join(safeDir(t), "revocations.json")
	if err := os.WriteFile(path, []byte("theirs"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := createExclusive(path, []byte("ours")); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("over an existing file: %v", err)
	}
	if got, _ := os.ReadFile(path); string(got) != "theirs" {
		t.Fatalf("replaced: %q", got)
	}
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".revocations.json.init-*")); len(left) != 0 {
		t.Fatalf("temporary files left: %v", left)
	}
}

// init writes the file before its marker, so a crash between the two
// leaves a file with no marker, which the next start loads and marks and
// the next init finds initialized, never a marker that claims a loss (task
// 2 review m1).
func TestInitRevocationsWritesTheFileBeforeTheMarker(t *testing.T) {
	path := filepath.Join(safeDir(t), "revocations.json")
	defer func(f func(string, []byte) error) { initCreate = f }(initCreate)
	var order []string
	initCreate = func(abs string, body []byte) error {
		order = append(order, filepath.Base(abs))
		if len(order) == 2 {
			return errors.New("crashed")
		}
		return createExclusive(abs, body)
	}
	if _, err := initRevocations(path, testInitConfig); err == nil {
		t.Fatal("the crash was not reported")
	}
	if len(order) != 2 || order[0] != "revocations.json" || order[1] != "revocations.json.created" {
		t.Fatalf("the order: %v", order)
	}
	initCreate = createExclusive
	if created, err := initRevocations(path, testInitConfig); err != nil || created {
		t.Fatalf("an init after the crash: %v %v", created, err)
	}
	if rs, err := loadRevocations(path); err != nil || len(rs) != 0 {
		t.Fatalf("a start after the crash: %v %v", rs, err)
	}
	if _, err := os.Lstat(markerOf(path)); err != nil {
		t.Fatalf("the start did not write the marker: %v", err)
	}
}

// Two inits racing: the one whose file lands second writes nothing and says
// another init ran, never a raw link error, and leaves the winner's file
// (task 2 review m3).
func TestARacedInitWritesNothingAndSaysSo(t *testing.T) {
	path := filepath.Join(safeDir(t), "revocations.json")
	defer func(f func(string, []byte) error) { initCreate = f }(initCreate)
	initCreate = func(abs string, body []byte) error {
		if abs == path {
			if err := os.WriteFile(path, []byte("theirs"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return createExclusive(abs, body)
	}
	_, err := initRevocations(path, testInitConfig)
	if err == nil || err.Error() != "appeared while this ran: another init-revocations is running or has just run; "+
		"nothing written" {
		t.Fatalf("%v", err)
	}
	if got, _ := os.ReadFile(path); string(got) != "theirs" {
		t.Fatalf("replaced: %q", got)
	}
	if _, err := os.Lstat(markerOf(path)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the losing init wrote the marker: %v", err)
	}
}

// The command reads broker.revocations_file and nothing else: a config
// whose secrets are not in the environment still inits, and a second run
// says the file is already initialized, exit 0. One with no broker block is
// refused, exit 1; stray arguments are usage, exit 2.
func TestInitRevocationsCmdReadsOnlyThePath(t *testing.T) {
	dir := safeDir(t)
	path := filepath.Join(dir, "revocations.json")
	cfg := filepath.Join(dir, "port49d.yaml")
	body := "encryption: {current: {id: k1, secret_env: PORT49_TEST_UNSET_SECRET}}\n" +
		"broker:\n  revocations_file: " + path + "\n"
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := initRevocationsCmd([]string{"--config", cfg}, &out, &errb); code != 0 ||
		!strings.Contains(out.String(), "created broker.revocations_file "+path) ||
		!strings.Contains(out.String(), "never on a start path") {
		t.Fatalf("code %d stdout %q stderr %q", code, out.String(), errb.String())
	}
	out.Reset()
	if code := initRevocationsCmd([]string{"--config", cfg}, &out, &errb); code != 0 ||
		!strings.Contains(out.String(), path+" is already initialized; nothing written") {
		t.Fatalf("the second run: code %d stdout %q stderr %q", code, out.String(), errb.String())
	}
	if err := os.WriteFile(cfg, []byte("listen: 127.0.0.1:49\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := initRevocationsCmd([]string{"--config", cfg}, &out, &errb); code != 1 ||
		!strings.Contains(errb.String(), "no broker.revocations_file") {
		t.Fatalf("no broker block: code %d stderr %q", code, errb.String())
	}
	if code := initRevocationsCmd([]string{"extra"}, &out, &errb); code != 2 {
		t.Fatalf("usage: %d", code)
	}
}

// A relative broker.revocations_file is refused, exit 1, and nothing is
// written: it would resolve against the caller's directory, not port49d's
// (task 2 review m2, m4).
func TestInitRevocationsCmdRefusesARelativePath(t *testing.T) {
	dir := safeDir(t)
	cfg := filepath.Join(dir, "port49d.yaml")
	if err := os.WriteFile(cfg, []byte("broker:\n  revocations_file: state/revocations.json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := initRevocationsCmd([]string{"--config", cfg}, &out, &errb); code != 1 ||
		!strings.Contains(errb.String(), `broker.revocations_file "state/revocations.json" is relative: it must be absolute`) ||
		out.Len() != 0 {
		t.Fatalf("code %d stdout %q stderr %q", code, out.String(), errb.String())
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{filepath.Join(cwd, "state"), filepath.Join(dir, "state")} {
		if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("a refused init wrote under %s: %v", p, err)
		}
	}
}

// The directory is fenced whether or not the file exists: a missing
// directory, or one others can write, refuses the start before "missing"
// can mean anything (pre-flight C1).
func TestTheDirectoryIsFencedWithOrWithoutTheFile(t *testing.T) {
	if _, err := loadRevocations(filepath.Join(safeDir(t), "missing", "revocations.json")); err == nil {
		t.Fatal("a missing directory read as no revocations")
	}
	open := safeDir(t)
	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := loadRevocations(filepath.Join(open, "revocations.json")); err == nil {
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
		if _, err := loadRevocations(path); err == nil {
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
	if _, err := restoreRevocations(context.Background(), memory.New(time.Now), path); err == nil ||
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
	if _, err := loadRevocations(path); err == nil {
		t.Fatal("a world-writable revocations file loaded")
	}
	link := filepath.Join(dir, "linked.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := loadRevocations(link); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("a link: %v", err)
	}
}

// A write that fails raises port49_revocations_file_failed; the next that
// succeeds lowers it.
func TestAFailedWriteIsAlarmed(t *testing.T) {
	m := newMetrics()
	st := memory.New(time.Now)
	if err := persister(st, filepath.Join(safeDir(t), "missing", "revocations.json"), nil, nil, m)(context.Background()); err == nil {
		t.Fatal("a write into a missing directory succeeded")
	}
	if testutil.ToFloat64(m.RevocationsFileFailed) != 1 {
		t.Fatal("not alarmed")
	}
	if err := persister(st, filepath.Join(safeDir(t), "revocations.json"), nil, nil, m)(context.Background()); err != nil {
		t.Fatal(err)
	}
	if testutil.ToFloat64(m.RevocationsFileFailed) != 0 {
		t.Fatal("not cleared")
	}
}

// hangWrites makes every revocations file write block until the returned
// release is called, and shortens persistDeadline to d. A test that hangs
// a write ends with settle, so no released write races the removal of its
// directory.
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

// settle releases the hung writes and waits for the slot: a call is given
// it only once every pass before it, catch-up passes included, has returned.
func settle(t *testing.T, release func(), persist func(context.Context) error) {
	t.Helper()
	release()
	persistDeadline = 5 * time.Second
	if err := persist(context.Background()); err != nil {
		t.Fatal(err)
	}
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
	persist := persister(st, path, nil, nil, m)
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
	settle(t, release, persist)
	rs, err := loadRevocations(path)
	if err != nil || len(rs) != 2 {
		t.Fatalf("after the hung write returned: %v %v", rs, err)
	}
	if testutil.ToFloat64(m.RevocationsFileFailed) != 0 {
		t.Fatal("not cleared")
	}
}

// Once a hung write returns, the file catches up on its own with the marks
// put while it hung, and only then is the alarm lowered: no further
// revocation is needed to save them (Task 9 review M3).
func TestTheFileCatchesUpAfterAHungWriteReturns(t *testing.T) {
	ctx := context.Background()
	m := newMetrics()
	st := memory.New(time.Now)
	path := filepath.Join(safeDir(t), "revocations.json")
	persist := persister(st, path, nil, nil, m)
	release := hangWrites(t, 50*time.Millisecond)
	for _, key := range []string{"user:alice@example.com", "user:bob@example.com"} {
		if err := st.PutRevocation(ctx, store.Revocation{Kind: store.RevocationPrincipal, Key: key, At: time.Now(),
			Origin: "test"}); err != nil {
			t.Fatal(err)
		}
		if err := persist(ctx); err == nil {
			t.Fatalf("%s: saved through a hung write", key)
		}
	}
	if testutil.ToFloat64(m.RevocationsFileFailed) != 1 {
		t.Fatal("not alarmed")
	}
	release()
	deadline := time.Now().Add(5 * time.Second)
	for {
		raw, _ := os.ReadFile(path)
		if strings.Contains(string(raw), "user:bob@example.com") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the file did not catch up: %s", raw)
		}
		time.Sleep(10 * time.Millisecond)
	}
	for testutil.ToFloat64(m.RevocationsFileFailed) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("the alarm stayed up after the file caught up")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if rs, err := loadRevocations(path); err != nil || len(rs) != 2 {
		t.Fatalf("%v %v", rs, err)
	}
	settle(t, release, persist)
}

// A revocation behind a hung write is not held by it: Revoke, as port49d
// wires it, returns unsaved within the deadline, the mark standing in the
// store, so its token and context passes run (Task 8 review).
func TestARevocationBehindAHungWriteIsReportedUnsaved(t *testing.T) {
	cfg := brokerConfig(t, minimalPolicy)
	st := memory.New(time.Now)
	m := newMetrics()
	minter := token.NewMinter(st, decision.NewJSONLines(io.Discard), rand.Reader, token.TagKey([]byte("revoke-test-key")),
		time.Now, 8)
	srv, brk, err := buildBroker(cfg, "inventory_file "+cfg.InventoryFile, st, minter,
		decision.NewJSONLines(io.Discard), m)
	if err != nil {
		t.Fatal(err)
	}
	brk.Sessions = session.New(st, time.Now, time.Hour, time.Hour)
	brk.Persist = persister(st, filepath.Join(safeDir(t), "revocations.json"), nil, nil, m)
	// alice holds an unspent token on leaf1, minted as port49d mints it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.ServeTLS(ln, "", "")
	t.Cleanup(func() { srv.Close() })
	if status, _, err := postAsAlice(filepath.Dir(cfg.Broker.ClientCAFile), ln.Addr().String()); err != nil ||
		status != http.StatusOK {
		t.Fatalf("the mint: %d %v", status, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	keys, err := st.TokensByPrincipal(ctx, "user:alice@example.com")
	if err != nil || len(keys) != 1 {
		t.Fatalf("alice's token keys: %v %v", keys, err)
	}

	release := hangWrites(t, 50*time.Millisecond)
	rep, err := brk.Revoke(ctx, broker.RevokeRequest{Principal: "user:alice@example.com", Origin: "test"})
	if err != nil || rep.Err != nil || rep.Saved || rep.SaveErr == nil || !errors.Is(rep.SaveErr, context.DeadlineExceeded) {
		t.Fatalf("%+v %v", rep, err)
	}
	if _, err := st.GetRevocation(ctx, store.RevocationPrincipal, "user:alice@example.com"); err != nil {
		t.Fatalf("the mark: %v", err)
	}
	if toks, err := st.Candidates(ctx, keys[0]); err != nil || len(toks) != 0 || rep.TokenKeys != 1 {
		t.Fatalf("alice's unspent token survived the revocation: %d left, %d keys emptied, %v", len(toks),
			rep.TokenKeys, err)
	}
	if testutil.ToFloat64(m.RevocationsFileFailed) != 1 {
		t.Fatal("an unsaved revocation is not alarmed")
	}
	if ctx.Err() != nil {
		t.Fatal("Revoke waited out the caller's deadline")
	}
	settle(t, release, brk.Persist)
}

// holdWrites makes every revocations file write say so on entered, then
// block until gate is closed; persistHook is reset at cleanup.
func holdWrites(t *testing.T) (entered chan struct{}, gate chan struct{}) {
	t.Helper()
	entered, gate = make(chan struct{}, 16), make(chan struct{})
	w, pd, h := writeRevocations, persistDeadline, persistHook
	writeRevocations = func(path string, rs []store.Revocation) error {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-gate
		return saveRevocations(path, rs)
	}
	t.Cleanup(func() {
		select {
		case <-gate:
		default:
			close(gate)
		}
		writeRevocations, persistDeadline, persistHook = w, pd, h
	})
	return entered, gate
}

// holdAt makes persistHook stop at point: it says so on reached and waits
// for proceed to be closed.
func holdAt(point string) (reached, proceed chan struct{}) {
	reached, proceed = make(chan struct{}), make(chan struct{})
	persistHook = func(p string) {
		if p == point {
			close(reached)
			<-proceed
		}
	}
	return reached, proceed
}

// waitUntil polls cond for up to five seconds.
func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); !cond(); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("waited for %s", what)
		}
	}
}

func fileHolds(path, key string) func() bool {
	return func() bool { raw, _ := os.ReadFile(path); return strings.Contains(string(raw), key) }
}

// A call that gives up waiting for the slot just after the pass it waited
// behind took its last look starts the catch-up itself: otherwise the mark
// put during that pass would wait for the next revocation to reach the
// file, under an alarm a restart would answer by losing it (Task 9
// re-review R1, variant a).
func TestACallThatGivesUpAsThePassEndsCatchesTheFileUp(t *testing.T) {
	ctx := context.Background()
	m := newMetrics()
	st := memory.New(time.Now)
	path := filepath.Join(safeDir(t), "revocations.json")
	persist := persister(st, path, nil, nil, m)
	entered, gate := holdWrites(t)
	put := func(key string) {
		if err := st.PutRevocation(ctx, store.Revocation{Kind: store.RevocationPrincipal, Key: key, At: time.Now(),
			Origin: "test"}); err != nil {
			t.Fatal(err)
		}
	}

	put("user:alice@example.com")
	persistDeadline = 5 * time.Second
	first := make(chan error, 1)
	go func() { first <- persist(ctx) }()
	<-entered // the first call's pass has listed alice alone and is writing
	put("user:bob@example.com")
	persistDeadline = 50 * time.Millisecond
	reached, proceed := holdAt("slot_wait_gave_up")
	second := make(chan error, 1)
	go func() { second <- persist(ctx) }()
	<-reached // the second call has given up waiting, and not yet said so

	close(gate)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if fileHolds(path, "user:bob@example.com")() {
		t.Fatal("the first pass listed bob")
	}
	close(proceed)
	if err := <-second; err == nil || !strings.Contains(err.Error(), "an earlier write has not returned") {
		t.Fatalf("the second call: %v", err)
	}
	waitUntil(t, "the file to hold bob with no further call", fileHolds(path, "user:bob@example.com"))
	waitUntil(t, "the alarm to clear", func() bool { return testutil.ToFloat64(m.RevocationsFileFailed) == 0 })
	persistDeadline = 5 * time.Second
	if err := persist(ctx); err != nil { // settles: the slot is free once the catch-up has returned
		t.Fatal(err)
	}
}

// A call whose deadline strikes during its own write: if the pass answers
// before the call gives up, the answer stands and no alarm is left up; if
// the call gives up first, the pass sees it and writes again, so a mark put
// after the call returned reaches the file and the alarm clears (Task 9
// re-review R1, variant b).
func TestACallWhoseWriteAnswersAsItGivesUp(t *testing.T) {
	for _, answersFirst := range []bool{true, false} {
		ctx := context.Background()
		m := newMetrics()
		st := memory.New(time.Now)
		path := filepath.Join(safeDir(t), "revocations.json")
		persist := persister(st, path, nil, nil, m)
		entered, gate := holdWrites(t)
		if err := st.PutRevocation(ctx, store.Revocation{Kind: store.RevocationPrincipal,
			Key: "user:alice@example.com", At: time.Now(), Origin: "test"}); err != nil {
			t.Fatal(err)
		}
		m.RevocationsFileFailed.Set(1) // an earlier failure, for the pass to clear
		persistDeadline = 50 * time.Millisecond
		reached, proceed := holdAt("write_wait_gave_up")
		call := make(chan error, 1)
		go func() { call <- persist(ctx) }()
		<-entered
		<-reached // the deadline has struck; the call has not yet looked for an answer

		if answersFirst {
			close(gate)
			waitUntil(t, "the pass to answer", func() bool { return testutil.ToFloat64(m.RevocationsFileFailed) == 0 })
			close(proceed)
			if err := <-call; err != nil {
				t.Fatalf("a pass that answered as the deadline struck was reported failed: %v", err)
			}
			if testutil.ToFloat64(m.RevocationsFileFailed) != 0 {
				t.Fatal("a false alarm was left up")
			}
		} else {
			close(proceed)
			if err := <-call; err == nil || !strings.Contains(err.Error(), "the write did not return") {
				t.Fatalf("the call: %v", err)
			}
			if testutil.ToFloat64(m.RevocationsFileFailed) != 1 {
				t.Fatal("not alarmed")
			}
			if err := st.PutRevocation(ctx, store.Revocation{Kind: store.RevocationPrincipal,
				Key: "user:bob@example.com", At: time.Now(), Origin: "test"}); err != nil {
				t.Fatal(err)
			}
			close(gate)
			waitUntil(t, "the file to hold bob", fileHolds(path, "user:bob@example.com"))
			waitUntil(t, "the alarm to clear", func() bool { return testutil.ToFloat64(m.RevocationsFileFailed) == 0 })
		}
		persistHook = func(string) {}
		persistDeadline = 5 * time.Second
		if err := persist(ctx); err != nil {
			t.Fatal(err)
		}
	}
}
