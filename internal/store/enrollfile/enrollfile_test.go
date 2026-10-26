package enrollfile

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/crypt"
	"github.com/rhwendt/port49/internal/store/storetest"
)

var t0 = time.Unix(1_000_000, 0).UTC()

func clock() time.Time { return t0 }

// keys is crypt_test.go's shape: v2 current, v1 previous.
func keys() crypt.Keys {
	var a, b [32]byte
	copy(a[:], "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	copy(b[:], "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	return crypt.Keys{Current: crypt.NewKey("v2", a), Previous: kp(crypt.NewKey("v1", b))}
}

func v1Only() crypt.Keys { return crypt.Keys{Current: *keys().Previous} }

func v0Only() crypt.Keys {
	var c [32]byte
	copy(c[:], "cccccccccccccccccccccccccccccccc")
	return crypt.Keys{Current: crypt.NewKey("v0", c)}
}

// dirFor is an empty directory only this user can write.
func dirFor(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func openAt(t *testing.T, path string, k crypt.Keys) *File {
	t.Helper()
	f, err := Open(path, k, clock)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

const alice = "user:alice@example.com"

func factor(principal, entry string) store.SecondFactor {
	return store.SecondFactor{Principal: principal, State: store.SecondFactorActive, EntryID: entry,
		Secret: []byte("01234567890123456789"), EnrolledAt: t0, EnrolledFrom: "192.0.2.0/32"}
}

// written is a file holding a mark and alice, sealed under k.
func written(t *testing.T, path string, k crypt.Keys) {
	t.Helper()
	ctx := context.Background()
	f := openAt(t, path, k)
	if err := f.CreateEnrollmentMark(ctx, store.EnrollmentMark{CreatedAt: t0}); err != nil {
		t.Fatal(err)
	}
	if err := f.SwapSecondFactor(ctx, factor(alice, "uuid:1"), 0); err != nil {
		t.Fatal(err)
	}
}

// tamper flips one byte of the file's sealed member.
func tamper(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	env.Sealed[len(env.Sealed)/2] ^= 0x01
	raw, err = json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestAMissingFileIsAnEmptyStoreWithNoMark(t *testing.T) {
	dir := dirFor(t)
	path := filepath.Join(dir, "enrollments.json")
	f := openAt(t, path, keys())
	if f.Lost() != "" {
		t.Fatalf("a missing file is lost: %s", f.Lost())
	}
	ctx := context.Background()
	if _, err := f.GetEnrollmentMark(ctx); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a missing file has a mark: %v", err)
	}
	if _, err := f.GetSecondFactor(ctx, alice); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("%v", err)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Fatalf("Open wrote %d files", len(ents))
	}
}

func TestTheFileReopensWithItsRecords(t *testing.T) {
	path := filepath.Join(dirFor(t), "enrollments.json")
	ctx := context.Background()
	written(t, path, keys())
	f := openAt(t, path, keys())
	if err := f.SwapSecondFactor(ctx, factor("user:bob@example.com", "uuid:2"), 0); err != nil {
		t.Fatal(err)
	}
	g := openAt(t, path, keys())
	for p, entry := range map[string]string{alice: "uuid:1", "user:bob@example.com": "uuid:2"} {
		got, err := g.GetSecondFactor(ctx, p)
		if err != nil || got.EntryID != entry || got.Rev == 0 {
			t.Fatalf("%s: %+v %v", p, got, err)
		}
	}
	if m, err := g.GetEnrollmentMark(ctx); err != nil || !m.CreatedAt.Equal(t0) {
		t.Fatalf("%+v %v", m, err)
	}
	if ps, _ := g.SecondFactorPrincipals(ctx); len(ps) != 2 {
		t.Fatalf("%v", ps)
	}
	// A revision read before the restart still compares after it.
	got, _ := g.GetSecondFactor(ctx, alice)
	if err := g.SwapSecondFactor(ctx, got, got.Rev); err != nil {
		t.Fatal(err)
	}
	if err := g.SwapSecondFactor(ctx, got, got.Rev); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("a stale revision: %v", err)
	}
}

// A file that does not unseal is lost, never empty: every method says so,
// and none answers not enrolled (D7).
func TestATamperedFileIsLostNeverEmpty(t *testing.T) {
	path := filepath.Join(dirFor(t), "enrollments.json")
	written(t, path, keys())
	tamper(t, path)
	f := openAt(t, path, keys())
	if f.Lost() == "" {
		t.Fatal("a tampered file opened")
	}
	ctx := context.Background()
	calls := map[string]error{
		"GetSecondFactor":        func() error { _, err := f.GetSecondFactor(ctx, alice); return err }(),
		"SwapSecondFactor":       f.SwapSecondFactor(ctx, factor(alice, "uuid:1"), 0),
		"SecondFactorPrincipals": func() error { _, err := f.SecondFactorPrincipals(ctx); return err }(),
		"GetEnrollmentMark":      func() error { _, err := f.GetEnrollmentMark(ctx); return err }(),
		"Export":                 func() error { _, err := f.Export(ctx); return err }(),
	}
	for name, err := range calls {
		if !errors.Is(err, store.ErrEnrollmentStoreLost) || errors.Is(err, store.ErrNotFound) {
			t.Errorf("%s on a lost store: %v", name, err)
		}
	}
}

func TestAFileUnderAnUnknownKeyIsLost(t *testing.T) {
	path := filepath.Join(dirFor(t), "enrollments.json")
	written(t, path, keys()) // under v2
	f := openAt(t, path, v0Only())
	if !strings.Contains(f.Lost(), `"v2"`) || !strings.Contains(f.Lost(), "encryption.previous") {
		t.Fatalf("the line does not name the key: %q", f.Lost())
	}
	if _, err := f.GetSecondFactor(context.Background(), alice); !errors.Is(err, store.ErrEnrollmentStoreLost) {
		t.Fatalf("%v", err)
	}
}

func TestAFileUnderThePreviousKeyIsRewrittenUnderTheCurrent(t *testing.T) {
	path := filepath.Join(dirFor(t), "enrollments.json")
	written(t, path, v1Only())
	keyID := func() string {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var env envelope
		if err := json.Unmarshal(raw, &env); err != nil {
			t.Fatal(err)
		}
		return env.KeyID
	}
	if keyID() != "v1" {
		t.Fatalf("written under %s", keyID())
	}
	f := openAt(t, path, keys())
	if f.Lost() != "" {
		t.Fatalf("a file under the previous key is lost: %s", f.Lost())
	}
	got, err := f.GetSecondFactor(context.Background(), alice)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.SwapSecondFactor(context.Background(), got, got.Rev); err != nil {
		t.Fatal(err)
	}
	if keyID() != "v2" {
		t.Fatalf("after a write: %s", keyID())
	}
	if g := openAt(t, path, crypt.Keys{Current: keys().Current}); g.Lost() != "" {
		t.Fatalf("the rewritten file needs the previous key: %s", g.Lost())
	}
}

func TestResetAllKeepsTheUnreadableFileAside(t *testing.T) {
	dir := dirFor(t)
	path := filepath.Join(dir, "enrollments.json")
	written(t, path, keys())
	old := tamper(t, path)
	f := openAt(t, path, keys())
	ctx := context.Background()
	if err := f.PutEnrollmentMark(ctx, store.EnrollmentMark{CreatedAt: t0.Add(time.Hour),
		ReopenAllUntil: t0.Add(25 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	aside, _ := filepath.Glob(filepath.Join(dir, "enrollments.json.unreadable-*"))
	if len(aside) != 1 {
		t.Fatalf("set aside: %v", aside)
	}
	if got, _ := os.ReadFile(aside[0]); !bytes.Equal(got, old) {
		t.Fatal("the file set aside is not the old bytes")
	}
	if f.Lost() != "" {
		t.Fatalf("still lost after the replace: %s", f.Lost())
	}
	g := openAt(t, path, keys())
	if m, err := g.GetEnrollmentMark(ctx); err != nil || !m.ReopenAllUntil.Equal(t0.Add(25*time.Hour)) {
		t.Fatalf("the new file: %+v %v", m, err)
	}
	if _, err := g.GetSecondFactor(ctx, alice); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the new file holds the old records: %v", err)
	}
	// A put over a store that opened sets nothing aside.
	if err := g.PutEnrollmentMark(ctx, store.EnrollmentMark{CreatedAt: t0}); err != nil {
		t.Fatal(err)
	}
	if aside, _ = filepath.Glob(filepath.Join(dir, "enrollments.json.unreadable-*")); len(aside) != 1 {
		t.Fatalf("a replace of a readable store set a file aside: %v", aside)
	}
}

func TestCreateRefusesAnyFileThere(t *testing.T) {
	dir := dirFor(t)
	path := filepath.Join(dir, "enrollments.json")
	ctx := context.Background()
	written(t, path, keys())
	old := tamper(t, path)
	f := openAt(t, path, keys())
	if err := f.CreateEnrollmentMark(ctx, store.EnrollmentMark{CreatedAt: t0}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("a create over a lost file: %v", err)
	}
	if got, _ := os.ReadFile(path); !bytes.Equal(got, old) {
		t.Fatal("the refused create changed the file")
	}
	// A file that appears after Open is not replaced either.
	other := filepath.Join(dir, "other.json")
	g := openAt(t, other, keys())
	if err := os.WriteFile(other, []byte("not ours"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := g.CreateEnrollmentMark(ctx, store.EnrollmentMark{CreatedAt: t0}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("a create over a file that appeared: %v", err)
	}
	if got, _ := os.ReadFile(other); string(got) != "not ours" {
		t.Fatal("the create replaced a file that appeared")
	}
	// With none there, it is created.
	h := openAt(t, filepath.Join(dir, "fresh.json"), keys())
	if err := h.CreateEnrollmentMark(ctx, store.EnrollmentMark{CreatedAt: t0}); err != nil {
		t.Fatal(err)
	}
	if m, err := openAt(t, filepath.Join(dir, "fresh.json"), keys()).GetEnrollmentMark(ctx); err != nil || !m.CreatedAt.Equal(t0) {
		t.Fatalf("%+v %v", m, err)
	}
}

func TestAFailedWriteChangesNothing(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes a directory made 0500")
	}
	dir := dirFor(t)
	path := filepath.Join(dir, "enrollments.json")
	ctx := context.Background()
	written(t, path, keys())
	f := openAt(t, path, keys())
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })
	bob := factor("user:bob@example.com", "uuid:2")
	if err := f.SwapSecondFactor(ctx, bob, 0); err == nil {
		t.Fatal("a swap into an unwritable directory succeeded")
	}
	got, err := f.GetSecondFactor(ctx, alice)
	if err != nil || got.EntryID != "uuid:1" {
		t.Fatalf("the record before the failed write: %+v %v", got, err)
	}
	if _, err := f.GetSecondFactor(ctx, bob.Principal); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the failed write is in memory: %v", err)
	}
	if err := f.PutEnrollmentMark(ctx, store.EnrollmentMark{CreatedAt: t0.Add(time.Hour)}); err == nil {
		t.Fatal("a mark put into an unwritable directory succeeded")
	}
	if m, _ := f.GetEnrollmentMark(ctx); !m.CreatedAt.Equal(t0) {
		t.Fatalf("the failed put is in memory: %+v", m)
	}
}

func TestTheFileIsOwnerOnlyAndHoldsNoSecretInTheClear(t *testing.T) {
	path := filepath.Join(dirFor(t), "enrollments.json")
	ctx := context.Background()
	f := openAt(t, path, keys())
	w := crypt.WrapEnrollments(f, keys(), nil)
	if err := w.PutEnrollmentMark(ctx, store.EnrollmentMark{CreatedAt: t0}); err != nil {
		t.Fatal(err)
	}
	if err := w.SwapSecondFactor(ctx, factor(alice, "uuid:1"), 0); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("%v %v", fi, err)
	}
	raw, _ := os.ReadFile(path)
	if bytes.Contains(raw, []byte("01234567890123456789")) || bytes.Contains(raw, []byte("uuid:1")) ||
		bytes.Contains(raw, []byte(alice)) {
		t.Fatal("the file holds a secret, an entry id or a principal in the clear")
	}
	// Nor does the body, once the file's own seal is off: the crypt layer
	// seals the three members again.
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	plain, err := keys().OpenBound(env.Sealed, fileBound)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(plain, []byte("01234567890123456789")) || bytes.Contains(plain, []byte("uuid:1")) ||
		bytes.Contains(plain, []byte("192.0.2.0")) {
		t.Fatal("the body holds a sealed member in the clear")
	}
}

func TestAGroupWritableDirectoryIsRefused(t *testing.T) {
	dir := dirFor(t)
	if err := os.Chmod(dir, 0o770); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(filepath.Join(dir, "enrollments.json"), keys(), clock); err == nil ||
		!strings.Contains(err.Error(), "writable by others") {
		t.Fatalf("a directory the group can write: %v", err)
	}
}

// A file that cannot be read, or is over the size bound, is a lost store,
// not an Open error: the broker's other paths keep serving (review I3).
func TestAnUnreadableOrOversizedFileIsLostNotAnOpenError(t *testing.T) {
	ctx := context.Background()
	check := func(t *testing.T, f *File) {
		t.Helper()
		if f.Lost() == "" || !strings.Contains(f.Lost(), "cannot be read") {
			t.Fatalf("lost: %q", f.Lost())
		}
		if _, err := f.GetSecondFactor(ctx, alice); !errors.Is(err, store.ErrEnrollmentStoreLost) {
			t.Fatalf("%v", err)
		}
		if _, err := f.GetEnrollmentMark(ctx); !errors.Is(err, store.ErrEnrollmentStoreLost) {
			t.Fatalf("%v", err)
		}
	}
	t.Run("unreadable", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root reads a file made 0000")
		}
		path := filepath.Join(dirFor(t), "enrollments.json")
		written(t, path, keys())
		if err := os.Chmod(path, 0); err != nil {
			t.Fatal(err)
		}
		f := openAt(t, path, keys())
		check(t, f)
		// It can still be replaced: the unreadable file is set aside.
		if err := f.PutEnrollmentMark(ctx, store.EnrollmentMark{CreatedAt: t0}); err != nil {
			t.Fatal(err)
		}
		if aside, _ := filepath.Glob(path + ".unreadable-*"); len(aside) != 1 {
			t.Fatalf("set aside: %v", aside)
		}
	})
	t.Run("oversized", func(t *testing.T) {
		path := filepath.Join(dirFor(t), "enrollments.json")
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Truncate(path, maxFile+1); err != nil {
			t.Fatal(err)
		}
		check(t, openAt(t, path, keys()))
	})
}

// A file the fence refuses (one the group can write) is a lost store whose
// text names the fence's reason and quotes nothing from the file (review N1).
func TestAFileTheFenceRefusesIsLostNamingTheReasonAndNothingOfItsContent(t *testing.T) {
	const sentinel = "SENTINEL-FILE-CONTENT"
	path := filepath.Join(dirFor(t), "enrollments.json")
	if err := os.WriteFile(path, []byte(sentinel), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o660); err != nil {
		t.Fatal(err)
	}
	f := openAt(t, path, keys())
	if !strings.Contains(f.Lost(), "writable by others") || strings.Contains(f.Lost(), sentinel) {
		t.Fatalf("lost: %q", f.Lost())
	}
	_, err := f.GetEnrollmentMark(context.Background())
	if !errors.Is(err, store.ErrEnrollmentStoreLost) || strings.Contains(err.Error(), sentinel) {
		t.Fatalf("%v", err)
	}
}

// Setting a file aside reports a directory it cannot look in; it does not
// loop on it (review M2).
func TestSettingAsideStopsOnAnErrorThatIsNotAbsence(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root searches any directory")
	}
	dir := dirFor(t)
	path := filepath.Join(dir, "enrollments.json")
	written(t, path, keys())
	tamper(t, path)
	f := openAt(t, path, keys())
	if err := os.Chmod(dir, 0o600); err != nil { // no search permission
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })
	done := make(chan error, 1)
	go func() { done <- f.PutEnrollmentMark(context.Background(), store.EnrollmentMark{CreatedAt: t0}) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a replace in a directory it cannot search succeeded")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("setting aside loops")
	}
}

func TestALinkAtThePathIsRefused(t *testing.T) {
	dir := dirFor(t)
	real := filepath.Join(dir, "real.json")
	written(t, real, keys())
	path := filepath.Join(dir, "enrollments.json")
	if err := os.Symlink(real, path); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, keys(), clock); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("a link at the path: %v", err)
	}
}

// Every enrollment property through the sealing layer over the file.
func TestTheFileHoldsEveryEnrollmentProperty(t *testing.T) {
	storetest.RunEnrollments(t, storetest.EnrollmentsBackend{Sealed: true,
		New: func(t *testing.T, clock func() time.Time) store.Enrollments {
			f, err := Open(filepath.Join(dirFor(t), "enrollments.json"), keys(), clock)
			if err != nil {
				t.Fatal(err)
			}
			return crypt.WrapEnrollments(f, keys(), nil)
		},
		NewBelow: func(t *testing.T, clock func() time.Time) (store.Enrollments, store.Enrollments) {
			f, err := Open(filepath.Join(dirFor(t), "enrollments.json"), keys(), clock)
			if err != nil {
				t.Fatal(err)
			}
			return crypt.WrapEnrollments(f, keys(), nil), f
		}})
}

func kp(k crypt.Key) *crypt.Key { return &k }
