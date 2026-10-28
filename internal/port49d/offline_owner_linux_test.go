//go:build linux

package port49d

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rhwendt/port49/internal/fence"
)

// asAnotherUser makes the fleet's broker.state_dir look owned by a uid that is not the caller's (and
// not root), the way it does to root at 3am when port49-broker owns it. The uid is injected, since CI
// has no second one; every other path keeps its real owner.
func asAnotherUser(t *testing.T, f *fleet) {
	t.Helper()
	dir := f.stateDir(t)
	real := fence.FileOwner
	t.Cleanup(func() { fence.FileOwner = real })
	fence.FileOwner = func(fi fs.FileInfo) (uint32, bool) {
		if st, err := os.Lstat(dir); err == nil && os.SameFile(st, fi) {
			return uint32(os.Geteuid()) + 1, true
		}
		return real(fi)
	}
}

func markInStore(t *testing.T, f *fleet, principal string) bool {
	t.Helper()
	resp, err := f.srv.Client(t, "root").Get(context.Background(), "/port49/v1/rv/principal/"+principal)
	if err != nil {
		t.Fatal(err)
	}
	return len(resp.Kvs) == 1
}

// A user who does not own broker.state_dir (root, on a directory port49-broker owns) is refused BEFORE
// any write: no mark in the store, exit 1, "nothing was revoked", and the line to run as the owner.
// The refusal is knowable before a write; an I/O failure of the copy is not, and keeps its
// write-anyway rule (TestAnOfflineRevokeSaysWhenTheHostsCopyCannotBeWritten, final review 7e-2 I-2).
func TestAnOfflineRevokeAsAnotherUserRefusesBeforeAnyWrite(t *testing.T) {
	f := splitFleet(t)
	const alice = "user:alice@example.com"
	asAnotherUser(t, f)
	var rout, rerr bytes.Buffer
	code := offlineRevoke([]string{"--offline", "--config", f.broker, "--principal", alice}, &rout, &rerr)
	say := rerr.String()
	if code != 1 || !strings.Contains(say, "nothing was revoked") || !strings.Contains(say, "run it as the user that owns") ||
		!strings.Contains(say, "do not chown the directory") {
		t.Fatalf("exit %d, want 1 with the refusal and the owner hint:\n%s", code, say)
	}
	if markInStore(t, f, alice) {
		t.Fatal("the refused revoke wrote the mark to the store")
	}
	if got := copyHolds(t, f.stateDir(t), alice); got != "0" {
		t.Fatalf("the refused revoke wrote the host's copy: %q", got)
	}
	if rout.Len() != 0 {
		t.Error("the refused revoke wrote a decision record")
	}
}

// The same for a lift: the mark stands, and the line says nothing was lifted.
func TestAnOfflineLiftAsAnotherUserRefusesBeforeAnyWrite(t *testing.T) {
	f := splitFleet(t)
	const alice = "user:alice@example.com"
	var rout, rerr bytes.Buffer
	if code := offlineRevoke([]string{"--offline", "--config", f.broker, "--principal", alice}, &rout, &rerr); code != 0 {
		t.Fatalf("control: exit %d: %s", code, rerr.String())
	}
	asAnotherUser(t, f)
	rerr.Reset()
	code := offlineRevoke([]string{"--offline", "--config", f.broker, "--principal", alice, "--lift"}, &rout, &rerr)
	if code != 1 || !strings.Contains(rerr.String(), "nothing was lifted") || !strings.Contains(rerr.String(), "run it as the user that owns") {
		t.Fatalf("exit %d, want 1 with the refusal:\n%s", code, rerr.String())
	}
	if !markInStore(t, f, alice) {
		t.Fatal("the refused lift removed the mark")
	}
}

// --list writes nothing, so any user may run it.
func TestAnOfflineListAsAnotherUserStillWorks(t *testing.T) {
	f := splitFleet(t)
	asAnotherUser(t, f)
	var rout, rerr bytes.Buffer
	if code := offlineRevoke([]string{"--offline", "--config", f.broker, "--list"}, &rout, &rerr); code != 0 {
		t.Fatalf("exit %d: %s", code, rerr.String())
	}
}

// A directory another user owns is reported as a wrong owner even when its mode is also bad, so the
// offline tools refuse before a write instead of treating it as an I/O failure (Task 9 re-review n-1).
func TestAWrongOwnerIsReportedBeforeABadMode(t *testing.T) {
	dir := safeDir(t)
	sub := filepath.Join(dir, "state")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sub, 0o775); err != nil { // group-writable: a mode error on its own
		t.Fatal(err)
	}
	if err := ownStateDir(sub); err == nil || errors.As(err, new(*wrongOwnerError)) {
		t.Fatalf("control: a group-writable directory of ours should be a mode error: %v", err)
	}
	real := fence.FileOwner
	t.Cleanup(func() { fence.FileOwner = real })
	fence.FileOwner = func(fi fs.FileInfo) (uint32, bool) {
		if st, err := os.Lstat(sub); err == nil && os.SameFile(st, fi) {
			return uint32(os.Geteuid()) + 1, true
		}
		return real(fi)
	}
	var wo *wrongOwnerError
	if err := ownStateDir(sub); !errors.As(err, &wo) {
		t.Fatalf("a directory another user owns, with a bad mode, was reported as %v, want a wrong owner", err)
	}
}
