//go:build linux

package port49d

import (
	"bytes"
	"context"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"errors"
	"github.com/rhwendt/port49/internal/broker"
	"github.com/rhwendt/port49/internal/fence"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/memory"
	"path/filepath"
)

// port49d revoke --offline run as a uid that does not own the revocations
// file (root, at 3am) refuses with the owner and the line to run, and changes
// nothing: no mark, no file, no .lock for a port49d running as the owner to
// trip on. The uid is injected, since CI has no second one.
func TestOfflineRevokeAsAnotherUidRefusesAndChangesNothing(t *testing.T) {
	b := brokerConfig(t, minimalPolicy).Broker
	cfgPath := writeRunConfig(t, b)
	other := uint32(os.Geteuid()) + 1
	defer func(g func() int) { fence.Geteuid = g }(fence.Geteuid)
	fence.Geteuid = func() int { return int(other) }
	os.Remove(b.RevocationsFile + ".lock")
	before, _ := os.ReadFile(b.RevocationsFile)
	for _, args := range [][]string{{"--principal", "user:alice@example.com"}, {"--list"}} {
		var log, say bytes.Buffer
		code := offlineRevokeDaemon(append([]string{"--offline", "--config", cfgPath}, args...), &log, &say)
		if code != 1 || !strings.Contains(say.String(), "sudo -u ") ||
			!strings.Contains(say.String(), "port49d revoke --offline --config "+cfgPath) ||
			!strings.Contains(say.String(), "nothing was changed") {
			t.Fatalf("%v: exit %d: %s", args, code, say.String())
		}
		if log.Len() != 0 {
			t.Fatalf("%v: a refused command wrote a decision record", args)
		}
	}
	if after, _ := os.ReadFile(b.RevocationsFile); !bytes.Equal(before, after) {
		t.Fatal("a refused revocation changed broker.revocations_file")
	}
	if _, err := os.Lstat(b.RevocationsFile + ".lock"); err == nil {
		t.Fatal("a refused revocation created the .lock")
	}
}

// The lock sidecar is never followed: a symlink in its place is refused, and
// what it points at is not touched.
func TestASymlinkedLockIsRefused(t *testing.T) {
	file := filepath.Join(safeDir(t), "revocations.json")
	target := filepath.Join(safeDir(t), "victim")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, file+".lock"); err != nil {
		t.Fatal(err)
	}
	release, err := lockRevocations(file)
	if err == nil || errors.Is(err, errRevocationsLocked) || !strings.Contains(err.Error(), "the revocations lock") {
		if release != nil {
			release()
		}
		t.Fatalf("a symlinked .lock: %v", err)
	}
	if b, _ := os.ReadFile(target); string(b) != "keep" {
		t.Fatal("the lock followed the link")
	}
}

// A pass that outlives the call that started it is drained before the lock is
// given up: the drain says no while the write hangs, and yes only once it has
// returned.
func TestADetachedPassIsDrainedBeforeTheUnlock(t *testing.T) {
	ctx := context.Background()
	st := memory.New(time.Now)
	path := filepath.Join(safeDir(t), "revocations.json")
	persist, drain := persisterDrain(st, path, nil, nil, newMetrics())
	release := hangWrites(t, 50*time.Millisecond)
	if err := st.PutRevocation(ctx, store.Revocation{Kind: store.RevocationPrincipal, Key: "user:alice@example.com",
		At: time.Now(), Origin: "test"}); err != nil {
		t.Fatal(err)
	}
	if err := persist(ctx); err == nil {
		t.Fatal("the hung write answered")
	}
	if drain(100 * time.Millisecond) {
		t.Fatal("drained while a pass was still writing")
	}
	release()
	if !drain(5 * time.Second) {
		t.Fatal("did not drain once the write returned")
	}
	rs, err := loadRevocations(path)
	if err != nil || len(rs) != 1 {
		t.Fatalf("the pass finished before the drain answered: %v %v", rs, err)
	}
}

// The daemon's own wiring: a write of the revocations file that outlives the
// revoke that started it keeps the lock held through shutdown until it
// returns; and once the lock is given up no pass can start, so a revoke that
// outlives the shutdown writes nothing beside an offline revoke.
func TestShutdownKeepsTheLockUntilAHungWriteReturns(t *testing.T) {
	var out syncBuffer
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o })
	stderr, stdout = &out, io.Discard
	b := brokerConfig(t, minimalPolicy).Broker
	cfgPath := writeRunConfig(t, b)
	brkCh := make(chan *broker.Broker, 1)
	daemonBrokerHook = func(brk *broker.Broker) { brkCh <- brk }
	w := persistDrainWait
	persistDrainWait = 20 * time.Second
	t.Cleanup(func() { daemonBrokerHook, persistDrainWait = nil, w })
	release := hangWrites(t, 50*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfgPath) }()
	returned := false
	t.Cleanup(func() {
		release()
		cancel()
		if !returned {
			select {
			case <-done:
			case <-time.After(30 * time.Second):
			}
		}
	})
	waitForCount(t, &out, "port49d: broker listening on ", 1)
	brk := <-brkCh

	req := broker.RevokeRequest{Principal: "user:alice@example.com", Origin: "test"}
	_, _ = brk.Revoke(context.Background(), req) // answers at the persist deadline; the write goes on
	cancel()
	select {
	case err := <-done:
		returned = true
		t.Fatalf("run returned (%v) with a write still hung", err)
	case <-time.After(400 * time.Millisecond):
	}
	if _, err := lockRevocations(b.RevocationsFile); !errors.Is(err, errRevocationsLocked) {
		t.Fatalf("the lock while a write hangs: %v", err)
	}
	release()
	select {
	case err := <-done:
		returned = true
		if err != nil {
			t.Fatalf("run: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not return once the write did")
	}
	unlock, err := lockRevocations(b.RevocationsFile)
	if err != nil {
		t.Fatalf("the lock after the write returned: %v", err)
	}
	defer unlock()
	// The pass that hung wrote its mark before the lock was given up.
	if rs, err := loadRevocations(b.RevocationsFile); err != nil || len(rs) != 1 {
		t.Fatalf("the file after the drain: %v %v", rs, err)
	}
	// A revoke that outlives the shutdown starts no pass: the slot is kept.
	_, _ = brk.Revoke(context.Background(), broker.RevokeRequest{Principal: "user:bob@example.com", Origin: "test"})
	if rs, _ := loadRevocations(b.RevocationsFile); len(rs) != 1 {
		t.Fatalf("a write landed after the unlock: %v", rs)
	}
}
