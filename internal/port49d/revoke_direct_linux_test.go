//go:build linux

package port49d

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/broker"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/session"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/memory"
	"github.com/rhwendt/port49/internal/token"
)

// hungStore hangs PutRevocation while hang is open, until its ctx ends,
// as a store behind a dead network does; ended gets the ctx's error. One
// hung when hang closes goes on.
type hungStore struct {
	store.Store
	hang    chan struct{}
	entered chan struct{}
	ended   chan error
}

func (h *hungStore) PutRevocation(ctx context.Context, r store.Revocation) error {
	select {
	case <-h.hang:
		return h.Store.PutRevocation(ctx, r)
	default:
	}
	h.entered <- struct{}{}
	select {
	case <-h.hang:
		return h.Store.PutRevocation(ctx, r)
	case <-ctx.Done():
	}
	h.ended <- ctx.Err()
	return ctx.Err()
}

// listFailingStore fails every list of the marks.
type listFailingStore struct{ store.Store }

func (listFailingStore) ListRevocations(context.Context) ([]store.Revocation, error) {
	return nil, context.DeadlineExceeded
}

// directBroker is a real broker on st with a revocations file and runTimeout as
// its revocation bound, the way the API's handler and the offline commands
// drive it.
func directBroker(t *testing.T, st store.Store, runTimeout time.Duration) *broker.Broker {
	t.Helper()
	cfg := brokerConfig(t, minimalPolicy)
	m := newMetrics()
	minter := token.NewMinter(st, decision.NewJSONLines(io.Discard), rand.Reader, token.TagKey([]byte("admin-test-key")),
		time.Now, 8)
	_, brk, err := buildBroker(cfg, "inventory_file "+cfg.InventoryFile, st, minter, decision.NewJSONLines(io.Discard), m)
	if err != nil {
		t.Fatal(err)
	}
	brk.Sessions = session.New(st, time.Now, time.Hour, time.Hour)
	brk.Persist = persister(st, filepath.Join(safeDir(t), "revocations.json"), nil, nil, m)
	brk.RevokeTimeout = runTimeout
	return brk
}

// A revocation behind a hung store gives up at the broker's bound, and the
// answer says nothing may have been recorded and how to cut access instead.
func TestARevocationOnAHungStoreGivesUpAtTheDeadlineAndSaysSo(t *testing.T) {
	st := &hungStore{Store: memory.New(time.Now), hang: make(chan struct{}), entered: make(chan struct{}, 1),
		ended: make(chan error, 1)}
	brk := directBroker(t, st, 200*time.Millisecond)
	start := time.Now()
	_, err := brk.Revoke(context.Background(), broker.RevokeRequest{Principal: "user:alice@example.com",
		Origin: "offline uid 0"})
	if err == nil || !strings.Contains(err.Error(), "may not have been recorded") ||
		!strings.Contains(err.Error(), "deadline exceeded") || !strings.Contains(err.Error(), "broker.policy_file") {
		t.Fatalf("%v", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("answered after %v", d)
	}
}

// A lift is out of this replica's copy, on disk, when it is answered
// (Broker.OnLift is wired to Lifted): a stop before the watch delivers it neither keeps the mark
// in force at the restart nor puts it back (TestATakeoverPutsBackAMarkTheStoreLost).
// The watch's late put of the lifted mark does not add it back; a newer
// revocation of the key does.
func TestALiftLeavesTheCopyBeforeItIsAnswered(t *testing.T) {
	st := memory.New(time.Now)
	brk := directBroker(t, st, time.Minute)
	path := filepath.Join(safeStateDir(t), "marks.json")
	var out bytes.Buffer
	c := openMarksCopy(path, &out)
	ctx := context.Background()
	const carol = "user:carol@example.com"
	req := broker.RevokeRequest{Principal: carol, Origin: "offline uid 0"}
	if _, err := brk.Revoke(ctx, req); err != nil {
		t.Fatal(err)
	}
	put, err := st.GetRevocation(ctx, store.RevocationPrincipal, carol)
	if err != nil {
		t.Fatal(err)
	}
	c.Apply(store.MarkChange{Revocation: put, Standing: true}) // the watch delivers the revocation
	rep, err := brk.Lift(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	// What the API's lift handler does with Broker.OnLift, which brokerd wires
	// to Lifted, before it answers.
	c.Lifted(rep.Mark)
	if got := openMarksCopy(path, io.Discard).All(); len(got) != 0 {
		t.Fatalf("after the lift was answered the file holds %+v", got)
	}
	c.Apply(store.MarkChange{Revocation: put, Standing: true}) // the watch, behind, delivers the put again
	if got := openMarksCopy(path, io.Discard).All(); len(got) != 0 {
		t.Fatalf("the watch's late put added the lifted mark back: %+v", got)
	}
	newer := store.Revocation{Kind: put.Kind, Key: put.Key, At: put.At.Add(time.Second)}
	c.Apply(store.MarkChange{Revocation: newer, Standing: true})
	c.Lifted(put) // a stale lift never drops a newer mark
	if got := openMarksCopy(path, io.Discard).All(); len(got) != 1 || !got[0].At.Equal(newer.At) {
		t.Fatalf("a newer revocation of the key: %+v", got)
	}
}

// A list the store cannot answer says what failed, not a bare store error.
func TestAFailedListSaysWhatFailed(t *testing.T) {
	var out bytes.Buffer
	code := offlineList(context.Background(), listFailingStore{memory.New(time.Now)}, daemonOfflineSay, &out)
	if code != 1 || !strings.HasPrefix(out.String(), daemonOfflineSay+"the revocations in force could not be read") ||
		!strings.Contains(out.String(), "deadline exceeded") {
		t.Fatalf("exit %d: %s", code, out.String())
	}
}
