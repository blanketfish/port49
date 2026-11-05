package broker

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/store"
	"github.com/blanketfish/port49/internal/store/crypt"
)

// readHoldingStore holds the first GetContext after the store has read
// the record, before it returns, so the sealing layer has not yet asked
// the ledger.
type readHoldingStore struct {
	store.RevStore
	read, release chan struct{}
	held          atomic.Bool
}

func (h *readHoldingStore) GetContext(ctx context.Context, k store.ContextKey) (store.Context, error) {
	c, err := h.RevStore.GetContext(ctx, k)
	if h.held.CompareAndSwap(false, true) {
		close(h.read)
		<-h.release
	}
	return c, err
}

// ledgerFixture puts the broker and a daemon sealing over inner (f's
// store, or one over it) on one ledger, its base set, as port49d runs them, and
// writes alice's live context on leaf1 through the daemon, indexed under
// her principal.
func ledgerFixture(t *testing.T, f *fixture, inner store.RevStore) (store.Store, store.ContextKey) {
	t.Helper()
	l := crypt.NewLedger()
	daemon := crypt.Wrap(inner, testKeys("k1"), nil, crypt.WithLedger(l))
	f.b.Store = crypt.Wrap(inner, testKeys("k1"), nil, crypt.WithLedger(l))
	l.SetBase(inner.Seen() + 1)
	ctx := context.Background()
	k := store.ContextKey{NAS: "leaf1", Username: "alice"}
	if err := daemon.PutContext(ctx, k, store.Context{CtxID: "ctx_leaf1", Principal: alicePrincipal,
		Username: "alice", PrivLvl: 1, AuthTime: f.now, RefreshedAt: f.now, BlobHash: "sha256:from-before"},
		time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := f.st.IndexContext(ctx, alicePrincipal, "", "", store.ContextRef{NAS: k.NAS, Username: k.Username},
		time.Hour); err != nil {
		t.Fatal(err)
	}
	return daemon, k
}

// A policy pass whose read races the daemon's write of the same context
// (an enable's SetPrivilege landing between the store's read and the
// ledger's check) judges the context; it does not revoke it as tampered
// (Task 13b review I-1).
func TestAPolicyPassRacingASetPrivilegeDoesNotRevoke(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, sharedPolicy)
	h := &readHoldingStore{RevStore: f.st, read: make(chan struct{}), release: make(chan struct{})}
	daemon, k := ledgerFixture(t, f, h)
	ctx := context.Background()
	done := make(chan error)
	go func() {
		_, err := f.b.RefreshAtStart(ctx)
		done <- err
	}()
	<-h.read
	// Raises the level: a level held is no write.
	if err := daemon.SetPrivilege(ctx, k, 2); err != nil {
		t.Fatal(err)
	}
	close(h.release)
	if err := <-done; err != nil {
		t.Fatalf("RefreshAtStart: %v", err)
	}
	if c, err := f.b.Store.GetContext(ctx, k); err != nil || !c.RevokedAt.IsZero() {
		t.Fatalf("a context whose read raced a write of its own was revoked: %+v %v", c.RevokedAt, err)
	}
}

// revokeUnopened reads once more before it revokes a context the ledger
// denied: one the store now answers, or holds at another revision, was a
// read that raced a write, and is left for the caller to read again; one
// still denied at the revision read is revoked, as a record put back, or
// restored under a running port49d, is (Task 13b review I-1; Ruling
// T13b-a).
func TestRevokeUnopenedReadsAgainBeforeItRevokes(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, sharedPolicy)
	daemon, k := ledgerFixture(t, f, f.st)
	ctx := context.Background()
	ref := store.ContextRef{NAS: k.NAS, Username: k.Username}
	first, err := f.st.GetContext(ctx, k)
	if err != nil {
		t.Fatal(err)
	}
	// Raises the level: a level held is no write.
	if err := daemon.SetPrivilege(ctx, k, 2); err != nil {
		t.Fatal(err)
	}
	stale := &store.UnreadableContextError{Rev: first.Rev,
		Err: fmt.Errorf("crypt: opening context: %w", crypt.ErrNotLastWritten)}
	var rep RefreshReport
	if _, err := f.b.revokeUnopened(ctx, f.b.Policy.Load(), nil, f.now, "test", ref, stale, &rep); !errors.Is(err,
		store.ErrConflict) {
		t.Fatalf("a stale denial: %v, want it read again", err)
	}
	if c, err := f.st.GetContext(ctx, k); err != nil || !c.RevokedAt.IsZero() || rep.Revoked != 0 {
		t.Fatalf("a stale denial revoked the context: %v %v", c.RevokedAt, err)
	}

	if err := f.st.PutContext(ctx, k, first, time.Hour); err != nil { // put back
		t.Fatal(err)
	}
	if _, err := f.b.RefreshAtStart(ctx); err != nil {
		t.Fatal(err)
	}
	if c, err := f.st.GetContext(ctx, k); err != nil || c.RevokedAt.IsZero() {
		t.Fatalf("an earlier version put back was not revoked: %v %v", c.RevokedAt, err)
	}
}
