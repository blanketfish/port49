package broker

import (
	"bytes"
	"context"
	"errors"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/rhwendt/port49/internal/store"
)

// unreadableAt is a store whose context at k will not open, as one sealed
// under a key this window lacks reads through the sealing layer.
type unreadableAt struct {
	store.Store
	k store.ContextKey
}

func (u unreadableAt) GetContext(ctx context.Context, k store.ContextKey) (store.Context, error) {
	if k == u.k {
		return store.Context{}, &store.UnreadableContextError{Err: errors.New("test: will not open")}
	}
	return u.Store.GetContext(ctx, k)
}

// undecodableAt is a store whose context at k does not decode, as the etcd
// backend reads a garbled record: unreadable at its own revision, and
// refused by every setter, the revocation too.
type undecodableAt struct {
	store.Store
	k store.ContextKey
}

func (u undecodableAt) GetContext(ctx context.Context, k store.ContextKey) (store.Context, error) {
	if k == u.k {
		c, err := u.Store.GetContext(ctx, k)
		if err != nil {
			return c, err
		}
		return store.Context{}, &store.UnreadableContextError{Rev: c.Rev, Err: errors.New("test: does not decode")}
	}
	return u.Store.GetContext(ctx, k)
}

func (u undecodableAt) SetRevokedAt(ctx context.Context, k store.ContextKey, at time.Time) error {
	if k == u.k {
		return &store.UnreadableContextError{Err: errors.New("test: does not decode")}
	}
	return u.Store.SetRevokedAt(ctx, k, at)
}

// failingAt is a store whose read of the context at k fails with err.
type failingAt struct {
	store.Store
	k   store.ContextKey
	err error
}

func (f failingAt) GetContext(ctx context.Context, k store.ContextKey) (store.Context, error) {
	if k == f.k {
		return store.Context{}, f.err
	}
	return f.Store.GetContext(ctx, k)
}

// A context whose index was lost is re-indexed, so a revocation by
// principal reaches it again, and judged against the policy in force at
// once (plan 7d; re-check IA2).
func TestReindexContextsRestoresRevocationsReach(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, sharedPolicy)
	ctx := context.Background()
	f.liveContext(t, "leaf1", "alice", alicePrincipal, "")
	ref := store.ContextRef{NAS: "leaf1", Username: "alice"}
	k := store.ContextKey{NAS: "leaf1", Username: "alice"}
	before, err := f.st.GetContext(ctx, k)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.st.SetContextPolicy(ctx, k, before.PolicyRev, store.ContextPolicy{BlobHash: "sha256:from-before",
		MaxPrivilege: before.MaxPrivilege, Enable: before.Enable}); err != nil {
		t.Fatal(err)
	}
	if err := f.st.UnindexRef(ctx, ref); err != nil { // what a deleted x/ record leaves
		t.Fatal(err)
	}
	if refs, _ := f.st.ContextsByPrincipal(ctx, alicePrincipal); len(refs) != 0 {
		t.Fatalf("the index still names it: %v", refs)
	}
	n, err := f.b.ReindexContexts(ctx, []store.IndexedRef{{ContextRef: ref}})
	if err != nil || n != 1 {
		t.Fatalf("ReindexContexts = %d, %v", n, err)
	}
	if refs, _ := f.st.ContextsByPrincipal(ctx, alicePrincipal); len(refs) != 1 || refs[0] != ref {
		t.Fatalf("not re-indexed: %v", refs)
	}
	if got, _ := f.st.GetContext(ctx, k); got.BlobHash == "sha256:from-before" {
		t.Fatal("re-indexed but not judged against the policy in force")
	}
	if v := testutil.ToFloat64(f.b.Metrics.ContextsReindexed); v != 1 {
		t.Fatalf("port49_contexts_reindexed_total = %v", v)
	}
	if refs, err := f.b.Sessions.RevokeByPrincipal(ctx, alicePrincipal); err != nil || len(refs) != 1 {
		t.Fatalf("a revocation by principal after the re-index: %v %v", refs, err)
	}
}

// An index record rewritten to list another principal hides the context
// as a deleted one does: the compare is with the context's own principal,
// read sealed, so it is re-indexed under its own, and the refresh and a
// revocation of its principal reach it again. One indexed as it should be
// is left alone and not counted (re-check I2).
func TestReindexContextsRestoresARewrittenIndex(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, sharedPolicy)
	ctx := context.Background()
	f.liveContext(t, "leaf1", "alice", alicePrincipal, "")
	f.liveContext(t, "nx1", "alice", alicePrincipal, "")
	ref := store.ContextRef{NAS: "leaf1", Username: "alice"}
	kept := store.ContextRef{NAS: "nx1", Username: "alice"}
	k := store.ContextKey{NAS: "leaf1", Username: "alice"}
	if err := f.st.UnindexRef(ctx, ref); err != nil {
		t.Fatal(err)
	}
	if err := f.st.IndexContext(ctx, "user:mallory@example.com", "", "", ref, time.Hour); err != nil {
		t.Fatal(err)
	}
	n, err := f.b.ReindexContexts(ctx, []store.IndexedRef{
		{ContextRef: ref, Principals: []string{"user:mallory@example.com"}},
		{ContextRef: kept, Principals: []string{alicePrincipal}},
	})
	if err != nil || n != 1 {
		t.Fatalf("ReindexContexts = %d, %v; want the rewritten one alone", n, err)
	}
	if v := testutil.ToFloat64(f.b.Metrics.ContextsReindexed); v != 1 {
		t.Fatalf("port49_contexts_reindexed_total = %v", v)
	}
	if refs, _ := f.st.ContextsByPrincipal(ctx, alicePrincipal); len(refs) != 2 {
		t.Fatalf("not re-indexed under its own principal: %v", refs)
	}
	// The refresh reaches it again: a policy written over it is judged.
	c, err := f.st.GetContext(ctx, k)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.st.SetContextPolicy(ctx, k, c.PolicyRev, store.ContextPolicy{BlobHash: "sha256:from-before",
		MaxPrivilege: c.MaxPrivilege, Enable: c.Enable}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.b.Refresh(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if got, _ := f.st.GetContext(ctx, k); got.BlobHash == "sha256:from-before" {
		t.Fatal("the refresh did not reach the re-indexed context")
	}
	refs, err := f.b.Sessions.RevokeByPrincipal(ctx, alicePrincipal)
	if err != nil || len(refs) != 2 {
		t.Fatalf("a revocation by principal after the re-index: %v %v", refs, err)
	}
	if got, _ := f.st.GetContext(ctx, k); got.RevokedAt.IsZero() {
		t.Fatal("the revocation did not reach the re-indexed context")
	}
}

// A context whose index record lists its principal but not its
// certificate, or no sid while it has one, is re-indexed: a revocation by
// either would miss it (re-check I2).
func TestReindexContextsRestoresASidOrCertificate(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, sharedPolicy)
	ctx := context.Background()
	ref := store.ContextRef{NAS: "leaf1", Username: "alice"}
	k := store.ContextKey{NAS: "leaf1", Username: "alice"}
	if err := f.st.PutContext(ctx, k, store.Context{CtxID: "ctx_leaf1", Principal: alicePrincipal, Username: "alice",
		PrivLvl: 1, AuthTime: f.now, RefreshedAt: f.now,
		Credential: store.Credential{Sid: "sid-1", Issuer: "corp", Serial: "01"}}, time.Hour); err != nil {
		t.Fatal(err)
	}
	ck := store.CertKey("corp", "01")
	for _, listed := range []store.IndexedRef{
		{ContextRef: ref, Principals: []string{alicePrincipal}, Sids: []string{"sid-1"}},
		{ContextRef: ref, Principals: []string{alicePrincipal}, Certs: []string{ck}},
	} {
		if err := f.st.UnindexRef(ctx, ref); err != nil {
			t.Fatal(err)
		}
		if n, err := f.b.ReindexContexts(ctx, []store.IndexedRef{listed}); err != nil || n != 1 {
			t.Fatalf("ReindexContexts(%+v) = %d, %v", listed, n, err)
		}
		if refs, _ := f.st.ContextsBySid(ctx, "sid-1"); len(refs) != 1 {
			t.Fatalf("after %+v, not indexed by sid: %v", listed, refs)
		}
		if refs, _ := f.st.ContextsByCert(ctx, ck); len(refs) != 1 {
			t.Fatalf("after %+v, not indexed by certificate: %v", listed, refs)
		}
	}
	// A rotated sid lists another than the record's: that is no loss.
	if n, err := f.b.ReindexContexts(ctx, []store.IndexedRef{{ContextRef: ref, Principals: []string{alicePrincipal},
		Sids: []string{"sid-2"}, Certs: []string{ck}}}); err != nil || n != 0 {
		t.Fatalf("ReindexContexts over a rotated sid = %d, %v", n, err)
	}
}

// One that will not open cannot be indexed, and no refresh would visit
// it: it is revoked, which needs no key.
func TestReindexContextsRevokesOneThatWillNotOpen(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, sharedPolicy)
	ctx := context.Background()
	f.liveContext(t, "leaf1", "alice", alicePrincipal, "")
	k := store.ContextKey{NAS: "leaf1", Username: "alice"}
	f.b.Store = unreadableAt{Store: f.st, k: k}
	if n, err := f.b.ReindexContexts(ctx, []store.IndexedRef{{ContextRef: store.ContextRef{NAS: "leaf1",
		Username: "alice"}}}); err != nil || n != 1 {
		t.Fatalf("ReindexContexts = %d, %v", n, err)
	}
	if got, _ := f.st.GetContext(ctx, k); got.RevokedAt.IsZero() {
		t.Fatal("an unindexed context that will not open was left unrevoked")
	}
}

// One that does not decode cannot be revoked either: it is deleted at its
// own revision, since nothing can use it, and the pass goes on (Task 7
// review K-1).
func TestReindexContextsDeletesOneThatDoesNotDecode(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, sharedPolicy)
	ctx := context.Background()
	f.liveContext(t, "leaf1", "alice", alicePrincipal, "")
	f.liveContext(t, "nx1", "alice", alicePrincipal, "")
	k := store.ContextKey{NAS: "leaf1", Username: "alice"}
	f.b.Store = undecodableAt{Store: f.st, k: k}
	n, err := f.b.ReindexContexts(ctx, []store.IndexedRef{{ContextRef: store.ContextRef{NAS: "leaf1",
		Username: "alice"}}, {ContextRef: store.ContextRef{NAS: "nx1", Username: "alice"}}})
	if err != nil || n != 2 {
		t.Fatalf("ReindexContexts = %d, %v", n, err)
	}
	if _, err := f.st.GetContext(ctx, k); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("an undecodable context was left: %v", err)
	}
}

// One context that fails is said, without its value, and counted, and the
// pass goes on to the rest; only the store being unavailable ends it
// (re-check I3).
func TestReindexContextsGoesOnPastAFailure(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, sharedPolicy)
	ctx := context.Background()
	f.liveContext(t, "leaf1", "alice", alicePrincipal, "")
	f.liveContext(t, "nx1", "alice", alicePrincipal, "")
	bad := store.ContextKey{NAS: "leaf1", Username: "alice"}
	refs := []store.IndexedRef{{ContextRef: store.ContextRef{NAS: "leaf1", Username: "alice"}},
		{ContextRef: store.ContextRef{NAS: "nx1", Username: "alice"}}}
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	f.b.Store = failingAt{Store: f.st, k: bad, err: errors.New("test: too large")}
	n, err := f.b.ReindexContexts(ctx, refs)
	if err != nil || n != 1 {
		t.Fatalf("ReindexContexts past one failure = %d, %v", n, err)
	}
	if v := testutil.ToFloat64(f.b.Metrics.ContextsReindexFailures); v != 1 {
		t.Fatalf("port49_contexts_reindex_failures_total = %v", v)
	}
	if !strings.Contains(buf.String(), `the context for "alice" on "leaf1"`) {
		t.Fatalf("the failure was not said: %q", buf.String())
	}
	f.b.Store = failingAt{Store: f.st, k: bad, err: store.ErrUnavailable}
	if _, err := f.b.ReindexContexts(ctx, refs); !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("ReindexContexts with the store unavailable = %v", err)
	}
}

// A context a mark revoked while it was hidden is marked by the re-index,
// not judged: the revocation walked the index and missed it, and the
// record must read as revoked (Task 7b review m-1).
func TestReindexContextsMarksOneAMarkRevokes(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, sharedPolicy)
	ctx := context.Background()
	f.liveContext(t, "leaf1", "alice", alicePrincipal, "")
	ref := store.ContextRef{NAS: "leaf1", Username: "alice"}
	if err := f.st.UnindexRef(ctx, ref); err != nil {
		t.Fatal(err)
	}
	at := f.now.Add(-time.Minute)
	f.b.Marks = store.NewMarks()
	f.b.Marks.Put(store.Revocation{Kind: store.RevocationPrincipal, Key: alicePrincipal, At: at})
	if n, err := f.b.ReindexContexts(ctx, []store.IndexedRef{{ContextRef: ref}}); err != nil || n != 1 {
		t.Fatalf("ReindexContexts = %d, %v", n, err)
	}
	if c, _ := f.st.GetContext(ctx, store.ContextKey{NAS: "leaf1", Username: "alice"}); !c.RevokedAt.Equal(at) {
		t.Fatalf("revoked_at = %v, want the mark's %v", c.RevokedAt, at)
	}
}

// One that will not open is revoked even when a principal lists it: the
// listing may name one no refresh walks. Each revoked is named in the log,
// and recorded as the refresh records one (Task 7b review m-2, m-3).
func TestReindexContextsRevokesOneListedThatWillNotOpen(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, sharedPolicy)
	ctx := context.Background()
	f.liveContext(t, "leaf1", "alice", alicePrincipal, "")
	k := store.ContextKey{NAS: "leaf1", Username: "alice"}
	f.b.Store = unreadableAt{Store: f.st, k: k}
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	if n, err := f.b.ReindexContexts(ctx, []store.IndexedRef{{ContextRef: store.ContextRef{NAS: "leaf1",
		Username: "alice"}, Principals: []string{"user:mallory@example.com"}}}); err != nil || n != 1 {
		t.Fatalf("ReindexContexts = %d, %v", n, err)
	}
	if got, _ := f.st.GetContext(ctx, k); got.RevokedAt.IsZero() {
		t.Fatal("a listed context that will not open was left unrevoked")
	}
	if !strings.Contains(buf.String(), `the context for "alice" on "leaf1", found by the re-index`) {
		t.Fatalf("the revocation was not named: %q", buf.String())
	}
	if !strings.Contains(f.log.String(), `"reason":"blob_unavailable"`) {
		t.Fatalf("no refresh record: %q", f.log.String())
	}
}
