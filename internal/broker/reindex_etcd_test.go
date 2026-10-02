package broker

import (
	"bytes"
	"context"
	"log"
	"net/url"
	"strings"
	"testing"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/rhwendt/port49/internal/session"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/crypt"
	"github.com/rhwendt/port49/internal/store/etcd"
	"github.com/rhwendt/port49/internal/store/etcd/etcdtest"
)

// onEtcd puts f's broker on a member of its own, through the sealing
// layer, as port49d runs it: the etcd store, the sealed store over it,
// and a raw client under the same prefix for a store writer's puts.
func onEtcd(t *testing.T, f *fixture) (*etcd.Store, store.Store, *clientv3.Client, string) {
	t.Helper()
	const prefix = "/port49-broker/"
	srv := etcdtest.Start(t, etcdtest.Options{})
	es, err := etcd.Open(etcd.Config{Endpoints: []string{srv.Endpoint}, Prefix: prefix, Now: f.b.Now})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { es.Close() })
	var k crypt.Key
	k.ID = "v1"
	copy(k.Bytes[:], "broker-test-context-key-32-bytes")
	sealed := crypt.Wrap(es, crypt.Keys{Current: k}, nil)
	f.b.Store = sealed
	f.b.Sessions = session.New(sealed, f.b.Now, time.Hour, time.Hour)
	return es, sealed, srv.Client(t, "raw"), prefix + "v1/"
}

// putJudged writes a live, indexed context for principal under (nas, user)
// through st, carrying a blob no policy compiles, so a refresh that
// reaches it is seen to.
func putJudged(t *testing.T, f *fixture, st store.Store, nas, user, principal string) {
	t.Helper()
	ctx := context.Background()
	if err := st.PutContext(ctx, store.ContextKey{NAS: nas, Username: user}, store.Context{CtxID: "ctx_" + nas,
		Principal: principal, Username: user, PrivLvl: 1, AuthTime: f.now, RefreshedAt: f.now,
		BlobHash: "sha256:from-before"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := st.IndexContext(ctx, principal, "", "", store.ContextRef{NAS: nas, Username: user}, time.Hour); err != nil {
		t.Fatal(err)
	}
}

// One context record a store writer garbled, still indexed, never stops
// the refresh: it cannot be revoked, so it is deleted at the revision read,
// and every other context, another principal's too, is judged (Task 7b
// review I-1).
func TestAGarbledContextNeverStopsTheRefresh(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, sharedPolicy)
	ctx := context.Background()
	_, sealed, raw, root := onEtcd(t, f)
	putJudged(t, f, sealed, "leaf1", "alice", alicePrincipal)
	putJudged(t, f, sealed, "nx1", "alice", alicePrincipal)
	putJudged(t, f, sealed, "nx1", "alice2", alice2)
	if _, err := raw.Put(ctx, root+"c/leaf1/alice", "not json"); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	if _, err := f.b.Refresh(ctx, nil); err != nil {
		t.Fatalf("a refresh over one garbled context: %v", err)
	}
	// Said by its key alone: the decoder's error quotes the stored bytes.
	if !strings.Contains(buf.String(), "does not decode") || strings.Contains(buf.String(), "invalid character") {
		t.Fatalf("the log does not say the record by its key alone: %q", buf.String())
	}
	if resp, err := raw.Get(ctx, root+"c/leaf1/alice"); err != nil || len(resp.Kvs) != 0 {
		t.Fatalf("the garbled context was left: %v %v", resp, err)
	}
	for _, k := range []store.ContextKey{{NAS: "nx1", Username: "alice"}, {NAS: "nx1", Username: "alice2"}} {
		// Judged: the policy in force written into it, or, for alice2,
		// whose subject's username is alice, revoked.
		if c, err := sealed.GetContext(ctx, k); err != nil || c.BlobHash == "sha256:from-before" && c.RevokedAt.IsZero() {
			t.Fatalf("%v was not judged: %v", k, err)
		}
	}
}

// A lookup entry a store writer planted whose key does not parse never
// stops the refresh: alice2's lookup skips it, and alice, sorted after
// alice2 ('2' before '@'), is still judged (final review I-1).
func TestAnUnparseableLookupEntryNeverStopsTheRefresh(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, sharedPolicy)
	ctx := context.Background()
	_, sealed, raw, root := onEtcd(t, f)
	putJudged(t, f, sealed, "nx1", "alice2", alice2)
	putJudged(t, f, sealed, "leaf1", "alice", alicePrincipal)
	if _, err := raw.Put(ctx, root+"ip/"+url.PathEscape(alice2)+"/%zz/x", "{}"); err != nil {
		t.Fatal(err)
	}
	rep, err := f.b.Refresh(ctx, nil)
	if err != nil || rep.Failed != 0 {
		t.Fatalf("a refresh over an unparseable lookup entry: %+v %v", rep, err)
	}
	for _, k := range []store.ContextKey{{NAS: "nx1", Username: "alice2"}, {NAS: "leaf1", Username: "alice"}} {
		if c, err := sealed.GetContext(ctx, k); err != nil || c.BlobHash == "sha256:from-before" && c.RevokedAt.IsZero() {
			t.Fatalf("%v was not judged: %v", k, err)
		}
	}
}

// The I2 path on etcd through the sealing layer: a raw rewrite of x/ to
// list another principal hides the context from the refresh; Unindexed and
// ReindexContexts restore it, and the next pass finds nothing (re-check I2).
func TestARewrittenIndexIsRestoredOnEtcd(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, sharedPolicy)
	ctx := context.Background()
	es, sealed, raw, root := onEtcd(t, f)
	putJudged(t, f, sealed, "leaf1", "alice", alicePrincipal)
	k := store.ContextKey{NAS: "leaf1", Username: "alice"}
	if _, err := raw.Put(ctx, root+"x/leaf1/alice", `{"principals":[{"key":"user:mallory@example.com","expires_at":"`+
		f.now.Add(time.Hour).Format(time.RFC3339)+`"}]}`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.b.Refresh(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if c, _ := sealed.GetContext(ctx, k); c.BlobHash != "sha256:from-before" {
		t.Fatal("the rewritten index did not hide the context; the test proves nothing")
	}
	refs, err := es.Unindexed(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := f.b.ReindexContexts(ctx, refs); err != nil || n != 1 {
		t.Fatalf("ReindexContexts = %d, %v", n, err)
	}
	if c, _ := sealed.GetContext(ctx, k); c.BlobHash == "sha256:from-before" {
		t.Fatal("re-indexed but not judged")
	}
	if refs, err = es.Unindexed(ctx); err != nil {
		t.Fatal(err)
	}
	if n, err := f.b.ReindexContexts(ctx, refs); err != nil || n != 0 {
		t.Fatalf("a second pass = %d, %v", n, err)
	}
	if got, err := f.b.Sessions.RevokeByPrincipal(ctx, alicePrincipal); err != nil || len(got) != 1 {
		t.Fatalf("a revocation of alice after the re-index: %v %v", got, err)
	}
}

// putWithSid is putJudged for an OIDC login under sid.
func putWithSid(t *testing.T, f *fixture, st store.Store, nas, user, principal, sid string) {
	t.Helper()
	ctx := context.Background()
	if err := st.PutContext(ctx, store.ContextKey{NAS: nas, Username: user}, store.Context{CtxID: "ctx_" + nas,
		Principal: principal, Username: user, PrivLvl: 1, AuthTime: f.now, RefreshedAt: f.now,
		BlobHash: "sha256:from-before", Credential: store.Credential{Method: "oidc", Sid: sid}}, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := st.IndexContext(ctx, principal, sid, "", store.ContextRef{NAS: nas, Username: user}, time.Hour); err != nil {
		t.Fatal(err)
	}
}

// reindexAll is port49d's pass: Unindexed, then ReindexContexts.
func reindexAll(t *testing.T, f *fixture, es *etcd.Store) int {
	t.Helper()
	refs, err := es.Unindexed(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	n, err := f.b.ReindexContexts(context.Background(), refs)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// A session refresh that rotates the sid writes it into the sealed record
// as well as the index, so the re-index finds nothing to repair; an x/
// record whose sid a store writer swapped hides the context from a
// revocation by its own sid, and is re-indexed, after which that
// revocation reaches it (Task 7b review I-2).
func TestASwappedSidIsRestoredOnEtcd(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, sharedPolicy)
	ctx := context.Background()
	es, sealed, raw, root := onEtcd(t, f)
	putWithSid(t, f, sealed, "leaf1", "alice", alicePrincipal, "sid-1")
	if n, err := f.b.Sessions.Refresh(ctx, alicePrincipal, f.now, f.now.Add(-time.Hour), "", "sid-1",
		"sid-2"); err != nil || n != 1 {
		t.Fatalf("a rotating refresh = %d, %v", n, err)
	}
	if n := reindexAll(t, f, es); n != 0 {
		t.Fatalf("the re-index after a rotation re-indexed %d", n)
	}
	if _, err := raw.Put(ctx, root+"x/leaf1/alice", `{"principals":[{"key":"`+alicePrincipal+`","expires_at":"`+
		f.now.Add(time.Hour).Format(time.RFC3339)+`"}],"sids":[{"key":"sid-x","expires_at":"`+
		f.now.Add(time.Hour).Format(time.RFC3339)+`"}]}`); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Put(ctx, root+"is/sid-x/leaf1/alice", "{}"); err != nil { // and its lookup, so x/ looks whole
		t.Fatal(err)
	}
	if refs, _ := sealed.ContextsBySid(ctx, "sid-2"); len(refs) != 0 {
		t.Fatalf("the swap did not hide the context; the test proves nothing: %v", refs)
	}
	if n := reindexAll(t, f, es); n != 1 {
		t.Fatalf("the re-index over a swapped sid re-indexed %d", n)
	}
	if refs, err := f.b.Sessions.RevokeBySid(ctx, "sid-2"); err != nil || len(refs) != 1 {
		t.Fatalf("a revocation by the sealed sid after the re-index: %v %v", refs, err)
	}
}

// A store write that deletes a context's lookup entry alone, its x/
// record intact, hides it from the revocation that starts there; the
// re-index sees the entry missing and puts it again (Task 7b review I-2).
func TestADeletedLookupEntryIsRestoredOnEtcd(t *testing.T) {
	for _, c := range []struct {
		name, entry string
		revoke      func(f *fixture) ([]store.ContextRef, error)
	}{
		{"principal", "ip/" + url.PathEscape(alicePrincipal) + "/leaf1/alice", func(f *fixture) ([]store.ContextRef, error) {
			return f.b.Sessions.RevokeByPrincipal(context.Background(), alicePrincipal)
		}},
		{"sid", "is/sid-1/leaf1/alice", func(f *fixture) ([]store.ContextRef, error) {
			return f.b.Sessions.RevokeBySid(context.Background(), "sid-1")
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFixtureWithPolicy(t, 8, sharedPolicy)
			ctx := context.Background()
			es, sealed, raw, root := onEtcd(t, f)
			putWithSid(t, f, sealed, "leaf1", "alice", alicePrincipal, "sid-1")
			if resp, err := raw.Delete(ctx, root+c.entry); err != nil || resp.Deleted != 1 {
				t.Fatalf("deleting %s: %v %v", c.entry, resp, err)
			}
			if n := reindexAll(t, f, es); n != 1 {
				t.Fatalf("the re-index over a deleted %s lookup re-indexed %d", c.name, n)
			}
			if refs, err := c.revoke(f); err != nil || len(refs) != 1 {
				t.Fatalf("a revocation by %s after the re-index: %v %v", c.name, refs, err)
			}
		})
	}
}
