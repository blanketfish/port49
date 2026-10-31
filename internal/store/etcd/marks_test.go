package etcd

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/crypt"
	"github.com/rhwendt/port49/internal/store/etcd/etcdtest"
	"github.com/rhwendt/port49/internal/store/storetest"
)

// twoOnShared is two processes' stores over one keyspace on the shared
// member, each its own Store, as two port49-broker processes are.
func twoOnShared(t *testing.T, clock func() time.Time) (*Store, *Store) {
	cli := etcdtest.Client(t)
	prefix := etcdtest.Prefix()
	return newStore(cli, cli, Config{Prefix: prefix, Now: clock}), newStore(cli, cli, Config{Prefix: prefix, Now: clock})
}

// The landed-after-lift flag against etcd, bare and through the sealing
// layer, which is what both brokers run (decision 51). The "flag set" and
// "flag clear" cases, each putting the mark key in one branch of the
// inner transaction, are the proof that etcd 3.6.15 takes a put of one key
// in both branches (re-review R-M3).
func TestTheEtcdStoreFlagsAMarkLandedAfterALift(t *testing.T) {
	t.Parallel()
	storetest.LandedAfterLift(t, func(t *testing.T) (store.Store, store.Store) {
		a, b := twoOnShared(t, func() time.Time { return t0 })
		return a, b
	}, t0)
}

func TestTheSealingLayerOverEtcdFlagsAMarkLandedAfterALift(t *testing.T) {
	t.Parallel()
	storetest.LandedAfterLift(t, func(t *testing.T) (store.Store, store.Store) {
		a, b := twoOnShared(t, func() time.Time { return t0 })
		return crypt.Wrap(a, sealKeys, nil), crypt.Wrap(b, sealKeys, nil)
	}, t0)
}

// A lift's record is a directory family in rv/'s keyspace, on the token
// client, so a revoke's transaction compares it with the mark on one
// cluster (re-review R-I3), on a lease: an hour plus the pool's grace.
func TestALiftsRecordIsBesideTheMarksOnALease(t *testing.T) {
	ctx := context.Background()
	s := onShared(t, func() time.Time { return t0 })
	r := store.Revocation{Kind: store.RevocationPrincipal, Key: "user:alice@example.com", At: t0}
	if err := s.PutRevocation(ctx, r); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteRevocation(ctx, r.Kind, r.Key, store.Lift{At: t0, Origin: "offline uid 0"}); err != nil {
		t.Fatal(err)
	}
	key := s.k.lift(r.Kind, r.Key)
	if !strings.HasPrefix(key, s.k.root+famLift) || famLift == famMark {
		t.Fatalf("the lift's record is at %q", key)
	}
	resp, err := s.tok.Get(ctx, key)
	if err != nil || len(resp.Kvs) != 1 || resp.Kvs[0].Lease == 0 {
		t.Fatalf("the lift's record: %v %v", resp, err)
	}
	ttl, err := s.tok.TimeToLive(ctx, clientv3.LeaseID(resp.Kvs[0].Lease))
	if err != nil || time.Duration(ttl.TTL)*time.Second < store.LiftTTL {
		t.Fatalf("the lift's record lives %ds: %v", ttl.TTL, err)
	}
	if strings.Contains(string(resp.Kvs[0].Value), "Origin") || !strings.Contains(string(resp.Kvs[0].Value), `"origin"`) {
		t.Fatalf("the record is not snake_case: %s", resp.Kvs[0].Value)
	}
}

// Once the lift's record is gone (its lease reclaimed it), a late put
// lands unflagged, as before the flag, and GetLift answers ErrNotFound; a
// record past its own expiry on the store's clock is ErrNotFound too.
func TestAnExpiredLiftsRecordFlagsNothing(t *testing.T) {
	ctx := context.Background()
	now := t0
	var mu sync.Mutex
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	s := onShared(t, clock)
	r := store.Revocation{Kind: store.RevocationPrincipal, Key: "user:alice@example.com", At: t0}
	if err := s.PutRevocation(ctx, r); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteRevocation(ctx, r.Kind, r.Key, store.Lift{At: t0}); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	now = t0.Add(store.LiftTTL + time.Second)
	mu.Unlock()
	if _, err := s.GetLift(ctx, r.Kind, r.Key); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a lift's record past its expiry: %v", err)
	}
	resp, err := s.tok.Get(ctx, s.k.lift(r.Kind, r.Key))
	if err != nil || len(resp.Kvs) != 1 {
		t.Fatalf("%v %v", resp, err)
	}
	if _, err := s.tok.Revoke(ctx, clientv3.LeaseID(resp.Kvs[0].Lease)); err != nil {
		t.Fatal(err)
	}
	other := onShared(t, clock)
	other.k = s.k // another process, its floor 0
	r.At = t0.Add(time.Minute)
	if err := other.PutRevocation(ctx, r); err != nil {
		t.Fatal(err)
	}
	if got, err := other.GetRevocation(ctx, r.Kind, r.Key); err != nil || got.LandedAfterLift {
		t.Fatalf("a put after the lift's record expired: %+v %v", got, err)
	}
}

// A lift whose record's lease cannot be had lifts nothing: the mark
// stands, and the error is ErrUnavailable, which Lift says as "could not
// be lifted, and stands" (re-review R-I3). That fails closed.
func TestALiftWhoseLeaseFailsLiftsNothing(t *testing.T) {
	ctx := context.Background()
	s := onShared(t, func() time.Time { return t0 })
	r := store.Revocation{Kind: store.RevocationPrincipal, Key: "user:alice@example.com", At: t0}
	if err := s.PutRevocation(ctx, r); err != nil {
		t.Fatal(err)
	}
	dead, err := clientv3.New(clientv3.Config{Endpoints: []string{"127.0.0.1:1"}, DialTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dead.Close() })
	s.tokLeases = newLeases(dead, s.now, 5*time.Minute)
	lctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if err := s.DeleteRevocation(lctx, r.Kind, r.Key, store.Lift{At: t0}); !errors.Is(err, store.ErrUnavailable) || !errors.Is(err, store.ErrNotSent) {
		t.Fatalf("a lift whose lease failed (nothing was sent): %v", err)
	}
	if _, err := s.GetRevocation(ctx, r.Kind, r.Key); err != nil {
		t.Fatalf("the mark does not stand after a failed lift: %v", err)
	}
	if _, err := s.GetLift(ctx, r.Kind, r.Key); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a failed lift left a record: %v", err)
	}
}

// A lift whose reply was lost after it committed, sent again (the hedge's
// copy) and answered by the else branch, still counts as this process's
// own lift: its own later revoke is not flagged.
func TestALiftAnsweredByItsOwnCopyIsStillOwn(t *testing.T) {
	ctx := context.Background()
	a, b := twoOnShared(t, func() time.Time { return t0 })
	r := store.Revocation{Kind: store.RevocationPrincipal, Key: "user:alice@example.com", At: t0}
	if err := b.PutRevocation(ctx, r); err != nil {
		t.Fatal(err)
	}
	by := store.Lift{At: t0.Add(time.Second), Origin: "offline uid 0"}
	// Between a's read and its transaction, the same lift commits (b stands
	// in for a's first copy, whose reply was lost): a's transaction finds
	// the mark gone and by's own record.
	afterLiftRead = func() {
		afterLiftRead = nil
		if err := b.DeleteRevocation(ctx, r.Kind, r.Key, by); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { afterLiftRead = nil })
	if err := a.DeleteRevocation(ctx, r.Kind, r.Key, by); err != nil {
		t.Fatal(err)
	}
	r.At = t0.Add(time.Minute)
	if err := a.PutRevocation(ctx, r); err != nil {
		t.Fatal(err)
	}
	if got, _ := a.GetRevocation(ctx, r.Kind, r.Key); got.LandedAfterLift {
		t.Fatalf("a lift answered by its own copy flagged its own revoke: %+v", got)
	}
}

// Two processes revoking and lifting the same keys at once: no revoke is
// ever refused (every put lands or finds a mark standing), a lift fails
// only as ErrConflict, and each process's own-lift floor is safe for
// concurrent use (run under -race).
func TestConcurrentRevokesAndLiftsNeverRefuseARevoke(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	a, b := twoOnShared(t, func() time.Time { return t0 })
	var wg sync.WaitGroup
	errs := make(chan error, 1000)
	for g, s := range []*Store{a, b, a, b} {
		wg.Add(1)
		go func(g int, s *Store) {
			defer wg.Done()
			for i := 0; i < 25; i++ {
				key := []string{"user:alice@example.com", "user:bob@example.com"}[(g+i)%2]
				r := store.Revocation{Kind: store.RevocationPrincipal, Key: key, At: t0.Add(time.Duration(i) * time.Second)}
				if err := s.PutRevocation(store.WithMarkFloor(ctx, uint64(i)), r); err != nil {
					errs <- err
				}
				if err := s.DeleteRevocation(ctx, r.Kind, r.Key, store.Lift{At: r.At}); err != nil &&
					!errors.Is(err, store.ErrConflict) {
					errs <- err
				}
			}
		}(g, s)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("a revoke or lift failed: %v", err)
	}
	if err := a.PutRevocation(ctx, store.Revocation{Kind: store.RevocationPrincipal, Key: "user:alice@example.com",
		At: t0.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if _, err := b.GetRevocation(ctx, store.RevocationPrincipal, "user:alice@example.com"); err != nil {
		t.Fatalf("the last revoke does not stand: %v", err)
	}
}
