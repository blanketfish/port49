package etcd

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"go.etcd.io/etcd/api/v3/etcdserverpb"
	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/blanketfish/port49/internal/store"
)

// A second PutBlob the stored blob already covers leaves the key at the
// same ModRevision: the broker's mint puts one blob once a mint.
func TestASecondPutBlobInsideTheBucketWritesNothing(t *testing.T) {
	t.Parallel()
	now := t0
	s := onShared(t, func() time.Time { return now })
	ctx := context.Background()
	if err := s.PutBlob(ctx, "h", []byte("x"), 10*time.Second); err != nil {
		t.Fatal(err)
	}
	r1, err := s.ctxKV.Get(ctx, s.k.blob("h"))
	if err != nil || len(r1.Kvs) != 1 {
		t.Fatal(err)
	}
	if err := s.PutBlob(ctx, "h", []byte("x"), 10*time.Second); err != nil {
		t.Fatal(err)
	}
	r2, _ := s.ctxKV.Get(ctx, s.k.blob("h"))
	if r2.Kvs[0].ModRevision != r1.Kvs[0].ModRevision {
		t.Fatalf("the second put wrote: mod %d then %d", r1.Kvs[0].ModRevision, r2.Kvs[0].ModRevision)
	}
	if err := s.PutBlob(ctx, "h", []byte("x"), time.Hour); err != nil {
		t.Fatal(err)
	}
	r3, _ := s.ctxKV.Get(ctx, s.k.blob("h"))
	if r3.Kvs[0].ModRevision == r1.Kvs[0].ModRevision {
		t.Fatal("a longer ttl did not write")
	}
}

// Fifty mints of one blob at once all return within the call timeout
// (load run 2: half of them failed at 500 ms on a shared CAS).
func TestFiftyConcurrentPutBlobsOnOneHashFinishInTime(t *testing.T) {
	t.Parallel()
	s := onShared(t, time.Now)
	var wg sync.WaitGroup
	errs := make(chan error, 50)
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancel()
			errs <- s.PutBlob(ctx, "hot", []byte("x"), time.Minute)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
}

// conflictKV is a KV whose every transaction loses its compare.
type conflictKV struct {
	clientv3.KV
	gets int
}

func (c *conflictKV) Get(ctx context.Context, _ string, _ ...clientv3.OpOption) (*clientv3.GetResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.gets++
	return &clientv3.GetResponse{}, nil
}

func (c *conflictKV) Txn(context.Context) clientv3.Txn { return lostTxn{} }

type lostTxn struct{}

func (t lostTxn) If(...clientv3.Cmp) clientv3.Txn  { return t }
func (t lostTxn) Then(...clientv3.Op) clientv3.Txn { return t }
func (t lostTxn) Else(...clientv3.Op) clientv3.Txn { return t }
func (lostTxn) Commit() (*clientv3.TxnResponse, error) {
	return &clientv3.TxnResponse{Header: &etcdserverpb.ResponseHeader{}}, nil
}

func TestACasThatKeepsLosingBacksOffAndEndsOnItsContext(t *testing.T) {
	t.Parallel()
	kv := &conflictKV{}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := cas(ctx, kv, nil, "k", func(struct{}) bool { return true },
		func(r *struct{}, found bool) (bool, time.Time, bool, error) { return true, time.Time{}, false, nil })
	if !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("want unavailable from the context ending, got %v", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("did not end on ctx: %v", d)
	}
	// 300 ms of backoff growing to 50 ms is tens of rounds; a spin is millions.
	if kv.gets > 200 || kv.gets < 3 {
		t.Fatalf("%d rounds in 300 ms: not sleeping between rounds", kv.gets)
	}
}
