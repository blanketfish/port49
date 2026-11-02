package etcd

import (
	"context"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/store/etcd/etcdtest"
)

// The 101st record of one expiry bucket gets a lease of its own, so no lease
// carries more than maxAttachesPerLease keys (etcd's checkLeasePutsKeys costs a
// put by the keys already on its lease); another bucket is unaffected.
func TestALeaseTakesAtMostMaxAttachesPerLease(t *testing.T) {
	ctx := context.Background()
	l := newLeases(etcdtest.Client(t), func() time.Time { return t0 }, 5*time.Minute)
	exp := t0.Add(10 * time.Minute)
	first, err := l.For(ctx, exp)
	if err != nil {
		t.Fatal(err)
	}
	for i := 2; i <= maxAttachesPerLease; i++ {
		id, err := l.For(ctx, exp)
		if err != nil || id != first {
			t.Fatalf("attach %d: lease %v, want the first %v (%v)", i, id, first, err)
		}
	}
	next, err := l.For(ctx, exp)
	if err != nil || next == first {
		t.Fatalf("attach %d: lease %v, want a fresh one (%v)", maxAttachesPerLease+1, next, err)
	}
	if again, err := l.For(ctx, exp); err != nil || again != next {
		t.Fatalf("attach %d: lease %v, want the fresh %v (%v)", maxAttachesPerLease+2, again, next, err)
	}
	other, err := l.For(ctx, exp.Add(2*leaseBucket))
	if err != nil || other == first || other == next {
		t.Fatalf("another bucket: lease %v (%v)", other, err)
	}
	if again, err := l.For(ctx, exp.Add(2*leaseBucket)); err != nil || again != other {
		t.Fatalf("another bucket's second attach: %v, want %v (%v)", again, other, err)
	}
}
