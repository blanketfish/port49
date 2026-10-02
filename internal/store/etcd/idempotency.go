package etcd

import (
	"context"
	"errors"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/rhwendt/port49/internal/store"
)

// errNoHolder refuses a record without a holder: the empty holder is one
// any request can name (the memory store's).
var errNoHolder = errors.New("store: an idempotency record must name its holder")

func (s *Store) liveIdem(r idemRec) bool { return r.ExpiresAt.After(s.now()) }

// ReserveIdempotency is design §17's put-if-absent: a live record is
// returned untouched, and only its absence is written, compare-and-set on
// the key, so of racing reservations exactly one lands.
func (s *Store) ReserveIdempotency(ctx context.Context, principal, key string, rec store.Idempotency) (store.Idempotency, bool, error) {
	if rec.Holder == "" {
		return store.Idempotency{}, false, errNoHolder
	}
	var cur store.Idempotency
	won := false
	err := cas(ctx, s.tok, s.tokLeases, s.k.idem(principal, key), s.liveIdem,
		func(r *idemRec, found bool) (bool, time.Time, bool, error) {
			if found {
				cur, won = r.idempotency(), false
				return false, time.Time{}, false, nil
			}
			*r = idemRecOf(rec)
			won = true
			return true, rec.ExpiresAt, false, nil
		})
	if err != nil || won {
		return store.Idempotency{}, won, err
	}
	return cur, false, nil
}

// CompleteIdempotency replaces the live record only while its holder is
// expect.
func (s *Store) CompleteIdempotency(ctx context.Context, principal, key, expect string, rec store.Idempotency) error {
	if rec.Holder == "" {
		return errNoHolder
	}
	if expect == "" {
		return store.ErrConflict
	}
	return cas(ctx, s.tok, s.tokLeases, s.k.idem(principal, key), s.liveIdem,
		func(r *idemRec, found bool) (bool, time.Time, bool, error) {
			if !found || r.Holder != expect {
				return false, time.Time{}, false, store.ErrConflict
			}
			*r = idemRecOf(rec)
			return true, rec.ExpiresAt, false, nil
		})
}

// ReleaseIdempotency deletes holder's own pending reservation and nothing
// else, compare-and-set on the record read.
func (s *Store) ReleaseIdempotency(ctx context.Context, principal, key, holder string) error {
	k := s.k.idem(principal, key)
	for {
		var r idemRec
		mod, ok, err := getJSON(ctx, s.tok, k, &r)
		if err != nil {
			return err
		}
		if !ok || !s.liveIdem(r) || !r.Pending || r.Holder != holder {
			return nil
		}
		if done, err := commit(ctx, s.tok, s.tokLeases, []clientv3.Cmp{unchanged(k, mod)}, nil, del{key: k}); err != nil || done {
			return err
		}
	}
}
