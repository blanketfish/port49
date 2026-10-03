package etcd

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/rhwendt/port49/internal/store"
)

// supersededRec is sp/<nas>/<user>, and meta/superseded_all for every key:
// when tokens were last superseded there, and until when that is kept
// (plan 7e, Ruling 9). The broker's role alone writes either, and alone
// reads sp/; meta/superseded_all sits under meta/, which the daemon's
// role reads, and tells it nothing it could use.
type supersededRec struct {
	At        time.Time `json:"at"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (r supersededRec) live(now time.Time) bool { return now.Before(r.ExpiresAt) }

// SupersedeTokens keeps the later instant at k, by a compare on the
// record's revision, on a lease past SupersededFor.
func (s *Store) SupersedeTokens(ctx context.Context, k store.TokenKey, at time.Time) error {
	return s.supersede(ctx, s.k.superseded(k), at)
}

// SupersedeAll is SupersedeTokens for every key.
func (s *Store) SupersedeAll(ctx context.Context, at time.Time) error {
	return s.supersede(ctx, s.k.meta("superseded_all"), at)
}

func (s *Store) supersede(ctx context.Context, key string, at time.Time) error {
	now := s.now()
	live := func(r supersededRec) bool { return r.live(now) }
	return cas(ctx, s.tok, s.tokLeases, key, live, func(r *supersededRec, found bool) (bool, time.Time, bool, error) {
		next := supersededRec{At: at, ExpiresAt: now.Add(store.SupersededFor)}
		if found && r.At.After(at) {
			next.At = r.At
		}
		*r = next
		return true, next.ExpiresAt, false, nil
	})
}

// SupersededAt reads k's record and the all-keys record in one
// transaction, and is the later live instant of the two.
func (s *Store) SupersededAt(ctx context.Context, k store.TokenKey) (time.Time, error) {
	resp, err := s.tok.Txn(ctx).Then(clientv3.OpGet(s.k.superseded(k)),
		clientv3.OpGet(s.k.meta("superseded_all"))).Commit()
	if err != nil {
		return time.Time{}, unavailable(err)
	}
	now := s.now()
	var at time.Time
	for _, r := range resp.Responses {
		kvs := r.GetResponseRange().Kvs
		if len(kvs) == 0 {
			continue
		}
		var rec supersededRec
		if json.Unmarshal(kvs[0].Value, &rec) != nil {
			return time.Time{}, notDecoded(fmt.Sprintf("superseded record %q", kvs[0].Key))
		}
		if rec.live(now) && rec.At.After(at) {
			at = rec.At
		}
	}
	return at, nil
}
