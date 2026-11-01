package etcd

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/blanketfish/port49/internal/store"
)

// ledgerRec is lw/<nas>/<user> (plan 7e, Ruling 4): the highest write
// sequence known at the key, a revocation floor and the sequence it holds
// through, and until when the mark is kept (zero: for good). Only the
// broker's role writes it.
type ledgerRec struct {
	Seq       uint64    `json:"seq"`
	RevokedAt time.Time `json:"revoked_at,omitempty"`
	FloorSeq  uint64    `json:"floor_seq,omitempty"`
	Until     time.Time `json:"until,omitempty"`
}

// raised is r with m applied: the higher sequence; at the same sequence
// the later keep (a zero keep, for good, wins). A floor, r's or m's, is
// kept while the sequence is at or below the one it holds through, the
// later floor and the higher sequence of the two; a sequence above it
// clears it, as crypt.Ledger does. ok is false when m raises nothing.
func (r ledgerRec) raised(m store.LedgerMark) (ledgerRec, bool) {
	out := r
	switch {
	case m.Seq > r.Seq:
		out = ledgerRec{Seq: m.Seq, Until: m.Until}
	case m.Seq == r.Seq && !out.Until.IsZero() && (m.Until.IsZero() || m.Until.After(out.Until)):
		out.Until = m.Until
	}
	out.RevokedAt, out.FloorSeq = time.Time{}, 0
	for _, f := range []struct {
		at  time.Time
		seq uint64
	}{{r.RevokedAt, r.FloorSeq}, {m.RevokedAt, m.FloorSeq}} {
		if f.at.IsZero() || out.Seq > f.seq {
			continue
		}
		if f.at.After(out.RevokedAt) {
			out.RevokedAt = f.at
		}
		out.FloorSeq = max(out.FloorSeq, f.seq)
	}
	return out, out.Seq != r.Seq || !out.Until.Equal(r.Until) || !out.RevokedAt.Equal(r.RevokedAt) ||
		out.FloorSeq != r.FloorSeq
}

// LedgerMarks is every mark the record holds, read at one revision a page
// at a time (store.LedgerSource). A record that does not decode is an
// error naming its key: skipped, a start would admit a put-back there.
func (s *Store) LedgerMarks(ctx context.Context) (uint64, []store.LedgerMark, error) {
	prefix := s.k.family(famLedger)
	end := clientv3.GetPrefixRangeEnd(prefix)
	from, rev := prefix, int64(0)
	var out []store.LedgerMark
	for {
		opts := []clientv3.OpOption{clientv3.WithRange(end), clientv3.WithLimit(500)}
		if rev > 0 {
			opts = append(opts, clientv3.WithRev(rev))
		}
		resp, err := s.ctxKV.Get(ctx, from, opts...)
		if err != nil {
			return 0, nil, unavailable(err)
		}
		if rev == 0 {
			rev = resp.Header.Revision
		}
		for _, kv := range resp.Kvs {
			nas, user, ok := lastTwo(string(kv.Key))
			var r ledgerRec
			if !ok || json.Unmarshal(kv.Value, &r) != nil {
				return 0, nil, fmt.Errorf("%w; delete that key as etcd's root to start without its mark, "+
					"accepting a context put back at that one key", notDecoded(fmt.Sprintf("ledger record %q", kv.Key)))
			}
			out = append(out, store.LedgerMark{Key: store.ContextKey{NAS: nas, Username: user}, Seq: r.Seq,
				RevokedAt: r.RevokedAt, FloorSeq: r.FloorSeq, Until: r.Until})
		}
		if !resp.More || len(resp.Kvs) == 0 {
			return uint64(rev), out, nil
		}
		from = string(resp.Kvs[len(resp.Kvs)-1].Key) + "\x00"
	}
}

// PutLedgerMarks raises each key's record to its mark (store.LedgerSink),
// never lowering one, by cas on the record's revision; a lost race reads
// again. A mark is leased to its Until, and one with none has no lease.
// It stops at the first error and returns it, with how many marks before
// it landed or raised nothing; the keeper owes the rest again.
func (s *Store) PutLedgerMarks(ctx context.Context, ms []store.LedgerMark) (int, error) {
	live := func(ledgerRec) bool { return true }
	for i, m := range ms {
		err := cas(ctx, s.ctxKV, s.ctxLeases, s.k.ledgerOf(m.Key), live,
			func(r *ledgerRec, _ bool) (bool, time.Time, bool, error) {
				next, ok := r.raised(m)
				if !ok {
					return false, time.Time{}, false, nil
				}
				*r = next
				return true, next.Until, false, nil
			})
		if err != nil {
			return i, err
		}
	}
	return len(ms), nil
}
