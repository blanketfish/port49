package etcd

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
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
// never lowering one. A batch of up to ledgerBatch marks is read in one
// transaction and written in one, each mark in a transaction of its own
// inside it with its own compare on the record's revision: a lost compare
// reads and writes that mark again, alone, and the batch's other marks
// stand. A mark is leased to its Until, and one with none has no lease.
// It stops at the first error and returns it, with how many marks before
// it landed or raised nothing; the keeper owes the rest again.
func (s *Store) PutLedgerMarks(ctx context.Context, ms []store.LedgerMark) (int, error) {
	for from := 0; from < len(ms); from += ledgerBatch {
		batch := ms[from:min(from+ledgerBatch, len(ms))]
		n, err := s.putLedgerBatch(ctx, batch)
		if err != nil {
			return from + n, err
		}
	}
	return len(ms), nil
}

// putLedgerBatch lands batch, and says how many marks from its start landed
// when it stops on an error. A record that does not decode stops it at that
// key: the keys before it are still written first.
func (s *Store) putLedgerBatch(ctx context.Context, batch []store.LedgerMark) (int, error) {
	// Marks for one key are applied in order, in one write.
	var todo []string
	byKey := map[string][]store.LedgerMark{}
	for _, m := range batch {
		k := s.k.ledgerOf(m.Key)
		if _, ok := byKey[k]; !ok {
			todo = append(todo, k)
		}
		byKey[k] = append(byKey[k], m)
	}
	pending := map[string]bool{}
	for _, k := range todo {
		pending[k] = true
	}
	// landed is how many marks from the batch's start have landed: up to the
	// first whose key is still pending.
	landed := func() int {
		for i, m := range batch {
			if pending[s.k.ledgerOf(m.Key)] {
				return i
			}
		}
		return len(batch)
	}
	var stop error
	for round := 0; len(todo) > 0; round++ {
		if round > 0 {
			if err := casBackoff(ctx, round); err != nil {
				return landed(), unavailable(err)
			}
		}
		gets := make([]clientv3.Op, len(todo))
		for i, k := range todo {
			gets[i] = clientv3.OpGet(k)
		}
		read, err := s.ctxKV.Txn(ctx).Then(gets...).Commit()
		if err != nil {
			return landed(), unavailable(err)
		}
		var writes []ledgerWrite
		for i := 0; i < len(todo); i++ {
			k := todo[i]
			var r ledgerRec
			var mod int64
			if kvs := read.Responses[i].GetResponseRange().Kvs; len(kvs) == 1 {
				if json.Unmarshal(kvs[0].Value, &r) != nil {
					stop, todo = notDecoded(k), todo[:i]
					break
				}
				mod = kvs[0].ModRevision
			}
			changed := false
			for _, m := range byKey[k] {
				if next, ok := r.raised(m); ok {
					r, changed = next, true
				}
			}
			if !changed {
				delete(pending, k)
				continue
			}
			writes = append(writes, ledgerWrite{key: k, mod: mod, rec: r})
		}
		lost, err := s.writeLedger(ctx, writes)
		if err != nil {
			return landed(), err
		}
		todo = lost
		for _, w := range writes {
			if !slices.Contains(lost, w.key) {
				delete(pending, w.key)
			}
		}
	}
	if stop != nil {
		return landed(), stop
	}
	return len(batch), nil
}

// ledgerWrite is one record to write, if its key is still at mod.
type ledgerWrite struct {
	key string
	mod int64
	rec ledgerRec
}

// writeLedger writes each of ws in a transaction of its own inside one
// transaction, each under its own compare on the key's revision, and
// returns the keys whose compare was lost. A lease etcd no longer knows
// costs one retry on fresh leases, as commit does.
func (s *Store) writeLedger(ctx context.Context, ws []ledgerWrite) ([]string, error) {
	if len(ws) == 0 {
		return nil, nil
	}
	for attempt := 0; ; attempt++ {
		ops := make([]clientv3.Op, len(ws))
		for i, w := range ws {
			body, err := json.Marshal(w.rec)
			if err != nil {
				return nil, err
			}
			put := clientv3.OpPut(w.key, string(body))
			if !w.rec.Until.IsZero() {
				id, err := s.ctxLeases.For(ctx, w.rec.Until)
				if err != nil {
					return nil, unavailable(err)
				}
				put = clientv3.OpPut(w.key, string(body), clientv3.WithLease(id))
			}
			ops[i] = clientv3.OpTxn([]clientv3.Cmp{unchanged(w.key, w.mod)}, []clientv3.Op{put}, nil)
		}
		resp, err := s.ctxKV.Txn(ctx).Then(ops...).Commit()
		if isLeaseLost(err) && attempt == 0 {
			s.ctxLeases.Reset()
			continue
		}
		if err != nil {
			return nil, unavailable(err)
		}
		var lost []string
		for i, r := range resp.Responses {
			if !r.GetResponseTxn().Succeeded {
				lost = append(lost, ws[i].key)
			}
		}
		return lost, nil
	}
}

// ledgerBatch is how many marks one transaction carries: etcd's default
// --max-txn-ops is 128, and chunked keeps to maxTxnOps.
const ledgerBatch = maxTxnOps
