package etcd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"

	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/rhwendt/port49/internal/store"
)

// refsUnder reads the lookup entries under fam/key and keeps each ref whose
// index record lists key live (Ruling 6), sorted as the memory store
// sorts them. A ref whose index record does not decode is kept unread,
// said and counted (undecodableIndex): a revocation then over-reaches onto
// that one ref, where the context's own record decides (one that is gone
// is ErrNotFound, and skipped), and every other ref is still answered.
// Failing the lookup instead would let one planted record turn a
// revocation of a principal into a revocation of nothing (Task 7 review
// I-1; pre-flight M18's aim, never a ref left out).
func (s *Store) refsUnder(ctx context.Context, fam, key string) ([]store.ContextRef, error) {
	if key == "" {
		return nil, nil
	}
	resp, err := s.ctx.Get(ctx, s.k.lookups(fam, key), clientv3.WithPrefix(), clientv3.WithKeysOnly())
	if err != nil {
		return nil, unavailable(err)
	}
	var refs []store.ContextRef
	var gets []clientv3.Op
	for _, kv := range resp.Kvs {
		// An entry that does not parse is an error, never skipped: a
		// revocation that skipped it would miss a context, which is
		// revocation failing open (pre-flight M18). It names no ref to keep.
		nas, user, ok := lastTwo(string(kv.Key))
		if !ok {
			return nil, fmt.Errorf("etcd: lookup entry %q does not parse", kv.Key)
		}
		r := store.ContextRef{NAS: nas, Username: user}
		refs = append(refs, r)
		gets = append(gets, clientv3.OpGet(s.k.indexed(r)))
	}
	now := s.now()
	var out []store.ContextRef
	i := 0
	if err := chunked(ctx, s.ctx, gets, func(t *clientv3.TxnResponse) {
		for _, op := range t.Responses {
			r := refs[i]
			i++
			for _, kv := range op.GetResponseRange().Kvs {
				var x idxRec
				if err := json.Unmarshal(kv.Value, &x); err != nil {
					s.undecodableIndex(kv.Key, "a lookup takes its ref unread")
					out = append(out, r)
					continue
				}
				if x.lists(fam, key, now) {
					out = append(out, r)
				}
			}
		}
	}); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].NAS+"\x00"+out[i].Username < out[j].NAS+"\x00"+out[j].Username
	})
	return out, nil
}

func (s *Store) ContextsByPrincipal(ctx context.Context, principal string) ([]store.ContextRef, error) {
	return s.refsUnder(ctx, famByPrincipal, principal)
}

func (s *Store) ContextsBySid(ctx context.Context, sid string) ([]store.ContextRef, error) {
	return s.refsUnder(ctx, famBySid, sid)
}

func (s *Store) ContextsByCert(ctx context.Context, certKey string) ([]store.ContextRef, error) {
	if store.BlankCertKey(certKey) {
		return nil, nil
	}
	return s.refsUnder(ctx, famByCert, certKey)
}

// eachIndexed calls f on every index record that decodes, a page at a
// time. One that does not is skipped, said and counted (undecodableIndex):
// it names no principal to refresh and no entry to prune, and failing the
// walk on it would stop the refresh for every principal and the sweep for
// every record (Task 7 review I-1). The context it hides is the
// re-index's to find (Task 7b).
func (s *Store) eachIndexed(ctx context.Context, f func(key string, mod int64, x idxRec)) error {
	prefix := s.k.family(famIndexed)
	end := clientv3.GetPrefixRangeEnd(prefix)
	from := prefix
	for {
		resp, err := s.ctx.Get(ctx, from, clientv3.WithRange(end), clientv3.WithLimit(500))
		if err != nil {
			return unavailable(err)
		}
		for _, kv := range resp.Kvs {
			var x idxRec
			if err := json.Unmarshal(kv.Value, &x); err != nil {
				s.undecodableIndex(kv.Key, "a walk of the index skips it")
				continue
			}
			f(string(kv.Key), kv.ModRevision, x)
		}
		if !resp.More || len(resp.Kvs) == 0 {
			return nil
		}
		from = string(resp.Kvs[len(resp.Kvs)-1].Key) + "\x00"
	}
}

// ActivePrincipals is every principal some index record lists live,
// sorted: one pass over the index records, no lookup entry read.
func (s *Store) ActivePrincipals(ctx context.Context) ([]string, error) {
	now := s.now()
	set := map[string]bool{}
	if err := s.eachIndexed(ctx, func(_ string, _ int64, x idxRec) {
		for _, e := range x.Principals {
			if e.ExpiresAt.After(now) {
				set[e.Key] = true
			}
		}
	}); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out, nil
}

// Sweep is the index's reclamation, which leases cannot do for it (Ruling
// 6). It runs in two passes:
//
//  1. Every index record drops its expired entries, and is deleted when
//     none is left.
//  2. Every lookup entry whose index record no longer lists its key at
//     all is deleted.
//
// Each change is compare-and-set against what was read, so a login
// listing a key between the read and the delete keeps its lookup entry.
// A lookup entry whose key is listed but expired is left for pass 1 of
// the next sweep: deleted any earlier, a restamp could list a key whose
// lookup is gone. pruned counts entries dropped, removed lookup entries
// deleted, each only by a write that landed. An index record that does not
// decode is never pruned, deleted, or a reason to delete a lookup entry
// naming it: it is skipped, said and counted, and the sweep goes on.
func (s *Store) Sweep(ctx context.Context) (pruned, removed int, err error) {
	now := s.now()
	type prune struct {
		key string
		mod int64
		x   idxRec
		n   int // entries dropped
	}
	var prunes []prune
	if err := s.eachIndexed(ctx, func(key string, mod int64, x idxRec) {
		before := len(x.Principals) + len(x.Sids) + len(x.Certs)
		keepLive := func(l []idxEntry) []idxEntry {
			var out []idxEntry
			for _, e := range l {
				if e.ExpiresAt.After(now) {
					out = append(out, e)
				}
			}
			return out
		}
		x.Principals, x.Sids, x.Certs = keepLive(x.Principals), keepLive(x.Sids), keepLive(x.Certs)
		if n := before - (len(x.Principals) + len(x.Sids) + len(x.Certs)); n > 0 {
			prunes = append(prunes, prune{key: key, mod: mod, x: x, n: n})
		}
	}); err != nil {
		return 0, 0, err
	}
	for _, p := range prunes {
		var puts []put
		var dels []del
		if p.x.empty() {
			dels = append(dels, del{key: p.key})
		} else {
			body, err := json.Marshal(p.x)
			if err != nil {
				return pruned, removed, err
			}
			puts = append(puts, put{key: p.key, val: body, exp: p.x.maxExp()})
		}
		done, err := commit(ctx, s.ctx, s.ctxLeases, []clientv3.Cmp{unchanged(p.key, p.mod)}, puts, dels...)
		if err != nil {
			return pruned, removed, err
		}
		if done { // one written since the read is the next sweep's
			pruned += p.n
		}
	}
	for _, fam := range []string{famByPrincipal, famBySid, famByCert} {
		n, err := s.sweepLookups(ctx, fam)
		removed += n
		if err != nil {
			return pruned, removed, err
		}
	}
	return pruned, removed, nil
}

// sweepLookups deletes fam's lookup entries whose index record does not
// list their key, each only while the entry and the record are as read.
// The index records a page names are read together, in transactions of
// gets (chunked), not one linearizable read per entry (pre-flight M25).
// An entry whose record does not decode is left: the sweep never deletes
// against a record it could not read.
func (s *Store) sweepLookups(ctx context.Context, fam string) (int, error) {
	prefix := s.k.family(fam)
	end := clientv3.GetPrefixRangeEnd(prefix)
	from := prefix
	removed := 0
	type entry struct {
		key, lookupKey, xk string
		mod                int64
	}
	type rec struct {
		x     idxRec
		mod   int64
		found bool
		bad   bool // present and undecodable
	}
	for {
		resp, err := s.ctx.Get(ctx, from, clientv3.WithRange(end), clientv3.WithLimit(500), clientv3.WithKeysOnly())
		if err != nil {
			return removed, unavailable(err)
		}
		var entries []entry
		var xks []string
		seen := map[string]bool{}
		for _, kv := range resp.Kvs {
			lookupKey, ref, ok := s.parseLookup(fam, string(kv.Key))
			if !ok {
				continue // not a lookup entry this sweep wrote; left alone
			}
			e := entry{key: string(kv.Key), lookupKey: lookupKey, xk: s.k.indexed(ref), mod: kv.ModRevision}
			entries = append(entries, e)
			if !seen[e.xk] {
				seen[e.xk] = true
				xks = append(xks, e.xk)
			}
		}
		gets := make([]clientv3.Op, len(xks))
		for i, xk := range xks {
			gets[i] = clientv3.OpGet(xk)
		}
		recs := map[string]rec{}
		i := 0
		if err := chunked(ctx, s.ctx, gets, func(t *clientv3.TxnResponse) {
			for _, op := range t.Responses {
				xk := xks[i]
				i++
				var r rec
				for _, kv := range op.GetResponseRange().Kvs {
					if err := json.Unmarshal(kv.Value, &r.x); err != nil {
						s.undecodableIndex(kv.Key, "the sweep leaves the lookup entries naming it")
						r.bad = true
					}
					r.mod, r.found = kv.ModRevision, true
				}
				recs[xk] = r
			}
		}); err != nil {
			return removed, err
		}
		for _, e := range entries {
			r := recs[e.xk]
			if r.bad || r.found && listed(r.x, fam, e.lookupKey) {
				continue
			}
			// The lookup entry's compare is the one that bites: a login
			// listing this key puts the entry again (addKeys), so it has
			// moved since the read. The record's is belt and braces; keep
			// both (Task 7 review m-3).
			done, err := commit(ctx, s.ctx, s.ctxLeases,
				[]clientv3.Cmp{unchanged(e.key, e.mod), unchanged(e.xk, r.mod)}, nil, del{key: e.key})
			if err != nil {
				return removed, err
			}
			if done {
				removed++
			}
		}
		if !resp.More || len(resp.Kvs) == 0 {
			return removed, nil
		}
		from = string(resp.Kvs[len(resp.Kvs)-1].Key) + "\x00"
	}
}

// listed reports whether x lists key under fam at all, live or not.
func listed(x idxRec, fam, key string) bool {
	for _, e := range *x.list(fam) {
		if e.Key == key {
			return true
		}
	}
	return false
}

// parseLookup splits a lookup entry's key into the indexed key and the
// ref.
func (s *Store) parseLookup(fam, key string) (string, store.ContextRef, bool) {
	rest := strings.TrimPrefix(key, s.k.family(fam))
	i := strings.IndexByte(rest, '/')
	if i < 0 {
		return "", store.ContextRef{}, false
	}
	indexed, err := url.PathUnescape(rest[:i])
	nas, user, ok := lastTwo(key)
	if err != nil || !ok {
		return "", store.ContextRef{}, false
	}
	return indexed, store.ContextRef{NAS: nas, Username: user}, true
}

// undecodableIndex says an index record that does not decode, by its key
// alone (its value is never logged, whatever a writer put there), and
// counts it (metrics.IndexRecordsUndecodable). Only a store writer makes
// one. Deleting the key is the operator's fix until Task 7b lets a login
// and the re-index write it whole again (Task 7 review K-2).
func (s *Store) undecodableIndex(key []byte, what string) {
	s.logf("etcd: index record %q does not decode; %s", key, what)
	if s.idxUndecodable != nil {
		s.idxUndecodable.Inc()
	}
}
