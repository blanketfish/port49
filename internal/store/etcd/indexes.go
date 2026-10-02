package etcd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

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
// time. One that does not is said and counted (undecodableIndex), handed
// to bad when it is not nil, and otherwise skipped: failing the walk on it
// would stop the refresh for every principal and the sweep for every
// record (Task 7 review I-1). The context it hides is the re-index's to
// find (Task 7b).
func (s *Store) eachIndexed(ctx context.Context, f func(key string, mod int64, x idxRec), bad func(key string)) error {
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
				if bad != nil {
					bad(string(kv.Key))
				}
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
// sorted: one pass over the index records, and no lookup entry read while
// every record decodes. A record that does not decode never drops a
// principal from the refresh, since one left out keeps a policy that may
// be wider than the one in force: each principal with a lookup entry
// naming that record's ref is kept, live or not, read off the entry's own
// key (ip/<principal>/<nas>/<user>), so its refresh runs and its contexts'
// own records decide (Task 7 review I-1, as refined).
func (s *Store) ActivePrincipals(ctx context.Context) ([]string, error) {
	now := s.now()
	set := map[string]bool{}
	bad := map[string]bool{}
	if err := s.eachIndexed(ctx, func(_ string, _ int64, x idxRec) {
		for _, e := range x.Principals {
			if e.ExpiresAt.After(now) {
				set[e.Key] = true
			}
		}
	}, func(key string) { bad[key] = true }); err != nil {
		return nil, err
	}
	if len(bad) > 0 {
		if err := s.principalsNaming(ctx, bad, set); err != nil {
			return nil, err
		}
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out, nil
}

// principalsNaming adds to set the principal of every principal lookup
// entry whose ref's index record key is in xks, paging the family
// keys-only. An entry that does not parse names no principal, as the sweep
// treats it.
func (s *Store) principalsNaming(ctx context.Context, xks, set map[string]bool) error {
	prefix := s.k.family(famByPrincipal)
	end := clientv3.GetPrefixRangeEnd(prefix)
	from := prefix
	for {
		resp, err := s.ctx.Get(ctx, from, clientv3.WithRange(end), clientv3.WithLimit(500), clientv3.WithKeysOnly())
		if err != nil {
			return unavailable(err)
		}
		for _, kv := range resp.Kvs {
			if p, ref, ok := s.parseLookup(famByPrincipal, string(kv.Key)); ok && xks[s.k.indexed(ref)] {
				set[p] = true
			}
		}
		if !resp.More || len(resp.Kvs) == 0 {
			return nil
		}
		from = string(resp.Kvs[len(resp.Kvs)-1].Key) + "\x00"
	}
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
	}, nil); err != nil {
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

// Unindexed is the ref of every context, with the keys its index record
// lists live whose lookup entry is there (withLookups), for the broker's ReindexContexts to compare with the
// context's own (plan 7d; Ruling 6; re-check IA2 and I2). A login writes a
// context and its index record in one step and every extension carries
// both, so a live context whose record is gone, lists no live principal,
// or lists another principal than its own was hidden by a store write:
// from the refresh, which walks the index, and from a revocation by sid or
// by --mine. This store cannot open a context to read whose it is, so it
// names every one, and the re-index, reading through the sealing layer,
// decides. It pages the context family keys-only and reads each page's
// index records in batched transactions, as the sweep does. A context past
// its expiry and not yet reclaimed may be named; ReindexContexts reads it
// and finds nothing.
//
// An index record that does not decode lists nothing, so the re-index
// writes it whole again; it is said by its key alone and counted
// (undecodableIndex). A context key that does not parse names no ref, and
// is said and skipped. Neither stops the scan: one bad record must not
// stop the start or the re-index of every other (re-check I3; Task 7
// review K-2).
func (s *Store) Unindexed(ctx context.Context) ([]store.IndexedRef, error) {
	prefix := s.k.family(famContext)
	end := clientv3.GetPrefixRangeEnd(prefix)
	from := prefix
	now := s.now()
	var out []store.IndexedRef
	for {
		resp, err := s.ctx.Get(ctx, from, clientv3.WithRange(end), clientv3.WithLimit(500), clientv3.WithKeysOnly())
		if err != nil {
			return out, unavailable(err)
		}
		refs := make([]store.ContextRef, 0, len(resp.Kvs))
		gets := make([]clientv3.Op, 0, len(resp.Kvs))
		for _, kv := range resp.Kvs {
			nas, user, ok := lastTwo(string(kv.Key))
			if !ok || strings.Count(strings.TrimPrefix(string(kv.Key), prefix), "/") != 1 {
				s.logf("etcd: context key %q does not parse; the re-index skips it", kv.Key)
				continue
			}
			ref := store.ContextRef{NAS: nas, Username: user}
			refs = append(refs, ref)
			gets = append(gets, clientv3.OpGet(s.k.indexed(ref)))
		}
		page := make([]store.IndexedRef, 0, len(refs))
		i := 0
		if err := chunked(ctx, s.ctx, gets, func(t *clientv3.TxnResponse) {
			for _, op := range t.Responses {
				r := store.IndexedRef{ContextRef: refs[i]}
				i++
				for _, kv := range op.GetResponseRange().Kvs {
					var x idxRec
					if err := json.Unmarshal(kv.Value, &x); err != nil {
						s.undecodableIndex(kv.Key, "the re-index writes it whole again")
						continue
					}
					r.Principals, r.Sids, r.Certs = liveKeys(x.Principals, now), liveKeys(x.Sids, now),
						liveKeys(x.Certs, now)
				}
				page = append(page, r)
			}
		}); err != nil {
			return out, err
		}
		if err := s.withLookups(ctx, page); err != nil {
			return out, err
		}
		out = append(out, page...)
		if !resp.More || len(resp.Kvs) == 0 {
			return out, nil
		}
		from = string(resp.Kvs[len(resp.Kvs)-1].Key) + "\x00"
	}
}

// withLookups keeps in each of page's lists only the keys whose lookup
// entry is there, counted in batched transactions of count-only gets: a
// lookup is where a revocation and the refresh start (refsUnder), so a key
// listed whose entry a store write deleted is hidden as one not listed is,
// and the re-index, which puts the entries again (addKeys), must see it
// missing (Task 7b review I-2).
func (s *Store) withLookups(ctx context.Context, page []store.IndexedRef) error {
	type at struct {
		list *[]string
		key  string
	}
	var ats []at
	var gets []clientv3.Op
	for i := range page {
		r := &page[i]
		for _, l := range []struct {
			fam  string
			keys *[]string
		}{{famByPrincipal, &r.Principals}, {famBySid, &r.Sids}, {famByCert, &r.Certs}} {
			for _, key := range *l.keys {
				ats = append(ats, at{list: l.keys, key: key})
				gets = append(gets, clientv3.OpGet(s.k.lookup(l.fam, key, r.ContextRef), clientv3.WithCountOnly()))
			}
			*l.keys = nil
		}
	}
	i := 0
	return chunked(ctx, s.ctx, gets, func(t *clientv3.TxnResponse) {
		for _, op := range t.Responses {
			if op.GetResponseRange().Count > 0 {
				*ats[i].list = append(*ats[i].list, ats[i].key)
			}
			i++
		}
	})
}

// liveKeys is the key of every entry live at now.
func liveKeys(l []idxEntry, now time.Time) []string {
	var out []string
	for _, e := range l {
		if e.ExpiresAt.After(now) {
			out = append(out, e.Key)
		}
	}
	return out
}

// undecodableIndex says an index record that does not decode, by its key
// alone (its value is never logged, whatever a writer put there), and
// counts it (metrics.IndexRecordsUndecodable). Only a store writer makes
// one. A login and the re-index write it whole again, each compared on its
// revision (readCtx; Task 7 review K-2).
func (s *Store) undecodableIndex(key []byte, what string) {
	s.logf("etcd: index record %q does not decode; %s", key, what)
	if s.idxUndecodable != nil {
		s.idxUndecodable.Inc()
	}
}
