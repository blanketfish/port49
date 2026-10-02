package etcd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/rhwendt/port49/internal/store"
)

// ctxSnap is one consistent read of a context, its ref's index record,
// and any marks a login compares: one transaction of gets, so all are as
// of one revision.
type ctxSnap struct {
	rec    ctxRec
	found  bool  // present and not past its expiry
	bad    error // present and undecodable: rec is empty (undecodable)
	mod    int64
	idx    idxRec
	idxMod int64
	// idxBad is an index record there that does not decode: idx is empty.
	// A login and an index write replace it whole, from what they index,
	// compared on idxMod, so it locks nobody out and the re-index can
	// repair it (Task 7 review K-2): that lifts no more than deleting it,
	// which the writer that garbled it could do as well. Every other write
	// that would carry it returns this; one that leaves it alone (a
	// revocation, any setter that does not extend) lands, compared on
	// idxMod (Task 7 review I-1).
	idxBad error
	marks  map[[2]string]markSnap
}

type markSnap struct {
	at  time.Time // zero: absent
	mod int64
}

func refOf(k store.ContextKey) store.ContextRef {
	return store.ContextRef{NAS: k.NAS, Username: k.Username}
}

// undecodable is a context record that is there and does not decode. It is
// unreadable, as one the sealing layer cannot open is
// (store.UnreadableContextError), so a login replaces it on its revision;
// a plain error on every read would lock the user out on that device until
// its lease ended (Task 6 review M-4). Its revocation is not known, so the
// replace keeps none: that lifts no more than deleting the record, which
// the writer that garbled it could do as well, and the marks a login
// compares still stand. The narrow setters refuse it with this error.
func undecodable(k store.ContextKey, mod int64, err error) error {
	return &store.UnreadableContextError{Rev: uint64(mod),
		Err: fmt.Errorf("etcd: context %v does not decode: %w", k, err)}
}

func (s *Store) readCtx(ctx context.Context, k store.ContextKey, marks ...[2]string) (ctxSnap, error) {
	ops := []clientv3.Op{clientv3.OpGet(s.k.context(k)), clientv3.OpGet(s.k.indexed(refOf(k)))}
	for _, m := range marks {
		ops = append(ops, clientv3.OpGet(s.k.mark(m[0], m[1])))
	}
	resp, err := s.ctx.Txn(ctx).Then(ops...).Commit()
	if err != nil {
		return ctxSnap{}, unavailable(err)
	}
	var snap ctxSnap
	if kvs := resp.Responses[0].GetResponseRange().Kvs; len(kvs) == 1 {
		snap.mod = kvs[0].ModRevision
		if err := json.Unmarshal(kvs[0].Value, &snap.rec); err != nil {
			snap.rec, snap.found, snap.bad = ctxRec{}, true, undecodable(k, snap.mod, err)
		} else {
			snap.found = snap.rec.ExpiresAt.After(s.now())
		}
	}
	if kvs := resp.Responses[1].GetResponseRange().Kvs; len(kvs) == 1 {
		if err := json.Unmarshal(kvs[0].Value, &snap.idx); err != nil {
			snap.idx, snap.idxBad = idxRec{}, fmt.Errorf("etcd: index record of %v does not decode: %w", k, err)
		}
		snap.idxMod = kvs[0].ModRevision
	}
	snap.marks = map[[2]string]markSnap{}
	for i, m := range marks {
		var ms markSnap
		if kvs := resp.Responses[2+i].GetResponseRange().Kvs; len(kvs) == 1 {
			var r markRec
			if err := json.Unmarshal(kvs[0].Value, &r); err != nil {
				return ctxSnap{}, fmt.Errorf("etcd: mark %v does not decode: %w", m, err)
			}
			ms = markSnap{at: r.At, mod: kvs[0].ModRevision}
		}
		snap.marks[m] = ms
	}
	return snap, nil
}

// commitCtx writes rec at k (nil: no context write) and idx as the ref's
// index record (nil: unchanged; empty: deleted), putting a lookup entry for
// each key in added, only while the context, the index record and every
// mark snap read are as read, reporting the revision it committed at. A
// context's lease follows its expiry; the index record's, its latest
// entry's.
func (s *Store) commitCtx(ctx context.Context, k store.ContextKey, snap ctxSnap, rec *ctxRec, idx *idxRec,
	added []string) (bool, int64, error) {
	ck, xk := s.k.context(k), s.k.indexed(refOf(k))
	cmps := []clientv3.Cmp{unchanged(ck, snap.mod), unchanged(xk, snap.idxMod)}
	for m, ms := range snap.marks {
		cmps = append(cmps, unchanged(s.k.mark(m[0], m[1]), ms.mod))
	}
	var puts []put
	var dels []del
	if rec != nil {
		body, err := json.Marshal(rec)
		if err != nil {
			return false, 0, err
		}
		puts = append(puts, put{key: ck, val: body, exp: rec.ExpiresAt})
	}
	if idx != nil {
		if idx.empty() {
			dels = append(dels, del{key: xk})
		} else {
			body, err := json.Marshal(idx)
			if err != nil {
				return false, 0, err
			}
			puts = append(puts, put{key: xk, val: body, exp: idx.maxExp()})
		}
	}
	for _, key := range added {
		puts = append(puts, put{key: key, val: []byte("{}")}) // no lease: the index record decides (Ruling 6)
	}
	return commitRev(ctx, s.ctx, s.ctxLeases, cmps, puts, dels...)
}

// seenCache is the plaintext bookkeeping of the last version GetContext
// read at each context key: its mod_revision and its record. RewriteContext
// takes it instead of reading again when it is asked to rewrite exactly
// that version with no ttl, so the sealing layer's narrow setter is two
// RPCs, its read and its transaction (re-check MA3). The transaction still
// compares the key's mod_revision, so a stale entry is a conflict, never a
// lost write. It holds at most seenMax entries and forgets them all past
// that: the cost of forgetting is one read.
type seenCache struct {
	mu sync.Mutex
	m  map[string]seenRec
}

type seenRec struct {
	mod int64
	rec ctxRec
}

const seenMax = 4096

func (c *seenCache) put(key string, mod int64, r ctxRec) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil || len(c.m) >= seenMax {
		c.m = map[string]seenRec{}
	}
	c.m[key] = seenRec{mod: mod, rec: r}
}

// take is the entry for key at mod, removed either way.
func (c *seenCache) take(key string, mod int64) (ctxRec, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[key]
	delete(c.m, key)
	return e.rec, ok && e.mod == mod
}

// GetContext reads the context alone: its revisions are its key's.
func (s *Store) GetContext(ctx context.Context, k store.ContextKey) (store.Context, error) {
	resp, err := s.ctx.Get(ctx, s.k.context(k))
	if err != nil {
		return store.Context{}, unavailable(err)
	}
	if len(resp.Kvs) == 0 {
		return store.Context{}, store.ErrNotFound
	}
	var r ctxRec
	mod := resp.Kvs[0].ModRevision
	if err := json.Unmarshal(resp.Kvs[0].Value, &r); err != nil {
		return store.Context{}, undecodable(k, mod, err)
	}
	if !r.ExpiresAt.After(s.now()) {
		return store.Context{}, store.ErrNotFound
	}
	s.seen.put(s.k.context(k), mod, r)
	return r.context(mod), nil
}

// whole is c as a whole-record write at now for ttl: stamped, and moving
// both revisions (a join, a replace and a seeding put all do).
func whole(c store.Context, now time.Time, ttl time.Duration) ctxRec {
	r := ctxRecOf(c)
	r.LastTouchedAt, r.ExpiresAt, r.PolicyMoved = now, now.Add(ttl), true
	return r
}

// The context writes return the revision each committed at, so the
// sealing layer can order its own writes by the store's (crypt.Ledger).
var _ store.RevStore = (*Store)(nil)

// PutContext writes c unconditionally, extending the ref's index entries
// with it (store.Store; no production path calls it).
func (s *Store) PutContext(ctx context.Context, k store.ContextKey, c store.Context, ttl time.Duration) error {
	_, err := s.PutContextRev(ctx, k, c, ttl)
	return err
}

// PutContextRev is PutContext, returning the revision it committed at:
// the context's Rev from then on (store.RevStore).
func (s *Store) PutContextRev(ctx context.Context, k store.ContextKey, c store.Context, ttl time.Duration) (uint64, error) {
	for {
		snap, err := s.readCtx(ctx, k)
		if err != nil {
			return 0, err
		}
		if snap.idxBad != nil {
			return 0, snap.idxBad
		}
		r := whole(c, s.now(), ttl)
		var idx *idxRec
		if snap.idxMod != 0 {
			x := snap.idx
			x.prune(s.now())
			x.restamp(r.ExpiresAt)
			idx = &x
		}
		if ok, mod, err := s.commitCtx(ctx, k, snap, &r, idx, nil); err != nil || ok {
			return uint64(mod), err
		}
	}
}

// SwapContext is SwapLogin with no index change and no mark.
func (s *Store) SwapContext(ctx context.Context, k store.ContextKey, rev uint64, c store.Context, ttl time.Duration) error {
	return s.SwapLogin(ctx, k, rev, c, ttl, store.LoginWrite{})
}

// SwapContextRev is SwapContext, returning the revision it committed at
// (PutContextRev).
func (s *Store) SwapContextRev(ctx context.Context, k store.ContextKey, rev uint64, c store.Context,
	ttl time.Duration) (uint64, error) {
	return s.SwapLoginRev(ctx, k, rev, c, ttl, store.LoginWrite{})
}

// SwapLogin is the login's one step (store.Store; plan 7d Ruling 7): the
// context, the ref's index change and the mark check in one transaction
// that holds only while the context, the index record and each mark are
// as read. A lost race on the index record alone (an IndexContext between
// the read and the write) reads again here; anything that moves the
// context or a mark is ErrConflict, for JoinContext to decide again.
func (s *Store) SwapLogin(ctx context.Context, k store.ContextKey, rev uint64, c store.Context, ttl time.Duration,
	w store.LoginWrite) error {
	_, err := s.SwapLoginRev(ctx, k, rev, c, ttl, w)
	return err
}

// SwapLoginRev is SwapLogin, returning the revision it committed at
// (PutContextRev).
func (s *Store) SwapLoginRev(ctx context.Context, k store.ContextKey, rev uint64, c store.Context, ttl time.Duration,
	w store.LoginWrite) (uint64, error) {
	marks := make([][2]string, 0, len(w.Marks))
	for _, m := range w.Marks {
		marks = append(marks, [2]string{m.Kind, m.Key})
	}
	ref := refOf(k)
	for {
		snap, err := s.readCtx(ctx, k, marks...)
		if err != nil {
			return 0, err
		}
		if snap.found && uint64(snap.mod) != rev || !snap.found && rev != 0 {
			return 0, store.ErrConflict
		}
		for _, m := range w.Marks {
			if !snap.marks[[2]string{m.Kind, m.Key}].at.Equal(m.At) {
				return 0, store.ErrConflict
			}
		}
		if snap.idxBad != nil {
			s.undecodableIndex([]byte(s.k.indexed(ref)), "a login writes it whole again")
		}
		now := s.now()
		r := whole(c, now, ttl)
		x := snap.idx
		touched := snap.idxMod != 0
		x.prune(now)
		x.restamp(r.ExpiresAt)
		if w.ClearRef {
			x = idxRec{}
		}
		if w.DropSid != "" {
			x.drop(famBySid, w.DropSid)
		}
		if w.DropCertKey != "" && !store.BlankCertKey(w.DropCertKey) {
			x.drop(famByCert, w.DropCertKey)
		}
		added := s.addKeys(&x, ref, w.Principal, w.Sid, w.CertKey, now.Add(w.IndexTTL))
		var idx *idxRec
		if touched || len(added) > 0 {
			idx = &x
		}
		if ok, mod, err := s.commitCtx(ctx, k, snap, &r, idx, added); err != nil || ok {
			return uint64(mod), err
		}
	}
}

// RewriteContext writes c's fields over the record at k only while its
// mod_revision is rev (store.Store; Task 4b): the sealing layer's narrow
// setter. No live record is ErrNotFound; one written since is ErrConflict,
// for the caller to read again. The expiry and LastTouchedAt stay the
// record's own unless ttl is set, which extends both and the ref's index
// entries as TouchContext does; PolicyRev moves to this write's revision
// only when policyMoved.
func (s *Store) RewriteContext(ctx context.Context, k store.ContextKey, rev uint64, c store.Context, ttl time.Duration,
	policyMoved bool) error {
	_, err := s.RewriteContextRev(ctx, k, rev, c, ttl, policyMoved)
	return err
}

// RewriteContextRev is RewriteContext, returning the revision it committed
// at (PutContextRev).
func (s *Store) RewriteContextRev(ctx context.Context, k store.ContextKey, rev uint64, c store.Context,
	ttl time.Duration, policyMoved bool) (uint64, error) {
	if r0, ok := s.seen.take(s.k.context(k), int64(rev)); ok && ttl == 0 {
		if !r0.ExpiresAt.After(s.now()) {
			return 0, store.ErrNotFound
		}
		r := ctxRecOf(c)
		r.ExpiresAt, r.LastTouchedAt = r0.ExpiresAt, r0.LastTouchedAt
		r.PolicyRev, r.PolicyMoved = r0.policyRev(int64(rev)), policyMoved
		body, err := json.Marshal(r)
		if err != nil {
			return 0, err
		}
		ck := s.k.context(k)
		ok, mod, err := commitRev(ctx, s.ctx, s.ctxLeases, []clientv3.Cmp{unchanged(ck, int64(rev))},
			[]put{{key: ck, val: body, exp: r.ExpiresAt}})
		switch {
		case err != nil:
			return 0, err
		case !ok:
			return 0, store.ErrConflict // moved, or gone, since the read: the caller reads again
		}
		return uint64(mod), nil
	}
	snap, err := s.readCtx(ctx, k)
	if err != nil {
		return 0, err
	}
	if !snap.found {
		return 0, store.ErrNotFound
	}
	if snap.bad != nil {
		return 0, snap.bad
	}
	if uint64(snap.mod) != rev {
		return 0, store.ErrConflict
	}
	r := ctxRecOf(c)
	r.ExpiresAt, r.LastTouchedAt = snap.rec.ExpiresAt, snap.rec.LastTouchedAt
	r.PolicyRev, r.PolicyMoved = snap.rec.policyRev(snap.mod), policyMoved
	var idx *idxRec
	if ttl > 0 {
		if snap.idxBad != nil {
			return 0, snap.idxBad
		}
		now := s.now()
		r.ExpiresAt, r.LastTouchedAt = now.Add(ttl), now
		if snap.idxMod != 0 {
			x := snap.idx
			x.prune(now)
			x.restamp(r.ExpiresAt)
			idx = &x
		}
	}
	ok, mod, err := s.commitCtx(ctx, k, snap, &r, idx, nil)
	if err != nil {
		return 0, err
	}
	if !ok {
		return 0, store.ErrConflict // the context or its index record moved since the read
	}
	return uint64(mod), nil
}

// addKeys lists ref under each non-empty key until exp (a blank
// certificate key is no key: store.BlankCertKey) and returns the lookup
// entries to put with it.
func (s *Store) addKeys(x *idxRec, ref store.ContextRef, principal, sid, certKey string, exp time.Time) []string {
	if store.BlankCertKey(certKey) {
		certKey = ""
	}
	var added []string
	for _, a := range []struct{ fam, key string }{{famByPrincipal, principal}, {famBySid, sid}, {famByCert, certKey}} {
		if a.key == "" {
			continue
		}
		x.add(a.fam, a.key, exp)
		added = append(added, s.k.lookup(a.fam, a.key, ref))
	}
	return added
}

// mutate is every narrow setter's read-change-write: f changes the live
// record, returning extend to carry the ref's index entries out to the
// record's new expiry; the write lands only if neither moved since the
// read, else it reads again. A read that fails returns at once, with the
// read's error: only a lost race loops, and that is bounded by the
// caller's deadline (pre-flight M23). Before f runs, a PolicyMoved left by
// the last write is resolved into policy_rev, so r.PolicyRev is the
// context's PolicyRev and f marks its own policy write by setting
// PolicyMoved.
func (s *Store) mutate(ctx context.Context, k store.ContextKey,
	f func(r *ctxRec, rev int64, now time.Time) (extend bool, err error)) error {
	for {
		snap, err := s.readCtx(ctx, k)
		if err != nil {
			return err
		}
		if !snap.found {
			return store.ErrNotFound
		}
		if snap.bad != nil {
			return snap.bad
		}
		r := snap.rec
		if r.PolicyMoved {
			r.PolicyRev, r.PolicyMoved = snap.mod, false
		}
		extend, err := f(&r, snap.mod, s.now())
		if err != nil {
			return err
		}
		if extend && snap.idxBad != nil {
			return snap.idxBad
		}
		var idx *idxRec
		if extend && snap.idxMod != 0 {
			x := snap.idx
			x.prune(s.now())
			x.restamp(r.ExpiresAt)
			idx = &x
		}
		if ok, _, err := s.commitCtx(ctx, k, snap, &r, idx, nil); err != nil || ok {
			return err
		}
	}
}

// TouchContext writes the expiry and LastTouchedAt, and nothing else
// (store.Store).
func (s *Store) TouchContext(ctx context.Context, k store.ContextKey, ttl time.Duration) error {
	return s.mutate(ctx, k, func(r *ctxRec, _ int64, now time.Time) (bool, error) {
		r.ExpiresAt, r.LastTouchedAt = now.Add(ttl), now
		return true, nil
	})
}

// applyTo runs one of the store's rules (store.Apply*, Task 4b) on the
// record as a store.Context and keeps what the rule changed: the rules are
// one definition for every backend and the sealing layer. The record's
// bookkeeping (its expiry and its policy revision) is mutate's, and stays.
func applyTo(r *ctxRec, rev int64, f func(c *store.Context) (bool, error)) (bool, error) {
	c := r.context(rev)
	moved, err := f(&c)
	if err != nil {
		return false, err
	}
	next := ctxRecOf(c)
	next.ExpiresAt, next.PolicyRev, next.PolicyMoved = r.ExpiresAt, r.PolicyRev, r.PolicyMoved
	*r = next
	return moved, nil
}

// SetPrivilege is store.ApplyPrivilege's rule; a level that moved is a
// policy write.
func (s *Store) SetPrivilege(ctx context.Context, k store.ContextKey, level uint8) error {
	return s.mutate(ctx, k, func(r *ctxRec, rev int64, _ time.Time) (bool, error) {
		moved, _ := applyTo(r, rev, func(c *store.Context) (bool, error) { return store.ApplyPrivilege(c, level), nil })
		r.PolicyMoved = moved
		return false, nil
	})
}

// AnnotateContext adds a discriminator and sets the state; neither the
// expiry nor LastTouchedAt moves (spec §5.8).
func (s *Store) AnnotateContext(ctx context.Context, k store.ContextKey, discHash, state string) error {
	return s.mutate(ctx, k, func(r *ctxRec, _ int64, _ time.Time) (bool, error) {
		if discHash != "" {
			r.SessionDiscriminators = addDiscriminator(r.SessionDiscriminators, discHash)
		}
		if state != "" {
			r.AccountingState = state
		}
		return false, nil
	})
}

// addDiscriminator is the memory store's, copied: a set capped at
// store.MaxSessionDiscriminators, oldest evicted, never edited in place.
func addDiscriminator(set []string, h string) []string {
	for _, existing := range set {
		if existing == h {
			return set
		}
	}
	out := make([]string, 0, store.MaxSessionDiscriminators)
	if len(set) >= store.MaxSessionDiscriminators {
		set = set[len(set)-store.MaxSessionDiscriminators+1:]
	}
	out = append(out, set...)
	return append(out, h)
}

// RefreshContext is store.ApplyRefresh's rule, ExpectRev compared with the
// revision this write will compare, and the record extended.
func (s *Store) RefreshContext(ctx context.Context, k store.ContextKey, rf store.ContextRefresh, ttl time.Duration) error {
	return s.mutate(ctx, k, func(r *ctxRec, rev int64, now time.Time) (bool, error) {
		if rf.ExpectRev != 0 && uint64(rev) != rf.ExpectRev {
			return false, store.ErrConflict
		}
		moved, err := applyTo(r, rev, func(c *store.Context) (bool, error) { return store.ApplyRefresh(c, rf) })
		if err != nil {
			return false, err
		}
		r.PolicyMoved = moved
		r.ExpiresAt, r.LastTouchedAt = now.Add(ttl), now
		return true, nil
	})
}

// SetRevokedAt is store.ApplyRevokedAt's rule, a policy write; it moves
// neither the expiry nor LastTouchedAt.
func (s *Store) SetRevokedAt(ctx context.Context, k store.ContextKey, at time.Time) error {
	return s.mutate(ctx, k, func(r *ctxRec, rev int64, _ time.Time) (bool, error) {
		applyTo(r, rev, func(c *store.Context) (bool, error) { store.ApplyRevokedAt(c, at); return true, nil })
		r.PolicyMoved = true
		return false, nil
	})
}

// SetContextPolicy is store.ApplyContextPolicy's rule, compared on the
// policy revision of the record this write compares.
func (s *Store) SetContextPolicy(ctx context.Context, k store.ContextKey, policyRev uint64, p store.ContextPolicy) error {
	if err := store.CheckContextPolicy(p); err != nil {
		return err
	}
	return s.mutate(ctx, k, func(r *ctxRec, rev int64, _ time.Time) (bool, error) {
		if uint64(r.PolicyRev) != policyRev {
			return false, store.ErrConflict
		}
		applyTo(r, rev, func(c *store.Context) (bool, error) { store.ApplyContextPolicy(c, p); return true, nil })
		r.PolicyMoved = true
		return false, nil
	})
}

// DeleteContext deletes the context alone, as the memory store's does.
func (s *Store) DeleteContext(ctx context.Context, k store.ContextKey) error {
	_, err := s.ctx.Delete(ctx, s.k.context(k))
	return unavailable(err)
}

// DeleteContextIf deletes the context only while its Rev is rev. One that
// does not decode is there at the Rev its UnreadableContextError carries,
// and is deleted on it as any other is (undecodable).
func (s *Store) DeleteContextIf(ctx context.Context, k store.ContextKey, rev uint64) error {
	ck := s.k.context(k)
	for {
		resp, err := s.ctx.Get(ctx, ck)
		if err != nil {
			return unavailable(err)
		}
		if len(resp.Kvs) == 0 {
			return store.ErrNotFound
		}
		var r ctxRec
		mod := resp.Kvs[0].ModRevision
		if json.Unmarshal(resp.Kvs[0].Value, &r) == nil && !r.ExpiresAt.After(s.now()) {
			return store.ErrNotFound
		}
		if uint64(mod) != rev {
			return store.ErrConflict
		}
		if done, err := commit(ctx, s.ctx, s.ctxLeases, []clientv3.Cmp{unchanged(ck, mod)}, nil, del{key: ck}); err != nil || done {
			return err
		}
	}
}

// PutBlob writes body, keeping the later of the existing and the new
// expiry. It is on the token pool, and GetBlob and BumpBlob on the context
// pool, on purpose: the broker's mint is what writes a blob, and the
// commands it authorizes and the refresh are what read and extend one, so
// each rides the pool of the path that calls it (design §12). The pools
// are one cluster, so a blob put on one is read on the other.
func (s *Store) PutBlob(ctx context.Context, hash string, body []byte, ttl time.Duration) error {
	exp := s.now().Add(ttl)
	return cas(ctx, s.tok, s.tokLeases, s.k.blob(hash), func(b blobRec) bool { return b.ExpiresAt.After(s.now()) },
		func(b *blobRec, found bool) (bool, time.Time, bool, error) {
			if found && b.ExpiresAt.After(exp) {
				exp = b.ExpiresAt
			}
			b.Body, b.ExpiresAt = bytes.Clone(body), exp
			return true, exp, false, nil
		})
}

// GetBlob is the blob's body until its expiry.
func (s *Store) GetBlob(ctx context.Context, hash string) ([]byte, error) {
	var b blobRec
	_, ok, err := getJSON(ctx, s.ctx, s.k.blob(hash), &b)
	if err != nil {
		return nil, err
	}
	if !ok || !b.ExpiresAt.After(s.now()) {
		return nil, store.ErrNotFound
	}
	return b.Body, nil
}

// BumpBlob extends a live blob to at least now+ttl, never shortening it.
func (s *Store) BumpBlob(ctx context.Context, hash string, ttl time.Duration) error {
	return cas(ctx, s.ctx, s.ctxLeases, s.k.blob(hash), func(b blobRec) bool { return b.ExpiresAt.After(s.now()) },
		func(b *blobRec, found bool) (bool, time.Time, bool, error) {
			if !found {
				return false, time.Time{}, false, store.ErrNotFound
			}
			exp := s.now().Add(ttl)
			if !exp.After(b.ExpiresAt) {
				return false, time.Time{}, false, nil
			}
			b.ExpiresAt = exp
			return true, exp, false, nil
		})
}

// indexOp is a write to the ref's index record alone: f changes it and
// returns the lookup entries to put with it.
func (s *Store) indexOp(ctx context.Context, ref store.ContextRef, f func(x *idxRec, now time.Time) []string) error {
	k := store.ContextKey{NAS: ref.NAS, Username: ref.Username}
	for {
		snap, err := s.readCtx(ctx, k)
		if err != nil {
			return err
		}
		if snap.idxBad != nil {
			s.undecodableIndex([]byte(s.k.indexed(ref)), "an index write writes it whole again")
		}
		x := snap.idx
		x.prune(s.now())
		added := f(&x, s.now())
		if snap.idxMod == 0 && x.empty() {
			return nil
		}
		// Only the index record is compared: an index write and the
		// context's own land in either order, as the memory store's
		// separate calls do.
		if ok, err := s.commitIndex(ctx, k, snap, &x, added); err != nil || ok {
			return err
		}
	}
}

// commitIndex is commitCtx comparing the index record alone.
func (s *Store) commitIndex(ctx context.Context, k store.ContextKey, snap ctxSnap, idx *idxRec, added []string) (bool, error) {
	xk := s.k.indexed(refOf(k))
	var puts []put
	var dels []del
	if idx.empty() {
		dels = append(dels, del{key: xk})
	} else {
		body, err := json.Marshal(idx)
		if err != nil {
			return false, err
		}
		puts = append(puts, put{key: xk, val: body, exp: idx.maxExp()})
	}
	for _, key := range added {
		puts = append(puts, put{key: key, val: []byte("{}")})
	}
	return commit(ctx, s.ctx, s.ctxLeases, []clientv3.Cmp{unchanged(xk, snap.idxMod)}, puts, dels...)
}

// IndexContext lists ref under each non-empty key for ttl.
func (s *Store) IndexContext(ctx context.Context, principal, sid, certKey string, ref store.ContextRef, ttl time.Duration) error {
	return s.indexOp(ctx, ref, func(x *idxRec, now time.Time) []string {
		return s.addKeys(x, ref, principal, sid, certKey, now.Add(ttl))
	})
}

// UnindexContext unlists ref from each key named; a blank certificate key
// was never listed.
func (s *Store) UnindexContext(ctx context.Context, principal, sid, certKey string, ref store.ContextRef) error {
	return s.indexOp(ctx, ref, func(x *idxRec, _ time.Time) []string {
		if principal != "" {
			x.drop(famByPrincipal, principal)
		}
		if sid != "" {
			x.drop(famBySid, sid)
		}
		if certKey != "" && !store.BlankCertKey(certKey) {
			x.drop(famByCert, certKey)
		}
		return nil
	})
}

// UnindexRef unlists ref from every key: its index record goes. The lookup
// entries it leaves name a record that lists nothing, so they answer
// nothing, and the sweep removes them (Ruling 6).
func (s *Store) UnindexRef(ctx context.Context, ref store.ContextRef) error {
	_, err := s.ctx.Delete(ctx, s.k.indexed(ref))
	return unavailable(err)
}

// ReindexSid moves ref from oldSid to newSid for ttl.
func (s *Store) ReindexSid(ctx context.Context, oldSid, newSid string, ref store.ContextRef, ttl time.Duration) error {
	return s.indexOp(ctx, ref, func(x *idxRec, now time.Time) []string {
		if oldSid != "" {
			x.drop(famBySid, oldSid)
		}
		if newSid == "" {
			return nil
		}
		x.add(famBySid, newSid, now.Add(ttl))
		return []string{s.k.lookup(famBySid, newSid, ref)}
	})
}
