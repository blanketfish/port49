package etcd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/client/v3/concurrency"
)

type holderRec struct {
	Who string `json:"who"`
}

// Hold takes the keyspace for one port49d (plan 7d, Ruling 11): a lock
// under meta/hold on an etcd session lease of ttl, with who written
// beside it under meta/holder. port49d takes it as the broker: the
// daemon's role cannot write meta/. While another holds it, Hold waits,
// telling waiting the holder's who every 30s, until ctx ends. Once it
// has the lock, it waits ttl/3 more before it returns.
//
// lost is closed when the hold is gone (pre-flight I15; re-check R-I4):
// the lock key deleted or on another lease, the lease expired, the
// session ended, or etcd not answering with half of ttl or less left on
// the lease as last reported. That is before etcd can expire the lease
// and let another port49d take the keyspace. The session's
// keepalive is its own, not ctx's, so a shutdown is not a loss. release
// lets go: it unlocks and revokes the lease, unless the hold was lost,
// when it does neither, since the store may not answer and the lease is
// gone or going (pre-flight M49).
func (s *Store) Hold(ctx context.Context, ttl time.Duration, who string, waiting func(holder string)) (<-chan struct{}, func(), error) {
	// The lease is granted under ctx and at most ttl/3, so a store that
	// hangs neither keeps a stopping port49d nor leaves a start silent: it
	// is unavailable, and the start says it is trying again (Task 12
	// review I-2). The session's keepalive is then off ctx.
	gctx, gcancel := context.WithTimeout(ctx, ttl/3)
	lease, err := s.ctx.Grant(gctx, int64(ttl/time.Second))
	gcancel()
	if err != nil {
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		return nil, nil, unavailable(err)
	}
	s.saw(lease.ResponseHeader.GetRevision())
	holdGranted()
	sctx, scancel := context.WithCancel(context.Background())
	sess, err := concurrency.NewSession(s.ctx, concurrency.WithTTL(int(ttl/time.Second)),
		concurrency.WithLease(lease.ID), concurrency.WithContext(sctx))
	if err != nil {
		scancel()
		rctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		if resp, err := s.ctx.Revoke(rctx, lease.ID); err == nil {
			s.saw(resp.Header.GetRevision())
		}
		cancel()
		return nil, nil, unavailable(err)
	}
	// letGo ends the session and revokes its lease, waiting a second at
	// most: sess.Close would wait out ttl on a hung store, and a lease not
	// revoked expires anyway (re-review m-6), which it says (re-review 2
	// m-7).
	letGo := func() {
		sess.Orphan()
		rctx, cancel := context.WithTimeout(context.Background(), time.Second)
		if resp, err := s.ctx.Revoke(rctx, lease.ID); err == nil {
			s.saw(resp.Header.GetRevision())
		} else {
			s.logf("etcd: letting go of %s: revoking its lease: %v; the lease was left to expire within "+
				"hold_ttl (%v), and the next port49d waits for it", s.k.meta("hold"), err, ttl)
		}
		cancel()
		scancel()
	}
	// Each call below is bounded as the Grant is (re-review m-6).
	bounded := func(f func(context.Context) error) error {
		cctx, cancel := context.WithTimeout(ctx, ttl/3)
		defer cancel()
		return f(cctx)
	}
	fail := func(err error) (<-chan struct{}, func(), error) {
		letGo()
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		return nil, nil, unavailable(err)
	}
	mu := concurrency.NewMutex(sess, s.k.meta("hold"))
	var said time.Time
	for {
		err := bounded(mu.TryLock)
		if err == nil {
			break
		}
		if !errors.Is(err, concurrency.ErrLocked) {
			return fail(err)
		}
		if time.Since(said) >= 30*time.Second {
			var h holderRec
			if bounded(func(c context.Context) error { _, _, err := getJSON(c, s.ctxKV, s.k.meta("holder"), &h); return err }) == nil {
				waiting(h.Who)
			}
			said = time.Now()
		}
		select {
		case <-ctx.Done():
			letGo()
			return nil, nil, ctx.Err()
		case <-time.After(time.Second):
		}
	}
	holdLocked()
	body, err := json.Marshal(holderRec{Who: who})
	if err != nil {
		letGo()
		return nil, nil, err
	}
	if err := bounded(func(c context.Context) error {
		_, err := s.ctxKV.Put(c, s.k.meta("holder"), string(body), clientv3.WithLease(sess.Lease()))
		return err
	}); err != nil {
		return fail(err)
	}
	lost := make(chan struct{})
	var once sync.Once
	lose := func() { once.Do(func() { close(lost) }) }
	fctx, stop := context.WithCancel(context.Background())
	go s.fence(fctx, sess, mu.Key(), ttl, lose)
	release := func() {
		stop()
		select {
		case <-lost:
			sess.Orphan()
		default:
			uctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			mu.Unlock(uctx)
			cancel()
			letGo()
		}
		scancel()
	}
	// A holder whose meta/hold was deleted sees it gone within ttl/3 (a
	// tick, then a read up to ttl/6), while this lock was free at once.
	// Waiting ttl/3 before serving keeps the two from serving at once
	// (Ruling T12-e). The fence runs through the wait.
	select {
	case <-ctx.Done():
		release()
		return nil, nil, ctx.Err()
	case <-lost:
	case <-time.After(ttl / 3):
	}
	return lost, release, nil
}

// holdGranted and holdLocked are told when Hold has its lease and when
// it has the lock: a test hangs the store there.
var holdGranted, holdLocked = func() {}, func() {}

// fence is the hold's watch (pre-flight I15; re-check R-I4). Every sixth
// of ttl it reads the lock key, linearizably, and the lease's remaining
// TTL. A key gone, or on a lease not this session's, is a hold lost at
// once: an operator deleted it, or the lease was reclaimed. A lease
// expired, or the session ending, is one too.
//
// expires is when the lease expires at the latest by the last answer:
// its send time plus the TTL it reported, which etcd counted after the
// send, so never later than etcd's own. An answered read is judged at
// its send time: the hold is lost when the TTL it reported is under half
// of ttl (the keepalives stalled while reads answer; re-check 2 M-B7),
// never by how long the read took, so a slow but healthy read keeps it
// (8b re-review R-M2). Under, not at: TTL is whole seconds rounded
// down, so a healthy lease at its lowest can report exactly ttl/2, and
// losing there would drop it (8b round 3b). With the reads not
// answering, it is lost once expires has half of ttl or less left.
// Reads are at most ttl/3 apart (a tick, then a read up to ttl/6 long).
// A read that kept the hold reported ttl/2 or more, and etcd's count is
// never below the reported one, so the lease had ttl/2 or more then;
// the next decision comes within ttl/3, with at least ttl/6 left. So
// the loss comes at least ttl/6 before etcd can expire the lease and a
// second port49d take the keyspace. Stamping at the send, and reading the TTL
// rather than counting from the last answer, is what keeps that margin:
// the lease's last keepalive can be up to ttl/3 older than the last
// answered read. A process paused past that is the residual: its next
// read finds the key gone.
func (s *Store) fence(ctx context.Context, sess *concurrency.Session, key string, ttl time.Duration, lose func()) {
	every := ttl / 6
	// The lock was just taken on this lease, which the session keeps alive
	// ttl/3 after each answer, checked every 500ms: about two thirds of ttl
	// is left, and as little as 2·ttl/3 − 0.5s − a round trip after a long
	// wait for the hold. Starting from two thirds is that much optimistic,
	// and only for the first read: if it fails, the loss still comes with
	// ttl/3 − 0.5s − a round trip left, at least ttl/6 within the round
	// trips a hold survives (8b re-review 4 C-2). The first answer replaces
	// it.
	expires := time.Now().Add(2 * ttl / 3)
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-sess.Done():
			lose()
			return
		case <-t.C:
		}
		sent := time.Now()
		rctx, cancel := context.WithTimeout(ctx, every)
		resp, err := s.ctxKV.Get(rctx, key)
		var left *clientv3.LeaseTimeToLiveResponse
		if err == nil {
			if left, err = s.ctx.TimeToLive(rctx, sess.Lease()); err == nil {
				s.saw(left.ResponseHeader.GetRevision())
			}
		}
		cancel()
		switch {
		case ctx.Err() != nil:
			return
		case err == nil && (len(resp.Kvs) == 0 || clientv3.LeaseID(resp.Kvs[0].Lease) != sess.Lease() || left.TTL <= 0):
			lose()
			return
		}
		var reported *int64
		if err == nil {
			reported = &left.TTL
		}
		var gone bool
		if gone, expires = judge(ttl, sent, reported, time.Now(), expires); gone {
			lose()
			return
		}
	}
}

// judge is the fence's keep-or-lose decision for one read, apart from the
// key and the lease's identity, so it is tested on its own (8b re-review 3
// R3-M1). An answered read (reported non-nil) is judged at its send: it
// loses when the TTL it reported is under half of ttl, whatever now is,
// and next is its send plus that TTL. A failed read loses once expires,
// the last answer's, has half of ttl or less left at now.
func judge(ttl time.Duration, sent time.Time, reported *int64, now, expires time.Time) (lose bool, next time.Time) {
	if reported != nil {
		left := time.Duration(*reported) * time.Second
		return left < ttl/2, sent.Add(left)
	}
	return expires.Sub(now) <= ttl/2, expires
}

// SealKeys is the encryption key window the last port49d on this keyspace
// started with: ids only, never key material (plan 7d, Ruling 14).
type SealKeys struct {
	Current   string    `json:"current"`
	Previous  string    `json:"previous,omitempty"`
	WrittenAt time.Time `json:"written_at"`
}

// ErrSealKeysUndecodable is a recorded window that does not decode. It is
// not an outage: a start says it and goes on (spec, a start on etcd, Keys).
var ErrSealKeysUndecodable = errors.New("etcd: the last start's key ids do not decode")

// SealKeys reads the window the last start recorded; false when none has.
func (s *Store) SealKeys(ctx context.Context) (SealKeys, bool, error) {
	var k SealKeys
	resp, err := s.ctxKV.Get(ctx, s.k.meta("seal_keys"))
	if err != nil {
		return SealKeys{}, false, unavailable(err)
	}
	if len(resp.Kvs) == 0 {
		return SealKeys{}, false, nil
	}
	if err := json.Unmarshal(resp.Kvs[0].Value, &k); err != nil {
		return SealKeys{}, false, ErrSealKeysUndecodable
	}
	return k, true, nil
}

// PutSealKeys records k as this start's window, over the last one.
func (s *Store) PutSealKeys(ctx context.Context, k SealKeys) error {
	body, err := json.Marshal(k)
	if err != nil {
		return err
	}
	_, err = s.ctxKV.Put(ctx, s.k.meta("seal_keys"), string(body))
	return unavailable(err)
}

// ClusterID is the etcd cluster's id, from a read's header (plan 11a, R28):
// two clients of one cluster read one id, whatever address each names.
func (s *Store) ClusterID(ctx context.Context) (uint64, error) {
	resp, err := s.tok.Get(ctx, s.k.meta("ping"), clientv3.WithKeysOnly())
	if err != nil {
		return 0, unavailable(err)
	}
	return resp.Header.ClusterId, nil
}

// maxJudgedPolicy is the most of a policy file meta/judged carries: under
// etcd's request limit (1.5 MiB by default) with room for the record.
const maxJudgedPolicy = 1 << 20

type judgedRec struct {
	Bundle    string    `json:"bundle"`
	Policy    []byte    `json:"policy,omitempty"`
	Omitted   bool      `json:"policy_omitted,omitempty"`
	InDoubt   bool      `json:"in_doubt,omitempty"`
	WrittenAt time.Time `json:"written_at"`
}

// JudgedRecord is meta/judged: the bundle a runner last judged every
// unspent token against (plan 7e, Ruling 7), and its policy file, for the
// reload guard at a start (Ruling 17). Policy is nil when the file was
// over maxJudgedPolicy. InDoubt is a record withdrawn while a replica
// served another bundle (JudgeInDoubt): the takeover purges as though
// there were none, and the guard at a start still judges against it.
type JudgedRecord struct {
	Bundle  string
	Policy  []byte
	InDoubt bool
}

// Judged reads meta/judged; ok is false when none was recorded. A record
// that does not decode is ok false too, said by its key alone: a takeover
// then purges, which fails closed.
func (s *Store) Judged(ctx context.Context) (JudgedRecord, bool, error) {
	key := s.k.meta("judged")
	resp, err := s.ctxKV.Get(ctx, key)
	if err != nil {
		return JudgedRecord{}, false, unavailable(err)
	}
	if len(resp.Kvs) == 0 {
		return JudgedRecord{}, false, nil
	}
	var r judgedRec
	if err := json.Unmarshal(resp.Kvs[0].Value, &r); err != nil {
		s.logf("etcd: %s does not decode; the takeover purges the unspent tokens", key)
		return JudgedRecord{}, false, nil
	}
	return JudgedRecord{Bundle: r.Bundle, Policy: r.Policy, InDoubt: r.InDoubt}, true, nil
}

// JudgedBundle reads meta/judged_bundle: the bundle's name alone, written
// with meta/judged so that port49d's gauge need not read the policy file
// in it. ok is false when none was recorded.
func (s *Store) JudgedBundle(ctx context.Context) (bundle string, ok bool, err error) {
	resp, err := s.ctxKV.Get(ctx, s.k.meta("judged_bundle"))
	if err != nil {
		return "", false, unavailable(err)
	}
	if len(resp.Kvs) == 0 {
		return "", false, nil
	}
	return string(resp.Kvs[0].Value), true, nil
}

func (s *Store) judgedBody(bundle string, policy []byte) (string, error) {
	r := judgedRec{Bundle: bundle, Policy: policy, WrittenAt: s.now().UTC()}
	if len(policy) > maxJudgedPolicy {
		r.Policy, r.Omitted = nil, true
	}
	body, err := json.Marshal(r)
	return string(body), err
}

// PutJudged records bundle as judged, with its policy file unless that is
// over maxJudgedPolicy, as the broker, whatever was written before it.
func (s *Store) PutJudged(ctx context.Context, bundle string, policy []byte) error {
	body, err := s.judgedBody(bundle, policy)
	if err != nil {
		return err
	}
	_, err = s.ctxKV.Txn(ctx).Then(clientv3.OpPut(s.k.meta("judged"), body),
		clientv3.OpPut(s.k.meta("judged_bundle"), bundle)).Commit()
	return unavailable(err)
}

// PutJudgedSince is PutJudged, written only while no replica's record
// and no meta/judged was written after rev, the revision BundlesAt read
// the records the runner judged at (Task 15a review I-1): a replica that
// started or swapped in between, or a mark in doubt, leaves the record
// as it is, and put is false. A record deleted since mints nothing more.
func (s *Store) PutJudgedSince(ctx context.Context, bundle string, policy []byte, rev uint64) (put bool, err error) {
	body, err := s.judgedBody(bundle, policy)
	if err != nil {
		return false, err
	}
	key := s.k.meta("judged")
	resp, err := s.ctxKV.Txn(ctx).If(
		clientv3.Compare(clientv3.ModRevision(s.k.meta("bundles/")), "<", int64(rev)+1).WithPrefix(),
		clientv3.Compare(clientv3.ModRevision(key), "<", int64(rev)+1),
	).Then(clientv3.OpPut(key, body), clientv3.OpPut(s.k.meta("judged_bundle"), bundle)).Commit()
	if err != nil {
		return false, unavailable(err)
	}
	return resp.Succeeded, nil
}

// JudgeInDoubt withdraws meta/judged while a replica serves another
// bundle (Task 15a review I-1): it marks the record in doubt, its bundle
// and policy kept for the guard at a start, so the next takeover purges.
// A record that names unless, when unless is not empty, is left clean: a
// replica that serves the bundle judged has nothing to withdraw, and the
// check is made in the same compare-and-swap as the mark (re-review 1,
// I-2). It reports the bundle recorded, and marked true only when this
// call marked it; no record, or one that does not decode, already purges
// and is left as it is.
func (s *Store) JudgeInDoubt(ctx context.Context, unless string) (bundle string, marked bool, err error) {
	key := s.k.meta("judged")
	for {
		resp, err := s.ctxKV.Get(ctx, key)
		if err != nil {
			return "", false, unavailable(err)
		}
		if len(resp.Kvs) == 0 {
			return "", false, nil
		}
		var r judgedRec
		if json.Unmarshal(resp.Kvs[0].Value, &r) != nil {
			return "", false, nil
		}
		if r.InDoubt || (unless != "" && r.Bundle == unless) {
			return r.Bundle, false, nil
		}
		r.InDoubt = true
		body, err := json.Marshal(r)
		if err != nil {
			return "", false, err
		}
		tr, err := s.ctxKV.Txn(ctx).If(clientv3.Compare(clientv3.ModRevision(key), "=", resp.Kvs[0].ModRevision)).
			Then(clientv3.OpPut(key, string(body))).Commit()
		if err != nil {
			return "", false, unavailable(err)
		}
		if tr.Succeeded {
			return r.Bundle, true, nil
		}
	}
}

// WitnessRead is meta/witness as one read found it (plan 7e, Ruling 18):
// the key's ModRevision, 0 when it is absent, and the revision etcd
// answered the read at. A restored key keeps its ModRevision, with or
// without --bump-revision; the header rises under the bump.
type WitnessRead struct {
	ModRevision uint64
	Header      uint64
}

// Witness reads meta/witness, as the broker.
func (s *Store) Witness(ctx context.Context) (WitnessRead, error) {
	resp, err := s.ctxKV.Get(ctx, s.k.meta("witness"))
	if err != nil {
		return WitnessRead{}, unavailable(err)
	}
	w := WitnessRead{Header: uint64(resp.Header.Revision)}
	if len(resp.Kvs) > 0 {
		w.ModRevision = uint64(resp.Kvs[0].ModRevision)
	}
	return w, nil
}

// PutWitness rewrites meta/witness, as the broker, if it is still at the
// ModRevision over (0: absent), and returns the revision it landed at, 0
// when another write got there first: two runners for a moment never
// write one over the other. It holds no secret: the runner's name and the
// time.
func (s *Store) PutWitness(ctx context.Context, who string, over uint64) (uint64, error) {
	key := s.k.meta("witness")
	body, err := json.Marshal(struct {
		Who string    `json:"who"`
		At  time.Time `json:"at"`
	}{who, s.now().UTC()})
	if err != nil {
		return 0, err
	}
	resp, err := s.ctxKV.Txn(ctx).If(clientv3.Compare(clientv3.ModRevision(key), "=", int64(over))).
		Then(clientv3.OpPut(key, string(body))).Commit()
	if err != nil {
		return 0, unavailable(err)
	}
	if !resp.Succeeded {
		return 0, nil
	}
	return uint64(resp.Header.Revision), nil
}

// PutPurged writes meta/purged, as the broker, once a runner's purge of
// every unspent token is done (Task 15d), if meta/witness is still at the
// ModRevision over (0: absent), the witness the purge read: a store
// restored since has another, and the write fails closed. It returns the
// revision it landed at, 0 when it was refused. A port49d that found the
// store restored serves redemptions again only on a meta/purged written
// after it found it. It holds no secret: the runner's name and the time.
func (s *Store) PutPurged(ctx context.Context, who string, over uint64) (uint64, error) {
	body, err := json.Marshal(struct {
		Who string    `json:"who"`
		At  time.Time `json:"at"`
	}{who, s.now().UTC()})
	if err != nil {
		return 0, err
	}
	resp, err := s.ctxKV.Txn(ctx).
		If(clientv3.Compare(clientv3.ModRevision(s.k.meta("witness")), "=", int64(over))).
		Then(clientv3.OpPut(s.k.meta("purged"), string(body))).Commit()
	if err != nil {
		return 0, unavailable(err)
	}
	if !resp.Succeeded {
		return 0, nil
	}
	return uint64(resp.Header.Revision), nil
}

// RestoreRead is meta/witness's and meta/purged's ModRevisions, 0 for one
// absent, and the revision etcd answered at, read at one revision (Task
// 15d).
type RestoreRead struct {
	Witness, Purged, Header uint64
}

// RestoreRead reads meta/witness and meta/purged in one transaction, as
// the daemon or the broker.
func (s *Store) RestoreRead(ctx context.Context) (RestoreRead, error) {
	resp, err := s.ctxKV.Txn(ctx).Then(clientv3.OpGet(s.k.meta("witness")), clientv3.OpGet(s.k.meta("purged"))).
		Commit()
	if err != nil {
		return RestoreRead{}, unavailable(err)
	}
	r := RestoreRead{Header: uint64(resp.Header.Revision)}
	at := func(i int) uint64 {
		if kvs := resp.Responses[i].GetResponseRange().GetKvs(); len(kvs) > 0 {
			return uint64(kvs[0].ModRevision)
		}
		return 0
	}
	r.Witness, r.Purged = at(0), at(1)
	return r, nil
}

// FollowWitness tells saw the ModRevision of meta/witness as it reads and
// watches it, until ctx ends (plan 7e, Ruling 18): one read, then a watch
// from the read's revision, and a read again a second after the watch
// ends (a compaction, or etcd gone). A lower revision than before, a
// restore's, is told too: saw keeps the highest.
func (s *Store) FollowWitness(ctx context.Context, saw func(uint64)) {
	key := s.k.meta("witness")
	for {
		if resp, err := s.ctxKV.Get(ctx, key); err == nil {
			if len(resp.Kvs) > 0 {
				saw(uint64(resp.Kvs[0].ModRevision))
			}
			wctx, cancel := context.WithCancel(clientv3.WithRequireLeader(ctx))
			for wr := range s.ctx.Watch(wctx, key, clientv3.WithRev(resp.Header.Revision+1)) {
				if wr.Err() != nil {
					break
				}
				for _, ev := range wr.Events {
					if ev.Type == clientv3.EventTypePut {
						saw(uint64(ev.Kv.ModRevision))
					}
				}
			}
			cancel()
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
}

// Holder reads meta/holder, the who of the replica holding the keyspace
// (Hold); false when none does.
func (s *Store) Holder(ctx context.Context) (string, bool, error) {
	var h holderRec
	_, ok, err := getJSON(ctx, s.ctxKV, s.k.meta("holder"), &h)
	return h.Who, ok, err
}

type bundleRec struct {
	Who       string    `json:"who"`
	Bundle    string    `json:"bundle"`
	At        time.Time `json:"at"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (r bundleRec) live(now time.Time) bool { return now.Before(r.ExpiresAt) }

// BundleRecord is meta/bundles/<who>: the bundle one port49-broker replica
// serves, written At and leased until ExpiresAt (plan 7e, Ruling 8;
// pre-flight I3), or meta/refresh_owed, a replica's ask for a full
// context pass, with no expiry.
type BundleRecord struct {
	Who, Bundle   string
	At, ExpiresAt time.Time
}

// PutBundle records bundle as the one who serves, until now + ttl; its
// lease is cas's bucket past that, and the expiry decides.
func (s *Store) PutBundle(ctx context.Context, who, bundle string, ttl time.Duration) error {
	now := s.now()
	live := func(r bundleRec) bool { return r.live(now) }
	return cas(ctx, s.ctxKV, s.ctxLeases, s.k.meta("bundles/")+esc(who), live,
		func(r *bundleRec, _ bool) (bool, time.Time, bool, error) {
			*r = bundleRec{Who: who, Bundle: bundle, At: now.UTC(), ExpiresAt: now.Add(ttl).UTC()}
			return true, r.ExpiresAt, false, nil
		})
}

// DeleteBundle deletes who's record, at its graceful stop (pre-flight
// 7e-2 P-5): a replica that stops mints nothing more.
func (s *Store) DeleteBundle(ctx context.Context, who string) error {
	_, err := s.ctxKV.Delete(ctx, s.k.meta("bundles/")+esc(who))
	return unavailable(err)
}

// Bundles is every replica's record whose ExpiresAt is after now, read at
// one revision a page at a time, as LedgerMarks reads. A lease only
// reclaims (leases.go), so a lapsed record can remain up to a minute and
// lease_grace past its ttl: it is skipped by its own expiry, as every
// leased record is. A record that does not decode is an error naming its
// key.
func (s *Store) Bundles(ctx context.Context) ([]BundleRecord, error) {
	recs, _, err := s.BundlesAt(ctx)
	return recs, err
}

// BundlesAt is Bundles, with the revision it read at, for PutJudgedSince.
func (s *Store) BundlesAt(ctx context.Context) ([]BundleRecord, uint64, error) {
	prefix := s.k.meta("bundles/")
	end := clientv3.GetPrefixRangeEnd(prefix)
	from, rev := prefix, int64(0)
	now := s.now()
	var out []BundleRecord
	for {
		opts := []clientv3.OpOption{clientv3.WithRange(end), clientv3.WithLimit(500)}
		if rev > 0 {
			opts = append(opts, clientv3.WithRev(rev))
		}
		resp, err := s.ctxKV.Get(ctx, from, opts...)
		if err != nil {
			return nil, 0, unavailable(err)
		}
		if rev == 0 {
			rev = resp.Header.Revision
		}
		for _, kv := range resp.Kvs {
			var r bundleRec
			if json.Unmarshal(kv.Value, &r) != nil {
				return nil, 0, notDecoded(fmt.Sprintf("bundle record %q", kv.Key))
			}
			if r.live(now) {
				out = append(out, BundleRecord{Who: r.Who, Bundle: r.Bundle, At: r.At, ExpiresAt: r.ExpiresAt})
			}
		}
		if !resp.More || len(resp.Kvs) == 0 {
			return out, uint64(rev), nil
		}
		from = string(resp.Kvs[len(resp.Kvs)-1].Key) + "\x00"
	}
}

// PutRefreshOwed records who's ask for a full context pass, made as it
// reloaded or started serving bundle: the runner carries every live
// context onto its policy, so a context made from who's token under
// another bundle is judged (pre-flight I3). A later ask replaces it.
func (s *Store) PutRefreshOwed(ctx context.Context, who, bundle string) error {
	body, err := json.Marshal(bundleRec{Who: who, Bundle: bundle, At: s.now().UTC()})
	if err != nil {
		return err
	}
	_, err = s.ctxKV.Put(ctx, s.k.meta("refresh_owed"), string(body))
	return unavailable(err)
}

// RefreshOwed reads the ask, with its mod revision for ClearRefreshOwed;
// ok is false when none is owed.
func (s *Store) RefreshOwed(ctx context.Context) (rev uint64, rec BundleRecord, ok bool, err error) {
	var r bundleRec
	mod, ok, err := getJSON(ctx, s.ctxKV, s.k.meta("refresh_owed"), &r)
	if !ok || err != nil {
		return 0, BundleRecord{}, false, err
	}
	return uint64(mod), BundleRecord{Who: r.Who, Bundle: r.Bundle, At: r.At}, true, nil
}

// ClearRefreshOwed deletes the ask only while its mod revision is still
// rev, the one the pass read: an ask written during the pass stays, owed.
func (s *Store) ClearRefreshOwed(ctx context.Context, rev uint64) error {
	key := s.k.meta("refresh_owed")
	_, err := s.ctxKV.Txn(ctx).If(clientv3.Compare(clientv3.ModRevision(key), "=", int64(rev))).
		Then(clientv3.OpDelete(key)).Commit()
	return unavailable(err)
}
