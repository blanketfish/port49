package etcd

import (
	"context"
	"encoding/json"
	"errors"
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
// telling waiting the holder's who every 30s, until ctx ends.
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
	sctx, scancel := context.WithCancel(context.Background())
	sess, err := concurrency.NewSession(s.ctx, concurrency.WithTTL(int(ttl/time.Second)), concurrency.WithContext(sctx))
	if err != nil {
		scancel()
		return nil, nil, unavailable(err)
	}
	quit := func() { sess.Close(); scancel() }
	mu := concurrency.NewMutex(sess, s.k.meta("hold"))
	var said time.Time
	for {
		err := mu.TryLock(ctx)
		if err == nil {
			break
		}
		if !errors.Is(err, concurrency.ErrLocked) {
			quit()
			return nil, nil, unavailable(err)
		}
		if time.Since(said) >= 30*time.Second {
			var h holderRec
			if _, _, err := getJSON(ctx, s.ctx, s.k.meta("holder"), &h); err == nil {
				waiting(h.Who)
			}
			said = time.Now()
		}
		select {
		case <-ctx.Done():
			quit()
			return nil, nil, ctx.Err()
		case <-time.After(time.Second):
		}
	}
	body, err := json.Marshal(holderRec{Who: who})
	if err != nil {
		quit()
		return nil, nil, err
	}
	if _, err := s.ctx.Put(ctx, s.k.meta("holder"), string(body), clientv3.WithLease(sess.Lease())); err != nil {
		quit()
		return nil, nil, unavailable(err)
	}
	lost := make(chan struct{})
	var once sync.Once
	lose := func() { once.Do(func() { close(lost) }) }
	fctx, stop := context.WithCancel(context.Background())
	go s.fence(fctx, sess, mu.Key(), ttl, lose)
	return lost, func() {
		stop()
		select {
		case <-lost:
			sess.Orphan()
		default:
			uctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			mu.Unlock(uctx)
			cancel()
			sess.Close()
		}
		scancel()
	}, nil
}

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
		resp, err := s.ctx.Get(rctx, key)
		var left *clientv3.LeaseTimeToLiveResponse
		if err == nil {
			left, err = s.ctx.TimeToLive(rctx, sess.Lease())
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
