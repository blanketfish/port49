package etcd

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/rhwendt/port49/internal/store"
)

// A mark carries no lease: it never expires, and only DeleteRevocation
// lifts it (spec §13, decision 32).

// PutRevocation writes r unless a mark for its key already stands: the
// put is conditional on the key's absence, so a repeat never moves the
// first's time or origin, or its flag. Inside it, the mark is put flagged
// LandedAfterLift when the key's lift record (rl/) was written above the
// writer's floor for the key, W_k: the larger of ctx's floor (the marks
// feed's, store.WithMarkFloor) and this process's own last lift of the key
// (decision 51; final check F-I2). Both branches put the mark, so it always
// lands and the system fails closed; a lift record gone leaves the mark
// unflagged, as before. A copy the hedge sends again compares the same
// floor.
func (s *Store) PutRevocation(ctx context.Context, r store.Revocation) error {
	if err := store.CheckRevocation(r); err != nil {
		return err
	}
	body, err := json.Marshal(markRecOf(r))
	if err != nil {
		return err
	}
	flagged := r
	flagged.LandedAfterLift = true
	late, err := json.Marshal(markRecOf(flagged))
	if err != nil {
		return err
	}
	key, tomb := s.k.mark(r.Kind, r.Key), s.k.lift(r.Kind, r.Key)
	floor := max(store.MarkFloor(ctx), s.ownLifts.floor(r.Kind, r.Key, s.now()))
	_, err = s.tok.Txn(idempotent(ctx)).
		If(clientv3.Compare(clientv3.CreateRevision(key), "=", 0)).
		Then(clientv3.OpTxn(
			[]clientv3.Cmp{clientv3.Compare(clientv3.ModRevision(tomb), "<", int64(floor)+1)},
			[]clientv3.Op{clientv3.OpPut(key, string(body))},
			[]clientv3.Op{clientv3.OpPut(key, string(late))})).
		Commit()
	return unavailable(err)
}

func (s *Store) GetRevocation(ctx context.Context, kind, key string) (store.Revocation, error) {
	var r markRec
	_, ok, err := getJSON(ctx, s.tok, s.k.mark(kind, key), &r)
	if err != nil {
		return store.Revocation{}, err
	}
	if !ok {
		return store.Revocation{}, store.ErrNotFound
	}
	return r.revocation(), nil
}

// afterLiftRead runs between DeleteRevocation's read and its delete, for a
// test that makes the mark change there. A package variable: not safe for a
// test under t.Parallel.
var afterLiftRead func()

// DeleteRevocation lifts the mark it reads, and only that one: the delete is
// conditional on the mark's revision. A copy of a lift that a stalled
// connection delivers late (the hedge's, or a lift's that timed out) finds a
// mark made since under a new revision, and leaves it standing. A copy sent
// twice is harmless for the same reason.
//
// The same transaction writes the lift's record (rl/, by's time and origin)
// on a lease from the shared pool for LiftTTL, which a later put of the
// mark compares (PutRevocation). A lease that cannot be had lifts nothing:
// ErrUnavailable, which the broker says as "could not be lifted, and
// stands" (re-review R-I3). Once committed, the lift raises this process's
// floor for the key alone to its revision (ownLifts), so its own later
// revoke is not flagged; a copy answered by the else branch that finds
// by's own record counts too.
func (s *Store) DeleteRevocation(ctx context.Context, kind, key string, by store.Lift) error {
	k, tomb := s.k.mark(kind, key), s.k.lift(kind, key)
	resp, err := s.tok.Get(ctx, k)
	if err != nil {
		return unavailable(err)
	}
	if len(resp.Kvs) == 0 {
		return nil
	}
	if afterLiftRead != nil {
		afterLiftRead()
	}
	now := s.now()
	until := now.Add(store.LiftTTL)
	rec, err := json.Marshal(liftRec{At: by.At, Origin: by.Origin, Until: until})
	if err != nil {
		return err
	}
	for attempt := 0; ; attempt++ {
		lease, err := s.tokLeases.For(ctx, until)
		if err != nil {
			return unavailable(err)
		}
		tr, err := s.tok.Txn(idempotent(ctx)).
			If(clientv3.Compare(clientv3.ModRevision(k), "=", resp.Kvs[0].ModRevision)).
			Then(clientv3.OpDelete(k), clientv3.OpPut(tomb, string(rec), clientv3.WithLease(lease))).
			Else(clientv3.OpGet(k, clientv3.WithCountOnly()), clientv3.OpGet(tomb)).
			Commit()
		if isLeaseLost(err) && attempt == 0 {
			s.tokLeases.Reset()
			continue
		}
		if err != nil {
			return unavailable(err)
		}
		if tr.Succeeded {
			s.ownLifts.note(kind, key, uint64(tr.Header.Revision), now)
			return nil
		}
		if tr.Responses[0].GetResponseRange().Count != 0 {
			return fmt.Errorf("%w: the principal or certificate was revoked again while the lift ran", store.ErrConflict)
		}
		if kvs := tr.Responses[1].GetResponseRange().Kvs; len(kvs) == 1 {
			var got liftRec
			if json.Unmarshal(kvs[0].Value, &got) == nil && got.At.Equal(by.At) && got.Origin == by.Origin {
				s.ownLifts.note(kind, key, uint64(kvs[0].ModRevision), now)
			}
		}
		return nil
	}
}

// GetLift is the lift record of (kind, key) with the revision it was
// written at, or ErrNotFound: none, or past its Until on the store's clock.
func (s *Store) GetLift(ctx context.Context, kind, key string) (store.Lift, error) {
	var r liftRec
	mod, ok, err := getJSONAs(ctx, s.tok, s.k.lift(kind, key), "a lift's record", &r)
	if err != nil {
		return store.Lift{}, err
	}
	if !ok || !s.now().Before(r.Until) {
		return store.Lift{}, store.ErrNotFound
	}
	return store.Lift{At: r.At, Origin: r.Origin, Revision: uint64(mod)}, nil
}

// ownLifts is this process's own lifts (final check F-I2): by key, the
// revision its lift committed at and until when it counts. A lift read the
// mark linearizably and overwrote the key's lift record, so it supersedes
// every earlier lift of that key, and raises the floor for that key alone:
// a process-wide raise would hide another process's lift of another key
// that this process's feed has not delivered.
type ownLifts struct {
	mu sync.Mutex
	m  map[[2]string]ownLift
}

type ownLift struct {
	rev   uint64
	until time.Time
}

// note records a lift of (kind, key) at rev, made at now, for LiftTTL,
// dropping the entries past their time.
func (o *ownLifts) note(kind, key string, rev uint64, now time.Time) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.m == nil {
		o.m = map[[2]string]ownLift{}
	}
	for k, l := range o.m {
		if !now.Before(l.until) {
			delete(o.m, k)
		}
	}
	k := [2]string{kind, key}
	if cur, ok := o.m[k]; !ok || rev > cur.rev || !now.Before(cur.until) {
		o.m[k] = ownLift{rev: rev, until: now.Add(store.LiftTTL)}
	}
}

// floor is the revision of this process's own last lift of (kind, key),
// 0 when it made none within LiftTTL of now.
func (o *ownLifts) floor(kind, key string, now time.Time) uint64 {
	o.mu.Lock()
	defer o.mu.Unlock()
	if l, ok := o.m[[2]string{kind, key}]; ok && now.Before(l.until) {
		return l.rev
	}
	return 0
}

// ListRevocations is every mark, sorted by (Kind, Key) as stored, not as
// escaped, read a page at a time (pre-flight I14).
func (s *Store) ListRevocations(ctx context.Context) ([]store.Revocation, error) {
	prefix := s.k.family(famMark)
	end := clientv3.GetPrefixRangeEnd(prefix)
	from := prefix
	var out []store.Revocation
	for {
		resp, err := s.tok.Get(ctx, from, clientv3.WithRange(end), clientv3.WithLimit(500))
		if err != nil {
			return nil, unavailable(err)
		}
		for _, kv := range resp.Kvs {
			var r markRec
			if err := json.Unmarshal(kv.Value, &r); err != nil {
				return nil, notDecoded(fmt.Sprintf("mark %q", kv.Key))
			}
			out = append(out, r.revocation())
		}
		if !resp.More || len(resp.Kvs) == 0 {
			break
		}
		from = string(resp.Kvs[len(resp.Kvs)-1].Key) + "\x00"
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Key < out[j].Key
	})
	return out, nil
}
