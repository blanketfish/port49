package etcd

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/rhwendt/port49/internal/store"
)

// A mark carries no lease: it never expires, and only DeleteRevocation
// lifts it (spec §13, decision 32).

// PutRevocation writes r unless a mark for its key already stands: the
// put is conditional on the key's absence, so a repeat never moves the
// first's time or origin.
func (s *Store) PutRevocation(ctx context.Context, r store.Revocation) error {
	if err := store.CheckRevocation(r); err != nil {
		return err
	}
	body, err := json.Marshal(markRecOf(r))
	if err != nil {
		return err
	}
	key := s.k.mark(r.Kind, r.Key)
	_, err = commit(idempotent(ctx), s.tok, s.tokLeases,
		[]clientv3.Cmp{clientv3.Compare(clientv3.CreateRevision(key), "=", 0)}, []put{{key: key, val: body}})
	return err
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
func (s *Store) DeleteRevocation(ctx context.Context, kind, key string) error {
	k := s.k.mark(kind, key)
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
	tr, err := s.tok.Txn(idempotent(ctx)).
		If(clientv3.Compare(clientv3.ModRevision(k), "=", resp.Kvs[0].ModRevision)).
		Then(clientv3.OpDelete(k)).
		Else(clientv3.OpGet(k, clientv3.WithCountOnly())).
		Commit()
	if err != nil {
		return unavailable(err)
	}
	if !tr.Succeeded && tr.Responses[0].GetResponseRange().Count != 0 {
		return fmt.Errorf("%w: the principal or certificate was revoked again while the lift ran", store.ErrConflict)
	}
	return nil
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
