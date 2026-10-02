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
	_, err = commit(ctx, s.tok, s.tokLeases,
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

func (s *Store) DeleteRevocation(ctx context.Context, kind, key string) error {
	_, err := s.tok.Delete(ctx, s.k.mark(kind, key))
	return unavailable(err)
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
