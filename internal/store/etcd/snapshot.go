package etcd

import (
	"context"
	"net/url"
	"strings"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
)

// The two kinds of directory snapshot record (plan 11a, R19): the marks,
// which port49d may read, and a broker's logouts and pins, which it may not.
const (
	SnapshotMarks  = "m"
	SnapshotBroker = "b"
)

// PutDirectorySnapshot writes writer's directory snapshot record of kind
// (plan 11a, R19): body is sealed by the caller; the record lives for ttl,
// so a writer that went away leaves nothing for long.
func (s *Store) PutDirectorySnapshot(ctx context.Context, kind, writer string, body []byte, ttl time.Duration) error {
	_, err := commit(ctx, s.tok, s.tokLeases, nil, []put{{key: s.k.snapshot(kind, writer), val: body,
		exp: s.now().Add(ttl)}})
	return err
}

// DirectorySnapshots is every live snapshot record of kind, by its writer.
// A key that does not parse is said and skipped.
func (s *Store) DirectorySnapshots(ctx context.Context, kind string) (map[string][]byte, error) {
	prefix := s.k.family(famSnapshot) + kind + "/"
	resp, err := s.tok.Get(ctx, prefix, clientv3.WithPrefix())
	if err != nil {
		return nil, unavailable(err)
	}
	out := make(map[string][]byte, len(resp.Kvs))
	for _, kv := range resp.Kvs {
		w, err := url.PathUnescape(strings.TrimPrefix(string(kv.Key), prefix))
		if err != nil {
			s.logf("etcd: the directory snapshot key %q does not parse; skipped", kv.Key)
			continue
		}
		out[w] = kv.Value
	}
	return out, nil
}
