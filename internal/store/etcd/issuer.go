package etcd

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
)

// IssuerRecord is meta/issuer (decision 53 ruling 10): the issuing CA every
// broker on this store issues from, by fingerprint. Never key material.
type IssuerRecord struct {
	Current   string    `json:"current"`
	Previous  string    `json:"previous,omitempty"`
	WrittenBy string    `json:"written_by"`
	WrittenAt time.Time `json:"written_at"`
}

// IssuerRecord reads meta/issuer and the revision it was written at; 0 when
// there is none.
func (s *Store) IssuerRecord(ctx context.Context) (IssuerRecord, uint64, error) {
	resp, err := s.ctxKV.Get(ctx, s.k.meta("issuer"))
	if err != nil {
		return IssuerRecord{}, 0, unavailable(err)
	}
	if len(resp.Kvs) == 0 {
		return IssuerRecord{}, 0, nil
	}
	var r IssuerRecord
	if err := json.Unmarshal(resp.Kvs[0].Value, &r); err != nil {
		return IssuerRecord{}, 0, fmt.Errorf("etcd: %s does not decode; port49-broker forget-issuer removes it",
			s.k.meta("issuer"))
	}
	return r, uint64(resp.Kvs[0].ModRevision), nil
}

// PutIssuerRecord writes r if meta/issuer is still at over (0: absent), and
// reports false when another write got there first.
func (s *Store) PutIssuerRecord(ctx context.Context, r IssuerRecord, over uint64) (bool, error) {
	key := s.k.meta("issuer")
	r.WrittenAt = s.now().UTC()
	body, err := json.Marshal(r)
	if err != nil {
		return false, err
	}
	resp, err := s.ctxKV.Txn(ctx).If(clientv3.Compare(clientv3.ModRevision(key), "=", int64(over))).
		Then(clientv3.OpPut(key, string(body))).Commit()
	if err != nil {
		return false, unavailable(err)
	}
	return resp.Succeeded, nil
}

// DeleteIssuerRecord removes meta/issuer, returning what it held.
func (s *Store) DeleteIssuerRecord(ctx context.Context) (IssuerRecord, bool, error) {
	r, rev, err := s.IssuerRecord(ctx)
	if err != nil || rev == 0 {
		return r, false, err
	}
	if _, err := s.ctxKV.Delete(ctx, s.k.meta("issuer")); err != nil {
		return r, false, unavailable(err)
	}
	return r, true, nil
}
