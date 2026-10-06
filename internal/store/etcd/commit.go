package etcd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"go.etcd.io/etcd/api/v3/v3rpc/rpctypes"
	clientv3 "go.etcd.io/etcd/client/v3"
)

// put is one write of a transaction, its lease chosen at commit: a zero
// exp is no lease (a mark, a lookup entry, the index record's own rule
// aside), and keep keeps the key's own lease (a receipt's flag).
type put struct {
	key  string
	val  []byte
	exp  time.Time
	keep bool
}

// del is one delete of a transaction; prefix deletes the range.
type del struct {
	key    string
	prefix bool
}

// commit runs one transaction on cli: if every cmp holds, every put and
// del. It reports whether the cmps held. A lease etcd no longer knows (one
// that expired while port49d was paused, or an operator revoked) costs one
// retry on fresh leases (Review Focus 2).
func commit(ctx context.Context, cli clientv3.KV, ls *leases, cmps []clientv3.Cmp, puts []put, dels ...del) (bool, error) {
	ok, _, err := commitRev(ctx, cli, ls, cmps, puts, dels...)
	return ok, err
}

// commitRev is commit, also returning the store revision the transaction
// ran at: when the cmps held, the revision its writes committed at, which
// is every written key's mod_revision.
func commitRev(ctx context.Context, cli clientv3.KV, ls *leases, cmps []clientv3.Cmp, puts []put,
	dels ...del) (bool, int64, error) {
	for attempt := 0; ; attempt++ {
		ops := make([]clientv3.Op, 0, len(puts)+len(dels))
		for _, p := range puts {
			switch {
			case p.keep:
				ops = append(ops, clientv3.OpPut(p.key, string(p.val), clientv3.WithIgnoreLease()))
			case p.exp.IsZero():
				ops = append(ops, clientv3.OpPut(p.key, string(p.val)))
			default:
				id, err := ls.For(ctx, p.exp)
				if err != nil {
					return false, 0, unavailable(err)
				}
				ops = append(ops, clientv3.OpPut(p.key, string(p.val), clientv3.WithLease(id)))
			}
		}
		for _, d := range dels {
			if d.prefix {
				ops = append(ops, clientv3.OpDelete(d.key, clientv3.WithPrefix()))
			} else {
				ops = append(ops, clientv3.OpDelete(d.key))
			}
		}
		resp, err := cli.Txn(ctx).If(cmps...).Then(ops...).Commit()
		if isLeaseLost(err) && attempt == 0 {
			ls.Reset()
			continue
		}
		if err != nil {
			return false, 0, unavailable(err)
		}
		return resp.Succeeded, resp.Header.Revision, nil
	}
}

// isLeaseLost is etcd saying a lease the put named is gone: one that
// expired while port49d was paused, or that an operator revoked.
func isLeaseLost(err error) bool { return errors.Is(err, rpctypes.ErrLeaseNotFound) }

// unchanged is the compare that key's mod_revision is still mod; 0 means
// the key is still absent.
func unchanged(key string, mod int64) clientv3.Cmp {
	return clientv3.Compare(clientv3.ModRevision(key), "=", mod)
}

// cas reads key's record, lets f change it, and writes it back only if
// nobody wrote key since the read, reading again on a lost race until one
// write lands or ctx ends. live decides whether a record is present to f:
// one past its expiry is handed over as absent, but its revision is still
// compared. f returns write false to write nothing (its answer stands),
// the expiry the write's lease follows (zero for none), keep to keep the
// key's own lease, or an error to stop.
func cas[R any](ctx context.Context, cli clientv3.KV, ls *leases, key string, live func(R) bool,
	f func(r *R, found bool) (write bool, exp time.Time, keep bool, err error)) error {
	return casAs(ctx, cli, ls, key, key, live, f)
}

// casAs is cas that names a record that does not decode as what, not by
// key: for the records whose key is a jti, a sid or a sub, which no error
// carries (plan 7h).
func casAs[R any](ctx context.Context, cli clientv3.KV, ls *leases, key, what string, live func(R) bool,
	f func(r *R, found bool) (write bool, exp time.Time, keep bool, err error)) error {
	for {
		resp, err := cli.Get(ctx, key)
		if err != nil {
			return unavailable(err)
		}
		var r R
		var mod int64
		found := false
		if len(resp.Kvs) == 1 {
			if err := json.Unmarshal(resp.Kvs[0].Value, &r); err != nil {
				return notDecoded(what)
			}
			mod, found = resp.Kvs[0].ModRevision, live(r)
			if !found {
				var zero R
				r = zero
			}
		}
		write, exp, keep, err := f(&r, found)
		if err != nil || !write {
			return err
		}
		body, err := json.Marshal(r)
		if err != nil {
			return err
		}
		ok, err := commit(ctx, cli, ls, []clientv3.Cmp{unchanged(key, mod)}, []put{{key: key, val: body, exp: exp, keep: keep}})
		if err != nil || ok {
			return err
		}
	}
}

// notDecoded is a record that does not decode, said by what it is alone:
// the decoder's error quotes the stored bytes, and an unvalidated body is
// never logged (Task 7b review).
func notDecoded(what string) error { return fmt.Errorf("etcd: %s does not decode", what) }

// getJSON reads key into v; false when it is absent.
func getJSON(ctx context.Context, cli clientv3.KV, key string, v any) (mod int64, ok bool, err error) {
	return getJSONAs(ctx, cli, key, key, v)
}

// getJSONAs is getJSON that names a record that does not decode as what.
func getJSONAs(ctx context.Context, cli clientv3.KV, key, what string, v any) (mod int64, ok bool, err error) {
	resp, err := cli.Get(ctx, key)
	if err != nil {
		return 0, false, unavailable(err)
	}
	if len(resp.Kvs) == 0 {
		return 0, false, nil
	}
	if err := json.Unmarshal(resp.Kvs[0].Value, v); err != nil {
		return 0, false, notDecoded(what)
	}
	return resp.Kvs[0].ModRevision, true, nil
}

// chunked calls f on ops in transactions of at most maxTxnOps: etcd's
// default --max-txn-ops is 128.
func chunked(ctx context.Context, cli clientv3.KV, ops []clientv3.Op, f func(*clientv3.TxnResponse)) error {
	for len(ops) > 0 {
		n := min(len(ops), maxTxnOps)
		resp, err := cli.Txn(ctx).Then(ops[:n]...).Commit()
		if err != nil {
			return unavailable(err)
		}
		if f != nil {
			f(resp)
		}
		ops = ops[n:]
	}
	return nil
}

const maxTxnOps = 64
