package etcd

import (
	"context"

	pb "go.etcd.io/etcd/api/v3/etcdserverpb"
	clientv3 "go.etcd.io/etcd/client/v3"
)

// sawKV is the context client's KV with every answered response's header
// revision handed to saw (Seen; plan 7e, Ruling T6-a). Every KV call on
// the context client goes through it (Store.ctxKV), so no read, write or
// transaction there can be left out of Seen, an absent key's read
// included.
type sawKV struct {
	clientv3.KV
	saw func(rev int64)
}

// header sees h's revision; a nil header is revision 0, which raises
// nothing.
func (k sawKV) header(h *pb.ResponseHeader) { k.saw(h.GetRevision()) }

func (k sawKV) Put(ctx context.Context, key, val string, opts ...clientv3.OpOption) (*clientv3.PutResponse, error) {
	resp, err := k.KV.Put(ctx, key, val, opts...)
	if err == nil {
		k.header(resp.Header)
	}
	return resp, err
}

func (k sawKV) Get(ctx context.Context, key string, opts ...clientv3.OpOption) (*clientv3.GetResponse, error) {
	resp, err := k.KV.Get(ctx, key, opts...)
	if err == nil {
		k.header(resp.Header)
	}
	return resp, err
}

func (k sawKV) Delete(ctx context.Context, key string, opts ...clientv3.OpOption) (*clientv3.DeleteResponse, error) {
	resp, err := k.KV.Delete(ctx, key, opts...)
	if err == nil {
		k.header(resp.Header)
	}
	return resp, err
}

func (k sawKV) Compact(ctx context.Context, rev int64, opts ...clientv3.CompactOption) (*clientv3.CompactResponse, error) {
	resp, err := k.KV.Compact(ctx, rev, opts...)
	if err == nil {
		k.header(resp.Header)
	}
	return resp, err
}

func (k sawKV) Do(ctx context.Context, op clientv3.Op) (clientv3.OpResponse, error) {
	resp, err := k.KV.Do(ctx, op)
	if err == nil {
		switch {
		case resp.Get() != nil:
			k.header(resp.Get().Header)
		case resp.Put() != nil:
			k.header(resp.Put().Header)
		case resp.Del() != nil:
			k.header(resp.Del().Header)
		case resp.Txn() != nil:
			k.header(resp.Txn().Header)
		}
	}
	return resp, err
}

func (k sawKV) Txn(ctx context.Context) clientv3.Txn { return sawTxn{k.KV.Txn(ctx), k} }

// sawTxn is a transaction whose committed response sawKV sees.
type sawTxn struct {
	clientv3.Txn
	kv sawKV
}

func (t sawTxn) If(cs ...clientv3.Cmp) clientv3.Txn   { return sawTxn{t.Txn.If(cs...), t.kv} }
func (t sawTxn) Then(ops ...clientv3.Op) clientv3.Txn { return sawTxn{t.Txn.Then(ops...), t.kv} }
func (t sawTxn) Else(ops ...clientv3.Op) clientv3.Txn { return sawTxn{t.Txn.Else(ops...), t.kv} }

func (t sawTxn) Commit() (*clientv3.TxnResponse, error) {
	resp, err := t.Txn.Commit()
	if err == nil {
		t.kv.header(resp.Header)
	}
	return resp, err
}
