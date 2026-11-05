package etcd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"go.etcd.io/etcd/api/v3/mvccpb"
	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/blanketfish/port49/internal/store"
)

// Every token is its own key under its (nas, username), so a put, a
// redeem and a delete by ID each touch one key and never rewrite another
// token's: DeleteTokenRacesRedeem cannot lose a concurrent put.

// liveTokens decodes the tokens in kvs that are live at now, each with its
// own copy of its secret.
func liveTokens(kvs []*mvccpb.KeyValue, now time.Time) []store.Token {
	var out []store.Token
	for _, kv := range kvs {
		var r tokenRec
		if json.Unmarshal(kv.Value, &r) != nil || !r.ExpiresAt.After(now) {
			continue
		}
		t := r.token()
		t.Revision = uint64(kv.CreateRevision)
		t.Secret = bytes.Clone(t.Secret)
		out = append(out, t)
	}
	return out
}

// beforeTokenTxn, when set by a test, is called with PutToken's Txn ctx,
// after its lease is had. A package variable: not safe for a test under
// t.Parallel.
var beforeTokenTxn func(ctx context.Context)

// PutToken writes t and counts the live tokens under k, in one
// transaction, as the memory store counts them after its append. A token
// that asks for index entries (store.Token.IndexTTL) has them in the same
// transaction, each kept at the later expiry by a compare on the entry's
// revision: a mint is one revision, and no token exists that a revocation
// cannot find.
func (s *Store) PutToken(ctx context.Context, k store.TokenKey, t store.Token) (int, error) {
	body, err := json.Marshal(tokenRecOf(t))
	if err != nil {
		return 0, err
	}
	for attempt, lost := 0, 0; ; {
		// The grant alone is hedged: a mint at a bucket's rollover grants,
		// and an unhedged grant on a dark member's stalled connection fails
		// one mint in three. The marked ctx goes to the grant only; the
		// token's Txn is never hedged or re-sent, and its create-only
		// compare makes a late copy a refused one, not a second token.
		id, err := s.tokLeases.For(idempotent(ctx), t.ExpiresAt)
		if err != nil {
			return 0, unavailable(err)
		}
		cmps, ops, err := s.tokenIndexOps(ctx, k, t)
		if err != nil {
			return 0, err
		}
		cmps = append(cmps, clientv3.Compare(clientv3.CreateRevision(s.k.token(k, t.ID)), "=", 0))
		ops = append([]clientv3.Op{clientv3.OpPut(s.k.token(k, t.ID), string(body), clientv3.WithLease(id))}, ops...)
		ops = append(ops, clientv3.OpGet(s.k.tokens(k), clientv3.WithPrefix()))
		if beforeTokenTxn != nil {
			beforeTokenTxn(ctx)
		}
		resp, err := s.tok.Txn(ctx).If(cmps...).Then(ops...).Commit()
		if isLeaseLost(err) && attempt == 0 {
			attempt++
			s.tokLeases.Reset()
			continue
		}
		if err != nil {
			return 0, unavailable(err)
		}
		if !resp.Succeeded {
			// The ID is taken, or an index entry moved since it was read. Taken
			// is final: the same ID is never written twice.
			if got, err := s.tok.Get(ctx, s.k.token(k, t.ID), clientv3.WithCountOnly()); err != nil {
				return 0, unavailable(err)
			} else if got.Count > 0 {
				return 0, fmt.Errorf("etcd store: token %q already exists: %w", t.ID, store.ErrConflict)
			}
			lost++
			if err := casBackoff(ctx, lost); err != nil {
				return 0, unavailable(err)
			}
			continue
		}
		return len(liveTokens(resp.Responses[len(ops)-1].GetResponseRange().Kvs, s.now())), nil
	}
}

// tokenIndexOps are the index entries t asks for, as the puts to add to its
// transaction and the compares that hold them: an entry already covering the
// expiry is not written, but is still compared, so a delete since the read
// is not missed. An empty or blank key is skipped (store.BlankCertKey).
func (s *Store) tokenIndexOps(ctx context.Context, k store.TokenKey, t store.Token) ([]clientv3.Cmp, []clientv3.Op, error) {
	if t.IndexTTL <= 0 {
		return nil, nil, nil
	}
	exp := s.now().Add(t.IndexTTL)
	var cmps []clientv3.Cmp
	var ops []clientv3.Op
	for _, ix := range []struct{ fam, key string }{{famTokByPrin, t.IndexPrincipal}, {famTokByCert, t.IndexCertKey}} {
		if ix.key == "" || ix.fam == famTokByCert && store.BlankCertKey(ix.key) {
			continue
		}
		key := s.k.tokenIndexed(ix.fam, ix.key, k)
		var r expiryRec
		mod, found, err := getJSON(ctx, s.tok, key, &r)
		if err != nil {
			return nil, nil, err
		}
		cmps = append(cmps, unchanged(key, mod))
		if found && !exp.After(r.ExpiresAt) {
			continue
		}
		body, err := json.Marshal(expiryRec{ExpiresAt: exp})
		if err != nil {
			return nil, nil, err
		}
		lease, err := s.tokLeases.For(idempotent(ctx), exp)
		if err != nil {
			return nil, nil, unavailable(err)
		}
		ops = append(ops, clientv3.OpPut(key, string(body), clientv3.WithLease(lease)))
	}
	return cmps, ops, nil
}

// Candidates is every live token under k.
func (s *Store) Candidates(ctx context.Context, k store.TokenKey) ([]store.Token, error) {
	resp, err := s.tok.Get(ctx, s.k.tokens(k), clientv3.WithPrefix())
	if err != nil {
		return nil, unavailable(err)
	}
	return liveTokens(resp.Kvs, s.now()), nil
}

// TokenIDs is the ID of every live token under k. A record that does not
// decode is left out, as Candidates leaves it: its lease reclaims it.
func (s *Store) TokenIDs(ctx context.Context, k store.TokenKey) ([]string, error) {
	resp, err := s.tok.Get(ctx, s.k.tokens(k), clientv3.WithPrefix())
	if err != nil {
		return nil, unavailable(err)
	}
	var ids []string
	for _, kv := range resp.Kvs {
		var r tokenRec
		if json.Unmarshal(kv.Value, &r) != nil || !r.ExpiresAt.After(s.now()) {
			continue
		}
		ids = append(ids, r.ID)
	}
	return ids, nil
}

// liveToken reads one token key: its revision, or found false when it is
// absent or past its expiry.
func (s *Store) liveToken(ctx context.Context, k store.TokenKey, id string) (mod int64, found bool, err error) {
	var r tokenRec
	mod, ok, err := getJSON(ctx, s.tok, s.k.token(k, id), &r)
	if err != nil || !ok {
		return 0, false, err
	}
	return mod, r.ExpiresAt.After(s.now()), nil
}

// tokenKV is the KV RedeemAndReceipt's transaction goes through: the token
// client, but for a test that stands between (redeem_hedge_test.go).
var tokenKV = func(kv clientv3.KV) clientv3.KV { return kv }

// RedeemAndReceipt deletes the token and writes the receipt and its index
// entry in one transaction that holds only while the token is the one
// read: of two racing redeemers, exactly one's compare holds (design §12).
func (s *Store) RedeemAndReceipt(ctx context.Context, k store.TokenKey, tokenID string, w store.ReceiptWrite) error {
	mod, live, err := s.liveToken(ctx, k, tokenID)
	if err != nil {
		return err
	}
	if !live {
		return store.ErrNotFound
	}
	nonce := newNonce()
	rec := receiptRecOf(w.Receipt)
	rec.Nonce = nonce
	body, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	puts := []put{{key: s.k.receipt(w.Key), val: body, exp: w.Receipt.RetainUntil}}
	if w.Principal != "" {
		idx, err := json.Marshal(expiryRec{ExpiresAt: s.now().Add(w.IndexTTL)})
		if err != nil {
			return err
		}
		puts = append(puts, put{key: s.k.receiptBy(w.Principal, w.Key), val: idx, exp: s.now().Add(w.IndexTTL)})
	}
	tk, rk := s.k.token(k, tokenID), s.k.receipt(w.Key)
	// Hedged (hedge.go): with one member dark, a Txn sent to its stalled
	// connection is sent again on the next. A second copy is safe: the
	// compare is the token's mod_revision, so once one copy has spent the
	// token the other's compare fails. That failure is read back in the else
	// branch: the receipt this request's own nonce wrote is a success, and
	// anything else is another redeemer, token_spent as ever.
	resp, err := commitTxn(idempotent(ctx), tokenKV(s.tok), s.tokLeases, []clientv3.Cmp{unchanged(tk, mod)}, puts,
		[]del{{key: tk}}, []clientv3.Op{clientv3.OpGet(rk)})
	if err != nil {
		return err
	}
	if !resp.Succeeded {
		if _, own := ownWrite(resp, func(value []byte) bool {
			var r receiptRec
			return json.Unmarshal(value, &r) == nil && r.Nonce == nonce
		}); own {
			return nil
		}
		return store.ErrNotFound // another redeemer, or a delete, took it
	}
	return nil
}

// ownWrite reads the else branch's one Get: the record's mod_revision, and
// whether own accepts its value.
func ownWrite(resp *clientv3.TxnResponse, own func(value []byte) bool) (mod int64, ok bool) {
	if len(resp.Responses) != 1 {
		return 0, false
	}
	kvs := resp.Responses[0].GetResponseRange().Kvs
	if len(kvs) != 1 || !own(kvs[0].Value) {
		return 0, false
	}
	return kvs[0].ModRevision, true
}

// DeleteTokens drops every token under k, spent or not.
func (s *Store) DeleteTokens(ctx context.Context, k store.TokenKey) error {
	_, err := s.tok.Delete(ctx, s.k.tokens(k), clientv3.WithPrefix())
	return unavailable(err)
}

// DeleteToken removes the live token with this ID under k, and only while
// it is the one read; nothing else. The token index is left as it is (7c
// ruling): it is by key, and pruning it could hide a second live token.
func (s *Store) DeleteToken(ctx context.Context, k store.TokenKey, id string) error {
	mod, live, err := s.liveToken(ctx, k, id)
	if err != nil {
		return err
	}
	if !live {
		return store.ErrNotFound
	}
	tk := s.k.token(k, id)
	ok, err := commit(ctx, s.tok, s.tokLeases, []clientv3.Cmp{unchanged(tk, mod)}, nil, del{key: tk})
	if err != nil {
		return err
	}
	if !ok {
		return store.ErrNotFound
	}
	return nil
}

// purgePage bounds one read of PurgeTokens: a page of sealed tokens is a
// few hundred kilobytes, well inside etcd's 1.5 MiB request and gRPC's
// 2 MiB message (pre-flight I14).
const purgePage = 256

// PurgeTokens deletes the token family a page at a time: it reads a page
// of tokens, counts its live ones, and deletes exactly that page's key
// range, until none is left. It runs with the keyspace held: at plan 7d's
// single-process start before any listener binds (Task 12), and at a
// port49-broker runner's takeover, with the API serving. There the
// replica's own start mints nothing until a takeover is seen done
// (decision 36, the mint gate at a start), and another replica's mint may
// land mid-purge: a token put mid-purge is purged by a later page or left,
// never half-deleted. A large t/ costs pages, never a request etcd
// refuses.
func (s *Store) PurgeTokens(ctx context.Context) (int, error) {
	prefix := s.k.family(famToken)
	end := clientv3.GetPrefixRangeEnd(prefix)
	n := 0
	for {
		resp, err := s.tok.Get(ctx, prefix, clientv3.WithRange(end), clientv3.WithLimit(purgePage))
		if err != nil {
			return n, unavailable(err)
		}
		if len(resp.Kvs) == 0 {
			return n, nil
		}
		n += len(liveTokens(resp.Kvs, s.now()))
		last := string(resp.Kvs[len(resp.Kvs)-1].Key)
		if _, err := s.tok.Delete(ctx, string(resp.Kvs[0].Key), clientv3.WithRange(last+"\x00")); err != nil {
			return n, unavailable(err)
		}
	}
}

// ErrTokenRecord is a token record LatestTokenExpiry could not decode. It
// names no record and holds no body.
var ErrTokenRecord = errors.New("etcd store: a token record does not decode")

// LatestTokenExpiry is the largest ExpiresAt among every record under the
// token family, expired or not, zero when there is none. It reads a page at a
// time, writes nothing and keeps nothing of a record but its expiry. A record
// that does not decode is an error (ErrTokenRecord), never skipped: port49d's
// restore guard (plan 12c, Task 9a) lifts only once this time has passed, and a
// record it could not read might be the latest. The time is the minting
// broker's, to be compared with the caller's clock as redemption compares it.
//
// mintedBy bounds the records counted to those minted at or before it (zero:
// every record): only a token minted before a restore can have been restored,
// and one a running broker minted after it must not move the bound. A record
// with no MintedAt cannot be shown to be later, so it counts. A record that
// does not decode is an error whatever its age.
func (s *Store) LatestTokenExpiry(ctx context.Context, mintedBy time.Time) (time.Time, error) {
	end := clientv3.GetPrefixRangeEnd(s.k.family(famToken))
	from := s.k.family(famToken)
	var latest time.Time
	for {
		resp, err := s.tok.Get(ctx, from, clientv3.WithRange(end), clientv3.WithLimit(purgePage))
		if err != nil {
			return time.Time{}, unavailable(err)
		}
		for _, kv := range resp.Kvs {
			var r tokenRec
			if json.Unmarshal(kv.Value, &r) != nil {
				return time.Time{}, ErrTokenRecord
			}
			if !mintedBy.IsZero() && r.MintedAt.After(mintedBy) {
				continue
			}
			if r.ExpiresAt.After(latest) {
				latest = r.ExpiresAt
			}
		}
		if len(resp.Kvs) < purgePage {
			return latest, nil
		}
		from = string(resp.Kvs[len(resp.Kvs)-1].Key) + "\x00"
	}
}

func (s *Store) liveReceipt(r receiptRec) bool { return r.RetainUntil.After(s.now()) }

// GetReceipt is the receipt until its RetainUntil (store.Receipt).
func (s *Store) GetReceipt(ctx context.Context, rk store.ReceiptKey) (store.Receipt, error) {
	var r receiptRec
	_, ok, err := getJSON(ctx, s.tok, s.k.receipt(rk), &r)
	if err != nil {
		return store.Receipt{}, err
	}
	if !ok || !s.liveReceipt(r) {
		return store.Receipt{}, store.ErrNotFound
	}
	return r.receipt(), nil
}

// ExtendReceipt moves IdleExpiresAt and nothing else, on the receipt's own
// lease: RetainUntil does not move, so neither does the lease.
func (s *Store) ExtendReceipt(ctx context.Context, rk store.ReceiptKey, idleExpiresAt time.Time) error {
	return cas(ctx, s.tok, s.tokLeases, s.k.receipt(rk), s.liveReceipt,
		func(r *receiptRec, found bool) (bool, time.Time, bool, error) {
			if !found {
				return false, time.Time{}, false, store.ErrNotFound
			}
			r.IdleExpiresAt = idleExpiresAt
			return true, time.Time{}, true, nil
		})
}

// FailReceipt sets Failed and nothing else.
func (s *Store) FailReceipt(ctx context.Context, rk store.ReceiptKey) error {
	return cas(ctx, s.tok, s.tokLeases, s.k.receipt(rk), s.liveReceipt,
		func(r *receiptRec, found bool) (bool, time.Time, bool, error) {
			if !found {
				return false, time.Time{}, false, store.ErrNotFound
			}
			r.Failed = true
			return true, time.Time{}, true, nil
		})
}

// DeleteReceiptsByPrincipal deletes every receipt the principal's index
// names, and those index entries, and counts the receipts that were live.
// It reads the index a page at a time and deletes exactly the entries it
// read, never the prefix: a receipt written after the read keeps its
// entry, so a later revocation still finds it (pre-flight M17). A receipt
// written after the read is not deleted, as one written after the memory
// store's lock is not: revocation's ordering reaches it (7a).
func (s *Store) DeleteReceiptsByPrincipal(ctx context.Context, principal string) (int, error) {
	prefix := s.k.receiptsBy(principal)
	end := clientv3.GetPrefixRangeEnd(prefix)
	from, n := prefix, 0
	for {
		resp, err := s.tok.Get(ctx, from, clientv3.WithRange(end), clientv3.WithLimit(500), clientv3.WithKeysOnly())
		if err != nil {
			return n, unavailable(err)
		}
		var gets, dels []clientv3.Op
		for _, kv := range resp.Kvs {
			rk := s.k.root + famReceipt + string(kv.Key[len(prefix):])
			gets = append(gets, clientv3.OpGet(rk))
			dels = append(dels, clientv3.OpDelete(rk), clientv3.OpDelete(string(kv.Key)))
		}
		if err := chunked(ctx, s.tok, gets, func(r *clientv3.TxnResponse) {
			for _, op := range r.Responses {
				for _, kv := range op.GetResponseRange().Kvs {
					var rec receiptRec
					if json.Unmarshal(kv.Value, &rec) == nil && s.liveReceipt(rec) {
						n++
					}
				}
			}
		}); err != nil {
			return n, err
		}
		if err := chunked(ctx, s.tok, dels, nil); err != nil {
			return n, err
		}
		if !resp.More || len(resp.Kvs) == 0 {
			return n, nil
		}
		from = string(resp.Kvs[len(resp.Kvs)-1].Key) + "\x00"
	}
}

func (s *Store) tokenKeys(ctx context.Context, fam, key string) ([]store.TokenKey, error) {
	if key == "" {
		return nil, nil
	}
	resp, err := s.tok.Get(ctx, s.k.tokenIndex(fam, key), clientv3.WithPrefix())
	if err != nil {
		return nil, unavailable(err)
	}
	now := s.now()
	var out []store.TokenKey
	for _, kv := range resp.Kvs {
		// An entry that does not decode is an error, never skipped: a
		// revocation that skipped it would miss that key's tokens, which
		// is revocation failing open (pre-flight M18). One whose key does
		// not parse names no token key, so it is said, counted and skipped,
		// as refsUnder skips a lookup entry's (final review I-1).
		var r expiryRec
		nas, user, ok := lastTwo(string(kv.Key))
		if !ok {
			s.unparseable("token index entry", kv.Key, "a lookup skips it")
			continue
		}
		if err := json.Unmarshal(kv.Value, &r); err != nil {
			return nil, notDecoded(fmt.Sprintf("token index entry %q", kv.Key))
		}
		if !r.ExpiresAt.After(now) {
			continue
		}
		out = append(out, store.TokenKey{NAS: nas, Username: user})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].NAS != out[j].NAS {
			return out[i].NAS < out[j].NAS
		}
		return out[i].Username < out[j].Username
	})
	return out, nil
}

func (s *Store) TokensByPrincipal(ctx context.Context, principal string) ([]store.TokenKey, error) {
	return s.tokenKeys(ctx, famTokByPrin, principal)
}

func (s *Store) TokensByCert(ctx context.Context, certKey string) ([]store.TokenKey, error) {
	if store.BlankCertKey(certKey) {
		return nil, nil
	}
	return s.tokenKeys(ctx, famTokByCert, certKey)
}
