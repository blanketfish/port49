package etcd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"go.etcd.io/etcd/api/v3/v3rpc/rpctypes"
	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/blanketfish/port49/internal/store"
)

// onceRec is on/<key> (plan 7h).
type onceRec struct {
	Value     []byte    `json:"value"`
	ExpiresAt time.Time `json:"expires_at"`
}

// PutOnce writes key only where no live record is, by a compare on its
// revision.
func (s *Store) PutOnce(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	if key == "" {
		return false, store.ErrNoKey
	}
	if ttl <= 0 {
		return false, store.ErrBadTTL
	}
	now := s.now()
	wrote := false
	err := casAs(ctx, s.tok, s.tokLeases, s.k.once(key), "once-only record", func(r onceRec) bool { return now.Before(r.ExpiresAt) },
		func(r *onceRec, found bool) (bool, time.Time, bool, error) {
			if found {
				wrote = false
				return false, time.Time{}, false, nil
			}
			*r = onceRec{Value: value, ExpiresAt: now.Add(ttl)}
			wrote = true
			return true, r.ExpiresAt, false, nil
		})
	return wrote && err == nil, err
}

// TakeOnce deletes key if it is still the record read, and returns its
// value; a lost race reads again, and finds it gone.
func (s *Store) TakeOnce(ctx context.Context, key string) ([]byte, error) {
	k := s.k.once(key)
	for {
		var r onceRec
		mod, ok, err := getJSONAs(ctx, s.tok, k, "once-only record", &r)
		switch {
		case err != nil:
			return nil, err
		case !ok:
			return nil, store.ErrNotFound
		}
		resp, err := s.tok.Txn(ctx).If(unchanged(k, mod)).Then(clientv3.OpDelete(k)).Commit()
		if err != nil {
			return nil, unavailable(err)
		}
		if !resp.Succeeded {
			continue
		}
		if !s.now().Before(r.ExpiresAt) {
			return nil, store.ErrNotFound // expired: deleted all the same
		}
		return r.Value, nil
	}
}

// ownerRec is oo/<OIDCKey>: every principal minting under it (Ruling 24),
// and the latest of their expiries, which the record's lease follows.
type ownerRec struct {
	Principals []ownerEntry `json:"principals"`
	ExpiresAt  time.Time    `json:"expires_at"`
}

type ownerEntry struct {
	Principal string    `json:"principal"`
	WrittenAt time.Time `json:"written_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// PutOIDCOwner merges principal into the record by a compare on its
// revision: a concurrent write of another principal is read again and kept,
// never overwritten (pre-flight I-1).
func (s *Store) PutOIDCOwner(ctx context.Context, key, principal string, ttl time.Duration) error {
	if key == "" {
		return store.ErrNoKey
	}
	if principal == "" {
		return store.ErrNoPrincipal
	}
	if ttl <= 0 {
		return store.ErrBadTTL
	}
	now := s.now()
	return casAs(ctx, s.tok, s.tokLeases, s.k.oidcOwner(key), "OIDC owner record", func(r ownerRec) bool { return now.Before(r.ExpiresAt) },
		func(r *ownerRec, found bool) (bool, time.Time, bool, error) {
			var live []ownerEntry
			if found {
				for _, e := range r.Principals {
					if now.Before(e.ExpiresAt) && e.Principal != principal {
						live = append(live, e)
					}
				}
			}
			exp := now.Add(ttl)
			if found {
				for _, e := range r.Principals {
					if e.Principal == principal && e.ExpiresAt.After(exp) {
						exp = e.ExpiresAt
					}
				}
			}
			next := ownerRec{Principals: append(live, ownerEntry{Principal: principal, WrittenAt: now, ExpiresAt: exp})}
			for _, e := range next.Principals {
				next.ExpiresAt = laterOf(next.ExpiresAt, e.ExpiresAt)
			}
			*r = next
			return true, next.ExpiresAt, false, nil
		})
}

func (s *Store) OIDCOwner(ctx context.Context, key string) (store.OIDCOwner, error) {
	var r ownerRec
	_, ok, err := getJSONAs(ctx, s.tok, s.k.oidcOwner(key), "OIDC owner record", &r)
	if err != nil {
		return store.OIDCOwner{}, err
	}
	now := s.now()
	var o store.OIDCOwner
	for _, e := range r.Principals {
		if ok && now.Before(e.ExpiresAt) {
			o.Principals = append(o.Principals, store.OwnerPrincipal{Principal: e.Principal, WrittenAt: e.WrittenAt,
				ExpiresAt: e.ExpiresAt})
		}
	}
	if len(o.Principals) == 0 {
		return store.OIDCOwner{}, store.ErrNotFound
	}
	slices.SortFunc(o.Principals, func(a, b store.OwnerPrincipal) int { return strings.Compare(a.Principal, b.Principal) })
	return o, nil
}

// logoutRec is lo/<OIDCKey>.
type logoutRec struct {
	At        time.Time `json:"at"`
	Origin    string    `json:"origin"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (s *Store) PutLogout(ctx context.Context, l store.Logout, ttl time.Duration) error {
	if l.Key == "" {
		return store.ErrNoKey
	}
	if ttl <= 0 {
		return store.ErrBadTTL
	}
	now := s.now()
	return casAs(ctx, s.tok, s.tokLeases, s.k.logout(l.Key), "logout record", func(r logoutRec) bool { return now.Before(r.ExpiresAt) },
		func(r *logoutRec, found bool) (bool, time.Time, bool, error) {
			next := logoutRec{At: l.At, Origin: l.Origin, ExpiresAt: now.Add(ttl)}
			if found {
				if r.At.After(l.At) {
					next.At, next.Origin = r.At, r.Origin
				}
				next.ExpiresAt = laterOf(next.ExpiresAt, r.ExpiresAt)
			}
			*r = next
			return true, next.ExpiresAt, false, nil
		})
}

func (s *Store) GetLogout(ctx context.Context, key string) (store.Logout, error) {
	var r logoutRec
	_, ok, err := getJSONAs(ctx, s.tok, s.k.logout(key), "logout record", &r)
	switch {
	case err != nil:
		return store.Logout{}, err
	case !ok || !s.now().Before(r.ExpiresAt):
		return store.Logout{}, store.ErrNotFound
	}
	return store.Logout{Key: key, At: r.At, Origin: r.Origin}, nil
}

// mfaProofRec is mp/<key> (plan 9c).
type mfaProofRec struct {
	Method    string    `json:"method"`
	At        time.Time `json:"at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// PutMFAProof keeps the later At and the later expiry, by a compare on the
// record's revision, as PutLogout does.
func (s *Store) PutMFAProof(ctx context.Context, p store.MFAProof, ttl time.Duration) error {
	if p.Key == "" {
		return store.ErrNoKey
	}
	if ttl <= 0 {
		return store.ErrBadTTL
	}
	now := s.now()
	return casAs(ctx, s.tok, s.tokLeases, s.k.mfaProof(p.Key), "per-login proof", func(r mfaProofRec) bool { return now.Before(r.ExpiresAt) },
		func(r *mfaProofRec, found bool) (bool, time.Time, bool, error) {
			next := mfaProofRec{Method: p.Method, At: p.At, ExpiresAt: now.Add(ttl)}
			if found {
				if r.At.After(p.At) {
					next.Method, next.At = r.Method, r.At
				}
				next.ExpiresAt = laterOf(next.ExpiresAt, r.ExpiresAt)
			}
			*r = next
			return true, next.ExpiresAt, false, nil
		})
}

func (s *Store) GetMFAProof(ctx context.Context, key string) (store.MFAProof, error) {
	var r mfaProofRec
	_, ok, err := getJSONAs(ctx, s.tok, s.k.mfaProof(key), "per-login proof", &r)
	switch {
	case err != nil:
		return store.MFAProof{}, err
	case !ok || !s.now().Before(r.ExpiresAt):
		return store.MFAProof{}, store.ErrNotFound
	}
	return store.MFAProof{Key: key, Method: r.Method, At: r.At}, nil
}

// Logouts is every live logout record at one revision, which it returns
// (store.LogoutFeed; plan 11a, R26), read a page at a time as the marks are
// (pre-flight I14): a logout record lives a day on a broker that issues, so
// the set can be large. A record that does not decode is said by its key and
// skipped.
func (s *Store) Logouts(ctx context.Context) (uint64, []store.LogoutEntry, error) {
	prefix := s.k.family(famLogout)
	end := clientv3.GetPrefixRangeEnd(prefix)
	from, rev := prefix, int64(0)
	now := s.now()
	var out []store.LogoutEntry
	for {
		opts := []clientv3.OpOption{clientv3.WithRange(end), clientv3.WithLimit(500)}
		if rev > 0 {
			opts = append(opts, clientv3.WithRev(rev))
		}
		resp, err := s.tok.Get(clientv3.WithRequireLeader(ctx), from, opts...)
		if errors.Is(err, rpctypes.ErrCompacted) {
			return 0, nil, store.ErrCompacted
		}
		if err != nil {
			return 0, nil, unavailable(err)
		}
		if rev == 0 {
			rev = resp.Header.Revision
		}
		for _, kv := range resp.Kvs {
			e, ok := s.logoutEntry(prefix, kv.Key, kv.Value)
			if ok && now.Before(e.Until) {
				e.Rev = uint64(kv.ModRevision)
				out = append(out, e)
			}
		}
		if !resp.More || len(resp.Kvs) == 0 {
			break
		}
		from = string(resp.Kvs[len(resp.Kvs)-1].Key) + "\x00"
	}
	return uint64(rev), out, nil
}

// WatchLogouts calls fn for every put and delete of a logout record after
// `after`, as WatchRevocations does for the marks.
func (s *Store) WatchLogouts(ctx context.Context, after uint64, fn func(store.LogoutEntry, bool, uint64),
	progress func(uint64)) error {
	wctx, cancel := context.WithCancel(clientv3.WithRequireLeader(ctx))
	defer cancel()
	prefix := s.k.family(famLogout)
	ch := s.tok.Watch(wctx, prefix, clientv3.WithPrefix(), clientv3.WithRev(int64(after)+1),
		clientv3.WithProgressNotify())
	for resp := range ch {
		if err := resp.Err(); err != nil {
			if resp.CompactRevision > 0 || errors.Is(err, rpctypes.ErrCompacted) {
				return store.ErrCompacted
			}
			return unavailable(err)
		}
		if resp.IsProgressNotify() {
			progress(uint64(resp.Header.Revision))
			continue
		}
		for _, ev := range resp.Events {
			rev := uint64(ev.Kv.ModRevision)
			if ev.Type == clientv3.EventTypeDelete {
				if k, err := url.PathUnescape(strings.TrimPrefix(string(ev.Kv.Key), prefix)); err == nil {
					fn(store.LogoutEntry{Logout: store.Logout{Key: k}}, true, rev)
				}
				continue
			}
			if e, ok := s.logoutEntry(prefix, ev.Kv.Key, ev.Kv.Value); ok {
				fn(e, false, rev)
			}
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return fmt.Errorf("%w: the logouts watch ended", store.ErrUnavailable)
}

// DeleteLogout removes the logout record under key if it is still the one
// read at rev (LogoutEntry.Rev): a pending logout the runner forwarded to
// the directory (placement.ForwardPending). A record written since, a second
// logout of the same key, stays pending for the next pass, as DeleteRevocation
// leaves a mark made since its read. None, or one changed, is not an error.
func (s *Store) DeleteLogout(ctx context.Context, key string, rev uint64) error {
	k := s.k.logout(key)
	_, err := s.tok.Txn(ctx).If(clientv3.Compare(clientv3.ModRevision(k), "=", int64(rev))).
		Then(clientv3.OpDelete(k)).Commit()
	return unavailable(err)
}

// logoutEntry decodes one lo/ key and value, saying by its key alone one
// that does not.
func (s *Store) logoutEntry(prefix string, key, value []byte) (store.LogoutEntry, bool) {
	k, err := url.PathUnescape(strings.TrimPrefix(string(key), prefix))
	var r logoutRec
	if err != nil || json.Unmarshal(value, &r) != nil {
		// The key names a session or a user: only its hash is said.
		sum := sha256.Sum256(key)
		s.logf("etcd: a logout record (key_sha256 %s) does not decode; the logouts feed skipped it", hex.EncodeToString(sum[:8]))
		return store.LogoutEntry{}, false
	}
	return store.LogoutEntry{Logout: store.Logout{Key: k, At: r.At, Origin: r.Origin}, Until: r.ExpiresAt}, true
}
