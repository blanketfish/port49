package etcd

import (
	"context"
	"slices"
	"strings"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/rhwendt/port49/internal/store"
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
