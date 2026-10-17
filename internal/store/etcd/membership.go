package etcd

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"sort"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/rhwendt/port49/internal/store"
)

// membershipRec is mb/<principal> (plan 7g, Ruling 10): what crypt sealed,
// the plaintext the backend keeps the later of, and its expiry. A forget
// replaces it with a tombstone (ForgottenAt) in the same key, so one compare
// decides a write against both.
type membershipRec struct {
	Principal  string    `json:"principal"`
	DN         string    `json:"dn,omitempty"`
	EntryID    string    `json:"entry_id,omitempty"`
	Username   string    `json:"username,omitempty"`
	GroupDNs   []string  `json:"group_dns,omitempty"`
	GroupNames []string  `json:"group_names,omitempty"`
	MapKeys    []string  `json:"map_keys,omitempty"`
	Refused    bool      `json:"refused,omitempty"`
	VerifiedAt time.Time `json:"verified_at"`
	Server     string    `json:"server,omitempty"`
	Site       string    `json:"site,omitempty"`
	Sealed     []byte    `json:"sealed,omitempty"`
	ExpiresAt  time.Time `json:"expires_at"`
	// ForgottenAt is set on the tombstone a forget leaves in place of the
	// record: no record, only the time a write must not be verified before.
	ForgottenAt time.Time `json:"forgotten_at,omitempty"`
}

// membershipKeyRec is mk/<map key>: every principal that registered a claim
// to the key, and when it was last refused. It holds no pointer:
// MembershipByKey answers the one claimant whose live record lists the key,
// so a claimant that stopped listing it, or whose record is gone, only
// ever denies. It lives as long as the longest record that registered.
type membershipKeyRec struct {
	Claimants []string  `json:"claimants,omitempty"`
	RefusedAt time.Time `json:"refused_at,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
}

// PutMembership registers m's principal on each of its keys, then keeps
// the later verification at mb/, by a compare on the record's revision. The
// two are not one transaction, so the registration comes first: a write
// torn between them leaves a claimant with no record, which only denies,
// never a record that lists a key its index does not know (review R2-b).
func (s *Store) PutMembership(ctx context.Context, m store.Membership, ttl time.Duration) error {
	now := s.now()
	exp := expiry(now, ttl)
	for _, key := range m.MapKeys {
		if err := s.registerKey(ctx, key, m.Principal, exp, now); err != nil {
			return err
		}
	}
	return cas(ctx, s.tok, s.tokLeases, s.k.membership(m.Principal),
		func(r membershipRec) bool { return alive(r.ExpiresAt, now) },
		func(r *membershipRec, found bool) (bool, time.Time, bool, error) {
			if found && r.tombstone() && m.VerifiedAt.Before(r.ForgottenAt) {
				return false, time.Time{}, false, nil // verified before the forget: never writes the old pin back
			}
			if found && !r.tombstone() && (r.VerifiedAt.After(m.VerifiedAt) ||
				(r.VerifiedAt.Equal(m.VerifiedAt) && r.Refused && !m.Refused)) { // a refusal outranks a grant at its instant
				return false, time.Time{}, false, nil
			}
			*r = membershipRec{Principal: m.Principal, DN: m.DN, EntryID: m.EntryID, Username: m.Username, GroupDNs: m.GroupDNs,
				GroupNames: m.GroupNames, MapKeys: m.MapKeys, Refused: m.Refused, VerifiedAt: m.VerifiedAt,
				Server: m.Server, Site: m.Site, Sealed: m.Sealed, ExpiresAt: exp}
			return true, exp, false, nil
		})
}

// claimsKey is whether principal has a live, unrefused record that lists
// key; an error only when the store could not say.
func (s *Store) claimsKey(ctx context.Context, principal, key string) (bool, error) {
	held, err := s.GetMembership(ctx, principal)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return false, nil
	case err != nil:
		return false, err
	}
	return !held.Refused && slices.Contains(held.MapKeys, key), nil
}

// registerKey adds principal to key's claimants, one compare on the key's
// revision, and extends the key to exp when that is later: on every call,
// whether or not the claimant was there already.
func (s *Store) registerKey(ctx context.Context, key, principal string, exp, now time.Time) error {
	return cas(ctx, s.tok, s.tokLeases, s.k.membershipKey(key),
		func(membershipKeyRec) bool { return true }, // a present marker keeps its claimants, whatever this clock says
		func(r *membershipKeyRec, found bool) (bool, time.Time, bool, error) {
			if !slices.Contains(r.Claimants, principal) {
				r.Claimants = append(r.Claimants, principal)
				sort.Strings(r.Claimants)
			}
			if found {
				r.ExpiresAt = laterExp(r.ExpiresAt, exp)
			} else {
				r.ExpiresAt = exp
			}
			return true, r.ExpiresAt, false, nil
		})
}

// expiry is ttl's expiry from now: none, the zero time, for
// store.NoExpiry (plan 11a, R13). commit puts a record with a zero expiry
// with no lease.
func expiry(now time.Time, ttl time.Duration) time.Time {
	if ttl == store.NoExpiry {
		return time.Time{}
	}
	return now.Add(ttl)
}

// alive reports whether a record expiring at exp stands at now: one with no
// expiry always does.
func alive(exp, now time.Time) bool { return exp.IsZero() || exp.After(now) }

// laterExp is the later of two expiries of records that exist, no expiry
// being the latest.
func laterExp(a, b time.Time) time.Time {
	if a.IsZero() || b.IsZero() {
		return time.Time{}
	}
	return laterOf(a, b)
}

func laterOf(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

// RefuseMapKeys marks each key refused as of at (Ruling 10): a record
// verified after it answers the key again, one verified at or before it
// does not. The claimants are kept.
func (s *Store) RefuseMapKeys(ctx context.Context, mapKeys []string, at time.Time, ttl time.Duration) error {
	now := s.now()
	exp := expiry(now, ttl)
	for _, key := range mapKeys {
		if err := cas(ctx, s.tok, s.tokLeases, s.k.membershipKey(key),
			func(membershipKeyRec) bool { return true }, // a present marker keeps its claimants, whatever this clock says
			func(r *membershipKeyRec, found bool) (bool, time.Time, bool, error) {
				r.RefusedAt = laterOf(r.RefusedAt, at)
				if found {
					r.ExpiresAt = laterExp(r.ExpiresAt, exp)
				} else {
					r.ExpiresAt = exp
				}
				return true, r.ExpiresAt, false, nil
			}); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) GetMembership(ctx context.Context, principal string) (store.Membership, error) {
	var r membershipRec
	if err := s.getLive(ctx, s.k.membership(principal), &r, func() bool { return alive(r.ExpiresAt, s.now()) }); err != nil {
		return store.Membership{}, err
	}
	if r.Principal != principal {
		return store.Membership{}, notDecoded(s.k.membership(principal)) // a record copied under another key
	}
	if r.tombstone() {
		return store.Membership{}, store.ErrForgotten
	}
	return r.membership(), nil
}

func (r membershipRec) tombstone() bool { return !r.ForgottenAt.IsZero() }

func (r membershipRec) membership() store.Membership {
	return store.Membership{Principal: r.Principal, DN: r.DN, EntryID: r.EntryID, Username: r.Username,
		GroupDNs: r.GroupDNs, GroupNames: r.GroupNames, MapKeys: r.MapKeys, Refused: r.Refused, VerifiedAt: r.VerifiedAt,
		Server: r.Server, Site: r.Site, Sealed: r.Sealed}
}

// DeleteMembership replaces mb/<principal> with a tombstone of the forget's
// time, in one compare on the record's revision, and returns what it held
// (Ruling 3's escape). The tombstone is kept as long as the record had left
// (at least store.TombstoneFloor): PutMembership drops a write verified before
// it, so a verification in flight at the forget cannot put the pin back.
// Its mk/ keys stay until their leases end: MembershipByKey answers
// ErrNotFound for a key whose record is gone, and the claimant is filtered
// there as one that lists nothing. A record that does not decode is replaced all the same and
// returned as its principal alone.
func (s *Store) DeleteMembership(ctx context.Context, principal string) (store.Membership, error) {
	key := s.k.membership(principal)
	for {
		now := s.now()
		resp, err := s.tok.Get(ctx, key)
		if err != nil {
			return store.Membership{}, unavailable(err)
		}
		if len(resp.Kvs) == 0 {
			return store.Membership{}, store.ErrNotFound
		}
		var r membershipRec
		var held store.Membership
		exp := now.Add(store.TombstoneFloor)
		if json.Unmarshal(resp.Kvs[0].Value, &r) != nil || r.Principal != principal {
			held = store.Membership{Principal: principal}
		} else {
			if !alive(r.ExpiresAt, now) || r.tombstone() {
				return store.Membership{}, store.ErrNotFound
			}
			held, exp = r.membership(), laterExp(r.ExpiresAt, exp)
		}
		body, err := json.Marshal(membershipRec{Principal: principal, ForgottenAt: now, ExpiresAt: exp})
		if err != nil {
			return store.Membership{}, err
		}
		ok, err := commit(ctx, s.tok, s.tokLeases, []clientv3.Cmp{unchanged(key, resp.Kvs[0].ModRevision)},
			[]put{{key: key, val: body, exp: exp}})
		if err != nil {
			return store.Membership{}, err
		}
		if ok {
			return held, nil
		}
	}
}

// MembershipByKey answers the one claimant whose live, unrefused record
// lists the key, when the key was not refused after that record's
// verification; none, or more than one, is ErrNotFound.
func (s *Store) MembershipByKey(ctx context.Context, mapKey string) (store.Membership, error) {
	var kr membershipKeyRec
	if err := s.getLive(ctx, s.k.membershipKey(mapKey), &kr, func() bool { return alive(kr.ExpiresAt, s.now()) }); err != nil {
		return store.Membership{}, err
	}
	var found *store.Membership
	for _, c := range kr.Claimants {
		m, err := s.GetMembership(ctx, c)
		switch {
		case errors.Is(err, store.ErrNotFound):
			continue
		case err != nil:
			return store.Membership{}, err
		}
		if m.Refused || !slices.Contains(m.MapKeys, mapKey) {
			continue
		}
		if found != nil {
			return store.Membership{}, store.ErrNotFound
		}
		found = &m
	}
	if found == nil || (!kr.RefusedAt.IsZero() && !found.VerifiedAt.After(kr.RefusedAt)) {
		return store.Membership{}, store.ErrNotFound
	}
	return *found, nil
}

// MembershipPrincipals pages mb/ as eachIndexed pages ix/: 500 at a time,
// a record that does not decode skipped and said.
func (s *Store) MembershipPrincipals(ctx context.Context) ([]string, error) {
	prefix := s.k.family(famMembership)
	end := clientv3.GetPrefixRangeEnd(prefix)
	now := s.now()
	var out []string
	for from := prefix; ; {
		resp, err := s.tok.Get(ctx, from, clientv3.WithRange(end), clientv3.WithLimit(500))
		if err != nil {
			return nil, unavailable(err)
		}
		for _, kv := range resp.Kvs {
			var r membershipRec
			if json.Unmarshal(kv.Value, &r) != nil {
				s.logf("etcd: membership record %q does not decode; it is left out of the list", kv.Key)
				continue
			}
			if alive(r.ExpiresAt, now) && !r.tombstone() {
				out = append(out, r.Principal)
			}
		}
		if !resp.More || len(resp.Kvs) == 0 {
			break
		}
		from = string(resp.Kvs[len(resp.Kvs)-1].Key) + "\x00"
	}
	sort.Strings(out)
	return out, nil
}

// getLive reads key into v on the token pool, ErrNotFound when absent or
// when live() is false once decoded.
func (s *Store) getLive(ctx context.Context, key string, v any, live func() bool) error {
	resp, err := s.tok.Get(ctx, key)
	if err != nil {
		return unavailable(err)
	}
	if len(resp.Kvs) == 0 {
		return store.ErrNotFound
	}
	if json.Unmarshal(resp.Kvs[0].Value, v) != nil {
		return notDecoded(key)
	}
	if !live() {
		return store.ErrNotFound
	}
	return nil
}
