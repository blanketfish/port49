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

// membershipKeyRec is mk/<map key>: the principal, and the verification
// that pointed it there, so a later one wins. Principal "" is a key no
// grace bind may use: ambiguous (Prior names the principal whose live
// record still claims it) or refused (Prior "").
type membershipKeyRec struct {
	Principal  string    `json:"principal"`
	Prior      string    `json:"prior,omitempty"`
	VerifiedAt time.Time `json:"verified_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// PutMembership keeps the later verification at mb/, by a compare on the
// record's revision, then claims each key the same way. The two are not
// one transaction: a reader finding a key whose record no longer lists it
// is answered ErrNotFound (MembershipByKey), so a torn write is a miss,
// never another principal's membership.
func (s *Store) PutMembership(ctx context.Context, m store.Membership, ttl time.Duration) error {
	now := s.now()
	exp := now.Add(ttl)
	kept := false
	err := cas(ctx, s.tok, s.tokLeases, s.k.membership(m.Principal),
		func(r membershipRec) bool { return r.ExpiresAt.After(now) },
		func(r *membershipRec, found bool) (bool, time.Time, bool, error) {
			if found && r.tombstone() && m.VerifiedAt.Before(r.ForgottenAt) {
				kept = true // verified before the forget: never writes the old pin back
				return false, time.Time{}, false, nil
			}
			if found && !r.tombstone() && r.VerifiedAt.After(m.VerifiedAt) {
				kept = true
				return false, time.Time{}, false, nil
			}
			*r = membershipRec{Principal: m.Principal, DN: m.DN, EntryID: m.EntryID, Username: m.Username, GroupDNs: m.GroupDNs,
				GroupNames: m.GroupNames, MapKeys: m.MapKeys, Refused: m.Refused, VerifiedAt: m.VerifiedAt,
				Server: m.Server, Site: m.Site, Sealed: m.Sealed, ExpiresAt: exp}
			return true, exp, false, nil
		})
	if err != nil || kept {
		return err
	}
	for _, key := range m.MapKeys {
		if err := s.claimKey(ctx, key, m.Principal, m.VerifiedAt, exp, now); err != nil {
			return err
		}
	}
	return nil
}

// claimKey points key at principal as of at, unless a later verification
// holds it, or a live record of another principal still lists it: then the
// key is ambiguous (pre-flight I-5), never the last writer's.
func (s *Store) claimKey(ctx context.Context, key, principal string, at, exp, now time.Time) error {
	return cas(ctx, s.tok, s.tokLeases, s.k.membershipKey(key),
		func(r membershipKeyRec) bool { return r.ExpiresAt.After(now) },
		func(r *membershipKeyRec, found bool) (bool, time.Time, bool, error) {
			if found && r.VerifiedAt.After(at) {
				return false, time.Time{}, false, nil
			}
			other := ""
			if found && r.Principal != principal {
				other = r.Principal
				if other == "" {
					other = r.Prior
				}
			}
			if other != "" {
				held, err := s.GetMembership(ctx, other)
				switch {
				case err == nil && !held.Refused && slices.Contains(held.MapKeys, key):
					*r = membershipKeyRec{Principal: "", Prior: other, VerifiedAt: at, ExpiresAt: exp}
					return true, exp, false, nil
				case err != nil && !errors.Is(err, store.ErrNotFound):
					return false, time.Time{}, false, err
				}
			}
			*r = membershipKeyRec{Principal: principal, VerifiedAt: at, ExpiresAt: exp}
			return true, exp, false, nil
		})
}

// RefuseMapKeys marks each key refused as of at (Ruling 10): the
// directory answered no for it, and grace must not answer yes.
func (s *Store) RefuseMapKeys(ctx context.Context, mapKeys []string, at time.Time, ttl time.Duration) error {
	now := s.now()
	exp := now.Add(ttl)
	for _, key := range mapKeys {
		if err := cas(ctx, s.tok, s.tokLeases, s.k.membershipKey(key),
			func(r membershipKeyRec) bool { return r.ExpiresAt.After(now) },
			func(r *membershipKeyRec, found bool) (bool, time.Time, bool, error) {
				if found && r.VerifiedAt.After(at) {
					return false, time.Time{}, false, nil
				}
				*r = membershipKeyRec{VerifiedAt: at, ExpiresAt: exp}
				return true, exp, false, nil
			}); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) GetMembership(ctx context.Context, principal string) (store.Membership, error) {
	var r membershipRec
	if err := s.getLive(ctx, s.k.membership(principal), &r, func() bool { return r.ExpiresAt.After(s.now()) }); err != nil {
		return store.Membership{}, err
	}
	if r.tombstone() {
		return store.Membership{}, store.ErrNotFound
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
// (a day when that is unknown): PutMembership drops a write verified before
// it, so a verification in flight at the forget cannot put the pin back.
// Its mk/ keys stay until their leases end: MembershipByKey answers
// ErrNotFound for a key whose record is gone, and claimKey treats it as
// unclaimed. A record that does not decode is replaced all the same and
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
		exp := now.Add(unknownTombstoneFor)
		if json.Unmarshal(resp.Kvs[0].Value, &r) != nil {
			held = store.Membership{Principal: principal}
		} else {
			if !r.ExpiresAt.After(now) || r.tombstone() {
				return store.Membership{}, store.ErrNotFound
			}
			held, exp = r.membership(), r.ExpiresAt
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

// unknownTombstoneFor is a forget's tombstone over a record that does not
// decode, so has no expiry to follow.
const unknownTombstoneFor = 24 * time.Hour

func (s *Store) MembershipByKey(ctx context.Context, mapKey string) (store.Membership, error) {
	var kr membershipKeyRec
	if err := s.getLive(ctx, s.k.membershipKey(mapKey), &kr, func() bool { return kr.ExpiresAt.After(s.now()) }); err != nil {
		return store.Membership{}, err
	}
	if kr.Principal == "" {
		return store.Membership{}, store.ErrNotFound
	}
	m, err := s.GetMembership(ctx, kr.Principal)
	if err != nil {
		return store.Membership{}, err
	}
	if m.Refused || !slices.Contains(m.MapKeys, mapKey) {
		return store.Membership{}, store.ErrNotFound
	}
	return m, nil
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
			if r.ExpiresAt.After(now) && !r.tombstone() {
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
