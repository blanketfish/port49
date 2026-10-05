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
// grace bind may use: ambiguous (Claimants names every principal that
// claimed it; a read answers the one still listing it, if exactly one) or
// Refused, which keeps the claimants it replaced and any claim older than
// it, so a later claim cannot take the key while another live record still
// lists it.
type membershipKeyRec struct {
	Principal  string    `json:"principal"`
	Claimants  []string  `json:"claimants,omitempty"`
	Refused    bool      `json:"refused,omitempty"`
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
			if found && !r.tombstone() && (r.VerifiedAt.After(m.VerifiedAt) ||
				(r.VerifiedAt.Equal(m.VerifiedAt) && r.Refused && !m.Refused)) { // a refusal outranks a grant at its instant
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

// claimKey points key at principal as of at, unless a live, unrefused
// record of another principal still lists it, whichever verification is
// later: then the key is ambiguous and names every claimant (pre-flight
// I-5), never the last writer's. A later refusal, or a later claim by
// principal itself, stands.
func (s *Store) claimKey(ctx context.Context, key, principal string, at, exp, now time.Time) error {
	return cas(ctx, s.tok, s.tokLeases, s.k.membershipKey(key),
		func(r membershipKeyRec) bool { return r.ExpiresAt.After(now) },
		func(r *membershipKeyRec, found bool) (bool, time.Time, bool, error) {
			if found {
				if r.Refused && !r.VerifiedAt.Before(at) {
					// The refusal stands, and remembers this claimant too.
					if slices.Contains(r.Claimants, principal) {
						return false, time.Time{}, false, nil
					}
					r.Claimants = append(r.Claimants, principal)
					sort.Strings(r.Claimants)
					r.ExpiresAt = laterOf(r.ExpiresAt, exp)
					return true, r.ExpiresAt, false, nil
				}
				var others []string
				for _, c := range append([]string{r.Principal}, r.Claimants...) {
					if c == "" || c == principal || slices.Contains(others, c) {
						continue
					}
					lists, err := s.claimsKey(ctx, c, key)
					if err != nil {
						return false, time.Time{}, false, err
					}
					if lists {
						others = append(others, c)
					}
				}
				if len(others) > 0 {
					others = append(others, principal)
					sort.Strings(others)
					*r = membershipKeyRec{Claimants: others, VerifiedAt: laterOf(r.VerifiedAt, at),
						ExpiresAt: laterOf(r.ExpiresAt, exp)}
					return true, r.ExpiresAt, false, nil
				}
				if r.Principal == principal && r.VerifiedAt.After(at) {
					return false, time.Time{}, false, nil
				}
				at = laterOf(r.VerifiedAt, at)
			}
			*r = membershipKeyRec{Principal: principal, VerifiedAt: at, ExpiresAt: exp}
			return true, exp, false, nil
		})
}

func laterOf(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
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
				refused := membershipKeyRec{Refused: true, VerifiedAt: at, ExpiresAt: exp}
				if found {
					refused.Claimants = slices.Clone(r.Claimants)
					if r.Principal != "" {
						refused.Claimants = append(refused.Claimants, r.Principal)
						sort.Strings(refused.Claimants)
					}
					refused.ExpiresAt = laterOf(r.ExpiresAt, exp)
				}
				*r = refused
				return true, refused.ExpiresAt, false, nil
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
	if r.Principal != principal {
		return store.Membership{}, notDecoded(s.k.membership(principal)) // a record copied under another key
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
// (at least store.TombstoneFloor): PutMembership drops a write verified before
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
		exp := now.Add(store.TombstoneFloor)
		if json.Unmarshal(resp.Kvs[0].Value, &r) != nil || r.Principal != principal {
			held = store.Membership{Principal: principal}
		} else {
			if !r.ExpiresAt.After(now) || r.tombstone() {
				return store.Membership{}, store.ErrNotFound
			}
			held, exp = r.membership(), laterOf(r.ExpiresAt, exp)
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

// MembershipByKey answers the one principal a key points at, or, for an
// ambiguous key, the one of its claimants that still lists it; none or more
// than one is ErrNotFound.
func (s *Store) MembershipByKey(ctx context.Context, mapKey string) (store.Membership, error) {
	var kr membershipKeyRec
	if err := s.getLive(ctx, s.k.membershipKey(mapKey), &kr, func() bool { return kr.ExpiresAt.After(s.now()) }); err != nil {
		return store.Membership{}, err
	}
	if kr.Refused {
		return store.Membership{}, store.ErrNotFound
	}
	cands := kr.Claimants
	if kr.Principal != "" {
		cands = []string{kr.Principal}
	}
	var found *store.Membership
	for _, c := range cands {
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
	if found == nil {
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
