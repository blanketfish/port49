package etcd

import (
	"context"
	"errors"
	"fmt"

	"go.etcd.io/etcd/api/v3/authpb"
	"go.etcd.io/etcd/api/v3/v3rpc/rpctypes"
	clientv3 "go.etcd.io/etcd/client/v3"
)

// The roles port49 runs under on etcd (plan 7d, Ruling 10; spec §12 and
// §13, decision 35). The daemon reads and writes what a login, an
// authorization and accounting touch, and reads the marks a login
// compares and the keyspace's meta records; it cannot write a mark, read
// or write an idempotency record (which holds minted tokens), read or
// write the token indexes, or write meta/ — so a stolen daemon key cannot
// lift a revocation by principal or certificate, or delete the keyspace
// hold (pre-flight I15) or the seal-key record. That holds for the
// daemon's credential taken alone: until plan 7e port49d also holds the
// broker's, whose role is the whole keyspace, marks included, and under
// store.etcd.roles: unenforced the daemon's is too. What a stolen daemon
// key can still do to a token, a receipt or a context is bounded by the
// seals, the ledger and the marks, record family by record family
// (Ruling 17's table).
const (
	RoleDaemon = "port49_daemon"
	RoleBroker = "port49_broker"
)

// Grant is one role permission over [Key, RangeEnd).
type Grant struct {
	Role, Key, RangeEnd string
	Write               bool
}

// The daemon's families: read-write on daemonWrites, read-only on
// daemonReads, nothing on daemonNever (spec §12).
var (
	daemonWrites = []string{famToken, famReceipt, famReceiptBy, famContext, famIndexed, famByPrincipal,
		famBySid, famByCert, famBlob}
	daemonReads = []string{famMark, famMeta}
	daemonNever = []string{famIdem, famTokByPrin, famTokByCert, famSuperseded}
)

// Roles is every grant the two roles need for prefix's keyspace.
func Roles(prefix string) []Grant {
	k := newKeys(prefix)
	var out []Grant
	for _, fam := range daemonWrites {
		p := k.family(fam)
		out = append(out, Grant{Role: RoleDaemon, Key: p, RangeEnd: clientv3.GetPrefixRangeEnd(p), Write: true})
	}
	for _, fam := range daemonReads {
		p := k.family(fam)
		out = append(out, Grant{Role: RoleDaemon, Key: p, RangeEnd: clientv3.GetPrefixRangeEnd(p)})
	}
	out = append(out, Grant{Role: RoleBroker, Key: k.root, RangeEnd: clientv3.GetPrefixRangeEnd(k.root), Write: true})
	return out
}

// RootUser is etcd's administrator, user and role alike. A store
// identity that is root bypasses every role, so neither component may be
// (Ruling T11-a).
const RootUser = "root"

// ErrNotSeparated is a store identity reaching past its role: the
// daemon's able to do what only the broker's may, either one etcd's root,
// or one whose etcd user cannot be read. etcd's roles for port49 are not
// in force.
var ErrNotSeparated = errors.New("etcd: a store identity reaches past its role")

// CheckIdentity is port49d's start check that the roles are in force.
// Neither identity may be etcd's root, by its certificate's CN or by
// holding the root role. Both must read the contexts.
//
// For the daemon, the authoritative check is its own grants, read with
// UserGet on itself and RoleGet on each of its roles: a grant of any kind
// that reaches an idempotency record or a token index, and a write grant
// that reaches a mark or meta/ or falls outside the daemon's nine
// families, is refused whatever its range. A grant on a sub-range is
// added to what a role holds, so sampling keys would miss one (task 11
// review I1).
//
// The probes are the backstop, chiefly for auth being off, when etcd
// has no grants to read: the broker's identity must be allowed, and the
// daemon's refused, each of reading the idempotency records and writing
// a mark, the token indexes, an idempotency record and meta/, one key in
// each. A write is probed by a transaction whose compare can never hold,
// so it writes nothing; etcd checks the permissions of both branches
// before it evaluates the compare, so a missing grant is still refused
// (pre-flight M32; measured on v3.6 by
// TestCheckIdentityRefusesADaemonWithTheBrokersReach).
func (s *Store) CheckIdentity(ctx context.Context, broker bool) error {
	switch {
	case s.user == RootUser:
		return fmt.Errorf("%w: its certificate's CN is %q, etcd's administrator", ErrNotSeparated, RootUser)
	case s.user == "" && !s.clear:
		// A certificate from GetClientCertificate, or one that does not
		// parse: etcd knows the user, port49 cannot read its grants (task
		// 11 re-review N1).
		return fmt.Errorf("%w: cannot tell which etcd user this identity is, so its grants go unread",
			ErrNotSeparated)
	}
	read := func(fam string) error {
		_, err := s.tok.Get(ctx, s.k.family(fam), clientv3.WithPrefix(), clientv3.WithLimit(1), clientv3.WithKeysOnly())
		return unavailable(err)
	}
	write := func(fam string) error {
		key := s.k.family(fam) + "_probe"
		_, err := s.tok.Txn(ctx).If(clientv3.Compare(clientv3.CreateRevision(key), "<", 0)).
			Then(clientv3.OpPut(key, "")).Commit()
		return unavailable(err)
	}
	if err := read(famContext); err != nil {
		return fmt.Errorf("reading %s: %w", s.k.family(famContext), err)
	}
	probes := []struct {
		what string
		do   func() error
	}{
		{"reading " + s.k.family(famIdem), func() error { return read(famIdem) }},
		{"writing " + s.k.family(famIdem), func() error { return write(famIdem) }},
		{"writing " + s.k.family(famMark), func() error { return write(famMark) }},
		{"writing " + s.k.family(famTokByPrin), func() error { return write(famTokByPrin) }},
		{"writing " + s.k.family(famTokByCert), func() error { return write(famTokByCert) }},
		{"writing " + s.k.family(famMeta), func() error { return write(famMeta) }},
	}
	for _, p := range probes {
		err := p.do()
		switch {
		case broker && err != nil:
			return fmt.Errorf("%s: %w", p.what, err)
		case !broker && err == nil:
			return fmt.Errorf("%w: it was allowed %s", ErrNotSeparated, p.what)
		case !broker && !errors.Is(err, ErrRefused):
			return fmt.Errorf("%s: %w", p.what, err) // an outage: the start waits
		}
	}
	return s.checkGrants(ctx, broker)
}

// checkGrants reads this identity's roles and, for the daemon, their
// permissions. AuthStatus is root's alone on v3.6, so auth being off is
// read from the user being unknown: with auth on, a request as a user
// etcd does not know is refused before this, at the probes. With auth
// off the probes have refused the daemon already, and the broker's reach
// is the keyspace's either way.
func (s *Store) checkGrants(ctx context.Context, broker bool) error {
	if s.user == "" {
		return nil // in the clear (CheckIdentity refused "" otherwise): auth cannot be on
	}
	u, err := s.tok.UserGet(ctx, s.user)
	if errors.Is(err, rpctypes.ErrUserNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("reading user %q's roles: %w", s.user, unavailable(err))
	}
	for _, role := range u.Roles {
		if role == RootUser {
			return fmt.Errorf("%w: user %q holds etcd's root role", ErrNotSeparated, s.user)
		}
		if broker {
			continue
		}
		r, err := s.tok.RoleGet(ctx, role)
		if err != nil {
			return fmt.Errorf("reading role %q's grants: %w", role, unavailable(err))
		}
		for _, p := range r.Perm {
			if why := s.k.beyondDaemon(string(p.Key), string(p.RangeEnd), p.PermType != authpb.READ); why != "" {
				return fmt.Errorf("%w: role %q grants %s on [%q, %q), which %s", ErrNotSeparated, role,
					authpb.Permission_Type_name[int32(p.PermType)], p.Key, p.RangeEnd, why)
			}
		}
	}
	return nil
}

// beyondDaemon says what a grant on etcd's [key, end) reaches that the
// daemon's role may not, or "" when nothing. An empty end is the one key;
// an end of "\x00" is every key from key on.
func (k keys) beyondDaemon(key, end string, write bool) string {
	switch end {
	case "":
		end = key + "\x00"
	case "\x00":
		end = "" // unbounded
	}
	overlaps := func(fam string) bool {
		f := k.family(fam)
		return key < clientv3.GetPrefixRangeEnd(f) && (end == "" || f < end)
	}
	for _, fam := range daemonNever {
		if overlaps(fam) {
			return "reaches " + k.family(fam)
		}
	}
	if !write {
		return ""
	}
	// A write must fall inside one family the daemon writes, which keeps
	// it off the marks and meta/ as well.
	for _, fam := range daemonWrites {
		f := k.family(fam)
		if key >= f && end != "" && end <= clientv3.GetPrefixRangeEnd(f) {
			return ""
		}
	}
	return "writes outside the families the daemon writes"
}
