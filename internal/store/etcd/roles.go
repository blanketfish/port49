package etcd

import (
	"context"
	"errors"
	"fmt"

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

// Roles is every grant the two roles need for prefix's keyspace.
func Roles(prefix string) []Grant {
	k := newKeys(prefix)
	var out []Grant
	for _, fam := range []string{famToken, famReceipt, famReceiptBy, famContext, famIndexed, famByPrincipal,
		famBySid, famByCert, famBlob} {
		p := k.family(fam)
		out = append(out, Grant{Role: RoleDaemon, Key: p, RangeEnd: clientv3.GetPrefixRangeEnd(p), Write: true})
	}
	for _, fam := range []string{famMark, famMeta} {
		p := k.family(fam)
		out = append(out, Grant{Role: RoleDaemon, Key: p, RangeEnd: clientv3.GetPrefixRangeEnd(p)})
	}
	out = append(out, Grant{Role: RoleBroker, Key: k.root, RangeEnd: clientv3.GetPrefixRangeEnd(k.root), Write: true})
	return out
}

// ErrNotSeparated is the daemon's identity able to do what only the
// broker's may: etcd's roles for port49 are not in force.
var ErrNotSeparated = errors.New("etcd: the daemon's identity has the broker's reach")

// CheckIdentity is port49d's start check that the roles are in force.
// Both identities must read the contexts. The broker's must be allowed,
// and the daemon's refused, each of: reading the idempotency records, and
// writing a mark, the token indexes, an idempotency record and meta/. A
// write is probed by a transaction whose compare can never hold, so it
// writes nothing; etcd checks the permissions of both branches before it
// evaluates the compare, so a missing grant is still refused (pre-flight
// M32; measured on v3.6 by TestCheckIdentityRefusesADaemonWithTheBrokersReach).
func (s *Store) CheckIdentity(ctx context.Context, broker bool) error {
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
	return nil
}
