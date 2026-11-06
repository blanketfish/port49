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
// compares, the ledger record (lw/, plan 7e, Ruling 4) and five single
// keys of meta/ (daemonMetaReads); it cannot write a mark, read or write an idempotency
// record (which holds minted tokens), read or write the token indexes or
// the superseded record (sp/, Ruling 9), or write meta/ or the ledger
// record — so a stolen daemon key cannot lift a revocation by principal or
// certificate, delete the keyspace hold (pre-flight I15) or the seal-key
// record, lower the ledger record a start seeds from, or forge a replay's
// superseded instant. That holds for the
// daemon's credential, which port49d holds alone (plan 7e); under
// etcd.roles: unenforced the daemon's is as wide as the broker's. What a stolen daemon
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
// daemonReads and on the keys of daemonMetaReads, nothing on daemonNever
// (spec §12).
var (
	daemonWrites = []string{famToken, famReceipt, famReceiptBy, famContext, famIndexed, famByPrincipal,
		famBySid, famByCert, famBlob}
	daemonReads = []string{famMark, famLedger}
	daemonNever = []string{famIdem, famTokByPrin, famTokByCert, famSuperseded, famMembership, famMembershipK,
		famOnce, famOIDCOwner, famLogout, famMFAProof, famSecondFactor, famSignInAttempts, famUnlock, famLift}
	// daemonMetaReads are the keys of meta/ port49d's code reads, each
	// granted by itself: seal_keys at a start, witness by the
	// restore floor, judged_bundle by the skew gauge (the bundle's name
	// alone, so the policy text in meta/judged stays the broker's), and ping
	// by the store probe.
	daemonMetaReads = []string{"seal_keys", "witness", "judged_bundle", "ping"}
)

// Scope is which of port49's stores a keyspace holds (plan 11a; spec §13
// decision 51, R23).
type Scope int

const (
	// ScopeShared is a single site's one store: every family.
	ScopeShared Scope = iota
	// ScopeDirectory holds the directory's families alone (R11): rv/, rl/
	// (a lift's record, beside the marks it is compared with: decision 51),
	// sf/, ul/, mb/, mk/, lo/, meta/enrollments, meta/seal_keys and
	// meta/ping.
	ScopeDirectory
	// ScopeSession holds every other family.
	ScopeSession
)

// Roles is every grant the two roles need for prefix's keyspace.
func Roles(prefix string) []Grant { return RolesFor(prefix, ScopeShared) }

// RolesFor is every grant the two roles need for a keyspace holding scope's
// families.
func RolesFor(prefix string, scope Scope) []Grant {
	k := newKeys(prefix)
	broker := Grant{Role: RoleBroker, Key: k.root, RangeEnd: clientv3.GetPrefixRangeEnd(k.root), Write: true}
	if scope == ScopeDirectory {
		p := k.family(famMark)
		return []Grant{
			{Role: RoleDaemon, Key: p, RangeEnd: clientv3.GetPrefixRangeEnd(p)},
			{Role: RoleDaemon, Key: k.meta("ping")},
			{Role: RoleDaemon, Key: k.meta("seal_keys")},
			broker,
		}
	}
	reads := daemonReads
	if scope == ScopeSession {
		reads = []string{famLedger}
	}
	var out []Grant
	for _, fam := range daemonWrites {
		p := k.family(fam)
		out = append(out, Grant{Role: RoleDaemon, Key: p, RangeEnd: clientv3.GetPrefixRangeEnd(p), Write: true})
	}
	for _, fam := range reads {
		p := k.family(fam)
		out = append(out, Grant{Role: RoleDaemon, Key: p, RangeEnd: clientv3.GetPrefixRangeEnd(p)})
	}
	for _, name := range daemonMetaReads {
		out = append(out, Grant{Role: RoleDaemon, Key: k.meta(name)}) // the one key: no RangeEnd
	}
	if scope == ScopeSession {
		// A daemon's key holder can neither delete nor replay a broker's
		// record (N1); it has no grant on ds/b/, which holds pins and logout
		// keys (N4).
		out = append(out,
			Grant{Role: RoleDaemon, Key: k.family(snapMarks), RangeEnd: clientv3.GetPrefixRangeEnd(k.family(snapMarks))},
			Grant{Role: RoleDaemon, Key: k.family(snapDaemon), RangeEnd: clientv3.GetPrefixRangeEnd(k.family(snapDaemon)), Write: true})
	}
	return append(out, broker)
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
// daemon's refused, each of reading the idempotency records and the
// superseded record, and writing a mark, the token indexes, an
// idempotency record, a superseded instant, the ledger record and meta/,
// one key in each; and both reading and writing each of the broker's own
// families, ul/ (a person's unlock, plan 11a) and rl/ (a lift's record,
// decision 51) among them. A write is probed by a transaction whose compare can never hold,
// so it writes nothing; etcd checks the permissions of both branches
// before it evaluates the compare, so a missing grant is still refused
// (pre-flight M32; measured on v3.6 by
// TestCheckIdentityRefusesADaemonWithTheBrokersReach).
func (s *Store) CheckIdentity(ctx context.Context, broker bool) error {
	return s.checkIdentityWith(ctx, broker, nil, nil, s.k.beyondDaemon)
}

// probe is one start-check probe: what it tried, and the try.
type probe struct {
	what string
	do   func() error
}

// checkUser refuses an identity that is etcd's root, or one whose etcd
// user cannot be told.
func (s *Store) checkUser() error {
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
	return nil
}

// probeRead reads one key of fam's prefix, keys only.
func (s *Store) probeRead(ctx context.Context, fam string) error {
	_, err := s.tok.Get(ctx, s.k.family(fam), clientv3.WithPrefix(), clientv3.WithLimit(1), clientv3.WithKeysOnly())
	return unavailable(err)
}

// probeWrite is a write under fam that writes nothing (see CheckIdentity).
func (s *Store) probeWrite(ctx context.Context, fam string) error {
	key := s.k.family(fam) + "_probe"
	_, err := s.tok.Txn(ctx).If(clientv3.Compare(clientv3.CreateRevision(key), "<", 0)).
		Then(clientv3.OpPut(key, "")).Commit()
	return unavailable(err)
}

// ErrMissingGrant is a broker's start refused for one grant its role
// lacks, which the refusal names as an etcdctl line: an upgrade's new
// family on a role granted family by family (task 2 review I2).
var ErrMissingGrant = errors.New("the broker's role lacks a grant")

// liftGrant is do, a probe of the lift records (rl/, post-11b), whose
// refusal names the grant: readwrite, whichever of the two was refused, so
// one restart after it is enough (task 2 review I2).
func (s *Store) liftGrant(do func() error) func() error {
	return func() error {
		err := do()
		if errors.Is(err, ErrRefused) {
			fam := s.k.family(famLift)
			return fmt.Errorf("%w; %w: readwrite on %s, the lift records: etcdctl role grant-permission %s readwrite "+
				"--prefix=true %s ('port49d store-roles' output grants it)", err, ErrMissingGrant, fam, RoleBroker, fam)
		}
		return err
	}
}

// judgeProbes runs probes: the broker's must answer, the daemon's must be
// refused.
func judgeProbes(broker bool, probes []probe) error {
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

// checkIdentityWith is CheckIdentity's checks for a keyspace whose extra
// requirements are need (both identities must answer) and judged (the
// broker's must answer, the daemon's be refused), with beyond judging the
// daemon's grants.
func (s *Store) checkIdentityWith(ctx context.Context, broker bool, need, judged []probe,
	beyond func(key, end string, write bool) string) error {
	if err := s.checkUser(); err != nil {
		return err
	}
	if err := s.probeRead(ctx, famContext); err != nil {
		return fmt.Errorf("reading %s: %w", s.k.family(famContext), err)
	}
	for _, p := range need {
		if err := p.do(); err != nil {
			return fmt.Errorf("%s: %w", p.what, err)
		}
	}
	probes := []probe{
		{"reading " + s.k.family(famIdem), func() error { return s.probeRead(ctx, famIdem) }},
		{"writing " + s.k.family(famIdem), func() error { return s.probeWrite(ctx, famIdem) }},
		{"writing " + s.k.family(famMark), func() error { return s.probeWrite(ctx, famMark) }},
		{"writing " + s.k.family(famLift), s.liftGrant(func() error { return s.probeWrite(ctx, famLift) })},
		{"reading " + s.k.family(famLift), s.liftGrant(func() error { return s.probeRead(ctx, famLift) })},
		{"writing " + s.k.family(famTokByPrin), func() error { return s.probeWrite(ctx, famTokByPrin) }},
		{"writing " + s.k.family(famTokByCert), func() error { return s.probeWrite(ctx, famTokByCert) }},
		{"reading " + s.k.family(famSuperseded), func() error { return s.probeRead(ctx, famSuperseded) }},
		{"writing " + s.k.family(famSuperseded), func() error { return s.probeWrite(ctx, famSuperseded) }},
		{"reading " + s.k.family(famMembership), func() error { return s.probeRead(ctx, famMembership) }},
		{"writing " + s.k.family(famMembership), func() error { return s.probeWrite(ctx, famMembership) }},
		{"reading " + s.k.family(famMembershipK), func() error { return s.probeRead(ctx, famMembershipK) }},
		{"writing " + s.k.family(famMembershipK), func() error { return s.probeWrite(ctx, famMembershipK) }},
		{"reading " + s.k.family(famOnce), func() error { return s.probeRead(ctx, famOnce) }},
		{"writing " + s.k.family(famOnce), func() error { return s.probeWrite(ctx, famOnce) }},
		{"reading " + s.k.family(famOIDCOwner), func() error { return s.probeRead(ctx, famOIDCOwner) }},
		{"writing " + s.k.family(famOIDCOwner), func() error { return s.probeWrite(ctx, famOIDCOwner) }},
		{"reading " + s.k.family(famLogout), func() error { return s.probeRead(ctx, famLogout) }},
		{"writing " + s.k.family(famLogout), func() error { return s.probeWrite(ctx, famLogout) }},
		{"reading " + s.k.family(famMFAProof), func() error { return s.probeRead(ctx, famMFAProof) }},
		{"writing " + s.k.family(famMFAProof), func() error { return s.probeWrite(ctx, famMFAProof) }},
		{"reading " + s.k.family(famSecondFactor), func() error { return s.probeRead(ctx, famSecondFactor) }},
		{"writing " + s.k.family(famSecondFactor), func() error { return s.probeWrite(ctx, famSecondFactor) }},
		{"reading " + s.k.family(famSignInAttempts), func() error { return s.probeRead(ctx, famSignInAttempts) }},
		{"writing " + s.k.family(famSignInAttempts), func() error { return s.probeWrite(ctx, famSignInAttempts) }},
		{"reading " + s.k.family(famUnlock), func() error { return s.probeRead(ctx, famUnlock) }},
		{"writing " + s.k.family(famUnlock), func() error { return s.probeWrite(ctx, famUnlock) }},
		{"writing " + s.k.family(famLedger), func() error { return s.probeWrite(ctx, famLedger) }},
		{"writing " + s.k.family(famMeta), func() error { return s.probeWrite(ctx, famMeta) }},
		{"reading " + s.k.meta("judged"), func() error {
			_, err := s.tok.Get(ctx, s.k.meta("judged"), clientv3.WithKeysOnly())
			return unavailable(err)
		}},
	}
	if err := judgeProbes(broker, append(probes, judged...)); err != nil {
		return err
	}
	return s.checkGrantsWith(ctx, broker, beyond)
}

// checkGrantsWith reads this identity's roles and, for the daemon, their
// permissions. AuthStatus is root's alone on v3.6, so auth being off is
// read from the user being unknown: with auth on, a request as a user
// etcd does not know is refused before this, at the probes. With auth
// off the probes have refused the daemon already, and the broker's reach
// is the keyspace's either way.
func (s *Store) checkGrantsWith(ctx context.Context, broker bool, beyond func(key, end string, write bool) string) error {
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
			if why := beyond(string(p.Key), string(p.RangeEnd), p.PermType != authpb.READ); why != "" {
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

// CheckIdentityAt is CheckIdentity for a keyspace holding scope's families
// (R23). A shared keyspace is checked as CheckIdentity checks one; a session
// keyspace too, where both identities read the marks snapshot records and
// write port49d's own, and the daemon's is refused writing another's or
// reading a broker's (R19; N1, N4). On a
// directory keyspace both identities read the marks and meta/seal_keys; the
// daemon's is refused writing a mark, a lift's record, meta/, a second
// factor, an unlock, a pin, a map key or a logout, and reading a lift's
// record, a second factor, an unlock, a pin, a map key, a logout or
// meta/enrollments; and its grants reach rv/,
// meta/ping and meta/seal_keys alone (beyondDirectoryDaemon).
func (s *Store) CheckIdentityAt(ctx context.Context, broker bool, scope Scope) error {
	switch scope {
	case ScopeShared:
		return s.CheckIdentity(ctx, broker)
	case ScopeSession:
		return s.checkIdentityWith(ctx, broker, []probe{
			{"reading " + s.k.family(snapMarks), func() error { return s.probeRead(ctx, snapMarks) }},
			{"writing " + s.k.family(snapDaemon), func() error { return s.probeWrite(ctx, snapDaemon) }},
		}, []probe{
			{"writing " + s.k.family(snapMarks) + "port49-broker@", func() error {
				return s.probeWrite(ctx, snapMarks+"port49-broker@")
			}},
			{"reading " + s.k.family(snapBroker), func() error { return s.probeRead(ctx, snapBroker) }},
		}, s.k.beyondSessionDaemon)
	}
	if err := s.checkUser(); err != nil {
		return err
	}
	if err := s.probeRead(ctx, famMark); err != nil {
		return fmt.Errorf("reading %s: %w", s.k.family(famMark), err)
	}
	if _, err := s.tok.Get(ctx, s.k.meta("seal_keys"), clientv3.WithKeysOnly()); err != nil {
		return fmt.Errorf("reading %s: %w", s.k.meta("seal_keys"), unavailable(err))
	}
	probes := []probe{
		{"writing " + s.k.family(famMark), func() error { return s.probeWrite(ctx, famMark) }},
		{"writing " + s.k.family(famLift), s.liftGrant(func() error { return s.probeWrite(ctx, famLift) })},
		{"reading " + s.k.family(famLift), s.liftGrant(func() error { return s.probeRead(ctx, famLift) })},
		{"reading " + s.k.family(famMembership), func() error { return s.probeRead(ctx, famMembership) }},
		{"writing " + s.k.family(famMembership), func() error { return s.probeWrite(ctx, famMembership) }},
		{"reading " + s.k.family(famMembershipK), func() error { return s.probeRead(ctx, famMembershipK) }},
		{"writing " + s.k.family(famMembershipK), func() error { return s.probeWrite(ctx, famMembershipK) }},
		{"reading " + s.k.family(famLogout), func() error { return s.probeRead(ctx, famLogout) }},
		{"writing " + s.k.family(famLogout), func() error { return s.probeWrite(ctx, famLogout) }},
		{"reading " + s.k.family(famSecondFactor), func() error { return s.probeRead(ctx, famSecondFactor) }},
		{"writing " + s.k.family(famSecondFactor), func() error { return s.probeWrite(ctx, famSecondFactor) }},
		{"reading " + s.k.family(famUnlock), func() error { return s.probeRead(ctx, famUnlock) }},
		{"writing " + s.k.family(famUnlock), func() error { return s.probeWrite(ctx, famUnlock) }},
		{"writing " + s.k.family(famMeta), func() error { return s.probeWrite(ctx, famMeta) }},
		{"reading " + s.k.enrollmentMark(), func() error {
			_, err := s.tok.Get(ctx, s.k.enrollmentMark(), clientv3.WithKeysOnly())
			return unavailable(err)
		}},
	}
	if err := judgeProbes(broker, probes); err != nil {
		return err
	}
	return s.checkGrantsWith(ctx, broker, s.k.beyondDirectoryDaemon)
}

// beyondDirectoryDaemon says what a grant on [key, end) reaches that the
// daemon's role on a directory keyspace may not: any write, or a read past
// rv/, meta/ping and meta/seal_keys. An empty end is the one key. A grant
// that does not reach the keyspace is not judged: two keyspaces on one
// cluster share role names (R23).
func (k keys) beyondDirectoryDaemon(key, end string, write bool) string {
	rootEnd := clientv3.GetPrefixRangeEnd(k.root)
	var reaches bool
	switch end {
	case "": // the one key
		reaches = key >= k.root && key < rootEnd
	case "\x00": // every key from key on
		reaches = key < rootEnd
	default:
		reaches = key < rootEnd && end > k.root
	}
	if !reaches {
		return "" // another keyspace's grant, on a cluster both share
	}
	if write {
		return "writes the directory store, which the broker alone writes"
	}
	marks := k.family(famMark)
	switch {
	case (key == k.meta("ping") || key == k.meta("seal_keys")) && end == "":
		return ""
	case key >= marks && end != "" && end != "\x00" && end <= clientv3.GetPrefixRangeEnd(marks):
		return ""
	}
	return "reads past rv/, meta/ping and meta/seal_keys"
}

// beyondSessionDaemon is beyondDaemon on a session keyspace: the same, but
// a read within ds/m/ and a write within ds/m/port49d@ are the daemon's
// own (R19; N1), and any other grant that reaches into ds/ is refused by
// name (N4): a read of a broker's record would hand the daemon the pins and
// logout keys mb/ and lo/ keep from it.
func (k keys) beyondSessionDaemon(key, end string, write bool) string {
	within := func(fam string) bool {
		p := k.family(fam)
		return key >= p && end != "" && end != "\x00" && end <= clientv3.GetPrefixRangeEnd(p)
	}
	if within(snapDaemon) || !write && within(snapMarks) {
		return ""
	}
	ds := k.family(famSnapshot)
	last := end
	if last == "" {
		last = key + "\x00" // the one key
	}
	if key < clientv3.GetPrefixRangeEnd(ds) && (end == "\x00" || last > ds) {
		return "reaches into ds/ past the marks records (ds/m/) and its own (ds/m/port49d@): a broker's " +
			"snapshot records (ds/b/) hold pins and logout keys the daemon must not read"
	}
	return k.beyondDaemon(key, end, write)
}
