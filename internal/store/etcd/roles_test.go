package etcd

import (
	"context"
	"crypto/tls"
	"errors"
	"strings"
	"testing"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/etcd/etcdtest"
)

// provisioned is a TLS member with auth on and port49's roles applied
// for prefix: users port49-daemon and port49-broker.
func provisioned(t *testing.T, prefix string) *etcdtest.Server {
	return provisionedWith(t, prefix, nil, nil)
}

// provisionedWith is provisioned with extra grants after port49's, and
// users overriding port49's two.
func provisionedWith(t *testing.T, prefix string, extra []etcdtest.Grant, users map[string][]string) *etcdtest.Server {
	srv := etcdtest.Start(t, etcdtest.Options{TLS: true})
	var grants []etcdtest.Grant
	for _, g := range Roles(prefix) {
		grants = append(grants, etcdtest.Grant{Role: g.Role, Key: g.Key, RangeEnd: g.RangeEnd, Write: g.Write})
	}
	all := map[string][]string{"port49-daemon": {RoleDaemon}, "port49-broker": {RoleBroker}}
	for u, rs := range users {
		all[u] = rs
	}
	srv.EnableAuth(t, append(grants, extra...), all)
	return srv
}

func openAs(t *testing.T, srv *etcdtest.Server, cn, prefix string) *Store {
	s, err := Open(Config{Endpoints: []string{srv.Endpoint}, TLS: srv.TLS(t, cn), Prefix: prefix,
		Now: func() time.Time { return t0 }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// Under port49's roles, each component does its own work and the daemon
// cannot do the broker's: it redeems, writes contexts and reads marks; it
// cannot write, overwrite or lift a mark, read an idempotency record or
// write the token index (Ruling 10).
func TestTheRolesSeparateTheComponents(t *testing.T) {
	const prefix = "/port49/"
	srv := provisioned(t, prefix)
	ctx := context.Background()
	d, b := openAs(t, srv, "port49-daemon", prefix), openAs(t, srv, "port49-broker", prefix)

	k := store.TokenKey{NAS: "leaf-01", Username: "alice"}
	if err := b.IndexToken(ctx, "user:alice", "", k, time.Minute); err != nil {
		t.Fatalf("the broker indexes a token: %v", err)
	}
	if _, err := b.PutToken(ctx, k, store.Token{ID: "t", Secret: []byte("s"), Kind: store.KindLogin,
		ExpiresAt: t0.Add(time.Minute)}); err != nil {
		t.Fatalf("the broker mints: %v", err)
	}
	if err := b.PutRevocation(ctx, store.Revocation{Kind: store.RevocationPrincipal, Key: "user:bob", At: t0}); err != nil {
		t.Fatalf("the broker marks: %v", err)
	}
	w := store.ReceiptWrite{Key: store.ReceiptKey{NAS: "leaf-01", Username: "alice", Kind: store.KindLogin},
		Receipt: store.Receipt{RetainUntil: t0.Add(time.Hour)}, Principal: "user:alice", IndexTTL: time.Hour}
	if err := d.RedeemAndReceipt(ctx, k, "t", w); err != nil {
		t.Fatalf("the daemon redeems: %v", err)
	}
	login := store.Context{CtxID: "c", Principal: "user:alice", Username: "alice", AuthTime: t0, RefreshedAt: t0}
	if _, err := store.JoinContext(ctx, d, store.ContextKey{NAS: "leaf-01", Username: "alice"}, login, t0, t0,
		time.Hour, store.LoginIndex{Principal: "user:alice", TTL: time.Hour}); err != nil {
		t.Fatalf("the daemon writes a login, comparing the marks: %v", err)
	}
	if _, err := d.ListRevocations(ctx); err != nil {
		t.Fatalf("the daemon reads the marks: %v", err)
	}
	lk := store.ContextKey{NAS: "leaf-01", Username: "alice"}
	if _, err := b.PutLedgerMarks(ctx, []store.LedgerMark{{Key: lk, Seq: 10}}); err != nil {
		t.Fatalf("the broker writes the ledger record: %v", err)
	}
	if _, ms, err := d.LedgerMarks(ctx); err != nil || len(ms) != 1 || ms[0].Seq != 10 {
		t.Fatalf("the daemon reads the ledger record: %+v %v", ms, err)
	}
	if _, _, err := b.NoteSignInAttempt(ctx, "principal:user:alice", time.Minute); err != nil {
		t.Fatalf("the broker counts a sign-in attempt: %v", err)
	}
	if err := b.CreateEnrollmentMark(ctx, store.EnrollmentMark{CreatedAt: t0}); err != nil {
		t.Fatalf("the broker creates the enrollment mark: %v", err)
	}
	if err := b.SwapSecondFactor(ctx, store.SecondFactor{Principal: "user:alice",
		State: store.SecondFactorActive}, 0); err != nil {
		t.Fatalf("the broker writes a second factor: %v", err)
	}
	for name, err := range map[string]error{
		"write a mark": d.PutRevocation(ctx, store.Revocation{Kind: store.RevocationPrincipal, Key: "user:x", At: t0}),
		"overwrite a mark": func() error {
			_, err := d.tok.Put(ctx, d.k.mark(store.RevocationPrincipal, "user:bob"), "{}")
			return unavailable(err)
		}(),
		"lift a mark":           d.DeleteRevocation(ctx, store.RevocationPrincipal, "user:bob"),
		"write the token index": d.IndexToken(ctx, "user:alice", "", k, time.Minute),
		"read the token index":  func() error { _, err := d.TokensByPrincipal(ctx, "user:alice"); return err }(),
		"write meta/":           func() error { _, err := d.ctx.Put(ctx, d.k.meta("hold"), "x"); return unavailable(err) }(),
		"lower the ledger record": func() error {
			_, err := d.ctx.Put(ctx, d.k.ledgerOf(lk), `{"seq":1}`)
			return unavailable(err)
		}(),
		"raise the ledger record": func() error {
			_, err := d.PutLedgerMarks(ctx, []store.LedgerMark{{Key: lk, Seq: 11}})
			return err
		}(),
		"count a sign-in attempt": func() error {
			_, _, err := d.NoteSignInAttempt(ctx, "principal:user:alice", time.Minute)
			return err
		}(),
		"read a second factor": func() error { _, err := d.GetSecondFactor(ctx, "user:alice"); return err }(),
		"write a second factor": d.SwapSecondFactor(ctx, store.SecondFactor{Principal: "user:alice",
			State: store.SecondFactorActive}, 0),
		"read the enrollment mark":  func() error { _, err := d.GetEnrollmentMark(ctx); return err }(),
		"write the enrollment mark": d.PutEnrollmentMark(ctx, store.EnrollmentMark{CreatedAt: t0}),
		"reserve an idempotency key": func() error {
			_, _, err := d.ReserveIdempotency(ctx, "user:alice", "k",
				store.Idempotency{Holder: "h", Pending: true, ExpiresAt: t0.Add(time.Minute)})
			return err
		}(),
	} {
		if !errors.Is(err, ErrRefused) {
			t.Errorf("the daemon could %s: %v", name, err)
		}
	}
	if r, err := b.GetRevocation(ctx, store.RevocationPrincipal, "user:bob"); err != nil || !r.At.Equal(t0) {
		t.Fatalf("the broker's mark after the daemon's attempts: %+v, %v", r, err)
	}
}

// CheckIdentity is port49d's start check: the daemon refused the broker's
// records and the broker allowed them pass; a daemon holding the broker's
// role, and etcd with auth off, fail with ErrNotSeparated (Review Focus 6).
func TestCheckIdentityRefusesADaemonWithTheBrokersReach(t *testing.T) {
	const prefix = "/port49/"
	srv := provisioned(t, prefix)
	ctx := context.Background()
	if err := openAs(t, srv, "port49-daemon", prefix).CheckIdentity(ctx, false); err != nil {
		t.Fatalf("the daemon as itself: %v", err)
	}
	if err := openAs(t, srv, "port49-broker", prefix).CheckIdentity(ctx, true); err != nil {
		t.Fatalf("the broker as itself: %v", err)
	}
	if err := openAs(t, srv, "port49-broker", prefix).CheckIdentity(ctx, false); !errors.Is(err, ErrNotSeparated) {
		t.Fatalf("the broker's certificate as the daemon: %v", err)
	}
	open := etcdtest.Start(t, etcdtest.Options{TLS: true}) // auth never enabled
	if err := openAs(t, open, "port49-daemon", prefix).CheckIdentity(ctx, false); !errors.Is(err, ErrNotSeparated) {
		t.Fatalf("etcd with auth off: %v", err)
	}
	// A daemon role that reads no idempotency record but may write a mark
	// is not separated either: the write probe catches it (pre-flight M32).
	marks := newKeys(prefix).family(famMark)
	loose := provisionedWith(t, prefix, []etcdtest.Grant{{Role: RoleDaemon, Key: marks,
		RangeEnd: clientv3.GetPrefixRangeEnd(marks), Write: true}}, nil)
	if err := openAs(t, loose, "port49-daemon", prefix).CheckIdentity(ctx, false); !errors.Is(err, ErrNotSeparated) {
		t.Fatalf("a daemon that may write a mark: %v", err)
	}
	// The probes wrote nothing, on either member.
	for _, srv := range []*etcdtest.Server{srv, loose} {
		resp, err := srv.Client(t, "root").Get(ctx, prefix, clientv3.WithPrefix(), clientv3.WithKeysOnly())
		if err != nil {
			t.Fatal(err)
		}
		if len(resp.Kvs) != 0 {
			t.Fatalf("CheckIdentity wrote %q", resp.Kvs[0].Key)
		}
	}
}

// A daemon role granted a write on lw/, or any access to sp/, mb/ or mk/, is
// refused at the start: the first would let a stolen daemon key lower the
// ledger record, the second forge a replay's superseded instant (Review
// Focus 8; Rulings 4, 9), and the last two hold every principal's groups
// (plan 7g, Ruling 10), and on/, oo/ and lo/, the broker's OIDC records
// (plan 7h).
func TestCheckIdentityRefusesADaemonThatCanWriteTheLedgerRecord(t *testing.T) {
	const prefix = "/port49/"
	ledger, superseded := newKeys(prefix).family(famLedger), newKeys(prefix).family(famSuperseded)
	membership, membershipK := newKeys(prefix).family(famMembership), newKeys(prefix).family(famMembershipK)
	once, owner, logout := newKeys(prefix).family(famOnce), newKeys(prefix).family(famOIDCOwner),
		newKeys(prefix).family(famLogout)
	secondFactor, attempts := newKeys(prefix).family(famSecondFactor), newKeys(prefix).family(famSignInAttempts)
	unlock := newKeys(prefix).family(famUnlock)
	srv := provisioned(t, prefix)
	if err := openAs(t, srv, "port49-daemon", prefix).CheckIdentity(context.Background(), false); err != nil {
		t.Fatalf("the daemon as itself, with its read on lw/: %v", err)
	}
	// The probes run before the grants are read, so each is named by its
	// own (review M-5).
	for _, c := range []struct {
		extra etcdtest.Grant
		probe string
	}{
		{etcdtest.Grant{Role: RoleDaemon, Key: ledger, RangeEnd: clientv3.GetPrefixRangeEnd(ledger), Write: true},
			"it was allowed writing " + ledger},
		{etcdtest.Grant{Role: RoleDaemon, Key: superseded, RangeEnd: clientv3.GetPrefixRangeEnd(superseded)},
			"it was allowed reading " + superseded},
		{etcdtest.Grant{Role: RoleDaemon, Key: membership, RangeEnd: clientv3.GetPrefixRangeEnd(membership)},
			"it was allowed reading " + membership},
		{etcdtest.Grant{Role: RoleDaemon, Key: membershipK, RangeEnd: clientv3.GetPrefixRangeEnd(membershipK)},
			"it was allowed reading " + membershipK},
		{etcdtest.Grant{Role: RoleDaemon, Key: membership, RangeEnd: clientv3.GetPrefixRangeEnd(membership), Write: true},
			"it was allowed reading " + membership}, // a write grant is read-write: the reading probe runs first
		{etcdtest.Grant{Role: RoleDaemon, Key: membershipK, RangeEnd: clientv3.GetPrefixRangeEnd(membershipK), Write: true},
			"it was allowed reading " + membershipK},
		{etcdtest.Grant{Role: RoleDaemon, Key: once, RangeEnd: clientv3.GetPrefixRangeEnd(once)},
			"it was allowed reading " + once},
		{etcdtest.Grant{Role: RoleDaemon, Key: once, RangeEnd: clientv3.GetPrefixRangeEnd(once), Write: true},
			"it was allowed reading " + once}, // a write grant is read-write: the reading probe runs first
		{etcdtest.Grant{Role: RoleDaemon, Key: owner, RangeEnd: clientv3.GetPrefixRangeEnd(owner)},
			"it was allowed reading " + owner},
		{etcdtest.Grant{Role: RoleDaemon, Key: owner, RangeEnd: clientv3.GetPrefixRangeEnd(owner), Write: true},
			"it was allowed reading " + owner}, // a write grant is read-write: the reading probe runs first
		{etcdtest.Grant{Role: RoleDaemon, Key: logout, RangeEnd: clientv3.GetPrefixRangeEnd(logout)},
			"it was allowed reading " + logout},
		{etcdtest.Grant{Role: RoleDaemon, Key: logout, RangeEnd: clientv3.GetPrefixRangeEnd(logout), Write: true},
			"it was allowed reading " + logout}, // a write grant is read-write: the reading probe runs first
		{etcdtest.Grant{Role: RoleDaemon, Key: secondFactor, RangeEnd: clientv3.GetPrefixRangeEnd(secondFactor)},
			"it was allowed reading " + secondFactor},
		{etcdtest.Grant{Role: RoleDaemon, Key: secondFactor, RangeEnd: clientv3.GetPrefixRangeEnd(secondFactor), Write: true},
			"it was allowed reading " + secondFactor},
		{etcdtest.Grant{Role: RoleDaemon, Key: attempts, RangeEnd: clientv3.GetPrefixRangeEnd(attempts)},
			"it was allowed reading " + attempts},
		{etcdtest.Grant{Role: RoleDaemon, Key: attempts, RangeEnd: clientv3.GetPrefixRangeEnd(attempts), Write: true},
			"it was allowed reading " + attempts},
		{etcdtest.Grant{Role: RoleDaemon, Key: unlock, RangeEnd: clientv3.GetPrefixRangeEnd(unlock)},
			"it was allowed reading " + unlock},
		{etcdtest.Grant{Role: RoleDaemon, Key: unlock, RangeEnd: clientv3.GetPrefixRangeEnd(unlock), Write: true},
			"it was allowed reading " + unlock},
	} {
		loose := provisionedWith(t, prefix, []etcdtest.Grant{c.extra}, nil)
		err := openAs(t, loose, "port49-daemon", prefix).CheckIdentity(context.Background(), false)
		if !errors.Is(err, ErrNotSeparated) || !strings.Contains(err.Error(), c.probe) {
			t.Fatalf("a daemon granted %+v: %v, want %q", c.extra, err, c.probe)
		}
	}
}

// Open dials two clients, the token pool and the context pool: one
// connection each (design §12).
func TestOpenDialsAPoolEach(t *testing.T) {
	s, err := Open(Config{Endpoints: []string{etcdtest.Endpoint()}, Prefix: etcdtest.Prefix()})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.tok == s.ctx || len(s.owned) != 2 || s.tokLeases == s.ctxLeases {
		t.Fatal("Open shares one client between the pools")
	}
}

// A daemon role widened on a range no probe key falls in is still not
// separated: CheckIdentity reads the daemon's own grants, so a grant
// that reaches a mark, the keyspace hold, an idempotency record, a token
// index, or anything outside the daemon's families is refused whatever
// its range (task 11 review I1).
func TestCheckIdentityReadsTheDaemonsGrants(t *testing.T) {
	const prefix = "/port49/"
	k := newKeys(prefix)
	sub := func(p string, write bool) etcdtest.Grant {
		return etcdtest.Grant{Role: RoleDaemon, Key: p, RangeEnd: clientv3.GetPrefixRangeEnd(p), Write: write}
	}
	for name, g := range map[string]etcdtest.Grant{
		"readwrite on rv/principal/":   sub(k.family(famMark)+store.RevocationPrincipal+"/", true),
		"readwrite on rv/cert/":        sub(k.family(famMark)+store.RevocationCert+"/", true),
		"readwrite on meta/hold":       {Role: RoleDaemon, Key: k.meta("hold"), Write: true},
		"readwrite on id/user:alice/":  sub(k.family(famIdem)+"user:alice/", true),
		"read on id/user:alice/":       sub(k.family(famIdem)+"user:alice/", false),
		"read on tp/user:alice/":       sub(k.family(famTokByPrin)+"user:alice/", false),
		"read on ul/user:alice/":       sub(k.family(famUnlock)+"user:alice/", false),
		"readwrite on ul/user:alice/":  sub(k.family(famUnlock)+"user:alice/", true),
		"read on sf/user:alice/":       sub(k.family(famSecondFactor)+"user:alice/", false),
		"readwrite on sf/user:alice/":  sub(k.family(famSecondFactor)+"user:alice/", true),
		"read on sa/user:alice/":       sub(k.family(famSignInAttempts)+"user:alice/", false),
		"readwrite on sa/user:alice/":  sub(k.family(famSignInAttempts)+"user:alice/", true),
		"readwrite outside its prefix": sub("/elsewhere/", true),
		"readwrite from v1/ onward":    {Role: RoleDaemon, Key: k.root, RangeEnd: "\x00", Write: true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			srv := provisionedWith(t, prefix, []etcdtest.Grant{g}, nil)
			err := openAs(t, srv, "port49-daemon", prefix).CheckIdentity(context.Background(), false)
			if !errors.Is(err, ErrNotSeparated) {
				t.Fatalf("CheckIdentity: %v", err)
			}
		})
	}
}

// A store identity that is etcd's root, by its certificate's CN or by
// holding the root role, bypasses every role: refused for the daemon
// and the broker alike (Ruling T11-a).
func TestCheckIdentityRefusesRoot(t *testing.T) {
	const prefix = "/port49/"
	ctx := context.Background()
	srv := provisionedWith(t, prefix, nil, map[string][]string{"port49-broker": {RoleBroker, "root"}})
	for _, broker := range []bool{true, false} {
		if err := openAs(t, srv, "root", prefix).CheckIdentity(ctx, broker); !errors.Is(err, ErrNotSeparated) {
			t.Errorf("CN root, broker %v: %v", broker, err)
		}
	}
	if err := openAs(t, srv, "port49-broker", prefix).CheckIdentity(ctx, true); !errors.Is(err, ErrNotSeparated) {
		t.Errorf("a broker holding the root role: %v", err)
	}
	// With auth off the broker is not refused: under
	// stores.directory.etcd.roles: unenforced it is the daemon's check that is waived.
	open := etcdtest.Start(t, etcdtest.Options{TLS: true})
	if err := openAs(t, open, "port49-broker", prefix).CheckIdentity(ctx, true); err != nil {
		t.Errorf("the broker on etcd with auth off: %v", err)
	}
	// Its certificate's CN is refused there too, by name: auth is off,
	// but turning it on would make that certificate etcd's root.
	if err := openAs(t, open, "root", prefix).CheckIdentity(ctx, true); !errors.Is(err, ErrNotSeparated) {
		t.Errorf("CN root on etcd with auth off: %v", err)
	}
}

// An identity whose etcd user port49 cannot read from its own TLS config
// (a certificate from GetClientCertificate, which etcd still sees) is
// refused, never let past the grant check (task 11 re-review N1).
func TestCheckIdentityRefusesAnIdentityItCannotName(t *testing.T) {
	const prefix = "/port49/"
	srv := provisioned(t, prefix)
	cfg := srv.TLS(t, "port49-daemon")
	pair := cfg.Certificates[0]
	cfg.Certificates = nil
	cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &pair, nil }
	s, err := Open(Config{Endpoints: []string{srv.Endpoint}, TLS: cfg, Prefix: prefix})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, broker := range []bool{false, true} {
		if err := s.CheckIdentity(context.Background(), broker); !errors.Is(err, ErrNotSeparated) {
			t.Errorf("broker %v: %v", broker, err)
		}
	}
}

// The roles are the golden ceiling (plan 7e, Task 16): a grant added to
// Roles that is not here fails, so widening a role is a decision made in
// this file. The broker holds the keyspace's root alone, the one range
// every family it touches sits under (spec §12); the daemon holds
// read-write on the nine families a login, an authorization and
// accounting touch, read on the marks and the ledger record, and read on
// five single keys of meta/ (the ones port49d's code reads), and nothing
// on the idempotency records, the token indexes or the superseded record.
// What the daemon's code reads is held by TestTheDaemonReadsExactlyItsMetaKeys.
func TestTheRolesAreTheGoldenCeiling(t *testing.T) {
	var got []string
	for _, g := range Roles("/port49/") {
		perm := "read"
		if g.Write {
			perm = "readwrite"
		}
		got = append(got, g.Role+" "+perm+" "+g.Key)
	}
	want := []string{
		"port49_daemon readwrite /port49/v1/t/", "port49_daemon readwrite /port49/v1/r/",
		"port49_daemon readwrite /port49/v1/rp/", "port49_daemon readwrite /port49/v1/c/",
		"port49_daemon readwrite /port49/v1/x/", "port49_daemon readwrite /port49/v1/ip/",
		"port49_daemon readwrite /port49/v1/is/", "port49_daemon readwrite /port49/v1/ic/",
		"port49_daemon readwrite /port49/v1/b/",
		"port49_daemon read /port49/v1/rv/", "port49_daemon read /port49/v1/lw/",
		"port49_daemon read /port49/v1/meta/seal_keys", "port49_daemon read /port49/v1/meta/witness",
		"port49_daemon read /port49/v1/meta/purged", "port49_daemon read /port49/v1/meta/judged_bundle",
		"port49_daemon read /port49/v1/meta/ping",
		"port49_broker readwrite /port49/v1/",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("the grants are not the ceiling:\n got %q\nwant %q", got, want)
	}
}

// Under the roles etcd enforces, the broker writes meta/judged,
// meta/witness and meta/purged, and the daemon reads the restore pair and
// follows meta/witness but writes none of the three: a stolen daemon key
// cannot forge a witness a restore is detected by, nor the purge that lets
// redemptions resume (Task 15d, Ruling 19).
func TestTheDaemonReadsExactlyItsMetaKeys(t *testing.T) {
	const prefix = "/port49/"
	srv := provisioned(t, prefix)
	ctx := context.Background()
	d, b := openAs(t, srv, "port49-daemon", prefix), openAs(t, srv, "port49-broker", prefix)

	if err := b.PutJudged(ctx, "bundle-1", []byte("policy")); err != nil {
		t.Fatalf("the broker writes meta/judged: %v", err)
	}
	w, err := b.PutWitness(ctx, "broker-a", 0)
	if err != nil || w == 0 {
		t.Fatalf("the broker writes meta/witness: %d, %v", w, err)
	}
	p, err := b.PutPurged(ctx, "broker-a", w)
	if err != nil || p == 0 {
		t.Fatalf("the broker writes meta/purged: %d, %v", p, err)
	}
	r, err := d.RestoreRead(ctx)
	if err != nil || r.Witness != w || r.Purged != p {
		t.Fatalf("the daemon reads the restore pair: %+v, %v (witness %d, purged %d)", r, err, w, p)
	}
	if wr, err := d.Witness(ctx); err != nil || wr.ModRevision != w {
		t.Fatalf("the daemon reads meta/witness: %+v, %v", wr, err)
	}
	fctx, cancel := context.WithCancel(ctx)
	defer cancel()
	seen := make(chan uint64, 4)
	go d.FollowWitness(fctx, func(rev uint64) { seen <- rev })
	if got := waitRevision(t, seen, w); got != w {
		t.Fatalf("the daemon follows meta/witness: %d, want %d", got, w)
	}
	if bundle, ok, err := d.JudgedBundle(ctx); err != nil || !ok || bundle != "bundle-1" {
		t.Fatalf("the daemon reads the bundle last judged: %q %v %v", bundle, ok, err)
	}
	if _, _, err := d.Judged(ctx); !errors.Is(err, ErrRefused) {
		t.Errorf("the daemon read meta/judged, the policy file: %v", err)
	}
	if err := d.Ping(ctx); err != nil {
		t.Errorf("the daemon pings: %v", err)
	}
	if _, _, err := d.SealKeys(ctx); err != nil {
		t.Errorf("the daemon reads meta/seal_keys: %v", err)
	}
	if _, _, err := d.Holder(ctx); !errors.Is(err, ErrRefused) {
		t.Errorf("the daemon read meta/holder: %v", err)
	}
	if _, err := d.Bundles(ctx); !errors.Is(err, ErrRefused) {
		t.Errorf("the daemon read meta/bundles/: %v", err)
	}
	if _, err := d.PutWitness(ctx, "daemon", w); !errors.Is(err, ErrRefused) {
		t.Errorf("the daemon wrote meta/witness: %v", err)
	}
	if _, err := d.PutPurged(ctx, "daemon", w); !errors.Is(err, ErrRefused) {
		t.Errorf("the daemon wrote meta/purged: %v", err)
	}
	if err := d.PutJudged(ctx, "bundle-2", []byte("policy")); !errors.Is(err, ErrRefused) {
		t.Errorf("the daemon wrote meta/judged: %v", err)
	}
}

// waitRevision returns the first revision on ch that is want, or the last
// one read when 5s pass.
func waitRevision(t *testing.T, ch <-chan uint64, want uint64) uint64 {
	t.Helper()
	var last uint64
	for {
		select {
		case r := <-ch:
			if last = r; r == want {
				return r
			}
		case <-time.After(5 * time.Second):
			return last
		}
	}
}

// An unlock is the broker's: the daemon's role neither reads nor writes
// ul/ (plan 11a, R23).
func TestTheDaemonCannotReachAnUnlock(t *testing.T) {
	const prefix = "/port49/"
	srv := provisioned(t, prefix)
	ctx := context.Background()
	d, b := openAs(t, srv, "port49-daemon", prefix), openAs(t, srv, "port49-broker", prefix)
	if err := b.PutUnlock(ctx, "user:alice@example.com", t0); err != nil {
		t.Fatalf("the broker unlocks: %v", err)
	}
	if _, err := d.GetUnlock(ctx, "user:alice@example.com"); !errors.Is(err, ErrRefused) {
		t.Fatalf("the daemon read an unlock: %v", err)
	}
	if err := d.PutUnlock(ctx, "user:alice@example.com", t0.Add(time.Hour)); !errors.Is(err, ErrRefused) {
		t.Fatalf("the daemon wrote an unlock: %v", err)
	}
}

// provisionedFor is provisioned with the roles of a keyspace holding
// scope's families (R23).
func provisionedFor(t *testing.T, prefix string, scope Scope) *etcdtest.Server {
	srv := etcdtest.Start(t, etcdtest.Options{TLS: true})
	var grants []etcdtest.Grant
	for _, g := range RolesFor(prefix, scope) {
		grants = append(grants, etcdtest.Grant{Role: g.Role, Key: g.Key, RangeEnd: g.RangeEnd, Write: g.Write})
	}
	srv.EnableAuth(t, grants, map[string][]string{"port49-daemon": {RoleDaemon}, "port49-broker": {RoleBroker}})
	return srv
}

// On a directory keyspace the daemon reads the marks, the ping and the key
// window (R23, R27), and nothing else.
func TestTheDirectoryRolesAreTheMarksAlone(t *testing.T) {
	k := newKeys("/port49/")
	got := RolesFor("/port49/", ScopeDirectory)
	want := []Grant{
		{Role: RoleDaemon, Key: k.family(famMark), RangeEnd: clientv3.GetPrefixRangeEnd(k.family(famMark))},
		{Role: RoleDaemon, Key: k.meta("ping")},
		{Role: RoleDaemon, Key: k.meta("seal_keys")},
		{Role: RoleBroker, Key: k.root, RangeEnd: clientv3.GetPrefixRangeEnd(k.root), Write: true},
	}
	if len(got) != len(want) {
		t.Fatalf("%+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("grant %d: %+v, want %+v", i, got[i], want[i])
		}
	}
}

// On a session keyspace the daemon does not read the marks; it reads every
// marks snapshot record, writes its own alone, and has no grant on a
// broker's records (R19, R23; the re-review's N1 and N4).
func TestTheSessionRolesLackTheMarks(t *testing.T) {
	k := newKeys("/port49/")
	reads, writes := false, false
	for _, g := range RolesFor("/port49/", ScopeSession) {
		switch {
		case g.Role != RoleDaemon:
		case g.Key == k.family(famMark):
			t.Fatalf("the session store's daemon role reads the marks: %+v", g)
		case g.Key == k.family(snapMarks) && !g.Write:
			reads = true
		case g.Key == k.family(snapDaemon) && g.Write:
			writes = true
		case strings.HasPrefix(g.Key, k.family(famSnapshot)):
			t.Fatalf("the daemon role reaches a snapshot record past its own and the marks: %+v", g)
		}
	}
	if !reads || !writes {
		t.Fatalf("the daemon role reads the marks records %v, writes its own %v", reads, writes)
	}
	for _, g := range RolesFor("/port49/", ScopeShared) {
		if strings.HasPrefix(g.Key, k.family(famSnapshot)) && g.Role == RoleDaemon {
			t.Fatalf("a shared store's daemon role reaches ds/, which only a split writes: %+v", g)
		}
	}
	if why := k.beyondSessionDaemon(k.family(snapBroker), clientv3.GetPrefixRangeEnd(k.family(snapBroker)), false); why == "" {
		t.Fatal("a daemon read grant on ds/b/ passed the session check")
	}
	if why := k.beyondSessionDaemon(k.family(famSnapshot), clientv3.GetPrefixRangeEnd(k.family(famSnapshot)), false); why == "" {
		t.Fatal("a daemon read grant on all of ds/ passed the session check")
	}
	if why := k.beyondSessionDaemon(k.family(snapMarks), clientv3.GetPrefixRangeEnd(k.family(snapMarks)), false); why != "" {
		t.Fatalf("the daemon's own ds/m/ read grant was refused: %s", why)
	}
	for _, fam := range []string{snapMarks, snapMarks + "port49-broker@"} {
		if why := k.beyondSessionDaemon(k.family(fam), clientv3.GetPrefixRangeEnd(k.family(fam)), true); why == "" {
			t.Fatalf("a daemon write grant on %s passed the session check", fam)
		}
	}
	if why := k.beyondSessionDaemon(k.family(snapDaemon), clientv3.GetPrefixRangeEnd(k.family(snapDaemon)), true); why != "" {
		t.Fatalf("the daemon's own write grant was refused: %s", why)
	}
	if why := k.beyondSessionDaemon(k.family("zz/"), "\x00", false); strings.Contains(why, "ds/") {
		t.Fatalf("an unbounded grant starting past ds/ is said to reach it: %s", why)
	}
	if len(RolesFor("/port49/", ScopeShared)) != len(Roles("/port49/")) {
		t.Fatal("Roles is not the shared scope's")
	}
}

// On a directory keyspace the daemon reads the marks and nothing else, and
// the start check holds it there: the shared roles applied to a directory
// keyspace are refused, as reaching past them.
func TestCheckIdentityAtTheDirectory(t *testing.T) {
	const prefix = "/port49/"
	ctx := context.Background()
	srv := provisionedFor(t, prefix, ScopeDirectory)
	d, b := openAs(t, srv, "port49-daemon", prefix), openAs(t, srv, "port49-broker", prefix)
	if err := d.CheckIdentityAt(ctx, false, ScopeDirectory); err != nil {
		t.Fatalf("the daemon: %v", err)
	}
	if err := b.CheckIdentityAt(ctx, true, ScopeDirectory); err != nil {
		t.Fatalf("the broker: %v", err)
	}
	if _, err := d.ListRevocations(ctx); err != nil {
		t.Fatalf("the daemon lists the marks: %v", err)
	}
	if err := d.PutRevocation(ctx, store.Revocation{Kind: store.RevocationPrincipal, Key: "user:bob", At: t0}); !errors.Is(err, ErrRefused) {
		t.Fatalf("the daemon wrote a mark: %v", err)
	}
	if _, _, err := d.SealKeys(ctx); err != nil {
		t.Fatalf("the daemon reads the directory's key window (R27): %v", err)
	}
	if _, err := d.GetMembership(ctx, "user:alice@example.com"); !errors.Is(err, ErrRefused) {
		t.Fatalf("the daemon read a pin: %v", err)
	}
	if _, err := d.GetLogout(ctx, "sid 1:i 1:s"); !errors.Is(err, ErrRefused) {
		t.Fatalf("the daemon read a logout: %v", err)
	}
	wide := provisioned(t, prefix)
	dw := openAs(t, wide, "port49-daemon", prefix)
	if err := dw.CheckIdentityAt(ctx, false, ScopeDirectory); !errors.Is(err, ErrNotSeparated) {
		t.Fatalf("the shared roles on a directory keyspace: %v", err)
	}
}

// The re-review's last minor: a session keyspace whose daemon role also
// reads a broker's snapshot records is refused at the daemon's start check,
// naming ds/b/; port49d's start turns it into exit 1 (a *storeFault).
func TestCheckIdentityAtRefusesADaemonReadOfBrokerSnapshots(t *testing.T) {
	const prefix = "/port49/"
	k := newKeys(prefix)
	srv := etcdtest.Start(t, etcdtest.Options{TLS: true})
	var grants []etcdtest.Grant
	for _, g := range append(RolesFor(prefix, ScopeSession), Grant{Role: RoleDaemon, Key: k.family(snapBroker),
		RangeEnd: clientv3.GetPrefixRangeEnd(k.family(snapBroker))}) {
		grants = append(grants, etcdtest.Grant{Role: g.Role, Key: g.Key, RangeEnd: g.RangeEnd, Write: g.Write})
	}
	srv.EnableAuth(t, grants, map[string][]string{"port49-daemon": {RoleDaemon}, "port49-broker": {RoleBroker}})
	d := openAs(t, srv, "port49-daemon", prefix)
	err := d.CheckIdentityAt(context.Background(), false, ScopeSession)
	if !errors.Is(err, ErrNotSeparated) || !strings.Contains(err.Error(), "ds/b/") {
		t.Fatalf("%v, want ErrNotSeparated naming ds/b/", err)
	}
}
