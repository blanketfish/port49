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

// A daemon role granted a write on lw/, or any access to sp/, is refused at
// the start: either would let a stolen daemon key lower the ledger record
// or forge a replay's superseded instant (Review Focus 8; Rulings 4, 9).
func TestCheckIdentityRefusesADaemonThatCanWriteTheLedgerRecord(t *testing.T) {
	const prefix = "/port49/"
	ledger, superseded := newKeys(prefix).family(famLedger), newKeys(prefix).family(famSuperseded)
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
	// store.etcd.roles: unenforced it is the daemon's check that is waived.
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

// The roles are no wider than the code uses (plan 7e, Task 16). The
// golden table is the ceiling: a grant added to Roles that is not here
// fails, so widening a role is a decision made in this file. The broker
// holds the keyspace's root alone, the one range every family it touches
// sits under (spec §12); the daemon holds read-write on the nine families
// a login, an authorization and accounting touch, and read on the marks,
// meta/ and the ledger record, and nothing on the idempotency records, the
// token indexes or the superseded record.
func TestTheRolesAreNoWiderThanTheCodeUses(t *testing.T) {
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
		"port49_daemon read /port49/v1/rv/", "port49_daemon read /port49/v1/meta/", "port49_daemon read /port49/v1/lw/",
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
func TestTheDaemonReadsTheRestorePairAndTheBrokerWritesIt(t *testing.T) {
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
