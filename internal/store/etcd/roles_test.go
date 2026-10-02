package etcd

import (
	"context"
	"errors"
	"testing"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/etcd/etcdtest"
)

// provisioned is a TLS member with auth on and port49's roles applied
// for prefix: users port49-daemon and port49-broker.
func provisioned(t *testing.T, prefix string) *etcdtest.Server {
	srv := etcdtest.Start(t, etcdtest.Options{TLS: true})
	var grants []etcdtest.Grant
	for _, g := range Roles(prefix) {
		grants = append(grants, etcdtest.Grant{Role: g.Role, Key: g.Key, RangeEnd: g.RangeEnd, Write: g.Write})
	}
	srv.EnableAuth(t, grants, map[string][]string{"port49-daemon": {RoleDaemon}, "port49-broker": {RoleBroker}})
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
	loose := etcdtest.Start(t, etcdtest.Options{TLS: true})
	var grants []etcdtest.Grant
	for _, g := range Roles(prefix) {
		grants = append(grants, etcdtest.Grant{Role: g.Role, Key: g.Key, RangeEnd: g.RangeEnd, Write: g.Write})
	}
	marks := newKeys(prefix).family(famMark)
	grants = append(grants, etcdtest.Grant{Role: RoleDaemon, Key: marks, RangeEnd: clientv3.GetPrefixRangeEnd(marks), Write: true})
	loose.EnableAuth(t, grants, map[string][]string{"port49-daemon": {RoleDaemon}, "port49-broker": {RoleBroker}})
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
