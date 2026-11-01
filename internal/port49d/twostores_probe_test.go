//go:build linux

package port49d

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/config"
	"github.com/blanketfish/port49/internal/store/etcd"
	"github.com/blanketfish/port49/internal/store/etcd/etcdtest"
)

func openAt(t *testing.T, endpoint, prefix string) *etcd.Store {
	t.Helper()
	s, err := etcd.Open(etcd.Config{Endpoints: []string{endpoint}, Prefix: prefix})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func twoPrefixes(dir, sess string) config.Config {
	var cfg config.Config
	cfg.Stores.Directory.Etcd, cfg.Stores.Session.Etcd = &config.EtcdConfig{}, &config.EtcdConfig{}
	cfg.Stores.Directory.Etcd.Prefix, cfg.Stores.Session.Etcd.Prefix = dir, sess
	return cfg
}

// R28's prefix rule on one member: a prefix that is the other's, or equal
// to it, is one keyspace; unrelated prefixes are two.
func TestTheTwoStoresCheckRefusesEqualAndNestedPrefixesOnOneCluster(t *testing.T) {
	srv := etcdtest.Start(t, etcdtest.Options{})
	for _, c := range []struct {
		name, dir, sess string
		refused         bool
	}{
		{"unrelated", "/other/", "/port49/", false},
		{"equal", "/port49/", "/port49/", true},
		{"directory inside session", "/port49/dir/", "/port49/", true},
		{"session inside directory", "/port49/", "/port49/dir/", true},
		{"siblings sharing a leading name", "/port49/", "/port49x/", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir, sess := openAt(t, srv.Endpoint, c.dir), openAt(t, srv.Endpoint, c.sess)
			err := checkTwoStores(context.Background(), twoPrefixes(c.dir, c.sess), sess, dir, 5*time.Second)
			if c.refused != (err != nil) || err != nil && !strings.Contains(err.Error(), "one keyspace named two ways") {
				t.Fatalf("refused=%v, want %v: %v", err != nil, c.refused, err)
			}
		})
	}
}

// Two separate clusters can share a cluster id (etcd derives it from the peer
// URLs and the token, as two default single-node etcds, or one chart in two
// regions, share it): they are two keyspaces and the split is accepted.
func TestTwoClustersSharingAnIdAreTwoKeyspaces(t *testing.T) {
	a := etcdtest.Start(t, etcdtest.Options{ClusterToken: "same"})
	b := etcdtest.Start(t, etcdtest.Options{ClusterToken: "same"})
	sess, dir := openAt(t, a.Endpoint, "/port49/"), openAt(t, b.Endpoint, "/port49/")
	ia, _ := sess.ClusterID(context.Background())
	ib, _ := dir.ClusterID(context.Background())
	if ia == 0 || ia != ib {
		t.Fatalf("setup: the clusters' ids are %x and %x, want one", ia, ib)
	}
	if err := checkTwoStores(context.Background(), twoPrefixes("/port49/", "/port49/"), sess, dir, 5*time.Second); err != nil {
		t.Fatalf("two clusters with one id were refused: %v", err)
	}
}

// The lease probe asks etcd for no role, so it works under enforced roles: one
// member named twice by a broker identity is refused as one keyspace, and the
// refusal is the keyspace's, not a permission error.
func TestTheLeaseProbeWorksUnderEnforcedRoles(t *testing.T) {
	srv, _ := rolesMemberScoped(t, etcd.ScopeDirectory)
	open := func(user string) *etcd.Store {
		s, err := etcd.Open(etcd.Config{Endpoints: []string{srv.Endpoint}, TLS: srv.TLS(t, user), Prefix: "/port49/"})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.Close() })
		return s
	}
	// The daemon identity reads and writes no lease-bearing key, and the
	// broker's directory role does not reach /port49/dir/ keys: neither matters.
	err := checkTwoStores(context.Background(), twoPrefixes("/port49/", "/port49/"), open("port49-broker"),
		open("port49-daemon"), 5*time.Second)
	if err == nil || !strings.Contains(err.Error(), "one keyspace named two ways") {
		t.Fatalf("%v", err)
	}
}

// Two enforced-roles members sharing a cluster id are two keyspaces.
func TestTwoEnforcedClustersSharingAnIdAreAccepted(t *testing.T) {
	mk := func() *etcd.Store {
		srv := etcdtest.Start(t, etcdtest.Options{TLS: true, ClusterToken: "same-enforced"})
		var grants []etcdtest.Grant
		for _, g := range etcd.RolesFor("/port49/", etcd.ScopeDirectory) {
			grants = append(grants, etcdtest.Grant{Role: g.Role, Key: g.Key, RangeEnd: g.RangeEnd, Write: g.Write})
		}
		srv.EnableAuth(t, grants, map[string][]string{"port49-daemon": {etcd.RoleDaemon}, "port49-broker": {etcd.RoleBroker}})
		s, err := etcd.Open(etcd.Config{Endpoints: []string{srv.Endpoint}, TLS: srv.TLS(t, "port49-broker"), Prefix: "/port49/"})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.Close() })
		return s
	}
	sess, dir := mk(), mk()
	if err := checkTwoStores(context.Background(), twoPrefixes("/port49/", "/port49/"), sess, dir, 5*time.Second); err != nil {
		t.Fatal(err)
	}
}

// A probe that cannot complete refuses the start, naming the handle and a
// closed-set cause, never etcd's text.
func TestAHandleThatCannotAnswerTheProbeIsNamedWithItsCause(t *testing.T) {
	srv := etcdtest.Start(t, etcdtest.Options{})
	live, gone := openAt(t, srv.Endpoint, "/port49/"), openAt(t, srv.Endpoint, "/port49/")
	gone.Close()
	for _, c := range []struct {
		name      string
		sess, dir *etcd.Store
		want      string
	}{
		{"directory", live, gone, "the directory store could not grant its probe lease (unreachable)"},
		{"session", gone, live, "the session store could not look up the probe lease (unreachable)"},
	} {
		t.Run(c.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, err := sameCluster(ctx, ctx, c.sess, c.dir, time.Second)
			if err == nil || err.Error() != c.want {
				t.Fatalf("%v, want %q", err, c.want)
			}
		})
	}
}

// R28 under enforced roles with nested prefixes (the key probe's failing case):
// one member, an A role set at /port49/ and a B role set at /port49/dir/, held
// by users of their own, so neither identity's grants reach the other's keys.
// The lease probe still finds one cluster, both ways round, as the broker and
// as the daemon.
func TestNestedPrefixesUnderEnforcedRolesAreOneKeyspace(t *testing.T) {
	srv := etcdtest.Start(t, etcdtest.Options{TLS: true})
	var grants []etcdtest.Grant
	users := map[string][]string{}
	for set, prefix := range map[string]string{"a": "/port49/", "b": "/port49/dir/"} {
		for _, g := range etcd.RolesFor(prefix, etcd.ScopeShared) {
			grants = append(grants, etcdtest.Grant{Role: set + "-" + g.Role, Key: g.Key, RangeEnd: g.RangeEnd, Write: g.Write})
		}
		users[set+"-broker"] = []string{set + "-" + etcd.RoleBroker}
		users[set+"-daemon"] = []string{set + "-" + etcd.RoleDaemon}
	}
	srv.EnableAuth(t, grants, users)
	open := func(user, prefix string) *etcd.Store {
		s, err := etcd.Open(etcd.Config{Endpoints: []string{srv.Endpoint}, TLS: srv.TLS(t, user), Prefix: prefix})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.Close() })
		return s
	}
	for _, who := range []string{"broker", "daemon"} {
		for _, c := range []struct{ name, sess, dir, su, du string }{
			{"directory inside session", "/port49/", "/port49/dir/", "a-", "b-"},
			{"session inside directory", "/port49/dir/", "/port49/", "b-", "a-"},
		} {
			t.Run(who+" "+c.name, func(t *testing.T) {
				err := checkTwoStores(context.Background(), twoPrefixes(c.dir, c.sess), open(c.su+who, c.sess),
					open(c.du+who, c.dir), 5*time.Second)
				if err == nil || !strings.Contains(err.Error(), "one keyspace named two ways") {
					t.Fatalf("%v", err)
				}
			})
		}
	}
}
