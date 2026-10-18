package port49d

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/store/etcd"
	"github.com/rhwendt/port49/internal/store/etcd/etcdtest"
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

// A probe that cannot complete refuses the start, naming the handle and a
// closed-set cause, never etcd's text.
func TestAHandleThatCannotWriteTheProbeRefusesTheStartWithItsCause(t *testing.T) {
	srv, _ := rolesMemberScoped(t, etcd.ScopeDirectory)
	open := func(user string) *etcd.Store {
		s, err := etcd.Open(etcd.Config{Endpoints: []string{srv.Endpoint}, TLS: srv.TLS(t, user), Prefix: "/port49/"})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.Close() })
		return s
	}
	// The daemon's directory role reads meta/ping, so ClusterID answers, and
	// writes nothing: the probe's write is refused.
	err := checkTwoStores(context.Background(), twoPrefixes("/port49/", "/port49/"), open("port49-broker"),
		open("port49-daemon"), 5*time.Second)
	if err == nil || !strings.Contains(err.Error(), "write its probe through the directory store (refused)") {
		t.Fatalf("%v", err)
	}
}
