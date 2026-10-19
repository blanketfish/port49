package port49d

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/daemon/admin"
	"github.com/rhwendt/port49/internal/store"
	etcdstore "github.com/rhwendt/port49/internal/store/etcd"
	"github.com/rhwendt/port49/internal/store/etcd/etcdtest"
)

// R21's lines, exactly.
func TestRoleStatusLines(t *testing.T) {
	for _, c := range []struct {
		s    roleStatus
		want string
	}{
		{roleStatus{role: "directory", backend: "etcd", answering: 3, listed: 3, reachable: true, cache: true,
			age: 400 * time.Millisecond, aged: true}, "directory  etcd    3/3 members  reachable  cache 0.4s"},
		{roleStatus{role: "session", backend: "etcd", answering: 1, listed: 1, reachable: true},
			"session    etcd    1/1 members  reachable"},
		{roleStatus{role: "session", shares: true}, "session    shares the directory store"},
		{roleStatus{role: "directory", backend: "memory"}, "directory  memory  in process"},
		{roleStatus{role: "directory", backend: "etcd", membersErr: true, cache: true, age: 41200 * time.Millisecond,
			aged: true, why: "store: unavailable: context deadline exceeded"},
			"directory  etcd    ?/? members  unreachable  cache 41.2s\n" +
				"           store: unavailable: context deadline exceeded"},
		{roleStatus{role: "directory", backend: "etcd", answering: 1, listed: 3, reachable: true, cache: true},
			"directory  etcd    1/3 members  reachable  cache none"},
		{roleStatus{role: "directory", backend: "etcd", answering: 3, listed: 3, reachable: true, cache: true,
			age: 3*time.Minute + 12*time.Second, aged: true}, "directory  etcd    3/3 members  reachable  cache 3m12s"},
		{roleStatus{role: "directory", backend: "etcd", membersErr: true, cache: true, age: 2 * time.Second, aged: true,
			pending: 2}, "directory  etcd    ?/? members  unreachable  cache 2.0s  2 logouts pending"},
		{roleStatus{role: "directory", backend: "etcd", membersErr: true, cache: true, age: 90 * time.Second, aged: true,
			snapshot: true}, "directory  etcd    ?/? members  unreachable  cache 1m30s (snapshot)"},
		// A feed down names itself: the cache's age stops at its last confirmation
		// (final review, M4).
		{roleStatus{role: "directory", backend: "etcd", answering: 3, listed: 3, reachable: true, cache: true,
			age: 40 * time.Second, aged: true, down: []string{"logouts"}, pending: 1},
			"directory  etcd    3/3 members  reachable  cache 40.0s  feeds down: logouts  1 logouts pending"},
	} {
		if got := c.s.line(); got != c.want {
			t.Errorf("%+v:\n got %q\nwant %q", c.s, got, c.want)
		}
	}
}

// answer reads each store: a session store that does not answer degrades the
// status though the directory does, and the snapshot and pending marks reach
// the directory's line (plan 11a, R21).
func TestStoreStatusAnswerReadsEachStore(t *testing.T) {
	d, sess := etcdtest.Start(t, etcdtest.Options{}), etcdtest.Start(t, etcdtest.Options{})
	proxy := etcdtest.NewProxy(t, strings.TrimPrefix(sess.Endpoint, "http://"))
	open := func(ep string) *etcdstore.Store {
		s, err := etcdstore.Open(etcdstore.Config{Endpoints: []string{ep}, Prefix: etcdtest.Prefix()})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.Close() })
		return s
	}
	h := &dirHandle{}
	h.set(open(d.Endpoint))
	ses := open("http://" + proxy.Addr())
	cfg := config.Config{}
	cfg.Stores.Directory = config.StoreConfig{Backend: config.BackendEtcd, Etcd: &config.EtcdConfig{CallTimeout: time.Second}}
	cfg.Stores.Session = config.StoreConfig{Backend: config.BackendEtcd, Etcd: &config.EtcdConfig{CallTimeout: 300 * time.Millisecond}}
	fresh := store.NewFreshness(time.Now)
	fresh.Seed(time.Now().Add(-90 * time.Second))
	st := newStoreStatus(cfg, h, ses, fresh)
	st.pending = func() int { return 2 }

	text, degraded, err := st.answer(context.Background())
	if err != nil || degraded || !strings.Contains(text, "directory  etcd    1/1 members  reachable  cache 1m") ||
		!strings.Contains(text, "(snapshot)  feeds down: marks  2 logouts pending") ||
		!strings.Contains(text, "session    etcd    1/1 members  reachable") {
		t.Fatalf("%q degraded=%v %v", text, degraded, err)
	}
	proxy.Hang(true)
	text, degraded, err = st.answer(context.Background())
	if err != nil || !degraded || !strings.Contains(text, "session    etcd    ?/? members  unreachable") ||
		!strings.Contains(text, "directory  etcd    1/1 members  reachable") {
		t.Fatalf("session cut: %q degraded=%v %v", text, degraded, err)
	}
	// A shared store has no session line of its own to fail.
	cfg.Stores.Shared = true
	text, degraded, _ = newStoreStatus(cfg, h, ses, fresh).answer(context.Background())
	if degraded || !strings.Contains(text, "session    shares the directory store") {
		t.Fatalf("shared: %q degraded=%v", text, degraded)
	}
	// Memory answers its two lines without a store.
	if text, degraded, _ = (*storeStatus)(nil).answer(context.Background()); degraded ||
		text != "directory  memory  in process\nsession    shares the directory store" {
		t.Fatalf("memory: %q %v", text, degraded)
	}
}

// With both stores hung at a call_timeout of 500ms, the status comes back over
// the socket, degraded and naming both stores, well inside the socket's own
// deadline: an operator in a partition gets lines, not EOF (R21).
func TestStoreStatusOverTheSocketWithBothStoresHung(t *testing.T) {
	d, sess := etcdtest.Start(t, etcdtest.Options{}), etcdtest.Start(t, etcdtest.Options{})
	dp := etcdtest.NewProxy(t, strings.TrimPrefix(d.Endpoint, "http://"))
	sp := etcdtest.NewProxy(t, strings.TrimPrefix(sess.Endpoint, "http://"))
	open := func(p *etcdtest.Proxy) *etcdstore.Store {
		s, err := etcdstore.Open(etcdstore.Config{Endpoints: []string{"http://" + p.Addr()}, Prefix: etcdtest.Prefix()})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.Close() })
		return s
	}
	h := &dirHandle{}
	h.set(open(dp))
	ses := open(sp)
	cfg := config.Config{}
	e := &config.EtcdConfig{CallTimeout: 500 * time.Millisecond}
	cfg.Stores.Directory = config.StoreConfig{Backend: config.BackendEtcd, Etcd: e}
	cfg.Stores.Session = config.StoreConfig{Backend: config.BackendEtcd, Etcd: e}
	st := newStoreStatus(cfg, h, ses, store.NewFreshness(time.Now))

	sock := filepath.Join(t.TempDir(), "p.sock")
	ln, err := admin.Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go (&admin.Server{Now: time.Now, StoreStatus: st.answer}).Serve(ctx, ln)
	dp.Hang(true)
	sp.Hang(true)

	start := time.Now()
	r, err := ask(sock, admin.Request{Op: "store_status"})
	if err != nil || !r.Degraded || strings.Count(r.Text, "unreachable") != 2 ||
		!strings.Contains(r.Text, "directory ") || !strings.Contains(r.Text, "session ") {
		t.Fatalf("%+v %v after %v", r, err, time.Since(start))
	}
	if took := time.Since(start); took > 900*time.Millisecond {
		t.Fatalf("both stores hung took %v, one call_timeout of 500ms expected, the stores and their reads being at once", took)
	}
}

// A Members failure on a reachable store says why (printed through printsafe).
func TestRoleStatusNamesAMembersFailureOnAReachableStore(t *testing.T) {
	got := roleStatus{role: "session", backend: "etcd", reachable: true, membersErr: true,
		why: "store: unavailable: member list\x1b[31m"}.line()
	want := "session    etcd    ?/? members  reachable\n           store: unavailable: member list?[31m"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}
