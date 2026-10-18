package port49d

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/daemon/admin"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/directory"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/etcd"
	"github.com/rhwendt/port49/internal/store/etcd/etcdtest"
	"github.com/rhwendt/port49/internal/store/memory"
	"github.com/rhwendt/port49/internal/store/placement"
)

// rolesMemberScoped is a TLS etcd member with the roles of a keyspace
// holding scope's families (plan 11a, R23), and a proxy to it.
func rolesMemberScoped(t *testing.T, scope etcd.Scope) (*etcdtest.Server, *etcdtest.Proxy) {
	t.Helper()
	srv := etcdtest.Start(t, etcdtest.Options{TLS: true})
	var grants []etcdtest.Grant
	for _, g := range etcd.RolesFor("/port49/", scope) {
		grants = append(grants, etcdtest.Grant{Role: g.Role, Key: g.Key, RangeEnd: g.RangeEnd, Write: g.Write})
	}
	srv.EnableAuth(t, grants, map[string][]string{"port49-daemon": {etcd.RoleDaemon}, "port49-broker": {etcd.RoleBroker}})
	return srv, etcdtest.NewProxy(t, strings.TrimPrefix(srv.Endpoint, "https://"))
}

// twoStores gives f a directory store of its own on a member of its own: f's
// store becomes the session store.
func (f *fleet) twoStores(t *testing.T) {
	t.Helper()
	srv, _ := rolesMemberScoped(t, etcd.ScopeDirectory)
	f.twoStoresOn(t, srv)
}

// twoStoresOn is twoStores on a directory member another fleet made: two
// regions sharing one directory. The daemon and the broker each reach it
// through a proxy of their own.
func (f *fleet) twoStoresOn(t *testing.T, srv *etcdtest.Server) {
	t.Helper()
	ep := strings.TrimPrefix(srv.Endpoint, "https://")
	f.dsrv, f.dproxy, f.ddproxy = srv, etcdtest.NewProxy(t, ep), etcdtest.NewProxy(t, ep)
	dc, dk := srv.ClientFiles(t, "port49-daemon")
	bc, bk := srv.ClientFiles(t, "port49-broker")
	withDirectory(t, f.daemon, f.ddproxy, srv, "daemon", dc, dk)
	withDirectory(t, f.broker, f.dproxy, srv, "broker", bc, bk)
}

// withDirectory rewrites the file at path: its stores.directory block
// becomes stores.session, and a directory block before it names the member
// behind proxy, with the identity role (daemon or broker) at cert and key.
func withDirectory(t *testing.T, path string, proxy *etcdtest.Proxy, srv *etcdtest.Server, role, cert, key string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	dir := fmt.Sprintf("stores:\n  directory:\n    backend: etcd\n    etcd:\n      endpoints: [https://%s]\n"+
		"      ca_file: %s\n      %s: {cert_file: %s, key_file: %s}\n      call_timeout: 200ms\n  session:\n",
		proxy.Addr(), filepath.Join(srv.Dir, "ca.pem"), role, cert, key)
	body := strings.Replace(string(raw), "stores:\n  directory:\n", dir, 1)
	if body == string(raw) {
		t.Fatalf("%s has no stores.directory block", path)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// addUnderDirectoryEtcd inserts line (no indent, no newline) under the
// directory store's etcd: block, the first in a two-store file.
func addUnderDirectoryEtcd(t *testing.T, path, line string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	body := strings.Replace(string(raw), "    etcd:\n", "    etcd:\n      "+line+"\n", 1)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// keysUnder counts the keys under prefix on srv, read as etcd's root.
func keysUnder(t *testing.T, srv *etcdtest.Server, prefix string) int64 {
	t.Helper()
	resp, err := srv.Client(t, "root").Get(context.Background(), prefix, clientv3.WithPrefix(), clientv3.WithCountOnly())
	if err != nil {
		t.Fatal(err)
	}
	return resp.Count
}

// R11: on two stores port49-broker loads the marks from the directory store
// and writes a revocation's mark there, never in the session store.
func TestABrokerOnTwoStoresMarksInTheDirectory(t *testing.T) {
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	f := splitFleet(t)
	f.twoStores(t)
	f.judged(t)
	startBroker(t, f.broker, &out, 1)
	waitFor(t, &out, "port49-broker: store: 0 revocation(s) in force from the directory store")
	r, err := ask(adminSocketOf(t, f.broker), admin.Request{Op: "revoke", Principal: "user:alice@example.com"})
	if err != nil || r.Error != "" {
		t.Fatalf("%+v %v", r, err)
	}
	if n := keysUnder(t, f.dsrv, "/port49/v1/rv/"); n != 1 {
		t.Fatalf("%d marks in the directory store, want 1", n)
	}
	if n := keysUnder(t, f.srv, "/port49/v1/rv/"); n != 0 {
		t.Fatalf("%d marks in the session store, want 0", n)
	}
}

// Review Focus 5: with the directory cut, a revocation is refused within the
// directory's call_timeout, saying it could not be recorded, and the
// broker says the directory is not answering.
func TestARevocationWithTheDirectoryCutFailsPromptly(t *testing.T) {
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	f := splitFleet(t)
	f.twoStores(t)
	f.judged(t)
	startBroker(t, f.broker, &out, 1)
	f.dproxy.Hang(true)
	start := time.Now()
	r, err := ask(adminSocketOf(t, f.broker), admin.Request{Op: "revoke", Principal: "user:alice@example.com"})
	if err != nil || !strings.Contains(r.Error, "could not be recorded") || time.Since(start) > 5*time.Second {
		t.Fatalf("%+v %v after %v", r, err, time.Since(start))
	}
	waitWithin(t, &out, "port49-broker: directory store: not answering", 10*time.Second)
}

// R20: a mark another region made reaches this region's tokens: its runner
// follows it and deletes them from its own session store.
func TestAMarkMadeInAnotherRegionReachesThisRegionsTokens(t *testing.T) {
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	a := splitFleet(t)
	a.twoStores(t)
	a.judged(t)
	c := splitFleet(t)
	c.twoStoresOn(t, a.dsrv)
	c.judged(t)
	startBroker(t, a.broker, &out, 1)
	apiC, _ := startBroker(t, c.broker, &out, 2)
	// Both runners hold their keyspaces before the revocation: a replica that
	// does not run leaves a followed mark to the runner (R29).
	waitCountWithin(t, &out, "port49-broker: runner: took keyspace", 2, 30*time.Second)
	_ = mintOn(t, apiC, c.pki, "leaf1") // held unspent in region c; never printed
	if n := keysUnder(t, c.srv, "/port49/v1/t/"); n != 1 {
		t.Fatalf("setup: %d token record(s) in region c", n)
	}
	r, err := ask(adminSocketOf(t, a.broker), admin.Request{Op: "revoke", Principal: "user:alice@example.com"})
	if err != nil || r.Error != "" {
		t.Fatalf("%+v %v", r, err)
	}
	waitWithin(t, &out, "a revocation of user:alice@example.com made elsewhere reached 1 token key(s)", 30*time.Second)
	if n := keysUnder(t, c.srv, "/port49/v1/t/"); n != 0 {
		t.Fatalf("%d token record(s) left in region c's session store", n)
	}
}

// R5: the enrollment store is the directory store: an unlock written
// through the broker's handle lands in the directory member, under ul/.
func TestPasswordSignInUsesTheDirectoryStore(t *testing.T) {
	srv, proxy := rolesMemberScoped(t, etcd.ScopeDirectory)
	cfg, _ := signInConfig(t, "127.0.0.1:0")
	cfg.Broker.Directory.EnrollmentStore = directory.EnrollmentStore{Backend: config.BackendEtcd}
	cfg.Stores.Directory = config.StoreConfig{Backend: config.BackendEtcd, Etcd: &config.EtcdConfig{
		Endpoints: []string{"https://" + proxy.Addr()}, CallTimeout: 500 * time.Millisecond, BulkTimeout: 5 * time.Second,
		Breaker:     config.EtcdBreaker{Failures: 5, OpenFor: time.Second},
		MaxInFlight: config.EtcdInFlight{Token: 8, Context: 8, Bulk: 2}}}
	raw, err := etcd.Open(etcd.Config{Endpoints: []string{"https://" + proxy.Addr()}, TLS: srv.TLS(t, "port49-broker"),
		Prefix: "/port49/"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { raw.Close() })
	m := metrics.New(prometheus.NewRegistry())
	b := builtSignInBroker(t, cfg, m)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var out syncBuffer
	dir := &dirHandle{}
	dir.set(raw)
	wirePasswordSignIn(ctx, cfg, b, signInTestKeys, m, dir, &out)
	if err := b.Enrollments.PutUnlock(ctx, "user:alice@example.com", time.Now()); err != nil {
		t.Fatal(err)
	}
	if n := keysUnder(t, srv, "/port49/v1/ul/"); n != 1 {
		t.Fatalf("%d unlock record(s) in the directory store, want 1", n)
	}
}

// onWrite tells hook each write before it reaches w, on the writer's own
// goroutine: a test cuts the directory at the instant a line is said.
type onWrite struct {
	w    *syncBuffer
	hook func(line string)
}

func (o onWrite) Write(p []byte) (int, error) {
	o.hook(string(p))
	return o.w.Write(p)
}

// notServedBeforeTheFirstLoad starts port49-broker on a two-store fleet,
// cuts the directory the instant cutAt is said, and checks nothing is
// served while the load that follows cannot finish: the metrics listener's
// /readyz answers 503 and no "listening on" line is said. It then heals the
// directory and checks the broker serves, with the load done.
func notServedBeforeTheFirstLoad(t *testing.T, cutAt, stillAt, loadedAt string) {
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	f := splitFleet(t)
	f.twoStores(t)
	f.judged(t)
	addUnderDirectoryEtcd(t, f.broker, "bulk_timeout: 1s")
	var cut atomic.Bool
	stderr = onWrite{w: &out, hook: func(line string) {
		if strings.Contains(line, cutAt) && cut.CompareAndSwap(false, true) {
			f.dproxy.Hang(true)
		}
	}}
	metricsAt, _ := startBrokerNoWait(t, f.broker, &out, 1)
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if got := out.String(); strings.Contains(got, stillAt) || strings.Contains(got, "port49-broker: listening on ") {
			break
		}
	}
	if !strings.Contains(out.String(), stillAt) {
		t.Fatalf("the load that cannot finish was not said (%q):\n%s", stillAt, out.String())
	}
	if strings.Contains(out.String(), "port49-broker: listening on ") {
		t.Fatalf("served before the first load finished:\n%s", out.String())
	}
	if code := metricsReadyz(t, metricsAt); code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz answered %d before the first load finished, want 503", code)
	}
	f.dproxy.Hang(false)
	waitWithin(t, &out, "port49-broker: listening on ", 40*time.Second)
	if !strings.Contains(out.String(), loadedAt) {
		t.Fatalf("serving without the load said:\n%s", out.String())
	}
}

// Task 9 ruling 1: the router is handed the marks copy only after the first
// load of the marks, so until then nothing is served: no request can find a
// mark "absent" in a copy that has not loaded.
func TestNothingIsServedBeforeTheDirectorysMarksLoad(t *testing.T) {
	notServedBeforeTheFirstLoad(t, "port49-broker: ledger: ",
		"reading the revocations in force", "revocation(s) in force from the directory store")
}

// Task 9 ruling 1: and the logout set is loaded before the router is handed
// it, so a mint or a refresh is never waved through a set that has not loaded.
func TestNothingIsServedBeforeTheDirectorysLogoutsLoad(t *testing.T) {
	notServedBeforeTheFirstLoad(t, "revocation(s) in force from the directory store",
		"nothing is served yet; trying again in 5s", "revocation(s) in force from the directory store")
}

// metricsReadyz is the status /readyz answers on the metrics listener.
func metricsReadyz(t *testing.T, addr string) int {
	t.Helper()
	resp, err := http.Get("http://" + addr + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

// The start's role check runs per store (Task 9 ruling 6): on a directory
// store the broker's role must reach ul/, which the shared-store check never
// probes. A broker whose role lacks it is refused, naming
// stores.directory.etcd.broker and the family.
func TestTheDirectorysRoleCheckRefusesABrokerWithoutUnlockRecords(t *testing.T) {
	const prefix = "/port49/"
	srv := etcdtest.Start(t, etcdtest.Options{TLS: true})
	var grants []etcdtest.Grant
	for _, g := range etcd.RolesFor(prefix, etcd.ScopeDirectory) {
		if g.Role == etcd.RoleBroker {
			continue
		}
		grants = append(grants, etcdtest.Grant{Role: g.Role, Key: g.Key, RangeEnd: g.RangeEnd, Write: g.Write})
	}
	// The broker reaches every directory family but ul/.
	for _, fam := range []string{"rv/", "mb/", "mk/", "lo/", "sf/", "meta/"} {
		k := prefix + "v1/" + fam
		grants = append(grants, etcdtest.Grant{Role: etcd.RoleBroker, Key: k, RangeEnd: clientv3.GetPrefixRangeEnd(k), Write: true})
	}
	srv.EnableAuth(t, grants, map[string][]string{"port49-daemon": {etcd.RoleDaemon}, "port49-broker": {etcd.RoleBroker}})
	tc := srv.TLS(t, "port49-broker")
	b, err := etcd.Open(etcd.Config{Endpoints: []string{srv.Endpoint}, TLS: tc, Prefix: prefix})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })
	leaf, err := x509.ParseCertificate(tc.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	e := &config.EtcdConfig{CallTimeout: 2 * time.Second, Roles: config.RolesEnforced}
	ref := storeRef{at: "stores.directory", scope: etcd.ScopeDirectory, dir: true}
	err = checkRoles(context.Background(), nil, b, e, map[string]*x509.Certificate{"broker": leaf}, ref)
	if err == nil || !strings.Contains(err.Error(), "stores.directory.etcd.broker") || !strings.Contains(err.Error(), "ul/") {
		t.Fatalf("a broker without ul/ passed the directory check, or was refused for another reason: %v", err)
	}
}

// An operator at 3am is not told a broker is serving when it is not: on one
// store the outage line says the broker refuses requests, not that it serves
// from a cache; on a split the cache wording stays. Both are pinned.
func TestTheDirectoryOutageLineIsTrueForTheDeployment(t *testing.T) {
	srv, proxy := rolesMemberScoped(t, etcd.ScopeDirectory)
	raw, err := etcd.Open(etcd.Config{Endpoints: []string{"https://" + proxy.Addr()}, TLS: srv.TLS(t, "port49-broker"),
		Prefix: "/port49/"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { raw.Close() })
	every := directoryCheckEvery
	t.Cleanup(func() { directoryCheckEvery = every })
	directoryCheckEvery = 20 * time.Millisecond
	for _, c := range []struct {
		name       string
		shared     bool
		down, up   string
		mustNotSay string
	}{
		{"shared", true, "port49-broker: store: not answering (not opened yet): this broker refuses requests until it " +
			"returns\n", "port49-broker: store: answering again\n", "the one store is not answering"},
		{"split", false, "port49-broker: directory store: not answering (", "port49-broker: directory store: answering again; the cache was ",
			"refuses requests until it returns"},
	} {
		t.Run(c.name, func(t *testing.T) {
			var out syncBuffer
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			h := &dirHandle{} // not opened yet: does not answer
			done := make(chan struct{})
			go func() {
				defer close(done)
				keepFresh(ctx, h, store.NewFreshness(time.Now), time.Second, &out, "port49-broker", c.shared)
			}()
			waitWithin(t, &out, c.down, 5*time.Second)
			h.set(raw)
			waitWithin(t, &out, c.up, 5*time.Second)
			cancel()
			<-done
			if strings.Contains(out.String(), c.mustNotSay) {
				t.Fatalf("%s: the line says %q:\n%s", c.name, c.mustNotSay, out.String())
			}
		})
	}
}

// pendingFake is a region's session store holding pending logouts.
type pendingFake struct{ es []store.LogoutEntry }

func (p pendingFake) Logouts(context.Context) (uint64, []store.LogoutEntry, error) {
	return 1, p.es, nil
}
func (p pendingFake) DeleteLogout(context.Context, string) error { return nil }

// cutDirectory takes no logout.
type cutDirectory struct{}

func (cutDirectory) PutLogout(context.Context, store.Logout, time.Duration) error {
	return fmt.Errorf("%w: cut", store.ErrUnavailable)
}

// M1: port49_store_logouts_pending is this replica's while it runs the
// duties; when they end (the hold moved) it is 0, so a sum() across replicas
// does not count the same pending logouts twice.
func TestThePendingLogoutsGaugeIsZeroedWhenTheDutiesEnd(t *testing.T) {
	m := metrics.New(prometheus.NewRegistry())
	st := placement.Wrap(placement.Config{Session: memory.New(time.Now), Directory: cutDirectory2{},
		Logouts: store.NewLogoutSet(time.Now), LogoutDir: cutDirectory{}, CallTimeout: 100 * time.Millisecond})
	rn := &runner{m: m, st: st}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		rn.forwardPendingFrom(ctx, pendingFake{es: []store.LogoutEntry{
			{Logout: store.Logout{Key: "k1"}, Until: time.Now().Add(time.Hour)},
			{Logout: store.Logout{Key: "k2"}, Until: time.Now().Add(time.Hour)}}})
	}()
	for deadline := time.Now().Add(5 * time.Second); testutil.ToFloat64(m.StoreLogoutsPending) != 2; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("the gauge never read 2: %v", testutil.ToFloat64(m.StoreLogoutsPending))
		}
	}
	cancel()
	<-done
	if got := testutil.ToFloat64(m.StoreLogoutsPending); got != 0 || rn.pending.Load() != 0 {
		t.Fatalf("after the duties ended: gauge %v, count %d", got, rn.pending.Load())
	}
}

// cutDirectory2 is the revocation half of a directory that never answers.
type cutDirectory2 struct{ placement.Directory }

// M2: a split broker's pins and logouts feeds read down from the first
// moment, before their feeds first run, so an alert on feed_up == 0 sees a
// broker stuck before them.
func TestASplitBrokerSaysItsPinsAndLogoutsFeedsAreDownFromTheStart(t *testing.T) {
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	f := splitFleet(t)
	f.twoStores(t)
	f.judged(t)
	f.dproxy.Hang(true) // the broker waits for the directory store, its feeds not yet run
	metricsAt, _ := startBrokerNoWait(t, f.broker, &out, 1)
	waitWithin(t, &out, "directory store: etcd at", 30*time.Second)
	resp, err := http.Get("http://" + metricsAt + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	for _, feed := range []string{"pins", "logouts", "marks", "contexts"} {
		if !strings.Contains(string(raw), `port49_store_feed_up{feed="`+feed+`"} 0`) {
			t.Errorf("no port49_store_feed_up{feed=%q} 0 series", feed)
		}
	}
}

// M3: a mark already in the directory store at start is in force on the very
// first request, and it is the directory's marks that load: a session store
// holding none must not be what the broker reads them from.
func TestAMarkAlreadyInTheDirectoryIsInForceOnTheFirstRequest(t *testing.T) {
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	f := splitFleet(t)
	f.twoStores(t)
	f.judged(t)
	raw, err := etcd.Open(etcd.Config{Endpoints: []string{f.dsrv.Endpoint}, TLS: f.dsrv.TLS(t, "port49-broker"), Prefix: "/port49/"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { raw.Close() })
	if err := raw.PutRevocation(context.Background(), store.Revocation{Kind: store.RevocationPrincipal,
		Key: "user:alice@example.com", At: time.Now(), Origin: "admin_socket uid 0"}); err != nil {
		t.Fatal(err)
	}
	api, _ := startBroker(t, f.broker, &out, 1)
	if !strings.Contains(out.String(), "port49-broker: store: 1 revocation(s) in force from the directory store") {
		t.Fatalf("the directory's mark was not loaded:\n%s", out.String())
	}
	if status, login, body := mintOnce(t, api, f.pki, "leaf1"); status == http.StatusOK || login != "" {
		t.Fatalf("a mint on the first request was served although the directory holds a mark: %d %s", status, body)
	}
}

// R27: a directory last written under a key this configuration does not
// hold refuses port49-broker's start, naming the directory store and the
// key id, never key material.
func TestADirectoryUnderAKeyThisRegionLacksRefusesTheStart(t *testing.T) {
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	f := splitFleet(t)
	f.twoStores(t)
	f.judged(t)
	if _, err := f.dsrv.Client(t, "root").Put(context.Background(), "/port49/v1/meta/seal_keys",
		`{"current":"key-from-elsewhere","written_at":"2026-10-17T00:00:00Z"}`); err != nil {
		t.Fatal(err)
	}
	errc := make(chan error, 1)
	go func() { errc <- runBroker(context.Background(), f.broker) }()
	select {
	case err := <-errc:
		if err == nil || !strings.Contains(err.Error(), "the directory store (etcd ") ||
			!strings.Contains(err.Error(), "key-from-elsewhere") ||
			!strings.Contains(err.Error(), "which this configuration does not hold") ||
			!strings.Contains(err.Error(), "set encryption.previous to \"key-from-elsewhere\"") ||
			strings.HasPrefix(err.Error(), "port49-broker:") { // main adds it
			t.Fatalf("%v", err)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("port49-broker started against a directory under a key it lacks")
	}
}

// R27: port49-broker records its window in the directory store at start.
func TestABrokerRecordsItsKeyWindowInTheDirectory(t *testing.T) {
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	f := splitFleet(t)
	f.twoStores(t)
	f.judged(t)
	startBroker(t, f.broker, &out, 1)
	if n := keysUnder(t, f.dsrv, "/port49/v1/meta/seal_keys"); n != 1 {
		t.Fatalf("%d key window record(s) in the directory store, want 1", n)
	}
	resp, err := f.dsrv.Client(t, "root").Get(context.Background(), "/port49/v1/meta/seal_keys")
	var rec struct {
		Current string `json:"current"`
	}
	if err != nil || len(resp.Kvs) != 1 || json.Unmarshal(resp.Kvs[0].Value, &rec) != nil || rec.Current == "" {
		t.Fatalf("the record does not name this window's current key id: %v", err)
	}
}

// R27: a running runner says, at its recheck, a directory now under a key
// it lacks (a region that rotated out of order).
func TestARunnerSaysADirectoryKeyItLacks(t *testing.T) {
	var out syncBuffer
	e, every := stderr, directoryKeysRecheckEvery
	t.Cleanup(func() { stderr, directoryKeysRecheckEvery = e, every })
	stderr, directoryKeysRecheckEvery = &out, time.Second
	f := splitFleet(t)
	f.twoStores(t)
	f.judged(t)
	startBroker(t, f.broker, &out, 1)
	waitWithin(t, &out, "port49-broker: runner: took keyspace", 30*time.Second)
	if _, err := f.dsrv.Client(t, "root").Put(context.Background(), "/port49/v1/meta/seal_keys",
		`{"current":"key-from-elsewhere","written_at":"2026-10-17T00:00:00Z"}`); err != nil {
		t.Fatal(err)
	}
	waitWithin(t, &out, "this process keeps running", 10*time.Second)
	if strings.Contains(out.String(), "port49-broker: port49-broker") {
		t.Fatalf("a doubled prefix:\n%s", out.String())
	}
}

// R28: stores.directory naming the session store's own cluster and prefix
// through another address is one keyspace, and port49-broker refuses it.
func TestOneClusterNamedTwiceIsRefused(t *testing.T) {
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	f := splitFleet(t)
	f.judged(t)             // before the split, which this start refuses
	f.twoStoresOn(t, f.srv) // the session store's own member, through a proxy of its own
	errc := make(chan error, 1)
	go func() { errc <- runBroker(context.Background(), f.broker) }()
	select {
	case err := <-errc:
		if err == nil || !strings.Contains(err.Error(), "reach one etcd cluster") {
			t.Fatalf("%v", err)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("port49-broker started with one keyspace named twice")
	}
}

// A key window record that decodes with no key id is as good as unreadable:
// the broker says so and writes its own window over it, with no operator step.
func TestAKeyWindowRecordWithNoIdIsRewrittenAtStart(t *testing.T) {
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	f := splitFleet(t)
	f.twoStores(t)
	f.judged(t)
	root := f.dsrv.Client(t, "root")
	if _, err := root.Put(context.Background(), "/port49/v1/meta/seal_keys",
		`{"current":"","written_at":"2026-10-17T00:00:00Z"}`); err != nil {
		t.Fatal(err)
	}
	startBroker(t, f.broker, &out, 1)
	if !strings.Contains(out.String(), "the directory store's key window (/port49/v1/meta/seal_keys) does not name a "+
		"readable key id; rewritten with this process's window") {
		t.Fatalf("the rewrite was not said:\n%s", out.String())
	}
	resp, err := root.Get(context.Background(), "/port49/v1/meta/seal_keys")
	var rec struct {
		Current string `json:"current"`
	}
	if err != nil || len(resp.Kvs) != 1 || json.Unmarshal(resp.Kvs[0].Value, &rec) != nil || rec.Current == "" {
		t.Fatalf("the record was not rewritten: %v", err)
	}
}
