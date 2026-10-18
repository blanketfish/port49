package port49d

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
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
	"github.com/rhwendt/port49/internal/tacacs/wire"
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
	if srv != f.srv {
		regrant(t, f.srv, "/port49/", etcd.ScopeSession)
	}
	ep := strings.TrimPrefix(srv.Endpoint, "https://")
	f.dsrv, f.dproxy, f.ddproxy = srv, etcdtest.NewProxy(t, ep), etcdtest.NewProxy(t, ep)
	dc, dk := srv.ClientFiles(t, "port49-daemon")
	bc, bk := srv.ClientFiles(t, "port49-broker")
	withDirectory(t, f.daemon, f.ddproxy, srv, "daemon", dc, dk)
	withDirectory(t, f.broker, f.dproxy, srv, "broker", bc, bk)
}

// regrant replaces the roles a member was started with (a shared keyspace's)
// by those of a keyspace holding scope's families, as a session store of its
// own has them (R23): the daemon there reads the marks snapshot at ds/m/.
func regrant(t *testing.T, srv *etcdtest.Server, prefix string, scope etcd.Scope) {
	t.Helper()
	ctx := context.Background()
	root := srv.Client(t, "root")
	for _, g := range etcd.Roles(prefix) {
		if _, err := root.RoleRevokePermission(ctx, g.Role, g.Key, g.RangeEnd); err != nil {
			t.Fatal(err)
		}
	}
	for _, g := range etcd.RolesFor(prefix, scope) {
		perm := clientv3.PermRead
		if g.Write {
			perm = clientv3.PermReadWrite
		}
		if _, err := root.RoleGrantPermission(ctx, g.Role, g.Key, g.RangeEnd, clientv3.PermissionType(perm)); err != nil {
			t.Fatal(err)
		}
	}
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

// Review Focus 1: a port49d cut from its directory keeps serving from its
// cache: an open session's commands, and a login with a token minted before
// the cut; port49_store_directory_reachable reads 0; the heal is said.
func TestADaemonCutFromItsDirectoryServesFromItsCache(t *testing.T) {
	var out, log syncBuffer
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o })
	stderr, stdout = &out, &log
	f := splitFleet(t)
	f.twoStores(t)
	f.judged(t)
	api, _ := startBroker(t, f.broker, &out, 1)
	dev := tacacsClient{t: t, addr: startSplitDaemon(t, f.daemon, &out, 1), key: []byte("run-test-secret")}
	waitFor(t, &out, "port49d: store: 0 revocation(s) in force from the directory store")
	loginSession(t, dev, mintOn(t, api, f.pki, "leaf1"), &log)
	tok := mintOn(t, api, f.pki, "leaf1")
	f.ddproxy.Hang(true)
	waitWithin(t, &out, "port49d: directory store: not answering", 10*time.Second)
	for i := 0; i < 3; i++ {
		if !dev.permits("alice", "show", "version") {
			t.Fatalf("a command was refused with the directory cut; log %s", log.String())
		}
	}
	if st := dev.login("alice", tok); st != wire.AuthenStatusPass {
		t.Fatalf("a token minted before the cut did not log in during it: status %d", st)
	}
	if v := metricAt(t, daemonMetrics(t, &out), "port49_store_directory_reachable"); v != 0 {
		t.Fatalf("port49_store_directory_reachable %v with the directory cut", v)
	}
	f.ddproxy.Hang(false)
	waitWithin(t, &out, "port49d: directory store: answering again", 10*time.Second)
}

// Review Focus 1, R17: a revocation made in another region while this one
// is cut does not reach it until the heal, and then does.
func TestAMarkMadeDuringACutReachesTheDaemonOnHeal(t *testing.T) {
	var out, log syncBuffer
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o })
	stderr, stdout = &out, &log
	a := splitFleet(t)
	a.twoStores(t)
	a.judged(t)
	c := splitFleet(t)
	c.twoStoresOn(t, a.dsrv)
	c.judged(t)
	startBroker(t, a.broker, &out, 1)
	apiC, stopC := startBroker(t, c.broker, &out, 2)
	dev := tacacsClient{t: t, addr: startSplitDaemon(t, c.daemon, &out, 1), key: []byte("run-test-secret")}
	loginSession(t, dev, mintOn(t, apiC, c.pki, "leaf1"), &log)
	// Region c's broker stops, so the daemon's own follow of the directory's
	// marks is the only way the mark can reach it.
	if err := stopC(); err != nil {
		t.Fatal(err)
	}
	c.dproxy.Hang(true)
	c.ddproxy.Hang(true)
	waitWithin(t, &out, "port49d: directory store: not answering", 10*time.Second)
	r, err := ask(adminSocketOf(t, a.broker), admin.Request{Op: "revoke", Principal: "user:alice@example.com"})
	if err != nil || r.Error != "" {
		t.Fatalf("%+v %v", r, err)
	}
	time.Sleep(2 * time.Second) // what a feed would need, had region c not been cut
	if !dev.permits("alice", "show", "version") {
		t.Fatal("region c denied the session during the cut: a mark made elsewhere cannot reach it until the heal (R17)")
	}
	c.dproxy.Hang(false)
	c.ddproxy.Hang(false)
	deadline := time.Now().Add(20 * time.Second)
	for dev.permits("alice", "show", "version") {
		if time.Now().After(deadline) {
			t.Fatal("region c's session was still permitted 20s after the heal")
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// Review Focus 2, R19: a cold start with the directory cut has no marks to
// serve from: the listeners never open, and it exits at start_timeout.
func TestAColdStartWithTheDirectoryCutStaysDark(t *testing.T) {
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	f := splitFleet(t)
	f.twoStores(t)
	addUnderDirectoryEtcd(t, f.daemon, "start_timeout: 5s")
	f.ddproxy.Hang(true)
	errc := make(chan error, 1)
	go func() { errc <- run(context.Background(), f.daemon) }()
	select {
	case err := <-errc:
		if err == nil || !strings.Contains(err.Error(), "stores.directory.etcd.start_timeout") {
			t.Fatalf("%v", err)
		}
	case <-time.After(45 * time.Second):
		t.Fatal("port49d did not give up on a directory that never answered")
	}
	if strings.Contains(out.String(), "port49d: listening on ") {
		t.Fatalf("port49d listened with no marks:\n%s", out.String())
	}
}

// Review Focus 2, R19: a run after a store gone holds its marks, and serves
// from them while the directory is still cut.
func TestARunAfterAStoreGoneServesThroughADirectoryCut(t *testing.T) {
	var out, log syncBuffer
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o })
	stderr, stdout = &out, &log
	f := splitFleet(t)
	f.twoStores(t)
	f.judged(t)
	api, _ := startBroker(t, f.broker, &out, 1)
	startSplitDaemon(t, f.daemon, &out, 1)
	f.ddproxy.Hang(true)
	f.proxy.Hang(true)
	waitWithin(t, &out, "closing every listener so that devices use their local method", 90*time.Second)
	f.proxy.Hang(false)
	waitCountWithin(t, &out, "port49d: listening on ", 2, 120*time.Second)
	addrs := regexp.MustCompile(`port49d: listening on (127\.0\.0\.1:\d+)`).FindAllStringSubmatch(out.String(), -1)
	dev := tacacsClient{t: t, addr: addrs[len(addrs)-1][1], key: []byte("run-test-secret")}
	loginSession(t, dev, mintOn(t, api, f.pki, "leaf1"), &log)
	if !dev.permits("alice", "show", "version") {
		t.Fatalf("a run after a store gone refused a command with the directory still cut; log %s", log.String())
	}
	if !strings.Contains(out.String(), "port49d: directory store: this run serves from the marks it holds") {
		t.Fatalf("the run did not say it serves from its marks:\n%s", out.String())
	}
}

// Carry (c): port49d's marks come from the directory store, not the session
// store: a mark the broker made is counted at the daemon's start, from the
// directory, and the session keyspace holds none.
func TestADaemonLoadsItsMarksFromTheDirectoryStore(t *testing.T) {
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	f := splitFleet(t)
	f.twoStores(t)
	f.judged(t)
	startBroker(t, f.broker, &out, 1)
	r, err := ask(adminSocketOf(t, f.broker), admin.Request{Op: "revoke", Principal: "user:alice@example.com"})
	if err != nil || r.Error != "" {
		t.Fatalf("%+v %v", r, err)
	}
	startSplitDaemon(t, f.daemon, &out, 1)
	waitFor(t, &out, "port49d: store: 1 revocation(s) in force from the directory store")
	if n := keysUnder(t, f.srv, "/port49/v1/rv/"); n != 0 {
		t.Fatalf("the session store holds %d mark(s)", n)
	}
	if n := keysUnder(t, f.dsrv, "/port49/v1/rv/"); n != 1 {
		t.Fatalf("the directory store holds %d mark(s), want 1", n)
	}
}

// Carry (b): the daemon's start runs the per-store role check on the
// directory: roles that reach past rv/, meta/ping and meta/seal_keys (here,
// a shared keyspace's) are refused, naming the directory block's identity.
func TestADaemonWhoseDirectoryRoleReachesTooFarIsRefused(t *testing.T) {
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	f := splitFleet(t)
	srv, _ := rolesMemberScoped(t, etcd.ScopeShared)
	f.twoStoresOn(t, srv)
	f.judged(t)
	errc := make(chan error, 1)
	go func() { errc <- run(context.Background(), f.daemon) }()
	select {
	case err := <-errc:
		if err == nil || !strings.Contains(err.Error(), "stores.directory.etcd.daemon") {
			t.Fatalf("%v", err)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("port49d started on a directory whose daemon role reaches past the marks")
	}
	if strings.Contains(out.String(), "port49d: listening on ") {
		t.Fatalf("port49d listened:\n%s", out.String())
	}
}

// R27: a directory last written under a key this configuration does not
// hold refuses port49d's start too, and port49d writes nothing there.
func TestADaemonRefusesADirectoryUnderAKeyThisRegionLacks(t *testing.T) {
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	f := splitFleet(t)
	f.twoStores(t)
	f.judged(t)
	const rec = `{"current":"key-from-elsewhere","written_at":"2026-10-17T00:00:00Z"}`
	root := f.dsrv.Client(t, "root")
	if _, err := root.Put(context.Background(), "/port49/v1/meta/seal_keys", rec); err != nil {
		t.Fatal(err)
	}
	errc := make(chan error, 1)
	go func() { errc <- run(context.Background(), f.daemon) }()
	select {
	case err := <-errc:
		if err == nil || !strings.Contains(err.Error(), "the directory store (etcd ") ||
			!strings.Contains(err.Error(), "key-from-elsewhere") ||
			!strings.Contains(err.Error(), "which this configuration does not hold") ||
			strings.Contains(err.Error(), "port49d: port49d:") {
			t.Fatalf("%v", err)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("port49d started against a directory under a key it lacks")
	}
	resp, err := root.Get(context.Background(), "/port49/v1/meta/seal_keys")
	if err != nil || len(resp.Kvs) != 1 || string(resp.Kvs[0].Value) != rec {
		t.Fatalf("port49d changed the directory's key window: %v", err)
	}
}

// R28: port49d refuses one keyspace named two ways, on its own identities:
// a directory at /port49/dir/ inside a session store at /port49/ on one
// member, each under roles of its own scope, so the role check passes and the
// lease probe is what finds one cluster.
func TestADaemonRefusesNestedPrefixesOnOneCluster(t *testing.T) {
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	f := splitFleet(t)
	f.judged(t)
	srv := etcdtest.Start(t, etcdtest.Options{TLS: true})
	var grants []etcdtest.Grant
	users := map[string][]string{}
	for set, c := range map[string]struct {
		prefix string
		scope  etcd.Scope
	}{"a": {"/port49/", etcd.ScopeSession}, "b": {"/port49/dir/", etcd.ScopeDirectory}} {
		for _, g := range etcd.RolesFor(c.prefix, c.scope) {
			grants = append(grants, etcdtest.Grant{Role: set + "-" + g.Role, Key: g.Key, RangeEnd: g.RangeEnd, Write: g.Write})
		}
		users[set+"-broker"] = []string{set + "-" + etcd.RoleBroker}
		users[set+"-daemon"] = []string{set + "-" + etcd.RoleDaemon}
	}
	srv.EnableAuth(t, grants, users)
	// The directory is named through a proxy, so the config's text compare
	// (R22) passes and only the lease probe can see one cluster.
	proxy := etcdtest.NewProxy(t, strings.TrimPrefix(srv.Endpoint, "https://"))
	block := func(user, prefix, endpoint string) string {
		c, k := srv.ClientFiles(t, user)
		return fmt.Sprintf("    backend: etcd\n    etcd:\n      endpoints: [%s]\n      ca_file: %s\n      prefix: %s\n"+
			"      daemon: {cert_file: %s, key_file: %s}\n      call_timeout: 500ms\n", endpoint,
			filepath.Join(srv.Dir, "ca.pem"), prefix, c, k)
	}
	raw, err := os.ReadFile(f.daemon)
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	body = body[:strings.Index(body, "stores:\n")] + "stores:\n  directory:\n" + block("b-daemon", "/port49/dir/", "https://"+proxy.Addr()) +
		"  session:\n    packet_deadline: 1s\n" + block("a-daemon", "/port49/", srv.Endpoint) + body[strings.Index(body, "admin_socket:"):]
	if err := os.WriteFile(f.daemon, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	errc := make(chan error, 1)
	go func() { errc <- run(context.Background(), f.daemon) }()
	select {
	case err := <-errc:
		if err == nil || !strings.Contains(err.Error(), "one keyspace named two ways") {
			t.Fatalf("%v\n%s", err, out.String())
		}
	case <-time.After(60 * time.Second):
		t.Fatal("port49d started with one keyspace named twice")
	}
}

// Carry (a): the marks copy loads before the first GetRevocation, so a cold
// start, cut from the directory after it opened it and before its marks
// loaded, serves nothing until they have: the
// listeners stay closed (a request is refused at the connect, never allowed
// on a copy that has not loaded), and the heal opens them with the load said.
func TestADaemonServesNothingBeforeItsMarksLoad(t *testing.T) {
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	f := splitFleet(t)
	f.twoStores(t)
	f.judged(t)
	var cut atomic.Bool
	stderr = onWrite{w: &out, hook: func(line string) {
		if strings.Contains(line, "port49d: directory store: the daemon's etcd certificate") && cut.CompareAndSwap(false, true) {
			f.ddproxy.Hang(true)
		}
	}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, f.daemon) }()
	t.Cleanup(func() { cancel(); <-done })
	const still = "the listeners stay closed; trying again in 5s"
	waitWithin(t, &out, still, 30*time.Second)
	if strings.Contains(out.String(), "port49d: listening on ") {
		t.Fatalf("served before the marks loaded:\n%s", out.String())
	}
	f.ddproxy.Hang(false)
	waitWithin(t, &out, "port49d: listening on ", 40*time.Second)
	if !strings.Contains(out.String(), "revocation(s) in force from the directory store") {
		t.Fatalf("serving without the load said:\n%s", out.String())
	}
}

// Task 10 review I2: a run after a store gone enforces a mark it holds. The
// mark is written to the directory as the broker's identity would, which
// leaves the token and the context alone, so the daemon's marks copy is the
// only thing that can refuse the login. The run that starts while the store
// is gone must refuse a token minted before the mark.
func TestAHeldRunStillEnforcesAMarkItHolds(t *testing.T) {
	var out, log syncBuffer
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o })
	stderr, stdout = &out, &log
	f := splitFleet(t)
	f.twoStores(t)
	f.judged(t)
	api, _ := startBroker(t, f.broker, &out, 1)
	startSplitDaemon(t, f.daemon, &out, 1)
	tok := mintOn(t, api, f.pki, "leaf1")
	dir, err := etcd.Open(etcd.Config{Endpoints: []string{f.dsrv.Endpoint}, TLS: f.dsrv.TLS(t, "port49-broker"),
		Prefix: "/port49/"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dir.Close() })
	if err := dir.PutRevocation(context.Background(), store.Revocation{Kind: store.RevocationPrincipal,
		Key: "user:alice@example.com", At: time.Now(), Origin: "test"}); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(20 * time.Second); metricAt(t, daemonMetrics(t, &out),
		`port49_revocations_in_force{by="principal"}`) != 1; time.Sleep(200 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the daemon never took the mark")
		}
	}
	f.ddproxy.Hang(true)
	f.proxy.Hang(true)
	waitWithin(t, &out, "closing every listener so that devices use their local method", 90*time.Second)
	f.proxy.Hang(false)
	waitCountWithin(t, &out, "port49d: listening on ", 2, 120*time.Second)
	addrs := regexp.MustCompile(`port49d: listening on (127\.0\.0\.1:\d+)`).FindAllStringSubmatch(out.String(), -1)
	dev := tacacsClient{t: t, addr: addrs[len(addrs)-1][1], key: []byte("run-test-secret")}
	if !strings.Contains(out.String(), "port49d: directory store: this run serves from the marks it holds (1)") {
		t.Fatalf("the held run did not say it holds the mark:\n%s", out.String())
	}
	if st := dev.login("alice", tok); st == wire.AuthenStatusPass {
		t.Fatal("a run after a store gone logged in a revoked principal: it forgot its marks")
	}
}

// Task 10 review I1: a held run runs the start checks before it follows a
// directory that answers late. Here the directory's key window names a key
// this region lacks: the run says so, never follows it, and keeps serving
// from the marks it holds.
func TestAHeldRunRefusesADirectoryThatFailsTheStartChecks(t *testing.T) {
	var out, log syncBuffer
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o })
	stderr, stdout = &out, &log
	f := splitFleet(t)
	f.twoStores(t)
	f.judged(t)
	api, _ := startBroker(t, f.broker, &out, 1)
	startSplitDaemon(t, f.daemon, &out, 1)
	f.ddproxy.Hang(true)
	f.proxy.Hang(true)
	waitWithin(t, &out, "closing every listener so that devices use their local method", 90*time.Second)
	if _, err := f.dsrv.Client(t, "root").Put(context.Background(), "/port49/v1/meta/seal_keys",
		`{"current":"key-from-elsewhere","written_at":"2026-10-17T00:00:00Z"}`); err != nil {
		t.Fatal(err)
	}
	f.proxy.Hang(false)
	waitCountWithin(t, &out, "port49d: listening on ", 2, 120*time.Second)
	addrs := regexp.MustCompile(`port49d: listening on (127\.0\.0\.1:\d+)`).FindAllStringSubmatch(out.String(), -1)
	dev := tacacsClient{t: t, addr: addrs[len(addrs)-1][1], key: []byte("run-test-secret")}
	loginSession(t, dev, mintOn(t, api, f.pki, "leaf1"), &log)
	mark := len(out.String())
	f.ddproxy.Hang(false)
	waitWithinFrom(t, &out, mark, "port49d: directory store: not followed yet (crypt: the directory store (etcd ", 30*time.Second)
	if got := out.String()[mark:]; !strings.Contains(got, "key-from-elsewhere") || strings.Contains(got, "port49d: port49d:") {
		t.Fatalf("the refusal reads wrong:\n%s", got)
	}
	r, err := ask(adminSocketOf(t, f.broker), admin.Request{Op: "revoke", Principal: "user:alice@example.com"})
	if err != nil || r.Error != "" {
		t.Fatalf("%+v %v", r, err)
	}
	time.Sleep(4 * time.Second) // what a followed directory would need
	// The broker's revoke also ends the session's context, so the observable
	// is the mark count: a followed directory would put the mark in the copy.
	if v := metricAt(t, daemonMetrics(t, &out), `port49_revocations_in_force{by="principal"}`); v != 0 {
		t.Fatalf("the run followed a directory that failed the start checks: %v mark(s) in force", v)
	}
}

// waitSnapshots waits until srv's session keyspace holds the region's
// first snapshot records: marks records from n processes, and a broker
// record.
func waitSnapshots(t *testing.T, srv *etcdtest.Server, n int64) {
	t.Helper()
	for deadline := time.Now().Add(30 * time.Second); keysUnder(t, srv, "/port49/v1/ds/m/") < n ||
		keysUnder(t, srv, "/port49/v1/ds/b/") < 1; time.Sleep(200 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("fewer than %d marks record(s), or no broker record, were written", n)
		}
	}
}

// Review Focus, R19: port49-broker and port49d restarted during a cut each
// serve from the region's snapshot: a mint answers, and a session's command
// is permitted.
func TestARestartDuringACutServesFromTheSnapshot(t *testing.T) {
	var out, log syncBuffer
	e, o, every := stderr, stdout, snapshotEvery
	t.Cleanup(func() { stderr, stdout, snapshotEvery = e, o, every })
	stderr, stdout, snapshotEvery = &out, &log, time.Second
	f := splitFleet(t)
	f.twoStores(t)
	f.judged(t)
	_, stopB := startBroker(t, f.broker, &out, 1)
	_, stopD := runSplitDaemon(t, f.daemon, &out, 1)
	waitSnapshots(t, f.srv, 2)
	f.dproxy.Hang(true)
	f.ddproxy.Hang(true)
	if err := stopD(); errors.Is(err, errDidNotStop) {
		t.Fatal(err)
	}
	if err := stopB(); errors.Is(err, errDidNotStop) {
		t.Fatal(err)
	}
	api, _ := startBroker(t, f.broker, &out, 2)
	dev := tacacsClient{t: t, addr: startSplitDaemon(t, f.daemon, &out, 2), key: []byte("run-test-secret")}
	for _, want := range []string{"port49-broker: directory store: not answering; serving from 2 snapshot(s)",
		"port49d: directory store: not answering; serving from 2 snapshot(s)"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("no %q:\n%s", want, out.String())
		}
	}
	loginSession(t, dev, mintOn(t, api, f.pki, "leaf1"), &log)
	if !dev.permits("alice", "show", "version") {
		t.Fatalf("a restart during the cut refused a command; log %s", log.String())
	}
}

// R19: a process serving a snapshot fails closed at the ceiling: port49d
// says so and closes its listeners.
func TestASnapshotPastTheCeilingFailsClosed(t *testing.T) {
	var out syncBuffer
	e, every, ceiling := stderr, snapshotEvery, snapshotCeiling
	t.Cleanup(func() { stderr, snapshotEvery, snapshotCeiling = e, every, ceiling })
	stderr, snapshotEvery = &out, time.Second
	snapshotCeiling = func(config.Config) time.Duration { return 20 * time.Second }
	f := splitFleet(t)
	f.twoStores(t)
	f.judged(t)
	startBroker(t, f.broker, &out, 1)
	_, stopD := runSplitDaemon(t, f.daemon, &out, 1)
	waitSnapshots(t, f.srv, 2)
	f.ddproxy.Hang(true)
	if err := stopD(); errors.Is(err, errDidNotStop) {
		t.Fatal(err)
	}
	startSplitDaemon(t, f.daemon, &out, 2)
	waitWithin(t, &out, "port49d: directory store: the snapshot this run serves from is", 60*time.Second)
	waitWithin(t, &out, "past session.staleness_ceiling (20s)", time.Second)
	waitWithin(t, &out, "closing every listener so that devices use their local method", 10*time.Second)
}

// R29: a runner taking over during a cut runs its session duties: the
// takeover finishes (a mint answers), the put-back waits for the directory
// and says so, and lands on the heal.
func TestATakeoverDuringACutRunsTheSessionDuties(t *testing.T) {
	var out syncBuffer
	e, every := stderr, snapshotEvery
	t.Cleanup(func() { stderr, snapshotEvery = e, every })
	stderr, snapshotEvery = &out, time.Second
	f := splitFleet(t)
	f.twoStores(t)
	f.judged(t)
	_, stop := startBroker(t, f.broker, &out, 1)
	waitWithin(t, &out, "port49-broker: runner: took keyspace", 30*time.Second)
	waitSnapshots(t, f.srv, 1)
	f.dproxy.Hang(true)
	if err := stop(); errors.Is(err, errDidNotStop) {
		t.Fatal(err)
	}
	api, _ := startBroker(t, f.broker, &out, 2)
	waitCountWithin(t, &out, "port49-broker: runner: took keyspace", 2, 60*time.Second)
	waitWithin(t, &out, "the put-back of broker.state_dir/marks.json waits for the directory store", 30*time.Second)
	_ = mintOn(t, api, f.pki, "leaf1") // the start's mint gate opened: the takeover finished in the cut
	f.dproxy.Hang(false)
	waitWithin(t, &out, "every revocation in broker.state_dir/marks.json is in the store", 60*time.Second)
}

// N2: a key fault found when the directory opens after a snapshot start
// ends port49d, exit 1, with the check's message; the listeners never open
// again.
func TestADeferredKeyFaultEndsPort49d(t *testing.T) {
	var out syncBuffer
	e, every := stderr, snapshotEvery
	t.Cleanup(func() { stderr, snapshotEvery = e, every })
	stderr, snapshotEvery = &out, time.Second
	f := splitFleet(t)
	f.twoStores(t)
	f.judged(t)
	startBroker(t, f.broker, &out, 1)
	_, stopD := runSplitDaemon(t, f.daemon, &out, 1)
	waitSnapshots(t, f.srv, 2)
	f.ddproxy.Hang(true)
	if err := stopD(); errors.Is(err, errDidNotStop) {
		t.Fatal(err)
	}
	errc := make(chan error, 1)
	go func() { errc <- run(context.Background(), f.daemon) }()
	waitCountWithin(t, &out, "port49d: listening on ", 2, 60*time.Second) // served from the snapshots
	if _, err := f.dsrv.Client(t, "root").Put(context.Background(), "/port49/v1/meta/seal_keys",
		`{"current":"key-from-elsewhere","written_at":"2026-10-17T00:00:00Z"}`); err != nil {
		t.Fatal(err)
	}
	f.ddproxy.Hang(false)
	select {
	case err := <-errc:
		if err == nil || !strings.Contains(err.Error(), "which this configuration does not hold") {
			t.Fatalf("%v", err)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("port49d kept running with a directory under a key it lacks")
	}
	if n := strings.Count(out.String(), "port49d: listening on "); n != 2 {
		t.Fatalf("the listeners opened %d times; want 2 (the first run, the snapshot run), no flapping", n)
	}
}

// Task 10a review I1: a deferred check fault found in a run after a store
// gone (a snapshot past its ceiling, then a younger one served) ends port49d
// as it does a cold start's, not a retry every 5s.
func TestADeferredKeyFaultAfterACeilingEndsPort49d(t *testing.T) {
	var out syncBuffer
	e, every, ceiling := stderr, snapshotEvery, snapshotCeiling
	t.Cleanup(func() { stderr, snapshotEvery, snapshotCeiling = e, every, ceiling })
	stderr, snapshotEvery = &out, time.Second
	snapshotCeiling = func(config.Config) time.Duration { return 20 * time.Second }
	f := splitFleet(t)
	f.twoStores(t)
	f.judged(t)
	startBroker(t, f.broker, &out, 1)
	_, stopD := runSplitDaemon(t, f.daemon, &out, 1)
	waitSnapshots(t, f.srv, 2)
	f.ddproxy.Hang(true)
	if err := stopD(); errors.Is(err, errDidNotStop) {
		t.Fatal(err)
	}
	errc := make(chan error, 1)
	go func() { errc <- run(context.Background(), f.daemon) }()
	waitWithin(t, &out, "closing every listener so that devices use their local method", 90*time.Second)
	// The live broker keeps writing records: the next run serves a younger one.
	waitCountWithin(t, &out, "port49d: listening on ", 3, 90*time.Second)
	if _, err := f.dsrv.Client(t, "root").Put(context.Background(), "/port49/v1/meta/seal_keys",
		`{"current":"key-from-elsewhere","written_at":"2026-10-17T00:00:00Z"}`); err != nil {
		t.Fatal(err)
	}
	f.ddproxy.Hang(false)
	select {
	case err := <-errc:
		if err == nil || !strings.Contains(err.Error(), "which this configuration does not hold") {
			t.Fatalf("%v", err)
		}
	case <-time.After(60 * time.Second):
		t.Fatalf("port49d kept starting again over a directory under a key it lacks:\n%.2000s", out.String())
	}
}

// Task 10a review I2: a ceiling gone with no younger snapshot in the session
// store keeps the listeners closed until the directory answers.
func TestACeilingWithNoYoungerSnapshotKeepsTheListenersClosed(t *testing.T) {
	var out syncBuffer
	e, every, ceiling := stderr, snapshotEvery, snapshotCeiling
	t.Cleanup(func() { stderr, snapshotEvery, snapshotCeiling = e, every, ceiling })
	stderr, snapshotEvery = &out, time.Second
	snapshotCeiling = func(config.Config) time.Duration { return 20 * time.Second }
	f := splitFleet(t)
	f.twoStores(t)
	f.judged(t)
	_, stopB := startBroker(t, f.broker, &out, 1)
	_, stopD := runSplitDaemon(t, f.daemon, &out, 1)
	waitSnapshots(t, f.srv, 2)
	f.ddproxy.Hang(true)
	if err := stopD(); errors.Is(err, errDidNotStop) {
		t.Fatal(err)
	}
	if err := stopB(); errors.Is(err, errDidNotStop) {
		t.Fatal(err)
	}
	startSplitDaemon(t, f.daemon, &out, 2)
	waitWithin(t, &out, "closing every listener so that devices use their local method", 90*time.Second)
	waitWithin(t, &out, "no snapshot in the session store is younger than session.staleness_ceiling (20s)", 60*time.Second)
	time.Sleep(3 * time.Second)
	if n := strings.Count(out.String(), "port49d: listening on "); n != 2 {
		t.Fatalf("the listeners opened %d times; want 2 (the first run, the snapshot run)", n)
	}
}
