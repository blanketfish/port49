package port49d

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/etcd"
	"github.com/rhwendt/port49/internal/store/etcd/etcdtest"
	"github.com/rhwendt/port49/internal/tacacs/wire"
	"github.com/rhwendt/port49/internal/testpki"
)

// etcdRun is a port49d config on a TLS etcd member with port49's roles,
// through a proxy the test can hang: the run_test.go config with a store:
// block and an admin_socket appended (etcd requires one, Ruling 13).
func etcdRun(t *testing.T) (cfgPath, pkiDir, revocations string, proxy *etcdtest.Proxy) {
	t.Helper()
	cfgPath, pkiDir, revocations, proxy, _ = etcdRunServer(t)
	return cfgPath, pkiDir, revocations, proxy
}

// etcdRunServer is etcdRun with the member, for a test that writes the
// store as its root.
func etcdRunServer(t *testing.T) (cfgPath, pkiDir, revocations string, proxy *etcdtest.Proxy, srv *etcdtest.Server) {
	t.Helper()
	return etcdRunServerWith(t, minimalPolicy, nil)
}

// etcdRunServerWith is etcdRunServer on policyBody, with a lab client
// certificate for each of others (brokerConfigWith).
func etcdRunServerWith(t *testing.T, policyBody string, others []string) (cfgPath, pkiDir, revocations string,
	proxy *etcdtest.Proxy, srv *etcdtest.Server) {
	t.Helper()
	srv = etcdtest.Start(t, etcdtest.Options{TLS: true})
	var grants []etcdtest.Grant
	for _, g := range etcd.Roles("/port49/") {
		grants = append(grants, etcdtest.Grant{Role: g.Role, Key: g.Key, RangeEnd: g.RangeEnd, Write: g.Write})
	}
	srv.EnableAuth(t, grants, map[string][]string{"port49-daemon": {etcd.RoleDaemon}, "port49-broker": {etcd.RoleBroker}})
	proxy = etcdtest.NewProxy(t, strings.TrimPrefix(srv.Endpoint, "https://"))
	dc, dk := srv.ClientFiles(t, "port49-daemon")
	bc, bk := srv.ClientFiles(t, "port49-broker")
	b := brokerConfigWith(t, policyBody, others).Broker
	cfgPath = writeRunConfig(t, b)
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	// A TACACS+ connection held across a hang outlives the default 30s
	// idle timeout, so it is reset by the store gone, not closed idle.
	raw = append(raw, []byte(fmt.Sprintf("\nstore:\n  backend: etcd\n  packet_deadline: 1s\n  etcd:\n"+
		"    endpoints: [https://%s]\n    ca_file: %s\n    daemon: {cert_file: %s, key_file: %s}\n"+
		"    broker: {cert_file: %s, key_file: %s}\n    call_timeout: 200ms\n    hold_ttl: 10s\n"+
		"    breaker: {failures: 3, open_for: 2s}\nadmin_socket: %s\nlimits: {idle_timeout: 2m}\n",
		proxy.Addr(), filepath.Join(srv.Dir, "ca.pem"), dc, dk, bc, bk, filepath.Join(t.TempDir(), "a.sock")))...)
	if err := os.WriteFile(cfgPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return cfgPath, filepath.Dir(b.TLSCertFile), b.RevocationsFile, proxy, srv
}

// startRun runs port49d on cfgPath until the test ends or stop is called,
// and returns the TACACS+ and broker addresses of its nth run in out: it
// waits for the nth "broker listening" line, never an earlier run's
// (pre-flight M37), and reads the newest addresses.
func startRun(t *testing.T, cfgPath string, out *syncBuffer, n int) (tacacs, brokerAddr string, stop func() error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfgPath) }()
	stopped := false
	stop = func() error {
		if stopped {
			return nil
		}
		stopped = true
		cancel()
		select {
		case err := <-done:
			return err
		case <-time.After(15 * time.Second):
			return fmt.Errorf("port49d did not stop")
		}
	}
	t.Cleanup(func() { stop() })
	waitCountWithin(t, out, "port49d: broker listening on ", n, 30*time.Second)
	tacacs, brokerAddr = newestAddrs(t, out)
	return tacacs, brokerAddr, stop
}

// newestAddrs is the last run's TACACS+ and broker addresses: each run
// says "listening on <tacacs>" and then "broker listening on <broker>".
func newestAddrs(t *testing.T, out *syncBuffer) (string, string) {
	t.Helper()
	addrs := regexp.MustCompile(`listening on (127\.0\.0\.1:\d+)`).FindAllStringSubmatch(out.String(), -1)
	if len(addrs) < 2 {
		t.Fatalf("no listening lines: %s", out.String())
	}
	return addrs[len(addrs)-2][1], addrs[len(addrs)-1][1]
}

// waitCountWithin is waitForCount with a deadline of the test's choosing.
func waitCountWithin(t *testing.T, buf *syncBuffer, want string, n int, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for strings.Count(buf.String(), want) < n {
		if time.Now().After(deadline) {
			t.Fatalf("waited %v for %q ×%d; have %q", d, want, n, buf.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// lastCommandPrincipal is the principal of the decision log's last
// authorize_command or redeem record: the one the session's records name.
func lastCommandPrincipal(t *testing.T, log *syncBuffer) string {
	t.Helper()
	recs := append(records(t, log, "redeem"), records(t, log, "authorize_command")...)
	for i := len(recs) - 1; i >= 0; i-- {
		if p, _ := recs[i]["principal"].(string); p != "" {
			return p
		}
	}
	t.Fatalf("no record names a principal; decision log %s", log.String())
	return ""
}

// loginSession logs alice in with tok and authorizes her exec session, as
// a device does before her first command: the session's level is raised
// to the context's ceiling there, not at the login.
func loginSession(t *testing.T, dev tacacsClient, tok string, log *syncBuffer) {
	t.Helper()
	if st := dev.login("alice", tok); st != wire.AuthenStatusPass {
		t.Fatalf("login: %d; log %s", st, log.String())
	}
	if r := dev.authorize("alice"); r.Status != wire.AuthorStatusPassAdd {
		t.Fatalf("session authorization: %+v", r)
	}
}

// A live session survives a port49d restart on etcd; a token minted
// before it does not, and an idempotent replay of a mint from before is
// minted again, not answered with that token (Ruling 12; spec §14, "A
// restart on etcd"; store.Store.SupersedeAll).
func TestRunOnEtcdKeepsALoginAcrossARestart(t *testing.T) {
	t.Skip("plan 7e Task 14: its fixture is a broker: block on etcd, which Task 13 refuses; Task 14 moves it to the split daemon")
	var out, log syncBuffer
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o })
	stderr, stdout = &out, &log
	cfgPath, pkiDir, _, _ := etcdRun(t)

	tacacs, brokerAddr, stop := startRun(t, cfgPath, &out, 1)
	dev := tacacsClient{t: t, addr: tacacs, key: []byte("run-test-secret")}
	loginSession(t, dev, mint(t, brokerAddr, pkiDir, "leaf1"), &log)
	spare := mint(t, brokerAddr, pkiDir, "leaf1")
	keyed := mintKeyed(t, brokerAddr, pkiDir, "leaf1", "restart-replay")
	if !dev.permits("alice", "configure") {
		t.Fatal("before the restart")
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}

	tacacs, brokerAddr, _ = startRun(t, cfgPath, &out, 2)
	waitForCount(t, &out, "unspent token(s) from before this start", 2)
	waitForCount(t, &out, "live context(s) carried onto the policy in force", 2)
	dev = tacacsClient{t: t, addr: tacacs, key: []byte("run-test-secret")}
	if !dev.permits("alice", "configure") {
		t.Fatalf("after the restart the session's next command was not answered from its context; log %s", log.String())
	}
	if st := dev.login("alice", spare); st == wire.AuthenStatusPass {
		t.Fatal("a token minted before the restart logged in")
	}
	replayed := mintKeyed(t, brokerAddr, pkiDir, "leaf1", "restart-replay")
	if replayed == keyed {
		t.Fatal("a replay of a mint from before the restart was answered with the purged token")
	}
	if st := dev.login("alice", replayed); st != wire.AuthenStatusPass {
		t.Fatalf("the token a replay minted again: %d", st)
	}
}

// A mark added to broker.revocations_file with port49d stopped reaches the
// live context the store kept, before any listener binds (pre-flight C1;
// spec §14, "A mark at start").
func TestAStartAppliesAStandingMarkToAKeptContext(t *testing.T) {
	t.Skip("plan 7e Task 14: its fixture is a broker: block on etcd, which Task 13 refuses; Task 14 moves it to the split daemon")
	var out, log syncBuffer
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o })
	stderr, stdout = &out, &log
	cfgPath, pkiDir, revocations, _ := etcdRun(t)

	tacacs, brokerAddr, stop := startRun(t, cfgPath, &out, 1)
	dev := tacacsClient{t: t, addr: tacacs, key: []byte("run-test-secret")}
	loginSession(t, dev, mint(t, brokerAddr, pkiDir, "leaf1"), &log)
	principal := lastCommandPrincipal(t, &log) // the principal the session's records name
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	if err := saveRevocations(revocations, []store.Revocation{{Kind: store.RevocationPrincipal, Key: principal,
		At: time.Now().UTC(), Origin: "test: the file edited with port49d stopped"}}); err != nil {
		t.Fatal(err)
	}

	tacacs, _, _ = startRun(t, cfgPath, &out, 2)
	// The start itself marked it, not only the daemon's marks at request
	// time (re-check R-M1): without ApplyMarksAtStart this line is absent.
	waitForCount(t, &out, "standing revocation(s) applied to the live contexts the store kept "+
		"(1 context(s) marked revoked)", 1)
	dev = tacacsClient{t: t, addr: tacacs, key: []byte("run-test-secret")}
	if dev.permits("alice", "configure") {
		t.Fatal("a kept context under a standing mark was permitted")
	}
	if r := lastCommand(t, &log); r["reason"] != "credential_revoked" {
		t.Fatalf("the denial: %v", r)
	}
}

// A context put back at a key the start never read is denied: the start
// seals the ledger once it has read every kept context, so a record a
// store writer puts back afterwards is never taken as that key's
// (decision 35, a start on etcd, step 7; re-check 2 I1). Unsealed, the
// first read would take it, and the session it was saved from would be
// answered again.
func TestAStartSealsTheLedgerOnceItHasReadTheStore(t *testing.T) {
	t.Skip("plan 7e Task 14: its fixture is a broker: block on etcd, which Task 13 refuses; Task 14 moves it to the split daemon")
	var out, log syncBuffer
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o })
	stderr, stdout = &out, &log
	cfgPath, pkiDir, _, _, srv := etcdRunServer(t)
	root := srv.Client(t, "root")
	ctx := context.Background()

	tacacs, brokerAddr, stop := startRun(t, cfgPath, &out, 1)
	dev := tacacsClient{t: t, addr: tacacs, key: []byte("run-test-secret")}
	loginSession(t, dev, mint(t, brokerAddr, pkiDir, "leaf1"), &log)
	if !dev.permits("alice", "configure") {
		t.Fatalf("before the restart: %v; out %s", lastCommand(t, &log), out.String())
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	// A store writer saves alice's sealed context and deletes it, and the
	// ledger record with it, so the next start finds nothing at its key:
	// the base alone judges it (the record's own test is
	// TestAStartSeededFromTheLedgerRecordDeniesAPutBack).
	resp, err := root.Get(ctx, "/port49/v1/c/", clientv3.WithPrefix())
	if err != nil || len(resp.Kvs) != 1 {
		t.Fatalf("the kept contexts: %v %v", resp, err)
	}
	saved := resp.Kvs[0]
	if _, err := root.Delete(ctx, string(saved.Key)); err != nil {
		t.Fatal(err)
	}
	if _, err := root.Delete(ctx, "/port49/v1/lw/", clientv3.WithPrefix()); err != nil {
		t.Fatal(err)
	}

	tacacs, _, _ = startRun(t, cfgPath, &out, 2)
	waitForCount(t, &out, "live context(s) carried onto the policy in force", 2)
	// Each start's scan says its ledger; neither found a context, so the
	// base alone judges a record at alice's key.
	waitForCount(t, &out, "port49d: ledger: 0 context key(s) known (0 from the ledger record); following the "+
		"store from revision ", 2)
	// ... and puts it back once the start has read the store.
	if _, err := root.Put(ctx, string(saved.Key), string(saved.Value)); err != nil {
		t.Fatal(err)
	}
	dev = tacacsClient{t: t, addr: tacacs, key: []byte("run-test-secret")}
	if dev.permits("alice", "configure") {
		t.Fatal("a context put back at a key the start never read was taken as that key's")
	}
	// Under port49's roles the daemon's identity watches the contexts: the
	// feed runs, and never stopped.
	ms := regexp.MustCompile(`port49d: metrics on (127\.0\.0\.1:\d+)`).FindAllStringSubmatch(out.String(), -1)
	if len(ms) == 0 {
		t.Fatalf("the metrics address is not said: %s", out.String())
	}
	scraped, err := http.Get("http://" + ms[len(ms)-1][1] + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(scraped.Body)
	scraped.Body.Close()
	if !regexp.MustCompile(`(?m)^port49_store_feed_up\{feed="contexts"\} 1$`).Match(body) {
		t.Fatalf("the context feed is not up:\n%s", body)
	}
	if strings.Contains(out.String(), "the context feed stopped") {
		t.Fatalf("the feed stopped: %s", out.String())
	}
}

// A second port49d on the keyspace binds no listener while the first
// holds it (Review Focus 4).
func TestASecondPort49dWaitsForTheKeyspace(t *testing.T) {
	t.Skip("plan 7e Task 14: its fixture is a broker: block on etcd, which Task 13 refuses; Task 14 moves it to the split daemon")
	var out, log syncBuffer
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o }) // runs last: after the second run has stopped
	stderr, stdout = &out, &log
	cfgPath, _, _, _ := etcdRun(t)
	startRun(t, cfgPath, &out, 1)
	n := strings.Count(out.String(), "listening on ")

	// The same file: a copy-pasted config is the case. The second waits for
	// the keyspace before it binds anything or touches the revocations file.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfgPath) }()
	t.Cleanup(func() { // pre-flight M38: the run ends before stderr is restored
		cancel()
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			t.Error("the second port49d did not stop")
		}
	})
	waitFor(t, &out, `is held by "port49d on`)
	time.Sleep(2 * time.Second)
	if got := strings.Count(out.String(), "listening on "); got != n {
		t.Fatalf("the second port49d bound a listener while the first held the keyspace:\n%s", out.String())
	}
}

// A store that hangs in the middle of a login: the device hears ERROR
// within store.packet_deadline, never silence (Review Focus 1). Then the
// store has been gone long enough, and port49d closes every listener and
// says why, without exiting; when the store returns, the same process
// listens again, and the session's next command is answered from its
// context (Ruling 11; pre-flight I19; Review Focus 4). While it waits,
// /readyz says so (I19), and an earlier version of the session's own
// context, which a store writer puts back in the dark, is denied after
// the return: the run after a store gone keeps the process's ledger,
// sealed, and the ledger names each write (decision 35; Ruling T12-b;
// Task 12 review m-3; Ruling T12-g). A ledger built again would take it
// at the start's first read. The start's refresh revokes the record put
// back (Ruling T13b-a), and that revocation stands on the key as the
// ledger's floor: the session's own record, put back after it, is answered
// revoked, and the session's owner logs in again (final review 7d-2 I-1).
func TestAHungStoreGoesDarkAndServesAgainWhenItReturns(t *testing.T) {
	t.Skip("plan 7e Task 14: its fixture is a broker: block on etcd, which Task 13 refuses; Task 14 moves it to the split daemon")
	var out, log syncBuffer
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o })
	stderr, stdout = &out, &log
	cfgPath, pkiDir, _, proxy, srv := etcdRunServer(t)
	root := srv.Client(t, "root")
	sctx := context.Background()

	// An earlier port49d's login, whose record a store writer keeps ...
	tacacs, brokerAddr, stop := startRun(t, cfgPath, &out, 1)
	loginSession(t, tacacsClient{t: t, addr: tacacs, key: []byte("run-test-secret")},
		mint(t, brokerAddr, pkiDir, "leaf1"), &log)
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	kept, err := root.Get(sctx, "/port49/v1/c/", clientv3.WithPrefix())
	if err != nil || len(kept.Kvs) != 1 {
		t.Fatalf("the kept contexts: %v %v", kept, err)
	}
	earlier := kept.Kvs[0]

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfgPath) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			t.Error("port49d did not stop")
		}
	})
	waitCountWithin(t, &out, "port49d: broker listening on ", 2, 30*time.Second)
	tacacs, brokerAddr = newestAddrs(t, &out)
	dev := tacacsClient{t: t, addr: tacacs, key: []byte("run-test-secret")}
	loginSession(t, dev, mint(t, brokerAddr, pkiDir, "leaf1"), &log)
	ids := map[string]bool{}
	for _, m := range regexp.MustCompile(`"ctx_id":"([^"]+)"`).FindAllStringSubmatch(log.String(), -1) {
		ids[m[1]] = true
	}
	if len(ids) != 1 {
		t.Fatalf("the second login did not join the earlier one's context: ctx_ids %v", ids)
	}
	tok := mint(t, brokerAddr, pkiDir, "leaf1")
	// A connection a device holds open across the hang (re-check R-M0).
	held, err := net.DialTimeout("tcp", tacacs, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()

	proxy.Hang(true)
	start := time.Now()
	if st := dev.login("alice", tok); st != wire.AuthenStatusError || time.Since(start) > 1500*time.Millisecond {
		t.Fatalf("a login on a hung store: status %d after %v", st, time.Since(start))
	}
	waitCountWithin(t, &out, "closing every listener so that devices use their local method", 1, 30*time.Second)
	// Reset, not closed with a FIN: L28 measured the fast fall to local on
	// a reset.
	held.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := held.Read(make([]byte, 1)); !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("a held connection on a store gone: %v, want a reset", err)
	}
	waitCountWithin(t, &out, "waiting for the store again, as at a start", 1, 20*time.Second)
	select {
	case err := <-done:
		t.Fatalf("port49d exited on a store gone: %v", err)
	default:
	}
	if c, err := net.DialTimeout("tcp", tacacs, time.Second); err == nil {
		c.Close()
		t.Fatal("TACACS+ still listens with the store gone")
	}
	waitCountWithin(t, &out, "port49d: metrics on ", 3, 20*time.Second)
	ms := regexp.MustCompile(`port49d: metrics on (127\.0\.0\.1:\d+)`).FindAllStringSubmatch(out.String(), -1)
	resp, err := http.Get("http://" + ms[len(ms)-1][1] + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("/readyz while waiting for the store: %d, want 503", resp.StatusCode)
	}
	// In the dark, a store writer puts the earlier login's record back at
	// the session's key, keeping the session's own: the next login joined
	// it, so both are the same context, under one ctx_id.
	now, err := root.Get(sctx, string(earlier.Key))
	if err != nil || len(now.Kvs) != 1 {
		t.Fatalf("the session's context: %v %v", now, err)
	}
	if _, err := root.Put(sctx, string(earlier.Key), string(earlier.Value)); err != nil {
		t.Fatal(err)
	}

	proxy.Hang(false)
	waitCountWithin(t, &out, "port49d: broker listening on ", 3, 60*time.Second)
	tacacs, brokerAddr = newestAddrs(t, &out)
	dev = tacacsClient{t: t, addr: tacacs, key: []byte("run-test-secret")}
	if dev.permits("alice", "configure") {
		t.Fatalf("a record put back while the store was gone was taken after it returned; log %s", log.String())
	}
	// The session's own record, put back, is admitted, and revoked: the
	// refresh's revocation of the record put back holds as the floor.
	if _, err := root.Put(sctx, string(earlier.Key), string(now.Kvs[0].Value)); err != nil {
		t.Fatal(err)
	}
	if dev.permits("alice", "configure") {
		t.Fatalf("the session's own record, put back, lifted the revocation the floor holds; log %s", log.String())
	}
	if !strings.Contains(log.String(), `"reason":"credential_revoked"`) {
		t.Fatalf("the session's own record, put back, was not answered revoked; log %s", log.String())
	}
	// A login after it is answered: the system serves again.
	loginSession(t, dev, mint(t, brokerAddr, pkiDir, "leaf1"), &log)
	if !dev.permits("alice", "configure") {
		t.Fatalf("after the store returned a new login's command was not permitted; log %s", log.String())
	}
}

// A mark another broker process puts in the store reaches this port49d
// through the marks feed (plan 7e, Ruling 5): alice's held broker
// connection is closed, and her next command is denied credential_revoked
// from the daemon's marks. Its lift lets her back in. And a mark standing
// in the store alone when port49d starts is in the listener's copy before
// any connection binds.
func TestAMarkFromAnotherBrokerProcessReachesThisOne(t *testing.T) {
	t.Skip("plan 7e Task 14: its fixture is a broker: block on etcd, which Task 13 refuses; Task 14 moves it to the split daemon")
	var out, log syncBuffer
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o })
	stderr, stdout = &out, &log
	cfgPath, pkiDir, _, _, srv := etcdRunServer(t)
	root := srv.Client(t, "root")
	ctx := context.Background()

	tacacs, brokerAddr, stop := startRun(t, cfgPath, &out, 1)
	dev := tacacsClient{t: t, addr: tacacs, key: []byte("run-test-secret")}
	loginSession(t, dev, mint(t, brokerAddr, pkiDir, "leaf1"), &log)
	principal := lastCommandPrincipal(t, &log)
	waitMetric(t, &out, `port49_store_feed_up{feed="marks"} 1`) // the marks feed runs (review M4)
	conn := heldBrokerConn(t, pkiDir, brokerAddr)
	key := "/port49/v1/rv/principal/" + url.PathEscape(principal)
	val := fmt.Sprintf(`{"kind":"principal","key":%q,"at":%q,"origin":"test: another broker process"}`,
		principal, time.Now().UTC().Format(time.RFC3339Nano))
	if _, err := root.Put(ctx, key, val); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("alice's held broker connection was not closed: %v", err)
	}
	// Said on port49d's own log, with its other lines (Ruling T9-c), and
	// counted in force.
	waitFor(t, &out, "broker: a revocation of "+principal+" made on a broker process closed ")
	waitInForce(t, &out, "principal", 1)
	if dev.permits("alice", "configure") {
		t.Fatal("a command under a mark the feed brought was permitted")
	}
	if r := lastCommand(t, &log); r["reason"] != "credential_revoked" {
		t.Fatalf("the denial: %v", r)
	}
	if _, err := root.Delete(ctx, key); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for !dev.permits("alice", "configure") {
		if time.Now().After(deadline) {
			t.Fatalf("a lift the feed brought did not let alice back in: %v", lastCommand(t, &log))
		}
		time.Sleep(100 * time.Millisecond)
	}
	waitInForce(t, &out, "principal", 0)
	if err := stop(); err != nil {
		t.Fatal(err)
	}

	// In the store alone, never this port49d's file: the next start reads
	// it from the store, and the listener refuses alice as she binds.
	if _, err := root.Put(ctx, key, val); err != nil {
		t.Fatal(err)
	}
	_, brokerAddr, _ = startRun(t, cfgPath, &out, 2)
	status, body, err := postAsAlice(pkiDir, brokerAddr)
	if err != nil || status != http.StatusUnauthorized || !strings.Contains(body, `"credential_revoked"`) {
		t.Fatalf("alice's first connection after the start: %s %v", reply(status, body), err)
	}
	waitFor(t, &out, "as it bound: "+principal+" or its certificate is revoked")
}

// heldBrokerConn opens a connection to the broker as the lab client and
// asks /v1/config on it, leaving it open: an agent's held connection.
func heldBrokerConn(t *testing.T, pkiDir, addr string) *tls.Conn {
	t.Helper()
	cert, err := tls.LoadX509KeyPair(filepath.Join(pkiDir, testpki.LabClientCert), filepath.Join(pkiDir, testpki.LabClientKey))
	if err != nil {
		t.Fatal(err)
	}
	caPEM, err := os.ReadFile(filepath.Join(pkiDir, testpki.LabCA))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	c, err := tls.Dial("tcp", addr, &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: roots,
		MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	if _, err := io.WriteString(c, "GET /v1/config HTTP/1.1\r\nHost: broker\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("/v1/config on a held connection: %v %v", resp, err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return c
}

// waitInForce waits up to 10s for the newest run's
// port49_revocations_in_force{by} to read n.
func waitInForce(t *testing.T, out *syncBuffer, by string, n int) {
	t.Helper()
	waitMetric(t, out, fmt.Sprintf(`port49_revocations_in_force{by="%s"} %d`, by, n))
}

// waitMetric waits up to 10s for the newest run's /metrics to hold line.
func waitMetric(t *testing.T, out *syncBuffer, line string) {
	t.Helper()
	ms := regexp.MustCompile(`port49d: metrics on (127\.0\.0\.1:\d+)`).FindAllStringSubmatch(out.String(), -1)
	if len(ms) == 0 {
		t.Fatalf("the metrics address is not said: %s", out.String())
	}
	want := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(line) + `$`)
	deadline := time.Now().Add(10 * time.Second)
	for {
		scraped, err := http.Get("http://" + ms[len(ms)-1][1] + "/metrics")
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(scraped.Body)
		scraped.Body.Close()
		if want.Match(body) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("/metrics lacks %q:\n%s", line, body)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// A context put back while port49d was stopped, at a key the ledger record
// holds a later mark for, is denied after the restart: the start seeds its
// ledger from the record before it scans (Review Focus 2; Ruling 4). In
// 7d this was the restart residual: the start took it as the key's.
//
// The put-back is a replay of another principal's earlier session at the
// same key: bob's, over alice's later one, at the username both log in as.
// The principal the device's command is attributed to shows which record
// was taken. Two positive controls: alice's own session is permitted
// before the stop, and after a restart with nothing put back.
func TestAStartSeededFromTheLedgerRecordDeniesAPutBack(t *testing.T) {
	t.Skip("plan 7e Task 14: its fixture is a broker: block on etcd, which Task 13 refuses; Task 14 moves it to the split daemon")
	var out, log syncBuffer
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o })
	stderr, stdout = &out, &log
	cfgPath, pkiDir, _, _, srv := etcdRunServerWith(t, sharedUsernamePolicy, []string{"bob@example.com"})
	root := srv.Client(t, "root")
	ctx := context.Background()
	tacacs, brokerAddr, stop := startRun(t, cfgPath, &out, 1)
	dev := tacacsClient{t: t, addr: tacacs, key: []byte("run-test-secret")}
	loginSession(t, dev, mintAs(t, brokerAddr, pkiDir, "leaf1", "bob@example.com"), &log)
	resp, err := root.Get(ctx, "/port49/v1/c/leaf1/alice")
	if err != nil || len(resp.Kvs) != 1 {
		t.Fatalf("bob's context: %v %v", resp, err)
	}
	bobs := resp.Kvs[0]
	s1 := waitForLedgerSeq(t, root, "/port49/v1/lw/leaf1/alice", 0)
	loginSession(t, dev, mint(t, brokerAddr, pkiDir, "leaf1"), &log) // alice's, later, at the same key
	waitForLedgerSeq(t, root, "/port49/v1/lw/leaf1/alice", s1)       // the record holds alice's
	if !dev.permits("alice", "configure") || lastCommandPrincipal(t, &log) != "user:alice@example.com" {
		t.Fatal("control: alice's own session was not permitted as alice before the stop")
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	tacacs, brokerAddr, stop = startRun(t, cfgPath, &out, 2) // nothing put back
	dev = tacacsClient{t: t, addr: tacacs, key: []byte("run-test-secret")}
	if !dev.permits("alice", "configure") {
		t.Fatal("control: alice's session was not permitted after a restart with nothing put back")
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	if _, err := root.Put(ctx, string(bobs.Key), string(bobs.Value)); err != nil {
		t.Fatal(err)
	}
	tacacs, _, _ = startRun(t, cfgPath, &out, 3)
	dev = tacacsClient{t: t, addr: tacacs, key: []byte("run-test-secret")}
	if dev.permits("alice", "configure") {
		t.Fatalf("bob's context put back over alice's while port49d was stopped was taken as the key's: %v",
			lastCommandPrincipal(t, &log))
	}
}

// waitForLedgerSeq polls the ledger record at key, as etcd's root, until
// its seq is above above or 10s pass, and returns it. The keeper writes
// within a second of a raise; a gauge read at 0 can be the round before
// (pre-flight I14).
func waitForLedgerSeq(t *testing.T, root *clientv3.Client, key string, above uint64) uint64 {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if resp, err := root.Get(context.Background(), key); err == nil && len(resp.Kvs) == 1 {
			var r struct {
				Seq uint64 `json:"seq"`
			}
			if json.Unmarshal(resp.Kvs[0].Value, &r) == nil && r.Seq > above {
				return r.Seq
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("the ledger record at %s never rose above %d", key, above)
	return 0
}
