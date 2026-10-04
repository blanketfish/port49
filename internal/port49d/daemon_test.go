package port49d

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/rhwendt/port49/internal/daemon/admin"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/tacacs/wire"
)

// startSplitDaemon runs port49d on cfgPath until the test ends, and
// returns the TACACS+ address of its nth run in out: startRun for a
// daemon with no broker, waiting for the nth "port49d: listening on" line,
// never an earlier run's, and reading the newest address.
func startSplitDaemon(t *testing.T, cfgPath string, out *syncBuffer, n int) (tacacs string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfgPath) }()
	t.Cleanup(func() { // before stderr is restored: registered after the caller's
		cancel()
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			t.Error("port49d did not stop")
		}
	})
	waitCountWithin(t, out, "port49d: listening on ", n, 30*time.Second)
	addrs := regexp.MustCompile(`port49d: listening on (127\.0\.0\.1:\d+)`).FindAllStringSubmatch(out.String(), -1)
	return addrs[len(addrs)-1][1]
}

// copyDaemon writes a copy of the daemon config at cfg with its own
// admin_socket, accounting.spool_path and metrics_listen, in a safeDir of
// its own, and returns its path: admin.Listen refuses a socket another
// port49d answers on.
func copyDaemon(t *testing.T, cfg string) string {
	t.Helper()
	raw, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	dir := safeDir(t)
	body := regexp.MustCompile(`(?m)^admin_socket: .*$`).ReplaceAllString(string(raw),
		"admin_socket: "+filepath.Join(dir, "a.sock"))
	body = regexp.MustCompile(`(?m)^accounting: .*$`).ReplaceAllString(body,
		"accounting: {spool_path: "+filepath.Join(dir, "acct.jsonl")+"}")
	body = regexp.MustCompile(`(?m)^metrics_listen: .*$`).ReplaceAllString(body, `metrics_listen: "127.0.0.1:0"`)
	p := filepath.Join(dir, "port49d.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// askAdmin serves srv on a socket of the test's own and asks it req.
func askAdmin(t *testing.T, srv *admin.Server, req admin.Request) admin.Response {
	t.Helper()
	p := filepath.Join(t.TempDir(), "port49d.sock")
	ln, err := admin.Listen(p)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go srv.Serve(ctx, ln)
	return askSocket(t, p, req)
}

// askSocket asks the admin socket at p req.
func askSocket(t *testing.T, p string, req admin.Request) admin.Response {
	t.Helper()
	c, err := net.Dial("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := json.NewEncoder(c).Encode(req); err != nil {
		t.Fatal(err)
	}
	var r admin.Response
	if err := json.NewDecoder(c).Decode(&r); err != nil {
		t.Fatal(err)
	}
	return r
}

// policyOnlyRun is run_test.go's config on the memory store with policy:
// {file, watch_interval: 1s} in place of broker:, and the policy file's
// path. inventory.max_removed_percent is 100, so a reload may quarantine
// its one device.
func policyOnlyRun(t *testing.T) (cfgPath, policyPath string) {
	t.Helper()
	b := brokerConfig(t, minimalPolicy).Broker
	cfgPath = writeRunConfig(t, b)
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	body = body[:strings.Index(body, "broker:\n")] + "policy: {file: " + b.PolicyFile + ", watch_interval: 1s}\n" +
		"inventory: {max_removed_percent: 100}\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfgPath, b.PolicyFile
}

// writePolicyFile replaces the policy file at path with body.
func writePolicyFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// quarantiningLeaf1 lands alice's arista_eos session at a level the
// platform cannot render, which quarantines leaf1 (reload_test.go's
// TestAReloadThatQuarantinesTheFleetIsRefused).
var quarantiningLeaf1 = unmappedLevel + strings.Replace(minimalPolicy, "privilege: admin", "privilege: unmapped", 1)

// leaf1Addr is leaf1's address in writeRunConfig's inventory.
const leaf1Addr = "127.0.0.1"

// answeredFrom reports whether port49d at addr answers a login start sent
// from the address from: a device it does not admit, or quarantines, is
// closed with no reply.
func answeredFrom(t *testing.T, addr, from string) bool {
	t.Helper()
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(from)}, Timeout: time.Second}
	conn, err := d.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	key := []byte("run-test-secret")
	body := wire.AuthenStart{Action: wire.AuthenActionLogin, PrivLvl: 1, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte("alice"), Port: []byte("ssh"),
		RemAddr: []byte("198.51.100.4")}.Encode()
	h := wire.Header{MajorVersion: 0xc, Type: wire.TypeAuthen, SeqNo: 1, SessionID: 0x5eed, Length: uint32(len(body))}
	if _, err := conn.Write(append(h.Encode(), wire.Obfuscate(h, key, body)...)); err != nil {
		return false
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = io.ReadFull(conn, make([]byte, wire.HeaderLen))
	return err == nil
}

// A port49d on etcd with no broker starts with no hold, says the ledger
// line and the marks, and a second one beside it serves too (Ruling 11):
// 7d's "waits for the keyspace" is gone.
func TestTwoDaemonsServeOneKeyspace(t *testing.T) {
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	daemonCfg, _ := etcdSplit(t)
	startSplitDaemon(t, daemonCfg, &out, 1)
	startSplitDaemon(t, copyDaemon(t, daemonCfg), &out, 2) // a second, its own addresses
	if strings.Contains(out.String(), "is held by") {
		t.Fatalf("a daemon waited for a hold:\n%s", out.String())
	}
	waitForCount(t, &out, "port49d: ledger: ", 2)
	waitForCount(t, &out, "port49d: store: 0 revocation(s) in force from the store", 2)
	// Its admin socket sends a revocation to port49-broker's (Ruling 13).
	raw, err := os.ReadFile(daemonCfg)
	if err != nil {
		t.Fatal(err)
	}
	socket := regexp.MustCompile(`(?m)^admin_socket: (\S+)$`).FindSubmatch(raw)[1]
	if r := askSocket(t, string(socket), admin.Request{Op: "revoke", Principal: "user:alice@example.com"}); !strings.Contains(
		r.Error, "port49-broker's admin socket") {
		t.Fatalf("a revocation at the daemon's socket: %+v", r)
	}
}

// An idle port49d whose store hangs goes dark on its probe alone: no
// device asks, and it closes its listeners within hold_ttl of the
// circuit opening, and listens again when the store returns (Ruling 11).
func TestAnIdleDaemonGoesDarkOnItsProbe(t *testing.T) {
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	daemonCfg, proxy := etcdSplit(t)
	startSplitDaemon(t, daemonCfg, &out, 1)
	proxy.Hang(true)
	waitWithin(t, &out, "closing every listener so that devices use their local method", 60*time.Second)
	proxy.Hang(false)
	waitCountWithin(t, &out, "port49d: listening on ", 2, 90*time.Second)
}

// A revocation sent to port49d's socket with no broker in it is refused,
// naming port49-broker's socket (Ruling 13).
func TestARevocationAtTheDaemonsSocketNamesTheBrokers(t *testing.T) {
	srv := &admin.Server{Now: time.Now, RevokeElsewhere: "port49-broker's admin socket (its admin_socket in port49-broker.yaml)"}
	resp := askAdmin(t, srv, admin.Request{Op: "revoke", Principal: "user:alice@example.com"})
	if !strings.Contains(resp.Error, "port49 revoke --socket") || !strings.Contains(resp.Error, "port49-broker") {
		t.Fatalf("%+v", resp)
	}
}

// A policy edit reloads into a port49d with no broker: admission and
// quarantine follow it, and no refresh runs (no line, no pending gauge).
// On the memory store: the reload path needs no etcd.
func TestADaemonWithNoBrokerReloadsItsPolicy(t *testing.T) {
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	cfgPath, policyPath := policyOnlyRun(t) // run_test.go's config, policy: {file, watch_interval: 1s} for broker:
	tacacs := startSplitDaemon(t, cfgPath, &out, 1)
	if !answeredFrom(t, tacacs, leaf1Addr) {
		t.Fatal("control: leaf1's connection was not answered before the edit")
	}
	writePolicyFile(t, policyPath, quarantiningLeaf1) // reload_test.go's quarantine fixture
	waitFor(t, &out, "is quarantined")
	if answeredFrom(t, tacacs, leaf1Addr) {
		t.Fatal("a quarantined device's connection was answered")
	}
	if strings.Contains(out.String(), "policy refresh") {
		t.Fatalf("a daemon with no broker ran a refresh:\n%s", out.String())
	}
	if v := gauge(t, &out, "port49_policy_refresh_pending"); v != 0 {
		t.Fatalf("port49_policy_refresh_pending %v", v)
	}
}

// port49d's hook before a marks reload keeps every mark it enforces that
// the store lacks, so the reload lifts none, and names them; one the store
// holds is not said (plan 7e, Ruling 5). The daemon's role cannot put a
// mark back. A read that fails refuses the reload (re-review 1 C-2). Each
// call counts a rescan.
func TestTheDaemonsReloadHookKeepsWhatTheStoreLost(t *testing.T) {
	ctx := context.Background()
	alice := store.Revocation{Kind: store.RevocationPrincipal, Key: "user:alice@example.com", At: time.Unix(10, 0).UTC()}
	carol := store.Revocation{Kind: store.RevocationPrincipal, Key: "user:carol@example.com", At: time.Unix(11, 0).UTC()}
	enforced := store.NewMarks()
	enforced.Set(alice, true)
	enforced.Set(carol, true)
	rescans := prometheus.NewCounter(prometheus.CounterOpts{Name: "rescans"})
	var out bytes.Buffer

	if err := daemonReloadHook(ctx, marksIn{err: store.ErrUnavailable}, enforced, rescans, time.Second, &out)(); err == nil ||
		!strings.HasSuffix(err.Error(), "the marks are not reloaded until they are read") {
		t.Fatalf("a read that failed: %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("a failed read said %q", out.String())
	}
	feed := marksIn{rs: []store.Revocation{carol}} // the restore lost alice's
	if err := daemonReloadHook(ctx, feed, enforced, rescans, time.Second, &out)(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "port49d: store: 1 revocation(s) this port49d enforces are missing from "+
		"the store as its marks feed reloads") || !strings.HasSuffix(out.String(),
		"until a lift this feed delivers or a restart: principal user:alice@example.com\n") {
		t.Fatalf("said %q", out.String())
	}
	if _, err := store.LoadMarks(ctx, feed, enforced, nil); err != nil {
		t.Fatal(err)
	}
	if !enforced.Holds(alice.Kind, alice.Key) || !enforced.Holds(carol.Kind, carol.Key) {
		t.Fatalf("the reload lifted a kept mark: %+v", enforced.All())
	}
	if n := testutil.ToFloat64(rescans); n != 2 {
		t.Fatalf("counted %v rescans, want 2", n)
	}
}

// marksIn is a store.MarkFeed holding rs at revision 7, or failing with
// err; its watch waits for ctx.
type marksIn struct {
	rs  []store.Revocation
	err error
}

func (f marksIn) Revocations(context.Context) (uint64, []store.Revocation, error) {
	return 7, f.rs, f.err
}

func (f marksIn) WatchRevocations(ctx context.Context, _ uint64, _ func(store.Revocation, bool, uint64),
	_ func(uint64)) error {
	<-ctx.Done()
	return ctx.Err()
}

// The put-back and keep lines name each mark, kind and key, up to 20, then
// how many more, so the operator knows what to lift again (re-check R4). A
// key is printed safe: a newline in it cannot forge a line.
func TestRestoredMarksAreNamedUpToTwenty(t *testing.T) {
	two := []store.Revocation{
		{Kind: store.RevocationPrincipal, Key: "user:alice@example.com"},
		{Kind: store.RevocationPrincipal, Key: "user:carol\nport49-broker: forged"},
	}
	if got := namedMarks(two); got != "principal user:alice@example.com, principal user:carol?port49-broker: forged" {
		t.Fatalf("%q", got)
	}
	var many []store.Revocation
	for i := range 23 {
		many = append(many, store.Revocation{Kind: store.RevocationPrincipal, Key: fmt.Sprintf("user:u%02d", i)})
	}
	got := namedMarks(many)
	if !strings.HasSuffix(got, "principal user:u19, and 3 more") || strings.Contains(got, "user:u20") {
		t.Fatalf("%q", got)
	}
}
