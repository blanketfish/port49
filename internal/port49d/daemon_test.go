package port49d

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
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
// In the dark, a connection a device held is reset (L28: the fast fall to
// local), TACACS+ takes no new one, and /readyz reads 503.
func TestAnIdleDaemonGoesDarkOnItsProbe(t *testing.T) {
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	daemonCfg, proxy := etcdSplit(t)
	tacacs := startSplitDaemon(t, daemonCfg, &out, 1)
	held, err := net.DialTimeout("tcp", tacacs, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	proxy.Hang(true)
	waitWithin(t, &out, "closing every listener so that devices use their local method", 60*time.Second)
	held.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := held.Read(make([]byte, 1)); !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("a held connection on a store gone: %v, want a reset", err)
	}
	waitWithin(t, &out, "waiting for the store again, as at a start", 20*time.Second)
	if c, err := net.DialTimeout("tcp", tacacs, time.Second); err == nil {
		c.Close()
		t.Fatal("TACACS+ still listens with the store gone")
	}
	waitCountWithin(t, &out, "port49d: metrics on ", 2, 20*time.Second)
	ms := regexp.MustCompile(`port49d: metrics on (127\.0\.0\.1:\d+)`).FindAllStringSubmatch(out.String(), -1)
	resp, err := http.Get("http://" + ms[len(ms)-1][1] + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("/readyz while waiting for the store: %d, want 503", resp.StatusCode)
	}
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
		"and stay in force here (to release one lifted on purpose, revoke it again on port49-broker, then lift "+
			"it with port49 revoke --lift, or restart this port49d): principal user:alice@example.com\n") {
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

// On a flapping store FollowMarks calls the hook again a second after a
// load that failed: the keep line is said once for one set of kept marks,
// again when the set changes, and again after a call that kept nothing
// (task 14 review M-1). Each call still keeps.
func TestTheDaemonsReloadHookSaysOneKeptSetOnce(t *testing.T) {
	ctx := context.Background()
	alice := store.Revocation{Kind: store.RevocationPrincipal, Key: "user:alice@example.com", At: time.Unix(10, 0).UTC()}
	carol := store.Revocation{Kind: store.RevocationPrincipal, Key: "user:carol@example.com", At: time.Unix(11, 0).UTC()}
	enforced := store.NewMarks()
	enforced.Set(alice, true)
	enforced.Set(carol, true)
	var out bytes.Buffer
	feed := &marksIn{rs: []store.Revocation{carol}} // the restore lost alice's
	hook := daemonReloadHook(ctx, feed, enforced, prometheus.NewCounter(prometheus.CounterOpts{Name: "rescans"}),
		time.Second, &out)
	call := func(want int) {
		t.Helper()
		if err := hook(); err != nil {
			t.Fatal(err)
		}
		if n := strings.Count(out.String(), "enforces are missing from the store"); n != want {
			t.Fatalf("said the keep line %d times, want %d:\n%s", n, want, out.String())
		}
	}
	for range 6 { // six reloads while the store flaps
		call(1)
	}
	if _, err := store.LoadMarks(ctx, feed, enforced, nil); err != nil || !enforced.Holds(alice.Kind, alice.Key) {
		t.Fatalf("a repeated call did not keep alice's mark: %v %v", enforced.All(), err)
	}
	feed.rs = nil // carol's lost too: a new set
	call(2)
	if !strings.Contains(out.String(), "port49d: store: 2 revocation(s)") {
		t.Fatalf("the new set: %q", out.String())
	}
	call(2)
	feed.rs = []store.Revocation{alice, carol} // put back: nothing kept, nothing said
	call(2)
	feed.rs = nil // the same set lost again after a call that kept nothing: said again
	call(3)
	if strings.Count(out.String(), "port49d: store: 2 revocation(s)") != 2 {
		t.Fatalf("the third line: %q", out.String())
	}
}

// A run after a store gone keeps, then loads, in one attempt, and each
// attempt the start retries keeps again first: a restore that lands
// between an attempt's keep and its load's retry is kept, not lifted
// (task 14 review M-3). The control: a first start keeps nothing.
func TestADaemonsMarksLoadKeepsBeforeEachAttempt(t *testing.T) {
	ctx := context.Background()
	alice := store.Revocation{Kind: store.RevocationPrincipal, Key: "user:alice@example.com", At: time.Unix(10, 0).UTC()}
	var out bytes.Buffer
	say := keptSayer(&out, "as it starts again after a store gone")
	enforced := store.NewMarks()
	enforced.Set(alice, true)
	feed := &marksScript{answers: []marksIn{
		{rs: []store.Revocation{alice}}, // attempt 1's keep: nothing lost yet
		{err: store.ErrUnavailable},     // its load: the store goes away
		{},                              // attempt 2's keep: back, restored without alice's
		{},                              // its load
	}}
	if _, err := loadDaemonMarks(ctx, feed, enforced, true, time.Second, say); !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("attempt 1: %v", err)
	}
	if _, err := loadDaemonMarks(ctx, feed, enforced, true, time.Second, say); err != nil {
		t.Fatal(err)
	}
	if !enforced.Holds(alice.Kind, alice.Key) || !strings.Contains(out.String(),
		"port49d: store: 1 revocation(s) this port49d enforces are missing from the store as it starts again "+
			"after a store gone") {
		t.Fatalf("a restore between attempts lifted alice's mark: %v\n%s", enforced.All(), out.String())
	}

	first := store.NewMarks()
	first.Set(alice, true)
	if _, err := loadDaemonMarks(ctx, &marksScript{answers: []marksIn{{}}}, first, false, time.Second,
		keptSayer(io.Discard, "")); err != nil || first.Holds(alice.Kind, alice.Key) {
		t.Fatalf("control: a first start's load: %v %v", first.All(), err)
	}
}

// marksScript is a store.MarkFeed answering each read with the next of
// answers.
type marksScript struct{ answers []marksIn }

func (f *marksScript) Revocations(ctx context.Context) (uint64, []store.Revocation, error) {
	a := f.answers[0]
	f.answers = f.answers[1:]
	return a.Revocations(ctx)
}

func (f *marksScript) WatchRevocations(ctx context.Context, after uint64, fn func(store.Revocation, bool, uint64),
	progress func(uint64)) error {
	return marksIn{}.WatchRevocations(ctx, after, fn, progress)
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
