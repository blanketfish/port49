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
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/rhwendt/port49/internal/broker"
	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/daemon/admin"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/crypt"
	"github.com/rhwendt/port49/internal/store/etcd/etcdtest"
	"github.com/rhwendt/port49/internal/tacacs/wire"
	"github.com/rhwendt/port49/internal/testpki"
)

// fleet is the split deployment on one TLS etcd member with port49's
// roles (plan 7e): a port49d.yaml with the daemon's identity alone
// (etcdSplitServerWith), and a port49-broker.yaml with the broker's,
// both reaching etcd through proxy, which the test can hang.
type fleet struct {
	daemon, broker string // the two configs
	pki            string // the lab PKI: the broker's TLS files and the agents' client certificates
	srv            *etcdtest.Server
	proxy          *etcdtest.Proxy
	inventory      string
	// policy is the policy file a broker copied from f.broker's at its
	// write starts with; editPolicy rewrites f.broker's own.
	policy string
}

// splitFleet is the fleet on minimalPolicy.
func splitFleet(t *testing.T) *fleet {
	t.Helper()
	return splitFleetWith(t, minimalPolicy, nil)
}

// splitFleetWith is the fleet on policyBody, with a lab client certificate
// for each of others (brokerConfigWith).
func splitFleetWith(t *testing.T, policyBody string, others []string) *fleet {
	t.Helper()
	return splitFleetOpts(t, policyBody, others, etcdtest.Options{TLS: true})
}

// splitFleetProgress is splitFleet on a member that sends a watch asking
// for them a progress notification every every (final review 7e-1 I-1).
func splitFleetProgress(t *testing.T, every time.Duration) *fleet {
	t.Helper()
	return splitFleetOpts(t, minimalPolicy, nil, etcdtest.Options{TLS: true, ProgressNotify: every})
}

// splitFleetOpts is splitFleetWith on a member started with o.
func splitFleetOpts(t *testing.T, policyBody string, others []string, o etcdtest.Options) *fleet {
	t.Helper()
	f := &fleet{}
	f.daemon, f.proxy, f.srv = etcdSplitServerOpts(t, policyBody, others, o)
	raw, err := os.ReadFile(f.daemon)
	if err != nil {
		t.Fatal(err)
	}
	f.inventory = regexp.MustCompile(`(?m)^inventory_file: (\S+)$`).FindStringSubmatch(string(raw))[1]
	f.policy = regexp.MustCompile(`(?m)^policy: \{file: ([^,]+),`).FindStringSubmatch(string(raw))[1]
	f.pki = filepath.Dir(f.policy) // brokerConfigWith writes the policy beside the PKI
	f.broker = f.brokerVia(t, f.proxy.Addr(), "port49-broker", "")
	f.policy = f.policyOf(t, f.broker)
	return f
}

// brokerVia writes a port49-broker.yaml reaching etcd at endpoint as the
// etcd user cn, with extra appended under store.etcd, and returns its
// path. Each has its own broker.listen and metrics_listen (both
// 127.0.0.1:0), its own admin_socket, its own broker.state_dir (mode
// 0700), and its own broker.policy_file, a copy of f.policy, in a safeDir.
func (f *fleet) brokerVia(t *testing.T, endpoint, cn, extra string) string {
	t.Helper()
	dir := safeDir(t)
	state := filepath.Join(dir, "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(f.policy)
	if err != nil {
		t.Fatal(err)
	}
	pol := filepath.Join(dir, "policy.yaml")
	writePolicyFile(t, pol, string(body))
	bc, bk := f.srv.ClientFiles(t, cn)
	p := filepath.Join(dir, "port49-broker.yaml")
	if err := os.WriteFile(p, []byte(fmt.Sprintf(`
metrics_listen: "127.0.0.1:0"
inventory_file: %s
key_refs: [k]
encryption:
  current: {id: v1, secret_env: T_RUN_ENC}
admin_socket: %s
broker:
  listen: "127.0.0.1:0"
  tls_cert_file: %s
  tls_key_file: %s
  client_ca_file: %s
  policy_file: %s
  state_dir: %s
  policy_watch_interval: 1s
  certificate_status: {disabled: true}
store:
  backend: etcd
  etcd:
    endpoints: [https://%s]
    ca_file: %s
    broker: {cert_file: %s, key_file: %s}
    call_timeout: 200ms
    hold_ttl: 10s
    breaker: {failures: 3, open_for: 2s}
%s`, f.inventory, filepath.Join(dir, "b.sock"), filepath.Join(f.pki, testpki.LabServerCert),
		filepath.Join(f.pki, testpki.LabServerKey), filepath.Join(f.pki, testpki.LabCA), pol, state, endpoint,
		filepath.Join(f.srv.Dir, "ca.pem"), bc, bk, extra)), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// copyBroker writes another replica's port49-broker.yaml: f.broker's, with
// its own listeners, admin socket, state_dir and policy file.
func (f *fleet) copyBroker(t *testing.T) string {
	t.Helper()
	return f.brokerVia(t, f.proxy.Addr(), "port49-broker", "")
}

// copyBrokerVia is copyBroker with the endpoint through a proxy of its own,
// which the test hangs to cut that replica off alone.
func (f *fleet) copyBrokerVia(t *testing.T) (string, *etcdtest.Proxy) {
	t.Helper()
	p := etcdtest.NewProxy(t, strings.TrimPrefix(f.srv.Endpoint, "https://"))
	return f.brokerVia(t, p.Addr(), "port49-broker", ""), p
}

// policyOf is the broker.policy_file the port49-broker.yaml at cfg names.
func (f *fleet) policyOf(t *testing.T, cfg string) string {
	t.Helper()
	raw, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return regexp.MustCompile(`(?m)^  policy_file: (\S+)$`).FindStringSubmatch(string(raw))[1]
}

// editPolicy rewrites f.broker's policy file with one comment line added,
// so its bundle differs.
func (f *fleet) editPolicy(t *testing.T) {
	t.Helper()
	body, err := os.ReadFile(f.policy)
	if err != nil {
		t.Fatal(err)
	}
	writePolicyFile(t, f.policy, string(body)+"# edited with no broker running\n")
}

// bundle is the bundle f.broker's policy file loads into, read as
// loadPolicy reads it.
func (f *fleet) bundle(t *testing.T) string {
	t.Helper()
	cfg, err := config.LoadBroker(f.broker)
	if err != nil {
		t.Fatal(err)
	}
	inv, _, err := fencedInventory(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Inventory = inv
	pol, err := loadPolicy(cfg, "the test's inventory")
	if err != nil {
		t.Fatal(err)
	}
	return pol.Bundle
}

// stateDirOf is the broker.state_dir the port49-broker.yaml at cfg names.
func (f *fleet) stateDirOf(t *testing.T, cfg string) string {
	t.Helper()
	raw, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return regexp.MustCompile(`(?m)^  state_dir: (\S+)$`).FindStringSubmatch(string(raw))[1]
}

// stateDir is f.broker's broker.state_dir.
func (f *fleet) stateDir(t *testing.T) string {
	t.Helper()
	return f.stateDirOf(t, f.broker)
}

// copyHolds reads marks.json in the broker.state_dir dir and returns a 1
// or a 0 per principal key, in order: whether the copy holds its mark.
func copyHolds(t *testing.T, dir string, keys ...string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, stateMarksFile))
	if errors.Is(err, os.ErrNotExist) {
		return strings.Repeat("0", len(keys))
	}
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Marks []struct{ Kind, Key string } `json:"marks"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		return "" // mid-write it is never partial (a rename), so this fails the wait
	}
	var b strings.Builder
	for _, k := range keys {
		held := "0"
		for _, m := range f.Marks {
			if m.Kind == store.RevocationPrincipal && m.Key == k {
				held = "1"
			}
		}
		b.WriteString(held)
	}
	return b.String()
}

// adminSocketOf is the admin_socket the config at cfg names.
func adminSocketOf(t *testing.T, cfg string) string {
	t.Helper()
	raw, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return regexp.MustCompile(`(?m)^admin_socket: (\S+)$`).FindStringSubmatch(string(raw))[1]
}

// startBroker runs port49-broker on cfg until the test ends or stop is
// called, and returns the API address of the nth broker serving in out:
// it waits for the nth "port49-broker: listening on" line, any replica's,
// and reads the newest.
func startBroker(t *testing.T, cfg string, out *syncBuffer, n int) (apiAddr string, stop func() error) {
	t.Helper()
	stop = runBrokerUntil(t, cfg, out, "port49-broker: listening on ", n)
	addrs := brokerLine.FindAllStringSubmatch(out.String(), -1)
	return addrs[len(addrs)-1][1], stop
}

// startBrokerNoWait is startBroker that waits for the nth metrics line,
// any replica's, not the API's, and returns the newest's metrics address:
// a start the guard holds serves metrics and nothing else.
func startBrokerNoWait(t *testing.T, cfg string, out *syncBuffer, n int) (metricsAddr string, stop func() error) {
	t.Helper()
	stop = runBrokerUntil(t, cfg, out, "port49-broker: metrics on ", n)
	addrs := metricsLine.FindAllStringSubmatch(out.String(), -1)
	return addrs[len(addrs)-1][1], stop
}

// metricsLine is port49-broker's first line once its metrics serve.
var metricsLine = regexp.MustCompile(`port49-broker: metrics on (127\.0\.0\.1:\d+)\n`)

// runBrokerUntil runs port49-broker on cfg until the test ends or stop is
// called, once out holds want n times.
func runBrokerUntil(t *testing.T, cfg string, out *syncBuffer, want string, n int) (stop func() error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runBroker(ctx, cfg) }()
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
			return errDidNotStop
		}
	}
	t.Cleanup(func() { // before stderr is restored: registered after the caller's
		if err := stop(); errors.Is(err, errDidNotStop) {
			t.Error(err)
		}
	})
	deadline := time.Now().Add(30 * time.Second)
	for strings.Count(out.String(), want) < n {
		select {
		case err := <-done:
			t.Fatalf("port49-broker returned before %q: %v\n%s", want, err, out.String())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("waited 30s for %q ×%d; have %q", want, n, out.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
	return stop
}

// writePolicyOf rewrites the broker.policy_file the port49-broker.yaml at
// cfg names with body, behind the fence's owner and mode rules.
func (f *fleet) writePolicyOf(t *testing.T, cfg, body string) {
	t.Helper()
	writePolicyFile(t, f.policyOf(t, cfg), body)
}

// withdrawnConfigurePolicy is minimalPolicy whose role permits `show **`
// alone: alice loses configure.
var withdrawnConfigurePolicy = strings.Replace(minimalPolicy, `permit: ["**"]`, `permit: ["show **"]`, 1)

// readyzAt is /readyz's status at addr.
func readyzAt(t *testing.T, addr string) int {
	t.Helper()
	resp, err := http.Get("http://" + addr + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// brokerLine is port49-broker's serving line: its API and metrics.
var brokerLine = regexp.MustCompile(`port49-broker: listening on (127\.0\.0\.1:\d+), metrics on (127\.0\.0\.1:\d+)`)

// waitBrokerMetric waits up to 10s for the newest port49-broker's
// /metrics to hold line.
func waitBrokerMetric(t *testing.T, out *syncBuffer, line string) {
	t.Helper()
	ms := brokerLine.FindAllStringSubmatch(out.String(), -1)
	if len(ms) == 0 {
		t.Fatalf("no port49-broker serves: %s", out.String())
	}
	waitBrokerMetricAt(t, ms[len(ms)-1][2], line)
}

// waitBrokerMetricAt waits up to 10s for the /metrics at addr to hold
// line.
func waitBrokerMetricAt(t *testing.T, addr, line string) {
	t.Helper()
	want := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(line) + `$`)
	deadline := time.Now().Add(10 * time.Second)
	for {
		scraped, err := http.Get("http://" + addr + "/metrics")
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(scraped.Body)
		scraped.Body.Close()
		if want.Match(body) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("port49-broker's /metrics lacks %q:\n%s", line, body)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// mintOn is run_test.go's mint, on a port49-broker's API.
func mintOn(t *testing.T, api, pki, device string) string {
	t.Helper()
	return mint(t, api, pki, device)
}

// mintOnAs is run_test.go's mintAs, on a port49-broker's API.
func mintOnAs(t *testing.T, api, pki, device, email string) string {
	t.Helper()
	return mintAs(t, api, pki, device, email)
}

// loadBroker loads the port49-broker.yaml at path, and its keys.
func loadBroker(t *testing.T, path string) (config.Config, crypt.Keys) {
	t.Helper()
	cfg, err := config.LoadBroker(path)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := cfg.EncryptionKeys()
	if err != nil {
		t.Fatal(err)
	}
	return cfg, keys
}

// openBrokerFor is openBroker on the port49-broker.yaml at path, closed
// when the test ends.
func openBrokerFor(t *testing.T, ctx context.Context, path string, m *metrics.Metrics,
	out io.Writer) (brokerStores, crypt.Keys) {
	t.Helper()
	cfg, keys := loadBroker(t, path)
	bs, err := openBroker(ctx, cfg, keys, m, out, crypt.NewLedger(), store.NewMarks())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { bs.raw.Close() })
	return bs, keys
}

// The first port49-broker takes the runner's hold and runs the takeover;
// a second serves the API and says who runs. When the runner stops, the
// second takes over within hold_ttl and a third (Review Focus 4; Ruling 6).
func TestARunnerThatStopsIsReplaced(t *testing.T) {
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	f := splitFleet(t) // hold_ttl 10s
	_, stopA := startBroker(t, f.broker, &out, 1)
	waitFor(t, &out, "runner: took keyspace /port49/")
	apiB, _ := startBroker(t, f.copyBroker(t), &out, 2)
	waitFor(t, &out, "this replica serves the API and takes over if that one stops")
	mintOn(t, apiB, f.pki, "leaf1") // the second serves the API before it runs anything
	start := time.Now()
	if err := stopA(); err != nil {
		t.Fatal(err)
	}
	waitCountWithin(t, &out, "runner: took keyspace /port49/", 2, 30*time.Second)
	if d := time.Since(start); d > 10*time.Second+10*time.Second/3+5*time.Second {
		t.Fatalf("the takeover took %v", d)
	}
	// A graceful stop lets go of the lease at once: the second takes the
	// lock within a second and waits a third of hold_ttl, never the lease's
	// lapse.
	if d := time.Since(start); d > 10*time.Second/3+5*time.Second {
		t.Fatalf("the takeover after a graceful stop took %v: the lease was not let go", d)
	}
}

// A runner cut off from etcd, which neither releases its lease nor renews
// it (a crash, a partition, or a pause past its fence), is replaced once
// its lease lapses: within hold_ttl and a third. Back, it says it lost the
// hold and waits behind the new runner; it runs nothing while that one
// holds (Review Focus 4; pre-flight M9). A graceful stop releases the
// lease at once, so TestARunnerThatStopsIsReplaced alone never reaches
// this path.
func TestARunnerCutOffIsReplacedAfterItsLease(t *testing.T) {
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	f := splitFleet(t)                 // hold_ttl 10s
	cfgA, proxyA := f.copyBrokerVia(t) // A reaches etcd through a proxy of its own
	startBroker(t, cfgA, &out, 1)
	waitFor(t, &out, "runner: took keyspace /port49/")
	startBroker(t, f.copyBroker(t), &out, 2)
	waitFor(t, &out, "this replica serves the API and takes over if that one stops")
	start := time.Now()
	proxyA.Hang(true)
	waitWithin(t, &out, "runner: lost the keyspace's hold", 15*time.Second)
	waitCountWithin(t, &out, "runner: took keyspace /port49/", 2, 30*time.Second)
	if d := time.Since(start); d > 10*time.Second+10*time.Second/3+5*time.Second {
		t.Fatalf("the takeover after a lease never released took %v", d)
	}
	proxyA.Hang(false)
	time.Sleep(10 * time.Second) // A tries again every 5s; B holds throughout
	if n := strings.Count(out.String(), "runner: took keyspace /port49/"); n != 2 {
		t.Fatalf("a runner cut off and back took the hold while another held it: %d takes", n)
	}
}

// A clean takeover, with nothing owed after its carry, records its bundle
// as judged itself: no reloader pass runs to do it (pre-flight I2). The
// next takeover on the same bundle purges nothing.
func TestACleanTakeoverRecordsItsBundleAsJudged(t *testing.T) {
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	f := splitFleet(t)
	_, stop := startBroker(t, f.broker, &out, 1)
	waitFor(t, &out, "runner: recorded bundle ")
	resp, err := f.srv.Client(t, "root").Get(context.Background(), "/port49/v1/meta/judged")
	if err != nil || len(resp.Kvs) != 1 || !strings.Contains(string(resp.Kvs[0].Value), `"bundle":"`+f.bundle(t)+`"`) {
		t.Fatalf("meta/judged after a clean takeover: %v %v", resp, err)
	}
	// The takeover records this start's seal keys (Ruling 6, step 1).
	if resp, err := f.srv.Client(t, "root").Get(context.Background(), "/port49/v1/meta/seal_keys"); err != nil ||
		len(resp.Kvs) != 1 || !strings.Contains(string(resp.Kvs[0].Value), `"current":"v1"`) {
		t.Fatalf("meta/seal_keys after a takeover: %v %v", resp, err)
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	startBroker(t, f.broker, &out, 2)
	waitFor(t, &out, "is the one the last runner judged; no unspent token purged")
}

// A takeover purges the unspent tokens only when the bundle in force is
// not the one the last runner judged (Ruling 7): a broker restart on the
// same policy keeps a minted token redeemable; an edit made with no
// broker running purges it, and an idempotent replay mints afresh. Each
// step waits on the judged line, never on a gauge already at 0 (pre-flight
// I14).
func TestATakeoverPurgesOnlyAnUnjudgedBundle(t *testing.T) {
	var out, log syncBuffer
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o })
	stderr, stdout = &out, &log
	f := splitFleet(t)
	tacacs := startSplitDaemon(t, f.daemon, &out, 1)
	api, stop := startBroker(t, f.broker, &out, 1)
	waitForCount(t, &out, "runner: recorded bundle ", 1)
	kept := mintOn(t, api, f.pki, "leaf1")
	keyed := mintKeyed(t, api, f.pki, "leaf1", "purge-replay")
	stop()
	api, stop = startBroker(t, f.broker, &out, 2)
	waitFor(t, &out, "is the one the last runner judged; no unspent token purged")
	dev := tacacsClient{t: t, addr: tacacs, key: []byte("run-test-secret")}
	if st := dev.login("alice", kept); st != wire.AuthenStatusPass {
		t.Fatalf("control: a token minted before a broker restart on the same policy: %d", st)
	}
	spare := mintOn(t, api, f.pki, "leaf1")
	stop()
	f.editPolicy(t) // a grant's comment changed: another bundle
	api, _ = startBroker(t, f.broker, &out, 3)
	// The second purge line: the first takeover, with nothing recorded,
	// said one too.
	waitForCount(t, &out, "unspent token(s) purged", 2)
	if st := dev.login("alice", spare); st == wire.AuthenStatusPass {
		t.Fatal("a token minted under a bundle no runner judged was not purged")
	}
	waitForCount(t, &out, "runner: recorded bundle ", 3) // the purge's takeover records the new bundle too
	replayed := mintKeyed(t, api, f.pki, "leaf1", "purge-replay")
	if replayed == keyed {
		t.Fatal("a replay of a mint from before the purge was answered with the purged token")
	}
	if st := dev.login("alice", replayed); st != wire.AuthenStatusPass {
		t.Fatalf("the token a replay minted again: %d", st)
	}
}

// A token another replica minted under the replaced policy before it
// reloaded is judged by the runner's settle pass (Ruling 8). The settle's
// delay is exact, not merely past a floor (pre-flight M4).
func TestTheSettlePassJudgesALateReplicasTokens(t *testing.T) {
	for interval, want := range map[time.Duration]time.Duration{
		time.Second: 30 * time.Second, 5 * time.Second: 30 * time.Second,
		20 * time.Second: 45 * time.Second, time.Minute: 125 * time.Second,
	} {
		if got := settleAfter(interval); got != want {
			t.Fatalf("settleAfter(%v) = %v, want %v", interval, got, want)
		}
	}
	rig := newReloadRig(t, minimalPolicy)   // reload_test.go's fixture: a reloader on a memory broker
	swapTo(t, rig, showOnly)                // the edit that withdraws alice's grant
	tok := mintUnder(t, rig, minimalPolicy) // another replica, still on the old policy
	runFirstPass(t, rig)
	runSettlePass(t, rig)
	if tokenStillRedeemable(t, rig, tok) {
		t.Fatal("the settle pass kept a token minted under the replaced policy after the first pass")
	}
}

// A runner whose hold was lost, and whose lease is live, says the keyspace
// is still held by this replica's last run, never that it is run by
// itself; a holder that is another replica's is named as that one (final
// review 7d-2 I-2, 4001732; pre-flight M7).
func TestAHoldStillOnThisReplicasLastRunIsSaidAsIts(t *testing.T) {
	f := splitFleet(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	holding, _ := openBrokerFor(t, ctx, f.broker, metrics.New(prometheus.NewRegistry()), io.Discard)
	waiting, _ := openBrokerFor(t, ctx, f.copyBroker(t), metrics.New(prometheus.NewRegistry()), io.Discard)
	cfg, _ := loadBroker(t, f.broker)
	last := "port49-broker on replica-a (pid 4242, since 2026-10-04T00:00:00Z)"
	_, release, err := holding.raw.Hold(ctx, cfg.Store.Etcd.HoldTTL, last, func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	for _, c := range []struct {
		held, want, never string
	}{
		{last, fmt.Sprintf("port49-broker: runner: keyspace /port49/ is still held by this replica's last run "+
			"(%q); waiting up to hold_ttl (10s) for its lease to expire\n", last), "is run by"},
		{"", fmt.Sprintf("port49-broker: runner: keyspace /port49/ is run by %q; this replica serves the API and "+
			"takes over if that one stops\n", last), "this replica's last run"},
	} {
		var out syncBuffer
		e := stderr
		stderr = &out
		r := &runner{cfg: cfg, raw: waiting.raw, m: metrics.New(prometheus.NewRegistry()), who: last, held: c.held}
		if c.held == "" {
			r.who = "port49-broker on replica-b (pid 7, since 2026-10-04T00:00:00Z)"
		}
		rctx, rcancel := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() { defer close(done); r.run(rctx) }()
		waitCountWithin(t, &out, "keyspace /port49/", 1, 10*time.Second)
		rcancel()
		<-done
		stderr = e
		if got := out.String(); !strings.Contains(got, c.want) || strings.Contains(got, c.never) {
			t.Fatalf("with this replica's last holder %q:\n%s", c.held, got)
		}
	}
}

// Under store.etcd.roles: unenforced the broker's role check still runs:
// an identity that cannot do the broker's work (the daemon's role, which
// cannot write meta/) is refused at start, naming store.etcd.broker (Task
// 11; plan 7e).
func TestTheBrokersRolesCheckRunsUnderUnenforced(t *testing.T) {
	f := splitFleet(t)
	unenforced := f.brokerVia(t, f.proxy.Addr(), "port49-daemon", "    roles: unenforced\n")
	cfg, keys := loadBroker(t, unenforced)
	var out syncBuffer
	_, err := openBroker(context.Background(), cfg, keys, metrics.New(prometheus.NewRegistry()), &out,
		crypt.NewLedger(), store.NewMarks())
	var fault *storeFault
	if !errors.As(err, &fault) || !errors.Is(err, store.ErrRefused) || !strings.Contains(err.Error(), "store.etcd.broker") {
		t.Fatalf("unenforced, a broker identity with the daemon's role: %v\n%s", err, out.String())
	}
	ok := f.brokerVia(t, f.proxy.Addr(), "port49-broker", "    roles: unenforced\n")
	cfg, keys = loadBroker(t, ok)
	bs, err := openBroker(context.Background(), cfg, keys, metrics.New(prometheus.NewRegistry()), &out,
		crypt.NewLedger(), store.NewMarks())
	if err != nil {
		t.Fatalf("unenforced, the broker's own identity: %v", err)
	}
	bs.raw.Close()
	if !strings.Contains(out.String(), "port49-broker: store.etcd.roles: unenforced") {
		t.Fatalf("said %q", out.String())
	}
}

// port49-broker's sealing layer is one, and its reads, the runner's
// included (runner.st), share one sayer: a key is said once, and the line
// is port49-broker's, never port49d's (unopenableSayer; pre-flight M44).
func TestTheBrokersStoresShareOneSayer(t *testing.T) {
	f := splitFleet(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var out syncBuffer
	bs, _ := openBrokerFor(t, ctx, f.broker, metrics.New(prometheus.NewRegistry()), &out)
	fctx, stopFollow := context.WithCancel(ctx)
	followDone := make(chan struct{})
	go func() { defer close(followDone); bs.followContexts(fctx) }()
	defer func() { stopFollow(); <-followDone }()
	k := store.ContextKey{NAS: "leaf1", Username: "alice"}
	retired := crypt.Keys{Current: crypt.Key{ID: "retired", Bytes: [32]byte{7}}}
	if err := crypt.Wrap(bs.raw, retired, nil).PutContext(ctx, k, store.Context{CtxID: "c", Principal: "user:alice",
		Username: "alice", AuthTime: time.Now(), RefreshedAt: time.Now()}, time.Hour); err != nil {
		t.Fatal(err)
	}
	r := &runner{st: bs.st}
	for _, read := range []store.Store{bs.st, r.st} {
		if _, err := read.GetContext(ctx, k); !errors.Is(err, crypt.ErrUnknownKey) {
			t.Fatalf("a context under a retired key: %v", err)
		}
	}
	got := out.String()
	if n := strings.Count(got, `sealed under key id "retired"`); n != 1 ||
		!strings.Contains(got, `port49-broker: crypt: a context is sealed under key id "retired", which this `+
			`port49-broker does not hold`) || strings.Contains(got, "port49d") {
		t.Fatalf("said %d times: %q", n, got)
	}
}

// The broker half of TestOpenStoresFencesEachLayerUnderItsGuard: the
// broker's layer is guard.WrapRev(crypt.Fenced(raw, ledger), …), so with
// its feed not running a context written after the start's scan is not
// read: a context-pool timeout at call_timeout in the broker's guard,
// counted in port49_store_fence_timeouts_total (pre-flight C1; final
// review 7e-1 M-4).
func TestTheBrokersStoreIsFencedUnderItsGuard(t *testing.T) {
	f := splitFleet(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := metrics.New(prometheus.NewRegistry())
	bs, keys := openBrokerFor(t, ctx, f.broker, m, io.Discard)
	other := crypt.NewLedger()
	other.SetBase(bs.raw.Seen() + 1)
	k := store.ContextKey{NAS: "leaf1", Username: "alice"}
	if err := crypt.Wrap(bs.raw, keys, nil, crypt.WithLedger(other)).PutContext(ctx, k, store.Context{CtxID: "c",
		Principal: "user:alice", Username: "alice", AuthTime: time.Now(), RefreshedAt: time.Now()},
		time.Hour); err != nil {
		t.Fatal(err)
	}
	if got, err := bs.st.GetContext(ctx, k); !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("the broker read %q with its feed not running: %v", got.CtxID, err)
	}
	if n := testutil.ToFloat64(m.StoreCalls.WithLabelValues("broker", "context", "timeout")); n != 1 {
		t.Fatalf("the broker's guard counted %v context timeouts", n)
	}
	if n := testutil.ToFloat64(m.StoreFenceTimeouts); n != 1 {
		t.Fatalf("port49_store_fence_timeouts_total = %v, want 1", n)
	}
}

// What the takeover's carry left decides what the takeover does (Rulings
// T12-a, T12-c, T12-d): an outage or an unvisited principal holds it,
// returned for the retry to wait on; a busy context goes on owing a pass
// at once, an unheld key goes on owing the next retry, and anything else
// is returned to end it (Task 12 review I-1; re-review m-5).
func TestTheStartsCarryDecidesHoldOrOpen(t *testing.T) {
	other := errors.New("test: something else")
	unvisited := fmt.Errorf("pass: %w", broker.ErrPrincipalUnvisited)
	outage := fmt.Errorf("pass: %w", store.ErrUnavailable)
	for _, c := range []struct {
		name  string
		err   error
		owed  refreshOwed
		again error
		waits error // what the takeover's retry waits on, for a hold
	}{
		{"nothing left", nil, refreshOwed{}, nil, nil},
		{"an unvisited principal holds", unvisited, refreshOwed{}, unvisited, broker.ErrPrincipalUnvisited},
		{"an outage holds", outage, refreshOwed{}, outage, store.ErrUnavailable},
		{"a busy context opens owing a pass now", fmt.Errorf("pass: %w", store.ErrConflict),
			refreshOwed{owed: true, now: true}, nil, nil},
		{"an unheld key opens owing the next retry", fmt.Errorf("pass: %w", broker.ErrLeftUnderUnheldKey),
			refreshOwed{owed: true}, nil, nil},
		{"anything else ends the start", other, refreshOwed{}, other, nil},
	} {
		owed, again := startLeftBy(c.err)
		if owed != c.owed || again != c.again {
			t.Errorf("%s: startLeftBy = %+v, %v; want %+v, %v", c.name, owed, again, c.owed, c.again)
		}
		if c.waits != nil && !errors.Is(again, c.waits) {
			t.Errorf("%s: the takeover's retry would not wait on %v", c.name, again)
		}
	}
}

// A live session survives a port49d restart on etcd, and a token minted
// before a broker restart on the same policy survives it too (Ruling 7):
// the takeover judges nothing changed, and purges nothing
// (TestATakeoverPurgesOnlyAnUnjudgedBundle has the purge).
func TestRunOnEtcdKeepsALoginAcrossARestart(t *testing.T) {
	var out, log syncBuffer
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o })
	stderr, stdout = &out, &log
	f := splitFleet(t)
	api, stopBroker := startBroker(t, f.broker, &out, 1)
	waitFor(t, &out, "runner: recorded bundle ")
	tacacs, stopDaemon := runSplitDaemon(t, f.daemon, &out, 1)
	dev := tacacsClient{t: t, addr: tacacs, key: []byte("run-test-secret")}
	loginSession(t, dev, mintOn(t, api, f.pki, "leaf1"), &log)
	spare := mintOn(t, api, f.pki, "leaf1")
	if !dev.permits("alice", "configure") {
		t.Fatal("before the restart")
	}
	if err := stopDaemon(); err != nil {
		t.Fatal(err)
	}
	tacacs, _ = runSplitDaemon(t, f.daemon, &out, 2)
	dev = tacacsClient{t: t, addr: tacacs, key: []byte("run-test-secret")}
	if !dev.permits("alice", "configure") {
		t.Fatalf("after port49d's restart the session's next command was not answered from its context; log %s",
			log.String())
	}
	if err := stopBroker(); err != nil {
		t.Fatal(err)
	}
	startBroker(t, f.broker, &out, 2)
	waitFor(t, &out, "is the one the last runner judged; no unspent token purged")
	waitForCount(t, &out, "live context(s) carried onto the policy in force", 2)
	if !dev.permits("alice", "configure") {
		t.Fatalf("after the broker's restart; log %s", log.String())
	}
	if st := dev.login("alice", spare); st != wire.AuthenStatusPass {
		t.Fatalf("a token minted before a broker restart on the same policy: %d", st)
	}
}

// A mark put into the store with every port49-broker stopped, as etcd's
// root (Ruling 13's break-glass with no broker host, in place of 7d's file
// edit), reaches the live context the store kept at the runner's takeover
// (pre-flight C1; spec §14, "A mark at start").
func TestAStartAppliesAStandingMarkToAKeptContext(t *testing.T) {
	var out, log syncBuffer
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o })
	stderr, stdout = &out, &log
	f := splitFleet(t)
	tacacs := startSplitDaemon(t, f.daemon, &out, 1)
	api, stop := startBroker(t, f.broker, &out, 1)
	dev := tacacsClient{t: t, addr: tacacs, key: []byte("run-test-secret")}
	loginSession(t, dev, mintOn(t, api, f.pki, "leaf1"), &log)
	principal := lastCommandPrincipal(t, &log) // the principal the session's records name
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	if _, err := f.srv.Client(t, "root").Put(context.Background(), "/port49/v1/rv/principal/"+principal,
		fmt.Sprintf(`{"kind":"principal","key":%q,"at":%q,"origin":"etcdctl"}`, principal,
			time.Now().UTC().Format(time.RFC3339Nano))); err != nil {
		t.Fatal(err)
	}
	startBroker(t, f.broker, &out, 2)
	// The takeover itself marked it, not only the daemon's marks at request
	// time (re-check R-M1): without ApplyMarksAtStart this line is absent.
	waitFor(t, &out, "port49-broker: runner: 1 standing revocation(s) applied to the live contexts the store kept "+
		"(1 context(s) marked revoked)")
	if dev.permits("alice", "configure") {
		t.Fatal("a kept context under a standing mark was permitted")
	}
	if r := lastCommand(t, &log); r["reason"] != "credential_revoked" {
		t.Fatalf("the denial: %v", r)
	}
}

// A context put back at a key port49d's start never read is denied: the
// start sets the ledger's base once it has read every kept context, so a
// record a store writer puts back afterwards is never taken as that key's
// (decision 35, a start on etcd, step 7; re-check 2 I1).
func TestAStartSealsTheLedgerOnceItHasReadTheStore(t *testing.T) {
	var out, log syncBuffer
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o })
	stderr, stdout = &out, &log
	f := splitFleet(t)
	root := f.srv.Client(t, "root")
	ctx := context.Background()
	api, stopBroker := startBroker(t, f.broker, &out, 1)
	tacacs, stopDaemon := runSplitDaemon(t, f.daemon, &out, 1)
	dev := tacacsClient{t: t, addr: tacacs, key: []byte("run-test-secret")}
	loginSession(t, dev, mintOn(t, api, f.pki, "leaf1"), &log)
	if !dev.permits("alice", "configure") {
		t.Fatalf("before the restart: %v; out %s", lastCommand(t, &log), out.String())
	}
	// Both stopped, the runner's keeper's last write made: nothing writes
	// the ledger record back after the test deletes it.
	if err := stopDaemon(); err != nil {
		t.Fatal(err)
	}
	if err := stopBroker(); err != nil {
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
	tacacs, _ = runSplitDaemon(t, f.daemon, &out, 2)
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
	waitMetric(t, &out, `port49_store_feed_up{feed="contexts"} 1`)
	if strings.Contains(out.String(), "the context feed stopped") {
		t.Fatalf("the feed stopped: %s", out.String())
	}
}

// A store that hangs in the middle of a login: the device hears ERROR
// within store.packet_deadline, never silence (Review Focus 1). Then the
// store has been gone long enough, and port49d closes every listener and
// says why, on its guard and probe, without exiting; port49-broker's
// runner loses its hold and keeps serving. When the store returns, the
// same port49d listens again, and the runner takes the hold again (Ruling
// 11; pre-flight I19; Review Focus 4). While port49d waits, /readyz says
// so (I19), and an earlier version of the session's own context, which a
// store writer puts back in the dark, is denied after the return: the run
// after a store gone keeps the process's ledger (decision 35; Ruling
// T12-b). The runner's carry revokes the record put back (Ruling T13b-a),
// and that revocation stands on the key as the ledger's floor: the
// session's own record, put back after it, is answered revoked (final
// review 7d-2 I-1).
func TestAHungStoreGoesDarkAndServesAgainWhenItReturns(t *testing.T) {
	var out, log syncBuffer
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o })
	stderr, stdout = &out, &log
	f := splitFleet(t)
	root := f.srv.Client(t, "root")
	sctx := context.Background()
	api, _ := startBroker(t, f.broker, &out, 1)
	waitFor(t, &out, "runner: recorded bundle ")

	// An earlier port49d's login, whose record a store writer keeps ...
	tacacs, stop := runSplitDaemon(t, f.daemon, &out, 1)
	loginSession(t, tacacsClient{t: t, addr: tacacs, key: []byte("run-test-secret")},
		mintOn(t, api, f.pki, "leaf1"), &log)
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	kept, err := root.Get(sctx, "/port49/v1/c/", clientv3.WithPrefix())
	if err != nil || len(kept.Kvs) != 1 {
		t.Fatalf("the kept contexts: %v %v", kept, err)
	}
	earlier := kept.Kvs[0]

	tacacs, stopDark := runSplitDaemon(t, f.daemon, &out, 2)
	dev := tacacsClient{t: t, addr: tacacs, key: []byte("run-test-secret")}
	loginSession(t, dev, mintOn(t, api, f.pki, "leaf1"), &log)
	ids := map[string]bool{}
	for _, m := range regexp.MustCompile(`"ctx_id":"([^"]+)"`).FindAllStringSubmatch(log.String(), -1) {
		ids[m[1]] = true
	}
	if len(ids) != 1 {
		t.Fatalf("the second login did not join the earlier one's context: ctx_ids %v", ids)
	}
	tok := mintOn(t, api, f.pki, "leaf1")
	// A connection a device holds open across the hang (re-check R-M0).
	held, err := net.DialTimeout("tcp", tacacs, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()

	f.proxy.Hang(true)
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
	// The broker's runner loses its hold; its API still answers.
	waitWithin(t, &out, "runner: lost the keyspace's hold", 30*time.Second)
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

	f.proxy.Hang(false)
	waitCountWithin(t, &out, "port49d: listening on ", 3, 60*time.Second)
	tacacs = regexp.MustCompile(`port49d: listening on (127\.0\.0\.1:\d+)`).FindAllStringSubmatch(out.String(), -1)[2][1]
	dev = tacacsClient{t: t, addr: tacacs, key: []byte("run-test-secret")}
	if dev.permits("alice", "configure") {
		t.Fatalf("a record put back while the store was gone was taken after it returned; log %s", log.String())
	}
	// The runner takes the hold again, and its carry revokes the record put
	// back.
	waitCountWithin(t, &out, "runner: took keyspace /port49/", 2, 60*time.Second)
	waitCountWithin(t, &out, "live context(s) carried onto the policy in force", 2, 30*time.Second)
	// The runner's revocation of the record put back reaches the running
	// port49d through its context feed, as a floor through the sequences
	// below the revocation's revision (Ruling T15-a): the session's own
	// record, sealed before it and put back after it, is answered revoked
	// (final review 7d-2 I-1).
	floorIn(t, root, "/port49/v1/lw/"+strings.TrimPrefix(string(earlier.Key), "/port49/v1/c/"))
	if _, err := root.Put(sctx, string(earlier.Key), string(now.Kvs[0].Value)); err != nil {
		t.Fatal(err)
	}
	if dev.permits("alice", "configure") {
		t.Fatalf("the session's own record, put back, lifted the revocation the floor holds; log %s", log.String())
	}
	if r := lastCommand(t, &log); r["reason"] != "credential_revoked" {
		t.Fatalf("the session's own record, put back, was not answered revoked: %v", r)
	}
	// A port49d started after it agrees: the runner's keeper wrote the
	// floor to the ledger record (Ruling 4), and the start is seeded with it.
	if err := stopDark(); err != nil {
		t.Fatal(err)
	}
	tacacs, _ = runSplitDaemon(t, f.daemon, &out, 4)
	dev = tacacsClient{t: t, addr: tacacs, key: []byte("run-test-secret")}
	if dev.permits("alice", "configure") {
		t.Fatalf("after a restart the session's own record, put back, was taken; log %s", log.String())
	}
	if r := lastCommand(t, &log); r["reason"] != "credential_revoked" {
		t.Fatalf("after a restart the session's own record, put back, was not answered revoked: %v", r)
	}
	// A login after the revocation is admitted: the system serves again.
	loginSession(t, dev, mintOn(t, api, f.pki, "leaf1"), &log)
	if !dev.permits("alice", "configure") {
		t.Fatalf("after the store returned a new login's command was not permitted; log %s", log.String())
	}
}

// A mark made on one port49-broker's admin socket reaches the other
// replica through the marks feed (plan 7e, Ruling 5): alice's held
// connection to it is closed, said on port49-broker's stderr through
// brk.Say (Ruling T9-c), and the daemon's marks deny her next command
// credential_revoked, its port49_revocations_in_force following. Its lift
// reaches both. And a mark standing in the store alone when a replica
// starts is in its listener's copy before any connection binds.
func TestAMarkFromAnotherBrokerProcessReachesThisOne(t *testing.T) {
	var out, log syncBuffer
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o })
	stderr, stdout = &out, &log
	f := splitFleet(t)
	root := f.srv.Client(t, "root")
	tacacs := startSplitDaemon(t, f.daemon, &out, 1)
	apiA, _ := startBroker(t, f.broker, &out, 1)
	waitFor(t, &out, "runner: recorded bundle ")
	cfgB := f.copyBroker(t)
	apiB, stopB := startBroker(t, cfgB, &out, 2)
	dev := tacacsClient{t: t, addr: tacacs, key: []byte("run-test-secret")}
	loginSession(t, dev, mintOn(t, apiA, f.pki, "leaf1"), &log)
	principal := lastCommandPrincipal(t, &log)
	waitBrokerMetric(t, &out, `port49_store_feed_up{feed="marks"} 1`) // B's marks feed runs (review M4)
	conn := heldBrokerConn(t, f.pki, apiB)
	if r := askSocket(t, adminSocketOf(t, f.broker), admin.Request{Op: "revoke", Principal: principal}); r.Error != "" {
		t.Fatalf("revoke on A's socket: %+v", r)
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("alice's held connection to the other replica was not closed: %v", err)
	}
	waitFor(t, &out, "port49-broker: broker: a revocation of "+principal+" made on a broker process closed 1 ")
	waitBrokerMetric(t, &out, `port49_revocations_in_force{by="principal"} 1`)
	waitInForce(t, &out, "principal", 1) // the daemon's
	if dev.permits("alice", "configure") {
		t.Fatal("a command under a mark the feed brought was permitted")
	}
	if r := lastCommand(t, &log); r["reason"] != "credential_revoked" {
		t.Fatalf("the denial: %v", r)
	}
	if r := askSocket(t, adminSocketOf(t, f.broker), admin.Request{Op: "revoke", Principal: principal,
		Lift: true}); r.Error != "" {
		t.Fatalf("lift on A's socket: %+v", r)
	}
	waitBrokerMetric(t, &out, `port49_revocations_in_force{by="principal"} 0`)
	waitInForce(t, &out, "principal", 0)
	if err := stopB(); err != nil {
		t.Fatal(err)
	}

	// In the store alone: the replica's next start reads it from the
	// store, and its listener refuses alice as she binds.
	if _, err := root.Put(context.Background(), "/port49/v1/rv/principal/"+principal,
		fmt.Sprintf(`{"kind":"principal","key":%q,"at":%q,"origin":"etcdctl"}`, principal,
			time.Now().UTC().Format(time.RFC3339Nano))); err != nil {
		t.Fatal(err)
	}
	apiB, _ = startBroker(t, cfgB, &out, 3)
	status, body, err := postAsAlice(f.pki, apiB)
	if err != nil || status != http.StatusUnauthorized || !strings.Contains(body, `"credential_revoked"`) {
		t.Fatalf("alice's first connection after the start: %s %v", reply(status, body), err)
	}
	waitFor(t, &out, "as it bound: "+principal+" or its certificate is revoked")
}

// A context put back while port49d was stopped, at a key the ledger record
// holds a later mark for, is denied after port49d's restart: the start
// seeds its ledger from the record, which the runner's keeper writes,
// before it scans (Review Focus 2; Ruling 4).
//
// The put-back is a replay of another principal's earlier session at the
// same key: bob's, over alice's later one, at the username both log in as
// (sharedUsernamePolicy). The principal the device's command is
// attributed to shows which record was taken. Two positive controls:
// alice's own session is permitted before the stop, and after a restart
// with nothing put back.
func TestAStartSeededFromTheLedgerRecordDeniesAPutBack(t *testing.T) {
	var out, log syncBuffer
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o })
	stderr, stdout = &out, &log
	f := splitFleetWith(t, sharedUsernamePolicy, []string{"bob@example.com"})
	root := f.srv.Client(t, "root")
	ctx := context.Background()
	api, _ := startBroker(t, f.broker, &out, 1)
	waitFor(t, &out, "runner: recorded bundle ")
	tacacs, stop := runSplitDaemon(t, f.daemon, &out, 1)
	dev := tacacsClient{t: t, addr: tacacs, key: []byte("run-test-secret")}
	loginSession(t, dev, mintOnAs(t, api, f.pki, "leaf1", "bob@example.com"), &log)
	resp, err := root.Get(ctx, "/port49/v1/c/leaf1/alice")
	if err != nil || len(resp.Kvs) != 1 {
		t.Fatalf("bob's context: %v %v", resp, err)
	}
	bobs := resp.Kvs[0]
	s1 := waitForLedgerSeq(t, root, "/port49/v1/lw/leaf1/alice", 0)
	loginSession(t, dev, mintOn(t, api, f.pki, "leaf1"), &log) // alice's, later, at the same key
	waitForLedgerSeq(t, root, "/port49/v1/lw/leaf1/alice", s1) // the runner's keeper holds alice's
	if !dev.permits("alice", "configure") || lastCommandPrincipal(t, &log) != "user:alice@example.com" {
		t.Fatal("control: alice's own session was not permitted as alice before the stop")
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	tacacs, stop = runSplitDaemon(t, f.daemon, &out, 2) // nothing put back
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
	tacacs, _ = runSplitDaemon(t, f.daemon, &out, 3)
	dev = tacacsClient{t: t, addr: tacacs, key: []byte("run-test-secret")}
	if dev.permits("alice", "configure") {
		t.Fatalf("bob's context put back over alice's while port49d was stopped was taken as the key's: %v",
			lastCommandPrincipal(t, &log))
	}
}

// A replica that does not run judges no context at its reload: its pass is
// the token half. The runner's is the whole refresh (Ruling 6).
func TestOnlyTheRunnersPassJudgesContexts(t *testing.T) {
	rig := newReloadRig(t, minimalPolicy)
	k := rig.aliceLoggedIn(t)
	rig.write(t, showOnly)
	r := &runner{brk: rig.b}
	rig.r.pass = r.pass
	rig.with(func() { rig.r.reload(context.Background(), "SIGHUP") })
	if c, err := rig.st.GetContext(context.Background(), k); err != nil || c.BlobHash != "sha256:before" {
		t.Fatalf("a replica that does not run judged a context: %+v %v", c, err)
	}
	ctx := context.Background()
	r.duty.Store(&ctx)
	rig.now = rig.r.settle
	rig.with(func() { rig.r.refresh(context.Background()) })
	if c, err := rig.st.GetContext(context.Background(), k); err != nil || c.BlobHash == "sha256:before" {
		t.Fatalf("the runner's pass did not judge the context: %+v %v", c, err)
	}
}

// port49-broker takes --config alone, or the revoke subcommand: any other
// argument is refused with exit 2, before anything starts, and so is revoke
// without --offline (TestARevokeWithoutOfflineNamesTheSocket).
func TestBrokerMainTakesConfigAlone(t *testing.T) {
	for _, args := range [][]string{{"revoke"}, {"--config", "/nonexistent", "extra"}, {"--listen", ":49"}} {
		if code := BrokerMain(args); code != 2 {
			t.Errorf("BrokerMain(%q) = %d, want 2", args, code)
		}
	}
	if code := BrokerMain([]string{"--config", filepath.Join(t.TempDir(), "absent.yaml")}); code != 1 {
		t.Errorf("a config that does not load: exit %d, want 1", code)
	}
}

// floorIn polls the ledger record at key, as etcd's root, until it holds a
// revocation floor, or 10s pass.
func floorIn(t *testing.T, root *clientv3.Client, key string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if resp, err := root.Get(context.Background(), key); err == nil && len(resp.Kvs) == 1 &&
			strings.Contains(string(resp.Kvs[0].Value), `"revoked_at":`) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("the ledger record at %s never held a floor", key)
}

// A replica that minted under a policy the runner had replaced, then
// reloads, has the runner carry the context its token made: the runner
// runs a full context pass on its ask. Meanwhile the runner records no
// bundle as judged (pre-flight I3; Ruling 8 corrected). Each replica
// mints under its swapped bundle: the runner's at once, the late one's
// once its ask has flagged it (Task 15a re-review 1, I-2).
func TestALateReplicasContextIsCarriedWhenItReloads(t *testing.T) {
	var out, log syncBuffer
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o })
	stderr, stdout = &out, &log
	f := splitFleet(t)
	tacacs := startSplitDaemon(t, f.daemon, &out, 1)
	apiA, _ := startBroker(t, f.broker, &out, 1)
	waitFor(t, &out, "runner: recorded bundle ")
	cfgB := f.copyBroker(t) // a policy file of its own
	apiB, _ := startBroker(t, cfgB, &out, 2)
	lines := brokerLine.FindAllStringSubmatch(out.String(), -1)
	metricsB := lines[len(lines)-1][2]
	f.writePolicyOf(t, f.broker, withdrawnConfigurePolicy) // A's file only: alice loses configure
	waitFor(t, &out, "policy reloaded")
	mintOn(t, apiA, f.pki, "leaf1") // the runner's swap opens its gate at once
	waitFor(t, &out, "this replica serves bundle ")
	// The runner's settle pass, settleAfter (30s) after its reload.
	waitWithin(t, &out, "runner: not recording bundle ", 45*time.Second)
	dev := tacacsClient{t: t, addr: tacacs, key: []byte("run-test-secret")}
	loginSession(t, dev, mintOn(t, apiB, f.pki, "leaf1"), &log) // under B's old policy
	if !dev.permits("alice", "configure") {
		t.Fatal("control: the context B's token made should carry the old grant")
	}
	// B's start asked for one pass already, and its record was judged:
	// count from here.
	recorded := strings.Count(out.String(), "runner: recorded bundle ")
	passes := strings.Count(out.String(), "runner: a full context pass owed by ")
	// B's swap mints nothing until its mark has landed, held here
	// (markSkew), no store fault needed (re-review 2, M-9): the gate's
	// gauge says so, and B stays ready, a store fault being an alarm and
	// never readiness (design §12; re-review 3, I-4).
	release := make(chan struct{})
	ms := markSkew.Load()
	t.Cleanup(func() { markSkew.Store(ms) })
	held := skewMarker(func(ctx context.Context, st startRecorder, bundle string, w io.Writer) error {
		select {
		case <-release:
		case <-ctx.Done():
			return store.ErrUnavailable // a try past its call timeout, tried again
		}
		return (*ms)(ctx, st, bundle, w)
	})
	markSkew.Store(&held)
	reloads := strings.Count(out.String(), "port49-broker: policy reloaded")
	f.writePolicyOf(t, cfgB, withdrawnConfigurePolicy) // B catches up
	waitForCount(t, &out, "port49-broker: policy reloaded", reloads+1)
	resp := postMint(t, apiB, f.pki, "leaf1", "", testpki.LabClientCert, testpki.LabClientKey)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable || !strings.Contains(string(body), `"store_unavailable"`) {
		t.Fatalf("a mint on B before its swap's mark landed: %d %s", resp.StatusCode, body)
	}
	waitBrokerMetricAt(t, metricsB, "port49_broker_mint_gate_closed 1")
	if code := readyzAt(t, metricsB); code != http.StatusOK {
		t.Fatalf("/readyz %d on B while its swap's mark is held", code)
	}
	close(release)
	waitBrokerMetricAt(t, metricsB, "port49_broker_mint_gate_closed 0")
	waitForCount(t, &out, "runner: a full context pass owed by ", passes+1)
	if dev.permits("alice", "configure") {
		t.Fatal("the context a late replica's token made kept the withdrawn grant after it reloaded")
	}
	// Every replica serves the bundle now: the full pass records it.
	waitForCount(t, &out, "runner: recorded bundle ", recorded+1)
	mintOn(t, apiB, f.pki, "leaf1") // B's ask flagged its swap before the pass it owed
}

// A start whose policy file the guard refuses against the bundle last
// judged stays not ready and takes no hold, until the file is fixed
// (Ruling 17; pre-flight I6). The refused file quarantines leaf1, the
// whole fleet: one admitting no device is refused by the start itself.
func TestAStartOnARefusedFileStaysNotReady(t *testing.T) {
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	f := splitFleet(t)
	_, stop := startBrokerNoWait(t, f.broker, &out, 1)
	waitFor(t, &out, "runner: recorded bundle ")
	stop()
	f.writePolicyOf(t, f.broker, quarantiningLeaf1)
	metricsAddr, _ := startBrokerNoWait(t, f.broker, &out, 2)
	waitFor(t, &out, "policy file refused at start against the bundle last judged")
	if code := readyzAt(t, metricsAddr); code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz %d while the file is refused", code)
	}
	waitBrokerMetricAt(t, metricsAddr, "port49_policy_file_refused 1")
	if strings.Count(out.String(), "runner: took keyspace") != 1 {
		t.Fatal("a broker on a refused file took the hold")
	}
	if strings.Count(out.String(), "port49-broker: listening on ") != 1 {
		t.Fatal("a broker on a refused file serves the API")
	}
	f.writePolicyOf(t, f.broker, minimalPolicy)
	waitForCount(t, &out, "runner: took keyspace", 2)
	// The start goes on with the version that passed in force: the takeover
	// carries it, and the reloader finds nothing to reload.
	waitFor(t, &out, "is the one the last runner judged; no unspent token purged")
	if strings.Contains(out.String(), "port49-broker: policy reloaded") {
		t.Fatalf("the start went on with the refused version in force:\n%s", out.String())
	}
	waitBrokerMetricAt(t, metricsAddr, "port49_policy_file_refused 0")
	if code := readyzAt(t, metricsAddr); code != http.StatusOK {
		t.Fatalf("/readyz %d once the file passes", code)
	}
}

// port49-broker's lines are its own: every line it writes, the shared
// paths' among them (the reloader's, the policy's notices, the start's),
// begins "port49-broker", never "port49d: " (Task 15a C1). port49d's are
// unchanged: its own tests read them.
func TestEveryBrokerLineNamesPort49Broker(t *testing.T) {
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	f := splitFleet(t)
	api, stop := startBroker(t, f.broker, &out, 1)
	waitFor(t, &out, "runner: recorded bundle ")
	// A refused handshake: the listener's line, which its caller prefixes
	// (Task 15a review M-6).
	conn, err := net.Dial("tcp", api)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = conn.Write([]byte("GET / HTTP/1.0\r\n\r\n"))
	_, _ = io.Copy(io.Discard, conn)
	conn.Close()
	waitFor(t, &out, "port49-broker: broker: TLS handshake from ")
	f.writePolicyOf(t, f.broker, withdrawnConfigurePolicy)
	waitFor(t, &out, "port49-broker: policy reloaded")
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	for _, l := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if !strings.HasPrefix(l, "port49-broker") {
			t.Fatalf("a port49-broker line not its own: %q\n%s", l, out.String())
		}
	}
}

// Nothing that mints is served, and no hold is taken, until the start's
// records land (recordStart): its first bundle record and, when meta/judged
// names another bundle, the mark (Task 15a review M-1; re-review 1, M-7).
func TestNothingIsServedUntilTheStartsRecordsLand(t *testing.T) {
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	held := make(chan struct{})
	reached := make(chan struct{}, 1)
	rs := recordStart
	t.Cleanup(func() { recordStart = rs })
	recordStart = func(ctx context.Context, st startRecorder, who, bundle string, ttl, call, wait time.Duration,
		w io.Writer) error {
		select {
		case reached <- struct{}{}:
		default:
		}
		select {
		case <-held:
		case <-ctx.Done():
			return ctx.Err()
		}
		return rs(ctx, st, who, bundle, ttl, call, wait, w)
	}
	f := splitFleet(t)
	metricsAddr, _ := startBrokerNoWait(t, f.broker, &out, 1)
	select {
	case <-reached:
	case <-time.After(30 * time.Second):
		t.Fatalf("the start never reached its records:\n%s", out.String())
	}
	time.Sleep(time.Second)
	if strings.Contains(out.String(), "port49-broker: listening on ") ||
		strings.Contains(out.String(), "runner: took keyspace") {
		t.Fatalf("served before the start's records landed:\n%s", out.String())
	}
	if code := readyzAt(t, metricsAddr); code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz %d before the start's records landed", code)
	}
	close(held)
	waitFor(t, &out, "port49-broker: listening on ")
}

// A runner's own swap marks the bundle last judged in doubt, as any
// replica's does: a runner that swaps, then stops before its settle pass,
// leaves tokens minted under a bundle no pass judged, so a takeover by a
// replica still on the judged bundle must purge (Task 15a re-review 2,
// I-3).
func TestARunnersSwapMarksTheJudgedBundleInDoubt(t *testing.T) {
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	f := splitFleet(t)
	_, stopA := startBroker(t, f.broker, &out, 1)
	waitFor(t, &out, "runner: recorded bundle ")
	cfgB := f.copyBroker(t) // still on the judged bundle
	f.writePolicyOf(t, f.broker, withdrawnConfigurePolicy)
	waitFor(t, &out, "port49-broker: policy reloaded")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bs, _ := openBrokerFor(t, ctx, f.broker, metrics.New(prometheus.NewRegistry()), io.Discard)
	waitUntil(t, "meta/judged marked in doubt by the runner's swap", func() bool {
		j, ok, err := bs.raw.Judged(ctx)
		return err == nil && ok && j.InDoubt
	})
	if err := stopA(); err != nil {
		t.Fatal(err)
	}
	startBroker(t, cfgB, &out, 2)
	waitWithin(t, &out, "is in doubt, a replica having served another since; ", 30*time.Second)
}

// After a restore loses a revocation, the runner's takeover puts it back
// from its copy and says so; a mark lifted through the watch is not put
// back (Ruling 12; pre-flight I5). Both were made and the lift lifted on
// the runner's own admin socket: its own changes reach its copy too.
func TestATakeoverPutsBackAMarkTheStoreLost(t *testing.T) {
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	f := splitFleet(t)
	root := f.srv.Client(t, "root")
	_, stop := startBroker(t, f.broker, &out, 1)
	waitFor(t, &out, "runner: recorded bundle ")
	sock := adminSocketOf(t, f.broker)
	for _, req := range []admin.Request{
		{Op: "revoke", Principal: "user:alice@example.com"},
		{Op: "revoke", Principal: "user:carol@example.com"},
		{Op: "revoke", Principal: "user:carol@example.com", Lift: true},
	} {
		if resp := askSocket(t, sock, req); resp.Error != "" {
			t.Fatalf("%+v: %+v", req, resp)
		}
	}
	waitUntil(t, "the copy to hold alice and not carol", func() bool {
		return copyHolds(t, f.stateDir(t), "user:alice@example.com", "user:carol@example.com") == "10"
	})
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	if _, err := root.Delete(context.Background(), "/port49/v1/rv/principal/user:alice@example.com"); err != nil {
		t.Fatal(err) // what a restore from before the revocation leaves
	}
	startBroker(t, f.broker, &out, 2)
	waitFor(t, &out, "1 revocation(s) in broker.state_dir/marks.json were missing from the store")
	waitFor(t, &out, "are put back: principal user:alice@example.com; lift any") // named (re-check R4)
	resp, err := root.Get(context.Background(), "/port49/v1/rv/principal/", clientv3.WithPrefix())
	if err != nil || len(resp.Kvs) != 1 || !strings.Contains(string(resp.Kvs[0].Key), "alice") {
		t.Fatalf("the store's marks after the takeover: %v %v", resp, err)
	}
}

// A lift made on another replica while the runner's marks watch is broken
// for a moment, within the compaction retention, reaches the runner's copy
// as a lift when its watch resumes from its last progress notification,
// and is never put back: no reload runs (final review 7e-1 I-1). Resumed
// from its last change instead, the watch would be compacted and reload,
// and the runner's hook would put alice back. The negative control of
// TestATakeoverPutsBackAMarkTheStoreLost.
func TestALiftAcrossAShortWatchBreakIsNotPutBack(t *testing.T) {
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	f := splitFleetProgress(t, 200*time.Millisecond)
	root := f.srv.Client(t, "root")
	ctx := context.Background()
	cfgA, proxyA := f.copyBrokerVia(t)
	startBroker(t, cfgA, &out, 1)
	waitFor(t, &out, "runner: recorded bundle ") // A runs
	cfgB := f.copyBroker(t)
	startBroker(t, cfgB, &out, 2)
	waitFor(t, &out, "this replica serves the API and takes over if that one stops")
	const alice = "user:alice@example.com"
	if resp := askSocket(t, adminSocketOf(t, cfgB), admin.Request{Op: "revoke", Principal: alice}); resp.Error != "" {
		t.Fatalf("revoke on B: %+v", resp)
	}
	waitUntil(t, "A's copy to hold alice", func() bool { return copyHolds(t, f.stateDirOf(t, cfgA), alice) == "1" })
	// Writes elsewhere move the store past alice's mark, A's marks watch is
	// told a progress at or above them, and the store is compacted there:
	// above A's last change, at or below its last progress.
	var top int64
	for range 3 {
		resp, err := root.Put(ctx, "/restore-test/bump", "x")
		if err != nil {
			t.Fatal(err)
		}
		top = resp.Header.Revision
	}
	time.Sleep(time.Second) // five progress intervals
	if _, err := root.Compact(ctx, top); err != nil {
		t.Fatal(err)
	}
	proxyA.Hang(true)
	if resp := askSocket(t, adminSocketOf(t, cfgB), admin.Request{Op: "revoke", Principal: alice,
		Lift: true}); resp.Error != "" {
		t.Fatalf("lift on B: %+v", resp)
	}
	proxyA.Drop() // A's streams end, and it reconnects
	waitUntil(t, "A's copy to drop alice", func() bool { return copyHolds(t, f.stateDirOf(t, cfgA), alice) == "0" })
	if s := out.String(); strings.Contains(s, "the marks feed's revision was compacted") ||
		strings.Contains(s, "were missing from the store") {
		t.Fatalf("a short break reloaded or put back:\n%s", s)
	}
	if resp, err := root.Get(ctx, "/port49/v1/rv/principal/"+url.PathEscape(alice)); err != nil || len(resp.Kvs) != 0 {
		t.Fatalf("the lift was put back: %v %v", resp, err)
	}
}

// A replica that does not run, restarted after a restore lost a mark its
// copy holds, keeps that mark in force from its start: its listener
// refuses alice as she binds, before any put-back, and the start names
// it. A restart never lifts a mark the store lost (Ruling 12).
func TestARestartedReplicaKeepsAMarkTheStoreLost(t *testing.T) {
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	f := splitFleet(t)
	root := f.srv.Client(t, "root")
	const alice = "user:alice@example.com"
	_, stopA := startBroker(t, f.broker, &out, 1)
	waitFor(t, &out, "runner: recorded bundle ")
	if resp := askSocket(t, adminSocketOf(t, f.broker), admin.Request{Op: "revoke", Principal: alice}); resp.Error != "" {
		t.Fatalf("revoke: %+v", resp)
	}
	waitUntil(t, "A's copy to hold alice", func() bool { return copyHolds(t, f.stateDir(t), alice) == "1" })
	if err := stopA(); err != nil {
		t.Fatal(err)
	}
	if _, err := root.Delete(context.Background(), "/port49/v1/rv/principal/"+alice); err != nil {
		t.Fatal(err) // what a restore from before the revocation leaves
	}
	cfgB := f.copyBroker(t) // its copy holds nothing: it runs, and puts nothing back
	startBroker(t, cfgB, &out, 2)
	waitFor(t, &out, "runner: recorded bundle ")
	apiA, _ := startBroker(t, f.broker, &out, 3)
	waitFor(t, &out, "this replica serves the API and takes over if that one stops")
	waitFor(t, &out, "port49-broker: store: 1 revocation(s) this replica enforces are missing from the store at "+
		"this start")
	status, body, err := postAsAlice(f.pki, apiA)
	if err != nil || status != http.StatusUnauthorized || !strings.Contains(body, `"credential_revoked"`) {
		t.Fatalf("alice's first connection to the restarted replica: %s %v", reply(status, body), err)
	}
	if resp, err := root.Get(context.Background(), "/port49/v1/rv/principal/"+alice); err != nil || len(resp.Kvs) != 0 {
		t.Fatalf("a replica that does not run put a mark back: %v %v", resp, err)
	}
}

// With every port49-broker stopped, the offline revocation reaches a live
// session on port49d at its next command, marks its live context and
// deletes a token minted before (Ruling 13; pre-flight I4). The next
// broker start refuses alice before it mints anything: its first request
// is refused as it binds.
func TestAnOfflineRevokeDeniesWithEveryBrokerStopped(t *testing.T) {
	var out, log syncBuffer
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o })
	stderr, stdout = &out, &log
	f := splitFleet(t)
	tacacs := startSplitDaemon(t, f.daemon, &out, 1)
	api, stop := startBroker(t, f.broker, &out, 1)
	dev := tacacsClient{t: t, addr: tacacs, key: []byte("run-test-secret")}
	loginSession(t, dev, mintOn(t, api, f.pki, "leaf1"), &log)
	spare := mintOn(t, api, f.pki, "leaf1")
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	if !dev.permits("alice", "configure") {
		t.Fatal("control: the session runs on with every broker stopped")
	}
	root := f.srv.Client(t, "root")
	tokens := func() int {
		resp, err := root.Get(context.Background(), "/port49/v1/t/leaf1/alice/", clientv3.WithPrefix(),
			clientv3.WithCountOnly())
		if err != nil {
			t.Fatal(err)
		}
		return int(resp.Count)
	}
	if tokens() == 0 {
		t.Fatal("control: the spare token is not in the store")
	}
	var rout, rerr bytes.Buffer
	if code := offlineRevoke([]string{"--offline", "--config", f.broker, "--principal", "user:alice@example.com"},
		&rout, &rerr); code != 0 {
		t.Fatalf("exit %d: %s", code, rerr.String())
	}
	// The whole revocation, in decision 32's order, not the mark alone: the
	// live context marked and the unspent token deleted (review I-1).
	if !strings.Contains(rerr.String(), "port49-broker: revoke (offline, no API): revoked user:alice@example.com") ||
		!strings.Contains(rerr.String(), ": 1 live context(s) marked, the unspent tokens under 1 (device, username) "+
			"key(s) deleted") {
		t.Fatalf("the report: %s", rerr.String())
	}
	// Who ran it, in the spec's origin vocabulary (Task 15b review M-3).
	if want := fmt.Sprintf(`"origin":"offline uid %d"`, os.Getuid()); !strings.Contains(rout.String(), want) {
		t.Fatalf("the revoke record lacks %s: %s", want, rout.String())
	}
	if n := tokens(); n != 0 {
		t.Fatalf("%d unspent token(s) of alice's left in the store after the offline revocation", n)
	}
	waitUntil(t, "the device to deny alice configure", func() bool { return !dev.permits("alice", "configure") })
	if r := lastCommand(t, &log); r["reason"] != "credential_revoked" {
		t.Fatalf("the denial: %v", r)
	}
	if st := dev.login("alice", spare); st == wire.AuthenStatusPass {
		t.Fatal("a token minted before the offline revocation still logged in")
	}
	api, _ = startBroker(t, f.broker, &out, 2)
	status, body, err := postAsAlice(f.pki, api)
	if err != nil || status != http.StatusUnauthorized || !strings.Contains(body, `"credential_revoked"`) {
		t.Fatalf("alice's first connection after the next start: %s %v", reply(status, body), err)
	}
}

// A restore under a running runner, which compacts its marks watch past
// its last change, is put back by the runner's hook before the marks
// reload: the store holds alice again, and the reload lifts her from no
// replica's marks or listener (plan 7e, Ruling 12; final review 7e-1
// C-1). The runner's hook as runBroker wires it.
func TestARestoreUnderARunningRunnerIsPutBackBeforeTheReload(t *testing.T) {
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	f := splitFleet(t)
	root := f.srv.Client(t, "root")
	ctx := context.Background()
	const alice = "user:alice@example.com"
	cfgA, proxyA := f.copyBrokerVia(t)
	apiA, _ := startBroker(t, cfgA, &out, 1)
	waitFor(t, &out, "runner: recorded bundle ")
	if resp := askSocket(t, adminSocketOf(t, cfgA), admin.Request{Op: "revoke", Principal: alice}); resp.Error != "" {
		t.Fatalf("revoke: %+v", resp)
	}
	waitUntil(t, "A's copy to hold alice", func() bool { return copyHolds(t, f.stateDirOf(t, cfgA), alice) == "1" })
	proxyA.Hang(true)
	if _, err := root.Delete(ctx, "/port49/v1/rv/principal/"+alice); err != nil {
		t.Fatal(err) // what a restore from before the revocation leaves
	}
	var top int64
	for range 3 {
		resp, err := root.Put(ctx, "/restore-test/bump", "x")
		if err != nil {
			t.Fatal(err)
		}
		top = resp.Header.Revision
	}
	if _, err := root.Compact(ctx, top); err != nil {
		t.Fatal(err)
	}
	proxyA.Drop()
	waitWithin(t, &out, "port49-broker: runner: 1 revocation(s) in broker.state_dir/marks.json were missing from the "+
		"store", 20*time.Second)
	if resp, err := root.Get(ctx, "/port49/v1/rv/principal/"+alice); err != nil || len(resp.Kvs) != 1 {
		t.Fatalf("the runner did not put alice back: %v %v", resp, err)
	}
	waitFor(t, &out, "standing revocation(s) applied to the live contexts after a put-back")
	if strings.Contains(out.String(), "a reload of the marks found the revocation of "+alice+" lifted") {
		t.Fatalf("the reload lifted alice:\n%s", out.String())
	}
	status, body, err := postAsAlice(f.pki, apiA)
	if err != nil || status != http.StatusUnauthorized || !strings.Contains(body, `"credential_revoked"`) {
		t.Fatalf("alice after the restore: %s %v", reply(status, body), err)
	}
}

// An etcd restore with every process stopped, as the runbook says, but its
// delete of meta/judged forgotten: the takeover finds meta/witness below
// what this replica recorded and purges, so a token redeemed after the
// snapshot stays spent. The revisions are padded past the record before
// anything starts, as --bump-revision moves them (Ruling 18; re-check R6).
// The backup is taken with every process stopped too: Backup restarts the
// member, and a runner whose hold lapsed across it would not witness the
// redemption.
func TestATakeoverAfterARestorePurgesWithoutTheRunbook(t *testing.T) {
	var out, log syncBuffer
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o })
	stderr, stdout = &out, &log
	f := splitFleet(t)
	root := f.srv.Client(t, "root")
	_, stopD := runSplitDaemon(t, f.daemon, &out, 1)
	api, stop := startBroker(t, f.broker, &out, 1)
	waitFor(t, &out, "runner: recorded bundle ")
	spent := mintOn(t, api, f.pki, "leaf1")
	waitUntil(t, "a witness", func() bool { return witnessAt(t, root) > 0 })
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	if err := stopD(); err != nil {
		t.Fatal(err)
	}
	snapshot := f.srv.Backup(t) // the token is unspent in it, and meta/judged names the bundle
	w0 := witnessAt(t, root)
	tacacs, stopD := runSplitDaemon(t, f.daemon, &out, 2)
	_, stop = startBroker(t, f.broker, &out, 2)
	waitForCount(t, &out, "runner: took keyspace /port49/", 2)
	dev := tacacsClient{t: t, addr: tacacs, key: []byte("run-test-secret")}
	if st := dev.login("alice", spent); st != wire.AuthenStatusPass {
		t.Fatalf("control: the token's first login: %d", st)
	}
	waitUntil(t, "the redemption's witness, recorded", func() bool { return witnessIn(t, f.stateDir(t)) > w0 })
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	if err := stopD(); err != nil {
		t.Fatal(err)
	}
	recorded := witnessIn(t, f.stateDir(t)) // saved as the broker stopped
	f.srv.Restore(t, snapshot)              // meta/judged left as the snapshot's
	padPast(t, root, recorded)              // as --bump-revision moves revisions up
	before := len(out.String())
	dev.addr = startSplitDaemon(t, f.daemon, &out, 3)
	api, _ = startBroker(t, f.broker, &out, 3)
	purged := fmt.Sprintf("below the %d this replica saw: the store was restored from a snapshot; every unspent "+
		"token is purged", recorded)
	waitWithin(t, &out, purged, 30*time.Second)
	// The takeover's purge, not the first witness pass after it: before the
	// carry, and with meta/judged's purge left unsaid.
	waitWithin(t, &out, "live context(s) carried onto the policy in force", 10*time.Second)
	after := out.String()[before:]
	if strings.Index(after, purged) > strings.Index(after, "live context(s) carried onto the policy in force") ||
		strings.Contains(after, "is the one the last runner judged; no unspent token purged") {
		t.Fatalf("the takeover went by meta/judged alone:\n%s", after)
	}
	if st := dev.login("alice", spent); st == wire.AuthenStatusPass {
		t.Fatal("a token redeemed after the snapshot logged in again after the restore")
	}
	if st := dev.login("alice", mintOn(t, api, f.pki, "leaf1")); st != wire.AuthenStatusPass {
		t.Fatalf("control: a token minted after the takeover: %d", st)
	}
}

// A replica that never ran, and only followed the witness, catches the
// restore at its takeover as the runner would have: the record is every
// replica's, not the runner's alone (Ruling 18; re-check R6). The backup
// is taken before B starts and while A is stopped: Backup restarts the
// member, and B could take a hold A lost across it.
func TestAWitnessRecordFromAnotherReplicaCatchesTheRestore(t *testing.T) {
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	f := splitFleet(t)
	root := f.srv.Client(t, "root")
	_, stopA := startBroker(t, f.broker, &out, 1)
	waitFor(t, &out, "runner: recorded bundle ")
	waitUntil(t, "a witness", func() bool { return witnessAt(t, root) > 0 })
	if err := stopA(); err != nil {
		t.Fatal(err)
	}
	snapshot := f.srv.Backup(t)
	w0 := witnessAt(t, root)
	apiA, stopA := startBroker(t, f.broker, &out, 2)
	waitForCount(t, &out, "runner: took keyspace /port49/", 2)
	cfgB := f.copyBroker(t) // a broker.state_dir of its own
	_, stopB := startBroker(t, cfgB, &out, 3)
	waitFor(t, &out, "this replica serves the API and takes over if that one stops")
	mintOn(t, apiA, f.pki, "leaf1") // brings a witness
	waitUntil(t, "B's copy of the witness to rise", func() bool { return witnessIn(t, f.stateDirOf(t, cfgB)) > w0 })
	// The follower path, proved: A held throughout, so B's record came only
	// from following. Had A's hold lapsed, B would have run and recorded its
	// own writes (final check, Minor 3).
	if n := strings.Count(out.String(), "runner: took keyspace /port49/"); n != 2 {
		t.Fatalf("the hold changed hands: %d takes; the follower path is not what was tested", n)
	}
	if err := stopB(); err != nil { // B first, so it never takes the hold
		t.Fatal(err)
	}
	if err := stopA(); err != nil {
		t.Fatal(err)
	}
	recorded := witnessIn(t, f.stateDirOf(t, cfgB))
	f.srv.Restore(t, snapshot)
	startBroker(t, cfgB, &out, 4)
	waitWithin(t, &out, fmt.Sprintf("the store's meta/witness is at revision %d, below the %d this replica saw: "+
		"the store was restored from a snapshot", w0, recorded), 30*time.Second)
}

// witnessAt is meta/witness's ModRevision read as etcd's root, 0 when it
// is absent, tried again for 10s while the member restarts under the
// client.
func witnessAt(t *testing.T, root *clientv3.Client) uint64 {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		resp, err := root.Get(ctx, "/port49/v1/meta/witness")
		cancel()
		if err == nil {
			if len(resp.Kvs) == 0 {
				return 0
			}
			return uint64(resp.Kvs[0].ModRevision)
		}
		if time.Now().After(deadline) {
			t.Fatalf("reading meta/witness: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// witnessIn is the mod_revision of witness.json in the broker.state_dir
// dir, 0 when there is none.
func witnessIn(t *testing.T, dir string) uint64 {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, stateWitnessFile))
	if errors.Is(err, os.ErrNotExist) {
		return 0
	}
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		ModRevision uint64 `json:"mod_revision"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("%s: %v", stateWitnessFile, err) // written by a rename, never partial
	}
	return f.ModRevision
}

// padPast puts /pad/<n> as etcd's root until a put's header revision is
// past rev, tried again for 10s while the member restarts: what
// --bump-revision does to the revisions a restore starts from.
func padPast(t *testing.T, root *clientv3.Client, rev uint64) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for n := 0; ; n++ {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		resp, err := root.Put(ctx, fmt.Sprintf("/pad/%d", n), "x")
		cancel()
		switch {
		case err == nil && uint64(resp.Header.Revision) > rev:
			return
		case err != nil && time.Now().After(deadline):
			t.Fatalf("padding the revisions past %d: %v", rev, err)
		case err != nil:
			time.Sleep(100 * time.Millisecond)
		}
	}
}
