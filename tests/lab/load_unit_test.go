//go:build lab

package lab

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/blanketfish/port49/internal/admission"
	"github.com/blanketfish/port49/internal/broker/api"
	"github.com/blanketfish/port49/internal/devicemock"
	"github.com/blanketfish/port49/internal/policy"
)

// TestLoadCellSelection pins PORT49_LAB_LOAD_CELLS: empty runs every cell, a
// list runs those in the harness's order, an unknown or repeated ID is refused.
func TestLoadCellSelection(t *testing.T) {
	all := []string{"a", "b", "c", "d", "e", "e2", "f"}
	for in, want := range map[string][]string{
		"":               all,
		"  ":             all,
		"a":              {"a"},
		"c,a":            {"a", "c"},
		" b , f ":        {"b", "f"},
		"a,b,c,d,e,e2,f": all,
	} {
		got, err := parseLoadCells(in)
		if err != nil || strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("parseLoadCells(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"g", "a,x", "a,a", "A", ",", "a,,b"} {
		if got, err := parseLoadCells(in); err == nil {
			t.Errorf("parseLoadCells(%q) = %v, want an error", in, got)
		}
	}
}

func TestLoadRefusesAShortRun(t *testing.T) {
	if err := validateLoadCell(loadCell{Rate: 170, Duration: 5 * time.Minute}); err == nil {
		t.Fatal("a 5 minute run at 170/s was accepted")
	}
	if err := validateLoadCell(loadCell{Rate: 170, Duration: 10 * time.Minute}); err != nil {
		t.Fatalf("the design's run: %v", err)
	}
	if err := validateLoadCell(loadCell{Rate: 0, Duration: 10 * time.Minute}); err == nil {
		t.Fatal("a run with no rate was accepted")
	}
	// Cell c's steps are a minute each, f's run is two.
	if err := validateLoadCell(loadCell{ID: "c", Rate: 170, Duration: time.Minute}); err != nil {
		t.Fatalf("a stepped accounting cell's 60 s step: %v", err)
	}
	if err := validateLoadCell(loadCell{ID: "f", Rate: 170, Duration: 30 * time.Second}); err == nil {
		t.Fatal("a 30 s netem run was accepted")
	}
}

func TestLoadNoteHoldsNoToken(t *testing.T) {
	const token = "not-a-real-token"
	// The observed values come from a fleet result: counts and durations,
	// never the logins the fleet played.
	res := devicemock.FleetResult{Plays: 100, Errors: 1,
		StepP50: map[string]time.Duration{"command_permitted": time.Millisecond},
		StepP99: map[string]time.Duration{"command_permitted": 2 * time.Millisecond}}
	_ = devicemock.Login{User: "svc00", Credential: []byte(token)}
	cells := []loadCell{{ID: "a", Transport: "tcp", Rate: 170, Duration: 10 * time.Minute, Pass: true,
		Observed: loadObserved(res, 3*time.Millisecond, 9*time.Millisecond)}}
	note, err := loadNote(cells, hostFacts{CPU: "test cpu", Cores: 8, RAMMB: 1024, Disk: "nvme", Kernel: "7.0"})
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{token, "credential", "token"} {
		if strings.Contains(strings.ToLower(note), bad) {
			t.Errorf("the note holds %q:\n%s", bad, note)
		}
	}
	if !strings.Contains(note, "command_permitted") {
		t.Errorf("the note lacks the step latencies:\n%s", note)
	}
	// An Observed value that does carry one is refused before anything is printed.
	for _, leak := range []string{token, "credential=abc", "eyJhbGciOiJIUzI1NiJ9", strings.Repeat("A", 30)} {
		poisoned := []loadCell{{ID: "a", Transport: "tcp", Rate: 170, Duration: 10 * time.Minute,
			Observed: map[string]string{"x": leak}}}
		if out, err := loadNote(poisoned, hostFacts{}); err == nil || out != "" {
			t.Errorf("a note over Observed %q was printed: %q, %v", leak, out, err)
		}
	}
}

func TestTheLoadPolicyHas500PrincipalsAnd10000Devices(t *testing.T) {
	var inv struct {
		Devices []struct {
			Name      string   `yaml:"name"`
			Platform  string   `yaml:"platform"`
			Addresses []string `yaml:"addresses"`
			Transport string   `yaml:"transport"`
		} `yaml:"devices"`
	}
	if err := yaml.Unmarshal([]byte(loadInventory(loadDevices, "tcp")), &inv); err != nil {
		t.Fatal(err)
	}
	if len(inv.Devices) != 10000 {
		t.Fatalf("%d devices, want 10000", len(inv.Devices))
	}
	for i, d := range inv.Devices {
		if want := devicemock.LoopbackSource(i); len(d.Addresses) != 1 || d.Addresses[0] != want {
			t.Fatalf("device %d on %v, want %s", i, d.Addresses, want)
		}
		if d.Platform != "arista_eos" || d.Name != loadDeviceName(i) {
			t.Fatalf("device %d is %+v", i, d)
		}
	}
	if inv.Devices[0].Addresses[0] != "127.0.1.1" || inv.Devices[0].Transport != "" {
		t.Fatalf("the first device: %+v", inv.Devices[0])
	}
	if err := yaml.Unmarshal([]byte(loadInventory(3, "tls")), &inv); err != nil || inv.Devices[2].Transport != "tls" {
		t.Fatalf("tls inventory: %v %+v", err, inv)
	}

	var pol struct {
		Subjects []struct {
			Name     string   `yaml:"name"`
			Identity []string `yaml:"identity"`
			Username string   `yaml:"username"`
		} `yaml:"subjects"`
		Grants []struct {
			Subject string   `yaml:"subject"`
			Scope   string   `yaml:"scope"`
			Roles   []string `yaml:"roles"`
		} `yaml:"grants"`
	}
	if err := yaml.Unmarshal([]byte(loadPolicy()), &pol); err != nil {
		t.Fatal(err)
	}
	granted := map[string]bool{}
	for _, g := range pol.Grants {
		granted[g.Subject] = true
	}
	var machines, humans int
	for _, s := range pol.Subjects {
		switch {
		case strings.HasPrefix(s.Name, "svc_"):
			machines++
			if !granted[s.Name] {
				t.Errorf("%s has no grant", s.Name)
			}
			if len(s.Identity) != 1 || s.Identity[0] != "user:"+loadPrincipalEmail(machines-1) {
				t.Errorf("%s identity %v", s.Name, s.Identity)
			}
		case strings.HasPrefix(s.Name, "human_"):
			humans++
		default:
			t.Errorf("subject %q is neither", s.Name)
		}
	}
	if machines != 50 || humans != 450 {
		t.Fatalf("%d machine and %d human subjects, want 50 and 450", machines, humans)
	}
}

// The policy the load run uses loads, at a small inventory and with the
// run's key in the environment.
func TestTheLoadPolicyLoads(t *testing.T) {
	t.Setenv("PORT49_KEY_LOAD", "not-a-real-key-0123456789")
	dev := []admission.Device{{Name: "load-00000", Platform: "arista_eos", Addresses: []netip.Addr{netip.MustParseAddr("127.0.1.1")}}}
	if _, err := policy.Parse([]byte(loadPolicy()), policy.Env{Now: time.Now(), Devices: dev}); err != nil {
		t.Fatal(err)
	}
}

func TestLoadNetemTouchesOnlyTheDirectoryPorts(t *testing.T) {
	up := loadNetem(true)
	joined := ""
	for _, c := range up {
		joined += strings.Join(c, " ") + "\n"
	}
	for _, port := range loadDirectoryClientPorts {
		if !strings.Contains(joined, "dport "+port) {
			t.Errorf("no filter for client port %s:\n%s", port, joined)
		}
	}
	if !strings.Contains(joined, "priomap 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1") {
		t.Errorf("the prio priomap must send ordinary traffic to band 2, not through netem:\n%s", joined)
	}
	if !strings.Contains(joined, "netem delay 40ms") || strings.Contains(joined, "root netem") {
		t.Errorf("netem must hang off a band, not the whole of lo:\n%s", joined)
	}
	if down := loadNetem(false); len(down) != 1 || strings.Join(down[0], " ") != "tc qdisc del dev lo root" {
		t.Errorf("down = %v", down)
	}
}

func TestLoadMetricsReading(t *testing.T) {
	text := `# HELP x y
port49_connections{state="open"} 7
port49_connections{state="idle"} 3
port49_accounting_spool_depth 12
port49_accounting_spool_drops_total{stage="full"} 2
port49_accounting_spool_drops_total{stage="write"} 1
port49_store_call_seconds_bucket{component="a",pool="p",le="0.01"} 90
port49_store_call_seconds_bucket{component="a",pool="p",le="0.1"} 99
port49_store_call_seconds_bucket{component="a",pool="p",le="+Inf"} 100
port49_store_call_seconds_bucket{component="b",pool="p",le="0.01"} 100
port49_store_call_seconds_bucket{component="b",pool="p",le="0.1"} 100
port49_store_call_seconds_bucket{component="b",pool="p",le="+Inf"} 100
`
	m := parseLoadMetrics(text)
	if m.Connections != 10 || m.SpoolDepth != 12 || m.SpoolDrops != 3 {
		t.Fatalf("%+v", m)
	}
	// 200 calls, the 198th at or under 0.1 s.
	if got := m.Quantile(0.99); got != 100*time.Millisecond {
		t.Fatalf("p99 = %s, want 100ms", got)
	}
	if got := m.Sub(m).Quantile(0.99); got != 0 {
		t.Fatalf("no new calls: p99 = %s", got)
	}
}

// The profile the load plays loads, and has the account steps cell c plays alone.
func TestLoadProfileLoads(t *testing.T) {
	p, err := devicemock.Load("../qual/profiles/"+loadProfile, "../..")
	if err != nil {
		t.Fatal(err)
	}
	var acct []string
	for _, s := range p.Stimulus.Steps {
		if s.Type == "acct" {
			acct = append(acct, s.Name)
		}
	}
	if strings.Join(acct, ",") != "account_start,account_stop" {
		t.Fatalf("acct steps %v", acct)
	}
}

// A run's STOP sentinel cancels the load within a poll, wherever a cell is.
func TestLoadStopsWhenTheSentinelAppears(t *testing.T) {
	var polls atomic.Int32
	check := func() error {
		if polls.Add(1) > 3 {
			return errors.New("the lab STOP sentinel exists")
		}
		return nil
	}
	ctx, stopped := loadStopOnSentinel(context.Background(), check, 10*time.Millisecond)
	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("the load ran on past the sentinel")
	}
	if err := stopped(); err == nil || !strings.Contains(err.Error(), "STOP") {
		t.Fatalf("stopped() = %v, want the guard's error", err)
	}

	// With the sentinel absent the context lives until stopped() is called, and
	// stopped() reports no error.
	ctx, stopped = loadStopOnSentinel(context.Background(), func() error { return nil }, 10*time.Millisecond)
	time.Sleep(60 * time.Millisecond)
	if ctx.Err() != nil {
		t.Fatalf("cancelled with no sentinel: %v", ctx.Err())
	}
	if err := stopped(); err != nil {
		t.Fatal(err)
	}
}

// Cell d passes only when every process confirms the swap.
func TestLoadReloadMustBeConfirmedByEveryProcess(t *testing.T) {
	ok := func() (time.Duration, error) { return 72 * time.Second, nil }
	missing := func() (time.Duration, error) { return 0, errors.New("did not say it") }
	obs, all := loadAwaitSwaps(map[string]func() (time.Duration, error){"port49d": ok, "port49_broker": ok})
	if !all || obs["port49d_reload_seconds"] != "72.0" || obs["port49_broker_reload_seconds"] != "72.0" {
		t.Fatalf("%v %v", obs, all)
	}
	obs, all = loadAwaitSwaps(map[string]func() (time.Duration, error){"port49d": ok, "port49_broker": missing})
	if all || obs["port49_broker_reload"] != "no swap seen" || obs["port49d_reload_seconds"] != "72.0" {
		t.Fatalf("a missing swap passed: %v %v", obs, all)
	}
}

// Cell d's fault counts only when all of it fell inside the fleet's run.
func TestLoadFaultMustFallInsideTheRun(t *testing.T) {
	t0 := time.Now()
	at := func(d time.Duration) time.Time { return t0.Add(d) }
	end := at(10 * time.Minute)
	for name, c := range map[string]struct {
		stop, cont time.Time
		want       bool
	}{
		"inside":                 {at(400 * time.Second), at(420 * time.Second), true},
		"never stopped":          {time.Time{}, time.Time{}, false},
		"stopped, never resumed": {at(400 * time.Second), time.Time{}, false},
		"after the fleet ended":  {at(11 * time.Minute), at(11*time.Minute + 20*time.Second), false},
		"resumed after the end":  {at(595 * time.Second), at(615 * time.Second), false},
	} {
		if got := loadFaultInWindow(c.stop, c.cont, end); got != c.want {
			t.Errorf("%s: %v, want %v", name, got, c.want)
		}
	}
}

// A session etcd left stopped by a killed run is reaped by the PID the run
// recorded, only while /proc says that PID still runs the etcd binary.
func TestLoadReapsOnlyTheRecordedEtcd(t *testing.T) {
	proc, dir := t.TempDir(), t.TempDir()
	etcd := filepath.Join(dir, "etcd")
	if err := os.WriteFile(etcd, nil, 0o755); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(dir, "other")
	if err := os.WriteFile(other, nil, 0o755); err != nil {
		t.Fatal(err)
	}
	pidfile := filepath.Join(dir, "session-etcd.pid")
	dataDir := filepath.Join(dir, "s.etcd")
	if _, reap, _ := loadStaleSession(pidfile, proc, etcd); reap {
		t.Fatal("reaped with no pidfile")
	}
	os.WriteFile(pidfile, []byte("4242\n"+dataDir+"\n"), 0o600)
	if _, reap, why := loadStaleSession(pidfile, proc, etcd); reap || why == "" {
		t.Fatalf("reaped a PID that is gone: %v %q", reap, why)
	}
	os.MkdirAll(filepath.Join(proc, "4242"), 0o755)
	os.Symlink(other, filepath.Join(proc, "4242", "exe"))
	if _, reap, _ := loadStaleSession(pidfile, proc, etcd); reap {
		t.Fatal("reaped a PID that now runs another program")
	}
	os.Remove(filepath.Join(proc, "4242", "exe"))
	os.Symlink(etcd, filepath.Join(proc, "4242", "exe"))
	// The same binary on another run's data directory (L74, L80, the store
	// harness) is refused.
	os.WriteFile(filepath.Join(proc, "4242", "cmdline"), []byte("etcd\x00--data-dir\x00"+filepath.Join(dir, "other.etcd")+"\x00"), 0o600)
	if _, reap, _ := loadStaleSession(pidfile, proc, etcd); reap {
		t.Fatal("reaped an etcd on another data directory")
	}
	os.WriteFile(filepath.Join(proc, "4242", "cmdline"), []byte("etcd\x00--data-dir\x00"+dataDir+"\x00"), 0o600)
	if pid, reap, _ := loadStaleSession(pidfile, proc, etcd); !reap || pid != 4242 {
		t.Fatalf("did not reap the recorded etcd: %d %v", pid, reap)
	}
	for _, bad := range []string{"1\n", "0", "abc", "-5"} {
		os.WriteFile(pidfile, []byte(bad+"\n"+dataDir), 0o600)
		if _, reap, _ := loadStaleSession(pidfile, proc, etcd); reap {
			t.Errorf("reaped on pidfile %q", bad)
		}
	}
}

func TestLoadNetemWillNotTouchAQdiscItDidNotInstall(t *testing.T) {
	for show, want := range map[string]struct {
		remove bool
		err    bool
	}{
		"qdisc noqueue 0: root refcnt 2\n": {false, false},
		"qdisc prio 1: root refcnt 2 bands 3 priomap 1 1 1\nqdisc netem 30: parent 1:3 limit 1000 delay 40ms\n": {true, false},
		"qdisc prio 1: root refcnt 2 bands 3 priomap 1 1 1\n":                                                   {false, true},
		"qdisc prio 1: root refcnt 2 bands 3 priomap 1 1 1\nqdisc netem 30: parent 1:3 limit 1000 delay 5ms\n":  {false, true},
		"qdisc fq_codel 0: root refcnt 2 limit 10240p\n":                                                        {false, true},
		"": {false, false},
	} {
		remove, err := loadNetemPlan(show)
		if remove != want.remove || (err != nil) != want.err {
			t.Errorf("%q: remove %v err %v", show, remove, err)
		}
	}
}

// Cell d's policy edit is one the real loader accepts, every reload: an edit
// above MaxTokenTTL was refused by both processes in load run 1.
func TestLoadPolicyEditIsAccepted(t *testing.T) {
	t.Setenv("PORT49_KEY_LOAD", "not-a-real-key-0123456789")
	dev := []admission.Device{{Name: "load-00000", Platform: "arista_eos", Addresses: []netip.Addr{netip.MustParseAddr("127.0.1.1")}}}
	path := filepath.Join(t.TempDir(), "policy.yaml")
	for reloads := 1; reloads <= 5; reloads++ {
		body := loadEditedPolicy(reloads)
		if body == loadPolicy() {
			t.Fatalf("reload %d: the edit changed nothing", reloads)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := policy.Load(path, policy.Env{Now: time.Now(), Devices: dev}); err != nil {
			t.Fatalf("reload %d: the loader refused the edit: %v", reloads, err)
		}
	}
}

// The burst cell models the client that ships, which holds one connection to the
// broker (internal/agent/agent.go, MaxConnsPerHost: 1); more would be evicted
// by the broker's per-principal cap.
func TestLoadBrokerTransportHoldsOneConnection(t *testing.T) {
	if got := loadBrokerTransport(nil).MaxConnsPerHost; got != 1 {
		t.Fatalf("MaxConnsPerHost = %d, want 1", got)
	}
}

// The broker is not ready at "listening on": it refuses mints with 503 until it
// logs "policy: mints open".
func TestLoadWaitsForTheBrokersMintGate(t *testing.T) {
	var want string
	for _, l := range loadStartLines["port49-broker"] {
		if strings.Contains(l, "mints open") {
			want = l
		}
	}
	if want == "" {
		t.Fatalf("the broker's start lines %v do not wait for its mint gate", loadStartLines["port49-broker"])
	}
	src, err := os.ReadFile("../../internal/port49d/policyskew.go")
	if err != nil || !strings.Contains(string(src), want) {
		t.Fatalf("policyskew.go does not log %q: %v", want, err)
	}
}

// Cell e2 is 20 real workload processes under one principal, run after cell e
// and before f; it passes iff all 20 exit 0.
func TestLoadWorkloadBurstShape(t *testing.T) {
	if loadWorkloadBurst != 20 || loadWorkloadPrincipal != 0 {
		t.Fatalf("burst %d under principal %d, want 20 under 0", loadWorkloadBurst, loadWorkloadPrincipal)
	}
	i, j, k := slices.Index(loadCellIDs, "e"), slices.Index(loadCellIDs, "e2"), slices.Index(loadCellIDs, "f")
	if i < 0 || j != i+1 || k != j+1 {
		t.Fatalf("cells %v: e2 does not run between e and f", loadCellIDs)
	}
	if err := validateLoadCell(loadCell{ID: "e2", Rate: loadRate, Duration: loadMinDuration}); err != nil {
		t.Fatal(err)
	}
	zeros := make([]int, loadWorkloadBurst)
	if !loadWorkloadPass(zeros) {
		t.Fatal("20 exits of 0 did not pass")
	}
	one := slices.Clone(zeros)
	one[7] = 75
	if loadWorkloadPass(one) {
		t.Fatal("a run with an exit 75 passed")
	}
	if loadWorkloadPass(zeros[:19]) {
		t.Fatal("19 processes passed")
	}
	args := loadWorkloadArgs("127.0.0.1:18443", "ca.pem", "c.pem", "k.pem", []string{"d1", "d2"})
	if got := strings.Join(args, " "); got != "workload token --broker https://127.0.0.1:18443 --broker-ca ca.pem --cert c.pem --key k.pem d1 d2" {
		t.Fatalf("args %q", got)
	}
}

// The evicted-connections counter is read from the broker's metrics.
func TestLoadMetricsReadsEvictions(t *testing.T) {
	m := parseLoadMetrics("port49_broker_connection_events_total{event=\"principal_cap_evicted\"} 16\n" +
		"port49_broker_connection_events_total{event=\"other\"} 3\n")
	if m.Evicted != 16 {
		t.Fatalf("Evicted = %v, want 16", m.Evicted)
	}
}

// The harness's broker clients time out as the agent's do (30 s, agent.go), and
// every process startProcs starts has start lines.
func TestLoadHarnessMatchesTheAgentAndKnowsEveryProcess(t *testing.T) {
	if loadClientTimeout != 30*time.Second {
		t.Fatalf("loadClientTimeout = %v, want 30s", loadClientTimeout)
	}
	for _, name := range []string{"port49-broker", "port49d"} {
		if len(loadStartLines[name]) == 0 {
			t.Fatalf("no start lines for %q", name)
		}
	}
}

// A failed mint's time and its status and reason are in the note: a cell that
// fails every mint no longer reads "p50 0".
func TestTakeMintsRecordsFailedMintsAndTheirReasons(t *testing.T) {
	r := &loadRun{}
	r.noteMint(10*time.Millisecond, true, nil)
	r.noteMint(500*time.Millisecond, false, &loadMintError{status: 503, reason: "store_unavailable"})
	r.noteMint(700*time.Millisecond, false, &loadMintError{status: 503, reason: "store_unavailable"})
	r.noteMint(5*time.Millisecond, false, &loadMintError{status: 401, reason: "secret token abc"})
	r.noteMint(time.Second, false, errors.New("mint: Post: some body text that is not a reason"))
	got := r.takeMints()
	if got.P50 != 10*time.Millisecond || got.Errs != 4 {
		t.Fatalf("p50 %v errs %d", got.P50, got.Errs)
	}
	if got.FailP50 != 500*time.Millisecond || got.FailP99 != time.Second {
		t.Fatalf("failed p50 %v p99 %v", got.FailP50, got.FailP99)
	}
	want := map[string]int{"503_store_unavailable": 2, "401_other": 1, "0_transport": 1}
	if len(got.Buckets) != len(want) {
		t.Fatalf("buckets %v, want %v", got.Buckets, want)
	}
	for k, n := range want {
		if got.Buckets[k] != n {
			t.Fatalf("bucket %s = %d, want %d (%v)", k, got.Buckets[k], n, got.Buckets)
		}
	}
	if again := r.takeMints(); again.Errs != 0 || len(again.Buckets) != 0 {
		t.Fatalf("takeMints did not reset: %+v", again)
	}
	o := map[string]string{}
	got = loadMintStats{FailP50: time.Second, FailP99: 2 * time.Second, Buckets: map[string]int{"503_store_unavailable": 2}}
	got.addTo(o)
	if o["mint_fail_p50_ms"] != "1000.00" || o["mint_fail_p99_ms"] != "2000.00" || o["mint_errors_503_store_unavailable"] != "2" {
		t.Fatalf("observed %v", o)
	}
}

// A reason comes from the reply's error code, never its detail or body.
func TestDecodeMintReadsTheReasonFieldNotTheBody(t *testing.T) {
	_, err := decodeMint(503, []byte(`{"error":"store_unavailable","detail":"dial tcp 10.1.2.3: refused"}`))
	var me *loadMintError
	if !errors.As(err, &me) || me.status != 503 || me.reason != "store_unavailable" {
		t.Fatalf("%v", err)
	}
	if strings.Contains(err.Error(), "10.1.2.3") {
		t.Fatalf("the detail reached the error: %v", err)
	}
	_, err = decodeMint(502, []byte("<html>bad gateway</html>"))
	if !errors.As(err, &me) || me.reason != "other" {
		t.Fatalf("a body that is not a reply: %v", err)
	}
	out, err := decodeMint(200, []byte(`{"principal":"p","results":[{"verdict":"deny","reason":"store_unavailable"}]}`))
	if err != nil || len(out.Results) != 1 || loadItemReason(out) != "store_unavailable" {
		t.Fatalf("%v %v", out, err)
	}
}

func TestTheWALFsyncMeanIsSumOverCount(t *testing.T) {
	m := parseLoadMetrics("etcd_disk_wal_fsync_duration_seconds_sum 2.5\netcd_disk_wal_fsync_duration_seconds_count 500\n")
	if got := m.WALFsyncMeanMS(); got != "5.00" {
		t.Fatalf("mean %q", got)
	}
	later := parseLoadMetrics("etcd_disk_wal_fsync_duration_seconds_sum 3.5\netcd_disk_wal_fsync_duration_seconds_count 600\n")
	if got := later.Sub(m).WALFsyncMeanMS(); got != "10.00" {
		t.Fatalf("the cell's own mean %q", got)
	}
	if got := parseLoadMetrics("").WALFsyncMeanMS(); got != "unknown" {
		t.Fatalf("no fsyncs: %q", got)
	}
}

func TestRunDirFSNamesTheFilesystem(t *testing.T) {
	for magic, want := range map[int64]string{0x01021994: "tmpfs", 0xEF53: "ext4", 0x58465342: "xfs", 0x1234: "unknown_0x1234"} {
		if got := loadFSName(magic); got != want {
			t.Errorf("%#x: %q, want %q", magic, got, want)
		}
	}
	note, err := loadNote(nil, hostFacts{RunDirFS: "ext4"})
	if err != nil || !strings.Contains(note, "run_dir_fs") || !strings.Contains(note, "ext4") {
		t.Fatalf("%q %v", note, err)
	}
}

// A p99 in a finite bucket is that bucket's upper bound; only one past the last
// finite bucket is a lower bound, and the note says which.
func TestQuantileLabelNamesABoundOrALowerBound(t *testing.T) {
	m := loadMetrics{buckets: map[float64]float64{0.001: 1, 0.5: 2, 1: 100, math.Inf(1): 100}}
	if got := m.QuantileLabel(0.99); got != "<=1000.00" {
		t.Fatalf("a finite top bucket: %q", got)
	}
	m = loadMetrics{buckets: map[float64]float64{0.001: 100, 0.5: 100, 1: 100, math.Inf(1): 100}}
	if got := m.QuantileLabel(0.99); got != "<=1.00" {
		t.Fatalf("%q", got)
	}
	m = loadMetrics{buckets: map[float64]float64{0.001: 1, 1: 1, math.Inf(1): 100}}
	if got := m.QuantileLabel(0.99); got != ">=1000.00" {
		t.Fatalf("past the top: %q", got)
	}
}

func TestAMintFaultItemKeepsItsErrorCode(t *testing.T) {
	out := api.MintResponse{Results: []api.MintItem{{Error: "broker_error"}}}
	if got := loadItemReason(out); got != "broker_error" {
		t.Fatalf("%q", got)
	}
}

// Cell f fails on a store-call p99 past the call timeout, however the note
// words it: a p99 in a finite bucket over 500 ms, or in +Inf.
func TestCellFFailsOnAP99PastTheCallTimeout(t *testing.T) {
	cell := func(buckets map[float64]float64) loadCell {
		m := loadMetrics{buckets: buckets}
		return loadCell{daemonStore: m, daemonScrapes: 2, Observed: map[string]string{"daemon_store_call_p99_ms": m.QuantileLabel(0.99)}}
	}
	fast := cell(map[float64]float64{0.005: 100, 0.25: 100, 1: 100, math.Inf(1): 100})
	if !loadNetemPass(0, fast) {
		t.Error("a p99 under the timeout failed the cell")
	}
	if loadNetemPass(1, fast) {
		t.Error("an error passed the cell")
	}
	slow := cell(map[float64]float64{0.005: 1, 0.25: 1, 1: 100, math.Inf(1): 100})
	if loadNetemPass(0, slow) {
		t.Error("a p99 in the (0.25, 1] bucket passed the cell")
	}
	inf := cell(map[float64]float64{0.005: 1, 0.25: 1, 1: 1, math.Inf(1): 100})
	if loadNetemPass(0, inf) {
		t.Error("a p99 past the last bucket passed the cell")
	}
	for _, n := range []int{0, 1} {
		unread := fast
		unread.daemonScrapes = n
		if loadNetemPass(0, unread) {
			t.Errorf("a cell with %d daemon scrapes passed on a delta nobody measured", n)
		}
	}
}

// One scrape is a point, not a change: the deltas read scrape_failed, the
// peaks (which one scrape gives) read their value.
func TestASamplerWithOneScrapeHasNoDeltas(t *testing.T) {
	s := &loadSampler{ok: 1, peakConns: 3, peakDepth: 2}
	obs := map[string]string{}
	addSamplerObserved(obs, s, s)
	if obs["spool_drops_during"] != loadScrapeFailed || obs["daemon_store_call_p99_ms"] != loadScrapeFailed ||
		obs["broker_store_call_p99_ms"] != loadScrapeFailed {
		t.Errorf("a delta from one scrape: %v", obs)
	}
	if obs["peak_port49_connections"] != "3" || obs["peak_spool_depth"] != "2" {
		t.Errorf("the peaks of one scrape: %v", obs)
	}
}

// A process whose RSS could not be read in the cell reads scrape_failed.
func TestAnUnreadableRSSReadsScrapeFailed(t *testing.T) {
	read := func(pf string) (int, error) {
		if pf == "bad" {
			return 0, errors.New("gone")
		}
		return 2048, nil
	}
	s := startLoadRSSSampler(map[string]string{"port49d": "ok", "etcd_session": "bad"}, read, time.Millisecond)
	obs := map[string]string{}
	addRSSObserved(obs, s.finish())
	if obs["peak_rss_mb_port49d"] != "2" || obs["peak_rss_mb_etcd_session"] != loadScrapeFailed {
		t.Fatalf("%v", obs)
	}
}

// The harness runs etcd as port49 ships it: its compaction and quota are the
// shipped example's, read from the file, not copied.
func TestTheHarnessEtcdRunsWithTheShippedCompactionAndQuota(t *testing.T) {
	raw, err := os.ReadFile("../../deploy/systemd/examples/etcd-1.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var shipped map[string]any
	if err := yaml.Unmarshal(raw, &shipped); err != nil {
		t.Fatal(err)
	}
	e := &regionEtcd{name: "s", bin: "/bin", client: "127.0.0.1:1", peer: "127.0.0.1:2", cluster: "s=http://127.0.0.1:2",
		data: "/d", log: "/l", pki: &regionPKI{}}
	argv := strings.Join(e.argv(), " ")
	for _, k := range []string{"auto-compaction-mode", "auto-compaction-retention", "quota-backend-bytes"} {
		want := fmt.Sprint(shipped[k])
		if want == "" || want == "<nil>" {
			t.Fatalf("the shipped example has no %s", k)
		}
		if !strings.Contains(argv, "--"+k+" "+want+" ") && !strings.HasSuffix(argv, "--"+k+" "+want) {
			t.Errorf("the harness's etcd lacks --%s %s: %s", k, want, argv)
		}
	}
}

func TestTheDBGrowthIsTheInUseChangePerMinute(t *testing.T) {
	const mb = 1 << 20
	if got := loadDBGrowthMBPerMin(100*mb, 160*mb, 10*time.Minute); got != "6.00" {
		t.Fatalf("%q", got)
	}
	if got := loadDBGrowthMBPerMin(100*mb, 100*mb, 10*time.Minute); got != "0.00" {
		t.Fatalf("%q", got)
	}
	if got := loadDBGrowthMBPerMin(100*mb, 160*mb, 0); got != "unknown" {
		t.Fatalf("%q", got)
	}
	m := parseLoadMetrics("etcd_mvcc_db_total_size_in_bytes 2097152\netcd_mvcc_db_total_size_in_use_in_bytes 1048576\n")
	if m.DBBytes != 2097152 || m.DBInUseBytes != 1048576 {
		t.Fatalf("%+v", m)
	}
}

// A cell that ends INVALID does not take the finished cells with it.
func TestTheNoteSurvivesAnInvalidCell(t *testing.T) {
	done := func(id string) loadCell {
		return loadCell{ID: id, Transport: "tcp", Rate: 170, Duration: 10 * time.Minute, Pass: true,
			Observed: map[string]string{"plays": "1"}}
	}
	cells := []loadCell{done("a"), done("b"),
		{ID: "c", Transport: "tcp", Rate: 170, Duration: time.Minute, Invalid: "etcdserver: mvcc: database space exceeded"}}
	note, err := loadNote(cells, hostFacts{})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"## Cell a", "## Cell b", "## Cell c", "**INVALID**", "database space exceeded"} {
		if !strings.Contains(note, want) {
			t.Errorf("the note lacks %q:\n%s", want, note)
		}
	}
	// A reason that could hold a credential is not printed.
	cells[2].Invalid = "bearer abc"
	note, err = loadNote(cells, hostFacts{})
	if err != nil || strings.Contains(note, "bearer") {
		t.Fatalf("%v\n%s", err, note)
	}
	if !strings.Contains(note, "INVALID") {
		t.Fatal("the withheld reason lost the verdict")
	}
}

// Compaction cannot hide the write rate: the revision counter only climbs.
func TestRevisionsPerMinuteAndTheCompactedFlag(t *testing.T) {
	if got := loadRevisionsPerMin(1000, 7000, 10*time.Minute); got != "600" {
		t.Fatalf("%q", got)
	}
	if got := loadRevisionsPerMin(1000, 7000, 0); got != "unknown" {
		t.Fatalf("%q", got)
	}
	if got := loadCompacted(100, 100); got != "false" {
		t.Fatalf("%q", got)
	}
	if got := loadCompacted(100, 5000); got != "true" {
		t.Fatalf("%q", got)
	}
	m := parseLoadMetrics("etcd_debugging_mvcc_current_revision 7000\netcd_debugging_mvcc_compact_revision 5000\n")
	if m.Revision != 7000 || m.CompactRevision != 5000 {
		t.Fatalf("%+v", m)
	}
}

// A compaction in the cell can take the in-use size down: the figure stays
// as measured and signed.
func TestTheDBGrowthKeepsItsSignWhenCompactionFreedMore(t *testing.T) {
	const mb = 1 << 20
	if got := loadDBGrowthMBPerMin(200*mb, 140*mb, 10*time.Minute); got != "-6.00" {
		t.Fatalf("%q", got)
	}
}

// The note outlives whatever ends the run: an INVALID cell, a STOP or the disk
// floor between cells, or the stopped check after the last one.
func TestTheNoteIsWrittenWhenARunEndsAnyWay(t *testing.T) {
	done := loadCell{ID: "a", Transport: "tcp", Rate: 170, Duration: 10 * time.Minute, Pass: true,
		Observed: map[string]string{"etcd_session_wal_fsync_mean_ms": "4.20"}}
	running := &loadCell{ID: "b", Transport: "tls", Rate: 170, Duration: 10 * time.Minute}
	note, err := loadPartialNote([]loadCell{done}, running, "the broker did not start", hostFacts{})
	if err != nil || !strings.Contains(note, "## Cell a") || !strings.Contains(note, "## Cell b") ||
		!strings.Contains(note, "**INVALID**") || !strings.Contains(note, "the broker did not start") ||
		!strings.Contains(note, "4.20") {
		t.Errorf("an INVALID cell: %v\n%s", err, note)
	}
	// Between cells: no cell in progress, the reason closes the note.
	note, err = loadPartialNote([]loadCell{done}, nil, "the STOP sentinel is set", hostFacts{})
	if err != nil || !strings.Contains(note, "## Cell a") || strings.Contains(note, "INVALID") ||
		!strings.Contains(note, "the STOP sentinel is set") {
		t.Errorf("a stop between cells: %v\n%s", err, note)
	}
	// After the last cell (the stopped check): the same shape.
	note, err = loadPartialNote([]loadCell{done, done}, nil, "the run was stopped", hostFacts{})
	if err != nil || strings.Count(note, "## Cell a") != 2 || !strings.Contains(note, "the run was stopped") {
		t.Errorf("a stop after the loop: %v\n%s", err, note)
	}
	// Nothing finished and nothing running: nothing to write.
	if note, err = loadPartialNote(nil, nil, "x", hostFacts{}); note != "" || err != nil {
		t.Errorf("an empty run wrote %q, %v", note, err)
	}
}

func TestTheNoteLegendNamesTheQuotaFigure(t *testing.T) {
	note, err := loadNote(nil, hostFacts{})
	if err != nil || !strings.Contains(note, "etcd_session_db_mb") || !strings.Contains(note, "understated") {
		t.Fatalf("%v\n%s", err, note)
	}
}

// PORT49_LAB_LOAD_KEEP=1 keeps the run directory and says where it is; any
// other value removes it.
func TestTheRunDirectoryIsKeptOnlyWhenAsked(t *testing.T) {
	for _, keep := range []string{"", "0", "yes"} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "broker.log"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := loadCleanRunDir(dir, keep); got != "the run directory is removed" {
			t.Errorf("keep %q: %q", keep, got)
		}
		if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("keep %q: the directory is still there (%v)", keep, err)
		}
	}
	dir := t.TempDir()
	log := filepath.Join(dir, "broker.log")
	if err := os.WriteFile(log, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := loadCleanRunDir(dir, "1"); !strings.Contains(got, dir) || !strings.Contains(got, "kept") {
		t.Errorf("keep 1: %q", got)
	}
	if _, err := os.Stat(log); err != nil {
		t.Errorf("keep 1: the log is gone: %v", err)
	}
}

// A scrape endpoint that answers 500 is a failed scrape, not an empty one: its
// body parses as zero metrics, and the cell must read scrape_failed, not 0.
func TestASamplerThatNeverGotAScrapeReadsScrapeFailed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")
	if _, err := loadScrape(addr); err == nil {
		t.Fatal("a 500 was read as metrics")
	}
	dsam, bsam := startLoadSampler(addr).finish(), startLoadSampler(addr).finish()
	if dsam.ok != 0 || bsam.ok != 0 {
		t.Fatalf("scrapes counted against a 500: %d, %d", dsam.ok, bsam.ok)
	}
	obs := map[string]string{}
	addSamplerObserved(obs, dsam, bsam)
	for _, k := range []string{"peak_port49_connections", "peak_spool_depth", "spool_drops_during",
		"daemon_store_call_p99_ms", "broker_store_call_p99_ms"} {
		if obs[k] != loadScrapeFailed {
			t.Errorf("%s = %q, want %s", k, obs[k], loadScrapeFailed)
		}
	}
}

// With at least one scrape the peaks are numbers, a real 0 among them.
func TestASamplerThatScrapedReadsItsPeaks(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "port49_accounting_spool_depth 0\n")
	}))
	defer srv.Close()
	s := startLoadSampler(strings.TrimPrefix(srv.URL, "http://")).finish()
	obs := map[string]string{}
	addSamplerObserved(obs, s, s)
	if s.ok == 0 || obs["peak_spool_depth"] != "0" {
		t.Fatalf("ok %d, peak_spool_depth %q", s.ok, obs["peak_spool_depth"])
	}
}

// The scrape client keeps no connection alive: a scrape after a restart reads
// the new process.
func TestTheScrapeClientKeepsNoConnectionAlive(t *testing.T) {
	var conns atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "port49_accounting_spool_depth 1\n")
	}))
	srv.Config.ConnState = func(_ net.Conn, st http.ConnState) {
		if st == http.StateNew {
			conns.Add(1)
		}
	}
	srv.Start()
	defer srv.Close()
	for i := 0; i < 3; i++ {
		if _, err := loadScrape(strings.TrimPrefix(srv.URL, "http://")); err != nil {
			t.Fatal(err)
		}
	}
	if conns.Load() != 3 {
		t.Fatalf("three scrapes used %d connections", conns.Load())
	}
}

// A cell's RSS peak is its own: the second cell, run after a heavy first, reads
// its own smaller peak, not the first's high-water mark.
func TestThePerCellRSSPeakResetsBetweenCells(t *testing.T) {
	var kb atomic.Int64
	read := func(string) (int, error) { return int(kb.Load()), nil }
	pids := map[string]string{"port49d": "unused"}
	kb.Store(1000)
	a := startLoadRSSSampler(pids, read, time.Millisecond)
	kb.Store(9000)
	time.Sleep(20 * time.Millisecond)
	kb.Store(2000)
	first := a.finish()
	if first["port49d"] != 9000 {
		t.Fatalf("cell one's peak %d, want 9000", first["port49d"])
	}
	kb.Store(1500)
	b := startLoadRSSSampler(pids, read, time.Millisecond)
	time.Sleep(10 * time.Millisecond)
	if second := b.finish(); second["port49d"] != 1500 {
		t.Fatalf("cell two's peak %d, want 1500 (cell one's 9000 carried over)", second["port49d"])
	}
}

// The etcd metrics a cell now reports are read by the names v3.6.15 exposes.
func TestTheEtcdCommitAndSlowApplyMetricsAreParsed(t *testing.T) {
	text := `etcd_disk_backend_commit_duration_seconds_bucket{le="0.001"} 0
etcd_disk_backend_commit_duration_seconds_bucket{le="0.002"} 90
etcd_disk_backend_commit_duration_seconds_bucket{le="0.004"} 98
etcd_disk_backend_commit_duration_seconds_bucket{le="0.008"} 100
etcd_disk_backend_commit_duration_seconds_bucket{le="+Inf"} 100
etcd_server_slow_apply_total 7
`
	before := parseLoadMetrics("etcd_server_slow_apply_total 2\n")
	m := parseLoadMetrics(text).Sub(before)
	if m.SlowApply != 5 {
		t.Fatalf("slow apply delta %v, want 5", m.SlowApply)
	}
	if got := m.BackendCommitP99(); got != "<=8.00" && got != "<=8" {
		t.Fatalf("backend commit p99 %q", got)
	}
}

func storeCalls(le005, le1, inf, drops float64) loadMetrics {
	return loadMetrics{SpoolDrops: drops, buckets: map[float64]float64{0.005: le005, 1: le1, math.Inf(1): inf}}
}

// port49d starts its registry over at every run, so a delta of the last scrape
// less the first goes negative across a restart. The sum of the positive
// increases (Prometheus increase()) does not, and a reset is counted.
func TestDeltasSurviveARegistryReset(t *testing.T) {
	s := &loadSampler{}
	s.observe(storeCalls(10, 10, 10, 1)) // baseline
	s.observe(storeCalls(30, 30, 30, 3)) // +20 calls, +2 drops
	s.observe(storeCalls(4, 5, 5, 0))    // the run restarted: 5 calls and no drops since
	s.observe(storeCalls(9, 12, 12, 1))  // +7 calls, +1 drop
	d := s.delta()
	if got := d.buckets[math.Inf(1)]; got != 32 {
		t.Errorf("store calls over the cell: %v, want 20+5+7 = 32", got)
	}
	if d.SpoolDrops != 3 {
		t.Errorf("drops over the cell: %v, want 2+0+1 = 3", d.SpoolDrops)
	}
	if s.restarts != 1 {
		t.Errorf("restarts %d, want 1", s.restarts)
	}
	obs := map[string]string{}
	addSamplerObserved(obs, s, s)
	if obs["daemon_run_restarts"] != "1" || obs["spool_drops_during"] != "3" {
		t.Errorf("%v", obs)
	}
	if obs["daemon_store_call_p99_ms"] == "<=0.00" || strings.HasPrefix(obs["daemon_store_call_p99_ms"], "-") {
		t.Errorf("p99 %q", obs["daemon_store_call_p99_ms"])
	}
}

// With no reset the delta is what it was: last less first.
func TestDeltasWithoutAResetAreLastLessFirst(t *testing.T) {
	s := &loadSampler{}
	s.observe(storeCalls(10, 10, 10, 1))
	s.observe(storeCalls(30, 30, 30, 3))
	s.observe(storeCalls(30, 30, 30, 3))
	if d := s.delta(); d.buckets[math.Inf(1)] != 20 || d.SpoolDrops != 2 || s.restarts != 0 {
		t.Errorf("%v %v %d", d.buckets, d.SpoolDrops, s.restarts)
	}
}

// A fake /sys with the run directory's device a partition of an NVMe drive.
func fakeSys(t *testing.T, model string) (sys string, major, minor uint32) {
	t.Helper()
	sys = t.TempDir()
	disk := filepath.Join(sys, "devices", "pci0", "nvme", "nvme0", "nvme0n1")
	part := filepath.Join(disk, "nvme0n1p2")
	for _, d := range []string{filepath.Join(disk, "device"), part, filepath.Join(sys, "dev", "block")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(disk, "device", "model"), []byte(model+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(part, "partition"), []byte("2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(part, filepath.Join(sys, "dev", "block", "259:2")); err != nil {
		t.Fatal(err)
	}
	return sys, 259, 2
}

// The disk's model is read for the run directory's device, through a partition.
func TestTheDiskModelIsReadThroughAPartition(t *testing.T) {
	sys, maj, min := fakeSys(t, "CT1000P3PSSD8")
	if got := loadDiskModel(sys, maj, min); got != "CT1000P3PSSD8" {
		t.Fatalf("%q", got)
	}
	if got := loadDiskModel(sys, 8, 1); got != "unknown" {
		t.Fatalf("a device with no sysfs entry: %q, want unknown", got)
	}
}

// A device-mapper device is resolved through its first slave.
func TestTheDiskModelIsReadThroughADeviceMapper(t *testing.T) {
	sys, _, _ := fakeSys(t, "SAMSUNG MZVL21T0")
	dm := filepath.Join(sys, "devices", "virtual", "block", "dm-0")
	if err := os.MkdirAll(filepath.Join(dm, "slaves"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(sys, "devices", "pci0", "nvme", "nvme0", "nvme0n1", "nvme0n1p2"),
		filepath.Join(dm, "slaves", "nvme0n1p2")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(dm, filepath.Join(sys, "dev", "block", "253:0")); err != nil {
		t.Fatal(err)
	}
	if got := loadDiskModel(sys, 253, 0); got != "SAMSUNG MZVL21T0" {
		t.Fatalf("%q", got)
	}
}

func TestTheStorageFactNamesWhatTheSessionEtcdRunsOn(t *testing.T) {
	if got := loadStorageFact(true, hostFacts{}); got != "ram (/dev/shm): not a deployable shape; port49's own ceiling" {
		t.Fatalf("%q", got)
	}
	if got := loadStorageFact(false, hostFacts{DiskModel: "CT1000P3PSSD8", RunDirFS: "ext4"}); got != "CT1000P3PSSD8, ext4" {
		t.Fatalf("%q", got)
	}
	if got := loadStorageFact(false, hostFacts{RunDirFS: "ext4"}); got != "unknown, ext4" {
		t.Fatalf("%q", got)
	}
}

// The note says which storage it measured right under its title, so a RAM run
// cannot be mistaken for a disk run; the WAL fsync of a RAM run is n/a.
func TestTheNoteSaysWhichStorageItMeasured(t *testing.T) {
	ram, err := loadNote(nil, hostFacts{SessionStorage: loadStorageFact(true, hostFacts{}), InRAM: true})
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(ram, "\n")
	if !strings.Contains(lines[0], "etcd in RAM") || !strings.Contains(lines[2], "session_etcd_storage") ||
		!strings.Contains(lines[2], "not a deployable shape") {
		t.Fatalf("the head of a RAM note:\n%s", strings.Join(lines[:4], "\n"))
	}
	disk, err := loadNote(nil, hostFacts{SessionStorage: "CT1000P3PSSD8, ext4"})
	if err != nil {
		t.Fatal(err)
	}
	dl := strings.Split(disk, "\n")
	if strings.Contains(dl[0], "RAM") || !strings.Contains(dl[2], "CT1000P3PSSD8, ext4") {
		t.Fatalf("the head of a disk note:\n%s", strings.Join(dl[:4], "\n"))
	}
	if got := loadWALMean(true, "4.20"); got != "n/a (ram)" {
		t.Fatalf("%q", got)
	}
	if got := loadWALMean(false, "4.20"); got != "4.20" {
		t.Fatalf("%q", got)
	}
}

// The RAM run and the disk run write different files.
func TestTheRAMRunWritesItsOwnNoteFile(t *testing.T) {
	if got := loadNoteName("beehive", false); got != "load-beehive.md" {
		t.Fatalf("%q", got)
	}
	if got := loadNoteName("beehive", true); got != "load-beehive-ram.md" {
		t.Fatalf("%q", got)
	}
}

// Only the session etcd's data goes under /dev/shm, in a 0700 directory.
func TestOnlyTheSessionEtcdDataGoesToRAM(t *testing.T) {
	run, shm := t.TempDir(), t.TempDir()
	if got, err := loadSessionDataDir(run, shm, false); err != nil || got != filepath.Join(run, "s.etcd") {
		t.Fatalf("disk: %q %v", got, err)
	}
	got, err := loadSessionDataDir(run, shm, true)
	if err != nil || !strings.HasPrefix(got, shm+string(filepath.Separator)) || filepath.Base(got) != "s.etcd" {
		t.Fatalf("ram: %q %v", got, err)
	}
	st, err := os.Stat(filepath.Dir(got))
	if err != nil || st.Mode().Perm() != 0o700 {
		t.Fatalf("the directory: %v %v", st, err)
	}
	if msg := loadCleanRunDir(filepath.Dir(got), ""); !strings.Contains(msg, "removed") {
		t.Fatal(msg)
	}
	if _, err := os.Stat(filepath.Dir(got)); !os.IsNotExist(err) {
		t.Fatal("the shm directory outlived cleanup")
	}
}

// A RAM run killed before its cleanup leaves the session etcd's data in
// /dev/shm; the next RAM run is INVALID and names it, and does not remove it
// (a kept directory is evidence).
func TestARamRunRefusesALeftoverSessionDirectory(t *testing.T) {
	shm := t.TempDir()
	free := func(string) (uint64, error) { return 16 << 30, nil }
	if err := loadShmCheck(shm, 8<<30, free); err != nil {
		t.Fatalf("an empty shm: %v", err)
	}
	left := filepath.Join(shm, "p49load-s123")
	if err := os.Mkdir(left, 0o700); err != nil {
		t.Fatal(err)
	}
	err := loadShmCheck(shm, 8<<30, free)
	if err == nil || !strings.Contains(err.Error(), left) || !strings.Contains(err.Error(), "remove") {
		t.Fatalf("a leftover directory: %v", err)
	}
	if _, serr := os.Stat(left); serr != nil {
		t.Fatal("the check removed the evidence")
	}
}

// Too little free RAM for the quota is INVALID before the run, not an ENOSPC mid-cell.
func TestARamRunNeedsTheQuotaFree(t *testing.T) {
	short := func(string) (uint64, error) { return 4 << 30, nil }
	err := loadShmCheck(t.TempDir(), 8<<30, short)
	if err == nil || !strings.Contains(err.Error(), "free") {
		t.Fatalf("%v", err)
	}
	broken := func(string) (uint64, error) { return 0, errors.New("statfs failed") }
	if err := loadShmCheck(t.TempDir(), 8<<30, broken); err == nil {
		t.Fatal("an unreadable /dev/shm passed")
	}
}

// An LV across two drives, or an md RAID, does not name one drive as the only one.
func TestTheDiskModelSaysWhenSeveralDevicesBackIt(t *testing.T) {
	sys, _, _ := fakeSys(t, "CT1000P3PSSD8")
	dm := filepath.Join(sys, "devices", "virtual", "block", "dm-1")
	if err := os.MkdirAll(filepath.Join(dm, "slaves"), 0o755); err != nil {
		t.Fatal(err)
	}
	part := filepath.Join(sys, "devices", "pci0", "nvme", "nvme0", "nvme0n1", "nvme0n1p2")
	for _, n := range []string{"a", "b"} {
		if err := os.Symlink(part, filepath.Join(dm, "slaves", n)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(dm, filepath.Join(sys, "dev", "block", "253:1")); err != nil {
		t.Fatal(err)
	}
	if got := loadDiskModel(sys, 253, 1); got != "CT1000P3PSSD8 (+1 more)" {
		t.Fatalf("%q", got)
	}
}

// A cell quoted alone keeps its label; and a sampler with under two scrapes
// reads daemon_run_restarts scrape_failed.
func TestACellHeadingCarriesTheRAMLabelAndRestartsNeedTwoScrapes(t *testing.T) {
	note, err := loadNote([]loadCell{{ID: "a", Transport: "tcp", Observed: map[string]string{}}},
		hostFacts{InRAM: true, SessionStorage: "ram"})
	if err != nil || !strings.Contains(note, "## Cell a (etcd in RAM)") {
		t.Fatalf("%v\n%s", err, note)
	}
	obs := map[string]string{}
	addSamplerObserved(obs, &loadSampler{ok: 1}, &loadSampler{ok: 1})
	if obs["daemon_run_restarts"] != loadScrapeFailed {
		t.Fatalf("%q", obs["daemon_run_restarts"])
	}
}
