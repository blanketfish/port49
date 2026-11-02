//go:build lab

package lab

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/blanketfish/port49/internal/admission"
	"github.com/blanketfish/port49/internal/devicemock"
	"github.com/blanketfish/port49/internal/policy"
)

// TestLoadCellSelection pins PORT49_LAB_LOAD_CELLS: empty runs every cell, a
// list runs those in the harness's order, an unknown or repeated ID is refused.
func TestLoadCellSelection(t *testing.T) {
	all := []string{"a", "b", "c", "d", "e", "f"}
	for in, want := range map[string][]string{
		"":            all,
		"  ":          all,
		"a":           {"a"},
		"c,a":         {"a", "c"},
		" b , f ":     {"b", "f"},
		"a,b,c,d,e,f": all,
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
