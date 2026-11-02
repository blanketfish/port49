//go:build lab

package lab

import (
	"net/netip"
	"strings"
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
