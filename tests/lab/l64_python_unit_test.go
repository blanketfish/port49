//go:build lab

package lab

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

// L65's driver builds port49.Agent from the tree's library. d97c52c6 removed
// its socket parameter, and the driver kept passing it: every L65 cell on
// 2026-11-06 failed with a TypeError before it reached a device.
func TestL65DriverPassesOnlyParametersAgentTakes(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "clients", "python", "src", "port49", "client.py"))
	if err != nil {
		t.Fatal(err)
	}
	sig := regexp.MustCompile(`(?s)class Agent:.*?def __init__\(self([^)]*)\)`).FindStringSubmatch(string(b))
	if sig == nil {
		t.Fatal("Agent.__init__ not found in client.py")
	}
	var params []string
	for _, p := range strings.Split(sig[1], ",") {
		if name, _, _ := strings.Cut(strings.TrimSpace(p), "="); name != "" {
			params = append(params, name)
		}
	}
	if !slices.Contains(params, "port49") {
		t.Fatalf("read Agent parameters %v", params)
	}
	call := regexp.MustCompile(`port49\.Agent\(([^)]*)\)`).FindStringSubmatch(l64DriverScript)
	if call == nil {
		t.Fatal("the driver builds no port49.Agent")
	}
	for _, kw := range regexp.MustCompile(`([a-z_0-9]+)=`).FindAllStringSubmatch(call[1], -1) {
		if !slices.Contains(params, kw[1]) {
			t.Errorf("the driver passes %s= to port49.Agent, which takes %v", kw[1], params)
		}
	}
}

// The library finds a non-default agent through PORT49_TEST_AGENT_SOCKET
// alone, which its CLI children inherit (d97c52c6).
func TestL65PythonEnvPointsTheCLIAtTheRunsAgent(t *testing.T) {
	e := &l64Env{home: "/w/home", sock: "/w/a/agent.sock", cfgPath: "/w/ssh_config", node: "leaf1"}
	if !slices.Contains(e.pythonEnv(), "PORT49_TEST_AGENT_SOCKET=/w/a/agent.sock") {
		t.Error("the driver's env does not name the run's agent socket")
	}
}

// A driver that never reached the Agent call or the device is a harness
// error, not a measurement: the 2026-11-06 L65 cells recorded a TypeError for
// a removed parameter as FAIL rows, and the run still exited 0.
func TestL65DriverFaultsAreHarnessErrors(t *testing.T) {
	for _, c := range []struct {
		name  string
		r     l64PyRun
		fault bool
	}{
		{"import error", l64PyRun{parsed: true, d: l64Driver{Outcome: "import_error", ErrorClass: "ModuleNotFoundError"}}, true},
		{"TypeError", l64PyRun{parsed: true, d: l64Driver{Outcome: "error", ErrorClass: "TypeError"}}, true},
		{"AttributeError", l64PyRun{parsed: true, d: l64Driver{Outcome: "error", ErrorClass: "AttributeError"}}, true},
		{"no result line", l64PyRun{exit: 1}, true},
		{"connected", l64PyRun{parsed: true, d: l64Driver{Outcome: "connected"}}, false},
		{"the host key the device presented was refused", l64PyRun{parsed: true, d: l64Driver{Outcome: "error", ErrorClass: "BadHostKeyException"}}, false},
		{"a port49 refusal", l64PyRun{parsed: true, d: l64Driver{Outcome: "port49_error", ErrorClass: "Port49Error"}}, false},
	} {
		if got := l64DriverFault(c.r) != ""; got != c.fault {
			t.Errorf("%s: fault = %v, want %v", c.name, got, c.fault)
		}
	}
}

func TestL65DriverFaultMakesTheCellINVALID(t *testing.T) {
	e := &l64Env{t: t, l: &lab{}, controlOK: true}
	ok := e.cell("L65e1", 5*time.Second, func(ctx context.Context) (bool, string) {
		e.noteDriver(l64PyRun{parsed: true, d: l64Driver{Outcome: "error", ErrorClass: "TypeError"}})
		return false, "the driver said TypeError"
	})
	if ok || len(e.results) != 1 || e.results[0].outcome != "INVALID" {
		t.Fatalf("results = %+v, want one INVALID cell", e.results)
	}
	if !strings.Contains(e.results[0].observation, "TypeError") {
		t.Errorf("the INVALID row does not name the driver's error: %q", e.results[0].observation)
	}
	// A driver that connected leaves the cell's own verdict alone.
	e = &l64Env{t: t, l: &lab{}, controlOK: true}
	e.cell("L65e1", 5*time.Second, func(ctx context.Context) (bool, string) {
		e.noteDriver(l64PyRun{parsed: true, d: l64Driver{Outcome: "connected"}})
		return true, "ok"
	})
	if e.results[0].outcome != "PASS" {
		t.Errorf("a connected driver: %+v", e.results[0])
	}
}

// An entry with an INVALID cell writes no note and fails the test, as L66's does.
func TestL64WritableRefusesAnEntryWithAnINVALIDCell(t *testing.T) {
	rs := []l64Result{{id: "L64a", outcome: "PASS"}, {id: "L65e1", outcome: "INVALID"}, {id: "L65a", outcome: "FAIL"}}
	if ok, why := l64Writable(rs, "L65"); ok || !strings.Contains(why, "L65e1") {
		t.Errorf("L65 with an INVALID cell: ok=%v why=%q", ok, why)
	}
	if ok, why := l64Writable(rs, "L64"); !ok {
		t.Errorf("L64 has no INVALID cell: %q", why)
	}
	if ok, _ := l64Writable(nil, "L64"); ok {
		t.Error("no cell ran, so nothing to write")
	}
}

// python() and l64WriteNotes are device-only; this holds their two calls.
func TestL65RunsNoteTheDriverAndTheNotesAreGated(t *testing.T) {
	b, err := os.ReadFile("l64_l65_test.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	body := func(sig string) string {
		i := strings.Index(s, sig)
		if i < 0 {
			t.Fatalf("%s not found", sig)
		}
		out := s[i:]
		if j := strings.Index(out, "\n}\n"); j >= 0 {
			out = out[:j]
		}
		return out
	}
	if !strings.Contains(body("func (e *l64Env) python("), "e.noteDriver(r)") {
		t.Error("python() does not pass its run to noteDriver, so a harness error is a FAIL row")
	}
	if !strings.Contains(body("func l64WriteNotes("), "l64Writable(e.results, entry)") {
		t.Error("l64WriteNotes writes notes without asking l64Writable")
	}
}
