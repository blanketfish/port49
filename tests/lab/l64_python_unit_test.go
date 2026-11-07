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
	calls := callArgs(l64DriverScript, "port49.Agent(")
	if len(calls) == 0 {
		t.Fatal("the driver builds no port49.Agent")
	}
	for _, call := range calls {
		for _, kw := range topLevelKeywords(call) {
			if !slices.Contains(params, kw) {
				t.Errorf("the driver passes %s= to port49.Agent, which takes %v", kw, params)
			}
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
		{"a policy denial", l64PyRun{parsed: true, d: l64Driver{Outcome: "port49_error", ErrorClass: "Denied"}}, false},
		{"the broker refused", l64PyRun{parsed: true, d: l64Driver{Outcome: "port49_error", ErrorClass: "BrokerRefused"}}, false},
		{"a plain port49 error", l64PyRun{parsed: true, d: l64Driver{Outcome: "port49_error", ErrorClass: "Port49Error"}}, false},
		{"a device host key refusal", l64PyRun{parsed: true, d: l64Driver{Outcome: "port49_error", ErrorClass: "HostKeyError", Code: "host_key_changed"}}, false},
		{"no agent", l64PyRun{parsed: true, d: l64Driver{Outcome: "port49_error", ErrorClass: "NoAgent", Code: "no_agent"}}, true},
		{"port49 not installed", l64PyRun{parsed: true, d: l64Driver{Outcome: "port49_error", ErrorClass: "NotInstalled"}}, true},
		{"session over", l64PyRun{parsed: true, d: l64Driver{Outcome: "port49_error", ErrorClass: "SessionOver"}}, true},
		{"temporary", l64PyRun{parsed: true, d: l64Driver{Outcome: "port49_error", ErrorClass: "Temporary"}}, true},
		{"an OSError", l64PyRun{parsed: true, d: l64Driver{Outcome: "error", ErrorClass: "OSError"}}, true},
		{"a ValueError", l64PyRun{parsed: true, d: l64Driver{Outcome: "error", ErrorClass: "ValueError"}}, true},
		{"a RuntimeError", l64PyRun{parsed: true, d: l64Driver{Outcome: "error", ErrorClass: "RuntimeError"}}, true},
		{"an unreadable ssh_config", l64PyRun{parsed: true, d: l64Driver{Outcome: "error", ErrorClass: "FileNotFoundError"}}, true},
		{"the library's own config codes", l64PyRun{parsed: true, d: l64Driver{Outcome: "port49_error", ErrorClass: "HostKeyError", Code: "ssh_config_unread"}}, true},
		{"known_hosts unread", l64PyRun{parsed: true, d: l64Driver{Outcome: "port49_error", ErrorClass: "HostKeyError", Code: "known_hosts_unread"}}, true},
		{"host key uncheckable", l64PyRun{parsed: true, d: l64Driver{Outcome: "port49_error", ErrorClass: "HostKeyError", Code: "host_key_uncheckable"}}, true},
		{"host keys not kept", l64PyRun{parsed: true, d: l64Driver{Outcome: "port49_error", ErrorClass: "HostKeyError", Code: "host_keys_not_kept"}}, true},
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

// callArgs returns the argument text of every call that starts with open
// (for example "port49.Agent("), up to its matching close paren: a nested call
// or a paren inside a string does not end it.
func callArgs(text, open string) []string {
	var out []string
	for rest := text; ; {
		i := strings.Index(rest, open)
		if i < 0 {
			return out
		}
		rest = rest[i+len(open):]
		depth, quote := 1, byte(0)
		end := -1
		for j := 0; j < len(rest) && end < 0; j++ {
			c := rest[j]
			switch {
			case quote != 0:
				if c == quote {
					quote = 0
				}
			case c == '\'' || c == '"':
				quote = c
			case c == '(':
				depth++
			case c == ')':
				if depth--; depth == 0 {
					end = j
				}
			}
		}
		if end < 0 {
			return out
		}
		out = append(out, rest[:end])
		rest = rest[end:]
	}
}

// topLevelKeywords are the key= names of args that are not inside a nested call, a list or a string.
func topLevelKeywords(args string) []string {
	var keys []string
	depth, quote, start := 0, byte(0), 0
	flush := func(end int) {
		if m := regexp.MustCompile(`^\s*([a-z_0-9]+)=`).FindStringSubmatch(args[start:end]); m != nil {
			keys = append(keys, m[1])
		}
	}
	for j := 0; j < len(args); j++ {
		c := args[j]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		case c == '(' || c == '[' || c == '{':
			depth++
		case c == ')' || c == ']' || c == '}':
			depth--
		case c == ',' && depth == 0:
			flush(j)
			start = j + 1
		}
	}
	flush(len(args))
	return keys
}

func TestCallArgsAndKeywordsHandleANestedCall(t *testing.T) {
	text := `x = port49.Agent(port49=os.environ.get("P49_BIN", default=("a)", 1)), socket=s, timeout=90)
y = port49.Agent(attempts=2)`
	calls := callArgs(text, "port49.Agent(")
	if len(calls) != 2 {
		t.Fatalf("calls = %q, want 2", calls)
	}
	if got := topLevelKeywords(calls[0]); !slices.Equal(got, []string{"port49", "socket", "timeout"}) {
		t.Errorf("keywords = %v: a nested call's default= is not the call's, and the call does not stop at the first )", got)
	}
	if got := topLevelKeywords(calls[1]); !slices.Equal(got, []string{"attempts"}) {
		t.Errorf("second call keywords = %v", got)
	}
	lk := `{{ lookup('port49.client.token', p49_name, field=x|default('a', b=1), port49=p49_bin) }}`
	if got := topLevelKeywords(callArgs(lk, "lookup(")[0]); !slices.Equal(got, []string{"field", "port49"}) {
		t.Errorf("lookup keywords = %v", got)
	}
}

// L65 (c) and (d) pin the refusal's code: every platform measured host_key_changed (the notes before
// 719721c7), and a code the library raises before it contacts the device must never pass as the refusal.
func TestL65ReplacedKeyCellsPinTheirCode(t *testing.T) {
	b, err := os.ReadFile("l64_l65_test.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), `l64GradePyRefusal(r.d, "",`) {
		t.Error(`a cell grades its refusal with wantCode "": c and d must pin l64WantChanged`)
	}
	if n := strings.Count(string(b), "l64GradePyRefusal(r.d, l64WantChanged,"); n != 2 {
		t.Errorf("%d cells pin l64WantChanged, want 2 (L65c and L65d)", n)
	}
	d := l64Driver{Outcome: "port49_error", ErrorClass: "HostKeyError", Code: "host_keys_not_kept"}
	if ok, _ := l64GradePyRefusal(d, l64WantChanged, 0, nil); ok {
		t.Error("host_keys_not_kept passed as a replaced key's refusal")
	}
	d.Code = "host_key_changed"
	if ok, why := l64GradePyRefusal(d, l64WantChanged, 0, nil); !ok {
		t.Errorf("host_key_changed: %s", why)
	}
}
