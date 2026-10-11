//go:build lab

package lab

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/tests/lab/labcreds"
)

// The leak check covers every daemon generation of the run, not the last one,
// and never prints the matched value.
func TestRunSecretsOutliveAReload(t *testing.T) {
	const first, second = "tok-first-generation-aaaaaaaa", "tok-second-generation-bbbbbbb"
	secrets := runSecrets([]labcreds.SeedToken{{Login: first}, {Login: second, Enable: "en-bbbbbbbbbbbbbbbbbb"}})
	err := leakIn("a note quoting "+first+" by mistake", secrets)
	if err == nil {
		t.Fatal("a first-generation token in a note was not caught")
	}
	if strings.Contains(err.Error(), first) {
		t.Errorf("the error prints the value: %v", err)
	}
	if leakIn("a clean note", secrets) != nil {
		t.Error("a clean note was flagged")
	}
	if leakIn("the password "+breakglassPassword, secrets) == nil {
		t.Error("the break-glass password was not caught")
	}
}

// A closed session is a deny only while the device is shown alive: a reboot
// between the reads turns W's closed-channel refusal into "not observed".
func TestXnmAliveAndSettle(t *testing.T) {
	const up = "System booted: 2026-10-11 10:00:00 UTC (00:20:00 ago)\n"
	const rebooted = "System booted: 2026-10-11 10:30:00 UTC (00:01:00 ago)\n"
	mk := func() map[string]l26cRun {
		return map[string]l26cRun{
			"W": jsdRun(map[string]string{"xnm-ssh": "hello", xnmRPCKey: xnmClosed}),
			"C": jsdRun(map[string]string{"xnm-ssh": "hello", xnmRPCKey: "result"}),
		}
	}
	alive, _ := xnmAlive(up, up, "result", 5*time.Minute)
	runs := mk()
	xnmSettle(runs, alive)
	if !alive || runs["W"].cells[xnmRPCKey] != xnmClosed {
		t.Errorf("a stable device: alive %v, W %q", alive, runs["W"].cells[xnmRPCKey])
	}
	r0, _ := entryVerdict(runs, []string{"W"}, "C", nil, xnmProbes)
	if g := xnmGate(r0, "result"); g != "closed" {
		t.Errorf("a closed session on a live device: %q", g)
	}
	alive, why := xnmAlive(up, rebooted, "result", 5*time.Minute)
	runs = mk()
	xnmSettle(runs, alive)
	if alive || runs["W"].cells[xnmRPCKey] != "not observed" {
		t.Errorf("a rebooted device (%s): alive %v, W %v", why, alive, runs["W"].cells)
	}
	r, _ := entryVerdict(runs, []string{"W"}, "C", nil, xnmProbes)
	if g := xnmGate(r, "result"); g == "closed" {
		t.Errorf("the gate closed on a closed session across a reboot: %q", g)
	}
	// No result for the control, or an unreadable boot time, is not alive either.
	if a, _ := xnmAlive(up, up, "refused", time.Minute); a {
		t.Error("alive without a control result")
	}
	if a, _ := xnmAlive("", up, "result", time.Minute); a {
		t.Error("alive without a readable boot time")
	}
}

// These run without a device: the entry cells' isolation verdict, and the
// op script's and scp's cells.

func TestEntryVerdict(t *testing.T) {
	const p830, xml, p22 = "port 830", "entry: xml-mode netconf need-trailer", "port 22 subsystem"
	runs := map[string]l26cRun{
		"W": jsdRun(map[string]string{p830: "refused", xml: "refused", p22: "refused"}),
		"V": jsdRun(map[string]string{p830: "hello", xml: "hello", p22: "refused"}),
		"C": jsdRun(map[string]string{p830: "hello", xml: "hello", p22: "refused"}),
	}
	readings, unisolated := entryVerdict(runs, []string{"W"}, "C", []string{p830, xml}, []string{p830, xml, p22})
	if readings["W "+p830] != "deny" || readings["W "+xml] != "deny" {
		t.Errorf("W refused where C reached: %v", readings)
	}
	// Port 22 runs nowhere: C refused it too, so W's refusal is no deny, and
	// it is not canonical, so nothing fails.
	if readings["W "+p22] != "runs nowhere" || len(unisolated) != 0 {
		t.Errorf("port 22: %v %v", readings, unisolated)
	}
	// A canonical probe C did not reach fails the run.
	runs["C"] = jsdRun(map[string]string{p830: "refused", xml: "hello"})
	if _, unisolated = entryVerdict(runs, []string{"W"}, "C", []string{p830, xml}, []string{p830, xml}); len(unisolated) != 1 {
		t.Errorf("C refused port 830: %v", unisolated)
	}
	// W reaching is "reached", the deny's failure, whatever C did.
	runs["W"] = jsdRun(map[string]string{p830: "hello"})
	if r, _ := entryVerdict(runs, []string{"W"}, "C", nil, []string{p830}); r["W "+p830] != "reached" {
		t.Errorf("W reached: %v", r)
	}
	// A token the device refused, or a cell not observed, says nothing about
	// the deny: never "deny", even where C reached (G2 must not drop a
	// service on a spent token).
	runs["C"] = jsdRun(map[string]string{p830: "hello"})
	for _, cell := range []string{"login refused", "not observed"} {
		runs["W"] = jsdRun(map[string]string{p830: cell})
		if r, _ := entryVerdict(runs, []string{"W"}, "C", nil, []string{p830}); r["W "+p830] != "not observed" {
			t.Errorf("W %s: %v", cell, r)
		}
	}
}

func TestOpScriptCell(t *testing.T) {
	for _, c := range []struct{ out, want string }{
		{"P49OP-VERSION srx1\nP49OP-CONFIG 1\n", "version and configuration"},
		{"P49OP-VERSION srx1\nP49OP-CONFIG 0\n", "version only"},
		{"P49OP-VERSION \nP49OP-CONFIG 0\n", "not observed"}, // jcs:invoke answered nothing
		{"P49OP-VERSION \nP49OP-CONFIG 0\nerror: permission denied\n", "refused"},
		{"error: permission denied\n", "refused"},
		{"syntax error, expecting <command>\n", "refused"},
		{"error: could not open /var/tmp/x.slax\n", "not observed"},
		{"", "not observed"},
	} {
		if got := opScriptCell(c.out); got != c.want {
			t.Errorf("%q: got %q, want %q", c.out, got, c.want)
		}
	}
}

func TestScpCell(t *testing.T) {
	for _, c := range []struct {
		n    int64
		err  error
		want string
	}{
		{4096, nil, "file read"},
		{0, errors.New("scp: permission denied"), "refused"},
		{0, fmt.Errorf("wrapped: %w", scpRefusal{"no such file"}), "refused"},
		{0, errors.New("scp: EOF "), "not observed"},
		{0, errors.New(`scp: "garbage"`), "not observed"},
		{0, nil, "not observed"},
	} {
		if got := scpCell(c.n, c.err); got != c.want {
			t.Errorf("%d %v: got %q, want %q", c.n, c.err, got, c.want)
		}
	}
}

func TestRestCell(t *testing.T) {
	for _, c := range []struct {
		status int
		body   string
		want   string
	}{
		{200, "<configuration><system><host-name>x</host-name></system></configuration>", "result"},
		{401, "", "login refused"},
		{401, "authentication failed", "login refused"},
		{403, "", "refused"},
		{200, "<rpc-error><error-severity>error</error-severity></rpc-error>", "refused"},
		{200, "<rpc-error><error-severity>warning</error-severity></rpc-error>", "not observed"},
		{500, "permission denied", "refused"},
		{500, "", "not observed"},
		{404, "not found", "not observed"},
		{200, "<configuration/>", "not observed"},
	} {
		if got := restCell(c.status, c.body); got != c.want {
			t.Errorf("%d %q: got %q, want %q", c.status, c.body, got, c.want)
		}
	}
}

func TestEntryErrRefusal(t *testing.T) {
	for _, c := range []struct {
		err  string
		want bool
	}{
		{`u: the device sent no NETCONF hello: the NETCONF channel closed: EOF (sent "error: unknown command: xml-mode")`, true},
		{"request the netconf subsystem on port 830: ssh: subsystem request failed", true},
		{"u: the device sent no NETCONF hello: the NETCONF channel closed: EOF ()", false},
		{"no NETCONF end-of-message marker within 45s", false},
		{"open session: ssh: unexpected packet", false},
	} {
		if got := entryErrRefusal(errors.New(c.err)); got != c.want {
			t.Errorf("%q: got %v, want %v", c.err, got, c.want)
		}
	}
}

func TestDialCell(t *testing.T) {
	if got := dialCell(errors.New("ssh: unable to authenticate")); got != "login refused" {
		t.Errorf("auth failure: %q", got)
	}
	if got := dialCell(errors.New("dial tcp: i/o timeout")); got != "not observed" {
		t.Errorf("timeout: %q", got)
	}
}

// The xnm-ssh cell: the JUNOScript greeting is a hello, a refusal text is
// refused, and silence is not observed.
func TestXnmHelloCell(t *testing.T) {
	for _, c := range []struct{ out, want string }{
		{"<?xml version=\"1.0\" encoding=\"us-ascii\"?>\n<junoscript xmlns=\"http://xml.juniper.net/xnm/1.1/xnm\" version=\"1.0\">", "hello"},
		{"error: permission denied\n", "refused"},
		{"", "not observed"},
		// A greeting and a refusal in one output says nothing either way.
		{"<junoscript version=\"1.0\">\nerror: permission denied\n", "not observed"},
	} {
		if got := xnmHelloCell(c.out); got != c.want {
			t.Errorf("%q: got %q, want %q", c.out, got, c.want)
		}
	}
}

// Silence on an open channel is never a refusal (a hang is not a deny); a
// closed channel after a permitted session is.
func TestXnmFirstCell(t *testing.T) {
	for _, c := range []struct {
		out               string
		closed, permitted bool
		want              string
	}{
		{"", false, true, "not observed"},
		{"", true, true, xnmClosed},
		{"", true, false, "not observed"},
		{"<junoscript version=\"1.0\">", false, true, "hello"},
	} {
		if got := xnmFirstCell(c.out, c.closed, c.permitted); got != c.want {
			t.Errorf("%+v: got %q, want %q", c, got, c.want)
		}
	}
}

func TestExecCell(t *testing.T) {
	for _, c := range []struct {
		out    string
		exited bool
		want   string
	}{
		{"<hello></hello>", false, "hello"},
		{"<hello></hello>", true, "hello"},
		{"", false, "not observed"}, // the hang: the channel is still open
		{"", true, "not observed"},  // a silent exit, permitted or not, is not a refusal
		{"unknown command.", true, "refused"},
		{"error: Permission denied", true, "refused"},
		{"unknown command.", false, "not observed"},
	} {
		if got := execCell(c.out, c.exited); got != c.want {
			t.Errorf("%+v: got %q, want %q", c, got, c.want)
		}
	}
}

// fakeStdin records, for each write, what the device had printed by then.
type fakeStdin struct {
	out    *xnmOut
	seen   []string
	closed bool
}

func (f *fakeStdin) Write(p []byte) (int, error) {
	f.seen = append(f.seen, f.out.String()+"|"+string(p))
	return len(p), nil
}

func (f *fakeStdin) Close() error { f.closed = true; return nil }

func TestExecDriveWaitsForTheHello(t *testing.T) {
	var out xnmOut
	f := &fakeStdin{out: &out}
	done := make(chan struct{})
	go func() { execDrive(f, &out, 5*time.Second); close(done) }()
	time.Sleep(300 * time.Millisecond)
	out.Write([]byte("<hello></hello>]]>]]>"))
	time.Sleep(300 * time.Millisecond)
	out.Write([]byte("<rpc-reply></rpc-reply>"))
	<-done
	if len(f.seen) != 3 || !f.closed {
		t.Fatalf("writes = %d, closed = %v, want 3 and true", len(f.seen), f.closed)
	}
	for i, w := range f.seen {
		if !strings.HasPrefix(w, "<hello></hello>") {
			t.Errorf("write %d went before the device's hello: %q", i, w)
		}
	}
	if !strings.Contains(f.seen[1], "<get-configuration>") || !strings.HasPrefix(f.seen[2], "<hello></hello>]]>]]><rpc-reply></rpc-reply>|") {
		t.Errorf("the RPC and the close are out of order: %q", f.seen)
	}
}

func TestExecDriveStopsWaitingOnExit(t *testing.T) {
	var out xnmOut
	f := &fakeStdin{out: &out}
	out.markClosed()
	start := time.Now()
	execDrive(f, &out, time.Minute)
	if time.Since(start) > 5*time.Second || !f.closed {
		t.Errorf("execDrive did not return on an exited command (closed = %v)", f.closed)
	}
}

func TestXnmRPCCell(t *testing.T) {
	for _, c := range []struct {
		reply  string
		closed bool
		want   string
	}{
		{"<rpc-reply><software-information><host-name>srx1</host-name></software-information></rpc-reply>", false, "result"},
		{"<xnm:error xmlns:xnm=\"x\"><message>permission denied</message></xnm:error>", false, "refused"},
		{"<rpc-reply><rpc-error><error-severity>error</error-severity></rpc-error></rpc-reply>", false, "refused"},
		{"", true, xnmClosed},       // the session closed after the RPC with no reply
		{"", false, "not observed"}, // a hang
		{"<rpc-reply>", true, xnmClosed},
		{"<rpc-reply></rpc-reply>", false, "not observed"},
	} {
		if got := xnmRPCCell(c.reply, c.closed); got != c.want {
			t.Errorf("%+v: got %q, want %q", c, got, c.want)
		}
	}
}

// G2: xnm-ssh closes only on a deny (at the greeting or the RPC) with a
// control result; every other reading leaves it failing.
func TestXnmGate(t *testing.T) {
	const h, r = "W xnm-ssh", "W " + xnmRPCKey
	for _, c := range []struct {
		name     string
		readings map[string]string
		control  string
		want     string
	}{
		{"deny at the greeting", map[string]string{h: "deny"}, "result", "closed"},
		{"deny at the RPC after a greeting", map[string]string{h: "reached", r: "deny"}, "result", "closed"},
		{"deny, the control had no result", map[string]string{h: "deny"}, "refused", ""},
		{"result reached", map[string]string{h: "reached", r: "reached"}, "result", "reached"},
		{"greeting only", map[string]string{h: "reached"}, "result", "reached"},
		{"runs nowhere", map[string]string{h: "runs nowhere"}, "result", ""},
		{"not observed", map[string]string{h: "not observed"}, "result", ""},
		{"nothing", map[string]string{}, "result", ""},
	} {
		if got := xnmGate(c.readings, c.control); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
	for _, g := range []string{"closed", "reached", ""} {
		if xnmGateWord(g) == "" {
			t.Errorf("no words for %q", g)
		}
	}
}
