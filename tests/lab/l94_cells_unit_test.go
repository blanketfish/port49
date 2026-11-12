//go:build lab

package lab

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/blanketfish/port49/internal/decision"
	"github.com/blanketfish/port49/internal/token"
)

// The platforms run in L94's priority order: NX-OS, then Junos (vJunos-router,
// vSRX), EOS, IOS-XE, XR; the first three block the merge.
func TestL94PlatformsRunInPriorityOrder(t *testing.T) {
	var sels []string
	for _, p := range l94Platforms {
		sels = append(sels, p.Sel)
		if p.Blocks != (p.Family == "nxos" || p.Family == "junos" || p.Family == "eos") {
			t.Errorf("%s: Blocks=%v", p.Sel, p.Blocks)
		}
		if p.Name != "" {
			if _, ok := l73Dialects[p.Name]; !ok {
				t.Errorf("%s: %s is no l73Dialects key", p.Sel, p.Name)
			}
		}
		if !optInPlatforms[p.Sel] && p.Sel != "vsrx" {
			t.Errorf("%s is not an opt-in TLS platform", p.Sel)
		}
	}
	if want := []string{"nxos106", "vjunos26", "vsrx", "ceos436", "iosxe1718", "xrd261"}; !slices.Equal(sels, want) {
		t.Errorf("order %v, want %v", sels, want)
	}
	if _, err := l94PlatformFor("vsrx"); err == nil || !strings.Contains(err.Error(), "INVALID") {
		t.Errorf("vsrx has no TLS dialect and must be INVALID, got %v", err)
	}
	if _, err := l94PlatformFor("srlinux"); err == nil {
		t.Error("srlinux is not L94's")
	}
	if p, err := l94PlatformFor("nxos106"); err != nil || p.Timeout != 6*time.Second {
		t.Errorf("nxos106: %+v %v", p, err)
	}
}

// c4 is NX-OS's and the fixed arm's only, and runs alone on its own build.
func TestL94CellSelection(t *testing.T) {
	if got := l94CellNames("nxos", "fixed"); !slices.Equal(got, []string{"c1", "c2", "c3", "c4", "c5"}) {
		t.Errorf("nxos fixed: %v", got)
	}
	for _, c := range [][2]string{{"nxos", "baseline"}, {"junos", "fixed"}, {"eos", "fixed"}} {
		if slices.Contains(l94CellNames(c[0], c[1]), "c4") {
			t.Errorf("%v plays c4", c)
		}
	}
	if _, err := l94Select("nxos", "fixed", nil); err == nil {
		t.Error("a fixed NX-OS run of every cell mixes c4's build with the others'")
	}
	if got, err := l94Select("junos", "fixed", nil); err != nil || len(got) != 4 {
		t.Errorf("junos fixed: %v %v", got, err)
	}
	if _, err := l94Select("nxos", "fixed", []string{"c4", "c1"}); err == nil {
		t.Error("c4 beside c1 must be refused")
	}
	if got, err := l94Select("nxos", "fixed", []string{"c4"}); err != nil || !slices.Equal(got, []string{"c4"}) {
		t.Errorf("c4 alone: %v %v", got, err)
	}
	if _, err := l94Select("eos", "fixed", []string{"c4"}); err == nil {
		t.Error("c4 on EOS must be refused")
	}
}

// c1's loop alternates the permitted and the qual policy's denied command.
func TestL94LoopAlternates(t *testing.T) {
	got := l94Loop("cisco_nxos", l94C1Commands)
	if len(got) != 20 || got[0] != "show version" || got[1] != "show users" || got[19] != "show users" {
		t.Errorf("nxos loop %v", got)
	}
	if j := l94Loop("juniper_junos", 2); j[0] != "show version | no-more" || j[1] != "show system users" {
		t.Errorf("junos loop %v", j)
	}
}

func l94Rec(ts time.Time, ev, verdict, vec string) map[string]any {
	r := map[string]any{"ts": ts.Format(time.RFC3339Nano), "event": ev, "verdict": verdict}
	var words []any
	for _, w := range strings.Fields(vec) {
		words = append(words, w)
	}
	switch ev {
	case "authorize_command":
		r["request"] = map[string]any{"vector": words}
	case "account":
		r["record"] = map[string]any{"vector": words}
	}
	return r
}

// c2's order is read from the records' ts: B's authorize_command against A's
// FAIL redeem, whose ts is A's read (before the delay).
// H2: c2 whose last try's timing is not "ok" measured nothing: INVALID, on
// either arm, never a pass.
func TestL94C2TimingThatNeverSettlesIsInvalid(t *testing.T) {
	if err := l94C2Valid("ok", 1); err != nil {
		t.Errorf("ok: %v", err)
	}
	for _, timing := range []string{"early", "none", ""} {
		err := l94C2Valid(timing, l94C2Tries)
		if err == nil || !strings.HasPrefix(err.Error(), "INVALID") {
			t.Errorf("%q: %v, want INVALID", timing, err)
		}
	}
}

func TestL94GapsAreReadFromRecordTimes(t *testing.T) {
	t0 := time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)
	recs := []map[string]any{
		l94Rec(t0, "redeem", "permit", ""),
		l94Rec(t0.Add(200*time.Millisecond), "authorize_command", "permit", "show version"),
		l94Rec(t0.Add(300*time.Millisecond), "authorize_command", "deny", "show users"),
		l94Rec(t0.Add(2100*time.Millisecond), "redeem", "deny", ""),
		{"ts": "not a time", "event": "authorize_command"},
		{"ts": t0.Format(time.RFC3339Nano), "event": "tls_refused"},
	}
	evs := l94Events(recs)
	if len(evs) != 4 {
		t.Fatalf("%d events, want 4 (the unparseable ts and the other event dropped)", len(evs))
	}
	// A redeem's ts is A's read (newRecord, before the delay: authen.go:235),
	// so a gap is B's read less A's: negative is B before A.
	gaps, ok := l94Gaps("cisco_nxos", evs, []string{"show version", "show users"})
	if !ok || len(gaps) != 2 || gaps[0] != -1900*time.Millisecond || gaps[1] != -1800*time.Millisecond {
		t.Fatalf("gaps %v ok=%v", gaps, ok)
	}
	if got := l94C2Timing(gaps); got != "early" {
		t.Errorf("B read before A: timing %s, want early", got)
	}
	if got := l94C2Timing([]time.Duration{300 * time.Millisecond, 1000 * time.Millisecond}); got != "ok" {
		t.Errorf("B after A's read: timing %s", got)
	}
	if got := l94C2Timing([]time.Duration{2000 * time.Millisecond}); got != "ok" {
		t.Errorf("B waited (a stop, not a retry): timing %s", got)
	}
	if got := l94C2Timing(nil); got != "none" {
		t.Errorf("no B request: %s", got)
	}
	if _, ok := l94Gaps("cisco_nxos", evs[:3], []string{"show version"}); ok {
		t.Error("no FAIL redeem: ok must be false")
	}
	// Junos asks about no command: B's account records are what is ordered.
	jrecs := []map[string]any{
		l94Rec(t0.Add(2400*time.Millisecond), "account", "", "show version"),
		l94Rec(t0.Add(2100*time.Millisecond), "redeem", "deny", ""),
	}
	jg, ok := l94Gaps("juniper_junos", l94Events(jrecs), []string{"show version | no-more"})
	if !ok || len(jg) != 1 || jg[0] != 300*time.Millisecond {
		t.Errorf("junos gaps %v ok=%v", jg, ok)
	}
}

// l94At is a time on the evidence's day, from its hh:mm:ss.mmm.
func l94At(t *testing.T, clock string) time.Time {
	t.Helper()
	ts, err := time.Parse("2006-01-02T15:04:05.000Z", "2026-11-12T"+clock+"Z")
	if err != nil {
		t.Fatal(err)
	}
	return ts
}

// Round 5, on the committed NX-OS evidence (1c1d105c fixed, 4481bbd8
// baseline, offered c2): fixed, A's deny 04:57:29.730 and B's
// authorize_commands 30.021 and 30.772 were answered inside A's delay;
// baseline, A 03:48:00.665 and B 02.665 (+2.000s) waited behind it.
func TestL94C2GradesTheEvidenceShapes(t *testing.T) {
	cmds := []string{"show version", "show users"}
	shape := func(a string, b ...string) []l94Event {
		evs := []l94Event{{TS: l94At(t, a), Event: "redeem", Verdict: "deny", Reason: "token_not_found"}}
		for i, ts := range b {
			evs = append(evs, l94Event{TS: l94At(t, ts), Event: "authorize_command", Vector: cmds[i]})
		}
		return evs
	}
	grade := func(evs []l94Event) (string, []string) {
		gaps, ok := l94Gaps("cisco_nxos", evs, cmds)
		if !ok {
			t.Fatal("no FAIL")
		}
		g := l94Clean()
		g.Cell, g.Outcomes, g.Gaps, g.Events = "c2", []l94Outcome{{AuthFailed: true}}, gaps, nil
		g.Typed = []l80Typed{{Command: "show version", Asked: true, Took: 0.75}, {Command: "show users", Asked: true, Denied: true, Took: 0.25}}
		return l94C2Timing(gaps), l94Stops(g)
	}
	timing, stops := grade(shape("04:57:29.730", "04:57:30.021", "04:57:30.772"))
	if timing != "ok" || len(stops) != 0 {
		t.Errorf("fixed shape: timing %s stops %v", timing, stops)
	}
	timing, stops = grade(shape("03:48:00.665", "03:48:02.665", "03:48:03.459"))
	if got := strings.Join(stops, "\n"); timing != "ok" || !strings.Contains(got, "waited behind A") {
		t.Errorf("baseline shape: timing %s stops %q", timing, got)
	}
	// B read before A: a retry, not a grade.
	if timing, _ := grade(shape("04:57:30.900", "04:57:30.021", "04:57:30.772")); timing != "early" {
		t.Errorf("B before A: timing %s", timing)
	}
	// The line is l94Delay less 250ms after A's read.
	if _, stops := grade(shape("04:57:29.730", "04:57:31.420")); len(stops) != 0 {
		t.Errorf("1.69s after A: %v", stops)
	}
	if _, stops := grade(shape("04:57:29.730", "04:57:31.480")); !strings.Contains(strings.Join(stops, "\n"), "waited behind A") {
		t.Errorf("1.75s after A: %v", stops)
	}
}

// Round 5: B's token login is inside A's delay when port49 read it after
// A's read and under l94Delay less 250ms later.
func TestL94LoginInsideDelayIsFromAsRead(t *testing.T) {
	a := l94At(t, "04:57:29.730")
	evs := func(b time.Duration) []l94Event {
		return []l94Event{{TS: a, Event: "redeem", Verdict: "deny"}, {TS: a.Add(b), Event: "redeem", Verdict: "permit"}}
	}
	if !l94LoginInsideDelay(evs(500 * time.Millisecond)) {
		t.Error("0.5s after A's read: inside")
	}
	if l94LoginInsideDelay(evs(-300 * time.Millisecond)) {
		t.Error("before A's read: not inside")
	}
	if l94LoginInsideDelay(evs(2 * time.Second)) {
		t.Error("the baseline's +2.000s: it waited, not inside")
	}
}

// A's credential is a password port49 refuses after the full delay: never a
// minted token (a spent token replays its receipt, spec §5.1.1) and never
// token-shaped (that is device_mismatch, not token_not_found). Fresh each call.
func TestL94RefusedCredentialIsNeverTokenShaped(t *testing.T) {
	seen := map[string]bool{}
	for range 200 {
		c := l94RefusedCredential()
		if c == "" {
			t.Fatal("an empty credential")
		}
		if _, ok := token.Parse([]byte(c)); ok {
			t.Fatal("a refused credential parsed as a token")
		}
		if seen[c] {
			t.Fatal("a refused credential repeated")
		}
		seen[c] = true
	}
}

// l94ARec is a redeem record carrying credential_sha256.
func l94ARec(ts time.Time, verdict, reason, sha string) map[string]any {
	r := l94Rec(ts, "redeem", verdict, "")
	r["reason"] = reason
	r["auth"] = map[string]any{"method": "ascii", "credential_sha256": sha}
	return r
}

// Round 4: A's login answered PERMIT receipt_replayed is not a FAIL, and the
// cell says so by name instead of "none of B's commands reached port49".
func TestL94AReplayedPermitIsInvalidNamingIt(t *testing.T) {
	t0 := time.Now()
	a := decision.CredentialHash([]byte(l94RefusedCredential()))
	b := decision.CredentialHash([]byte(l94RefusedCredential()))
	replayed := l94Events([]map[string]any{
		l94ARec(t0, "permit", "receipt_replayed", a),
		l94Rec(t0.Add(time.Second), "authorize_command", "permit", "show version"),
	})
	err := l94C2Verdict(replayed, []string{a}, "none", 1)
	if err == nil || !strings.Contains(err.Error(), "INVALID") || !strings.Contains(err.Error(), "receipt_replayed") || strings.Contains(err.Error(), "none of B's") {
		t.Errorf("replayed permit in c2: %v", err)
	}
	refused := l94Events([]map[string]any{l94ARec(t0.Add(2*time.Second), "deny", "token_not_found", a)})
	if err := l94AValid("c2", refused, []string{a}, true); err != nil {
		t.Errorf("a token_not_found deny: %v", err)
	}
	if err := l94C2Verdict(refused, []string{a}, "ok", 1); err != nil {
		t.Errorf("c2 refused and ok: %v", err)
	}
	if err := l94AValid("c3", refused, []string{a, b}, true); err == nil || !strings.Contains(err.Error(), "no redeem") {
		t.Errorf("a credential port49 never recorded: %v", err)
	}
	if err := l94AValid("c5", refused, []string{a, b}, false); err != nil {
		t.Errorf("c5 need not record every A: %v", err)
	}
	other := l94Events([]map[string]any{l94ARec(t0, "deny", "device_mismatch", a)})
	if err := l94AValid("c3", other, []string{a}, true); err == nil || !strings.Contains(err.Error(), "device_mismatch") {
		t.Errorf("a deny with another reason: %v", err)
	}
	if err := l94AValid("c5", replayed, []string{a}, false); err == nil || !strings.Contains(err.Error(), "receipt_replayed") {
		t.Errorf("c5 replayed permit: %v", err)
	}
}

func TestL94OutcomeOfALogin(t *testing.T) {
	if o := l94OutcomeOf(2*time.Second, errors.New("ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password]")); !o.AuthFailed || o.LoggedIn || o.Err != "" {
		t.Errorf("auth failure: %+v", o)
	}
	if o := l94OutcomeOf(time.Second, nil); !o.LoggedIn {
		t.Errorf("a login: %+v", o)
	}
	if o := l94OutcomeOf(time.Minute, errors.New("i/o timeout")); o.AuthFailed || o.Err == "" {
		t.Errorf("a timeout: %+v", o)
	}
	if got := l94Regressed([]l94Outcome{{AuthFailed: true}}, []l94Outcome{{Err: "timeout"}}); len(got) != 1 {
		t.Errorf("a FAIL become a timeout: %v", got)
	}
	if got := l94Regressed([]l94Outcome{{AuthFailed: true}}, []l94Outcome{{AuthFailed: true}}); len(got) != 0 {
		t.Errorf("no regression: %v", got)
	}
}

func TestL94DuplicatesAreFound(t *testing.T) {
	typed := []l80Typed{{Command: "show version"}, {Command: "show users"}}
	evs := []l94Event{{Event: "authorize_command", Vector: "show version"}, {Event: "authorize_command", Vector: "show users"},
		{Event: "account", Flags: "start", TaskID: "7"}, {Event: "account", Flags: "stop", TaskID: "7"}}
	if got := l94Dup(evs, typed); len(got) != 0 {
		t.Errorf("no duplicate: %v", got)
	}
	evs = append(evs, l94Event{Event: "authorize_command", Vector: "show version"}, l94Event{Event: "account", Flags: "stop", TaskID: "7"})
	if got := l94Dup(evs, typed); len(got) != 2 {
		t.Errorf("a retransmitted authorization and accounting record: %v", got)
	}
}

func l94Clean() l94Grade {
	p, _ := l94PlatformFor("nxos106")
	return l94Grade{Arm: "fixed", Cell: "c1", Platform: "cisco_nxos", P: p, Conns: 1, MostOpen: 1,
		Typed:  []l80Typed{{Command: "show version", Asked: true}, {Command: "show users", Asked: true, Denied: true}},
		Events: append(l94SessionAcct(), l94Event{Event: "authorize_command", Vector: "show version"}, l94Event{Event: "authorize_command", Vector: "show users"})}
}

// l94SessionAcct is c1's two sessions' accounting START and STOP records.
func l94SessionAcct() []l94Event {
	return []l94Event{{Event: "account", Flags: "start", TaskID: "1"}, {Event: "account", Flags: "start", TaskID: "2"},
		{Event: "account", Flags: "stop", TaskID: "1"}, {Event: "account", Flags: "stop", TaskID: "2"}}
}

// H1: on the fixed arm a permitted command refused, any prompt that never came
// back, a c1/c4 command slower than the platform's L13 timeout (or than
// l94FastB where commands are asked), and a c1 without its sessions'
// accounting START and STOP records are each a stop.
func TestL94RefusedPermittedLostPromptsSlowCommandsAndMissingAccountingStop(t *testing.T) {
	cases := map[string]func(*l94Grade){
		"permitted command was refused":    func(g *l94Grade) { g.Typed[0].Denied = true },
		"prompt never came back":           func(g *l94Grade) { g.Typed[1].Err = true },
		"reached port49 1.2s after":        func(g *l94Grade) { g.Events[4].TS = g.Typed[0].At.Add(1200 * time.Millisecond) },
		"accounting START record(s), want": func(g *l94Grade) { g.Events = g.Events[2:] },
		"accounting STOP record(s), want":  func(g *l94Grade) { g.Events = append(g.Events[:2:2], g.Events[4:]...) },
	}
	for want, mut := range cases {
		for _, cell := range []string{"c1", "c4"} {
			g := l94Clean()
			g.Cell = cell
			g.Typed = slices.Clone(g.Typed)
			g.Events = slices.Clone(g.Events)
			mut(&g)
			if got := strings.Join(l94Stops(g), "\n"); !strings.Contains(got, want) {
				t.Errorf("%s %s: stops %q", cell, want, got)
			}
			g.Arm = "baseline"
			if s := l94Stops(g); len(s) != 0 {
				t.Errorf("%s %s: the baseline stops: %v", cell, want, s)
			}
		}
	}
	// c2 has its own latency bound and runs no session START/STOP check.
	g := l94Clean()
	g.Cell, g.Outcomes, g.Gaps = "c2", []l94Outcome{{AuthFailed: true}}, []time.Duration{300 * time.Millisecond}
	g.Events = g.Events[4:]
	if got := l94Stops(g); len(got) != 0 {
		t.Errorf("c2 graded on c1's accounting: %v", got)
	}
	// Junos asks about no command: its bound is its L13 timeout (3s), not l94FastB.
	p, _ := l94PlatformFor("vjunos26")
	j := l94Grade{Arm: "fixed", Cell: "c1", Platform: "juniper_junos", P: p, Conns: 1, MostOpen: 1, Events: l94SessionAcct(),
		Typed: []l80Typed{{Command: "show version | no-more", Took: 2}, {Command: "show system users"}}}
	if got := l94Stops(j); len(got) != 0 {
		t.Errorf("junos 2s under its 3s timeout: %v", got)
	}
	j.Typed[0].Took = 3.5
	if got := strings.Join(l94Stops(j), "\n"); !strings.Contains(got, "took 3.50s, over 3s") {
		t.Errorf("junos over its timeout: %q", got)
	}
}

// Round 5, on the committed NX-OS evidence (1c1d105c, offered c1): NX-OS
// holds one vty's prompt while another session runs (s1 "show version"
// typed 04:48:05.229 took 6.76s; the baseline does it too), but port49 read
// it at 05.249. Where commands are asked, c1/c4/c3 grade that arrival
// (the matched authorize_command's ts less the typing), under l94FastB; the
// prompt time is the summary's.
func TestL94CommandsAreGradedOnArrivalNotPrompt(t *testing.T) {
	typed := func() []l80Typed {
		return []l80Typed{
			{Session: 0, Command: "show version", Asked: true, Took: 1.75, At: l94At(t, "04:47:59.198")},
			{Session: 1, Command: "show version", Asked: true, Took: 0.75, At: l94At(t, "04:47:59.213")},
			{Session: 0, Command: "show users", Asked: true, Denied: true, Took: 0.25, At: l94At(t, "04:48:00.952")},
			{Session: 1, Command: "show version", Asked: true, Took: 6.76, At: l94At(t, "04:48:05.229")},
		}
	}
	events := func() []l94Event {
		return append(l94SessionAcct(),
			l94Event{TS: l94At(t, "04:47:59.219"), Event: "authorize_command", Verdict: "permit", Vector: "show version"},
			l94Event{TS: l94At(t, "04:47:59.236"), Event: "authorize_command", Verdict: "permit", Vector: "show version"},
			l94Event{TS: l94At(t, "04:48:00.972"), Event: "authorize_command", Verdict: "deny", Vector: "show users"},
			l94Event{TS: l94At(t, "04:48:05.249"), Event: "authorize_command", Verdict: "permit", Vector: "show version"})
	}
	for _, cell := range []string{"c1", "c4", "c3"} {
		g := l94Clean()
		g.Cell, g.Typed, g.Events = cell, typed(), events()
		if cell == "c3" {
			g.Outcomes = []l94Outcome{{AuthFailed: true}, {AuthFailed: true}, {AuthFailed: true}}
			g.Events = append(g.Events, l94Event{Event: "redeem", Verdict: "deny"}, l94Event{Event: "redeem", Verdict: "deny"}, l94Event{Event: "redeem", Verdict: "deny"})
			g.Baseline = &l94Baseline{MaxTook: 0.5}
		}
		if got := l94Stops(g); len(got) != 0 {
			t.Errorf("%s: the evidence's shape stops: %v", cell, got)
		}
		g.Events[len(l94SessionAcct())+3].TS = l94At(t, "04:48:06.329") // read 1.1s after it was typed
		if got := strings.Join(l94Stops(g), "\n"); !strings.Contains(got, `session 1 "show version" reached port49 1.1s after it was typed`) {
			t.Errorf("%s: a late arrival: %q", cell, got)
		}
	}
	// A stall is not hidden behind a later session's request: s0 typed at
	// 59.198 and read at 00.400 (1.2s), s1 typed at 59.700 and read at
	// 59.720. Each record goes to the latest unmatched typing before it.
	g := l94Clean()
	g.Typed = []l80Typed{
		{Session: 0, Command: "show version", Asked: true, At: l94At(t, "04:47:59.198")},
		{Session: 1, Command: "show version", Asked: true, At: l94At(t, "04:47:59.700")},
	}
	g.Events = append(l94SessionAcct(),
		l94Event{TS: l94At(t, "04:47:59.720"), Event: "authorize_command", Verdict: "permit", Vector: "show version"},
		l94Event{TS: l94At(t, "04:48:00.400"), Event: "authorize_command", Verdict: "permit", Vector: "show version"})
	if got := strings.Join(l94Stops(g), "\n"); !strings.Contains(got, `session 0 "show version" reached port49 1.202s after`) {
		t.Errorf("a stall behind a later request: %q", got)
	}
}

// The merge criteria, one at a time, on the fixed arm; the baseline stops on nothing.
func TestL94StopsAreTheMergeCriteria(t *testing.T) {
	if got := l94Stops(l94Clean()); len(got) != 0 {
		t.Fatalf("a clean c1 stops: %v", got)
	}
	cases := map[string]func(*l94Grade){
		"lost or run unasked":   func(g *l94Grade) { g.Typed[0].Asked = false },
		"ran":                   func(g *l94Grade) { g.Typed[1].Denied = false },
		"retransmitted":         func(g *l94Grade) { g.Events = append(g.Events, g.Events[0]) },
		"must hold exactly one": func(g *l94Grade) { g.Conns = 2 },
		"open at once":          func(g *l94Grade) { g.MostOpen = 2 },
		"second_connection":     func(g *l94Grade) { g.Second = 1 },
		"read the kept debug":   func(g *l94Grade) { g.DeadOrSSL = 1 },
		"logged in":             func(g *l94Grade) { g.Outcomes = []l94Outcome{{LoggedIn: true}} },
	}
	for want, mut := range cases {
		g := l94Clean()
		g.Typed = slices.Clone(g.Typed)
		mut(&g)
		got := strings.Join(l94Stops(g), "\n")
		if !strings.Contains(got, want) {
			t.Errorf("%s: stops %q", want, got)
		}
		g.Arm = "baseline"
		if s := l94Stops(g); len(s) != 0 {
			t.Errorf("%s: the baseline stops: %v", want, s)
		}
	}
}

func TestL94C2Stops(t *testing.T) {
	g := l94Clean()
	g.Cell = "c2"
	g.Outcomes = []l94Outcome{{AuthFailed: true}}
	g.Gaps = []time.Duration{300 * time.Millisecond, 1000 * time.Millisecond}
	g.Typed[0].Took, g.Typed[1].Took = 0.3, 0.4
	if got := l94Stops(g); len(got) != 0 {
		t.Fatalf("a clean c2 stops: %v", got)
	}
	g.Gaps[1] = 2000 * time.Millisecond // read when A's delay ran out: it waited behind A
	g.Typed[1].Took = 2.1
	g.Outcomes[0] = l94Outcome{Err: "timeout"}
	got := strings.Join(l94Stops(g), "\n")
	for _, want := range []string{"waited behind A", "took 2.10s", "not refused as an authentication failure"} {
		if !strings.Contains(got, want) {
			t.Errorf("want %q in %q", want, got)
		}
	}
	g.Outcomes[0] = l94Outcome{Err: "timeout"}
	g.Baseline = &l94Baseline{Outcomes: []l94Outcome{{AuthFailed: true}}}
	if got := strings.Join(l94Stops(g), "\n"); !strings.Contains(got, "became a timeout") {
		t.Errorf("a FAIL the baseline delivered: %q", got)
	}
}

// c3: no B command over the baseline's slowest or the platform's L13
// timeout, and all three FAILs delivered and recorded.
func TestL94C3Stops(t *testing.T) {
	g := l94Clean()
	g.Cell = "c3"
	g.Outcomes = []l94Outcome{{AuthFailed: true}, {AuthFailed: true}, {AuthFailed: true}}
	g.Events = append(g.Events, l94Event{Event: "redeem", Verdict: "deny"}, l94Event{Event: "redeem", Verdict: "deny"}, l94Event{Event: "redeem", Verdict: "deny"})
	// Round 5: where commands are asked the prompt time is not graded
	// (arrival is: TestL94CommandsAreGradedOnArrivalNotPrompt), so neither
	// the row's 1s nor the baseline's slowest applies to it.
	g.Typed[0].Took, g.Typed[1].Took = 0.4, 1.2
	g.Baseline = &l94Baseline{MaxTook: 0.5}
	if got := strings.Join(l94Stops(g), "\n"); strings.Contains(got, "took") {
		t.Errorf("NX-OS c3 graded on its prompt: %q", got)
	}
	g.Baseline = nil
	// H5: where no command is asked (Junos), the prompt is all there is: the
	// baseline's slowest plus 250ms, not the bare slowest.
	p, _ := l94PlatformFor("vjunos26")
	j := l94Grade{Arm: "fixed", Cell: "c3", Platform: "juniper_junos", P: p, Conns: 1, MostOpen: 1,
		Typed: []l80Typed{{Command: "show version | no-more", Took: 0.7}}, Baseline: &l94Baseline{MaxTook: 0.5}}
	if got := strings.Join(l94Stops(j), "\n"); strings.Contains(got, "took") {
		t.Errorf("0.7s is within the baseline's 0.5s + 250ms: %q", got)
	}
	j.Typed[0].Took = 0.8
	if got := strings.Join(l94Stops(j), "\n"); !strings.Contains(got, "took 0.80s, above 0.75s") {
		t.Errorf("above the baseline's slowest + 250ms: %q", got)
	}
	g.Typed[1].Took = 0.5
	g.Outcomes = g.Outcomes[:2]
	g.Events = g.Events[:len(g.Events)-2] // two of the three FAIL redeems gone
	got := strings.Join(l94Stops(g), "\n")
	if !strings.Contains(got, "2 of 3 FAILs") || !strings.Contains(got, "recorded 1 FAIL") {
		t.Errorf("a FAIL lost: %q", got)
	}
	// Round 4: the lab client offers password, then keyboard-interactive
	// (labSSHConfig), so one refused A login may be two FAIL redeems. Six for
	// three logins is not a stop: l94AValid checks each credential instead.
	g.Outcomes = append(g.Outcomes, l94Outcome{AuthFailed: true})
	for range 5 {
		g.Events = append(g.Events, l94Event{Event: "redeem", Verdict: "deny"})
	}
	if got := strings.Join(l94Stops(g), "\n"); strings.Contains(got, "FAIL redeem") {
		t.Errorf("two FAILs per login: %q", got)
	}
}

// H5: where the device asks port49 about no command (Junos), c2 and c3 hold a
// B token login during A's FAILs: it must log in, within the platform's L13
// timeout, and port49 must have answered it inside A's delay (a permit
// redeem read under l94Inside after A's), so it was neither queued nor a
// fall-through.
func TestL94JunosHoldsABLoginDuringTheFails(t *testing.T) {
	t0 := time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)
	p, _ := l94PlatformFor("vjunos26")
	for _, cell := range []string{"c2", "c3"} {
		fails := 1
		if cell == "c3" {
			fails = l94C3Fails
		}
		clean := func() l94Grade {
			g := l94Grade{Arm: "fixed", Cell: cell, Platform: "juniper_junos", P: p, Conns: 1, MostOpen: 1,
				Typed: []l80Typed{{Command: "show version | no-more", Took: 0.3}}, Gaps: []time.Duration{300 * time.Millisecond},
				BLogin: &l94Outcome{LoggedIn: true, Took: 1.1},
				Events: []l94Event{{TS: t0.Add(-5 * time.Second), Event: "redeem", Verdict: "permit"}, // B's session
					{TS: t0.Add(1200 * time.Millisecond), Event: "redeem", Verdict: "permit"}}} // B's login, inside the delay
			for range fails {
				g.Outcomes = append(g.Outcomes, l94Outcome{AuthFailed: true})
				g.Events = append(g.Events, l94Event{TS: t0, Event: "redeem", Verdict: "deny"}) // A's read
			}
			return g
		}
		if got := l94Stops(clean()); len(got) != 0 {
			t.Fatalf("%s: a clean Junos cell stops: %v", cell, got)
		}
		cases := map[string]func(*l94Grade){
			"no B token login":         func(g *l94Grade) { g.BLogin = nil },
			"B's token login did not":  func(g *l94Grade) { g.BLogin = &l94Outcome{AuthFailed: true, Took: 2.2} },
			"B's token login took 3.4": func(g *l94Grade) { g.BLogin.Took = 3.4 },
			"not answered inside A's":  func(g *l94Grade) { g.Events[1].TS = t0.Add(2000 * time.Millisecond) },
		}
		for want, mut := range cases {
			g := clean()
			b := *g.BLogin
			g.BLogin = &b
			mut(&g)
			if got := strings.Join(l94Stops(g), "\n"); !strings.Contains(got, want) {
				t.Errorf("%s %s: stops %q", cell, want, got)
			}
		}
	}
	// Where commands are asked the B login is not part of the cell.
	g := l94Clean()
	g.Cell, g.Outcomes, g.Gaps = "c2", []l94Outcome{{AuthFailed: true}}, []time.Duration{300 * time.Millisecond}
	if got := l94Stops(g); len(got) != 0 {
		t.Errorf("NX-OS c2 graded on a B login: %v", got)
	}
}

// c5: a command run unasked stops; one the device refused locally across the
// restart does not; with no asked command after the restart the device did
// not reconnect.
func TestL94C5Stops(t *testing.T) {
	t0 := time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)
	g := l94Clean()
	g.Cell, g.Conns, g.MostOpen = "c5", 2, 1
	g.RestartAt, g.UpAt = t0, t0.Add(3*time.Second)
	g.Typed = []l80Typed{{Command: "show version", Asked: true, At: t0.Add(-time.Second)},
		{Command: "show version", Denied: true, At: t0.Add(time.Second)}, // refused locally inside the restart
		{Command: "show version", Asked: true, At: t0.Add(5 * time.Second)}}
	g.Events = []l94Event{{Event: "authorize_command", Vector: "show version"}, {Event: "authorize_command", Vector: "show version"}}
	if got := l94Stops(g); len(got) != 0 {
		t.Fatalf("a clean c5 stops: %v", got)
	}
	g.Typed[2].Asked = false
	got := strings.Join(l94Stops(g), "\n")
	if !strings.Contains(got, "run unasked") || !strings.Contains(got, "did not reconnect") {
		t.Errorf("c5: %q", got)
	}
	g.UpAt = time.Time{}
	if got := strings.Join(l94Stops(g), "\n"); !strings.Contains(got, "did not come back") {
		t.Errorf("c5 no restart: %q", got)
	}
}

// Junos asks about no command (decision 21): no "never asked" stop, and the
// denied command is the policy's business at login, not this cell's.
func TestL94JunosIsNotGradedOnAsking(t *testing.T) {
	p, _ := l94PlatformFor("vjunos26")
	g := l94Grade{Arm: "fixed", Cell: "c1", Platform: "juniper_junos", P: p, Conns: 1, MostOpen: 1, Events: l94SessionAcct(),
		Typed: []l80Typed{{Command: "show version | no-more"}, {Command: "show system users"}}}
	if got := l94Stops(g); len(got) != 0 {
		t.Errorf("junos c1: %v", got)
	}
	g.Typed[0].Err = true
	if got := l94Stops(g); len(got) != 1 {
		t.Errorf("a lost prompt on Junos: %v", got)
	}
}

// Fix round 3: the delay config is the conformance config TestL94 builds
// (qualConfigYAML, as q.config does), and the line edits l73DaemonYAML
// applies after it (the exact `limits:` line, the 2-space `idle_timeout`
// that DefaultIdle comments out) must still find their lines. Every line but
// the two delay keys is the file's own, byte for byte.
func TestL94DelayConfigKeepsTheRealConfigsLayout(t *testing.T) {
	read := func(parts ...string) string {
		b, err := os.ReadFile(filepath.Join(append([]string{qualRoot(t)}, parts...)...))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	base, err := qualConfigYAML(read("tests", "lab", "port49d-lab.yaml"), read("tests", "lab", "slice", "broker.yaml"),
		read("tests", "qual", "qual-daemon.yaml"), "/x/qual-policy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	delayed, err := l94DelayConfig(base, l94Delay)
	if err != nil {
		t.Fatal(err)
	}
	var kept []string
	for _, ln := range strings.Split(delayed, "\n") {
		if k := strings.TrimSpace(ln); !strings.HasPrefix(k, "auth_failure_delay_base:") && !strings.HasPrefix(k, "auth_failure_delay_max:") {
			kept = append(kept, ln)
		}
	}
	var was []string
	for _, ln := range strings.Split(base, "\n") {
		if k := strings.TrimSpace(ln); !strings.HasPrefix(k, "auth_failure_delay_base:") && !strings.HasPrefix(k, "auth_failure_delay_max:") {
			was = append(was, ln)
		}
	}
	if !slices.Equal(kept, was) {
		t.Fatal("l94DelayConfig changed lines other than the two delay keys: the later prefix edits may not find theirs")
	}
	out, err := l73DaemonYAML(delayed, l73Daemon{Inventory: "/x/inv.yaml", TLSListen: "172.100.100.1:300", DefaultIdle: true,
		Cert: "/x/c", Key: "/x/k", ClientCA: "/x/ca", StateDir: "/x/s", Status: "{disabled: true}"})
	if err != nil {
		t.Fatalf("l73DaemonYAML on the delay config: %v", err)
	}
	var cfg struct {
		Limits map[string]string `yaml:"limits"`
	}
	if err := yaml.Unmarshal([]byte(out), &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Limits["auth_failure_delay_base"] != l94Delay.String() || cfg.Limits["auth_failure_delay_max"] != l94Delay.String() {
		t.Errorf("limits %v: want both delay keys %s", cfg.Limits, l94Delay)
	}
	if _, ok := cfg.Limits["idle_timeout"]; ok {
		t.Error("DefaultIdle did not comment out idle_timeout")
	}
}

func TestL94DelayConfigSetsBothKnobs(t *testing.T) {
	in := "listen: 0.0.0.0:49\nlimits:\n    idle_timeout: 5m\n    auth_failure_delay_max: 9s\n"
	out, err := l94DelayConfig(in, l94Delay)
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Listen string            `yaml:"listen"`
		Limits map[string]string `yaml:"limits"`
	}
	if err := yaml.Unmarshal([]byte(out), &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != "0.0.0.0:49" || cfg.Limits["idle_timeout"] != "5m" || cfg.Limits["auth_failure_delay_base"] != "2s" || cfg.Limits["auth_failure_delay_max"] != "2s" {
		t.Errorf("config %+v", cfg)
	}
	// The block's own indent is kept, the existing key replaced in place.
	if !strings.Contains(out, "\n    idle_timeout: 5m\n") || !strings.Contains(out, "\n    auth_failure_delay_max: 2s\n") || strings.Contains(out, "9s") {
		t.Errorf("the 4-space block was re-laid out: %q", out)
	}
	if _, err := l94DelayConfig("limits: {}\n", l94Delay); err == nil {
		t.Error("a flow-style limits cannot take a line edit and must be refused")
	}
	out, err = l94DelayConfig("listen: x\n", l94Delay)
	if err != nil || !strings.Contains(out, "auth_failure_delay_base: 2s") {
		t.Errorf("no limits block: %q %v", out, err)
	}
	if _, err := l94DelayConfig("- a\n", l94Delay); err == nil {
		t.Error("a list is no config")
	}
}

// H4: the harness's standard daemon path refuses a binary built with the
// hold tag, read from the binary itself (go version -m), and takes one
// built without it. Two throwaway binaries are built to show it.
func TestTheStandardDaemonPathRefusesTheHoldBuild(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"go.mod":  "module holdprobe\n\ngo 1.26\n",
		"main.go": "package main\n\nfunc main() {}\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	build := func(out string, tags ...string) string {
		args := []string{"build", "-o", filepath.Join(dir, out)}
		if len(tags) > 0 {
			args = append(args, "-tags", strings.Join(tags, ","))
		}
		cmd := exec.Command("go", append(args, ".")...)
		cmd.Dir, cmd.Env = dir, append(os.Environ(), "CGO_ENABLED=0", "GOWORK=off", "GOFLAGS=")
		if b, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("go build %v: %v %s", tags, err, b)
		}
		return filepath.Join(dir, out)
	}
	if err := l94StandardBin(build("plain")); err != nil {
		t.Errorf("a plain build was refused: %v", err)
	}
	if err := l94StandardBin(build("other", "hwkey_dlopen")); err != nil {
		t.Errorf("a build with another tag was refused: %v", err)
	}
	err := l94StandardBin(build("held", "hwkey_dlopen", l94HoldTag))
	if err == nil || !strings.Contains(err.Error(), l94HoldTag) {
		t.Errorf("the hold build was taken: %v", err)
	}
	if l94StandardBin(filepath.Join(dir, "missing")) == nil {
		t.Error("a binary that cannot be read was taken")
	}
	if l94HoldBin == "bin/port49d" || !strings.HasPrefix(l94HoldBin, "bin/") {
		t.Errorf("c4's build goes to %q: its own path under bin/, never bin/port49d", l94HoldBin)
	}
}

// c4's build carries the hold tag and no other cell's does.
func TestL94BuildTags(t *testing.T) {
	out := "port49d: go1.26.0\n\tpath\tgithub.com/blanketfish/port49/cmd/port49d\n\tbuild\t-tags=port49_lab_acct_hold\n\tbuild\tvcs.revision=abc\n"
	if got := parseBuildTags(out); got != l94HoldTag {
		t.Fatalf("tags %q", got)
	}
	if parseBuildTags("\tbuild\tvcs.revision=abc\n") != "" {
		t.Error("no -tags line")
	}
	if l94TagCheck("c4", l94HoldTag) != nil || l94TagCheck("c1", "") != nil || l94TagCheck("c1", "hwkey_dlopen") != nil {
		t.Error("the right builds were refused")
	}
	if l94TagCheck("c4", "") == nil || l94TagCheck("c2", "x,"+l94HoldTag) == nil {
		t.Error("the wrong builds were accepted")
	}
}

// L94's arms are checked against decision 59's commit, not L80's.
func TestL94ArmCheckNamesItsFix(t *testing.T) {
	err := armCheckFor("baseline", buildVCS{Revision: "1111"}, "2222", l94FixCommit, func(string) (bool, error) { return true, nil })
	if err == nil || !strings.Contains(err.Error(), l94FixCommit) {
		t.Errorf("baseline holding the fix: %v", err)
	}
	if err := armCheckFor("baseline", buildVCS{Revision: "1111"}, "2222", l94FixCommit, func(string) (bool, error) { return false, nil }); err != nil {
		t.Errorf("a clean baseline: %v", err)
	}
}

func TestL94SuspectLinesAreCounted(t *testing.T) {
	kept := "Nov 12 tacacs: server 10.0.0.1 marked dead\nNov 12 tacacs: request sent\nNov 12 tls: SSL read error\nNov 12 aaa: unexpected seq_no 4\n"
	if got := l94Suspect(kept); got != 3 {
		t.Errorf("suspect lines %d, want 3", got)
	}
	if got := l94SuspectLines(kept); len(got) != 3 || got[1] != "Nov 12 tls: SSL read error" {
		t.Errorf("suspect lines %q", got)
	}
}

// The broad suspect pattern (not NX-OS's measured markers) stops the fixed
// arm only past the baseline arm's count for the same cell and mode; with no
// baseline count there is nothing to compare, which stops too.
func TestL94SuspectLinesStopOnlyPastTheBaseline(t *testing.T) {
	p, _ := l94PlatformFor("ceos436")
	g := l94Grade{Arm: "fixed", Cell: "c1", Platform: "arista_eos", P: p, Conns: 1, MostOpen: 1, Events: l94SessionAcct(),
		Typed:     []l80Typed{{Command: "show version", Asked: true}},
		DeadOrSSL: 2, Suspect: true, Baseline: &l94Baseline{Suspect: 2, HasSuspect: true}}
	g.Events = append(g.Events, l94Event{Event: "authorize_command", Vector: "show version"})
	if got := l94Stops(g); len(got) != 0 {
		t.Errorf("as many suspect lines as the baseline: %v", got)
	}
	g.DeadOrSSL = 3
	if got := strings.Join(l94Stops(g), "\n"); !strings.Contains(got, "3 suspect device debug line(s), the baseline arm's 2") {
		t.Errorf("past the baseline: %q", got)
	}
	g.Baseline = nil
	if got := strings.Join(l94Stops(g), "\n"); !strings.Contains(got, "no baseline count") {
		t.Errorf("no baseline: %q", got)
	}
	// NX-OS's markers are measured strings: any is a stop, baseline or not.
	n := l94Clean()
	n.DeadOrSSL, n.Baseline = 1, &l94Baseline{Suspect: 5, HasSuspect: true}
	if got := strings.Join(l94Stops(n), "\n"); !strings.Contains(got, "read the kept debug") {
		t.Errorf("an NX-OS marker: %q", got)
	}
}
