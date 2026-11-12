//go:build lab

package lab

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"net"
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
	"github.com/blanketfish/port49/tests/lab/labpcap"
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
	for _, c := range [][2]string{{"nxos", "baseline"}, {"junos", "baseline"}, {"eos", "fixed"}} {
		if slices.Contains(l94CellNames(c[0], c[1]), "c4") {
			t.Errorf("%v plays c4", c)
		}
	}
	for _, f := range []string{"nxos", "junos"} {
		if _, err := l94Select(f, "fixed", nil); err == nil {
			t.Errorf("a fixed %s run of every cell mixes c4's build with the others'", f)
		}
		if got, err := l94Select(f, "fixed", []string{"c1", "c2", "c3", "c5"}); err != nil || len(got) != 4 {
			t.Errorf("%s fixed without c4: %v %v", f, got, err)
		}
	}
	if got, err := l94Select("eos", "fixed", nil); err != nil || len(got) != 4 {
		t.Errorf("eos fixed: %v %v", got, err)
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
	gaps, ok := l94Gaps("cisco_nxos", evs, []string{"show version", "show users"}, "")
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
	if _, ok := l94Gaps("cisco_nxos", evs[:3], []string{"show version"}, ""); ok {
		t.Error("no FAIL redeem: ok must be false")
	}
	// Junos asks about no command: B's token login is what is ordered, not
	// its command accounting (round 7, TestL94JunosC2IsGradedOnBsLogin).
	bSHA := decision.CredentialHash([]byte(l94RefusedCredential()))
	bRec := l94Rec(t0.Add(2400*time.Millisecond), "redeem", "permit", "")
	bRec["auth"] = map[string]any{"method": "ascii", "credential_sha256": bSHA}
	jrecs := []map[string]any{
		l94Rec(t0.Add(2400*time.Millisecond), "account", "", "show version | no-more <cr>"),
		bRec,
		l94Rec(t0.Add(2100*time.Millisecond), "redeem", "deny", ""),
	}
	jg, ok := l94Gaps("juniper_junos", l94Events(jrecs), []string{"show version | no-more"}, bSHA)
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
		gaps, ok := l94Gaps("cisco_nxos", evs, cmds, "")
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

// Round 7, on vJunos 26.2R1.7 (baseline c1, 08:34): Junos asks about no
// command, and its command accounting is no clock for c2: the records come
// in bursts about 5s apart (13.381-.389, 18.415-.431, 23.452) and each
// carries the line as the device logged it, "show version | no-more <cr>".
// So c2's gap there is B's token login: its permit redeem's ts less A's
// read, the window l94LoginInsideDelay grades. The session logins were read
// 105ms apart (11.534, 11.639).
func TestL94JunosC2IsGradedOnBsLogin(t *testing.T) {
	cmds := []string{"show version | no-more", "show system users"}
	b := decision.CredentialHash([]byte(l94RefusedCredential()))
	shape := func(ts string) []l94Event {
		evs := []l94Event{{TS: l94At(t, "08:34:11.534"), Event: "redeem", Verdict: "deny", Reason: "token_not_found"}}
		if ts != "" {
			evs = append(evs, l94Event{TS: l94At(t, ts), Event: "redeem", Verdict: "permit", Cred: b})
		}
		return append(evs, l94Event{TS: l94At(t, "08:34:13.388"), Event: "account", Flags: "stop", TaskID: "2", Vector: "show version | no-more <cr>"})
	}
	gaps, ok := l94Gaps("juniper_junos", shape("08:34:11.639"), cmds, b)
	if !ok || len(gaps) != 1 || gaps[0] != 105*time.Millisecond || l94C2Timing(gaps) != "ok" {
		t.Fatalf("B's login 105ms after A: gaps %v ok=%v timing %s", gaps, ok, l94C2Timing(gaps))
	}
	if !l94LoginInsideDelay(shape("08:34:11.639"), b) {
		t.Error("the same window as l94LoginInsideDelay")
	}
	// Round 7c: B's login is the redeem of B's own token. A permit redeem
	// with another credential inside the window (a re-authentication, a
	// second attempt) is not B: c2 grades "none", the wait goes on, and
	// the B-login check finds no B login inside A's delay.
	stray := shape("")
	stray = append(stray, l94Event{TS: l94At(t, "08:34:11.639"), Event: "redeem", Verdict: "permit", Cred: decision.CredentialHash([]byte(l94RefusedCredential()))})
	if gaps, _ := l94Gaps("juniper_junos", stray, cmds, b); l94C2Timing(gaps) != "none" {
		t.Errorf("a stray permit timed as B: gaps %v", gaps)
	}
	if l94LoginInsideDelay(stray, b) {
		t.Error("a stray permit taken for B's login inside A's delay")
	}
	strayA := decision.CredentialHash([]byte(l94RefusedCredential()))
	stray[0].Cred = strayA
	if l94C2Recorded("juniper_junos", stray, strayA, b) {
		t.Error("a stray permit ended the wait for B's login")
	}
	p, _ := l94PlatformFor("vjunos26")
	g := l94Grade{Arm: "fixed", Cell: "c2", Platform: "juniper_junos", P: p, Conns: 1, MostOpen: 1, Gaps: gaps, BSHA: b,
		Outcomes: []l94Outcome{{AuthFailed: true}}, BLogin: &l94Outcome{LoggedIn: true, Took: 0.4}, Events: shape("08:34:11.639"),
		Typed: []l80Typed{{Command: cmds[0], Took: 0.25}, {Command: cmds[1], Denied: true, Took: 0.25}}}
	if got := l94Stops(g); len(got) != 0 {
		t.Errorf("a Junos c2 inside A's delay stops: %v", got)
	}
	// Round 8 (ruling): port49 is never asked about a Junos command, so its
	// prompt time is not c2's grade (vJunos's first command takes 1.50s in
	// both arms). Where commands are asked it still is.
	g.Typed[0].Took = 1.5
	if got := strings.Join(l94Stops(g), "\n"); strings.Contains(got, "took") {
		t.Errorf("Junos c2 graded on B's prompt: %q", got)
	}
	n := l94Clean()
	n.Cell, n.Outcomes, n.Gaps = "c2", []l94Outcome{{AuthFailed: true}}, []time.Duration{300 * time.Millisecond}
	n.Typed = slices.Clone(n.Typed)
	n.Typed[0].Took = 1.5
	if got := strings.Join(l94Stops(n), "\n"); !strings.Contains(got, `c2: B's "show version" took 1.50s, over 1s`) {
		t.Errorf("NX-OS c2 at 1.5s: %q", got)
	}
	g.Events = shape("08:34:13.534") // the baseline's +2.000s
	g.Gaps, _ = l94Gaps("juniper_junos", g.Events, cmds, b)
	if got := strings.Join(l94Stops(g), "\n"); !strings.Contains(got, "waited behind A") {
		t.Errorf("B's login read when A's delay ran out: %q", got)
	}
	if gaps, _ := l94Gaps("juniper_junos", shape("08:34:11.300"), cmds, b); l94C2Timing(gaps) != "early" {
		t.Errorf("B's login before A: %v", gaps)
	}
	if gaps, _ := l94Gaps("juniper_junos", shape(""), cmds, b); l94C2Timing(gaps) != "none" {
		t.Errorf("no B login: %v", gaps)
	}
	// The loop's wait ends when A's redeem is in and, where no command is
	// asked, B's login too; where commands are asked, A's alone, as before.
	a := decision.CredentialHash([]byte(l94RefusedCredential()))
	aOnly := []l94Event{{TS: l94At(t, "08:34:11.534"), Event: "redeem", Verdict: "deny", Cred: a}}
	both := append(slices.Clone(aOnly), l94Event{TS: l94At(t, "08:34:11.639"), Event: "redeem", Verdict: "permit", Cred: b})
	if l94C2Recorded("juniper_junos", aOnly, a, b) || !l94C2Recorded("juniper_junos", both, a, b) {
		t.Error("Junos: wait for A's redeem and B's login")
	}
	if !l94C2Recorded("cisco_nxos", aOnly, a, "") || l94C2Recorded("cisco_nxos", nil, a, "") {
		t.Error("NX-OS: wait for A's redeem only")
	}
}

// Round 7: NX-OS's c2 grading is unchanged. The committed fixed-arm c2
// summaries (5131998b) print the loop's gaps; the records they list, graded
// again here, give the same gaps first (the trailing command's follows).
func TestL94NXOSC2EvidenceRegradesTheSame(t *testing.T) {
	for _, mode := range []string{"offered", "single"} {
		b, err := os.ReadFile(filepath.Join(qualRoot(t), "tests", "lab", "evidence", "L94-cisco_nxos", "fixed", mode, "c2-summary.txt"))
		if err != nil {
			t.Fatal(err)
		}
		var printed string
		var evs []l94Event
		inRecs := false
		for _, ln := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(ln, "try ") {
				printed = ln[strings.Index(ln, "gaps=")+len("gaps="):]
			}
			if ln == "port49 records:" {
				inRecs = true
				continue
			}
			if !inRecs || !strings.HasPrefix(ln, "  ") {
				inRecs = inRecs && strings.HasPrefix(ln, "  ")
				continue
			}
			f := strings.Fields(ln)
			e := l94Event{TS: l94At(t, f[0]), Event: f[1]}
			if len(f) > 2 {
				e.Verdict = f[2]
			}
			if i := strings.Index(ln, `"`); i >= 0 {
				e.Vector = strings.Trim(ln[i:], `"`)
			}
			evs = append(evs, e)
		}
		gaps, ok := l94Gaps("cisco_nxos", evs, []string{"show version", "show users"}, "")
		if !ok || printed == "" || len(gaps) < 2 {
			t.Fatalf("%s: gaps %v ok=%v printed %q", mode, gaps, ok, printed)
		}
		if got := fmt.Sprint(gaps[:len(gaps)-1]); got != printed {
			t.Errorf("%s: regraded %s, the run printed %s", mode, got, printed)
		}
		if l94C2Timing(gaps[:len(gaps)-1]) != "ok" {
			t.Errorf("%s: timing %s", mode, l94C2Timing(gaps))
		}
	}
}

// Round 5: B's token login is inside A's delay when port49 read it after
// A's read and under l94Delay less 250ms later.
func TestL94LoginInsideDelayIsFromAsRead(t *testing.T) {
	a := l94At(t, "04:57:29.730")
	bSHA := decision.CredentialHash([]byte(l94RefusedCredential()))
	evs := func(b time.Duration) []l94Event {
		return []l94Event{{TS: a, Event: "redeem", Verdict: "deny"}, {TS: a.Add(b), Event: "redeem", Verdict: "permit", Cred: bSHA}}
	}
	if !l94LoginInsideDelay(evs(500*time.Millisecond), bSHA) {
		t.Error("0.5s after A's read: inside")
	}
	if l94LoginInsideDelay(evs(-300*time.Millisecond), bSHA) {
		t.Error("before A's read: not inside")
	}
	if l94LoginInsideDelay(evs(2*time.Second), bSHA) {
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
	if got := l94Dup("cisco_nxos", evs, typed); len(got) != 0 {
		t.Errorf("no duplicate: %v", got)
	}
	evs = append(evs, l94Event{Event: "authorize_command", Vector: "show version"}, l94Event{TS: evs[3].TS.Add(2 * time.Second), Event: "account", Flags: "stop", TaskID: "7"})
	if got := l94Dup("cisco_nxos", evs, typed); len(got) != 2 {
		t.Errorf("a retransmitted authorization and accounting record: %v", got)
	}
}

// Round 5, on the committed NX-OS evidence (both arms): NX-OS sends two
// accounting STOPs per session 15-19ms apart. A repeat counts only from 1s
// after the first.
func TestL94AccountingRepeatsCountFromOneSecond(t *testing.T) {
	stop := func(clock string) l94Event {
		return l94Event{TS: l94At(t, clock), Event: "account", Flags: "stop", TaskID: "172.100.100.1@pts/4", Port: "0"}
	}
	if got := l94Dup("cisco_nxos", []l94Event{stop("04:48:11.253"), stop("04:48:11.269")}, nil); len(got) != 0 {
		t.Errorf("NX-OS's pair 16ms apart: %v", got)
	}
	if got := l94Dup("cisco_nxos", []l94Event{stop("04:48:11.253"), stop("04:48:11.269"), stop("04:48:12.300")}, nil); len(got) != 1 || !strings.Contains(got[0], "recorded 2 times") {
		t.Errorf("a repeat 1.05s after the first: %v", got)
	}
	if got := l94Dup("cisco_nxos", []l94Event{stop("04:48:12.253"), stop("04:48:11.253")}, nil); len(got) != 1 {
		t.Errorf("a repeat 1s apart, out of record order: %v", got)
	}
}

// l94AcctRows reads "hh:mm:ss.mmm<TAB>flags<TAB>task_id<TAB>port<TAB>vector"
// rows, the decision log's account fields as jq prints them.
func l94AcctRows(t *testing.T, rows string) []l94Event {
	t.Helper()
	var out []l94Event
	for _, ln := range strings.Split(strings.Trim(rows, "\n"), "\n") {
		f := strings.SplitN(ln, "\t", 5)
		if len(f) != 5 {
			t.Fatalf("row %q", ln)
		}
		out = append(out, l94Event{TS: l94At(t, f[0]), Event: "account", Flags: f[1], TaskID: f[2], Port: f[3], Vector: f[4]})
	}
	return out
}

// vJunos 26's fixed c1 (2026-11-12, tests/lab/logs/decisions-juniper_vjunos-router.jsonl,
// 09:46:48-09:47:04): two vtys (ports 1 and 2) whose task_ids count up per
// session from 1, in bursts about 5s apart; system processes (port non-tty)
// and the harness's own config session (port 0) in the same window. The old
// key, flags/task_id, stopped it on start/1 x3, stop/1 x5 and stop/2 x3.
const l94VJunosC1Acct = `
09:46:48.164	stop	1	0	commit and-quit <cr>
09:46:48.164	start	1	non-tty	login
09:46:48.165	start	1	non-tty	login
09:46:48.166	stop	2	non-tty	clear alarm 130 <cr>
09:46:48.166	stop	2	non-tty	clear alarm 0 <cr>
09:46:48.167	stop	1	non-tty	logout
09:46:48.168	stop	1	non-tty	logout
09:46:48.168	start	1	1	login
09:46:48.169	start	1	2	login
09:46:48.169	stop	2	1	show version | no-more <cr>
09:46:48.170	stop	2	2	show version | no-more <cr>
09:46:53.198	stop	3	1	show version | no-more <cr>
09:46:53.199	stop	3	2	show version | no-more <cr>
09:46:53.201	stop	4	1	show version | no-more <cr>
09:46:53.202	stop	4	2	show version | no-more <cr>
09:46:58.232	stop	1	1	logout
09:46:58.234	stop	1	2	logout
09:47:03.258	start	1	non-tty	login
09:47:03.259	stop	2	non-tty	set alarm yellow alarm-id 0 <cr>
09:47:03.261	start	1	non-tty	login
09:47:03.262	stop	1	non-tty	logout
09:47:03.264	stop	1	non-tty	logout`

// The accounting key is flags/task_id/port/vector: a retransmission is the
// same request. Where the device asks port49 about no command, only records
// of a typed command count; session START and STOP are
// l94SessionAccounting's.
func TestL94AccountingDuplicatesAreKeyedByTheRequest(t *testing.T) {
	typed := []l80Typed{{Session: 0, Command: "show version | no-more"}, {Session: 1, Command: "show version | no-more"},
		{Session: 0, Command: "show system users"}}
	evs := l94AcctRows(t, l94VJunosC1Acct)
	if got := l94Dup("juniper_junos", evs, typed); len(got) != 0 {
		t.Errorf("vJunos c1 as measured: %v", got)
	}
	// Two vtys with the same task_id and vector, 1s or more apart: two requests.
	two := l94AcctRows(t, "09:46:48.169\tstop\t2\t1\tshow version | no-more <cr>\n09:46:49.500\tstop\t2\t2\tshow version | no-more <cr>")
	if got := l94Dup("juniper_junos", two, typed); len(got) != 0 {
		t.Errorf("two vtys, one task_id: %v", got)
	}
	// The same port, task_id and vector 1s or more apart: a retransmission.
	again := append(slices.Clone(evs), l94AcctRows(t, "09:46:54.300\tstop\t3\t1\tshow version | no-more <cr>")...)
	if got := l94Dup("juniper_junos", again, typed); len(got) != 1 ||
		!strings.Contains(got[0], `account flags/task_id/port/vector stop/3/1/"show version | no-more <cr>" recorded 2 times`) {
		t.Errorf("a repeat on port 1: %v", got)
	}
	// Non-tty and the config session repeat 1s or more apart, and are not
	// counted where no command is asked.
	sys := l94AcctRows(t, "09:46:48.164\tstart\t1\tnon-tty\tlogin\n09:47:03.258\tstart\t1\tnon-tty\tlogin\n"+
		"09:46:48.164\tstop\t1\t0\tcommit and-quit <cr>\n09:47:03.300\tstop\t1\t0\tcommit and-quit <cr>")
	if got := l94Dup("juniper_junos", sys, typed); len(got) != 0 {
		t.Errorf("non-tty and port 0 on Junos: %v", got)
	}
	// Where commands are asked, every record counts, as before.
	if got := l94Dup("cisco_nxos", sys, typed); len(got) != 2 {
		t.Errorf("the same records on NX-OS: %v", got)
	}
	// NX-OS's measured shape (decisions-cisco_nxos.jsonl, 2026-11-12 07:58):
	// session records at port 0 with no vector, STOP pairs 17-19ms apart.
	nx := l94AcctRows(t, "07:58:37.723\tstart\t172.100.100.1@pts/4\t0\t\n07:58:37.739\tstart\t172.100.100.1@pts/5\t0\t\n"+
		"07:58:54.942\tstop\t172.100.100.1@pts/5\t0\t\n07:58:54.961\tstop\t172.100.100.1@pts/5\t0\t\n"+
		"07:58:57.941\tstop\t172.100.100.1@pts/4\t0\t\n07:58:57.958\tstop\t172.100.100.1@pts/4\t0\t")
	if got := l94Dup("cisco_nxos", nx, nil); len(got) != 0 {
		t.Errorf("NX-OS as measured: %v", got)
	}
	if got := l94Dup("cisco_nxos", append(nx, l94AcctRows(t, "07:58:59.000\tstop\t172.100.100.1@pts/4\t0\t")...), nil); len(got) != 1 {
		t.Errorf("NX-OS, a third STOP 1s on: %v", got)
	}
	// One session's task_id on two commands, 2s apart: two requests.
	cmds := l94AcctRows(t, "07:58:40.000\tstop\t172.100.100.1@pts/4\t0\tshow version\n07:58:42.000\tstop\t172.100.100.1@pts/4\t0\tshow users")
	if got := l94Dup("cisco_nxos", cmds, nil); len(got) != 0 {
		t.Errorf("two commands under one task_id: %v", got)
	}
}

// l94VJunosC4 is a Junos c4 grade in vJunos 26's measured shapes (fixed c1,
// 2026-11-12): the two per-login connections port49 closes (server-fin) and
// the one that stays open and carries the accounting bursts about 5s apart
// (l94VJunosC1Acct); each session's three permitted commands ran and its
// denied one was refused on the device.
func l94VJunosC4(t *testing.T) l94Grade {
	p, _ := l94PlatformFor("vjunos26")
	var typed []l80Typed
	for range 3 {
		for s := range 2 {
			typed = append(typed, l80Typed{Session: s, Command: "show version | no-more", Took: 0.25},
				l80Typed{Session: s, Command: "show system users", Denied: true, Took: 0.25})
		}
	}
	evs := l94AcctRows(t, l94VJunosC1Acct)
	// The hold went on before the first record and off after the last, and
	// held every reply between.
	hold := l94HoldWindow{On: l94At(t, "09:46:48.000"), Off: l94At(t, "09:47:04.000"), Held: len(evs)}
	return l94Grade{Arm: "fixed", Cell: "c4", Platform: "juniper_junos", P: p, Typed: typed,
		Events: evs, Conns: 3, MostOpen: 1, Ends: []string{"server-fin", "server-fin", "open"}, Hold: hold,
		Suspect: true, DeadOrSSL: 1, Baseline: &l94Baseline{Conns: 3, HasConns: true, Suspect: 1, HasSuspect: true}}
}

// Round 10: c4 on Junos. The device opens a connection per login, so c2/c3
// never put two requests on one connection, but its accounting rides the one
// connection that stays open: c4 holds each accounting reply 1.5s on it.
// It stops if the device drops that connection, repeats a record, or loses
// a session's accounting; a dead-server mark is l94SuspectMarks', compared to
// the baseline arm's c1 (the same loop, unheld).
func TestL94JunosC4Stops(t *testing.T) {
	if got := l94CellNames("junos", "fixed"); !slices.Equal(got, []string{"c1", "c2", "c3", "c4", "c5"}) {
		t.Errorf("junos fixed: %v", got)
	}
	if slices.Contains(l94CellNames("junos", "baseline"), "c4") {
		t.Error("the baseline build has no hold")
	}
	g := l94VJunosC4(t)
	if got := l94Stops(g); len(got) != 0 {
		t.Fatalf("vJunos's measured shape stops: %q", got)
	}
	if got := l94Findings(g); !slices.Equal(got, []string{"c4: device opens a connection per login (baseline 3, fixed 3)"}) {
		t.Errorf("findings %q", got)
	}
	drop := func(port, vector string) func(*l94Grade) {
		return func(g *l94Grade) {
			for i, e := range g.Events {
				if e.Port == port && e.Vector == vector {
					g.Events = slices.Delete(slices.Clone(g.Events), i, i+1)
					return
				}
			}
			t.Fatalf("no %s %q", port, vector)
		}
	}
	cases := map[string]func(*l94Grade){
		"c4: the device closed 1 connection(s) first (device-rst/device-fin) while accounting replies were held": func(g *l94Grade) { g.Ends = []string{"server-fin", "device-rst", "open"} },
		"c4: no connection was open at the cell's end: the device dropped the held accounting connection":        func(g *l94Grade) { g.Ends = []string{"server-fin", "server-fin", "server-fin"} },
		`c4: "show version | no-more": 5 accounting record(s), 6 ran: a session's accounting was lost`:           drop("2", "show version | no-more <cr>"),
		"c4: port 2 carried typed commands, but its session has no accounting STOP":                              drop("2", "logout"),
		"c4: port 1 carried typed commands, but its session has no accounting START":                             drop("1", "login"),
		`c4: account flags/task_id/port/vector stop/3/1/"show version | no-more <cr>" recorded 2 times`: func(g *l94Grade) {
			g.Events = append(slices.Clone(g.Events), l94AcctRows(t, "09:46:54.300\tstop\t3\t1\tshow version | no-more <cr>")...)
		},
		"c4: 2 suspect device debug line(s), the baseline arm's 1":                 func(g *l94Grade) { g.DeadOrSSL = 2 },
		"c4: 4 TLS connection(s), the baseline arm's 3: port49 forced a reconnect": func(g *l94Grade) { g.Conns = 4 },
		`c4: session 0 "show version | no-more" took 7.00s, over`:                  func(g *l94Grade) { g.Typed[0].Took = 7 },
		"c4: typed commands' accounting on 1 port(s), want 2 (one per session)":    func(g *l94Grade) { g.Events = l94KeepPort(g.Events, "1") },
	}
	for want, mut := range cases {
		g := l94VJunosC4(t)
		g.Typed = slices.Clone(g.Typed)
		mut(&g)
		if got := strings.Join(l94Stops(g), "\n"); !strings.Contains(got, want) {
			t.Errorf("%s: stops %q", want, got)
		}
	}
	// Round 10b: a record of the denied command (refused on the device, so
	// it did not run) does not offset a lost record of the permitted one:
	// six typed-command records against six that ran, but the permitted
	// command has five. Each command is counted on its own.
	off := l94VJunosC4(t)
	drop("2", "show version | no-more <cr>")(&off)
	off.Events = append(off.Events, l94AcctRows(t, "09:46:53.300\tstop\t12\t2\tshow system users <cr>")...)
	if got := strings.Join(l94Stops(off), "\n"); !strings.Contains(got, `c4: "show version | no-more": 5 accounting record(s), 6 ran: a session's accounting was lost`) {
		t.Errorf("a denied command's record offsets a lost permitted one: stops %q", got)
	}
	// Where commands are asked (NX-OS), the session accounting stays
	// l94SessionAccounting's, and its one connection is the held one.
	n := l94Clean()
	n.Cell, n.Ends = "c4", []string{"open"}
	if got := l94Stops(n); len(got) != 0 {
		t.Errorf("NX-OS c4 clean: %q", got)
	}
	n.Ends = []string{"device-fin"}
	if got := strings.Join(l94Stops(n), "\n"); !strings.Contains(got, "dropped the held accounting connection") {
		t.Errorf("NX-OS c4, its connection closed: %q", got)
	}
}

// vJunos 26 c4 r2 (2026-11-12): the hold build held every accounting reply
// from start, so the backlog vJunos drained after the harness's login (26
// records, one per held reply) kept a connection open past the clean-start
// wait. c4's hold goes on only once the clean point is reached; a wait that
// fails never switches it on; other cells have none.
func TestL94C4HoldsOnlyFromTheCleanPoint(t *testing.T) {
	clean := time.Date(2026, 11, 12, 11, 23, 0, 0, time.UTC)
	var order []string
	wait := func() (time.Time, error) { order = append(order, "wait"); return clean, nil }
	on := func() (time.Time, error) { order = append(order, "on"); return clean.Add(time.Millisecond), nil }
	cleanAt, onAt, err := l94CleanThenHold(wait, on)
	if err != nil || !cleanAt.Equal(clean) || !onAt.Equal(clean.Add(time.Millisecond)) {
		t.Fatalf("cleanAt %v onAt %v err %v", cleanAt, onAt, err)
	}
	if !slices.Equal(order, []string{"wait", "on"}) {
		t.Errorf("order %v: the hold must go on after the clean point, not before", order)
	}
	order = nil
	stuck := func() (time.Time, error) {
		order = append(order, "wait")
		return time.Time{}, errors.New("1 connections still open")
	}
	if _, _, err := l94CleanThenHold(stuck, on); err == nil || !slices.Equal(order, []string{"wait"}) {
		t.Errorf("a failed clean-start wait: err %v order %v; the hold must stay off", err, order)
	}
	if _, onAt, err := l94CleanThenHold(wait, nil); err != nil || !onAt.IsZero() {
		t.Errorf("no hold: onAt %v err %v", onAt, err)
	}
}

// The control file: l94HoldOn creates it empty; the hold build appends a
// line per held reply; l94HoldOff counts them and removes it.
func TestL94HoldControlFileCountsHeldReplies(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hold")
	t0 := time.Now()
	onAt, err := l94HoldOn(path)
	if err != nil || onAt.Before(t0) {
		t.Fatalf("on: %v at %v", err, onAt)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("held\nheld\nheld\n")
	f.Close()
	held, offAt, err := l94HoldOff(path)
	if err != nil || held != 3 || offAt.Before(onAt) {
		t.Errorf("off: held %d at %v err %v, want 3", held, offAt, err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the control file outlived the cell: %v", err)
	}
	if _, _, err := l94HoldOff(path); err == nil {
		t.Error("a control file already gone counts nothing: that is an error")
	}
}

// c4 measures held replies: an accounting record written while the hold was
// on, past its count of held replies, was answered without it.
func TestL94C4StopsOnAnUnheldAccountingRecord(t *testing.T) {
	g := l94VJunosC4(t)
	g.Hold.Held--
	want := fmt.Sprintf("c4: %d accounting record(s) while the hold was on, %d held: a reply went out without the hold", len(g.Events), len(g.Events)-1)
	if got := strings.Join(l94Stops(g), "\n"); !strings.Contains(got, want) {
		t.Errorf("one reply unheld: stops %q", got)
	}
	// Records before the hold went on (the device's own backlog) are not
	// the cell's: they drained unheld.
	g = l94VJunosC4(t)
	g.Hold.On, g.Hold.Held = l94At(t, "09:46:53.000"), len(g.Events)-10
	if got := l94Stops(g); len(got) != 0 {
		t.Errorf("records before the hold went on: %q", got)
	}
	g = l94VJunosC4(t)
	g.Hold.Err = "open hold: no such file or directory"
	if got := strings.Join(l94Stops(g), "\n"); !strings.Contains(got, "c4: the accounting hold: open hold: no such file or directory") {
		t.Errorf("hold error: stops %q", got)
	}
	g = l94VJunosC4(t)
	g.Hold = l94HoldWindow{}
	if got := strings.Join(l94Stops(g), "\n"); !strings.Contains(got, "c4: the accounting hold was never measured") {
		t.Errorf("no hold: stops %q", got)
	}
	// c1 has no hold.
	c1 := l94Clean()
	c1.Hold = l94HoldWindow{}
	if got := l94Stops(c1); len(got) != 0 {
		t.Errorf("c1: %q", got)
	}
}

// l94KeepPort is evs less every vty record but port's (non-tty and port 0
// stay).
func l94KeepPort(evs []l94Event, port string) []l94Event {
	var out []l94Event
	for _, e := range evs {
		if e.Port == port || e.Port == "non-tty" || e.Port == "0" {
			out = append(out, e)
		}
	}
	return out
}

// The collection waits for the accounting where no command is asked:
// l94AcctComplete is the predicate, true once nothing is lost.
func TestL94AcctCompleteWaitsForEveryTypedRecord(t *testing.T) {
	g := l94VJunosC4(t)
	if !l94AcctComplete(g.Platform, g.Events, g.Typed, 2) {
		t.Error("the measured shape is complete")
	}
	if l94AcctComplete(g.Platform, g.Events[:12], g.Typed, 2) {
		t.Error("a burst still to come is not complete")
	}
	if !l94AcctComplete("cisco_nxos", nil, g.Typed, 2) {
		t.Error("where commands are asked there is nothing to wait for")
	}
}

// c4 is compared to the baseline arm's c1: the baseline plays no c4.
func TestL94C4IsComparedToTheBaselinesC1(t *testing.T) {
	for cell, want := range map[string]string{"c1": "c1", "c2": "c2", "c3": "c3", "c4": "c1", "c5": "c5"} {
		if got := l94BaselineCell(cell); got != want {
			t.Errorf("%s: %s", cell, got)
		}
	}
}

// The port comes from the record's session.port.
func TestL94EventsCarryTheSessionPort(t *testing.T) {
	evs := l94Events([]map[string]any{{"event": "account", "ts": "2026-11-12T09:46:48.169Z", "flags": "stop", "task_id": "2",
		"session": map[string]any{"port": "1"}, "record": map[string]any{"vector": []any{"show", "version"}}}})
	if len(evs) != 1 || evs[0].Port != "1" {
		t.Fatalf("%+v", evs)
	}
}

func l94Clean() l94Grade {
	p, _ := l94PlatformFor("nxos106")
	// Its records carry no time: as c4, a hold from the zero time on that
	// held each of its four accounting replies.
	hold := l94HoldWindow{Off: time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC), Held: len(l94SessionAcct())}
	return l94Grade{Arm: "fixed", Cell: "c1", Platform: "cisco_nxos", P: p, Conns: 1, MostOpen: 1, Ends: []string{"open"}, Hold: hold,
		Typed:  []l80Typed{{Command: "show version", Asked: true}, {Command: "show users", Asked: true, Denied: true}},
		Events: append(l94SessionAcct(), l94Event{Event: "authorize_command", Verdict: "permit", Vector: "show version"}, l94Event{Event: "authorize_command", Verdict: "deny", Vector: "show users"})}
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

// vJunos opens a TLS connection per login in both arms (L94 evidence,
// vJunos 26: c1 3 and 3, c2 5 and 5, c3 9 and 9, baseline and fixed). Where
// the baseline cell held more than one, the count is a finding unless the
// fixed arm opened more (port49 forced a reconnect); how many were open at
// once is overlap timing and is not compared. NX-OS's baseline held one, so
// a second connection there still stops.
func TestL94ConnectionCountIsGradedAgainstTheBaseline(t *testing.T) {
	grade := func(g l94Grade) (stops, finds []string) {
		for _, s := range l94Stops(g) {
			if strings.Contains(s, "TLS connection") {
				stops = append(stops, s)
			}
		}
		return stops, l94Findings(g)
	}
	p, _ := l94PlatformFor("vjunos26")
	j := l94Grade{Arm: "fixed", Cell: "c3", Platform: "juniper_junos", P: p, Conns: 9, MostOpen: 5,
		Baseline: &l94Baseline{Conns: 9, HasConns: true}}
	if s, f := grade(j); len(s) != 0 || !slices.Equal(f, []string{"c3: device opens a connection per login (baseline 9, fixed 9)"}) {
		t.Errorf("vJunos 9 and 9: stops %q findings %q", s, f)
	}
	j.Conns = 7
	if s, f := grade(j); len(s) != 0 || len(f) != 1 {
		t.Errorf("vJunos 7 against 9: stops %q findings %q", s, f)
	}
	j.Conns = 10
	if s, f := grade(j); len(f) != 0 || len(s) != 1 || !strings.Contains(s[0], "c3: 10 TLS connection(s), the baseline arm's 9: port49 forced a reconnect") {
		t.Errorf("vJunos 10 against 9: stops %q findings %q", s, f)
	}
	j.Conns, j.Baseline = 9, &l94Baseline{HasSuspect: true}
	if s, f := grade(j); len(f) != 0 || len(s) != 1 || !strings.Contains(s[0], "must hold exactly one") {
		t.Errorf("no baseline connection count: stops %q findings %q", s, f)
	}
	j.Baseline = &l94Baseline{Conns: 9, HasConns: true}
	j.Arm = "baseline"
	if s, f := grade(j); len(s) != 0 || len(f) != 0 {
		t.Errorf("the baseline arm: stops %q findings %q", s, f)
	}
	n := l94Clean()
	n.Conns, n.Baseline = 2, &l94Baseline{Conns: 1, HasConns: true}
	if s, f := grade(n); len(f) != 0 || len(s) != 1 || !strings.Contains(s[0], "c1: 2 TLS connection(s), 1 open at once: the cell must hold exactly one") {
		t.Errorf("NX-OS 2 against 1: stops %q findings %q", s, f)
	}
}

// The baseline's connection count is the length of its committed
// <cell>.tls.json, the capture's connection list.
func TestL94ReadBaselineCountsItsConnections(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{"c3-typed.json": "[]", "c3-a.json": "[]",
		"c3.tls.json":   `[{"server":"172.100.100.1:300","device_port":1},{"server":"172.100.100.1:300","device_port":2}]`,
		"c1-typed.json": "[]", "c1-a.json": "[]"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if b := l94ReadBaseline(t, dir, "c3"); b == nil || b.Conns != 2 || !b.HasConns {
		t.Errorf("c3: %+v", b)
	}
	if b := l94ReadBaseline(t, dir, "c1"); b == nil || b.HasConns {
		t.Errorf("c1, no tls.json: %+v", b)
	}
}

// The merge criteria, one at a time, on the fixed arm; the baseline stops on nothing.
func TestL94StopsAreTheMergeCriteria(t *testing.T) {
	if got := l94Stops(l94Clean()); len(got) != 0 {
		t.Fatalf("a clean c1 stops: %v", got)
	}
	cases := map[string]func(*l94Grade){
		"lost or run unasked": func(g *l94Grade) { g.Typed[0].Asked = false },
		"ran":                 func(g *l94Grade) { g.Typed[1].Denied = false },
		"retransmitted": func(g *l94Grade) {
			e := g.Events[0]
			e.TS = e.TS.Add(2 * time.Second)
			g.Events = append(g.Events, e)
		},
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
	bSHA := decision.CredentialHash([]byte(l94RefusedCredential()))
	for _, cell := range []string{"c2", "c3"} {
		fails := 1
		if cell == "c3" {
			fails = l94C3Fails
		}
		clean := func() l94Grade {
			g := l94Grade{Arm: "fixed", Cell: cell, Platform: "juniper_junos", P: p, Conns: 1, MostOpen: 1,
				Typed: []l80Typed{{Command: "show version | no-more", Took: 0.3}}, Gaps: []time.Duration{300 * time.Millisecond},
				BLogin: &l94Outcome{LoggedIn: true, Took: 1.1}, BSHA: bSHA,
				Events: []l94Event{{TS: t0.Add(-5 * time.Second), Event: "redeem", Verdict: "permit"}, // B's session
					{TS: t0.Add(1200 * time.Millisecond), Event: "redeem", Verdict: "permit", Cred: bSHA}}} // B's login, inside the delay
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

// Round 5, on the committed NX-OS evidence (1c1d105c, offered c5): after
// the restart port49 itself denied "show version" (context_missing: the
// memory store lost the context), typed 05:06:26.718, read 26.737, and the
// baseline does the same. Round 6: that is the one exemption. A permitted
// command refused stops in every other case: a port49 deny in c1-c4 (port49
// wrongly denying it is the failure), a c5 deny with another reason, a
// device refusal of a port49 permit, and, with no record, the old rule (c5
// only inside the restart window is exempt).
func TestL94PermittedRefusedMeansPort49PermittedIt(t *testing.T) {
	grade := func(cell string, last *l94Event) string {
		g := l94Clean()
		g.Cell = cell
		g.RestartAt, g.UpAt = l94At(t, "05:06:18.953"), l94At(t, "05:06:19.208")
		if cell == "c5" {
			g.Conns = 2
		}
		g.Typed = []l80Typed{
			{Command: "show version", Asked: true, At: l94At(t, "05:06:16.949")},
			{Command: "show version", Asked: true, Denied: true, At: l94At(t, "05:06:26.718")},
		}
		g.Events = append(l94SessionAcct(),
			l94Event{TS: l94At(t, "05:06:16.969"), Event: "authorize_command", Verdict: "permit", Vector: "show version"})
		if last != nil {
			e := *last
			e.TS, e.Event, e.Vector = l94At(t, "05:06:26.737"), "authorize_command", "show version"
			g.Events = append(g.Events, e)
		}
		return strings.Join(l94Stops(g), "\n")
	}
	const want = "a permitted command was refused"
	cases := []struct {
		name, cell string
		last       *l94Event
		stop       bool
	}{
		{"c5 context_missing deny", "c5", &l94Event{Verdict: "deny", Reason: "context_missing"}, false},
		{"c1 port49 deny", "c1", &l94Event{Verdict: "deny", Reason: "no_permit_dominates_deny"}, true},
		{"c1 context_missing deny", "c1", &l94Event{Verdict: "deny", Reason: "context_missing"}, true},
		{"c5 deny, another reason", "c5", &l94Event{Verdict: "deny", Reason: "no_permit_dominates_deny"}, true},
		{"c5 permit the device refused", "c5", &l94Event{Verdict: "permit"}, true},
		{"c1 permit the device refused", "c1", &l94Event{Verdict: "permit"}, true},
		{"c5 after UpAt, no record", "c5", nil, true},
		{"c1 no record", "c1", nil, true},
	}
	for _, c := range cases {
		if got := strings.Contains(grade(c.cell, c.last), want); got != c.stop {
			t.Errorf("%s: stop=%v, want %v", c.name, got, c.stop)
		}
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

// vJunos fixed r2 and c4 ended INVALID at qualStillClean twice: the device
// opens accounting connections on its own schedule, between the gauge's 0
// and the capture's start. The capture now starts first; the clean point is
// the start of the first read that came back 0.
func TestL94WaitCleanIsTheFirstZeroRead(t *testing.T) {
	t0 := l94At(t, "09:46:40.000")
	clock := t0
	now := func() time.Time { return clock }
	sleep := func(d time.Duration) { clock = clock.Add(d) }
	reads := []float64{1, 0, 1}
	read := func() (float64, bool) {
		v := reads[0]
		reads = reads[1:]
		clock = clock.Add(5 * time.Millisecond) // the scrape takes time
		return v, true
	}
	at, err := l94WaitClean(read, 60, sleep, now)
	if err != nil || !at.Equal(t0.Add(time.Second+5*time.Millisecond)) {
		t.Errorf("gauge 1 then 0: %s %v, want the second read's start", at.Format("15:04:05.000"), err)
	}
	none := func() (float64, bool) { return 0, false }
	if at, err := l94WaitClean(none, 60, sleep, now); err != nil || at.IsZero() {
		t.Errorf("no series is no connection: %s %v", at, err)
	}
	busy := func() (float64, bool) { return 2, true }
	if _, err := l94WaitClean(busy, 3, sleep, now); err == nil || !strings.Contains(err.Error(), "INVALID: 2 connections still open after 3s") {
		t.Errorf("never 0: %v", err)
	}
}

// l94SinceClean keeps the connections whose SYN is at or after the clean
// point, sets aside one before it only if it closed before it (the gauge's
// 0 says so of every connection port49 accepted), and is INVALID for one
// opened before it and still open after: a SYN port49 had not accepted when
// the gauge read 0, or a capture that did not start clean.
func TestL94SinceCleanNeverLoosensTheCleanStart(t *testing.T) {
	clean := l94At(t, "09:46:46.000")
	conn := func(port uint16, syn, end string, how string) l73Conn {
		c := l73Conn{Server: "172.100.100.1:300", DevicePort: port, SYNAt: l94At(t, syn), End: how}
		if end != "" {
			c.EndAt = l94At(t, end)
		}
		return c
	}
	// vJunos fixed c1's shape, all after the clean point: kept whole.
	c1 := []l73Conn{conn(58970, "09:46:46.184", "09:46:46.195", "server-fin"),
		conn(58982, "09:46:46.285", "09:46:46.295", "server-fin"), conn(48328, "09:46:48.152", "", "open")}
	kept, pre, err := l94SinceClean(c1, clean)
	if err != nil || len(kept) != 3 || len(pre) != 0 {
		t.Errorf("vJunos c1: kept %d pre %d %v", len(kept), len(pre), err)
	}
	// An accounting connection that opened and closed before the clean point.
	early := conn(41000, "09:46:45.100", "09:46:45.900", "server-fin")
	kept, pre, err = l94SinceClean(append([]l73Conn{early}, c1...), clean)
	if err != nil || len(kept) != 3 || len(pre) != 1 || pre[0].DevicePort != 41000 {
		t.Errorf("closed before: kept %d pre %v %v", len(kept), pre, err)
	}
	for name, c := range map[string]l73Conn{
		"still open":         conn(41002, "09:46:45.100", "", "open"),
		"closed after clean": conn(41004, "09:46:45.100", "09:46:46.300", "server-fin"),
	} {
		if _, _, err := l94SinceClean(append([]l73Conn{c}, c1...), clean); err == nil ||
			!strings.Contains(err.Error(), "INVALID: the connection from device port") || !strings.Contains(err.Error(), "the capture did not start clean") {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A SYN exactly at the clean point is the cell's.
	at := conn(41006, "09:46:46.000", "", "open")
	if kept, pre, err := l94SinceClean([]l73Conn{at}, clean); err != nil || len(kept) != 1 || len(pre) != 0 {
		t.Errorf("SYN at the clean point: kept %d pre %d %v", len(kept), len(pre), err)
	}
}

// l94Splice is a's savefile with b's records after a's (b's file header
// dropped): one capture holding both flows.
func l94Splice(a, b []byte) []byte {
	return append(append([]byte{}, a...), b[24:]...)
}

// A connection whose SYN came before tcpdump was live is no l73Conn
// (l73Conns counts from a captured SYN), so l94SinceClean never sees it.
// l94OlderThanCapture scans the same savefile, headers only, for a flow to
// the server port with packets but no captured device SYN: one with a
// packet at or after the clean point is INVALID, unless the server only
// reset it (stale, a finding); one wholly before is ignored.
func TestL94RefusesAConnectionOlderThanItsCapture(t *testing.T) {
	clean := l94At(t, "09:46:46.000")
	at := func(c string) time.Time { return l94At(t, c) }
	// A cell connection, its SYN captured after the clean point.
	cellConn := l73FakePcap(48328, l73TLSPort, []l73FakeSeg{
		{true, tcpSYN, 1000, nil, at("09:46:48.152")}, {false, tcpSYN | tcpACK, 5000, nil, at("09:46:48.153")},
		{true, tcpACK, 1001, nil, at("09:46:48.154")}})
	if _, err := l94OlderThanCapture(cellConn, l73TDevice, l73TLSPort, clean, nil); err != nil {
		t.Errorf("a captured SYN: %v", err)
	}
	orphan := func(port uint16, segs ...l73FakeSeg) []byte { return l73FakePcap(port, l73TLSPort, segs) }
	// Packets of a connection that was open before the capture, the last
	// after the clean point: INVALID, whichever side sent it.
	for name, o := range map[string][]byte{
		"device's packet after": orphan(41000, l73FakeSeg{true, tcpACK, 7000, nil, at("09:46:45.500")}, l73FakeSeg{true, tcpACK | tcpPSH, 7000, nil, at("09:46:46.200")}),
		"server's packet after": orphan(41000, l73FakeSeg{true, tcpACK, 7000, nil, at("09:46:45.500")}, l73FakeSeg{false, tcpACK, 9000, nil, at("09:46:46.000")}),
	} {
		_, err := l94OlderThanCapture(l94Splice(cellConn, o), l73TDevice, l73TLSPort, clean, nil)
		if err == nil || !strings.Contains(err.Error(), "INVALID: a connection older than the capture") || !strings.Contains(err.Error(), "device port 41000") {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Wholly before the clean point: ignored, as the gauge's 0 says it ended.
	before := orphan(41002, l73FakeSeg{true, tcpACK, 7000, nil, at("09:46:45.500")}, l73FakeSeg{true, tcpFIN | tcpACK, 7000, nil, at("09:46:45.900")})
	if _, err := l94OlderThanCapture(l94Splice(cellConn, before), l73TDevice, l73TLSPort, clean, nil); err != nil {
		t.Errorf("an old flow wholly before the clean point: %v", err)
	}
	// Another server port is not the cell's TLS server.
	other := l73FakePcap(41004, 49, []l73FakeSeg{{true, tcpACK, 7000, nil, at("09:46:47.000")}})
	if _, err := l94OlderThanCapture(l94Splice(cellConn, other), l73TDevice, l73TLSPort, clean, nil); err != nil {
		t.Errorf("port 49: %v", err)
	}
	// A reused source port: the old flow's packets before the clean point,
	// then a new connection's captured SYN on the same port: not an orphan.
	reused := orphan(41006, l73FakeSeg{true, tcpACK, 7000, nil, at("09:46:45.500")},
		l73FakeSeg{true, tcpSYN, 8000, nil, at("09:46:47.000")}, l73FakeSeg{false, tcpSYN | tcpACK, 9000, nil, at("09:46:47.001")})
	if _, err := l94OlderThanCapture(reused, l73TDevice, l73TLSPort, clean, nil); err != nil {
		t.Errorf("a reused port with its SYN captured: %v", err)
	}
	// Stale: the server's only answer after the clean point is a RST, with
	// no data from it anywhere: port49 had no socket for the flow, and the
	// server's kernel reset the device's write (cEOS 4.36 baseline c3,
	// 2026-11-12: a c2 connection port49d's stop left open on the device).
	// A finding, not INVALID; the cell grades on.
	rst := orphan(41008, l73FakeSeg{true, tcpACK, 7000, nil, at("09:46:45.500")}, l73FakeSeg{false, tcpRST, 9000, nil, at("09:46:46.100")})
	stale, err := l94OlderThanCapture(rst, l73TDevice, l73TLSPort, clean, nil)
	want := "device port 41008 sent a packet on a connection from before the capture at 09:46:45.500; the server reset it (no socket): the device carried a stale connection into the cell"
	if err != nil || !slices.Equal(stale, []string{want}) {
		t.Errorf("a server RST alone after the clean point: stale %q err %v", stale, err)
	}
	// cEOS's shape: the device's write after the clean point, the server's
	// RST at once; a pure ACK of the server's before the clean point is
	// allowed.
	ceos := orphan(41012, l73FakeSeg{false, tcpACK, 9000, nil, at("09:46:45.600")},
		l73FakeSeg{true, tcpACK | tcpPSH, 7000, []byte{1, 2, 3}, at("09:46:46.561")}, l73FakeSeg{false, tcpRST, 9000, nil, at("09:46:46.561")})
	stale, err = l94OlderThanCapture(l94Splice(cellConn, ceos), l73TDevice, l73TLSPort, clean, nil)
	want = "device port 41012 sent a packet on a connection from before the capture at 09:46:46.561; the server reset it (no socket): the device carried a stale connection into the cell"
	if err != nil || !slices.Equal(stale, []string{want}) {
		t.Errorf("cEOS's stale write: stale %q err %v", stale, err)
	}
	// The same shape while port49 refused a connection in the cell: port49
	// may have accepted the pre-capture SYN after the 0 read and reset it
	// itself (reset at Accept: shed, held, declined). INVALID.
	refused := []string{`port49_connections_shed_total{reason="global_cap"} +1`}
	stale, err = l94OlderThanCapture(l94Splice(cellConn, ceos), l73TDevice, l73TLSPort, clean, refused)
	if err == nil || stale != nil || !strings.Contains(err.Error(), "device port 41012") ||
		!strings.Contains(err.Error(), `port49 refused connections in the cell (port49_connections_shed_total{reason="global_cap"} +1)`) {
		t.Errorf("a reset while port49 refused: stale %q err %v", stale, err)
	}
	// Anything else from the server is a socket port49 had: INVALID.
	dev := l73FakeSeg{true, tcpACK | tcpPSH, 7000, []byte{1, 2, 3}, at("09:46:46.500")}
	for name, o := range map[string][]byte{
		"server ACK after the clean point":  orphan(41014, dev, l73FakeSeg{false, tcpACK, 9000, nil, at("09:46:46.501")}, l73FakeSeg{false, tcpRST, 9000, nil, at("09:46:46.600")}),
		"server data after the clean point": orphan(41014, dev, l73FakeSeg{false, tcpACK | tcpPSH, 9000, []byte{4, 5}, at("09:46:46.501")}, l73FakeSeg{false, tcpRST, 9000, nil, at("09:46:46.600")}),
		"server data before the clean point": orphan(41014, l73FakeSeg{false, tcpACK | tcpPSH, 9000, []byte{4, 5}, at("09:46:45.501")},
			dev, l73FakeSeg{false, tcpRST, 9000, nil, at("09:46:46.600")}),
		"a RST carrying data":        orphan(41014, dev, l73FakeSeg{false, tcpRST | tcpACK, 9000, []byte{4}, at("09:46:46.501")}),
		"the device's write, no RST": orphan(41014, dev),
		"server FIN after the clean": orphan(41014, dev, l73FakeSeg{false, tcpFIN | tcpACK, 9000, nil, at("09:46:46.501")}),
		"server RST and then ACK":    orphan(41014, dev, l73FakeSeg{false, tcpRST, 9000, nil, at("09:46:46.501")}, l73FakeSeg{false, tcpACK, 9000, nil, at("09:46:46.502")}),
	} {
		stale, err := l94OlderThanCapture(l94Splice(cellConn, o), l73TDevice, l73TLSPort, clean, nil)
		if err == nil || !strings.Contains(err.Error(), "INVALID: a connection older than the capture") || !strings.Contains(err.Error(), "device port 41014") || stale != nil {
			t.Errorf("%s: stale %q err %v", name, stale, err)
		}
	}
	// Flows are keyed by device port and server, as l73Conns keys them: a
	// captured SYN from the same device port to another server (the lab's
	// second port49, 172.100.100.2) does not mask an orphan to the first.
	// In time order, as tcpdump writes: A's packet, B's SYN, A's packet.
	a1 := orphan(41010, l73FakeSeg{true, tcpACK, 7000, nil, at("09:46:45.500")})
	toB := l94ReServer(t, orphan(41010, l73FakeSeg{true, tcpSYN, 8000, nil, at("09:46:46.200")}, l73FakeSeg{false, tcpSYN | tcpACK, 9000, nil, at("09:46:46.201")}), "172.100.100.2")
	a2 := orphan(41010, l73FakeSeg{true, tcpACK | tcpPSH, 7000, nil, at("09:46:46.500")})
	if _, err := l94OlderThanCapture(l94Splice(l94Splice(a1, toB), a2), l73TDevice, l73TLSPort, clean, nil); err == nil ||
		!strings.Contains(err.Error(), "device port 41010") || !strings.Contains(err.Error(), "172.100.100.1:300") {
		t.Errorf("a SYN to another server on the same device port: %v", err)
	}
}

// The refusal series are every counter port49 moves when it resets or closes
// a connection it refused (internal/daemon/server: server.go's Accept,
// tls.go, conn.go), and nothing a served connection moves.
func TestL94RefusalsAreTheCountersOfARefusedConnection(t *testing.T) {
	before := l94Refusals(`# HELP port49_connection_events_total x
port49_connection_events_total{event="admission_closed"} 0
port49_connection_events_total{event="declined_refused"} 0
port49_connection_events_total{event="held_refused"} 0
port49_connection_events_total{event="idle_closed"} 4
port49_connection_events_total{event="key_miss_closed"} 0
port49_connection_events_total{event="refused_cap"} 0
port49_connection_events_total{event="single_connect_second_connection"} 2
port49_connection_events_total{event="tls_refused"} 1
port49_connection_events_total{event="transport_mismatch"} 0
port49_connection_events_total{event="unadmitted_source"} 0
port49_connections_shed_total{reason="global_cap"} 0
port49_tls_handshakes_total{outcome="ok"} 7
port49_tls_handshakes_total{outcome="resumed"} 1
port49_tls_handshakes_total{outcome="sni_mismatch"} 0
port49_tls_handshakes_total{outcome="status_unavailable"} 0
port49_connections{state="open"} 1
`)
	// Eight connection events, the shed, two TLS declines; not idle_closed,
	// a second connection, ok or resumed, which served connections move.
	if len(before) != 11 || before[`port49_connection_events_total{event="tls_refused"}`] != 1 {
		t.Errorf("the refusal series read: %v", before)
	}
	if got := l94RefusalMoves(before, before); got != nil {
		t.Errorf("nothing moved: %q", got)
	}
	served := l94Refusals("port49_connection_events_total{event=\"idle_closed\"} 9\nport49_tls_handshakes_total{outcome=\"ok\"} 9\n" +
		"port49_connection_events_total{event=\"single_connect_second_connection\"} 3\n")
	if len(served) != 0 {
		t.Errorf("served connections' series read as refusals: %v", served)
	}
	for _, s := range []string{
		`port49_connection_events_total{event="admission_closed"}`, `port49_connection_events_total{event="declined_refused"}`,
		`port49_connection_events_total{event="held_refused"}`, `port49_connection_events_total{event="key_miss_closed"}`,
		`port49_connection_events_total{event="refused_cap"}`, `port49_connection_events_total{event="tls_refused"}`,
		`port49_connection_events_total{event="transport_mismatch"}`, `port49_connection_events_total{event="unadmitted_source"}`,
		`port49_connections_shed_total{reason="global_cap"}`, `port49_tls_handshakes_total{outcome="sni_mismatch"}`,
		`port49_tls_handshakes_total{outcome="status_unavailable"}`,
	} {
		after := maps.Clone(before)
		after[s]++
		if got := l94RefusalMoves(before, after); !slices.Equal(got, []string{s + " +1"}) {
			t.Errorf("%s moved: %q", s, got)
		}
	}
	// A series that first appears in the cell moved from 0; a counter that
	// fell (port49d restarted, c5) counts from 0 again.
	after := maps.Clone(before)
	after[`port49_tls_handshakes_total{outcome="unknown_ca"}`] = 2
	if got := l94RefusalMoves(before, after); !slices.Equal(got, []string{`port49_tls_handshakes_total{outcome="unknown_ca"} +2`}) {
		t.Errorf("a new series: %q", got)
	}
	high := maps.Clone(before)
	high[`port49_connection_events_total{event="tls_refused"}`] = 5
	restarted := maps.Clone(before)
	restarted[`port49_connection_events_total{event="tls_refused"}`] = 2 // below 5: reset, then 2
	if got := l94RefusalMoves(high, restarted); !slices.Equal(got, []string{`port49_connection_events_total{event="tls_refused"} +2`}) {
		t.Errorf("a restarted counter: %q", got)
	}
}

// c5 restarts port49d: the first snapshot is the old daemon's, the last the
// new one's. The old daemon's refusals are counted to a snapshot taken just
// before the restart, and every count of the new daemon from 0.
func TestL94RefusalsAreCountedAcrossC5sRestart(t *testing.T) {
	s := `port49_connection_events_total{event="held_refused"}`
	o := `port49_connections_shed_total{reason="global_cap"}`
	before, pre, after := map[string]float64{s: 1, o: 0}, map[string]float64{s: 2, o: 0}, map[string]float64{s: 1, o: 0}
	if got := l94RefusalMovesAcross(before, pre, after); !slices.Equal(got, []string{s + " +2"}) {
		t.Errorf("before 1, pre-restart 2, after 1: %q, want +2", got)
	}
	// The old daemon refused nothing; the new one refused once.
	if got := l94RefusalMovesAcross(before, before, map[string]float64{s: 0, o: 1}); !slices.Equal(got, []string{o + " +1"}) {
		t.Errorf("the new daemon's refusal: %q", got)
	}
	if got := l94RefusalMovesAcross(before, before, map[string]float64{s: 0, o: 0}); got != nil {
		t.Errorf("no refusal on either daemon: %q", got)
	}
	// No restart (pre nil): before to after.
	if got := l94RefusalMovesAcross(before, nil, pre); !slices.Equal(got, []string{s + " +1"}) {
		t.Errorf("no restart: %q", got)
	}
}

// A RST is a minimum-size Ethernet frame: 54 bytes padded to 60. The
// padding is not data, or every kernel reset would read as port49's.
func TestL94TCPDataLenIgnoresEthernetPadding(t *testing.T) {
	pkt := make([]byte, 14+20+20+6)
	binary.BigEndian.PutUint16(pkt[12:], 0x0800)
	pkt[14] = 0x45
	binary.BigEndian.PutUint16(pkt[14+2:], 40)
	pkt[14+9] = 6
	pkt[14+20+12] = 5 << 4
	pkt[14+20+13] = tcpRST
	fl, ok := labpcap.FlowOf(labpcap.LinkEthernet, pkt)
	if !ok || fl.PayloadLen != 6 {
		t.Fatalf("flow %v %+v", ok, fl)
	}
	if n := l94TCPDataLen(pkt, fl); n != 0 {
		t.Errorf("a padded RST carries %d data bytes, want 0", n)
	}
	binary.BigEndian.PutUint16(pkt[14+2:], 43)
	if n := l94TCPDataLen(pkt, fl); n != 3 {
		t.Errorf("3 data bytes read as %d", n)
	}
}

// l94ReServer is raw (an l73FakePcap savefile) with the server's address,
// l73TServer, rewritten to server in every record's IPv4 header.
func l94ReServer(t *testing.T, raw []byte, server string) []byte {
	t.Helper()
	out := append([]byte{}, raw...)
	old, ip := net.ParseIP(l73TServer).To4(), net.ParseIP(server).To4()
	for off := 24; off+16 <= len(out); {
		n := int(binary.LittleEndian.Uint32(out[off+8:]))
		pkt := out[off+16 : off+16+n]
		for _, at := range []int{14 + 12, 14 + 16} {
			if bytes.Equal(pkt[at:at+4], old) {
				copy(pkt[at:at+4], ip)
			}
		}
		off += 16 + n
	}
	return out
}
