package lab

import (
	"crypto/rand"
	"errors"
	"fmt"
	"maps"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/blanketfish/port49/internal/decision"
)

// L94 (spec §15 L94; §13 decision 59, provisional on it): whether a device
// takes port49's replies to the sessions it multiplexes on one single-connect
// connection out of request order. These are the pure parts of l94_test.go:
// the cells, the platforms in the order they run, and the graders. Order is
// graded from the ts of port49's own records (authorize_command, account,
// redeem), never from the wire: the TACACS+ header is inside the TLS
// ciphertext and no body is decoded.
//
//	c1  natural interleave: two token-logged-in CLI sessions, 20 commands each
//	    (permitted and denied alternating), started ~100ms apart
//	c2  forced reorder: B logged in; A logs in with a refused credential
//	    (l94RefusedCredential: FAIL token_not_found after the 2s delay);
//	    within 200ms of A's request B types the permitted and the denied
//	    command
//	c3  queued FAILs: A1-A3 FAIL at once while B types every 250ms for 6s
//	c4  NX-OS only, fixed arm only: c1's loop on a port49d built with
//	    port49_lab_acct_hold, which holds every accounting reply 1.5s so the
//	    command authorization NX-OS writes behind an accounting record is
//	    answered first
//	c5  restart: L80's restart cell, with a session inside its FAIL delay at
//	    the restart

// l94FixCommit is decision 59's code (lanes). A rebase changes it; the
// baseline check then falls back to l94FixFile.
const (
	l94FixCommit = "dbe08cec"
	l94FixFile   = "internal/daemon/server/lanes.go"
	// l94BaselineCommit is main before decision 59: one reply at a time.
	l94BaselineCommit = "6eecb79b"
	// l94HoldTag is the lab-only tag c4's port49d is built with
	// (internal/daemon/acct/hold_lab.go; tests/ci keeps it out of releases).
	l94HoldTag = "port49_lab_acct_hold"
	// l94Delay is both failure-delay knobs (as L13's writeDelayConfig sets them).
	l94Delay = 2 * time.Second
	// l94Inside is c2's pass line: a B request port49 read under this after
	// A's read was answered inside A's delay. A redeem record's ts is its
	// read (newRecord, before the delay: internal/daemon/authen/authen.go:235),
	// as an authorize_command's is (Handle's start: author.go:245); the
	// baseline's B is read when A's delay runs out, +l94Delay.
	l94Inside = l94Delay - 250*time.Millisecond
	// l94AcctRepeat is how long after an accounting record's first copy a
	// repeat of its flags/task_id counts as a retransmission (l94Dup).
	l94AcctRepeat = time.Second
	// l94FastB is how long, at most, a B command may take on the fixed arm in
	// c2 (and the expectation in c3).
	l94FastB = time.Second
	// l94C1Commands is each c1/c4 session's command count; l94C1Stagger the
	// start of one session after the other.
	l94C1Commands = 20
	l94C1Stagger  = 100 * time.Millisecond
	// c3's B loop.
	l94C3Every = 250 * time.Millisecond
	l94C3For   = 6 * time.Second
	l94C3Fails = 3
	// l94C2Lead is how long after A's dial B starts typing in c2, and
	// l94C2Tries how many times the cell is played when B's requests reached
	// port49 before A's (the gap was longer than the delay).
	l94C2Lead  = 400 * time.Millisecond
	l94C2Tries = 3
)

// l94Platform is one platform of the row, in the order they run.
type l94Platform struct {
	Sel     string // PORT49_LAB_PLATFORMS selector
	Name    string // the l73Dialects key; "" when the lab has no TLS dialect for it
	Family  string
	Ref     string // the reference device configuration the cells run under
	Timeout time.Duration
	// TimeoutFrom names where Timeout comes from (spec §15 L13).
	TimeoutFrom string
	// Blocks is whether a stop on this platform blocks the merge (NX-OS,
	// Junos, EOS); IOS-XE and XR run in the same session and keep their
	// warning while L94 stays open for them.
	Blocks bool
}

// l94Platforms are L94's platforms in priority order (spec §15 L94).
var l94Platforms = []l94Platform{
	{"nxos106", "cisco_nxos", "nxos", "deploy/device-aaa/cisco_nxos-tls.cfg", 6 * time.Second, "L13: about 6s on the N9Kv, which also retransmits", true},
	{"vjunos26", "juniper_vjunos-router", "junos", "deploy/device-aaa/juniper_junos-tls.set", 3 * time.Second, "L13: about 3s on both Junos images", true},
	{"vsrx", "", "junos", "deploy/device-aaa/juniper_junos-tls.set", 3 * time.Second, "L13: about 3s on both Junos images", true},
	{"ceos436", "arista_ceos", "eos", "deploy/device-aaa/arista_eos-tls.cfg", 5 * time.Second, "L13: 5.0s on vEOS (cEOS unmeasured)", true},
	{"iosxe1718", "cisco_iosxe", "iosxe", "deploy/device-aaa/cisco_iosxe-tls.cfg", 12 * time.Second, "L13: above 12s on IOS-XE (unbounded above)", false},
	{"xrd261", "cisco_xrd", "xr", "deploy/device-aaa/cisco_iosxr-tls.cfg", 0, "L13: unmeasured on XR", false},
}

// l94PlatformFor is sel's row entry.
func l94PlatformFor(sel string) (l94Platform, error) {
	for _, p := range l94Platforms {
		if p.Sel != sel {
			continue
		}
		if p.Name == "" {
			return p, fmt.Errorf("INVALID: %s has no RFC 9887 dialect in this harness (l73Dialects): L94 stays open for it", sel)
		}
		return p, nil
	}
	var sels []string
	for _, p := range l94Platforms {
		sels = append(sels, p.Sel)
	}
	return l94Platform{}, fmt.Errorf("INVALID: L94 runs on %s, not %s", strings.Join(sels, ", "), sel)
}

// l94CellNames are the cells a platform plays on an arm, in order: c4 is
// NX-OS's and the fixed arm's alone (the baseline build has no hold to
// build with, and answers one reply at a time anyway).
func l94CellNames(family, arm string) []string {
	cells := []string{"c1", "c2", "c3"}
	if family == "nxos" && arm == "fixed" {
		cells = append(cells, "c4")
	}
	return append(cells, "c5")
}

// l94Select is the cells a run plays: all of them, or only's. c4 runs alone,
// because its port49d is a different build.
func l94Select(family, arm string, only []string) ([]string, error) {
	all := l94CellNames(family, arm)
	if len(only) == 0 {
		if slices.Contains(all, "c4") {
			return nil, errors.New("INVALID: c4 runs on its own build: PORT49_L94_CELLS=c4, and the other cells in another run")
		}
		return all, nil
	}
	var out []string
	for _, c := range only {
		if !slices.Contains(all, c) {
			return nil, fmt.Errorf("INVALID: cell %q is not L94's on %s, arm %s (%s)", c, family, arm, strings.Join(all, ","))
		}
		out = append(out, c)
	}
	if slices.Contains(out, "c4") && len(out) > 1 {
		return nil, errors.New("INVALID: c4 runs on its own build: PORT49_L94_CELLS=c4 alone")
	}
	return out, nil
}

// l94Commands is the permitted and the denied command on platform (a port49
// platform name): the qual policy's (qualDeniedCommand). Junos pages, so its
// permitted command does not.
func l94Commands(platform string) (permitted, denied string) {
	if platform == "juniper_junos" {
		return "show version | no-more", qualDeniedCommand(platform)
	}
	return "show version", qualDeniedCommand(platform)
}

// l94Loop is n commands, permitted and denied alternating, permitted first.
func l94Loop(platform string, n int) []string {
	p, d := l94Commands(platform)
	out := make([]string, n)
	for i := range out {
		out[i] = p
		if i%2 == 1 {
			out[i] = d
		}
	}
	return out
}

// l94Event is one of port49's records as L94 grades it: no field but these.
type l94Event struct {
	TS      time.Time
	Event   string
	Verdict string
	Reason  string
	Vector  string // authorize_command's request vector, account's record vector
	Flags   string // account
	TaskID  string // account
	Cred    string // redeem: auth.credential_sha256
}

// l94Events reads recs in record order; a record with no parseable ts is
// dropped (it cannot be ordered).
func l94Events(recs []map[string]any) []l94Event {
	var out []l94Event
	for _, r := range recs {
		ev, _ := r["event"].(string)
		if !slices.Contains([]string{"redeem", "authorize_session", "authorize_command", "account"}, ev) {
			continue
		}
		ts, _ := r["ts"].(string)
		t, err := time.Parse(time.RFC3339Nano, ts)
		if err != nil {
			continue
		}
		e := l94Event{TS: t, Event: ev}
		e.Verdict, _ = r["verdict"].(string)
		e.Reason, _ = r["reason"].(string)
		e.Flags, _ = r["flags"].(string)
		e.TaskID, _ = r["task_id"].(string)
		if a, ok := r["auth"].(map[string]any); ok {
			e.Cred, _ = a["credential_sha256"].(string)
		}
		switch ev {
		case "authorize_command":
			e.Vector = qualVector(r)
		case "account":
			if rec, ok := r["record"].(map[string]any); ok {
				vec, _ := rec["vector"].([]any)
				var words []string
				for _, w := range vec {
					s, _ := w.(string)
					words = append(words, s)
				}
				e.Vector = strings.Join(words, " ")
			}
		}
		out = append(out, e)
	}
	return out
}

// l94Commanded is whether platform's device asks port49 about each command
// (Junos and SR Linux do not: qualNoCommandAuth). Where it does not, a B
// command reaches port49 only as accounting, and c2/c3 order B's account
// records against A's FAIL instead.
func l94Commanded(platform string) bool { return !qualNoCommandAuth(platform) }

// l94BEvent is whether e is one of B's command events on platform: an
// authorize_command where commands are asked, a command account record
// otherwise. cmds are B's typed commands.
func l94BEvent(platform string, e l94Event, cmds []string) bool {
	if !slices.Contains(cmds, e.Vector) && !slices.ContainsFunc(cmds, func(c string) bool { return strings.HasPrefix(c, e.Vector+" |") }) {
		return false
	}
	if l94Commanded(platform) {
		return e.Event == "authorize_command"
	}
	return e.Event == "account"
}

// l94Fails are recs' FAIL redeems, in order: A's refused-credential logins
// (l94AValid holds each of A's to deny token_not_found; B's are minted).
func l94Fails(evs []l94Event) []l94Event {
	var out []l94Event
	for _, e := range evs {
		if e.Event == "redeem" && e.Verdict == "deny" {
			out = append(out, e)
		}
	}
	return out
}

// l94Gaps is, for each of B's command events, how long after the first FAIL
// redeem's ts (A's read) port49 read it (negative: before it). ok is false
// with no FAIL. A gap in (0, l94Inside) was answered inside A's delay; one
// near l94Delay waited behind A.
func l94Gaps(platform string, evs []l94Event, cmds []string) (gaps []time.Duration, ok bool) {
	fails := l94Fails(evs)
	if len(fails) == 0 {
		return nil, false
	}
	for _, e := range evs {
		if l94BEvent(platform, e, cmds) {
			gaps = append(gaps, e.TS.Sub(fails[0].TS))
		}
	}
	return gaps, true
}

// l94C2Timing is whether c2's timing stands: every B event read after A's
// request, and at least one B event. "early" (a B event read before A's)
// asks for another play with a longer lead; "none" means B reached port49
// not at all. A gap past l94Inside is a stop (l94Stops), not a retry.
func l94C2Timing(gaps []time.Duration) string {
	if len(gaps) == 0 {
		return "none"
	}
	for _, g := range gaps {
		if g < 0 {
			return "early"
		}
	}
	return "ok"
}

// l94C2Valid is whether c2 measured anything: its last try's timing must be
// "ok". Still "early" after tries plays, or "none", is INVALID on either
// arm: the cell did not put B's requests inside A's delay, so it can neither
// pass nor fail.
func l94C2Valid(timing string, tries int) error {
	switch timing {
	case "ok":
		return nil
	case "early":
		return fmt.Errorf("INVALID: c2: in %d tries B's requests reached port49 before A's, so none was inside A's delay", tries)
	case "none":
		return errors.New("INVALID: c2: none of B's commands reached port49")
	}
	return fmt.Errorf("INVALID: c2: timing %q", timing)
}

// l94RefusedCredential is A's password: one port49 refuses with
// token_not_found after the full failure delay, generated fresh at runtime and
// never printed. A minted token cannot be A's credential: a spent token
// replays its stored decision (PERMIT receipt_replayed) for receipt_idle_ttl,
// up to receipt_max_age (spec §5.1.1; §13 "a sliding receipt", ruled
// 2026-09-22), so it is never a
// FAIL. This is 26 base32 characters, not token.Len, so token.Parse refuses
// it and the device-tag check (internal/daemon/authen/authen.go:268, which
// would be device_mismatch) is skipped; no receipt holds its hash (receipts
// are written only for a token that matched, authen.go:573), so GetReceipt
// misses and no candidate matches: authen.go:462 fail(token_not_found), whose
// delay is authen.go:1033-1054. base = max = l94Delay, so escalation adds
// nothing.
func l94RefusedCredential() string { return rand.Text() }

// l94AValid is whether port49 refused each of A's credentials (creds are
// their credential_sha256) as the cell needs: every redeem it recorded for
// one is deny token_not_found, so the delay is the FAIL's. Anything else
// (PERMIT receipt_replayed above all) means the cell has no FAIL to measure:
// INVALID, named. recorded also requires a redeem for every credential; c5's
// restart may drop A's request before its record, so c5 passes false.
func l94AValid(cell string, evs []l94Event, creds []string, recorded bool) error {
	for i, c := range creds {
		n := 0
		for _, e := range evs {
			if e.Event != "redeem" || e.Cred != c {
				continue
			}
			n++
			if e.Verdict != "deny" || e.Reason != string(decision.TokenNotFound) {
				return fmt.Errorf("INVALID: %s: A's refused credential %d was answered %s %s, not deny %s: the cell has no FAIL to measure (a credential that was never minted must never be permitted: read the record)", cell, i+1, e.Verdict, e.Reason, decision.TokenNotFound)
			}
		}
		if n == 0 && recorded {
			return fmt.Errorf("INVALID: %s: port49 recorded no redeem for A's refused credential %d", cell, i+1)
		}
	}
	return nil
}

// l94C2Verdict is c2's validity: A's refusal first, so that a login port49
// did not refuse is named as that rather than as "none" (B's commands are
// graded against a FAIL that never came), then the timing (l94C2Valid).
func l94C2Verdict(evs []l94Event, creds []string, timing string, tries int) error {
	if err := l94AValid("c2", evs, creds, true); err != nil {
		return err
	}
	return l94C2Valid(timing, tries)
}

// l94Outcome is one A login's outcome, as the CLI saw it.
type l94Outcome struct {
	Took       float64 `json:"took_s"`
	AuthFailed bool    `json:"auth_failed"` // the device refused the login (not a timeout, not a login)
	LoggedIn   bool    `json:"logged_in"`   // a refused credential logged in: a fall-through or worse
	Err        string  `json:"err,omitempty"`
}

// l94OutcomeOf classifies A's login: err nil is a login (which a refused
// credential must never get), an SSH authentication refusal is a failure delivered, and
// any other error (a timeout, a reset) is not.
func l94OutcomeOf(took time.Duration, err error) l94Outcome {
	o := l94Outcome{Took: took.Seconds()}
	switch {
	case err == nil:
		o.LoggedIn = true
	case strings.Contains(err.Error(), "unable to authenticate"):
		o.AuthFailed = true
	default:
		o.Err = strings.Join(strings.Fields(err.Error()), " ")
		if len(o.Err) > 120 {
			o.Err = o.Err[:120]
		}
	}
	return o
}

// l94Regressed is review's merge criterion for c2/c3: a FAIL the baseline
// delivered (an authentication failure) that the fixed arm did not.
func l94Regressed(baseline, fixed []l94Outcome) []string {
	var out []string
	delivered := 0
	for _, b := range baseline {
		if b.AuthFailed {
			delivered++
		}
	}
	got := 0
	for _, f := range fixed {
		if f.AuthFailed {
			got++
		}
	}
	if got < delivered {
		out = append(out, fmt.Sprintf("the baseline delivered %d FAIL(s) as an authentication failure, the fixed arm %d: a FAIL became a timeout or a fall-through", delivered, got))
	}
	return out
}

// l94Match is, for each typed command, the authorize_command port49 recorded
// for it, or nil. Records are taken in ts order (port49's read,
// author.go:245), and each goes to the unmatched command of its words typed
// latest at or before it. Two sessions typing the same words are told apart
// by time, not by the order typed was appended in, and a request that
// stalled is not credited to a later session's that overtook it.
func l94Match(typed []l80Typed, evs []l94Event) []*l94Event {
	var asks []int
	for j, e := range evs {
		if e.Event == "authorize_command" {
			asks = append(asks, j)
		}
	}
	slices.SortStableFunc(asks, func(a, b int) int { return evs[a].TS.Compare(evs[b].TS) })
	out := make([]*l94Event, len(typed))
	for _, j := range asks {
		best := -1
		for i, x := range typed {
			if out[i] != nil || x.Command != evs[j].Vector || x.At.After(evs[j].TS) {
				continue
			}
			if best < 0 || x.At.After(typed[best].At) {
				best = i
			}
		}
		if best >= 0 {
			out[best] = &evs[j]
		}
	}
	return out
}

// l94Dup is a duplicate or retransmitted request: an authorize_command for a
// command more often than it was typed, or an account record whose flags and
// task_id repeat l94AcctRepeat or more after the first. NX-OS sends two
// STOPs per session 15-19ms apart, in both arms (1c1d105c, 4481bbd8): that
// pair is the device's, not a retransmission.
func l94Dup(evs []l94Event, typed []l80Typed) []string {
	typedN := map[string]int{}
	for _, x := range typed {
		typedN[x.Command]++
	}
	asked := map[string]int{}
	first := map[string]time.Time{}
	for _, e := range evs {
		if k := e.Flags + "/" + e.TaskID; e.Event == "account" && e.TaskID != "" {
			if f, ok := first[k]; !ok || e.TS.Before(f) {
				first[k] = e.TS
			}
		}
	}
	acct := map[string]int{}
	for k := range first {
		acct[k] = 1
	}
	for _, e := range evs {
		switch e.Event {
		case "authorize_command":
			asked[e.Vector]++
		case "account":
			if k := e.Flags + "/" + e.TaskID; e.TaskID != "" && e.TS.Sub(first[k]) >= l94AcctRepeat {
				acct[k]++
			}
		}
	}
	var out []string
	for _, v := range slices.Sorted(maps.Keys(asked)) {
		if asked[v] > typedN[v] {
			out = append(out, fmt.Sprintf("%q asked %d time(s), typed %d: a duplicate or retransmitted authorization", v, asked[v], typedN[v]))
		}
	}
	for _, k := range slices.Sorted(maps.Keys(acct)) {
		if acct[k] > 1 {
			out = append(out, fmt.Sprintf("account flags/task_id %s recorded %d times: a duplicate or retransmitted accounting record", k, acct[k]))
		}
	}
	return out
}

// l94SuspectMarks are the device debug lines, on the platforms whose debug
// is not NX-OS's (whose markers are nxosDebugMarkers), that may name a dead
// server, a TLS read error, a fall-through, or a session_id or sequence
// complaint. The pattern is broad on purpose and is no measurement: a count
// above 0 is a stop to read the kept debug, never a result by itself.
var l94SuspectMarks = regexp.MustCompile(`(?i)\bdead\b|unreachable|timed? ?out|ssl.{0,20}(fail|error)|fall(ing)? ?(back|through)|session.?id|sequence|\bseq\b|out of order|unexpected`)

// l94Suspect counts kept's suspect lines.
func l94Suspect(kept string) int { return len(l94SuspectLines(kept)) }

// l94SuspectLines are kept's suspect lines, for the summary (the caller
// passes them through qualGate before they are written).
func l94SuspectLines(kept string) []string {
	var out []string
	for _, ln := range strings.Split(kept, "\n") {
		if l94SuspectMarks.MatchString(ln) {
			out = append(out, ln)
		}
	}
	return out
}

// l94Grade is what a cell's harness hands the grader.
type l94Grade struct {
	Arm      string
	Cell     string
	Platform string // port49 platform name
	P        l94Platform
	Typed    []l80Typed // every B (and c1/c4 every) command
	Events   []l94Event
	Conns    int // TLS connections the capture saw in the cell
	MostOpen int
	Second   float64 // single_connect_second_connection delta
	// DeadOrSSL is NX-OS's ssl_read_failed + mark_server_dead (+ fallbacks)
	// in the cell's window, or l94Suspect's count elsewhere (Suspect true):
	// that broad pattern stops only past the baseline arm's count.
	DeadOrSSL int
	Suspect   bool
	Outcomes  []l94Outcome // c2/c3/c5: A's logins
	// BLogin is c2's and c3's B token login during A's FAILs, on a platform
	// whose device asks port49 about no command (l94Commanded false).
	BLogin   *l94Outcome
	Baseline *l94Baseline // the baseline arm's evidence, when it was run
	Gaps     []time.Duration
	// Restart is c5's window.
	RestartAt, UpAt time.Time
}

// l94Baseline is what the fixed arm compares to: the baseline arm's evidence
// for the same cell and platform.
type l94Baseline struct {
	MaxTook  float64
	Outcomes []l94Outcome
	// Suspect is the baseline's l94Suspect count for the cell and mode;
	// HasSuspect is whether its evidence recorded one.
	Suspect    int
	HasSuspect bool
}

// l94Stops are the cell's stop conditions (the review's merge criteria), on
// the fixed arm only; the baseline is the before-the-fix evidence and stops
// on nothing. A stop on a platform whose P.Blocks is false is still listed:
// the harness reports it as a finding that keeps the platform's warning.
func l94Stops(g l94Grade) []string {
	if g.Arm != "fixed" {
		return nil
	}
	var out []string
	permitted, denied := l94Commands(g.Platform)
	commanded := l94Commanded(g.Platform)
	loop := g.Cell == "c1" || g.Cell == "c4"
	// Where the device asks port49 about each command, c1/c4/c3 grade when
	// port49 read it (l94Match), under the row's <1s: NX-OS holds one vty's
	// prompt while another session runs, in the in-order baseline too, so
	// the prompt time is the summary's, not a grade. Where it asks nothing,
	// the prompt is all there is: c1/c4 against the platform's L13 timeout,
	// c3 below.
	arrival := commanded && (loop || g.Cell == "c3")
	match := l94Match(g.Typed, g.Events)
	for i, x := range g.Typed {
		if m := match[i]; arrival && m != nil {
			if lat := m.TS.Sub(x.At); lat >= l94FastB {
				out = append(out, fmt.Sprintf("%s: session %d %q reached port49 %s after it was typed, not under %s", g.Cell, x.Session, x.Command, lat.Round(time.Millisecond), l94FastB))
			}
		}
		if commanded && !x.Asked && (g.Cell != "c5" || l80Ran(x)) {
			out = append(out, fmt.Sprintf("%s: session %d %q was never asked: lost or run unasked", g.Cell, x.Session, x.Command))
		}
		if commanded && x.Command == denied && !x.Denied && !x.Err {
			out = append(out, fmt.Sprintf("%s: session %d %q, which port49 denies, ran", g.Cell, x.Session, x.Command))
		}
		// A permitted command refused is one port49 permitted (its matched
		// authorize_command) and the device refused anyway. One port49 itself
		// denied is not: after c5's restart the memory store has lost the
		// context (context_missing), in the baseline too. Where the device
		// asks about no command there is no record to match: c5's commands
		// inside the restart are refused locally by design, and one after
		// port49d is back must run.
		refused := x.Command == permitted && x.Denied
		if commanded {
			refused = refused && match[i] != nil && match[i].Verdict == "permit"
		} else {
			refused = refused && (g.Cell != "c5" || x.At.After(g.UpAt))
		}
		if refused {
			out = append(out, fmt.Sprintf("%s: session %d %q: a permitted command was refused", g.Cell, x.Session, x.Command))
		}
		if x.Err {
			out = append(out, fmt.Sprintf("%s: session %d %q: its prompt never came back", g.Cell, x.Session, x.Command))
		}
		if loop && !commanded && g.P.Timeout > 0 && x.Took > g.P.Timeout.Seconds() {
			out = append(out, fmt.Sprintf("%s: session %d %q took %.2fs, over %s", g.Cell, x.Session, x.Command, x.Took, g.P.Timeout))
		}
	}
	if loop {
		out = append(out, l94SessionAccounting(g.Cell, g.Events, 2)...)
	}
	out = append(out, prefixAll(g.Cell+": ", l94Dup(g.Events, g.Typed))...)
	if g.Cell != "c5" && (g.Conns != 1 || g.MostOpen > 1) {
		out = append(out, fmt.Sprintf("%s: %d TLS connection(s), %d open at once: the cell must hold exactly one", g.Cell, g.Conns, g.MostOpen))
	}
	if g.Second > 0 {
		out = append(out, fmt.Sprintf("%s: single_connect_second_connection +%v", g.Cell, g.Second))
	}
	switch {
	case g.DeadOrSSL == 0:
	case !g.Suspect:
		out = append(out, fmt.Sprintf("%s: %d device debug line(s) naming a dead server, a TLS read error, a fall-through or a session/sequence complaint: read the kept debug", g.Cell, g.DeadOrSSL))
	case g.Baseline == nil || !g.Baseline.HasSuspect:
		out = append(out, fmt.Sprintf("%s: %d suspect device debug line(s) and no baseline count for this cell and mode to compare: run the baseline arm first", g.Cell, g.DeadOrSSL))
	case g.DeadOrSSL > g.Baseline.Suspect:
		out = append(out, fmt.Sprintf("%s: %d suspect device debug line(s), the baseline arm's %d: read the lines in the summary", g.Cell, g.DeadOrSSL, g.Baseline.Suspect))
	}
	for i, o := range g.Outcomes {
		if o.LoggedIn {
			out = append(out, fmt.Sprintf("%s: refused-credential login %d logged in: a fall-through or worse", g.Cell, i+1))
		}
	}
	switch g.Cell {
	case "c2":
		for i, gap := range g.Gaps {
			if gap >= l94Inside {
				out = append(out, fmt.Sprintf("c2: B's request %d was read %s after A's, not under %s: it waited behind A", i+1, gap.Round(time.Millisecond), l94Inside))
			}
		}
		for _, x := range g.Typed {
			if x.Took > l94FastB.Seconds() {
				out = append(out, fmt.Sprintf("c2: B's %q took %.2fs, over %s", x.Command, x.Took, l94FastB))
			}
		}
		if len(g.Outcomes) != 1 || !g.Outcomes[0].AuthFailed {
			out = append(out, "c2: A's refused-credential login was not refused as an authentication failure")
		}
	case "c3":
		// Where no command is asked, B's prompt is bounded by the lower of
		// the platform's L13 timeout and the baseline arm's slowest B command
		// plus 250ms. Where commands are asked, arrival is graded above.
		limit, from := g.P.Timeout.Seconds(), g.P.TimeoutFrom
		if g.Baseline != nil {
			if b := g.Baseline.MaxTook + 0.25; limit == 0 || b < limit {
				limit, from = b, "the baseline arm's slowest + 250ms"
			}
		}
		for _, x := range g.Typed {
			if !commanded && limit > 0 && x.Took > limit {
				out = append(out, fmt.Sprintf("c3: B's %q took %.2fs, above %.2fs (%s)", x.Command, x.Took, limit, from))
			}
		}
		if n := l94FailsDelivered(g.Outcomes); n != l94C3Fails {
			out = append(out, fmt.Sprintf("c3: %d of %d FAILs delivered as an authentication failure", n, l94C3Fails))
		}
		// At least one per A login: the lab client offers password and then
		// keyboard-interactive (labSSHConfig), so a login can be two FAILs.
		// That each of A's credentials was refused is l94AValid's.
		if n := len(l94Fails(g.Events)); n < l94C3Fails {
			out = append(out, fmt.Sprintf("c3: port49 recorded %d FAIL redeem(s), want at least %d", n, l94C3Fails))
		}
	case "c5":
		if g.UpAt.IsZero() {
			out = append(out, "c5: port49d did not come back after the restart")
		} else if commanded && !slices.ContainsFunc(g.Typed, func(x l80Typed) bool { return x.Asked && x.At.After(g.UpAt) }) {
			out = append(out, "c5: no command after the restart was asked: the device did not reconnect")
		}
	}
	if !commanded && (g.Cell == "c2" || g.Cell == "c3") {
		out = append(out, l94BLoginStops(g)...)
	}
	if g.Baseline != nil && (g.Cell == "c2" || g.Cell == "c3") {
		out = append(out, prefixAll(g.Cell+": ", l94Regressed(g.Baseline.Outcomes, g.Outcomes))...)
	}
	return out
}

// l94BLoginStops grades c2's and c3's B token login on a platform whose
// device asks port49 about no command, so that a B request port49 must
// answer is in the cell: it logs in, within the platform's L13 timeout, and
// port49 read its permit redeem inside A's delay (l94LoginInsideDelay), so
// it neither waited behind A nor fell through to a local method.
func l94BLoginStops(g l94Grade) []string {
	b := g.BLogin
	if b == nil {
		return []string{g.Cell + ": no B token login during A's FAILs"}
	}
	var out []string
	if !b.LoggedIn {
		out = append(out, fmt.Sprintf("%s: B's token login did not log in (auth_failed=%v err=%q)", g.Cell, b.AuthFailed, b.Err))
	}
	if g.P.Timeout > 0 && b.Took > g.P.Timeout.Seconds() {
		out = append(out, fmt.Sprintf("%s: B's token login took %.2fs, over %s (%s)", g.Cell, b.Took, g.P.Timeout, g.P.TimeoutFrom))
	}
	if !l94LoginInsideDelay(g.Events) {
		out = append(out, g.Cell+": B's token login was not answered inside A's delay: no permit redeem read within "+l94Inside.String()+" after A's")
	}
	return out
}

// l94LoginInsideDelay is whether port49 read a permit redeem inside the
// first FAIL's delay: at or after the FAIL's ts (A's read) and under
// l94Inside later, c2's line (the baseline's B is read at +l94Delay).
func l94LoginInsideDelay(evs []l94Event) bool {
	fails := l94Fails(evs)
	if len(fails) == 0 {
		return false
	}
	from, to := fails[0].TS, fails[0].TS.Add(l94Inside)
	return slices.ContainsFunc(evs, func(e l94Event) bool {
		return e.Event == "redeem" && e.Verdict == "permit" && !e.TS.Before(from) && e.TS.Before(to)
	})
}

// l94SessionAccounting is c1's (and c4's) check that each of its sessions
// left an accounting START and STOP record: at least sessions of each. A
// command's own accounting is a STOP too, so STOP is a floor, not a count.
func l94SessionAccounting(cell string, evs []l94Event, sessions int) []string {
	n := map[string]int{}
	for _, e := range evs {
		if e.Event == "account" {
			n[e.Flags]++
		}
	}
	var out []string
	for _, f := range []string{"start", "stop"} {
		if n[f] < sessions {
			out = append(out, fmt.Sprintf("%s: %d accounting %s record(s), want at least %d (one per session)", cell, n[f], strings.ToUpper(f), sessions))
		}
	}
	return out
}

// l94FailsDelivered counts the outcomes that were an authentication failure.
func l94FailsDelivered(os []l94Outcome) int {
	n := 0
	for _, o := range os {
		if o.AuthFailed {
			n++
		}
	}
	return n
}

func prefixAll(p string, ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = p + s
	}
	return out
}

// l94DelayConfig is a port49d config text with both failure-delay knobs set
// to d, as L13's writeDelayConfig sets them on the lab config: both, so the
// first FAIL already waits d.
//
// It edits lines, in l73SetLine's style, and never re-encodes: every line
// but the two keys stays the file's own, because the edits l73DaemonYAML
// makes after it match exact lines (`limits:`) and prefixes (`  idle_timeout: `).
// A key under limits is replaced in place at the block's own indent; a
// missing one goes right under `limits:`; with no limits block, one is
// appended. The YAML is parsed only to check it, before and after.
func l94DelayConfig(text string, d time.Duration) (string, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(text), &doc); err != nil {
		return "", err
	}
	if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return "", errors.New("the config is not a mapping")
	}
	keys := []string{"auth_failure_delay_base", "auth_failure_delay_max"}
	lines := strings.Split(text, "\n")
	at := -1
	for i, ln := range lines {
		switch {
		case ln == "limits:":
			if at >= 0 {
				return "", errors.New("the config has two `limits:` lines")
			}
			at = i
		case strings.HasPrefix(ln, "limits:"):
			return "", fmt.Errorf("limits is not a block mapping on a line of its own (%q): a line edit cannot set it", ln)
		}
	}
	var out string
	if at < 0 {
		var b strings.Builder
		b.WriteString(strings.TrimRight(text, "\n") + "\nlimits:\n")
		for _, k := range keys {
			fmt.Fprintf(&b, "  %s: %s\n", k, d)
		}
		out = b.String()
	} else {
		// The block runs to the first non-blank line at column 0; its indent
		// is its first key's.
		end := at + 1
		for end < len(lines) && (lines[end] == "" || strings.HasPrefix(lines[end], " ")) {
			end++
		}
		indent := "  "
		for _, ln := range lines[at+1 : end] {
			if t := strings.TrimLeft(ln, " "); t != "" && !strings.HasPrefix(t, "#") {
				indent = ln[:len(ln)-len(t)]
				break
			}
		}
		set := map[string]bool{}
		for i := at + 1; i < end; i++ {
			ln := lines[i]
			if !strings.HasPrefix(ln, indent) || strings.HasPrefix(ln, indent+" ") {
				continue
			}
			for _, k := range keys {
				if strings.HasPrefix(ln[len(indent):], k+":") {
					lines[i] = indent + k + ": " + d.String()
					set[k] = true
				}
			}
		}
		var add []string
		for _, k := range keys {
			if !set[k] {
				add = append(add, indent+k+": "+d.String())
			}
		}
		lines = append(lines[:at+1], append(add, lines[at+1:]...)...)
		out = strings.Join(lines, "\n")
	}
	var check struct {
		Limits map[string]any `yaml:"limits"`
	}
	if err := yaml.Unmarshal([]byte(out), &check); err != nil {
		return "", fmt.Errorf("the delay config does not parse: %w", err)
	}
	for _, k := range keys {
		if v, _ := check.Limits[k].(string); v != d.String() {
			return "", fmt.Errorf("the delay config's limits.%s reads %v, want %s", k, check.Limits[k], d)
		}
	}
	return out, nil
}

// parseBuildTags is the -tags a `go version -m` output says the binary was
// built with ("" for none).
func parseBuildTags(out string) string {
	for _, ln := range strings.Split(out, "\n") {
		f := strings.Fields(ln)
		if len(f) == 2 && f[0] == "build" {
			if v, ok := strings.CutPrefix(f[1], "-tags="); ok {
				return v
			}
		}
	}
	return ""
}

// l94TagCheck is whether a binary built with tags is the build cell needs:
// c4's carries the hold tag, every other cell's does not.
func l94TagCheck(cell, tags string) error {
	has := slices.Contains(strings.Split(tags, ","), l94HoldTag)
	switch {
	case cell == "c4" && !has:
		return fmt.Errorf("INVALID: c4 needs port49d built with -tags %s; it was built with %q", l94HoldTag, tags)
	case cell != "c4" && has:
		return fmt.Errorf("INVALID: %s ran a port49d built with the lab-only %s, which holds every accounting reply", cell, l94HoldTag)
	}
	return nil
}

// l94HoldBin is where c4's held port49d is built, relative to the repo
// root: its own path, never bin/port49d, so no other test can start it.
const l94HoldBin = "bin/port49d-l94-acct-hold"

// l94StandardBin is the harness's check of the binary at its standard path
// (bin/port49d, initGlobal): one built with the hold tag holds every
// accounting reply 1.5s, and every other test would measure that hold.
// A binary that cannot be read is refused too.
func l94StandardBin(path string) error {
	tags, err := binaryTags(path)
	if err != nil {
		return err
	}
	if slices.Contains(strings.Split(tags, ","), l94HoldTag) {
		return fmt.Errorf("%s was built with the lab-only -tags %s, which holds every accounting reply: rebuild it (make build); "+
			"L94's c4 builds its own to %s", path, l94HoldTag, l94HoldBin)
	}
	return nil
}

// binaryTags is `go version -m path`'s -tags.
func binaryTags(path string) (string, error) {
	out, err := exec.Command("go", "version", "-m", path).Output()
	if err != nil {
		return "", fmt.Errorf("go version -m %s: %w", path, err)
	}
	return parseBuildTags(string(out)), nil
}
