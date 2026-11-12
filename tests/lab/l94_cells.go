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
	"github.com/blanketfish/port49/tests/lab/labpcap"
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
//	c4  NX-OS and Junos, fixed arm only: c1's loop on a port49d built with
//	    port49_lab_acct_hold, which holds every accounting reply 1.5s so the
//	    command authorization NX-OS writes behind an accounting record is
//	    answered first; on Junos, both vtys' accounting bursts ride the one
//	    connection that stays open while their replies are held
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
// NX-OS's and Junos's, on the fixed arm alone (the baseline build has no
// hold to build with, and answers one reply at a time anyway). NX-OS
// pipelines a command authorization behind an accounting record on its one
// connection; vJunos opens a connection per login, but its accounting
// bursts ride the one connection that stays open.
func l94CellNames(family, arm string) []string {
	cells := []string{"c1", "c2", "c3"}
	if (family == "nxos" || family == "junos") && arm == "fixed" {
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
	Port    string // session.port
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
		if s, ok := r["session"].(map[string]any); ok {
			e.Port, _ = s["port"].(string)
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
// command reaches port49 only as accounting, sent when the device likes, so
// c2/c3 time B's token login against A's read instead (l94BEvent).
func l94Commanded(platform string) bool { return !qualNoCommandAuth(platform) }

// l94BEvent is whether e is one of B's requests c2 times against A's read on
// platform. Where commands are asked, B's authorize_command for one of cmds
// (B's typed commands). Where none is, B's token login: the permit redeem of
// B's own token, credential_sha256 bSHA (startBLogin mints it), so a stray
// permit (a re-authentication, a second attempt) never times the cell.
// Command accounting is no clock there: vJunos 26.2R1.7 sends it in bursts
// about 5s apart, each line as the device logged it ("show version |
// no-more <cr>"), so a B command's record may come after A's FAIL however
// fast port49 was.
func l94BEvent(platform string, e l94Event, cmds []string, bSHA string) bool {
	if !l94Commanded(platform) {
		return l94BLogin(e, bSHA)
	}
	if !slices.Contains(cmds, e.Vector) && !slices.ContainsFunc(cmds, func(c string) bool { return strings.HasPrefix(c, e.Vector+" |") }) {
		return false
	}
	return e.Event == "authorize_command"
}

// l94BLogin is whether e is B's token login: a permit redeem whose
// credential_sha256 is bSHA, B's token's. An empty bSHA is no login.
func l94BLogin(e l94Event, bSHA string) bool {
	return bSHA != "" && e.Event == "redeem" && e.Verdict == "permit" && e.Cred == bSHA
}

// l94C2Recorded is whether c2's loop has the records it grades: A's redeem
// for aSHA and, where no command is asked, B's login for bSHA (l94BEvent).
func l94C2Recorded(platform string, evs []l94Event, aSHA, bSHA string) bool {
	a := slices.ContainsFunc(evs, func(e l94Event) bool { return e.Event == "redeem" && e.Cred == aSHA })
	return a && (l94Commanded(platform) || slices.ContainsFunc(evs, func(e l94Event) bool { return l94BEvent(platform, e, nil, bSHA) }))
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

// l94Gaps is, for each of B's events (l94BEvent), how long after the first FAIL
// redeem's ts (A's read) port49 read it (negative: before it). ok is false
// with no FAIL. A gap in (0, l94Inside) was answered inside A's delay; one
// near l94Delay waited behind A.
func l94Gaps(platform string, evs []l94Event, cmds []string, bSHA string) (gaps []time.Duration, ok bool) {
	fails := l94Fails(evs)
	if len(fails) == 0 {
		return nil, false
	}
	for _, e := range evs {
		if l94BEvent(platform, e, cmds, bSHA) {
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
// command more often than it was typed, or an account record whose
// flags/task_id/port/vector (one request: a retransmission repeats all four)
// repeats l94AcctRepeat or more after the first. NX-OS sends two STOPs per
// session 15-19ms apart, in both arms (1c1d105c, 4481bbd8): that pair is the
// device's, not a retransmission. Junos counts task_ids from 1 in each
// session, so two vtys share them; port tells them apart.
//
// Where the device asks port49 about no command, only the records of a
// typed command count: vJunos logs system processes (port non-tty) and the
// harness's config session (port 0) in the same window, and session START
// and STOP are l94SessionAccounting's.
func l94Dup(platform string, evs []l94Event, typed []l80Typed) []string {
	typedN := map[string]int{}
	for _, x := range typed {
		typedN[x.Command]++
	}
	commanded := l94Commanded(platform)
	counted := func(e l94Event) bool {
		if e.Event != "account" || e.TaskID == "" {
			return false
		}
		return commanded || typedN[strings.TrimSuffix(e.Vector, " <cr>")] > 0
	}
	key := func(e l94Event) string {
		return fmt.Sprintf("%s/%s/%s/%q", e.Flags, e.TaskID, e.Port, e.Vector)
	}
	asked := map[string]int{}
	first := map[string]time.Time{}
	for _, e := range evs {
		if k := key(e); counted(e) {
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
		switch {
		case e.Event == "authorize_command":
			asked[e.Vector]++
		case counted(e):
			if k := key(e); e.TS.Sub(first[k]) >= l94AcctRepeat {
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
			out = append(out, fmt.Sprintf("account flags/task_id/port/vector %s recorded %d times: a duplicate or retransmitted accounting record", k, acct[k]))
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
	// Ends is each of those connections' l73Conn.End (device-fin,
	// server-fin, device-rst, server-rst, open): c4's held accounting
	// connection must stay open, and the device must close none first.
	Ends   []string
	Second float64 // single_connect_second_connection delta
	// DeadOrSSL is NX-OS's ssl_read_failed + mark_server_dead (+ fallbacks)
	// in the cell's window, or l94Suspect's count elsewhere (Suspect true):
	// that broad pattern stops only past the baseline arm's count.
	DeadOrSSL int
	Suspect   bool
	Outcomes  []l94Outcome // c2/c3/c5: A's logins
	// BLogin is c2's and c3's B token login during A's FAILs, on a platform
	// whose device asks port49 about no command (l94Commanded false).
	BLogin *l94Outcome
	// BSHA is that login's credential_sha256 (its token's hash): the one
	// redeem that is B's login (l94BEvent, l94LoginInsideDelay).
	BSHA     string
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
	// Conns is the TLS connections the baseline's capture saw in the cell
	// (its <cell>.tls.json); HasConns is whether that file was there.
	Conns    int
	HasConns bool
}

// l94Findings are the cell's fixed-arm lines that are measured device
// behavior, not a stop: a device that opens a connection per login in the
// baseline arm too (l94ConnGrade).
func l94Findings(g l94Grade) []string {
	if g.Arm != "fixed" {
		return nil
	}
	if _, f := l94ConnGrade(g); f != "" {
		return []string{f}
	}
	return nil
}

// l94ConnGrade is the cell's connection count as a stop or a finding (c5's
// restart reconnects by design and is graded on neither). The cell must hold
// one connection, unless the baseline cell held more than one too: vJunos
// opens one per login in both arms (L94 evidence, vJunos 26). Then only more
// connections than the baseline's stop, since that is port49 forcing a
// reconnect; how many were open at once is overlap timing and is not
// compared.
func l94ConnGrade(g l94Grade) (stop, finding string) {
	if g.Cell == "c5" || (g.Conns == 1 && g.MostOpen <= 1) {
		return "", ""
	}
	if b := g.Baseline; b != nil && b.HasConns && b.Conns > 1 {
		if g.Conns > b.Conns {
			return fmt.Sprintf("%s: %d TLS connection(s), the baseline arm's %d: port49 forced a reconnect", g.Cell, g.Conns, b.Conns), ""
		}
		return "", fmt.Sprintf("%s: device opens a connection per login (baseline %d, fixed %d)", g.Cell, b.Conns, g.Conns)
	}
	return fmt.Sprintf("%s: %d TLS connection(s), %d open at once: the cell must hold exactly one", g.Cell, g.Conns, g.MostOpen), ""
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
		// A permitted command refused stops, whoever refused it: port49
		// wrongly denying it is as much the failure as the device refusing a
		// permit. One exemption where commands are asked: after c5's restart
		// the memory store has lost the context and port49 denies it
		// context_missing, in the baseline too. With no matched record (and
		// wherever the device asks about no command), c5's commands inside
		// the restart are refused locally by design, and one after port49d
		// is back must run.
		refused := x.Command == permitted && x.Denied
		if m := match[i]; commanded && m != nil {
			refused = refused && !(g.Cell == "c5" && m.Verdict == "deny" && m.Reason == string(decision.ContextMissing))
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
	if g.Cell == "c4" {
		out = append(out, l94LostAccounting(g.Cell, g.Platform, g.Events, g.Typed, 2)...)
		out = append(out, l94HeldStops(g)...)
	}
	out = append(out, prefixAll(g.Cell+": ", l94Dup(g.Platform, g.Events, g.Typed))...)
	if s, _ := l94ConnGrade(g); s != "" {
		out = append(out, s)
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
		// B's prompt time measures port49 only where port49 is asked about
		// the command; elsewhere B's login is graded (l94BLoginStops).
		for _, x := range g.Typed {
			if commanded && x.Took > l94FastB.Seconds() {
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
	if !l94LoginInsideDelay(g.Events, g.BSHA) {
		out = append(out, g.Cell+": B's token login was not answered inside A's delay: no permit redeem read within "+l94Inside.String()+" after A's")
	}
	return out
}

// l94LoginInsideDelay is whether port49 read B's login (l94BLogin, bSHA)
// inside the first FAIL's delay: at or after the FAIL's ts (A's read) and
// under l94Inside later, c2's line (the baseline's B is read at +l94Delay).
func l94LoginInsideDelay(evs []l94Event, bSHA string) bool {
	fails := l94Fails(evs)
	if len(fails) == 0 {
		return false
	}
	from, to := fails[0].TS, fails[0].TS.Add(l94Inside)
	return slices.ContainsFunc(evs, func(e l94Event) bool {
		return l94BLogin(e, bSHA) && !e.TS.Before(from) && e.TS.Before(to)
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

// l94LostAccounting is c4's check, where the device asks
// port49 about no command, that no session's accounting was lost: for each
// typed command, as many distinct records with its vector (by
// flags/task_id/port/vector, as l94Dup) as times it ran, on at least
// sessions ports, each with its session's START and
// STOP. Junos logs system processes (port non-tty) and the harness's config
// session (port 0) in the same window, so l94SessionAccounting's flag count
// alone cannot tell a lost vty's records. Where commands are asked, there is
// nothing here: l80Ask and l94SessionAccounting grade them.
func l94LostAccounting(cell, platform string, evs []l94Event, typed []l80Typed, sessions int) []string {
	if l94Commanded(platform) {
		return nil
	}
	// Per command: a record of one command (the denied one, say) must not
	// offset a lost record of another.
	typedN := map[string]bool{}
	ran := map[string]int{}
	for _, x := range typed {
		typedN[x.Command] = true
		if !x.Denied && !x.Err {
			ran[x.Command]++
		}
	}
	recs := map[string]map[string]bool{} // command -> its distinct records
	ports := map[string]bool{}
	for _, e := range evs {
		if c := strings.TrimSuffix(e.Vector, " <cr>"); e.Event == "account" && e.TaskID != "" && typedN[c] {
			if recs[c] == nil {
				recs[c] = map[string]bool{}
			}
			recs[c][fmt.Sprintf("%s/%s/%s/%q", e.Flags, e.TaskID, e.Port, e.Vector)] = true
			ports[e.Port] = true
		}
	}
	var out []string
	for _, c := range slices.Sorted(maps.Keys(ran)) {
		if n := len(recs[c]); n < ran[c] {
			out = append(out, fmt.Sprintf("%s: %q: %d accounting record(s), %d ran: a session's accounting was lost", cell, c, n, ran[c]))
		}
	}
	if len(ports) < sessions {
		out = append(out, fmt.Sprintf("%s: typed commands' accounting on %d port(s), want %d (one per session)", cell, len(ports), sessions))
	}
	for _, port := range slices.Sorted(maps.Keys(ports)) {
		for _, f := range []string{"start", "stop"} {
			if !slices.ContainsFunc(evs, func(e l94Event) bool {
				return e.Event == "account" && e.Port == port && e.Flags == f && !typedN[strings.TrimSuffix(e.Vector, " <cr>")]
			}) {
				out = append(out, fmt.Sprintf("%s: port %s carried typed commands, but its session has no accounting %s", cell, port, strings.ToUpper(f)))
			}
		}
	}
	return out
}

// l94AcctWait bounds c4's wait for its accounting where no command is
// asked: a 20-record burst answered one at a time at the 1.5s hold is 30s.
const l94AcctWait = 60 * time.Second

// l94BaselineCell is the baseline arm's cell the fixed arm's cell is
// compared to: c4 is c1's loop on the held build, and the baseline arm plays
// no c4, so c4 is compared to c1.
func l94BaselineCell(cell string) string {
	if cell == "c4" {
		return "c1"
	}
	return cell
}

// l94AcctComplete is the record collection's wait predicate: nothing of the
// sessions' accounting is still to come (l94LostAccounting finds nothing).
// c4 holds each accounting reply 1.5s and its record is written before the
// hold, so a device that sends its next record only after the last reply
// drains a burst slowly: a short wait would read that as a loss.
func l94AcctComplete(platform string, evs []l94Event, typed []l80Typed, sessions int) bool {
	return len(l94LostAccounting("", platform, evs, typed, sessions)) == 0
}

// l94HeldStops is c4's check of the connection its accounting replies are
// held on: still open at the cell's end, and no connection closed by the
// device first (a device that gave up on a held reply). Per-login
// connections are closed by port49 (server-fin) on every platform L94 has
// measured.
func l94HeldStops(g l94Grade) []string {
	var out []string
	closed := 0
	for _, e := range g.Ends {
		if e == "device-fin" || e == "device-rst" {
			closed++
		}
	}
	if closed > 0 {
		out = append(out, fmt.Sprintf("%s: the device closed %d connection(s) first (device-rst/device-fin) while accounting replies were held", g.Cell, closed))
	}
	if !slices.Contains(g.Ends, "open") {
		out = append(out, fmt.Sprintf("%s: no connection was open at the cell's end: the device dropped the held accounting connection", g.Cell))
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

// l94WaitClean waits, with the cell's capture already running, for no
// connection open on port49d (the gauge, one poll a second, at most limit
// polls) and returns the clean point: the time just before the first read
// that came back 0 (or with no series, which is no connection). vJunos opens
// accounting connections on its own schedule, so waiting for 0 before the
// capture started left a window qualStillClean lost twice (fixed r2, c4).
func l94WaitClean(read func() (float64, bool), limit int, sleep func(time.Duration), now func() time.Time) (time.Time, error) {
	last := -1.0
	for range limit {
		at := now()
		v, ok := read()
		if !ok || v == 0 {
			return at, nil
		}
		last = v
		sleep(time.Second)
	}
	return time.Time{}, fmt.Errorf("INVALID: %v connections still open after %ds; the capture would not start clean", last, limit)
}

// l94SinceClean splits the capture's connections at the clean point. One
// whose SYN is at or after it is the cell's, and its SYN is in the capture.
// One whose SYN is before it is set aside (pre) only if it also ended before
// it, as the gauge's 0 says every connection port49 accepted had. One opened
// before the clean point and still open after it (or ended after it) is
// INVALID: a SYN port49 had not accepted when the gauge read 0. It sees only
// connections whose SYN the capture holds (l73Conns counts from the SYN); one
// whose SYN came before tcpdump was live is l94OlderThanCapture's.
func l94SinceClean(conns []l73Conn, cleanAt time.Time) (kept, pre []l73Conn, err error) {
	for _, c := range conns {
		switch {
		case !c.SYNAt.Before(cleanAt):
			kept = append(kept, c)
		case c.End != "open" && !c.EndAt.IsZero() && c.EndAt.Before(cleanAt):
			pre = append(pre, c)
		default:
			return nil, nil, fmt.Errorf("INVALID: the connection from device port %d opened at %s, before the cell's clean point %s, and was still open after it (%s at %s); the capture did not start clean",
				c.DevicePort, c.SYNAt.UTC().Format("15:04:05.000"), cleanAt.UTC().Format("15:04:05.000"), c.End, c.EndAt.UTC().Format("15:04:05.000"))
		}
	}
	return kept, pre, nil
}

// l94OlderThanCapture is INVALID for a connection older than the cell's
// capture: a flow between the device and srvPort with packets but no
// captured device SYN, and a packet at or after the clean point.
// l73Conns counts a connection only from its SYN, so such a flow is no
// l73Conn and l94SinceClean cannot see it; port49 may have accepted it
// after the gauge's first 0. A flow wholly before the clean point ended
// before it (the gauge says so) and is ignored. It reads the savefile with
// the same reader as l73Conns, headers only: addresses, ports, flags and
// times. No payload byte is read and no body is decoded.
func l94OlderThanCapture(raw []byte, device string, srvPort uint16, cleanAt time.Time) error {
	f, err := labpcap.Parse(raw)
	if err != nil {
		return fmt.Errorf("INVALID: reading the cell's capture for connections older than it: %w", err)
	}
	type orphan struct{ first, last time.Time }
	synced := map[uint16]bool{} // device ports whose SYN the capture holds
	orphans := map[uint16]*orphan{}
	for i, r := range f.Records {
		fl, ok := labpcap.FlowOf(f.Link, f.Bytes(r))
		if !ok {
			continue
		}
		var port uint16
		fromDevice := fl.Src.String() == device && fl.DstPort == srvPort
		switch {
		case fromDevice:
			port = fl.SrcPort
		case fl.Dst.String() == device && fl.SrcPort == srvPort:
			port = fl.DstPort
		default:
			continue
		}
		if fromDevice && fl.SYN() {
			synced[port] = true // a new connection on this port, counted by l73Conns
			continue
		}
		if synced[port] {
			continue
		}
		at := f.TimeOf(i)
		if o := orphans[port]; o == nil {
			orphans[port] = &orphan{at, at}
		} else {
			o.last = at
		}
	}
	for _, port := range slices.Sorted(maps.Keys(orphans)) {
		if o := orphans[port]; !o.last.Before(cleanAt) {
			return fmt.Errorf("INVALID: a connection older than the capture: device port %d sent or received packets from %s to %s with no SYN captured, the last at or after the cell's clean point %s; the capture did not start clean",
				port, o.first.UTC().Format("15:04:05.000"), o.last.UTC().Format("15:04:05.000"), cleanAt.UTC().Format("15:04:05.000"))
		}
	}
	return nil
}
