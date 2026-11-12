package lab

import (
	"errors"
	"fmt"
	"maps"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
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
//	c2  forced reorder: B logged in; A logs in with a stale token (FAIL after
//	    the 2s delay); within 200ms of A's request B types the permitted and
//	    the denied command
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
	// l94MinGap is c2's pass line: B's requests precede A's FAIL by at least this.
	l94MinGap = 1500 * time.Millisecond
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

// l94Fails are recs' FAIL redeems, in order: the stale-token logins.
func l94Fails(evs []l94Event) []l94Event {
	var out []l94Event
	for _, e := range evs {
		if e.Event == "redeem" && e.Verdict == "deny" {
			out = append(out, e)
		}
	}
	return out
}

// l94Gaps is, for each of B's command events, how long before the first FAIL
// redeem it was recorded (negative: after it). ok is false with no FAIL.
// The FAIL redeem is recorded once its delay has passed, so a B event
// recorded at least l94MinGap before it was answered inside A's delay.
func l94Gaps(platform string, evs []l94Event, cmds []string) (gaps []time.Duration, ok bool) {
	fails := l94Fails(evs)
	if len(fails) == 0 {
		return nil, false
	}
	for _, e := range evs {
		if l94BEvent(platform, e, cmds) {
			gaps = append(gaps, fails[0].TS.Sub(e.TS))
		}
	}
	return gaps, true
}

// l94C2Timing is whether c2's timing stands: every B event recorded after
// A's request was read (a gap no longer than the delay, with 250ms for the
// record's own write), and at least one B event. "early" asks for another
// play with a longer lead; "none" means B reached port49 not at all.
func l94C2Timing(gaps []time.Duration, delay time.Duration) string {
	if len(gaps) == 0 {
		return "none"
	}
	for _, g := range gaps {
		if g > delay+250*time.Millisecond {
			return "early"
		}
	}
	return "ok"
}

// l94Outcome is one A login's outcome, as the CLI saw it.
type l94Outcome struct {
	Took       float64 `json:"took_s"`
	AuthFailed bool    `json:"auth_failed"` // the device refused the login (not a timeout, not a login)
	LoggedIn   bool    `json:"logged_in"`   // a stale token logged in: a fall-through or worse
	Err        string  `json:"err,omitempty"`
}

// l94OutcomeOf classifies A's login: err nil is a login (which a stale token
// must never get), an SSH authentication refusal is a failure delivered, and
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

// l94Dup is a duplicate or retransmitted request: an authorize_command for a
// command more often than it was typed, or an account record whose flags and
// task_id repeat.
func l94Dup(evs []l94Event, typed []l80Typed) []string {
	typedN := map[string]int{}
	for _, x := range typed {
		typedN[x.Command]++
	}
	asked := map[string]int{}
	acct := map[string]int{}
	for _, e := range evs {
		switch e.Event {
		case "authorize_command":
			asked[e.Vector]++
		case "account":
			if e.TaskID != "" {
				acct[e.Flags+"/"+e.TaskID]++
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
func l94Suspect(kept string) int {
	n := 0
	for _, ln := range strings.Split(kept, "\n") {
		if l94SuspectMarks.MatchString(ln) {
			n++
		}
	}
	return n
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
	// in the cell's window, or l94Suspect's count elsewhere.
	DeadOrSSL int
	Outcomes  []l94Outcome // c2/c3/c5: A's logins
	Baseline  *l94Baseline // the baseline arm's evidence, when it was run
	Gaps      []time.Duration
	// Restart is c5's window.
	RestartAt, UpAt time.Time
}

// l94Baseline is what the fixed arm compares to: the baseline arm's evidence
// for the same cell and platform.
type l94Baseline struct {
	MaxTook  float64
	Outcomes []l94Outcome
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
	_, denied := l94Commands(g.Platform)
	commanded := l94Commanded(g.Platform)
	for _, x := range g.Typed {
		if commanded && !x.Asked && (g.Cell != "c5" || l80Ran(x)) {
			out = append(out, fmt.Sprintf("%s: session %d %q was never asked: lost or run unasked", g.Cell, x.Session, x.Command))
		}
		if commanded && x.Command == denied && !x.Denied && !x.Err {
			out = append(out, fmt.Sprintf("%s: session %d %q, which port49 denies, ran", g.Cell, x.Session, x.Command))
		}
		if !commanded && x.Err {
			out = append(out, fmt.Sprintf("%s: session %d %q never got its prompt back", g.Cell, x.Session, x.Command))
		}
	}
	out = append(out, prefixAll(g.Cell+": ", l94Dup(g.Events, g.Typed))...)
	if g.Cell != "c5" && (g.Conns != 1 || g.MostOpen > 1) {
		out = append(out, fmt.Sprintf("%s: %d TLS connection(s), %d open at once: the cell must hold exactly one", g.Cell, g.Conns, g.MostOpen))
	}
	if g.Second > 0 {
		out = append(out, fmt.Sprintf("%s: single_connect_second_connection +%v", g.Cell, g.Second))
	}
	if g.DeadOrSSL > 0 {
		out = append(out, fmt.Sprintf("%s: %d device debug line(s) naming a dead server, a TLS read error, a fall-through or a session/sequence complaint: read the kept debug", g.Cell, g.DeadOrSSL))
	}
	for i, o := range g.Outcomes {
		if o.LoggedIn {
			out = append(out, fmt.Sprintf("%s: stale-token login %d logged in: a fall-through or worse", g.Cell, i+1))
		}
	}
	switch g.Cell {
	case "c2":
		for i, gap := range g.Gaps {
			if gap < l94MinGap {
				out = append(out, fmt.Sprintf("c2: B's request %d was recorded %s before A's FAIL, under %s: it waited behind A", i+1, gap.Round(time.Millisecond), l94MinGap))
			}
		}
		for _, x := range g.Typed {
			if x.Took > l94FastB.Seconds() {
				out = append(out, fmt.Sprintf("c2: B's %q took %.2fs, over %s", x.Command, x.Took, l94FastB))
			}
		}
		if len(g.Outcomes) != 1 || !g.Outcomes[0].AuthFailed {
			out = append(out, "c2: A's stale-token login was not refused as an authentication failure")
		}
	case "c3":
		limit := g.P.Timeout.Seconds()
		if g.Baseline != nil && (limit == 0 || g.Baseline.MaxTook < limit) {
			limit = g.Baseline.MaxTook
		}
		for _, x := range g.Typed {
			if limit > 0 && x.Took > limit {
				out = append(out, fmt.Sprintf("c3: B's %q took %.2fs, above %.2fs (the baseline arm's slowest, or %s)", x.Command, x.Took, limit, g.P.TimeoutFrom))
			}
		}
		if n := l94FailsDelivered(g.Outcomes); n != l94C3Fails {
			out = append(out, fmt.Sprintf("c3: %d of %d FAILs delivered as an authentication failure", n, l94C3Fails))
		}
		if len(l94Fails(g.Events)) != l94C3Fails {
			out = append(out, fmt.Sprintf("c3: port49 recorded %d FAIL redeem(s), want %d", len(l94Fails(g.Events)), l94C3Fails))
		}
	case "c5":
		if g.UpAt.IsZero() {
			out = append(out, "c5: port49d did not come back after the restart")
		} else if commanded && !slices.ContainsFunc(g.Typed, func(x l80Typed) bool { return x.Asked && x.At.After(g.UpAt) }) {
			out = append(out, "c5: no command after the restart was asked: the device did not reconnect")
		}
	}
	if g.Baseline != nil && (g.Cell == "c2" || g.Cell == "c3") {
		out = append(out, prefixAll(g.Cell+": ", l94Regressed(g.Baseline.Outcomes, g.Outcomes))...)
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
func l94DelayConfig(text string, d time.Duration) (string, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(text), &doc); err != nil {
		return "", err
	}
	if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return "", errors.New("the config is not a mapping")
	}
	m := doc.Content[0]
	var limits *yaml.Node
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == "limits" {
			limits = m.Content[i+1]
		}
	}
	if limits == nil {
		limits = &yaml.Node{Kind: yaml.MappingNode}
		m.Content = append(m.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: "limits"}, limits)
	}
	if limits.Kind != yaml.MappingNode {
		return "", errors.New("limits is not a mapping")
	}
	for _, k := range []string{"auth_failure_delay_base", "auth_failure_delay_max"} {
		set := false
		for i := 0; i+1 < len(limits.Content); i += 2 {
			if limits.Content[i].Value == k {
				limits.Content[i+1] = &yaml.Node{Kind: yaml.ScalarNode, Value: d.String()}
				set = true
			}
		}
		if !set {
			limits.Content = append(limits.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: k}, &yaml.Node{Kind: yaml.ScalarNode, Value: d.String()})
		}
	}
	out, err := yaml.Marshal(&doc)
	return string(out), err
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

// binaryTags is `go version -m path`'s -tags.
func binaryTags(path string) (string, error) {
	out, err := exec.Command("go", "version", "-m", path).Output()
	if err != nil {
		return "", fmt.Errorf("go version -m %s: %w", path, err)
	}
	return parseBuildTags(string(out)), nil
}
