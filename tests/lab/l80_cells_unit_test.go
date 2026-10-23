package lab

import (
	"slices"
	"strings"
	"testing"
	"time"
)

// The cells are the design's: the baseline runs s1 and s3; the fixed arm adds
// sp, each idle gap at least 5 times (35 s twice), and three concurrent
// sessions of arm E's sequence 1 with `show users`.
func TestL80CellsAreTheDesigns(t *testing.T) {
	names := func(cs []l80Cell) string {
		var out []string
		for _, c := range cs {
			out = append(out, c.Name)
		}
		return strings.Join(out, ",")
	}
	if got := names(l80Cells("baseline")); got != "s1,s3" {
		t.Fatalf("baseline cells %s", got)
	}
	fixed := l80Cells("fixed")
	if got := names(fixed); got != "s1,s3,sp,idle29,idle30,idle31,idle35,concurrent,restart" {
		t.Fatalf("fixed cells %s", got)
	}
	for _, c := range fixed {
		gaps := map[string]int{}
		for _, cmd := range c.Sessions[0] {
			if g, ok := strings.CutPrefix(cmd, "@sleep "); ok {
				gaps[g]++
			}
		}
		switch c.Name {
		case "idle29", "idle30", "idle31":
			if gaps[strings.TrimPrefix(c.Name, "idle")] < 5 {
				t.Errorf("%s samples its gap %v times, want at least 5", c.Name, gaps)
			}
		case "idle35":
			if gaps["35"] < 2 {
				t.Errorf("idle35 samples %v", gaps)
			}
		case "concurrent":
			if len(c.Sessions) != 3 || c.Sessions[0][len(c.Sessions[0])-1] != "show users" {
				t.Errorf("concurrent: %d sessions, %v", len(c.Sessions), c.Sessions[0])
			}
		}
		for _, s := range c.Sessions {
			for i, cmd := range s {
				if c.Name != "restart" && strings.HasPrefix(cmd, "@sleep ") && (i+1 >= len(s) || s[i+1] != "show users") {
					t.Errorf("%s: a gap not followed by `show users`", c.Name)
				}
			}
		}
	}
}

func TestL80AskMatchesRecordsInOrder(t *testing.T) {
	typed := []l80Typed{{Command: "terminal length 0"}, {Command: "show users"}, {Command: "terminal length 0"}, {Command: "show users"}}
	l80Ask(typed, []string{"show users", "terminal length 0", "show users"})
	if !typed[0].Asked || !typed[1].Asked || typed[2].Asked || !typed[3].Asked {
		t.Fatalf("%+v", typed)
	}
}

func TestL80StopsAreTheDesigns(t *testing.T) {
	ok := []l80Typed{{Command: "terminal length 0", Asked: true}, {Command: "show users", Asked: true, Denied: true}}
	if s := l80Stops("fixed", "idle31", ok, 1, 0, nil); len(s) != 0 {
		t.Fatalf("a clean sample stops: %v", s)
	}
	lost := []l80Typed{{Command: "terminal length 0", Asked: true}, {Command: "show users", Gap: 31}}
	if s := l80Stops("fixed", "idle31", lost, 1, 0, nil); len(s) != 2 {
		t.Fatalf("a lost and run `show users` is two stops: %v", s)
	}
	if s := l80Stops("baseline", "s1", lost, 1, 0, nil); len(s) != 0 {
		t.Fatalf("the baseline stops on nothing: %v", s)
	}
	if s := l80Stops("fixed", "concurrent", ok, 2, 0, nil); len(s) != 1 {
		t.Fatalf("two connections at once: %v", s)
	}
	if s := l80Stops("fixed", "concurrent", ok, 1, 1, nil); len(s) != 1 {
		t.Fatalf("a second-connection count with every command asked: %v", s)
	}
	if s := l80Stops("fixed", "idle31", ok, 2, 0, nil); len(s) != 0 {
		t.Fatalf("most open at once is the concurrent cell's stop: %v", s)
	}
	// Review M4 (c): a second-connection count in a sequential cell is the
	// same false fire.
	if s := l80Stops("fixed", "s1", ok, 1, 1, nil); len(s) != 1 {
		t.Fatalf("a second-connection count in a sequential cell: %v", s)
	}
	// Review M4 (b): past the idle close the device reconnects cleanly.
	dead := map[string]int{"ssl_read_failed": 1, "mark_server_dead": 1}
	for _, cell := range []string{"idle31", "idle35"} {
		if s := l80Stops("fixed", cell, ok, 1, 0, dead); len(s) != 2 {
			t.Fatalf("%s with a failed read and a dead mark: %v", cell, s)
		}
	}
	if s := l80Stops("fixed", "idle29", ok, 1, 0, dead); len(s) != 0 {
		t.Fatalf("the read and dead stops are the past-the-close cells': %v", s)
	}
}

// Review M4 (a): the concurrent summary says interleaving is not observable.
func TestL80InterleavingIsSaidNotObservable(t *testing.T) {
	if !strings.Contains(l80Interleaving, "not observable") || !strings.Contains(l80Interleaving, "ciphertext") {
		t.Fatalf("%q", l80Interleaving)
	}
}

func TestL80MostOpen(t *testing.T) {
	at := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	c := func(syn, end time.Duration, how string) l73Conn {
		x := l73Conn{SYNAt: at.Add(syn), End: how}
		if how != "open" {
			x.EndAt = at.Add(end)
		}
		return x
	}
	if n := l80MostOpen([]l73Conn{c(0, time.Second, "server-fin"), c(2*time.Second, 3*time.Second, "server-fin")}); n != 1 {
		t.Fatalf("one after another: %d", n)
	}
	if n := l80MostOpen([]l73Conn{c(0, 0, "open"), c(2*time.Second, 3*time.Second, "server-fin")}); n != 2 {
		t.Fatalf("one held open: %d", n)
	}
}

// The timeline keeps the time, the event, the verdict and a command's words,
// and nothing else from a record.
func TestL80TimelineKeepsNoOtherField(t *testing.T) {
	recs := []map[string]any{
		{"ts": "2026-10-22T12:00:01.5Z", "event": "authorize_command", "verdict": "deny",
			"request": map[string]any{"vector": []any{"show", "users"}}, "credential_sha256": "fakehash01"},
		{"ts": "2026-10-22T12:00:02Z", "event": "unvalidated", "diagnosis": "fakediag"},
		{"ts": "2026-10-22T12:00:03Z", "event": "redeem", "verdict": "permit", "session": map[string]any{"username": "fakeuser9"}},
	}
	got := strings.Join(l80Timeline(recs), "\n")
	if got != "12:00:01.500 authorize_command deny \"show users\"\n12:00:03.000 redeem permit" {
		t.Fatalf("%q", got)
	}
}

// Fix round 4: readiness is the device reaching port49d. A device port49
// offered single-connect sends the probe on the connection it holds, so
// the probe's capture holds no new SYN; port49's record of the probe is
// enough. A new SYN alone still counts, as L73 cell a needs (a port
// nothing answers TLS on records nothing).
func TestL73ReadyIsAConnectionOrARecord(t *testing.T) {
	at := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	syn := []l73Conn{{Server: l73Server + ":300", SYNAt: at.Add(time.Second)}}
	rec := []map[string]any{{"event": "redeem", "verdict": "deny"}}
	for name, c := range map[string]struct {
		conns []l73Conn
		recs  []map[string]any
		want  bool
	}{
		"a new connection, no record":                 {syn, nil, true},
		"a record over a held connection, no new SYN": {nil, rec, true},
		"neither":                                  {nil, nil, false},
		"a SYN to another address, no record":      {[]l73Conn{{Server: "192.0.2.9:300", SYNAt: at.Add(time.Second)}}, nil, false},
		"a connection before the probe, no record": {[]l73Conn{{Server: l73Server + ":300", SYNAt: at.Add(-time.Second)}}, nil, false},
	} {
		if got := l73Ready(c.conns, at, at.Add(time.Minute), c.recs); got != c.want {
			t.Errorf("%s: %v, want %v", name, got, c.want)
		}
	}
}

// Fix round 4: an L80 cell opens on a fresh connection, so it waits, without
// probing, for no connection open, past port49d's default idle close (L80
// runs it: DefaultIdle).
func TestL80CleanWaitOutlastsTheDefaultIdleClose(t *testing.T) {
	if time.Duration(l80CleanPolls)*time.Second < l80DefaultIdle+30*time.Second {
		t.Fatalf("the wait (%ds) does not outlast the default idle close %v", l80CleanPolls, l80DefaultIdle)
	}
}

// The restart cell: 20 permitted commands, a `show users` after every fourth,
// one every half second, and "@restart" after the 8th permitted command; no
// other cell has one, and the baseline arm has none.
func TestL80RestartSequenceIsTheDesigns(t *testing.T) {
	var seq []string
	for _, c := range l80Cells("fixed") {
		if c.Name == "restart" {
			seq = c.Sessions[0]
		}
		if c.Name != "restart" && slices.Contains(c.Sessions[0], "@restart") {
			t.Errorf("%s restarts port49d", c.Name)
		}
	}
	if seq == nil || seq[0] != "terminal length 0" {
		t.Fatalf("no restart cell, or it does not open on terminal length 0: %v", seq)
	}
	permitted, users, at := 0, 0, -1
	for i, cmd := range seq {
		switch cmd {
		case "show clock", "show version":
			permitted++
		case "show users":
			users++
		case "@restart":
			at = permitted
			if i == 0 || seq[i-1] == "@sleep 0.5" {
				t.Errorf("@restart is not right after a typed command")
			}
		case "@sleep 0.5", "terminal length 0":
		default:
			t.Errorf("unexpected %q", cmd)
		}
	}
	if permitted != 20 || users != 5 || at != 8 {
		t.Errorf("%d permitted, %d show users, restart after %d", permitted, users, at)
	}
	for _, c := range l80Cells("baseline") {
		if c.Name == "restart" {
			t.Errorf("the baseline arm has a restart cell")
		}
	}
}

// The restart sequence types only listed words.
func TestL80RestartSequenceUsesOnlyListedWords(t *testing.T) {
	for _, cmd := range l80RestartSeq() {
		if strings.HasPrefix(cmd, "@") {
			continue
		}
		for _, w := range strings.Fields(cmd) {
			if !slices.Contains(nxosDebugWords, w) {
				t.Errorf("%q types %q, which nxosDebugWords does not list", cmd, w)
			}
		}
	}
}

var l80T0 = time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)

// typedAt is a command typed at l80T0+at that came back 0.4 s later.
func typedAt(cmd string, at float64, asked, denied bool) l80Typed {
	a := l80T0.Add(time.Duration(at * float64(time.Second)))
	return l80Typed{Command: cmd, At: a, Done: a.Add(400 * time.Millisecond), Asked: asked, Denied: denied}
}

// The window: port49d stops at +10 s and is listening again at +13 s.
var l80Win = l80RestartWindow{StopAt: l80T0.Add(10 * time.Second), UpAt: l80T0.Add(13 * time.Second)}

func l80Conns(closeNotify bool) []l73Conn {
	old := l73Conn{SYNAt: l80T0, Answer: "syn-ack", End: "server-fin", EndAt: l80T0.Add(10 * time.Second).Add(20 * time.Millisecond)}
	if closeNotify {
		old.Alerts = []l73Alert{{Level: 1, Description: 0, FromDevice: false}}
	}
	return []l73Conn{old,
		{SYNAt: l80T0.Add(11 * time.Second), Answer: "rst", End: "server-rst", EndAt: l80T0.Add(11 * time.Second)}, // port49d down
		{SYNAt: l80T0.Add(13500 * time.Millisecond), Answer: "syn-ack", End: "open"}}
}

func has(facts []string, sub string) bool {
	for _, f := range facts {
		if strings.Contains(f, sub) {
			return true
		}
	}
	return false
}

// A clean reconnect: every command asked, the device found the close on read
// and opened a new connection once port49d was back.
func TestL80RestartGradesACleanReconnect(t *testing.T) {
	typed := []l80Typed{typedAt("show clock", 8, true, false), typedAt("show users", 9, true, true),
		typedAt("show version", 11, true, false), typedAt("show clock", 14, true, false)}
	g := l80GradeRestart(l80StoreMemory, typed, l80Win, map[string]int{"ssl_read_failed": 1}, 0, l80Conns(true))
	if g.Verdict != l80RestartClean || g.Permitted != 3 || g.Denied != 1 || g.Lost != 0 || g.Unasked != 0 || g.Reconnects != 1 {
		t.Fatalf("%+v", g)
	}
	if !has(g.Facts, "close_notify: seen as a plaintext alert") || !has(g.Facts, "ended: server-fin +0.02s after the stop") {
		t.Errorf("facts %v", g.Facts)
	}
	if l80Stops("fixed", "restart", typed, 1, 0, map[string]int{"ssl_read_failed": 1}) != nil {
		t.Errorf("a clean restart stops")
	}
}

// A lost request: two commands typed while port49d was down never reached it
// and did not run; the device marked the server dead and fell back.
func TestL80RestartGradesALostRequest(t *testing.T) {
	typed := []l80Typed{typedAt("show clock", 8, true, false),
		typedAt("show version", 11, false, true), typedAt("show clock", 12, false, true),
		typedAt("show clock", 16, true, false)}
	g := l80GradeRestart(l80StoreMemory, typed, l80Win, map[string]int{"ssl_read_failed": 1, "mark_server_dead": 1}, 1, l80Conns(false))
	if g.Verdict != l80RestartLost || g.Lost != 2 || g.LostAcross != 2 || g.Unasked != 0 {
		t.Fatalf("%+v", g)
	}
	if !has(g.Facts, "mark_server_dead=1") || !has(g.Facts, "fallback_lines=1") || !has(g.Facts, "close_notify: not seen") {
		t.Errorf("facts %v", g.Facts)
	}
	// A lost command is the cell's result, not a stop.
	if s := l80Stops("fixed", "restart", typed, 1, 0, nil); len(s) != 0 {
		t.Errorf("a lost command stops the restart cell: %v", s)
	}
	if s := l80Stops("fixed", "idle31", typed, 1, 0, nil); len(s) != 2 {
		t.Errorf("another cell must still stop on a lost command: %v", s)
	}
}

// An unasked command: the device ran a command port49 was never asked about,
// and a `show users` it ran too. That is the failure L80 measures.
func TestL80RestartGradesAnUnaskedCommand(t *testing.T) {
	typed := []l80Typed{typedAt("show clock", 8, true, false),
		typedAt("show version", 11, false, false), typedAt("show users", 12, false, false),
		typedAt("show clock", 14, true, false)}
	g := l80GradeRestart(l80StoreMemory, typed, l80Win, map[string]int{"mark_server_dead": 1}, 1, l80Conns(false))
	if g.Verdict != l80RestartUnasked || g.Unasked != 2 || g.UnaskedAcross != 2 || g.Lost != 0 {
		t.Fatalf("%+v", g)
	}
	if s := l80Stops("fixed", "restart", typed, 1, 0, nil); len(s) != 3 {
		t.Errorf("two unasked commands and a `show users` that ran are three stops: %v", s)
	}
	// A command that did not answer is not one that ran.
	typed[1].Err = true
	if g := l80GradeRestart(l80StoreMemory, typed, l80Win, nil, 0, l80Conns(false)); g.Unasked != 1 || g.Lost != 1 {
		t.Errorf("an errored command: %+v", g)
	}
}

// What the capture and the records cannot place is absent, not inferred.
func TestL80RestartLeavesOutWhatItCannotPlace(t *testing.T) {
	typed := []l80Typed{typedAt("show clock", 11, false, true)}
	g := l80GradeRestart(l80StoreMemory, typed, l80RestartWindow{}, nil, 0, l80Conns(true))
	if g.LostAcross != 0 || g.Reconnects != 0 || g.Verdict != l80RestartLost {
		t.Errorf("%+v", g)
	}
	for _, f := range g.Facts {
		if strings.Contains(f, "while port49d was down") || strings.Contains(f, "close_notify") || strings.Contains(f, "answered by port49") {
			t.Errorf("an unplaced fact is stated: %q", f)
		}
	}
	if !has(g.Facts, "restart window not recorded") {
		t.Errorf("facts %v", g.Facts)
	}
	// A command whose typed time is unknown is not placed either.
	x := typedAt("show clock", 11, false, true)
	x.At, x.Done = time.Time{}, time.Time{}
	if g := l80GradeRestart(l80StoreMemory, []l80Typed{x}, l80Win, nil, 0, nil); g.Lost != 1 || g.LostAcross != 0 {
		t.Errorf("%+v", g)
	}
	// A command typed and answered before the stop is not across it.
	if g := l80GradeRestart(l80StoreMemory, []l80Typed{typedAt("show clock", 2, false, true)}, l80Win, nil, 0, nil); g.LostAcross != 0 {
		t.Errorf("%+v", g)
	}
	// With port49d never back up, a command typed after the stop is across it.
	if g := l80GradeRestart(l80StoreMemory, []l80Typed{typedAt("show clock", 40, false, true)}, l80RestartWindow{StopAt: l80Win.StopAt}, nil, 0, nil); g.LostAcross != 1 {
		t.Errorf("%+v", g)
	}
}

func TestL80RestartOtherVerdicts(t *testing.T) {
	typed := []l80Typed{typedAt("show clock", 8, true, false), typedAt("show clock", 14, true, false)}
	if g := l80GradeRestart(l80StoreMemory, typed, l80Win, nil, 0, l80Conns(false)[:2]); g.Verdict != l80RestartNoConn || g.Reconnects != 0 {
		t.Errorf("no connection after the stop: %+v", g)
	}
	if g := l80GradeRestart(l80StoreMemory, typed, l80Win, map[string]int{"mark_server_dead": 1}, 0, l80Conns(false)); g.Verdict != l80RestartDeadOnly {
		t.Errorf("dead mark with nothing lost: %+v", g)
	}
	if g := l80GradeRestart(l80StoreMemory, typed, l80Win, nil, 1, l80Conns(false)); g.Verdict != l80RestartDeadOnly {
		t.Errorf("a fallback with nothing lost: %+v", g)
	}
}

// A close_notify counts only from port49 (the server) on a connection open at
// the stop; the device's own alert, or one on a connection that had already
// ended, does not.
func TestL80RestartCloseNotifyIsPort49sOnAConnectionOpenAtTheStop(t *testing.T) {
	typed := []l80Typed{typedAt("show clock", 8, true, false)}
	conns := l80Conns(false)
	conns[0].Alerts = []l73Alert{{Level: 1, Description: 0, FromDevice: true}}
	if g := l80GradeRestart(l80StoreMemory, typed, l80Win, nil, 0, conns); !has(g.Facts, "close_notify: not seen") {
		t.Errorf("the device's own close_notify was taken for port49's: %v", g.Facts)
	}
	conns = l80Conns(true)
	conns[0].EndAt = l80Win.StopAt.Add(-time.Second) // ended before the restart
	if g := l80GradeRestart(l80StoreMemory, typed, l80Win, nil, 0, conns); !has(g.Facts, "close_notify: not seen") {
		t.Errorf("a close before the stop was placed at it: %v", g.Facts)
	}
}

// A command typed after port49d was back is not across the restart.
func TestL80RestartAfterTheWindowIsNotAcross(t *testing.T) {
	typed := []l80Typed{typedAt("show clock", 20, false, true), typedAt("show clock", 11, false, true)}
	if g := l80GradeRestart(l80StoreMemory, typed, l80Win, nil, 0, nil); g.Lost != 2 || g.LostAcross != 1 {
		t.Errorf("%+v", g)
	}
}

// A permitted command asked about and denied after the restart is a port49
// finding (the session did not survive), ranked above a lost request and below
// an unasked command; `show users` denied is the policy working.
func TestL80RestartGradesAPermittedCommandDeniedAfterTheRestart(t *testing.T) {
	typed := []l80Typed{typedAt("show clock", 8, true, false), typedAt("show users", 9, true, true),
		typedAt("show version", 14, true, true), typedAt("show users", 15, true, true)}
	g := l80GradeRestart(l80StoreMemory, typed, l80Win, nil, 0, l80Conns(false))
	if g.Verdict != l80RestartPermDenied || g.PermittedDenied != 1 || g.Denied != 3 {
		t.Fatalf("%+v", g)
	}
	if !has(g.Facts, `permitted command "show version" typed 4.0s after the stop was asked about and denied: the session did not survive the restart`) {
		t.Errorf("no per-command line: %v", g.Facts)
	}
	// Before the stop it is an ordinary denial; `show users` after it is the policy.
	ord := []l80Typed{typedAt("show version", 5, true, true), typedAt("show users", 15, true, true)}
	if g := l80GradeRestart(l80StoreMemory, ord, l80Win, nil, 0, l80Conns(false)); g.Verdict != l80RestartClean || g.PermittedDenied != 0 {
		t.Errorf("%+v", g)
	}
	// Ranks: an unasked command is above it, a lost request below it.
	if g := l80GradeRestart(l80StoreMemory, append(typed, typedAt("show clock", 16, false, false)), l80Win, nil, 0, l80Conns(false)); g.Verdict != l80RestartUnasked {
		t.Errorf("unasked must stay on top: %+v", g)
	}
	if g := l80GradeRestart(l80StoreMemory, append(typed, typedAt("show clock", 16, false, true)), l80Win, nil, 0, l80Conns(false)); g.Verdict != l80RestartPermDenied || g.Lost != 1 {
		t.Errorf("above a lost request: %+v", g)
	}
	// Unplaced: no stop recorded, no finding.
	if g := l80GradeRestart(l80StoreMemory, typed, l80RestartWindow{}, nil, 0, nil); g.PermittedDenied != 0 {
		t.Errorf("a finding without a recorded stop: %+v", g)
	}
}

func withReason(x l80Typed, reason string) l80Typed { x.Reason = reason; return x }

func ctxMissing(typed ...l80Typed) []l80Typed {
	for i := range typed {
		if typed[i].Denied && typed[i].Command != "show users" {
			typed[i].Reason = l80ReasonContextMissing
		}
	}
	return typed
}

// On the memory store a restart loses every login context, so each permitted
// command after it is denied context_missing: the documented behavior, measured,
// and not a stop.
func TestL80RestartMemoryStoreContextMissingIsNotAFinding(t *testing.T) {
	typed := ctxMissing(typedAt("show clock", 8, true, false), typedAt("show users", 9, true, true),
		typedAt("show version", 14, true, true), typedAt("show clock", 15, true, true))
	g := l80GradeRestart(l80StoreMemory, typed, l80Win, nil, 0, l80Conns(false))
	if g.Verdict != l80RestartCtxLost || g.PermittedDenied != 2 || g.ContextMissing != 2 {
		t.Fatalf("%+v", g)
	}
	if !has(g.Facts, "session store memory: 2 of 2 permitted commands denied after the stop were denied context_missing") {
		t.Errorf("facts: %v", g.Facts)
	}
}

// One denial after the restart for any other reason is the port49 finding.
func TestL80RestartMemoryStoreAnotherReasonStaysAFinding(t *testing.T) {
	typed := ctxMissing(typedAt("show clock", 8, true, false), typedAt("show version", 14, true, true), typedAt("show clock", 15, true, true))
	typed[2].Reason = "policy_deny"
	if g := l80GradeRestart(l80StoreMemory, typed, l80Win, nil, 0, l80Conns(false)); g.Verdict != l80RestartPermDenied || g.ContextMissing != 1 {
		t.Errorf("%+v", g)
	}
	// A denial with no record to read a reason from is not context_missing.
	typed[2].Reason = ""
	if g := l80GradeRestart(l80StoreMemory, typed, l80Win, nil, 0, l80Conns(false)); g.Verdict != l80RestartPermDenied {
		t.Errorf("no reason: %+v", g)
	}
}

// On etcd the contexts are kept, so context_missing is the finding.
func TestL80RestartEtcdContextMissingIsAFinding(t *testing.T) {
	typed := ctxMissing(typedAt("show clock", 8, true, false), typedAt("show version", 14, true, true))
	if g := l80GradeRestart(l80StoreEtcd, typed, l80Win, nil, 0, l80Conns(false)); g.Verdict != l80RestartPermDenied {
		t.Errorf("%+v", g)
	}
	if got := l80RestartStore("restart_etcd") + l80RestartStore("restart"); got != "etcdmemory" {
		t.Errorf("stores %q", got)
	}
}

// The memory verdict ranks under an unasked command and a lost request, above the rest.
func TestL80RestartContextLostRanks(t *testing.T) {
	base := ctxMissing(typedAt("show clock", 8, true, false), typedAt("show version", 14, true, true))
	if g := l80GradeRestart(l80StoreMemory, append(slices.Clone(base), typedAt("show clock", 16, false, false)), l80Win, nil, 0, l80Conns(false)); g.Verdict != l80RestartUnasked {
		t.Errorf("unasked: %+v", g)
	}
	if g := l80GradeRestart(l80StoreMemory, append(slices.Clone(base), typedAt("show clock", 16, false, true)), l80Win, nil, 0, l80Conns(false)); g.Verdict != l80RestartLost {
		t.Errorf("lost: %+v", g)
	}
	if g := l80GradeRestart(l80StoreMemory, base, l80Win, map[string]int{"mark_server_dead": 1}, 0, l80Conns(false)); g.Verdict != l80RestartCtxLost {
		t.Errorf("dead: %+v", g)
	}
}

func TestL80ReasonsFollowTheRecordsInOrder(t *testing.T) {
	rec := func(cmd, reason string) map[string]any {
		return map[string]any{"event": "authorize_command", "reason": reason,
			"request": map[string]any{"vector": []any{cmd}}}
	}
	typed := []l80Typed{{Command: "show clock"}, {Command: "show clock", Denied: true}, {Command: "show users", Denied: true}, {Command: "show clock", Denied: true}}
	l80Reasons(typed, []map[string]any{rec("show clock", "ok"), rec("show clock", "context_missing"), rec("show users", "policy_deny"),
		{"event": "account", "reason": "x"}, rec("show clock", "store_unavailable")})
	got := typed[0].Reason + "|" + typed[1].Reason + "|" + typed[2].Reason + "|" + typed[3].Reason
	if got != "|context_missing|policy_deny|store_unavailable" {
		t.Errorf("%q", got)
	}
}

// A verdict is longer than the 24-character mask; the summary must still name it.
func TestL80FilterKeepsOnlyAKnownRestartVerdict(t *testing.T) {
	for _, v := range []string{l80RestartCtxLost, l80RestartPermDenied, l80RestartClean} {
		if got := l80Filter("restart verdict: " + v); got != "restart verdict: "+v {
			t.Errorf("%q masked: %q", v, got)
		}
	}
	long := "restart verdict: " + strings.Repeat("a", 40)
	if got := l80Filter(long); got != "restart verdict: <LONG>" {
		t.Errorf("an unknown word must stay masked: %q", got)
	}
	if got := l80Filter("restart verdict: " + l80RestartCtxLost + " token"); got != "" {
		t.Errorf("a secret word must still drop the line: %q", got)
	}
}
