package lab

import (
	"fmt"
	"slices"
	"strings"
	"time"
)

// L80's re-measure on nxos106 over per-request TLS (spec §15 L80; §13
// decision 50 ruling 20; design Task 7 lab step 2). These are the pure parts
// of l80_test.go: the cells, what each typed command did, and the stop
// conditions the design names.

// l80Cell is one login's worth (or, for the concurrent cell, three logins
// started within a second) of commands; "@sleep N" waits N seconds.
type l80Cell struct {
	Name     string
	Sessions [][]string
}

// l80Cells are the arm's cells. The baseline (the build before Task 7's
// code) runs s1 and s3 once, the before-the-fix evidence; the fixed arm runs
// the A/B's s1, s3 and sp, the idle boundary at port49d's default
// idle_timeout (30 s) with each gap at least 5 times (35 s twice), and the
// concurrent-sessions cell.
func l80Cells(arm string) []l80Cell {
	cells := []l80Cell{{"s1", [][]string{nxosSeqS1}}, {"s3", [][]string{nxosSeqS3}}}
	if arm == "baseline" {
		return cells
	}
	var sp []string
	for _, gap := range []string{"0.5", "1.9", "2.1", "10", "29", "31"} {
		sp = append(sp, nxosSeqSpacing[0], "@sleep "+gap, nxosSeqSpacing[1])
	}
	cells = append(cells, l80Cell{"sp", [][]string{sp}})
	for _, g := range []struct {
		gap string
		n   int
	}{{"29", 5}, {"30", 5}, {"31", 5}, {"35", 2}} {
		var seq []string
		for range g.n {
			seq = append(seq, nxosSeqSpacing[0], "@sleep "+g.gap, nxosSeqSpacing[1])
		}
		cells = append(cells, l80Cell{"idle" + g.gap, [][]string{seq}})
	}
	cells = append(cells, l80Cell{"concurrent", [][]string{nxosSeqE1, nxosSeqE1, nxosSeqE1}})
	return append(cells, l80Cell{"restart", [][]string{l80RestartSeq()}})
}

// The restart cell (device-debug shapes follow-up, step 3): port49d is stopped
// and started again in the middle of a command loop, on an offered NX-OS that
// holds one connection between requests, to see what the device does with the
// close_notify of the restart. The loop is l80RestartPermitted permitted
// commands, one every half second, with `show users` (denied) after every
// l80RestartDeniedEvery of them; "@restart" follows the l80RestartAfter-th
// permitted command and the loop keeps typing across the restart.
const (
	l80RestartPermitted   = 20
	l80RestartAfter       = 8
	l80RestartDeniedEvery = 4
)

func l80RestartSeq() []string {
	seq := []string{nxosSeqSpacing[0]}
	for i := 1; i <= l80RestartPermitted; i++ {
		cmd := "show clock"
		if i%2 == 0 {
			cmd = "show version"
		}
		seq = append(seq, "@sleep 0.5", cmd)
		if i == l80RestartAfter {
			seq = append(seq, "@restart")
		}
		if i%l80RestartDeniedEvery == 0 {
			seq = append(seq, "@sleep 0.5", nxosSeqSpacing[1])
		}
	}
	return seq
}

// l80Typed is one command as typed, and what came of it.
type l80Typed struct {
	Session int     `json:"session"`
	Command string  `json:"command"`
	Gap     float64 `json:"gap_s,omitempty"` // the sleep before it
	Took    float64 `json:"took_s"`
	Denied  bool    `json:"denied"` // its first output line said "AAA authorization failed"
	Asked   bool    `json:"asked"`  // an authorize_command record for it, matched in order
	// At and Done are when it was typed and when its prompt came back; Err is
	// that the prompt did not (a timeout or a lost session). The restart cell
	// places a command against the restart window with them.
	At   time.Time `json:"at,omitzero"`
	Done time.Time `json:"done,omitzero"`
	Err  bool      `json:"err,omitempty"`
	// Reason is port49's reason code on the authorize_command record this
	// command matched, when the device denied it (l80Reasons).
	Reason string `json:"reason,omitempty"`
}

// l80Ask marks each typed command asked while port49 has an unmatched
// authorize_command record of its words, in typing order; recorded is each
// record's command words in record order.
func l80Ask(typed []l80Typed, recorded []string) {
	left := map[string]int{}
	for _, v := range recorded {
		left[v]++
	}
	for i := range typed {
		if left[typed[i].Command] > 0 {
			left[typed[i].Command]--
			typed[i].Asked = true
		}
	}
}

// l80Reasons sets Reason on each denied typed command from the reason of the
// authorize_command record it matches, records taken in order as l80Ask takes
// them. A command with no matching record keeps no reason.
func l80Reasons(typed []l80Typed, recs []map[string]any) {
	left := map[string][]string{}
	for _, r := range recs {
		if r["event"] == "authorize_command" {
			reason, _ := r["reason"].(string)
			left[qualVector(r)] = append(left[qualVector(r)], reason)
		}
	}
	for i := range typed {
		q := left[typed[i].Command]
		if len(q) == 0 {
			continue
		}
		if typed[i].Denied {
			typed[i].Reason = q[0]
		}
		left[typed[i].Command] = q[1:]
	}
}

// l80MostOpen is the most connections open at once.
func l80MostOpen(conns []l73Conn) int {
	most := 0
	for _, x := range conns {
		n := 0
		for _, y := range conns {
			if !y.SYNAt.After(x.SYNAt) && (y.EndAt.IsZero() || y.End == "open" || y.EndAt.After(x.SYNAt)) {
				n++
			}
		}
		most = max(most, n)
	}
	return most
}

// l80Stops are the design's stop conditions for the fixed arm; the baseline
// is expected to lose commands and stops on nothing.
//   - any command lost or run unasked, and any `show users` not denied;
//   - single_connect_second_connection above 0 in any cell: the ignore
//     signal firing on honest use (review M4 c);
//   - in the concurrent cell, more than one connection open at once;
//   - past the idle close (idle31, idle35), any `nxos_ssl_read() failed` or
//     `mark server ... dead`: the device found the close only on write,
//     which is the fail-open path (review M4 b). counts is nxosDebugCounts.
func l80Stops(arm, cell string, typed []l80Typed, mostOpen int, second float64, counts map[string]int) []string {
	if arm == "baseline" {
		return nil
	}
	var out []string
	for _, x := range typed {
		// The restart cell measures lost commands: a command port49 never saw
		// that the device did not run is its result, not a stop. One that ran
		// unasked is the failure L80 measures.
		if !x.Asked && (!l80IsRestart(cell) || l80Ran(x)) {
			out = append(out, fmt.Sprintf("%s: session %d %q (after %.1fs) was never asked: lost or run unasked", cell, x.Session, x.Command, x.Gap))
		}
		if x.Command == "show users" && !x.Denied {
			out = append(out, fmt.Sprintf("%s: session %d `show users` (after %.1fs) was not denied", cell, x.Session, x.Gap))
		}
	}
	if second > 0 {
		out = append(out, fmt.Sprintf("%s: single_connect_second_connection +%v; the ignore signal fired on honest use", cell, second))
	}
	if cell == "concurrent" && mostOpen > 1 {
		out = append(out, fmt.Sprintf("concurrent: %d connections open at once; the ignore signal would fire on honest use", mostOpen))
	}
	if cell == "idle31" || cell == "idle35" {
		for _, k := range []string{"ssl_read_failed", "mark_server_dead"} {
			if counts[k] > 0 {
				out = append(out, fmt.Sprintf("%s: %s %d past the idle close; the device found the close only on write", cell, k, counts[k]))
			}
		}
	}
	return out
}

// l80Interleaving is what the concurrent cell's summary says of the design's
// "whether session_ids from different CLI sessions interleave on one
// connection" (review M4 a).
const l80Interleaving = "interleaving: not observable. The TACACS+ header, session_id included, is inside the TLS " +
	"ciphertext, and port49's records carry no connection identity (no source port or connection id; cert_sha256 is " +
	"the device's on every connection). Connections per device, above, is the measure."

// l80ConnLine is one connection in a summary: its port, when, how long, and
// who ended it.
func l80ConnLine(c l73Conn) string {
	hold := "open"
	if !c.EndAt.IsZero() && c.End != "open" {
		hold = fmt.Sprintf("%.2fs", c.EndAt.Sub(c.SYNAt).Seconds())
	}
	return fmt.Sprintf("conn port=%d syn=%s hold=%s end=%s", c.DevicePort, c.SYNAt.UTC().Format("15:04:05.000"), hold, c.End)
}

// l80Timeline is port49's records of a cell as the summary keeps them:
// time, event, verdict and the command's words, never anything else.
func l80Timeline(recs []map[string]any) []string {
	var out []string
	for _, r := range recs {
		ev, _ := r["event"].(string)
		if !slices.Contains([]string{"redeem", "authorize_session", "authorize_command", "account"}, ev) {
			continue
		}
		ts, _ := r["ts"].(string)
		if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
			ts = t.UTC().Format("15:04:05.000")
		}
		verdict, _ := r["verdict"].(string)
		line := strings.TrimSpace(fmt.Sprintf("%s %s %s", ts, ev, verdict))
		if ev == "authorize_command" {
			line += fmt.Sprintf(" %q", qualVector(r))
		}
		out = append(out, line)
	}
	return out
}

// l73Ready is whether a readiness probe reached port49d: the probe's capture
// holds a new connection to port49's address (L73 cell a: a port nothing
// answers TLS on records nothing), or port49 recorded the probe (fix round
// 4: a device port49 offered single-connect sends it on the connection it
// already holds, so no SYN is captured). The lab has one device, so any
// record since the probe's mark is that device's.
func l73Ready(conns []l73Conn, from, to time.Time, recs []map[string]any) bool {
	return len(l73Window(conns, l73Server, from, to)) > 0 || len(recs) > 0
}

// l80DefaultIdle is port49d's default limits.idle_timeout
// (internal/config/config.go), which L80's daemon runs (DefaultIdle).
const l80DefaultIdle = 30 * time.Second

// l80CleanPolls bounds the wait, one poll a second, for no connection open
// before an L80 cell's capture: past the default idle close of a connection
// an offered NX-OS holds (fix round 4).
const l80CleanPolls = 60

// l80Ran is whether the device ran a typed command: it answered and did not
// deny it.
func l80Ran(x l80Typed) bool { return !x.Denied && !x.Err }

// l80RestartWindow is when port49d was down: StopAt is when the harness began
// stopping it, UpAt when it announced its listener again (zero if it never did).
type l80RestartWindow struct{ StopAt, UpAt time.Time }

// The restart cell's verdicts.
const (
	l80RestartClean = "clean_reconnect"
	l80RestartLost  = "lost_request"
	// l80RestartPermDenied is a port49 finding: a command port49's policy permits
	// was asked about after the restart and denied, so the session did not
	// survive the restart. It is not an ordinary denial.
	l80RestartPermDenied = "permitted_denied_after_restart"
	l80RestartUnasked    = "unasked_command"
	l80RestartDeadOnly   = "marked_dead_no_loss"
	l80RestartNoConn     = "no_reconnect_seen"
	// l80RestartCtxLost is the memory store's documented behavior, measured: every
	// permitted command denied after the restart was denied context_missing,
	// because the login contexts lived in the stopped process. On etcd the same
	// denial is a port49 finding (l80RestartPermDenied).
	l80RestartCtxLost = "context_lost_on_memory_store"
)

// l80IsVerdict is whether v is one of the restart cell's verdict words.
func l80IsVerdict(v string) bool {
	return slices.Contains([]string{l80RestartClean, l80RestartLost, l80RestartPermDenied, l80RestartUnasked,
		l80RestartDeadOnly, l80RestartNoConn, l80RestartCtxLost}, v)
}

// The restart cells' session stores.
const (
	l80StoreMemory = "memory"
	l80StoreEtcd   = "etcd"
)

// l80ReasonContextMissing is spec §5.7's reason for a command whose login
// context the store no longer holds.
const l80ReasonContextMissing = "context_missing"

// l80IsRestart is whether the cell is one of the restart cells.
func l80IsRestart(cell string) bool { return cell == "restart" || cell == "restart_etcd" }

// l80RestartStore is the session store a restart cell runs on.
func l80RestartStore(cell string) string {
	if cell == "restart_etcd" {
		return l80StoreEtcd
	}
	return l80StoreMemory
}

// l80RestartGrade is the restart cell graded: each typed command as asked and
// permitted, asked and denied, or not asked (lost if the device did not run it,
// unasked if it did), where each fell against the restart window, and the facts
// the debug and the capture give.
type l80RestartGrade struct {
	Verdict                          string
	Permitted, Denied, Lost, Unasked int
	LostAcross, UnaskedAcross        int // not asked, typed while port49d was down or coming up
	PermittedDenied                  int // asked and denied after the stop, though the policy permits it
	ContextMissing                   int // of those, denied context_missing
	Reconnects                       int // connections port49 answered that began after the stop
	Facts                            []string
}

// l80GradeRestart grades the restart cell, run on the session store named, from typed (Asked already set by
// l80Ask), the restart window, nxosDebugCounts, the fallback count and the
// capture's connections. A fact the records or the capture cannot place is
// left out, never inferred: with no StopAt no command is placed against the
// window and no connection is counted as a reconnect.
func l80GradeRestart(store string, typed []l80Typed, w l80RestartWindow, counts map[string]int, fallbacks int, conns []l73Conn) l80RestartGrade {
	var g l80RestartGrade
	placed := !w.StopAt.IsZero()
	across := func(x l80Typed) bool {
		if !placed || x.At.IsZero() {
			return false
		}
		end := x.Done
		if end.IsZero() {
			end = x.At
		}
		return !x.At.After(w.upOrOpen()) && !end.Before(w.StopAt)
	}
	var permDenied []string
	for _, x := range typed {
		switch {
		case x.Asked && x.Denied:
			g.Denied++
			if placed && x.Command != "show users" && !x.At.Before(w.StopAt) {
				g.PermittedDenied++
				if x.Reason == l80ReasonContextMissing {
					g.ContextMissing++
				}
				permDenied = append(permDenied, fmt.Sprintf("permitted command %q typed %.1fs after the stop was asked about and denied: the session did not survive the restart",
					x.Command, x.At.Sub(w.StopAt).Seconds()))
			}
		case x.Asked:
			g.Permitted++
		case l80Ran(x):
			g.Unasked++
			if across(x) {
				g.UnaskedAcross++
			}
		default:
			g.Lost++
			if across(x) {
				g.LostAcross++
			}
		}
	}
	if placed {
		for _, c := range conns {
			if !c.SYNAt.Before(w.StopAt) && c.Answer == "syn-ack" {
				g.Reconnects++
			}
		}
	}
	dead, readFail := counts["mark_server_dead"], counts["ssl_read_failed"]
	switch {
	case g.Unasked > 0:
		g.Verdict = l80RestartUnasked
	case g.PermittedDenied > 0 && !(store == l80StoreMemory && g.ContextMissing == g.PermittedDenied):
		g.Verdict = l80RestartPermDenied
	case g.Lost > 0:
		g.Verdict = l80RestartLost
	case g.PermittedDenied > 0:
		g.Verdict = l80RestartCtxLost
	case dead > 0 || fallbacks > 0:
		g.Verdict = l80RestartDeadOnly
	case placed && g.Reconnects == 0:
		g.Verdict = l80RestartNoConn
	default:
		g.Verdict = l80RestartClean
	}
	g.Facts = append(g.Facts, fmt.Sprintf("commands: %d asked and permitted, %d asked and denied, %d not asked and not run (lost), %d not asked and run (unasked)",
		g.Permitted, g.Denied, g.Lost, g.Unasked))
	g.Facts = append(g.Facts, permDenied...)
	if g.PermittedDenied > 0 {
		g.Facts = append(g.Facts, fmt.Sprintf("session store %s: %d of %d permitted commands denied after the stop were denied %s",
			store, g.ContextMissing, g.PermittedDenied, l80ReasonContextMissing))
	}
	if placed {
		g.Facts = append(g.Facts, fmt.Sprintf("while port49d was down or coming up: %d lost, %d unasked", g.LostAcross, g.UnaskedAcross))
		g.Facts = append(g.Facts, fmt.Sprintf("connections answered by port49 after the stop: %d", g.Reconnects))
		closing, notify := l80RestartCloses(w, conns)
		g.Facts = append(g.Facts, closing...)
		if notify {
			g.Facts = append(g.Facts, "close_notify: seen as a plaintext alert from port49 on a connection open at the stop")
		} else {
			g.Facts = append(g.Facts, "close_notify: not seen in a plaintext alert; an encrypted alert is not visible in a header-only capture, so this is not evidence it was not sent")
		}
	} else {
		g.Facts = append(g.Facts, "restart window not recorded: no command is placed against it and no reconnect is counted")
	}
	g.Facts = append(g.Facts, fmt.Sprintf("debug: ssl_read_failed=%d mark_server_dead=%d fallback_lines=%d", readFail, dead, fallbacks))
	return g
}

// upOrOpen is the end of the window: UpAt, or, if port49d never came back, a
// time past every command.
func (w l80RestartWindow) upOrOpen() time.Time {
	if w.UpAt.IsZero() {
		return time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	return w.UpAt
}

// l80RestartCloses is how each connection open at the stop ended, and whether
// port49 sent a plaintext close_notify on one. A connection whose end the
// capture did not record is "open".
func l80RestartCloses(w l80RestartWindow, conns []l73Conn) (lines []string, notify bool) {
	for _, c := range conns {
		if !c.SYNAt.Before(w.StopAt) || (!c.EndAt.IsZero() && c.End != "open" && c.EndAt.Before(w.StopAt)) {
			continue
		}
		how := c.End
		if !c.EndAt.IsZero() && c.End != "open" {
			how += fmt.Sprintf(" %+.2fs after the stop", c.EndAt.Sub(w.StopAt).Seconds())
		}
		lines = append(lines, "connection open at the stop ended: "+how)
		for _, a := range c.Alerts {
			if a.Description == 0 && !a.FromDevice {
				notify = true
			}
		}
	}
	if len(lines) == 0 {
		lines = append(lines, "no connection was open at the stop in the capture")
	}
	return lines, notify
}
