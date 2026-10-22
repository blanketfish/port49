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
	return append(cells, l80Cell{"concurrent", [][]string{nxosSeqE1, nxosSeqE1, nxosSeqE1}})
}

// l80Typed is one command as typed, and what came of it.
type l80Typed struct {
	Session int     `json:"session"`
	Command string  `json:"command"`
	Gap     float64 `json:"gap_s,omitempty"` // the sleep before it
	Took    float64 `json:"took_s"`
	Denied  bool    `json:"denied"` // its first output line said "AAA authorization failed"
	Asked   bool    `json:"asked"`  // an authorize_command record for it, matched in order
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
		if !x.Asked {
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
