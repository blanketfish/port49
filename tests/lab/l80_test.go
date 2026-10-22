//go:build lab

package lab

// L80's re-measure (spec §15 L80; §13 decision 50 ruling 20; design Task 7
// lab step 2) on nxos106 over per-request TLS, at port49d's default
// idle_timeout (30 s). One arm per run:
//
//	PORT49_L80_ARM=baseline  bin/port49d built from the commit before Task 7's code
//	PORT49_L80_ARM=fixed     bin/port49d built from the branch head
//
// PORT49_L80_CELLS (optional, comma-separated) runs only the named cells of
// the arm (l80Cells). The harness does not build or swap the binary: the
// runner builds bin/port49d for the arm before the run.
//
// Device debug is on in a break-glass session held across each cell, and is
// read only through nxosDebugKeep, so nothing reaches disk unfiltered. The
// wire evidence is the header-only *.tls.json; no body is decoded and no
// key is logged. Evidence goes to tests/lab/evidence/L80-cisco_nxos/<arm>/.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/testpki"
)

// l80Debug are the debug lines a cell turns on (the A/B's).
var l80Debug = []string{"debug tacacs+ all", "debug aaa events", "debug aaa errors", "debug aaa aaa-requests"}

var (
	l80SecretLine = regexp.MustCompile(`(?i)password|token|secret|eyJ|payload`)
	l80Long       = regexp.MustCompile(`[A-Za-z0-9_+/=.-]{24,}`)
)

// l80Filter is the summary's own credential filter: a line with a secret
// word is dropped, and a run of 24 or more characters masked.
func l80Filter(s string) string {
	var out []string
	for _, ln := range strings.Split(s, "\n") {
		if !l80SecretLine.MatchString(ln) {
			out = append(out, l80Long.ReplaceAllString(strings.TrimRight(ln, "\r"), "<LONG>"))
		}
	}
	return strings.Join(out, "\n")
}

// l80Events is port49_connection_events_total by event, from the metrics
// endpoint: counts only, no labels but the event.
func l80Events() map[string]float64 {
	out := map[string]float64{}
	r, err := http.Get("http://127.0.0.1:9049/metrics")
	if err != nil {
		return out
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	re := regexp.MustCompile(`^port49_connection_events_total\{event="([a-z_]+)"\} ([0-9.e+]+)$`)
	for _, ln := range strings.Split(string(b), "\n") {
		if m := re.FindStringSubmatch(ln); m != nil {
			out[m[1]], _ = strconv.ParseFloat(m[2], 64)
		}
	}
	return out
}

func TestL80Remeasure(t *testing.T) {
	arm := os.Getenv("PORT49_L80_ARM")
	if arm != "baseline" && arm != "fixed" {
		t.Skip("PORT49_L80_ARM=baseline or fixed")
	}
	only := strings.FieldsFunc(os.Getenv("PORT49_L80_CELLS"), func(r rune) bool { return r == ',' })
	// The build check runs before any platform is up, so initGlobal has not set
	// root yet (as L72 does, l72_test.go:400).
	if root == "" {
		r, err := repoRoot()
		if err != nil {
			t.Fatalf("INVALID: repo root: %v", err)
		}
		root = r
	}
	// Which build the arm runs is checked, never taken on trust (review I2).
	vcs, err := binaryVCS(filepath.Join(root, "bin", "port49d"))
	if err != nil {
		t.Fatalf("INVALID: %v", err)
	}
	if err := l80ArmCheck(arm, vcs, gitHead(root), func(rev string) (bool, error) { return l80HasFix(root, rev) }); err != nil {
		t.Fatal(err)
	}
	// The harness and its evidence paths must be clean too, untracked files
	// included (review N4): an earlier batch's evidence is committed, and the
	// binary rebuilt, before the next batch.
	if dirty, err := treeDirty(root, codePaths...); err != nil || dirty != "" {
		t.Fatalf("INVALID: the tree is not clean (%v):\n%s\ncommit or remove it, then rebuild after committing (make build)", err, dirty)
	}
	sel, _, err := platformSelection()
	if err != nil || len(sel) != 1 || sel[0].sel != "nxos106" {
		t.Fatalf("PORT49_LAB_PLATFORMS=nxos106 only: %v", err)
	}
	if err := labOccupyForRun(labLockPath, fmt.Sprintf("l80 %s pid %d", arm, os.Getpid())); err != nil {
		t.Fatalf("INVALID: %v", err)
	}
	if err := labGuardAt(l66StopSentinel, "/", l66DiskFloorMB); err != nil {
		t.Fatalf("INVALID: %v", err)
	}
	out := filepath.Join(root, "tests/lab/evidence/L80-cisco_nxos", arm)
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatal(err)
	}
	l := labFor(t, sel[0])
	q := newQualEnv(t, l)
	q.guard()
	if err := testpki.WriteLab(filepath.Join(root, slicePKIDir), sliceEmail, time.Now()); err != nil {
		t.Fatal(err)
	}
	q.cfg = q.config()
	// The platform's readiness daemon still holds :49 (as play does, qualify_test.go:147).
	if err := l.stopDaemon(); err != nil {
		t.Fatal(err)
	}
	q.startDaemon(q.cfg)
	defer q.restoreDaemon()
	q.start = l.mark()
	q.login()
	defer q.stopAgent()
	e := newL73Env(t, l, l73Dialects[l.p.name])
	q.e = e
	if !e.helpProbe() {
		t.Fatal("INVALID: no RFC 9887 client")
	}
	q.guard()
	e.enrol()
	e.port = l73TLSPort
	daemon := l73Daemon{Intermediates: e.files["inter.pem"], DefaultIdle: true}
	q.tlsDaemon(e, "l80", daemon)
	q.guard()
	e.configure(e.base())
	q.login()
	e.ready("l80")

	var minted []string
	var mintMu sync.Mutex
	mint := func() string {
		mintMu.Lock()
		defer mintMu.Unlock()
		tok := q.mint()
		minted = append(minted, tok)
		return tok
	}
	// Every file is checked against every minted credential before any is
	// written; a hit writes nothing.
	write := func(files map[string]string) {
		for name, body := range files {
			for _, tok := range minted {
				if tok != "" && strings.Contains(body, tok) {
					t.Fatalf("INVALID: %s holds a minted credential; nothing written", name)
				}
			}
		}
		for name, body := range files {
			if err := os.WriteFile(filepath.Join(out, name), []byte(body+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}

	// The debug filter keeps only the lab's own values: port49's listen
	// address, the device's, and the server group the device is configured
	// with (review N6).
	var filter nxosDebugFilter
	for _, a := range []string{l73Server, l.p.addr} {
		addr, err := netip.ParseAddr(a)
		if err != nil {
			t.Fatalf("INVALID: lab address %q: %v", a, err)
		}
		filter.Addrs = append(filter.Addrs, addr)
	}
	filter.Groups = []string{l73Group}

	var stops []string
	for _, cell := range l80Cells(arm) {
		if len(only) > 0 && !slices.Contains(only, cell.Name) {
			continue
		}
		label := "l80" + arm[:1] + cell.Name
		e.guard()
		e.settle()
		e.cli(func(c *cliConn) error {
			adm := func(ln string) { c.sendExpect(ln, 120*time.Second, c.prompt) }
			adm("terminal length 0")
			adm("debug logfile " + label)
			for _, ln := range l80Debug {
				adm(ln)
			}
			// e.cli stopped port49d for this break-glass session; the cell
			// runs against it started again, debug held on here.
			q.tlsDaemon(e, "l80", daemon)
			q.login()
			time.Sleep(40 * time.Second)
			q.cell("l80_" + cell.Name)
			stop := e.capture("l80_" + cell.Name)
			off := l.mark()
			before := l80Events()
			var sum strings.Builder
			fmt.Fprintf(&sum, "L80 re-measure, arm %s, cell %s, nxos106 per-request TLS, idle_timeout default\n", arm, cell.Name)
			fmt.Fprintf(&sum, "bin/port49d: vcs.revision=%s vcs.modified=%v\n", vcs.Revision, vcs.Modified)
			var mu sync.Mutex
			var typed []l80Typed
			var wg sync.WaitGroup
			for i, seq := range cell.Sessions {
				wg.Add(1)
				go func(i int, seq []string) {
					defer wg.Done()
					time.Sleep(time.Duration(i) * 300 * time.Millisecond) // all within 1 s
					began := time.Now()
					qc, err := l.sshCLI(qualUser, mint())
					if err != nil {
						mu.Lock()
						fmt.Fprintf(&sum, "session %d: login error: %v\n", i, err != nil)
						mu.Unlock()
						return
					}
					defer qc.Close()
					qc.prompt = l.p.node + "#"
					_, perr := qc.expect(120*time.Second, qc.prompt)
					mu.Lock()
					fmt.Fprintf(&sum, "session %d: login_latency_s=%.2f prompt_err=%v\n", i, time.Since(began).Seconds(), perr != nil)
					mu.Unlock()
					gap := 0.0
					for _, cmd := range seq {
						if g, ok := strings.CutPrefix(cmd, "@sleep "); ok {
							gap, _ = strconv.ParseFloat(g, 64)
							time.Sleep(time.Duration(gap * float64(time.Second)))
							continue
						}
						at := len(qc.transcript())
						b0 := time.Now()
						_, err := qc.sendExpect(cmd, 120*time.Second, qc.prompt, l.p.node+"(config")
						first := ""
						for _, ln := range strings.Split(strings.ReplaceAll(qc.transcript()[at:], "\r", ""), "\n")[1:] {
							if strings.TrimSpace(ln) != "" {
								first = oneLine(hideKeys(l73LogScreen(ln)))
								break
							}
						}
						x := l80Typed{Session: i, Command: cmd, Gap: gap, Took: time.Since(b0).Seconds(),
							Denied: strings.Contains(first, "AAA authorization failed")}
						mu.Lock()
						typed = append(typed, x)
						fmt.Fprintf(&sum, "  s%d %-20q gap=%.1fs took=%.2fs err=%v first=%q\n", i, cmd, gap, x.Took, err != nil, first)
						mu.Unlock()
						gap = 0
					}
					qc.send("exit")
					time.Sleep(3 * time.Second)
				}(i, seq)
			}
			wg.Wait()
			time.Sleep(40 * time.Second) // holds, idle closes
			recs := l.waitForRecords(off, 10*time.Second, func([]map[string]any) bool { return false })
			var recorded []string
			for _, r := range recs {
				if r["event"] == "authorize_command" {
					recorded = append(recorded, qualVector(r))
				}
			}
			l80Ask(typed, recorded)
			after := l80Events()
			second := after["single_connect_second_connection"] - before["single_connect_second_connection"]
			conns := stop()
			most := l80MostOpen(conns)
			fmt.Fprintf(&sum, "tls connections: %d, most open at once: %d\n", len(conns), most)
			for _, cn := range conns {
				sum.WriteString("  " + l80ConnLine(cn) + "\n")
			}
			fmt.Fprintf(&sum, "connection_events deltas: single_connect_second_connection=%v idle_closed=%v refused_cap=%v\n",
				second, after["idle_closed"]-before["idle_closed"], after["refused_cap"]-before["refused_cap"])
			sum.WriteString("port49 records:\n")
			for _, ln := range l80Timeline(recs) {
				sum.WriteString("  " + ln + "\n")
			}
			for _, x := range typed {
				fmt.Fprintf(&sum, "typed s%d %q gap=%.1fs asked=%v denied=%v\n", x.Session, x.Command, x.Gap, x.Asked, x.Denied)
			}
			e.l.stopDaemon()
			time.Sleep(15 * time.Second)
			at := len(c.transcript())
			c.sendExpect("show debug logfile "+label, 180*time.Second, c.prompt)
			kept := filter.Keep(c.transcript()[at:])
			cnt := nxosDebugCounts(kept)
			var ks []string
			for k := range nxosDebugMarkers {
				ks = append(ks, fmt.Sprintf("%s=%d", k, cnt[k]))
			}
			slices.Sort(ks)
			sum.WriteString("debug counts: " + strings.Join(ks, " ") + "\n")
			// Each fallback with the request before it, for the note's
			// attribution: what was authorized, and whether it ran on it.
			for i, f := range nxosFallbacks(kept) {
				fmt.Fprintf(&sum, "fallback %d at device %s: %s\n  before: %s\n", i+1, f.At, f.Line, f.Before)
				for _, ln := range f.Context {
					sum.WriteString("    " + ln + "\n")
				}
			}
			if cell.Name == "concurrent" {
				sum.WriteString(l80Interleaving + "\n")
			}
			cellStops := l80Stops(arm, cell.Name, typed, most, second, cnt)
			for _, s := range cellStops {
				sum.WriteString("STOP: " + s + "\n")
			}
			tj, _ := json.Marshal(typed)
			write(map[string]string{
				cell.Name + "-summary.txt": l80Filter(sum.String()),
				cell.Name + "-debug.txt":   kept,
				cell.Name + ".tls.json":    string(e.evidence["l80_"+cell.Name+".tls.json"]),
				cell.Name + "-typed.json":  string(tj),
			})
			c.sendExpect("undebug all", 60*time.Second, c.prompt)
			stops = append(stops, cellStops...)
			return nil
		})
		if len(stops) > 0 {
			t.Fatalf("STOP (report before shipping; evidence for %s is written):\n%s", cell.Name, strings.Join(stops, "\n"))
		}
	}
}
