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
	// The harness and its evidence paths must be clean, untracked files
	// included (review N4): an earlier batch's evidence is committed before
	// the next batch.
	if dirty, err := treeDirty(root, codePaths...); err != nil || dirty != "" {
		t.Fatalf("INVALID: the tree is not clean (%v):\n%s\ncommit or remove it first", err, dirty)
	}
	// The harness builds the port49d the arm runs (fix round 4): the
	// baseline from l80BaselineCommit, the fixed arm from HEAD, each in a
	// private clone so the stamp is right, then checks it (review I2).
	rev := "HEAD"
	if arm == "baseline" {
		rev = l80BaselineCommit
	}
	bin := filepath.Join(root, "bin", "port49d")
	vcs, err := buildPort49dAt(root, rev, os.TempDir(), bin)
	if err != nil {
		t.Fatal(err)
	}
	if err := labSetcap(bin); err != nil {
		t.Fatalf("INVALID: %v", err)
	}
	if err := l80ArmCheck(arm, vcs, gitHead(root), func(rev string) (bool, error) { return l80HasFix(root, rev) }); err != nil {
		t.Fatal(err)
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
	// The restart_etcd cell's broker and etcd: stopped before the standing
	// config comes back (defers run last in, first out), which needs :8449.
	var stack *l80EtcdStack
	defer func() { stack.stop() }()
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

	// The debug filter is the NX-OS profile of the device-debug filter: facility,
	// payload drop, redaction of every secret the run has handled (the tokens
	// minted so far included), long-run mask, fail closed.
	filter := deviceDebugFilter{Platform: "nxos", Secrets: func() []string {
		mintMu.Lock()
		defer mintMu.Unlock()
		return append(q.ddSecrets(), minted...)
	}}

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
			if l80RestartStore(cell.Name) == l80StoreEtcd {
				// The conformance config's broker moves out of the daemon, which
				// runs on etcd beside port49-broker (see l80_etcd.go).
				if stack == nil {
					stack = l80EtcdUp(t, l, q, e)
				}
				memText := q.cfgText
				q.cfgText = stack.daemonText
				q.tlsDaemon(e, "l80", daemon)
				q.cfgText = memText
			} else {
				q.tlsDaemon(e, "l80", daemon)
			}
			q.login()
			time.Sleep(40 * time.Second)
			// Every cell opens on a fresh connection: wait, without probing,
			// until none is open (an offered NX-OS holds one until the idle
			// close), and read the gauge again once the capture is live
			// (fix round 4). Either failure is INVALID.
			read := func() (float64, bool) { return e.metric(qualConnectionsOpen) }
			if err := qualWaitNoConnections(read, l80CleanPolls, time.Sleep); err != nil {
				t.Fatal(err)
			}
			q.cell("l80_" + cell.Name)
			stop := e.capture("l80_" + cell.Name)
			if err := qualStillClean(read); err != nil {
				t.Fatal(err)
			}
			off := l.mark()
			before := l80Events()
			var sum strings.Builder
			fmt.Fprintf(&sum, "L80 re-measure, arm %s, cell %s, nxos106 per-request TLS, idle_timeout default\n", arm, cell.Name)
			fmt.Fprintf(&sum, "bin/port49d: vcs.revision=%s vcs.modified=%v\n", vcs.recorded().Revision, vcs.Modified)
			if l80IsRestart(cell.Name) {
				fmt.Fprintf(&sum, "session store: %s\n", l80RestartStore(cell.Name))
			}
			if l80RestartStore(cell.Name) == l80StoreEtcd {
				fmt.Fprintf(&sum, "etcd: %s, a single member; keys under /port49/ at the start: %s\n", stack.version, stack.keyCount())
			}
			var mu sync.Mutex
			var typed []l80Typed
			var wg sync.WaitGroup
			// The restart cell stops port49d by its recorded PID and starts it
			// again while the loop keeps typing (see l80RestartDaemon).
			var window l80RestartWindow
			var restartErr error
			var restartWG sync.WaitGroup
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
						if cmd == "@restart" {
							restartWG.Add(1)
							go func() {
								defer restartWG.Done()
								mu.Lock()
								window.StopAt = time.Now()
								mu.Unlock()
								err := l80RestartDaemon(e, l)
								mu.Lock()
								defer mu.Unlock()
								restartErr = err
								if err == nil {
									window.UpAt = time.Now()
								}
							}()
							continue
						}
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
							Denied: strings.Contains(first, "AAA authorization failed"),
							At:     b0, Done: time.Now(), Err: err != nil}
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
			restartWG.Wait()
			time.Sleep(40 * time.Second) // holds, idle closes
			recs := l.waitForRecords(off, 10*time.Second, func([]map[string]any) bool { return false })
			var recorded []string
			for _, r := range recs {
				if r["event"] == "authorize_command" {
					recorded = append(recorded, qualVector(r))
				}
			}
			l80Ask(typed, recorded)
			l80Reasons(typed, recs)
			after := l80Events()
			second := after["single_connect_second_connection"] - before["single_connect_second_connection"]
			if l80IsRestart(cell.Name) {
				// The restart reset port49d's counters: a delta across it says nothing.
				second = 0
				sum.WriteString("restart: port49d's connection-event counters were reset by the restart; their deltas below are not graded\n")
			}
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
			keptText, keepErr := filter.Keep(c.transcript()[at:])
			if keepErr != nil {
				c.sendExpect("undebug all", 60*time.Second, c.prompt)
				t.Fatalf("INVALID: %s's debug capture was discarded (%v); nothing written", cell.Name, keepErr)
			}
			kept := string(keptText)
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
			var g l80RestartGrade
			if l80IsRestart(cell.Name) {
				if l80RestartStore(cell.Name) == l80StoreEtcd {
					fmt.Fprintf(&sum, "etcd: keys under /port49/ at the end: %s\n", stack.keyCount())
				}
				if restartErr != nil {
					sum.WriteString("restart: port49d did not come back\n")
				}
				g = l80GradeRestart(l80RestartStore(cell.Name), typed, window, cnt, len(nxosFallbacks(kept)), conns)
				fmt.Fprintf(&sum, "restart window: stop=%s up=%s\n", l80Clock(window.StopAt), l80Clock(window.UpAt))
				for _, f := range g.Facts {
					sum.WriteString("restart: " + f + "\n")
				}
				fmt.Fprintf(&sum, "restart verdict: %s\n", g.Verdict)
			}
			cellStops := l80Stops(arm, cell.Name, typed, most, second, cnt)
			if l80IsRestart(cell.Name) && restartErr != nil {
				cellStops = append(cellStops, "restart: port49d did not come back after the restart")
			}
			if g.Verdict == l80RestartPermDenied {
				cellStops = append(cellStops, fmt.Sprintf("restart: %d permitted command(s) denied after the restart, %d of them not for context_missing on the memory store: the session did not survive it (a port49 finding)",
					g.PermittedDenied, g.PermittedDenied-g.ContextMissing))
			}
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

// l80Clock is a time as the summary keeps it, or "never".
func l80Clock(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return t.UTC().Format("15:04:05.000")
}

// l80RestartDaemon stops port49d by the harness's recorded process and starts it
// on the cell's config again, returning once it announces its RFC 9887
// listener. It is l73Env.startOn with errors returned, not Fatal, because the
// restart runs beside the typing loop, off the test goroutine. It does not wait
// on ready(): that probes through a break-glass CLI, which stops port49d.
func l80RestartDaemon(e *l73Env, l *lab) error {
	if err := l.stopDaemon(); err != nil {
		return err
	}
	off := fileSize(l.errPath)
	healthListen = e.listen
	defer func() { healthListen = "" }()
	if err := l.startDaemonWith(e.cfg, true); err != nil {
		return err
	}
	deadline := time.Now().Add(20 * time.Second)
	for {
		b, _ := os.ReadFile(l.errPath)
		if int64(len(b)) > off && strings.Contains(string(b[off:]), "RFC 9887 listener on") {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("port49d never announced its RFC 9887 listener")
		}
		time.Sleep(200 * time.Millisecond)
	}
}
