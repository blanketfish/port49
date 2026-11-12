//go:build lab

package lab

// L94 (spec §15 L94; §13 decision 59, provisional on it): whether a device
// takes port49's replies to the sessions it multiplexes on one single-connect
// RFC 9887 connection out of request order. One arm per run, as L80's:
//
//	PORT49_L94_ARM=baseline  port49d built from l94BaselineCommit (one reply at a time)
//	PORT49_L94_ARM=fixed     port49d built from HEAD (decision 59's lanes)
//
// PORT49_L94_CELLS (optional, comma-separated) runs only the named cells
// (l94CellNames). c4 is NX-OS's and the fixed arm's alone and runs on its own
// build (-tags port49_lab_acct_hold), so it runs alone: PORT49_L94_CELLS=c4.
// PORT49_LAB_PLATFORMS names one platform of l94Platforms. The harness builds
// bin/port49d for the arm itself, in a private clone, and checks the build.
//
// Both failure-delay knobs are 2s (as L13's writeDelayConfig sets them). The
// device runs its single-connection reference configuration; NX-OS runs each
// cell twice, offered (per-request, port49 offers single-connect, L80) and
// with single-connection configured.
//
// Device debug is on in a break-glass session held across each cell and is
// read only through the device-debug filter, so nothing reaches disk
// unfiltered. Order is graded from port49's record ts, never from the wire:
// the wire evidence is the header-only *.tls.json; no body is decoded and no
// key is logged. Evidence goes to tests/lab/evidence/L94-<platform>/<arm>/<mode>/.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/testpki"
)

// l94Prompts are the prompts a token session's command can end at: the
// node's exec prompts, and Junos's operational prompt.
func l94Prompts(l *lab) []string {
	return []string{l.p.node + "#", l.p.node + ">", junosOpPrompt}
}

// l94Type types cmd on session i and reads what came of it: the first line
// after the echo, masked, says whether the device refused it (qualRan).
func l94Type(l *lab, qc *cliConn, i int, cmd string) l80Typed {
	at := len(qc.transcript())
	b0 := time.Now()
	_, err := qc.sendExpect(cmd, 120*time.Second, l94Prompts(l)...)
	lines := strings.Split(strings.ReplaceAll(qc.transcript()[at:], "\r", ""), "\n")
	rest := ""
	if len(lines) > 1 {
		rest = strings.Join(lines[1:], "\n")
	}
	ran, _ := qualRan(rest)
	return l80Typed{Session: i, Command: cmd, Took: time.Since(b0).Seconds(), Denied: !ran && err == nil,
		At: b0, Done: time.Now(), Err: err != nil}
}

func TestL94(t *testing.T) {
	arm := os.Getenv("PORT49_L94_ARM")
	if arm != "baseline" && arm != "fixed" {
		t.Skip("PORT49_L94_ARM=baseline or fixed")
	}
	only := strings.FieldsFunc(os.Getenv("PORT49_L94_CELLS"), func(r rune) bool { return r == ',' })
	if root == "" {
		r, err := repoRoot()
		if err != nil {
			t.Fatalf("INVALID: repo root: %v", err)
		}
		root = r
	}
	if dirty, err := qualTreeDirty(root); err != nil || dirty != "" {
		t.Fatalf("INVALID: the tree is not clean (%v):\n%s\ncommit or remove it first", err, dirty)
	}
	sel, _, err := platformSelection()
	if err != nil || len(sel) != 1 {
		t.Fatalf("PORT49_LAB_PLATFORMS names one of L94's platforms: %v", err)
	}
	p, err := l94PlatformFor(sel[0].sel)
	if err != nil {
		t.Fatal(err)
	}
	cells, err := l94Select(p.Family, arm, only)
	if err != nil {
		t.Fatal(err)
	}
	// The lab is taken before anything is built: a build replaces
	// bin/port49d, which another run holding the lab may be running.
	if err := labOccupyForRun(labLockPath, fmt.Sprintf("l94 %s pid %d", arm, os.Getpid())); err != nil {
		t.Fatalf("INVALID: %v", err)
	}
	if err := labGuardAt(l66StopSentinel, "/", l66DiskFloorMB); err != nil {
		t.Fatalf("INVALID: %v", err)
	}
	// The harness builds the arm's port49d: the baseline from
	// l94BaselineCommit, the fixed arm from HEAD, to bin/port49d. c4 runs a
	// second build of the same revision with the hold tag, at l94HoldBin and
	// never at bin/port49d (initGlobal refuses a held bin/port49d).
	rev := "HEAD"
	if arm == "baseline" {
		rev = l94BaselineCommit
	}
	armCheck := func(v buildVCS) {
		t.Helper()
		if err := armCheckFor(arm, v, gitHead(root), l94FixCommit, func(rev string) (bool, error) {
			return hasFixAt(root, l94FixCommit, l94FixFile, rev)
		}); err != nil {
			t.Fatal(err)
		}
	}
	bin := filepath.Join(root, "bin", "port49d")
	vcs, err := buildPort49dAt(root, rev, os.TempDir(), bin)
	if err != nil {
		t.Fatal(err)
	}
	if err := labSetcap(bin); err != nil {
		t.Fatalf("INVALID: %v", err)
	}
	armCheck(vcs)
	if err := l94StandardBin(bin); err != nil {
		t.Fatalf("INVALID: %v", err)
	}
	run := bin
	if slices.Contains(cells, "c4") {
		run = filepath.Join(root, l94HoldBin)
		hv, err := buildPort49dAt(root, rev, os.TempDir(), run, l94HoldTag)
		if err != nil {
			t.Fatal(err)
		}
		if err := labSetcap(run); err != nil {
			t.Fatalf("INVALID: %v", err)
		}
		armCheck(hv)
	}
	built, err := binaryTags(run)
	if err != nil {
		t.Fatalf("INVALID: %v", err)
	}
	for _, c := range cells {
		if err := l94TagCheck(c, built); err != nil {
			t.Fatal(err)
		}
	}
	evRoot := filepath.Join(root, "tests/lab/evidence", "L94-"+p.Name)

	l := labFor(t, sel[0])
	q := newQualEnv(t, l)
	q.guard()
	if err := testpki.WriteLab(filepath.Join(root, slicePKIDir), sliceEmail, time.Now()); err != nil {
		t.Fatal(err)
	}
	q.cfg = q.config()
	if err := l.stopDaemon(); err != nil {
		t.Fatal(err)
	}
	q.startDaemon(q.cfg)
	defer q.restoreDaemon()
	q.start = l.mark()
	q.login()
	defer q.stopAgent()
	e := newL73Env(t, l, l73Dialects[p.Name])
	q.e = e
	if !e.helpProbe() {
		t.Fatal("INVALID: no RFC 9887 client")
	}
	q.guard()
	e.enrol()
	e.port = l73TLSPort
	// Both failure-delay knobs at l94Delay on every TLS daemon of the run.
	delayed, err := l94DelayConfig(q.cfgText, l94Delay)
	if err != nil {
		t.Fatalf("INVALID: %v", err)
	}
	q.cfgText = delayed
	// c4's TLS daemons run the held build. Set here, after restoreDaemon is
	// deferred, so the reset (deferred later, run earlier) comes first and
	// the standing daemon is restored on bin/port49d.
	if run != bin {
		daemonBin = run
		defer func() { daemonBin = "" }()
	}
	daemon := l73Daemon{Intermediates: e.files["inter.pem"], DefaultIdle: true}
	q.tlsDaemon(e, "l94", daemon)
	q.guard()

	var minted []string
	var mintMu sync.Mutex
	mint := func() string {
		mintMu.Lock()
		defer mintMu.Unlock()
		tok := q.mint()
		minted = append(minted, tok)
		return tok
	}
	secrets := func() []string {
		mintMu.Lock()
		defer mintMu.Unlock()
		return append(q.ddSecrets(), minted...)
	}
	// Every file is checked against every minted credential before any is
	// written; a hit writes nothing.
	write := func(dir string, files map[string]string) {
		for name, body := range files {
			for _, tok := range secrets() {
				if tok != "" && strings.Contains(body, tok) {
					t.Fatalf("INVALID: %s holds a credential; nothing written", name)
				}
			}
		}
		for name, body := range files {
			if strings.HasSuffix(name, "-debug.txt") {
				if bad := qualGate(map[string][]byte{name: []byte(body)}, secrets()); len(bad) > 0 {
					t.Fatalf("INVALID: nothing written:\n  %s", strings.Join(bad, "\n  "))
				}
			}
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		for name, body := range files {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(body+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	dialFor := e.d.LoginDial
	if dialFor == 0 {
		dialFor = 60 * time.Second
	}
	// stale is a token that has logged in once: port49 refuses it again
	// (FAIL after the delay). Its own login is outside every cell's window.
	stale := func() string {
		tok := mint()
		off := l.mark()
		c, err := l.dial(qualUser, tok, dialFor)
		if err != nil {
			t.Fatalf("INVALID: the token a stale-token login reuses did not log in the first time: %v", err != nil)
		}
		c.Close()
		l.waitForRecords(off, 20*time.Second, func(rs []map[string]any) bool {
			return slices.ContainsFunc(l94Events(rs), func(e l94Event) bool { return e.Event == "redeem" && e.Verdict == "permit" })
		})
		time.Sleep(3 * time.Second)
		return tok
	}
	// failLogin is one A login with a stale token.
	failLogin := func(tok string) l94Outcome {
		b0 := time.Now()
		c, err := l.dial(qualUser, tok, dialFor)
		if c != nil {
			c.Close()
		}
		return l94OutcomeOf(time.Since(b0), err)
	}
	// tryB logs a token session in; openB is it on the test goroutine.
	tryB := func(i int) (*cliConn, error) {
		qc, err := l.sshCLI(qualUser, mint())
		if err != nil {
			return nil, fmt.Errorf("INVALID: session %d did not log in", i)
		}
		if _, err := qc.expect(120*time.Second, l94Prompts(l)...); err != nil {
			qc.Close()
			return nil, fmt.Errorf("INVALID: session %d gave no prompt", i)
		}
		return qc, nil
	}
	openB := func(i int) *cliConn {
		qc, err := tryB(i)
		if err != nil {
			t.Fatal(err)
		}
		return qc
	}
	permitted, _ := l94Commands(q.run.Platform)

	modes := []string{"single"}
	if p.Family == "nxos" {
		modes = []string{"offered", "single"}
	}
	var stops, findings []string
	for _, mode := range modes {
		dev := e.base()
		dev.SingleConnection = mode == "single"
		e.configure(dev)
		if dev.SingleConnection {
			// The device goes back to per-request whatever the run's end.
			defer e.configure(e.base())
		}
		q.login()
		e.ready("l94_" + mode)
		out := filepath.Join(evRoot, arm, mode)

		for _, cell := range cells {
			name := "l94_" + mode + "_" + cell
			label := "l94" + arm[:1] + mode[:1] + cell
			e.guard()
			e.settle()

			var (
				sum       strings.Builder
				mu        sync.Mutex
				typed     []l80Typed
				outcomes  []l94Outcome
				gaps      []time.Duration
				recs      []map[string]any
				conns     []l73Conn
				second    float64
				upAt      time.Time
				restartAt time.Time
			)
			fmt.Fprintf(&sum, "L94, arm %s, cell %s, mode %s, %s (%s) over RFC 9887, reference %s, failure delay %s\n",
				arm, cell, mode, p.Sel, l.p.version, p.Ref, l94Delay)
			fmt.Fprintf(&sum, "port49d: %s vcs.revision=%s vcs.modified=%v tags=%q\n", filepath.Base(run), vcs.recorded().Revision, vcs.Modified, built)
			add := func(x l80Typed) {
				mu.Lock()
				defer mu.Unlock()
				typed = append(typed, x)
				fmt.Fprintf(&sum, "  s%d %-24q took=%.2fs denied=%v err=%v at=%s\n", x.Session, x.Command, x.Took, x.Denied, x.Err, l80Clock(x.At))
			}

			// body plays the cell with port49d up on the TLS config and debug
			// on; it ends with port49d stopped, for the collection.
			body := func() {
				q.tlsDaemon(e, "l94", daemon)
				q.login()
				read := func() (float64, bool) { return e.metric(qualConnectionsOpen) }
				if err := qualWaitNoConnections(read, l80CleanPolls, time.Sleep); err != nil {
					t.Fatal(err)
				}
				q.cell(name)
				stop := e.capture(name)
				if err := qualStillClean(read); err != nil {
					t.Fatal(err)
				}
				// A's stale tokens are spent before the window.
				var staleToks []string
				switch cell {
				case "c2", "c5":
					staleToks = []string{stale()}
				case "c3":
					for range l94C3Fails {
						staleToks = append(staleToks, stale())
					}
				}
				off := l.mark()
				before := l80Events()
				switch cell {
				case "c1", "c4":
					var wg sync.WaitGroup
					for i := range 2 {
						wg.Add(1)
						go func(i int) {
							defer wg.Done()
							time.Sleep(time.Duration(i) * l94C1Stagger)
							qc, err := tryB(i)
							if err != nil {
								t.Error(err)
								return
							}
							defer qc.Close()
							for _, cmd := range l94Loop(q.run.Platform, l94C1Commands) {
								add(l94Type(l, qc, i, cmd))
							}
							qc.send("exit")
						}(i)
					}
					wg.Wait()
				case "c2":
					qc := openB(0)
					lead := l94C2Lead
					timing, tries := "", 0
					for try := 1; try <= l94C2Tries; try++ {
						tries = try
						if try > 1 {
							staleToks[0] = stale()
						}
						off = l.mark()
						mu.Lock()
						typed, outcomes = nil, nil
						mu.Unlock()
						done := make(chan l94Outcome, 1)
						go func() { done <- failLogin(staleToks[0]) }()
						time.Sleep(lead)
						_, d := l94Commands(q.run.Platform)
						add(l94Type(l, qc, 0, permitted))
						add(l94Type(l, qc, 0, d))
						outcomes = append(outcomes, <-done)
						recs = l.waitForRecords(off, l94Delay+30*time.Second, func(rs []map[string]any) bool {
							return len(l94Fails(l94Events(rs))) > 0
						})
						var ok bool
						gaps, ok = l94Gaps(q.run.Platform, l94Events(recs), []string{permitted, d})
						timing = l94C2Timing(gaps, l94Delay)
						fmt.Fprintf(&sum, "try %d: lead=%s fail_recorded=%v timing=%s gaps=%v\n", try, lead, ok, timing, gaps)
						if timing != "early" {
							break
						}
						lead += 400 * time.Millisecond
					}
					// A c2 that never put B inside A's delay measured nothing.
					if err := l94C2Valid(timing, tries); err != nil {
						qc.Close()
						t.Fatal(err)
					}
					// B's next command, on the same connection.
					add(l94Type(l, qc, 0, permitted))
					qc.send("exit")
					qc.Close()
				case "c3":
					qc := openB(0)
					var wg sync.WaitGroup
					outs := make([]l94Outcome, len(staleToks))
					for i, tok := range staleToks {
						wg.Add(1)
						go func(i int, tok string) {
							defer wg.Done()
							outs[i] = failLogin(tok)
						}(i, tok)
					}
					start := time.Now()
					for next := start; time.Since(start) < l94C3For; next = next.Add(l94C3Every) {
						time.Sleep(time.Until(next))
						add(l94Type(l, qc, 0, permitted))
					}
					wg.Wait()
					outcomes = outs
					qc.send("exit")
					qc.Close()
				case "c5":
					qc := openB(0)
					_, d := l94Commands(q.run.Platform)
					var aw, rw sync.WaitGroup
					var restartErr error
					for i := 1; i <= 16; i++ {
						time.Sleep(500 * time.Millisecond)
						cmd := permitted
						if i%4 == 0 {
							cmd = d
						}
						add(l94Type(l, qc, 0, cmd))
						if i == 8 {
							// A's FAIL is inside its delay when port49d restarts.
							aw.Add(1)
							go func() {
								defer aw.Done()
								o := failLogin(staleToks[0])
								mu.Lock()
								outcomes = append(outcomes, o)
								mu.Unlock()
							}()
							time.Sleep(500 * time.Millisecond)
							rw.Add(1)
							go func() {
								defer rw.Done()
								mu.Lock()
								restartAt = time.Now()
								mu.Unlock()
								err := l80RestartDaemon(e, l)
								mu.Lock()
								defer mu.Unlock()
								restartErr = err
								if err == nil {
									upAt = time.Now()
								}
							}()
						}
					}
					aw.Wait()
					rw.Wait()
					if restartErr != nil {
						sum.WriteString("restart: port49d did not come back\n")
					}
					qc.send("exit")
					qc.Close()
				}
				time.Sleep(10 * time.Second)
				if cell != "c2" {
					recs = l.waitForRecords(off, 10*time.Second, func([]map[string]any) bool { return false })
				}
				after := l80Events()
				second = after["single_connect_second_connection"] - before["single_connect_second_connection"]
				if cell == "c5" {
					second = 0 // the restart reset port49d's counters
				}
				conns = stop()
				if err := e.l.stopDaemon(); err != nil {
					t.Errorf("stopping port49d after %s: %v", cell, err)
				}
			}

			// Debug on, the cell, port49d stopped, the collection.
			var kept string
			deadOrSSL := 0
			if p.Family == "nxos" {
				filter := deviceDebugFilter{Platform: "nxos", Secrets: secrets}
				e.cli(func(c *cliConn) error {
					adm := func(ln string) { c.sendExpect(ln, 120*time.Second, c.prompt) }
					// A Fatal in body() still stops port49d, turns debug off and
					// closes the session.
					defer l80DebugOff(e.l, c, label)
					adm("terminal length 0")
					adm("debug logfile " + label)
					for _, ln := range l80Debug {
						adm(ln)
					}
					body()
					time.Sleep(15 * time.Second)
					at := len(c.transcript())
					c.sendExpect("show debug logfile "+label, 180*time.Second, c.prompt)
					k, keepErr := filter.Keep(c.transcript()[at:])
					if keepErr != nil {
						t.Fatalf("INVALID: %s's debug capture was discarded (%v); nothing written", cell, keepErr)
					}
					kept = string(k)
					return nil
				})
				cnt := nxosWindowedCounts(kept)
				_, cellText, _ := nxosCellWindow(kept)
				fb := len(nxosFallbacks(cellText))
				fmt.Fprintf(&sum, "debug counts: ssl_read_failed=%d mark_server_dead=%d fallbacks=%d request_authen=%d request_author=%d request_acct=%d window_unmeasured=%d\n",
					cnt["ssl_read_failed"], cnt["mark_server_dead"], fb, cnt["request_authen"], cnt["request_author"], cnt["request_acct"], cnt["window_unmeasured"])
				deadOrSSL = cnt["ssl_read_failed"] + cnt["mark_server_dead"] + fb
			} else {
				platform, _ := ddArmPlatform(p.Family)
				drops := &ddDropCounts{}
				filter := deviceDebugFilter{Platform: platform, Secrets: secrets, Drops: drops}
				var (
					rawLines              int
					sample, answers, flgs []string
					authd                 [2]int
					capErr                error
					ran                   bool
				)
				e.cli(func(c *cliConn) error {
					run := ddArmRun(c, filter, secrets, platform, &rawLines, &sample, &answers, &flgs, &authd)
					var k deviceDebugKept
					k, capErr = captureDeviceDebug(filter, run, func() error {
						ran = true
						finished := false
						defer func() {
							if !finished { // a Fatal in the body: debug must still go off
								e.l.stopDaemon()
								disableDeviceDebug(deviceDebugCmds[platform], run)
							}
						}()
						body()
						finished = true
						return nil
					})
					kept = string(k)
					return nil
				})
				if !ran {
					t.Fatalf("INVALID: device debug would not go on for %s (%v)", cell, capErr)
				}
				if capErr != nil {
					fmt.Fprintf(&sum, "debug capture error: %v\n", capErr)
				}
				n := l94Suspect(kept)
				fmt.Fprintf(&sum, "debug: %d device log lines, kept %d, suspect %d (l94SuspectMarks: read the kept lines)\n", rawLines, ddArmLineCount(deviceDebugKept(kept)), n)
				deadOrSSL = n
			}
			if cell == "c5" {
				// A restart closes the connection under the device: TLS errors
				// and a reconnect are the cell's subject, not a stop.
				deadOrSSL = 0
			}
			q.login()

			evs := l94Events(recs)
			var recorded []string
			for _, r := range recs {
				if r["event"] == "authorize_command" {
					recorded = append(recorded, qualVector(r))
				}
			}
			l80Ask(typed, recorded)
			l80Reasons(typed, recs)
			most := l80MostOpen(conns)
			fmt.Fprintf(&sum, "tls connections: %d, most open at once: %d\n", len(conns), most)
			for _, cn := range conns {
				sum.WriteString("  " + l80ConnLine(cn) + "\n")
			}
			fmt.Fprintf(&sum, "single_connect_second_connection delta: %v\n", second)
			for i, o := range outcomes {
				fmt.Fprintf(&sum, "stale-token login %d: took=%.2fs auth_failed=%v logged_in=%v err=%q\n", i+1, o.Took, o.AuthFailed, o.LoggedIn, o.Err)
			}
			if cell == "c5" {
				fmt.Fprintf(&sum, "restart window: stop=%s up=%s\n", l80Clock(restartAt), l80Clock(upAt))
			}
			sum.WriteString("port49 records:\n")
			for _, ln := range l80Timeline(recs) {
				sum.WriteString("  " + ln + "\n")
			}
			g := l94Grade{Arm: arm, Cell: cell, Platform: q.run.Platform, P: p, Typed: typed, Events: evs,
				Conns: len(conns), MostOpen: most, Second: second, DeadOrSSL: deadOrSSL, Outcomes: outcomes,
				Gaps: gaps, RestartAt: restartAt, UpAt: upAt}
			if cell == "c2" || cell == "c3" {
				g.Baseline = l94ReadBaseline(t, filepath.Join(evRoot, "baseline", mode), cell)
				if arm == "fixed" && g.Baseline == nil {
					sum.WriteString("baseline: no baseline evidence for this cell; the fixed arm is graded on its own and on L13's timeout\n")
				}
			}
			cellStops := l94Stops(g)
			for _, s := range cellStops {
				sum.WriteString("STOP: " + s + "\n")
			}
			tj, _ := json.Marshal(typed)
			aj, _ := json.Marshal(outcomes)
			write(out, map[string]string{
				cell + "-summary.txt": l80Filter(sum.String()),
				cell + "-debug.txt":   kept,
				cell + ".tls.json":    string(e.evidence[name+".tls.json"]),
				cell + "-typed.json":  string(tj),
				cell + "-a.json":      string(aj),
			})
			if p.Blocks {
				stops = append(stops, prefixAll(mode+" ", cellStops)...)
			} else {
				findings = append(findings, prefixAll(mode+" ", cellStops)...)
			}
		}
	}
	if len(findings) > 0 {
		t.Logf("FINDINGS on %s (not blocking: the platform page keeps its warning and L94 stays open for it):\n%s", p.Sel, strings.Join(findings, "\n"))
	}
	if len(stops) > 0 {
		t.Fatalf("STOP (report before merging; evidence is written):\n%s", strings.Join(stops, "\n"))
	}
}

// l94ReadBaseline is the baseline arm's evidence for cell under dir, or nil
// when the baseline was not run.
func l94ReadBaseline(t *testing.T, dir, cell string) *l94Baseline {
	t.Helper()
	tb, err := os.ReadFile(filepath.Join(dir, cell+"-typed.json"))
	if err != nil {
		return nil
	}
	ab, err := os.ReadFile(filepath.Join(dir, cell+"-a.json"))
	if err != nil {
		return nil
	}
	var typed []l80Typed
	var b l94Baseline
	if json.Unmarshal(tb, &typed) != nil || json.Unmarshal(ab, &b.Outcomes) != nil {
		t.Fatalf("INVALID: the baseline evidence under %s does not parse", dir)
	}
	for _, x := range typed {
		b.MaxTook = max(b.MaxTook, x.Took)
	}
	return &b
}
