//go:build lab

package lab

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// TestL88 loads the shipped reference AAA configuration (deploy/device-aaa) on each
// selected image and measures spec section 15's L88 cells against it. One selector per run.
func TestL88(t *testing.T) {
	if err := labOccupyForRun(labLockPath, "TestL88 pid "+strconv.Itoa(os.Getpid())); err != nil {
		t.Fatal(err)
	}
	if err := labGuardAt(l66StopSentinel, "/", l66DiskFloorMB); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("docker", "ps", "--filter", "label=containerlab", "--format", "{{.Names}}").Output(); err != nil {
		t.Fatalf("INVALID: docker ps: %v", err)
	} else if s := strings.TrimSpace(string(out)); s != "" {
		t.Fatalf("a containerlab topology is already up (%s): the lab is single-occupant", strings.ReplaceAll(s, "\n", ", "))
	}
	sel, _, err := platformSelection()
	if err != nil {
		t.Fatal(err)
	}
	// Both kinds of row: the note name carries the selector where a default row shares the name.
	for _, p := range append(rowsFor(sel, false), rowsFor(sel, true)...) {
		p := p
		if _, ok := l88Refs[p.name]; !ok {
			continue
		}
		t.Run(p.name, func(t *testing.T) { l88Run(t, labFor(t, p)) })
	}
}

type l88Env struct {
	t    *testing.T
	l    *lab
	n    *l88Note
	pw   string
	hash string
	tls  bool
}

func (e *l88Env) logf(format string, args ...any) {
	e.t.Helper()
	e.t.Logf("%s", e.n.mask(fmt.Sprintf(format, args...)))
}

func l88Run(t *testing.T, l *lab) {
	pw, err := l73NewRootPassword()
	if err != nil {
		t.Fatal(err)
	}
	hash, err := l88PasswordHash(l.p.name, pw)
	if err != nil {
		t.Fatalf("INVALID: %v", err)
	}
	e := &l88Env{t: t, l: l, pw: pw, hash: hash}
	e.n = newL88Note(l.p, "tcp", pw, hash)
	if !l88Junos(l.p) && l.p.name != "nokia_srlinux" {
		if lines := l88Clear(l.p); len(lines) > 0 {
			e.must("clearing the lab's own server lines", l88Admin(l, func(c *cliConn) error {
				_, err := l73CiscoRun(c, l73Lines(lines...), nil, true, l73ExtraMarks(l88Family(l.p))...)
				if err != nil {
					t.Logf("clear (lenient): %s", e.n.mask(oneLine(err.Error())))
				}
				return nil
			}))
		}
	}
	e.addSecondAddress()
	e.must("applying the reference", l88Apply(l, "tcp"))
	e.n.fact("the reference loaded: `deploy/device-aaa/" + l88Refs[l.p.name] + "` (tcp), values: servers " +
		strings.Join(l88Servers, ", ") + "; the second is an address on the bridge where nothing listens")
	e.deviceFacts()
	e.cells("tcp", l88Cells(l.p.sel, false))
	e.finish()
}

func (e *l88Env) must(what string, err error) {
	e.t.Helper()
	if err != nil {
		e.t.Fatalf("INVALID: %s: %s", what, e.n.mask(oneLine(err.Error())))
	}
}

func (e *l88Env) cells(transport string, ids []string) {
	for _, id := range ids {
		e.t.Logf("lab: cell %s (%s)", id, transport)
		switch id {
		case "a":
			e.cellA()
		case "b":
			e.cellB()
		case "c", "d":
			if id == "c" {
				e.cellsCD()
			}
		case "e":
			e.cellE()
		case "f":
			e.cellF()
		case "i":
			e.cellI()
		default:
			e.n.cell(id, "NOT MEASURED", "the harness does not run cell "+id+" yet", "")
		}
	}
}

func (e *l88Env) finish() {
	out, err := e.n.render()
	if err != nil {
		e.t.Fatal(err)
	}
	path := filepath.Join(root, "tests", "lab", "results", l88NoteName(e.l.p))
	if err := os.WriteFile(path, []byte(out), 0o644); err != nil {
		e.t.Fatal(err)
	}
	e.t.Logf("lab: wrote %s", path)
}

// l88NoteName is L88-<platform>.md, with the image's selector when a default row shares the name.
func l88NoteName(p platform) string {
	for _, q := range platforms {
		if q.name == p.name && q.sel != p.sel && !optInPlatforms[q.sel] {
			return "L88-" + p.name + "-" + p.sel + ".md"
		}
	}
	return "L88-" + p.name + ".md"
}

// addSecondAddress puts 172.100.100.2 on the bridge, so a connection to it is refused at once.
func (e *l88Env) addSecondAddress() {
	dev, err := bridgeDevice()
	if err != nil {
		e.t.Fatalf("INVALID: %v", err)
	}
	del := func() { _ = exec.Command("sudo", "-n", "ip", "addr", "del", l88Servers[1]+"/24", "dev", dev).Run() }
	del()
	e.t.Cleanup(del)
	if out, err := exec.Command("sudo", "-n", "ip", "addr", "add", l88Servers[1]+"/24", "dev", dev).CombinedOutput(); err != nil {
		e.t.Fatalf("INVALID: adding %s to %s: %v\n%s", l88Servers[1], dev, err, out)
	}
}

func (e *l88Env) restart() {
	e.t.Helper()
	base, err := e.l.configPath()
	if err == nil {
		err = e.l.startDaemonWith(base, true)
	}
	e.must("restarting port49d", err)
}

func l88RecUser(r map[string]any) string {
	if u := str(sub(r, "session"), "username"); u != "" {
		return u
	}
	return str(r, "username")
}

// cellA: a user port49 denies who has a local account with the same password: PASS iff
// refused, with no fall-through. The control is a login with port49d stopped, where the
// device takes the local password, so the refusal is not a bad account.
func (e *l88Env) cellA() {
	add, del := l88LocalAccount(e.l.p.name, l88DenyUser, e.hash)
	if add == nil {
		e.n.cell("a", "NOT MEASURED", "no local-account lines for "+e.l.p.name, "")
		return
	}
	e.must("creating the local account", l88Admin(e.l, func(c *cliConn) error { return l88Push(e.l.p, c, add) }))
	defer func() {
		e.must("removing the local account", l88Admin(e.l, func(c *cliConn) error {
			if l88Junos(e.l.p) {
				_, err := junosConfigure(c, del...)
				return err
			}
			_, err := l73CiscoRun(c, l88WithCommit(e.l.p, l88Confirming(del)), nil, true, l73ExtraMarks(l88Family(e.l.p))...)
			return err
		}))
	}()
	// The control.
	e.must("stopping port49d", e.l.stopDaemon())
	cl, cerr := e.l.dial(l88DenyUser, e.pw, 120*time.Second)
	if cerr == nil {
		cl.Close()
	}
	e.restart()
	off := e.l.mark()
	t0 := time.Now()
	cl, err := e.l.dial(l88DenyUser, e.pw, 120*time.Second)
	took := time.Since(t0)
	if err == nil {
		cl.Close()
	}
	recs := e.l.waitForRecords(off, 30*time.Second, func(rs []map[string]any) bool { return redeemFor(rs, l88DenyUser) != nil })
	var verdict, reason string
	if r := redeemFor(recs, l88DenyUser); r != nil {
		verdict, reason = str(r, "verdict"), str(r, "reason")
	}
	obs := fmt.Sprintf("control (port49d stopped, the local password): logged in %v (%s). With port49d answering: logged in %v after %s (%s); "+
		"port49 decision for the attempt: verdict=%q reason=%q", cerr == nil, l73Err(cerr), err == nil, took.Round(time.Millisecond), l73Err(err), verdict, reason)
	switch {
	case cerr != nil:
		e.n.cell("a", "INVALID", obs+": the control failed, so the refusal says nothing", summarize(recs))
		e.t.Errorf("cell a: the control login failed: %s", e.n.mask(oneLine(l73Err(cerr))))
	case err == nil:
		e.n.cell("a", "FAIL", obs, summarize(recs))
		e.t.Errorf("cell a FAIL: a port49-denied user logged in on the local password")
	case verdict != "deny":
		e.n.cell("a", "INVALID", obs+": port49 did not deny the attempt", summarize(recs))
		e.t.Errorf("cell a: no port49 denial for the attempt")
	default:
		e.n.cell("a", "PASS", obs, summarize(recs))
	}
}

// cellB: port49d stopped (connections refused): PASS iff break-glass logs in within 10 s.
func (e *l88Env) cellB() {
	e.must("stopping port49d", e.l.stopDaemon())
	t0 := time.Now()
	cl, err := e.l.dial(breakglassUser, breakglassPassword, 120*time.Second)
	took := time.Since(t0)
	if err == nil {
		cl.Close()
	}
	e.restart()
	obs := fmt.Sprintf("break-glass login with port49d stopped: ok %v in %s (%s)", err == nil, took.Round(10*time.Millisecond), l73Err(err))
	if err == nil && took <= 10*time.Second {
		e.n.cell("b", "PASS", obs, "")
		return
	}
	e.n.cell("b", "FAIL", obs+" (the bound is 10 s)", "")
	e.t.Errorf("cell b FAIL: %s", e.n.mask(obs))
}

// cellE: a token login, one permitted and one denied command: PASS iff the permit runs,
// the deny is refused, and accounting START and STOP arrive.
func (e *l88Env) cellE() {
	user, secret := e.l.nextLogin(e.t)
	e.n.addSecret(secret)
	// A device that marked port49 dead after the refusals of the cells before answers
	// locally, with no packet, until its dead time runs out (IOS XE, L73): the login is
	// retried every 10 s for 5 minutes, on the same token, until port49 sees it.
	var outs []string
	var err error
	var recs []map[string]any
	start, tries := time.Now(), 0
	for {
		tries++
		off := e.l.mark()
		outs, err = e.l.loginWithin(user, secret, 60*time.Second, "show version", l88DenyCommand(e.l.p))
		recs = e.l.waitForRecords(off, 40*time.Second, func(rs []map[string]any) bool {
			s, p := l88AccountCounts(rs, user)
			return s > 0 && p > 0
		})
		if redeemFor(recs, user) != nil || time.Since(start) > 5*time.Minute {
			break
		}
		time.Sleep(10 * time.Second)
	}
	waited := fmt.Sprintf("login attempt %d, %s after the first", tries, time.Since(start).Round(time.Second))
	permits, denies := 0, 0
	for _, r := range recs {
		if str(r, "event") == "authorize_command" && l88RecUser(r) == user {
			switch str(r, "verdict") {
			case "permit":
				permits++
			case "deny":
				denies++
			}
		}
	}
	starts, stops := l88AccountCounts(recs, user)
	shown := ""
	for i, o := range outs {
		o = oneLine(stripPrompt(o))
		if len(o) > 160 {
			o = o[:160] + "..."
		}
		shown += fmt.Sprintf("[%d] %s ", i, o)
	}
	judged := permits > 0 && denies > 0
	how := "port49 authorized one command and denied the other"
	if l88Junos(e.l.p) {
		// Junos authorizes a command by the login class, locally: port49 sees no command request.
		judged = len(outs) == 2 && strings.TrimSpace(outs[0]) != "" && !l88Refused(outs[0]) && l88Refused(outs[1])
		how = "judged on the device output: Junos authorizes a command by the login class and asks port49 for none"
	}
	obs := fmt.Sprintf("token login (%s) %s: %d command authorizations permitted, %d denied by port49; accounting START %d, STOP %d; %s; command output: %s",
		waited, e.n.redact(l88Err(err)), permits, denies, starts, stops, how, shown)
	if err == nil && judged && starts > 0 && stops > 0 {
		e.n.cell("e", "PASS", obs, summarize(recs))
		return
	}
	e.n.cell("e", "FAIL", obs, summarize(recs))
	e.t.Errorf("cell e FAIL: %s", e.n.mask(obs))
}

// cellF: the first server refusing (reset at Accept), the second answering: PASS iff a token
// login succeeds through the second. port49d moves to the second address and a listener that
// resets every connection takes the first.
func (e *l88Env) cellF() {
	// IOS XE: the device's own server state before and after, and its tacacs debug around the
	// login (the lead's ruling after the first run's FAIL).
	var ev *l88FEvidence
	if e.l.p.name == "cisco_iosxe" {
		ev = e.fEvidenceStart()
	}
	e.must("stopping port49d", e.l.stopDaemon())
	base, err := e.l.configPath()
	e.must("reading the standing config", err)
	raw, err := os.ReadFile(base)
	e.must("reading the standing config", err)
	cfg, err := l73SetLine(string(raw), "listen: ", `listen: "`+net.JoinHostPort(l88Servers[1], "49")+`"`)
	e.must("moving the listener", err)
	path := filepath.Join(root, "tests", "lab", "logs", "port49d-l88f-"+e.l.p.name+".yaml")
	e.must("writing the config", os.WriteFile(path, []byte(cfg), 0o644))
	healthListen = net.JoinHostPort(l88Servers[1], "49") // the health gate dials where the listener moved
	serr := e.l.startDaemonWith(path, true)
	healthListen = ""
	e.must("starting port49d on the second address", serr)
	rst, err := l88ResetListener(l88Servers[0], "49")
	e.must("the resetting listener", err)
	restore := func() {
		rst.stop()
		e.must("stopping the second-address daemon", e.l.stopDaemon())
		e.restart()
	}
	user, secret := e.l.nextLogin(e.t)
	e.n.addSecret(secret)
	off := e.l.mark()
	t0 := time.Now()
	outs, lerr := e.l.loginWithin(user, secret, 120*time.Second, "show version")
	took := time.Since(t0)
	recs := e.l.waitForRecords(off, 30*time.Second, func(rs []map[string]any) bool { return redeemFor(rs, user) != nil })
	n := rst.n.Load()
	evidence := ""
	if ev != nil {
		evidence = ev.finish()
	}
	restore()
	red := redeemFor(recs, user)
	obs := fmt.Sprintf("token login with the first server (%s) resetting every connection at Accept and port49d on the second (%s): %s in %s; "+
		"connections the first server reset: %d; port49 redeemed the token: %v; first command output: %s",
		l88Servers[0], l88Servers[1], e.n.redact(l88Err(lerr)), took.Round(10*time.Millisecond), n, red != nil, oneLine(stripPrompt(firstOut(outs))))
	if ev != nil {
		evidence = ev.before + "\n" + evidence + "\n" + summarize(recs)
	} else {
		evidence = summarize(recs)
	}
	if lerr == nil && red != nil && n > 0 {
		e.n.cell("f", "PASS", obs, evidence)
		return
	}
	e.n.cell("f", "FAIL", obs, evidence)
	e.t.Errorf("cell f FAIL: %s", e.n.mask(obs))
}

// l88Reset is the first server of cell f: a listener that accepts each connection and resets
// it (SO_LINGER 0). Port 49 is privileged and the test binary holds no capability, so a
// python under sudo does it; it stops itself after 10 minutes in case the test dies.
type l88Reset struct {
	cmd *exec.Cmd
	n   atomic.Int64
}

const l88ResetPy = `
import socket, struct, sys, time
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((sys.argv[1], int(sys.argv[2]))); s.listen(16); s.settimeout(600)
print("listening", flush=True)
while True:
    c, _ = s.accept()
    c.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    c.close()
    print("reset", flush=True)
`

func l88ResetListener(host, port string) (*l88Reset, error) {
	r := &l88Reset{cmd: exec.Command("sudo", "-n", "python3", "-I", "-c", l88ResetPy, host, port)}
	out, err := r.cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := r.cmd.Start(); err != nil {
		return nil, err
	}
	ready := make(chan struct{})
	go func() {
		sc := bufio.NewScanner(out)
		for sc.Scan() {
			switch sc.Text() {
			case "listening":
				close(ready)
			case "reset":
				r.n.Add(1)
			}
		}
	}()
	select {
	case <-ready:
		return r, nil
	case <-time.After(20 * time.Second):
		r.stop()
		return nil, errors.New("the resetting listener did not start")
	}
}

// stop ends the listener by the PID the test recorded when it started it.
func (r *l88Reset) stop() {
	_ = r.cmd.Process.Signal(syscall.SIGTERM)
	_ = r.cmd.Wait()
}

// cellI: Junos only: the largest idle-timeout the commit accepts, by bisection.
func (e *l88Env) cellI() {
	var max int64
	var detail string
	err := l88Admin(e.l, func(c *cliConn) error {
		if _, err := c.sendExpect("configure", 60*time.Second, junosCfgPrompt); err != nil {
			return err
		}
		defer func() {
			c.sendExpect("rollback 0", 60*time.Second, junosCfgPrompt)
			c.sendExpect("exit", 60*time.Second, junosOpPrompt)
		}()
		accepts := func(n int64) bool {
			out, err := c.sendExpect(fmt.Sprintf("set system login class l88i idle-timeout %d", n), 60*time.Second, junosCfgPrompt)
			if err != nil || strings.Contains(out, "error") || strings.Contains(out, "syntax") || strings.Contains(out, "range") {
				detail = oneLine(out)
				c.sendExpect("rollback 0", 60*time.Second, junosCfgPrompt)
				return false
			}
			out, err = c.sendExpect("commit check", 120*time.Second, "configuration check succeeds", "error", "failed")
			ok := err == nil && strings.Contains(out, "configuration check succeeds")
			if !ok {
				detail = oneLine(out)
			}
			c.sendExpect("rollback 0", 60*time.Second, junosCfgPrompt)
			return ok
		}
		lo, hi := int64(1), int64(1)<<32
		if accepts(hi) {
			max = hi
			return nil
		}
		for hi-lo > 1 {
			mid := lo + (hi-lo)/2
			if accepts(mid) {
				lo = mid
			} else {
				hi = mid
			}
		}
		max = lo
		return nil
	})
	if err != nil {
		e.n.cell("i", "NOT MEASURED", e.n.mask(oneLine(err.Error())), "")
		e.t.Errorf("cell i: %s", e.n.mask(oneLine(err.Error())))
		return
	}
	e.n.cell("i", "MEASURED", fmt.Sprintf("the largest `idle-timeout` the commit accepts is %d (the next value up was refused: %s)", max, detail), "")
}

// l88Confirming is lines, each answering a confirmation prompt the device may put to a
// removal (IOS XE and XR ask before some `no` lines).
func l88Confirming(lines []string) []l73Dialog {
	out := l73Lines(lines...)
	for i := range out {
		out[i].Steps = []l73Step{{"[confirm]", ""}, {"[yes/no]", "yes"}, {"[y/n]", "y"}}
	}
	return out
}

// deviceFacts records what the device holds after the reference is on: on Junos the
// authentication order (a `set` on a list adds to it) and fxp0's address (the source pin).
func (e *l88Env) deviceFacts() {
	if !l88Junos(e.l.p) {
		return
	}
	_ = l88Admin(e.l, func(c *cliConn) error {
		for _, cmd := range []string{"show configuration system authentication-order | display set", "show interfaces terse | match fxp0"} {
			out, err := junosShow(c, cmd)
			if err != nil {
				continue
			}
			e.n.fact("`" + cmd + "`: " + oneLine(stripPrompt(out)))
		}
		return nil
	})
}

// l88DenyCommand is the command cell e expects refused: the lab's deny prefix, or on Junos
// (which authorizes commands by class) one the read-only template class lacks.
func l88DenyCommand(p platform) string {
	if l88Junos(p) {
		return "clear arp" // needs the clear permission; the template class holds view only
	}
	return shortDenyPrefix
}

func l88Refused(out string) bool {
	o := strings.ToLower(out)
	return strings.Contains(o, "permission denied") || strings.Contains(o, "authorization denied") || strings.Contains(o, "not allowed") ||
		// Junos hides the commands a class lacks: `error: unknown command: clear` for a view-only class.
		strings.Contains(o, "unknown command")
}

// cellsCD run on etcd, with port49d and port49-broker on the store the lab's proxy can hang
// (the machinery TestStoreOutageEndToEnd uses: startSplit, Proxy.Hang, port49d's own
// "closing every listener" line). They run in a subtest so the split's cleanup puts the
// standing daemon back before the next cell.
//
// (c) the store hangs and port49 answers ERROR: break-glass login and one command, with
// the time and whether port49d went dark meanwhile. (d) port49d has gone dark (its
// health checks closed the listener): PASS iff break-glass logs in and runs a command.
func (e *l88Env) cellsCD() {
	e.t.Run("etcd", func(t *testing.T) {
		x := *e
		x.t = t
		s := x.l.startSplit(t, splitCfg{})
		hang := func(on bool) { s.Proxy.Hang(on) }
		restore := func(off int64) {
			hang(false)
			time.Sleep(15 * time.Second) // the circuits' probes and the fence's next answered read
			// It says "listens again" only after it closed its listeners.
			if len(x.l.errLinesSince(off, darkCloseText)) > 0 {
				x.must("port49d listening again", x.l.listenAgain(off, 150*time.Second))
			}
			x.must("port49d healthy", func() error {
				if !daemonHealthy() {
					return fmt.Errorf("port49d is not healthy after the store returned")
				}
				return nil
			}())
		}
		// (c) what happened, not why. Break-glass is tried again and again from the start of the
		// hang through design §12's bound on the listener close (close_after x interval +
		// call_timeout, 5.5 s at the defaults) plus 30 s; the notes give the first success and
		// the moment port49d's own close line appeared, both from the hang's start.
		off := x.l.errLogSize()
		mark := x.l.mark()
		const window = 5*time.Second + 500*time.Millisecond + 30*time.Second
		stopWatch := make(chan struct{})
		darkAt := darkWatch(stopWatch, func() bool { return len(x.l.errLinesSince(off, darkCloseText)) > 0 })
		hang(true)
		t0 := time.Now()
		type try struct {
			at   time.Duration
			took time.Duration
			err  error
			out  string
		}
		var tries []try
		var first *try
		for time.Since(t0) < window {
			at := time.Since(t0)
			ts := time.Now()
			outs, err := x.l.loginWithin(breakglassUser, breakglassPassword, 60*time.Second, "show version")
			tr := try{at, time.Since(ts), err, l88Brief(firstOut(outs))}
			tries = append(tries, tr)
			if err == nil && first == nil {
				first = &tr
				break
			}
			time.Sleep(time.Second)
		}
		// The close line may land just after the last try: give it until the window's end.
		for time.Since(t0) < window && len(x.l.errLinesSince(off, darkCloseText)) == 0 {
			time.Sleep(500 * time.Millisecond)
		}
		close(stopWatch)
		at := <-darkAt
		dark := x.l.errLinesSince(off, darkCloseText)
		recs := x.l.recordsSince(mark)
		hang(false)
		var b strings.Builder
		for i, tr := range tries {
			if i >= 12 {
				fmt.Fprintf(&b, "; ... %d more tries", len(tries)-i)
				break
			}
			if i > 0 {
				b.WriteString("; ")
			}
			fmt.Fprintf(&b, "try at +%s took %s: %s", tr.at.Round(100*time.Millisecond), tr.took.Round(100*time.Millisecond), l88TryResult(tr.err, tr.out))
		}
		succeeded := fmt.Sprintf("break-glass never logged in within %s of the hang's start", window)
		if first != nil {
			succeeded = fmt.Sprintf("break-glass first logged in at +%s", first.at.Round(100*time.Millisecond))
		}
		closed := "port49d's log showed no listener close within the window"
		if !at.IsZero() {
			closed = fmt.Sprintf("port49d's own close line appeared at +%s: %s", at.Sub(t0).Round(100*time.Millisecond), dark[0])
		}
		x.n.cell("c", "OBSERVED", x.n.redact(fmt.Sprintf("the store hung (the proxy to etcd held); %s; %s; port49d records: authorize_session %v, authorize_command %v, accounting %v; tries: %s",
			succeeded, closed, reasonsOf(recs, "authorize_session"), reasonsOf(recs, "authorize_command"), reasonsOf(recs, "accounting"), b.String())), "")
		restore(off)
		// (d)
		off = x.l.errLogSize()
		hang(true)
		deadline := time.Now().Add(90 * time.Second)
		for len(x.l.errLinesSince(off, darkCloseText)) == 0 && time.Now().Before(deadline) {
			time.Sleep(time.Second)
		}
		wentDark := len(x.l.errLinesSince(off, darkCloseText)) > 0
		t0 = time.Now()
		outs, err := x.l.loginWithin(breakglassUser, breakglassPassword, 60*time.Second, "show version")
		took := time.Since(t0)
		hang(false)
		shown := l88Brief(firstOut(outs))
		obs := x.n.redact(fmt.Sprintf("port49d dark (its log shows it closed its listeners: %v): break-glass login %s in %s, `show version` output %q", wentDark, l88Err(err), took.Round(10*time.Millisecond), shown))
		if wentDark && err == nil && strings.TrimSpace(firstOut(outs)) != "" {
			x.n.cell("d", "PASS", obs, "")
		} else {
			x.n.cell("d", "FAIL", obs, "")
			t.Errorf("cell d FAIL: %s", x.n.mask(obs))
		}
		restore(off)
	})
}

// l88Brief is out on one line, cut to 160 characters.
func l88Brief(out string) string {
	o := strings.Join(strings.Fields(out), " ")
	if len(o) > 160 {
		o = o[:160] + "..."
	}
	return o
}

// l88Err is err on one line. It is masked by n.redact before it is written, never here.
func l88Err(err error) string {
	if err == nil {
		return "no error"
	}
	return strings.Join(strings.Fields(err.Error()), " ")
}

// l88FEvidence is the device's own view around cell f on IOS XE: `show tacacs` before (and
// until it reads clean of a dead server, so f starts from a known state), the tacacs debug
// during the login, and `show tacacs` and the buffered debug lines after. Every line the
// device printed passes l88Evidence's filter and the note's redaction.
type l88FEvidence struct {
	e      *l88Env
	c      *cliConn
	before string
}

var l88Unsafe = regexp.MustCompile(`(?i)password|token|secret|eyJ|payload`)

// l88Evidence drops each line that could hold a credential or a payload.
func l88Evidence(s string) string {
	var keep []string
	for _, ln := range strings.Split(strings.ReplaceAll(s, "\r", ""), "\n") {
		if !l88Unsafe.MatchString(ln) {
			keep = append(keep, ln)
		}
	}
	return strings.Join(keep, "\n")
}

// run types one exec-mode command and returns what the device printed, filtered and redacted.
func (v *l88FEvidence) run(cmd string) string {
	out, err := v.c.sendExpect(cmd, 90*time.Second, "xe1#")
	if err != nil {
		out += "\n(" + err.Error() + ")"
	}
	return v.e.n.redact(l88Evidence(out))
}

func (e *l88Env) fEvidenceStart() *l88FEvidence {
	e.must("stopping port49d", e.l.stopDaemon())
	open := l88Opener(e.l.p)
	c, err := open(e.l)
	e.must("opening the break-glass CLI for the evidence", err)
	v := &l88FEvidence{e: e, c: c}
	v.run("terminal length 0")
	t0 := time.Now()
	var b strings.Builder
	clean := false
	for time.Since(t0) < 150*time.Second {
		out := v.run("show tacacs")
		fmt.Fprintf(&b, "`show tacacs` %s after the break-glass login (port49d stopped):\n%s\n", time.Since(t0).Round(time.Second), out)
		if !strings.Contains(strings.ToLower(out), "dead") {
			clean = true
			break
		}
		time.Sleep(10 * time.Second)
	}
	v.before = b.String()
	if !clean {
		e.n.cell("f", "INVALID", "the device's server state never read clean of a dead server within 150 s", v.before)
		c.Close()
		e.t.Fatalf("cell f INVALID: IOS XE still shows a dead server after 150 s")
	}
	v.before += "`debug tacacs` on:\n" + v.run("debug tacacs")
	return v
}

func (v *l88FEvidence) finish() string {
	v.e.must("stopping the second-address daemon", v.e.l.stopDaemon())
	var b strings.Builder
	b.WriteString("`show tacacs` after the login (port49d stopped):\n" + v.run("show tacacs") + "\n")
	b.WriteString("`show logging` tacacs lines:\n" + v.run("show logging | include TAC|tacacs|TPLUS|AAA") + "\n")
	v.run("undebug all")
	v.c.Close()
	return b.String()
}

// l88TryResult is one break-glass try on a line: its error, or the command's first output.
func l88TryResult(err error, out string) string {
	if err != nil {
		return l88Err(err)
	}
	return fmt.Sprintf("logged in, `show version` printed %q", out)
}
