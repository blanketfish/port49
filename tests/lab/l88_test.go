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
			_, err := l73CiscoRun(c, l73Lines(del...), nil, true, l73ExtraMarks(l88Family(e.l.p))...)
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
	off := e.l.mark()
	outs, err := e.l.loginWithin(user, secret, 60*time.Second, "show version", shortDenyPrefix)
	recs := e.l.waitForRecords(off, 40*time.Second, func(rs []map[string]any) bool {
		s, p := l88AccountCounts(rs, user)
		return s > 0 && p > 0
	})
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
		shown += fmt.Sprintf("[%d] %s ", i, oneLine(stripPrompt(o)))
	}
	obs := fmt.Sprintf("token login %s: %d command authorizations permitted, %d denied; accounting START %d, STOP %d; command output: %s",
		l73Err(err), permits, denies, starts, stops, shown)
	if len(obs) > 600 {
		obs = obs[:600] + "..."
	}
	if err == nil && permits > 0 && denies > 0 && starts > 0 && stops > 0 {
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
	off := e.l.mark()
	t0 := time.Now()
	outs, lerr := e.l.loginWithin(user, secret, 120*time.Second, "show version")
	took := time.Since(t0)
	recs := e.l.waitForRecords(off, 30*time.Second, func(rs []map[string]any) bool { return redeemFor(rs, user) != nil })
	n := rst.n.Load()
	restore()
	red := redeemFor(recs, user)
	obs := fmt.Sprintf("token login with the first server (%s) resetting every connection at Accept and port49d on the second (%s): %s in %s; "+
		"connections the first server reset: %d; port49 redeemed the token: %v; first command output: %s",
		l88Servers[0], l88Servers[1], l73Err(lerr), took.Round(10*time.Millisecond), n, red != nil, oneLine(stripPrompt(firstOut(outs))))
	if lerr == nil && red != nil && n > 0 {
		e.n.cell("f", "PASS", obs, summarize(recs))
		return
	}
	e.n.cell("f", "FAIL", obs, summarize(recs))
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
