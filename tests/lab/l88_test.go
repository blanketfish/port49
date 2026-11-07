//go:build lab

package lab

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/blanketfish/port49/tests/lab/labpcap"
	"golang.org/x/crypto/ssh"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
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
	// noteName is the results note's file name; empty is l88NoteName's.
	noteName string
}

func (e *l88Env) logf(format string, args ...any) {
	e.t.Helper()
	e.t.Logf("%s", e.n.mask(fmt.Sprintf(format, args...)))
}

func l88Run(t *testing.T, l *lab) { l88RunAs(t, l, l88Variant{}) }

// l88Variant is a register entry that runs on the L88 plumbing (the reference loaded, the
// lab's management address, the teardown) and measures its own cells: L87 is one. The zero
// value is L88 itself.
type l88Variant struct {
	id       string // the register entry, "L87"; empty is L88
	noteName string
	cells    func(e *l88Env)
}

func l88RunAs(t *testing.T, l *lab, v l88Variant) {
	pw, err := l73NewRootPassword()
	if err != nil {
		t.Fatal(err)
	}
	hash, err := l88PasswordHash(l.p.name, pw)
	if err != nil {
		t.Fatalf("INVALID: %v", err)
	}
	e := &l88Env{t: t, l: l, pw: pw, hash: hash, tls: l88TLSPass()}
	if e.tls && !l88HasTLS(l.p.sel) {
		t.Skipf("%s has no RFC 9887 client in this lab", l.p.sel)
	}
	transport := "tcp"
	if e.tls {
		transport = "tls"
	}
	e.n = newL88Note(l.p, transport, pw, hash)
	e.n.id, e.noteName = v.id, v.noteName
	if !l88Junos(l.p) && l.p.name != "nokia_srlinux" {
		if lines := l88Clear(l.p); len(lines) > 0 {
			e.must("clearing the lab's own server lines", l88Admin(l, func(c *cliConn) error {
				_, err := l73CiscoRun(c, l88WithCommit(l.p, l73Lines(lines...)), nil, true, l73ExtraMarks(l88Family(l.p))...)
				if err != nil {
					t.Logf("clear (lenient): %s", e.n.mask(oneLine(err.Error())))
				}
				return nil
			}))
		}
	}
	e.addSecondAddress()
	undoVRF := func() {}
	if l.p.name == "nokia_srlinux" {
		e.srFacts()
		// SR Linux commits a server's source-address only when the address is configured on an
		// interface of the network instance; the management address is learned by DHCP, which
		// does not count (the first run's commit failure, in the note). The lab scaffolding
		// configures the same address statically for the run and takes it off after.
		addr := l.p.addr + "/24"
		// The device refuses a configured address while the DHCP client is present ("ipv4 address
		// not configurable while ipv4 dhcp-client present"), so the client goes in the same commit.
		set := []string{"delete interface mgmt0 subinterface 0 ipv4 dhcp-client", "interface mgmt0 {", "subinterface 0 {", "ipv4 {", "address " + addr + " {", "}", "}", "}", "}"}
		e.must("configuring the management address statically", l88SRPush(set))
		e.n.fact("the lab scaffolding configured `" + addr + "` statically on mgmt0.0 in place of the DHCP client (the address is DHCP-learned; the commit of a source-address needs a configured one)")
		srDone := false
		undoVRF = func() {
			if srDone {
				return
			}
			srDone = true
			// The servers' source-address names the static address, so it goes in the same commit.
			undo := []string{}
			for _, sv := range l88Servers {
				undo = append(undo, "delete system aaa server-group port49 server "+sv+" tacacs source-address")
			}
			undo = append(undo, "delete interface mgmt0 subinterface 0 ipv4 address "+addr,
				"interface mgmt0 {", "subinterface 0 {", "ipv4 {", "dhcp-client {", "}", "}", "}", "}")
			if err := l88SRPush(undo); err != nil {
				e.n.fact("teardown: removing the static management address said " + e.n.redact(err.Error()))
				e.t.Errorf("INVALID: the SR Linux undo was refused: %s", e.n.mask(oneLine(err.Error())))
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			out, _ := exec.CommandContext(ctx, "docker", "exec", l76Container, "sr_cli", "-d",
				"info from running interface mgmt0 subinterface 0 ipv4").CombinedOutput()
			back := e.n.redact(string(out))
			e.n.fact("teardown, `info from running interface mgmt0 subinterface 0 ipv4`: " + oneLine(back))
			if !strings.Contains(string(out), "dhcp-client") || strings.Contains(string(out), addr) {
				e.t.Errorf("INVALID: the SR Linux undo did not take: mgmt0 is not back on the DHCP client:\n%s", back)
				return
			}
			e.n.fact("teardown: the static management address was removed and mgmt0 is back on the DHCP client (read back)")
		}
		defer undoVRF()
	}
	if name := l88XRVRF(); name != "" && l.p.name == "cisco_xrd" {
		set, undo := l88XRVRFLines(name, l.p.addr)
		push := func(lines []string) error {
			return l88Admin(l, func(c *cliConn) error {
				items := l88WithCommit(l.p, l88Confirming(lines))
				items[len(items)-1].Detach = true // the commit moves the SSH server the session came in on
				_, err := l73CiscoRun(c, items, nil, true, l73ExtraMarks(l88Family(l.p))...)
				return err
			})
		}
		// The commit moves the interface the session came in on, so the session may end
		// with it; the reconnect below is the check. docker exec into the node's XR CLI is the
		// recovery if it does not come back.
		_ = push(set)
		e.n.fact("named-VRF pass: the management interface and the SSH server moved into vrf " + name + " by the lab scaffolding (`" + strings.Join(set, "; ") + "`)")
		undone := false
		undoVRF = func() {
			if undone {
				return
			}
			undone = true
			var td strings.Builder
			perr := push(undo)
			// The read-back is the teardown line of the note: a device left in the VRF would
			// skew any later XR run.
			rerr := l88Admin(l, func(c *cliConn) error {
				for _, cmd := range []string{"show ipv4 vrf all interface brief", "show running-config ssh"} {
					out, err := c.sendExpect(cmd, 60*time.Second, "xrd1#")
					if err != nil {
						return err
					}
					shown := oneLine(stripPrompt(e.n.redact(l88Evidence(out))))
					td.WriteString(shown + "\n")
					e.n.fact("teardown, `" + cmd + "`: " + shown)
				}
				return nil
			})
			if perr != nil || rerr != nil {
				e.n.fact(fmt.Sprintf("teardown: the undo push said %v; the read-back said %v", perr, rerr))
			}
			// The read-back is the verdict: the interface back in default, no vrf on the ssh server.
			facts := td.String()
			if rerr != nil || !strings.Contains(facts, "Up Up default") || strings.Contains(facts, "ssh server vrf") {
				e.t.Errorf("INVALID: the XR VRF undo did not take: push %v, read-back %v; the device must be restored before the next run", perr, rerr)
			}
		}
		defer undoVRF()
		e.must("reaching the device in the new VRF", l88Admin(l, func(c *cliConn) error {
			out, err := c.sendExpect("show vrf all", 60*time.Second, "xrd1#")
			e.n.fact("`show vrf all` after the move: " + oneLine(stripPrompt(e.n.redact(l88Evidence(out)))))
			return err
		}))
	}
	if e.tls {
		e.enrolTLS()
	}
	e.must("applying the reference", l88Apply(l, transport))
	shown := transport
	if l.p.name == "nokia_srlinux" {
		shown = "tcp, then tls-profile and port 300 added by the harness"
	}
	e.n.fact("the reference loaded: `deploy/device-aaa/" + l88Refs[l.p.name] + "` (" + shown + "), values: servers " +
		strings.Join(l88Servers, ", ") + "; the second is an address on the bridge where nothing listens")
	e.deviceFacts()
	e.debugOn()
	if v.cells != nil {
		v.cells(e)
	} else {
		e.cells(transport, l88Cells(l.p.sel, e.tls))
	}
	if e.tls && l.p.name == "nokia_srlinux" {
		e.srEvidence()
	}
	undoVRF()
	e.finish()
}

func (e *l88Env) must(what string, err error) {
	e.t.Helper()
	if err != nil {
		e.t.Fatalf("INVALID: %s: %s", what, e.n.mask(oneLine(err.Error())))
	}
}

func (e *l88Env) cells(transport string, ids []string) {
	// PORT49_L88_CELLS=a,b,e,f runs only those cells: an isolation aid for a cell that fails
	// after others; a note from such a run says which cells it ran.
	if only := os.Getenv("PORT49_L88_CELLS"); only != "" {
		ids = l88OnlyCells(ids, only)
		e.n.fact("this run ran only cells " + strings.Join(ids, ", ") + " (PORT49_L88_CELLS)")
	}
	for _, id := range ids {
		e.t.Logf("lab: cell %s (%s)", id, transport)
		switch id {
		case "a":
			e.cellA()
		case "b":
			e.cellB()
		case "c", "d":
			if id == "c" || !slices.Contains(ids, "c") {
				e.cellsCD(slices.Contains(ids, "c"), slices.Contains(ids, "d"))
			}
		case "f2":
			e.cellF2()
		case "f3":
			e.cellF3()
		case "e":
			e.cellE()
		case "f":
			e.cellF()
		case "g":
			e.cellG()
		case "h":
			e.cellH()
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
	name := l88NoteName(e.l.p)
	if e.noteName != "" {
		name = e.noteName
	}
	path := filepath.Join(root, "tests", "lab", "results", name)
	if os.Getenv("PORT49_L88_CELLS") != "" {
		// A filtered run is an isolation aid, never the record: its note goes to the temp dir.
		path = filepath.Join(os.TempDir(), "partial-"+name)
	}
	if err := os.WriteFile(path, []byte(out), 0o644); err != nil {
		e.t.Fatal(err)
	}
	e.t.Logf("lab: wrote %s", path)
}

// l88NoteName is L88-<platform>.md, with the image's selector when a default row shares the name.
func l88NoteName(p platform) string {
	if l88TLSPass() {
		return strings.TrimSuffix(l88NoteName0(p), ".md") + "-tls.md"
	}
	return l88NoteName0(p)
}

func l88NoteName0(p platform) string {
	for _, q := range platforms {
		if q.name == p.name && q.sel != p.sel && !optInPlatforms[q.sel] {
			return "L88-" + p.name + "-" + p.sel + ".md"
		}
	}
	if p.name == "cisco_xrd" && l88XRVRF() != "" {
		return "L88-" + p.name + "-named-vrf.md"
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
			if e.l.p.name == "nokia_srlinux" {
				if err := l88SRPush(del); err != nil {
					return err
				}
				ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
				defer cancel()
				out, _ := exec.CommandContext(ctx, "docker", "exec", l76Container, "sr_cli", "-d",
					"info from running system aaa authentication").CombinedOutput()
				return l88AccountGone(l88DenyUser, string(out))
			}
			if l88Junos(e.l.p) {
				if _, err := junosConfigure(c, del...); err != nil {
					return err
				}
				out, err := junosShow(c, "show configuration system login | display set")
				if err != nil {
					return err
				}
				return l88AccountGone(l88DenyUser, out)
			}
			if _, err := l73CiscoRun(c, l88WithCommit(e.l.p, l88Confirming(del)), nil, true, l73ExtraMarks(l88Family(e.l.p))...); err != nil {
				return err
			}
			out, err := c.sendExpect("show running-config | include username", 60*time.Second, c.prompt)
			if err != nil {
				return err
			}
			return l88AccountGone(l88DenyUser, out)
		}))
	}()
	// The control.
	e.must("stopping port49d", e.l.stopDaemon())
	cl, cerr := e.l.dial(l88DenyUser, e.pw, 120*time.Second)
	if cerr == nil {
		cl.Close()
	}
	e.restart()
	// A device that marked port49d dead during the control answers locally, with no packet,
	// until its dead time runs out (XR 26.1.1 and IOS XE; cell e waits the same way). The
	// attempt is repeated every 10 s for up to 5 minutes until port49 sees one; the attempts
	// that never reached port49 are recorded, and the one that did is judged.
	var (
		err    error
		took   time.Duration
		recs   []map[string]any
		before []string
		start  = time.Now()
	)
	for {
		off := e.l.mark()
		t0 := time.Now()
		var cl *ssh.Client
		cl, err = e.l.dial(l88DenyUser, e.pw, 120*time.Second)
		took = time.Since(t0)
		if err == nil {
			cl.Close()
		}
		recs = e.l.waitForRecords(off, 10*time.Second, func(rs []map[string]any) bool { return redeemFor(rs, l88DenyUser) != nil })
		if redeemFor(recs, l88DenyUser) != nil || time.Since(start) > 5*time.Minute {
			break
		}
		before = append(before, fmt.Sprintf("+%s logged in %v without port49 seeing it", time.Since(start).Round(time.Second), err == nil))
		time.Sleep(10 * time.Second)
	}
	seenAt := time.Since(start).Round(time.Second)
	window := fmt.Sprintf("attempts %d, port49 first saw one at +%s", len(before)+1, seenAt)
	if redeemFor(recs, l88DenyUser) == nil {
		window = fmt.Sprintf("attempts %d, port49 saw none in %s (the 5 minute cap)", len(before)+1, seenAt)
	}
	if len(before) > 0 {
		e.n.fact("cell a: before an attempt reached port49 the denied user was tried " + fmt.Sprint(len(before)) + " times: " + strings.Join(before, "; "))
	}
	var verdict, reason string
	if r := redeemFor(recs, l88DenyUser); r != nil {
		verdict, reason = str(r, "verdict"), str(r, "reason")
	}
	obs := fmt.Sprintf("control (port49d stopped, the local account): logged in %v (%s). With port49d answering: logged in %v after %s (%s); "+
		"port49 decision for the attempt: verdict=%q reason=%q; %s", cerr == nil, l73Err(cerr), err == nil, took.Round(time.Millisecond), l73Err(err), verdict, reason, window)
	switch {
	case cerr != nil:
		e.n.cell("a", "INVALID", obs+": the control failed, so the refusal says nothing", summarize(recs))
		e.t.Errorf("cell a: the control login failed: %s", e.n.mask(oneLine(l73Err(cerr))))
	case err == nil:
		e.n.cell("a", "FAIL", obs, summarize(recs))
		e.t.Errorf("cell a FAIL: a port49-denied user logged in on the local account")
	case verdict == "":
		e.n.cell("a", "FAIL", obs+": the device answered locally for the whole cap", summarize(recs))
		e.t.Errorf("cell a FAIL: the device never asked port49 within the cap")
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
		outs, err = e.l.l88LoginWithin(user, secret, 60*time.Second, "show version", l88DenyCommand(e.l.p))
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
	if e.l.p.name == "nokia_srlinux" && err == nil && starts > 0 && stops > 0 && permits+denies == 0 && len(outs) == 2 &&
		strings.TrimSpace(outs[0]) != "" && strings.TrimSpace(outs[1]) != "" && !l88Refused(outs[1]) {
		// SR Linux asks port49 for no command (L76: its native schema has no TACACS+ authorization
		// method; the role rules decide), so port49 cannot deny a command here. The login, both
		// commands and the accounting are measured; the denial is not enforceable and is recorded as such.
		obs := fmt.Sprintf("login with a one-time credential (%s) %s: port49 received 0 command authorizations (SR Linux asks for none, L76); "+
			"the command port49's policy denies on other platforms (`%s`) ran and printed output, so no command denial through port49 exists on SR Linux; "+
			"accounting START %d, STOP %d; command output: %s", waited, e.n.redact(l88Err(err)), l88DenyCommand(e.l.p), starts, stops, shown)
		e.n.cell("e", "OBSERVED", obs, summarize(recs))
		return
	}
	obs := fmt.Sprintf("login with a one-time credential (%s) %s: %d command authorizations permitted, %d denied by port49; accounting START %d, STOP %d; %s; command output: %s",
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
	e.must("stopping port49d", e.l.stopDaemon())
	base, err := e.l.configPath()
	e.must("reading the standing config", err)
	raw, err := os.ReadFile(base)
	e.must("reading the standing config", err)
	cfg, err := l73SetLine(string(raw), "listen: ", `listen: "`+net.JoinHostPort(l88Servers[1], "49")+`"`)
	e.must("moving the listener", err)
	resetPort := "49"
	if e.tls {
		// The device dials port 300: the RFC 9887 listener moves to the second address and the
		// resetting listener takes the first address on 300.
		resetPort = strconv.Itoa(l73TLSPort)
		from := `"` + net.JoinHostPort(l88Servers[0], resetPort) + `"`
		if strings.Count(cfg, from) != 1 {
			e.t.Fatalf("INVALID: the TLS config holds %d copies of %s", strings.Count(cfg, from), from)
		}
		cfg = strings.Replace(cfg, from, `"`+net.JoinHostPort(l88Servers[1], resetPort)+`"`, 1)
	}
	path := filepath.Join(root, "tests", "lab", "logs", "port49d-l88f-"+e.l.p.name+".yaml")
	e.must("writing the config", os.WriteFile(path, []byte(cfg), 0o644))
	healthListen = net.JoinHostPort(l88Servers[1], "49") // the health gate dials where the listener moved
	serr := e.l.startDaemonWith(path, true)
	healthListen = ""
	e.must("starting port49d on the second address", serr)
	rst, err := l88ResetListener(l88Servers[0], resetPort)
	e.must("the resetting listener", err)
	restore := func() {
		rst.stop()
		e.must("stopping the second-address daemon", e.l.stopDaemon())
		e.restart()
	}
	user, secret := e.l.nextLogin(e.t)
	e.n.addSecret(secret)
	stopCap := e.l.capture(e.t, e.capName("L88-f"))
	e.n.capture(e.l.evidencePath)
	defer stopCap()
	// A device that marked both servers dead earlier (XR 26.1.1 and IOS XE, cell e) fails the
	// login at once without sending a packet until its dead time runs out: the login is
	// retried every 10 s for 5 minutes on the same credential, and the tries are recorded.
	off := e.l.mark()
	t0 := time.Now()
	var (
		outs  []string
		lerr  error
		recs  []map[string]any
		tries int
	)
	for {
		tries++
		outs, lerr = e.l.l88LoginWithin(user, secret, 120*time.Second, "show version")
		recs = e.l.waitForRecords(off, 15*time.Second, func(rs []map[string]any) bool { return redeemFor(rs, user) != nil })
		if redeemFor(recs, user) != nil || time.Since(t0) > 5*time.Minute {
			break
		}
		time.Sleep(10 * time.Second)
	}
	took := time.Since(t0)
	e.l.flushCapture(e.t)
	wire := l88Wire(e.l, t0, time.Now())
	if tries > 1 {
		e.n.fact(fmt.Sprintf("cell f: the login took %d tries over %s before port49 saw it", tries, took.Round(time.Second)))
	}
	n := rst.n.Load()
	restore()
	red := redeemFor(recs, user)
	obs := fmt.Sprintf("login with a one-time credential, the first server (%s) resetting every connection at Accept and port49d on the second (%s): %s in %s; "+
		"connections the first server reset: %d; port49 redeemed the credential: %v; tries %d, the login reached port49 after %s; first command output: %s",
		l88Servers[0], l88Servers[1], e.n.redact(l88Err(lerr)), took.Round(10*time.Millisecond), n, red != nil, tries, took.Round(time.Second), oneLine(stripPrompt(firstOut(outs))))
	evidence := summarize(recs) + "\nthe wire during the login (headers only):\n" + wire + e.debugRead()
	if e.l.p.name == "cisco_iosxe" {
		// The device's own state, read after f: a break-glass login with port49d stopped made
		// the next login choose no server when it came before f (this run's first two tries).
		evidence += "\n" + e.afterFEvidence()
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
	cmd     *exec.Cmd
	n       atomic.Int64
	stopped bool
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
	if r.stopped {
		return
	}
	r.stopped = true
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
	if e.l.p.name == "cisco_xrd" {
		_ = l88Admin(e.l, func(c *cliConn) error {
			for _, cmd := range []string{"terminal length 0", "show running-config interface MgmtEth0/RP0/CPU0/0", "show ipv4 vrf all interface brief",
				"show running-config router static", "show running-config ssh", "show vrf all"} {
				out, err := c.sendExpect(cmd, 60*time.Second, "xrd1#")
				if err != nil {
					continue
				}
				e.n.fact("`" + cmd + "`: " + oneLine(stripPrompt(e.n.redact(l88Evidence(out)))))
			}
			return nil
		})
		return
	}
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
func (e *l88Env) cellsCD(runC, runD bool) {
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
		if runC {
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
				outs, err := x.l.l88LoginWithin(breakglassUser, breakglassPassword, 60*time.Second, "show version")
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
		}
		if !runD {
			return
		}
		// (d)
		off := x.l.errLogSize()
		hang(true)
		deadline := time.Now().Add(90 * time.Second)
		for len(x.l.errLinesSince(off, darkCloseText)) == 0 && time.Now().Before(deadline) {
			time.Sleep(time.Second)
		}
		wentDark := len(x.l.errLinesSince(off, darkCloseText)) > 0
		t0 := time.Now()
		outs, err := x.l.l88LoginWithin(breakglassUser, breakglassPassword, 60*time.Second, "show version")
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

// afterFEvidence is the IOS XE's TACACS+ state after cell f: `show tacacs`, the sockets and
// the TACACS process, filtered and redacted. It runs after f, never before it: a break-glass
// login with port49d stopped, opened before f, left the device choosing no server for f's
// login (tests/lab/results/L88-cisco_iosxe-f-evidence-run.md).
func (e *l88Env) afterFEvidence() string {
	var b strings.Builder
	err := l88Admin(e.l, func(c *cliConn) error {
		for _, cmd := range []string{"terminal length 0", "show tacacs", "show tcp brief", "show processes | include TACACS"} {
			out, err := c.sendExpect(cmd, 90*time.Second, "xe1#")
			if err != nil {
				out += "\n(" + err.Error() + ")"
			}
			fmt.Fprintf(&b, "`%s` after f:\n%s\n", cmd, e.n.redact(l88Evidence(out)))
		}
		return nil
	})
	if err != nil {
		fmt.Fprintf(&b, "(the evidence session failed: %s)\n", e.n.redact(err.Error()))
	}
	return b.String()
}

// l88OnlyCells is ids narrowed to the comma-separated list only; an empty list keeps them all.
func l88OnlyCells(ids []string, only string) []string {
	if only == "" {
		return ids
	}
	var keep []string
	for _, id := range ids {
		if slices.Contains(strings.Split(only, ","), id) {
			keep = append(keep, id)
		}
	}
	return keep
}

// l88TryResult is one break-glass try on a line: its error, or the command's first output.
func l88TryResult(err error, out string) string {
	if err != nil {
		return l88Err(err)
	}
	return fmt.Sprintf("logged in, `show version` printed %q", out)
}

// cellF2 measures what an IOS XE does after a break-glass session ran while port49d was
// down (the lead's 2026-11-03 ruling after cell f failed when such a session came before
// it): port49d stopped, a break-glass session runs five commands, port49d comes back, and
// a token login and a break-glass login are tried every 10 s for up to 5 minutes. The
// session is closed 60 s after port49d is back. MEASURED, not graded: it records how long
// the device chooses no server for a login, whether that ends when the session exits or
// only with time, what the failed login shows, and the device's own tacacs state after.
func (e *l88Env) cellF2() {
	e.must("stopping port49d", e.l.stopDaemon())
	c, err := l88Opener(e.l.p)(e.l)
	e.must("opening the break-glass CLI", err)
	var b strings.Builder
	run := func(cmd string) string {
		out, err := c.sendExpect(cmd, 90*time.Second, "xe1#")
		if err != nil {
			out += "\n(" + err.Error() + ")"
		}
		return out
	}
	run("terminal length 0")
	run("debug tacacs")
	cmds := []string{"show version", "show clock", "show ip interface brief", "show tacacs", "show processes | include TACACS"}
	for _, cmd := range cmds {
		run(cmd)
	}
	stopCap := e.l.capture(e.t, e.capName("L88-f2"))
	e.n.capture(e.l.evidencePath)
	defer stopCap()
	errOff := e.l.errLogSize()
	mark := e.l.mark()
	hostBefore := l88Sockets()
	// port49d comes back as a NEW process on the same config: the lab's seed credentials are
	// minted again at its start, so a credential minted before this restart no longer exists.
	e.restart()
	user, secret := e.l.nextLogin(e.t)
	e.n.addSecret(secret)
	fmt.Fprintf(&b, "break-glass session ran %d commands with port49d stopped; port49d was then started again as a new process (same config, same address) and the session stayed open for 60 s\n", len(cmds))
	t0 := time.Now()
	wall0 := t0
	closedAt := time.Duration(-1)
	var tokenOK, bgFirst time.Duration = -1, -1
	var hostMid string
	for time.Since(t0) < 5*time.Minute {
		at := time.Since(t0)
		if closedAt < 0 && at >= 60*time.Second {
			c.Close()
			closedAt = at
			fmt.Fprintf(&b, "+%s: the break-glass session was closed\n", at.Round(time.Second))
		}
		if hostMid == "" && at >= 150*time.Second {
			hostMid = l88Sockets()
		}
		_, terr := e.l.l88LoginWithin(user, secret, 20*time.Second, "show version")
		_, berr := e.l.l88LoginWithin(breakglassUser, breakglassPassword, 20*time.Second, "show version")
		fmt.Fprintf(&b, "+%s: one-time-credential login: %s; break-glass login: %s\n", at.Round(time.Second),
			e.n.redact(l88Err(terr)), e.n.redact(l88Err(berr)))
		if berr == nil && bgFirst < 0 {
			bgFirst = at
		}
		if terr == nil {
			tokenOK = at
			break
		}
		time.Sleep(10 * time.Second)
	}
	end := time.Now()
	if closedAt < 0 {
		c.Close()
	}
	hostAfter := l88Sockets()
	e.l.flushCapture(e.t)
	wire := l88Wire(e.l, wall0, end)
	after := e.afterEvidenceWith("show logging | include Authentication start|Using server|Opening TCP|Socket I/O|Choosing next")
	verdict := fmt.Sprintf("the first one-time-credential login that port49 answered came at +%s after port49d was back", tokenOK.Round(time.Second))
	if tokenOK < 0 {
		verdict = "no one-time-credential login succeeded within 5 minutes of port49d being back"
	}
	closed := "the session was still open when the loop began and was closed at +" + closedAt.Round(time.Second).String()
	bg := "a break-glass login never succeeded while port49d answered"
	if bgFirst >= 0 {
		bg = fmt.Sprintf("a break-glass login first succeeded at +%s", bgFirst.Round(time.Second))
	}
	recs := e.l.recordsSince(mark)
	state := fmt.Sprintf("port49d's own view of the window: %d decision records; its stderr lines: %s", len(recs),
		e.n.redact(strings.Join(lastLines(e.l.errLinesSince(errOff, ""), 12), " / ")))
	e.n.cell("f2", "MEASURED", fmt.Sprintf("%s; %s; %s", verdict, closed, bg),
		b.String()+"\n"+state+"\n"+summarize(recs)+"\n`ss -tn` on port 49 before port49d restarted:\n"+hostBefore+
			"\nmid-window:\n"+hostMid+"\nafter:\n"+hostAfter+"\nthe wire (headers only):\n"+wire+"\n"+after)
}

// l88Sockets is the host's TCP sockets on port 49, no process names.
func l88Sockets() string {
	out, err := exec.Command("ss", "-tn", "state", "all", "( sport = :49 or dport = :49 )").CombinedOutput()
	if err != nil {
		return "(ss failed: " + err.Error() + ")"
	}
	return string(out)
}

// l88Wire reads the capture's headers only: for each connection the device opened to port 49
// in [from, to], what flags crossed in each direction. It never reads a payload.
func l88Wire(l *lab, from, to time.Time) string {
	port := uint16(49)
	if l88TLSPass() {
		port = l73TLSPort // the RFC 9887 pass: the device dials 300, which the capture filter includes
	}
	return l88WireFile(l.capAbs, l.p.addr, port, from, to)
}

func l88WireFile(path, addr string, port uint16, from, to time.Time) string {
	pkts, err := l29PacketsOn(path, addr, port)
	if err != nil {
		return "(the capture could not be read: " + err.Error() + ")"
	}
	type conn struct {
		first                       time.Time
		server                      string
		syn, synack, devFIN, srvFIN bool
		devRST, srvRST              bool
		devPkts, srvPkts            int
	}
	conns := map[uint16]*conn{}
	var order []uint16
	for _, p := range pkts {
		if p.at.Before(from) || p.at.After(to) {
			continue
		}
		c := conns[p.port]
		if c == nil {
			c = &conn{first: p.at}
			conns[p.port] = c
			order = append(order, p.port)
		}
		f := p.fl.Flags
		if p.fromDevice {
			c.devPkts++
			c.server = p.fl.Dst.String()
			c.syn = c.syn || (f&0x02 != 0 && f&0x10 == 0)
			c.devFIN = c.devFIN || f&0x01 != 0
			c.devRST = c.devRST || f&0x04 != 0
		} else {
			c.srvPkts++
			c.server = p.fl.Src.String()
			c.synack = c.synack || f&0x12 == 0x12
			c.srvFIN = c.srvFIN || f&0x01 != 0
			c.srvRST = c.srvRST || f&0x04 != 0
		}
	}
	var b strings.Builder
	var syn, synack, rsts int
	for _, port := range order {
		c := conns[port]
		if c.syn {
			syn++
		}
		if c.synack {
			synack++
		}
		if c.srvRST || c.devRST {
			rsts++
		}
	}
	fmt.Fprintf(&b, "%d connections from the device in the window: %d with a SYN, %d answered SYN-ACK, %d with an RST\n", len(order), syn, synack, rsts)
	for i, port := range order {
		if i >= 40 {
			fmt.Fprintf(&b, "... %d more\n", len(order)-i)
			break
		}
		c := conns[port]
		fmt.Fprintf(&b, "+%s %s sport %d: SYN %v SYN-ACK %v; device packets %d, server packets %d; FIN dev %v srv %v; RST dev %v srv %v\n",
			c.first.Sub(from).Round(100*time.Millisecond), c.server, port, c.syn, c.synack, c.devPkts, c.srvPkts, c.devFIN, c.srvFIN, c.devRST, c.srvRST)
	}
	return b.String()
}

// afterEvidenceWith is the IOS XE's tacacs state and one `show logging` filter, read through a
// break-glass session with port49d stopped, filtered and redacted, and cut to its last 200 lines.
func (e *l88Env) afterEvidenceWith(logging string) string {
	var b strings.Builder
	err := l88Admin(e.l, func(c *cliConn) error {
		for _, cmd := range []string{"terminal length 0", "show tacacs", "show tcp brief", "show processes | include TACACS", logging} {
			out, err := c.sendExpect(cmd, 90*time.Second, "xe1#")
			if err != nil {
				out += "\n(" + err.Error() + ")"
			}
			lines := strings.Split(e.n.redact(l88Evidence(out)), "\n")
			if len(lines) > 200 {
				lines = lines[len(lines)-200:]
			}
			fmt.Fprintf(&b, "`%s`:\n%s\n", cmd, strings.Join(lines, "\n"))
		}
		return nil
	})
	if err != nil {
		fmt.Fprintf(&b, "(the evidence session failed: %s)\n", e.n.redact(err.Error()))
	}
	return b.String()
}

// lastLines is the last n of lines.
func lastLines(lines []string, n int) []string {
	if len(lines) > n {
		return lines[len(lines)-n:]
	}
	return lines
}

// l88Debug is the device debug a platform runs with from the start of the run, so that the
// log buffer holds what the device did at cell f without a session being opened before f
// (a break-glass session with port49d down changes the device's server state: IOS XE, f2).
var l88Debug = map[string]struct {
	on, off []string
	read    []string
	prompt  string
}{
	"cisco_xrd": {on: []string{"debug tacacs", "debug aaa authentication"}, off: []string{"undebug all"},
		read: []string{"show logging | include tacacs", "show logging | include TACACS", "show logging | include AAA", "show logging | include aaa"}, prompt: "xrd1#"},
}

func (e *l88Env) debugOn() {
	d, ok := l88Debug[e.l.p.name]
	if !ok {
		return
	}
	e.must("turning the device debug on", l88Admin(e.l, func(c *cliConn) error {
		for _, cmd := range append([]string{"terminal length 0"}, d.on...) {
			if _, err := c.sendExpect(cmd, 60*time.Second, d.prompt); err != nil {
				return err
			}
		}
		return nil
	}))
	e.n.fact("device debug on from before cell a: " + strings.Join(d.on, ", "))
}

// debugRead is the device's log lines for the debug, filtered and redacted, and turns the debug off.
func (e *l88Env) debugRead() string {
	d, ok := l88Debug[e.l.p.name]
	if !ok {
		return ""
	}
	var b strings.Builder
	err := l88Admin(e.l, func(c *cliConn) error {
		for _, cmd := range append([]string{"terminal length 0"}, d.read...) {
			out, err := c.sendExpect(cmd, 90*time.Second, d.prompt)
			if err != nil {
				out += "\n(" + err.Error() + ")"
			}
			lines := strings.Split(e.n.redact(l88Evidence(out)), "\n")
			if len(lines) > 250 {
				lines = lines[len(lines)-250:]
			}
			fmt.Fprintf(&b, "\n`%s`:\n%s\n", cmd, strings.Join(lines, "\n"))
		}
		for _, cmd := range d.off {
			c.sendExpect(cmd, 60*time.Second, d.prompt)
		}
		return nil
	})
	if err != nil {
		fmt.Fprintf(&b, "(the debug read failed: %s)\n", e.n.redact(err.Error()))
	}
	return b.String()
}

// cellF3 (MEASURED, IOS XE): a 3am sequence. port49d's first address is down (resetting every
// connection), the second answers, and an operator has just used break-glass with port49d
// stopped. The break-glass session stays open 60 s; token logins run every 10 s for up to 5
// minutes. It records when the first reached the second server, what the user saw until
// then, whether ending the session cleared it, and the device's state at the first failure.
func (e *l88Env) cellF3() {
	e.must("stopping port49d", e.l.stopDaemon())
	c, err := l88Opener(e.l.p)(e.l)
	e.must("opening the break-glass CLI", err)
	run := func(cmd string) string {
		out, err := c.sendExpect(cmd, 90*time.Second, "xe1#")
		if err != nil {
			out += "\n(" + err.Error() + ")"
		}
		return out
	}
	run("terminal length 0")
	run("debug tacacs")
	cmds := []string{"show version", "show clock", "show ip interface brief", "show tacacs", "show processes | include TACACS"}
	for _, cmd := range cmds {
		run(cmd)
	}
	base, err := e.l.configPath()
	e.must("reading the standing config", err)
	raw, err := os.ReadFile(base)
	e.must("reading the standing config", err)
	cfg, err := l73SetLine(string(raw), "listen: ", `listen: "`+net.JoinHostPort(l88Servers[1], "49")+`"`)
	e.must("moving the listener", err)
	path := filepath.Join(root, "tests", "lab", "logs", "port49d-l88f3-"+e.l.p.name+".yaml")
	e.must("writing the config", os.WriteFile(path, []byte(cfg), 0o644))
	healthListen = net.JoinHostPort(l88Servers[1], "49")
	serr := e.l.startDaemonWith(path, true)
	healthListen = ""
	e.must("starting port49d on the second address", serr)
	rst, err := l88ResetListener(l88Servers[0], "49")
	e.must("the resetting listener", err)
	defer func() {
		rst.stop()
		e.must("stopping the second-address daemon", e.l.stopDaemon())
		e.restart()
	}()
	user, secret := e.l.nextLogin(e.t)
	e.n.addSecret(secret)
	stopCap := e.l.capture(e.t, e.capName("L88-f3"))
	e.n.capture(e.l.evidencePath)
	defer stopCap()
	mark := e.l.mark()
	var b strings.Builder
	fmt.Fprintf(&b, "break-glass session ran %d commands with port49d stopped; port49d was then started on the second address (%s) while the first (%s) reset every connection; the session stayed open 60 s\n", len(cmds), l88Servers[1], l88Servers[0])
	t0 := time.Now()
	closedAt := time.Duration(-1)
	reached := time.Duration(-1)
	atFirstFailure := ""
	for time.Since(t0) < 5*time.Minute {
		at := time.Since(t0)
		if closedAt < 0 && at >= 60*time.Second {
			c.Close()
			c = nil
			closedAt = at
			fmt.Fprintf(&b, "+%s: the break-glass session was closed\n", at.Round(time.Second))
		}
		off := e.l.mark()
		_, terr := e.l.l88LoginWithin(user, secret, 20*time.Second, "show version")
		recs := e.l.waitForRecords(off, 5*time.Second, func(rs []map[string]any) bool { return redeemFor(rs, user) != nil })
		seen := redeemFor(recs, user) != nil
		fmt.Fprintf(&b, "+%s: one-time-credential login: %s; port49 saw it: %v\n", at.Round(time.Second), e.n.redact(l88Err(terr)), seen)
		if terr != nil && atFirstFailure == "" && c != nil {
			var fb strings.Builder
			for _, cmd := range []string{"show tacacs", "show logging | include Authentication start|Using server|Opening TCP|Socket I/O|Choosing next"} {
				out := run(cmd)
				lines := strings.Split(e.n.redact(l88Evidence(out)), "\n")
				if len(lines) > 80 {
					lines = lines[len(lines)-80:]
				}
				fmt.Fprintf(&fb, "`%s`:\n%s\n", cmd, strings.Join(lines, "\n"))
			}
			atFirstFailure = fb.String()
		}
		if terr == nil && seen {
			reached = at
			break
		}
		time.Sleep(10 * time.Second)
	}
	end := time.Now()
	if c != nil {
		c.Close()
	}
	e.l.flushCapture(e.t)
	wire := l88Wire(e.l, t0, end)
	after := e.afterEvidenceWith("show logging | include Authentication start|Using server|Opening TCP|Socket I/O|Choosing next")
	verdict := fmt.Sprintf("the first one-time-credential login that reached the second server came at +%s", reached.Round(time.Second))
	if reached < 0 {
		verdict = "no one-time-credential login reached the second server within 5 minutes"
	}
	closed := "the break-glass session was closed at +" + closedAt.Round(time.Second).String()
	if closedAt < 0 {
		closed = "the break-glass session was never closed in the loop"
	}
	recs := e.l.recordsSince(mark)
	e.n.cell("f3", "MEASURED", verdict+"; "+closed,
		b.String()+"\ndevice state at the first failed login (read over the still-open session):\n"+atFirstFailure+
			"\n"+summarize(recs)+"\nthe wire (headers only):\n"+wire+"\n"+after)
}

// cellG (OBSERVED, the platforms L29 did not measure): single-connection on, a token session
// open, a reload that retires the open connection's key version (L29's re-keyed phase: the
// device's reviewed pin moves onto a key it does not hold), then the command in flight, a
// second command, the next token login and break-glass. It runs L29's own phase code, so the
// observation is L29's; a failed premise check is INVALID, never a result.
func (e *l88Env) cellG() {
	var failed []string
	fail := func(format string, args ...any) {
		msg := fmt.Sprintf(format, args...)
		failed = append(failed, msg)
	}
	if e.l.p.name == "nokia_srlinux" {
		// The schema, read from the device, says whether a TACACS+ single-connection leaf exists.
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		out, err := exec.CommandContext(ctx, "docker", "exec", l76Container, "sr_cli", "-d", "tree flat system aaa server-group").CombinedOutput()
		cancel()
		low := strings.ToLower(string(out))
		obs := "`tree flat system aaa server-group`, read from the device: " + oneLine(e.n.redact(string(out)))
		if err != nil || len(strings.TrimSpace(low)) == 0 {
			e.n.cell("g", "INVALID", fmt.Sprintf("the schema read failed (%v): %s", err, obs), "")
			e.t.Errorf("cell g: schema read failed: %v", err)
			return
		}
		if strings.Contains(low, "single") || strings.Contains(low, "multiplex") || strings.Contains(low, "persist") {
			e.n.cell("g", "INVALID", "the schema offers a connection-sharing leaf the harness does not drive yet: "+obs, "")
			e.t.Errorf("cell g: SR Linux schema has a connection-sharing leaf")
			return
		}
		e.n.cell("g", "OBSERVED", "SR Linux has no single-connection setting, so a key-retiring reload has no open shared connection to reset. "+obs, "")
		return
	}
	if _, ok := l29Refusals[e.l.p.name]; !ok {
		e.n.cell("g", "INVALID", "no measured refusal text for "+e.l.p.name+" in l29Refusals, so a refusal could not be told from output", "")
		e.t.Errorf("cell g: no l29Refusals entry for %s", e.l.p.name)
		return
	}
	pr := l29Heartbeat(e.t)
	defer pr.end()
	src := labSourceFrom(e.t)
	policy := filepath.Join(privateDir(e.t, "l88g-"+e.l.p.name), "policy.yaml")
	single := e.l.singleConnection(e.t)
	if !l29SingleSet(single) {
		fail("single-connection was not set on the device (its `?` offered it nowhere): no connection stays open across a reload")
	}
	li := e.l.startInventory(e.t, src, filepath.Join(root, "tests", "lab", "l29", "policy.yaml"))
	l29CapturePrefix = e.capName("L88-g") + "-"
	defer func() { l29CapturePrefix = "L29-reload-" }()
	var section string
	for _, ph := range l29Phases(src) {
		if ph.name == "rekeyed" {
			section = e.l.l29ReloadPhase(e.t, li, src, policy, ph, pr, fail)
		}
	}
	// The standing daemon is put back before the next cell.
	if err := e.l.stopDaemon(); err == nil {
		e.restart()
	}
	// The phase's first table (step | outcome) is the observation; the connection table that
	// follows is evidence.
	var rows []string
	inTable := false
	for _, ln := range strings.Split(section, "\n") {
		switch {
		case strings.HasPrefix(ln, "| step"):
			inTable = true
		case inTable && strings.HasPrefix(ln, "|---"):
		case inTable && strings.HasPrefix(ln, "| "):
			rows = append(rows, strings.ReplaceAll(strings.Trim(ln, "| "), " | ", ": "))
		case inTable:
			inTable = false
		}
		if !inTable && len(rows) > 0 {
			break
		}
	}
	obs := "single-connection: " + oneLine(single) + "; the re-keyed phase: " + strings.Join(rows, "; ")
	// A device that opens a new connection for each request holds none open across the
	// reload, so there is no open connection for port49d to reset: that is the answer to the
	// cell, not a failed run, and it is said in the row. Any other failed premise is INVALID.
	var other []string
	for _, f := range failed {
		if !strings.Contains(f, "no connection open across the change was reset") &&
			!strings.Contains(f, "no reset of an open connection was captured") {
			other = append(other, f)
		}
	}
	switch {
	case len(other) > 0:
		e.t.Error(e.n.mask(strings.Join(other, " / ")))
		e.n.cell("g", "INVALID", obs+"; premise checks failed: "+oneLine(strings.Join(other, " / ")), e.n.redact(section))
	case len(failed) > 0:
		e.n.cell("g", "OBSERVED", "the device held no connection open across the reload that port49d reset (single-connection was on; "+
			"what it sent after the reload went on connections it opened after it); "+obs, e.n.redact(section))
	default:
		e.n.cell("g", "OBSERVED", obs, e.n.redact(section))
	}
}

// capName is a capture's name for this run. An opt-in image shares its platform's name with
// the default row's (iosxe1718 and iosxe are both cisco_iosxe), and the capture file is named
// by platform, so it carries its selector and never overwrites the default row's evidence.
func (e *l88Env) capName(base string) string {
	if e.tls {
		base += "-tls"
	}
	if l88XRVRF() != "" && e.l.p.name == "cisco_xrd" {
		base += "-vrf"
	}
	if optInPlatforms[e.l.p.sel] {
		return base + "-" + e.l.p.sel
	}
	return base
}

// srFacts logs what SR Linux says about its management addressing, read through sr_cli (setup
// channel), before the reference goes on: the source-address must be one the node holds in the
// management network instance.
func (e *l88Env) srFacts() {
	for _, q := range []string{"info from state interface mgmt0 subinterface 0 ipv4", "info from state network-instance mgmt interface", "info from running network-instance mgmt"} {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		out, err := exec.CommandContext(ctx, "docker", "exec", l76Container, "sr_cli", "-d", q).CombinedOutput()
		cancel()
		txt := "`" + q + "`: " + oneLine(e.n.redact(l88Evidence(string(out))))
		if err != nil {
			txt += fmt.Sprintf(" (%v)", err)
		}
		e.n.fact(txt)
		e.t.Log(e.n.mask(txt))
	}
}

// srEvidence records what SR Linux says about its TLS profile and its TACACS+ servers, and the
// lines its debug logs hold about them, read through docker exec (setup channel). A `key` line is
// dropped and a hashed value masked before anything is kept (l88DropKeyLines, l88Hashed).
func (e *l88Env) srEvidence() {
	for _, q := range []string{
		"info from state system aaa server-group port49",
		"info from running system aaa server-group port49",
		"info from state system tls",
		"show system aaa server-group port49",
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		out, err := exec.CommandContext(ctx, "docker", "exec", l76Container, "sr_cli", "-d", q).CombinedOutput()
		cancel()
		txt := "`" + q + "`: " + oneLine(e.n.redact(l88DropKeyLines(string(out))))
		if err != nil {
			txt += fmt.Sprintf(" (%v)", err)
		}
		e.n.fact(txt)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", "exec", l76Container, "sh", "-c",
		"cd /var/log/srlinux/debug && echo 'files naming tls or tacacs or l73-dev:'; grep -ilE 'tls|tacacs|l73-dev' *.log; "+
			"echo 'sr_aaa_mgr.log lines naming server, tls, tacacs, handshake, ssl, certificate or profile:'; "+
			"grep -iE 'server|tls|tacacs|handshake|ssl|certificate|profile' sr_aaa_mgr.log | tail -n 40; echo '(end)'").CombinedOutput()
	txt := "the device's own aaa log (/var/log/srlinux/debug), read after the h login: " + oneLine(e.n.redact(string(out)))
	if err != nil {
		txt += fmt.Sprintf(" (%v)", err)
	}
	e.n.fact(txt)
}

// cellH is SR Linux's TLS pass: its server entry takes a tls-profile, the profile loads, and the
// question is what the device then puts on port 300. One login is tried, with a capture of port
// 300 held in memory (never written: it would carry the lab's plain TACACS+ bytes). Of the
// device's first data packet only the first byte is read: 0x16 opens a TLS handshake record.
func (e *l88Env) cellH() {
	e.n.noCapture = "the port 300 capture is held in memory by design (it carries plain TACACS+ bytes); only the first data byte and the SYN and SYN-ACK counts are kept"
	cap := exec.Command("sudo", "-n", "tcpdump", "-Z", "root", "-U", "-nn", "-i", "any", "-w", "-",
		"host "+e.l.p.addr+" and tcp port 300")
	var buf bytes.Buffer
	cap.Stdout = &buf
	e.must("starting the port 300 capture", cap.Start())
	time.Sleep(3 * time.Second)
	cl, err := e.l.dial("l88h", e.pw, 120*time.Second)
	if err == nil {
		cl.Close()
	}
	time.Sleep(3 * time.Second)
	_ = cap.Process.Signal(syscall.SIGTERM)
	_ = cap.Wait()
	f, perr := labpcap.Parse(buf.Bytes())
	if perr != nil {
		e.n.cell("h", "INVALID", "the port 300 capture did not parse: "+perr.Error(), "")
		e.t.Errorf("INVALID: %v", perr)
		return
	}
	var syn, synack, first int = 0, 0, -1
	for _, r := range f.Records {
		fl, ok := labpcap.FlowOf(f.Link, f.Bytes(r))
		if !ok {
			continue
		}
		switch {
		case fl.DstPort == 300 && fl.SYN():
			syn++
		case fl.SrcPort == 300 && fl.Flags&0x12 == 0x12:
			synack++
		case fl.DstPort == 300 && fl.PayloadLen > 0 && first < 0:
			first = int(f.Bytes(r)[fl.PayloadOff])
		}
	}
	got := fmt.Sprintf("the device opened %d connection attempts to port 300 (%d SYN-ACKs); ", syn, synack)
	switch {
	case first < 0:
		got += "it sent no data on any"
	case first == 0x16:
		got += "its first data byte is 0x16, a TLS handshake record"
	default:
		got += fmt.Sprintf("its first data byte is 0x%02x, not a TLS record (0x16): a TACACS+ header's version byte is 0xc0 or 0xc1", first)
	}
	e.n.cell("h", "OBSERVED", got+"; the login "+map[bool]string{true: "succeeded", false: "failed"}[err == nil], "")
}

// l88AccountGone is nil when no line of a device's account listing names user as an account.
// The command's own echo ("... | include username") does not start a line with it.
func l88AccountGone(user, listing string) error {
	for _, ln := range strings.Split(strings.ReplaceAll(listing, "\r", ""), "\n") {
		f := strings.Fields(ln)
		for i, w := range f {
			if (w == "user" || w == "username") && i+1 < len(f) && f[i+1] == user && !strings.HasPrefix(strings.TrimSpace(ln), "show ") {
				return fmt.Errorf("INVALID: the local account %s is still on the device after its removal: %s", user, strings.TrimSpace(ln))
			}
		}
		if strings.HasPrefix(strings.TrimSpace(ln), user+" {") { // SR Linux's `info` form: the account is a list entry
			return fmt.Errorf("INVALID: the local account %s is still on the device after its removal", user)
		}
	}
	return nil
}
