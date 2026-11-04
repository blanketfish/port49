//go:build lab

package lab

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestL87 measures spec section 15's L87: SR Linux with `exit-on-reject true` (the reference
// configuration sets it) when port49 answers ERROR, and once port49d has closed its listeners
// on a store that stopped answering. It runs on the L88 plumbing: the reference loaded, the lab's
// management address, the teardown. One selector per run: PORT49_LAB_PLATFORMS=srlinux.
func TestL87(t *testing.T) {
	if err := labOccupyForRun(labLockPath, "TestL87 pid "+strconv.Itoa(os.Getpid())); err != nil {
		t.Fatal(err)
	}
	if err := labGuardAt(l66StopSentinel, "/", l66DiskFloorMB); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("PORT49_LAB_ETCD_BIN") == "" {
		t.Fatal("INVALID: PORT49_LAB_ETCD_BIN names no directory holding etcd, etcdctl and etcdutl v3.6.15; cell (b) needs a real etcd to pause")
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
	ran := 0
	for _, p := range append(rowsFor(sel, false), rowsFor(sel, true)...) {
		p := p
		if p.name != "nokia_srlinux" {
			continue
		}
		ran++
		t.Run(p.name, func(t *testing.T) {
			l88RunAs(t, labFor(t, p), l88Variant{id: "L87", noteName: "L87-nokia_srlinux.md", cells: l87Cells})
		})
	}
	if ran == 0 {
		t.Fatal("INVALID: the selection names no SR Linux row (PORT49_LAB_PLATFORMS=srlinux)")
	}
}

// l87Faults is the lab fault switch's file and the daemon that reads it.
type l87Faults struct{ path string }

func (f l87Faults) set(t *testing.T, name string) {
	t.Helper()
	if err := os.WriteFile(f.path, []byte(name+"\n"), 0o600); err != nil {
		t.Fatalf("INVALID: writing the fault switch: %v", err)
	}
}

// l87Daemon restarts the standing daemon on its lab config with `lab.fault_file` naming a file
// the cells write.
func (e *l88Env) l87Daemon() l87Faults {
	e.must("stopping port49d", e.l.stopDaemon())
	base, err := e.l.configPath()
	e.must("reading the standing config", err)
	raw, err := os.ReadFile(base)
	e.must("reading the standing config", err)
	dir, err := labPrivateSub("l87")
	e.must("the private directory", err)
	e.must("the private directory", os.MkdirAll(dir, 0o700))
	f := l87Faults{path: filepath.Join(dir, "fault")}
	f.set(e.t, "")
	cfg, err := l73AddAfter(string(raw), "lab:", "  fault_file: "+f.path)
	e.must("adding the fault switch to the config", err)
	cfgPath := filepath.Join(dir, "port49d-l87.yaml")
	e.must("writing the config", os.WriteFile(cfgPath, []byte(cfg), 0o600))
	e.must("starting port49d with the fault switch", e.l.startDaemonWith(cfgPath, true))
	return f
}

// l87Login is a token login that runs cmds, retried every 10 s for up to 2 minutes while port49
// does not see it (a device that marked the server dead answers locally until its dead time ends).
func (e *l88Env) l87Login(user, secret string, cmds ...string) (outs []string, err error, recs []map[string]any, took time.Duration) {
	start := time.Now()
	for {
		off := e.l.mark()
		outs, err = e.l.loginWithin(user, secret, 60*time.Second, cmds...)
		recs = e.l.waitForRecords(off, 15*time.Second, func(rs []map[string]any) bool { return redeemFor(rs, user) != nil })
		if redeemFor(recs, user) != nil || time.Since(start) > 2*time.Minute {
			return outs, err, recs, time.Since(start)
		}
		time.Sleep(10 * time.Second)
	}
}

func l87Cells(e *l88Env) {
	stopCap := e.l.capture(e.t, "L87")
	e.n.capture(e.l.evidencePath)
	defer stopCap()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	out, err := exec.CommandContext(ctx, "docker", "exec", l76Container, "sr_cli", "-d",
		"info from running system aaa authentication exit-on-reject").CombinedOutput()
	cancel()
	if err != nil || !strings.Contains(string(out), "true") {
		e.t.Fatalf("INVALID: exit-on-reject is not true on the device after the reference loaded: %v %s", err, e.n.redact(string(out)))
	}
	e.n.fact("`info from running system aaa authentication exit-on-reject`: " + oneLine(e.n.redact(string(out))))

	faults := e.l87Daemon()
	mark := e.l87AAAMark()
	e.l87A(faults)
	e.l87AAAFact("a", &mark)
	e.l87C(faults)
	e.l87AAAFact("c", &mark)
	faults.set(e.t, "")
	e.must("stopping port49d", e.l.stopDaemon())
	e.restart() // the standing daemon, no fault switch
	e.l87B()
	e.l87AAAFact("b", &mark)
}

const l87AAALogPath = "/var/log/srlinux/debug/sr_aaa_mgr.log"

// l87AAAMark is how many lines SR Linux's aaa_mgr log holds now: a cell's own lines follow it.
func (e *l88Env) l87AAAMark() int {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, "docker", "exec", l76Container, "sh", "-c", "wc -l < "+l87AAALogPath).Output()
	n, _ := strconv.Atoi(strings.TrimSpace(string(out)))
	return n
}

// l87AAAFact records the aaa_mgr event lines (authentication, "is down", failures, rejects, priv-lvl)
// written since *mark, which is then moved to the end of the log: one fact per cell. Lines naming a
// credential word are dropped before they are read.
func (e *l88Env) l87AAAFact(cell string, mark *int) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", "exec", l76Container, "sh", "-c",
		fmt.Sprintf("tail -n +%d %s | grep -E 'sr_aaa_mgr: aaa/|Opened session| is down|fail|reject|priv-lvl' | grep -viE 'password|token|secret|eyJ|payload' | tail -n 40",
			*mark+1, l87AAALogPath)).CombinedOutput()
	*mark = e.l87AAAMark()
	txt := oneLine(e.n.redact(string(out)))
	if err != nil {
		txt += fmt.Sprintf(" (%v)", err)
	}
	e.n.fact("the device's own aaa log (`" + l87AAALogPath + "`), the event lines written during cell " + cell + ": " + txt)
}

// l87Redeems is the verdict and reason of each redeem record for user.
func l87Redeems(recs []map[string]any, user string) []string {
	var out []string
	for _, r := range recs {
		if str(r, "event") == "redeem" && l88RecUser(r) == user {
			out = append(out, str(r, "verdict")+" "+str(r, "reason"))
		}
	}
	return out
}

// l87A: authentication answered ERROR (the lab fault switch, store_unavailable). The break-glass
// account's outcome and time, then a port49 user's token login; a control with the switch off and
// the same credential shows the credential was good, so the refusal was the fault.
func (e *l88Env) l87A(f l87Faults) {
	f.set(e.t, "store_unavailable")
	off := e.l.mark()
	t0 := time.Now()
	outs, err := e.l.loginWithin(breakglassUser, breakglassPassword, 60*time.Second, "show version")
	bgTook := time.Since(t0)
	bgRecs := e.l.waitForRecords(off, 10*time.Second, func(rs []map[string]any) bool { return len(reasonsOf(rs, "redeem")) > 0 })
	bgReasons := l87Redeems(bgRecs, breakglassUser)

	user, secret := e.l.nextLogin(e.t)
	e.n.addSecret(secret)
	_, terr, trecs, ttook := e.l87Login(user, secret, "show version")
	tokenReasons := l87Redeems(trecs, user)

	f.set(e.t, "")
	_, cerr, crecs, _ := e.l87Login(user, secret, "show version")
	control := redeemFor(crecs, user)

	obs := fmt.Sprintf("authentication answered ERROR (fault switch store_unavailable) by the first server; the second server in the device's list (172.100.100.2) is an address where nothing listens, so an ERROR from two real port49d is not measured. Break-glass login (logged in and ran a command): %s in %s, `show version` output %s; port49 records for it: redeem %v. "+
		"A port49 user's token login: %s after %s; port49 records: redeem %v. Control, switch off, the same credential: %s, redeemed %v",
		l88Err(err), bgTook.Round(10*time.Millisecond), firstOut(outs), bgReasons,
		l88Err(terr), ttook.Round(10*time.Millisecond), tokenReasons, l88Err(cerr), control != nil && str(control, "verdict") == "permit")
	switch {
	case !strings.Contains(strings.Join(bgReasons, " "), "store_unavailable"):
		e.n.cell("a", "INVALID", e.n.redact(obs+": port49 logged no store_unavailable answer for the break-glass login, so the ERROR was not served"), "")
		e.t.Errorf("cell a: no store_unavailable record for the break-glass login")
	case control == nil || cerr != nil:
		e.n.cell("a", "INVALID", e.n.redact(obs+": the control login failed, so the token refusal says nothing"), "")
		e.t.Errorf("cell a: the control token login failed")
	default:
		e.n.cell("a", "OBSERVED", e.n.redact(obs), "")
	}
}

var l87Gauge = regexp.MustCompile(`(?m)^port49_store_health_failures\s+([0-9.eE+-]+)`)

// l87Failures is port49d's port49_store_health_failures gauge, or -1.
func l87Failures() float64 {
	resp, err := (&http.Client{Timeout: 2 * time.Second}).Get("http://" + metricsAddr + "/metrics")
	if err != nil {
		return -1
	}
	defer resp.Body.Close()
	buf := make([]byte, 1<<20)
	n, _ := resp.Body.Read(buf)
	m := l87Gauge.FindSubmatch(buf[:n])
	if m == nil {
		return -1
	}
	v, _ := strconv.ParseFloat(string(m[1]), 64)
	return v
}

// l87B: port49d on a real etcd, the etcd paused (SIGSTOP) until port49d has closed its listeners;
// then break-glass. PASS iff it logs in.
func (e *l88Env) l87B() {
	e.t.Run("etcd", func(t *testing.T) {
		x := *e
		x.t = t
		re := newRealEtcd(t, os.Getenv("PORT49_LAB_ETCD_BIN"))
		re.start(t, re.data)
		daemonStore := fmt.Sprintf("\nstores:\n  directory:\n    backend: etcd\n    etcd:\n      endpoints: [https://%s]\n      ca_file: %s\n"+
			"      daemon: {cert_file: %s, key_file: %s}\n      hold_ttl: 20s\n", re.client, re.ca, re.daemC, re.daemK)
		brokerStore := fmt.Sprintf("\nstores:\n  directory:\n    backend: etcd\n    etcd:\n      endpoints: [https://%s]\n      ca_file: %s\n"+
			"      broker: {cert_file: %s, key_file: %s}\n      hold_ttl: 20s\n", re.client, re.ca, re.brokC, re.brokK)
		s := x.l.prepareSplit(t, splitCfg{Store: &splitStore{Daemon: daemonStore, Broker: brokerStore}})
		re.storeRoles(t, s.CfgA, s.CfgBroker)
		s.start(t)

		paused := false
		resume := func() {
			if paused && re.cmd != nil && re.cmd.Process != nil {
				_ = re.cmd.Process.Signal(syscall.SIGCONT)
			}
			paused = false
		}
		t.Cleanup(resume) // runs before newRealEtcd's stop: a stopped process would not see its SIGTERM

		off := x.l.errLogSize()
		pid := re.cmd.Process.Pid
		x.must("pausing etcd", re.cmd.Process.Signal(syscall.SIGSTOP))
		paused = true
		pausedAt := time.Now()
		deadline := pausedAt.Add(90 * time.Second)
		for len(x.l.errLinesSince(off, darkCloseText)) == 0 && time.Now().Before(deadline) {
			time.Sleep(500 * time.Millisecond)
		}
		wentDark := len(x.l.errLinesSince(off, darkCloseText)) > 0
		darkAfter := time.Since(pausedAt)
		gauge := l87Failures()

		recMark := x.l.mark()
		t0 := time.Now()
		outs, err := x.l.loginWithin(breakglassUser, breakglassPassword, 60*time.Second, "show version")
		took := time.Since(t0)
		recs := x.l.recordsSince(recMark)
		resume()
		obs := x.n.redact(fmt.Sprintf("port49d on etcd %s (pid %d, paused with SIGSTOP); port49d closed its listeners (its log) %v after %s; the store health failures gauge (port49_store_health_failures) was %v; "+
			"break-glass login (logged in and ran a command) %s in %s, `show version` output %s; port49d records: redeem %v",
			"v3.6.15", pid, wentDark, darkAfter.Round(100*time.Millisecond), gauge, l88Err(err), took.Round(10*time.Millisecond), firstOut(outs), l87Redeems(recs, breakglassUser)))

		// Back to a healthy store, as L88 c and d do.
		time.Sleep(15 * time.Second)
		if len(x.l.errLinesSince(off, darkCloseText)) > 0 {
			x.must("port49d listening again", x.l.listenAgain(off, 150*time.Second))
		}
		x.must("port49d healthy", func() error {
			if !daemonHealthy() {
				return fmt.Errorf("port49d is not healthy after the store returned")
			}
			return nil
		}())
		if wentDark && err == nil && strings.TrimSpace(firstOut(outs)) != "" && firstOut(outs) != "nothing" {
			x.n.cell("b", "PASS", obs, "")
			return
		}
		x.n.cell("b", "FAIL", obs, "")
		t.Errorf("cell b FAIL: %s", x.n.mask(obs))
	})
}

// l87C: an ERROR to the session authorization of a login port49 authenticated (the fault switch,
// session_error). Whether the login completes and the roles the device gives it, from the session
// table, beside a control with the switch off.
func (e *l88Env) l87C(f l87Faults) {
	const table = "show system aaa authentication session"
	run := func(fault string) (user string, outs []string, err error, recs []map[string]any) {
		f.set(e.t, fault)
		user, secret := e.l.nextLogin(e.t)
		e.n.addSecret(secret)
		outs, err, recs, _ = e.l87Login(user, secret, "show version", table)
		return
	}
	cu, couts, cerr, crecs := run("")
	u, outs, err, recs := run("session_error")
	f.set(e.t, "")
	roles := func(user string, outs []string, err error) string {
		if len(outs) < 2 {
			return "(no session table: " + l88Err(err) + ")"
		}
		return l76SessionRoles(outs[1], user)
	}
	authz := func(recs []map[string]any) string {
		var parts []string
		for _, r := range recs {
			if str(r, "event") == "authorize_session" {
				parts = append(parts, str(r, "verdict")+" "+str(r, "reason"))
			}
		}
		return fmt.Sprintf("%v", parts)
	}
	obs := fmt.Sprintf("session authorization answered ERROR (fault switch session_error) after a PASS authentication. Login: %s, `show version` output %s; "+
		"port49 records: redeem %v, authorize_session %s; roles in the session table: %s. Control, switch off: %s, redeem %v, authorize_session %s, roles %s",
		l88Err(err), firstOut(outs), reasonsOf(recs, "redeem"), authz(recs), roles(u, outs, err),
		l88Err(cerr), reasonsOf(crecs, "redeem"), authz(crecs), roles(cu, couts, cerr))
	if redeemFor(recs, u) == nil || !strings.Contains(authz(recs), "store_unavailable") {
		e.n.cell("c", "INVALID", e.n.redact(obs+": port49 did not log the authentication and the ERROR, so the ERROR was not served"), "")
		e.t.Errorf("cell c: no authorize_session store_unavailable record")
		return
	}
	e.n.cell("c", "OBSERVED", e.n.redact(obs), summarize(recs))
}
