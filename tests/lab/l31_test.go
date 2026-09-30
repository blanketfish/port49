//go:build lab

package lab

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/tacacs/wire"
	"github.com/rhwendt/port49/tests/lab/labpcap"
)

const l31Claim = "What break-glass costs on IOS-XE and NX-OS with single-connection on when port49d declines " +
	"the device (removed from the inventory, refused admission, or quarantined), now that the first " +
	"connection is reset at once and the source's next connections are refused at Accept for a short window: " +
	"break-glass login plus three commands, against port49d stopped and a key miss (the rekeyed control), and " +
	"whether the device's retries are refused at Accept before it writes (spec §15 L31)."

// l31Reading says once, in every note, what the records and captures can tell.
const l31Reading = "**Reading the records and the captures.** port49d records the first packet of a connection " +
	"it declines (`unadmitted_source`, `admission_refused` or `device_quarantined`; `no_known_key_matches` in the " +
	"rekeyed control) and resets it at once. A connection from the same source inside the window that close " +
	"opened is reset at Accept, before the device sends anything, and is not recorded: the capture's per-" +
	"connection table reads it as \"reset before the device sent on it (refused at Accept)\". The single-connect " +
	"count reads the flag byte of each TACACS+ header the device sent (0x04 is single-connection on), and no " +
	"body byte, on the connections the device opened after the change. The bar holds each declined phase's " +
	"break-glass to the rekeyed control's time plus 1.5 s, and never 5 s or more: no AAA exchange waited out " +
	"the device's timeout. The refusals at Accept the verdict rests on are counted inside the break-glass " +
	"session's own interval, since the token login before it retries too; a phase in which the device opened no " +
	"connection to port 49 during break-glass is not a measurement, because the device went to local without " +
	"asking. A break-glass whose commands the device answered with its refusal text did not run them. IOS-XE " +
	"retries about 100–200 ms after a reset, against a first window of 100 ms, so one or two of its first " +
	"retries may land after the window and be recorded before the doubling catches up. The control has the same " +
	"dynamics. The stopped control is measured before this test sets " +
	"single-connection, as in L29. With nothing listening, the SYN itself is refused, so the flag plays no " +
	"part there.\n\n"

// l31Phase is one way port49d stops serving the device under test, or the
// rekeyed control. diag is the diagnosis of the first recorded packet from
// the device after the change; change makes the change and returns what it
// did, for the note, and the port49d lines that say it is in force.
type l31Phase struct {
	name, diag string
	change     func(t *testing.T, l *lab, li *labInventory, policy string) (did string, wait []string)
}

// l31Result is one phase's section of the note and its break-glass time.
// timed is true once the logins ran, so bg and bgOK mean something. measured
// is true only when, beyond that, the capture was read and every premise of
// the phase held; otherwise atAccept means nothing and the phase is not a
// measurement. atAccept counts the refusals at Accept inside the break-glass
// session's interval, atAcceptPhase those since the change.
type l31Result struct {
	section, bgCell, tally  string
	bg                      time.Duration
	timed, bgOK, measured   bool
	atAccept, atAcceptPhase int
}

// l31Phases: the rekeyed control first, since the declined phases are held to
// its time; then the three declines L31 measured slow.
func l31Phases(src string) []l31Phase {
	sync := func(phase string) func(*testing.T, *lab, *labInventory, string) (string, []string) {
		return func(t *testing.T, l *lab, li *labInventory, _ string) (string, []string) {
			body, err := l29Edit(src, l.p.node, phase)
			if err != nil {
				t.Fatal(err)
			}
			li.writeSource(t, body)
			return "`port49 inventory sync`:\n\n```\n" + li.sync(t) + "```",
				[]string{"port49d: inventory reloaded (inventory service, bundle"}
		}
	}
	return []l31Phase{
		{"rekeyed", "no_known_key_matches", func(t *testing.T, l *lab, _ *labInventory, policy string) (string, []string) {
			raw, err := os.ReadFile(policy)
			if err != nil {
				t.Fatal(err)
			}
			writeAtomic(t, policy, []byte(l29Pin(string(raw), l.p.node)), 0o600)
			return "port49d's broker.policy_file given `- {match: {name: " + l.p.node + "}, key_ref: lab_key2}`, " +
				"a key the device does not hold (L29's rekeyed phase: a key miss)", []string{"port49d: policy reloaded"}
		}},
		{"removed", "unadmitted_source", sync("removed")},
		{"refused", "admission_refused", sync("refused")},
		{"quarantined", "device_quarantined", func(t *testing.T, l *lab, _ *labInventory, policy string) (string, []string) {
			raw, err := os.ReadFile(filepath.Join(root, "tests", "lab", "quarantine-sync", "policy.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			writeAtomic(t, policy, raw, 0o600)
			platform := labPlatformOf(labInventoryText(t), l.p.node)
			return "port49d's broker.policy_file replaced by `tests/lab/quarantine-sync/policy.yaml`, whose probe " +
					"grants quarantine " + l.p.node + "; the service's copy unchanged",
				[]string{"port49d: policy reloaded", "port49d: broker: device " + l.p.node + " (" + platform + ") is quarantined"}
		}},
	}
}

// l31Bar is the bar a declined phase's break-glass is held to: within 1.5 s
// of the same run's rekeyed control, and under 5 s, the device's own AAA
// timeout, so no exchange in the session waited one out.
func l31Bar(control time.Duration) time.Duration {
	return min(control+1500*time.Millisecond, 5*time.Second)
}

// TestL31BreakGlass times break-glass on the device with single-connection
// on, with port49d stopped, then under a key miss (the control), then with
// the device removed, refused and quarantined. It is run on IOS-XE and NX-OS,
// the images L31 measured slow, and on vEOS as a no-regression check.
//
// Every premise is asserted. If single-connection was not set, a change was
// not applied, the path under test recorded nothing, break-glass never asked
// port49d (no SYN from the device during it), a Cisco device's packets lacked
// the single-connect flag, the capture could not be read, or the control was
// itself slow, the run fails and its note opens with the NOT A MEASUREMENT
// banner. Such a phase, or any phase without a timed control, is written as
// not a measurement, never as a contradiction. A measured phase whose
// break-glass did not log in and run its commands (a refusal is not running
// them), or went over the bar, contradicts the fix: the run fails, and the
// note says the claim did not hold.
func TestL31BreakGlass(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		cisco := l.p.name == "cisco_iosxe" || l.p.name == "cisco_nxos"
		if !cisco && l.p.name != "arista_eos" {
			t.Skipf("L31 is IOS-XE and NX-OS, with vEOS as the no-regression check; %s is not run", l.p.name)
		}
		pr := l29Heartbeat(t)
		defer pr.end()
		var failed, contradicted []string
		fail := func(format string, args ...any) {
			msg := fmt.Sprintf(format, args...)
			failed = append(failed, msg)
			t.Error(msg)
		}
		contradict := func(format string, args ...any) {
			msg := fmt.Sprintf(format, args...)
			contradicted = append(contradicted, msg)
			t.Error(msg)
		}
		src := labSourceFrom(t)
		policy := filepath.Join(privateDir(t, "l31-"+l.p.name), "policy.yaml")
		var obs strings.Builder
		fmt.Fprintf(&obs, "%s\n\n", l29Built())
		pr.at(t, "the stopped control")
		l29Budget(t, 10*time.Minute)
		fmt.Fprintf(&obs, "**Control, port49d stopped** (L28's `stopped` phase):\n\n%s", l.l28Phase(t, "stopped", "", ""))
		pr.at(t, "single-connection")
		single := l.singleConnection(t)
		fmt.Fprintf(&obs, "Single-connection: %s.\n\n", single)
		if !l29SingleSet(single) {
			fail("single-connection was not set on the device: L31 is single-connection on, so this run measured nothing")
		}
		li := l.startInventory(t, src, filepath.Join(root, "tests", "lab", "l29", "policy.yaml"))
		l29RestoreStanding(t, l)
		obs.WriteString(l31Reading)
		summary := "| phase | break-glass login plus three `show version` | bar | connections refused at Accept " +
			"during break-glass | refused at Accept since the change | records from the device since just before " +
			"the change |\n" +
			"|---|---|---|---|---|---|\n"
		var control time.Duration
		controlOK := false
		for _, ph := range l31Phases(src) {
			r := l.l31Run(t, li, src, policy, ph, cisco, pr, fail)
			obs.WriteString(r.section)
			bar := "(the control)"
			switch {
			case ph.name == "rekeyed":
				switch {
				case r.timed && (!r.bgOK || r.bg >= 5*time.Second):
					fail("the rekeyed control's break-glass did not log in and run its commands under 5 s (%s): there "+
						"is no fast path in this run to hold the declined phases to", r.bgCell)
				case r.measured:
					control, controlOK = r.bg, true
				}
			case !r.measured:
				bar = "not a measurement"
			case !controlOK:
				bar = "no control"
			case !r.bgOK:
				contradict("%s: break-glass did not log in and run its commands (%s)", ph.name, r.bgCell)
			default:
				b := l31Bar(control)
				bar = b.Round(10 * time.Millisecond).String()
				if r.bg > b || r.bg >= 5*time.Second {
					contradict("%s: break-glass took %s, over the bar of %s (the rekeyed control's %s plus 1.5 s, "+
						"under 5 s)", ph.name, r.bg.Round(10*time.Millisecond), bar, control.Round(10*time.Millisecond))
				}
			}
			// The mechanism, not only the time: L31 asks whether the device's
			// retries are refused at Accept before it writes. Without one, a
			// fast phase would pass for some other reason nobody observed.
			if cisco && r.measured && r.atAccept == 0 {
				if ph.name == "rekeyed" {
					fail("rekeyed: no connection from the device was refused at Accept during break-glass: the " +
						"control's fast path did not run")
				} else {
					contradict("%s: no connection from the device was refused at Accept during break-glass (spec §15 L31)",
						ph.name)
				}
			}
			summary += fmt.Sprintf("| %s | %s | %s | %d | %d | %s |\n", ph.name, r.bgCell, bar, r.atAccept,
				r.atAcceptPhase, r.tally)
		}
		obs.WriteString("### Summary\n\n" + summary + "\n")
		switch {
		case len(contradicted) > 0 && len(failed) > 0:
			obs.WriteString("**Not a measurement, so these are not findings against the claim.** The steps also " +
				"showed:\n\n")
		case len(contradicted) > 0:
			obs.WriteString("**The claim did not hold here.** The steps ran, and:\n\n")
		}
		if len(contradicted) > 0 {
			for _, m := range contradicted {
				obs.WriteString("- " + m + "\n")
			}
		}
		pr.end()
		l.l29Note(t, "L31", l31Claim, obs.String(), failed)
	})
}

// l31Run runs one phase from the lab source and policy as committed, on a
// freshly started port49d, and returns its section of the note.
func (l *lab) l31Run(t *testing.T, li *labInventory, src, policy string, ph l31Phase, cisco bool,
	pr *l29Progress, fail func(string, ...any)) l31Result {
	t.Helper()
	r := l31Result{bgCell: "not measured", tally: "none"}
	var b strings.Builder
	fmt.Fprintf(&b, "### Phase: %s\n\n", ph.name)
	pr.at(t, "phase %s: restoring the source and the policy", ph.name)
	l29Budget(t, 15*time.Minute)
	raw, err := os.ReadFile(filepath.Join(root, "tests", "lab", "l29", "policy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	writeAtomic(t, policy, raw, 0o600)
	li.writeSource(t, src)
	if out := li.sync(t); !strings.Contains(out, "published bundle") && !strings.HasPrefix(out, "unchanged:") {
		fail("%s: the sync restoring the lab source neither published it nor found it current: %s", ph.name, oneLine(out))
		r.section = b.String() + "Not measured: the lab source could not be restored.\n\n"
		return r
	}
	stop := l.capture(t, "L31-"+ph.name)
	defer stop()
	pr.at(t, "phase %s: port49d restarted on the service config, probing until the device asks it", ph.name)
	live := l.l28Live(t, l.serviceConfig(t, li, policy))
	fmt.Fprintf(&b, "%s\n\n", live)
	if !l28Reached(live) {
		fail("%s: no probe login reached port49d before the change", ph.name)
		r.section = b.String()
		return r
	}

	pr.at(t, "phase %s: the change", ph.name)
	off, errOff := l.mark(), l.errMark()
	did, waits := ph.change(t, l, li, policy)
	fmt.Fprintf(&b, "The change: %s\n\n", did)
	var applied time.Time
	for _, w := range waits {
		at, ok := l.waitForLine(t, errOff, w, 30*time.Second)
		if !ok {
			fail("%s: port49d did not say %q within 30s of the change: the change under test did not happen", ph.name, w)
			r.section = b.String()
			return r
		}
		applied = at
	}

	pr.at(t, "phase %s: the logins", ph.name)
	rows, bgFrom, bg, bgOK := l.timeLogins(t)
	bgUntil := bgFrom.Add(bg)
	r.timed, r.bg, r.bgOK = true, bg, bgOK
	r.bgCell = "did not log in and run them, in " + bg.Round(10*time.Millisecond).String() + " (the phase's table says why)"
	if bgOK {
		r.bgCell = "logged in and ran them in " + bg.Round(10*time.Millisecond).String()
	}
	premised := true
	failp := func(format string, args ...any) {
		premised = false
		fail(format, args...)
	}
	recs := l29FromDevice(l.drainRecords(off, 10*time.Second), l.p.addr)
	r.tally = l29Tally(recs)
	if !l31Recorded(recs, ph.diag) {
		failp("%s: no record from the device with diagnosis %s after the change: the path under test did not run",
			ph.name, ph.diag)
	}

	// stop() flushes the capture and ends tcpdump. Only then is the file read
	// and its count quoted, so no count comes from a half-written tail and
	// nothing that arrived after a flush is left out.
	stop()
	capLine := l.stoppedCaptureLine(t)
	conns, _, _ := l29Connections(l.capAbs, l.p.addr, applied)
	asked, errAsked := l31Opened(l.capAbs, l.p.addr, bgFrom, bgUntil)
	atAccept, errWindow := l31RefusedAtAccept(l.capAbs, l.p.addr, bgFrom, bgUntil)
	atPhase, errPhase := l31RefusedAtAccept(l.capAbs, l.p.addr, applied, time.Time{})
	set, unset, errFlag := l31SingleConnect(l.capAbs, l.p.addr, applied)
	r.atAccept, r.atAcceptPhase = atAccept, atPhase
	switch err := errors.Join(errAsked, errWindow, errPhase, errFlag); {
	case err != nil:
		failp("%s: the capture could not be read: %v", ph.name, err)
	case asked == 0:
		failp("%s: break-glass never asked port49d: the device opened no connection to port 49 between %s and %s "+
			"(host UTC), so it went to local without trying, and this phase measured nothing", ph.name,
			l29Clock(bgFrom), l29Clock(bgUntil))
	case cisco && set == 0:
		failp("%s: no TACACS+ packet the device sent after the change carried the single-connect flag (0x04; %d "+
			"without it): this phase did not measure L31's variable", ph.name, unset)
	}
	r.measured = premised
	fmt.Fprintf(&b, "port49d said the change was in force by %s (host UTC).\n\n| step | outcome |\n|---|---|\n%s\n",
		l29Clock(applied), rows)
	fmt.Fprintf(&b, "Break-glass ran from %s to %s (host UTC); the device opened %d connection(s) to port 49 in that "+
		"interval, and port49d refused %d of them at Accept (%d since the change).\n\n", l29Clock(bgFrom),
		l29Clock(bgUntil), asked, atAccept, atPhase)
	fmt.Fprintf(&b, "TACACS+ headers the device sent after the change: single-connect flag (0x04) set on %d, clear on "+
		"%d.\n\nRecords from the device since just before the change: %s\n\nConnections between the device and "+
		"port 49 in this "+
		"phase's capture:\n\n%s\nCapture: %s\n\n", set, unset, r.tally, conns, capLine)
	r.section = b.String()
	return r
}

// l31Recorded reports whether any record carries an unvalidated diagnosis diag.
func l31Recorded(recs []map[string]any, diag string) bool {
	for _, r := range recs {
		if str(sub(r, "unvalidated"), "diagnosis") == diag {
			return true
		}
	}
	return false
}

// l31Within reports whether at falls in [since, until]; a zero until is no
// upper bound.
func l31Within(at, since, until time.Time) bool {
	return !at.Before(since) && (until.IsZero() || !at.After(until))
}

// l31Opened counts the connections from addr to port 49 whose SYN falls in
// [since, until]: whether the device asked port49d at all in that interval.
// A connection is known by the device's port, and `tcpdump -i any`'s copies
// of one SYN count once.
func l31Opened(path, addr string, since, until time.Time) (int, error) {
	pkts, err := l29Packets(path, addr)
	if err != nil {
		return 0, err
	}
	opened := map[uint16]bool{}
	for _, p := range pkts {
		if p.fromDevice && p.fl.SYN() && l31Within(p.at, since, until) {
			opened[p.port] = true
		}
	}
	return len(opened), nil
}

// l31RefusedAtAccept counts the connections from addr to port 49 opened in
// [since, until] (a zero until is no upper bound) that port49d reset before
// the device sent anything on them, which is what a refusal at Accept looks
// like. Only what the device sent and port49d reset at or after since is
// read, so an earlier connection on a reused port does not mask one. It
// reads TCP flags and payload lengths only. `tcpdump -i any` sees each packet
// more than once, which the per-port flags absorb.
func l31RefusedAtAccept(path, addr string, since, until time.Time) (int, error) {
	pkts, err := l29Packets(path, addr)
	if err != nil {
		return 0, err
	}
	type conn struct{ syn, sent, rst bool }
	conns := map[uint16]*conn{}
	for _, p := range pkts {
		if p.at.Before(since) {
			continue
		}
		c := conns[p.port]
		if c == nil {
			c = &conn{}
			conns[p.port] = c
		}
		switch {
		case p.fromDevice && p.fl.SYN():
			c.syn = c.syn || l31Within(p.at, since, until)
		case p.fromDevice && p.fl.PayloadLen > 0:
			c.sent = true
		case !p.fromDevice && p.fl.Flags&0x04 != 0:
			c.rst = true
		}
	}
	n := 0
	for _, c := range conns {
		if c.syn && c.rst && !c.sent {
			n++
		}
	}
	return n, nil
}

// l31SingleConnect counts the TACACS+ packets the device sent in the capture
// at path, on connections it opened at or after since, by whether the
// header's single-connect flag (0x04) is set. That flag is the device-side
// variable L31 turns on. Only the 12-byte cleartext header is used: the
// decode is given no key, so no body is readable, and nothing from a body is
// kept or printed. A connection is known by the device's port, as in
// l31RefusedAtAccept.
func l31SingleConnect(path, addr string, since time.Time) (set, unset int, err error) {
	pkts, err := l29Packets(path, addr)
	if err != nil {
		return 0, 0, err
	}
	opened := map[uint16]bool{}
	for _, p := range pkts {
		if p.fromDevice && p.fl.SYN() && !p.at.Before(since) {
			opened[p.port] = true
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, err
	}
	f, err := labpcap.Parse(raw)
	if err != nil {
		return 0, 0, fmt.Errorf("%s: %w", path, err)
	}
	_, subnet, err := net.ParseCIDR(labSubnet)
	if err != nil {
		return 0, 0, err
	}
	d, err := f.Decode("", subnet)
	if err != nil {
		return 0, 0, err
	}
	for _, p := range d.Packets {
		if !p.FromDevice || !strings.HasPrefix(p.Conn, addr+":") || !opened[p.SrcPort] {
			continue
		}
		if p.Header.Flags&wire.FlagSingleConnect != 0 {
			set++
		} else {
			unset++
		}
	}
	return set, unset, nil
}
