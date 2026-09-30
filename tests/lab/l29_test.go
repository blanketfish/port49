//go:build lab

package lab

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/testpki"
	"github.com/rhwendt/port49/tests/lab/labcreds"
	"github.com/rhwendt/port49/tests/lab/labpcap"
)

const l29ReloadClaim = "What a device does when port49d resets an open connection at its first packet after a " +
	"reload removed, renamed, re-platformed, refused or re-keyed its device, each reload but the re-key a sync " +
	"through the inventory service: the command in flight, the next token login and break-glass (spec §15 L29)."

// l29PremiseBanner opens a note written from a run that failed a premise check: a
// note that measured nothing must never read as L29's answer.
const l29PremiseBanner = "**THIS RUN FAILED ITS PREMISE CHECKS: NOT A MEASUREMENT.** It is re-run, never read as an " +
	"answer (plan 6b Task 19). Failed checks:\n\n"

// l29Reading is what each phase's records and capture can and cannot tell
// apart, said once in every note.
const l29Reading = "**Reading the records and the captures.** port49d writes one record for a packet on a " +
	"connection it admitted before the change and no longer admits: `event=unvalidated reason=device_unknown`, " +
	"naming the device the connection was admitted as, then resets that connection (`admission_withdrawn` for a " +
	"rename, re-key or re-platform; `unadmitted_source` for a removal; `admission_refused` for a refusal). A " +
	"packet opening a new connection is recorded without `reason=device_unknown`: `unadmitted_source` with no " +
	"device, `admission_refused` naming it, or `no_known_key_matches` for a key it does not hold; a source inside " +
	"the backoff a key miss earned is reset at Accept with no record at all. So the records say whether port49d " +
	"reset a connection that was open across the change; they cannot say which of the device's connections " +
	"carried the command in flight (an unvalidated record carries the source address, not its port), nor what " +
	"the device did with the reset. The first comes from the capture: the per-connection table below reads each " +
	"connection's 4-tuple, whether the device sent on it before the change, and when port49d reset it. The " +
	"second comes from the device's own output in the open session.\n\n"

// l29Phase is one change to the device under test. change makes it and
// returns what it did, for the note, and the port49d line it must produce
// before the next command.
type l29Phase struct {
	name   string
	change func(t *testing.T, l *lab, li *labInventory, policy string) (did, wait string)
}

// l29Phases change the device under test one way each. The source edits are
// l29Edit's and the policy edit l29Pin's, which the unit test checks on
// every node.
func l29Phases(src string) []l29Phase {
	sync := func(phase string) func(*testing.T, *lab, *labInventory, string) (string, string) {
		return func(t *testing.T, l *lab, li *labInventory, _ string) (string, string) {
			body, err := l29Edit(src, l.p.node, phase)
			if err != nil {
				t.Fatal(err)
			}
			li.writeSource(t, body)
			return "`port49 inventory sync`:\n\n```\n" + li.sync(t) + "```", "port49d: inventory reloaded (inventory service, bundle"
		}
	}
	return []l29Phase{
		{"removed", sync("removed")},
		{"renamed", sync("renamed")},
		{"replatformed", sync("replatformed")},
		{"refused", sync("refused")},
		{"rekeyed", func(t *testing.T, l *lab, _ *labInventory, policy string) (string, string) {
			raw, err := os.ReadFile(policy)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(policy, []byte(l29Pin(string(raw), l.p.node)), 0o600); err != nil {
				t.Fatal(err)
			}
			did := "port49d's broker.policy_file given `- {match: {name: " + l.p.node + "}, key_ref: lab_key2}` " +
				"(a reviewed pin onto the rotation key, which the device does not hold); the service's copy unchanged"
			return did, "port49d: policy reloaded"
		}},
	}
}

// TestL29Reload holds a token session open on the device while one change
// takes its admission away, then times the command in flight, a second
// command, the next token login and break-glass. Each phase restarts port49d
// on a fresh service config from the source and policy as committed, so each
// starts from the device admitted as it is in the lab inventory.
//
// The premise is asserted, never only recorded: a phase that did not show
// the session admitted before the change, whose change port49d did not
// apply, whose command neither returned nor ended the session, or after
// whose change no packet from the device reached port49d, fails the run, and
// the note opens with a banner saying it is not a measurement.
func TestL29Reload(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		if _, ok := l29Refusals[l.p.name]; !ok {
			t.Fatalf("no measured refusal text for %s in l29Refusals; a refusal could not be told from output", l.p.name)
		}
		pr := l29Heartbeat(t)
		defer pr.end()
		var failed []string
		fail := func(format string, args ...any) {
			msg := fmt.Sprintf(format, args...)
			failed = append(failed, msg)
			t.Error(msg)
		}
		src := labSourceFrom(t)
		policy := filepath.Join(privateDir(t, "l29-"+l.p.name), "policy.yaml")
		var obs strings.Builder
		fmt.Fprintf(&obs, "%s\n\n", l29Built())
		pr.at(t, "the stopped control")
		l29Budget(t, 10*time.Minute)
		fmt.Fprintf(&obs, "**Control, port49d stopped** (L28's `stopped` phase):\n\n%s", l.l28Phase(t, "stopped", "", ""))
		pr.at(t, "single-connection")
		fmt.Fprintf(&obs, "Single-connection: %s.\n\n", l.singleConnection(t))
		pr.at(t, "the device clock")
		fmt.Fprintf(&obs, "%s\n\n", l.deviceClock(t))
		li := l.startInventory(t, src, filepath.Join(root, "tests", "lab", "l29", "policy.yaml"))
		l29RestoreStanding(t, l)
		obs.WriteString(l29Reading)
		obs.WriteString("Each phase has a capture of its own, named in its section; the header's is the last phase's.\n\n")
		for _, ph := range l29Phases(src) {
			obs.WriteString(l.l29ReloadPhase(t, li, src, policy, ph, pr, fail))
		}
		pr.end()
		l.l29Note(t, "L29-reload", l29ReloadClaim, obs.String(), failed)
	})
}

// l29ReloadPhase runs one phase and returns its section of the note.
func (l *lab) l29ReloadPhase(t *testing.T, li *labInventory, src, policy string, ph l29Phase, pr *l29Progress,
	fail func(string, ...any)) string {
	t.Helper()
	var b strings.Builder
	fmt.Fprintf(&b, "### Phase: %s\n\n", ph.name)
	pr.at(t, "phase %s: restoring the source and the policy", ph.name)
	l29Budget(t, 20*time.Minute)
	raw, err := os.ReadFile(filepath.Join(root, "tests", "lab", "l29", "policy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policy, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	li.writeSource(t, src)
	if out := li.sync(t); !strings.Contains(out, "published bundle") && !strings.HasPrefix(out, "unchanged:") {
		fail("%s: the sync restoring the lab source neither published it nor found it current: %s", ph.name, oneLine(out))
		return b.String() + "Not measured: the lab source could not be restored.\n\n"
	}
	stop := l.capture(t, "L29-reload-"+ph.name)
	defer stop()
	pr.at(t, "phase %s: port49d restarted on the service config, probing until the device asks it", ph.name)
	live := l.l28Live(t, l.serviceConfig(t, li, policy))
	fmt.Fprintf(&b, "%s\n\n", live)
	if strings.Contains(live, "no probe login reached") {
		fail("%s: no probe login reached port49d before the change", ph.name)
		return b.String()
	}
	pr.at(t, "phase %s: the token session", ph.name)
	off := l.mark()
	user, secret := l.nextLogin(t)
	sh, err := l.shell(user, secret)
	if err != nil {
		fail("%s: the token session as %s did not open: %s", ph.name, user, oneLine(err.Error()))
		return b.String()
	}
	defer sh.Close()
	out, took, ended, err := sh.runOrEnd("show version", 30*time.Second)
	if err != nil || ended || l29Refused(l.p.name, out) {
		fail("%s: `show version` before the change did not run (ended %v, %v): %q", ph.name, ended, err, firstLine(out))
		return b.String()
	}
	before := took.Round(10 * time.Millisecond)
	recs := l.waitForRecords(off, 15*time.Second, func(rs []map[string]any) bool { return l29Redeemed(rs, user) })
	if !l29Redeemed(recs, user) {
		fail("%s: no token_redeemed record for %s: the session was not shown to be admitted by port49d", ph.name, user)
	}

	pr.at(t, "phase %s: the change", ph.name)
	changeAt := time.Now()
	offChange, errOff := l.mark(), l.errMark()
	did, wait := ph.change(t, l, li, policy)
	fmt.Fprintf(&b, "The change: %s\n\n", did)
	appliedAt, ok := l.waitForLine(t, errOff, wait, 30*time.Second)
	if !ok {
		fail("%s: port49d did not say %q within 30s of the change: the reload under test did not happen", ph.name, wait)
		return b.String()
	}

	pr.at(t, "phase %s: the command in flight", ph.name)
	sentAt := time.Now()
	first := l29Outcome(l.p.name, sh, "show version", fail, ph.name+": the first `show version` after the change")
	second := "not run: the session had ended"
	if !sh.ended() {
		second = l29Outcome(l.p.name, sh, "show version", fail, ph.name+": the second `show version` after the change")
	}
	sh.Close()
	recs = l.drainRecords(offChange, 10*time.Second)
	fromDevice := l29FromDevice(recs, l.p.addr)
	if len(fromDevice) == 0 {
		fail("%s: no packet from the device reached port49d after the change: this phase measured nothing", ph.name)
	}

	pr.at(t, "phase %s: the next logins", ph.name)
	offNext := l.mark()
	next := l.timedLogins(t)
	nextRecs := l29FromDevice(l.drainRecords(offNext, 10*time.Second), l.p.addr)
	capLine := l.captureLine(t)
	conns := l29Connections(l.capAbs, l.p.addr, changeAt)
	stop()
	fmt.Fprintf(&b, "Times are the host's, UTC: the change began %s; port49d said `%s` by %s; the command in flight "+
		"was sent at %s.\n\n", l29Clock(changeAt), wait, l29Clock(appliedAt), l29Clock(sentAt))
	fmt.Fprintf(&b, "| step | outcome |\n|---|---|\n| token session (`%s`), `show version` before the change | ran in %s |\n"+
		"| first `show version` after the change, same session | %s |\n| second `show version`, same session | %s |\n%s\n",
		user, before, first, second, next)
	fmt.Fprintf(&b, "Records from the device since the change, before the next logins: %s\n\n"+
		"Records from the device during the next logins: %s\n\n", l29Tally(fromDevice), l29Tally(nextRecs))
	fmt.Fprintf(&b, "Connections between the device and port 49 in this phase's capture:\n\n%s\nCapture: %s\n\n", conns, capLine)
	return b.String()
}

const quarantineSyncClaim = "Spec §14: a sync introducing a device whose platform fails joint validation " +
	"publishes the bundle with that device quarantined, the rest of the sync applies, a connection from the " +
	"device is closed without a reply and logged device_quarantined, the device falls to its local method, and " +
	"the next sync after the named fix admits it."

// TestQuarantineThroughASync introduces the device under test through a sync
// whose policy quarantines it, beside a change to a dummy device, and then
// makes the named fix and syncs again. Premise failures (the service or
// port49d did not do the step) and claim failures (the step happened and
// the claim did not hold) both fail the run, and are said apart in the note.
func TestQuarantineThroughASync(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
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
		inv := labInventoryText(t)
		node, platform := l.p.node, labPlatformOf(inv, l.p.node)
		introduce, err := quarantineSource(inv, node)
		if err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(root, "tests", "lab", "quarantine-sync")
		policy := filepath.Join(privateDir(t, "quarantine-sync-"+l.p.name), "policy.yaml")
		raw, err := os.ReadFile(filepath.Join(dir, "policy.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(policy, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		var obs strings.Builder
		fmt.Fprintf(&obs, "%s\n\n", l29Built())
		l29Budget(t, 30*time.Minute)
		pr.at(t, "single-connection")
		fmt.Fprintf(&obs, "Single-connection: %s.\n\n", l.singleConnection(t))
		li := l.startInventory(t, quarantineDummies, policy)
		l29RestoreStanding(t, l)
		stop := l.capture(t, "quarantine-sync")
		defer stop()
		pr.at(t, "port49d on bundle 1, the dummies alone")
		l.l28Restart(t, l.serviceConfig(t, li, policy))

		// 1. The sync that introduces the device, and changes dummy-xe beside it.
		pr.at(t, "the sync introducing %s", node)
		errOff := l.errMark()
		li.writeSource(t, introduce)
		out := li.sync(t)
		fmt.Fprintf(&obs, "Sync introducing the device, and changing dummy-xe's `site` beside it:\n\n```\n%s```\n\n", out)
		if !strings.Contains(out, "published bundle 2") || !strings.Contains(out, "; 1 quarantined") {
			fail("the sync introducing %s did not publish bundle 2 with one device quarantined: %s", node, oneLine(out))
		}
		if !strings.Contains(out, "device "+node+" ("+platform+") is quarantined") {
			contradict("the sync's output does not name %s (%s) quarantined", node, platform)
		}
		if !strings.Contains(out, "dummy-xe") {
			contradict("the sync's output does not show dummy-xe's change: the rest of the sync was not shown to apply")
		}
		reloadAt, ok := l.waitForLine(t, errOff, "port49d: inventory reloaded (inventory service, bundle 2)", 30*time.Second)
		if !ok {
			fail("port49d did not reload bundle 2 within 30s")
		}
		quarAt, ok := l.waitForLine(t, errOff, "port49d: broker: device "+node+" ("+platform+") is quarantined", 5*time.Second)
		if !ok {
			contradict("port49d did not say %s (%s) is quarantined after bundle 2", node, platform)
		}
		fmt.Fprintf(&obs, "port49d reloaded bundle 2 by %s and named %s quarantined by %s (host UTC).\n\n",
			l29Clock(reloadAt), node, l29Clock(quarAt))

		// 2. A mint for the device, over a held broker session.
		pr.at(t, "the mint while quarantined")
		agent, stopAgent := l29Agent(t)
		defer stopAgent()
		mintQ, tokQ := l29Mint(agent, node)
		if tokQ != "" {
			contradict("the broker minted a token for %s while it is quarantined", node)
		} else if !strings.Contains(mintQ, "device_quarantined") {
			contradict("the mint for %s was refused without naming device_quarantined: %s", node, oneLine(mintQ))
		}

		// 3. A connection from the device, and break-glass.
		pr.at(t, "the logins while quarantined")
		off := l.mark()
		quarantined := l.timedLogins(t)
		recs := l.drainRecords(off, 10*time.Second)
		if !hasReason(recs, "device_quarantined") {
			contradict("no device_quarantined record from %s's connections: %s", node, oneLine(summarize(recs)))
		}
		if !strings.Contains(quarantined, "| break-glass login plus three `show version` | logged in") {
			contradict("break-glass did not log in while %s is quarantined: the device was not shown to fall to "+
				"its local method", node)
		}

		// 4. The named fix, in both policy copies, and the next sync. port49d
		// applies the inventory against its own broker.policy_file (spec §13,
		// decision 29), so the fix reaches it through that file's watch; the
		// sync republishes the service's bundle under the fixed policy.
		pr.at(t, "the named fix and the next sync")
		errOff = l.errMark()
		fixedAt := time.Now()
		fixed, err := os.ReadFile(filepath.Join(dir, "fixed.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(policy, fixed, 0o600); err != nil {
			t.Fatal(err)
		}
		li.writePolicy(t, policy)
		out = li.sync(t)
		if !strings.Contains(out, "published bundle 3") || !strings.Contains(out, "; 0 quarantined") {
			contradict("the sync after the fix did not publish bundle 3 with none quarantined: %s", oneLine(out))
		}
		polAt, ok := l.waitForLine(t, errOff, "port49d: policy reloaded", 30*time.Second)
		if !ok {
			fail("port49d did not reload its policy_file within 30s of the fix")
		}
		if _, ok := l.waitForLine(t, errOff, "0 device(s) quarantined now", time.Second); !ok {
			contradict("port49d's reload after the fix does not say 0 device(s) quarantined now")
		}
		fmt.Fprintf(&obs, "After the fix (`quarantine-sync/fixed.yaml` written at %s to port49d's policy_file and the "+
			"service's):\n\n```\n%s```\n\nport49d said `policy reloaded` by %s. port49d took the fix from its own "+
			"policy_file (spec §13, decision 29): the service's bundle 3 carries the same devices, so it changes "+
			"nothing at port49d, and the sync's part in the fix is the service's own report of 0 quarantined.\n\n",
			l29Clock(fixedAt), out, l29Clock(polAt))

		// 5. The device admitted: probed until it asks port49d, then the mint
		// and the logins.
		pr.at(t, "the logins after the fix")
		probe := l.l29Probe(t)
		if strings.Contains(probe, "no probe login reached") {
			fail("no probe login reached port49d after the fix")
		}
		off = l.mark()
		mintA, tokA := l29Mint(agent, node)
		slice := "not tried: no token was minted"
		if tokA == "" {
			contradict("no token was minted for %s after the fix: %s", node, oneLine(mintA))
		} else {
			t0 := time.Now()
			if c, err := l.dial(sliceUser, tokA, 120*time.Second); err != nil {
				slice = fmt.Sprintf("refused in %s: %s", time.Since(t0).Round(10*time.Millisecond), oneLine(err.Error()))
			} else {
				c.Close()
				slice = fmt.Sprintf("logged in in %s", time.Since(t0).Round(10*time.Millisecond))
			}
			mintA = "a token (not printed)"
		}
		admitted := l.timedLogins(t)
		after := l.drainRecords(off, 10*time.Second)
		if hasReason(after, "device_quarantined") {
			contradict("a device_quarantined record after the fix")
		}
		if !strings.Contains(admitted, "| next token login (") || !strings.Contains(admitted, " | logged in in ") {
			contradict("the token login after the fix did not log in")
		}
		capLine := l.captureLine(t)
		stop()
		fmt.Fprintf(&obs, "| step | while quarantined | after the fix |\n|---|---|---|\n"+
			"| `port49 token %s` over a held `port49 login` | %s | %s |\n"+
			"| `%s` logs in with the minted token | not tried: nothing minted | %s |\n\n",
			node, l29Cell(mintQ), mintA, sliceUser, slice)
		fmt.Fprintf(&obs, "While quarantined:\n\n| step | outcome |\n|---|---|\n%s\nRecords: %s\n\n", quarantined, l29Tally(recs))
		fmt.Fprintf(&obs, "After the fix: %s\n\n| step | outcome |\n|---|---|\n%s\nRecords: %s\n\nCapture: %s\n",
			probe, admitted, l29Tally(after), capLine)
		if len(contradicted) > 0 {
			var c strings.Builder
			c.WriteString("**The claim did not hold here.** The steps ran, and:\n\n")
			for _, m := range contradicted {
				c.WriteString("- " + m + "\n")
			}
			obs.WriteString("\n" + c.String())
		}
		pr.end()
		l.l29Note(t, "quarantine-sync", quarantineSyncClaim, obs.String(), failed)
	})
}

// l29Note writes the note and, when a premise check failed, puts the
// banner above everything in it, so the first thing a reader sees is that
// the run measured nothing.
func (l *lab) l29Note(t *testing.T, entry, claim, obs string, failed []string) {
	t.Helper()
	l.result(t, entry, claim, obs)
	if len(failed) == 0 {
		return
	}
	var b strings.Builder
	b.WriteString(l29PremiseBanner)
	for _, f := range failed {
		b.WriteString("- " + f + "\n")
	}
	b.WriteString("\n")
	path := filepath.Join(root, "tests", "lab", "results", entry+"-"+l.p.name+".md")
	note, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the failed run's banner: %v", err)
	}
	if err := os.WriteFile(path, []byte(labcreds.RedactNote(b.String())+string(note)), 0o644); err != nil {
		t.Fatalf("the failed run's banner: %v", err)
	}
}

// l29Built names the binaries' commit.
func l29Built() string {
	rev, _ := exec.Command("git", "-C", root, "rev-parse", "--short", "HEAD").Output()
	return fmt.Sprintf("port49d, port49 and port49-inventory built from `%s` (`make build`).", strings.TrimSpace(string(rev)))
}

// l29RestoreStanding puts port49d back on this platform's standing config
// when the test ends, however it ends, so a later test in the run is not
// measured against the service's inventory or a phase's policy.
func l29RestoreStanding(t *testing.T, l *lab) {
	t.Cleanup(func() {
		if err := l.stopDaemon(); err != nil {
			t.Errorf("stopping port49d after the test: %v", err)
			return
		}
		std, err := l.configPath()
		if err == nil {
			err = l.startDaemonWith(std, true)
		}
		if err != nil {
			t.Errorf("putting port49d back on the standing config: %v", err)
		}
	})
}

// l29Budget fails the test now, while its cleanups can still run, when less
// than need is left before `go test -timeout`: that panic tears nothing down.
func l29Budget(t *testing.T, need time.Duration) {
	t.Helper()
	if d, ok := t.Deadline(); ok && time.Until(d) < need {
		t.Fatalf("%s left before go test's -timeout, and the next step may take %s: stopping here so the "+
			"teardown runs; re-run with a longer -timeout", time.Until(d).Round(time.Second), need)
	}
}

// l29Progress says what the test is doing at least every 30 seconds, so the
// controller's stall watchdog sees a live log through every wait.
type l29Progress struct {
	mu    sync.Mutex
	t     *testing.T
	step  string
	since time.Time
	quit  chan struct{}
	done  chan struct{}
	once  sync.Once
}

func l29Heartbeat(t *testing.T) *l29Progress {
	p := &l29Progress{t: t, step: "starting", since: time.Now(), quit: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(p.done)
		tick := time.NewTicker(30 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-p.quit:
				return
			case <-tick.C:
				p.mu.Lock()
				p.t.Logf("l29: %s: still at %s (%s)", time.Now().UTC().Format("15:04:05Z"), p.step,
					time.Since(p.since).Round(time.Second))
				p.mu.Unlock()
			}
		}
	}()
	return p
}

func (p *l29Progress) at(t *testing.T, format string, args ...any) {
	t.Helper()
	p.mu.Lock()
	p.step, p.since = fmt.Sprintf(format, args...), time.Now()
	p.mu.Unlock()
	t.Logf("l29: %s: %s", time.Now().UTC().Format("15:04:05Z"), fmt.Sprintf(format, args...))
}

// end stops the heartbeat; safe to call twice, and called before the test
// returns, since a Logf after it would panic.
func (p *l29Progress) end() {
	p.once.Do(func() { close(p.quit); <-p.done })
}

// ended reports whether the device ended the session.
func (sh *labShell) ended() bool {
	if sh.c.done == nil {
		return false
	}
	select {
	case <-sh.c.done:
		return true
	default:
		return false
	}
}

// runOrEnd is Run that also returns, at once, when the device ends the
// session: ended is then true and err nil. err is the deadline, which a
// caller reads as "not observed".
func (sh *labShell) runOrEnd(cmd string, per time.Duration) (out string, took time.Duration, ended bool, err error) {
	from := len(sh.c.transcript())
	t0 := time.Now()
	if err := sh.c.send(cmd); err != nil && sh.ended() {
		return "", time.Since(t0), true, nil
	}
	deadline := t0.Add(per)
	for {
		s := sh.c.transcript()
		tail := s[min(from, len(s)):]
		for _, p := range sh.prompts {
			if strings.Contains(tail, p) {
				return tail, time.Since(t0), false, nil
			}
		}
		if sh.ended() {
			return tail, time.Since(t0), true, nil
		}
		if !time.Now().Before(deadline) {
			return tail, time.Since(t0), false, fmt.Errorf("neither the prompt nor the session's end within %s", per)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// l29Outcome runs cmd in sh and says what happened, for a table cell. A
// deadline with the session still open is "not observed", which fails the
// run.
func l29Outcome(platform string, sh *labShell, cmd string, fail func(string, ...any), what string) string {
	out, took, ended, err := sh.runOrEnd(cmd, 60*time.Second)
	d := took.Round(10 * time.Millisecond)
	switch {
	case err != nil:
		fail("%s: not observed: %v", what, err)
		return "**not observed in 60s**: " + l29Cell(out)
	case ended:
		return fmt.Sprintf("the device ended the session after %s; it printed %s", d, l29Cell(out))
	case l29Refused(platform, out):
		return fmt.Sprintf("refused in %s: %s", d, l29Cell(l29RefusalLine(platform, out)))
	}
	return fmt.Sprintf("printed its output in %s", d)
}

// l29RefusalLine is the line of out that carries platform's refusal text.
func l29RefusalLine(platform, out string) string {
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, l29Refusals[platform]) {
			return strings.TrimSpace(line)
		}
	}
	return firstLine(out)
}

// l29Cell is s for a table cell: one line, quoted, bounded.
func l29Cell(s string) string {
	s = oneLine(strings.ReplaceAll(s, "`", "'"))
	if s == "" {
		return "nothing"
	}
	if len(s) > 160 {
		s = s[:160] + "…"
	}
	return "`" + s + "`"
}

func l29Clock(at time.Time) string {
	if at.IsZero() {
		return "(not observed)"
	}
	return at.UTC().Format("15:04:05.000Z")
}

// l29Redeemed reports whether a token for user was redeemed.
func l29Redeemed(recs []map[string]any, user string) bool {
	for _, r := range recs {
		if str(r, "event") == "redeem" && str(r, "reason") == "token_redeemed" && str(sub(r, "session"), "username") == user {
			return true
		}
	}
	return false
}

// l29FromDevice is the records about a packet from addr: an unvalidated
// record names its source, and every other its device's address.
func l29FromDevice(recs []map[string]any, addr string) []map[string]any {
	var out []map[string]any
	for _, r := range recs {
		if str(sub(r, "unvalidated"), "source") == addr || str(sub(r, "device"), "nas") == addr {
			out = append(out, r)
		}
	}
	return out
}

// l29Tally counts records by event, reason and diagnosis, and names the
// device an unvalidated record was admitted as: the fields that tell a reset
// of an open connection from a refused first packet (l29Reading).
func l29Tally(recs []map[string]any) string {
	if len(recs) == 0 {
		return "none"
	}
	n := map[string]int{}
	for _, r := range recs {
		k := "event=" + str(r, "event")
		if v := str(r, "reason"); v != "" {
			k += " reason=" + v
		}
		if u := sub(r, "unvalidated"); u != nil {
			k += " diagnosis=" + str(u, "diagnosis")
			if name := str(sub(r, "device"), "name"); name != "" {
				k += " device=" + name
			}
			typ, _ := u["type"].(float64)
			k += " type=" + l28Types[int(typ)]
		}
		n[k]++
	}
	keys := make([]string, 0, len(n))
	for k := range n {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "`%s` ×%d; ", k, n[k])
	}
	return strings.TrimSuffix(b.String(), "; ")
}

// hasReason reports whether any record carries reason.
func hasReason(recs []map[string]any, reason string) bool {
	for _, r := range recs {
		if str(r, "reason") == reason {
			return true
		}
	}
	return false
}

// l29Probe is l28Live without the restart: probe logins until one reaches
// port49d, or 150s.
func (l *lab) l29Probe(t *testing.T) string {
	t.Helper()
	t0 := time.Now()
	for attempt := 1; ; attempt++ {
		off := l.mark()
		if c, err := l.dial(l4ProbeUser, l4ProbePassword, 30*time.Second); err == nil {
			c.Close()
		}
		recs := l.waitForRecords(off, 15*time.Second, func(rs []map[string]any) bool {
			return redeemFor(rs, l4ProbeUser) != nil
		})
		took := time.Since(t0).Round(time.Second)
		switch {
		case redeemFor(recs, l4ProbeUser) != nil:
			return fmt.Sprintf("probe attempt %d reached port49 (%s).", attempt, took)
		case time.Since(t0) > 150*time.Second:
			return fmt.Sprintf("**no probe login reached port49 in %s**.", took)
		}
		time.Sleep(5 * time.Second)
	}
}

// l29Agent runs `port49 login` against port49d's broker and returns the
// agent's socket, and a func that stops the agent.
func l29Agent(t *testing.T) (sock string, stop func()) {
	t.Helper()
	pki := filepath.Join(root, slicePKIDir)
	dir, err := os.MkdirTemp("", "p49l29")
	if err != nil {
		t.Fatal(err)
	}
	sock = filepath.Join(dir, "a", "agent.sock")
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, filepath.Join(root, "bin", "port49"), "login", "--broker", sliceBrokerURL,
		"--cert", filepath.Join(pki, testpki.LabClientCert), "--key", filepath.Join(pki, testpki.LabClientKey),
		"--broker-ca", filepath.Join(pki, testpki.LabCA), "--socket", sock).CombinedOutput()
	if err != nil {
		os.RemoveAll(dir)
		t.Fatalf("port49 login: %v\n%s", err, out)
	}
	return sock, func() { stopSliceAgent(t, string(out)); os.RemoveAll(dir) }
}

// l29Mint asks the agent for a token for device. tok is the token, or ""
// with said the tool's refusal; the token is never printed.
func l29Mint(sock, device string) (said, tok string) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, filepath.Join(root, "bin", "port49"), "token", "--socket", sock, device)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if s := strings.TrimSpace(string(out)); err == nil && len(s) == labcreds.TokenLen {
		return "", s
	}
	if err != nil {
		return fmt.Sprintf("%s (exit: %v)", strings.TrimSpace(stderr.String()), err), ""
	}
	return fmt.Sprintf("%d characters on stdout, not a token; stderr: %s", len(out), strings.TrimSpace(stderr.String())), ""
}

// l29Connections reads the capture at path for every TCP connection between
// addr and port 49: when it was first seen, whether the device sent on it
// before change, when the device first sent on it after, and when port49d
// reset it. A connection the device sent on before the change and port49d
// reset after it is one reset mid-connection; one opened after the change
// and reset at its first packet is a first-packet miss. `tcpdump -i any`
// sees a packet on each interface it crosses; each is read once here by
// taking the first sighting.
func l29Connections(path, addr string, change time.Time) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Sprintf("the capture could not be read (%v).\n", err)
	}
	f, err := labpcap.Parse(raw)
	if err != nil {
		return fmt.Sprintf("the capture could not be parsed (%v).\n", err)
	}
	nano := binary.LittleEndian.Uint32(raw[0:4]) == 0xa1b23c4d
	type conn struct {
		port                          uint16
		seen, before, after, rst, syn time.Time
		sentBefore                    bool
	}
	conns := map[uint16]*conn{}
	var order []uint16
	for _, r := range f.Records {
		fl, ok := labpcap.FlowOf(f.Link, f.Bytes(r))
		if !ok {
			continue
		}
		var port uint16
		fromDevice := fl.Src.String() == addr && fl.DstPort == 49
		switch {
		case fromDevice:
			port = fl.SrcPort
		case fl.Dst.String() == addr && fl.SrcPort == 49:
			port = fl.DstPort
		default:
			continue
		}
		sec := binary.LittleEndian.Uint32(f.Raw[r.HeaderOff : r.HeaderOff+4])
		frac := binary.LittleEndian.Uint32(f.Raw[r.HeaderOff+4 : r.HeaderOff+8])
		at := time.Unix(int64(sec), int64(frac)*1000)
		if nano {
			at = time.Unix(int64(sec), int64(frac))
		}
		c := conns[port]
		if c == nil {
			c = &conn{port: port, seen: at}
			conns[port] = c
			order = append(order, port)
		}
		switch {
		case fromDevice && fl.SYN() && c.syn.IsZero():
			c.syn = at
		case fromDevice && fl.PayloadLen > 0 && at.Before(change):
			c.sentBefore = true
		case fromDevice && fl.PayloadLen > 0 && c.after.IsZero():
			c.after = at
		case !fromDevice && fl.Flags&0x04 != 0 && c.rst.IsZero():
			c.rst = at
		}
	}
	if len(order) == 0 {
		return "none: the capture holds no packet between the device and port 49.\n"
	}
	var b strings.Builder
	b.WriteString("| device port | first seen | device sent before the change | device first sent after it | " +
		"port49d reset it | reading |\n|---|---|---|---|---|---|\n")
	for i, p := range order {
		if i == 40 {
			fmt.Fprintf(&b, "| … | %d more connection(s) not listed | | | | |\n", len(order)-40)
			break
		}
		c := conns[p]
		var reading string
		switch {
		case c.rst.IsZero():
			reading = "not reset by port49d"
		case c.rst.Before(change):
			reading = "reset before the change"
		case c.sentBefore:
			reading = "**reset mid-connection**: open across the change"
		case !c.after.IsZero() && !c.after.After(c.rst):
			reading = "reset at its first packet after the change"
		case c.after.IsZero():
			reading = "reset before the device sent on it (refused at Accept)"
		default:
			reading = "reset"
		}
		fmt.Fprintf(&b, "| %d | %s | %v | %s | %s | %s |\n", p, l29Clock(c.seen), c.sentBefore, l29Clock(c.after),
			l29Clock(c.rst), reading)
	}
	fmt.Fprintf(&b, "\nThe change began at %s (host UTC).\n", l29Clock(change))
	return b.String()
}
