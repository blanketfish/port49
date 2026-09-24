//go:build lab

package lab

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	adapter "github.com/rhwendt/port49/internal/platform"
)

// TestAdapterReplies is the differential test of the per-command adapters
// (plan 5a, Task 17; spec §8, "Differential testing is required"): for each
// reserved level, the exact reply the built-in adapter renders is delivered,
// and what the device does with it is measured against what the adapter says
// it will do — the privilege or role the device reports, and which of the
// ceiling commands it sends port49 at all (tests/lab/results/ceiling-*.md).
// Then each candidate inert attribute beside admin's reply: whether the
// session still opens, the privilege is unchanged, the same ceiling commands
// reach port49 and a `show version` is still authorized — L18 saw the C8000V
// open a session and then refuse every command in it — which is what listing
// it inert would claim (spec §6). On NX-OS the bare `show interface` is
// recorded too: production has seen network-operator prompted for sudo there
// (roadmap, plan 5), and readonly gets that role.
//
// Last, the fallback decision 25 rests on: operator's reply, one interactive
// session, port49d stopped under it, and a configuration change typed — the
// device's method list falls back to local, and the role it delivered at
// login is the policy. admin's reply is the control: a refusal that happens
// to every session says nothing about the role.
//
// The lab authorizer delivers the reply (`lab.session_attributes`), so every
// variant is one daemon restart and one seeded login; the rendering itself is
// the adapter's, read from the binary under test, so the note measures what
// ships. The level and inert variants send each command on its own SSH exec
// channel, as the harness's login does; the fallback holds one pty session,
// because port49d stops in the middle of it. The note is L22's (spec §15).

// adapterProbe is one level's expectation: the identity line the device must
// print, and whether each ceiling command reaches port49.
type adapterProbe struct {
	identity                 string
	clearReached, cfgReached bool
}

var adapterExpect = map[string]map[string]adapterProbe{
	// ceiling-arista_eos.md: level 1 refuses both in the parser; 15 sends both.
	"arista_eos": {
		"readonly": {"Current privilege level is 1", false, false},
		"operator": {"Current privilege level is 15", true, true},
		"admin":    {"Current privilege level is 15", true, true},
	},
	// ceiling-cisco_nxos.md: every role sends both; the role is what differs.
	"cisco_nxos": {
		"readonly": {"roles:network-operator", true, true},
		"operator": {"roles:network-operator", true, true},
		"admin":    {"roles:network-admin", true, true},
	},
	// ceiling-cisco_iosxe.md, with tests/lab/configs/iosxe-startup.cfg's
	// `privilege exec level 7 clear counters`.
	"cisco_iosxe": {
		"readonly": {"Current privilege level is 1", false, false},
		"operator": {"Current privilege level is 7", true, false},
		"admin":    {"Current privilege level is 15", true, true},
	},
}

// inertCandidates are the attributes Task 18 lists inert where this run finds
// the session unchanged — opened, admin's identity and reach, and a permitted
// `show version` — spec §6's own case and two Cisco shell attributes an
// operator is likeliest to add under `all`.
var inertCandidates = []string{"home-directory*/home/port49", "idletime*30", "timeout*480"}

func TestAdapterReplies(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		expect, ok := adapterExpect[l.p.name]
		if !ok {
			t.Skipf("%s renders no level until plan 5b's projection", l.p.name)
		}
		d, _ := adapter.DialectFor(l.p.name)
		stop := l.capture(t, "L22")
		defer stop()
		defer func() {
			std, err := l.configPath()
			if err == nil {
				err = l.restart(std)
			}
			if err != nil {
				t.Fatalf("could not put port49d back on the lab config: %v", err)
			}
		}()
		var obs strings.Builder
		fmt.Fprintf(&obs, "| level | reply | session | identity | `clear counters` | `configure terminal` | bare `show interface` |\n"+
			"|---|---|---|---|---|---|---|\n")
		for _, level := range []string{"readonly", "operator", "admin"} {
			attrs, _ := d.Render(level)
			row := l.adapterVariant(t, level, attrs)
			fmt.Fprintf(&obs, "| %s | `%s` | %s | %s | %s | %s | %s |\n", level, strings.Join(attrs, "`, `"), row.session,
				row.identity, reached(row.clear), reached(row.cfg), row.showIf)
			want := expect[level]
			switch {
			case row.err != nil:
				t.Errorf("%s: the adapter's reply %q did not open a session: %v", level, attrs, row.err)
			case !strings.Contains(row.identity, want.identity):
				t.Errorf("%s: the device reports %q, the adapter promises %q", level, row.identity, want.identity)
			case row.clear != want.clearReached || row.cfg != want.cfgReached:
				t.Errorf("%s: clear counters reached port49 %v (want %v), configure terminal %v (want %v)", level,
					row.clear, want.clearReached, row.cfg, want.cfgReached)
			}
		}
		fmt.Fprintf(&obs, "\n### Inert candidates, each beside admin's reply\n\n"+
			"| attribute | session | identity | `clear counters` | `configure terminal` | `show version` | inert |\n"+
			"|---|---|---|---|---|---|---|\n")
		admin, _ := d.Render("admin")
		adminRow := l.adapterVariant(t, "admin-control", admin)
		for _, a := range inertCandidates {
			row := l.adapterVariant(t, "inert-"+strings.SplitN(a, "*", 2)[0], append(slices.Clone(admin), a))
			// Inert only where nothing about the session moved: opened, admin's
			// identity, admin's reach, and a command still authorized.
			inert := row.err == nil && row.identity == adminRow.identity && row.clear == adminRow.clear &&
				row.cfg == adminRow.cfg && row.showVersion
			fmt.Fprintf(&obs, "| `%s` | %s | %s | %s | %s | %s | %s |\n", a, row.session, row.identity,
				reached(row.clear), reached(row.cfg), permitted(row.showVersion), yesNo(inert))
			if row.err != nil && l.p.name == "cisco_iosxe" {
				// A refused session stops this image answering SSH for about a
				// minute (L18); wait it out before the next variant.
				if err := l.waitDeviceReady(3 * time.Minute); err != nil {
					t.Fatalf("after %s: %v", a, err)
				}
			}
		}
		fmt.Fprintf(&obs, "\n### Fallback: port49d stopped under an open session\n\n"+
			"| level | reply | `configure terminal`, then `hostname %s` | transcript after port49d stopped |\n"+
			"|---|---|---|---|\n", l.p.node)
		for _, level := range []string{"operator", "admin"} {
			attrs, _ := d.Render(level)
			fb := l.fallbackVariant(t, level, attrs)
			fmt.Fprintf(&obs, "| %s | `%s` | %s | `%s` |\n", level, strings.Join(attrs, "`, `"), fb.outcome(),
				strings.ReplaceAll(fb.transcript, "\n", " ⏎ "))
			switch {
			case fb.err != nil:
				t.Errorf("fallback %s: %v", level, fb.err)
			case level == "operator" && fb.changed:
				t.Errorf("fallback: an operator changed the configuration with port49 down; decision 25 says the "+
					"role it was given refuses it (L16, command authorization LOCAL):\n%s", fb.transcript)
			case level == "admin" && !fb.changed && l.p.name != "cisco_iosxe":
				// The control: network-admin configures under local
				// authorization, or the operator's refusal measured nothing.
				t.Errorf("fallback control: admin could not change the configuration either, so the operator's "+
					"refusal says nothing about its role:\n%s", fb.transcript)
			}
		}
		l.result(t, "L22", "Each built-in adapter's reply at readonly, operator and admin is applied by the "+
			"device as the adapter says — the privilege or role the device reports, and which of `clear counters` "+
			"and `configure terminal` it sends port49 at all; which candidate inert attributes leave admin's "+
			"session unchanged; and, with port49d stopped under an open session, that operator's reply cannot "+
			"change the configuration where admin's can (plan 5a, Task 17; spec §6, §8, §15 L22; decision 25).",
			obs.String())
	})
}

// adapterRow is one variant's measurement.
type adapterRow struct {
	err              error
	session          string
	identity         string
	clear, cfg       bool
	showVersion      bool // a `show version` authorize_command was permitted
	clearOut, cfgOut string
	// showIf is the first line of NX-OS's reply to a bare `show interface`,
	// "—" elsewhere.
	showIf string
}

func reached(b bool) string {
	if b {
		return "sent to port49"
	}
	return "refused by the device"
}

func permitted(b bool) string {
	if b {
		return "permitted by port49"
	}
	return "not permitted"
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// adapterVariant restarts port49d delivering attrs, logs in with a fresh
// seeded token, and runs the identity command and the two ceiling commands.
func (l *lab) adapterVariant(t *testing.T, name string, attrs []string) adapterRow {
	t.Helper()
	quoted, _ := json.Marshal(attrs)
	cfg, err := l.derivedConfig("adapter-"+name, string(quoted), "")
	if err != nil {
		t.Fatal(err)
	}
	if err := l.restart(cfg); err != nil {
		t.Fatalf("%s: port49d would not start: %v", name, err)
	}
	user, secret := l.nextLogin(t)
	identity := "show privilege"
	if l.p.name == "cisco_nxos" {
		identity = "show user-account " + user
	}
	commands := []string{identity, "clear counters", "configure terminal", "show version"}
	if l.p.name == "cisco_nxos" {
		commands = append(commands, "show interface")
	}
	off := l.mark()
	// Each command has a deadline: the first NX-OS run hung here for 76
	// minutes on an exec channel the device never ran. NX-OS takes about two
	// minutes to finish `clear counters` on an exec channel, so the deadline
	// clears that.
	outs, err := l.loginWithin(user, secret, 150*time.Second, commands...)
	recs := l.drainRecords(off, 3*time.Second)
	row := adapterRow{session: "opened", showIf: "—"}
	if err != nil && len(outs) == 0 {
		row.err = err
		row.session = "refused: " + oneLine(err.Error())
		return row
	}
	if err != nil {
		row.session = "opened, then: " + oneLine(err.Error())
	}
	if len(outs) == 5 {
		row.showIf = "`" + strings.TrimSpace(strings.Split(strings.TrimSpace(outs[4])+"\n", "\n")[0]) + "`"
	}
	if len(outs) >= 3 {
		row.identity = strings.TrimSpace(strings.Split(strings.TrimSpace(outs[0]), "\n")[0])
		if l.p.name == "cisco_nxos" {
			for _, line := range strings.Split(outs[0], "\n") {
				if strings.Contains(line, "roles:") {
					row.identity = strings.TrimSpace(line)
				}
			}
		}
		row.clearOut, row.cfgOut = outs[1], outs[2]
	}
	for _, r := range recs {
		if str(r, "event") != "authorize_command" {
			continue
		}
		v := strs(sub(r, "request"), "vector")
		switch {
		case len(v) >= 2 && v[0] == "clear" && v[1] == "counters":
			row.clear = true
		case len(v) >= 2 && v[0] == "configure" && v[1] == "terminal":
			row.cfg = true
		case len(v) >= 2 && v[0] == "show" && v[1] == "version" && str(r, "verdict") == "permit":
			row.showVersion = true
		}
	}
	return row
}

// restart runs port49d on cfg.
func (l *lab) restart(cfg string) error {
	if err := l.stopDaemon(); err != nil {
		return err
	}
	if err := l.startDaemonWith(cfg, true); err != nil {
		return err
	}
	return l.awaitTACACS()
}

// awaitTACACS waits, on IOS-XE, until the device speaks TACACS+ to the
// restarted daemon again. Once it has found port49d unreachable — the
// fallback steps stop it under an open session — the C8000V answered the
// next token logins from its local database without sending port49 a
// packet (this task's first IOS-XE pass: every login after the fallback
// failed `no supported methods remain`, with no record). The probe is the
// bring-up gate's: a break-glass login port49 denies, so it spends no token.
func (l *lab) awaitTACACS() error {
	if l.p.name != "cisco_iosxe" {
		return nil
	}
	return l.waitTACACSReady(3 * time.Minute)
}

// fallbackRow is one fallback variant: whether the configuration change
// took, and what the device printed after port49d stopped.
type fallbackRow struct {
	err        error
	changed    bool
	transcript string
}

func (f fallbackRow) outcome() string {
	switch {
	case f.err != nil:
		return "not measured: " + f.err.Error()
	case f.changed:
		return "**accepted**"
	}
	return "refused"
}

// fallbackVariant delivers attrs, opens one interactive session, stops
// port49d under it, and types `configure terminal` and `hostname <node>` —
// the value the device already holds, as L16 did, so an accepted change
// changes nothing. The device's command method list ends in local
// (tests/lab/configs/*-startup.cfg), so with port49d gone it authorizes on
// its own. The change took where the device printed no `%` error after the
// hostname line and left configuration mode on `end`.
func (l *lab) fallbackVariant(t *testing.T, level string, attrs []string) fallbackRow {
	t.Helper()
	quoted, _ := json.Marshal(attrs)
	cfg, err := l.derivedConfig("fallback-"+level, string(quoted), "")
	if err != nil {
		t.Fatal(err)
	}
	if err := l.restart(cfg); err != nil {
		t.Fatalf("fallback %s: port49d would not start: %v", level, err)
	}
	user, secret := l.nextLogin(t)
	c, err := l.dial(user, secret, 45*time.Second)
	if err != nil {
		return fallbackRow{err: err}
	}
	defer c.Close()
	// Every step below is bounded: a device that stops answering closes the
	// connection at three minutes, and the row reports it unmeasured rather
	// than the run hanging (the first NX-OS run hung 76 minutes elsewhere).
	var expired atomic.Bool
	watchdog := time.AfterFunc(3*time.Minute, func() { expired.Store(true); c.Close() })
	defer watchdog.Stop()
	s, err := c.NewSession()
	if err != nil {
		return fallbackRow{err: err}
	}
	defer s.Close()
	if err := s.RequestPty("vt100", 40, 200, ssh.TerminalModes{ssh.ECHO: 0}); err != nil {
		return fallbackRow{err: fmt.Errorf("request pty: %w", err)}
	}
	stdin, err := s.StdinPipe()
	if err != nil {
		return fallbackRow{err: err}
	}
	var buf syncBuffer
	s.Stdout, s.Stderr = &buf, &buf
	if err := s.Shell(); err != nil {
		return fallbackRow{err: fmt.Errorf("start shell: %w", err)}
	}
	typeLine := func(line string, wait time.Duration) {
		_, _ = io.WriteString(stdin, line+"\r")
		time.Sleep(wait)
	}
	typeLine("", 3*time.Second)
	if err := l.stopDaemon(); err != nil {
		return fallbackRow{err: err}
	}
	mark := buf.Len()
	// A down TACACS+ server is a refused connection, so the device moves to
	// local at once; the waits are for the device's own prompt.
	typeLine("configure terminal", 5*time.Second)
	typeLine("hostname "+l.p.node, 5*time.Second)
	afterHostname := buf.Len()
	typeLine("end", 3*time.Second)
	typeLine("exit", 2*time.Second)
	stdin.Close()
	out := buf.String()
	hostnameOut := out[mark:afterHostname]
	if i := strings.Index(hostnameOut, "hostname "+l.p.node); i >= 0 {
		hostnameOut = hostnameOut[i:]
	}
	if expired.Load() {
		return fallbackRow{err: fmt.Errorf("the session did not finish within 3m and was closed"),
			transcript: strings.TrimSpace(out)}
	}
	return fallbackRow{changed: strings.Contains(out[mark:afterHostname], "(config)#") &&
		!strings.Contains(hostnameOut, "%"), transcript: strings.TrimSpace(out[mark:])}
}

// syncBuffer is a bytes.Buffer the SSH session writes from its own
// goroutine while the test reads it.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *syncBuffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Len()
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}
