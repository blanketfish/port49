//go:build lab

package lab

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// L4: whether a method list falls through to a local account when TACACS+
// answers FAIL — a denial — rather than only when the server is unreachable.
//
// Spec §5.6 argues "a denial is FAIL, so no fallback to local authorization
// follows", and the `enable: auto` exposure argument rests on that. Before this
// test the register had exactly one data point: vJunos-router falls through
// with the server *unreachable*. Nothing at all was measured for a server that
// is up and rejecting, which is the case the spec's sentence is about.
//
// The matrix is two method lists crossed with two server conditions:
//
//	order A — the permissive shape: Junos `authentication-order [ tacplus
//	          password ]`, EOS `... group <g> local`
//	order B — the stricter reference shape: Junos `authentication-order
//	          tacplus`, EOS the named-group line the lab config already carries
//	          versus `group tacacs+ local`
//	cond 1  — port49d not listening, so the device's connection is refused
//	cond 2  — port49d up and answering FAIL to this login: the local account
//	          presents its correct LOCAL password, port49 holds no token for
//	          that username, and replies FAIL (reason token_not_found)
//
// A cell is "measured" when the login was attempted and the device did
// something. On condition 2 it is measured only if the decision log also shows
// the FAIL that was sent for that attempt: a login that fell through before
// port49 ever answered would otherwise read as fall-through on FAIL.
func TestL4FallThrough(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		stop := l.capture(t, "L4")
		defer stop()
		switch {
		case strings.HasPrefix(l.p.name, "juniper_"):
			l4Junos(t, l)
		case l.p.name == "cisco_nxos":
			l4NXOS(t, l)
		default:
			l4EOS(t, l)
		}
	})
}

// l4FailDelay is what port49's per-(nas, username) failure delay is set to for
// the whole of L4, so the time column measures the device and not the daemon.
// The product default is 500ms doubling to 5s, and a cell that took 18s would
// otherwise leave a reader guessing how much of that was port49 sleeping.
// Whether a device even waits for a delayed FAIL is L13's question, not this
// one.
const l4FailDelay = 100 * time.Millisecond

// The gate this test used to carry now lives in harness_test.go as
// waitTACACSReady and runs once per platform during bring-up, so every register
// test gets it rather than only L4 and L13. Nothing here waits for it again:
// by the time a test body runs, the device has been seen sending port49d a
// packet.

// l4Cell is one (order, condition) measurement.
type l4Cell struct {
	order     string // the configured method list in force
	condition string // what port49d was doing
	attempted bool
	ok        bool          // the local account logged in
	took      time.Duration // how long the attempt took, whichever way it ended
	err       error         // why SSH refused, when it did
	evidence  string        // what the decision log showed for this attempt
	note      string        // why a cell was not attempted, when it was not
}

func (c l4Cell) outcome() string {
	switch {
	case !c.attempted:
		return "**not measured**"
	case c.ok:
		return "**logged in**"
	default:
		return "refused"
	}
}

func (c l4Cell) tookStr() string {
	if !c.attempted {
		return "—"
	}
	return c.took.Round(10 * time.Millisecond).String()
}

// l4Attempt runs one cell: a login as the local break-glass account with its
// local password.
func (l *lab) l4Attempt(t *testing.T, order, condition string, expectFail bool) l4Cell {
	t.Helper()
	c := l4Cell{order: order, condition: condition, attempted: true}
	off := l.mark()
	t0 := time.Now()
	cl, err := l.dial(breakglassUser, breakglassPassword, 120*time.Second)
	c.took = time.Since(t0)
	if err == nil {
		c.ok = true
		cl.Close()
	} else {
		c.err = err
	}

	if !expectFail {
		c.evidence = "port49d was not listening, so no decision record could exist for this attempt. " +
			"The capture holds the device's refused connection attempts to port 49."
		return c
	}
	recs := l.waitForRecords(off, 30*time.Second, func(rs []map[string]any) bool {
		return redeemFor(rs, breakglassUser) != nil
	})
	rec := redeemFor(recs, breakglassUser)
	if rec == nil {
		c.evidence = "**no redeem record for `" + breakglassUser + "` reached the decision log**, so port49 " +
			"did not answer this login at all and whatever the device did is not a response to a FAIL." +
			summarize(recs)
		return c
	}
	c.evidence = fmt.Sprintf("`event=%s verdict=%s reason=%s`, so port49 replied FAIL for this attempt.",
		str(rec, "event"), str(rec, "verdict"), str(rec, "reason"))
	if str(rec, "verdict") != "deny" {
		c.evidence = fmt.Sprintf("**the record for this attempt was not a denial**: `event=%s verdict=%s reason=%s`",
			str(rec, "event"), str(rec, "verdict"), str(rec, "reason"))
	}
	return c
}

// ---------------------------------------------------------------------------
// Junos
// ---------------------------------------------------------------------------

// The two authentication orders under test, and the statement that sets each.
var l4JunosOrders = []struct {
	shown string
	set   string
}{
	{"authentication-order [ tacplus password ]", "set system authentication-order [ tacplus password ]"},
	{"authentication-order tacplus", "set system authentication-order tacplus"},
}

func l4Junos(t *testing.T, l *lab) {
	cfg := l.writeDelayConfig(t, l4FailDelay)

	var cells []l4Cell
	var configEvidence, channel string

	for i, order := range l4JunosOrders {
		if err := l.stopDaemon(); err != nil {
			t.Fatalf("could not stop port49d, so the unreachable condition could not be created: %v", err)
		}

		if i > 0 {
			// Switch the order with the server still down, because that is the
			// one condition in which a local login is known to work on at least
			// one of these images. Doing it with port49d up would make the
			// configuration change depend on the very behavior under test.
			c, err := l.junosCLI(breakglassUser, breakglassPassword)
			if err != nil {
				cells = append(cells,
					l4Cell{order: order.shown, condition: "port49d not listening", note: "the device could not be reached on any CLI channel to set this order: " + err.Error()},
					l4Cell{order: order.shown, condition: "port49d answering FAIL", note: "the order was never set"})
				break
			}
			out, err := junosConfigure(c, "delete system authentication-order", order.set)
			c.Close()
			if err != nil {
				// A cell that will not measure is a finding, not a dead run:
				// record what the device said and leave the cells already
				// measured standing.
				why := fmt.Sprintf("the order could not be set: %v (device said: %s)", err, oneLine(out))
				cells = append(cells,
					l4Cell{order: order.shown, condition: "port49d not listening", note: why},
					l4Cell{order: order.shown, condition: "port49d answering FAIL", note: why})
				break
			}
		}

		if i == 0 {
			// The first cell doubles as the check that the break-glass account
			// has a usable password at all, which is what the encrypted-password
			// change in configs/vjunos-startup.conf was for. Read the committed
			// configuration back over whatever channel is available.
			cell := l.l4Attempt(t, order.shown, "port49d not listening", false)
			cells = append(cells, cell)
			configEvidence, channel = l4JunosConfigEvidence(t, l)
		} else {
			cells = append(cells, l.l4Attempt(t, order.shown, "port49d not listening", false))
		}

		if err := l.startDaemonWith(cfg, true); err != nil {
			t.Fatalf("could not restart port49d, so the FAIL condition could not be created: %v", err)
		}
		cells = append(cells, l.l4Attempt(t, order.shown, "port49d answering FAIL", true))
	}

	// Put the device back the way the topology deploys it, so nothing later in
	// this run measures an order this test left behind.
	restore := "restored"
	if err := l.stopDaemon(); err != nil {
		restore = "not restored: " + err.Error()
	} else {
		if c, err := l.junosCLI(breakglassUser, breakglassPassword); err != nil {
			restore = "not restored: " + err.Error()
		} else {
			_, err := junosConfigure(c, "delete system authentication-order", l4JunosOrders[0].set)
			c.Close()
			if err != nil {
				restore = "not restored: " + err.Error()
			}
		}
		if err := l.startDaemonWith(labConfigPath(), true); err != nil {
			t.Fatalf("could not restart port49d after the test: %v", err)
		}
	}

	l.result(t, "L4", l4Claim, l4Observation(l, cells, configEvidence, channel,
		fmt.Sprintf("The order was switched in place over the device's own CLI and %s afterwards.", restore)))
	l4Assert(t, cells)
}

// l4JunosConfigEvidence reads back whether the break-glass account has an
// encrypted password on this image. The value is never read and never logged;
// only whether the line exists.
func l4JunosConfigEvidence(t *testing.T, l *lab) (evidence, channel string) {
	t.Helper()
	c, err := l.junosCLI(breakglassUser, breakglassPassword)
	if err != nil {
		return "Not read: no CLI channel was available (" + err.Error() + ").", "none"
	}
	defer c.Close()
	out, err := junosShow(c, "show configuration system login user "+breakglassUser+" | no-more")
	if err != nil {
		return "Not read: " + err.Error(), c.name
	}
	has := strings.Contains(out, "encrypted-password")
	plain := strings.Contains(out, "plain-text-password-value")
	// `| display set` and not the plain form: this file carries a long comment
	// above the statement, and `show configuration` prints it, which buried the
	// one line that matters under forty lines of prose in the first note.
	order, _ := junosShow(c, "show configuration system authentication-order | display set | no-more")
	switch {
	case has:
		evidence = "`show configuration system login user " + breakglassUser + "` carries an " +
			"**`encrypted-password` line** (the value is not reproduced here). The startup config's hash " +
			"survived the commit on this image."
	case plain:
		evidence = "`show configuration system login user " + breakglassUser + "` still shows " +
			"**`plain-text-password-value`, and no `encrypted-password` line** — the same defect this change " +
			"was meant to remove."
	default:
		evidence = "`show configuration system login user " + breakglassUser + "` shows **no password " +
			"statement of either form**."
	}
	evidence += "\n\nThe order in force when this was read, per `show configuration system authentication-order`:\n\n```\n" +
		redactSecrets(strings.TrimSpace(stripPrompt(order))) + "\n```"
	return evidence, c.name
}

// ---------------------------------------------------------------------------
// EOS and NX-OS: `aaa authentication login default`
// ---------------------------------------------------------------------------

// l4AAADriver is what one `aaa authentication login default` platform has to
// supply. EOS and NX-OS run the identical matrix over an identical statement
// and differ only in how a CLI is opened, how configuration is applied, and
// which second method list is the interesting one, so the matrix itself is
// written once. Junos keeps its own function: `authentication-order` is a
// different statement with a commit step.
type l4AAADriver struct {
	open      func(user, password string) (*cliConn, error)
	configure func(c *cliConn, lines ...string) (string, error)
	show      func(c *cliConn, cmd string) (string, error)

	// alternative is the second method list the matrix sets, chosen per
	// platform because the interesting contrast differs. On EOS the lab's own
	// line names a group and the question was whether the built-in `tacacs+`
	// group behaves differently. On NX-OS the lab's line already ends in
	// `local`, so the contrast worth measuring is the same one Junos gave:
	// a list with no local method at all.
	alternative string

	// evidence is the platform's paragraph under "### The local account".
	evidence string
}

func l4EOS(t *testing.T, l *lab) {
	l4AAA(t, l, l4AAADriver{
		open:        l.eosCLI,
		configure:   eosConfigure,
		show:        eosShow,
		alternative: "aaa authentication login default group tacacs+ local",
		evidence: "EOS has no equivalent of the Junos password-materialisation defect: the `username " +
			breakglassUser + "` line in `tests/lab/configs/eos-startup.cfg` produces a usable local password, and " +
			"every cell above that logged in proves it.\n\n" +
			"That line now also carries `role network-admin`, and the reason belongs in this note. With " +
			"`privilege 15` alone, this account logged in while port49d was unreachable and was then refused its " +
			"first configuration command: `% Authorization denied for command 'configure'`. EOS command " +
			"authorization under `... group port49 local` falls back to the local **role**, and a role is not a " +
			"privilege level — an account with no role gets the default one, which authorizes `show` and `enable` " +
			"and stops there. A break-glass account that can log in during an outage and cannot change anything is " +
			"worth knowing about before the outage.",
	})
}

func l4NXOS(t *testing.T, l *lab) {
	l4AAA(t, l, l4AAADriver{
		open:        l.nxosCLI,
		configure:   nxosConfigure,
		show:        nxosShow,
		alternative: "aaa authentication login default group port49",
		evidence: "The local account is the `username " + breakglassUser + " ... role network-admin` line in " +
			"`tests/lab/configs/nxos-startup.cfg`, which only commits because `no password strength-check` " +
			"precedes it: NX-OS rejects a password that fails its complexity rules, and the lab's does. Every " +
			"cell above that logged in is the proof the account exists.\n\n" +
			"The second method list here is not EOS's contrast. On EOS the lab line already names a group and " +
			"ends in `local`, so the alternative worth trying was the built-in `tacacs+` group. On NX-OS the " +
			"contrast that matters is the one Junos answered: a list with **no local method at all**, which is " +
			"what `aaa authentication login default group port49` is. If NX-OS still takes a local password " +
			"under that list when port49 is unreachable, it behaves like Junos — \"TACACS+ only while the " +
			"server answers\" — and if it refuses, it behaves like the spec assumes.\n\n" +
			"Console access is unaffected either way: NX-OS keeps a separate `aaa authentication login console` " +
			"list and with none configured it defaults to `local`, which is why the restore below can use the " +
			"console when SSH is shut out.",
	})
}

func l4AAA(t *testing.T, l *lab, d l4AAADriver) {
	cfg := l.writeDelayConfig(t, l4FailDelay)

	// What the lab's startup config already carries, read back from the device
	// rather than from the file, and the reference shape spec work asks about.
	//
	// Read with port49d stopped, and that is not housekeeping. The first attempt
	// read it with the daemon up and EOS refused the CLI login outright: under
	// `group port49 local` it asked port49 about `breakglass`, got FAIL, and did
	// not try the local password — the very behavior this test measures, met
	// while trying to set up to measure it. Every CLI channel this test opens is
	// therefore opened in the one condition where a local login is not itself
	// the question.
	if err := l.stopDaemon(); err != nil {
		t.Fatalf("could not stop port49d before reading the device's configuration: %v", err)
	}
	configured, err := l4AAAConfigured(l, d)
	if err != nil {
		t.Fatalf("could not read the configured login method list, so there is nothing to attribute a result to: %v", err)
	}
	orders := []string{configured, d.alternative}

	var cells []l4Cell
	for i, order := range orders {
		if err := l.stopDaemon(); err != nil {
			t.Fatalf("could not stop port49d, so the unreachable condition could not be created: %v", err)
		}
		if i > 0 {
			c, err := d.open(breakglassUser, breakglassPassword)
			if err != nil {
				cells = append(cells,
					l4Cell{order: order, condition: "port49d not listening", note: "the device could not be reached to set this method list: " + err.Error()},
					l4Cell{order: order, condition: "port49d answering FAIL", note: "the method list was never set"})
				break
			}
			out, err := d.configure(c, order)
			c.Close()
			if err != nil {
				why := fmt.Sprintf("the method list could not be set: %v (device said: %s)", err, oneLine(out))
				cells = append(cells,
					l4Cell{order: order, condition: "port49d not listening", note: why},
					l4Cell{order: order, condition: "port49d answering FAIL", note: why})
				break
			}
		}
		cells = append(cells, l.l4Attempt(t, order, "port49d not listening", false))
		if err := l.startDaemonWith(cfg, true); err != nil {
			t.Fatalf("could not restart port49d, so the FAIL condition could not be created: %v", err)
		}
		cells = append(cells, l.l4Attempt(t, order, "port49d answering FAIL", true))
	}

	restore := "restored"
	channel := "SSH CLI as " + breakglassUser
	if err := l.stopDaemon(); err != nil {
		restore = "not restored: " + err.Error()
	} else {
		if c, err := d.open(breakglassUser, breakglassPassword); err != nil {
			restore = "not restored: " + err.Error()
		} else {
			channel = c.name
			_, err := d.configure(c, orders[0])
			c.Close()
			if err != nil {
				restore = "not restored: " + err.Error()
			}
		}
		if err := l.startDaemonWith(labConfigPath(), true); err != nil {
			t.Fatalf("could not restart port49d after the test: %v", err)
		}
	}

	l.result(t, "L4", l4Claim, l4Observation(l, cells, d.evidence, channel,
		fmt.Sprintf("The method list was switched in place over the device's own CLI and %s afterwards.", restore)))
	l4Assert(t, cells)
}

// l4AAAConfigured reads the login method list the lab config actually applied,
// so the results note attributes each row to the line that was in force rather
// than to the line the test meant to set.
//
// The `| include` filter is deliberately one word. Both platforms take a longer
// filter and both take it differently — NX-OS wants the multi-word form quoted
// and EOS does not — so the line is picked out of a short `aaa` listing in Go
// instead, where a quoting mistake cannot look like a device that has no such
// statement.
func l4AAAConfigured(l *lab, d l4AAADriver) (string, error) {
	c, err := d.open(breakglassUser, breakglassPassword)
	if err != nil {
		return "", err
	}
	defer c.Close()
	out, err := d.show(c, "show running-config | include aaa")
	if err != nil {
		return "", err
	}
	for _, ln := range strings.Split(stripPrompt(out), "\n") {
		ln = strings.TrimSpace(strings.TrimRight(ln, "\r"))
		if strings.HasPrefix(ln, "aaa authentication login default") {
			return ln, nil
		}
	}
	return "", fmt.Errorf("no `aaa authentication login default` line in:\n%s", out)
}

// ---------------------------------------------------------------------------
// The note
// ---------------------------------------------------------------------------

const l4Claim = "Whether any method-list configuration falls through to local on FAIL rather than only on ERROR " +
	"— specifically Junos `authentication-order` with `password` listed — and `deadtime` behavior."

func l4Observation(l *lab, cells []l4Cell, configEvidence, channel, restoreNote string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "The local account `%s` presented its own LOCAL password over SSH, under each method list "+
		"and each server condition. Under `port49d answering FAIL` that account has no token in port49's store, "+
		"so port49 answers the device FAIL; the decision log column is the proof that it did, for that attempt.\n\n"+
		"The time column is the device's, not port49's: for this test both `limits.auth_failure_delay_base` and "+
		"`limits.auth_failure_delay_max` were pinned to %s, rather than the product defaults of 500ms doubling "+
		"to 5s, so nothing in these figures is the daemon sleeping.\n\n",
		breakglassUser, l4FailDelay)
	b.WriteString("| method list | port49d | local login | time | decision log |\n|---|---|---|---|---|\n")
	for _, c := range cells {
		ev := c.evidence
		if c.note != "" {
			ev = c.note
		}
		fmt.Fprintf(&b, "| `%s` | %s | %s | %s | %s |\n", c.order, c.condition, c.outcome(), c.tookStr(),
			strings.ReplaceAll(strings.ReplaceAll(ev, "\n", " "), "|", "\\|"))
	}

	b.WriteString("\n### What the device said when it refused\n\n")
	any := false
	for _, c := range cells {
		if c.err == nil {
			continue
		}
		any = true
		fmt.Fprintf(&b, "- `%s` / %s: `%v`\n", c.order, c.condition, c.err)
	}
	if !any {
		b.WriteString("Nothing: every cell that was attempted logged in.\n")
	}

	fmt.Fprintf(&b, "\n### Does fall-through happen on a denial?\n\n%s\n", l4Verdict(cells))
	fmt.Fprintf(&b, "\n### The local account\n\n%s\n\nCLI channel used: %s. %s\n", configEvidence, channel, restoreNote)
	b.WriteString("\n### Not measured\n\n" +
		"- `deadtime` — this lab has one TACACS+ server and no dead-server timer was exercised.\n" +
		"- Every transport but SSH: console, eAPI, NX-API and NETCONF.\n" +
		"- A second TACACS+ server, so nothing here says what a device does with one server rejecting and " +
		"another reachable.\n" +
		"- NX-OS and IOS-XE, and any Junos or EOS release but the one named above.\n" +
		"- Authorization fall-through. This measures the authentication method list only; whether command " +
		"authorization falls back to local on a deny is a separate question spec §5.6 also leans on.\n")
	return b.String()
}

// l4Verdict states, in one sentence per method list, whether a denial produced
// a local login.
func l4Verdict(cells []l4Cell) string {
	var b strings.Builder
	for _, c := range cells {
		if c.condition != "port49d answering FAIL" {
			continue
		}
		switch {
		case !c.attempted:
			fmt.Fprintf(&b, "- `%s`: **not measured** — %s\n", c.order, c.note)
		case c.ok:
			fmt.Fprintf(&b, "- `%s`: **yes.** port49 replied FAIL and the device then accepted the local "+
				"password. A denial is not treated as final.\n", c.order)
		default:
			fmt.Fprintf(&b, "- `%s`: **no.** port49 replied FAIL and the device refused the login rather than "+
				"trying the local password.\n", c.order)
		}
	}
	if b.Len() == 0 {
		return "Not measured: no cell reached the FAIL condition."
	}
	return b.String()
}

// l4Assert fails the test when nothing was measured. Whichever way the device
// behaved is the result; a cell that never ran is not.
func l4Assert(t *testing.T, cells []l4Cell) {
	t.Helper()
	fail, unreach := 0, 0
	for _, c := range cells {
		if !c.attempted {
			t.Errorf("cell not measured: %s / %s — %s", c.order, c.condition, c.note)
			continue
		}
		if c.condition == "port49d answering FAIL" {
			if !strings.Contains(c.evidence, "replied FAIL") {
				t.Errorf("cell %s / %s: port49 was not shown to have replied FAIL, so what the device did is "+
					"not attributable to a denial: %s", c.order, c.condition, c.evidence)
				continue
			}
			fail++
			continue
		}
		unreach++
	}
	if fail == 0 {
		t.Error("no cell measured a device's response to a FAIL, which is the whole of L4's open half")
	}
	if unreach == 0 {
		t.Error("no cell measured a device's response to an unreachable server")
	}
}

// redactSecrets removes credential material from device output before a results
// note quotes it.
//
// A results note may not contain a password, key or hash, and a device is happy
// to print all three at the slightest provocation. `show configuration system
// tacplus-server` answers with `secret "$9$..."`, which is the shared key in
// Junos' reversible type-9 encoding, and `show running-config | include tacacs`
// on EOS answers with `key 7 ...`, which is the same thing in Arista's. Both
// landed in a draft of the L13 note. The keyword survives so the reader can see
// which statement was there; the value does not.
func redactSecrets(s string) string {
	lines := strings.Split(s, "\n")
	for i, ln := range lines {
		lower := strings.ToLower(ln)
		for _, kw := range []string{"secret", "password", "key"} {
			if j := strings.Index(lower, kw); j >= 0 {
				lines[i] = ln[:j+len(kw)] + " <redacted by the harness>"
				break
			}
		}
	}
	return strings.Join(lines, "\n")
}

// oneLine flattens a device transcript for a table cell.
func oneLine(s string) string {
	return strings.Join(strings.Fields(strings.ReplaceAll(s, "|", "/")), " ")
}

// stripPrompt drops the trailing prompt line from a command's output, so a note
// quotes what the device said rather than where it said it from.
func stripPrompt(out string) string {
	lines := strings.Split(strings.ReplaceAll(out, "\r\n", "\n"), "\n")
	for len(lines) > 0 {
		last := strings.TrimSpace(lines[len(lines)-1])
		if last == "" || strings.HasSuffix(last, ">") || strings.HasSuffix(last, "#") {
			lines = lines[:len(lines)-1]
			continue
		}
		break
	}
	if len(lines) > 0 && strings.TrimSpace(lines[0]) != "" {
		// The first line is the command as the device echoed it back.
		lines = lines[1:]
	}
	return strings.Join(lines, "\n")
}
