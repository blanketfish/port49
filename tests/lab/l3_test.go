//go:build lab

package lab

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// L3: what the `enable` authentication exchange carries.
//
// The register asks whether the enable START carries `rem_addr` and what is in
// it. The memo at docs/design/2026-09-20-login-context-key-options.md asks more
// than that and for a sharper reason: `enable` is the one exchange in TACACS+
// where the username on the wire may not be the operator's. If a device sends
// `$enab15$`, then every enable on that device arrives under one username, and
// the `(nas, username)` login-context key the owner has chosen collapses to a
// single context for every operator who types `enable`. That is the enable
// regression the memo prices, and nothing in this lab had ever performed an
// enable exchange at all.
//
// So this measures four things and each is read off the wire, not the log:
//
//  1. the username the device puts in the enable START;
//  2. `port`, `rem_addr` and `priv_lvl` on it, and `service` — an enable START
//     is `service=enable(2)` where a login is `service=login(1)`, and whether
//     the device actually spells it that way is the first thing to check;
//  3. whether two CONCURRENT enables are distinguishable from each other by any
//     field at all;
//  4. what happens when the enable is allowed rather than denied — which needs
//     port49 to hold a token under whatever username step 1 discovered, so it
//     is done in a second phase against a daemon restarted with that seed.
//
// The seeded session is `priv-lvl=15` (lab.session_attributes), so a login
// lands in enable mode already and typing `enable` there is a no-op that
// authenticates nothing. `disable` first is what creates the exchange: it drops
// the session to privilege 1, and `enable` from there is the real thing an
// operator types.
func TestL3Enable(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		if strings.HasPrefix(l.p.name, "juniper_") {
			t.Skip("Junos has no enable exchange: a class is assigned at login and there is no second " +
				"authentication to raise privilege (spec decision 21)")
		}
		stop := l.capture(t, "L3")
		defer stop()

		u1, s1 := l.nextLogin(t)
		u2, s2 := l.nextLogin(t)

		off := l.mark()
		trans := l.l3Concurrent(t, u1, s1, u2, s2)
		recs := l.waitForRecords(off, 45*time.Second, func(rs []map[string]any) bool {
			return len(l3EnableRecords(rs, u1, u2)) >= 2
		})
		recs = l.drainRecords(off, 10*time.Second)

		enables := l3EnableRecords(recs, u1, u2)
		obs := "### Before anything was measured\n\n" + l3AuthzConfigNote + "\n" + l3Observation(l, trans, recs, enables)

		// Phase two only runs if phase one learned a username, because the seed
		// is that username. A run that learned nothing writes the note anyway —
		// what the device said is the finding — and fails below.
		if len(enables) > 0 {
			obs += l.l3Allowed(t, l3Username(enables[0]), l3EchoesOperator(enables, u1, u2))
		} else {
			obs += "\n### When the enable is allowed\n\nNot measured: phase one produced no enable " +
				"authentication record, so there was no username to seed a token under.\n"
		}

		obs += l3Caveats
		l.result(t, "L3", l3Claim, obs)

		// "This device has no enable command" is an answer to L3, not a failure
		// to answer it. Only a run where the device *did* offer an enable and
		// port49 never saw it has measured nothing.
		if strings.Contains(trans, l3NoEnableMarker) {
			t.Logf("%s: no enable exchange exists on this platform; the device rejected the command outright, "+
				"which is what the note records", l.p.name)
			return
		}
		if len(enables) == 0 {
			t.Fatalf("no authentication record that could be an enable reached the decision log, so neither the "+
				"wire username nor `rem_addr` was measured. What the device said:\n%s\nrecords:%s",
				trans, summarize(recs))
		}
	})
}

const l3Claim = "Whether the enable START carries `rem_addr`, and what it contains — bare address, or address " +
	"and source port. Also, because the login-context key now rests on it: what **username** the device puts " +
	"on an enable START, and whether two concurrent enables are distinguishable."

// l3NoSuchCommand are the things a device says when the command does not exist
// on it, and l3NoEnableMarker is how a session records having been told so.
//
// NX-OS is why they are here. On the N9Kv, `disable` answers:
//
//	disable
//	       ^
//	% Invalid command at '^' marker.
//
// There is no enable exchange on that platform unless `feature privilege` is
// configured, which this lab does not configure. "This device has no enable"
// is a perfectly good answer to L3 for that platform — it is the measurement,
// not the absence of one — so the test records it and passes, rather than
// spending 45 seconds per session waiting for a prompt that cannot appear and
// then failing as if nothing had been learned.
var l3NoSuchCommand = []string{"% Invalid", "Invalid command", "% Incomplete", "unknown command"}

const l3NoEnableMarker = "THIS PLATFORM HAS NO ENABLE COMMAND. The device rejected it outright:"

func l3RejectedCommand(out string) bool {
	for _, m := range l3NoSuchCommand {
		if strings.Contains(out, m) {
			return true
		}
	}
	return false
}

// l3EnablePassword is typed at the enable prompt in both phases, so that the
// only difference between the denied attempt and the allowed one is whether
// port49 holds a token under the username the device sent. It is a lab token of
// the same shape as every other in port49d-lab.yaml and it is seeded at
// runtime, not in the checked-in config, because until phase one runs nobody
// knows which username to seed it under.
const l3EnablePassword = "p49_labenable01"

// l3Concurrent drives two overlapping sessions through `disable` then `enable`,
// and returns what both devices said. Overlapping is the point: the third
// question is whether anything on the wire tells two simultaneous enables
// apart, and two enables one after the other cannot answer it.
func (l *lab) l3Concurrent(t *testing.T, u1, s1, u2, s2 string) string {
	t.Helper()
	var mu sync.Mutex
	said := map[string]string{}
	record := func(u, text string) {
		mu.Lock()
		said[u] = text
		mu.Unlock()
	}

	// Both sessions reach the enable prompt before either answers it, so the two
	// exchanges are genuinely in flight together.
	atPrompt := make(chan struct{}, 2)
	release := make(chan struct{})

	var wg sync.WaitGroup
	for _, cred := range []struct{ user, secret string }{{u1, s1}, {u2, s2}} {
		cred := cred
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := l.l3CLI(cred.user, cred.secret)
			if err != nil {
				record(cred.user, "could not open a CLI: "+err.Error())
				atPrompt <- struct{}{}
				return
			}
			defer c.Close()
			from := len(c.transcript())
			if out, err := c.sendExpect("disable", 45*time.Second, append([]string{">"}, l3NoSuchCommand...)...); err != nil {
				record(cred.user, "the device did not drop to an unprivileged prompt on `disable`: "+err.Error())
				atPrompt <- struct{}{}
				return
			} else if l3RejectedCommand(out) {
				record(cred.user, l3NoEnableMarker+"\n"+strings.TrimSpace(stripPrompt(out)))
				atPrompt <- struct{}{}
				return
			}
			out, err := c.sendExpect("enable", 45*time.Second, append([]string{"assword", "#"}, l3NoSuchCommand...)...)
			if err != nil {
				record(cred.user, "`enable` produced neither a password prompt nor an enabled prompt: "+err.Error())
				atPrompt <- struct{}{}
				return
			}
			if l3RejectedCommand(out) {
				record(cred.user, l3NoEnableMarker+"\n"+strings.TrimSpace(stripPrompt(out)))
				atPrompt <- struct{}{}
				return
			}
			if !strings.Contains(out, "assword") {
				record(cred.user, "`enable` asked for no password at all; the device said: "+oneLine(out))
				atPrompt <- struct{}{}
				return
			}
			atPrompt <- struct{}{}
			<-release
			final, _ := c.sendExpect(l3EnablePassword, 90*time.Second, "#", ">", "ailed", "enied", "nvalid")
			record(cred.user, strings.TrimSpace(stripPrompt(c.transcript()[from:])+"\n"+oneLine(final)))
		}()
	}

	// Wait for both to be at the prompt (or to have given up), then let both
	// answer at once.
	for i := 0; i < 2; i++ {
		select {
		case <-atPrompt:
		case <-time.After(3 * time.Minute):
		}
	}
	close(release)
	wg.Wait()

	var b strings.Builder
	for _, u := range []string{u1, u2} {
		fmt.Fprintf(&b, "**%s**:\n\n```\n%s\n```\n\n", u, trimForNote(said[u]))
	}
	return b.String()
}

// l3AuthzConfigNote is the paragraph this test's note owes the reader about
// the device's authorization configuration. It says "left alone" because it
// now is.
//
// It used to be produced by l3RelaxExecAuthz, which removed the device's
// `aaa authorization exec` and `aaa authorization commands` lines for this
// test's duration and put them back afterwards. That workaround existed for
// one reason: under the `(nas, port)` login-context key, vEOS wrote the
// context at the authentication (where it says `port=ssh`) and read it at the
// authorization (where the same image says `port=vty5`), the lookup missed,
// and the device killed the session with
// `Authorization denied: port49: this session was not authenticated by
// port49`. No token user could reach a prompt, so the enable exchange this
// test measures could not happen. Pointing the same statements at `local`
// failed differently — `Authorization denied: Unknown user`, because a token
// user has no local account, which is the point of port49.
//
// The key is now `(nas, username)` (spec §13, decision 15) and the lookup no
// longer depends on a field the device changes mid-session, so the device's
// own authorization configuration stays in force for this test like every
// other.
const l3AuthzConfigNote = "The device's authorization configuration was left exactly as `tests/lab/configs` " +
	"deploys it: `aaa authorization exec` and `aaa authorization commands` were in force throughout, and the " +
	"token sessions below passed them.\n"

// l3CLI opens an interactive CLI as a token user rather than as the break-glass
// account. It is the token session that matters here: the enable is performed
// by an operator port49 authenticated, which is the case the login-context key
// is about.
//
// On EOS it deliberately does NOT reuse eosCLI, which types `enable` on the way
// in. Here that would be the exchange under test happening during setup, and —
// worse — if the device asked for a password at that point, eosCLI's next line
// would be typed into the password prompt. So this one only takes whatever
// prompt the login produced and turns paging off. Which prompt that is is
// itself worth having in the note: `#` means the session authorization's
// `priv-lvl=15` reached the device, `>` means it did not.
func (l *lab) l3CLI(user, password string) (*cliConn, error) {
	if l.p.name == "cisco_nxos" {
		return l.nxosCLI(user, password)
	}
	// IOS-XE is the platform this row exists for, so its opener is the one that
	// must not type `enable`: on this device that is the exchange under test.
	// iosxeCLIRaising with raise=false takes whatever prompt the login produced
	// and stops there. Which prompt that is is itself a finding -- `#` means the
	// session authorization's `priv-lvl=15` reached the device, `>` means it did
	// not -- and the `disable` below works from either.
	if l.p.name == "cisco_iosxe" {
		return l.iosxeCLIRaising(user, password, false)
	}
	c, err := l.sshCLI(user, password)
	if err != nil {
		return nil, err
	}
	c.prompt = l.p.node + "#"
	if _, err := c.expect(45*time.Second, c.prompt, l.p.node+">"); err != nil {
		c.Close()
		return nil, err
	}
	if _, err := c.sendExpect("terminal length 0", 45*time.Second, c.prompt, l.p.node+">"); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

// l3EnableRecords picks the authentication records that are the enable rather
// than the login.
//
// It cannot filter on `service`, because the decision log does not carry it —
// that is what the capture is for. So it uses the two shapes an enable can
// take, and the first version of this function only knew one of them:
//
//   - a *different* username. This is the `$enab{level}$` shape the whole row
//     is named after, and the one the memo prices.
//   - the **same** username, a second time. This is what vEOS 4.32.2F actually
//     does, measured: the enable START carries `alice01`, the operator's own
//     name. The first version excluded exactly those records and then failed
//     the test for finding none — reporting a measurement it had made as a
//     measurement it had not.
//
// Records arrive in order, so the first redeem for a login username is that
// login and every later one is an enable.
func l3EnableRecords(recs []map[string]any, loginUsers ...string) []map[string]any {
	isLogin := map[string]bool{}
	for _, u := range loginUsers {
		isLogin[u] = true
	}
	seen := map[string]bool{}
	var out []map[string]any
	for _, r := range recs {
		if str(r, "event") != "redeem" {
			continue
		}
		s := sub(r, "session")
		if s == nil {
			continue
		}
		u := str(s, "username")
		if isLogin[u] && !seen[u] {
			seen[u] = true // this is the login itself
			continue
		}
		out = append(out, r)
	}
	return out
}

// l3EchoesOperator reports whether the device put the operator's own username
// on the enable START rather than a fixed one.
func l3EchoesOperator(enables []map[string]any, loginUsers ...string) bool {
	for _, u := range loginUsers {
		for _, r := range enables {
			if l3Username(r) == u {
				return true
			}
		}
	}
	return false
}

func l3Username(r map[string]any) string { return str(sub(r, "session"), "username") }

func l3Observation(l *lab, transcripts string, recs, enables []map[string]any) string {
	var b strings.Builder
	b.WriteString("Two overlapping sessions, each logged in with its own token and each holding at the enable " +
		"password prompt until the other had reached it, then both answering at once. `disable` precedes " +
		"`enable` because the seeded session is `priv-lvl=15`: a login lands in enable mode already and typing " +
		"`enable` there authenticates nothing.\n\n### What the device said\n\n")
	b.WriteString(transcripts)

	b.WriteString("### The enable authentication, in the decision log\n\n")
	if len(enables) == 0 {
		b.WriteString("**No authentication record arrived under a username other than the two the harness logged " +
			"in as.** Either the device sent the operator's own username on the enable START — which the wire " +
			"table below settles — or it never asked port49 about the enable at all. Every record in the " +
			"window:" + summarize(recs) + "\n\n")
	} else {
		b.WriteString("| wire username | verdict | reason | `port` | `rem_addr` |\n|---|---|---|---|---|\n")
		for _, r := range enables {
			s := sub(r, "session")
			port := str(s, "port")
			if port == "" {
				port = "(empty string)"
			}
			rem := str(s, "rem_addr")
			if rem == "" {
				rem = "(empty string)"
			}
			fmt.Fprintf(&b, "| `%s` | %s | `%s` | %s | %s |\n",
				str(s, "username"), str(r, "verdict"), str(r, "reason"), port, rem)
		}
		b.WriteString("\n" + l3KeyVerdict(enables) + "\n")
	}

	b.WriteString("\n### The enable exchange on the wire\n\n")
	b.WriteString(l.tacacsHeaderFacts())
	b.WriteString("\nRead the `service=` field in that table: a login START is `login(1)` and an enable START is " +
		"`enable(2)`. `priv_lvl` on the enable START is the level being asked for, which is what decides " +
		"whether the username is `$enab15$` or something else on a device that spells it that way.\n")
	return b.String()
}

// l3KeyVerdict says what the measured username does to the login-context key.
func l3KeyVerdict(enables []map[string]any) string {
	names := map[string]bool{}
	ports := map[string]bool{}
	rems := map[string]bool{}
	for _, r := range enables {
		s := sub(r, "session")
		names[str(s, "username")] = true
		ports[str(s, "port")] = true
		rems[str(s, "rem_addr")] = true
	}
	var b strings.Builder
	if len(names) == 1 && len(enables) > 1 {
		var only string
		for n := range names {
			only = n
		}
		fmt.Fprintf(&b, "**Both concurrent enables arrived under the same username, `%s`.** The login-context "+
			"key `(nas, username)` therefore gives every enable on this device one context: the second "+
			"operator's enable overwrites the first operator's, and neither is attributable to the person who "+
			"typed it. That is the enable regression section 3 of the login-context memo prices, measured.\n\n",
			only)
	} else if len(names) > 1 {
		b.WriteString("**The two concurrent enables arrived under different usernames**, so the device puts the " +
			"operator's own identity on the enable START and `(nas, username)` keeps them apart.\n\n")
	}
	fmt.Fprintf(&b, "Distinct `port` values across the two: %d. Distinct `rem_addr` values: %d. "+
		"A field with one distinct value across two concurrent enables cannot tell them apart.\n",
		len(ports), len(rems))
	return b.String()
}

// l3Allowed is phase two: seed a token under the username the device actually
// sent, restart port49d on that config, and type the same password again.
//
// The point is not to prove a token works. It is that a *denied* enable shows
// only the authentication half. An allowed one shows whether the device then
// sends an authorization request for the raised privilege, what `service` and
// `priv-lvl` it carries, and what accounting follows — none of which can be
// seen from a device that was refused.
func (l *lab) l3Allowed(t *testing.T, wireUser string, echoesOperator bool) string {
	t.Helper()

	// Which name to seed the token under depends on what phase one measured.
	// If the device sends a fixed name like `$enab15$`, seed that. If it sends
	// the operator's own — which vEOS does — the name that will arrive is the
	// name of whoever logs in for phase two, so the login has to be taken
	// first and its username seeded instead.
	user, secret := l.nextLogin(t)
	seedUser := wireUser
	if echoesOperator {
		seedUser = user
	}
	cfg, err := l.writeSeedConfig(seedUser, l3EnablePassword)
	if err != nil {
		return fmt.Sprintf("\n### When the enable is allowed\n\nNot measured: a daemon config seeding a token "+
			"under `%s` could not be written (%v).\n", seedUser, err)
	}
	if err := l.stopDaemon(); err != nil {
		return fmt.Sprintf("\n### When the enable is allowed\n\nNot measured: port49d could not be stopped to "+
			"reload it with the seed (%v).\n", err)
	}
	if err := l.startDaemonWith(cfg, true); err != nil {
		t.Fatalf("could not restart port49d with the enable seed, so the run cannot continue: %v", err)
	}
	defer func() {
		if err := l.stopDaemon(); err != nil {
			t.Errorf("could not stop the seeded daemon: %v", err)
			return
		}
		if err := l.startDaemonWith(labConfigPath(), true); err != nil {
			t.Fatalf("could not put port49d back on the lab config: %v", err)
		}
	}()

	off := l.mark()
	said := "the CLI never opened"
	c, err := l.l3CLI(user, secret)
	if err == nil {
		from := len(c.transcript())
		if _, err := c.sendExpect("disable", 45*time.Second, ">"); err == nil {
			if out, err := c.sendExpect("enable", 45*time.Second, "assword", "#"); err == nil && strings.Contains(out, "assword") {
				_, _ = c.sendExpect(l3EnablePassword, 90*time.Second, "#", ">", "ailed", "enied")
				// One command at the raised privilege, so that whatever
				// authorization the device sends for an enabled session is in
				// this window too.
				_, _ = c.sendExpect("show clock", 45*time.Second, "#", ">")
			}
		}
		said = strings.TrimSpace(stripPrompt(c.transcript()[from:]))
		c.Close()
	} else {
		said = "the CLI never opened: " + err.Error()
	}

	recs := l.waitForRecords(off, 45*time.Second, func(rs []map[string]any) bool {
		return len(l3EnableRecords(rs, user)) > 0
	})
	recs = l.drainRecords(off, 15*time.Second)

	var b strings.Builder
	fmt.Fprintf(&b, "\n### When the enable is allowed\n\nphase one measured that this device puts %s on the "+
		"enable START. port49d was therefore restarted on a config seeding one token under `%s`, and the same "+
		"keystrokes were repeated as `%s`. Nothing else changed.\n\nWhat the device said:\n\n```\n%s\n```\n\n"+
		"Every record in that window:\n\n```\n",
		map[bool]string{true: "**the operator's own username**", false: fmt.Sprintf("the fixed username `%s`", wireUser)}[echoesOperator],
		seedUser, user, trimForNote(said))
	if len(recs) == 0 {
		b.WriteString("(none)\n")
	}
	for _, r := range recs {
		s := sub(r, "session")
		fmt.Fprintf(&b, "%s event=%s verdict=%s reason=%s user=%q port=%q rem_addr=%q\n",
			str(r, "ts"), str(r, "event"), str(r, "verdict"), str(r, "reason"),
			str(s, "username"), str(s, "port"), str(s, "rem_addr"))
		for _, a := range strs(sub(r, "request"), "raw") {
			fmt.Fprintf(&b, "    request AV: %s\n", a)
		}
		for _, a := range rawOf(r) {
			fmt.Fprintf(&b, "    accounting AV: %s\n", a)
		}
	}
	b.WriteString("```\n")
	return b.String()
}

// writeSeedConfig copies the lab daemon config with one extra seeded login
// appended, and returns the new path.
//
// It appends rather than splicing, and it checks first that the file really
// does end in the seed list. A splice into the middle of a YAML block is one
// indentation mistake away from a config that parses into something else
// entirely, and a daemon that started on a config the test did not intend
// would answer every later measurement wrongly with no symptom that says so.
func (l *lab) writeSeedConfig(user, secret string) (string, error) {
	raw, err := os.ReadFile(labConfigPath())
	if err != nil {
		return "", err
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) == 0 || !strings.HasPrefix(lines[len(lines)-1], "    - {nas: ") {
		return "", fmt.Errorf("tests/lab/port49d-lab.yaml no longer ends with a seed_tokens entry (its last line "+
			"is %q), so appending one would not land in the list", lines[len(lines)-1])
	}
	// Quote the username: the enable name a device sends is commonly `$enab15$`,
	// and an unquoted `$` at the start of a YAML scalar is not something to rely
	// on parsing the way it looks.
	// `kind: enable`, not `kind: login`, and the first run is why the
	// distinction is spelled out here. Seeded as a login token, the enable was
	// refused `token_kind_mismatch` — port49 reads the authentication START's
	// `service` and looks for a token of the matching kind
	// (internal/daemon/authen/authen.go, internal/store). A note that reported
	// that as device behavior would have been reporting a harness mistake.
	out := string(raw) + fmt.Sprintf("    - {nas: %s, username: \"%s\", secret: %s, kind: enable}\n",
		l.p.node, user, secret)
	path := filepath.Join(root, "tests", "lab", "logs", "port49d-lab-enable-seed.yaml")
	if err := os.WriteFile(path, []byte(out), 0o644); err != nil {
		return "", err
	}
	return path, nil
}

const l3Caveats = "\n### Not measured\n\n" +
	"- Two operators from two different client addresses. Both sessions here come from the harness at the " +
	"bridge's `.1`, so `rem_addr` not distinguishing them is measured only for the shared-bastion case.\n" +
	"- Privilege levels other than the one `enable` with no argument asks for.\n" +
	"- `enable` over any transport but the interactive SSH CLI.\n" +
	"- IOS-XE, which is the platform the `$enab{level}$` spelling comes from and the one this row most needs.\n" +
	"- Whether a device that is refused an enable falls back to a local enable secret, which is L4's question " +
	"asked of the enable method list rather than the login one.\n"
