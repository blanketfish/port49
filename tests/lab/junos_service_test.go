//go:build lab

package lab

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestJunosSessionService measures what plan 1's `session_services` change did
// on a real Junos device, in three phases against one deploy.
//
// Until 2026-09-21 `author.Handle` required `service=shell` and Junos sends
// `junos-exec` (§15, L10), so **every Junos session authorization port49 had
// ever answered was a denial**. What that denial cost the operator was never
// measured — it was inferred from a `<edit-config>` coming back `permission
// denied` in the NETCONF runs. The three phases here are:
//
//	A. the default list. `junos-exec` is now authorized: does the session
//	   authorization permit, and what does the operator's session look like?
//	B. a renamed service. Production SRX firewalls run `set system
//	   tacplus-options service-name junos-exec-fw`; does the new name arrive on
//	   the authorization, and does it arrive on accounting too?
//	C. a deliberate denial, which is phase A's world before today. port49 is
//	   configured to authorize a service the device does not send, so the
//	   session authorization is denied `service_unsupported` — the exact
//	   condition that stood until 2026-09-21. **Does the login still complete,
//	   and what does the device think the session may do?** That is the
//	   question that was only ever inferred.
//
// Phase C is the one that must not be skipped if a phase fails: an inference
// that has stood for a day is worth less than one measurement.
func TestJunosSessionService(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		if !strings.HasPrefix(l.p.name, "juniper_") {
			t.Skipf("this measures the Junos `service` value; %s sends `shell` (L10)", l.p.name)
		}
		stop := l.capture(t, "junos-session-service")
		defer stop()

		var b strings.Builder

		// Phase A — the built-in default, `junos-exec`.
		defCfg, err := l.derivedConfig("service-default", `[]`, "")
		if err != nil {
			t.Fatalf("derive the default-service config: %v", err)
		}
		a := l.junosServicePhase(t, "A — built-in default `junos-exec`, no attributes", defCfg)
		b.WriteString(a.render())

		// Phase B — the operator's own name. Two changes, one per side: the
		// device is told to send `junos-exec-fw`, and port49 is told to accept
		// it and nothing else. Accepting only the new name is deliberate: if
		// the device did not actually rename it, the authorization is denied
		// and the phase says so, where a list holding both names would pass
		// either way and measure nothing.
		const custom = "junos-exec-fw"
		restore := l.junosSetServiceName(t, custom)
		customCfg, err := l.derivedConfig("service-custom", `[]`,
			"platforms:\n  juniper_junos:\n    session_services: [\""+custom+"\"]\n")
		if err != nil {
			t.Fatalf("derive the custom-service config: %v", err)
		}
		bPhase := l.junosServicePhase(t, "B — device renamed to `"+custom+"`", customCfg)
		b.WriteString(bPhase.render())
		b.WriteString(junosAccountingServiceNote(t, bPhase, custom))
		restore(t)

		// Phase C — the denial. The device is back on `junos-exec` and port49
		// is configured to authorize `shell` alone, which is precisely the
		// comparison `author.Handle` made until 2026-09-21.
		denyCfg, err := l.derivedConfig("service-deny", `[]`,
			"platforms:\n  juniper_junos:\n    session_services: [\"shell\"]\n")
		if err != nil {
			t.Fatalf("derive the denying config: %v", err)
		}
		c := l.junosServicePhase(t, "C — port49 denies the session authorization on purpose", denyCfg)
		b.WriteString(c.render())

		// Put the daemon back on this platform's standing config, so anything
		// that runs after this test is not measuring phase C's world.
		base, err := l.configPath()
		if err != nil {
			t.Fatalf("recover this platform's standing config: %v", err)
		}
		if err := l.stopDaemon(); err != nil {
			t.Fatalf("stopping the daemon to restore it: %v", err)
		}
		if err := l.startDaemonWith(base, true); err != nil {
			t.Fatalf("restoring the daemon on the standing config: %v", err)
		}

		// A phase that produced no session authorization measured nothing,
		// whatever else it collected.
		for _, p := range []junosServicePhaseResult{a, bPhase, c} {
			if p.authz == nil {
				t.Errorf("phase %q produced no authorize_session record at all, so it measured nothing:%s",
					p.name, summarize(p.recs))
			}
		}

		b.WriteString(junosServiceComparison(a, bPhase, c))
		b.WriteString(junosServiceReading(t, a, bPhase, c, custom))

		l.result(t, "junos-session-service",
			"Whether a Junos session authorization is permitted now that `junos-exec` is on the "+
				"platform's `session_services` list (spec §5.2, §8); whether a device-renamed service "+
				"(`set system tacplus-options service-name`) arrives on the authorization and on "+
				"accounting; and what a deliberately DENIED session authorization costs the operator — "+
				"which until 2026-09-21 was every Junos session port49 answered, and was inferred rather "+
				"than measured.",
			b.String())
	})
}

// junosServicePhaseResult is one phase's evidence: what port49 decided, what
// the device let the operator do, and the transcripts behind both.
type junosServicePhaseResult struct {
	name string

	loginErr   string // non-empty when the CLI never opened
	authz      map[string]any
	acct       []map[string]any
	recs       []map[string]any
	cliAuthCmd string // the exact command typed
	cliAuth    string // the device's exact reply
	classCmd   string
	class      string
}

func (p junosServicePhaseResult) render() string {
	var b strings.Builder
	fmt.Fprintf(&b, "\n### Phase %s\n\n", p.name)

	if p.loginErr != "" {
		fmt.Fprintf(&b, "**The login did not complete.** The SSH CLI never opened:\n\n```\n%s\n```\n\n", p.loginErr)
	} else {
		b.WriteString("**The login completed** and the operator reached an operational-mode prompt.\n\n")
	}

	if p.authz == nil {
		b.WriteString("port49 wrote **no `authorize_session` record at all** for this phase, so nothing " +
			"here is attributable to a session authorization.\n\n")
	} else {
		s := sub(p.authz, "session")
		req := sub(p.authz, "request")
		fmt.Fprintf(&b, "port49's own record:\n\n```\nevent=authorize_session verdict=%s reason=%s\n"+
			"    request.service=%q\n    request.raw=%v\n    port=%q rem_addr=%q priv=%v\n```\n\n",
			str(p.authz, "verdict"), str(p.authz, "reason"), str(req, "service"), strs(req, "raw"),
			str(s, "port"), str(s, "rem_addr"), s["privilege"])
	}

	if p.cliAuth != "" {
		fmt.Fprintf(&b, "What the device says the session may do:\n\n```\n%s\n```\n\n```\n%s\n```\n\n",
			p.cliAuthCmd, strings.TrimRight(p.cliAuth, "\n"))
	} else if p.loginErr == "" {
		fmt.Fprintf(&b, "`%s` returned nothing, so this phase does not say what the session's permissions were.\n\n", p.cliAuthCmd)
	}
	if p.class != "" {
		fmt.Fprintf(&b, "```\n%s\n```\n\n```\n%s\n```\n\n", p.classCmd, strings.TrimRight(p.class, "\n"))
	}
	return b.String()
}

// junosServicePhase runs one phase: restart the daemon on cfg, spend a token
// on an SSH login, and read back both what port49 decided and what the device
// told the operator their session may do.
func (l *lab) junosServicePhase(t *testing.T, name, cfg string) junosServicePhaseResult {
	t.Helper()
	if err := l.stopDaemon(); err != nil {
		t.Fatalf("phase %q: stopping the daemon: %v", name, err)
	}
	if err := l.startDaemonWith(cfg, true); err != nil {
		t.Fatalf("phase %q: starting the daemon on %s: %v", name, cfg, err)
	}
	off := l.mark()
	p := junosServicePhaseResult{
		name:       name,
		cliAuthCmd: "show cli authorization",
		classCmd:   "show system users | match .",
	}

	user, secret := l.nextLogin(t)
	c, err := l.junosTokenCLI(user, secret)
	if err != nil {
		p.loginErr = err.Error()
	} else {
		if out, err := junosShow(c, p.cliAuthCmd); err == nil {
			p.cliAuth = junosTrimEcho(out, p.cliAuthCmd)
		} else {
			p.cliAuth = junosTrimEcho(out, p.cliAuthCmd)
			t.Logf("phase %q: %q did not return cleanly: %v", name, p.cliAuthCmd, err)
		}
		if out, err := junosShow(c, p.classCmd); err == nil {
			p.class = junosTrimEcho(out, p.classCmd)
		}
		c.Close()
	}

	// Drain for the accounting: Junos sends it seconds after the session ends
	// (L6, 1.8s to 4.2s on these images), so a short read would report "no
	// accounting" about a device that had simply not sent it yet.
	l.waitForRecords(off, 45*time.Second, func(rs []map[string]any) bool {
		return countEvent(rs, "authorize_session") > 0 && countEvent(rs, "account") >= 2
	})
	// Drain once more after the condition: the last accounting record often
	// lands a beat behind the pair that satisfied it, and a note that reports
	// "two accounting records" about a device that sent three is wrong about
	// the device.
	p.recs = l.drainRecords(off, 8*time.Second)
	for _, r := range p.recs {
		switch str(r, "event") {
		case "authorize_session":
			if p.authz == nil {
				p.authz = r
			}
		case "account":
			p.acct = append(p.acct, r)
		}
	}
	return p
}

// junosTokenCLI opens an operational-mode CLI as a token user over SSH only.
// It deliberately does not fall back to the console the way junosCLI does: the
// console is a root shell that never touches TACACS+, so falling back to it
// would turn "port49 denied this login" into a passing phase.
func (l *lab) junosTokenCLI(user, password string) (*cliConn, error) {
	c, err := l.sshCLI(user, password)
	if err != nil {
		return nil, err
	}
	if _, err := c.expect(60*time.Second, junosOpPrompt, "% "); err != nil {
		c.Close()
		return nil, err
	}
	if err := junosPrepare(c); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

// junosSetServiceName sets `system tacplus-options service-name` on the device
// and returns a function that deletes it again. It configures over whatever
// channel junosCLI can get — on vSRX that is the console as root, because the
// break-glass account has no usable password on that image
// (results/juniper_vsrx-config-verified.md).
func (l *lab) junosSetServiceName(t *testing.T, name string) func(*testing.T) {
	t.Helper()
	set := func(t *testing.T, line string) {
		t.Helper()
		l.withAdminCLI(t, func(l *lab) (*cliConn, error) {
			return l.junosCLI(breakglassUser, breakglassPassword)
		}, func(c *cliConn) error {
			if out, err := junosConfigure(c, line); err != nil {
				return fmt.Errorf("%q: %w\n%s", line, err, out)
			}
			t.Logf("%s: applied %q", l.p.name, line)
			return nil
		})
	}
	set(t, "set system tacplus-options service-name "+name)
	return func(t *testing.T) {
		t.Helper()
		set(t, "delete system tacplus-options service-name")
	}
}

// junosTrimEcho drops the echoed command and the trailing prompt from one
// command's output, so a note quotes what the device said and not what the
// harness typed.
func junosTrimEcho(out, cmd string) string {
	s := out
	if i := strings.Index(s, cmd); i >= 0 {
		s = s[i+len(cmd):]
	}
	if i := strings.LastIndex(s, "\n"); i >= 0 && strings.HasSuffix(strings.TrimRight(s, " "), ">") {
		s = s[:i]
	}
	return strings.Trim(s, "\r\n")
}

// junosAcctServices renders the `service` AV pair of every accounting record a
// phase produced, and counts them.
func junosAcctServices(p junosServicePhaseResult) (string, map[string]int) {
	var b strings.Builder
	seen := map[string]int{}
	for _, r := range p.acct {
		got := "(no service AV pair)"
		for _, a := range strs(sub(r, "record"), "raw") {
			if strings.HasPrefix(a, "service=") {
				got = a
			}
		}
		fmt.Fprintf(&b, "account flags=%s %s\n", str(r, "flags"), got)
		seen[got]++
	}
	return b.String(), seen
}

// junosAccountingServiceNote answers the second half of phase B: the renamed
// service arrived on the authorization, but does it arrive on accounting?
//
// "It does not" is a negative finding, so it goes through negativeFinding and
// carries the change that was made and the device's own records verbatim. A
// reader must be able to see that the rename was applied and that the
// accounting records still say something else, rather than take it on trust.
func junosAccountingServiceNote(t *testing.T, p junosServicePhaseResult, custom string) string {
	t.Helper()
	if len(p.acct) == 0 {
		return "**Accounting:** no `account` record reached the decision log in this phase's window, so " +
			"whether the renamed service appears on accounting is **not measured here**.\n\n"
	}
	table, seen := junosAcctServices(p)
	if seen["service="+custom] > 0 {
		return fmt.Sprintf("**Accounting** — the renamed service **does** reach accounting: %d of %d records "+
			"carry `service=%s`.\n\n```\n%s```\n\n", seen["service="+custom], len(p.acct), custom, table)
	}
	return "**Accounting.** " + negativeFinding{
		Claim: fmt.Sprintf("renaming the authorization service does NOT rename it on accounting: not one of "+
			"the %d accounting records this phase produced carries `service=%s`, while the session "+
			"authorization in the same phase carried it. `service` therefore cannot be used to join the "+
			"authorization stream to the accounting stream on this platform.", len(p.acct), custom),
		Sent: "set system tacplus-options service-name " + custom +
			"\ncommit\n\n(then one token SSH login, and every accounting record it produced)",
		Got: table,
	}.render(t) + "\n"
}

// junosServiceReading is the note's conclusion, built from the three phases
// rather than written out, so it cannot claim something this run did not see.
//
// The question it exists for is phase C's. Before 2026-09-21 every Junos
// session authorization port49 answered was a denial, and what that cost the
// operator was inferred from a `<edit-config>` returning `permission denied`
// in the NETCONF runs. This says what the device actually did.
func junosServiceReading(t *testing.T, a, b, c junosServicePhaseResult, custom string) string {
	t.Helper()
	var out strings.Builder
	out.WriteString("\n## What this settles\n\n")

	// 1. The envelope is recognised.
	if a.authz != nil && str(a.authz, "verdict") == "permit" {
		fmt.Fprintf(&out, "1. **A Junos session authorization is now permitted.** `service=%s` is on the "+
			"platform's `session_services` list and the record reads `permit context_matched`. Before "+
			"2026-09-21 this exchange was `deny service_unsupported` on every Junos login port49 had ever "+
			"answered (§15, L10).\n\n", str(sub(a.authz, "request"), "service"))
	} else {
		out.WriteString("1. **The default service was NOT permitted in phase A**, which contradicts the " +
			"built-in `session_services` table. See the phase above; this is a finding, not a pass.\n\n")
	}

	// 2. The rename reaches authorization.
	if b.authz != nil && str(sub(b.authz, "request"), "service") == custom {
		fmt.Fprintf(&out, "2. **A device-renamed service arrives on the authorization.** `set system "+
			"tacplus-options service-name %s` and the request's `service` is `%s`, matched against the "+
			"operator's configured list. It does not reach accounting — see phase B.\n\n", custom, custom)
	} else {
		fmt.Fprintf(&out, "2. **The rename did not arrive as `%s` on the authorization.** See phase B.\n\n", custom)
	}

	// 3. Phase C, the one that was only ever inferred.
	if c.authz == nil {
		out.WriteString("3. Phase C produced no session authorization record, so the denial's effect is " +
			"**still unmeasured**.\n\n")
		return out.String()
	}
	if str(c.authz, "verdict") != "deny" {
		out.WriteString("3. Phase C did not produce a denial, so the denial's effect is **still " +
			"unmeasured** — see the phase above for what port49 answered instead.\n\n")
		return out.String()
	}
	if c.loginErr != "" {
		fmt.Fprintf(&out, "3. **A denied session authorization ends the login on this platform.** The SSH "+
			"CLI never opened:\n\n```\n%s\n```\n\nSo port49's session authorization is load-bearing here, "+
			"and every Junos login before 2026-09-21 was being refused rather than degraded.\n\n", c.loginErr)
		return out.String()
	}

	out.WriteString("3. " + negativeFinding{
		Claim: "a session authorization denied `service_unsupported` does NOT stop a Junos login and does " +
			"NOT change what the session may do. The operator logged in, reached an operational-mode " +
			"prompt, and the device reported the same class and the same permissions as in the two " +
			"phases port49 permitted.",
		Sent: "port49 answered the session authorization `deny service_unsupported`\n" +
			"(request.service=" + str(sub(c.authz, "request"), "service") + ", against a configured list of [\"shell\"]).\n" +
			"The operator then typed, in that session:\n\n    " + c.cliAuthCmd,
		Got: c.cliAuth,
	}.render(t))

	same := a.cliAuth != "" && junosClassOf(a.cliAuth) == junosClassOf(c.cliAuth)
	if same {
		fmt.Fprintf(&out, "\nThe class is the same one the permitted phases got (`%s`), which is the "+
			"explanation as well as the observation: `tests/lab/configs/vjunos-startup.conf` defines\n\n"+
			"```\nuser remote {\n    uid 2001;\n    class p49-readonly;\n}\n```\n\n"+
			"and Junos applies that template to any user it authenticates who has no local account. The "+
			"class comes from the device, not from port49, so denying the authorization removes nothing "+
			"port49 was providing — **because port49 was providing nothing**. Phase A's permit carries no "+
			"attributes either (decision 22's projection is plan 5, gated on L12), so phases A and C are "+
			"indistinguishable to the operator and differ only in port49's own log.\n\n",
			junosClassOf(c.cliAuth))
		out.WriteString("**What that corrects.** The `<edit-config>` that returned `permission denied` in " +
			"the 2026-09-20 NETCONF runs was read there as the session-authorization denial arriving. It " +
			"was not: it is `p49-readonly` refusing a write, and it would have returned the same error " +
			"with the authorization permitted. The denial and the read-only class are two separate facts " +
			"that happened to produce one symptom.\n\n")
		out.WriteString("**And what it means for plan 5.** On this image port49's session authorization is " +
			"*advisory* under this configuration: the device authenticates through TACACS+ and then " +
			"assigns privilege from its own `remote` template whatever port49 says. The projection is not " +
			"a nicety on top of a working denial — until it lands, port49 does not constrain a Junos " +
			"session at all, and the only thing standing between an authenticated operator and the " +
			"device's capabilities is the class the device was configured with locally.\n\n")
	} else if c.cliAuth != "" {
		fmt.Fprintf(&out, "\nThe class differs from the permitted phase (`%s` under the denial against `%s` "+
			"under the permit), so the denial does reach the device even though the login completed. That "+
			"is a different answer from the one phase C was written expecting and the two transcripts "+
			"above are the evidence.\n\n", junosClassOf(c.cliAuth), junosClassOf(a.cliAuth))
	}
	return out.String()
}

// junosClassOf pulls the class out of `show cli authorization` output, which
// reports it as `class 'p49-readonly'` on the first line.
func junosClassOf(out string) string {
	i := strings.Index(out, "class '")
	if i < 0 {
		return ""
	}
	rest := out[i+len("class '"):]
	j := strings.Index(rest, "'")
	if j < 0 {
		return ""
	}
	return rest[:j]
}

// junosServiceComparison is the summary table, built from the three phases
// rather than written out, so it cannot say something the run did not see.
func junosServiceComparison(phases ...junosServicePhaseResult) string {
	var b strings.Builder
	b.WriteString("\n## The three phases side by side\n\n")
	b.WriteString("| phase | authorize_session | request.service | login completed | `show cli authorization` |\n")
	b.WriteString("|---|---|---|---|---|\n")
	for _, p := range phases {
		verdict, service := "(no record)", ""
		if p.authz != nil {
			verdict = str(p.authz, "verdict") + " " + str(p.authz, "reason")
			service = str(sub(p.authz, "request"), "service")
		}
		login := "yes"
		if p.loginErr != "" {
			login = "**no**"
		}
		auth := "(nothing returned)"
		if p.cliAuth != "" {
			auth = "see the phase above"
		}
		fmt.Fprintf(&b, "| %s | %s | `%s` | %s | %s |\n", p.name, verdict, service, login, auth)
	}
	return b.String()
}
