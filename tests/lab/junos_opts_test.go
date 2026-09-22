//go:build lab

package lab

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// TestJunosTacplusOptions measures the `system tacplus-options` statements that
// change what a port49 answer MEANS on Junos, against one deploy per image.
//
// It exists because of what the 2026-09-21 run measured and what a production
// operator then pointed at. The lab measured that on vSRX 21.4R3.15 and
// vJunos-router 23.4R2-S2.1 a session authorization port49 DENIED neither stops
// the login nor changes the session's class: under the reference configuration
// in tests/lab/configs/vjunos-startup.conf, Junos authorization is advisory and
// port49 constrains nothing (results/junos-session-service-*.md, §15 L10, L14).
// The owner, who runs Junos 23.4R2-S8.7 in production, then named the two
// statements that are supposed to change that and one production observation:
//
//	set system tacplus-options strict-authorization
//	set system tacplus-options enhanced-accounting
//	`show version` triggers an RPC that runs as root, so some accounting
//	records carry a user who is not the operator.
//
// Five items, in the order they run, all against one deploy:
//
//  5. every `tacplus-options` knob the image offers, verbatim. First because
//     it is one `?` and it tells items 1 and 4 what the image will accept.
//  1. strict-authorization: permit, deny, server down under two
//     authentication orders, an unanswered authorization, and NETCONF.
//  2. enhanced-accounting: the same login with and without it, diffed.
//  3. what the records of `show version`, `show chassis hardware`, a commit
//     and a NETCONF get-config carry in `user` — and what port49 does with a
//     record whose user is root.
//  4. authorization-time-interval: does the device re-authorize a live
//     session, and what does a DENIED re-authorization do to it.
//
// The rule from the L3-cisco_nxos defect applies throughout: a claim that this
// platform does not or cannot do something renders through negativeFinding,
// which fails the test rather than writing a note without the exact command
// sent and the device's exact reply.
func TestJunosTacplusOptions(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		if !strings.HasPrefix(l.p.name, "juniper_") {
			t.Skipf("`system tacplus-options` is a Junos statement; %s has no such hierarchy", l.p.name)
		}
		stop := l.capture(t, "L17")
		defer stop()

		s := &optsRun{l: l}
		s.permitCfg = s.config(t, "opts-permit", "")
		s.denyCfg = s.config(t, "opts-deny",
			"platforms:\n  juniper_junos:\n    session_services: [\"shell\"]\n")

		var b strings.Builder
		b.WriteString(s.item5Knobs(t))
		b.WriteString(s.item1Strict(t))
		b.WriteString(s.item2EnhancedAccounting(t))
		b.WriteString(s.item3RootRecords(t))
		b.WriteString(s.item4Interval(t))
		b.WriteString(s.reading())

		// Leave the device the way the topology deploys it, whatever happened
		// above: anything that runs after this test must not be measuring a
		// tacplus-options world this one left behind.
		s.restoreDevice(t)

		l.result(t, "L17", l17Claim, b.String())
		s.assert(t)
	})
}

const l17Claim = "Which `system tacplus-options` statements change what a port49 answer means on Junos: " +
	"whether `strict-authorization` makes a DENIED session authorization refuse the login (and what it " +
	"does to break-glass when port49d is down, which is the 3am case), what AV pairs `enhanced-accounting` " +
	"adds and to which record types, which accounting records carry a user that is not the logged-in " +
	"operator and what port49 does with them today, and whether `authorization-time-interval` re-authorizes " +
	"a live session so that a revocation can reach it."

// ---------------------------------------------------------------------------
// Logins of this test's own
// ---------------------------------------------------------------------------

// junosOptsPoolSize is how many `jopt<NN>` logins tests/lab/port49d-lab.yaml
// seeds per NAS. This test spends about a dozen across five items and the
// alice pool is sixteen for the whole run, so it has a pool of its own.
const junosOptsPoolSize = 20

var (
	optsTokenMu sync.Mutex
	optsTokenN  = map[string]int{}
)

// nextOptsLogin hands out the next unspent `jopt<NN>` login for this platform.
// Redemption deletes the token, so every login spends one — except where a
// caller deliberately presents a spent one again, which is the receipt path
// and is the measurement in item 2.
func (l *lab) nextOptsLogin(t *testing.T) (user, secret string) {
	t.Helper()
	optsTokenMu.Lock()
	optsTokenN[l.p.name]++
	n := optsTokenN[l.p.name]
	optsTokenMu.Unlock()
	if n > junosOptsPoolSize {
		t.Fatalf("%s: this test's seeded login pool of %d is exhausted; seed more `jopt` logins in "+
			"tests/lab/port49d-lab.yaml", l.p.name, junosOptsPoolSize)
	}
	user = fmt.Sprintf("jopt%02d", n)
	return user, l.mustLogin(t, user)
}

// ---------------------------------------------------------------------------
// The run's own state
// ---------------------------------------------------------------------------

// optsRun carries what the five items have to share: the two daemon configs,
// what is committed on the device right now, and the assertions the test makes
// at the end. Everything an item finds is rendered into the note as it goes.
type optsRun struct {
	l *lab

	permitCfg string // port49 authorizes `junos-exec`: the session authorization permits
	denyCfg   string // port49 authorizes `shell` alone: every Junos session authorization is denied

	// committed is the set of `tacplus-options` statements this test has left
	// on the device, so restoreDevice deletes exactly those.
	committed []string

	// strictRefused and enhancedRefused record that this IMAGE does not offer
	// a statement at all, which is a finding and not a failure: the sections
	// below them then measure nothing, and the assertions must not demand
	// records from a phase that could never run.
	strictRefused   bool
	enhancedRefused bool

	// What the items measured, for the assertions and the reading.
	knobs          string
	strictPermit   optsLogin
	strictDeny     optsLogin
	breakglass     []optsBreakglassCell
	unanswered     string
	netconfStrict  string
	acctPlain      []acctRow
	acctEnhanced   []acctRow
	addedKeys      []string
	rootRows       []acctRow
	intervalReply  string
	intervalSet    time.Duration
	reauthFindings []string
}

func (s *optsRun) config(t *testing.T, suffix, extra string) string {
	t.Helper()
	// "[]" and not "": the Junos platforms send no session attributes in this
	// lab (platformSessionAttributes in harness_test.go), and a phase that sent
	// `shell:roles*network-admin` would be measuring an attribute set no Junos
	// measurement has ever used.
	cfg, err := s.l.derivedConfig(suffix, `[]`, extra)
	if err != nil {
		t.Fatalf("derive the %s daemon config: %v", suffix, err)
	}
	return cfg
}

// useConfig restarts port49d on cfg. Every item that changes what port49
// answers goes through this rather than restarting by hand, so the resume flag
// is never forgotten: a truncated decision log would invalidate every offset an
// earlier mark() handed out.
func (s *optsRun) useConfig(t *testing.T, cfg string) {
	t.Helper()
	if err := s.l.stopDaemon(); err != nil {
		t.Fatalf("stopping port49d to put it on %s: %v", cfg, err)
	}
	if err := s.l.startDaemonWith(cfg, true); err != nil {
		t.Fatalf("starting port49d on %s: %v", cfg, err)
	}
}

// admin runs fn against a break-glass CLI with port49d STOPPED, and restarts
// the daemon on restartCfg afterwards.
//
// Stopping it is the same rule withAdminCLI documents: with the daemon running
// the device asks port49 about `breakglass`, and what happens next is the
// measurement rather than a precondition a configuration change may depend on.
// This is withAdminCLI with two differences it needs — the caller chooses which
// config the daemon comes back on, and fn's error is RETURNED rather than
// fatal, because item 4's whole question is whether the device refuses a
// statement and what it says when it does.
func (s *optsRun) admin(t *testing.T, restartCfg string, fn func(*cliConn) (string, error)) (string, error) {
	t.Helper()
	if restartCfg == "" {
		restartCfg = s.permitCfg
	}
	if err := s.l.stopDaemon(); err != nil {
		t.Fatalf("could not stop port49d before opening an admin CLI: %v", err)
	}
	restart := func() {
		if err := s.l.startDaemonWith(restartCfg, true); err != nil {
			t.Fatalf("restarting port49d after the admin CLI: %v", err)
		}
	}
	c, err := s.l.junosCLI(breakglassUser, breakglassPassword)
	if err != nil {
		restart()
		t.Fatalf("no admin CLI (port49d was stopped for this, so the device should have taken the "+
			"local password): %v", err)
	}
	out, fnErr := fn(c)
	c.Close()
	restart()
	return out, fnErr
}

// optsReadBack is how every statement this test sets is PROVED to be in force.
// Nothing here trusts a commit that said nothing: the hierarchy is read back
// after each change, and the phase that follows says which world it ran in.
const optsReadBack = "show configuration system tacplus-options | display set | no-more"

// stmtResult is one configuration change: what the device said, whether the
// commit completed, and what the hierarchy holds afterwards.
//
// The read-back is the point. A `set` of a leaf an image does not have is
// refused at parse time and enters nothing, and a commit of an unchanged
// candidate then completes perfectly — so "the commit succeeded" is not
// evidence that the statement is in force, and a run that took it for evidence
// would spend forty minutes waiting for a re-authorization under a statement
// the device never accepted, and write it up as measured.
type stmtResult struct {
	lines    []string
	applied  bool   // the commit completed
	reply    string // the device's exact words along the way
	readBack string // `show configuration system tacplus-options | display set`
	err      error
}

// carries reports whether the read-back shows the leaf actually in the
// configuration. `applied && carries(leaf)` is the only thing this test treats
// as "the statement is in force".
func (r stmtResult) carries(leaf string) bool {
	return strings.Contains(r.readBack, "tacplus-options "+leaf)
}

func (r stmtResult) render() string {
	var b strings.Builder
	fmt.Fprintf(&b, "\n```\n%s\ncommit\n```\n\n", strings.Join(r.lines, "\n"))
	if strings.TrimSpace(r.reply) != "" {
		fmt.Fprintf(&b, "The device said:\n\n```\n%s\n```\n\n", trimForNote(redactSecrets(strings.TrimSpace(r.reply))))
	}
	fmt.Fprintf(&b, "`%s` then showed:\n\n```\n%s\n```\n\n", optsReadBack,
		trimForNote(redactSecrets(firstNonEmpty(r.readBack,
			"(the hierarchy is empty: no `system tacplus-options` statement is configured)"))))
	return b.String()
}

// apply commits configuration lines over the admin CLI and reads the
// `tacplus-options` hierarchy back. It never fails the test: "this image
// refuses that statement, and here is what it said" is a finding, and it is one
// of the things this run was sent to collect.
func (s *optsRun) apply(t *testing.T, restartCfg string, lines ...string) stmtResult {
	t.Helper()
	res := stmtResult{lines: lines}
	out, err := s.admin(t, restartCfg, func(c *cliConn) (string, error) {
		o, e := junosApply(c, lines...)
		rb, _ := junosShow(c, optsReadBack)
		res.readBack = strings.TrimSpace(stripPrompt(junosTrimEcho(rb, optsReadBack)))
		return o, e
	})
	res.reply, res.err, res.applied = strings.TrimSpace(out), err, err == nil
	if err != nil {
		t.Logf("%s: %v was not applied: %v", s.l.p.name, lines, err)
	} else {
		t.Logf("%s: committed %v", s.l.p.name, lines)
	}
	return res
}

// junosApply is junosConfigure with the one behaviour this test needs and that
// one does not have: it DISCARDS the candidate when anything goes wrong.
//
// Junos' plain `configure` is a shared candidate. A statement this image
// refuses, or a commit that does not complete, leaves whatever was typed in
// that candidate — and the next phase's commit would carry it along with its
// own change, silently, so a later measurement would run under a statement no
// phase meant to set. `rollback` before leaving makes that impossible.
func junosApply(c *cliConn, lines ...string) (string, error) {
	if _, err := c.sendExpect("configure", 60*time.Second, junosCfgPrompt); err != nil {
		return c.transcript(), fmt.Errorf("entering configuration mode: %w", err)
	}
	var b strings.Builder
	discard := func(format string, a ...any) (string, error) {
		_, _ = c.sendExpect("rollback", 60*time.Second, junosCfgPrompt)
		_, _ = c.sendExpect("exit", 60*time.Second, junosOpPrompt)
		return b.String(), fmt.Errorf(format, a...)
	}
	for _, ln := range lines {
		out, err := c.sendExpect(ln, 60*time.Second, junosCfgPrompt)
		b.WriteString(strings.TrimSpace(stripPrompt(junosTrimEcho(out, ln))) + "\n")
		if err != nil {
			return discard("%q: %w", ln, err)
		}
		if junosRefused(out) {
			return discard("the device refused %q", ln)
		}
	}
	out, err := c.sendExpect("commit", 180*time.Second, "commit complete", "error:", "failed")
	b.WriteString(strings.TrimSpace(stripPrompt(junosTrimEcho(out, "commit"))) + "\n")
	if err != nil {
		return discard("commit: %w", err)
	}
	if !strings.Contains(out, "commit complete") {
		return discard("the commit did not complete")
	}
	if _, err := c.sendExpect("exit", 60*time.Second, junosOpPrompt); err != nil {
		return b.String(), fmt.Errorf("leaving configuration mode: %w", err)
	}
	return b.String(), nil
}

// junosRefused reads a configuration-mode reply for a refusal.
//
// It is wider than junosConfigure's two markers on purpose. A leaf an image
// does not have is a `syntax error`; a value outside a leaf's range is
// `Value N is not within range`, which junosConfigure would have walked
// straight past and then committed an unchanged candidate — reporting the
// statement as accepted. `warning:` is deliberately NOT here: deleting a leaf
// that is not configured warns and is not a failure.
func junosRefused(out string) bool {
	for _, marker := range []string{
		"syntax error", "unknown command", "error:", "not within range",
		"invalid value", "is not recognized",
	} {
		if strings.Contains(out, marker) {
			return true
		}
	}
	return false
}

// track remembers a `tacplus-options` leaf this test set, so restoreDevice can
// delete exactly what was added and nothing else.
func (s *optsRun) track(leaf string) {
	for _, l := range s.committed {
		if l == leaf {
			return
		}
	}
	s.committed = append(s.committed, leaf)
}

func (s *optsRun) restoreDevice(t *testing.T) {
	t.Helper()
	var lines []string
	for _, leaf := range s.committed {
		lines = append(lines, "delete system tacplus-options "+leaf)
	}
	// The class swap item 3 needs is undone here too, whichever way that item
	// ended: a `remote` template left on a configure-capable class would give
	// every later test's token operator more than the lab's reference config
	// grants, silently.
	lines = append(lines,
		"delete system login class "+optsRPCClass,
		"set system login user remote class p49-readonly",
		"delete system authentication-order",
		"set system authentication-order [ tacplus password ]")
	if r := s.apply(t, s.permitCfg, lines...); !r.applied {
		t.Errorf("the device was NOT restored to its deployed configuration: %v\n%s",
			r.err, redactSecrets(r.reply))
	}
}

// ---------------------------------------------------------------------------
// One login, in the three steps an operator experiences separately
// ---------------------------------------------------------------------------

// optsLogin is one attempt at an interactive session, recorded in the three
// steps that fail separately and mean different things.
//
// The distinction is the whole point of item 1(b). "The login was refused" is
// three different device behaviours: SSH authentication refused (the device
// never let the credential through), the shell channel refused or closed
// (authenticated, then thrown out), or a session that opened normally. An
// operator sees a different thing in each case and a results note that calls
// all three "refused" has measured none of them.
type optsLogin struct {
	name   string
	user   string
	cfg    string // which daemon config was answering
	device string // what was committed on the device

	dialErr   string // SSH authentication refused; this is the CLIENT's message
	shellErr  string // authenticated, but no shell
	promptErr string // shell opened, no prompt arrived
	opened    bool

	transcript string // everything the device said on the channel
	cliAuth    string // `show cli authorization`
	cmdOut     map[string]string

	authz map[string]any
	recs  []map[string]any
	acct  []acctRow
}

func (p optsLogin) outcome() string {
	switch {
	case p.dialErr != "":
		return "**SSH authentication refused**"
	case p.shellErr != "":
		return "**authenticated, no shell**"
	case p.promptErr != "":
		return "**shell opened, no prompt**"
	case p.opened:
		return "logged in"
	}
	return "**not attempted**"
}

// optsSession opens a session in the three separate steps and runs cmds in it.
// It deliberately does not fall back to the console the way junosCLI does: the
// console is a root shell that never touches TACACS+, so a fallback would turn
// "the device refused this login" into a passing phase.
func (l *lab) optsSession(t *testing.T, name, user, secret string, cmds ...string) (optsLogin, *cliConn) {
	t.Helper()
	p := optsLogin{name: name, user: user, cmdOut: map[string]string{}}

	// Step 1 — SSH authentication. This is where port49 answers the
	// authentication START, and on a device that refuses an authorization at
	// the PAM account stage it is also where that refusal lands.
	cl, err := l.dial(user, secret, 120*time.Second)
	if err != nil {
		p.dialErr = err.Error()
		return p, nil
	}

	// Step 2 — the shell channel.
	c, err := cliOn(cl, "SSH CLI as "+user)
	if err != nil {
		p.shellErr = err.Error()
		cl.Close()
		return p, nil
	}

	// Step 3 — the prompt.
	if _, err := c.expect(90*time.Second, junosOpPrompt, "% "); err != nil {
		p.promptErr = err.Error()
		p.transcript = c.transcript()
		c.Close()
		return p, nil
	}
	p.opened = true
	if err := junosPrepare(c); err != nil {
		t.Logf("%s: `set cli screen-length 0` did not answer: %v", name, err)
	}
	// A `show` that does not return cleanly is not an error here: whatever the
	// device said is the measurement, and junosTrimEcho renders it either way.
	cliAuthOut, _ := junosShow(c, "show cli authorization")
	p.cliAuth = junosTrimEcho(cliAuthOut, "show cli authorization")
	for _, cmd := range cmds {
		out, err := junosShow(c, cmd)
		if err != nil {
			t.Logf("%s: %q did not return cleanly: %v", name, cmd, err)
		}
		p.cmdOut[cmd] = junosTrimEcho(out, cmd)
	}
	p.transcript = c.transcript()
	return p, c
}

// cliOn wraps an SSH client that is already authenticated in a cliConn. It is
// sshCLI's second half, split out so that optsSession can tell an SSH
// authentication failure apart from a shell that would not open — which on a
// device with strict-authorization committed is the difference between the
// authorization being enforced at authentication and at session start.
func cliOn(cl *ssh.Client, name string) (*cliConn, error) {
	s, err := cl.NewSession()
	if err != nil {
		return nil, fmt.Errorf("open a session channel: %w", err)
	}
	if err := s.RequestPty("vt100", 200, 200, ssh.TerminalModes{ssh.ECHO: 0}); err != nil {
		s.Close()
		return nil, fmt.Errorf("request pty: %w", err)
	}
	in, err := s.StdinPipe()
	if err != nil {
		s.Close()
		return nil, err
	}
	buf := &syncBuf{}
	s.Stdout, s.Stderr = buf, buf
	if err := s.Shell(); err != nil {
		s.Close()
		return nil, fmt.Errorf("start shell: %w", err)
	}
	return &cliConn{
		name: name,
		in:   in,
		out:  buf,
		close: func() {
			in.Close()
			go s.Wait()
			s.Close()
			cl.Close()
		},
	}, nil
}

// drain waits for this phase's records and sorts them into the phase. Junos
// sends accounting seconds after the session ends (L6: 1.8s to 4.2s on these
// images), so a short read would report "no accounting" about a device that had
// simply not sent it yet.
func (p *optsLogin) drain(l *lab, off int64) {
	// A login that never opened produces no session accounting to wait for, so
	// waiting the full window for records that cannot arrive only slows the run
	// down; the authorization record is still the thing to wait for, because on
	// a refused login it is the only evidence there is.
	window := 60 * time.Second
	if !p.opened {
		window = 25 * time.Second
	}
	l.waitForRecords(off, window, func(rs []map[string]any) bool {
		return countEvent(rs, "authorize_session") > 0 &&
			(!p.opened || countEvent(rs, "account") >= 2)
	})
	p.recs = l.drainRecords(off, 8*time.Second)
	for _, r := range p.recs {
		switch str(r, "event") {
		case "authorize_session":
			if p.authz == nil {
				p.authz = r
			}
		case "account":
			p.acct = append(p.acct, acctRowOf(r))
		}
	}
}

func (p optsLogin) render() string {
	var b strings.Builder
	fmt.Fprintf(&b, "\n#### %s\n\n", p.name)
	fmt.Fprintf(&b, "Committed on the device: `%s`. port49 was answering from `%s`.\n\n",
		p.device, p.cfg)
	fmt.Fprintf(&b, "**Outcome: %s.**\n\n", p.outcome())

	switch {
	case p.dialErr != "":
		b.WriteString("The SSH client never got past authentication. This string is the **Go SSH client's**, " +
			"not the device's — an operator at a terminal sees their own client's wording of the same " +
			"event, and what the DEVICE said is in its own log below:\n\n```\n" + p.dialErr + "\n```\n\n")
	case p.shellErr != "":
		b.WriteString("SSH authentication **succeeded** and the session channel did not:\n\n```\n" +
			p.shellErr + "\n```\n\n")
	case p.promptErr != "":
		b.WriteString("The shell started and no prompt ever arrived:\n\n```\n" + p.promptErr + "\n```\n\n")
	}
	if p.transcript != "" {
		b.WriteString("What the device wrote on the channel:\n\n```\n" +
			trimForNote(redactSecrets(p.transcript)) + "\n```\n\n")
	}

	if p.authz == nil {
		b.WriteString("port49 wrote **no `authorize_session` record at all** for this attempt.\n\n")
	} else {
		req := sub(p.authz, "request")
		ses := sub(p.authz, "session")
		fmt.Fprintf(&b, "port49's own record:\n\n```\nevent=authorize_session verdict=%s reason=%s\n"+
			"    request.service=%q request.raw=%v\n    port=%q rem_addr=%q\n```\n\n",
			str(p.authz, "verdict"), str(p.authz, "reason"), str(req, "service"), strs(req, "raw"),
			str(ses, "port"), str(ses, "rem_addr"))
	}
	if p.cliAuth != "" {
		fmt.Fprintf(&b, "What the device says the session may do:\n\n```\nshow cli authorization\n```\n\n```\n%s\n```\n\n",
			strings.TrimRight(p.cliAuth, "\n"))
	}
	for _, cmd := range sortedKeys(p.cmdOut) {
		fmt.Fprintf(&b, "```\n%s\n```\n\n```\n%s\n```\n\n", cmd, trimForNote(strings.TrimRight(p.cmdOut[cmd], "\n")))
	}
	if len(p.acct) > 0 {
		fmt.Fprintf(&b, "Accounting for this attempt (%d records):\n\n%s\n", len(p.acct), acctTable(p.acct))
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// Accounting records, field by field
// ---------------------------------------------------------------------------

// acctRow is one accounting record reduced to the fields item 2 diffs and item
// 3 reads: who the device says did it, on what port, under what task, and what
// port49 made of it.
type acctRow struct {
	flags      string
	user       string
	port       string
	remAddr    string
	taskID     string
	sessionPID string
	cmd        string
	service    string
	attribution
	raw []string
}

// attribution is what port49 concluded about the record, kept as its own type
// so the note can say plainly that a record naming root resolves to nothing.
type attribution struct {
	verdict   string // the `attribution` field: resolved | unattributed
	principal string
	ctxID     string
}

func acctRowOf(r map[string]any) acctRow {
	ses := sub(r, "session")
	rec := sub(r, "record")
	raw := strs(rec, "raw")
	return acctRow{
		flags:      str(r, "flags"),
		user:       str(ses, "username"),
		port:       str(ses, "port"),
		remAddr:    str(ses, "rem_addr"),
		taskID:     str(r, "task_id"),
		sessionPID: avOf(raw, "session_pid"),
		cmd:        avOf(raw, "cmd"),
		service:    avOf(raw, "service"),
		attribution: attribution{
			verdict:   str(r, "attribution"),
			principal: str(r, "principal"),
			ctxID:     str(ses, "ctx_id"),
		},
		raw: raw,
	}
}

// splitAcctAV splits one ACCOUNTING AV pair at its first separator and TRIMS
// both halves. (register_test.go has a splitAV of its own for authorization
// requests; it does not trim, and no device has sent a spaced argument on one.)
//
// The trimming is a measurement, not tidiness. vSRX 21.4R3.15 sends
//
//	session_pid = 31050
//
// with a space on each side of the `=`, where every other argument in the same
// record is `key=value` with none. A matcher that required `key=` missed it
// entirely — and `session_pid` is the one field that separates two concurrent
// sessions of one user, so the first run of this test published a table saying
// nothing distinguished them beside a record dump that plainly did. Measured
// 2026-09-21; this function is that defect's fix.
//
// Both separators are accepted because RFC 8907 spells a mandatory argument
// `key=value` and an optional one `key*value`, and a device may use either.
func splitAcctAV(a string) (key, value string, ok bool) {
	i := strings.IndexAny(a, "=*")
	if i < 0 {
		return strings.TrimSpace(a), "", false
	}
	return strings.TrimSpace(a[:i]), strings.TrimSpace(a[i+1:]), true
}

// avOf returns the value of one AV pair.
func avOf(raw []string, key string) string {
	for _, a := range raw {
		if k, v, ok := splitAcctAV(a); ok && k == key {
			return v
		}
	}
	return ""
}

// avKeys is the set of argument NAMES a record carried, which is what item 2
// diffs: enhanced-accounting is a claim about which AV pairs appear, not about
// their values.
func avKeys(raw []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, a := range raw {
		k, _, _ := splitAcctAV(a)
		if k != "" && !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func acctTable(rows []acctRow) string {
	var b strings.Builder
	b.WriteString("| flags | `user` | `port` | `rem_addr` | `task_id` | `session_pid` | `service` | `cmd` | port49 `attribution` |\n")
	b.WriteString("|---|---|---|---|---|---|---|---|---|\n")
	for _, r := range rows {
		fmt.Fprintf(&b, "| %s | `%s` | `%s` | `%s` | `%s` | `%s` | `%s` | `%s` | `%s` |\n",
			r.flags, r.user, r.port, r.remAddr, r.taskID, dash(r.sessionPID), dash(r.service),
			oneLine(dash(r.cmd)), r.attribution.verdict)
	}
	return b.String()
}

// acctRaw dumps every AV pair of every record verbatim. The table above is a
// reading of the records; this is the records, and it is what makes the
// enhanced-accounting diff checkable by someone who does not trust the diff.
func acctRaw(rows []acctRow) string {
	var b strings.Builder
	b.WriteString("```\n")
	for _, r := range rows {
		fmt.Fprintf(&b, "account flags=%s user=%s\n", r.flags, r.user)
		for _, a := range r.raw {
			fmt.Fprintf(&b, "    %s\n", a)
		}
	}
	b.WriteString("```\n")
	return b.String()
}

func dash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// keySetsByFlags collects, per record type, the union of AV pair names seen.
// "Per record type" is the brief's own question — the owner says
// enhanced-accounting adds fields to login records only — so the diff is
// computed per flags value rather than over the whole stream, where a field
// added to one record type would look like a field added to all of them.
func keySetsByFlags(rows []acctRow) map[string][]string {
	byFlags := map[string]map[string]bool{}
	for _, r := range rows {
		kind := r.flags + "/" + recordKind(r)
		if byFlags[kind] == nil {
			byFlags[kind] = map[string]bool{}
		}
		for _, k := range avKeys(r.raw) {
			byFlags[kind][k] = true
		}
	}
	out := map[string][]string{}
	for kind, set := range byFlags {
		var ks []string
		for k := range set {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		out[kind] = ks
	}
	return out
}

// recordKind names what a record is about, from the arguments it carries.
//
// `login` and `logout` are separated from every other `cmd=` because they are
// the record type the whole of item 2 is about: the owner's claim is that
// `enhanced-accounting` adds fields to LOGIN accounting only, and lumping the
// login record in with the interactive-command records under one "command"
// label hides the very distinction the diff exists to show.
func recordKind(r acctRow) string {
	switch {
	case r.cmd == "login":
		return "login"
	case r.cmd == "logout":
		return "logout"
	case r.cmd != "":
		return "command"
	case r.service != "":
		return "service=" + r.service
	}
	return "session"
}

// operatorRows keeps the records belonging to the named users and drops the
// rest.
//
// The rest are this harness's own noise, and the first run of this test
// published them as a finding: every `tacplus-options` change goes in over an
// admin CLI as `breakglass`, Junos accounts for those commands like any other,
// and the accounting drain that follows a phase catches them. Item 3 then
// reported "10 of 27 records name a user who is not the operator" — all ten of
// them `breakglass`, the harness talking to itself, in answer to a question
// about `root`. A note that counts the instrument as the measurement is worse
// than no note.
func operatorRows(rows []acctRow, users ...string) []acctRow {
	keep := map[string]bool{}
	for _, u := range users {
		keep[u] = true
	}
	var out []acctRow
	for _, r := range rows {
		if keep[r.user] {
			out = append(out, r)
		}
	}
	return out
}

// otherUserRows is operatorRows' complement, minus this harness's own admin
// account: the records that name somebody neither the operator nor the test
// itself. On Junos that is what the production `root` observation is about.
func otherUserRows(rows []acctRow, users ...string) []acctRow {
	skip := map[string]bool{breakglassUser: true}
	for _, u := range users {
		skip[u] = true
	}
	var out []acctRow
	for _, r := range rows {
		if !skip[r.user] {
			out = append(out, r)
		}
	}
	return out
}

// missingFrom returns the members of want that are not in have.
func missingFrom(want, have []string) []string {
	in := map[string]bool{}
	for _, h := range have {
		in[h] = true
	}
	var out []string
	for _, w := range want {
		if !in[w] {
			out = append(out, w)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Item 5 — what the image offers
// ---------------------------------------------------------------------------

// item5Knobs lists every `tacplus-options` leaf the image will accept, straight
// from the device's own completion help. It runs first and costs one `?`: items
// 1 and 4 are both asking for statements that may not exist on a given image,
// and this is the image saying which do.
func (s *optsRun) item5Knobs(t *testing.T) string {
	t.Helper()
	out, err := s.admin(t, s.permitCfg, func(c *cliConn) (string, error) {
		if _, err := c.sendExpect("configure", 60*time.Second, junosCfgPrompt); err != nil {
			return "", fmt.Errorf("entering configuration mode: %w", err)
		}
		var b strings.Builder
		for _, prefix := range []string{
			"set system tacplus-options",
			"set system tacplus-options authorization-time-interval",
		} {
			help, err := junosHelp(c, prefix)
			fmt.Fprintf(&b, "\n`%s ?`\n\n```\n%s\n```\n", prefix, strings.TrimRight(help, "\n"))
			if err != nil {
				fmt.Fprintf(&b, "\n(the completion listing did not come back cleanly: %v)\n", err)
			}
		}
		// `rollback` before `exit`, and it is not belt and braces. If the Ctrl-U
		// in junosHelp ever failed to erase the redisplayed line, the newline
		// after it would submit `set system tacplus-options` as a statement and
		// leave it in the SHARED candidate — where the next `junosConfigure` in
		// this run would commit it along with whatever that phase meant to set.
		// A candidate this function discards cannot do that.
		if _, err := c.sendExpect("rollback", 60*time.Second, junosCfgPrompt); err != nil {
			return b.String(), fmt.Errorf("discarding the candidate: %w", err)
		}
		if _, err := c.sendExpect("exit", 60*time.Second, junosOpPrompt); err != nil {
			return b.String(), fmt.Errorf("leaving configuration mode: %w", err)
		}
		return b.String(), nil
	})
	if err != nil {
		t.Logf("%s: the tacplus-options completion listing did not come back cleanly: %v", s.l.p.name, err)
	}
	s.knobs = out

	var b strings.Builder
	b.WriteString("## 5. Every `tacplus-options` knob this image offers\n\n")
	b.WriteString("Listed, not measured: this is the device's own completion help, verbatim, so that a reader " +
		"can see which of the statements below exist on this release before reading what they did.\n")
	b.WriteString(redactSecrets(out))
	return b.String()
}

// junosHelp types `<prefix> ?` WITHOUT a newline and reads the completion
// listing, then erases the line.
//
// The `?` is not a command: Junos answers it the instant it is typed and then
// redisplays the partial line. Sending it with cliConn.send, which appends a
// newline, would submit `set system tacplus-options` as a statement — which on
// a container node either commits nothing or raises a syntax error, and in
// either case the transcript would no longer be a listing. Ctrl-U (0x15)
// erases the redisplayed line, so nothing this function types can reach the
// candidate configuration.
func junosHelp(c *cliConn, prefix string) (string, error) {
	from := len(c.transcript())
	if _, err := fmt.Fprint(c.in, prefix+" ?"); err != nil {
		return "", err
	}
	_, err := c.expectFrom(from, 45*time.Second, "Possible completions:", "syntax error", "unknown command")
	// The listing arrives in several reads; give it a moment to finish before
	// taking the transcript, or a note quotes half a table.
	time.Sleep(3 * time.Second)
	out := c.transcript()[from:]
	if _, werr := fmt.Fprint(c.in, "\x15\n"); werr != nil {
		return out, werr
	}
	if _, cerr := c.expectFrom(len(c.transcript()), 45*time.Second, junosCfgPrompt); cerr != nil && err == nil {
		err = cerr
	}
	return strings.TrimRight(out, " \t"), err
}

// ---------------------------------------------------------------------------
// Item 1 — strict-authorization
// ---------------------------------------------------------------------------

func (s *optsRun) item1Strict(t *testing.T) string {
	t.Helper()
	l := s.l
	var b strings.Builder
	b.WriteString("\n## 1. `set system tacplus-options strict-authorization`\n\n")

	st := s.apply(t, s.permitCfg, "set system tacplus-options strict-authorization")
	b.WriteString("Applied for every attempt in this section:\n")
	b.WriteString(st.render())
	if !st.applied || !st.carries("strict-authorization") {
		s.strictRefused = true
		b.WriteString(negativeFinding{
			Claim: "this image does not put `strict-authorization` into force: either it refused the " +
				"statement outright or the commit completed and left the `system tacplus-options` " +
				"hierarchy without it. Nothing below it in this section was measured, because there is " +
				"no `strict-authorization` on this image to measure.",
			Sent: "set system tacplus-options strict-authorization\ncommit\n" + optsReadBack,
			Got: firstNonEmpty(st.reply, st.readBack,
				"(the read-back showed an empty `system tacplus-options` hierarchy)"),
		}.render(t))
		b.WriteString("\nItem 5's completion listing is the image's own statement of which leaves it " +
			"does offer under `tacplus-options`.\n")
		return b.String()
	}
	s.track("strict-authorization")

	// (a) port49 permits.
	b.WriteString("\n### (a) port49 PERMITS the session authorization\n")
	off := l.mark()
	user, secret := l.nextOptsLogin(t)
	p, c := l.optsSession(t, "(a) permit, strict-authorization committed", user, secret)
	if c != nil {
		c.Close()
	}
	p.cfg, p.device = "session_services: [junos-exec] (the built-in default)", "strict-authorization"
	p.drain(l, off)
	s.strictPermit = p
	b.WriteString(p.render())

	// (b) port49 denies on purpose.
	b.WriteString("\n### (b) port49 DENIES the session authorization on purpose\n\n")
	b.WriteString("port49 is configured to authorize `shell` alone, so a Junos `junos-exec` request is denied " +
		"`service_unsupported` — the same condition that stood on every Junos login port49 answered before " +
		"2026-09-21 (§15 L10), and the condition the 2026-09-21 run measured to be **advisory** without " +
		"`strict-authorization`.\n")
	s.useConfig(t, s.denyCfg)
	off = l.mark()
	user, secret = l.nextOptsLogin(t)
	p, c = l.optsSession(t, "(b) deny, strict-authorization committed", user, secret)
	if c != nil {
		c.Close()
	}
	p.cfg, p.device = "session_services: [shell] — every Junos session authorization denied", "strict-authorization"
	p.drain(l, off)
	s.strictDeny = p
	b.WriteString(p.render())

	// What the DEVICE said about that refusal, in its own words. The client's
	// error string is the client's; this is the device's.
	// `| match <user> | no-more` and NOT `| last 20 | no-more`. With `last` in
	// the pipeline the first run of this test got back exactly
	//
	//	---(more 100%)---
	//
	// and nothing else: the pager ran despite `no-more`, and the note quoted a
	// paging prompt where the device's own explanation should have been.
	devLogCmd := "show log messages | match " + p.user + " | no-more"
	deviceLog, logErr := s.admin(t, s.denyCfg, func(c *cliConn) (string, error) {
		return junosShow(c, devLogCmd)
	})
	deviceLog = junosTrimEcho(deviceLog, devLogCmd)
	b.WriteString("\n**What the device itself logged for that attempt**, which is the operator's real answer " +
		"to \"why was I refused\":\n\n")
	if logErr != nil || strings.TrimSpace(stripPrompt(deviceLog)) == "" {
		fmt.Fprintf(&b, "```\n%s\n```\n\n```\n%s\n```\n\n",
			devLogCmd, "(nothing matching this login reached `messages` on this image, or the command did not "+
				"return: "+fmt.Sprint(logErr)+")")
	} else {
		fmt.Fprintf(&b, "```\n%s\n```\n\n```\n%s\n```\n\n",
			devLogCmd, trimForNote(redactSecrets(strings.TrimSpace(stripPrompt(deviceLog)))))
	}

	// The comparison that is the point of (a) and (b).
	b.WriteString(s.strictVerdict(t))

	// (c) break-glass with port49d stopped, under both authentication orders.
	b.WriteString(s.item1cBreakglass(t))

	// (d) an authorization nobody answers.
	b.WriteString(s.item1dUnanswered(t))

	// (e) NETCONF.
	b.WriteString(s.item1eNETCONF(t))
	return b.String()
}

// strictVerdict is the (a)/(b) reading, built from the two attempts rather than
// written out, so it cannot claim something this run did not see.
func (s *optsRun) strictVerdict(t *testing.T) string {
	t.Helper()
	a, d := s.strictPermit, s.strictDeny
	var b strings.Builder
	b.WriteString("\n### (a) against (b)\n\n")
	b.WriteString("| | port49 answered | login | class the device gave |\n|---|---|---|---|\n")
	for _, p := range []optsLogin{a, d} {
		verdict := "(no record)"
		if p.authz != nil {
			verdict = str(p.authz, "verdict") + " " + str(p.authz, "reason")
		}
		fmt.Fprintf(&b, "| %s | %s | %s | `%s` |\n", p.name, verdict, p.outcome(), junosClassOf(p.cliAuth))
	}
	b.WriteString("\n")

	if d.authz == nil || str(d.authz, "verdict") != "deny" {
		b.WriteString("**(b) did not produce a denial**, so what `strict-authorization` does to one is not " +
			"measured here. See the attempt above for what port49 answered instead.\n")
		return b.String()
	}
	if !d.opened {
		fmt.Fprintf(&b, "**`strict-authorization` makes a denied session authorization binding on this image.** "+
			"The same denial that completed a login on 2026-09-21 now ends it at the %s step. That is the "+
			"statement the reference configuration in `tests/lab/configs/vjunos-startup.conf` is missing, and "+
			"without it port49's session authorization constrains nothing on Junos.\n",
			strings.Trim(d.outcome(), "*"))
		return b.String()
	}

	// The negative: the statement is committed and the denial still does not
	// bind. That is a claim about what this platform cannot do, so it renders
	// through negativeFinding or the test fails.
	b.WriteString(negativeFinding{
		Claim: "with `set system tacplus-options strict-authorization` committed, a session authorization " +
			"port49 denied `service_unsupported` STILL does not stop the login on this image: the operator " +
			"reached an operational-mode prompt and the device reported the same class as the permitted " +
			"attempt. `strict-authorization` is therefore not the statement that makes a port49 denial " +
			"binding here.",
		Sent: "set system tacplus-options strict-authorization\ncommit\n\n" +
			"(then one token SSH login as " + d.user + ", which port49 answered\n" +
			" deny service_unsupported, followed in that session by:)\n\n    show cli authorization",
		Got: firstNonEmpty(d.cliAuth, d.transcript, emptyDeviceReply),
	}.render(t))
	return b.String()
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// optsBreakglassCell is one (authentication-order, server condition) attempt by
// the local break-glass account: the 3am case.
type optsBreakglassCell struct {
	order     string
	condition string
	attempted bool
	ok        bool
	took      time.Duration
	err       string
	note      string
}

// item1cBreakglass is the question that decides whether `strict-authorization`
// can be recommended at all.
//
// The statement is an authorization knob, and the failure it could cause is an
// authentication one: if committing it means the local account cannot get in
// while port49 is down, then the statement that makes port49's denials binding
// also makes port49 a single point of failure for the device. That is the 3am
// case — the broker is unreachable, the store is down, and somebody has to get
// into the box.
func (s *optsRun) item1cBreakglass(t *testing.T) string {
	t.Helper()
	l := s.l
	var b strings.Builder
	b.WriteString("\n### (c) port49d stopped entirely — can break-glass still get in?\n\n")
	b.WriteString("`strict-authorization` is committed for every cell below. The account is the local " +
		"`" + breakglassUser + "` with its local password, over SSH, with port49d **not listening** — so the " +
		"device sees the server as unreachable, which is the one condition L4 measured a local password " +
		"being taken at all.\n\n")

	for i, order := range l4JunosOrders {
		if err := l.stopDaemon(); err != nil {
			t.Fatalf("could not stop port49d, so the unreachable condition could not be created: %v", err)
		}
		if i > 0 {
			// Switch the order with the server already down, for L4's reason:
			// doing it with port49d up would make the configuration change
			// depend on the behaviour under test.
			c, err := l.junosCLI(breakglassUser, breakglassPassword)
			if err != nil {
				s.breakglass = append(s.breakglass, optsBreakglassCell{order: order.shown,
					condition: "port49d not listening",
					note:      "the device could not be reached on any CLI channel to set this order: " + err.Error()})
				break
			}
			out, err := junosConfigure(c, "delete system authentication-order", order.set)
			c.Close()
			if err != nil {
				s.breakglass = append(s.breakglass, optsBreakglassCell{order: order.shown,
					condition: "port49d not listening",
					note:      fmt.Sprintf("the order could not be set: %v (device said: %s)", err, oneLine(redactSecrets(out)))})
				break
			}
		}
		cell := optsBreakglassCell{order: order.shown, condition: "port49d not listening", attempted: true}
		t0 := time.Now()
		cl, err := l.dial(breakglassUser, breakglassPassword, 120*time.Second)
		cell.took = time.Since(t0)
		if err == nil {
			cell.ok = true
			cl.Close()
		} else {
			cell.err = err.Error()
		}
		s.breakglass = append(s.breakglass, cell)
	}

	// Put the order back and the daemon up before anything else runs.
	if r := s.apply(t, s.permitCfg,
		"delete system authentication-order", l4JunosOrders[0].set); !r.applied {
		t.Errorf("the authentication order was not restored after item 1(c): %v", r.err)
	}

	b.WriteString("| `authentication-order` | port49d | `" + breakglassUser + "` over SSH | took |\n|---|---|---|---|\n")
	for _, c := range s.breakglass {
		outcome := "**not measured**"
		took := "—"
		switch {
		case !c.attempted:
			outcome = "**not measured**: " + c.note
		case c.ok:
			outcome = "**logged in**"
			took = c.took.Round(10 * time.Millisecond).String()
		default:
			outcome = "refused"
			took = c.took.Round(10 * time.Millisecond).String()
		}
		fmt.Fprintf(&b, "| `%s` | not listening | %s | %s |\n", c.order, outcome, took)
	}
	b.WriteString("\n")
	for _, c := range s.breakglass {
		if c.attempted && !c.ok {
			fmt.Fprintf(&b, "Under `%s` the client was refused with:\n\n```\n%s\n```\n\n", c.order, c.err)
		}
	}
	return b.String()
}

// item1dUnanswered produces the state the brief asks for: port49 answers the
// AUTHENTICATION and is then gone before the AUTHORIZATION.
//
// It is produced without a race where the device allows it. SSH authentication
// and the session channel are two steps the client controls separately, so if
// Junos sends the session authorization when the SHELL starts rather than when
// the password is checked, the daemon can be stopped in between deterministically
// — and whether it does is itself worth knowing, because it says where in the
// login a revocation could still land.
//
// If the authorization has already arrived by the time authentication returns,
// that route cannot produce the state and this says so rather than pretending:
// a racing kill would sometimes win and sometimes not, and a note that cannot
// say which happened is not a measurement.
func (s *optsRun) item1dUnanswered(t *testing.T) string {
	t.Helper()
	l := s.l
	var b strings.Builder
	b.WriteString("\n### (d) port49 answers the authentication and is gone before the authorization\n\n")

	s.useConfig(t, s.permitCfg)
	off := l.mark()
	user, secret := l.nextOptsLogin(t)

	cl, err := l.dial(user, secret, 120*time.Second)
	if err != nil {
		fmt.Fprintf(&b, "**Not produced.** The SSH authentication itself failed, so there was no "+
			"authenticated session to strand:\n\n```\n%s\n```\n\n", err)
		s.unanswered = "not produced: authentication failed"
		return b.String()
	}

	// Did the session authorization already happen, inside SSH authentication?
	recs := l.waitForRecords(off, 10*time.Second, func(rs []map[string]any) bool {
		return countEvent(rs, "authorize_session") > 0
	})
	early := countEvent(recs, "authorize_session") > 0

	if early {
		cl.Close()
		b.WriteString("**The session authorization arrives during SSH authentication on this image, not when " +
			"the shell starts.** Ten seconds after the SSH client finished authenticating — and before it had " +
			"asked for a session channel at all — port49 had already answered the `authorize_session`:\n\n")
		fmt.Fprintf(&b, "```%s\n```\n\n", summarize(recs))
		b.WriteString("So the two exchanges cannot be separated from the client side, and this run does **not** " +
			"produce the stranded-authorization state by stopping the daemon between them. A racing kill " +
			"would win sometimes and lose sometimes, and a note that cannot say which happened for the " +
			"attempt it is describing measures nothing.\n\n")
		b.WriteString("What it does settle, and it is the more useful half: **a revocation has no window here.** " +
			"Authentication and authorization are one event to the operator, so there is no point between " +
			"them at which port49 could change its mind about a login already in flight. Whatever makes a " +
			"Junos session stop has to reach an ALREADY ESTABLISHED session, which is what item 4 asks.\n")
		s.unanswered = "not produced; the authorization arrives inside SSH authentication"
		return b.String()
	}

	// The deterministic route: the authorization has not happened yet, so stop
	// the daemon and then ask for the shell.
	b.WriteString("The session authorization had **not** been sent ten seconds after SSH authentication " +
		"completed, so it is sent when the session channel opens. port49d was therefore stopped here, " +
		"with an authenticated SSH connection already open, and the shell requested afterwards — which is " +
		"exactly the state the brief asks for, produced without a race.\n\n")
	if err := l.stopDaemon(); err != nil {
		t.Fatalf("stopping port49d between the authentication and the authorization: %v", err)
	}
	c, shellErr := cliOn(cl, "SSH CLI as "+user+", shell requested with port49d stopped")
	var transcript, promptErr string
	if shellErr == nil {
		if _, perr := c.expect(120*time.Second, junosOpPrompt, "% "); perr != nil {
			promptErr = perr.Error()
		}
		transcript = c.transcript()
		c.Close()
	} else {
		cl.Close()
	}
	if err := l.startDaemonWith(s.permitCfg, true); err != nil {
		t.Fatalf("restarting port49d after the unanswered-authorization attempt: %v", err)
	}

	switch {
	case shellErr != nil:
		fmt.Fprintf(&b, "**The shell was refused.** With `strict-authorization` committed and nothing "+
			"answering the authorization, the authenticated session got no shell:\n\n```\n%s\n```\n\n", shellErr)
		s.unanswered = "shell refused"
	case promptErr != "":
		fmt.Fprintf(&b, "**The shell opened and no prompt arrived.**\n\n```\n%s\n```\n\n", promptErr)
		s.unanswered = "no prompt"
	default:
		fmt.Fprintf(&b, "**The login completed anyway**, with `strict-authorization` committed and the "+
			"authorization unanswered. The device wrote:\n\n```\n%s\n```\n\n",
			trimForNote(redactSecrets(transcript)))
		s.unanswered = "login completed with the authorization unanswered"
	}
	return b.String()
}

// item1eNETCONF asks whether strict-authorization reaches port 830. It matters
// because NETCONF is where the automation is: a statement that binds an
// interactive login and not an RPC session would leave the larger half of the
// traffic unconstrained.
func (s *optsRun) item1eNETCONF(t *testing.T) string {
	t.Helper()
	l := s.l
	var b strings.Builder
	b.WriteString("\n### (e) NETCONF on port 830, with `strict-authorization` committed\n\n")
	if netconfPort(l.p) == "" {
		b.WriteString("This lab does not enable NETCONF on this platform, so nothing was measured here.\n")
		return b.String()
	}

	type cell struct {
		name    string
		cfg     string
		err     string
		hello   string
		reply   string
		authz   map[string]any
		opened  bool
		records []map[string]any
	}
	var cells []cell
	for _, c := range []struct{ name, cfg string }{
		{"port49 permits", s.permitCfg},
		{"port49 denies `service_unsupported`", s.denyCfg},
	} {
		s.useConfig(t, c.cfg)
		off := l.mark()
		user, secret := l.nextOptsLogin(t)
		out := cell{name: c.name, cfg: c.cfg}
		n, hello, err := l.netconfDial(user, secret)
		out.hello = hello
		if err != nil {
			out.err = err.Error()
		} else {
			out.opened = true
			reply, rerr := n.rpc(1, `<get-configuration><configuration><system><host-name/></system></configuration></get-configuration>`)
			out.reply = reply
			if rerr != nil {
				out.err = rerr.Error()
			}
			n.Close()
		}
		out.records = l.waitForRecords(off, 45*time.Second, func(rs []map[string]any) bool {
			return countEvent(rs, "authorize_session") > 0
		})
		for _, r := range out.records {
			if str(r, "event") == "authorize_session" {
				out.authz = r
				break
			}
		}
		cells = append(cells, out)
	}

	b.WriteString("| port49 answered | NETCONF session | `<get-configuration>` |\n|---|---|---|\n")
	for _, c := range cells {
		verdict := "(no authorize_session record)"
		if c.authz != nil {
			verdict = str(c.authz, "verdict") + " " + str(c.authz, "reason")
		}
		open := "**refused**"
		if c.opened {
			open = "opened"
		}
		rpc := "—"
		if c.reply != "" {
			rpc = "see below"
		}
		fmt.Fprintf(&b, "| %s | %s | %s |\n", verdict, open, rpc)
	}
	b.WriteString("\n")
	for _, c := range cells {
		fmt.Fprintf(&b, "**%s.**\n\n", c.name)
		if c.err != "" {
			fmt.Fprintf(&b, "```\n%s\n```\n\n", trimForNote(c.err))
		}
		if c.reply != "" {
			fmt.Fprintf(&b, "```\n%s\n```\n\n", trimForNote(redactSecrets(c.reply)))
		}
		if c.authz == nil {
			b.WriteString("port49 wrote no `authorize_session` record for this attempt.\n\n")
		}
	}
	s.netconfStrict = fmt.Sprintf("%d cells", len(cells))
	return b.String()
}

// ---------------------------------------------------------------------------
// Item 2 — enhanced-accounting
// ---------------------------------------------------------------------------

// optsAcctProbe is the identical session run under both accounting settings.
// Identical is the point: any AV pair that appears in one and not the other is
// the statement's doing and nothing else's.
var optsAcctProbe = []string{"show version", "show system uptime"}

func (s *optsRun) item2EnhancedAccounting(t *testing.T) string {
	t.Helper()
	l := s.l
	var b strings.Builder
	b.WriteString("\n## 2. `set system tacplus-options enhanced-accounting`\n\n")
	b.WriteString("The same session, twice: log in with a token, run `" + strings.Join(optsAcctProbe, "`, `") +
		"`, log out, and collect every accounting record. Once without the statement and once with it, " +
		"nothing else changed.\n")

	// Without. strict-authorization comes off first so that this section is
	// measuring one statement rather than two.
	if !s.strictRefused {
		s.apply(t, s.permitCfg, "delete system tacplus-options strict-authorization")
		s.untrack("strict-authorization")
	}

	off := l.mark()
	user, secret := l.nextOptsLogin(t)
	plain, c := l.optsSession(t, "without enhanced-accounting", user, secret, optsAcctProbe...)
	if c != nil {
		c.Close()
	}
	plain.cfg, plain.device = "(the permitting config)", "no tacplus-options statement"
	plain.drain(l, off)
	// The operator's own records only. Applying the statement above went in
	// over an admin CLI as `breakglass`, Junos accounts for those commands like
	// any other, and their accounting lands inside this phase's drain window —
	// so the raw set holds a handful of records belonging to the instrument
	// rather than to the measurement.
	s.acctPlain = operatorRows(plain.acct, user)
	fmt.Fprintf(&b, "\n### Without the statement — %d records for `%s`\n\n%s\n%s\n",
		len(s.acctPlain), user, acctTable(s.acctPlain), acctRaw(s.acctPlain))

	// With.
	st := s.apply(t, s.permitCfg, "set system tacplus-options enhanced-accounting")
	b.WriteString(st.render())
	if !st.applied || !st.carries("enhanced-accounting") {
		s.enhancedRefused = true
		b.WriteString("\n" + negativeFinding{
			Claim: "this image does not put `enhanced-accounting` into force: either it refused the " +
				"statement outright or the commit completed and left the `system tacplus-options` " +
				"hierarchy without it. What it adds is therefore not measurable on this image, and the " +
				"records above are what this image sends with no `tacplus-options` statement at all.",
			Sent: "set system tacplus-options enhanced-accounting\ncommit\n" + optsReadBack,
			Got: firstNonEmpty(st.reply, st.readBack,
				"(the read-back showed an empty `system tacplus-options` hierarchy)"),
		}.render(t))
		return b.String()
	}
	s.track("enhanced-accounting")

	off = l.mark()
	user, secret = l.nextOptsLogin(t)
	enhanced, c := l.optsSession(t, "with enhanced-accounting", user, secret, optsAcctProbe...)
	if c != nil {
		c.Close()
	}
	enhanced.cfg, enhanced.device = "(the permitting config)", "enhanced-accounting"
	enhanced.drain(l, off)
	s.acctEnhanced = operatorRows(enhanced.acct, user)
	fmt.Fprintf(&b, "\n### With `enhanced-accounting` — %d records for `%s`\n\n%s\n%s\n",
		len(s.acctEnhanced), user, acctTable(s.acctEnhanced), acctRaw(s.acctEnhanced))

	b.WriteString(s.acctDiff(t))
	b.WriteString(s.item2Concurrent(t))
	return b.String()
}

// untrack forgets a statement this test has deleted again, so restoreDevice
// does not delete a leaf that is already gone and turn a clean restore into an
// error nobody needs to read.
func (s *optsRun) untrack(leaf string) {
	out := s.committed[:0]
	for _, l := range s.committed {
		if l != leaf {
			out = append(out, l)
		}
	}
	s.committed = out
}

// acctDiff is the answer to "every added AV pair exactly as spelled, on which
// record types". It is computed from the two record sets rather than written
// out, and a statement that added nothing renders as a negative finding with
// both sets behind it.
func (s *optsRun) acctDiff(t *testing.T) string {
	t.Helper()
	var b strings.Builder
	b.WriteString("\n### What `enhanced-accounting` added\n\n")
	if len(s.acctPlain) == 0 || len(s.acctEnhanced) == 0 {
		b.WriteString("**Not measured.** One of the two runs produced no accounting records at all, so there " +
			"is nothing to diff.\n")
		return b.String()
	}

	plain, enh := keySetsByFlags(s.acctPlain), keySetsByFlags(s.acctEnhanced)
	var kinds []string
	for k := range enh {
		kinds = append(kinds, k)
	}
	for k := range plain {
		if _, ok := enh[k]; !ok {
			kinds = append(kinds, k)
		}
	}
	sort.Strings(kinds)

	b.WriteString("| record (`flags`/kind) | AV pairs added | AV pairs no longer sent |\n|---|---|---|\n")
	var allAdded []string
	for _, kind := range kinds {
		added := missingFrom(enh[kind], plain[kind])
		gone := missingFrom(plain[kind], enh[kind])
		allAdded = append(allAdded, added...)
		fmt.Fprintf(&b, "| `%s` | %s | %s |\n", kind, codeList(added), codeList(gone))
	}
	b.WriteString("\n")

	sort.Strings(allAdded)
	s.addedKeys = uniqueStrings(allAdded)

	if len(s.addedKeys) == 0 {
		b.WriteString(negativeFinding{
			Claim: "`set system tacplus-options enhanced-accounting` adds NO AV pair to any accounting record " +
				"this session produced on this image: the argument names are the same set with the statement " +
				"committed as without it.",
			Sent: "set system tacplus-options enhanced-accounting\ncommit\n\n" +
				"(then the identical token login and the identical commands as the run above)",
			Got: "With the statement committed, the accounting records carried:\n\n" +
				strings.TrimSpace(acctRaw(s.acctEnhanced)),
		}.render(t))
		return b.String()
	}

	fmt.Fprintf(&b, "**Added, exactly as the device spells them:** %s.\n\n", codeList(s.addedKeys))
	b.WriteString("Each one, with a value the device actually sent:\n\n```\n")
	for _, k := range s.addedKeys {
		for _, r := range s.acctEnhanced {
			if v := avOf(r.raw, k); v != "" {
				fmt.Fprintf(&b, "%-20s on flags=%s/%s: %s=%s\n", k, r.flags, recordKind(r), k, v)
				break
			}
		}
	}
	b.WriteString("```\n")
	return b.String()
}

func codeList(vs []string) string {
	if len(vs) == 0 {
		return "—"
	}
	out := make([]string, len(vs))
	for i, v := range vs {
		out[i] = "`" + v + "`"
	}
	return strings.Join(out, ", ")
}

func uniqueStrings(vs []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range vs {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

// item2Concurrent answers the clause the brief puts last and that matters most
// for reconciliation: does anything enhanced-accounting adds tell two live
// sessions of ONE user apart?
//
// Two concurrent sessions of one user on a single-use token is the receipt path
// (§13, decision 15): the second login presents the same spent credential and
// is permitted out of the receipt. That is deliberately the shape a real
// ten-worker automation job has, and it is the shape in which port49's own
// `ctx_id` is the same for both sessions — so if the device does not
// distinguish them either, nothing downstream can.
func (s *optsRun) item2Concurrent(t *testing.T) string {
	t.Helper()
	l := s.l
	var b strings.Builder
	b.WriteString("\n### Two concurrent sessions of the same user\n\n")

	off := l.mark()
	user, secret := l.nextOptsLogin(t)

	// Both authentications go on the wire back to back, before either session
	// is used for anything. That is not tidiness: the receipt has a 30s TTL by
	// default, and a second login that waited for the first session to finish
	// running commands would be refused `token_not_found` on the timer rather
	// than measuring anything about accounting.
	cl1, err := l.dial(user, secret, 120*time.Second)
	if err != nil {
		fmt.Fprintf(&b, "**Not measured**: the first session did not authenticate (%v).\n", err)
		return b.String()
	}
	cl2, err2 := l.dial(user, secret, 120*time.Second)
	if err2 != nil {
		cl1.Close()
		fmt.Fprintf(&b, "**Not measured**: the second concurrent login for `%s`, presenting the same spent "+
			"token, did not authenticate (%v). On a single-use token a second login is only permitted out "+
			"of the receipt, so that is a receipt result rather than an accounting one.\n", user, err2)
		return b.String()
	}
	c1, e1 := cliOn(cl1, "SSH CLI as "+user+" (session 1)")
	c2, e2 := cliOn(cl2, "SSH CLI as "+user+" (session 2)")
	if e1 != nil || e2 != nil {
		if c1 != nil {
			c1.Close()
		}
		if c2 != nil {
			c2.Close()
		}
		fmt.Fprintf(&b, "**Not measured**: both logins authenticated and a shell did not open (%v / %v).\n", e1, e2)
		return b.String()
	}
	for _, c := range []*cliConn{c1, c2} {
		if _, err := c.expect(90*time.Second, junosOpPrompt, "% "); err != nil {
			t.Logf("%s: a concurrent session did not reach a prompt: %v", l.p.name, err)
			continue
		}
		_ = junosPrepare(c)
		_, _ = junosShow(c, "show system users | match .")
	}
	c1.Close()
	c2.Close()

	// A flat drain rather than optsLogin.drain: this phase's answer is a COUNT
	// of records across two sessions, so there is nothing to wait *for* — only
	// a window long enough that a late record cannot be mistaken for an absent
	// one. Junos sends its session accounting 1.8s to 4.2s after a session ends
	// (L6), and both sessions have just ended.
	var rows []acctRow
	for _, r := range l.drainRecords(off, 45*time.Second) {
		if str(r, "event") == "account" {
			rows = append(rows, acctRowOf(r))
		}
	}
	rows = operatorRows(rows, user)
	fmt.Fprintf(&b, "Two sessions of `%s` were open at once (the second presented the same, spent, token and "+
		"was permitted out of the receipt). Their accounting, %d records:\n\n%s\n%s\n",
		user, len(rows), acctTable(rows), acctRaw(rows))

	// Which fields actually differ between the two sessions' LOGIN records.
	//
	// The login records and not the whole stream, and that is the difference
	// between a useful answer and a wrong one: `task_id` is per record, so
	// across a stream it takes many values whether or not the two sessions are
	// distinguishable, and a table built over every record would list it beside
	// the fields that genuinely separate the sessions.
	//
	// Every AV pair the device sent is examined rather than a hard-coded five.
	// The first run of this test asked about `rem_addr` alone and answered "no
	// accounting record carries the client's source port" while the records
	// beside it carried `Port=45566` and `Port=45554` — one per session. A
	// question about "any added field" has to be asked of every field.
	logins := loginRows(rows)
	if len(logins) < 2 {
		fmt.Fprintf(&b, "\nOnly %d `cmd=login` record%s arrived for the two sessions, so which fields "+
			"separate them is **not measured** here.\n", len(logins), plural(len(logins)))
		return b.String()
	}

	fields := map[string]map[string]bool{}
	note := func(k, v string) {
		if fields[k] == nil {
			fields[k] = map[string]bool{}
		}
		fields[k][v] = true
	}
	for _, r := range logins {
		note("port (TACACS+ header)", r.port)
		note("rem_addr (TACACS+ header)", r.remAddr)
		note("ctx_id (port49's own)", r.attribution.ctxID)
		for _, a := range r.raw {
			if k, v, ok := splitAcctAV(a); ok {
				note(k, v)
			}
		}
	}
	var keys []string
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var separators []string
	fmt.Fprintf(&b, "\nThe two `cmd=login` records, field by field:\n\n"+
		"| field | distinct values across the two sessions | separates them |\n|---|---|---|\n")
	for _, k := range keys {
		var vs []string
		for v := range fields[k] {
			vs = append(vs, v)
		}
		sort.Strings(vs)
		sep := "no"
		if len(vs) > 1 {
			sep = "**yes**"
			separators = append(separators, k)
		}
		fmt.Fprintf(&b, "| `%s` | %s | %s |\n", k, codeList(vs), sep)
	}

	if len(separators) == 0 {
		b.WriteString("\n" + negativeFinding{
			Claim: "NO field of either login record separates two concurrent sessions of one user on this " +
				"image: every argument the device sent, and every TACACS+ header field, holds the same " +
				"value in both. Two shells of one operator are indistinguishable in the accounting stream.",
			Sent: "(two concurrent token logins as " + user + ", the second presenting the same spent token\n" +
				" and permitted out of the receipt; every accounting record they produced)",
			Got: strings.TrimSpace(acctRaw(logins)),
		}.render(t))
		return b.String()
	}

	fmt.Fprintf(&b, "\n**%s separate the two sessions.** port49's own `ctx_id` does not — one context "+
		"covers both, which is decision 15 behaving as specified — so anything that needs to tell two "+
		"shells of one operator apart has to carry one of these forward from the record.\n",
		codeList(separators))
	return b.String()
}

// loginRows keeps the `cmd=login` records, which are the per-session records:
// one per shell, carrying whatever the device knows about that shell at the
// moment it starts.
func loginRows(rows []acctRow) []acctRow {
	var out []acctRow
	for _, r := range rows {
		if r.cmd == "login" {
			out = append(out, r)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Item 3 — the records that name somebody else
// ---------------------------------------------------------------------------

// optsRPCClass is a login class with enough permission to enter configuration
// mode and commit.
//
// It exists because the lab's `remote` template is `class p49-readonly`
// (`permissions [ view view-configuration ]`), under which a token operator
// cannot run `configure` at all — and a `configure`/`commit` is one of the four
// activities item 3 is asked to account for. The class is created for this item
// and deleted again in restoreDevice, and the note says which activity was
// measured under which class, because "what accounting arrives for a commit"
// read under a class that cannot commit would measure the refusal instead.
const optsRPCClass = "p49-rpc"

func (s *optsRun) item3RootRecords(t *testing.T) string {
	t.Helper()
	l := s.l
	var b strings.Builder
	b.WriteString("\n## 3. Which accounting records name a user who is not the operator\n\n")
	b.WriteString("The production observation this item exists for: `show version` triggers an RPC that runs " +
		"as root, so some records carry a user who is not the person who typed the command. " +
		"`enhanced-accounting` is committed for this section.\n\n")
	b.WriteString("The token operator is given a class that can commit for the duration of this item:\n\n" +
		"```\nset system login class " + optsRPCClass + " permissions all\n" +
		"set system login user remote class " + optsRPCClass + "\ncommit\n```\n\n" +
		"The lab's deployed template is `class p49-readonly` (`permissions [ view view-configuration ]`), " +
		"under which `configure` is refused outright — so a commit could not be accounted for at all. " +
		"The class is deleted again at the end of this test.\n")

	if r := s.apply(t, s.permitCfg,
		"set system login class "+optsRPCClass+" permissions all",
		"set system login user remote class "+optsRPCClass); !r.applied {
		fmt.Fprintf(&b, "\n**The class swap did not commit** (%v), so the `configure`/`commit` half of this "+
			"item runs under the deployed `p49-readonly` class and is expected to be refused. The device "+
			"said:\n\n```\n%s\n```\n\n", r.err, trimForNote(redactSecrets(r.reply)))
	}

	off := l.mark()
	user, secret := l.nextOptsLogin(t)
	p, c := l.optsSession(t, "item 3 — RPC activity", user, secret,
		"show version", "show chassis hardware")
	if c == nil {
		fmt.Fprintf(&b, "\n**Not measured**: the session did not open (%s).\n",
			firstNonEmpty(p.dialErr, p.shellErr, p.promptErr))
		return b.String()
	}
	// A configure/commit in the same session, so its records sit beside the
	// show commands' in one stream under one login. junosApply and not
	// junosConfigure: this one runs as the TOKEN operator, whose class may
	// refuse the statement half-way, and a refusal that left the change in the
	// shared candidate would be committed by restoreDevice at the end of the
	// test — a device left configured by a phase that failed.
	commitOut, commitErr := junosApply(c, "set system location building port49-lab-L17")
	if commitErr != nil {
		t.Logf("%s: the item-3 commit did not complete: %v", l.p.name, commitErr)
	}
	c.Close()

	// A NETCONF get-config as its own session, because that is how automation
	// reaches the device and the question is what user its records name.
	ncUser, ncSecret := l.nextOptsLogin(t)
	ncReply, ncErr := func() (string, error) {
		n, _, err := l.netconfDial(ncUser, ncSecret)
		if err != nil {
			return "", err
		}
		defer n.Close()
		return n.rpc(1, `<get-config><source><running/></source></get-config>`)
	}()

	p.drain(l, off)
	// `breakglass` is dropped here and the reason is a defect this test
	// published on its first run: the class swap above goes in over an admin
	// CLI as that account, Junos accounts for every one of those commands, and
	// this item then reported "10 of 27 records name a user who is not the
	// operator" — all ten of them the harness talking to itself, in answer to a
	// question about `root`. otherUserRows is what the question actually asks.
	all := p.acct
	rows := operatorRows(all, user, ncUser)
	s.rootRows = otherUserRows(all, user, ncUser)

	fmt.Fprintf(&b, "\nThe operator was `%s` over SSH and `%s` over NETCONF. What the device accounted for "+
		"under those two names, %d of the %d records in the window (the rest belong to the `%s` admin "+
		"session this test used to swap the class, and are excluded):\n\n%s\n%s\n",
		user, ncUser, len(rows), len(all), breakglassUser, acctTable(rows), acctRaw(rows))

	fmt.Fprintf(&b, "\n```\nconfigure\nset system location building port49-lab-L17\ncommit\n```\n\n```\n%s\n```\n",
		trimForNote(redactSecrets(strings.TrimSpace(stripPrompt(commitOut)))))
	if ncErr != nil {
		fmt.Fprintf(&b, "\nThe NETCONF `<get-config>`:\n\n```\n%s\n```\n", trimForNote(ncErr.Error()))
	} else {
		fmt.Fprintf(&b, "\nThe NETCONF `<get-config>` returned %d bytes; its first lines:\n\n```\n%s\n```\n",
			len(ncReply), trimForNote(redactSecrets(ncReply)))
	}

	b.WriteString("\n### The records that name somebody else\n\n")
	if len(s.rootRows) == 0 {
		b.WriteString(negativeFinding{
			Claim: fmt.Sprintf("every accounting record this activity produced names the logged-in operator "+
				"(`%s` or `%s`): NOT ONE carries `root` or any other user, on this image, under this "+
				"accounting configuration (`events [ login change-log interactive-commands ]`), with "+
				"`enhanced-accounting` committed.", user, ncUser),
			Sent: "show version\nshow chassis hardware\nconfigure; set system location building port49-lab-L17; commit\n" +
				"<get-config><source><running/></source></get-config>\n\n" +
				"(every accounting record port49 received in that window, excluding the\n " + breakglassUser +
				" admin session this test used to swap the login class)",
			// rows, not all: the Sent line above says the admin session is
			// excluded, so showing it here would contradict the claim it is
			// evidence for.
			Got: strings.TrimSpace(acctRaw(rows)),
		}.render(t))
		b.WriteString("\nThat is a finding about **this image under this accounting configuration**, not a " +
			"contradiction of the production observation. The lab accounts for " +
			"`events [ login change-log interactive-commands ]`; a fleet that also accounts for other event " +
			"classes may well see records the lab's event list never asks the device to send. What it does " +
			"settle is that the four activities named in the brief — `show version`, `show chassis " +
			"hardware`, a `configure`/`commit` and a NETCONF `<get-config>` — do not by themselves produce " +
			"a record under another name on this image.\n")
		return b.String()
	}

	fmt.Fprintf(&b, "**%d records name a user who is neither the operator nor this test's own `%s` admin "+
		"session.**\n\n%s\n", len(s.rootRows), breakglassUser, acctTable(s.rootRows))
	b.WriteString("\n**What port49 does with them today.** The `attribution` column above is the answer and " +
		"it is not a good one: accounting attributes on `(nas, username)` (`internal/daemon/acct/acct.go`), " +
		"port49 holds no login context for `root`, so each of these records is spooled `unattributed` with " +
		"no `principal` and an empty `ctx_id`. It is never discarded — spec §5.7 — but nothing joins it to " +
		"the operator whose command caused it. In the audit trail the command is attributed and its effect " +
		"is not.\n")
	return b.String()
}

// ---------------------------------------------------------------------------
// Item 4 — authorization-time-interval
// ---------------------------------------------------------------------------

// optsIntervalCandidates are the values tried, smallest first. The units are
// not assumed: item 5's completion listing states them, and whichever value
// commits is reported with the device's own word for its unit.
var optsIntervalCandidates = []int{1, 5, 10, 15}

// optsIntervalBudget bounds what this item may spend waiting. A re-authorization
// interval is measured by holding a session across it, so the wall clock is the
// instrument; this is the ceiling past which the item reports what it reached
// rather than running the `go test` timeout out from under every later item.
const optsIntervalBudget = 60 * time.Minute

func (s *optsRun) item4Interval(t *testing.T) string {
	t.Helper()
	var b strings.Builder
	b.WriteString("\n## 4. `set system tacplus-options authorization-time-interval`\n\n")
	b.WriteString("This is the revocation question. port49 can stop issuing tokens in an instant; what it " +
		"cannot do is reach a session that is already open. If the device re-sends the session authorization " +
		"on a timer, a denial on the second pass is a revocation that lands on a live session — and if it " +
		"does not, nothing port49 decides after a login has begun can affect it.\n\n")

	// Find a value this image accepts, and PROVE it landed: a `set` of a leaf
	// this image does not have enters nothing, and the commit of an unchanged
	// candidate then completes perfectly.
	var accepted int
	var last stmtResult
	for _, v := range optsIntervalCandidates {
		r := s.apply(t, s.permitCfg,
			"set system tacplus-options authorization-time-interval "+strconv.Itoa(v))
		last = r
		if r.applied && r.carries("authorization-time-interval") {
			accepted = v
			s.track("authorization-time-interval")
			break
		}
	}
	s.intervalReply = firstNonEmpty(last.reply, last.readBack)
	b.WriteString(last.render())

	if accepted == 0 {
		b.WriteString(negativeFinding{
			Claim: "this image does not accept `set system tacplus-options authorization-time-interval` at " +
				"any of the values tried (" + joinInts(optsIntervalCandidates) + "), so there is no periodic " +
				"re-authorization to measure on it and a port49 revocation cannot reach a live session by " +
				"this route.",
			Sent: "set system tacplus-options authorization-time-interval " + joinInts(optsIntervalCandidates) +
				"\n(each tried on its own, each followed by commit and by\n " + optsReadBack + ")",
			Got: firstNonEmpty(s.intervalReply, emptyDeviceReply),
		}.render(t))
		b.WriteString("\nThe completion listing in item 5 is the image's own statement of which leaves it does " +
			"offer under `tacplus-options`.\n")
		return b.String()
	}

	interval := time.Duration(accepted) * time.Minute
	s.intervalSet = interval
	fmt.Fprintf(&b, "The image accepted `authorization-time-interval %d`. **The unit is not assumed here**: "+
		"item 5's completion listing is the device's own statement of it, and this section reads the interval "+
		"back off the wire — the gap between two `authorize_session` records for one live session is the "+
		"measurement, whatever the statement's unit turns out to be.\n\n", accepted)

	deadline := time.Now().Add(optsIntervalBudget)

	// The strict-authorization case runs FIRST, and the order is a judgement
	// about which half of this item is worth the budget. Both cases ask whether
	// the device re-sends at all; only this one can answer "and does a denial
	// on the second pass end the session", which is the question a revocation
	// story rests on. If one interval's wait is all there is time for, it
	// should be spent here.
	switch {
	case s.strictRefused:
		b.WriteString("\n### With `strict-authorization` committed\n\n**Not measured**: this image does not " +
			"put `strict-authorization` into force — see item 1.\n")
	default:
		if r := s.apply(t, s.permitCfg, "set system tacplus-options strict-authorization"); r.applied {
			s.track("strict-authorization")
			b.WriteString(s.reauthCase(t, "with `strict-authorization` committed", interval, deadline))
		} else {
			fmt.Fprintf(&b, "\n### With `strict-authorization` committed\n\n**Not measured**: the statement "+
				"would not commit this time (%v).\n", r.err)
		}
	}

	// Then without it, if there is budget left for a full interval.
	if r := s.apply(t, s.permitCfg, "delete system tacplus-options strict-authorization"); r.applied {
		s.untrack("strict-authorization")
	}
	b.WriteString(s.reauthCase(t, "without `strict-authorization`", interval, deadline))
	return b.String()
}

func joinInts(vs []int) string {
	out := make([]string, len(vs))
	for i, v := range vs {
		out[i] = strconv.Itoa(v)
	}
	return strings.Join(out, ", ")
}

// reauthCase holds one session open across the interval and watches for a
// second session authorization, then denies the one after it.
func (s *optsRun) reauthCase(t *testing.T, name string, interval time.Duration, deadline time.Time) string {
	t.Helper()
	l := s.l
	var b strings.Builder
	fmt.Fprintf(&b, "\n### %s\n\n", name)

	s.useConfig(t, s.permitCfg)
	off := l.mark()
	user, secret := l.nextOptsLogin(t)
	p, c := l.optsSession(t, "re-authorization, "+name, user, secret)
	if c == nil {
		fmt.Fprintf(&b, "**Not measured**: the session did not open (%s).\n",
			firstNonEmpty(p.dialErr, p.shellErr, p.promptErr))
		return b.String()
	}
	defer c.Close()

	// The login's OWN authorization record, which is what the re-authorization
	// interval is later measured from. optsSession does not collect it — the
	// full drain waits on accounting this phase has no use for and would spend
	// a minute of the interval budget doing it — so it is read here directly.
	for _, r := range l.waitForRecords(off, 30*time.Second, func(rs []map[string]any) bool {
		return countEvent(recordsForUser(rs, user), "authorize_session") > 0
	}) {
		if str(r, "event") == "authorize_session" && str(sub(r, "session"), "username") == user {
			p.authz = r
			break
		}
	}
	if p.authz == nil {
		fmt.Fprintf(&b, "**Not measured**: the session opened and port49 wrote no `authorize_session` record "+
			"for `%s`, so there is no first authorization to measure an interval from.\n", user)
		return b.String()
	}

	// The session is open under a PERMIT. port49 is switched to the denying
	// configuration right now, before the first re-authorization is due, so the
	// very next one is denied.
	//
	// That shape costs ONE interval where waiting for a permitted
	// re-authorization and then denying the one after it costs two, and on this
	// image an interval is fifteen minutes — the minimum the statement accepts.
	// It also answers both halves at once: a denial arriving at all proves the
	// device re-authorizes, and what the live session does next is the
	// revocation question itself.
	fmt.Fprintf(&b, "The session of `%s` was opened while port49 permitted, and port49 was switched to the "+
		"denying configuration immediately afterwards — **with that session still open** — so the first "+
		"re-authorization the device sends is refused.\n\n"+
		"The refusal arrives as `deny context_missing` rather than `deny service_unsupported`, and that is "+
		"worth a sentence of its own. Switching port49's configuration restarts the daemon, and the login "+
		"context store is in memory (`internal/store/memory`), so the context created by this session's own "+
		"login does not survive the restart. **Every live Junos session's next re-authorization is denied "+
		"`context_missing` after a port49d restart** — which under `strict-authorization` is the difference "+
		"between restarting the daemon and cutting off every operator currently logged in, on a timer they "+
		"cannot see. It is the same denial either way for the purposes of this measurement, and a more "+
		"realistic one than a service-name mismatch.\n\n", user)
	off2 := l.mark()
	s.useConfig(t, s.denyCfg)

	// The budget may truncate the wait, and a truncated wait MUST NOT become a
	// negative finding. "No re-authorization arrived in six minutes" says
	// nothing at all when the configured interval is fifteen, and it would read
	// in the note exactly like "this image does not re-authorize" — a false
	// negative, published, about the one mechanism that could revoke a live
	// session. So a wait shorter than the interval is reported as not measured.
	wait := interval + 2*time.Minute
	if until := time.Until(deadline); until < wait {
		wait = until
	}
	if wait < interval+30*time.Second {
		fmt.Fprintf(&b, "**Not measured.** This item is allowed to spend %s waiting and %s of that was left, "+
			"which is less than the %s interval the device is configured for. A wait shorter than the "+
			"interval cannot tell \"this image does not re-authorize\" from \"the run did not wait long "+
			"enough\", so nothing is claimed here.\n",
			optsIntervalBudget, wait.Round(time.Second), interval)
		s.reauthFindings = append(s.reauthFindings, name+": not measured, the budget was shorter than the interval")
		return b.String()
	}
	t0 := time.Now()
	recs := l.waitForRecords(off2, wait, func(rs []map[string]any) bool {
		for _, r := range recordsForUser(rs, user) {
			if str(r, "event") == "authorize_session" && str(r, "verdict") == "deny" {
				return true
			}
		}
		return false
	})
	mine := recordsForUser(recs, user)
	var denied map[string]any
	for _, r := range mine {
		if str(r, "event") == "authorize_session" && str(r, "verdict") == "deny" {
			denied = r
			break
		}
	}

	// The live session is probed whichever way the wait ended, and that is the
	// fix for the first run's blind spot. With no probe, "no re-authorization
	// arrived" cannot be told from "the session had already gone, so there was
	// nothing left to re-authorize" — and those are opposite answers to the
	// revocation question.
	lv := junosLiveness(c)

	// And the same question asked of the DEVICE, on a channel of its own.
	//
	// The in-session probe above is the operator's view and it has proved
	// fragile: on both images a command typed into a session that had been idle
	// for the interval came back re-split, so "the session could still work"
	// was not answerable from inside it. `show system users` is answerable from
	// outside it, cannot be mangled by the idle session's own line editor, and
	// is the device stating whether the login is still there — which is exactly
	// what "did the denial tear the session down" asks.
	const usersCmd = "show system users | no-more"
	users, usersErr := s.admin(t, s.denyCfg, func(ac *cliConn) (string, error) {
		return junosShow(ac, usersCmd)
	})
	users = strings.TrimSpace(stripPrompt(junosTrimEcho(users, usersCmd)))
	lv.listed = usersErr == nil && strings.Contains(users, user)
	lv.listedOut, lv.listedCmd = users, usersCmd

	probeOut := firstNonEmpty(lv.cmdOut, lv.promptOut, emptyDeviceReply)
	alive := lv.cmdOK || lv.listed
	aliveWord := lv.summary()

	if denied == nil {
		fmt.Fprintf(&b, "Waited %s with the session open and idle, with port49 denying every Junos session "+
			"authorization for all of it. **No re-authorization of any kind arrived.** Probed at the end of "+
			"that wait, the session %s:\n\n%s\n",
			time.Since(t0).Round(time.Second), aliveWord, lv.render())
		b.WriteString(negativeFinding{
			Claim: fmt.Sprintf("with `authorization-time-interval %d` in force, this image sent NO "+
				"re-authorization for a live session inside %s, %s. A port49 denial cannot reach a "+
				"session that is already open by this route.",
				int(interval/time.Minute), wait.Round(time.Second), name),
			Sent: "set system tacplus-options authorization-time-interval " +
				strconv.Itoa(int(interval/time.Minute)) + "\ncommit\n\n" +
				"(then one token SSH login as " + user + ", held open and idle for " +
				time.Since(t0).Round(time.Second).String() + ", with port49\n" +
				" answering deny service_unsupported to every Junos session authorization)",
			Got: "port49's decision log for that user over the whole window:" + summarize(mine),
		}.render(t))
		s.reauthFindings = append(s.reauthFindings,
			name+": no re-authorization inside "+wait.Round(time.Second).String()+", session "+strings.Trim(aliveWord, "*"))
		return b.String()
	}

	// It re-authorized, and port49 refused. Report the interval measured off
	// the wire — the gap from the login, not from a configured figure — and
	// what the request carried.
	gap := "unknown"
	if t1, ok := recTime(p.authz); ok {
		if t2, ok2 := recTime(denied); ok2 {
			gap = t2.Sub(t1).Round(time.Second).String()
		}
	}
	req := sub(denied, "request")
	ses := sub(denied, "session")
	fmt.Fprintf(&b, "**This image DOES re-authorize a live session, and port49 refused the re-authorization.** "+
		"It arrived %s after the login's own authorization — the statement is configured for %s, and this "+
		"is that interval measured off the wire rather than read off the configuration:\n\n"+
		"```\nevent=authorize_session verdict=%s reason=%s\n    request.service=%q request.raw=%v\n"+
		"    port=%q rem_addr=%q\n```\n\n", gap, interval, str(denied, "verdict"), str(denied, "reason"),
		str(req, "service"), strs(req, "raw"), str(ses, "port"), str(ses, "rem_addr"))

	fmt.Fprintf(&b, "The session that was already open was then probed, and it %s:\n\n%s\n",
		aliveWord, lv.render())

	switch {
	case alive:
		b.WriteString(negativeFinding{
			Claim: "a DENIED re-authorization does not end a Junos session that is already open on this " +
				"image, " + name + ": after port49 refused its re-authorization the session was still " +
				"there — " + lv.evidenceFor() + ". Revocation does not reach a live session this way, and " +
				"the re-authorization is an audit event rather than an enforcement point.",
			Sent: "port49 was switched to a configuration that denies every Junos session authorization,\n" +
				"with the session of " + user + " still open. The re-authorization that arrived " + gap + "\n" +
				"later was answered `deny " + str(denied, "reason") + "`. The operator then typed, in that " +
				"same session:\n\n    " + livenessProbe,
			Got: firstNonEmpty(probeOut, emptyDeviceReply),
		}.render(t))
		s.reauthFindings = append(s.reauthFindings, name+": re-authorizes after "+gap+
			", and a denial did NOT end the live session")

	case lv.promptOK:
		// The weaker claim, and it is written as the weaker claim. The session
		// is demonstrably still there — the device reprinted its prompt — but
		// neither the probe command nor the device's own user list confirmed
		// it, so "it kept working" is more than this run can say.
		b.WriteString(negativeFinding{
			Claim: "a DENIED re-authorization does not CLOSE a Junos session that is already open on this " +
				"image, " + name + ": after port49 refused its re-authorization the session was still " +
				"there and the device still reprinted its prompt. Whether the session could still do " +
				"useful work is NOT settled here — neither the probe command nor `show system users` " +
				"confirmed it — so the claim is only that the session was not torn down.",
			Sent: "port49 was switched to a configuration that denies every Junos session authorization,\n" +
				"with the session of " + user + " still open. The re-authorization that arrived " + gap + "\n" +
				"later was answered `deny " + str(denied, "reason") + "`. A bare newline was then sent on\n" +
				"that same session, followed twice by:\n\n    " + livenessProbe,
			Got: firstNonEmpty(lv.promptOut, emptyDeviceReply) + "\n\n" +
				firstNonEmpty(lv.cmdOut, emptyDeviceReply),
		}.render(t))
		s.reauthFindings = append(s.reauthFindings, name+": re-authorizes after "+gap+
			", and a denial did not close the session (command probe inconclusive)")

	default:
		fmt.Fprintf(&b, "**The live session was gone after the denial** — not even a bare newline brought "+
			"the prompt back (%s). That is a revocation reaching a session that was already open, which is "+
			"the thing port49 has had no way to do.\n", lv.err)
		s.reauthFindings = append(s.reauthFindings, name+": re-authorizes after "+gap+
			", and a denial ENDED the live session")
	}
	return b.String()
}

// evidenceFor names what actually carried the claim, so a reader is never left
// to guess which of the three probes answered and which did not.
func (lv liveness) evidenceFor() string {
	var parts []string
	if lv.promptOK {
		parts = append(parts, "it answered its prompt")
	}
	if lv.cmdOK {
		parts = append(parts, "it ran `"+livenessProbe+"`")
	}
	if lv.listed {
		parts = append(parts, "and the device still listed the login in `"+lv.listedCmd+"`")
	}
	if len(parts) == 0 {
		return "on no evidence at all"
	}
	return strings.Join(parts, ", ")
}

func (lv liveness) render() string {
	var b strings.Builder
	b.WriteString("A bare newline, to see whether the session is still there at all:\n\n```\n" +
		trimForNote(firstNonEmpty(lv.promptOut, emptyDeviceReply)) + "\n```\n\n")
	b.WriteString("Then, twice, a command whose real output contains `" + livenessMarker + "`:\n\n```\n" +
		livenessProbe + "\n```\n\n```\n" + trimForNote(firstNonEmpty(lv.cmdOut, emptyDeviceReply)) + "\n```\n")
	if lv.err != "" {
		b.WriteString("\nThe probe also reported: `" + oneLine(lv.err) + "`\n")
	}
	if lv.listedCmd != "" {
		b.WriteString("\nAnd the device's own answer, asked on a separate admin CLI while that session was " +
			"still open:\n\n```\n" + lv.listedCmd + "\n```\n\n```\n" +
			trimForNote(redactSecrets(firstNonEmpty(lv.listedOut, emptyDeviceReply))) + "\n```\n")
	}
	return b.String()
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// livenessProbe is the command a held-open session is asked to run, and the
// string its real output must contain.
//
// The marker is the whole point. The first version of this probe called a
// session "still working" whenever the channel returned any bytes at all, and
// on a session that had been idle fifteen minutes the device returned
//
//	show
//	             ^
//	unknown command.
//
// three times over — the typed line arriving mangled — which the test scored as
// working and wrote up as "the operator's session kept working". Non-empty is
// not the same as answered. Asserting on a string only the real output contains
// cannot be satisfied by an error message or by a scrambled echo.
const (
	livenessProbe  = "show system uptime"
	livenessMarker = "Current time"
)

// liveness is what a held-open session did when it was asked to do something.
// The two halves are separate because they answer different questions: whether
// the SESSION is still there, and whether it still WORKS.
type liveness struct {
	promptOK  bool // a bare newline brought the prompt back
	promptOut string
	cmdOK     bool // the probe returned its own output, not an error and not an echo
	cmdOut    string
	err       string

	// listed is the device's own answer, from a separate admin CLI: is this
	// login still in `show system users`?
	listed    bool
	listedCmd string
	listedOut string
}

func (lv liveness) summary() string {
	switch {
	case lv.cmdOK && lv.listed:
		return "was still working, and the device still listed it"
	case lv.listed:
		return "**was still listed by the device**"
	case lv.cmdOK:
		return "was still working"
	case lv.promptOK:
		return "**still had a prompt, but the command did not run and the device did not list it**"
	}
	return "**was gone**"
}

// junosLiveness asks a held-open CLI two questions, weakest first.
//
// A bare newline that brings the prompt back proves the session is open and the
// device is still reading from it — which is a real answer on its own, and the
// only one available when the line editor mangles a typed command. The probe
// command is then tried twice, because the mangling seen on 2026-09-21 was a
// property of the first line typed after a long idle and not of the session.
func junosLiveness(c *cliConn) liveness {
	var lv liveness
	out, err := c.sendExpect("", 45*time.Second, junosOpPrompt)
	if err != nil {
		lv.err = err.Error()
		return lv
	}
	lv.promptOK, lv.promptOut = true, strings.TrimSpace(out)

	// `complete-on-space off` before typing anything, because of what the
	// 2026-09-21 runs caught on BOTH images. A command written to the channel
	// in one go, on a session that had been idle for fifteen minutes, came back
	//
	//	show
	//	             ^
	//	unknown command.
	//	jopt11@srx1> show   system
	//	jopt11@srx1> showsystem   uptime
	//
	// — the words re-split and the spaces moved. Junos completes a keyword on
	// SPACE by default, so a line delivered faster than the CLI consumes it has
	// its own completions interleaved with the characters still arriving. The
	// session was fine; the typing was not. Turning completion off removes the
	// mechanism, and the paced retry below removes the race.
	_, _ = c.sendExpect("set cli complete-on-space off", 45*time.Second, junosOpPrompt)

	for i := 0; i < 2; i++ {
		var out string
		var err error
		if i == 0 {
			out, err = junosShow(c, livenessProbe)
		} else {
			out, err = junosShowPaced(c, livenessProbe)
		}
		lv.cmdOut = strings.TrimSpace(junosTrimEcho(out, livenessProbe))
		if err != nil {
			lv.err = err.Error()
			continue
		}
		if strings.Contains(lv.cmdOut, livenessMarker) {
			lv.cmdOK = true
			return lv
		}
	}
	return lv
}

// junosShowPaced types a command one character at a time, which is the retry
// for a CLI whose line editor has re-split a line written in one write. It is
// slow on purpose and is never the first thing tried.
func junosShowPaced(c *cliConn, cmd string) (string, error) {
	from := len(c.transcript())
	for _, ch := range cmd {
		if _, err := fmt.Fprintf(c.in, "%c", ch); err != nil {
			return c.transcript()[from:], err
		}
		time.Sleep(40 * time.Millisecond)
	}
	if _, err := fmt.Fprint(c.in, "\n"); err != nil {
		return c.transcript()[from:], err
	}
	return c.expectFrom(from, 60*time.Second, junosOpPrompt)
}

// ---------------------------------------------------------------------------
// The reading, and the assertions
// ---------------------------------------------------------------------------

func (s *optsRun) reading() string {
	var b strings.Builder
	b.WriteString("\n## What this settles\n\n")

	// 1. strict-authorization.
	switch {
	case s.strictRefused:
		b.WriteString("1. **This image does not offer `strict-authorization` at all.** Section 1 carries the " +
			"device's own refusal and the read-back behind it, and item 5 lists what the image does offer. " +
			"So on this release there is no statement of that name to make a port49 denial binding.\n\n")
	case s.strictDeny.authz == nil:
		b.WriteString("1. **strict-authorization: not settled.** The denying attempt produced no " +
			"`authorize_session` record, so nothing was measured about what the statement does to a denial.\n\n")
	case !s.strictDeny.opened:
		b.WriteString("1. **`strict-authorization` is the statement that makes a port49 denial bind on Junos.** " +
			"With it committed, the denial that completed a login on 2026-09-21 refuses one. The reference " +
			"configuration in `tests/lab/configs/vjunos-startup.conf` does not carry it, which is why the " +
			"2026-09-21 measurement found Junos authorization advisory: that was a property of the " +
			"configuration, not of the vendor.\n\n")
	default:
		b.WriteString("1. **`strict-authorization` did NOT make the denial bind on this image.** The negative " +
			"finding in section 1 carries the transcript. Whatever makes a port49 denial binding on Junos, " +
			"this statement alone is not it here.\n\n")
	}

	// The 3am clause.
	var lockedOut []string
	for _, c := range s.breakglass {
		if c.attempted && !c.ok {
			lockedOut = append(lockedOut, c.order)
		}
	}
	if len(s.breakglass) == 0 {
		b.WriteString("2. **Break-glass under `strict-authorization`: not measured** — the statement is not " +
			"in force on this image, so there is no condition to measure it under.\n\n")
	} else if len(lockedOut) == 0 {
		b.WriteString("2. **Break-glass survives it.** With `strict-authorization` committed and port49d not " +
			"listening, the local account logged in over SSH under every authentication order measured. The " +
			"statement makes port49's answer binding without making port49 a single point of failure for the " +
			"device.\n\n")
	} else {
		fmt.Fprintf(&b, "2. **Break-glass does NOT survive it under %s.** With `strict-authorization` "+
			"committed and port49d not listening, the local account was refused over SSH. That is the 3am "+
			"case failing: the statement that makes port49's denials binding also makes port49 a single "+
			"point of failure for the device under that order.\n\n", codeList(lockedOut))
	}

	// enhanced-accounting.
	if s.enhancedRefused {
		b.WriteString("3. **This image does not offer `enhanced-accounting` either.** Section 2 carries the " +
			"refusal, and the records it did collect are what this image sends with no `tacplus-options` " +
			"statement at all.\n\n")
	} else if len(s.acctPlain) == 0 || len(s.acctEnhanced) == 0 {
		b.WriteString("3. **enhanced-accounting: not measured** — one of the two runs produced no records.\n\n")
	} else if len(s.addedKeys) == 0 {
		b.WriteString("3. **`enhanced-accounting` added no AV pair** to any record this session produced. " +
			"Section 2 carries both record sets.\n\n")
	} else {
		fmt.Fprintf(&b, "3. **`enhanced-accounting` adds %s.** Section 2 says on which record types, and "+
			"whether any of them tells two concurrent sessions of one user apart.\n\n", codeList(s.addedKeys))
	}

	// root records.
	if len(s.rootRows) > 0 {
		fmt.Fprintf(&b, "4. **%d accounting records named a user who is not the operator**, and port49 spools "+
			"every one of them `unattributed`: it attributes on `(nas, username)` and holds no context for "+
			"that name. The command is attributed and its effect is not.\n\n", len(s.rootRows))
	} else {
		b.WriteString("4. **No accounting record named a user other than the operator** under this lab's " +
			"accounting event list. Section 3 carries the negative with the records behind it.\n\n")
	}

	// re-authorization.
	if len(s.reauthFindings) == 0 {
		b.WriteString("5. **Re-authorization: not measured** — see section 4 for why.\n")
	} else {
		b.WriteString("5. **Re-authorization:** " + strings.Join(s.reauthFindings, "; ") + ".\n")
	}
	return b.String()
}

// assert fails the run when an item measured nothing. The items that are
// conditional on the image offering a statement are not asserted here — their
// own sections carry the device's refusal verbatim, which is a measurement —
// but the three that must always produce something are.
func (s *optsRun) assert(t *testing.T) {
	t.Helper()
	if strings.TrimSpace(s.knobs) == "" {
		t.Errorf("item 5 produced no completion listing at all, so the note cannot say which " +
			"`tacplus-options` leaves this image offers")
	}
	// A statement this image does not have is a finding, rendered through
	// negativeFinding with the device's own refusal behind it. The phases under
	// it could not run, so they are not asserted — asserting them would fail a
	// run that measured exactly what it was sent to find out.
	if !s.strictRefused {
		if s.strictPermit.authz == nil {
			t.Errorf("item 1(a) produced no authorize_session record with strict-authorization in force, "+
				"so the permitting case measured nothing:%s", summarize(s.strictPermit.recs))
		}
		if s.strictDeny.authz == nil {
			t.Errorf("item 1(b) produced no authorize_session record, so what strict-authorization does to "+
				"a denial measured nothing:%s", summarize(s.strictDeny.recs))
		} else if str(s.strictDeny.authz, "verdict") != "deny" {
			t.Errorf("item 1(b) was meant to produce a denial and port49 answered %q %q instead, so nothing "+
				"was measured about a denied session authorization",
				str(s.strictDeny.authz, "verdict"), str(s.strictDeny.authz, "reason"))
		}
		if len(s.breakglass) == 0 {
			t.Errorf("item 1(c) attempted no break-glass login, so the 3am case measured nothing")
		}
	}
	if len(s.acctPlain) == 0 {
		t.Errorf("item 2 collected no accounting records with no `tacplus-options` statement set, so there " +
			"is no baseline to diff against and item 3 has no record stream either")
	}
	if !s.enhancedRefused && len(s.acctEnhanced) == 0 {
		t.Errorf("item 2 collected no accounting records with enhanced-accounting in force, so the " +
			"statement's effect measured nothing")
	}
}
