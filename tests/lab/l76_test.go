//go:build lab

package lab

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/tests/lab/labcreds"
)

// TestL76 measures Nokia SR Linux against port49 (spec §15 L76). It runs only
// when PORT49_LAB_PLATFORMS is exactly "srlinux", and only as
// -run '^TestL76$' (TestL73 also runs the opt-in rows).
func TestL76(t *testing.T) {
	sel, _, err := platformSelection()
	if err != nil {
		t.Fatal(err)
	}
	if len(sel) != 1 || sel[0].sel != l76Sel {
		t.Skipf("L76 runs alone: PORT49_LAB_PLATFORMS=%s", l76Sel)
	}
	// Held until TestMain's teardown has destroyed the topology (labRelease).
	if err := labOccupyForRun(labLockPath, fmt.Sprintf("TestL76 pid %d", os.Getpid())); err != nil {
		t.Fatalf("INVALID: %v", err)
	}
	if err := labGuardAt(l66StopSentinel, "/", l66DiskFloorMB); err != nil {
		t.Fatalf("INVALID: %v", err)
	}
	// Names only, as TestL73 does: nothing here touches another container
	// (pre-flight M6).
	if out, err := exec.Command("docker", "ps", "--filter", "label=containerlab", "--format", "{{.Names}}").Output(); err != nil {
		t.Fatalf("INVALID: docker ps: %v", err)
	} else if s := strings.TrimSpace(string(out)); s != "" {
		t.Fatalf("INVALID: a containerlab topology is already up (%s): the lab is single-occupant",
			strings.ReplaceAll(s, "\n", ", "))
	}
	// eachOptInPlatform, not eachPlatform: the srlinux row is opt-in, and
	// eachPlatform runs only the rows that are not (pre-flight C1).
	eachOptInPlatform(t, func(t *testing.T, l *lab) {
		stop := l.capture(t, "L76")
		defer stop()
		e := &l76Env{t: t, l: l, start: l.mark(), evidence: map[string]string{}, out: map[string]string{}}
		e.wrongPassword = randomHex(t, 15)
		e.wrongKey = randomHex(t, 16)
		e.checkSchema()
		e.cellA()
		e.cellB()
		e.cellC()
		e.cellD()
		e.cellH()
		e.cellI()
		e.cellJ()
		e.cellK()
		e.cellL()
		e.cellE()
		e.cellF()
		e.cellG()
		stop()
		e.note()
	})
}

type l76Env struct {
	t        *testing.T
	l        *lab
	start    int64             // the decision log's size when the test began
	evidence map[string]string // file name under evidence/L76-<platform>/ -> content
	out      map[string]string // cell id -> observation
	schema   string            // the note's schema section

	wrongPassword, wrongKey string

	aUser string           // cell (a)'s port49 user
	aOuts []string         // cell (a)'s command outputs, unfiltered
	aRecs []map[string]any // cell (a)'s records

	retries []string // try's retried dials, both attempts each (pre-flight M3)
	dumped  bool     // dumpDevice has run

	// l76Restoring's restoring flag is set by restore for the length of a
	// deferred restore, and by nothing else: it lets invalid log instead of
	// stop while the run is already failing.
	l76Restoring
}

// guard is the STOP sentinel and the disk floor, before every cell.
func (e *l76Env) guard() {
	e.t.Helper()
	if err := labGuardAt(l66StopSentinel, "/", l66DiskFloorMB); err != nil {
		e.t.Fatalf("INVALID: %v", err)
	}
}

// invalid ends the run with no note. Its message is masked and then passes
// l76Leaks against the run's secrets.
// A restore that fails inside a deferred call after an earlier INVALID
// (the test is already failing and unwinding) is logged, not raised again,
// so the first INVALID's reason stays the run's reason. Only a deferred
// restore sets e.restoring; any other INVALID stops the run, even if a stray
// non-fatal failure came first.
func (e *l76Env) invalid(format string, args ...any) {
	e.t.Helper()
	// Not l76FilterLog: it would drop this message's own wording when it names
	// a password. Every caller filters or masks the device text it passes in.
	secrets, _ := e.secrets() // on a seed error, the fixed secrets still gate
	msg := l76InvalidText(fmt.Sprintf(format, args...), secrets)
	if l76ReturnsFromInvalid(e.restoring, e.t.Failed()) {
		e.t.Logf("also INVALID, while restoring after the first: %s", msg)
		return
	}
	e.dumpDevice()
	e.t.Fatalf("INVALID: %s", msg)
}

// dumpDevice keeps the device's own view of an INVALID run, best-effort, in
// the git-ignored tests/lab/logs/L76-invalid-<stamp>/, so the next attempt
// does not re-boot blind (pre-flight I6): the masked running config, the AAA
// log's last 400 lines, the session table and port49's decision log. Each passes through
// l76FilterLog and then l76Leaks; a file with a hit is withheld. It never
// writes to results/ or evidence/, and it never raises: it calls sr and
// aaaTail, not running or invalid, and logs its own failures, so the INVALID
// that called it stays the run's reason.
func (e *l76Env) dumpDevice() {
	if e.dumped {
		return
	}
	e.dumped = true
	dir := filepath.Join(root, "tests", "lab", "logs", "L76-invalid-"+time.Now().UTC().Format("20060102T150405Z"))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		e.t.Logf("INVALID dump: %v", err)
		return
	}
	secrets, err := e.secrets()
	if err != nil {
		e.t.Logf("INVALID dump: the run's seed tokens: %v; checking the other secrets only", err)
	}
	run, _, runErr := e.sr(60*time.Second, l76ReadRunning)
	aaa, aaaErr := e.aaaTail()
	sess, _, sessErr := e.sr(60*time.Second, l76ReadSessions)
	type read struct {
		text string
		err  error
	}
	for name, r := range map[string]read{
		"running.txt":  {l76MaskConfig(run), runErr},
		"aaa-log.txt":  {aaa, aaaErr},
		"sessions.txt": {sess, sessErr},
		// The port49 side: why the server answered as it did. Credentials
		// appear only as redacted hashes (l76RedactHashes).
		"decisions.jsonl": {l76DecisionDump(e.l.recordsSince(e.start)), nil},
	} {
		text := r.text
		if r.err != nil {
			text = fmt.Sprintf("(not read cleanly: %v)\n%s", r.err, text)
		}
		text = l76FilterLog(text)
		if leaks := l76Leaks(text, secrets); len(leaks) > 0 {
			e.t.Logf("INVALID dump: %s withheld: it holds %v", name, leaks)
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text+"\n"), 0o600); err != nil {
			e.t.Logf("INVALID dump: %s: %v", name, err)
		}
	}
	e.t.Logf("INVALID dump: the device's view is in %s", dir)
}

// secrets is every secret the run knows, for the leak gates: the lab key,
// the break-glass password, SR Linux's default admin password, the wrong key
// and password, and every seed token. If the seeds cannot be read it returns
// the others, and the error.
func (e *l76Env) secrets() ([]string, error) {
	fixed := []string{labKeyDefault, breakglassPassword, l76AdminDefault, e.wrongKey, e.wrongPassword}
	runSeedsMu.Lock()
	seeds, err := labcreds.SecretsOf(runSeeds)
	runSeedsMu.Unlock()
	if err != nil {
		return fixed, err
	}
	return append(fixed, seeds...), nil
}

// sr runs sr_cli -d in the node as the container's root, outside TACACS+,
// and returns its output unfiltered: callers filter before keeping it.
// docker exec runs as root because containerlab starts SR Linux nodes with
// user 0:0 (its nodes/srl/srl.go; the image's own default is user:user).
func (e *l76Env) sr(within time.Duration, args ...string) (string, time.Duration, error) {
	ctx, cancel := context.WithTimeout(context.Background(), within)
	defer cancel()
	argv := append([]string{"exec", l76Container, "sr_cli", "-d"}, args...)
	start := time.Now()
	out, err := exec.CommandContext(ctx, "docker", argv...).CombinedOutput()
	return string(out), time.Since(start), err
}

// running is `info from running system aaa` (CM#configuration-datastores),
// unmasked: callers mask it.
func (e *l76Env) running() string {
	out, _, err := e.sr(60*time.Second, l76ReadRunning)
	if err != nil {
		e.invalid("%s: %v\n%s", l76ReadRunning, err, l76MaskConfig(out))
	}
	return out
}

// set applies one flat `set /` line (CLAB#cli's flat form) and reads it back.
// It tries `sr_cli -d --candidate-mode --commit-at-end -- <line>`, the form
// sr_cli's own help example shows (HELP; pre-flight M8). If the read-back
// says that did not apply, it sends `enter candidate`, the line and `commit
// now` on stdin (CM#configuration-modes,
// CM#commit-configuration-in-candidate-mode). If neither applies, the run is
// INVALID.
func (e *l76Env) set(line string, applied func(running string) bool) {
	e.t.Helper()
	out, _, err := e.sr(90*time.Second, "--candidate-mode", "--commit-at-end", "--", line)
	if err == nil && applied(e.running()) {
		return
	}
	first := l76MaskConfig(out)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", "exec", "-i", l76Container, "sr_cli", "-d")
	cmd.Stdin = strings.NewReader("enter candidate\n" + line + "\ncommit now\n")
	out2, err2 := cmd.CombinedOutput()
	if !applied(e.running()) {
		e.invalid("%q did not apply: sr_cli --candidate-mode --commit-at-end said (%v) %s; stdin said (%v) %s",
			line, err, first, err2, l76MaskConfig(string(out2)))
	}
}

// aaaTail is the AAA manager log's last 400 lines through the log filter
// (SA#configuring-local-accounting). It never raises: dumpDevice uses it.
func (e *l76Env) aaaTail() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", "exec", l76Container, "tail", "-n", "400", l76AAALog).CombinedOutput()
	return l76FilterLog(string(out)), err
}

// aaaLog is aaaTail's lines that name any key.
func (e *l76Env) aaaLog(keys ...string) string {
	out, err := e.aaaTail()
	if err != nil {
		return fmt.Sprintf("(the AAA log could not be read: %v)", err)
	}
	return l76Grep(out, keys)
}

// try is one SSH login and how long the device took to answer it. A dial
// that fails before authentication (a TCP reset or an EOF, not
// isAuthRejection) is retried once after 5 s; both attempts are recorded in
// e.retries for the note, and the second is the one returned (pre-flight
// M3: L73's XRd reset, d03ca159).
func (e *l76Env) try(user, pw string) (time.Duration, error) {
	once := func() (time.Duration, error) {
		start := time.Now()
		c, err := e.l.dial(user, pw, 60*time.Second)
		took := time.Since(start)
		if err == nil {
			c.Close()
		}
		return took, err
	}
	took, err := once()
	if err == nil || isAuthRejection(err) {
		return took, err
	}
	time.Sleep(5 * time.Second)
	took2, err2 := once()
	again := "logged in"
	if err2 != nil {
		again = oneLine(err2.Error())
	}
	e.retries = append(e.retries, fmt.Sprintf("`%s`: the first dial failed before authentication after %v (%s); "+
		"retried after 5 s: %s after %v", user, took.Round(time.Millisecond), oneLine(err.Error()), again,
		took2.Round(time.Millisecond)))
	return took2, err2
}

// restart puts port49d on cfg and waits until the device asks it again.
func (e *l76Env) restart(cfg string) {
	e.t.Helper()
	if err := e.l.restart(cfg); err != nil {
		e.invalid("restarting port49d on %s: %v", cfg, err)
		return
	}
	if err := e.l.waitTACACSReady(3 * time.Minute); err != nil {
		e.invalid("after restarting port49d: %v", err)
	}
}

// restartStanding puts port49d back on the platform's standing config.
func (e *l76Env) restartStanding() {
	e.t.Helper()
	cfg, err := e.l.configPath()
	if err != nil {
		e.invalid("the standing config: %v", err)
		return
	}
	e.restart(cfg)
}

// tokenLogin spends one seed token on a login that runs l76Commands (Task
// 4), and returns the user, the outputs and the user's records. Each command
// has 60 s (loginWithin; pre-flight I1): a command the device never answers
// is closed, and err is a *notObserved naming it, rather than a run that
// waits until -test.timeout. outs holds one entry per command that was sent,
// so callers check len(outs). The records wait for the redeem and for two
// accounting records, or 30 s.
func (e *l76Env) tokenLogin(label string) (string, []string, []map[string]any, error) {
	e.t.Helper()
	return e.tokenLoginCmds(label, l76Commands)
}

// tokenLoginCmds is tokenLogin for the given commands, each its own exec
// channel on the one SSH connection (loginWithin).
func (e *l76Env) tokenLoginCmds(label string, cmds []string) (string, []string, []map[string]any, error) {
	e.t.Helper()
	off := e.l.mark()
	user, secret := e.l.nextLogin(e.t)
	outs, err := e.l.loginWithin(user, secret, 60*time.Second, cmds...)
	recs := e.l.waitForRecords(off, 30*time.Second, func(rs []map[string]any) bool {
		return redeemFor(rs, user) != nil && l76Count(l76Of(rs, user), "account") >= 2
	})
	for i, o := range outs {
		e.evidence[fmt.Sprintf("%s-%d.txt", label, i+1)] = "$ " + cmds[i] + "\n" + l76FilterLog(o)
	}
	return user, outs, l76Of(recs, user), err
}

// l76SessionOf is user's row in the session table, or nil.
func l76SessionOf(out, user string) *l76Session {
	for _, s := range l76Sessions(out) {
		if s.User == user {
			return &s
		}
	}
	return nil
}
func (e *l76Env) checkSchema() {
	e.guard()
	// Exactly the cited form, `sr_cli --help`: not through sr, which adds -d.
	// It keeps sr's 30 s bound.
	helpCtx, cancelHelp := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelHelp()
	helpOut, err := exec.CommandContext(helpCtx, "docker", "exec", l76Container, "sr_cli", "--help").CombinedOutput()
	help := string(helpOut)
	for _, flag := range []string{"--dumb-terminal", "--candidate-mode", "--commit-at-end"} {
		if !strings.Contains(help, flag) {
			e.invalid("sr_cli --help lacks %s (err %v), so the harness's device commands are not this image's", flag, err)
		}
	}
	ver, _, err := e.sr(30*time.Second, l76ReadVersion)
	if err != nil || !strings.Contains(ver, "26.7.2") {
		e.invalid("the node is not SR Linux 26.7.2 (err %v):\n%s", err, l76FilterLog(ver))
	}
	run := e.running()
	for _, s := range []string{"server-group port49", "server-group local", "priv-lvl-authorization true",
		"network-instance mgmt", "event command", "record start-stop", "p49-admin", "p49-read"} {
		if !strings.Contains(run, s) {
			e.invalid("the running config lacks %q, so the startup config did not apply as written:\n%s",
				s, l76MaskConfig(run))
		}
	}
	if got := l76LeafList(run, "authentication-method"); strings.Join(got, " ") != "port49 local" {
		e.invalid("authentication-method is %v, want [port49 local]", got)
	}
	if got := l76LeafList(run, "accounting-method"); strings.Join(got, " ") != "port49" {
		e.invalid("accounting-method is %v, want [port49]", got)
	}
	model := func(name string) string {
		out, err := exec.Command("docker", "exec", l76Container, "sh", "-c",
			"cat \"$(find /opt/srlinux/models -name "+name+" | head -1)\"").CombinedOutput()
		if err != nil || len(out) == 0 {
			e.invalid("reading %s from the image: %v", name, err)
		}
		return string(out)
	}
	aaa, types := model("srl_nokia-aaa.yang"), model("srl_nokia-aaa-types.yang")
	findings := l76SchemaFindings(aaa, types)
	if len(findings) != l76SchemaFindingCount {
		e.invalid("the image's AAA models say %d of the %d things this plan read from them:\n%s",
			len(findings), l76SchemaFindingCount, strings.Join(findings, "\n"))
	}
	groups, _, _ := e.sr(30*time.Second, l76ReadGroup)
	e.evidence["schema-running.txt"] = l76MaskConfig(run)
	e.evidence["schema-models.txt"] = l76SchemaExcerpt(aaa, []string{l76LocalNameRule, "grouping aaa-authorization-methods-config",
		"grouping aaa-authorization-events-top", "uses aaa-authorization", "authorization is skipped for TACACS+"}) + "\n" +
		l76SchemaExcerpt(types, []string{"identity command ", "identity commands ", "base aaa_accounting_event_type",
			"base aaa_authorization_event_type"})
	e.evidence["schema-server-group.txt"] = l76MaskConfig(l76FilterLog(groups))
	e.schema = fmt.Sprintf("Version: `%s`.\n\nThe configuration under test, as the device reports it "+
		"(`info from running system aaa`, values masked):\n\n```\n%s\n```\n\nWhat the image's own YANG says "+
		"where Nokia's guide says otherwise or nothing:\n\n- %s\n\nThe server group's state "+
		"(`info from state system aaa server-group port49`):\n\n```\n%s\n```\n",
		oneLine(l76VersionText(ver)), l76MaskConfig(run), strings.Join(findings, "\n- "),
		e.evidence["schema-server-group.txt"])
}

// (a) the control login. A port49 user that fails here makes the run
// INVALID: nothing after it would be about TACACS+.
func (e *l76Env) cellA() {
	e.guard()
	start := time.Now()
	user, outs, recs, err := e.tokenLogin("a")
	took := time.Since(start)
	// Any error is INVALID here, a *notObserved (a command that did not
	// finish in 60 s) included: (a) is the control (pre-flight I1).
	if err != nil {
		secrets, _ := e.secrets() // on a seed error, the fixed secrets still gate
		e.invalid("cell a: the control login as %s failed after %v: %v\n%s", user, took, err, l76Summarize(recs, secrets))
	}
	if len(outs) != len(l76Commands) {
		e.invalid("cell a: %d outputs for %d commands", len(outs), len(l76Commands))
	}
	red := redeemFor(recs, user)
	if red == nil || l76Str(red, "verdict") != "permit" {
		e.invalid("cell a: no permitted redeem for %s, so the device did not ask port49:\n%s", user, l76Render(recs))
	}
	s := l76SessionOf(outs[0], user)
	if s == nil {
		// Not l.ptyCommands: it drives l.shell, which expects a Cisco/EOS
		// prompt and sends `terminal length 0`, syntax no SR Linux document
		// cites (pre-flight I7).
		e.invalid("cell a: the session table has no row for %s. If the outputs are empty, SR Linux's sshd did "+
			"not run the exec command in sr_cli. The fix is a cited SR Linux pty opener, in a follow-up commit, "+
			"with its prompt and paging command cited to the 26.7 CLI guide.\n%s", user, l76FilterLog(outs[0]))
	}
	e.aUser, e.aOuts, e.aRecs = user, outs, recs

	// Spec §8 says an unknown platform gets an alarm. This cell measures and
	// records what port49 did; it changes no port49 code and adds no reason
	// code (pre-flight M7). platform_unknown is defined in
	// internal/decision/reasons.go and, at plan time, emitted nowhere.
	unknownRecs := 0
	for _, r := range e.l.recordsSince(e.start) {
		if l76Str(r, "reason") == "platform_unknown" {
			unknownRecs++
		}
	}
	daemonLog := "(port49d's log could not be read)"
	if raw, err := os.ReadFile(e.l.errPath); err == nil {
		lines := strings.Split(l76Grep(string(raw), []string{"platform_unknown", "unknown platform",
			"unknown_platform", l76PlatformName}), "\n")
		if len(lines) > 20 {
			lines = lines[len(lines)-20:]
		}
		daemonLog = l76FilterLog(string(l76RedactHashes([]byte(strings.Join(lines, "\n")))))
	}
	e.evidence["a-port49d-log.txt"] = daemonLog
	alarm := "port49 raised no unknown-platform signal: no record has reason `platform_unknown`, and its log " +
		"names no unknown platform. Spec §8's alarm was not observed; this is a question for Ryan, not a code change."
	if unknownRecs > 0 || strings.Contains(strings.ToLower(daemonLog), "unknown") {
		alarm = fmt.Sprintf("port49's unknown-platform signal: %d record(s) with reason `platform_unknown`; its log's "+
			"lines are below.", unknownRecs)
	}

	e.out["a"] = fmt.Sprintf("`%s` (a user with no local account) logged in over SSH in %v. port49's redeem: "+
		"%s/%s, auth.method `%s`. The session table's row: id %s, service `%s`, method `%s`, priv-lvl `%s`, "+
		"tty `%s`.\n\n```\n%s\n```\n\nRecords:\n\n```\n%s\n```\n\n**Unknown platform (spec §8).** The redeem's "+
		"reason is `%s`. %s\n\nport49d's log, the lines naming `platform_unknown`, an unknown platform or `%s` "+
		"(last 20):\n\n```\n%s\n```",
		user, took.Round(time.Millisecond), l76Str(red, "verdict"), l76Str(red, "reason"), l76Str(red, "auth", "method"),
		s.ID, s.Service, s.Method, s.PrivLvl, s.TTY, l76FilterLog(outs[0]), l76Render(recs),
		l76Str(red, "reason"), alarm, l76PlatformName, daemonLog)
	if note := l76ChdirNote(outs); note != "" {
		e.out["a"] += "\n\n" + note
	}
}

// (b) the authorization (a)'s login sent, read from (a)'s records.
func (e *l76Env) cellB() {
	e.guard()
	if len(e.aOuts) != len(l76Commands) {
		e.invalid("cell b: cell (a) kept %d outputs for %d commands", len(e.aOuts), len(l76Commands))
	}
	reqs := authzRequests(e.aRecs)
	// Only the user's own session blocks (pre-flight I2).
	own := l76UserRows(e.aOuts[0], e.aUser)
	roles := l76SessionRoles(e.aOuts[0], e.aUser)
	s := l76SessionOf(e.aOuts[0], e.aUser)
	// What port49 sent is read from its records, never assumed from the config.
	var reply []string
	for _, r := range reqs {
		if l76Str(r, "event") == "authorize_session" {
			reply = l76Strs(r, "reply", "attributes")
		}
	}
	e.out["b"] = fmt.Sprintf("%d authorization request(s) for `%s`: %d `authorize_session`, %d `authorize_command` "+
		"(per-command). Services: %v. port49's reply attributes (from its record): %v. The session's roles "+
		"(the Role column of this user's rows in `show system aaa authentication session`): %s; priv-lvl in the table: `%s`. "+
		"`network-admin` %s in this user's rows.\n\n```\n%s\n```\n\nThis user's rows in the session table, as the device printed them:\n\n```\n%s\n```",
		len(reqs), e.aUser, l76Count(reqs, "authorize_session"), l76Count(reqs, "authorize_command"),
		l76Services(reqs), reply, roles, s.PrivLvl, l76Appears(own, "network-admin"), l76Render(reqs),
		l76FilterLog(own))

	// What the device does with the optional attributes: two probes, each on
	// its own seeded user, so a refused login cannot touch the control. The
	// optional shell:roles and an invented attribute are measured here rather
	// than inherited.
	cfg1, err := e.l.derivedConfig("l76-b1", l76ProbeRoles, "")
	if err != nil {
		e.invalid("cell b: %v", err)
	}
	cfg2, err := e.l.derivedConfig("l76-b2", l76ProbeInvented, "")
	if err != nil {
		e.invalid("cell b: %v", err)
	}
	defer e.restore(e.restartStanding)
	e.restart(cfg1)
	user1, _, recs1, err1 := e.tokenLogin("b1")
	e.restart(cfg2)
	user2, _, recs2, err2 := e.tokenLogin("b2")
	e.out["b"] += "\n\n" + l76AttrProbeText("b1", l76ProbeRoles, user1, err1, recs1) +
		"\n\n" + l76AttrProbeText("b2", l76ProbeInvented, user2, err2, recs2)
}

// l76Appears says whether text names word.
func l76Appears(text, word string) string {
	if strings.Contains(text, word) {
		return "**appears**"
	}
	return "does not appear"
}

// (c) the accounting (a)'s three commands sent.
func (e *l76Env) cellC() {
	e.guard()
	var acct []map[string]any
	for _, r := range e.aRecs {
		if l76Str(r, "event") == "account" {
			acct = append(acct, r)
		}
	}
	flags := map[string]int{}
	noCmd := 0
	for _, r := range acct {
		flags[l76Str(r, "flags")]++
		has := false
		for _, a := range l76Strs(r, "record", "raw") {
			if strings.HasPrefix(a, "cmd=") || strings.HasPrefix(a, "cmd*") {
				has = true
			}
		}
		if !has {
			noCmd++
		}
	}
	e.out["c"] = fmt.Sprintf("%d accounting record(s) for `%s`'s %d commands, by flags %v. Records with no `cmd` "+
		"(a session start or stop): %d.\n\n```\n%s\n```",
		len(acct), e.aUser, len(l76Commands), flags, noCmd, l76Render(acct)) +
		"\n\n" + l76ChannelText(l76ChannelFacts(e.aRecs, e.aUser), 15)
}

// (d) a wrong password for a port49 user, then the break-glass account with
// port49 up: whether a port49 deny falls through to local (exit-on-reject is
// its default, false).
func (e *l76Env) cellD() {
	e.guard()
	off := e.l.mark()
	user, _ := e.l.nextLogin(e.t)
	took, err := e.try(user, e.wrongPassword)
	if err == nil {
		e.invalid("cell d: %s logged in with a wrong password", user)
	}
	if !isAuthRejection(err) {
		e.invalid("cell d: the login with the wrong credential failed before authentication: %v", err)
	}
	bgTook, bgErr := e.try(breakglassUser, breakglassPassword)
	recs := e.l.waitForRecords(off, 20*time.Second, func(rs []map[string]any) bool {
		return redeemFor(rs, user) != nil && redeemFor(rs, breakglassUser) != nil
	})
	bg := "logged in"
	if bgErr != nil {
		bg = "was **refused** (" + oneLine(bgErr.Error()) + ")"
	}
	e.evidence["d-aaa-log.txt"] = e.aaaLog(user, breakglassUser)
	// Ruling 1: a fall-through is stated as the operator hazard it is.
	hazard := ""
	if bgErr == nil {
		hazard = "\n\n**Operator hazard:** with `exit-on-reject` at its default, a person whom port49 denies " +
			"still gets in if the device has a local account for them. port49's deny is not final on this " +
			"platform. Plan 12's reference config sets `exit-on-reject` (Ruling 1)."
	}
	e.out["d"] = l76ExitDefaultNote + "\n\n" + fmt.Sprintf("A wrong password for `%s` was refused in %v. port49's records:\n\n```\n%s\n```\n\n"+
		"With port49 up, `%s` (local only; port49 denies it, having no token for it) %s in %v. So a port49 deny "+
		"%s through to `local` with `exit-on-reject` at its default.%s\n\nThe AAA log's lines for both users:\n\n```\n%s\n```",
		user, took.Round(time.Millisecond), l76Render(recs), breakglassUser, bg, bgTook.Round(time.Millisecond),
		map[bool]string{true: "**falls**", false: "does **not** fall"}[bgErr == nil], hazard, e.evidence["d-aaa-log.txt"]) +
		"\n\n" + l76DeviceMismatchNote
}

// (h) priv-lvl=1 in the reply.
func (e *l76Env) cellH() {
	e.guard()
	cfg, err := e.l.derivedConfig("l76-priv1", `["priv-lvl=1"]`, "")
	if err != nil {
		e.invalid("cell h: %v", err)
	}
	defer e.restore(e.restartStanding)
	e.restart(cfg)
	user, outs, recs, err := e.tokenLogin("h")
	if err != nil {
		e.out["h"] = fmt.Sprintf("With `priv-lvl=1` the login as `%s` **failed**: %s\n\n```\n%s\n```",
			user, oneLine(err.Error()), l76Render(recs))
		return
	}
	if len(outs) < 1 {
		e.out["h"] = fmt.Sprintf("With `priv-lvl=1` the login as `%s` returned %d output(s) for %d commands; "+
			"the session table was not read.\n\n```\n%s\n```", user, len(outs), len(l76Commands), l76Render(recs))
		return
	}
	s := l76SessionOf(outs[0], user)
	priv := "(no row)"
	if s != nil {
		priv = s.PrivLvl
	}
	// Only this user's session blocks: cell (d)'s break-glass session
	// (p49-admin) may still be listed (pre-flight I2).
	e.out["h"] = fmt.Sprintf("With port49 replying `priv-lvl=1`, `%s` logged in with roles %s and priv-lvl `%s` "+
		"in the session table.\n\n```\n%s\n```\n\nThis user's rows in the session table, as the device printed them:\n\n```\n%s\n```",
		user, l76SessionRoles(outs[0], user), priv, l76Render(recs), l76FilterLog(l76UserRows(outs[0], user))) +
		"\n\n" + l76ChannelText(l76ChannelFacts(recs, user), 1)
}

// (i) priv-lvl-authorization false: the YANG default.
func (e *l76Env) cellI() {
	e.guard()
	const on = "priv-lvl-authorization true"
	defer e.restore(func() {
		e.set(l76PrivLvlAuthzOn, func(run string) bool { return strings.Contains(run, on) })
	})
	e.set(l76PrivLvlAuthzOff, func(run string) bool { return !strings.Contains(run, on) })
	user, outs, recs, err := e.tokenLogin("i")
	if err != nil {
		e.out["i"] = fmt.Sprintf("With `priv-lvl-authorization false` the login as `%s` **failed**: %s\n\n```\n%s\n```",
			user, oneLine(err.Error()), l76Render(recs))
		return
	}
	if len(outs) < 1 {
		e.out["i"] = fmt.Sprintf("With `priv-lvl-authorization false`, `%s` logged in and returned %d output(s) for "+
			"%d commands; the session table was not read. Authorization requests: %d.\n\n```\n%s\n```",
			user, len(outs), len(l76Commands), len(authzRequests(recs)), l76Render(recs))
		return
	}
	e.out["i"] = fmt.Sprintf("With `priv-lvl-authorization false`, `%s` logged in. Authorization requests: %d. "+
		"Roles in the Role column of this user's rows: %s.\n\n```\n%s\n```\n\n"+
		"This user's rows in the session table, as the device printed them:\n\n```\n%s\n```", user, len(authzRequests(recs)),
		l76SessionRoles(outs[0], user), l76Render(recs), l76FilterLog(l76UserRows(outs[0], user))) +
		"\n\n" + l76PrivLvlAuthzHazard
}

// (j) the Nokia role service request on top of priv-lvl authorization.
func (e *l76Env) cellJ() {
	e.guard()
	const on = "nokia-srl-authorization-role true"
	defer e.restore(func() {
		e.set(l76RoleServiceOff, func(run string) bool { return !strings.Contains(run, on) })
	})
	e.set(l76RoleServiceOn, func(run string) bool { return strings.Contains(run, on) })
	user, outs, recs, err := e.tokenLogin("j")
	survived := "survived"
	if err != nil {
		survived = "**failed** (" + oneLine(err.Error()) + ")"
	}
	reqs := authzRequests(recs)
	roles := "(the session table was not read)"
	rows := ""
	if len(outs) > 0 {
		roles = l76SessionRoles(outs[0], user)
		rows = "\n\nThis user's rows in the session table, as the device printed them:\n\n```\n" +
			l76FilterLog(l76UserRows(outs[0], user)) + "\n```"
	}
	e.out["j"] = fmt.Sprintf("With `service-request nokia-srl-authorization-role true`, the login as `%s` %s. "+
		"Authorization requests: %d, services %v. Roles: %s.\n\n```\n%s\n```%s",
		user, survived, len(reqs), l76Services(reqs), roles, l76Render(recs), rows)
}

// (k) the second exec channel of a priv-lvl 1 login: the roles the session
// table shows on each channel, and one write that p49-read must not be
// allowed, as the first and as the second exec. A write that succeeds is a
// measurement, not INVALID.
func (e *l76Env) cellK() {
	e.guard()
	cfg, err := e.l.derivedConfig("l76-k", `["priv-lvl=1"]`, "")
	if err != nil {
		e.invalid("cell k: %v", err)
	}
	defer e.restore(e.restartStanding)
	e.restart(cfg)

	user1, outs1, recs1, err1 := e.tokenLoginCmds("k1", []string{l76ReadSessions, l76ReadSessions})
	roles := "(not read)"
	rows := ""
	if len(outs1) == 2 {
		roles = fmt.Sprintf("first exec %s, second exec %s", l76SessionRoles(outs1[0], user1), l76SessionRoles(outs1[1], user1))
		rows = fmt.Sprintf("\n\nThe first exec's rows for this user:\n\n```\n%s\n```\n\nThe second exec's rows for this user:\n\n```\n%s\n```",
			l76FilterLog(l76UserRows(outs1[0], user1)), l76FilterLog(l76UserRows(outs1[1], user1)))
	}
	e.out["k"] = fmt.Sprintf("With port49 replying `priv-lvl=1`, `%s` ran the session-table read as its first and as its second exec "+
		"(error: %v). The Role cell: %s.%s\n\n%s", user1, err1, roles, rows, l76ChannelText(l76ChannelFacts(recs1, user1), 1))

	// The write as the second exec (a read first), then as the first exec of a
	// login of its own. The container's root removes what it made.
	attempt := func(label, name string, cmds []string, at int) l76Write {
		_, outs, _, _ := e.tokenLoginCmds(label, cmds)
		w := l76Write{Name: name}
		if len(outs) > at {
			w.MakeOut = oneLine(l76FilterLog(outs[at]))
		}
		clearOut, _, clearErr := e.sr(60*time.Second, l76CheckpointClear(name))
		w.ClearOut = oneLine(l76FilterLog(clearOut))
		w.Done = l76WriteDone(w.MakeOut, w.ClearOut, clearErr)
		return w
	}
	second := attempt("k2", l76CheckpointNameSecond, []string{l76ReadSessions, l76CheckpointMake(l76CheckpointNameSecond)}, 1)
	first := attempt("k3", l76CheckpointNameFirst, []string{l76CheckpointMake(l76CheckpointNameFirst)}, 0)
	e.out["k"] += "\n\n" + l76WriteText(first, second)
}

// (l) exit-on-reject true: cell (d), (e) and (f)'s break-glass question again.
func (e *l76Env) cellL() {
	e.guard()
	defer e.restore(func() {
		e.set(l76ExitOnRejectOff, func(run string) bool { return !strings.Contains(run, "exit-on-reject true") })
	})
	e.set(l76ExitOnRejectOn, func(run string) bool { return strings.Contains(run, "exit-on-reject true") })
	var b strings.Builder
	var refused []string
	scenario := func(name string, took time.Duration, err error, recs []map[string]any) {
		fmt.Fprintf(&b, "\n\n**%s.** `%s` (local): %s in %v.", name, breakglassUser, l76Outcome(err), took.Round(time.Millisecond))
		if len(recs) > 0 {
			fmt.Fprintf(&b, "\n\n```\n%s\n```", l76Render(recs))
		}
		if err != nil {
			refused = append(refused, name)
		}
	}

	// port49 up: a port49 user still logs in, and port49 denies the break-glass account.
	_, _, _, ctlErr := e.tokenLogin("l0")
	off := e.l.mark()
	took, err := e.try(breakglassUser, breakglassPassword)
	recs := e.l.waitForRecords(off, 20*time.Second, func(rs []map[string]any) bool { return redeemFor(rs, breakglassUser) != nil })
	scenario("A port49 deny of the break-glass account (port49 up)", took, err, recs)
	e.evidence["l1-aaa-log.txt"] = e.aaaLog(breakglassUser)

	// A wrong shared secret.
	path := e.wrongKeyConfig("l")
	defer e.restore(e.restartStanding)
	if err := e.l.restart(path); err != nil {
		e.invalid("cell l: restarting port49d on the wrong key: %v", err)
	}
	off = e.l.mark()
	took, err = e.try(breakglassUser, breakglassPassword)
	recs = e.l.drainRecords(off, 10*time.Second)
	scenario("A wrong shared secret", took, err, recs)
	e.evidence["l2-aaa-log.txt"] = e.aaaLog(breakglassUser, "tacacs")

	// port49 stopped.
	if err := e.l.stopDaemon(); err != nil {
		e.invalid("cell l: stopping port49d: %v", err)
	}
	took, err = e.try(breakglassUser, breakglassPassword)
	scenario("port49 stopped", took, err, nil)
	e.evidence["l3-aaa-log.txt"] = e.aaaLog(breakglassUser, "tacacs")

	e.out["l"] = fmt.Sprintf("With `exit-on-reject` true (srl_nokia-aaa.yang:1165), a port49 user's token login: %s.%s\n\n%s\n\n"+
		"The AAA log, per scenario, is in `l1-aaa-log.txt`, `l2-aaa-log.txt` and `l3-aaa-log.txt` under the evidence directory.",
		l76Outcome(ctlErr), b.String(), l76ExitHazard(refused))
}

// (e) a wrong shared secret: port49d is restarted with a random key; the
// device keeps the published one.
func (e *l76Env) cellE() {
	e.guard()
	path := e.wrongKeyConfig("e")
	defer e.restore(e.restartStanding)
	if err := e.l.restart(path); err != nil {
		e.invalid("cell e: restarting port49d on the wrong key: %v", err)
	}
	off := e.l.mark()
	user, secret := e.l.nextLogin(e.t)
	userTook, userErr := e.try(user, secret)
	bgTook, bgErr := e.try(breakglassUser, breakglassPassword)
	recs := e.l.drainRecords(off, 10*time.Second)
	e.evidence["e-aaa-log.txt"] = e.aaaLog(user, breakglassUser, "tacacs")
	e.out["e"] = l76ExitDefaultNote + "\n\n" + fmt.Sprintf("port49d on a key the device does not have. `%s` (port49 user): %s in %v. "+
		"`%s` (local): %s in %v. port49's diagnoses: %v (%d unvalidated record(s), %d redeem(s)).\n\n"+
		"```\n%s\n```\n\nThe AAA log:\n\n```\n%s\n```",
		user, l76Outcome(userErr), userTook.Round(time.Millisecond), breakglassUser, l76Outcome(bgErr),
		bgTook.Round(time.Millisecond), l76Diagnoses(recs), l76Count(recs, "unvalidated"), l76Count(recs, "redeem"),
		l76Render(recs), e.evidence["e-aaa-log.txt"])
}

// wrongKeyConfig writes the standing config with the wrong shared key and
// points l76WrongKeyEnv at it; cell is the calling cell, for INVALID text.
func (e *l76Env) wrongKeyConfig(cell string) string {
	e.t.Helper()
	base, err := e.l.configPath()
	if err != nil {
		e.invalid("cell %s: %v", cell, err)
	}
	raw, err := os.ReadFile(base)
	if err != nil {
		e.invalid("cell %s: %v", cell, err)
	}
	wrong, err := l76WrongKeyConfig(string(raw))
	if err != nil {
		e.invalid("cell %s: %v", cell, err)
	}
	path := filepath.Join(root, "tests", "lab", "logs", "port49d-lab-"+e.l.p.name+"-l76-wrongkey.yaml")
	if err := os.WriteFile(path, []byte(wrong), 0o600); err != nil {
		e.invalid("cell %s: %v", cell, err)
	}
	e.t.Setenv(l76WrongKeyEnv, e.wrongKey)
	return path
}

func l76Outcome(err error) string {
	if err == nil {
		return "logged in"
	}
	return "refused (" + oneLine(err.Error()) + ")"
}

// (f) port49d stopped. It stays stopped into (g).
func (e *l76Env) cellF() {
	e.guard()
	if err := e.l.stopDaemon(); err != nil {
		e.invalid("cell f: stopping port49d: %v", err)
	}
	bgTook, bgErr := e.try(breakglassUser, breakglassPassword)
	user, secret := e.l.nextLogin(e.t)
	userTook, userErr := e.try(user, secret)
	// The question is whether a command runs while accounting is unreachable,
	// so a hang is a plausible answer: 60 s per command (loginWithin), and a
	// *notObserved is the measurement, not INVALID (pre-flight I1).
	start := time.Now()
	outs, cmdErr := e.l.loginWithin(breakglassUser, breakglassPassword, 60*time.Second, l76ReadVersion)
	cmdTook := time.Since(start)
	var missed *notObserved
	ran := "did not run"
	switch {
	case cmdErr == nil && len(outs) == 1 && strings.Contains(outs[0], "26.7"):
		ran = "ran"
	case errors.As(cmdErr, &missed):
		ran = "did not finish within 60 s (" + oneLine(missed.Error()) + ")"
	case cmdErr != nil:
		ran = "did not run (" + oneLine(cmdErr.Error()) + ")"
	}
	_, rootTook, rootErr := e.sr(120*time.Second, l76ReadVersion)
	e.evidence["f-aaa-log.txt"] = e.aaaLog(breakglassUser, user, "tacacs")
	e.out["f"] = l76ExitDefaultNote + "\n\n" + fmt.Sprintf("port49d stopped. `%s`: %s in %v. `%s` (port49 user): %s in %v. A CLI command in a "+
		"break-glass session with accounting unreachable %s; login and command took %v. The same command as the "+
		"container's root (`sr_cli`) took %v (err %v).\n\nThe AAA log:\n\n```\n%s\n```",
		breakglassUser, l76Outcome(bgErr), bgTook.Round(time.Millisecond), user, l76Outcome(userErr),
		userTook.Round(time.Millisecond), ran, cmdTook.Round(time.Millisecond), rootTook.Round(time.Millisecond),
		rootErr, e.evidence["f-aaa-log.txt"])
	if bgErr != nil {
		e.t.Logf("cell f: break-glass was refused with port49 stopped; that is the measurement, not a failure")
	}
}

// (g) port49d restarted: how long until the device asks it again, then a
// quiet 70 s window for the health checks.
func (e *l76Env) cellG() {
	e.guard()
	cfg, err := e.l.configPath()
	if err != nil {
		e.invalid("cell g: %v", err)
	}
	if err := e.l.startDaemonWith(cfg, true); err != nil {
		e.invalid("cell g: starting port49d: %v", err)
	}
	t0 := time.Now()
	var back time.Duration
	probes := 0
	for time.Since(t0) < 5*time.Minute {
		probes++
		off := e.l.mark()
		e.try(breakglassUser, breakglassPassword)
		if redeemFor(e.l.waitForRecords(off, 5*time.Second, func(rs []map[string]any) bool {
			return redeemFor(rs, breakglassUser) != nil
		}), breakglassUser) != nil {
			back = time.Since(t0)
			break
		}
		// 5 s between probes keeps the logins well under SR Linux's SSH
		// rate-limit, default 20 unauthenticated sessions (srl_nokia-ssh.yang
		// 479; pre-flight M3).
		time.Sleep(5 * time.Second)
	}
	if back == 0 {
		e.invalid("cell g: the device never asked the restarted port49d in 5 minutes (%d probes)", probes)
		return
	}
	user, _, recs, err := e.tokenLogin("g")
	login := "logged in"
	if err != nil {
		login = "**failed** (" + oneLine(err.Error()) + ")"
	}
	e.l.flushCapture(e.t)
	off := e.l.mark()
	from := time.Now()
	time.Sleep(70 * time.Second)
	e.l.flushCapture(e.t)
	to := time.Now()
	quiet := e.l.recordsSince(off)
	syns, data, err := splitSent(e.l.capAbs, e.l.p.addr, from, to)
	if err != nil {
		e.invalid("cell g: reading the capture: %v", err)
	}
	e.out["g"] = fmt.Sprintf("After a restart, the device asked port49 again %v later (%d break-glass probe(s), "+
		"each a login followed by up to 5 s waiting for its record, then 5 s apart, under the SSH rate-limit default "+
		"of 20 unauthenticated sessions, srl_nokia-ssh.yang 479). The next port49 login as `%s` %s.\n\n```\n%s\n```\n\nIn a quiet %v with nobody logging in, the "+
		"device opened %d connection(s) to port49 and sent %d packet(s) with a payload; port49 wrote %d record(s).",
		back.Round(time.Second), probes, user, login, l76Render(recs), to.Sub(from).Round(time.Second),
		syns, data, len(quiet))
}

// note writes the evidence and the results note, and only after every cell
// was measured and nothing the run knew as secret is in any of it.
func (e *l76Env) note() {
	e.guard()
	for _, c := range l76Cells {
		if e.out[c.id] == "" {
			e.invalid("cell %s was not measured", c.id)
			return
		}
	}
	secrets, err := e.secrets()
	if err != nil {
		e.invalid("the run's seed tokens: %v", err)
		return
	}

	decisions, err := l76DecisionEvidence(e.l.recordsSince(e.start))
	if err != nil {
		e.invalid("%v", err)
		return
	}
	e.evidence["decisions.jsonl"] = decisions
	obs := l76Observation(e.out, e.schema, l76RunSection(e.retries, "L76-"+e.l.p.name))

	// The leak gates, every one before anything is written. Beside l76Leaks
	// they are L73's (pre-flight I5): l72HashValueLeaks on every evidence
	// file and on the note (the backstop for the token_sha256 array form),
	// l72TranscriptLeaks on every .txt file, and TokenShaped on the note too
	// (the L71 lesson: the note gets every check its evidence gets).
	names := make([]string, 0, len(e.evidence))
	for n := range e.evidence {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		body := e.evidence[n]
		if leaks := l76Leaks(body, secrets); len(leaks) > 0 {
			e.invalid("evidence %s holds %v", n, leaks)
			return
		}
		if leaks := l72HashValueLeaks(body); len(leaks) > 0 {
			e.invalid("evidence %s holds a hash value under %v", n, leaks)
			return
		}
		if strings.HasSuffix(n, ".txt") {
			if leaks := l72TranscriptLeaks(body); len(leaks) > 0 {
				e.invalid("evidence %s carries %v", n, leaks)
				return
			}
		}
		if n != "decisions.jsonl" {
			if w := labcreds.TokenShaped([]byte(body)); w != "" {
				e.invalid("evidence %s holds a token-shaped string", n)
				return
			}
		}
	}
	note := obs + l76Claim()
	if leaks := l76Leaks(note, secrets); len(leaks) > 0 {
		e.invalid("the note holds %v", leaks)
		return
	}
	if leaks := l72HashValueLeaks(note); len(leaks) > 0 {
		e.invalid("the note holds a hash value under %v", leaks)
		return
	}
	if w := labcreds.TokenShaped([]byte(note)); w != "" {
		e.invalid("the note holds a token-shaped string")
		return
	}
	dir := filepath.Join(root, "tests", "lab", "evidence", "L76-"+e.l.p.name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		e.invalid("%v", err)
		return
	}
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(e.evidence[n]), 0o644); err != nil {
			e.invalid("%v", err)
			return
		}
	}
	e.l.result(e.t, "L76", l76Claim(), obs)
}
