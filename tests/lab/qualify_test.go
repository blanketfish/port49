//go:build lab

package lab

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/devicemock"
	adapter "github.com/rhwendt/port49/internal/platform"
	"github.com/rhwendt/port49/internal/testpki"
	"github.com/rhwendt/port49/tests/lab/labcreds"
)

// qualUser is the username tests/qual/qual-policy.yaml gives its one subject.
const qualUser = "qual01"

// TestQualify is the conformance run a firmware is vetted by (plan 11b): the
// fixed cells, under tests/qual/qual-policy.yaml and tests/qual/qual-daemon.yaml
// with tokens the broker mints, on each selected platform, default or opt-in.
// It writes whitelisted evidence the generator reads and a note citing the rows
// each cell re-measures. It closes no row.
func TestQualify(t *testing.T) {
	if os.Getenv("PORT49_LAB_QUALIFY") != "1" {
		t.Skip("opt-in: make lab-qualify P=<selector>")
	}
	sel, _, err := platformSelection()
	if err != nil {
		t.Fatal(err)
	}
	if len(sel) != 1 {
		t.Fatalf("one platform at a time: PORT49_LAB_PLATFORMS names %d", len(sel))
	}
	if err := labOccupyForRun(labLockPath, fmt.Sprintf("TestQualify pid %d", os.Getpid())); err != nil {
		t.Fatalf("INVALID: %v", err)
	}
	if err := labGuardAt(l66StopSentinel, "/", l66DiskFloorMB); err != nil {
		t.Fatalf("INVALID: %v", err)
	}
	if out, err := exec.Command("docker", "ps", "--filter", "label=containerlab", "--format", "{{.Names}}").Output(); err != nil {
		t.Fatalf("INVALID: docker ps: %v", err)
	} else if s := strings.TrimSpace(string(out)); s != "" {
		t.Fatalf("INVALID: a containerlab topology is already up (%s): the lab is single-occupant", strings.ReplaceAll(s, "\n", ", "))
	}
	// The selection itself, default and opt-in rows alike: eachSelected keeps
	// only one kind (rowsFor), which would skip the five older images.
	p := sel[0]
	if helpOnlyPlatforms[p.sel] {
		t.Skipf("%s is help-only: it runs no TACACS+", p.sel)
	}
	// The harness builds the port49d the whole run uses, from this tree's
	// clean HEAD, in a private clone so its VCS stamp is right (fix round 4;
	// a build in a nested worktree is stamped with the main checkout's HEAD).
	if root == "" {
		r, err := repoRoot()
		if err != nil {
			t.Fatalf("INVALID: repo root: %v", err)
		}
		root = r
	}
	if dirty, err := treeDirty(root, codePaths...); err != nil || dirty != "" {
		t.Fatalf("INVALID: the tree is not clean (%v):\n%s\ncommit or remove it first", err, dirty)
	}
	bin := filepath.Join(root, "bin", "port49d")
	if qualPort49dBuild, err = buildPort49dAt(root, "HEAD", os.TempDir(), bin); err != nil {
		t.Fatal(err)
	}
	if err := labSetcap(bin); err != nil {
		t.Fatalf("INVALID: %v", err)
	}
	t.Run(p.name, func(t *testing.T) { newQualEnv(t, labFor(t, p)).play() })
}

type qualEnv struct {
	t        *testing.T
	l        *lab
	slug     string
	start    int64
	sock     string
	agentOut string
	secrets  []string // every credential this run used, for the leak gate
	run      qualRun
	cfg      string // the conformance config's path
	cfgText  string // its text, the base of the TLS cells' configs
	starts   map[string]time.Time
	ends     map[string]time.Time
	order    []string
	tlsFiles map[string][]byte // <cell>.tls.json
	notes    []string
	master   string  // the run's capture
	e        *l73Env // the TLS cells' environment, once there is one
	dd       ddArmState
}

func newQualEnv(t *testing.T, l *lab) *qualEnv {
	slug := devicemock.Slug(l.p.version)
	// A side run (a policy block removed, say) names itself so its capture, evidence and note
	// never overwrite the standard run's.
	if v := os.Getenv("PORT49_LAB_QUAL_VARIANT"); v != "" {
		slug += "-variant-" + v
	}
	q := &qualEnv{t: t, l: l, slug: slug, starts: map[string]time.Time{}, ends: map[string]time.Time{}, tlsFiles: map[string][]byte{},
		dd: ddArmState{files: map[string][]byte{}, conns: map[string][]l73Conn{}}}
	// Firmware is the platform row's version string as the results notes' Image version line
	// carries it, so the slug is e.g. Nexus-9300v-10.6-2-F.
	q.run = qualRun{Platform: inventoryPlatform(t, l.p.node), LabPlatform: l.p.name, Image: l.p.version,
		Firmware: l.p.version, Date: time.Now().UTC().Format("2006-01-02"), Commit: qualGitHead(t), Transports: []string{"tcp"},
		Cells: map[string]string{}, Registers: map[string][]string{}, BreakGlass: map[string]bool{}, Results: map[string]string{}}
	return q
}

// inventoryPlatform is node's platform in tests/lab/inventory-lab.yaml: the
// port49 platform the profile's mock is admitted as.
func inventoryPlatform(t *testing.T, node string) string {
	t.Helper()
	inv, err := admission.LoadFile(filepath.Join(root, "tests", "lab", "inventory-lab.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range inv.Devices {
		if d.Name == node {
			return d.Platform
		}
	}
	t.Fatalf("INVALID: tests/lab/inventory-lab.yaml has no device %q", node)
	return ""
}

// qualGitHead is `git rev-parse --short=12 HEAD`: twelve hex characters, under
// l73SummaryLeaks' 32 and devicemock.Load's 40, so a recorded commit never
// trips a leak gate.
func qualGitHead(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("git", "-C", root, "rev-parse", "--short=12", "HEAD").Output()
	if err != nil {
		t.Fatalf("INVALID: git rev-parse: %v", err)
	}
	return strings.TrimSpace(string(out))
}

func (q *qualEnv) noCommandAuth() bool { return qualNoCommandAuth(q.run.Platform) }

func (q *qualEnv) guard() {
	q.t.Helper()
	if err := labGuardAt(l66StopSentinel, "/", l66DiskFloorMB); err != nil {
		q.t.Fatalf("INVALID: %v", err)
	}
}

// play starts port49d on the conformance config, opens the broker session as
// the slice does, and plays each cell under one capture.
func (q *qualEnv) play() {
	if os.Getenv(ddArmEnv) == "1" {
		q.ddArmCheck()
	}
	q.guard()
	// The broker's server certificate must exist when port49d starts, and a
	// later write would mint a new CA the running daemon does not trust.
	if err := testpki.WriteLab(filepath.Join(root, slicePKIDir), sliceEmail, time.Now()); err != nil {
		q.t.Fatal(err)
	}
	q.cfg = q.config()
	if err := q.l.stopDaemon(); err != nil {
		q.t.Fatal(err)
	}
	q.startDaemon(q.cfg)
	defer q.restoreDaemon()
	rawStop := q.l.capture(q.t, ddArmMasterName(q.slug, os.Getenv(ddArmEnv) == "1"))
	q.master = q.l.capAbs
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		q.l.capAbs = q.master // e.capture moved it
		rawStop()
		q.l.capAbs = "" // a sub-capture's flush must not probe the stopped master
	}
	defer stop() // a Fatal must not leave a root tcpdump running
	q.start = q.l.mark()
	q.login()
	defer func() { q.stopAgent() }()
	q.cellTokenLogin()
	q.cellCommands()
	q.cellAccounting()
	q.cellWrongCredential()
	q.cellStoreUnavailable()
	q.cellSingleConnection()
	// TLS only on the L73 images: the older rows share a platform name (and so
	// an l73Dialects key) with them but carry no RFC 9887 client (L71).
	if d, ok := l73Dialects[q.l.p.name]; ok && !d.HelpOnly && optInPlatforms[q.l.p.sel] {
		q.tlsCells(d)
		q.run.Transports = append(q.run.Transports, "tls")
	} else {
		for _, c := range []string{"tls_token_login", "tls_denied_command", "tls_store_unavailable", "tls_unknown_ca", "tls_single_connection"} {
			q.verdict(c, "not_run", "this image carries no RFC 9887 client (L71)")
		}
	}
	stop()
	q.l.capAbs = q.master // the note points at the master capture
	q.l.captureNote = q.l.stoppedCaptureLine(q.t)
	q.l.capAbs = ""
	if os.Getenv(ddArmEnv) == "1" {
		q.writeDebug()
		return
	}
	q.write()
}

// config writes the conformance run's port49d config and returns its path:
// qualConfigYAML over the lab file, the slice's broker block and the shared
// fragment, with the policy and inventory behind the fence a broker run needs.
func (q *qualEnv) config() string {
	q.t.Helper()
	read := func(parts ...string) string {
		b, err := os.ReadFile(filepath.Join(append([]string{root}, parts...)...))
		if err != nil {
			q.t.Fatal(err)
		}
		return string(b)
	}
	text, err := qualConfigYAML(read("tests", "lab", "port49d-lab.yaml"), read("tests", "lab", "slice", "broker.yaml"),
		read("tests", "qual", "qual-daemon.yaml"), filepath.Join(root, "tests", "qual", "qual-policy.yaml"))
	if err != nil {
		q.t.Fatalf("INVALID: %v", err)
	}
	dir := filepath.Join(root, "tests", "lab", "logs")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		q.t.Fatal(err)
	}
	priv, err := labPrivateSub("port49d-qual-" + q.l.p.name + "-policy")
	if err != nil {
		q.t.Fatalf("INVALID: %v", err)
	}
	text, err = privatePolicy(text, priv)
	if err != nil {
		q.t.Fatalf("INVALID: %v", err)
	}
	if text, err = stagePrivateFiles(text); err != nil {
		q.t.Fatalf("INVALID: %v", err)
	}
	q.cfgText = text
	path := filepath.Join(dir, "port49d-qual-"+q.l.p.name+".yaml")
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		q.t.Fatal(err)
	}
	return path
}

func (q *qualEnv) startDaemon(cfg string) {
	q.t.Helper()
	// The conformance config has no lab seed file: the broker mints every
	// token, so there is no seed file for the harness to read.
	q.l.splitActive = true
	if err := q.l.startDaemonWith(cfg, true); err != nil {
		q.t.Fatalf("INVALID: port49d would not start on the conformance config: %v", err)
	}
	if err := q.l.awaitTACACS(); err != nil {
		q.t.Fatal(err)
	}
}

// restoreDaemon puts port49d back on the platform's standing config, as the
// slice's deferred function does.
func (q *qualEnv) restoreDaemon() {
	if err := q.l.stopDaemon(); err != nil {
		q.t.Errorf("could not stop the conformance daemon: %v", err)
		return
	}
	q.l.splitActive = false
	std, err := q.l.configPath()
	if err != nil {
		q.t.Errorf("derive this platform's daemon config: %v", err)
		return
	}
	if err := q.l.startDaemonWith(std, true); err != nil {
		q.t.Errorf("could not put port49d back on the lab config: %v", err)
	}
}

// login opens the broker session through the slice's PKI, exactly as
// TestSliceEndToEnd does. A held session does not outlive a daemon restart,
// so it is called again after one.
func (q *qualEnv) login() {
	q.t.Helper()
	q.stopAgent()
	port49 := filepath.Join(root, "bin", "port49")
	if _, err := os.Stat(port49); err != nil {
		q.t.Fatalf("INVALID: %s is missing: run `make build` first (%v)", port49, err)
	}
	pki := filepath.Join(root, slicePKIDir)
	sockDir, err := os.MkdirTemp("", "p49qual")
	if err != nil {
		q.t.Fatal(err)
	}
	q.t.Cleanup(func() { os.RemoveAll(sockDir) })
	q.sock = filepath.Join(sockDir, "a", "agent.sock")
	out, err := withAgent(exec.Command(port49, "login", "--broker", sliceBrokerURL,
		"--cert", filepath.Join(pki, testpki.LabClientCert), "--key", filepath.Join(pki, testpki.LabClientKey),
		"--broker-ca", filepath.Join(pki, testpki.LabCA)), q.sock).CombinedOutput()
	if err != nil {
		q.t.Fatalf("INVALID: port49 login: %v", err)
	}
	q.agentOut = string(out)
}

func (q *qualEnv) stopAgent() {
	if q.agentOut == "" {
		return
	}
	stopSliceAgent(q.t, q.agentOut)
	q.agentOut = ""
}

// mint runs `port49 token`; the token is never printed.
func (q *qualEnv) mint() string {
	q.t.Helper()
	tok := sliceToken(q.t, filepath.Join(root, "bin", "port49"), q.sock, q.l.p.node)
	q.secrets = append(q.secrets, tok)
	return tok
}

// cell starts a cell: the guards, its start time, its rows. It returns the
// decision-log offset to read the cell's records from.
func (q *qualEnv) cell(name string) int64 {
	q.t.Helper()
	q.guard()
	now := time.Now().UTC()
	q.starts[name] = now
	q.order = append(q.order, name)
	q.run.Cells[name] = now.Format(time.RFC3339Nano)
	for _, c := range qualCells {
		if c.Name == name {
			q.run.Registers[name] = c.Rows
		}
	}
	return q.l.mark()
}

// verdict records a cell's outcome. A pass or a fail also ends the cell's
// window; a fail fails the test but the run goes on, so the evidence of the
// other cells is still written.
func (q *qualEnv) verdict(name, result, why string) {
	q.t.Helper()
	q.run.Results[name] = result
	q.notes = append(q.notes, fmt.Sprintf("- `%s` (re-measures %s): **%s**. %s", name, strings.Join(qualRows(name), ", "), result, why))
	if result == "fail" {
		q.t.Errorf("cell %s failed: %s", name, why)
	}
	if _, ok := q.starts[name]; ok {
		q.ends[name] = time.Now().UTC()
	}
	if result == "not_applicable" || result == "not_run" {
		delete(q.run.Cells, name)
		delete(q.starts, name)
		delete(q.run.Registers, name)
		q.order = removeString(q.order, name)
	}
}

func removeString(xs []string, s string) []string {
	var out []string
	for _, x := range xs {
		if x != s {
			out = append(out, x)
		}
	}
	return out
}

func qualRows(name string) []string {
	for _, c := range qualCells {
		if c.Name == name {
			return c.Rows
		}
	}
	return nil
}

func qualEvents(recs []map[string]any, event string, keep func(map[string]any) bool) []map[string]any {
	var out []map[string]any
	for _, r := range recs {
		if str(r, "event") == event && (keep == nil || keep(r)) {
			out = append(out, r)
		}
	}
	return out
}

func qualHasStop(recs []map[string]any) bool {
	return len(qualEvents(recs, "account", func(r map[string]any) bool { return str(r, "flags") == "stop" })) > 0
}

func qualRedeemed(recs []map[string]any) bool {
	return len(qualEvents(recs, "redeem", func(r map[string]any) bool { return str(r, "verdict") == "permit" })) > 0
}

func (q *qualEnv) waitStop(off int64) []map[string]any {
	return q.l.waitForRecords(off, 60*time.Second, qualHasStop)
}

// check is the conformance of one login's commands against its records: the
// permitted command was permitted, and the denied one was refused by the
// policy's deny. Junos sends no command authorization (L18), so its denied
// command is not sent and not asked.
func (q *qualEnv) check(recs []map[string]any) (denied string, problems []string) {
	if !qualRedeemed(recs) {
		problems = append(problems, "no permitted redeem")
	}
	if q.noCommandAuth() {
		return qualNoCommandAuthWhy(q.run.Platform), problems
	}
	if err := qualPermitProven(recs, "show version"); err != nil {
		problems = append(problems, err.Error())
	}
	cmd := qualDeniedCommand(q.run.Platform)
	if err := qualDenyProven(recs, cmd); err != nil {
		problems = append(problems, err.Error())
	}
	return "", problems
}

func (q *qualEnv) cellTokenLogin() {
	off := q.cell("token_login")
	outs, err := q.l.loginWithin(qualUser, q.mint(), 150*time.Second, "show version")
	recs := q.waitStop(off)
	if err != nil {
		q.t.Fatalf("INVALID: the broker-minted token login failed: %v\nrecords:%s", err, summarize(recs))
	}
	if !qualRedeemed(recs) {
		q.verdict("token_login", "fail", "the login ran but no redeem record permitted it:"+summarize(recs))
		return
	}
	if ran, says := qualRan(strings.Join(outs, "\n")); !ran {
		q.verdict("token_login", "fail", fmt.Sprintf("logged in, but `show version` did not run (%q)", oneLine(hideKeys(l73LogScreen(says))))+summarize(recs))
		return
	}
	q.verdict("token_login", "pass", fmt.Sprintf("a broker-minted token logged in over SSH and ran `show version` (%d bytes of output).", len(strings.Join(outs, ""))))
}

// cellCommands plays command_permitted and command_denied from one login.
func (q *qualEnv) cellCommands() {
	cmds := qualProbeCommands(q.run.Platform)
	off := q.cell("command_permitted")
	outs, err := q.l.loginWithin(qualUser, q.mint(), 150*time.Second, cmds...)
	recs := q.l.waitForRecords(off, 30*time.Second, func(rs []map[string]any) bool {
		return len(qualEvents(rs, "authorize_command", nil)) >= len(cmds) || q.noCommandAuth() && qualRedeemed(rs)
	})
	if err != nil {
		q.t.Fatalf("INVALID: the commands login failed: %v\nrecords:%s", err, summarize(recs))
	}
	permitted, denied, why := qualCommandCells(q.run.Platform, recs)
	if q.noCommandAuth() {
		q.verdict("command_permitted", permitted, why)
		q.verdict("command_denied", denied, why)
		return
	}
	if ran, says := qualRan(qualFirstOut(outs)); permitted == "pass" && !ran {
		permitted, why = "fail", fmt.Sprintf("an authorize_command record permits `show version`, but the device printed %q", oneLine(hideKeys(l73LogScreen(says))))
	}
	if permitted == "pass" {
		q.verdict("command_permitted", "pass", "an authorize_command record permits `show version`.")
	} else {
		// What the device printed for each command says whether it ran it, refused it
		// or never got to it: the first line of each, masked like any screen.
		said := ""
		for i, o := range outs {
			said += fmt.Sprintf(" %q said %q;", cmds[min(i, len(cmds)-1)], oneLine(hideKeys(l73LogScreen(firstLine(o)))))
		}
		q.verdict("command_permitted", "fail", why+":"+said+summarize(recs))
	}
	q.starts["command_denied"], q.run.Cells["command_denied"] = q.starts["command_permitted"], q.run.Cells["command_permitted"]
	q.order = append(q.order, "command_denied")
	q.run.Registers["command_denied"] = qualRows("command_denied")
	cmd := qualDeniedCommand(q.run.Platform)
	if denied != "pass" {
		q.verdict("command_denied", "fail", why+":"+summarize(recs))
	} else {
		q.verdict("command_denied", "pass", fmt.Sprintf("`%s` was refused with no_permit_dominates_deny.", cmd))
	}
}

func (q *qualEnv) cellAccounting() {
	off := q.cell("accounting")
	if _, err := q.l.loginWithin(qualUser, q.mint(), 150*time.Second, "show version"); err != nil {
		q.t.Fatalf("INVALID: the accounting login failed: %v", err)
	}
	recs := q.waitStop(off)
	starts := qualEvents(recs, "account", func(r map[string]any) bool { return str(r, "flags") == "start" })
	if len(starts) == 0 || !qualHasStop(recs) {
		q.verdict("accounting", "fail", fmt.Sprintf("%d start records, stop seen %v:%s", len(starts), qualHasStop(recs), summarize(recs)))
		return
	}
	q.verdict("accounting", "pass", "the login's start and stop records arrived.")
}

func (q *qualEnv) cellWrongCredential() {
	off := q.cell("wrong_credential")
	bad := randomHex(q.t, 16)
	q.secrets = append(q.secrets, bad)
	_, err := q.l.loginWithin(qualUser, bad, 60*time.Second)
	recs := q.l.recordsSince(off)
	switch {
	case err == nil:
		q.verdict("wrong_credential", "fail", "a random string logged in")
	case qualRedeemed(recs):
		q.verdict("wrong_credential", "fail", "the login failed but a redeem was permitted:"+summarize(recs))
	case !qualDenied(recs):
		// A login that failed before the device asked port49d anything proves nothing about
		// the credential: XRd's sshd resets a session over its rate limit.
		q.verdict("wrong_credential", "fail", fmt.Sprintf("the login failed (%s) but port49d logged no denied redeem, so the device never sent it the credential:%s",
			oneLine(hideKeys(l73LogScreen(l73Err(err)))), summarize(recs)))
	default:
		q.verdict("wrong_credential", "pass", "a random string as password was refused, and port49d denied its redeem.")
	}
}

func (q *qualEnv) cellStoreUnavailable() {
	off := q.cell("store_unavailable")
	tok := q.mint() // before the fault: the broker's mint is not what is under test
	if err := os.WriteFile(qualFaultFile, []byte("store_unavailable\n"), 0o644); err != nil {
		q.t.Fatal(err)
	}
	defer os.Remove(qualFaultFile)
	_, tokErr := q.l.loginWithin(qualUser, tok, 90*time.Second)
	start := time.Now()
	c, bgErr := q.l.dial(breakglassUser, breakglassPassword, 120*time.Second)
	took := time.Since(start).Round(time.Millisecond)
	if bgErr == nil {
		c.Close()
	}
	q.run.BreakGlass["store_unavailable"] = bgErr == nil
	recs := q.l.recordsSince(off)
	if result, why := qualStoreVerdict(tokErr, recs, qualUser); result != "pass" {
		q.verdict("store_unavailable", result, why+summarize(recs))
	} else {
		q.verdict("store_unavailable", "pass", fmt.Sprintf("the token login was refused; break-glass logged in %v after %s.", bgErr == nil, took))
	}
}

// cellSingleConnection turns the platform's single-connection mode on where
// the image offers it (singleConnection asks `?` first), then plays the TLS
// cell's sequence: show version, the denied command, the stop record.
func (q *qualEnv) cellSingleConnection() {
	q.guard()
	said := q.l.singleConnection(q.t)
	if strings.Contains(said, "The phases run on whatever connections the device opens") {
		q.verdict("single_connection", "not_run", "the image's `?` offers no single-connection form")
		return
	}
	// The admin CLI restarted port49d on the standing config.
	q.guard()
	if err := q.l.stopDaemon(); err != nil {
		q.t.Fatal(err)
	}
	q.startDaemon(q.cfg)
	q.login()
	off := q.cell("single_connection")
	began := time.Now()
	attempts, err := qualRetryUnreached(q.l.p.name, func() error {
		_, err := q.l.loginWithin(qualUser, q.mint(), 150*time.Second, qualProbeCommands(q.run.Platform)...)
		return err
	}, func() bool { return qualDenied(q.l.recordsSince(off)) }, 5*time.Minute, time.Sleep)
	if err != nil {
		q.t.Fatalf("INVALID: the single-connection login failed after %d attempt(s): %v\nrecords:%s", attempts, err, summarize(q.l.recordsSince(off)))
	}
	if attempts > 1 {
		said += fmt.Sprintf("; after port49d restarted the device refused %d login(s) over %s before it reached port49d (no record of them)",
			attempts-1, time.Since(began).Round(time.Second))
	}
	recs := q.waitStop(off)
	_, problems := q.check(recs)
	if !qualHasStop(recs) {
		problems = append(problems, "no stop record")
	}
	if len(problems) > 0 {
		q.verdict("single_connection", "fail", strings.Join(problems, "; ")+summarize(recs))
		return
	}
	q.verdict("single_connection", "pass", "single-connection on: "+oneLine(said)+".")
}

// tlsCells reuses L73's machinery with the conformance config as its base. The
// login cells grade what arrived at port49 in the mode the device ran
// (review batch 2 C1, I1): tls_token_login per-request, the device default,
// and tls_single_connection with single-connection on, last. The harness never
// turns single-connection on to make a per-request cell pass.
func (q *qualEnv) tlsCells(d l73Dialect) {
	e := newL73Env(q.t, q.l, d)
	q.e = e
	// The help probe fills e.x, the words the image's CLI lists: NX-OS types
	// `tacacs-server secure tls` only when the help offers it, and without it the
	// device sends plain TACACS+ to port 300.
	if !e.helpProbe() {
		q.t.Fatalf("INVALID: %s lists no RFC 9887 client", q.l.p.version)
	}
	q.guard()
	e.enrol()
	// EOS defaults to 300 and its running-config omits a port typed as 300
	// (L73-arista_ceos cell a), so the readback would miss the line.
	if e.d.Family != "eos" {
		e.port = l73TLSPort
	}
	q.guard()
	q.tlsDaemon(e, "qual-tls", l73Daemon{Intermediates: e.files["inter.pem"]})
	q.guard()
	e.configure(e.base())
	q.login()
	e.ready("qual-tls")

	login, err := qualTLSLogin(q.l, d)
	if err != nil {
		q.t.Fatalf("INVALID: %v", err)
	}
	keep := func(cell string, conns []l73Conn) {
		q.tlsFiles[cell+".tls.json"] = e.evidence[cell+".tls.json"]
		q.dd.conns[cell] = conns
	}
	q.run.CommandAuthorization, q.run.DeniedCommandRan, q.run.DeniedCommandAsked = map[string]string{}, map[string]bool{}, map[string]bool{}
	// The offer is read from this tree's table, so bin/port49d must be a
	// clean build of this tree's HEAD, or the two could differ (review I2).
	// TestQualify built it (fix round 4); check what it says.
	vcs := qualPort49dBuild
	if err := qualBinaryCheck(vcs, gitHead(root)); err != nil {
		q.t.Fatal(err)
	}
	// The harness compiles the same table the offer is read from: its tree
	// must be HEAD's too, untracked files included (review N4).
	if dirty, err := treeDirty(root, codePaths...); err != nil || dirty != "" {
		q.t.Fatalf("INVALID: the harness tree is not clean (%v):\n%s\ncommit or remove it first", err, dirty)
	}
	q.run.Port49d = vcs.recorded()
	q.run.TLSServerSingleConnectOffered = adapter.TLSServerSingleConnect(q.run.Platform)

	// tls_token_login is graded per connection (honored or ignored, decision 50
	// ruling 20), so its capture starts clean (review I1, O1, N1, N4, R3): no
	// connection open before or at its start. The capture sees only
	// connections whose SYN it caught, so the gauge decides.
	//   - First the readiness login's own records land (guard, settle).
	//   - Then the gauge must read 0 within qualCleanPolls: past idle_timeout,
	//     which closes, with close_notify, a connection the readiness login
	//     left held (an offered NX-OS one); a per-request device's closes at
	//     once.
	//   - It is read again once the capture has started.
	// Either failure is INVALID; only then does run.json record the clean start.
	var (
		off      int64
		stop     func() []l73Conn
		outs     []string
		recs     []map[string]any
		loginErr error
	)
	restartTLS := func() {
		q.tlsDaemon(e, "qual-tls", l73Daemon{Intermediates: e.files["inter.pem"]})
		q.login()
		q.dd.ready = len(e.ready("qual-tls-debug"))
	}
	q.debugCell(e, "tls_token_login", restartTLS, func() { e.ready("qual-tls-post") }, func() {
		e.guard()
		e.settle()
		read := func() (float64, bool) { return e.metric(qualConnectionsOpen) }
		if err := qualWaitNoConnections(read, qualCleanPolls, time.Sleep); err != nil {
			q.t.Fatal(err)
		}

		// tls_token_login: the plain token_login, command_permitted, command_denied and
		// accounting cells together, per-request.
		off = q.cell("tls_token_login")
		stop = e.capture("tls_token_login")
		if err := qualStillClean(read); err != nil {
			q.t.Fatal(err)
		}
		q.run.TLSCaptureStartedClean = true
		outs, loginErr = login(qualUser, q.mint(), qualProbeCommands(q.run.Platform)...)
		recs = q.waitStop(off)
		time.Sleep(l73SettleTail)
		keep("tls_token_login", stop())
	})
	q.tlsLoginVerdict("tls_token_login", qualPerRequest, outs, loginErr, recs)

	q.tlsDeniedCommand(e, login, keep)

	// tls_store_unavailable: the plain cell, over TLS.
	e.guard()
	e.settle()
	off = q.cell("tls_store_unavailable")
	stop = e.capture("tls_store_unavailable")
	tok := q.mint()
	if err := os.WriteFile(qualFaultFile, []byte("store_unavailable\n"), 0o644); err != nil {
		q.t.Fatal(err)
	}
	defer os.Remove(qualFaultFile)
	_, tokErr := login(qualUser, tok)
	start := time.Now()
	c, bgErr := q.l.dial(breakglassUser, breakglassPassword, 120*time.Second)
	took := time.Since(start).Round(time.Millisecond)
	if bgErr == nil {
		c.Close()
	}
	os.Remove(qualFaultFile)
	time.Sleep(l73SettleTail)
	keep("tls_store_unavailable", stop())
	q.run.BreakGlass["tls_store_unavailable"] = bgErr == nil
	recs = q.l.recordsSince(off)
	if result, why := qualStoreVerdict(tokErr, recs, qualUser); result != "pass" {
		q.verdict("tls_store_unavailable", result, why+summarize(recs))
	} else {
		q.verdict("tls_store_unavailable", "pass", fmt.Sprintf("the token login was refused over TLS; break-glass logged in %v after %s.", bgErr == nil, took))
	}

	// tls_unknown_ca: port49's client_ca_file is a CA that did not sign the device's leaf.
	q.debugCell(e, "tls_unknown_ca", restartTLS, nil, func() {
		e.guard()
		e.settle()
		q.guard()
		// The offset and the capture come before the refusing daemon: a device that
		// connects on its own as the daemon comes up is refused and struck, and a
		// record written before the offset is never graded, while the break-glass
		// login below then meets the strike backoff (held_refused, no record).
		off = q.cell("tls_unknown_ca")
		stop = e.capture("tls_unknown_ca")
		q.tlsDaemon(e, "qual-unknown-ca", l73Daemon{Intermediates: e.files["inter.pem"], ClientCA: e.files["other.pem"]})
		// The handshake is refused whatever the credential: a break-glass login makes the device try port49.
		_, _, _ = e.breakglassLogin()
		recs = q.l.waitForRecords(off, 60*time.Second, func(rs []map[string]any) bool {
			for _, r := range qualEvents(rs, "unvalidated", nil) {
				if str(sub(r, "unvalidated"), "tls_outcome") == "unknown_ca" {
					return true
				}
			}
			return false
		})
		time.Sleep(l73SettleTail)
		keep("tls_unknown_ca", stop())
	})
	refused := false
	for _, r := range qualEvents(recs, "unvalidated", nil) {
		refused = refused || str(sub(r, "unvalidated"), "tls_outcome") == "unknown_ca"
	}
	switch {
	case !refused:
		q.verdict("tls_unknown_ca", "fail", "port49d logged no tls_refused unknown_ca:"+summarize(recs))
	case qualRedeemed(recs):
		q.verdict("tls_unknown_ca", "fail", "a redeem was permitted over an untrusted chain")
	default:
		q.verdict("tls_unknown_ca", "pass", "the handshake was refused as unknown_ca and no token was redeemed.")
	}

	q.tlsSingleConnection(e, login, keep)
	q.notes = append(q.notes, "- TLS handshake facts: "+strings.Join(e.facts, "; "))
}

// tlsLoginVerdict grades a TLS login cell from its records (qualTLSCommands)
// and the first line of each command's output, and records what its commands
// did in run.json for genprofile.
func (q *qualEnv) tlsLoginVerdict(cell, mode string, outs []string, err error, recs []map[string]any) {
	var problems []string
	if !qualRedeemed(recs) {
		problems = append(problems, "no permitted redeem")
	}
	if !qualHasStop(recs) {
		problems = append(problems, "no stop record")
	}
	if err != nil {
		problems = append(problems, "the login failed: "+l73Err(err))
	}
	state, cmdProblems := qualTLSCommands(q.run.Platform, recs)
	problems = append(problems, cmdProblems...)
	var firsts []string
	for _, o := range outs {
		firsts = append(firsts, oneLine(hideKeys(l73LogScreen(firstLine(o)))))
	}
	if ran, says := qualRan(qualFirstOut(outs)); err == nil && state != "not_sent" && !ran {
		// Where port49 decided the commands (or the device sends none), show version must have run.
		problems = append(problems, fmt.Sprintf("`show version` did not run (%q)", oneLine(hideKeys(l73LogScreen(says)))))
	}
	q.run.CommandAuthorization[cell] = state
	result, why := qualTLSLoginVerdict(mode, q.run.Platform, state, problems, firsts)
	if result == "fail" {
		why += summarize(recs)
	}
	q.verdict(cell, result, why)
}

// tlsDeniedCommand is L80's cell: where per-request TLS sent port49 no command
// authorization (tls_token_login), a login typing only the command the qual
// policy denies, graded from its first output line and port49's records.
func (q *qualEnv) tlsDeniedCommand(e *l73Env, login func(string, string, ...string) ([]string, error), keep func(string, []l73Conn)) {
	switch q.run.CommandAuthorization["tls_token_login"] {
	case "not_applicable":
		q.verdict("tls_denied_command", "not_applicable", qualNoCommandAuthWhy(q.run.Platform))
		return
	case "sent":
		q.verdict("tls_denied_command", "not_run", "per-request TLS sent port49 command authorization (tls_token_login), so port49 decided the denied command there")
		return
	}
	// The closed L80 note is refused before the device time is spent, not after.
	if qualL80Applies(q.run.Platform, q.run.Firmware) {
		if why := q.l.guardRefusal("L80"); why != "" {
			q.t.Fatalf("INVALID: %s", why)
		}
	}
	e.guard()
	e.settle()
	denied := qualDeniedCommand(q.run.Platform)
	off := q.cell("tls_denied_command")
	stop := e.capture("tls_denied_command")
	outs, err := login(qualUser, q.mint(), denied)
	recs := q.waitStop(off)
	time.Sleep(l73SettleTail)
	keep("tls_denied_command", stop())
	if err != nil {
		q.verdict("tls_denied_command", "fail", qualPerRequest+": the login failed: "+l73Err(err)+summarize(recs))
		return
	}
	// The first line, masked like any screen, before it is graded or quoted.
	result, ran, why := qualDeniedCommandVerdict(denied, oneLine(hideKeys(l73LogScreen(firstLine(qualFirstOut(outs))))), recs)
	if result == "observed" {
		q.run.DeniedCommandRan["tls_denied_command"] = ran
		q.run.DeniedCommandAsked["tls_denied_command"] = len(qualCommandRecords(recs, denied)) > 0
	} else {
		why += summarize(recs)
	}
	q.verdict("tls_denied_command", result, qualPerRequest+": "+why)
}

// tlsSingleConnection is the TLS twin of single_connection: single-connection
// on the TLS server (as L73 cell h), the tls_token_login sequence, then the
// device back to per-request. The capture starts before the configuration:
// the device may open its one connection at the commit (XR) or at once.
func (q *qualEnv) tlsSingleConnection(e *l73Env, login func(string, string, ...string) ([]string, error), keep func(string, []l73Conn)) {
	e.guard()
	e.settle()
	q.guard()
	q.tlsDaemon(e, "qual-tls", l73Daemon{Intermediates: e.files["inter.pem"]})
	single := e.base()
	single.SingleConnection = true
	stop := e.capture("tls_single_connection")
	// A Fatal from the configure on must not leave the device in single-connection
	// mode. qualSwitchedFor defers the undo before the switch: a defer, not
	// t.Cleanup, because Goexit runs it here, before play's deferred
	// restoreDaemon, while port49d still runs the TLS config e.cli restarts; a
	// cleanup would run after restoreDaemon and restart the TLS daemon.
	qualSwitchedFor(func() { e.configure(single) }, func() { e.configure(e.base()) }, func(perRequest func()) {
		if e.d.EarlyCapture {
			_, _, _ = e.breakglassLogin()
		} else {
			e.ready("tls_single_connection")
		}
		q.login()
		off := q.cell("tls_single_connection")
		began := time.Now()
		var outs []string
		attempts, err := qualRetryUnreached(q.l.p.name, func() error {
			var err error
			outs, err = login(qualUser, q.mint(), qualProbeCommands(q.run.Platform)...)
			return err
		}, func() bool { return qualDenied(q.l.recordsSince(off)) }, 5*time.Minute, time.Sleep)
		recs := q.waitStop(off)
		time.Sleep(l73SettleTail)
		keep("tls_single_connection", stop())
		perRequest()
		mode := qualSingleConnection
		if attempts > 1 {
			mode += fmt.Sprintf(" (after port49d restarted the device refused %d login(s) over %s before it reached port49d; no record of them)",
				attempts-1, time.Since(began).Round(time.Second))
		}
		q.tlsLoginVerdict("tls_single_connection", mode, outs, err, recs)
	})
}

// tlsDaemon starts port49d on the conformance config plus a tls_listener.
func (q *qualEnv) tlsDaemon(e *l73Env, name string, o l73Daemon) {
	q.t.Helper()
	o.Inventory = e.invTLS
	o.TLSListen = net.JoinHostPort(l73Server, strconv.Itoa(l73TLSPort))
	o.Cert, o.Key = e.files["server.crt"], e.files["server.key"]
	if o.ClientCA == "" {
		o.ClientCA = e.files["root.pem"]
	}
	o.StateDir = e.mkdir("state")
	o.Status = "{disabled: true}"
	o.HandshakeTimeout = e.d.HandshakeTimeout
	cfg, err := l73DaemonYAML(q.cfgText, o)
	if err != nil {
		q.t.Fatalf("INVALID: %v", err)
	}
	e.cfg = e.write("port49d-"+name+".yaml", []byte(cfg))
	if err := q.l.stopDaemon(); err != nil {
		q.t.Fatalf("INVALID: stopping port49d for %s: %v", name, err)
	}
	e.startOn()
}

// qualConn is a plain 49 connection as the evidence keeps it: who, when and
// the 12-byte headers, nothing of any body.
type qualConn struct {
	Server     string     `json:"server"`
	DevicePort uint16     `json:"device_port"`
	SYNAt      time.Time  `json:"syn_at"`
	End        string     `json:"end"`
	EndAt      time.Time  `json:"end_at"`
	Plain      []l73Plain `json:"plain_tacacs_from_device,omitempty"`
}

// write builds every evidence file, gates them all, and only then writes any.
func (q *qualEnv) write() {
	q.t.Helper()
	recs := q.l.recordsSince(q.start)
	kept, err := qualRecords(recs, qualUser, q.secrets)
	if err != nil {
		q.t.Fatalf("INVALID: %v", err)
	}
	files := map[string][]byte{}
	var lines []string
	for _, r := range kept {
		b, _ := json.Marshal(r)
		lines = append(lines, string(b))
	}
	files["decisions.jsonl"] = []byte(strings.Join(lines, "\n") + "\n")

	raw, err := os.ReadFile(q.master)
	if err != nil {
		q.t.Fatalf("INVALID: %v", err)
	}
	conns, err := l73Conns(raw, q.l.p.addr)
	if err != nil {
		q.t.Fatalf("INVALID: reading the capture: %v", err)
	}
	for _, cell := range q.order {
		if strings.HasPrefix(cell, "tls_") {
			continue
		}
		var out []qualConn
		for _, c := range l73Window(conns, l73Server, q.starts[cell], q.ends[cell].Add(l73SettleTail)) {
			out = append(out, qualConn{c.Server, c.DevicePort, c.SYNAt, c.End, c.EndAt, c.Plain})
		}
		b, _ := json.MarshalIndent(out, "", "  ")
		files[cell+".conns.json"] = b
	}
	for name, b := range q.tlsFiles {
		files[name] = b
	}
	rb, _ := json.MarshalIndent(q.run, "", "  ")
	files["run.json"] = rb

	secrets := append([]string{breakglassPassword, labcreds.Key}, q.secrets...)
	if q.e != nil {
		secrets = append(secrets, q.e.allSecrets()...)
	}
	dir := filepath.Join(root, "tests", "lab", "evidence", "QUAL-"+q.slug+"-"+q.l.p.name)
	claim := "The conformance cells of plan 11b under tests/qual/qual-policy.yaml and tests/qual/qual-daemon.yaml, with " +
		"tokens the broker minted. Each cell re-measures the register rows it cites and closes none."
	obs := "Every cell's verdict, with the rows it re-measures:\n\n" + strings.Join(q.notes, "\n") + qualOperatorSection(q.run.Platform) +
		fmt.Sprintf("\n\nEvidence: `tests/lab/evidence/QUAL-%s-%s/` (whitelisted decision records, connection headers and run.json).", q.slug, q.l.p.name)
	if bad := qualWriteEvidence(dir, files, claim+"\n"+obs, secrets); len(bad) > 0 {
		q.t.Fatalf("INVALID: nothing written:\n  %s", strings.Join(bad, "\n  "))
	}
	q.l.result(q.t, "QUAL-"+q.slug, claim, obs)
	if qualL80Applies(q.run.Platform, q.run.Firmware) {
		fix := qualL80Fix{Offered: q.run.TLSServerSingleConnectOffered}
		// Only a committed baseline is cited: git, not the working tree, says so.
		base := "tests/lab/evidence/L80-" + q.l.p.name + "/baseline/"
		if out, err := exec.Command("git", "-C", root, "ls-files", "--", base).Output(); err == nil && len(strings.TrimSpace(string(out))) > 0 {
			fix.Baseline = base
		}
		err := qualWriteL80(q.notes, "QUAL-"+q.slug+"-"+q.l.p.name, secrets, fix, func(claim, obs string) {
			q.l.result(q.t, "L80", claim, obs)
		})
		if err != nil {
			q.t.Fatal(err)
		}
	}
}

// qualFirstOut is the first output of a login's commands, "" when it had none.
func qualFirstOut(outs []string) string {
	if len(outs) == 0 {
		return ""
	}
	return outs[0]
}

// qualTLSLogin is how a TLS cell logs in: loginWithin, which types IOS XE's
// commands at one pty (it answers a second exec channel with EOF), when the
// dialect keeps the default dial, else loginWithinDial with the dialect's
// (NX-OS 10.6 needs 90 s: five 5.00 s waits). loginWithin's pty path cannot
// widen the dial, so a pty platform whose dialect widens it is refused, never
// cut back to the default in silence (review M10).
func qualTLSLogin(l *lab, d l73Dialect) (func(user, secret string, cmds ...string) ([]string, error), error) {
	if d.LoginDial == 0 {
		return func(user, secret string, cmds ...string) ([]string, error) {
			return l.loginWithin(user, secret, 150*time.Second, cmds...)
		}, nil
	}
	if l.p.name == "cisco_iosxe" {
		return nil, fmt.Errorf("the %s dialect widens the login dial to %s, which loginWithin's pty path cannot honour", l.p.name, d.LoginDial)
	}
	return func(user, secret string, cmds ...string) ([]string, error) {
		return l.loginWithinDial(l.p.addr+":22", user, secret, d.LoginDial, 150*time.Second, cmds...)
	}, nil
}
