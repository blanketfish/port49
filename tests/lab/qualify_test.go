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
}

func newQualEnv(t *testing.T, l *lab) *qualEnv {
	slug := devicemock.Slug(l.p.version)
	q := &qualEnv{t: t, l: l, slug: slug, starts: map[string]time.Time{}, ends: map[string]time.Time{}, tlsFiles: map[string][]byte{}}
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

func (q *qualEnv) junos() bool { return q.run.Platform == "juniper_junos" }

func (q *qualEnv) guard() {
	q.t.Helper()
	if err := labGuardAt(l66StopSentinel, "/", l66DiskFloorMB); err != nil {
		q.t.Fatalf("INVALID: %v", err)
	}
}

// play starts port49d on the conformance config, opens the broker session as
// the slice does, and plays each cell under one capture.
func (q *qualEnv) play() {
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
	rawStop := q.l.capture(q.t, "QUAL-"+q.slug)
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
		for _, c := range []string{"tls_token_login", "tls_store_unavailable", "tls_unknown_ca"} {
			q.verdict(c, "not_run", "this image carries no RFC 9887 client (L71)")
		}
	}
	stop()
	q.l.capAbs = q.master // the note points at the master capture
	q.l.captureNote = q.l.stoppedCaptureLine(q.t)
	q.l.capAbs = ""
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
	text, err = privatePolicy(text, filepath.Join(dir, "port49d-qual-"+q.l.p.name+"-policy"))
	if err != nil {
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
	out, err := exec.Command(port49, "login", "--broker", sliceBrokerURL,
		"--cert", filepath.Join(pki, testpki.LabClientCert), "--key", filepath.Join(pki, testpki.LabClientKey),
		"--broker-ca", filepath.Join(pki, testpki.LabCA), "--socket", q.sock).CombinedOutput()
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
	if q.junos() {
		return qualJunosL18, problems
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
	q.verdict("token_login", "pass", fmt.Sprintf("a broker-minted token logged in over SSH and ran `show version` (%d bytes of output).", len(strings.Join(outs, ""))))
}

// cellCommands plays command_permitted and command_denied from one login.
func (q *qualEnv) cellCommands() {
	cmds := qualProbeCommands(q.run.Platform)
	off := q.cell("command_permitted")
	_, err := q.l.loginWithin(qualUser, q.mint(), 150*time.Second, cmds...)
	recs := q.l.waitForRecords(off, 30*time.Second, func(rs []map[string]any) bool {
		return len(qualEvents(rs, "authorize_command", nil)) >= len(cmds) || q.junos() && qualRedeemed(rs)
	})
	if err != nil {
		q.t.Fatalf("INVALID: the commands login failed: %v\nrecords:%s", err, summarize(recs))
	}
	permitted, denied, why := qualCommandCells(q.run.Platform, recs)
	if q.junos() {
		q.verdict("command_permitted", permitted, why)
		q.verdict("command_denied", denied, why)
		return
	}
	if permitted == "pass" {
		q.verdict("command_permitted", "pass", "an authorize_command record permits `show version`.")
	} else {
		q.verdict("command_permitted", "fail", why+":"+summarize(recs))
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
	default:
		q.verdict("wrong_credential", "pass", "a random string as password was refused.")
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
	switch {
	case tokErr == nil:
		q.verdict("store_unavailable", "fail", "a token login succeeded with the store unavailable")
	case qualRedeemed(recs):
		q.verdict("store_unavailable", "fail", "a redeem was permitted with the store unavailable:"+summarize(recs))
	default:
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
	if _, err := q.l.loginWithin(qualUser, q.mint(), 150*time.Second, qualProbeCommands(q.run.Platform)...); err != nil {
		q.t.Fatalf("INVALID: the single-connection login failed: %v\nrecords:%s", err, summarize(q.l.recordsSince(off)))
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

// tlsCells reuses L73's machinery with the conformance config as its base.
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
	base := e.base()
	if e.d.Family == "nxos" {
		// NX-OS 10.6 sends no command authorization on a per-request TLS connection
		// (L73-cisco_nxos.md: cell a's logins show only `end`, cell h's single-connection
		// logins show `show version`), so the TLS cells run with single-connection on.
		base.SingleConnection = true
		e.facts = append(e.facts, "NX-OS sends no command authorization on a per-request TLS connection (L73 cells a and h); the TLS cells run with single-connection on")
	}
	e.configure(base)
	if base.SingleConnection {
		// The device may open its one connection as soon as the line is typed, before any
		// readiness capture runs, and then reuse it for every request: restart port49d so
		// the first login opens a connection the probe's capture sees.
		q.guard()
		q.tlsDaemon(e, "qual-tls", l73Daemon{Intermediates: e.files["inter.pem"]})
	}
	q.login()
	e.ready("qual-tls")
	if base.SingleConnection {
		// The probe's connection would carry the cell's login, so the cell's capture would
		// hold no handshake; a restart ends it and the login opens its own.
		q.guard()
		q.tlsDaemon(e, "qual-tls", l73Daemon{Intermediates: e.files["inter.pem"]})
		q.login()
	}

	dial := d.LoginDial
	if dial == 0 {
		dial = 45 * time.Second
	}
	login := func(user, secret string, cmds ...string) error {
		_, err := q.l.loginWithinDial(q.l.p.addr+":22", user, secret, dial, 150*time.Second, cmds...)
		return err
	}
	keep := func(cell string, _ []l73Conn) {
		q.tlsFiles[cell+".tls.json"] = e.evidence[cell+".tls.json"]
	}

	// tls_token_login: the plain token_login, command_permitted, command_denied and accounting cells together.
	off := q.cell("tls_token_login")
	stop := e.capture("tls_token_login")
	err := login(qualUser, q.mint(), qualProbeCommands(q.run.Platform)...)
	recs := q.waitStop(off)
	time.Sleep(l73SettleTail)
	keep("tls_token_login", stop())
	_, problems := q.check(recs)
	if !qualHasStop(recs) {
		problems = append(problems, "no stop record")
	}
	if err != nil {
		problems = append(problems, "the login failed: "+l73Err(err))
	}
	if len(problems) > 0 {
		q.verdict("tls_token_login", "fail", strings.Join(problems, "; ")+summarize(recs))
	} else {
		q.verdict("tls_token_login", "pass", "a token login over RFC 9887, show version, the denied command, and the stop record.")
	}

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
	tokErr := login(qualUser, tok)
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
	switch {
	case tokErr == nil:
		q.verdict("tls_store_unavailable", "fail", "a token login succeeded with the store unavailable")
	case qualRedeemed(recs):
		q.verdict("tls_store_unavailable", "fail", "a redeem was permitted with the store unavailable:"+summarize(recs))
	default:
		q.verdict("tls_store_unavailable", "pass", fmt.Sprintf("the token login was refused over TLS; break-glass logged in %v after %s.", bgErr == nil, took))
	}

	// tls_unknown_ca: port49's client_ca_file is a CA that did not sign the device's leaf.
	e.guard()
	e.settle()
	q.guard()
	q.tlsDaemon(e, "qual-unknown-ca", l73Daemon{Intermediates: e.files["inter.pem"], ClientCA: e.files["other.pem"]})
	off = q.cell("tls_unknown_ca")
	stop = e.capture("tls_unknown_ca")
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
	q.notes = append(q.notes, "- TLS handshake facts: "+strings.Join(e.facts, "; "))
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
	obs := "Every cell's verdict, with the rows it re-measures:\n\n" + strings.Join(q.notes, "\n") +
		fmt.Sprintf("\n\nEvidence: `tests/lab/evidence/QUAL-%s-%s/` (whitelisted decision records, connection headers and run.json).", q.slug, q.l.p.name)
	if bad := qualWriteEvidence(dir, files, claim+"\n"+obs, secrets); len(bad) > 0 {
		q.t.Fatalf("INVALID: nothing written:\n  %s", strings.Join(bad, "\n  "))
	}
	q.l.result(q.t, "QUAL-"+q.slug, claim, obs)
}
