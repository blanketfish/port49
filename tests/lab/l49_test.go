//go:build lab

package lab

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/blanketfish/port49/internal/testpki"
	"github.com/blanketfish/port49/tests/lab/labcreds"
)

// L49 (policy engine spec §15): Oxidized as the day-one consumer of minted
// tokens. The claim is the row's text, word for word (a unit test holds the
// two equal).
const l49Claim = "Oxidized as the day-one consumer of minted tokens (plan 8): the commands each model (`eos`, `nxos`, " +
	"`ios`, `junos`) sends at login and during a backup, as port49 receives them; whether Oxidized reads a node's " +
	"username and password from its CSV source at each `/reload` and uses them at the node's next run " +
	"(`/node/next/<node>`); with a token past its TTL, how many authentications one node's run costs and what " +
	"Oxidized records; that no token appears in Oxidized's log at its default level; and that a backup made with a " +
	"minted token holds the device's configuration, the decision log naming the workload's principal."

const (
	// oxidizedBuild is what `oxidized --version` says of the pinned image; the
	// run asks the container and uses this only when it cannot.
	oxidizedBuild = "0.37.0-101-g65125713"
	// receiptIdleTTL is phase B's receipt window (the default is 15m).
	receiptIdleTTL = "2m"
)

// staleRunExcerpt is the lines of an Oxidized log that name what happened to a
// run: the exception class and message, and the crashfile line. Each is cut to
// 220 characters, and the excerpt is refused (empty, with an error) when it
// holds a registered secret or a compact JWS. Nothing else of the log is
// quoted.
func staleRunExcerpt(log string, secrets []string) (string, error) {
	var kept []string
	for _, ln := range strings.Split(log, "\n") {
		for _, m := range []string{"Errno::", "Net::SSH", "crashfile", " raised "} {
			if strings.Contains(ln, m) {
				// scrub the whole line, then cut it: a token across the cut
				// would leave its prefix
				if err := stepLeak(ln, secrets); err != nil {
					return "", err
				}
				kept = append(kept, oneLineMax(strings.TrimSpace(ln), 220))
				break
			}
		}
	}
	return strings.Join(kept, "\n"), nil
}

// oxidizedHostRoot is the host path of Oxidized's ROOT (config.rb:7:
// OXIDIZED_HOME, else ~/.config/oxidized), read from the overlay's environment
// and volumes so the two cannot drift. local is the stack's c.local. An error
// when ROOT is not a mount of ${PORT49_COMPOSE_LOCAL}.
func oxidizedHostRoot(overlay []byte, local string) (string, error) {
	var f struct {
		Services map[string]struct {
			Environment map[string]string `yaml:"environment"`
			Volumes     []string          `yaml:"volumes"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(overlay, &f); err != nil {
		return "", err
	}
	svc, ok := f.Services["oxidized"]
	if !ok {
		return "", errors.New("the overlay has no oxidized service")
	}
	rootDir := svc.Environment["OXIDIZED_HOME"]
	if rootDir == "" {
		if svc.Environment["HOME"] == "" {
			return "", errors.New("the overlay sets neither OXIDIZED_HOME nor HOME")
		}
		rootDir = svc.Environment["HOME"] + "/.config/oxidized"
	}
	const prefix = "${PORT49_COMPOSE_LOCAL}/"
	for _, v := range svc.Volumes {
		parts := strings.Split(v, ":")
		if len(parts) >= 2 && parts[1] == rootDir && strings.HasPrefix(parts[0], prefix) {
			return filepath.Join(local, strings.TrimPrefix(parts[0], prefix)), nil
		}
	}
	return "", fmt.Errorf("Oxidized's root %s is not a mount of ${PORT49_COMPOSE_LOCAL} in the overlay", rootDir)
}

// crashfilesSince are the node crashfiles under root whose mtime is at or
// after since. Oxidized names a crashfile by the device address, so a second
// failure overwrites the first: the name says nothing of when it was written.
func crashfilesSince(root string, since time.Time) []string {
	ents, err := os.ReadDir(filepath.Join(root, "crashes"))
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range ents {
		if !e.Type().IsRegular() {
			continue
		}
		if fi, err := e.Info(); err == nil && !fi.ModTime().Before(since) {
			names = append(names, e.Name())
		}
	}
	return names
}

// oxidizedDownWhy is why Oxidized is not serving after a run, or "" when its
// REST API answers (restErr nil). A process-crash file alone, with the API
// answering, is not down.
func oxidizedDownWhy(crashFile bool, restErr error) string {
	if restErr == nil {
		return ""
	}
	if crashFile {
		return "Oxidized's REST API does not answer and the process-crash file exists: the process crashed"
	}
	return "Oxidized's REST API does not answer (" + oneLineMax(restErr.Error(), 120) + ")"
}

// scrubWrapperSaid is the wrapper's stderr, or a line saying it was withheld
// because it holds a registered secret or a compact JWS.
func scrubWrapperSaid(said string, secrets []string) string {
	if err := stepLeak(said, secrets); err != nil {
		return "(withheld: " + err.Error() + ")"
	}
	return said
}

var offeredShape = regexp.MustCompile(`Permission denied \(([a-z,-]+)\)`)

// offeredMethods reads the authentication methods an sshd lists from the
// client's refusal of `none`: "Permission denied (publickey,...)".
func offeredMethods(stderr string) (string, bool) {
	m := offeredShape.FindStringSubmatch(stderr)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// deviceOffers asks the device's sshd which methods it lists, by trying `none`
// (the server refuses it locally; no TACACS+ authentication is attempted).
func (r *l49Run) deviceOffers() (string, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, "ssh", "-o", "BatchMode=yes", "-o", "PreferredAuthentications=none",
		"-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=15",
		"-o", "LogLevel=ERROR", "probe@"+r.l.p.addr, "true").CombinedOutput()
	return offeredMethods(string(out))
}

// authMethodsLine is phase A's note line about the example's auth_methods. It
// states what the example sets and what this device's sshd listed when asked;
// the EOS finding is cited only in the EOS note.
func authMethodsLine(platform, offered string, ok bool) string {
	s := "The example's `config` sets `auth_methods` with `keyboard-interactive` (which Oxidized's default list " +
		"`none`, `publickey`, `password` lacks) for the `eos` model alone, under `models: eos: vars`."
	if platform == "arista_eos" {
		s += " It is there for Arista EOS, which does not offer `password` (tests/lab/results/L4-error-arista_eos.md); net-ssh " +
			"skips a method the server does not list, so without it Oxidized never sends the token."
	}
	if ok {
		return s + " This device's sshd listed, for `none`: `" + offered + "`."
	}
	return s + " This device's sshd methods could not be read."
}

// authorizationLine is the note line for a run that produced no
// authorize_command record, which is a measurement: "" when n > 0. Junos
// sends no per-command TACACS+ authorization for these commands, as the
// snippet's unenforced_rules say; no other platform is said to agree.
func authorizationLine(platform string, n int) string {
	if n > 0 {
		return ""
	}
	s := "The device sent no per-command authorization for Oxidized's commands (no authorize_command record)."
	if strings.HasPrefix(platform, "juniper_") {
		s += " This is consistent with the snippet's `unenforced_rules` on Junos."
	}
	return s
}

// processCrashed is whether ROOT/crash exists: the single file cli.rb writes
// when the whole Oxidized process crashes.
func processCrashed(root string) bool {
	fi, err := os.Stat(filepath.Join(root, "crash"))
	return err == nil && fi.Mode().IsRegular()
}

// crashfiles are the names of the node crashfiles Oxidized wrote under its
// ROOT (node.rb writes one per failed node to ROOT/crashes, named by the
// device address; config.rb:48).
func crashfiles(root string) []string {
	ents, err := os.ReadDir(filepath.Join(root, "crashes"))
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range ents {
		if e.Type().IsRegular() {
			names = append(names, e.Name())
		}
	}
	return names
}

// logSince is what Oxidized's followed output files hold past the offsets
// (fileSize before the step).
func logSince(c *composeStack, outOff, errOff int64) string {
	var b strings.Builder
	for _, f := range []struct {
		name string
		off  int64
	}{{"oxidized.out", outOff}, {"oxidized.err", errOff}} {
		raw, err := os.ReadFile(filepath.Join(c.dir, f.name))
		if err != nil || int64(len(raw)) <= f.off {
			continue
		}
		b.Write(raw[f.off:])
		b.WriteByte('\n')
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

// l49ResultName is the stem of a platform's note and evidence.
func l49ResultName(platform string) string { return "L49-oxidized-" + platform }

// withReceiptIdleTTL adds the top-level receipt_idle_ttl key to the stack's
// port49d.yaml (phase B needs a spent token's receipt to lapse in minutes).
func withReceiptIdleTTL(files map[string]string, ttl string) error {
	b, ok := files["port49d.yaml"]
	if !ok {
		return fmt.Errorf("the stack has no port49d.yaml")
	}
	if strings.Contains(b, "receipt_idle_ttl:") {
		return fmt.Errorf("port49d.yaml already sets receipt_idle_ttl")
	}
	if !strings.HasSuffix(b, "\n") {
		b += "\n"
	}
	files["port49d.yaml"] = b + "receipt_idle_ttl: " + ttl + "\n"
	return nil
}

// recordsFor are the decision-log records whose session names username.
func recordsFor(recs []map[string]any, username string) []map[string]any {
	var out []map[string]any
	for _, r := range recs {
		if str(sub(r, "session"), "username") == username {
			out = append(out, r)
		}
	}
	return out
}

// redeemSummary counts the redeem records, in all and by "verdict/reason".
func redeemSummary(recs []map[string]any) (int, map[string]int) {
	by := map[string]int{}
	n := 0
	for _, r := range recs {
		if str(r, "event") != "redeem" {
			continue
		}
		n++
		by[str(r, "verdict")+"/"+str(r, "reason")]++
	}
	return n, by
}

// mintPrincipals are the principals of the mint records, in order, once each.
func mintPrincipals(recs []map[string]any) []string {
	var out []string
	seen := map[string]bool{}
	for _, r := range recs {
		if p := str(r, "principal"); str(r, "event") == "mint" && p != "" && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

// commandVerdict is one authorize_command record: what was asked, what the
// daemon decided and why.
type commandVerdict struct {
	Command string `json:"command"`
	Verdict string `json:"verdict"`
	Reason  string `json:"reason"`
}

// commandVerdicts are username's authorize_command records, in order.
func commandVerdicts(recs []map[string]any, username string) []commandVerdict {
	var out []commandVerdict
	for _, r := range recs {
		if str(r, "event") != "authorize_command" || str(sub(r, "session"), "username") != username {
			continue
		}
		out = append(out, commandVerdict{strings.Join(strs(sub(r, "request"), "vector"), " "), str(r, "verdict"), str(r, "reason")})
	}
	return out
}

// deniedCommands are the commands with a verdict other than permit, once each.
func deniedCommands(vs []commandVerdict) []string {
	var out []string
	seen := map[string]bool{}
	for _, v := range vs {
		if v.Verdict != "permit" && !seen[v.Command] {
			seen[v.Command] = true
			out = append(out, v.Command)
		}
	}
	return out
}

// hostnameLine is the first line of a device configuration that sets the
// hostname (`hostname x`, or Junos's `host-name x;`), trimmed; "" for none.
func hostnameLine(cfg string) string {
	for _, ln := range strings.Split(cfg, "\n") {
		if t := strings.TrimSpace(ln); strings.HasPrefix(t, "hostname ") || strings.HasPrefix(t, "host-name ") {
			return t
		}
	}
	return ""
}

// startupFault is a setup fault in Oxidized's startup run, which logs in with
// the setup run's live token: a run that did not end, or one that put no
// authentication to port49d (Oxidized never offered the device the token).
// Either is INVALID; a run port49d heard from is measured, whatever its status.
func startupFault(status string, ended bool, redeems int) error {
	if !ended {
		return fmt.Errorf("Oxidized's startup run did not end (status %q) (INVALID, not a measured no)", status)
	}
	if redeems == 0 {
		return fmt.Errorf("Oxidized's startup run ended with status %q and no authentication reached port49d: Oxidized "+
			"never logged in to the device (INVALID, not a measured no)", status)
	}
	return nil
}

// wrapperFault is a wrapper run that did not mint and queue the node: its
// phase has nothing to measure, so it is INVALID, never a failed cell.
func wrapperFault(code int, said string) error {
	if code == 0 {
		return nil
	}
	return fmt.Errorf("port49-oxidized-run exited %d (INVALID, not a measured no): %s", code, oneLineMax(said, 400))
}

// endedWord says whether a run ended, for a note.
func endedWord(ended bool, within time.Duration) string {
	if ended {
		return "ended"
	}
	return "did not end within " + within.String()
}

// wantsEvents is a wait condition: every event has a record whose session
// names username.
func wantsEvents(username string, events ...string) func([]map[string]any) bool {
	return func(recs []map[string]any) bool {
		mine := recordsFor(recs, username)
		for _, ev := range events {
			found := false
			for _, r := range mine {
				if str(r, "event") == ev {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
		return true
	}
}

const (
	// settleQuiet and settleBound: a log is read once the wanted records are
	// in and it has been quiet this long, and in any case after the bound.
	settleQuiet = 5 * time.Second
	settleBound = 60 * time.Second
)

// settleRecordsFn polls read until want holds and the record count has not
// changed for quiet, or bound passes. ok is whether want held.
func settleRecordsFn(read func() []map[string]any, want func([]map[string]any) bool, quiet, bound time.Duration) ([]map[string]any, bool) {
	deadline := time.Now().Add(bound)
	poll := min(max(quiet/4, 10*time.Millisecond), 500*time.Millisecond)
	last, lastChange := -1, time.Now()
	for {
		recs := read()
		if len(recs) != last {
			last, lastChange = len(recs), time.Now()
		}
		met := want(recs)
		if met && time.Since(lastChange) >= quiet {
			return recs, true
		}
		if !time.Now().Before(deadline) {
			return recs, met
		}
		time.Sleep(poll)
	}
}

// settleRecords reads port49d's decision log from off (see settleRecordsFn).
func (l *lab) settleRecords(off int64, want func([]map[string]any) bool) ([]map[string]any, bool) {
	return settleRecordsFn(func() []map[string]any { return l.recordsSince(off) }, want, settleQuiet, settleBound)
}

// parseMintedLogin is the user and token of the first line of a
// `workload token --format tsv` output (node, ?, platform, user, token).
func parseMintedLogin(tsv string) (user, token string, err error) {
	for _, ln := range strings.Split(tsv, "\n") {
		if f := strings.Split(ln, "\t"); len(f) >= 5 && f[3] != "" && f[4] != "" {
			return f[3], f[4], nil
		}
	}
	return "", "", fmt.Errorf("the output holds no line with a user and a token")
}

// ---------------------------------------------------------------------------
// Oxidized's REST API, beyond Task 13's
// ---------------------------------------------------------------------------

// nextRequest is `PUT /node/next/<node>` with the wrapper's body, `{}`:
// oxidized-web parses the body as JSON and answers an empty one 500.
func nextRequest(node string) (*http.Request, error) {
	req, err := http.NewRequest(http.MethodPut, oxidizedREST+"/node/next/"+node+"?format=json", strings.NewReader("{}"))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return req, nil
}

// putNext is `PUT /node/next/<node>`: queue the node for its next run, as the
// wrapper does, but without a new mint.
func (o *oxidized) putNext(node string) (int, error) {
	req, err := nextRequest(node)
	if err != nil {
		return 0, err
	}
	resp, err := o.http.Do(req)
	if err != nil {
		return 0, err
	}
	resp.Body.Close()
	return resp.StatusCode, nil
}

// awaitRun waits for a run of node that ended at or after since (second
// resolution, as Oxidized writes it), and returns its status. ended is false
// when none did within the time, with the status last seen.
func (o *oxidized) awaitRun(node string, since time.Time, within time.Duration) (status string, ended bool) {
	deadline := time.Now().Add(within)
	for {
		if st, end, err := o.nodeStatus(node); err == nil && st != "" {
			status = st
			if !end.Before(since.Truncate(time.Second)) {
				return st, true
			}
		}
		if time.Now().After(deadline) {
			return status, false
		}
		time.Sleep(3 * time.Second)
	}
}

// ---------------------------------------------------------------------------
// The phases
// ---------------------------------------------------------------------------

// l49Run is one platform's TestL49Oxidized: the observation and evidence
// built by the phases, which each run on their own stack.
type l49Run struct {
	t       *testing.T
	l       *lab
	obs     strings.Builder
	ev      stepEvidence
	secrets []string // every token minted and the workload's key material, never printed
	logs    []string // phase D's findings, one line per stack
	version string
	startup string // the last stack's startup run, for the note
}

func (r *l49Run) say(format string, a ...any) { fmt.Fprintf(&r.obs, format+"\n", a...) }

// startStack brings the compose stack and Oxidized up. router.db holds live
// tokens, so it is removed when the stack is gone (this cleanup runs after the
// stack's own).
func (r *l49Run) startStack(t *testing.T, restricted bool, phase string) *oxidized {
	t.Helper()
	rdb := filepath.Join(root, "tests", "lab", "logs", composeDirName(r.l.p.name, phase), "local", "oxidized", "router.db")
	t.Cleanup(func() {
		_ = os.Remove(rdb)
		_ = os.Remove(rdb + ".lock")
	})
	o := startOxidized(t, r.l, restricted, phase)
	if raw, err := os.ReadFile(filepath.Join(o.workload, testpki.WorkloadKey)); err == nil {
		o.secrets = append(o.secrets, keySecrets(raw)...)
	}
	o.awaitNode(r.l.p.node, 3*time.Minute)
	if r.version == "" {
		build := oxidizedBuild
		if out, err := o.c.run("--profile", "oxidized", "exec", "-T", "oxidized", "oxidized", "--version"); err == nil {
			if line, _, _ := strings.Cut(strings.TrimSpace(out), "\n"); line != "" && stepLeak(line, nil) == nil {
				build = oneLineMax(line, 80)
			}
		}
		r.version = fmt.Sprintf("%s (`%s`), Oxidized %s (image `%s`, %s)", r.l.p.version, r.l.p.image, build, oxidizedImage,
			imageID(oxidizedImage))
	}
	// Oxidized runs the node once at start, with the setup run's token. Let that
	// finish, so what a phase measures is its own run. Whether it succeeded is
	// recorded; whether it reached port49d at all is the setup's check. The
	// stack's decision log is new with the stack, so it is read from its start.
	st, ended := o.awaitRun(r.l.p.node, time.Time{}, 5*time.Minute)
	recs, _ := r.l.settleRecords(0, wantsEvents(oxidizedUser, "redeem"))
	n, by := redeemSummary(recordsFor(recs, oxidizedUser))
	if err := startupFault(st, ended, n); err != nil {
		t.Fatalf("%v\nOxidized's last output:\n%s", err, o.startupTail())
	}
	r.startup = fmt.Sprintf("Oxidized's own startup run (with the setup run's token, before this phase's mark) %s, status `%s`; "+
		"authentications at port49d: %d (%s).", endedWord(ended, 5*time.Minute), st, n, describeCounts(by))
	return o
}

// finish records the stack's tokens as secrets and checks Oxidized's log for
// them (phase D). The log stays on disk; a note quotes none of it here (phase B
// quotes a leak-checked excerpt of the stale run's class-and-message lines).
func (r *l49Run) finish(o *oxidized, stack string) {
	r.secrets = append(r.secrets, o.secrets...)
	out, err := o.c.run("--profile", "oxidized", "logs", "--no-color", "oxidized")
	if err != nil {
		r.logs = append(r.logs, fmt.Sprintf("%s: `docker compose logs` FAILED (%s); not checked.", stack, oneLineMax(err.Error(), 200)))
		return
	}
	if lerr := stepLeak(out, r.secrets); lerr != nil {
		r.logs = append(r.logs, fmt.Sprintf("%s: FAILED, Oxidized's log (%d bytes) holds a secret: %v. It stays on disk, unquoted.",
			stack, len(out), lerr))
		return
	}
	r.logs = append(r.logs, fmt.Sprintf("%s: Oxidized's log (%d bytes, default level) holds none of the %d tokens minted so far and no "+
		"compact JWS.", stack, len(out), len(r.secrets)))
}

// deviceHostname is the hostname line of the device's own configuration, read
// through a login with a token the workload mints for itself (the compose
// stack has no seeded logins, and port49d refuses the breakglass account on
// vEOS, N9Kv and IOS-XE). The role is `**`, so any command goes. It is taken
// before a phase's mark: its authentications are not the phase's. A device
// whose line cannot be read is t.Fatal (INVALID); the node's name is never
// stood in for it.
func (r *l49Run) deviceHostname(t *testing.T, o *oxidized) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "login.tsv")
	cmd := exec.Command(filepath.Join(o.repo, "bin", "port49"), "workload", "token", "--broker", brokerPublished,
		"--broker-ca", filepath.Join(o.c.local, "broker", testpki.LabCA), "--cert", filepath.Join(o.workload, testpki.WorkloadCert),
		"--key", filepath.Join(o.workload, testpki.WorkloadKey), "--ttl", "5m", "--purpose", "hostname for L49", "--format", "tsv",
		"--out", out, r.l.p.node)
	var errb bytes.Buffer
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		t.Fatalf("minting a login to read the hostname (INVALID, not a measured no): %v: %s", err, oneLineMax(errb.String(), 400))
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	o.secrets = append(o.secrets, routerDBSecrets(string(raw))...)
	user, token, err := parseMintedLogin(string(raw))
	if err != nil {
		t.Fatalf("the minted login (INVALID): %v", err)
	}
	show := "show running-config"
	if strings.HasPrefix(r.l.p.name, "juniper") {
		show = "show configuration"
	}
	outs, err := r.l.loginWithin(user, token, 60*time.Second, show)
	if err != nil || len(outs) == 0 {
		t.Fatalf("reading the device's configuration for its hostname (INVALID, not a measured no): %v", err)
	}
	h := hostnameLine(outs[0])
	if h == "" {
		t.Fatalf("the device's %q output has no hostname line (INVALID, not a measured no)", show)
	}
	return h
}

func (r *l49Run) phaseA(t *testing.T) {
	o := r.startStack(t, false, "a")
	node := r.l.p.node
	// The hostname login's own records (its redeem and commands) are let land
	// before phase A's mark, so they are not counted as the phase's.
	pre := r.l.mark()
	hostname := r.deviceHostname(t, o)
	// Only the redeem is waited for: a device may send no per-command
	// authorization (Junos), and the quiet period takes one that is late.
	if _, ok := r.l.settleRecords(pre, wantsEvents(oxidizedUser, "redeem")); !ok {
		t.Fatalf("the hostname login's redeem did not reach the decision log within %s (INVALID, not a measured no)", settleBound)
	}
	mark, boff := r.l.mark(), fileSize(o.c.brokerLog)
	start := time.Now()
	if err := wrapperFault(o.runWrapper("15m")); err != nil {
		t.Fatalf("phase A: %v", err)
	}
	r.say("- **A. What Oxidized sends** (role `**`, `port49-oxidized-run` with `PORT49_TTL=15m`):")
	offered, offeredOK := r.deviceOffers()
	r.say("  - %s", authMethodsLine(r.l.p.name, offered, offeredOK))
	r.ev.add("a_ssh_methods", map[string]any{"offered_for_none": offered, "read": offeredOK})
	r.say("  - %s", r.startup)
	status, ended := o.awaitRun(node, start, 5*time.Minute)
	recs, settled := r.l.settleRecords(mark, wantsEvents(oxidizedUser, "redeem"))
	// The mint is in the broker's log, not port49d's.
	brecs := waitRecordsOf(o.c.brokerLog, boff, 30*time.Second, func(rs []map[string]any) bool { return len(mintPrincipals(rs)) > 0 })
	mine := recordsFor(recs, oxidizedUser)
	cmds := oxidizedCommands(recs, oxidizedUser, "")
	n, by := redeemSummary(mine)
	principals := mintPrincipals(brecs)
	r.say("  - The run %s with status `%s`; the wrapper exited 0.", endedWord(ended, 5*time.Minute), status)
	if !settled {
		r.say("  - Only %d port49d records for `%s` arrived within %s: no redeem among them.",
			len(mine), oxidizedUser, settleBound)
	}
	if line := authorizationLine(r.l.p.name, len(oxidizedCommands(recs, oxidizedUser, ""))); line != "" {
		r.say("  - %s", line)
	}
	r.say("  - Commands port49 received from `%s`, in order, once each (%d): `%s`.", oxidizedUser, len(cmds), strings.Join(cmds, "`, `"))
	r.say("  - Authentications (redeem records) for the run: %d (%s).", n, describeCounts(by))
	if len(principals) == 0 {
		r.say("  - No mint record reached the broker's log within 30s.")
	} else {
		r.say("  - The mint record's principal: `%s` (the workload's ID: %s).", strings.Join(principals, "`, `"),
			yesNo(len(principals) == 1 && principals[0] == l48ID))
	}
	var cfg string
	if status != "success" {
		// fetchConfig is the latest stored backup, which may be an earlier run's.
		r.say("  - The run's status was `%s`, so `GET /node/fetch` (the latest stored backup) is not read as this run's.", status)
	} else if c, cerr := o.fetchConfig(node); cerr != nil {
		r.say("  - The backup: `GET /node/fetch` FAILED: %s", oneLineMax(cerr.Error(), 200))
	} else {
		cfg = c
		r.say("  - The backup holds the device's own line `%s`: %s; it is %d bytes (over 1 KiB: %s).", hostname,
			yesNo(strings.Contains(cfg, hostname)), len(cfg), yesNo(len(cfg) > 1024))
	}
	r.ev.add("a_what_oxidized_sends", map[string]any{"status": status, "ended": ended, "commands": cmds, "redeem_count": n,
		"redeem_by_verdict_reason": by, "mint_principals": principals, "config_bytes": len(cfg), "hostname_checked": hostname,
		"settled": settled, "startup_run": r.startup, "command_verdicts": commandVerdicts(recs, oxidizedUser)})
	r.finish(o, "A")
}

func (r *l49Run) phasesBC(t *testing.T) {
	o := r.startStack(t, true, "bc")
	node := r.l.p.node

	// B. A stale token.
	r.say("- **B. A stale token** (the example's role; `receipt_idle_ttl: %s` in this stack's `port49d.yaml`, so a spent token's "+
		"receipt lapses in minutes; the default is 15m):", receiptIdleTTL)
	r.say("  - %s", r.startup)
	start := time.Now()
	if err := wrapperFault(o.runWrapper("60s")); err != nil {
		t.Fatalf("phase B: %v", err)
	}
	status, ended := o.awaitRun(node, start, 5*time.Minute)
	r.say("  - A 60s token: the run %s with status `%s`.", endedWord(ended, 5*time.Minute), status)
	time.Sleep(3 * time.Minute) // past the token's 60s and the receipt's 2m
	markB := r.l.mark()
	outOff, errOff := fileSize(filepath.Join(o.c.dir, "oxidized.out")), fileSize(filepath.Join(o.c.dir, "oxidized.err"))
	overlay, oerr := os.ReadFile(filepath.Join(root, "tests", "lab", "compose", "oxidized.yaml"))
	if oerr != nil {
		t.Fatal(oerr)
	}
	oxRoot, oerr := oxidizedHostRoot(overlay, o.c.local)
	if oerr != nil {
		t.Fatalf("phase B: %v (INVALID)", oerr)
	}
	putAt := time.Now()
	putCode, perr := o.putNext(node)
	if perr != nil || putCode != http.StatusOK {
		t.Fatalf("phase B: `PUT /node/next/%s` answered %d (%v) (INVALID, not a measured no)", node, putCode, perr)
	}
	staleStatus, staleEnded := o.awaitRun(node, putAt, 3*time.Minute)
	bRecs, bSettled := r.l.settleRecords(markB, wantsEvents(oxidizedUser, "redeem"))
	n, by := redeemSummary(recordsFor(bRecs, oxidizedUser))
	r.say("  - 3m later, `PUT /node/next/%s` with no new mint: the run %s; Oxidized's status `%s` (a success would be `success`).",
		node, endedWord(staleEnded, 3*time.Minute), staleStatus)
	r.say("  - Authentications that one stale run cost: %d redeem records for `%s` between the mark taken just before the "+
		"`PUT` and the settle after it (%s); no other run was started in that span.", n, oxidizedUser, describeCounts(by))
	if !bSettled {
		r.say("  - No redeem record for `%s` arrived within %s of the run's end.", oxidizedUser, settleBound)
	}
	// What Oxidized's own log says of the stale run: the class and message only,
	// leak-checked against every token so far. net-ssh's keyboard-interactive
	// asks a tty for a second password when the first is refused, so the
	// expected class is Errno::ENOTTY, not AuthenticationFailed.
	excerpt, xerr := staleRunExcerpt(logSince(o.c, outOff, errOff), append(append([]string{}, r.secrets...), o.secrets...))
	switch {
	case xerr != nil:
		r.say("  - Oxidized's log for the stale run is withheld: %v. It stays on disk, unquoted.", xerr)
	case excerpt == "":
		r.say("  - Oxidized's log for the stale run holds no exception or crashfile line.")
	default:
		r.say("  - Oxidized's log for the stale run (class and message lines only):")
		for _, ln := range strings.Split(excerpt, "\n") {
			r.say("    - `%s`", ln)
		}
	}
	// A crashfile is named by the device address, so a later failure overwrites
	// an earlier one: the stale run wrote one when a file's mtime is at or after
	// the PUT.
	crashAll, crashStale := crashfiles(oxRoot), crashfilesSince(oxRoot, putAt)
	processCrash := processCrashed(oxRoot)
	r.say("  - Node crashfiles in Oxidized's `crashes` directory: %d written by the stale run (modified at or after the `PUT`), "+
		"%d in all; the process-crash file `crash` exists: %s.", len(crashStale), len(crashAll), yesNo(processCrash))
	stale := map[string]any{"first_status": status, "stale_status": staleStatus, "stale_run_ended": staleEnded,
		"stale_redeem_count": n, "stale_redeem_by_verdict_reason": by, "receipt_idle_ttl": receiptIdleTTL,
		"oxidized_log_excerpt": excerpt, "crashfile_written_by_stale_run": len(crashStale) > 0, "crashfiles_total": len(crashAll),
		"process_crash_file": processCrash}
	// Oxidized itself gone after the stale token is a finding, not a setup
	// fault: it is recorded, and the rest of the phase cannot run.
	if why := oxidizedDownWhy(processCrash, o.awaitREST(20*time.Second)); why != "" {
		r.say("  - After the stale run: %s. The wrapper-again run and phase C were not run.", why)
		stale["oxidized_down"] = why
		r.ev.add("b_stale_token", stale)
		r.say("- **C. The example's role**: not run, Oxidized was down after phase B's stale run.")
		r.finish(o, "B")
		return
	}
	restart := time.Now()
	if err := wrapperFault(o.runWrapper("60s")); err != nil {
		t.Fatalf("phase B, the wrapper again: %v", err)
	}
	reStatus, reEnded := o.awaitRun(node, restart, 5*time.Minute)
	r.say("  - The wrapper again with a new 60s token (wrapper exit 0): the run %s with status `%s`; Oxidized read the new "+
		"credential at `/reload`: %s.", endedWord(reEnded, 5*time.Minute), reStatus, yesNo(reEnded && reStatus == "success"))
	stale["again_wrapper_exit"], stale["again_status"], stale["again_ended"] = 0, reStatus, reEnded
	r.ev.add("b_stale_token", stale)

	// C. The example's role.
	markC := r.l.mark()
	startC := time.Now()
	if err := wrapperFault(o.runWrapper("15m")); err != nil {
		t.Fatalf("phase C: %v", err)
	}
	r.say("- **C. The example's role** (`examples/oxidized/policy.yaml`, the same stack):")
	cStatus, cEnded := o.awaitRun(node, startC, 5*time.Minute)
	cRecs, cSettled := r.l.settleRecords(markC, wantsEvents(oxidizedUser, "redeem"))
	rows := commandVerdicts(cRecs, oxidizedUser)
	denied := deniedCommands(rows)
	r.say("  - The run %s with status `%s`; %d authorize_command records, %d denied.",
		endedWord(cEnded, 5*time.Minute), cStatus, len(rows), len(denied))
	if !cSettled {
		r.say("  - No redeem record for `%s` arrived within %s of the run's end.", oxidizedUser, settleBound)
	}
	if line := authorizationLine(r.l.p.name, len(rows)); line != "" {
		r.say("  - %s", line)
	} else if len(denied) == 0 {
		r.say("  - Every command was permitted.")
	} else {
		r.say("  - The snippet lacks: `%s`.", strings.Join(denied, "`, `"))
	}
	r.ev.add("c_example_role", map[string]any{"status": cStatus, "ended": cEnded, "command_verdicts": rows, "denied": denied})
	r.finish(o, "B and C")
}

// TestL49Oxidized measures L49 (policy engine spec §15) on each selected
// platform: the compose stack with Oxidized on it. Its phases are a
// measurement whatever they find; a fault in the setup is t.Fatal, INVALID,
// and no note is written for a run that failed.
func TestL49Oxidized(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		stop := l.capture(t, "L49-oxidized")
		defer stop()
		r := &l49Run{t: t, l: l}
		// Each phase has its own stack: the configs are copied into the stack's
		// volumes once, at `up`, so a different role is a different start.
		t.Run("a_what_oxidized_sends", r.phaseA)
		if t.Failed() {
			return
		}
		t.Run("b_and_c_stale_token_and_example_role", r.phasesBC)
		if t.Failed() {
			return
		}
		r.say("- **D. No token in Oxidized's log** (`docker compose logs oxidized`, through the secrets check against every " +
			"token minted in A to C and the workload's key):")
		for _, ln := range r.logs {
			r.say("  - %s", ln)
		}
		r.write(t, l.captureLine(t))
	})
}

// write writes the platform's note and evidence, or fails the test when either
// would hold a token, a key or a compact JWS.
func (r *l49Run) write(t *testing.T, captureLine string) {
	t.Helper()
	name := l49ResultName(r.l.p.name)
	evPath := filepath.Join("tests", "lab", "evidence", name+".json")
	body, err := r.ev.encode(r.secrets)
	if err != nil {
		t.Fatal(err)
	}
	obs := "- **Device capture:** " + captureLine + "\n" + r.obs.String()
	note := workloadNote("L49", r.l.p.name, l49Claim, obs, evPath, runLine(), r.version)
	if lerr := stepLeak(note, r.secrets); lerr != nil {
		t.Fatalf("the note is not written: %v", lerr)
	}
	for _, d := range []string{"evidence", "results"} {
		if err := os.MkdirAll(filepath.Join(root, "tests", "lab", d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, evPath), body, 0o644); err != nil {
		t.Fatal(err)
	}
	notePath := filepath.Join(root, "tests", "lab", "results", name+".md")
	if err := os.WriteFile(notePath, []byte(labcreds.RedactNote(note)), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %s and %s", notePath, filepath.Join(root, evPath))
}
