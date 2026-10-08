//go:build lab

package lab

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/testpki"
	"github.com/rhwendt/port49/tests/lab/labcreds"
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

// ---------------------------------------------------------------------------
// Oxidized's REST API, beyond Task 13's
// ---------------------------------------------------------------------------

// putNext is `PUT /node/next/<node>`: queue the node for its next run, as the
// wrapper does, but without a new mint.
func (o *oxidized) putNext(node string) (int, error) {
	req, err := http.NewRequest(http.MethodPut, oxidizedREST+"/node/next/"+node+"?format=json", nil)
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
}

func (r *l49Run) say(format string, a ...any) { fmt.Fprintf(&r.obs, format+"\n", a...) }

// startStack brings the compose stack and Oxidized up. router.db holds live
// tokens, so it is removed when the stack is gone (this cleanup runs after the
// stack's own).
func (r *l49Run) startStack(t *testing.T, restricted bool) *oxidized {
	t.Helper()
	rdb := filepath.Join(root, "tests", "lab", "logs", "compose-"+r.l.p.name, "local", "oxidized", "router.db")
	t.Cleanup(func() {
		_ = os.Remove(rdb)
		_ = os.Remove(rdb + ".lock")
	})
	o := startOxidized(t, r.l, restricted)
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
	// not asked here.
	o.awaitRun(r.l.p.node, time.Time{}, 5*time.Minute)
	return o
}

// finish records the stack's tokens as secrets and checks Oxidized's log for
// them (phase D). The log stays on disk and is never quoted.
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

// breakglassHostname is the hostname line of the device's own configuration,
// taken through the breakglass account, or "" and the reason when it cannot be.
func (r *l49Run) breakglassHostname() (string, string) {
	cmd := "show running-config"
	if strings.HasPrefix(r.l.p.name, "juniper") {
		cmd = "show configuration"
	}
	outs, err := r.l.loginWithin(breakglassUser, breakglassPassword, 60*time.Second, cmd)
	if err != nil || len(outs) == 0 {
		return "", fmt.Sprintf("breakglass login failed (%s)", oneLineMax(fmt.Sprint(err), 160))
	}
	if h := hostnameLine(outs[0]); h != "" {
		return h, ""
	}
	return "", "the device's configuration has no hostname line"
}

func (r *l49Run) phaseA(t *testing.T) {
	o := r.startStack(t, false)
	node := r.l.p.node
	hostname, why := r.breakglassHostname()
	if hostname == "" {
		hostname = node
	}
	mark := r.l.mark()
	start := time.Now()
	code, said := o.runWrapper("15m")
	r.say("- **A. What Oxidized sends** (role `**`, `port49-oxidized-run` with `PORT49_TTL=15m`):")
	if code != 0 {
		r.say("  - FAILED: the wrapper exited %d: %s", code, oneLineMax(said, 400))
		r.ev.add("a_wrapper", map[string]any{"exit": code, "stderr": oneLineMax(said, 400)})
		r.finish(o, "A")
		return
	}
	status, ended := o.awaitRun(node, start, 5*time.Minute)
	time.Sleep(10 * time.Second) // the decision log is followed from the container: let it catch up
	recs := r.l.recordsSince(mark)
	mine := recordsFor(recs, oxidizedUser)
	cmds := oxidizedCommands(recs, oxidizedUser, "")
	n, by := redeemSummary(mine)
	principals := mintPrincipals(recs)
	cfg, cerr := o.fetchConfig(node)
	r.say("  - The run %s with status `%s`; the wrapper exited 0.", map[bool]string{true: "ended", false: "did not end within 5m"}[ended], status)
	r.say("  - Commands port49 received from `%s`, in order, once each (%d): `%s`.", oxidizedUser, len(cmds), strings.Join(cmds, "`, `"))
	r.say("  - Authentications (redeem records) for the run: %d (%s).", n, describeCounts(by))
	r.say("  - The mint record's principal: `%s` (the workload's ID: %s).", strings.Join(principals, "`, `"),
		yesNo(len(principals) == 1 && principals[0] == l48ID))
	switch {
	case cerr != nil:
		r.say("  - The backup: `GET /node/fetch` FAILED: %s", oneLineMax(cerr.Error(), 200))
	default:
		what := "the node's name `" + node + "` (" + why + ")"
		if why == "" {
			what = "the device's own line `" + hostname + "`"
		}
		r.say("  - The backup holds %s: %s; it is %d bytes (over 1 KiB: %s).", what, yesNo(strings.Contains(cfg, hostname)), len(cfg),
			yesNo(len(cfg) > 1024))
	}
	r.ev.add("a_what_oxidized_sends", map[string]any{"status": status, "ended": ended, "commands": cmds, "redeem_count": n,
		"redeem_by_verdict_reason": by, "mint_principals": principals, "config_bytes": len(cfg), "hostname_checked": hostname,
		"hostname_note": why, "command_verdicts": commandVerdicts(recs, oxidizedUser)})
	r.finish(o, "A")
}

func (r *l49Run) phasesBC(t *testing.T) {
	o := r.startStack(t, true)
	node := r.l.p.node

	// B. A stale token.
	r.say("- **B. A stale token** (the example's role; `receipt_idle_ttl: %s` in this stack's `port49d.yaml`, so a spent token's "+
		"receipt lapses in minutes; the default is 15m):", receiptIdleTTL)
	start := time.Now()
	code, said := o.runWrapper("60s")
	if code != 0 {
		r.say("  - FAILED: the wrapper exited %d: %s", code, oneLineMax(said, 400))
		r.ev.add("b_wrapper", map[string]any{"exit": code, "stderr": oneLineMax(said, 400)})
		r.finish(o, "B and C")
		return
	}
	status, ended := o.awaitRun(node, start, 5*time.Minute)
	r.say("  - A 60s token: the run %s with status `%s`.", map[bool]string{true: "ended", false: "did not end within 5m"}[ended], status)
	time.Sleep(3 * time.Minute) // past the token's 60s and the receipt's 2m
	markB := r.l.mark()
	putAt := time.Now()
	putCode, perr := o.putNext(node)
	if perr != nil || putCode != http.StatusOK {
		r.say("  - FAILED: `PUT /node/next/%s` answered %d (%v).", node, putCode, perr)
		r.ev.add("b_put", map[string]any{"status": putCode, "error": fmt.Sprint(perr)})
		r.finish(o, "B and C")
		return
	}
	staleStatus, staleEnded := o.awaitRun(node, putAt, 3*time.Minute)
	time.Sleep(10 * time.Second)
	bRecs := r.l.recordsSince(markB)
	n, by := redeemSummary(recordsFor(bRecs, oxidizedUser))
	r.say("  - 3m later, `PUT /node/next/%s` with no new mint: the run %s; Oxidized's status `%s` (a success would be `success`).",
		node, map[bool]string{true: "ended", false: "did not end within 3m"}[staleEnded], staleStatus)
	r.say("  - Authentications that one run cost: %d redeem records (%s).", n, describeCounts(by))
	restart := time.Now()
	code, said = o.runWrapper("60s")
	reStatus, reEnded := "", false
	if code == 0 {
		reStatus, reEnded = o.awaitRun(node, restart, 5*time.Minute)
	}
	r.say("  - The wrapper again with a new 60s token (wrapper exit %d): the run %s with status `%s`; Oxidized read the new "+
		"credential at `/reload`: %s.", code, map[bool]string{true: "ended", false: "did not end within 5m"}[reEnded], reStatus,
		yesNo(reEnded && reStatus == "success"))
	r.ev.add("b_stale_token", map[string]any{"first_status": status, "stale_status": staleStatus, "stale_run_ended": staleEnded,
		"stale_redeem_count": n, "stale_redeem_by_verdict_reason": by, "again_wrapper_exit": code, "again_status": reStatus,
		"again_ended": reEnded, "receipt_idle_ttl": receiptIdleTTL})

	// C. The example's role.
	markC := r.l.mark()
	startC := time.Now()
	code, said = o.runWrapper("15m")
	r.say("- **C. The example's role** (`examples/oxidized/policy.yaml`, the same stack):")
	if code != 0 {
		r.say("  - FAILED: the wrapper exited %d: %s", code, oneLineMax(said, 400))
		r.ev.add("c_wrapper", map[string]any{"exit": code, "stderr": oneLineMax(said, 400)})
		r.finish(o, "B and C")
		return
	}
	cStatus, cEnded := o.awaitRun(node, startC, 5*time.Minute)
	time.Sleep(10 * time.Second)
	rows := commandVerdicts(r.l.recordsSince(markC), oxidizedUser)
	denied := deniedCommands(rows)
	r.say("  - The run %s with status `%s`; %d authorize_command records, %d denied.",
		map[bool]string{true: "ended", false: "did not end within 5m"}[cEnded], cStatus, len(rows), len(denied))
	if len(denied) == 0 {
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
