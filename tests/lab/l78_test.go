//go:build lab

package lab

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/testpki"
	"github.com/rhwendt/port49/tests/lab/labcreds"
)

// TestL78 is L78: whether Junos refuses a login whose permit session reply
// totals more than 255 bytes with every attribute at most 255. It steps a role
// through l78Steps under TestQualify's conformance config and mint path,
// proving break-glass before each step and after the last, as L2 did
// (TestL2Truncation), and stops at the first step that leaves break-glass
// refused. It closes no row: a VM showing no lockout leaves L78 open for
// hardware Junos.
func TestL78(t *testing.T) {
	if os.Getenv("PORT49_LAB_L78") != "1" {
		t.Skip("opt-in: PORT49_LAB_L78=1 PORT49_LAB_PLATFORMS=vjunos (or vjunos26)")
	}
	sel, _, err := platformSelection()
	if err != nil {
		t.Fatal(err)
	}
	if len(sel) != 1 {
		t.Fatalf("one platform at a time: PORT49_LAB_PLATFORMS names %d", len(sel))
	}
	p := sel[0]
	if p.name != "juniper_vjunos-router" {
		t.Fatalf("L78 is measured on vJunos-router (vjunos, vjunos26); %s is %s", p.sel, p.name)
	}
	if err := labOccupyForRun(labLockPath, fmt.Sprintf("TestL78 pid %d", os.Getpid())); err != nil {
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
	t.Run(p.name, func(t *testing.T) { newQualEnv(t, labFor(t, p)).l78() })
}

// l78Entry is the results note's entry: L78 and the firmware's slug, so each
// image's note, capture and evidence are its own (both are juniper_vjunos-router).
func (q *qualEnv) l78Entry() string { return "L78-" + q.slug }

func (q *qualEnv) l78() {
	q.guard()
	if err := testpki.WriteLab(filepath.Join(root, slicePKIDir), sliceEmail, time.Now()); err != nil {
		q.t.Fatal(err)
	}
	cfg := q.config() // writes the private copy of the policy the steps replace
	policy := filepath.Join(root, "tests", "lab", "logs", "port49d-qual-"+q.l.p.name+"-policy", "policy.yaml")
	if _, err := os.Stat(policy); err != nil {
		q.t.Fatalf("INVALID: the conformance config's private policy is not at %s: %v", policy, err)
	}
	if err := q.l.stopDaemon(); err != nil {
		q.t.Fatal(err)
	}
	q.startDaemon(cfg)
	defer q.restoreDaemon()
	rawStop := q.l.capture(q.t, q.l78Entry())
	q.master = q.l.capAbs
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		rawStop()
	}
	defer stop()
	q.start = q.l.mark()
	q.login()
	defer q.stopAgent()

	var rows []l78Row
	var bgRows []string
	breakglass := func(when string) bool {
		outs, err := q.l.loginWithin(breakglassUser, breakglassPassword, 60*time.Second, "show version")
		said, ok := breakglassRan(q.l.p.name, outs, err, 1)
		bgRows = append(bgRows, fmt.Sprintf("| %s | %s |", when, said))
		return ok
	}
	if !breakglass("before any step") {
		q.t.Fatalf("INVALID: break-glass did not log in before any step, so a lockout cannot be told from a harness fault: %s",
			bgRows[len(bgRows)-1])
	}
	stoppedAt := ""
	for _, s := range l78Steps {
		q.guard()
		row := l78Row{Target: s.Target}
		off := q.errSize()
		if err := q.l78Write(policy, l78Policy(s)); err != nil {
			q.t.Fatal(err)
		}
		line, refused := q.l78Reload(off)
		if refused {
			// The projection refused the policy at load: the step is recorded as
			// that, with the process log's own line, and the policy in force is
			// the step before's. It is never worked around.
			row.Refused = line
			row.Login = "not tried: refused at load"
			row.BreakGlass = "not run"
			rows = append(rows, row)
			continue
		}
		if line == "" {
			q.t.Fatalf("INVALID: step %d: no policy reload line in the process log within 30s of the write and SIGHUP", s.Target)
		}
		if !breakglass(fmt.Sprintf("before %d", s.Target)) {
			stoppedAt = fmt.Sprintf("break-glass refused before %d", s.Target)
			row.Login, row.BreakGlass = "not tried", "refused"
			rows = append(rows, row)
			break
		}
		tok, mintErr := q.l78Mint()
		if mintErr != "" {
			row.Login = "not tried: the broker refused the mint: " + mintErr
			row.BreakGlass = "not run"
			rows = append(rows, row)
			continue
		}
		moff := q.l.mark()
		outs, lerr := q.l.loginWithin(qualUser, tok, 150*time.Second, "show version")
		recs := q.l.waitForRecords(moff, 30*time.Second, func(rs []map[string]any) bool {
			return len(qualEvents(rs, "authorize_session", nil)) > 0
		})
		_, ran := breakglassRan(q.l.p.name, outs, lerr, 1)
		var have bool
		for _, r := range qualEvents(recs, "authorize_session", nil) {
			if parts, total, ok := l78Reply(r); ok {
				row.Parts, row.Total, have = parts, total, true
			}
		}
		row.LoggedIn = ran
		if len(outs) > 0 {
			// What the device answered, first line only: a refusal and the version
			// text read differently, and the record cannot show which.
			row.Shown = q.scrub(oneLine(firstLine(outs[0])))
			if len(row.Shown) > 80 {
				row.Shown = row.Shown[:80]
			}
		}
		row.Lockout, row.Login = l78Grade(ran, have, row.Total, row.Shown)
		if !ran && lerr != nil {
			row.Login += ": " + q.scrub(oneLine(lerr.Error()))
		}
		if !s.FailClosed && have && row.Total != s.Want {
			q.t.Errorf("step %d: the record's reply is %d bytes, `port49 explain` rendered %d", s.Target, row.Total, s.Want)
		}
		// Break-glass is proved after every step; the brief asks for it after the
		// last, and an earlier one is what stops the run.
		if breakglass(fmt.Sprintf("after %d", s.Target)) {
			row.BreakGlass = "logged in"
		} else {
			row.BreakGlass = "refused"
			stoppedAt = fmt.Sprintf("break-glass refused after %d", s.Target)
			rows = append(rows, row)
			break
		}
		rows = append(rows, row)
		if s.Target == l78Steps[0].Target && !ran {
			q.t.Fatalf("INVALID: the control step (%d bytes, under 255) was refused: %s", s.Target, row.Login)
		}
	}
	stop()
	q.l.captureNote = q.l.stoppedCaptureLine(q.t)
	q.l78Note(rows, bgRows, stoppedAt)
}

// l78Write replaces the policy file atomically (a temporary file renamed over
// it), mode 0600 in the private 0700 directory port49d's fence requires.
func (q *qualEnv) l78Write(path, text string) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(text), 0o600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (q *qualEnv) errSize() int64 {
	fi, err := os.Stat(q.l.errPath)
	if err != nil {
		return 0
	}
	return fi.Size()
}

// l78Reload sends SIGHUP to the daemon this run started (its recorded pid) and
// returns the first policy reload line port49d logs after off, and whether it
// says the reload was refused. It returns "" when none came.
func (q *qualEnv) l78Reload(off int64) (line string, refused bool) {
	if q.l.daemon == nil || q.l.daemon.Process == nil {
		q.t.Fatalf("INVALID: no daemon this run started")
	}
	if err := syscall.Kill(q.l.daemon.Process.Pid, syscall.SIGHUP); err != nil {
		q.t.Fatalf("INVALID: SIGHUP to port49d pid %d: %v", q.l.daemon.Process.Pid, err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if buf, err := os.ReadFile(q.l.errPath); err == nil && int64(len(buf)) > off {
			for _, l := range strings.Split(string(buf[off:]), "\n") {
				if strings.Contains(l, "policy reload") {
					return q.scrub(l), strings.Contains(l, "refused")
				}
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	return "", false
}

var l78Long = regexp.MustCompile(`[A-Za-z0-9_+/=.-]{24,}`)

// scrub masks what the harness's log filter masks: a line naming a credential
// word is dropped to its kind, and a long run becomes <LONG>.
func (q *qualEnv) scrub(s string) string {
	low := strings.ToLower(s)
	if strings.Contains(low, "password") || strings.Contains(low, "token") || strings.Contains(low, "secret") || strings.Contains(s, "eyJ") {
		return "<line names a credential word and is withheld>"
	}
	return l78Long.ReplaceAllString(s, "<LONG>")
}

// l78Mint runs `port49 token`; unlike q.mint a refusal is a result, not a
// harness fault. The token is never printed. mintErr is stderr's first line.
func (q *qualEnv) l78Mint() (tok, mintErr string) {
	cmd := exec.Command(filepath.Join(root, "bin", "port49"), "token", "--socket", q.sock, q.l.p.node)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	tok = strings.TrimSpace(string(out))
	if err != nil || len(tok) != labcreds.TokenLen {
		return "", q.scrub(oneLine(firstLine(stderr.String())))
	}
	q.secrets = append(q.secrets, tok)
	return tok, ""
}

// l78Note writes the evidence and the results note.
func (q *qualEnv) l78Note(rows []l78Row, bgRows []string, stoppedAt string) {
	recs := q.l.recordsSince(q.start)
	kept, err := qualRecords(recs, qualUser, q.secrets)
	if err != nil {
		q.t.Fatalf("INVALID: %v", err)
	}
	var lines []string
	for _, r := range kept {
		b, _ := json.Marshal(r)
		lines = append(lines, string(b))
	}
	files := map[string][]byte{"decisions.jsonl": []byte(strings.Join(lines, "\n") + "\n")}

	var b strings.Builder
	b.WriteString("Steps, each a role the projection renders to about the target size, run through a broker-minted token login " +
		"(`qual01`, `show version`) with break-glass proved before it and after it. \"Reply bytes\" is the sum of the attribute " +
		"lengths in the `authorize_session` record's `reply.attributes` (user-permissions, deny-commands, allow-commands, each at " +
		"most 255). \"Target\" is the brief's total. The 400 and 600 roles' deny-commands would pass 255, so the projection fails " +
		"closed (decision 26) and `port49 policy test` refuses those policies with exit 1. Those two rows are therefore not a " +
		"normal grant: the records carry reason `projection_fail_closed` and the reply `user-permissions=network`, " +
		"`deny-commands=^.*$` and an allow of ping, traceroute, telnet, ssh and mtrace only. The login worked, and the device " +
		"refused `show version` (its first line is in the login column): deny-all stopped the command.\n\n")
	b.WriteString("| target | reply bytes (attributes) | login | break-glass after |\n|---|---|---|---|\n")
	for _, r := range rows {
		reply := "no record"
		if r.Total > 0 {
			parts := make([]string, len(r.Parts))
			for i, p := range r.Parts {
				parts[i] = fmt.Sprint(p)
			}
			reply = fmt.Sprintf("%d (%s)", r.Total, strings.Join(parts, " + "))
		}
		login := r.Login
		if r.Shown != "" {
			login += "; the device's first line: `" + r.Shown + "`"
		}
		if r.Refused != "" {
			login = "refused at load: `" + r.Refused + "`"
		}
		fmt.Fprintf(&b, "| %d | %s | %s | %s |\n", r.Target, reply, login, r.BreakGlass)
	}
	b.WriteString("\nBreak-glass (`" + breakglassUser + "`, local password) around the steps:\n\n| when | result |\n|---|---|\n")
	for _, r := range bgRows {
		b.WriteString(r + "\n")
	}
	if stoppedAt != "" {
		fmt.Fprintf(&b, "\nThe run stopped: %s.\n", stoppedAt)
	}
	conclusion := l78Conclusion(rows, q.l.p.version)
	fmt.Fprintf(&b, "\n**Result: %s.** L78 stays open: hardware Junos is unmeasured, and decision 48's 255-byte budget stays.\n", conclusion)
	fmt.Fprintf(&b, "\nEvidence: `tests/lab/evidence/L78-%s-%s/decisions.jsonl` (whitelisted decision records).\n", q.slug, q.l.p.name)
	claim := "Whether Junos locks a user out when a permit session reply totals more than 255 bytes with every attribute at most 255 " +
		"(spec §15 L78), on " + q.l.p.version + ". This measures a VM and closes nothing."

	secrets := append([]string{breakglassPassword, labcreds.Key}, q.secrets...)
	dir := filepath.Join(root, "tests", "lab", "evidence", "L78-"+q.slug+"-"+q.l.p.name)
	if bad := qualWriteEvidence(dir, files, claim+"\n"+b.String(), secrets); len(bad) > 0 {
		q.t.Fatalf("INVALID: nothing written:\n  %s", strings.Join(bad, "\n  "))
	}
	q.l.result(q.t, q.l78Entry(), claim, b.String())
}
