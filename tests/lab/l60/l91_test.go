// The L91 session harness (spec §15 L91): `port49 hwkey status` and `setup` on a
// real YubiKey. It is the same kind of run as L86: Ryan's own terminal, a real
// token, a broker served in-process, `port49` driven as a child process, and no
// ykman, pkcs11-tool or tpm2 run by the harness. tests/lab/L91-runbook.md is the
// order Ryan runs it in. Nothing here writes to the token: port49 hwkey is
// read-only on it, and the one write the cells make is to the config in the run's
// own HOME.
//
// One test, gated by PORT49_L91=1, with five cells in the row's order:
//
//	(a) status before setup: exit 1, the config checks FAIL, the slot checks pass,
//	    no PIN asked, no serial printed
//	(b) setup: exit 0, only issued_key and touch_key change, and Ryan's own
//	    `ykman piv info` reads the same before and after by sha256sum (their yes or no only)
//	(c) whether libykcs11 lists a slot's key with no certificate in it: an
//	    observation, "no such slot" when the token has none
//	(d) status after setup with an agent logged in: exit 0 and touch_key: true
//	(e) status --json: snake_case keys, neither the serial nor the PIN
//
// TODO(L91): the row stays open until Ryan runs this at the SER8 and the lead
// writes the note and the §15 Status; the fixtures of internal/hwkeysetup/testdata/l91
// are the token's captured facts, not a measurement of hwkey, and close no cell.

package l60

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/hwkey/serialmask"
)

const (
	gateL91         = "PORT49_L91"
	envL91Firmware  = "PORT49_L91_FIRMWARE" // typed by Ryan from their own tool
	stopSentinel    = "/tmp/port49-STOP-LAB"
	l91ResultsNote  = "tests/lab/results/L91-ser8.md"
	l91SlotChecks   = "session_slot touch_slot attestation_roots session_attested touch_attested touch_policy same_token"
	l91ConfigChecks = "config_issued_key config_touch_key"
)

// What Ryan types around setup. `ykman piv info` holds the serial, so its output is never written to a
// file: it goes into sha256sum, and Ryan compares the two hashes by eye.
const (
	l91StepBefore = "In ANOTHER terminal, Ryan types this: ykman piv info | sha256sum    (note the hash; do not paste it anywhere), then press Enter here"
	l91StepAfter  = "In the same terminal, Ryan types this: ykman piv info | sha256sum    (the same command again) and compares its hash with the first"
)

// stopRequested is whether the lab's STOP sentinel is there (tests/lab/README.md):
// the run ends cleanly between cells.
func stopRequested(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

var (
	serialRun   = regexp.MustCompile(`\d{7,}`)
	pinOrPUK    = regexp.MustCompile(`(?i)\b(pin|puk)\b`)
	snakeKey    = regexp.MustCompile(`^[a-z_]+$`)
	statusLines = regexp.MustCompile(`(?m)^(ok|FAIL)\s+([a-z_]+)`)
)

// holdsSerial is whether s holds a serial in any form the masking rule knows, or
// a run of seven or more digits.
func holdsSerial(s string) bool { return serialmask.MaskSerial(s) != s || serialRun.MatchString(s) }

// checkResults are the status lines of out as name -> "ok" or "FAIL".
func checkResults(out string) map[string]string {
	m := map[string]string{}
	for _, l := range statusLines.FindAllStringSubmatch(out, -1) {
		m[l[2]] = l[1]
	}
	return m
}

// l91VerdictA: status before setup.
func l91VerdictA(r result) l86Verdict {
	got := checkResults(r.stdout)
	all := r.stdout + r.stderr
	switch {
	case r.code != 1:
		return l86Verdict{false, fmt.Sprintf("status exited %d, want 1", r.code)}
	case holdsSerial(all):
		return l86Verdict{false, "the output holds a serial"}
	case pinOrPUK.MatchString(all):
		return l86Verdict{false, "the output mentions a PIN: it asked for one"}
	}
	for _, n := range strings.Fields(l91ConfigChecks) {
		if got[n] != "FAIL" {
			return l86Verdict{false, fmt.Sprintf("%s is %q, want FAIL (the config had no keys)", n, got[n])}
		}
	}
	for _, n := range strings.Fields(l91SlotChecks) {
		if got[n] != "ok" {
			return l86Verdict{false, fmt.Sprintf("%s is %q, want ok", n, got[n])}
		}
	}
	return l86Verdict{true, "exit 1; the config checks FAIL, the slot checks pass; no PIN asked, no serial printed"}
}

// configOnlyKeysChanged is whether after differs from before only in its
// issued_key and touch_key lines: every other line of each is the same, in order.
func configOnlyKeysChanged(before, after string) bool {
	rest := func(s string) []string {
		var out []string
		for _, l := range strings.Split(s, "\n") {
			if !strings.HasPrefix(l, "issued_key:") && !strings.HasPrefix(l, "touch_key:") {
				out = append(out, l)
			}
		}
		return out
	}
	b, a := rest(before), rest(after)
	if len(a) != len(b) {
		// the appended keys end the file; a trailing newline can differ by one empty element
		a, b = trimEmpty(a), trimEmpty(b)
	}
	return strings.Join(a, "\n") == strings.Join(b, "\n")
}

func trimEmpty(l []string) []string {
	for len(l) > 0 && l[len(l)-1] == "" {
		l = l[:len(l)-1]
	}
	return l
}

// l91VerdictB: setup. ykmanSame is Ryan's answer: 1 when their two
// `ykman piv info` listings match.
func l91VerdictB(r result, before, after string, ykmanSame int) l86Verdict {
	switch {
	case r.code != 0:
		return l86Verdict{false, fmt.Sprintf("setup exited %d, want 0", r.code)}
	case holdsSerial(r.stdout + r.stderr):
		return l86Verdict{false, "the output holds a serial"}
	case !configOnlyKeysChanged(before, after):
		return l86Verdict{false, "the config changed in a line other than issued_key and touch_key"}
	case !strings.Contains(after, "issued_key:") || !strings.Contains(after, "touch_key:"):
		return l86Verdict{false, "setup did not write issued_key and touch_key"}
	case ykmanSame != 1:
		return l86Verdict{false, "Ryan reports `ykman piv info` differs before and after"}
	}
	return l86Verdict{true, "exit 0; only issued_key and touch_key changed; ykman piv info reads the same before and after (Ryan's yes)"}
}

// l91VerdictD: status after setup with an agent logged in.
func l91VerdictD(r result) l86Verdict {
	switch {
	case r.code != 0:
		return l86Verdict{false, fmt.Sprintf("status exited %d, want 0", r.code)}
	case !strings.Contains(r.stdout, "ok    agent: touch_key: true"):
		return l86Verdict{false, "the agent check does not read touch_key: true"}
	}
	return l86Verdict{true, "exit 0; the agent check reads touch_key: true"}
}

// l91VerdictE: status --json. The object is stdout alone.
func l91VerdictE(r result) l86Verdict {
	var generic map[string]any
	if err := json.Unmarshal([]byte(r.stdout), &generic); err != nil {
		return l86Verdict{false, "stdout is not one JSON object"}
	}
	var bad []string
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, e := range x {
				if !snakeKey.MatchString(k) {
					bad = append(bad, k)
				}
				walk(e)
			}
		case []any:
			for _, e := range x {
				walk(e)
			}
		}
	}
	walk(generic)
	switch {
	case len(bad) > 0:
		return l86Verdict{false, "keys that are not snake_case: " + strings.Join(bad, ", ")}
	case holdsSerial(r.stdout + r.stderr):
		return l86Verdict{false, "the output holds a serial"}
	case pinOrPUK.MatchString(r.stdout + r.stderr):
		return l86Verdict{false, "the output mentions a PIN"}
	}
	return l86Verdict{true, "the keys are snake_case and neither the serial nor a PIN appears"}
}

// l91Versions records the firmware Ryan named and libykcs11's package version.
func (h *lab) l91Versions() error {
	fw := strings.TrimSpace(os.Getenv(envL91Firmware))
	if !regexp.MustCompile(`^\d+\.\d+\.\d+$`).MatchString(fw) {
		return fmt.Errorf("INVALID: %s=%q is not a firmware version like 5.4.3 (L91-runbook.md step 3)", envL91Firmware, fw)
	}
	h.obs("firmware_operator_reported_from_ykman", fw)
	h.obs("libykcs11_module", h.module)
	out, err := exec.Command("dpkg-query", "-W", "-f=${Version}", "ykcs11").Output()
	if err != nil || len(out) == 0 {
		return fmt.Errorf("INVALID: dpkg-query found no ykcs11 package: libykcs11's version cannot be recorded")
	}
	h.obs("libykcs11_package_version", string(out))
	return nil
}

// hwkey runs `port49 hwkey <args>` in the run's HOME. Nothing is given a
// terminal: a PIN prompt would fail rather than be answered, and the output
// is what a person would read.
func (h *lab) hwkey(field string, extra []string, args ...string) result {
	h.t.Helper()
	r := h.port49(runOpts{detached: true}, l91Args(args, extra, os.Getenv(envModule), h.noAgent)...)
	h.obsResult(field, r)
	return r
}

// l91Args are `port49 hwkey`'s arguments, pinned to an agent socket: the cell's
// own when args name one (onSock), else noAgent, a path where no agent runs. XDG_RUNTIME_DIR
// is the child's too, so without this a cell would read Ryan's running agent.
func l91Args(args, extra []string, module, noAgent string) []string {
	out := append([]string{"hwkey"}, args...)
	if module != "" {
		out = append(out, "--module", module)
	}
	out = append(out, extra...)
	if _, sock := splitSock(out); sock == "" {
		out = append(out, onSock(noAgent))
	}
	return out
}

// cellVerdict records a cell's result and fails the test on a FAIL.
func (h *lab) cellVerdict(cell string, v l86Verdict) {
	h.t.Helper()
	h.obs("cell_"+cell+"_verdict", v.String())
	if !v.pass {
		h.t.Errorf("L91 (%s): %s", cell, v)
	}
}

// ranOn is the stop check before a cell: true when the run goes on.
func (h *lab) ranOn(cell string) bool {
	h.t.Helper()
	if stopRequested(stopSentinel) {
		h.obs("stopped", "the lab's STOP sentinel "+stopSentinel+" was present before cell ("+cell+"); the run ends here")
		return false
	}
	return true
}

func TestL91(t *testing.T) {
	if os.Getenv(gateL91) != "1" {
		t.Skipf("set %s=1 and run from a terminal (a real token); see tests/lab/L91-runbook.md", gateL91)
	}
	h := newStudyLab(t, "L91", "all", true)
	h.needPKCS11()
	h.labLock(t, "TestL91")
	h.noAgent = socketIn(t)
	dl, _ := t.Deadline()
	h.l86Guard(os.Exit, dl)
	if err := h.l91Versions(); err != nil {
		t.Fatal(err)
	}
	ca := h.needLabCA()
	b := h.startLabBrokerWith(ca, h.yubicoRoots(), l86Policy)
	sock := socketIn(t)
	cfgPath := filepath.Join(h.home, ".port49", "config.yaml")
	base := fmt.Sprintf("broker: %s\nbroker_ca: %s\n", b.url, b.serverCA)
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, []byte(base), 0o600); err != nil {
		t.Fatal(err)
	}
	h.obs("scope", "port49 hwkey status and setup on the SER8's YubiKey; the config has no issued_key or touch_key at the start")

	// (a)
	if !h.ranOn("a") {
		return
	}
	h.step("1", "port49 hwkey status, before setup. It asks for nothing; touch and type nothing")
	ra := h.hwkey("a_status", nil, "status")
	h.cellVerdict("a", l91VerdictA(ra))

	// (b)
	if !h.ranOn("b") {
		return
	}
	before, _ := os.ReadFile(cfgPath)
	h.step("2", "%s", l91StepBefore)
	h.waitEnter("the first `ykman piv info | sha256sum` hash is noted", handDeadline)
	rb := h.hwkey("b_setup", nil, "setup")
	after, _ := os.ReadFile(cfgPath)
	h.step("3", "%s", l91StepAfter)
	same := h.askInt("Are the two hashes identical? 1 = yes, 0 = no")
	h.obs("b_ykman_piv_info_same", strconv.Itoa(same))
	h.cellVerdict("b", l91VerdictB(rb, string(before), string(after), same))

	// (c)
	if !h.ranOn("c") {
		return
	}
	keyless := h.askInt("Does your token have slot 9e holding a key but NO certificate? 1 = yes, 0 = no (if unsure, 0)")
	if keyless == 1 {
		rc := h.hwkey("c_status_9e", []string{"--session-slot", "9e"}, "status")
		h.obs("c_libykcs11_lists_a_key_without_a_certificate", strconv.FormatBool(checkResults(rc.stdout)["session_slot"] == "ok"))
	} else {
		h.obs("c_libykcs11_lists_a_key_without_a_certificate", "no such slot on this token")
	}

	// (d)
	if !h.ranOn("d") {
		return
	}
	login := h.typedLogin("4", "d_login", loginArgs(b, sock, h.keyRef(slot9a, false), "", h.keyRef(slot9c, false)))
	h.mustOK(login, "the login")
	rd := h.hwkey("d_status", nil, "status", onSock(sock))
	h.stopAgent(sock)
	h.cellVerdict("d", l91VerdictD(rd))

	// (e)
	if !h.ranOn("e") {
		return
	}
	re := h.hwkey("e_status_json", nil, "status", "--json")
	re.stdout = strings.TrimSpace(re.stdout)
	h.cellVerdict("e", l91VerdictE(re))
	h.writeResultsNote(t)
}

// writeResultsNote writes the run's observations for the lead, masked, to
// tests/lab/results/L91-ser8.md. It closes nothing: the lead edits §15.
func (h *lab) writeResultsNote(t *testing.T) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(h.dir, fileObs))
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, l := range strings.Split(string(raw), "\n") {
		if strings.Contains(l, " L91 ") {
			lines = append(lines, redact(l))
		}
	}
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "# L91: port49 hwkey on the SER8's YubiKey (%s)\n\n", time.Now().UTC().Format("2006-01-02"))
	buf.WriteString("Platform: SER8, YubiKey 5, libykcs11 (versions below). Written by `TestL91` from its own observations, " +
		"the serial masked; the row stays open until the lead reads this and edits spec §15.\n\n```\n")
	buf.WriteString(strings.Join(lines, "\n"))
	buf.WriteString("\n```\n")
	out := filepath.Join(repoRoot(t), l91ResultsNote)
	if err := os.WriteFile(out, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	h.say("wrote %s", l91ResultsNote)
}
