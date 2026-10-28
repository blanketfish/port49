// The L86 session harness (spec §15 L86): an admin call's touch on a real
// YubiKey. It lives beside the L60 harness because it is the same kind of run:
// Ryan's own terminal, a real token, a broker served in-process, and `port49`
// driven as a child process (the harness uses neither ykman, pkcs11-tool nor
// tpm2). tests/lab/L86-runbook.md is the order the cells run in.
//
// One Go test per cell, each run by its anchored name and gated by PORT49_L86=1:
//
//	(a) TestL86A  two admin calls 5 s apart: each needs its own touch
//	(b) TestL86B  no touch: the time to failure, the words, no mark
//	(c) TestL86C  a session key in slot 9e (not 9a) beside the touch key: one touch
//	(d) TestL86D  the key unplugged: the CLI says to insert it, nothing is sent
//
// Each cell records PASS or FAIL on a line `L86 <cell> verdict: ...`, with the
// libykcs11 package version and the firmware, in the test log and in
// observations.log in the lab directory (the lead writes L86-ser8.md from
// them). A PIN goes only from Ryan's keyboard to port49's own prompt. A token,
// a challenge, a signature and a response are never read: port49's stdout and
// stderr are recorded line by line through redact, which also masks a serial
// and any long opaque value, and the decision log is read for event names only.

package l60

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/clientkey"
)

const (
	gateL86       = "PORT49_L86"
	gateL86Prep   = "PORT49_L86_PREP"
	envFirmware   = "PORT49_L86_FIRMWARE" // typed by Ryan from their own tool: port49 does not report it
	envSlot9eID   = "PORT49_L86_SLOT_9E_ID"
	defaultSlot9e = "04" // libykcs11's CKA_ID for PIV slot 9e (9a 01, 9c 02, 9d 03)
	fileSlot9e    = "slot9e.pem"
	labLockFile   = "/tmp/port49-lab.lock" // tests/lab/occupancy.go's lock: one occupant
)

// The words and numbers the cells judge by (spec §15 L86; hwkey.ErrTouchTimeout;
// agent/keyerror.go).
const (
	touchTimeoutWords = "no touch within 15s"
	insertWords       = "insert your key"
	gapBetweenCalls   = 5 * time.Second
	adminDeadline     = 60 * time.Second
)

// l86Policy is labPolicy with the broker API's two admin rights on the subject:
// the person who revokes and lifts, and the only one the lab has.
func l86Policy(touch bool) string {
	return strings.Replace(labPolicy(touch), "token_ttl: 60s}", "token_ttl: 60s, api: [revoke_others, lift_revocations]}", 1)
}

// l86Verdict is one cell's result.
type l86Verdict struct {
	pass bool
	why  string
}

func (v l86Verdict) String() string {
	if v.pass {
		return "PASS: " + v.why
	}
	return "FAIL: " + v.why
}

// l86VerdictA: each admin call needs its own touch. The first, touched, ran;
// the second, untouched, failed with the timeout words; the third, touched
// again, ran.
func l86VerdictA(c1, c2, c3 result, blinkedAgain int) l86Verdict {
	switch {
	case c1.code != 0:
		return l86Verdict{false, fmt.Sprintf("the first, touched, call exited %d", c1.code)}
	case c2.code == 0:
		return l86Verdict{false, "the second call ran with no touch: the first touch was reused"}
	case !strings.Contains(c2.stderr, touchTimeoutWords):
		return l86Verdict{false, fmt.Sprintf("the second call failed (exit %d) without the timeout words", c2.code)}
	case c3.code != 0:
		return l86Verdict{false, fmt.Sprintf("the third, touched, call exited %d", c3.code)}
	}
	return l86Verdict{true, fmt.Sprintf("each call took its own touch; Ryan saw the second blink again: %d (1 yes, 0 no)", blinkedAgain)}
}

// l86VerdictB: the CLI prints the timeout line, exits 1, and the revocation
// list shows no mark for the target.
func l86VerdictB(c result, list result, target string) l86Verdict {
	switch {
	case c.code != 1:
		return l86Verdict{false, fmt.Sprintf("the untouched call exited %d, want 1", c.code)}
	case !strings.Contains(c.stderr, touchTimeoutWords):
		return l86Verdict{false, "the CLI did not print the timeout line"}
	case list.code != 0:
		return l86Verdict{false, fmt.Sprintf("revoke --list exited %d", list.code)}
	case strings.Contains(list.stdout, target):
		return l86Verdict{false, "revoke --list shows a mark for the untouched call's target"}
	}
	return l86Verdict{true, fmt.Sprintf("exit 1 with the timeout line after %s; no mark", c.took.Round(100*time.Millisecond))}
}

// l86VerdictC: the admin call with the 9e session key succeeds with one touch.
func l86VerdictC(c result, touches int) l86Verdict {
	switch {
	case c.code != 0:
		return l86Verdict{false, fmt.Sprintf("the call exited %d", c.code)}
	case touches != 1:
		return l86Verdict{false, fmt.Sprintf("Ryan counted %d touches, want 1", touches)}
	}
	return l86Verdict{true, "the call succeeded with one touch"}
}

// l86VerdictD: the CLI fails saying to insert the key, and the broker's decision
// log grew by no admin record at all, so nothing was sent and no
// admin_touch_refused was made.
func l86VerdictD(c result, grown []string) l86Verdict {
	switch {
	case c.code == 0:
		return l86Verdict{false, "the call succeeded with the key out"}
	case !strings.Contains(strings.ToLower(c.stderr), insertWords):
		return l86Verdict{false, "the CLI did not say to insert the key"}
	case len(grown) != 0:
		return l86Verdict{false, "the broker's log grew by " + strings.Join(grown, ", ")}
	}
	return l86Verdict{true, "the CLI said to insert the key and the broker's log grew by no admin record"}
}

// l86Firmware checks the firmware string Ryan typed: three numbers, as the
// token's own tool prints it.
func l86Firmware(s string) (string, error) {
	s = strings.TrimSpace(s)
	if !regexp.MustCompile(`^\d+\.\d+\.\d+$`).MatchString(s) {
		return "", fmt.Errorf("%s=%q is not a firmware version like 5.4.3", envFirmware, s)
	}
	return s, nil
}

// l86AdminEvents are the decision-log lines past the first from lines whose
// event is an admin call's or a revoke, as "event reason" names. Only
// names are read: never a principal, a challenge or a body.
func l86AdminEvents(logPath string, from int) ([]string, int, error) {
	raw, err := os.ReadFile(logPath)
	if err != nil {
		return nil, from, err
	}
	return l86AdminEventsFrom(string(raw), from)
}

// l86AdminEventsFrom is l86AdminEvents over the log's text.
func l86AdminEventsFrom(text string, from int) ([]string, int, error) {
	var out []string
	n := 0
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		n++
		if n <= from {
			continue
		}
		var rec struct {
			Event  string `json:"event"`
			Reason string `json:"reason"`
		}
		if json.Unmarshal(sc.Bytes(), &rec) != nil {
			continue
		}
		if strings.HasPrefix(rec.Event, "admin") || strings.HasPrefix(rec.Event, "revoke") {
			out = append(out, strings.TrimSpace(rec.Event+" "+rec.Reason))
		}
	}
	return out, n, sc.Err()
}

// l86Lock takes the lab's single-occupant lock for the cell, as the
// topology runs do, and lets it go with the process.
func l86Lock(t *testing.T, cell string) {
	t.Helper()
	f, err := os.OpenFile(labLockFile, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("INVALID: the lab lock: %v", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		holder, _ := os.ReadFile(labLockFile)
		f.Close()
		t.Fatalf("INVALID: the lab is occupied: %s holds %s; wait for it, never kill it", strings.TrimSpace(string(holder)), labLockFile)
	}
	_ = f.Truncate(0)
	_, _ = f.WriteAt([]byte(fmt.Sprintf("TestL86%s pid %d\n", cell, os.Getpid())), 0)
	t.Cleanup(func() { f.Close() })
}

// l86Versions records the firmware Ryan named and libykcs11's package
// version, from the package manager's metadata (no token is touched).
func (h *lab) l86Versions() {
	h.t.Helper()
	fw, err := l86Firmware(os.Getenv(envFirmware))
	if err != nil {
		h.t.Fatalf("INVALID: %v (the register needs the firmware recorded; RUNBOOK step 3)", err)
	}
	h.obs("firmware", fw)
	h.obs("libykcs11_module", h.module)
	out, err := exec.Command("dpkg-query", "-W", "-f=${Version}", "ykcs11").Output()
	if err != nil || len(out) == 0 {
		h.t.Fatalf("INVALID: dpkg-query found no ykcs11 package: libykcs11's version cannot be recorded")
	}
	h.obs("libykcs11_package_version", string(out))
}

// l86Cell is a cell's running state.
type l86Cell struct {
	h       *lab
	b       *labBroker
	sock    string
	logPath string
}

// l86Start sets the cell up: the terminal, the lock, the versions, the lab CA,
// a broker under the admin policy with Yubico's roots, and one login on
// sessionID with the touch key on slot 9c. Ryan types the PIN at port49's own
// prompt.
func l86Start(t *testing.T, cell, sessionID string) *l86Cell {
	t.Helper()
	if os.Getenv(gateL86) != "1" {
		t.Skipf("set %s=1 and run from a terminal (an admin touch on your key); see tests/lab/L86-runbook.md", gateL86)
	}
	h := newStudyLab(t, "L86", cell, true)
	h.needPKCS11()
	l86Lock(t, cell)
	h.l86Versions()
	ca := h.needLabCA()
	b := h.startLabBrokerWith(ca, h.yubicoRoots(), l86Policy)
	c := &l86Cell{h: h, b: b, sock: socketIn(t), logPath: filepath.Join(h.dir, "decisions-"+cell+".jsonl")}
	r := h.typedLogin("1", "login", loginArgs(b, c.sock, h.keyRef(sessionID, false), "", h.keyRef(slot9c, false)))
	h.mustOK(r, "the login")
	st := h.obsStatus("status", c.sock)
	if !st.TouchKey {
		t.Fatalf("INVALID: the agent has no usable touch key (%s): admin calls need one on the same token", st.TouchKeyUnusable)
	}
	return c
}

// revoke is an admin call: `port49 revoke --principal target --yes` through
// the agent. It waits for a touch, so the deadline is a minute.
func (c *l86Cell) revoke(field, target string) result {
	c.h.t.Helper()
	r := c.h.port49(runOpts{deadline: adminDeadline}, "revoke", "--principal", target, "--yes", onSock(c.sock))
	c.h.obsResult(field, r)
	return r
}

// list is `port49 revoke --list`, a read that needs no touch.
func (c *l86Cell) list(field string) result {
	c.h.t.Helper()
	r := c.h.port49(runOpts{}, "revoke", "--list", onSock(c.sock))
	c.h.obsResult(field, r)
	return r
}

// finish records the verdict and fails the test on a FAIL.
func (c *l86Cell) finish(v l86Verdict) {
	c.h.t.Helper()
	c.h.obs("verdict", v.String())
	c.h.stopAgent(c.sock)
	if !v.pass {
		c.h.t.Errorf("L86 %s: %s", c.h.cell, v)
	}
}

func l86Target(cell string, n int) string {
	return fmt.Sprintf("user:l86-%s-%d@example.com", strings.ToLower(cell), n)
}

// Cell (a): two admin calls 5 s apart under touch policy `always`.
func TestL86A(t *testing.T) {
	c := l86Start(t, "a", slot9a)
	h := c.h
	h.step("2", "call 1: TOUCH the key when it blinks (within 15 s)")
	c1 := c.revoke("call1", l86Target("a", 1))
	h.say("  waiting %v before call 2...", gapBetweenCalls)
	time.Sleep(gapBetweenCalls)
	h.step("3", "call 2: do NOT touch the key. Watch whether it blinks. The call fails after about 15 s")
	c2 := c.revoke("call2", l86Target("a", 2))
	blinked := h.askInt("Did the key blink again for call 2? 1 = yes, 0 = no")
	h.obs("call2_blinked", strconv.Itoa(blinked))
	h.step("4", "call 3: TOUCH the key when it blinks")
	c3 := c.revoke("call3", l86Target("a", 3))
	c.finish(l86VerdictA(c1, c2, c3, blinked))
}

// Cell (b): no touch at all.
func TestL86B(t *testing.T) {
	c := l86Start(t, "b", slot9a)
	h := c.h
	target := l86Target("b", 1)
	h.step("2", "do NOT touch the key. The call fails after about 15 s; the time and the words are recorded")
	r := c.revoke("untouched", target)
	list := c.list("list_after")
	c.finish(l86VerdictB(r, list, target))
}

// Cell (c): a session key in slot 9e, not 9a, on the same token as the touch key.
// The OIDC issuance that would put it there is L60 cell (g)'s (plan 9e); this
// cell measures the admin path's half: that session key, the same token's touch
// key, one touch. It needs TestL86Prep9e's certificate imported first.
func TestL86C(t *testing.T) {
	c := l86Start(t, "c", cmpOr(os.Getenv(envSlot9eID), defaultSlot9e))
	h := c.h
	h.obs("scope", "session key in slot 9e with a lab-CA certificate; OIDC issuance not exercised (L60 cell g)")
	h.step("2", "TOUCH the key once when it blinks (do not touch twice)")
	r := c.revoke("call", l86Target("c", 1))
	touches := h.askInt("How many times did you touch the key?")
	h.obs("touches", strconv.Itoa(touches))
	c.finish(l86VerdictC(r, touches))
}

// Cell (d): the key unplugged with the agent running.
func TestL86D(t *testing.T) {
	c := l86Start(t, "d", slot9a)
	h := c.h
	_, before, err := l86AdminEvents(c.logPath, 0)
	if err != nil {
		t.Fatalf("INVALID: the decision log: %v", err)
	}
	h.step("2", "pull the key out of the SER8")
	h.waitEnter("Pull the key out, then press Enter", handDeadline)
	r := c.revoke("unplugged", l86Target("d", 1))
	grown, _, err := l86AdminEvents(c.logPath, before)
	if err != nil {
		t.Fatalf("INVALID: the decision log: %v", err)
	}
	h.obs("broker_admin_records_after_pull", strconv.Itoa(len(grown)))
	h.step("3", "put the key back")
	h.waitEnter("Re-insert the key, then press Enter", handDeadline)
	c.finish(l86VerdictD(r, grown))
}

// TestL86Prep9e makes the certificate for slot 9e's public key (read from the
// token with no PIN) from the lab CA and prints the import command Ryan runs.
// It writes nothing to the token.
func TestL86Prep9e(t *testing.T) {
	gate(t, gateL86Prep, "makes slot 9e's certificate from the lab CA; prints the ykman import")
	h := newStudyLab(t, "L86", "prep9e", false)
	h.needPKCS11()
	ca := h.needLabCA()
	id := cmpOr(os.Getenv(envSlot9eID), defaultSlot9e)
	k, err := clientkey.Open(h.keyRef(id, false), nil)
	if err != nil {
		t.Fatalf("opening slot 9e (CKA_ID %s): %s", id, redact(err.Error()))
	}
	p, err := issueFor(ca, k.Public(), time.Now())
	_ = k.Close()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(h.dir, fileSlot9e)
	if err := os.WriteFile(path, p, 0o600); err != nil {
		t.Fatal(err)
	}
	h.obs("slot9e_certificate", "made: "+path)
	h.say("\n  NEXT, run this yourself:\n\n      ykman piv certificates import 9e %s\n", path)
}
