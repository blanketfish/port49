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
//	(c) TestL86C  the real OIDC path: the lab's Keycloak, `port49 login --oidc` with
//	              issued_key_store: pkcs11 (slot 9e), one admin call, one touch
//	    TestL86C9eFallback  the proxy: a lab-CA certificate in 9e; does not close (c)
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
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/clientkey"
	"github.com/blanketfish/port49/internal/decision"
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
	refusedReason     = "admin_touch_refused" // spec §5.7 (decision.AdminTouchRefused)
	signedInWords     = "; your certificate from "
	oidcDeadline      = 5 * time.Minute // a sign-in in a browser, then the PIN
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

// noRevocationWords is what `revoke --list` prints for an empty store
// (broker.RevocationsText). Each cell's broker starts empty, so cell (b) needs exactly
// these words: any mark, or a list format that no longer says them, FAILs loudly
// instead of passing because the target happens not to be spelled.
const noRevocationWords = "no revocation is in force"

// l86VerdictB: the CLI prints the timeout line, exits 1, and the revocation
// list says no revocation is in force.
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
	case !strings.Contains(list.stdout, noRevocationWords):
		return l86Verdict{false, "revoke --list does not say \"" + noRevocationWords + "\": a mark, or a changed list format"}
	}
	return l86Verdict{true, fmt.Sprintf("exit 1 with the timeout line after %s; no mark", c.took.Round(100*time.Millisecond))}
}

// l86VerdictC: the session key was issued by the OIDC sign-in (the login exited 0,
// said the certificate is the sign-in's, asked the token's PIN once, and the
// broker's log holds a permitted issue record), and the admin call with that key
// succeeds with one touch. The cell pins issued_key_store: pkcs11, which refuses
// rather than falls back, so the key is the token's; login says "the key is the
// one issued_key names" only when it chose the store itself, never under a
// pinned store (L86 run 2026-11-01). The one PIN prompt is the token's own
// evidence: no other store asks for a PIN.
func l86VerdictC(login, call result, issued bool, pinPrompts, touches int) l86Verdict {
	switch {
	case login.code != 0:
		return l86Verdict{false, fmt.Sprintf("the OIDC login exited %d", login.code)}
	case !strings.Contains(login.stdout, signedInWords):
		return l86Verdict{false, "the login did not say a certificate was issued for the sign-in"}
	case pinPrompts != 1:
		return l86Verdict{false, fmt.Sprintf("Ryan counted %d PIN prompts, want 1: the token's key asks once", pinPrompts)}
	case !issued:
		return l86Verdict{false, "the broker's log has no permitted issue record: the certificate was not issued by this sign-in"}
	case call.code != 0:
		return l86Verdict{false, fmt.Sprintf("the admin call exited %d", call.code)}
	case touches != 1:
		return l86Verdict{false, fmt.Sprintf("Ryan counted %d touches, want 1", touches)}
	}
	return l86Verdict{true, "the OIDC-issued session key in the token's slot made the admin call succeed with one touch"}
}

// l86VerdictC9e is the proxy's: a lab-CA certificate in slot 9e, no OIDC. It can fail
// the admin path; it can never close row L86's (c), and its verdict says so.
func l86VerdictC9e(c result, touches int) l86Verdict {
	switch {
	case c.code != 0:
		return l86Verdict{false, fmt.Sprintf("the call exited %d", c.code)}
	case touches != 1:
		return l86Verdict{false, fmt.Sprintf("Ryan counted %d touches, want 1", touches)}
	}
	return l86Verdict{true, "the call succeeded with one touch (proxy: does not close (c))"}
}

// l86VerdictD: the CLI fails saying to insert the key, the broker's log has no
// admin_touch_refused (checked by that name: a refusal is the row's one named
// failure), and it grew by no admin record at all, so nothing was sent.
func l86VerdictD(c result, grown []string, refused int) l86Verdict {
	switch {
	case c.code == 0:
		return l86Verdict{false, "the call succeeded with the key out"}
	case !strings.Contains(strings.ToLower(c.stderr), insertWords):
		return l86Verdict{false, "the CLI did not say to insert the key"}
	case refused != 0:
		return l86Verdict{false, "the broker's log has admin_touch_refused (" + strconv.Itoa(refused) + " times): the call was sent"}
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

// l86Refused counts the decision-log lines past the first from lines whose reason is
// admin_touch_refused, whatever their event: the one failure row L86 (d) names.
// Only the reason is read.
func l86Refused(text string, from int) int {
	var n, line int
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line++
		if line <= from {
			continue
		}
		var rec struct {
			Reason string `json:"reason"`
		}
		if json.Unmarshal(sc.Bytes(), &rec) == nil && rec.Reason == refusedReason {
			n++
		}
	}
	return n
}

// l86Issued is whether the decision log holds a permitted issue record: the broker
// exchanged a person's ID token for a certificate. Only the event and verdict are read.
func l86Issued(text string) bool {
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var rec struct {
			Event   string `json:"event"`
			Verdict string `json:"verdict"`
		}
		if json.Unmarshal(sc.Bytes(), &rec) == nil && rec.Event == decision.EventIssue && rec.Verdict == decision.VerdictPermit {
			return true
		}
	}
	return false
}

// l86Lock takes the lab's single-occupant lock for the cell, as the
// topology runs do, and lets it go with the process.
func (h *lab) l86Lock(t *testing.T, cell string) {
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
	h.onKill = append(h.onKill, func() { f.Close() }) // a killed process lets the lock go too; say so explicitly
}

// l86Versions records the firmware Ryan named and libykcs11's package
// version, from the package manager's metadata (no token is touched).
func (h *lab) l86Versions() error {
	h.t.Helper()
	fw, err := l86Firmware(os.Getenv(envFirmware))
	if err != nil {
		return fmt.Errorf("INVALID: %v (the register needs the firmware recorded; RUNBOOK step 3)", err)
	}
	h.obs("firmware_operator_reported_from_ykman", fw) // typed by Ryan: port49 does not read it
	h.obs("libykcs11_module", h.module)
	out, err := exec.Command("dpkg-query", "-W", "-f=${Version}", "ykcs11").Output()
	if err != nil || len(out) == 0 {
		return fmt.Errorf("INVALID: dpkg-query found no ykcs11 package: libykcs11's version cannot be recorded")
	}
	h.obs("libykcs11_package_version", string(out))
	return nil
}

// l86Cell is a cell's running state.
type l86Cell struct {
	h       *lab
	b       *labBroker
	sock    string
	logPath string
}

// l86Begin is what every cell starts with: the gate, the terminal, the token's
// module, the lab lock, and the versions (the firmware as Ryan reported it from
// ykman, the libykcs11 package's).
func l86Begin(t *testing.T, cell string) *lab {
	t.Helper()
	if os.Getenv(gateL86) != "1" {
		t.Skipf("set %s=1 and run from a terminal (an admin touch on your key); see tests/lab/L86-runbook.md", gateL86)
	}
	h := newStudyLab(t, "L86", cell, true)
	h.needPKCS11()
	h.l86Lock(t, cell)
	dl, _ := t.Deadline()
	if err := h.l86Ready(os.Exit, dl); err != nil {
		t.Fatal(err)
	}
	return h
}

// l86Ready is what a cell does before it starts anything: the kill guard, the check that
// slot 9c's key is there (INVALID, before any agent exists), and the recorded versions.
func (h *lab) l86Ready(exit func(int), deadline time.Time) error {
	h.t.Helper()
	h.l86Guard(exit, deadline)
	if err := h.l86Need9c(); err != nil {
		return err
	}
	return h.l86Versions()
}

// l86KillGrace is how long before the test binary's own deadline the cell cleans
// up and exits: the testing package's timeout panic runs no t.Cleanup.
var l86KillGrace = 45 * time.Second

// l86Guard makes a killed cell clean up what t.Cleanup would: a SIGINT or SIGTERM,
// or the test's own deadline (-test.timeout) a grace period away, stops every agent
// the cell started by its recorded pid (a PIN-unlocked session must not outlive
// the cell), restores the terminal, and runs h.onKill (Keycloak's down -v, the lab
// lock), then calls exit. Go's testing package runs no t.Cleanup on a signal or on
// its timeout panic. The guard is dropped when the cell ends normally.
func (h *lab) l86Guard(exit func(int), deadline time.Time) {
	h.t.Helper()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	done := make(chan struct{})
	var timeout <-chan time.Time
	if !deadline.IsZero() {
		tm := time.NewTimer(time.Until(deadline) - l86KillGrace)
		timeout = tm.C
		h.t.Cleanup(func() { tm.Stop() })
	}
	h.t.Cleanup(func() { signal.Stop(sig); close(done) })
	go func() {
		var why string
		select {
		case s := <-sig:
			why = "got " + s.String()
		case <-timeout:
			why = "the test's own deadline is " + l86KillGrace.String() + " away"
		case <-done:
			return
		}
		h.say("\n  L86 cell %s: %s; cleaning up (agents by pid, the terminal, Keycloak, the lab lock) and stopping", h.cell, why)
		h.stopAllAgents()
		h.restoreTTY()
		h.mu.Lock()
		kill := append([]func(){}, h.onKill...)
		h.mu.Unlock()
		for i := len(kill) - 1; i >= 0; i-- {
			kill[i]()
		}
		h.obs("killed", why+"; the cell did not finish and has no verdict")
		exit(2)
	}()
}

// l86Need9c refuses to go on when slot 9c's key is not on the token. The runbook never makes,
// resets or overwrites a slot: the touch key is the 9c key provisioned for L60 (touch always).
func (h *lab) l86Need9c() error {
	h.t.Helper()
	return l86CheckSlot(func() error { return openSlot(h.keyRef(slot9c, false)) })
}

// openSlot opens the key at ref read-only and closes it; a variable so a unit test can say
// the slot is absent without a token.
var openSlot = func(ref string) error {
	k, err := clientkey.Open(ref, nil)
	if err == nil {
		_ = k.Close()
	}
	return err
}

// l86CheckSlot is the INVALID a missing 9c key reads as. It names no key and no PIN.
func l86CheckSlot(open func() error) error {
	if err := open(); err != nil {
		return fmt.Errorf("INVALID: slot 9c (CKA_ID %s) is not on the token (%s). The harness and the runbook never "+
			"create, reset or overwrite a slot: stop and tell the lead", slot9c, redact(err.Error()))
	}
	return nil
}

// l86Start sets the cell up: the terminal, the lock, the versions, the lab CA,
// a broker under the admin policy with Yubico's roots, and one login on
// sessionID with the touch key on slot 9c. Ryan types the PIN at port49's own
// prompt.
func l86Start(t *testing.T, cell, sessionID string) *l86Cell {
	t.Helper()
	h := l86Begin(t, cell)
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

// Cell (c): the real OIDC path (row L86 (c); L60 cell (g)'s open issued-key cell). The
// lab's Keycloak and an in-process broker that verifies its ID tokens and issues
// certificates; `port49 login --oidc` with issued_key_store: pkcs11, so the session key
// is the key Ryan made in slot 9e and the certificate is the broker's, issued for the
// sign-in; then one admin call with the same token's touch key, one touch.
func TestL86C(t *testing.T) {
	h := l86Begin(t, "c")
	addrs, _ := net.LookupHost(kcHost)
	if !l86HostsOK(addrs) {
		t.Fatalf("INVALID: %s does not resolve to 127.0.0.1 on this host: type "+
			"`echo '127.0.0.1 %s # port49-l86' | sudo tee -a /etc/hosts` yourself (tests/lab/L86-runbook.md, cell (c) setup) and run the cell again",
			kcHost, kcHost)
	}
	roots := h.yubicoRoots()
	k := h.l86StartKeycloak()
	b := k.startOIDCBroker(roots)
	c := &l86Cell{h: h, b: b, sock: socketIn(t), logPath: filepath.Join(h.dir, "decisions-c.jsonl")}
	id := cmpOr(os.Getenv(envSlot9eID), defaultSlot9e)
	cfg := l86Config{broker: b.url, touchKey: h.keyRef(slot9c, false), issuedKey: h.keyRef(id, false),
		redirectPort: kcRedirectPort}
	if err := cfg.writeConfig(h.home); err != nil {
		t.Fatalf("INVALID: the cell's config: %v", err)
	}
	h.obs("scope", "the real OIDC path: Keycloak realm "+kcRealm+", sign-in as "+l86OIDCUser+", issued_key_store: pkcs11 "+
		"(slot 9e, CKA_ID "+id+"), touch key slot 9c")
	h.step("1", "port49 login --oidc prints an address: open it in your browser, sign in as %s "+
		"(password: see the runbook), then type your PIN at port49's own prompt (the key in slot 9e signs the "+
		"certificate request). %s", l86OIDCUser, pinHelp)
	login := h.port49(runOpts{deadline: oidcDeadline, terminal: true}, "login", "--oidc", "--no-browser",
		"--broker-ca", b.serverCA, "--oidc-ca", k.caFile, "--redirect-port", strconv.Itoa(kcRedirectPort), onSock(c.sock))
	login.stderr = l86LoginWords(login.stderr)
	h.obsResult("login", login)
	pinPrompts := h.askInt("How many times did port49 ask for the PIN?")
	h.obs("login_pin_prompts", strconv.Itoa(pinPrompts))
	h.mustOK(login, "the OIDC login")
	text, _ := os.ReadFile(c.logPath)
	issued := l86Issued(string(text))
	h.obs("broker_issue_record_permitted", strconv.FormatBool(issued))
	st := h.obsStatus("status", c.sock)
	if !st.TouchKey {
		t.Fatalf("INVALID: the agent has no usable touch key (%s): admin calls need one on the same token", st.TouchKeyUnusable)
	}
	h.step("2", "TOUCH the key once when it blinks (do not touch twice)")
	call := c.revoke("call", l86Target("c", 1))
	touches := h.askInt("How many times did you touch the key?")
	h.obs("touches", strconv.Itoa(touches))
	c.finish(l86VerdictC(login, call, issued, pinPrompts, touches))
}

// TestL86C9eFallback is the proxy for cell (c): the same admin path with a lab-CA
// certificate Ryan imported into slot 9e (TestL86Prep9e), no OIDC. It measures the
// admin path's half only. Its result is recorded as "proxy, does not close (c)": a
// row is not closed on a proxy. Run it only when the Keycloak stack cannot be had.
func TestL86C9eFallback(t *testing.T) {
	c := l86Start(t, "c9e", cmpOr(os.Getenv(envSlot9eID), defaultSlot9e))
	h := c.h
	h.obs("scope", "PROXY, does not close (c): a lab-CA certificate in slot 9e, no OIDC sign-in, no issuance")
	h.step("2", "TOUCH the key once when it blinks (do not touch twice)")
	r := c.revoke("call", l86Target("c9e", 1))
	touches := h.askInt("How many times did you touch the key?")
	h.obs("touches", strconv.Itoa(touches))
	h.obs("row_status", "proxy, does not close (c)")
	c.finish(l86VerdictC9e(r, touches))
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
	text, err := os.ReadFile(c.logPath)
	if err != nil {
		t.Fatalf("INVALID: the decision log: %v", err)
	}
	refused := l86Refused(string(text), before)
	h.obs("broker_"+refusedReason+"_after_pull", strconv.Itoa(refused))
	h.step("3", "put the key back")
	h.waitEnter("Re-insert the key, then press Enter", handDeadline)
	c.finish(l86VerdictD(r, grown, refused))
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
