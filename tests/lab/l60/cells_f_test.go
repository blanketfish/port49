package l60

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

func itoa(n int) string { return strconv.Itoa(n) }

// guardWords is what port49 says when it holds a pin-source PIN back because
// the token reports few tries (pkcs11.ErrPINTriesLow).
const guardWords = "will not spend one unattended"

// guardProbe asks port49's pin-source guard whether the token reports
// CKF_USER_PIN_COUNT_LOW or CKF_USER_PIN_FINAL_TRY: a `port49 login` with
// the pin-source reference, in a session of its own with no terminal, so
// nothing can be asked. "held" is the guard refusing (a flag is set, no try
// spent); "sent" is the file's PIN sent and taken (neither flag set; a
// success, which clears the token's count); anything else ends the cell.
func (h *lab) guardProbe(field string, b *labBroker) string {
	h.t.Helper()
	s := socketIn(h.t)
	r := h.port49(runOpts{detached: true}, loginArgs(b, s, h.keyRef(slot9a, true), "", "")...)
	h.obsResult(field, r)
	h.stopAgent(s)
	switch {
	case r.code == 0:
		h.obs(field+"_reading", "sent: the guard saw neither flag; the file's PIN was sent and taken")
		return "sent"
	case strings.Contains(r.stderr, guardWords):
		h.obs(field+"_reading", "held: the token reports count_low or final_try; no try was spent")
		return "held"
	}
	h.t.Fatalf("the pin-source probe neither logged in nor was held back (%s); if the file's PIN is wrong a try "+
		"was spent: check with ykman piv info, and run `port49 login` at a terminal to type your PIN", pinWords(r.stderr))
	return ""
}

// Cell (f): ONE wrong PIN, typed deliberately. port49's words, one try
// fewer, no second attempt; whether libykcs11 sets CKF_USER_PIN_COUNT_LOW and
// CKF_USER_PIN_FINAL_TRY after it (port49's words, and the pin-source guard
// that reads them); then a typed correct PIN, and whether that cleared them.
func TestL60F(t *testing.T) {
	gate(t, gateF, "ONE wrong PIN on purpose; needs "+envPINSource)
	h := newLab(t, "f", true)
	h.needPKCS11()
	ca := h.needLabCA()
	b := h.startLabBroker(ca, nil)
	h.pinSourcePath()

	h.step("1", "PIN tries before; the cell refuses to run under 3")
	if left := h.pinTries("pin_tries_before"); left < 3 {
		t.Fatalf("%d PIN tries remain; this cell needs 3. Type your PIN once at `port49 login` (or ykman) to reset the count", left)
	}

	h.step("2", "the guard before the wrong PIN (no terminal; the file's PIN, sent only if no flag is set)")
	if got := h.guardProbe("guard_before", b); got != "sent" {
		t.Fatal("the token reports few tries before the wrong PIN; stop and check with ykman piv info")
	}

	s := socketIn(t)
	h.step("3", "ONE WRONG PIN. When port49 shows `PIN for …:`, type a PIN you know is wrong (not your PIN, "+
		"and not a default), and Enter. If asked again, press Enter on the empty prompt.")
	r := h.port49(runOpts{deadline: typedDeadline, terminal: true}, loginArgs(b, s, h.keyRef(slot9a, false), "", "")...)
	h.obsResult("wrong_pin", r)
	h.obs("wrong_pin_pin_prompts", itoa(h.askInt("How many times did port49 ask for the PIN?")))
	h.obs("wrong_pin_flags_from_words", pinWords(r.stderr))
	h.stopAgent(s) // none should have started
	if r.code == 0 {
		t.Fatal("the login succeeded: the PIN typed was the right one; the cell measured nothing")
	}

	h.step("4", "PIN tries after the wrong PIN")
	h.pinTries("pin_tries_after_wrong")

	h.step("5", "the guard after the wrong PIN")
	if h.guardProbe("guard_after_wrong", b) == "sent" {
		h.obs("count_low_after_wrong", "not set: the guard sent the file's PIN, which succeeded")
		h.obs("typed_success_clears_count_low", "not measured: libykcs11 set no flag to clear")
		h.pinTries("pin_tries_end")
		return
	}
	h.obs("count_low_after_wrong", "set (or final_try): the guard held the file's PIN back")

	h.say("\nNext, a typed correct PIN: port49 login at a terminal, with the pin-source reference, asks it here.")
	t2 := socketIn(t)
	r = h.typedLogin("6", "typed_success", loginArgs(b, t2, h.keyRef(slot9a, true), "", ""))
	h.stopAgent(t2)
	h.mustOK(r, "the typed correct PIN")

	h.step("7", "the guard after the typed success")
	switch h.guardProbe("guard_after_typed", b) {
	case "sent":
		h.obs("typed_success_clears_count_low", "yes: the guard no longer holds the file's PIN back")
	default:
		h.obs("typed_success_clears_count_low", "no: the guard still holds the file's PIN back")
	}
	h.pinTries("pin_tries_end")
}

// Cell (f-lock), approved by Ryan: three wrong PINs to a blocked PIN, run
// last. port49's words at each wrong try and on the blocked PIN, from
// `port49 login` and from a running agent's refresh and re-login, with GET
// /status after each; then Ryan unblocks with ykman and a correct PIN works
// again. It starts only from exactly 3 tries.
func TestL60FLock(t *testing.T) {
	gate(t, gateFLock, "THREE wrong PINs: the PIN blocks and you unblock it with the PUK; run it last")
	h := newLab(t, "flock", true)
	h.needPKCS11()
	ca := h.needLabCA()
	b := h.startLabBroker(ca, nil)

	h.step("1", "PIN tries: the cell starts only from exactly 3")
	if left := h.pinTries("pin_tries_before"); left != 3 {
		t.Fatalf("%d PIN tries remain; this cell starts only from exactly 3", left)
	}

	a := socketIn(t)
	r := h.typedLogin("2", "login_a", loginArgs(b, a, h.keyRef(slot9a, false), "", ""))
	h.mustOK(r, "agent A's login with your PIN")
	h.obsStatus("status_a", a)

	wrong := socketIn(t) // never has an agent: each try is a fresh login
	for i := 1; i <= 3; i++ {
		n := itoa(i)
		h.step("3."+n, "WRONG PIN %d of 3: type a PIN you know is wrong (not your PIN, not a default). "+
			"If asked again, press Enter on the empty prompt.", i)
		r := h.port49(runOpts{deadline: typedDeadline, terminal: true}, loginArgs(b, wrong, h.keyRef(slot9a, false), "", "")...)
		h.obsResult("wrong_"+n, r)
		h.obs("wrong_"+n+"_flags_from_words", pinWords(r.stderr))
		h.obs("wrong_"+n+"_pin_prompts", itoa(h.askInt("How many times did port49 ask for the PIN?")))
		h.stopAgent(wrong)
		if r.code == 0 {
			t.Fatal("a login succeeded: that was the right PIN; the cell stops (tries are reset by it)")
		}
		h.step("3."+n+"r", "agent A's refresh and GET /status after wrong PIN %d", i)
		h.obsResult("refresh_a_after_wrong_"+n, h.port49(runOpts{}, "refresh", "--socket", a))
		h.obsStatus("status_a_after_wrong_"+n, a)
	}

	h.step("4", "the PIN is blocked. A fresh `port49 login`: type your PIN (the right one; a blocked PIN takes none). "+
		"If it does not ask, nothing to type.")
	r = h.port49(runOpts{deadline: typedDeadline, terminal: true}, loginArgs(b, wrong, h.keyRef(slot9a, false), "", "")...)
	h.obsResult("blocked_login", r)
	h.obs("blocked_login_flags_from_words", pinWords(r.stderr))
	h.obs("blocked_login_pin_prompts", itoa(h.askInt("How many times did port49 ask for the PIN?")))
	h.stopAgent(wrong)

	h.step("5", "`port49 login` through agent A, with the PIN blocked. If it asks, type your PIN.")
	r = h.port49(runOpts{deadline: typedDeadline, terminal: true}, loginArgs(b, a, h.keyRef(slot9a, false), "", "")...)
	h.obsResult("blocked_login_a", r)
	h.obs("blocked_login_a_flags_from_words", pinWords(r.stderr))
	h.obs("blocked_login_a_pin_prompts", itoa(h.askInt("How many times did port49 ask for the PIN?")))
	h.obsResult("blocked_refresh_a", h.port49(runOpts{}, "refresh", "--socket", a))
	h.obsStatus("blocked_status_a", a)
	h.stopAgent(a)
	h.pinTries("pin_tries_blocked")

	h.step("6", "UNBLOCK with the PUK")
	h.waitEnter("In another terminal run:  ykman piv access unblock-pin\n"+
		"      Type the PUK, then your PIN as the new PIN, at ykman's prompts only.\n"+
		"      Keep the same PIN, or update your pin-source file to match.", 10*time.Minute)
	if left := h.pinTries("pin_tries_after_unblock"); left != 3 {
		t.Fatalf("%d PIN tries after the unblock, want 3", left)
	}

	c := socketIn(t)
	r = h.typedLogin("7", "login_after_unblock", loginArgs(b, c, h.keyRef(slot9a, false), "", ""))
	h.mustOK(r, "the login after the unblock")
	h.obsStatus("status_after_unblock", c)
	h.obsResult("refresh_after_unblock", h.port49(runOpts{}, "refresh", "--socket", c))
	h.stopAgent(c)
	h.pinTries("pin_tries_end")
}
