package l60

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"os"
	"testing"

	"github.com/rhwendt/port49/internal/clientkey"
	"github.com/rhwendt/port49/internal/hwkey"
)

// Cell (e): the unplug. A mint on the held connection, `port49 refresh`
// saying to insert the key, the session surviving; after re-insertion, with
// nothing minted between, GET /status says locked, `port49 login` asks the
// PIN and the refresh works. Then, with the agent stopped, the return code a
// physical pull gives, read in this process.
func TestL60E(t *testing.T) {
	gate(t, gateE, "the unplug; you type your PIN twice and pull the key twice; with "+envPINSource+
		" set, the last step also logs in once in this process with that file's PIN")
	h := newLab(t, "e", true)
	h.needPKCS11()
	ca := h.needLabCA()
	b := h.startLabBroker(ca, nil)
	h.pinTries("pin_tries_before")

	s := socketIn(t)
	r := h.typedLogin("1", "login", loginArgs(b, s, h.keyRef(slot9a, false), "", ""))
	h.mustOK(r, "the slot 9a login")
	h.obsStatus("status_before_pull", s)

	h.step("2", "PULL the key")
	h.waitEnter("Pull the YubiKey out of the machine now.", handDeadline)
	h.obsStatus("status_after_pull", s)

	h.step("3", "port49 token leaf1 with the key out: on the held connection")
	h.obsResult("mint_held", h.port49(runOpts{token: true}, "token", onSock(s), leafPlain))

	h.step("4", "port49 refresh with the key out")
	h.obsResult("refresh_key_out", h.port49(runOpts{}, "refresh", onSock(s)))

	h.step("5", "the session survives: GET /status and a second mint")
	h.obsStatus("status_key_out", s)
	h.obsResult("mint_held_again", h.port49(runOpts{token: true}, "token", onSock(s), leafPlain))

	h.step("6", "RE-INSERT the key; nothing is minted until the status is read")
	h.waitEnter("Put the YubiKey back and wait for its light.", handDeadline)
	h.obsStatus("status_after_reinsert", s)

	r = h.typedLogin("7", "relogin", loginArgs(b, s, h.keyRef(slot9a, false), "", ""))
	h.obsStatus("status_after_relogin", s)

	h.step("8", "port49 refresh after the re-login")
	h.obsResult("refresh_after_relogin", h.port49(runOpts{}, "refresh", onSock(s)))
	h.stopAgent(s)

	h.pullCode()
	h.pinTries("pin_tries_after")
}

// pullCode is the PKCS#11 return code a physical pull gives, read in this
// process with the agent stopped. With PORT49_L60_PIN_SOURCE the key is
// opened logged in through port49's pin-source and a C_Sign is made after
// the pull; without it the key is opened with no PIN and the token's
// certificates are listed (C_FindObjectsInit). The words carry the code.
func (h *lab) pullCode() {
	h.t.Helper()
	withPIN := os.Getenv(envPINSource) != ""
	if withPIN {
		h.step("9", "the return code of a physical pull, in this process (agent stopped); "+
			"%s's PIN is sent once now, in this process: a wrong file spends a try", envPINSource)
	} else {
		h.step("9", "the return code of a physical pull, in this process (agent stopped); no PIN")
	}
	k, err := clientkey.Open(h.keyRef(slot9a, withPIN), nil)
	if err != nil {
		h.obs("pull_code_open", err.Error())
		return
	}
	defer k.Close()
	h.obs("pull_code_state_before", k.State().String())
	h.waitEnter("Pull the YubiKey out again.", handDeadline)
	if withPIN && k.State() != hwkey.Locked {
		d := sha256.Sum256([]byte("port49 L60 pull probe"))
		_, err = k.Sign(nil, d[:], crypto.SHA256)
		h.obs("pull_code_call", "C_Sign on a logged-in session")
	} else {
		c, ok := k.(interface {
			Certificates() ([]*x509.Certificate, error)
		})
		if !ok {
			h.obs("pull_code_call", "none: the key lists no certificates")
			return
		}
		_, err = c.Certificates()
		h.obs("pull_code_call", "C_FindObjects on a session with no login")
	}
	if err != nil {
		h.obs("pull_code_error", err.Error())
	} else {
		h.obs("pull_code_error", "none: the call succeeded with the key out")
	}
	h.obs("pull_code_state_after", k.State().String())
	h.waitEnter("Put the YubiKey back and wait for its light.", handDeadline)
	h.obs("pull_code_state_reinserted", k.State().String())
}

// Cell (e2): a second terminal's `port49 login` and `port49 token` leave the
// agent's PIV login in place. Then a second agent of its own logs in to the
// same key (its own C_Login) and the first agent's refresh is read again.
func TestL60E2(t *testing.T) {
	gate(t, gateE2, "a second process's login and token; you type your PIN twice")
	h := newLab(t, "e2", true)
	h.needPKCS11()
	ca := h.needLabCA()
	b := h.startLabBroker(ca, nil)
	h.pinTries("pin_tries_before")

	a := socketIn(t)
	r := h.typedLogin("1", "login_a", loginArgs(b, a, h.keyRef(slot9a, false), "", ""))
	h.mustOK(r, "agent A's login")
	h.obsStatus("status_a", a)

	h.step("2", "a second `port49 login` to agent A's socket (another process): no PIN is expected")
	h.say("  If it asks for a PIN, press Enter on the empty prompt; do not type it.")
	h.obsResult("second_login", h.port49(runOpts{deadline: typedDeadline, terminal: true}, loginArgs(b, a, h.keyRef(slot9a, false), "", "")...))
	h.obs("second_login_pin_prompts", itoa(h.askInt("How many times did that login ask for the PIN?")))

	h.step("3", "a second `port49 token leaf1` (another process)")
	h.obsResult("second_token", h.port49(runOpts{token: true}, "token", onSock(a), leafPlain))

	h.step("4", "agent A still logged in: GET /status and a refresh, which signs")
	h.obsStatus("status_a_after", a)
	h.obsResult("refresh_a_after", h.port49(runOpts{}, "refresh", onSock(a)))

	bs := socketIn(t)
	r = h.typedLogin("5", "login_b", loginArgs(b, bs, h.keyRef(slot9a, false), "", ""))
	h.obsStatus("status_a_after_b_login", a)
	h.obsResult("refresh_a_after_b_login", h.port49(runOpts{}, "refresh", onSock(a)))
	if r.code == 0 {
		h.obsResult("refresh_b", h.port49(runOpts{}, "refresh", onSock(bs)))
	}

	h.step("6", "agent B stops; agent A's refresh again")
	h.stopAgent(bs)
	h.obsStatus("status_a_after_b_stop", a)
	h.obsResult("refresh_a_after_b_stop", h.port49(runOpts{}, "refresh", onSock(a)))
	h.stopAgent(a)
	h.pinTries("pin_tries_after")
}
