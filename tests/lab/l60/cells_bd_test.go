package l60

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/clientkey"
)

// pinHelp is what Ryan is told before a prompt that wants their PIN.
const pinHelp = "When port49 shows `PIN for …:`, type your PIN and Enter (nothing echoes). " +
	"If it asks a second time, press Enter on the empty prompt instead of typing it again."

// needPKCS11 fails a cell built without the purego backend.
func (h *lab) needPKCS11() {
	h.t.Helper()
	if !clientkey.HasPKCS11 {
		h.t.Fatal("this cell opens the token: run it with -tags hwkey_dlopen and CGO_ENABLED=0 (RUNBOOK.md)")
	}
}

// typedLogin runs a `port49 login` that asks Ryan for their PIN, records it
// and how many times the PIN was asked.
func (h *lab) typedLogin(n, field string, args []string) result {
	h.t.Helper()
	h.step(n, "port49 login: it asks your PIN. %s", pinHelp)
	r := h.port49(runOpts{deadline: typedDeadline, terminal: true}, args...)
	h.obsResult(field, r)
	h.obs(field+"_pin_prompts", strconv.Itoa(h.askInt("How many times did port49 ask for the PIN?")))
	if tail := agentLogTail(r.stdout, 6); tail != "" {
		h.obs(field+"_agent_log", tail)
	}
	return r
}

// mustOK ends the cell when a step it builds on failed; what was seen is
// recorded already.
func (h *lab) mustOK(r result, what string) {
	h.t.Helper()
	if r.code != 0 {
		h.t.Fatalf("%s failed (exit %d); the cell stops here: %s", what, r.code, redact(r.stderr))
	}
}

// spkiHash is a short SHA-256 of a public key, to tell keys apart.
func spkiHash(pub any) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "unreadable: " + err.Error()
	}
	s := sha256.Sum256(der)
	return hex.EncodeToString(s[:8])
}

// The import step for cell (b): a lab CA (kept in the lab directory), and a
// certificate from it for slot 9a's public key, read from the token with no
// PIN. It writes nothing to the token: it prints the ykman command Ryan runs.
func TestL60Import9a(t *testing.T) {
	gate(t, gateImport, "makes the lab CA and slot 9a's certificate; prints the ykman import")
	h := newLab(t, "import", false)
	h.needPKCS11()
	now := time.Now()

	h.step("1", "the lab CA in %s", h.dir)
	ca, err := loadClientCA(h.dir)
	switch {
	case err == nil:
		h.obs("lab_ca", "kept from an earlier run, valid until "+ca.Cert.NotAfter.UTC().Format(time.RFC3339))
	case os.IsNotExist(err):
		if ca, err = writeClientCA(h.dir, now); err != nil {
			t.Fatal(err)
		}
		h.obs("lab_ca", "made, valid until "+ca.Cert.NotAfter.UTC().Format(time.RFC3339))
	default:
		t.Fatalf("the lab CA in %s does not load: %v", h.dir, err)
	}

	h.step("2", "reading slot 9a's public key from the token (no PIN; nothing written)")
	k, err := clientkey.Open(h.keyRef(slot9a, false), nil)
	if err != nil {
		t.Fatalf("opening slot 9a: %s", redact(err.Error()))
	}
	pub := k.Public()
	h.obs("slot9a_state_no_pin", k.State().String())
	h.obs("slot9a_public_key_sha256_8", spkiHash(pub))
	if c, ok := k.(interface {
		Certificate() (*x509.Certificate, error)
	}); ok {
		cert, err := c.Certificate()
		if err != nil {
			h.obs("slot9a_certificate_before_import", err.Error())
		} else {
			h.obs("slot9a_certificate_before_import", "subject "+cert.Subject.String()+" issuer "+cert.Issuer.String())
		}
	}
	_ = k.Close()

	h.step("3", "the certificate for slot 9a")
	path := filepath.Join(h.dir, fileSlotCert)
	if raw, err := os.ReadFile(path); err == nil {
		if b, _ := pem.Decode(raw); b != nil {
			if c, err := x509.ParseCertificate(b.Bytes); err == nil && spkiHash(c.PublicKey) == spkiHash(pub) &&
				c.CheckSignatureFrom(ca.Cert) == nil && now.Before(c.NotAfter) {
				h.obs("slot9a_certificate", "kept from an earlier run: "+path)
				h.printImport(path)
				return
			}
		}
	}
	p, err := issueFor(ca, pub, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, p, 0o600); err != nil {
		t.Fatal(err)
	}
	h.obs("slot9a_certificate", fmt.Sprintf("made: %s (CN %s, email SAN, clientAuth, 90 days, issuer the lab CA)", path, labEmail))
	h.printImport(path)
}

// printImport tells Ryan the import command.
func (h *lab) printImport(path string) {
	h.say("\n  NEXT (RUNBOOK.md step 2), run this yourself:\n\n      ykman piv certificates import 9a %s\n\n"+
		"  ykman uses the default management key; if it asks for anything, type it at ykman's prompt only.\n"+
		"  Then run cell (b).", path)
	h.obs("import_command", "ykman piv certificates import 9a "+path)
}

// Cell (b): `port49 login --key` on slot 9a with the token's certificate. The
// PIN is asked once, the agent connects, a refresh signs. Control: the same
// broker and identity with a file key.
func TestL60B(t *testing.T) {
	gate(t, gateB, "port49 login --key on slot 9a; you type your PIN once")
	h := newLab(t, "b", true)
	h.needPKCS11()
	ca := h.needLabCA()
	b := h.startLabBroker(ca, nil)

	h.step("1", "control: a file key, no token (about 5s)")
	cert, key := fileClient(t, ca)
	s0 := socketIn(t)
	r := h.port49(runOpts{}, loginArgs(b, s0, key, cert, "")...)
	h.obsResult("control_login", r)
	h.mustOK(r, "the control login")
	h.obsStatus("control_status", s0)
	h.obsResult("control_refresh", h.port49(runOpts{}, "refresh", onSock(s0)))
	h.stopAgent(s0)

	h.step("2", "PIN tries before (ykman piv info, read only)")
	h.pinTries("pin_tries_before")

	s1 := socketIn(t)
	r = h.typedLogin("3", "login", loginArgs(b, s1, h.keyRef(slot9a, false), "", ""))
	h.obs("cert_source", "the token's own certificate (no --cert)")
	h.mustOK(r, "the slot 9a login")
	st := h.obsStatus("status", s1)
	h.obs("status_key_ref", st.KeyRef)

	h.step("4", "port49 refresh: signs with slot 9a, no PIN (about 2s)")
	rr := h.port49(runOpts{}, "refresh", onSock(s1))
	h.obsResult("refresh", rr)
	h.step("5", "port49 token leaf1 on the held connection (the token is not shown)")
	h.obsResult("token", h.port49(runOpts{token: true}, "token", onSock(s1), leafPlain))
	h.obsStatus("status_after", s1)
	h.stopAgent(s1)

	h.step("6", "PIN tries after")
	h.pinTries("pin_tries_after")
}

// Cell (d): `port49 token` on a device under hardware_key_touch, the touch
// key slot 9c (touch always): with a touch, with none, and the control
// device with no requirement.
func TestL60D(t *testing.T) {
	gate(t, gateD, "port49 token under hardware_key_touch; you type your PIN once and touch twice")
	h := newLab(t, "d", true)
	h.needPKCS11()
	ca := h.needLabCA()
	b := h.startLabBroker(ca, h.yubicoRoots())
	h.pinTries("pin_tries_before")

	s := socketIn(t)
	r := h.typedLogin("1", "login", loginArgs(b, s, h.keyRef(slot9a, false), "", h.keyRef(slot9c, false)))
	h.mustOK(r, "the login with the touch key")
	h.obsStatus("status", s)

	h.step("2", "control: port49 token %s, no second factor asked. Hands off (about 2s).", leafPlain)
	h.obsResult("control_token", h.port49(runOpts{deadline: touchDeadline, token: true}, "token", onSock(s), leafPlain))

	h.step("3", "port49 token %s WITH a touch", leafTouch)
	h.waitEnter("After you press Enter, TOUCH the key when it blinks.", handDeadline)
	h.obsResult("touched_token", h.port49(runOpts{deadline: touchDeadline, token: true}, "token", onSock(s), leafTouch))

	h.step("4", "port49 token %s with NO touch", leafTouch)
	h.waitEnter("After you press Enter, do NOT touch the key; hands off until port49 reports (about 15s).", handDeadline)
	h.obsResult("untouched_token", h.port49(runOpts{deadline: touchDeadline, token: true}, "token", onSock(s), leafTouch))
	h.obsStatus("status_after_untouched", s)

	h.step("5", "port49 token %s with a touch, right after the timeout", leafTouch)
	h.waitEnter("After you press Enter, TOUCH the key when it blinks.", handDeadline)
	h.obsResult("touched_after_timeout_token", h.port49(runOpts{deadline: touchDeadline, token: true}, "token", onSock(s), leafTouch))
	h.obsStatus("status_end", s)
	h.stopAgent(s)
	h.pinTries("pin_tries_after")
}
