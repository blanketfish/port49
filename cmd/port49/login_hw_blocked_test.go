//go:build hwkey && hwkey_dlopen && linux

package main

import (
	"bytes"
	"crypto/tls"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/agent"
	"github.com/rhwendt/port49/internal/clientkey"
	"github.com/rhwendt/port49/internal/hwkey"
	"github.com/rhwendt/port49/internal/hwkey/hwtest"
	"github.com/rhwendt/port49/internal/hwkey/pkcs11"
	"github.com/rhwendt/port49/internal/testpki"
)

// loginOnce is one `port49 login` with the PIN typed at its prompt, and what
// it said.
func loginOnce(t *testing.T, l *labBroker, sock, ref, pin string) (code int, stderr string, prompts int) {
	t.Helper()
	asked, _ := pinPty(t, pin)
	var out, errb bytes.Buffer
	code = run(append([]string{"login"}, flagsWithKey(t, l, sock, ref, false)...), &out, &errb)
	return code, errb.String(), int(asked.Load())
}

// A token whose PIN is blocked is told so, with the way out, on both paths a
// PIN takes: straight to the key in the login (the key opened here), and to the
// running agent's /unlock. Two cases each: the wrong PIN that was the last
// try, which the token reports by CKF_USER_PIN_LOCKED while C_Login still
// answers CKR_PIN_INCORRECT, and the next try, which it answers
// CKR_PIN_LOCKED to even for the right PIN. Neither is the "token refused the
// PIN" that invites another try.
func TestABlockedPINIsSaidAsBlockedOnBothPaths(t *testing.T) {
	l := newLabBroker(t, time.Hour)
	t.Setenv(runCLIEnv, "1")

	// check: a wrong PIN on a token that is not blocked is the ordinary
	// refusal; then SoftHSM2, which never blocks a PIN itself, is made to read
	// as blocked (pkcs11.BlockPIN): a wrong PIN, the try that was the last,
	// says blocked; and the right PIN, which a blocked token answers
	// CKR_PIN_LOCKED to, says it too.
	check := func(path string, run func(pin string) (int, string, int)) {
		t.Helper()
		code, msg, _ := run("000000")
		if code != 1 || !strings.Contains(msg, "the token refused the PIN") || strings.Contains(msg, "blocked") {
			t.Fatalf("%s, a wrong PIN: code %d %q, want an ordinary refusal", path, code, msg)
		}
		for _, tc := range []struct {
			name         string
			answerLocked bool
			noFlag       bool // the token sets no CKF_USER_PIN_LOCKED; only C_Login says so
			pin          string
		}{
			{"the wrong PIN that was the last try", false, false, "000000"},
			{"CKR_PIN_LOCKED for the wrong PIN", true, false, "000000"},
			{"CKR_PIN_LOCKED for the right PIN", true, false, hwtest.SoftHSMUserPIN},
			{"CKR_PIN_LOCKED with no token flag, wrong PIN", true, true, "000000"},
			{"CKR_PIN_LOCKED with no token flag, right PIN", true, true, hwtest.SoftHSMUserPIN},
		} {
			restore := pkcs11.BlockPIN(tc.answerLocked)
			if tc.noFlag {
				restore()
				restore = pkcs11.BlockPINWithoutFlag()
			}
			code, msg, prompts := run(tc.pin)
			restore()
			// The token says CKF_USER_PIN_LOCKED before any PIN is typed, so
			// none is asked for (L60 F2); a token that says it only at
			// C_Login is found out by the try.
			if !tc.noFlag && prompts != 0 {
				t.Errorf("%s, %s: asked for the PIN %d times on a token that already says it is blocked", path, tc.name, prompts)
			}
			if code != 1 || !strings.Contains(msg, hwkey.PINBlockedWords) || strings.Contains(msg, "refused the PIN") {
				t.Errorf("%s, %s: code %d %q, want the blocked PIN's words and no refusal", path, tc.name, code, msg)
			}
			if !strings.Contains(msg, "unblock it with its PUK") || !strings.Contains(msg, "ykman piv access unblock-pin") {
				t.Errorf("%s, %s: %q does not say the way out", path, tc.name, msg)
			}
		}
	}

	// Straight to the key: a login with no agent running.
	ref := tokenWithTheLabKey(t, l)
	sock := privateSocket(t)
	t.Cleanup(func() { stopAgentAt(sock) })
	check("the login's own key", func(pin string) (int, string, int) {
		return loginOnce(t, l, sock, ref, pin)
	})
	if _, err := agent.NewClient(sock).Status(t.Context()); err == nil {
		t.Fatal("an agent started on a blocked PIN")
	}

	// Through the running agent's /unlock: an agent holding the key, locked.
	ref2 := tokenWithTheLabKey(t, l)
	u, err := pkcs11.ParseURI(ref2)
	if err != nil {
		t.Fatal(err)
	}
	key, err := pkcs11.Open(u, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { key.Close() })
	if key.State() != hwkey.Locked {
		t.Fatalf("the token's key is %s, want locked", key.State())
	}
	cert, err := tls.LoadX509KeyPair(filepath.Join(l.dir, testpki.LabClientCert), filepath.Join(l.dir, testpki.LabClientKey))
	if err != nil {
		t.Fatal(err)
	}
	cert.PrivateKey = key
	sock2 := privateSocket(t)
	a := agent.New(agent.Config{BrokerURL: l.url, Cert: cert, KeyRef: clientkey.CanonicalRef(ref2)})
	ln, err := agent.Listen(sock2)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: a.Handler()}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	check("the agent's /unlock", func(pin string) (int, string, int) {
		return loginOnce(t, l, sock2, ref2, pin)
	})
}
