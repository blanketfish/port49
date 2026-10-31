package main

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/rhwendt/port49/internal/agent"
	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/hwkey"
	"github.com/rhwendt/port49/internal/mfatouch"
	"github.com/rhwendt/port49/internal/oidc/oidctest"
	"github.com/rhwendt/port49/internal/testpki"
	"github.com/rhwendt/port49/internal/userconfig"
)

// signInFixture makes the sign-in runnable at a terminal against m: a
// provider that signs a user in, the config file the command reads (broker
// and broker_ca lines as given, plus the provider's CA), and the browser
// stub. It returns the provider, to count its sign-ins.
func signInFixture(t *testing.T, m *mfaLab, iss *oidctest.Issuer, brokerLines string) *oidctest.AuthServer {
	t.Helper()
	as := iss.AuthServer(t, "port49-cli", "sub-alice",
		map[string]any{"preferred_username": "alice@example.com", "amr": []string{"mfa"}})
	as.Now = m.now
	dir := privateDir(t)
	idpCA := filepath.Join(dir, "idp-ca.pem")
	if err := os.WriteFile(idpCA, iss.CertPEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfg, []byte(brokerLines+"oidc_ca: "+idpCA+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(userconfig.EnvConfig, cfg)
	withTerminal(t, true)
	savedBrowser, savedPaste := openBrowser, readPaste
	openBrowser = func(u string) error { go func() { _ = iss.Browser()(u) }(); return nil }
	readPaste = func() (string, error) { return "", io.EOF }
	t.Cleanup(func() { openBrowser, readPaste = savedBrowser, savedPaste })
	return as
}

// The sign-in's ID token goes to the broker the AGENT's session is with, the
// one the challenge came from, with the CA and CRL check the agent's session
// used: never the config file's broker when they differ. The other broker
// gets no request at all, and its CA is not what the proof is checked with.
func TestTheSignInsProofGoesToTheAgentsBrokerNotTheConfigs(t *testing.T) {
	iss := oidctest.NewIssuer(t)
	m := newMFALab(t, false, iss, "")
	var other atomic.Int32
	otherSrv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { other.Add(1) }))
	t.Cleanup(otherSrv.Close)
	otherCA := filepath.Join(privateDir(t), "other-ca.pem")
	if err := os.WriteFile(otherCA, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: otherSrv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	as := signInFixture(t, m, iss, "broker: "+otherSrv.URL+"\nbroker_ca: "+otherCA+"\n")

	code, out, errb := m.token(t, "leaf1")
	if code != 0 || strings.Count(out, "\n") != 1 {
		t.Fatalf("exit %d stdout %s stderr %q", code, tokenOut(out), errb)
	}
	if n := other.Load(); n != 0 {
		t.Fatalf("the config's broker got %d requests, want 0: the proof went to the wrong broker", n)
	}
	if m.bearers.Load() != 1 || len(as.Authorizations()) != 1 {
		t.Fatalf("the agent's broker saw %d bearer proofs, %d sign-ins", m.bearers.Load(), len(as.Authorizations()))
	}
}

// A login made with flags leaves no broker_ca in any file: the proof takes
// the CA from the agent's session, not from "broker_ca in the config".
func TestTheSignInTakesTheBrokerCAFromTheAgentsSession(t *testing.T) {
	iss := oidctest.NewIssuer(t)
	m := newMFALab(t, false, iss, "")
	as := signInFixture(t, m, iss, "") // a config with no broker and no broker_ca
	code, out, errb := m.token(t, "leaf1")
	if code != 0 || strings.Count(out, "\n") != 1 || m.bearers.Load() != 1 || len(as.Authorizations()) != 1 {
		t.Fatalf("exit %d stdout %s stderr %q (%d bearers)", code, tokenOut(out), errb, m.bearers.Load())
	}
}

// ruling 18: with the touch key absent, or its token showing no attestation,
// and idp_mfa accepted, the command falls back to the sign-in and says so in
// one line. It never says "touch your key now" first (the state is checked,
// then the prompt), and no touch is asked of the key.
func TestTokenFallsBackToTheSignInWhenTheTouchCannotBeMade(t *testing.T) {
	for _, tc := range []struct {
		name string
		prep func(m *mfaLab)
		why  string
	}{
		{"the key is out", func(m *mfaLab) { m.touch.SetState(hwkey.Absent) }, "touch key is not in the machine"},
		{"the key is locked", func(m *mfaLab) { m.touch.SetState(hwkey.Locked) }, "touch key needs its PIN"},
		{"no attestations", func(m *mfaLab) { m.touch.SetCertificates() }, "shows no attestation"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			iss := oidctest.NewIssuer(t)
			m := newMFALab(t, true, iss, "")
			as := signInFixture(t, m, iss, "broker: "+m.url+"\nbroker_ca: "+filepath.Join(m.dir, testpki.LabCA)+"\n")
			tc.prep(m)
			code, out, errb := m.token(t, "leaf1")
			if code != 0 || strings.Count(out, "\n") != 1 {
				t.Fatalf("exit %d stdout %s stderr %q", code, tokenOut(out), errb)
			}
			if strings.Contains(errb, "touch your key now") || m.touch.Signs() != 0 {
				t.Fatalf("the key was asked: signs %d, stderr %q", m.touch.Signs(), errb)
			}
			if !strings.Contains(errb, tc.why) || !strings.Contains(errb, "idp_mfa") || strings.Count(errb, "falling back") != 1 {
				t.Fatalf("stderr lacks the one fallback line (%q, idp_mfa): %q", tc.why, errb)
			}
			if m.bearers.Load() != 1 || len(as.Authorizations()) != 1 {
				t.Fatalf("%d bearer proofs, %d sign-ins", m.bearers.Load(), len(as.Authorizations()))
			}
		})
	}
}

// With no fallback the item allows (a touch alone), a key that is out ends
// the command in the Task 6 words, exit 1, before any "touch your key now";
// and with a sign-in accepted but no terminal, the key's words stay.
func TestAKeyThatIsOutWithNoFallbackIsInsertYourKey(t *testing.T) {
	for _, tc := range []struct {
		name    string
		methods []string
		term    bool
	}{
		{"a touch alone", []string{"hardware_key_touch"}, true},
		{"both methods, no terminal", []string{"hardware_key_touch", "idp_mfa"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var touches atomic.Int32
			req := coreRequirement()
			req.Methods = tc.methods
			sock := agentStub(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/status":
					_ = json.NewEncoder(w).Encode(agent.Status{TouchKey: true, TouchKeyState: "absent"})
				case "/mfa/touch":
					touches.Add(1)
					w.WriteHeader(http.StatusBadGateway)
					_ = json.NewEncoder(w).Encode(api.Error{Error: "key_absent", Detail: (&agent.KeyAbsentError{State: hwkey.Absent}).Error()})
				default:
					w.WriteHeader(http.StatusPreconditionRequired)
					_ = json.NewEncoder(w).Encode(req)
				}
			}))
			withTerminal(t, tc.term)
			var out, errb bytes.Buffer
			t.Setenv("PORT49_TEST_AGENT_SOCKET", sock)
			code := run([]string{"token", "core-sw01"}, &out, &errb)
			if code != 1 || out.Len() != 0 || strings.Contains(errb.String(), "touch your key now") ||
				!strings.Contains(errb.String(), "insert your key") {
				t.Fatalf("exit %d stdout %s stderr %q", code, tokenOut(out.String()), errb.String())
			}
		})
	}
}

// A connection that changed during a workload's touch is a run that may be
// run again: exit 75 (EX_TEMPFAIL), in the error's own words, with what was
// minted counted.
func TestAWorkloadsChangedConnectionIsTempFail(t *testing.T) {
	var errb bytes.Buffer
	err := fmt.Errorf("proving the touch for leaf1: %w", mfatouch.ErrConnectionChanged)
	resp := api.MintResponse{Results: []api.MintItem{{Device: "leaf2", Verdict: "permit", Login: "T"}}}
	if code := mintOutcome(&errb, "port49 workload token", "", []string{"leaf1", "leaf2"}, resp, err); code != exitTemporary ||
		!strings.Contains(errb.String(), "run it again") || !strings.Contains(errb.String(), "1 tokens minted") {
		t.Fatalf("exit %d: %q", code, errb.String())
	}
	errb.Reset()
	if code := mintOutcome(&errb, "port49 workload token", "", []string{"leaf1"}, resp, errors.New("refused")); code != 1 {
		t.Fatalf("a final refusal: exit %d, want 1", code)
	}
	// A --scope sweep's says which sweep stopped (final review client M3).
	errb.Reset()
	if code := mintOutcome(&errb, "port49 workload token", "core", nil, resp, err); code != exitTemporary ||
		!strings.Contains(errb.String(), "the sweep of scope core stopped after 1 tokens minted") {
		t.Fatalf("a sweep's changed connection: exit %d: %q", code, errb.String())
	}
}
