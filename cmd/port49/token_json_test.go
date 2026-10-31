package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rhwendt/port49/internal/agent"
	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/brokercrl"
	"github.com/rhwendt/port49/internal/hwkey"
)

func TestTokenFailureCodes(t *testing.T) {
	need := api.PerLoginMFA{Device: "core1", Challenge: "CHALLENGE", Accept: []string{"hardware_key_touch"},
		ReuseForSeconds: 900, ReuseFrom: "scope core"}
	for _, tc := range []struct {
		name string
		item api.MintItem
		err  error
		want tokenFailure
	}{
		{"deny", api.MintItem{Device: "core1", Verdict: "deny", Reason: "no_grants_matched", Detail: "d"}, nil,
			tokenFailure{Device: "core1", Verdict: "deny", Reason: "no_grants_matched", Detail: "d"}},
		{"item error", api.MintItem{Device: "core1", Error: "broker_error", Detail: "d"},
			&agent.ItemError{Device: "core1", Code: "broker_error", Detail: "d"},
			tokenFailure{Device: "core1", Error: "broker_error", Detail: "d"}},
		{"no agent", api.MintItem{}, fmt.Errorf("%w at /s: refused", agent.ErrNoAgent),
			tokenFailure{Device: "core1", Error: "no_agent"}},
		{"too old", api.MintItem{}, agent.ErrAgentTooOld, tokenFailure{Device: "core1", Error: "agent_too_old"}},
		{"over", api.MintItem{}, agent.ErrSessionOver, tokenFailure{Device: "core1", Error: "session_over"}},
		{"revoked", api.MintItem{}, &agent.RevokedError{Detail: "d"}, tokenFailure{Device: "core1", Error: "credential_revoked"}},
		{"running", api.MintItem{}, &agent.RevocationRunningError{Detail: "d"},
			tokenFailure{Device: "core1", Error: "revocation_running"}},
		{"mfa", api.MintItem{}, &agent.MFARequiredError{Requirement: need},
			tokenFailure{Device: "core1", Error: "per_login_mfa_required",
				PerLoginMFA: &mfaRequirement{Accept: need.Accept, ReuseForSeconds: 900, ReuseFrom: "scope core"}}},
		{"no terminal", api.MintItem{}, &mfaUnprovedError{Requirement: need, Err: errors.New("no terminal")},
			tokenFailure{Device: "core1", Error: "per_login_mfa_required",
				PerLoginMFA: &mfaRequirement{Accept: need.Accept, ReuseForSeconds: 900, ReuseFrom: "scope core"}}},
		{"touch timeout", api.MintItem{}, &mfaUnprovedError{Requirement: need,
			Err: &agent.KeyError{Err: hwkey.ErrTouchTimeout}}, tokenFailure{Device: "core1", Error: "touch_timeout"}},
		{"changed", api.MintItem{}, &mfaUnprovedError{Requirement: need, Err: agent.ErrConnectionChanged},
			tokenFailure{Device: "core1", Error: "connection_changed"}},
		// A proof that met the session's own failure says that failure (pre-flight M8).
		{"proof: revoked", api.MintItem{}, &mfaUnprovedError{Requirement: need, Err: &agent.RevokedError{Detail: "d"}},
			tokenFailure{Device: "core1", Error: "credential_revoked"}},
		{"proof: over", api.MintItem{}, &mfaUnprovedError{Requirement: need, Err: agent.ErrSessionOver},
			tokenFailure{Device: "core1", Error: "session_over"}},
		{"proof: no agent", api.MintItem{}, &mfaUnprovedError{Requirement: need,
			Err: fmt.Errorf("%w at /s: refused", agent.ErrNoAgent)}, tokenFailure{Device: "core1", Error: "no_agent"}},
		{"proof: too old", api.MintItem{}, &mfaUnprovedError{Requirement: need, Err: agent.ErrAgentTooOld},
			tokenFailure{Device: "core1", Error: "agent_too_old"}},
		// A broker that is down is temporary; a broker whose certificate the CRL
		// check refused is not; neither is a requirement to prove (review I1, I2).
		{"unreachable", api.MintItem{}, &agent.BrokerUnavailableError{Err: errors.New("agent: the broker at https://b is unreachable")},
			tokenFailure{Device: "core1", Error: "broker_unavailable"}},
		{"proof: unreachable", api.MintItem{}, &mfaUnprovedError{Requirement: need,
			Err: &agent.BrokerUnavailableError{Err: errors.New("the broker at https://b is unreachable")}},
			tokenFailure{Device: "core1", Error: "broker_unavailable"}},
		// A touch proof through the socket: the broker down, or refusing it (a 4xx).
		{"proof: touch unreachable", api.MintItem{}, &mfaUnprovedError{Requirement: need,
			Err: &agent.BrokerUnavailableError{Err: errors.New("agent: the broker at https://b is unreachable")}},
			tokenFailure{Device: "core1", Error: "broker_unavailable"}},
		{"proof: touch refused", api.MintItem{}, &mfaUnprovedError{Requirement: need,
			Err: &agent.APIError{Status: 400, Code: "bad_request", Detail: "d"}},
			tokenFailure{Device: "core1", Error: "broker_refused"}},
		{"proof: touch broker fault", api.MintItem{}, &mfaUnprovedError{Requirement: need,
			Err: &agent.APIError{Status: 500, Code: "internal", Detail: "d"}},
			tokenFailure{Device: "core1", Error: "agent_error"}},
		{"proof: crl revoked", api.MintItem{}, &mfaUnprovedError{Requirement: need,
			Err: &brokercrl.RevokedError{Subject: "CN=broker", Serial: "7", List: "l"}},
			tokenFailure{Device: "core1", Error: "broker_refused"}},
		{"proof: crl unchecked", api.MintItem{}, &mfaUnprovedError{Requirement: need,
			Err: &brokercrl.UncheckedError{Detail: "d"}}, tokenFailure{Device: "core1", Error: "broker_refused"}},
		{"key locked", api.MintItem{}, &agent.KeyError{Err: hwkey.ErrLocked}, tokenFailure{Device: "core1", Error: "key_locked"}},
		{"key absent", api.MintItem{}, &agent.KeyError{Err: hwkey.ErrKeyAbsent}, tokenFailure{Device: "core1", Error: "key_absent"}},
		{"proof: key locked", api.MintItem{}, &mfaUnprovedError{Requirement: need, Err: &agent.KeyError{Err: hwkey.ErrLocked}},
			tokenFailure{Device: "core1", Error: "key_locked"}},
		{"refused", api.MintItem{}, &agent.BrokerRefusedError{Err: errors.New("revoked")},
			tokenFailure{Device: "core1", Error: "broker_refused"}},
		{"no token", api.MintItem{Device: "core1", Verdict: "permit"}, nil, tokenFailure{Device: "core1", Error: "no_token"}},
		{"other", api.MintItem{}, errors.New("agent: something"), tokenFailure{Device: "core1", Error: "agent_error"}},
	} {
		got := tokenFailureOf("core1", tc.item, tc.err)
		got.Detail, tc.want.Detail = "", "" // the words are checked below
		gj, _ := json.Marshal(got)
		wj, _ := json.Marshal(tc.want)
		if string(gj) != string(wj) {
			t.Errorf("%s: got %s want %s", tc.name, gj, wj)
		}
		if strings.Contains(string(gj), "CHALLENGE") {
			t.Errorf("%s: the challenge was printed", tc.name)
		}
	}
}

// --json on a failure: one object on stdout, the exit status as before, the
// stderr line as before, and no token anywhere.
func TestTokenJSONOnADeny(t *testing.T) {
	sock := agentStub(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A faulty broker's token beside a deny: it must reach no stream.
		_ = json.NewEncoder(w).Encode(api.MintItem{Device: "leaf1", Verdict: "deny", Reason: "no_grants_matched",
			Login: "LOGINTOKEN"})
	}))
	var out, errb lockedBuffer
	t.Setenv("PORT49_TEST_AGENT_SOCKET", sock)
	code := run([]string{"token", "--json", "leaf1"}, &out, &errb)
	var f tokenFailure
	if code != 1 || json.Unmarshal([]byte(out.String()), &f) != nil || f.Reason != "no_grants_matched" ||
		strings.Count(out.String(), "\n") != 1 || !strings.Contains(errb.String(), "deny no_grants_matched") ||
		strings.Contains(out.String(), "LOGINTOKEN") || strings.Contains(errb.String(), "LOGINTOKEN") {
		t.Fatalf("code %d stdout %q stderr %q", code, out.String(), errb.String())
	}
}

// The IdP proof path's real producers (postIdPProof and fetchBrokerConfig,
// against a TLS broker) map as the touch path and /token do: an outage (down or
// 503, store_unavailable included) is broker_unavailable, a 4xx refusal is
// broker_refused, a 500 is agent_error. A hand-built error would only prove the
// switch, not the producers.
func TestTheIdPProofPathMapsAsTheTouchPathDoes(t *testing.T) {
	need := api.PerLoginMFA{Device: "core1", Challenge: "CHALLENGE", Accept: []string{"idp_mfa"}}
	code := func(err error) string {
		f := tokenFailureOf("core1", api.MintItem{}, &mfaUnprovedError{Requirement: need, Err: err})
		if strings.Contains(f.Detail, "IDTOKEN") || strings.Contains(f.Detail, "CHALLENGE") {
			t.Errorf("a secret in %q", f.Detail)
		}
		return f.Error
	}
	for _, tc := range []struct {
		name   string
		status int
		body   api.Error
		want   string
	}{
		{"503 store_unavailable", 503, api.Error{Error: "store_unavailable", Detail: "ask again and prove again"}, "broker_unavailable"},
		{"500", 500, api.Error{Error: "internal", Detail: "x"}, "agent_error"},
		{"401 refused", 401, api.Error{Error: "per_login_mfa_refused", Detail: "acr"}, "broker_refused"},
		{"no API error", 502, api.Error{}, "agent_error"},
	} {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(tc.status)
			_ = json.NewEncoder(w).Encode(tc.body)
		}))
		pool := x509.NewCertPool()
		pool.AddCert(srv.Certificate())
		if got := code(postIdPProof(context.Background(), srv.URL, pool, nil, "IDTOKEN", "CHALLENGE")); got != tc.want {
			t.Errorf("/v1/mfa %s: %s, want %s", tc.name, got, tc.want)
		}
		if tc.status == 503 || tc.status == 500 {
			_, err := fetchBrokerConfig(context.Background(), srv.URL, pool, nil)
			if got := code(err); got != tc.want {
				t.Errorf("/v1/config %s: %s, want %s", tc.name, got, tc.want)
			}
		}
		srv.Close()
	}
	pool := x509.NewCertPool()
	if got := code(postIdPProof(context.Background(), "https://127.0.0.1:1", pool, nil, "IDTOKEN", "CHALLENGE")); got != "broker_unavailable" {
		t.Errorf("/v1/mfa unreachable: %s", got)
	}
	_, err := fetchBrokerConfig(context.Background(), "https://127.0.0.1:1", pool, nil)
	if got := code(configFault(err)); got != "broker_unavailable" {
		t.Errorf("/v1/config unreachable: %s", got)
	}
	// A redirect, a body that is not a config, and a certificate the CA does not
	// verify are faults, as on the touch path (Task 5 re-review 2, N1).
	for _, tc := range []struct {
		name string
		h    http.HandlerFunc
		pool bool
	}{
		{"302", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://elsewhere.example/", http.StatusFound)
		}, true},
		{"html 200", func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, "<html>")
		}, true},
		{"wrong CA", func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(api.Config{})
		}, false},
	} {
		srv := httptest.NewTLSServer(tc.h)
		pool := x509.NewCertPool()
		if tc.pool {
			pool.AddCert(srv.Certificate())
		}
		_, err := fetchBrokerConfig(context.Background(), srv.URL, pool, nil)
		if got := code(configFault(err)); got != "agent_error" {
			t.Errorf("/v1/config %s: %s, want agent_error", tc.name, got)
		}
		srv.Close()
	}
}

// A broker fault the agent can only call broker_error crosses the socket on the
// touch path as 502, and is agent_error, never a requirement to prove again.
func TestATouchProofBrokerFaultIsAgentError(t *testing.T) {
	sock := agentStub(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			w.WriteHeader(428)
			_ = json.NewEncoder(w).Encode(api.PerLoginMFA{Device: "leaf1", Challenge: "CHALLENGE", Accept: []string{"hardware_key_touch"}})
		case "/status":
			_ = json.NewEncoder(w).Encode(agent.Status{TouchKey: true})
		case "/mfa/touch":
			w.WriteHeader(502)
			_ = json.NewEncoder(w).Encode(api.Error{Error: "broker_error", Detail: "agent: the broker answered 500 Internal Server Error: x y"})
		}
	}))
	var out, errb lockedBuffer
	t.Setenv("PORT49_TEST_AGENT_SOCKET", sock)
	code := run([]string{"token", "--json", "leaf1"}, &out, &errb)
	var f tokenFailure
	if code != 1 || json.Unmarshal([]byte(out.String()), &f) != nil || f.Error != "agent_error" || f.PerLoginMFA != nil {
		t.Fatalf("code %d stdout %q", code, out.String())
	}
}

// A detail with a control character is printed safe.
func TestTokenFailureDetailIsPrintable(t *testing.T) {
	f := tokenFailureOf("leaf1", api.MintItem{Device: "leaf1", Verdict: "deny", Reason: "no_grants_matched",
		Detail: "a\x1b[2Jb"}, nil)
	if strings.ContainsRune(f.Detail, 0x1b) {
		t.Fatalf("detail %q", f.Detail)
	}
}
