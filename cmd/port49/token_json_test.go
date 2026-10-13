package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
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
	code := run([]string{"token", "--json", "--socket", sock, "leaf1"}, &out, &errb)
	var f tokenFailure
	if code != 1 || json.Unmarshal([]byte(out.String()), &f) != nil || f.Reason != "no_grants_matched" ||
		strings.Count(out.String(), "\n") != 1 || !strings.Contains(errb.String(), "deny no_grants_matched") ||
		strings.Contains(out.String(), "LOGINTOKEN") || strings.Contains(errb.String(), "LOGINTOKEN") {
		t.Fatalf("code %d stdout %q stderr %q", code, out.String(), errb.String())
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
