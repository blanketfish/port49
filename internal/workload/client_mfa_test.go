package workload

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/hwkey"
	"github.com/rhwendt/port49/internal/hwkey/hwfake"
	"github.com/rhwendt/port49/internal/pivattest"
	"github.com/rhwendt/port49/internal/testpki"
)

// needsProof answers the page as the broker does under a requirement on
// leaf1 alone (applies_to_machines): leaf1 is denied per_login_mfa_required
// with the challenge, every other device is minted at once.
func needsProof(challenge string) func(http.ResponseWriter, api.MintRequest) {
	return func(w http.ResponseWriter, req api.MintRequest) {
		resp := api.MintResponse{Principal: "spiffe://corp.example.com/host/oxidized-01", Subject: "svc_oxidized"}
		for _, d := range req.Devices {
			if d == "leaf1" && req.PerLoginMFAChallenge == "" {
				resp.Results = append(resp.Results, api.MintItem{Device: d, Verdict: "deny", Reason: "per_login_mfa_required",
					Detail: "leaf1 asks for a second factor at each login: scope core accepts hardware_key_touch (reuse 0m, from scope core)",
					PerLoginMFA: &api.PerLoginMFA{Device: d, Challenge: challenge, Accept: []string{"hardware_key_touch"},
						Methods: []string{"hardware_key_touch"}, ReuseFrom: "scope core"}})
				continue
			}
			resp.Results = append(resp.Results, api.MintItem{Device: d, Verdict: "permit", Username: "svc-oxidized", Login: "TOKEN" + d})
		}
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// touchHarness is a harness whose workload key has a touch key beside it on
// one fake token, the attestations in the touch key's certificate list.
func touchHarness(t *testing.T, f *fakeBroker) (*harness, *hwfake.Key) {
	t.Helper()
	h := newHarness(t, f, 24*time.Hour)
	session, err := tls.LoadX509KeyPair(h.cfg.CertFile, h.cfg.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	piv, err := testpki.NewPIV(h.now)
	if err != nil {
		t.Fatal(err)
	}
	touchKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	touch := hwfake.New(touchKey, "/fake/module.so", "TOKEN1")
	touchAtt, err := piv.Slot(&touchKey.PublicKey, pivattest.TouchAlways)
	if err != nil {
		t.Fatal(err)
	}
	sessionAtt, err := piv.Slot(session.PrivateKey.(*ecdsa.PrivateKey).Public(), pivattest.TouchNever)
	if err != nil {
		t.Fatal(err)
	}
	touch.SetCertificates(touchAtt, piv.Device, sessionAtt)
	h.cfg.TouchKey = touch
	return h, touch
}

type said struct {
	mu    sync.Mutex
	lines []string
}

func (s *said) say(format string, args ...any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lines = append(s.lines, fmt.Sprintf(format, args...))
}

func (s *said) text() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.Join(s.lines, "\n")
}

// A page of two devices, one under applies_to_machines: the run mints the
// other at once, proves the touch on its own connection, and retries only the
// asked-for item in a new request under a new Idempotency-Key (the same key
// with a changed body is a 409, and a retried whole page would mint the other
// device twice).
func TestAWorkloadProvesWithItsTouchKey(t *testing.T) {
	challenge := base64.RawURLEncoding.EncodeToString(make([]byte, api.MFAChallengeLen))
	f := &fakeBroker{batchMax: 10, answers: []func(http.ResponseWriter, api.MintRequest){needsProof(challenge)}}
	h, touch := touchHarness(t, f)
	var s said
	h.cfg.Say = s.say
	resp, err := h.client(t).Mint(context.Background(), MintOptions{Devices: []string{"leaf1", "leaf2"}, TTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Results) != 2 || resp.Results[0].Device != "leaf1" || resp.Results[0].Verdict != "permit" ||
		resp.Results[1].Device != "leaf2" || resp.Results[1].Verdict != "permit" {
		t.Fatalf("results: %+v", resp.Results)
	}
	if len(f.keys) != 2 || f.keys[0] == f.keys[1] || len(f.bodies[0].Devices) != 2 ||
		len(f.bodies[1].Devices) != 1 || f.bodies[1].Devices[0] != "leaf1" ||
		f.bodies[0].PerLoginMFAChallenge != "" || f.bodies[1].PerLoginMFAChallenge != challenge {
		t.Fatalf("keys %v, bodies %+v", f.keys, f.bodies)
	}
	if len(f.mfa) != 1 || f.mfa[0].req.Method != "hardware_key_touch" || f.mfa[0].req.Challenge != challenge ||
		len(f.mfa[0].req.Attestation) != 3 {
		t.Fatalf("proofs: %+v", f.mfa)
	}
	// The signature is the touch key's over the challenge and the exporter
	// value of the connection the proof came on.
	sig, err := base64.RawURLEncoding.DecodeString(f.mfa[0].req.Signature)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(api.MFAMessage(make([]byte, api.MFAChallengeLen), f.mfa[0].ekm))
	if !ecdsa.VerifyASN1(&touch.PrivateKey.PublicKey, sum[:], sig) {
		t.Fatal("the signature is not the touch key's over MFAMessage(challenge, this connection's exporter value)")
	}
	if !strings.Contains(s.text(), "touch the key for leaf1") || strings.Contains(s.text(), challenge) {
		t.Fatalf("said: %q", s.text())
	}
}

// Without a touch key the item fails with the broker's sentence, nothing is
// proved, and nothing is retried: the run reports it as any refused item.
func TestAWorkloadWithoutATouchKeyReportsTheRequirement(t *testing.T) {
	challenge := base64.RawURLEncoding.EncodeToString(make([]byte, api.MFAChallengeLen))
	f := &fakeBroker{batchMax: 10, answers: []func(http.ResponseWriter, api.MintRequest){needsProof(challenge)}}
	h := newHarness(t, f, 24*time.Hour)
	resp, err := h.client(t).Mint(context.Background(), MintOptions{Devices: []string{"leaf1", "leaf2"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Results) != 2 || resp.Results[0].Reason != "per_login_mfa_required" ||
		!strings.Contains(resp.Results[0].Detail, "asks for a second factor at each login") ||
		resp.Results[1].Verdict != "permit" {
		t.Fatalf("results: %+v", resp.Results)
	}
	if len(f.keys) != 1 || len(f.mfa) != 0 {
		t.Fatalf("%d mints, %d proofs", len(f.keys), len(f.mfa))
	}
}

// A touch not made ends the proof with the key's words and keeps what was
// already minted: the run is told, and leaf2's token is not lost.
func TestAWorkloadsMissedTouchKeepsWhatWasMinted(t *testing.T) {
	challenge := base64.RawURLEncoding.EncodeToString(make([]byte, api.MFAChallengeLen))
	f := &fakeBroker{batchMax: 10, answers: []func(http.ResponseWriter, api.MintRequest){needsProof(challenge)}}
	h, touch := touchHarness(t, f)
	touch.OnSign(func() error { return hwkey.ErrTouchTimeout })
	resp, err := h.client(t).Mint(context.Background(), MintOptions{Devices: []string{"leaf1", "leaf2"}})
	if !errors.Is(err, hwkey.ErrTouchTimeout) || !strings.Contains(err.Error(), "leaf1") {
		t.Fatalf("%v", err)
	}
	if len(resp.Results) != 2 || resp.Results[1].Verdict != "permit" || resp.Results[0].Reason != "per_login_mfa_required" {
		t.Fatalf("results: %+v", resp.Results)
	}
	if len(f.mfa) != 0 || len(f.keys) != 1 || touch.Signs() != 1 {
		t.Fatalf("%d proofs, %d mints, %d signs", len(f.mfa), len(f.keys), touch.Signs())
	}
}

// The line before the touch names devices the broker sent: control bytes in
// a name reach no terminal or cron mail.
func TestTheTouchPromptNamesDevicesSafely(t *testing.T) {
	challenge := base64.RawURLEncoding.EncodeToString(make([]byte, api.MFAChallengeLen))
	const evil = "leaf1\x1b[2J\r\nnot-a-line"
	f := &fakeBroker{batchMax: 10, answers: []func(http.ResponseWriter, api.MintRequest){
		func(w http.ResponseWriter, req api.MintRequest) {
			resp := api.MintResponse{Principal: "spiffe://corp.example.com/host/oxidized-01", Subject: "svc_oxidized"}
			for _, d := range req.Devices {
				if req.PerLoginMFAChallenge == "" {
					resp.Results = append(resp.Results, api.MintItem{Device: d, Verdict: "deny", Reason: "per_login_mfa_required",
						PerLoginMFA: &api.PerLoginMFA{Device: d, Challenge: challenge, Accept: []string{"hardware_key_touch"},
							Methods: []string{"hardware_key_touch"}}})
					continue
				}
				resp.Results = append(resp.Results, api.MintItem{Device: d, Verdict: "permit", Username: "svc", Login: "T"})
			}
			_ = json.NewEncoder(w).Encode(resp)
		}}}
	h, _ := touchHarness(t, f)
	var s said
	h.cfg.Say = s.say
	_, _ = h.client(t).Mint(context.Background(), MintOptions{Devices: []string{evil}})
	text := s.text()
	if !strings.Contains(text, "touch the key for leaf1") || strings.ContainsAny(text, "\x1b\r") || strings.Contains(text, "\n") {
		t.Fatalf("said: %q", text)
	}
}

// The broker refusing the proof is final: the refusal's code and detail, no
// second mint.
func TestAWorkloadsRefusedProofIsFinal(t *testing.T) {
	challenge := base64.RawURLEncoding.EncodeToString(make([]byte, api.MFAChallengeLen))
	f := &fakeBroker{batchMax: 10, mfaStatus: http.StatusUnauthorized,
		answers: []func(http.ResponseWriter, api.MintRequest){needsProof(challenge)}}
	h, _ := touchHarness(t, f)
	_, err := h.client(t).Mint(context.Background(), MintOptions{Devices: []string{"leaf1", "leaf2"}})
	var ae *APIError
	if !errors.As(err, &ae) || ae.Code != "per_login_mfa_refused" || len(f.keys) != 1 {
		t.Fatalf("%v (%d mints)", err, len(f.keys))
	}
}
