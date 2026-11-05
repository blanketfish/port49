package broker

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/broker/api"
	"github.com/blanketfish/port49/internal/policy"
	"github.com/blanketfish/port49/internal/store"
)

// proveIdPFor is who's idp_mfa proof of ch.
func (f *mfaFixture) proveIdPFor(t *testing.T, who, ch string) {
	t.Helper()
	tok := f.idToken(t, idTokenOpts{principal: who + "@example.com", nonceFor: ch, amr: []string{"pwd", "mfa"},
		authTime: f.clock.Now()})
	if code, detail := f.proveIdPDetail(t, tok, ch); code != http.StatusOK {
		t.Fatalf("POST /v1/mfa (idp) = %d %s", code, detail)
	}
}

// agentHash is the agent_sha256 of an agent session value, "" for none.
func agentHash(session string) string {
	r := &http.Request{Header: http.Header{}}
	r.Header.Set(api.AgentSessionHeader, session)
	return agentKey(r)
}

// setContextProof records the per-login proof a context was minted under,
// by the binding whose agent session is agent ("" for a bearer proof).
func (f *mfaFixture) setContextProof(t *testing.T, device, username, method string, at time.Time, agent string) {
	t.Helper()
	c := f.context(t, device, username)
	c.Credential.MFAMethod, c.Credential.MFAAt, c.Credential.MFAAgentSHA256 = method, at, agentHash(agent)
	if err := f.st.PutContext(context.Background(), store.ContextKey{NAS: device, Username: username}, c, 24*time.Hour); err != nil {
		t.Fatal(err)
	}
}

// requireCore is a fixture with alice's live context on core-sw01, minted
// with no proof, and the requirement added since.
func requireCore(t *testing.T, opts ...mfaOpt) *mfaFixture {
	t.Helper()
	f := newMFAFixture(t, append([]mfaOpt{withJunosCore()}, opts...)...)
	f.setRequirement(t, false)
	f.loginOnDevice(t, f.alice, "core-sw01")
	f.setRequirement(t, true)
	return f
}

func TestARefreshReadsTheContextsOwnProof(t *testing.T) {
	f := requireCore(t) // reuse_for 15m
	f.setContextProof(t, "core-sw01", "alice", "hardware_key_touch", f.clock.Now(), f.alice.agent)
	provedAt := f.clock.Now()
	f.clock.Advance(5 * time.Minute)
	out := f.refresh(t, f.alice)
	if s := out.find("core-sw01"); s.Outcome != "extended" || out.PerLoginMFA != nil {
		t.Fatalf("a refresh within reuse_for of the context's own proof = %+v", out)
	}
	c := f.context(t, "core-sw01", "alice")
	if c.Credential.MFAMethod != "hardware_key_touch" || !c.Credential.MFAAt.Equal(provedAt) {
		t.Fatalf("the context records proof %q at %v, want touch at %v", c.Credential.MFAMethod, c.Credential.MFAAt, provedAt)
	}
	f.assertRecordWith(t, "refresh", "permit", "grants_matched", func(r map[string]any) bool {
		m, _ := r["per_login_mfa"].(map[string]any)
		return m != nil && m["method"] == "hardware_key_touch" && m["reused"] == true
	})
	// reuse_for has passed since mfa_at: a proof is needed.
	f.clock.Advance(11 * time.Minute)
	if s := f.refresh(t, f.alice).find("core-sw01"); s.Outcome != "per_login_mfa_required" {
		t.Fatalf("a refresh past reuse_for of the context's own proof = %+v", s)
	}
}

func TestAnotherAgentsRefreshIsNotCoveredByTheRecordedProof(t *testing.T) {
	f := requireCore(t)
	f.setContextProof(t, "core-sw01", "alice", "hardware_key_touch", f.clock.Now(), f.alice.agent)
	f.clock.Advance(time.Minute)
	if s := f.refreshAs(t, f.alice, f.otherAgent).find("core-sw01"); s.Outcome != "per_login_mfa_required" {
		t.Fatalf("agent B's refresh under agent A's recorded proof = %+v", s)
	}
}

func TestAContextStoredBeforeTheAgentWasRecordedIsNotCovered(t *testing.T) {
	f := requireCore(t)
	f.setContextProof(t, "core-sw01", "alice", "hardware_key_touch", f.clock.Now(), "")
	f.clock.Advance(time.Minute)
	if s := f.refresh(t, f.alice).find("core-sw01"); s.Outcome != "per_login_mfa_required" {
		t.Fatalf("a refresh under a proof with no recorded agent = %+v", s)
	}
}

func TestAMintRecordsTheProvingAgentOnTheContext(t *testing.T) {
	f := newMFAFixture(t, withJunosCore())
	ch := f.mint(t, f.alice, "core-sw01", "").find("core-sw01").PerLoginMFA.Challenge
	f.proveTouch(t, f.alice, ch)
	if it := f.mint(t, f.alice, "core-sw01", ch).Results[0]; it.Verdict != "permit" {
		t.Fatalf("mint after a proof = %+v", it)
	}
	cands, err := f.st.Candidates(context.Background(), store.TokenKey{NAS: "core-sw01", Username: "alice"})
	if err != nil || len(cands) != 1 {
		t.Fatalf("%d tokens: %v", len(cands), err)
	}
	if got := cands[0].Credential.MFAAgentSHA256; got == "" || got != agentHash(f.alice.agent) {
		t.Fatalf("the minted credential records agent %q, want the proving agent's hash", got)
	}
}

func TestAnExtensionRecordsTheProvingAgentOnTheContext(t *testing.T) {
	f := requireCore(t)
	f.setContextProof(t, "core-sw01", "alice", "idp_mfa", f.clock.Now(), f.otherAgent)
	f.clock.Advance(20 * time.Minute) // the recorded proof has lapsed
	ch := f.refreshAsked(t, f.alice)
	f.proveTouch(t, f.alice, ch)
	if s := f.refreshNaming(t, f.alice, ch).find("core-sw01"); s.Outcome != "extended" {
		t.Fatalf("refresh after a proof = %+v", s)
	}
	if got := f.context(t, "core-sw01", "alice").Credential.MFAAgentSHA256; got != agentHash(f.alice.agent) {
		t.Fatalf("the context records agent %q after alice's agent proved, want its hash", got)
	}
}

func TestAContextsOwnProofOfAMethodNotAcceptedHereDoesNotCover(t *testing.T) {
	f := requireCore(t, withTouchOnlyCore())
	f.setContextProof(t, "core-sw01", "alice", "idp_mfa", f.clock.Now(), f.alice.agent)
	f.clock.Advance(time.Minute)
	if s := f.refresh(t, f.alice).find("core-sw01"); s.Outcome != "per_login_mfa_required" {
		t.Fatalf("an idp_mfa proof on a touch-only device = %+v", s)
	}
}

func TestAnExtensionWritesTheCoveringProofToTheContext(t *testing.T) {
	f := requireCore(t)
	f.setContextProof(t, "core-sw01", "alice", "idp_mfa", f.clock.Now(), f.alice.agent)
	f.clock.Advance(20 * time.Minute) // the recorded proof has lapsed
	ch := f.refreshAsked(t, f.alice)
	provedAt := f.clock.Now()
	f.proveTouch(t, f.alice, ch)
	if s := f.refreshNaming(t, f.alice, ch).find("core-sw01"); s.Outcome != "extended" {
		t.Fatalf("refresh after a proof = %+v", s)
	}
	c := f.context(t, "core-sw01", "alice")
	if c.Credential.MFAMethod != "hardware_key_touch" || !c.Credential.MFAAt.Equal(provedAt) {
		t.Fatalf("the context records proof %q at %v, want touch at %v", c.Credential.MFAMethod, c.Credential.MFAAt, provedAt)
	}
}

func TestARefreshWhoseProofReadFailsRecordsTheContext(t *testing.T) {
	f := requireCore(t)
	before := f.context(t, "core-sw01", "alice").SessionExpires
	f.clock.Advance(time.Hour)
	f.store.failOn("GetMFAProof")
	status, body := f.refreshStatus(t, f.alice, f.alice.agent, "", false)
	if status != http.StatusServiceUnavailable {
		t.Fatalf("POST /v1/refresh = %d %s, want 503", status, body)
	}
	if got := f.context(t, "core-sw01", "alice").SessionExpires; !got.Equal(before) {
		t.Fatalf("the ceiling moved to %v", got)
	}
	for _, r := range f.recs(t) {
		sess, _ := r["session"].(map[string]any)
		if r["event"] == "refresh" && r["verdict"] == "deny" && r["reason"] == "store_unavailable" &&
			r["per_login_mfa"] != nil && sess != nil && sess["ctx_id"] != nil {
			return
		}
	}
	t.Fatalf("no per-context refresh deny store_unavailable record with the per_login_mfa block in\n%s", f.logs.String())
}

func TestARefreshUnderARequirementNoMethodCanMeetIsUnavailablePerDevice(t *testing.T) {
	f := newMFAFixture(t, withJunosCore(), withTouchOnlyCore(), withoutAttestationRoots())
	f.setRequirement(t, false)
	f.loginOnDevice(t, f.alice, "core-sw01")
	f.loginOnDevice(t, f.alice, "edge-sw01")
	f.setRequirement(t, true)
	f.clock.Advance(time.Hour)
	out := f.refresh(t, f.alice)
	if s := out.find("core-sw01"); s.Outcome != "per_login_mfa_unavailable" {
		t.Fatalf("core = %+v", out)
	}
	if s := out.find("edge-sw01"); s.Outcome != "extended" || out.PerLoginMFA != nil {
		t.Fatalf("edge, which asks nothing = %+v", out)
	}
	f.assertRecordWith(t, "refresh", "deny", "per_login_mfa_unavailable", func(r map[string]any) bool {
		sess, _ := r["session"].(map[string]any)
		return r["per_login_mfa"] != nil && sess != nil
	})
}

func TestAStoreErrorAtTheChallengeRequestIsPacedNotExempt(t *testing.T) {
	f := requireCore(t)
	f.clock.Advance(time.Hour)
	ch := f.refreshAsked(t, f.alice) // the connection refreshed just now
	f.proveTouch(t, f.alice, ch)
	f.store.failOn("TakeOnce")
	if code := f.refreshChallengeNaming(t, f.alice, ch); code != http.StatusTooManyRequests {
		t.Fatalf("a challenge request whose proof could not be read: %d, want 429", code)
	}
	f.store.failOn()
	if code := f.refreshChallengeNaming(t, f.alice, ch); code != http.StatusOK {
		t.Fatalf("the proof the failed take did not spend: %d, want 200", code)
	}
}

// A ResolveMember error where the extension reads the policy again is a
// context not judged, never one extended on a default.
func TestAnExtensionWhosePolicyReadFailsIsNotJudged(t *testing.T) {
	f := requireCore(t)
	at := f.clock.Now()
	const ghost = "user:ghost@example.com"
	f.liveContextAt(t, "core-sw01", "ghost", ghost, "", at, at.Add(8*time.Hour))
	f.clock.Advance(time.Hour)
	pol := f.b.Policy.Load()
	dev, _ := pol.Device("core-sw01")
	out, _, err := f.b.extend(context.Background(), newHeldLog(), pol, policy.Member{Principal: ghost}, nil,
		store.Credential{}, store.ContextRef{NAS: "core-sw01", Username: "ghost"}, dev, f.clock.Now(), false, nil, nil,
		&refreshAsk{})
	if err != nil || out != "not_judged" {
		t.Fatalf("extend = %q, %v, want not_judged", out, err)
	}
	if got := f.context(t, "core-sw01", "ghost").AuthTime; !got.Equal(at) {
		t.Fatalf("auth_time moved to %v", got)
	}
}
