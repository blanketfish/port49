package broker

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/broker/api"
	"github.com/blanketfish/port49/internal/policy"
	"github.com/blanketfish/port49/internal/store"
)

// mfaRefreshResp is a refresh's 200.
type mfaRefreshResp struct{ api.RefreshResponse }

func (r mfaRefreshResp) find(device string) api.RefreshedSession {
	for _, s := range r.Sessions {
		if s.Device == device {
			return s
		}
	}
	return api.RefreshedSession{}
}

// setRequirement loads the fixture's policy with or without core's
// per_login_mfa: the reload that adds a requirement under live contexts.
func (f *mfaFixture) setRequirement(t *testing.T, on bool) {
	t.Helper()
	o := f.opts
	o.noRequirement = !on
	f.loadPolicy(t, mfaPolicy(o))
}

// loginOnDevice is a live context of who on device, minted with no proof:
// authenticated now with an eight-hour ceiling.
func (f *mfaFixture) loginOnDevice(t *testing.T, who *mfaActor, device string) {
	t.Helper()
	at := f.b.Now()
	f.liveContextAt(t, device, "alice", alicePrincipal, certKey(who.cert), at, at.Add(8*time.Hour))
}

func (f *mfaFixture) context(t *testing.T, device, username string) store.Context {
	t.Helper()
	c, err := f.st.GetContext(context.Background(), store.ContextKey{NAS: device, Username: username})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// refreshChallengeStep asks for a refresh challenge on who's held
// connection, naming a proved challenge when ch is not empty, and returns
// the status and the nonce a 200 carries.
func (f *mfaFixture) refreshChallengeStep(t *testing.T, who *mfaActor, agent, ch string) (int, string) {
	t.Helper()
	body := ""
	if ch != "" {
		raw, err := json.Marshal(api.RefreshChallengeRequest{PerLoginMFAChallenge: ch})
		if err != nil {
			t.Fatal(err)
		}
		body = string(raw)
	}
	hdr := map[string]string{}
	if agent != "" {
		hdr[api.AgentSessionHeader] = agent
	}
	code, raw := who.conn.post(t, "/v1/refresh/challenge", hdr, body)
	if code != http.StatusOK {
		return code, ""
	}
	var c api.RefreshChallenge
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	return code, c.Nonce
}

// refreshWith is a whole refresh on who's held connection: the challenge,
// named or not, then the signed answer. nameInAnswer names ch in the answer
// instead of the challenge request.
func (f *mfaFixture) refreshWith(t *testing.T, who *mfaActor, agent, ch string, nameInAnswer bool) mfaRefreshResp {
	t.Helper()
	status, body := f.refreshStatus(t, who, agent, ch, nameInAnswer)
	if status != http.StatusOK {
		t.Fatalf("POST /v1/refresh = %d %s", status, body)
	}
	var out mfaRefreshResp
	if err := json.Unmarshal(body, &out.RefreshResponse); err != nil {
		t.Fatal(err)
	}
	return out
}

// refreshStatus is refreshWith up to the answer's status and body.
func (f *mfaFixture) refreshStatus(t *testing.T, who *mfaActor, agent, ch string, nameInAnswer bool) (int, []byte) {
	t.Helper()
	nameAtChallenge := ch
	if nameInAnswer {
		nameAtChallenge = ""
	}
	code, nonceText := f.refreshChallengeStep(t, who, agent, nameAtChallenge)
	if code != http.StatusOK {
		t.Fatalf("POST /v1/refresh/challenge = %d", code)
	}
	nonce, _ := base64.RawURLEncoding.DecodeString(nonceText)
	sig, err := api.SignRefresh(who.cert.PrivateKey.(crypto.Signer), api.RefreshMessage(nonce, who.refreshExporter(t)))
	if err != nil {
		t.Fatal(err)
	}
	req := api.RefreshRequest{Nonce: nonceText, Signature: base64.RawURLEncoding.EncodeToString(sig)}
	if nameInAnswer {
		req.PerLoginMFAChallenge = ch
	}
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	hdr := map[string]string{}
	if agent != "" {
		hdr[api.AgentSessionHeader] = agent
	}
	return who.conn.post(t, "/v1/refresh", hdr, string(raw))
}

func (a *mfaActor) refreshExporter(t *testing.T) []byte {
	t.Helper()
	cs := a.conn.c.ConnectionState()
	ekm, err := cs.ExportKeyingMaterial(api.RefreshExporterLabel, nil, 32)
	if err != nil {
		t.Fatal(err)
	}
	return ekm
}

func (f *mfaFixture) refresh(t *testing.T, who *mfaActor) mfaRefreshResp {
	t.Helper()
	return f.refreshWith(t, who, who.agent, "", false)
}

// refreshAsked refreshes and returns the challenge the refresh asked for.
func (f *mfaFixture) refreshAsked(t *testing.T, who *mfaActor) string {
	t.Helper()
	out := f.refresh(t, who)
	if out.PerLoginMFA == nil {
		t.Fatalf("the refresh asked for no proof: %+v", out)
	}
	return out.PerLoginMFA.Challenge
}

func (f *mfaFixture) refreshAs(t *testing.T, who *mfaActor, agent string) mfaRefreshResp {
	t.Helper()
	return f.refreshWith(t, who, agent, "", false)
}

func (f *mfaFixture) refreshNaming(t *testing.T, who *mfaActor, ch string) mfaRefreshResp {
	t.Helper()
	return f.refreshWith(t, who, who.agent, ch, false)
}

// refreshChallengeNaming is the challenge request alone, naming ch, and its
// status.
func (f *mfaFixture) refreshChallengeNaming(t *testing.T, who *mfaActor, ch string) int {
	t.Helper()
	code, _ := f.refreshChallengeStep(t, who, who.agent, ch)
	return code
}

// assertRecordWith wants the last event verdict reason record to satisfy ok.
func (f *mfaFixture) assertRecordWith(t *testing.T, event, verdict, reason string, ok func(map[string]any) bool) {
	t.Helper()
	r := f.find(t, event, verdict, reason)
	if r == nil || !ok(r) {
		t.Fatalf("no %s %s %s record that qualifies in\n%s", event, verdict, reason, f.logs.String())
	}
}

func TestARequirementAddedRevokesNothing(t *testing.T) {
	f := newMFAFixture(t, withJunosCore())
	f.setRequirement(t, false)
	f.loginOnDevice(t, f.alice, "core-sw01") // a live context, minted with no proof
	f.setRequirement(t, true)                // the reload adds one
	if _, err := f.b.Refresh(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	ctx := f.context(t, "core-sw01", "alice")
	if !ctx.RevokedAt.IsZero() {
		t.Fatal("a reload that added per_login_mfa revoked a live context")
	}
}

// reload swaps in the fixture's policy under o and runs the refresh a reload
// runs, with the policy it replaced as the prior.
func (f *mfaFixture) reload(t *testing.T, o mfaOpts) {
	t.Helper()
	pol, err := policy.Parse([]byte(mfaPolicy(o)), policy.Env{Devices: f.inventory(), Now: f.b.Now()})
	if err != nil {
		t.Fatal(err)
	}
	prior := []Prior{{Policy: f.b.Policy.Swap(pol), At: f.b.Now()}}
	if _, err := f.b.Refresh(context.Background(), prior); err != nil {
		t.Fatal(err)
	}
}

func (f *mfaFixture) unspent(t *testing.T, device, username string) int {
	t.Helper()
	toks, err := f.st.Candidates(context.Background(), store.TokenKey{NAS: device, Username: username})
	if err != nil {
		t.Fatal(err)
	}
	return len(toks)
}

// A requirement added or tightened by a reload gates the logins not yet made:
// an unspent token minted under the weaker one is superseded, and a retry of
// its mint under the same Idempotency-Key is judged afresh and asked for a
// proof, not answered from the record (final review broker I1). One whose
// requirement is unchanged or loosened is kept.
func TestARequirementAddedOrTightenedSupersedesUnspentTokens(t *testing.T) {
	t.Run("added", func(t *testing.T) {
		f := newMFAFixture(t)
		f.setRequirement(t, false)
		if it := f.mintWithKey(t, f.alice, "core-sw01", "", "idem-1").Results[0]; it.Verdict != "permit" {
			t.Fatalf("mint with no requirement = %+v", it)
		}
		f.reload(t, f.opts)
		if n := f.unspent(t, "core-sw01", "alice"); n != 0 {
			t.Fatalf("%d unspent tokens minted with no proof survive the reload that adds per_login_mfa", n)
		}
		it := f.mintWithKey(t, f.alice, "core-sw01", "", "idem-1").Results[0]
		if it.Verdict != "deny" || it.Reason != "per_login_mfa_required" || it.PerLoginMFA == nil {
			t.Fatalf("the retried mint after the reload = %+v, want asked for a proof", it)
		}
	})
	t.Run("tightened", func(t *testing.T) {
		f := newMFAFixture(t)
		ch := f.ask(t, f.alice, "core-sw01")
		f.proveTouch(t, f.alice, ch)
		if it := f.mint(t, f.alice, "core-sw01", ch).Results[0]; it.Verdict != "permit" {
			t.Fatalf("mint under the requirement = %+v", it)
		}
		o := f.opts
		o.reuseZero = true // reuse_for 15m → 0m
		f.reload(t, o)
		if n := f.unspent(t, "core-sw01", "alice"); n != 0 {
			t.Fatalf("%d unspent tokens survive the reload that shortens reuse_for", n)
		}
	})
	t.Run("removed", func(t *testing.T) {
		f := newMFAFixture(t)
		ch := f.ask(t, f.alice, "core-sw01")
		f.proveTouch(t, f.alice, ch)
		if it := f.mint(t, f.alice, "core-sw01", ch).Results[0]; it.Verdict != "permit" {
			t.Fatalf("mint under the requirement = %+v", it)
		}
		o := f.opts
		o.noRequirement = true
		f.reload(t, o)
		if n := f.unspent(t, "core-sw01", "alice"); n != 1 {
			t.Fatalf("%d unspent tokens after the reload that removes per_login_mfa, want the 1 kept", n)
		}
	})
}

func TestRefreshUnderARequirementNeedsAProof(t *testing.T) {
	f := newMFAFixture(t, withJunosCore())
	f.setRequirement(t, false)
	f.loginOnDevice(t, f.alice, "core-sw01")
	before := f.context(t, "core-sw01", "alice").SessionExpires
	f.setRequirement(t, true)
	f.clock.Advance(time.Hour)
	out := f.refresh(t, f.alice)
	s := out.find("core-sw01")
	if s.Outcome != "per_login_mfa_required" || !s.Unreached || out.PerLoginMFA == nil {
		t.Fatalf("refresh = %+v", out)
	}
	if out.PerLoginMFA.Device != "" || out.PerLoginMFA.Challenge == "" {
		t.Fatalf("the refresh's challenge = %+v", out.PerLoginMFA)
	}
	if got := f.context(t, "core-sw01", "alice").SessionExpires; !got.Equal(before) {
		t.Fatalf("the ceiling moved to %v without a proof", got)
	}
	f.assertRecordWith(t, "refresh", "deny", "per_login_mfa_required", func(r map[string]any) bool {
		sess, _ := r["session"].(map[string]any)
		return sess != nil && sess["unreached"] == true && r["per_login_mfa"] != nil
	})
	// One touch, and the refresh right after it, on the same held connection
	// and within the 10s pacing (no clock advance), names the challenge and
	// extends it (pre-flight I5).
	ch := out.PerLoginMFA.Challenge
	f.proveTouch(t, f.alice, ch)
	if s := f.refreshNaming(t, f.alice, ch).find("core-sw01"); s.Outcome != "extended" {
		t.Fatalf("refresh after a proof = %+v", s)
	}
	// The exemption is spent with the proof: a third refresh at once is paced.
	if code := f.refreshChallengeNaming(t, f.alice, ch); code != http.StatusTooManyRequests {
		t.Fatalf("a second exemption from the same proof: %d, want 429", code)
	}
	// Another caller naming alice's proved challenge finds nothing and spends
	// nothing: alice's exemption survives bob's request (re-review R1).
	f.clock.Advance(16 * time.Minute) // past the pacing and reuse_for: asked again
	ch2 := f.refreshAsked(t, f.alice)
	f.proveTouch(t, f.alice, ch2)
	_ = f.refreshChallengeNaming(t, f.bob, ch2)
	if s := f.refreshNaming(t, f.alice, ch2).find("core-sw01"); s.Outcome != "extended" {
		t.Fatalf("alice's refresh after bob named her challenge = %+v", s)
	}
}

// The proof may also be named in the answer itself, with no exemption from
// the challenge's pacing: the caller waited out the pacing.
func TestRefreshNamesItsProofInTheAnswer(t *testing.T) {
	f := newMFAFixture(t, withJunosCore())
	f.setRequirement(t, false)
	f.loginOnDevice(t, f.alice, "core-sw01")
	f.setRequirement(t, true)
	f.clock.Advance(time.Hour)
	ch := f.refreshAsked(t, f.alice)
	f.proveTouch(t, f.alice, ch)
	f.clock.Advance(11 * time.Second)
	if s := f.refreshWith(t, f.alice, f.alice.agent, ch, true).find("core-sw01"); s.Outcome != "extended" {
		t.Fatalf("refresh naming its proof in the answer = %+v", s)
	}
}

func TestRefreshWithinReuseNeedsNoNewProof(t *testing.T) {
	f := newMFAFixture(t, withJunosCore()) // reuse_for 15m on core
	f.setRequirement(t, false)
	f.loginOnDevice(t, f.alice, "core-sw01")
	f.setRequirement(t, true)
	f.proveTouch(t, f.alice, f.mint(t, f.alice, "core-sw01", "").find("core-sw01").PerLoginMFA.Challenge)
	f.clock.Advance(5 * time.Minute)
	out := f.refresh(t, f.alice)
	if s := out.find("core-sw01"); s.Outcome != "extended" || out.PerLoginMFA != nil {
		t.Fatalf("refresh within reuse_for = %+v", out)
	}
	// Another agent session of alice's is not covered by it.
	f.clock.Advance(11 * time.Second)
	if s := f.refreshAs(t, f.alice, f.otherAgent).find("core-sw01"); s.Outcome != "per_login_mfa_required" {
		t.Fatalf("another agent's refresh = %+v", s)
	}
}
