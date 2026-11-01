package broker

import (
	"bufio"
	"context"
	"crypto"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/blanketfish/port49/internal/admission"
	"github.com/blanketfish/port49/internal/broker/api"
	"github.com/blanketfish/port49/internal/daemon/metrics"
	"github.com/blanketfish/port49/internal/directory"
	"github.com/blanketfish/port49/internal/store"
)

// challengeOn asks for a challenge on c and returns its nonce bytes and
// its text.
func challengeOn(t *testing.T, c *tls.Conn, br *bufio.Reader) ([]byte, string) {
	t.Helper()
	r := postOn(t, c, br, "/v1/refresh/challenge", "")
	var ch api.RefreshChallenge
	if err := json.Unmarshal([]byte(r.body), &ch); err != nil || r.status != 200 {
		t.Fatalf("challenge: %s", reply(r.status, r.body))
	}
	nonce, _ := base64.RawURLEncoding.DecodeString(ch.Nonce)
	return nonce, ch.Nonce
}

// answerOn signs nonce with cert's key over over's exporter value, and
// sends it on c.
func answerOn(t *testing.T, c *tls.Conn, br *bufio.Reader, over *tls.Conn, cert tls.Certificate, nonce []byte,
	nonceText string) (int, string) {
	t.Helper()
	cs := over.ConnectionState()
	ekm, err := cs.ExportKeyingMaterial(api.RefreshExporterLabel, nil, 32)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := api.SignRefresh(cert.PrivateKey.(crypto.Signer), api.RefreshMessage(nonce, ekm))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(api.RefreshRequest{Nonce: nonceText, Signature: base64.RawURLEncoding.EncodeToString(sig)})
	r := postOn(t, c, br, "/v1/refresh", string(body))
	return r.status, r.body
}

// refreshOn is a correct refresh on c.
func refreshOn(t *testing.T, c *tls.Conn, br *bufio.Reader, cert tls.Certificate) (int, api.RefreshResponse) {
	t.Helper()
	nonce, text := challengeOn(t, c, br)
	status, body := answerOn(t, c, br, c, cert, nonce, text)
	var resp api.RefreshResponse
	_ = json.Unmarshal([]byte(body), &resp)
	return status, resp
}

// A refresh extends a live context the policy in force grants, from the
// broker's verification time, to the ceiling that policy gives (here the
// default, 12h, where the context had 8h); the connection's session clock
// moves with it, so a mint past the handshake's ceiling goes through (spec
// §5.6; decision 33; pre-flight I5).
func TestARefreshExtendsToThePolicysCeiling(t *testing.T) {
	f := newFixture(t, 8)
	addr, _ := serveThrough(t, f, DefaultListenerLimits, nil)
	c, br := held(t, f, addr, f.alice)
	auth := f.now
	f.liveContextAt(t, "leaf1", "alice", alicePrincipal, certKey(f.alice), auth, auth.Add(8*time.Hour))
	f.advance(7*time.Hour + 50*time.Minute)
	status, resp := refreshOn(t, c, br, f.alice)
	if status != 200 || len(resp.Sessions) != 1 || resp.Sessions[0].Outcome != "extended" {
		t.Fatalf("%d %+v", status, resp)
	}
	got, _ := f.st.GetContext(context.Background(), store.ContextKey{NAS: "leaf1", Username: "alice"})
	if !got.AuthTime.Equal(f.b.Now()) || !got.SessionExpires.Equal(f.b.Now().Add(f.b.MaxSessionAge)) {
		t.Fatalf("auth_time %v, session_expires %v", got.AuthTime, got.SessionExpires)
	}
	recs := eventsOf(f.records(t), "refresh")
	if last := recs[len(recs)-1]; last["verdict"] != "permit" || last["reason"] != "grants_matched" ||
		last["session"].(map[string]any)["auth_time"] == nil {
		t.Fatalf("the refresh record: %v", last)
	}
	if n := testutil.ToFloat64(f.b.Metrics.SessionRefreshes.WithLabelValues("extended")); n != 1 {
		t.Fatalf("port49_session_refreshes_total{outcome=extended} = %v", n)
	}
	// The judgment before the extension is the session refresh's, not a
	// policy refresh's: an alert on the policy metric must not see it
	// (final review M-2).
	if n := testutil.CollectAndCount(f.b.Metrics.ContextRefreshes); n != 0 {
		t.Fatalf("a session refresh moved port49_context_refreshes_total: %d series", n)
	}
	f.advance(4*time.Hour + 20*time.Minute)
	if r := postOn(t, c, br, "/v1/tokens", `{"devices":["leaf1"]}`); r.status != 200 {
		t.Fatalf("a mint after the refresh, past the handshake's ceiling: %s", reply(r.status, r.body))
	}
}

// What the policy did not just judge and keep is not extended: a context
// past its grace window is deleted and named; one on a quarantined device
// ("bare", which has no platform) and one whose policy write lost every race
// are not judged; a withdrawn grant is revoked; one on a session-only
// platform (Junos) is extended and named unreached (pre-flight I4; re-check
// R2).
func TestARefreshExtendsOnlyWhatThePolicyKept(t *testing.T) {
	f := newFixtureWithDevices(t, 8, admission.Device{Name: "mx1", Platform: "juniper_junos",
		Addresses: []netip.Addr{netip.MustParseAddr("172.100.100.51")}})
	if _, err := f.b.Policy.Load().Resolve(alicePrincipal, f.devices["mx1"], f.now); err != nil {
		t.Fatalf("mx1 must resolve for alice, not be quarantined: %v", err)
	}
	addr, _ := serveThrough(t, f, DefaultListenerLimits, nil)
	c, br := held(t, f, addr, f.alice)
	auth := f.now
	f.b.GraceWindow = 10 * time.Minute
	f.liveContextAt(t, "leaf1", "alice", alicePrincipal, certKey(f.alice), auth, auth.Add(time.Hour))    // inside grace
	f.liveContextAt(t, "nx1", "alice", alicePrincipal, certKey(f.alice), auth, auth.Add(30*time.Minute)) // past grace
	f.liveContextAt(t, "bare", "alice", alicePrincipal, certKey(f.alice), auth, auth.Add(8*time.Hour))   // quarantined
	f.liveContextAt(t, "mx1", "alice", alicePrincipal, certKey(f.alice), auth, auth.Add(8*time.Hour))    // session-only
	f.advance(time.Hour + 5*time.Minute)
	status, resp := refreshOn(t, c, br, f.alice)
	by := map[string]api.RefreshedSession{}
	for _, s := range resp.Sessions {
		by[s.Device] = s
	}
	if status != 200 || by["leaf1"].Outcome != "extended" || by["nx1"].Outcome != "past_grace" ||
		by["bare"].Outcome != "not_judged" || by["mx1"].Outcome != "extended" || !by["mx1"].Unreached {
		t.Fatalf("%d %+v", status, resp)
	}
	if _, err := f.st.GetContext(context.Background(), store.ContextKey{NAS: "nx1", Username: "alice"}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a context past its grace window was kept: %v", err)
	}
	// A store whose policy writes always conflict: refreshContext gives up,
	// and the context is not judged, so not extended.
	f.advance(11 * time.Second)
	f.loadPolicy(t, strings.Replace(testPolicy, `permit: ["**"]`, `permit: ["show **"]`, 1)) // leaf1's answer changes
	f.b.Store = conflictingPolicyStore{f.st}
	logs := &lockedBuffer{}
	prev := log.Writer()
	log.SetOutput(logs)
	status, resp = refreshOn(t, c, br, f.alice)
	log.SetOutput(prev)
	// No retry follows a session refresh, so the line does not promise one
	// (final review M-2).
	if l := logs.String(); !strings.Contains(l, "still changing after") ||
		!strings.Contains(l, "not extended; run 'port49 refresh' again") || strings.Contains(l, "left for the retry") {
		t.Fatalf("the process log for a context that lost every race: %q", l)
	}
	seen := false
	for _, s := range resp.Sessions {
		if s.Device == "leaf1" {
			seen = true
			if s.Outcome != "not_judged" {
				t.Fatalf("a context whose policy write lost every race was %s", s.Outcome)
			}
		}
	}
	if status != 200 || !seen {
		t.Fatalf("a refresh over a conflicting store: %d %+v", status, resp)
	}
	// The grant withdrawn: revoked, never extended.
	f.b.Store = f.st
	f.advance(11 * time.Second)
	f.loadPolicy(t, strings.Replace(testPolicy, "grants:\n  - {subject: netops", "grants:\n  - {subject: idle", 1))
	status, resp = refreshOn(t, c, br, f.alice)
	if status != 200 || len(resp.Sessions) == 0 {
		t.Fatalf("a refresh after the grant was withdrawn: %d %+v", status, resp)
	}
	for _, s := range resp.Sessions {
		if s.Outcome == "extended" {
			t.Fatalf("after the grant was withdrawn, %s was extended", s.Device)
		}
		if s.Device == "leaf1" && s.Outcome != "revoked" {
			t.Fatalf("after the grant was withdrawn, leaf1 was %s", s.Outcome)
		}
	}
}

// conflictingPolicyStore refuses every SetContextPolicy with ErrConflict.
type conflictingPolicyStore struct{ store.Store }

func (conflictingPolicyStore) SetContextPolicy(context.Context, store.ContextKey, uint64, store.ContextPolicy) error {
	return store.ErrConflict
}

// The nonce is bound to its connection and to its key, single use, and
// good for 60s; each refusal is a refresh deny record with neither the
// nonce nor the signature in the log (pre-flight I10).
func TestARefreshIsBoundToItsConnectionAndItsKey(t *testing.T) {
	f := newFixture(t, 8)
	addr, _ := serveThrough(t, f, DefaultListenerLimits, nil)
	c, br := held(t, f, addr, f.alice)
	other, obr := held(t, f, addr, f.alice)

	// Signed over another connection's exporter value: refused; over its
	// own: accepted.
	nonce, text := challengeOn(t, other, obr)
	if s, _ := answerOn(t, other, obr, c, f.alice, nonce, text); s != 401 {
		t.Fatalf("other's nonce signed over c's exporter, sent on other: %d", s)
	}
	f.advance(11 * time.Second)
	nonce, text = challengeOn(t, other, obr)
	if s, body := answerOn(t, other, obr, other, f.alice, nonce, text); s != 200 {
		t.Fatalf("the same answer over other's own exporter: %s", reply(s, body))
	}

	// Replay: a correct answer sent twice; the second is refused.
	f.advance(11 * time.Second)
	nonce, text = challengeOn(t, c, br)
	if s, _ := answerOn(t, c, br, c, f.alice, nonce, text); s != 200 {
		t.Fatalf("the first answer: %d", s)
	}
	f.advance(11 * time.Second)
	if s, body := answerOn(t, c, br, c, f.alice, nonce, text); s != 401 || !strings.Contains(body, "refresh_challenge_missing") {
		t.Fatalf("a replayed answer: %s", reply(s, body))
	}

	// 59s: accepted; 61s: refused.
	nonce, text = challengeOn(t, c, br)
	f.advance(59 * time.Second)
	if s, _ := answerOn(t, c, br, c, f.alice, nonce, text); s != 200 {
		t.Fatalf("an answer at 59s: %d", s)
	}
	f.advance(11 * time.Second) // past the 59s refresh's 10s pacing (re-check R1)
	nonce, text = challengeOn(t, c, br)
	f.advance(61 * time.Second)
	if s, _ := answerOn(t, c, br, c, f.alice, nonce, text); s != 401 {
		t.Fatalf("an answer at 61s: %d", s)
	}

	// Another key, the same principal: refused. (The 61s answer's nonce had
	// expired, so it is not paced: the agent's retry gets its challenge.)
	nonce, text = challengeOn(t, c, br)
	renewed := f.client(t, "alice@example.com", f.now.Add(time.Hour))
	if s, _ := answerOn(t, c, br, c, renewed, nonce, text); s != 401 {
		t.Fatalf("a signature by another key: %d", s)
	}
	if strings.Contains(f.log.String(), text) {
		t.Fatal("a nonce reached the log")
	}
	refusals := 0
	for _, r := range eventsOf(f.records(t), "refresh") {
		raw, _ := json.Marshal(r)
		if strings.Contains(string(raw), "signature") {
			t.Fatalf("a refresh record carries a signature: %s", raw)
		}
		if r["verdict"] == "deny" && r["reason"] == "trust_domain_unresolved" {
			refusals++
		}
	}
	if refusals != 4 {
		t.Fatalf("%d refresh deny trust_domain_unresolved records, want 4", refusals)
	}
}

// A connection refreshes once per 10s, and a bad answer is paced as a good
// one is: a mismatched nonce counts (pre-flight M17). An expired one does
// not, so the agent's one retry after refresh_challenge_missing gets a new
// challenge at once (Task 7 re-review R1).
func TestARefreshIsRateLimited(t *testing.T) {
	f := newFixture(t, 8)
	addr, _ := serveThrough(t, f, DefaultListenerLimits, nil)
	c, br := held(t, f, addr, f.alice)
	if s, _ := refreshOn(t, c, br, f.alice); s != 200 {
		t.Fatal(s)
	}
	if r := postOn(t, c, br, "/v1/refresh/challenge", ""); r.status != 429 || !strings.Contains(r.body, "refresh_too_soon") {
		t.Fatalf("a second refresh inside 10s: %d (body withheld: a 200 carries a challenge)", r.status)
	}
	f.advance(11 * time.Second)
	nonce, text := challengeOn(t, c, br)
	renewed := f.client(t, "alice@example.com", f.now.Add(time.Hour))
	if s, _ := answerOn(t, c, br, c, renewed, nonce, text); s != 401 {
		t.Fatalf("a bad answer: %d", s)
	}
	if r := postOn(t, c, br, "/v1/refresh/challenge", ""); r.status != 429 || !strings.Contains(r.body, "refresh_too_soon") {
		t.Fatalf("a challenge inside 10s of a bad answer: %d (body withheld: a 200 carries a challenge)", r.status)
	}

	// A wrong nonce while a live one is outstanding consumes it and is paced.
	f.advance(11 * time.Second)
	_, _ = challengeOn(t, c, br)
	wrong := base64.RawURLEncoding.EncodeToString(make([]byte, api.RefreshNonceLen))
	if s, body := answerOn(t, c, br, c, f.alice, make([]byte, api.RefreshNonceLen), wrong); s != 401 ||
		!strings.Contains(body, "refresh_challenge_missing") {
		t.Fatalf("a mismatched nonce: %s", reply(s, body))
	}
	if r := postOn(t, c, br, "/v1/refresh/challenge", ""); r.status != 429 {
		t.Fatalf("a challenge at once after a mismatched nonce: %d (body withheld: a 200 carries a challenge)", r.status)
	}

	// A stale nonce is not paced: the agent's one retry after
	// refresh_challenge_missing gets a new challenge at once.
	f.advance(11 * time.Second)
	nonce, text = challengeOn(t, c, br)
	f.advance(61 * time.Second)
	if s, body := answerOn(t, c, br, c, f.alice, nonce, text); s != 401 || !strings.Contains(body, "refresh_challenge_missing") {
		t.Fatalf("a stale nonce: %s", reply(s, body))
	}
	if r := postOn(t, c, br, "/v1/refresh/challenge", ""); r.status != 200 {
		t.Fatalf("a challenge at once after a stale nonce: %s", reply(r.status, r.body))
	}
}

// A revoked principal, or a revoked certificate, cannot refresh:
// credential_revoked, recorded as a refresh, nothing extended (pre-flight
// M2).
func TestARevokedCallerCannotRefresh(t *testing.T) {
	for _, by := range []string{store.RevocationPrincipal, store.RevocationCert} {
		t.Run(by, func(t *testing.T) {
			f := newFixture(t, 8)
			addr, _ := serveThrough(t, f, DefaultListenerLimits, nil)
			c, br := held(t, f, addr, f.alice)
			auth := f.now
			f.liveContextAt(t, "leaf1", "alice", alicePrincipal, certKey(f.alice), auth, auth.Add(time.Hour))
			key := alicePrincipal
			if by == store.RevocationCert {
				key = certKey(f.alice)
			}
			f.revoke(t, by, key)
			nonce, text := challengeOn(t, c, br)
			if s, body := answerOn(t, c, br, c, f.alice, nonce, text); s != 401 || !strings.Contains(body, "credential_revoked") {
				t.Fatalf("%s", reply(s, body))
			}
			recs := eventsOf(f.records(t), "refresh")
			if last := recs[len(recs)-1]; last["reason"] != "credential_revoked" || last["verdict"] != "deny" {
				t.Fatalf("%v", last)
			}
			got, _ := f.st.GetContext(context.Background(), store.ContextKey{NAS: "leaf1", Username: "alice"})
			if !got.AuthTime.Equal(auth) {
				t.Fatalf("a revoked caller's context was extended: auth_time %v", got.AuthTime)
			}
		})
	}
}

// A refresh the store fails is answered 503 store_unavailable with one
// refresh deny store_unavailable record naming the principal, as a mint's
// store error is (spec §5.7): the marks unreadable before the extension
// (nothing extended), the live sessions unreadable, or the marks unreadable
// after the extension (the connection renewed, some sessions may be
// extended; Retry-After waits out the pacing).
func TestARefreshTheStoreFailsIsRecorded(t *testing.T) {
	for _, tc := range []struct {
		name  string
		st    func(store.Store) store.Store
		text  string
		retry string
	}{
		{"marks", func(s store.Store) store.Store { return &revocationFailingStore{Store: s} },
			"could not read the revocations in force, so it extended nothing", "10"},
		{"sessions", func(s store.Store) store.Store { return indexUnreadableStore{s} },
			"some may have been extended", "10"},
		{"marks_after", func(s store.Store) store.Store { return &revocationFailingStore{Store: s, ok: 2} },
			"some may have been extended", "10"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, 8)
			addr, _ := serveThrough(t, f, DefaultListenerLimits, nil)
			c, br := held(t, f, addr, f.alice)
			f.liveContextAt(t, "leaf1", "alice", alicePrincipal, certKey(f.alice), f.now, f.now.Add(time.Hour))
			f.b.Store = tc.st(f.st)
			nonce, text := challengeOn(t, c, br)
			status, body, retry := answerHeaders(t, c, br, f.alice, nonce, text)
			if status != 503 || !strings.Contains(body, "store_unavailable") || !strings.Contains(body, tc.text) ||
				retry != tc.retry {
				t.Fatalf("%s Retry-After %q", reply(status, body), retry)
			}
			denies := 0
			for _, r := range eventsOf(f.records(t), "refresh") {
				if r["verdict"] == "deny" {
					denies++
					if r["reason"] != "store_unavailable" || r["principal"] != alicePrincipal {
						t.Fatalf("the refresh record: %v", r)
					}
				}
			}
			if denies != 1 {
				t.Fatalf("%d refresh deny records, want 1", denies)
			}
			if n := testutil.ToFloat64(f.b.Metrics.SessionRefreshes.WithLabelValues("store_error")); n != 1 {
				t.Fatalf("port49_session_refreshes_total{outcome=store_error} = %v", n)
			}
		})
	}
}

// indexUnreadableStore cannot read the context index.
type indexUnreadableStore struct{ store.Store }

func (indexUnreadableStore) ContextsByPrincipal(context.Context, string) ([]store.ContextRef, error) {
	return nil, errors.New("store: connection refused")
}

// answerHeaders is answerOn over c's own exporter, returning Retry-After
// too.
func answerHeaders(t *testing.T, c *tls.Conn, br *bufio.Reader, cert tls.Certificate, nonce []byte,
	nonceText string) (int, string, string) {
	t.Helper()
	cs := c.ConnectionState()
	ekm, err := cs.ExportKeyingMaterial(api.RefreshExporterLabel, nil, 32)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := api.SignRefresh(cert.PrivateKey.(crypto.Signer), api.RefreshMessage(nonce, ekm))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(api.RefreshRequest{Nonce: nonceText, Signature: base64.RawURLEncoding.EncodeToString(sig)})
	r := postOn(t, c, br, "/v1/refresh", string(body))
	return r.status, r.body, r.retryAfter
}

// A revocation that lands while a refresh extends is answered
// credential_revoked, as a mint's is after its last write (revokedSince):
// the refresh is not reported extended (7a parity).
func TestARevocationDuringARefreshIsAnswered(t *testing.T) {
	f := newFixture(t, 8)
	addr, _ := serveThrough(t, f, DefaultListenerLimits, nil)
	c, br := held(t, f, addr, f.alice)
	f.liveContextAt(t, "leaf1", "alice", alicePrincipal, certKey(f.alice), f.now, f.now.Add(time.Hour))
	f.b.Store = markingStore{Store: f.st, f: f}
	nonce, text := challengeOn(t, c, br)
	if s, body := answerOn(t, c, br, c, f.alice, nonce, text); s != 401 || !strings.Contains(body, "credential_revoked") {
		t.Fatalf("%s", reply(s, body))
	}
	recs := eventsOf(f.records(t), "refresh")
	if last := recs[len(recs)-1]; last["reason"] != "credential_revoked" || last["verdict"] != "deny" {
		t.Fatalf("%v", last)
	}
}

// markingStore revokes alice's principal as the refresh reads her live
// sessions: after the first mark check, before the extension.
type markingStore struct {
	store.Store
	f *fixture
}

func (s markingStore) ContextsByPrincipal(ctx context.Context, principal string) ([]store.ContextRef, error) {
	if err := s.Store.PutRevocation(ctx, store.Revocation{Kind: store.RevocationPrincipal, Key: principal,
		At: s.f.b.Now(), Origin: "test"}); err != nil {
		return nil, err
	}
	return s.Store.ContextsByPrincipal(ctx, principal)
}

// A session refresh with a directory verifies the membership (fresh, or
// grace) and writes refreshed_at as the membership's verification, never
// later; a refresh the directory refuses extends nothing.
func TestASessionRefreshVerifiesTheMembership(t *testing.T) {
	a := answerFor(corpAlice, "alice")
	a.Source, a.VerifiedAt = directory.Grace, time.Now().Add(-10*time.Minute).Truncate(time.Second)
	answers := map[string]directory.Answer{alicePrincipal: a, corpAlice: a}
	f, _ := groupFixture(t, answers, nil)
	f.b.Directory = directory.ForTestsStaticResolver(f.st, answers, nil) // answers stays the test's to change
	addr, _ := serveMapped(t, f)
	c, br := held(t, f, addr, f.alice)
	before := f.memberContext(t, a, "leaf1", f.now.Add(-time.Hour))
	f.advance(time.Minute)
	status, resp := refreshOn(t, c, br, f.alice)
	if status != 200 || len(resp.Sessions) != 1 || resp.Sessions[0].Outcome != "extended" {
		t.Fatalf("%d %+v", status, resp)
	}
	got := f.context(t, "leaf1", "alice")
	if !got.RefreshedAt.Equal(a.VerifiedAt) || !got.AuthTime.Equal(f.b.Now()) || !got.RefreshedAt.After(before.RefreshedAt) {
		t.Fatalf("refreshed_at %v, want the membership's verification %v (auth_time %v)", got.RefreshedAt,
			a.VerifiedAt, got.AuthTime)
	}
	// A membership verified just now stamps the refresh's own time.
	a.Source, a.VerifiedAt = directory.Fresh, f.b.Now().Add(time.Hour) // not before at: at wins
	answers[alicePrincipal], answers[corpAlice] = a, a
	f.advance(refreshEvery)
	if status, _ := refreshOn(t, c, br, f.alice); status != 200 {
		t.Fatalf("%d", status)
	}
	if got := f.context(t, "leaf1", "alice"); !got.RefreshedAt.Equal(f.b.Now()) {
		t.Fatalf("refreshed_at %v, want at %v", got.RefreshedAt, f.b.Now())
	}
	// The directory refuses the principal: nothing is extended.
	delete(answers, corpAlice)
	prev := f.context(t, "leaf1", "alice")
	f.advance(refreshEvery)
	nonce, text := challengeOn(t, c, br)
	status, body := answerOn(t, c, br, c, f.alice, nonce, text)
	var e api.Error
	if err := json.Unmarshal([]byte(body), &e); err != nil || status != 401 || e.Error != "identity_unmapped" {
		t.Fatalf("status %d, error %q", status, e.Error)
	}
	if after := f.context(t, "leaf1", "alice"); !after.AuthTime.Equal(prev.AuthTime) ||
		!after.SessionExpires.Equal(prev.SessionExpires) || !after.RefreshedAt.Equal(prev.RefreshedAt) {
		t.Fatalf("a refused refresh extended the context: %+v", after)
	}
	if strings.Contains(f.log.String(), "secret-group") {
		t.Fatal("a group reached the log")
	}
}

// probeDownResolver is a real Resolver whose every server refuses to dial,
// so Current reaches grace through the store, as in an outage.
func probeDownResolver(f *fixture) *directory.Resolver {
	cfg := directory.Config{Servers: []directory.Server{{URI: "ldaps://dc-down", Priority: 100}},
		UserFilter: "(objectClass=person)", PrincipalAttribute: "userPrincipalName", UsernameAttribute: "sAMAccountName",
		QueryTimeout: 200 * time.Millisecond, Grace: time.Hour, FailureThreshold: 3, ProbeInterval: time.Minute,
		HealthInterval: 30 * time.Second, HealthTimeout: time.Second, Nested: "direct"}
	m := metrics.New(prometheus.NewRegistry())
	dial := func(context.Context, directory.Server) (directory.Client, error) {
		return nil, errors.New("connection refused")
	}
	check := func(context.Context, directory.Searcher) error { return nil }
	return &directory.Resolver{Cfg: cfg, Pool: directory.NewPool(cfg, dial, check, f.b.Now, m, func(string, ...any) {}),
		Store: f.st, Now: f.b.Now, M: m, Say: func(string, ...any) {}}
}

// With every directory server down, a session refresh within grace extends
// with refreshed_at the stored verification; past grace, or on a refused
// membership, it is 503 directory_unavailable and extends nothing, revokes
// nothing (pre-flight C-1).
func TestASessionRefreshInAnOutageUsesGraceOrRefuses(t *testing.T) {
	for _, tc := range []struct {
		name    string
		advance time.Duration
		refused bool
		want    int
	}{{"within grace", time.Minute, false, 200}, {"past grace", 2 * time.Hour, false, 503},
		{"refused in grace", time.Minute, true, 503}} {
		t.Run(tc.name, func(t *testing.T) {
			a := answerFor(corpAlice, "alice")
			f, _ := groupFixture(t, map[string]directory.Answer{alicePrincipal: a, corpAlice: a}, nil)
			addr, _ := serveMapped(t, f)
			c, br := held(t, f, addr, f.alice)
			f.memberContext(t, a, "leaf1", f.now.Add(-time.Hour))
			f.b.Directory = probeDownResolver(f)
			m := a.Membership
			m.VerifiedAt, m.Refused = f.now.Add(-10*time.Minute).Truncate(time.Second), tc.refused
			if err := f.st.PutMembership(context.Background(), m, 24*time.Hour); err != nil {
				t.Fatal(err)
			}
			f.advance(tc.advance)
			prev := f.context(t, "leaf1", "alice")
			nonce, text := challengeOn(t, c, br)
			status, body := answerOn(t, c, br, c, f.alice, nonce, text)
			after := f.context(t, "leaf1", "alice")
			if status != tc.want {
				t.Fatalf("status %d, want %d", status, tc.want)
			}
			if tc.want == 200 {
				if !after.RefreshedAt.Equal(m.VerifiedAt) {
					t.Fatalf("refreshed_at %v, want %v", after.RefreshedAt, m.VerifiedAt)
				}
				return
			}
			var e api.Error
			if err := json.Unmarshal([]byte(body), &e); err != nil || e.Error != "directory_unavailable" {
				t.Fatalf("error %q", e.Error)
			}
			if !after.AuthTime.Equal(prev.AuthTime) || !after.SessionExpires.Equal(prev.SessionExpires) ||
				!after.RefreshedAt.Equal(prev.RefreshedAt) || !after.RevokedAt.IsZero() {
				t.Fatal("the context moved")
			}
		})
	}
}
