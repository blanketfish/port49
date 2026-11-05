package broker

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/broker/api"
	"github.com/blanketfish/port49/internal/decision"
	"github.com/blanketfish/port49/internal/directory"
	"github.com/blanketfish/port49/internal/oidc/oidctest"
	"github.com/blanketfish/port49/internal/store"
	"github.com/blanketfish/port49/internal/token"
)

// shown is a mint response as a failure message may print it: the code is the
// caller's, and the decoded items withhold their tokens (MintItem.String).
func shown(w *httptest.ResponseRecorder) string {
	var e api.Error
	if json.Unmarshal(w.Body.Bytes(), &e) == nil && e.Error != "" {
		return fmt.Sprintf("code %d, error %q, detail %q", w.Code, e.Error, e.Detail)
	}
	var r api.MintResponse
	if json.Unmarshal(w.Body.Bytes(), &r) != nil {
		return fmt.Sprintf("code %d, not a mint response", w.Code)
	}
	return fmt.Sprintf("code %d, %v", w.Code, r.Results)
}

const mintLeaf1 = `{"devices":["leaf1"],"ttl_seconds":60}`

func TestAnOIDCPersonMints(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withOIDC(t)
	w := f.bearer(context.Background(), "POST", "/v1/tokens", mintLeaf1, f.idToken(t, iss, nil))
	resp := decodeMint(t, w)
	if w.Code != 200 || resp.Principal != alicePrincipal || resp.Results[0].Verdict != decision.VerdictPermit {
		t.Fatalf("%s", shown(w))
	}
	toks, err := f.st.Candidates(context.Background(), store.TokenKey{NAS: "leaf1", Username: "alice"})
	if err != nil || len(toks) != 1 {
		t.Fatalf("tokens %d %v", len(toks), err)
	}
	cred := toks[0].Credential
	if cred.Method != "cert" || cred.Sub != "sub-alice" || cred.Sid != store.SidKey(iss.URL, "s-sub-alice") ||
		strings.Join(cred.AMR, ",") != "pwd,otp" || cred.ACR != "1" {
		t.Fatalf("credential %+v", cred)
	}
	mints := eventsOf(f.records(t), decision.EventMint)
	auth := mints[len(mints)-1]["auth"].(map[string]any)
	o, _ := auth["oidc"].(map[string]any)
	if auth["method"] != "cert" || o["issuer"] != iss.URL || o["sub"] != "sub-alice" || o["sid"] != "s-sub-alice" {
		t.Fatalf("the mint record's auth: %v", auth)
	}
	for _, key := range []string{store.SidKey(iss.URL, "s-sub-alice"), store.OIDCKey(store.OIDCSub, iss.URL, "sub-alice")} {
		if own, err := f.st.OIDCOwner(context.Background(), key); err != nil || strings.Join(own.Names(), ",") != alicePrincipal {
			t.Fatalf("owner of %q: %+v %v", key, own, err)
		}
	}
}

const machinePolicy = `
scopes:
  - {name: all_devices, match: {}}
roles:
  - {name: network_admin, privilege: admin, permit: ["**"]}
subjects:
  - {name: netops, identity: ["user:alice@example.com"], username: alice, enable: token, token_ttl: 60s}
  - {name: backup, identity: ["app:Oxidized-01"], username: svc-backup, token_ttl: 60s}
grants:
  - {subject: netops, scope: all_devices, roles: [network_admin], max_privilege: admin}
  - {subject: backup, scope: all_devices, roles: [network_admin], max_privilege: admin}
`

func TestAMachineMintsAsApp(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, machinePolicy)
	iss := f.withOIDC(t)
	now := f.b.Now()
	raw := iss.Token(t, "k1", map[string]any{"iss": iss.URL, "aud": "api://port49-svc", "sub": "svc",
		"azp": "Oxidized-01", "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()})
	w := f.bearer(context.Background(), "POST", "/v1/tokens", mintLeaf1, raw)
	resp := decodeMint(t, w)
	if w.Code != 200 || resp.Principal != "app:Oxidized-01" || resp.Results[0].Username != "svc-backup" {
		t.Fatalf("%s", shown(w))
	}
	// A machine has no session a provider logs out: it writes no owner
	// record (pre-flight M-16).
	if _, err := f.st.OIDCOwner(context.Background(), store.OIDCKey(store.OIDCSub, iss.URL, "svc")); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a machine's mint wrote an owner record: %v", err)
	}
	// Nor does a logout under its sub refuse it: a machine has no session a
	// provider logs out (pre-flight M-16).
	if err := f.st.PutLogout(context.Background(), store.Logout{Key: store.OIDCKey(store.OIDCSub, iss.URL, "svc"),
		At: f.b.Now(), Origin: "backchannel_logout " + iss.URL}, time.Hour); err != nil {
		t.Fatal(err)
	}
	if w := f.bearer(context.Background(), "POST", "/v1/tokens", `{"devices":["nx1"],"ttl_seconds":60}`, raw); w.Code != 200 {
		t.Fatalf("a logout under a machine's sub refused its mint: %s", shown(w))
	}
}

func TestOneCredentialPerRequest(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withOIDC(t)
	both := httptestRequest("POST", "/v1/tokens", mintLeaf1)
	both.TLS = f.state(f.alice)
	both.Header.Set("Authorization", "Bearer "+f.idToken(t, iss, nil))
	w := httptestServe(f, both)
	if w.Code != 400 || !strings.Contains(w.Body.String(), "one credential per request") {
		t.Fatalf("a certificate and a bearer: %s", shown(w))
	}
	for _, h := range []string{"Basic YWxpY2U6eA==", "Bearer", "Bearer a b", "bearer"} {
		q := httptestRequest("POST", "/v1/tokens", mintLeaf1)
		q.Header.Set("Authorization", h)
		w := httptestServe(f, q)
		if w.Code != 401 || !strings.Contains(w.Body.String(), string(decision.TrustDomainUnresolved)) {
			t.Errorf("Authorization %q: %s", h, shown(w))
		}
	}
}

// Review Focus 1, 4: a token the broker cannot verify is refused, recorded
// with no principal, and nothing of it is said.
func TestARefusedBearerIsRecordedWithNoPrincipalAndNotQuoted(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withOIDC(t)
	var said strings.Builder
	f.b.Say = func(format string, args ...any) { said.WriteString(fmt.Sprintf(format, args...) + "\n") }
	forger := oidctest.NewIssuer(t)
	forged := forger.TokenWith(t, "k1", map[string]any{"kid": "k1"}, map[string]any{"iss": iss.URL, "aud": testClientID,
		"sub": "sub-marker", "preferred_username": "alice@example.com", "iat": f.b.Now().Unix(),
		"exp": f.b.Now().Add(time.Minute).Unix(), "auth_time": f.b.Now().Unix()})
	w := f.bearer(context.Background(), "POST", "/v1/tokens", mintLeaf1, forged)
	if w.Code != 401 || !strings.Contains(w.Body.String(), string(decision.TrustDomainUnresolved)) {
		t.Fatalf("%s", shown(w))
	}
	recs := eventsOf(f.records(t), decision.EventMint)
	last := recs[len(recs)-1]
	if last["principal"] != nil || last["auth"].(map[string]any)["method"] != "oidc" || last["auth"].(map[string]any)["oidc"] != nil {
		t.Fatalf("the refusal's record: %v", last)
	}
	for name, s := range map[string]string{"the log": f.log.String(), "said": said.String(), "the body": w.Body.String()} {
		if strings.Contains(s, "sub-marker") || strings.Contains(s, forged) {
			t.Fatalf("an unverified token's claim or the token itself was written to %s", name)
		}
	}
}

func TestAProviderOutageIsRetriable(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withOIDC(t)
	raw := f.idToken(t, iss, nil)
	iss.Close()
	w := f.bearer(context.Background(), "POST", "/v1/tokens", mintLeaf1, raw)
	if w.Code != 503 || w.Header().Get("Retry-After") != "30" ||
		!strings.Contains(w.Body.String(), "identity_provider_unavailable") {
		t.Fatalf("%s, Retry-After %q", shown(w), w.Header().Get("Retry-After"))
	}
}

func TestAnUnusablePrincipalClaimIsUnmapped(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withOIDC(t)
	w := f.bearer(context.Background(), "POST", "/v1/tokens", mintLeaf1, f.idToken(t, iss,
		map[string]any{"preferred_username": "alice"}))
	if w.Code != 401 || !strings.Contains(w.Body.String(), string(decision.IdentityUnmapped)) {
		t.Fatalf("%s", shown(w))
	}
}

// A standing mark refuses an OIDC caller as it refuses a certificate
// (Ruling 8): port49 revoke ends a person on both paths.
func TestAMarkRefusesTheOIDCPath(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withOIDC(t)
	if err := f.st.PutRevocation(context.Background(), store.Revocation{Kind: store.RevocationPrincipal,
		Key: alicePrincipal, At: f.b.Now(), Origin: "offline uid 0"}); err != nil {
		t.Fatal(err)
	}
	w := f.bearer(context.Background(), "POST", "/v1/tokens", mintLeaf1, f.idToken(t, iss, nil))
	if w.Code != 401 || !strings.Contains(w.Body.String(), string(decision.CredentialRevoked)) {
		t.Fatalf("%s", shown(w))
	}
}

// A logged-out sid is refused at every endpoint; a sub logout refuses only
// tokens issued before it (Ruling 13).
func TestALoggedOutSessionIsRefusedEverywhere(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withOIDC(t)
	ctx := context.Background()
	raw := f.idToken(t, iss, nil)
	if err := f.st.PutLogout(ctx, store.Logout{Key: store.SidKey(iss.URL, "s-sub-alice"), At: f.b.Now(),
		Origin: "backchannel_logout " + iss.URL}, time.Hour); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ method, path, body string }{
		{"POST", "/v1/tokens", mintLeaf1}, {"GET", "/v1/identity", ""},
		{"POST", "/v1/explain", `{"device":"leaf1"}`}, {"POST", "/v1/tokens/revoke", `{"mine":true}`},
	} {
		w := f.bearer(ctx, c.method, c.path, c.body, raw)
		if w.Code != 401 || !strings.Contains(w.Body.String(), string(decision.CredentialRevoked)) ||
			!strings.Contains(w.Body.String(), "identity provider ended this session") {
			t.Errorf("%s %s: %s", c.method, c.path, shown(w))
		}
	}
	// By sub: a token issued at the logout is refused; one issued after it,
	// beyond clock_skew, is a new login and accepted.
	f2 := newFixture(t, 8)
	iss2 := f2.withOIDC(t)
	at := f2.b.Now()
	if err := f2.st.PutLogout(ctx, store.Logout{Key: store.OIDCKey(store.OIDCSub, iss2.URL, "sub-alice"), At: at},
		time.Hour); err != nil {
		t.Fatal(err)
	}
	if w := f2.bearer(ctx, "POST", "/v1/tokens", mintLeaf1, f2.idToken(t, iss2, nil)); w.Code != 401 {
		t.Fatalf("a token issued at the sub's logout: %s", shown(w))
	}
	// Inside clock_skew after the logout is still the old session's.
	f2.advance(30 * time.Second)
	if w := f2.bearer(ctx, "POST", "/v1/tokens", mintLeaf1, f2.idToken(t, iss2, nil)); w.Code != 401 {
		t.Fatalf("a token issued 30s after the sub's logout: %s", shown(w))
	}
	f2.advance(90 * time.Second)
	if w := f2.bearer(ctx, "POST", "/v1/tokens", mintLeaf1, f2.idToken(t, iss2, nil)); w.Code != 200 {
		t.Fatalf("a token issued 2m after the sub's logout: %s", shown(w))
	}
}

// hookStore runs before when a method named in it is called on the
// minter's store.
type hookStore struct {
	store.Store
	before map[string]func() error
}

func (h hookStore) PutToken(ctx context.Context, k store.TokenKey, t store.Token) (int, error) {
	if f := h.before["PutToken"]; f != nil {
		if err := f(); err != nil {
			return 0, err
		}
	}
	return h.Store.PutToken(ctx, k, t)
}

func (h hookStore) PutOIDCOwner(ctx context.Context, key, principal string, ttl time.Duration) error {
	if f := h.before["PutOIDCOwner"]; f != nil {
		if err := f(); err != nil {
			return err
		}
	}
	return h.Store.PutOIDCOwner(ctx, key, principal, ttl)
}

func (h hookStore) PutLogout(ctx context.Context, l store.Logout, ttl time.Duration) error {
	if f := h.before["PutLogout"]; f != nil {
		if err := f(); err != nil {
			return err
		}
	}
	return h.Store.PutLogout(ctx, l, ttl)
}

func (h hookStore) TakeOnce(ctx context.Context, key string) ([]byte, error) {
	if f := h.before["TakeOnce"]; f != nil {
		if err := f(); err != nil {
			return nil, err
		}
	}
	return h.Store.TakeOnce(ctx, key)
}

func (h hookStore) PutOnce(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	if f := h.before["PutOnce"]; f != nil {
		if err := f(); err != nil {
			return false, err
		}
	}
	return h.Store.PutOnce(ctx, key, value, ttl)
}

// Review Focus 7: a logout that lands while the mint writes is read after
// the last token write, and the mint's tokens are deleted.
func TestAMintRacingALogoutLeavesNoToken(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withOIDC(t)
	ctx := context.Background()
	hooked := hookStore{Store: f.st, before: map[string]func() error{"PutToken": func() error {
		return f.st.PutLogout(ctx, store.Logout{Key: store.SidKey(iss.URL, "s-sub-alice"), At: f.b.Now()}, time.Hour)
	}}}
	f.b.Minter = token.NewMinter(hooked, f.b.Log, rand.Reader, token.TagKey([]byte("k")), f.b.Now, 8)
	w := f.bearer(ctx, "POST", "/v1/tokens", mintLeaf1, f.idToken(t, iss, nil))
	if w.Code != 401 || !strings.Contains(w.Body.String(), string(decision.CredentialRevoked)) {
		t.Fatalf("%s", shown(w))
	}
	if toks, _ := f.st.Candidates(ctx, store.TokenKey{NAS: "leaf1", Username: "alice"}); len(toks) != 0 {
		t.Fatalf("%d tokens survived a logout that landed mid-mint", len(toks))
	}
	// The per-device records say which session was ended.
	var seen int
	for _, rec := range eventsOf(f.records(t), decision.EventMint) {
		if rec["reason"] != string(decision.CredentialRevoked) {
			continue
		}
		seen++
		if o, _ := rec["auth"].(map[string]any)["oidc"].(map[string]any); o["sid"] != "s-sub-alice" {
			t.Fatalf("a credential_revoked record without auth.oidc: %v", rec["auth"])
		}
	}
	if seen == 0 {
		t.Fatal("no credential_revoked record")
	}
}

// No token exists that a logout cannot find (Ruling 11): the owner write
// failing refuses the mint before a token is written.
func TestAnOwnerWriteFailureRefusesTheMint(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withOIDC(t)
	f.b.Store = hookStore{Store: f.st, before: map[string]func() error{
		"PutOIDCOwner": func() error { return store.ErrUnavailable }}}
	w := f.bearer(context.Background(), "POST", "/v1/tokens", mintLeaf1, f.idToken(t, iss, nil))
	if w.Code != 503 || !strings.Contains(w.Body.String(), string(decision.StoreUnavailable)) {
		t.Fatalf("%s", shown(w))
	}
	if toks, _ := f.st.Candidates(context.Background(), store.TokenKey{NAS: "leaf1", Username: "alice"}); len(toks) != 0 {
		t.Fatal("a token was written without its owner record")
	}
}

func TestIdentityAnswersAnOIDCCaller(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withOIDC(t)
	w := f.bearer(context.Background(), "GET", "/v1/identity", "", f.idToken(t, iss, nil))
	var id api.Identity
	if err := json.Unmarshal(w.Body.Bytes(), &id); err != nil || w.Code != 200 {
		t.Fatalf("%s", shown(w))
	}
	if id.Principal != alicePrincipal || id.Method != "cert" || id.OIDC == nil || id.OIDC.Issuer != iss.URL ||
		id.OIDC.Sid != "s-sub-alice" || id.AuthTime != f.b.Now().UTC().Format(time.RFC3339) {
		t.Fatalf("identity %+v", id)
	}
}

// With a directory, an OIDC principal's username and groups are the
// directory's, read as a certificate's are (Ruling 7; 7g's carry).
func TestAnOIDCPrincipalResolvesThroughTheDirectory(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withOIDC(t)
	res := withDirectory(f, map[string]directory.Answer{alicePrincipal: answerFor(alicePrincipal, "alice2")}, nil)
	w := f.bearer(context.Background(), "POST", "/v1/tokens", mintLeaf1, f.idToken(t, iss, nil))
	resp := decodeMint(t, w)
	if w.Code != 200 || resp.Results[0].Username != "alice2" || res.Calls.Load() != 1 {
		t.Fatalf("%s, calls %d", shown(w), res.Calls.Load())
	}
}

// Without an OIDC verifier, a bearer is no one's.
func TestABearerWithNoOIDCIsRefused(t *testing.T) {
	f := newFixture(t, 8)
	iss := oidctest.NewIssuer(t)
	raw := iss.IDToken(t, "k1", testClientID, "x", f.b.Now(), map[string]any{"preferred_username": "alice@example.com"})
	if w := f.bearer(context.Background(), "POST", "/v1/tokens", mintLeaf1, raw); w.Code != 401 {
		t.Fatalf("%s", shown(w))
	}
}

// An owner entry is written again once it is ownerFresh old, so someone who
// keeps minting never outlives their own record (Ruling 11).
func TestTheOwnerEntryIsRenewedAsItAges(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withOIDC(t)
	ctx := context.Background()
	key := store.SidKey(iss.URL, "s-sub-alice")
	if w := f.bearer(ctx, "POST", "/v1/tokens", mintLeaf1, f.idToken(t, iss, nil)); w.Code != 200 {
		t.Fatalf("the first mint: %s", shown(w))
	}
	f.advance(2 * time.Hour)
	if w := f.bearer(ctx, "POST", "/v1/tokens", `{"devices":["nx1"],"ttl_seconds":60}`, f.idToken(t, iss, nil)); w.Code != 200 {
		t.Fatalf("the second mint: %s", shown(w))
	}
	own, err := f.st.OIDCOwner(ctx, key)
	e, ok := own.Entry(alicePrincipal)
	if err != nil || !ok || !e.WrittenAt.Equal(f.b.Now()) {
		t.Fatalf("the owner entry %+v (found %v, err %v) was not written at %v", e, ok, err, f.b.Now())
	}
}
