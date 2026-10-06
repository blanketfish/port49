package broker

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/directory"
	"github.com/rhwendt/port49/internal/oidc/oidctest"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/token"
)

const mintLeaf1 = `{"devices":["leaf1"],"ttl_seconds":60}`

func TestAnOIDCPersonMints(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withOIDC(t)
	w := f.bearer(context.Background(), "POST", "/v1/tokens", mintLeaf1, f.idToken(t, iss, nil))
	resp := decodeMint(t, w)
	if w.Code != 200 || resp.Principal != alicePrincipal || resp.Results[0].Verdict != decision.VerdictPermit {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	toks, err := f.st.Candidates(context.Background(), store.TokenKey{NAS: "leaf1", Username: "alice"})
	if err != nil || len(toks) != 1 {
		t.Fatalf("tokens %d %v", len(toks), err)
	}
	cred := toks[0].Credential
	if cred.Method != "oidc" || cred.Sub != "sub-alice" || cred.Sid != store.SidKey(iss.URL, "s-sub-alice") ||
		strings.Join(cred.AMR, ",") != "pwd,otp" || cred.ACR != "1" || cred.Fingerprint != "" {
		t.Fatalf("credential %+v", cred)
	}
	mints := eventsOf(f.records(t), decision.EventMint)
	auth := mints[len(mints)-1]["auth"].(map[string]any)
	o, _ := auth["oidc"].(map[string]any)
	if auth["method"] != "oidc" || o["issuer"] != iss.URL || o["sub"] != "sub-alice" || o["sid"] != "s-sub-alice" {
		t.Fatalf("the mint record's auth: %v", auth)
	}
	for _, key := range []string{store.SidKey(iss.URL, "s-sub-alice"), store.OIDCKey(store.OIDCSub, iss.URL, "sub-alice")} {
		if own, err := f.st.OIDCOwner(context.Background(), key); err != nil || strings.Join(own.Names(), ",") != alicePrincipal {
			t.Fatalf("owner of %q: %+v %v", key, own, err)
		}
	}
}

// The session clock is the token's auth_time, not the request's (Ruling 9).
func TestTheOIDCSessionClockIsAuthTime(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withOIDC(t)
	authAt := f.b.Now().Add(-2 * time.Hour)
	w := f.bearer(context.Background(), "POST", "/v1/tokens", mintLeaf1, f.idToken(t, iss, map[string]any{"auth_time": authAt.Unix()}))
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	toks, _ := f.st.Candidates(context.Background(), store.TokenKey{NAS: "leaf1", Username: "alice"})
	if len(toks) != 1 || !toks[0].AuthTime.Equal(authAt.Truncate(time.Second)) {
		t.Fatalf("token auth_time %v, want %v", toks[0].AuthTime, authAt)
	}
	old := f.idToken(t, iss, map[string]any{"auth_time": f.b.Now().Add(-13 * time.Hour).Unix()})
	if w := f.bearer(context.Background(), "POST", "/v1/tokens", mintLeaf1, old); w.Code != 401 ||
		!strings.Contains(w.Body.String(), string(decision.SessionExpired)) || !strings.Contains(w.Body.String(), "port49 login") {
		t.Fatalf("an authentication 13h ago: %d %s", w.Code, w.Body)
	}
	// An auth_time ahead of the broker's clock, within clock_skew, is now: a
	// session clock never starts in the future (pre-flight M-18).
	ahead := f.idToken(t, iss, map[string]any{"auth_time": f.b.Now().Add(30 * time.Second).Unix(),
		"iat": f.b.Now().Add(30 * time.Second).Unix()})
	if w := f.bearer(context.Background(), "POST", "/v1/tokens", `{"devices":["nx1"],"ttl_seconds":60}`, ahead); w.Code != 200 {
		t.Fatalf("an auth_time 30s ahead: %d %s", w.Code, w.Body)
	}
	toks, _ = f.st.Candidates(context.Background(), store.TokenKey{NAS: "nx1", Username: "alice"})
	if len(toks) != 1 || toks[0].AuthTime.After(f.b.Now()) {
		t.Fatalf("a token's auth_time %v is after the broker's now %v", toks[0].AuthTime, f.b.Now())
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
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	// A machine has no session a provider logs out: it writes no owner
	// record (pre-flight M-16).
	if _, err := f.st.OIDCOwner(context.Background(), store.OIDCKey(store.OIDCSub, iss.URL, "svc")); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a machine's mint wrote an owner record: %v", err)
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
		t.Fatalf("a certificate and a bearer: %d %s", w.Code, w.Body)
	}
	for _, h := range []string{"Basic YWxpY2U6eA==", "Bearer", "Bearer a b", "bearer"} {
		q := httptestRequest("POST", "/v1/tokens", mintLeaf1)
		q.Header.Set("Authorization", h)
		w := httptestServe(f, q)
		if w.Code != 401 || !strings.Contains(w.Body.String(), string(decision.TrustDomainUnresolved)) {
			t.Errorf("Authorization %q: %d %s", h, w.Code, w.Body)
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
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	recs := eventsOf(f.records(t), decision.EventMint)
	last := recs[len(recs)-1]
	if last["principal"] != nil || last["auth"].(map[string]any)["method"] != "oidc" || last["auth"].(map[string]any)["oidc"] != nil {
		t.Fatalf("the refusal's record: %v", last)
	}
	for _, s := range []string{f.log.String(), said.String(), w.Body.String()} {
		if strings.Contains(s, "sub-marker") || strings.Contains(s, forged) {
			t.Fatalf("an unverified token's claim or the token itself was written: %s", s)
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
		t.Fatalf("%d %v %s", w.Code, w.Header(), w.Body)
	}
}

func TestAnUnusablePrincipalClaimIsUnmapped(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withOIDC(t)
	w := f.bearer(context.Background(), "POST", "/v1/tokens", mintLeaf1, f.idToken(t, iss,
		map[string]any{"preferred_username": "alice"}))
	if w.Code != 401 || !strings.Contains(w.Body.String(), string(decision.IdentityUnmapped)) {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

// A standing mark refuses an OIDC caller as it refuses a certificate
// (Ruling 8): port49 revoke ends a person on both paths.
func TestAMarkRefusesTheOIDCPath(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withOIDC(t)
	if err := f.st.PutRevocation(context.Background(), store.Revocation{Kind: store.RevocationPrincipal,
		Key: alicePrincipal, At: f.b.Now(), Origin: "admin_socket uid 0"}); err != nil {
		t.Fatal(err)
	}
	w := f.bearer(context.Background(), "POST", "/v1/tokens", mintLeaf1, f.idToken(t, iss, nil))
	if w.Code != 401 || !strings.Contains(w.Body.String(), string(decision.CredentialRevoked)) {
		t.Fatalf("%d %s", w.Code, w.Body)
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
			t.Errorf("%s %s: %d %s", c.method, c.path, w.Code, w.Body)
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
		t.Fatalf("a token issued at the sub's logout: %d %s", w.Code, w.Body)
	}
	f2.advance(2 * time.Minute)
	if w := f2.bearer(ctx, "POST", "/v1/tokens", mintLeaf1, f2.idToken(t, iss2, nil)); w.Code != 200 {
		t.Fatalf("a token issued 2m after the sub's logout: %d %s", w.Code, w.Body)
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
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if toks, _ := f.st.Candidates(ctx, store.TokenKey{NAS: "leaf1", Username: "alice"}); len(toks) != 0 {
		t.Fatalf("%d tokens survived a logout that landed mid-mint", len(toks))
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
		t.Fatalf("%d %s", w.Code, w.Body)
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
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if id.Principal != alicePrincipal || id.Method != "oidc" || id.OIDC == nil || id.OIDC.Issuer != iss.URL ||
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
		t.Fatalf("%d %s, calls %d", w.Code, w.Body, res.Calls.Load())
	}
}

// Without an OIDC verifier, a bearer is no one's.
func TestABearerWithNoOIDCIsRefused(t *testing.T) {
	f := newFixture(t, 8)
	iss := oidctest.NewIssuer(t)
	raw := iss.IDToken(t, "k1", testClientID, "x", f.b.Now(), map[string]any{"preferred_username": "alice@example.com"})
	if w := f.bearer(context.Background(), "POST", "/v1/tokens", mintLeaf1, raw); w.Code != 401 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}
