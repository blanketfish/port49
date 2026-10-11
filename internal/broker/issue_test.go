package broker

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/issuer"
	"github.com/rhwendt/port49/internal/oidc"
	"github.com/rhwendt/port49/internal/oidc/oidctest"
	"github.com/rhwendt/port49/internal/store"
)

func newECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// csrBody is POST /v1/certificate's body for key.
func csrBody(t *testing.T, key crypto.Signer) string {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(api.IssueRequest{CSR: base64.RawURLEncoding.EncodeToString(der)})
	return string(b)
}

// signInFor is alice's ID token from iss whose nonce names key, with extra
// claims over withOIDC's.
func (f *fixture) signInFor(t *testing.T, iss *oidctest.Issuer, key crypto.Signer, extra map[string]any) string {
	t.Helper()
	nonce, err := api.IssuanceNonce(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	c := map[string]any{"nonce": nonce}
	for k, v := range extra {
		c[k] = v
	}
	return f.idToken(t, iss, c)
}

// apiError is w's API error, "" when it is none.
func apiError(w *httptest.ResponseRecorder) string {
	var e api.Error
	_ = json.Unmarshal(w.Body.Bytes(), &e)
	return e.Error
}

// A fresh sign-in whose nonce names the CSR's key is issued a certificate for
// that key, carrying the sign-in, valid certificate_lifetime; the issue
// record names its serial; and the certificate mints (decision 43 rulings
// 8–10, 22).
func TestASignInIsIssuedACertificate(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withIssuance(t)
	key := newECKey(t)
	w := f.bearer(context.Background(), "POST", "/v1/certificate", csrBody(t, key), f.signInFor(t, iss, key, nil))
	var resp api.IssueResponse
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &resp) != nil || resp.Principal != alicePrincipal {
		t.Fatalf("%s", shown(w))
	}
	blk, rest := pem.Decode([]byte(resp.Certificate))
	if ca, _ := pem.Decode(rest); blk == nil || ca == nil {
		t.Fatalf("the chain: %q", resp.Certificate)
	}
	leaf, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	s, err := issuer.ReadSignIn(leaf)
	if err != nil || s.Sid != "s-sub-alice" || s.Subject != "sub-alice" || !key.PublicKey.Equal(leaf.PublicKey) ||
		!leaf.NotAfter.Equal(f.b.Now().Add(issuer.DefaultLifetime)) || resp.Serial != leaf.SerialNumber.Text(16) {
		t.Fatalf("%+v %v, not after %s", s, err, leaf.NotAfter)
	}
	recs := eventsOf(f.records(t), decision.EventIssue)
	if len(recs) != 1 || recs[0]["verdict"] != "permit" || recs[0]["reason"] != "certificate_issued" {
		t.Fatalf("%v", recs)
	}
	if cert, _ := recs[0]["certificate"].(map[string]any); cert["serial"] != resp.Serial ||
		cert["fingerprint"] != issuer.Fingerprint(leaf) {
		t.Fatalf("the record's certificate: %v", cert)
	}
	if n := testutil.ToFloat64(f.b.Metrics.CertificatesIssued.WithLabelValues("issued")); n != 1 {
		t.Fatalf("issued %v", n)
	}
	c := tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: key, Leaf: leaf}
	if w := f.postAt(context.Background(), f.issuedState(c), mintLeaf1, "", f.now); w.Code != 200 {
		t.Fatalf("the issued certificate's mint: %s", shown(w))
	}
}

// A token whose nonce names another key, or none, is refused and recorded: a
// token taken in flight certifies no key but its own (decision 43 ruling 8;
// R2).
func TestATokenForAnotherKeyIsRefused(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withIssuance(t)
	key, other := newECKey(t), newECKey(t)
	for name, tok := range map[string]string{
		"another key's nonce": f.signInFor(t, iss, other, nil),
		"no nonce":            f.idToken(t, iss, nil),
	} {
		if w := f.bearer(context.Background(), "POST", "/v1/certificate", csrBody(t, key), tok); w.Code != 401 ||
			apiError(w) != "sign_in_not_bound" {
			t.Errorf("%s: %s", name, shown(w))
		}
	}
	recs := eventsOf(f.records(t), decision.EventIssue)
	if len(recs) != 2 || recs[0]["verdict"] != "deny" || recs[0]["principal"] != alicePrincipal ||
		recs[0]["reason"] != "trust_domain_unresolved" {
		t.Fatalf("%v", recs)
	}
}

// A sign-in is exchanged once (decision 43 ruling 8).
func TestASignInIsExchangedOnce(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withIssuance(t)
	key := newECKey(t)
	tok := f.signInFor(t, iss, key, nil)
	if w := f.bearer(context.Background(), "POST", "/v1/certificate", csrBody(t, key), tok); w.Code != 200 {
		t.Fatalf("the first: %s", shown(w))
	}
	if w := f.bearer(context.Background(), "POST", "/v1/certificate", csrBody(t, key), tok); w.Code != 401 ||
		apiError(w) != "sign_in_spent" {
		t.Fatalf("the second: %s", shown(w))
	}
}

// An auth_time over 5 minutes before the token's iat is a prompt=login the
// provider ignored, judged on the provider's own clock; a token issued over 5
// minutes before the broker's now is a slow sign-in or two clocks apart, and
// never blamed on prompt=login; an auth_time after the iat (the verifier
// refuses one ahead of the broker's now) is no sign-in.
// Each is refused and recorded (decision 43 ruling 8; R3). An auth_time and
// iat 4 minutes old, the control, is issued.
func TestAStaleSignInIsRefused(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withIssuance(t)
	now := f.b.Now()
	for name, c := range map[string]struct {
		claims       map[string]any
		want, unwant string
	}{
		"prompt=login ignored": {map[string]any{"auth_time": now.Add(-10 * time.Minute).Unix()},
			"prompt=login was not honoured", "clocks"},
		"the clocks apart": {map[string]any{"auth_time": now.Add(-10 * time.Minute).Unix(),
			"iat": now.Add(-10 * time.Minute).Unix()}, "clock and the broker's differ", "prompt=login"},
		"auth_time after iat": {map[string]any{"auth_time": now.Unix(), "iat": now.Add(-4 * time.Minute).Unix()},
			"after it issued the token", "prompt=login"},
	} {
		key := newECKey(t)
		w := f.bearer(context.Background(), "POST", "/v1/certificate", csrBody(t, key), f.signInFor(t, iss, key, c.claims))
		if w.Code != 401 || apiError(w) != "sign_in_not_fresh" || !strings.Contains(w.Body.String(), c.want) ||
			strings.Contains(w.Body.String(), c.unwant) {
			t.Errorf("%s: %s", name, shown(w))
		}
	}
	if recs := eventsOf(f.records(t), decision.EventIssue); len(recs) != 3 || recs[0]["verdict"] != "deny" {
		t.Fatalf("%v", recs)
	}
	key := newECKey(t)
	tok := f.signInFor(t, iss, key, map[string]any{"auth_time": now.Add(-4 * time.Minute).Unix(),
		"iat": now.Add(-4 * time.Minute).Unix()})
	if w := f.bearer(context.Background(), "POST", "/v1/certificate", csrBody(t, key), tok); w.Code != 200 {
		t.Fatalf("the control, 4 minutes old: %s", shown(w))
	}
}

// A logged-out person is issued nothing, as a mint is refused.
func TestALoggedOutPersonIsIssuedNothing(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withIssuance(t)
	if err := f.st.PutLogout(context.Background(), store.Logout{Key: store.OIDCKey(store.OIDCSub, iss.URL, "sub-alice"),
		At: f.b.Now(), Origin: "backchannel_logout " + iss.URL}, time.Hour); err != nil {
		t.Fatal(err)
	}
	key := newECKey(t)
	if w := f.bearer(context.Background(), "POST", "/v1/certificate", csrBody(t, key), f.signInFor(t, iss, key, nil)); w.Code != 401 ||
		apiError(w) != "credential_revoked" {
		t.Fatalf("%s", shown(w))
	}
	if recs := eventsOf(f.records(t), decision.EventIssue); len(recs) != 1 || recs[0]["reason"] != "credential_revoked" {
		t.Fatalf("%v", recs)
	}
}

// A CSR whose signature is not its key's, or whose key is too weak, is
// refused.
func TestABadCSRIsRefused(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withIssuance(t)
	key := newECKey(t)
	var req api.IssueRequest
	_ = json.Unmarshal([]byte(csrBody(t, key)), &req)
	der, _ := base64.RawURLEncoding.DecodeString(req.CSR)
	der[len(der)-1] ^= 0xff // the signature's last byte
	bad, _ := json.Marshal(api.IssueRequest{CSR: base64.RawURLEncoding.EncodeToString(der)})
	if w := f.bearer(context.Background(), "POST", "/v1/certificate", string(bad), f.signInFor(t, iss, key, nil)); w.Code != 400 {
		t.Fatalf("a bad signature: %s", shown(w))
	}
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if w := f.bearer(context.Background(), "POST", "/v1/certificate", csrBody(t, weak), f.signInFor(t, iss, weak, nil)); w.Code != 400 ||
		!strings.Contains(w.Body.String(), "2048") {
		t.Fatalf("a 1024-bit key: %s", shown(w))
	}
	if recs := eventsOf(f.records(t), decision.EventIssue); len(recs) != 2 || recs[0]["verdict"] != "deny" ||
		recs[1]["verdict"] != "deny" {
		t.Fatalf("each bad CSR is a deny record: %v", recs)
	}
}

// A machine is issued nothing.
func TestAMachineIsIssuedNothing(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, machinePolicy)
	iss := f.withIssuance(t)
	now := f.b.Now()
	machine := iss.Token(t, "k1", map[string]any{"iss": iss.URL, "aud": "api://port49-svc", "sub": "svc",
		"azp": "Oxidized-01", "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()})
	if w := f.bearer(context.Background(), "POST", "/v1/certificate", csrBody(t, newECKey(t)), machine); w.Code != 400 {
		t.Fatalf("%s", shown(w))
	}
	if recs := eventsOf(f.records(t), decision.EventIssue); len(recs) != 1 || recs[0]["verdict"] != "deny" ||
		recs[0]["reason"] != "trust_domain_unresolved" {
		t.Fatalf("a machine's refusal is a deny record: %v", recs)
	}
}

// A broker whose CA cannot issue says so, without the file's name, records
// nothing, and counts it; one with no issuance answers 404 (decision 43
// rulings 8 and 14).
func TestIssuanceUnavailableSaysSo(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withIssuance(t)
	f.b.Issuer.Unavailable = errors.New("issuing-ca.key is not usable: missing")
	key := newECKey(t)
	w := f.bearer(context.Background(), "POST", "/v1/certificate", csrBody(t, key), f.signInFor(t, iss, key, nil))
	if w.Code != 503 || w.Header().Get("Retry-After") != "60" || apiError(w) != "issuance_unavailable" ||
		strings.Contains(w.Body.String(), "issuing-ca.key") {
		t.Fatalf("%s", shown(w))
	}
	if n := len(eventsOf(f.records(t), decision.EventIssue)); n != 0 {
		t.Fatalf("%d issue records for the broker's own fault", n)
	}
	if n := testutil.ToFloat64(f.b.Metrics.CertificatesIssued.WithLabelValues("unavailable")); n != 1 {
		t.Fatalf("unavailable %v", n)
	}
	f.b.Issuer = nil
	if w := f.bearer(context.Background(), "POST", "/v1/certificate", csrBody(t, key), f.signInFor(t, iss, key, nil)); w.Code != 404 ||
		apiError(w) != "not_issuing" {
		t.Fatalf("no issuance: %s", shown(w))
	}
}

// /v1/config says the broker issues, and for how long (decision 43 ruling
// 18).
func TestConfigSaysTheBrokerIssues(t *testing.T) {
	f := newFixture(t, 8)
	f.withIssuance(t)
	f.b.CertificateLifetime = 8 * time.Hour
	w := httptest.NewRecorder()
	f.b.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/v1/config", nil))
	var c api.Config
	if json.Unmarshal(w.Body.Bytes(), &c) != nil || c.Issuance == nil || c.Issuance.CertificateLifetimeSeconds != 8*3600 {
		t.Fatalf("%s", w.Body)
	}
	if c.Issuance.Available == nil || !*c.Issuance.Available || c.Issuance.Unavailable() {
		t.Fatalf("a broker whose CA is usable says it cannot issue: %s", w.Body)
	}
	// M1: a CA that cannot issue is said in the config, before anyone signs in.
	f.b.Issuer.Unavailable = errors.New("issuing-ca.key is not usable: missing")
	w = httptest.NewRecorder()
	f.b.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/v1/config", nil))
	c = api.Config{}
	if json.Unmarshal(w.Body.Bytes(), &c) != nil || c.Issuance == nil || !c.Issuance.Unavailable() ||
		!strings.Contains(w.Body.String(), `"available":false`) || strings.Contains(w.Body.String(), "issuing-ca.key") {
		t.Fatalf("%s", w.Body)
	}
	// A config without the field (an older broker) means available.
	var old api.Config
	if json.Unmarshal([]byte(`{"issuance":{"certificate_lifetime_seconds":3600}}`), &old) != nil ||
		old.Issuance == nil || old.Issuance.Unavailable() {
		t.Fatalf("a config with no available field: %+v", old.Issuance)
	}
	f.b.Issuer = nil
	w = httptest.NewRecorder()
	f.b.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/v1/config", nil))
	if strings.Contains(w.Body.String(), "issuance") {
		t.Fatalf("a broker that does not issue says it does: %s", w.Body)
	}
}

// A logout's record stands on a broker that issues while a certificate
// issued on a sign-in before it may still be presented: the certificate
// carries no mark of its own, so past max_token_age its next mint is refused
// still (decision 43 ruling 16). The record stands the longest lifetime any
// broker may issue, so a lifetime lowered since keeps it; a broker that
// issued nothing when the logout landed keeps the record max_token_age
// alone, the control that shows the mint would otherwise pass. A recovery
// for a logout the store could not write names the shorter path, revoking
// the sign-in's certificates by serial, on a broker that issues alone.
func TestALogoutOutlivesMaxTokenAgeForAnIssuedCertificate(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withIssuance(t)
	tm := f.b.Identity.Timing
	if got, want := f.b.logoutRecordTTL(), issuer.MaxLifetime+2*tm.ClockSkew; got != want {
		t.Fatalf("an issuing broker's logout record stands %s, want %s", got, want)
	}
	f.b.CertificateLifetime = time.Hour
	if got, want := f.b.logoutRecordTTL(), issuer.MaxLifetime+2*tm.ClockSkew; got != want {
		t.Fatalf("with the lifetime lowered to 1h the record stands %s, want %s", got, want)
	}
	f.b.CertificateLifetime = 0
	f.b.AdminSocket = "/run/port49/admin.sock"
	if got := f.b.logoutUnapplied(alicePrincipal, f.b.Now().Add(f.b.logoutRecordTTL())); !strings.Contains(got,
		"`port49 revoke --cert-issuer DN --cert-serial HEX`") ||
		!strings.Contains(got, "every certificate issued to "+alicePrincipal+" before the logout, by every broker") ||
		!strings.Contains(got, f.b.Now().Add(tm.MaxTokenAge+2*tm.ClockSkew).UTC().Format(time.RFC3339)) {
		t.Fatalf("the recovery names no shorter path: %s", got)
	}
	past := tm.MaxTokenAge + 2*tm.ClockSkew + time.Minute
	logout := func(f *fixture, iss *oidctest.Issuer) {
		t.Helper()
		if _, err := f.b.Logout(context.Background(), oidc.LogoutToken{Issuer: iss.URL, Sid: "s-sub-alice",
			IssuedAt: f.b.Now(), Domains: []string{"example.com"}}, "backchannel_logout "+iss.URL); err != nil {
			t.Fatal(err)
		}
	}
	c := f.issued(t, f.aliceSignIn(iss))
	logout(f, iss)
	f.advance(past)
	if w := f.postAt(context.Background(), f.issuedState(c), mintLeaf1, "", f.b.Now()); w.Code != 401 ||
		apiError(w) != "credential_revoked" || !strings.Contains(w.Body.String(), "back-channel logout") {
		t.Fatalf("a mint %s after the logout: %s", past, shown(w))
	}

	g := newFixture(t, 8)
	giss := g.withIssuance(t)
	gc := g.issued(t, g.aliceSignIn(giss))
	ca := g.b.Issuer
	g.b.Issuer = nil
	g.b.AdminSocket = "/run/port49/admin.sock"
	if got := g.b.logoutUnapplied(alicePrincipal, g.b.Now()); strings.Contains(got, "--cert-serial") {
		t.Fatalf("a broker that issues nothing names revoking by serial: %s", got)
	}
	logout(g, giss)
	g.b.Issuer = ca
	g.advance(past)
	if w := g.postAt(context.Background(), g.issuedState(gc), mintLeaf1, "", g.b.Now()); w.Code != 200 {
		t.Fatalf("the control, a record kept max_token_age alone: %s", shown(w))
	}
}

// failOnce is a store whose PutOnce or PutOIDCOwner fails.
type failOnce struct {
	store.Store
	putOnce, owner bool
}

func (s failOnce) PutOnce(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	if s.putOnce {
		return false, errors.New("store: connection refused")
	}
	return s.Store.PutOnce(ctx, key, value, ttl)
}

func (s failOnce) PutOIDCOwner(ctx context.Context, key, principal string, ttl time.Duration) error {
	if s.owner {
		return errors.New("store: connection refused")
	}
	return s.Store.PutOIDCOwner(ctx, key, principal, ttl)
}

// A CA outside its validity cannot issue: 503, unrecorded, and the same token
// is exchanged once the CA is cured.
func TestAnExpiredCAIssuesNothingAndSpendsNothing(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withIssuance(t)
	good := f.b.Issuer
	old, err := issuer.Ephemeral(f.b.Now().AddDate(-20, 0, 0))
	if err != nil {
		t.Fatal(err)
	}
	f.b.Issuer = old
	key := newECKey(t)
	tok := f.signInFor(t, iss, key, nil)
	w := f.bearer(context.Background(), "POST", "/v1/certificate", csrBody(t, key), tok)
	if w.Code != 503 || apiError(w) != "issuance_unavailable" || w.Header().Get("Retry-After") != "60" {
		t.Fatalf("%s", shown(w))
	}
	if n := len(eventsOf(f.records(t), decision.EventIssue)); n != 0 {
		t.Fatalf("%d issue records for the broker's own fault", n)
	}
	f.b.Issuer = good
	if w := f.bearer(context.Background(), "POST", "/v1/certificate", csrBody(t, key), tok); w.Code != 200 {
		t.Fatalf("the same sign-in after the CA was cured: %s", shown(w))
	}
}

// A sign-in refused for its CSR or its nonce is not spent: a thief without
// the key cannot burn it, and a retry with the right request succeeds.
func TestARefusedSignInIsStillExchangeable(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withIssuance(t)
	key, other := newECKey(t), newECKey(t)
	tok := f.signInFor(t, iss, key, nil)
	if w := f.bearer(context.Background(), "POST", "/v1/certificate", csrBody(t, other), tok); w.Code != 401 ||
		apiError(w) != "sign_in_not_bound" {
		t.Fatalf("another key's CSR: %s", shown(w))
	}
	if w := f.bearer(context.Background(), "POST", "/v1/certificate", `{"csr":"AAAA"}`, tok); w.Code != 400 {
		t.Fatalf("a bad CSR: %s", shown(w))
	}
	if w := f.bearer(context.Background(), "POST", "/v1/certificate", csrBody(t, key), tok); w.Code != 200 {
		t.Fatalf("the right request after two refusals: %s", shown(w))
	}
}

// A store that cannot record the sign-in (the once-only key or the owner
// record) issues nothing: 503 store_unavailable, recorded, counted refused,
// and no certificate.
func TestAStoreThatCannotRecordTheSignInIssuesNothing(t *testing.T) {
	for name, st := range map[string]failOnce{"the once-only key": {putOnce: true}, "the owner record": {owner: true}} {
		f := newFixture(t, 8)
		iss := f.withIssuance(t)
		st.Store = f.st
		f.b.Store = st
		key := newECKey(t)
		w := f.bearer(context.Background(), "POST", "/v1/certificate", csrBody(t, key), f.signInFor(t, iss, key, nil))
		if w.Code != 503 || apiError(w) != "store_unavailable" || strings.Contains(w.Body.String(), "BEGIN CERTIFICATE") {
			t.Errorf("%s: %s", name, shown(w))
		}
		recs := eventsOf(f.records(t), decision.EventIssue)
		if len(recs) != 1 || recs[0]["verdict"] != "deny" || recs[0]["reason"] != "store_unavailable" {
			t.Errorf("%s: %v", name, recs)
		}
		if n := testutil.ToFloat64(f.b.Metrics.CertificatesIssued.WithLabelValues("refused")); n != 1 {
			t.Errorf("%s: refused %v", name, n)
		}
		if n := testutil.ToFloat64(f.b.Metrics.CertificatesIssued.WithLabelValues("issued")); n != 0 {
			t.Errorf("%s: issued %v", name, n)
		}
	}
}

// A sign-in is exchanged with no client certificate: one presented is
// refused, recorded and counted.
func TestAClientCertificateIsRefusedAtTheExchange(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withIssuance(t)
	key := newECKey(t)
	r := httptest.NewRequest("POST", "/v1/certificate", strings.NewReader(csrBody(t, key)))
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{}}}
	r.Header.Set("Authorization", "Bearer "+f.signInFor(t, iss, key, nil))
	w := httptest.NewRecorder()
	f.b.Handler().ServeHTTP(w, r)
	if w.Code != 400 {
		t.Fatalf("%s", shown(w))
	}
	recs := eventsOf(f.records(t), decision.EventIssue)
	if len(recs) != 1 || recs[0]["verdict"] != "deny" || recs[0]["reason"] != "trust_domain_unresolved" {
		t.Fatalf("%v", recs)
	}
	if auth, _ := recs[0]["auth"].(map[string]any); auth["method"] != "cert" {
		t.Fatalf("the credential presented was a certificate: %v", recs[0]["auth"])
	}
	if n := testutil.ToFloat64(f.b.Metrics.CertificatesIssued.WithLabelValues("refused")); n != 1 {
		t.Fatalf("refused %v", n)
	}
}
