package broker

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/engine"
	"github.com/rhwendt/port49/internal/oidc"
	"github.com/rhwendt/port49/internal/oidc/oidctest"
	"github.com/rhwendt/port49/internal/policy"
	"github.com/rhwendt/port49/internal/session"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/memory"
	"github.com/rhwendt/port49/internal/testpki"
	"github.com/rhwendt/port49/internal/token"
)

const testPolicy = `
scopes:
  - {name: all_devices, match: {}}
roles:
  - {name: network_admin, privilege: admin, permit: ["**"]}
  - {name: no_reload, deny: ["reload **"]}
subjects:
  - {name: netops, identity: ["user:alice@example.com"], username: alice, enable: token, token_ttl: 60s}
  - {name: idle, identity: ["user:carol@example.com"], username: carol, token_ttl: 60s}
grants:
  - {subject: netops, scope: all_devices, roles: [network_admin, no_reload], max_privilege: admin}
`

type fixture struct {
	b     *Broker
	st    *memory.Store
	log   *bytes.Buffer
	now   time.Time
	ca    *testpki.CA
	alice tls.Certificate
	mu    sync.Mutex
	// devices is the inventory the fixture's policy is loaded against, by
	// name, for tests that load another policy over it.
	devices map[string]admission.Device
}

// alicePrincipal is the principal f.alice's certificate maps to.
const alicePrincipal = "user:alice@example.com"

// newFixture's clock starts at the real time: Task 10's handshakes verify
// certificates against it, and the fixture's certificates are cut around it.
// "bare" is in inventory with no platform, which admission.LoadFile allows.
func newFixture(t *testing.T, candidateCap int) *fixture {
	t.Helper()
	return newFixtureWithPolicy(t, candidateCap, testPolicy)
}

// newFixtureWithDevices is newFixture with extra added to the inventory the
// policy loads against.
func newFixtureWithDevices(t *testing.T, candidateCap int, extra ...admission.Device) *fixture {
	t.Helper()
	return newFixtureWith(t, candidateCap, testPolicy, extra...)
}

// newFixtureWithPolicy is newFixture with policyText in place of testPolicy.
func newFixtureWithPolicy(t *testing.T, candidateCap int, policyText string) *fixture {
	t.Helper()
	return newFixtureWith(t, candidateCap, policyText)
}

func newFixtureWith(t *testing.T, candidateCap int, policyText string, extra ...admission.Device) *fixture {
	t.Helper()
	f := &fixture{log: &bytes.Buffer{}, now: time.Now().Truncate(time.Second)}
	clock := func() time.Time {
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.now
	}
	f.st = memory.New(clock)
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(policyText), 0o600); err != nil {
		t.Fatal(err)
	}
	devices := map[string]admission.Device{
		"leaf1": {Name: "leaf1", Platform: "arista_eos", Addresses: []netip.Addr{netip.MustParseAddr("172.100.100.11")}},
		"nx1":   {Name: "nx1", Platform: "cisco_nxos", Addresses: []netip.Addr{netip.MustParseAddr("172.100.100.31")}},
		"bare":  {Name: "bare", Addresses: []netip.Addr{netip.MustParseAddr("172.100.100.41")}},
	}
	for _, d := range extra {
		devices[d.Name] = d
	}
	f.devices = devices
	pol, err := policy.Load(path, policy.Env{Devices: f.inventory()})
	if err != nil {
		t.Fatal(err)
	}
	if f.ca, err = testpki.NewCA("port49 test ca", f.now.Add(-time.Hour), f.now.Add(48*time.Hour)); err != nil {
		t.Fatal(err)
	}
	f.alice = f.client(t, "alice@example.com", f.now.Add(24*time.Hour))
	log := decision.NewJSONLines(f.log)
	f.b = &Broker{Policy: policy.NewLive(pol),
		Minter: token.NewMinter(f.st, log, rand.Reader, token.TagKey([]byte("k")), clock, candidateCap),
		Store:  f.st, Log: log, Metrics: metrics.New(prometheus.NewRegistry()), Now: clock,
		MaxSessionAge: 12 * time.Hour, BatchMax: 4, Sessions: session.New(f.st, clock, time.Hour, time.Hour),
		ContextIdleTTL: time.Hour}
	return f
}

// inventory is f.devices as a list: leaf1, nx1 and bare, then the rest in
// name order.
func (f *fixture) inventory() []admission.Device {
	out := []admission.Device{f.devices["leaf1"], f.devices["nx1"], f.devices["bare"]}
	var rest []string
	for name := range f.devices {
		if name != "leaf1" && name != "nx1" && name != "bare" {
			rest = append(rest, name)
		}
	}
	sort.Strings(rest)
	for _, name := range rest {
		out = append(out, f.devices[name])
	}
	return out
}

// loadPolicy swaps f.b.Policy to a policy loaded from text over f.devices.
func (f *fixture) loadPolicy(t *testing.T, text string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	pol, err := policy.Load(path, policy.Env{Devices: f.inventory()})
	if err != nil {
		t.Fatal(err)
	}
	f.b.Policy.Swap(pol)
}

// liveContext writes a live context for principal under (device, username),
// indexed by principal and certificate, as a redemption would.
func (f *fixture) liveContext(t *testing.T, device, username, principal, certKey string) {
	t.Helper()
	ctx := context.Background()
	k := store.ContextKey{NAS: device, Username: username}
	if err := f.st.PutContext(ctx, k, store.Context{CtxID: "ctx_" + device, Principal: principal, Username: username,
		PrivLvl: 1, AuthTime: f.now, RefreshedAt: f.now}, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := f.st.IndexContext(ctx, principal, "", certKey, store.ContextRef{NAS: device, Username: username},
		time.Hour); err != nil {
		t.Fatal(err)
	}
}

// putBlobLogged is putBlob outside a mint, as the refresh writes a blob:
// its record is written to b.Log at once, and its hash marked when it lands.
func (b *Broker) putBlobLogged(ctx context.Context, hash string, body []byte, ttl time.Duration) error {
	one := newHeldLog()
	err := b.putBlob(ctx, one, hash, body, ttl)
	one.Flush(b.Log, b.blobLanded)
	return err
}

// liveContextAt writes a live context for principal on device under
// username, authenticated at auth with the given ceiling (zero: none), as a
// redemption of a token the policy in force minted would: its blob is that
// policy's compiled blob for principal on device, written through putBlob;
// its store TTL is a day, so a test may advance the clock by hours; it is
// indexed by principal and by certificate.
func (f *fixture) liveContextAt(t *testing.T, device, username, principal, certKey string, auth, expires time.Time) {
	t.Helper()
	ctx := context.Background()
	pol := f.b.Policy.Load()
	dev, ok := pol.Device(device)
	if !ok {
		t.Fatalf("no device %s", device)
	}
	var hash string
	if res, err := pol.Resolve(principal, dev, f.b.Now()); err == nil {
		body, h, err := engine.Encode(res.Blob)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.b.putBlobLogged(ctx, h, body, 24*time.Hour); err != nil {
			t.Fatal(err)
		}
		hash = h
	} else {
		hash = "sha256:" + strings.Repeat("0", 64) // a device with no platform: no blob compiles
	}
	k := store.ContextKey{NAS: device, Username: username}
	if err := f.st.PutContext(ctx, k, store.Context{CtxID: "ctx_" + device, Principal: principal, Username: username,
		PrivLvl: 1, BlobHash: hash, AuthTime: auth, SessionExpires: expires, RefreshedAt: auth,
		LastTouchedAt: auth}, 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := f.st.IndexContext(ctx, principal, "", certKey, store.ContextRef{NAS: device, Username: username},
		24*time.Hour); err != nil {
		t.Fatal(err)
	}
}

// certKey is the mark key of c, as Identity names its credential.
func certKey(c tls.Certificate) string {
	return store.CertKey(c.Leaf.Issuer.String(), c.Leaf.SerialNumber.Text(16))
}

// advance moves the clock under the lock, for tests where a server goroutine
// reads it. Single-goroutine tests may still assign f.now directly.
func (f *fixture) advance(d time.Duration) {
	f.mu.Lock()
	f.now = f.now.Add(d)
	f.mu.Unlock()
}

func (f *fixture) client(t *testing.T, email string, notAfter time.Time) tls.Certificate {
	t.Helper()
	c, err := f.ca.Issue(testpki.Leaf{CommonName: email, Emails: []string{email}, Client: true,
		NotBefore: f.now.Add(-time.Hour), NotAfter: notAfter})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (f *fixture) state(c tls.Certificate) *tls.ConnectionState {
	return &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{c.Leaf, f.ca.Cert}}}
}

func (f *fixture) post(ctx context.Context, cs *tls.ConnectionState, body, key string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/v1/tokens", strings.NewReader(body)).WithContext(ctx)
	r.TLS = cs
	if key != "" {
		r.Header.Set("Idempotency-Key", key)
	}
	w := httptest.NewRecorder()
	f.b.Handler().ServeHTTP(w, r)
	return w
}

// postAt is post on a connection that authenticated at at, as Server's
// ConnContext gives every request on one connection.
func (f *fixture) postAt(ctx context.Context, cs *tls.ConnectionState, body, key string,
	at time.Time) *httptest.ResponseRecorder {
	return f.post(withHeldConn(ctx, at, nil), cs, body, key)
}

// call sends one request to path through the broker's handler on a
// connection whose verified chain is cs. ctx carries the held connection,
// if the test gives one (withHeldConn).
func (f *fixture) call(ctx context.Context, cs *tls.ConnectionState, method, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body)).WithContext(ctx)
	r.TLS = cs
	w := httptest.NewRecorder()
	f.b.Handler().ServeHTTP(w, r)
	return w
}

// heldAnswer is one response on a held connection.
type heldAnswer struct {
	status     int
	body       string
	retryAfter string
}

// postOn writes one POST to path with body on the held connection c and
// reads its whole response.
func postOn(t *testing.T, c *tls.Conn, br *bufio.Reader, path, body string) heldAnswer {
	t.Helper()
	if _, err := fmt.Fprintf(c, "POST %s HTTP/1.1\r\nHost: broker\r\nContent-Type: application/json\r\n"+
		"Content-Length: %d\r\n\r\n%s", path, len(body), body); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("POST %s on a held connection: %v", path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return heldAnswer{status: resp.StatusCode, body: string(raw), retryAfter: resp.Header.Get("Retry-After")}
}

func (f *fixture) records(t *testing.T) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(f.log.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatal(err)
		}
		out = append(out, m)
	}
	return out
}

// blobRecords are the log's blob events with their bodies as the exact bytes
// written, which a map would re-encode.
func (f *fixture) blobRecords(t *testing.T) []decision.Blob {
	t.Helper()
	var out []decision.Blob
	for _, line := range strings.Split(strings.TrimSpace(f.log.String()), "\n") {
		var r struct {
			Event string         `json:"event"`
			Blob  *decision.Blob `json:"blob"`
		}
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatal(err)
		}
		if r.Event == decision.EventBlob {
			if r.Blob == nil {
				t.Fatalf("a blob event with no blob: %s", line)
			}
			out = append(out, *r.Blob)
		}
	}
	return out
}

func decodeMint(t *testing.T, w *httptest.ResponseRecorder) api.MintResponse {
	t.Helper()
	if w.Code != 200 {
		t.Fatalf("status %s", answer(w))
	}
	var r api.MintResponse
	if err := json.Unmarshal(w.Body.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	return r
}

func eventsOf(recs []map[string]any, event string) []map[string]any {
	var out []map[string]any
	for _, r := range recs {
		if r["event"] == event {
			out = append(out, r)
		}
	}
	return out
}

// testClientID is the human OIDC verifier's client_id in withOIDC.
const testClientID = "port49-cli"

// withOIDC gives f's broker an OIDC set over a test provider, on f's clock:
// a human verifier (client_id port49-cli, principal from
// preferred_username, for example.com) and a machine verifier (audience
// api://port49-svc, client Oxidized-01 whose sub is svc).
func (f *fixture) withOIDC(t *testing.T) *oidctest.Issuer {
	t.Helper()
	iss := oidctest.NewIssuer(t)
	f.addIssuer(t, iss, "example.com", true)
	return iss
}

// addIssuer adds iss to f's OIDC set (making the set if there is none): a
// human verifier for domain, and, with machine, the machine verifier.
func (f *fixture) addIssuer(t *testing.T, iss *oidctest.Issuer, domain string, machine bool) {
	t.Helper()
	ks := oidc.NewKeySet(oidc.KeySetConfig{Issuer: iss.URL, Client: oidc.NewClient(iss.Roots()), Refresh: time.Hour,
		MaxAge: 24 * time.Hour, Now: f.b.Now, M: f.b.Metrics})
	if f.b.Identity == nil {
		f.b.Identity = &oidc.Set{Timing: oidc.DefaultTiming, Now: f.b.Now, M: f.b.Metrics}
	}
	f.b.Identity.Verifiers = append(f.b.Identity.Verifiers, &oidc.Verifier{VerifierConfig: oidc.VerifierConfig{
		Domain: oidc.Humans, Issuer: iss.URL, ClientID: testClientID, PrincipalClaim: oidc.ClaimPreferredUsername,
		PrincipalDomains: []string{domain}, Scopes: []string{"openid"}, Algorithms: []oidc.Alg{oidc.RS256}}, Keys: ks})
	if machine {
		f.b.Identity.Verifiers = append(f.b.Identity.Verifiers, &oidc.Verifier{VerifierConfig: oidc.VerifierConfig{
			Domain: oidc.Machines, Issuer: iss.URL, Audience: "api://port49-svc",
			Clients:    []oidc.MachineClient{{ClientID: "Oxidized-01", Sub: "svc"}},
			Algorithms: []oidc.Alg{oidc.RS256}}, Keys: ks})
	}
}

// idToken is alice's ID token from iss at f's now, sid s-alice, sub
// sub-alice; extra overrides, nil deleting.
func (f *fixture) idToken(t *testing.T, iss *oidctest.Issuer, extra map[string]any) string {
	t.Helper()
	c := map[string]any{"preferred_username": "alice@example.com", "amr": []string{"pwd", "otp"}, "acr": "1"}
	for k, v := range extra {
		c[k] = v
	}
	return iss.IDToken(t, "k1", testClientID, "sub-alice", f.b.Now(), c)
}

// bearer sends one request with no client certificate and token as its
// bearer through the broker's handler.
func (f *fixture) bearer(ctx context.Context, method, path, body, token string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body)).WithContext(ctx)
	r.TLS = &tls.ConnectionState{}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	f.b.Handler().ServeHTTP(w, r)
	return w
}

// httptestRequest is a request with no client certificate.
func httptestRequest(method, path, body string) *http.Request {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.TLS = &tls.ConnectionState{}
	return r
}

// httptestServe serves r through f's broker.
func httptestServe(f *fixture, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	f.b.Handler().ServeHTTP(w, r)
	return w
}
