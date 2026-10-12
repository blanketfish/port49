package broker

import (
	"bufio"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/oidc"
	"github.com/rhwendt/port49/internal/oidc/oidctest"
	"github.com/rhwendt/port49/internal/pivattest"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/testpki"
	"github.com/rhwendt/port49/internal/token"
)

// Yubico's PIV attestation extensions, as pivattest reads them.
var (
	testOIDSerial = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 7}
	testOIDPolicy = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 8}
)

type mfaOpts struct {
	reuseZero     bool
	noRoots       bool
	touchOnlyCore bool
	machines      bool
	intermediate  bool // the device certificate is signed by an intermediate under the root
	listInter     bool // and the operator's roots file lists that intermediate
	shortCeiling  bool // alice's grant on core carries a one-hour session ceiling
	noRequirement bool // core carries no per_login_mfa (a policy before the reload that adds one)
	junosCore     bool // core-sw01 is on juniper_junos, which never asks about a command
}

type mfaOpt func(*mfaOpts)

func withReuseFor(d time.Duration) mfaOpt {
	return func(o *mfaOpts) { o.reuseZero = d == 0 }
}
func withoutAttestationRoots() mfaOpt { return func(o *mfaOpts) { o.noRoots = true } }
func withTouchOnlyCore() mfaOpt       { return func(o *mfaOpts) { o.touchOnlyCore = true } }
func withAppliesToMachines() mfaOpt   { return func(o *mfaOpts) { o.machines = true } }
func withShortCeiling() mfaOpt        { return func(o *mfaOpts) { o.shortCeiling = true } }
func withJunosCore() mfaOpt           { return func(o *mfaOpts) { o.junosCore = true } }
func withDeviceUnderIntermediate(listed bool) mfaOpt {
	return func(o *mfaOpts) { o.intermediate, o.listInter = true, listed }
}

// mfaPolicy: scope core requires per_login_mfa on core-sw01, scope edge
// nothing on edge-sw01. alice and bob are people; oxidized is a workload.
func mfaPolicy(o mfaOpts) string {
	accept, reuse, machines := "[hardware_key_touch, idp_mfa]", "15m", ""
	if o.touchOnlyCore {
		accept = "[hardware_key_touch]"
	}
	if o.reuseZero {
		reuse = "0m"
	}
	if o.machines {
		machines = ", applies_to_machines: true"
	}
	coreMFA := fmt.Sprintf(", per_login_mfa: {accept: %s, reuse_for: %s%s}", accept, reuse, machines)
	if o.noRequirement {
		coreMFA = ""
	}
	ceilingRole, ceilingGrant := "", ""
	if o.shortCeiling {
		ceilingRole = "\n  - {name: short_session, max_session_age: 1h}"
		ceilingGrant = "\n  - {subject: netops, scope: core, roles: [short_session]}"
	}
	return fmt.Sprintf(`
scopes:
  - {name: core, match: {name: core-sw01}%s}
  - {name: edge, match: {name: edge-sw01}}
roles:
  - {name: network_admin, privilege: admin, permit: ["**"]}%s
subjects:
  - {name: netops, identity: ["user:alice@example.com"], username: alice, enable: token, token_ttl: 60s}
  - {name: bobs, identity: ["user:bob@example.com"], username: bob, token_ttl: 60s}
  - {name: svc_oxidized, identity: ["spiffe://corp.example.com/host/oxidized-01"], username: svc-oxidized, token_ttl: 60s}
grants:
  - {subject: netops, scope: core, roles: [network_admin], max_privilege: admin}
  - {subject: netops, scope: edge, roles: [network_admin], max_privilege: admin}%s
  - {subject: bobs, scope: core, roles: [network_admin], max_privilege: admin}
  - {subject: bobs, scope: edge, roles: [network_admin], max_privilege: admin}
  - {subject: svc_oxidized, scope: core, roles: [network_admin], max_privilege: admin}
  - {subject: svc_oxidized, scope: edge, roles: [network_admin], max_privilege: admin}
`, coreMFA, ceilingRole, ceilingGrant)
}

// failStore fails the named store methods, for the store-down cases.
type failStore struct {
	store.Store
	mu   sync.Mutex
	fail map[string]bool
}

var errInjected = errors.New("injected store failure")

func (s *failStore) failOn(names ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fail = map[string]bool{}
	for _, n := range names {
		s.fail[n] = true
	}
}

func (s *failStore) failing(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fail[name]
}

func (s *failStore) PutOnce(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	if s.failing("PutOnce") {
		return false, errInjected
	}
	return s.Store.PutOnce(ctx, key, value, ttl)
}

func (s *failStore) TakeOnce(ctx context.Context, key string) ([]byte, error) {
	if s.failing("TakeOnce") {
		return nil, errInjected
	}
	return s.Store.TakeOnce(ctx, key)
}

func (s *failStore) GetMFAProof(ctx context.Context, key string) (store.MFAProof, error) {
	if s.failing("GetMFAProof") {
		return store.MFAProof{}, errInjected
	}
	return s.Store.GetMFAProof(ctx, key)
}

func (s *failStore) PutMFAProof(ctx context.Context, p store.MFAProof, ttl time.Duration) error {
	if s.failing("PutMFAProof") {
		return errInjected
	}
	return s.Store.PutMFAProof(ctx, p, ttl)
}

// stepClock is the minter's clock: the fixture's until armed, then one that
// advances by step on every read, starting at start. A test arms it so the
// minter's reads straddle an instant.
type stepClock struct {
	mu   sync.Mutex
	base func() time.Time
	next time.Time
	step time.Duration
}

func (c *stepClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.next.IsZero() {
		return c.base()
	}
	t := c.next
	c.next = c.next.Add(c.step)
	return t
}

func (c *stepClock) arm(start time.Time, step time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.next, c.step = start, step
}

type mfaClock struct{ f *fixture }

func (c mfaClock) Now() time.Time          { return c.f.b.Now() }
func (c mfaClock) Advance(d time.Duration) { c.f.advance(d) }

// mfaConn is a held connection to the broker.
type mfaConn struct {
	c  *tls.Conn
	br *bufio.Reader
}

func (c *mfaConn) exporter(t *testing.T) []byte {
	t.Helper()
	cs := c.c.ConnectionState()
	ekm, err := cs.ExportKeyingMaterial(api.MFAExporterLabel, nil, 32)
	if err != nil {
		t.Fatal(err)
	}
	return ekm
}

// post writes one POST on the held connection and reads its answer.
func (c *mfaConn) post(t *testing.T, path string, hdr map[string]string, body string) (int, []byte) {
	t.Helper()
	var h strings.Builder
	for k, v := range hdr {
		fmt.Fprintf(&h, "%s: %s\r\n", k, v)
	}
	if _, err := fmt.Fprintf(c.c, "POST %s HTTP/1.1\r\nHost: broker\r\nContent-Type: application/json\r\n%sContent-Length: %d\r\n\r\n%s",
		path, h.String(), len(body), body); err != nil {
		t.Fatal(err)
	}
	_ = c.c.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(c.br, nil)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, raw
}

// mfaActor is a person (or workload) with a held connection and a token: a
// touch key and its attestations, from the one test device certificate.
type mfaActor struct {
	cert     tls.Certificate
	conn     *mfaConn
	agent    string
	touchKey *ecdsa.PrivateKey
	atts     [][]byte
}

type mfaFixture struct {
	*fixture
	clock       mfaClock
	minterClock *stepClock // the minter's clock
	store       *failStore
	addr        string
	iss         *oidctest.Issuer

	root      *testpki.CA
	inter     *testpki.CA
	device    *x509.Certificate
	deviceKey *ecdsa.PrivateKey

	alice, bob, aliceOtherCert, oxidized *mfaActor
	otherAgent                           string

	// alice's token, and another token's touch key with attestations that
	// pair its touch slot with alice's session slot.
	touchKey               *ecdsa.PrivateKey
	attestations           [][]byte
	otherTokenTouchKey     *ecdsa.PrivateKey
	otherTokenAttestations [][]byte

	logs *lockedBuffer
	opts mfaOpts // the options the fixture was made with, for a policy reload
}

func newAgentSession() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func newMFAFixture(t *testing.T, opts ...mfaOpt) *mfaFixture {
	t.Helper()
	var o mfaOpts
	for _, opt := range opts {
		opt(&o)
	}
	devs := []admission.Device{
		{Name: "core-sw01", Platform: "arista_eos", Addresses: []netip.Addr{netip.MustParseAddr("172.100.100.51")}},
		{Name: "edge-sw01", Platform: "arista_eos", Addresses: []netip.Addr{netip.MustParseAddr("172.100.100.52")}},
	}
	if o.junosCore {
		devs[0].Platform = "juniper_junos"
	}
	base := newFixtureWith(t, 16, mfaPolicy(o), devs...)
	f := &mfaFixture{fixture: base, clock: mfaClock{base}, otherAgent: newAgentSession(), logs: &lockedBuffer{}, opts: o}
	f.b.Log = decision.NewJSONLines(f.logs)
	f.minterClock = &stepClock{base: f.b.Now}
	f.b.Minter = token.NewMinter(f.st, f.b.Log, rand.Reader, token.TagKey([]byte("k")), f.minterClock.Now, 16)
	f.store = &failStore{Store: f.st}
	f.b.Store = f.store
	f.iss = f.withOIDC(t)
	wca := f.withWorkload(t)

	// The attestation PKI: a root, perhaps an intermediate, a device (f9).
	var err error
	if f.root, err = testpki.NewCA("Yubico PIV Root", f.now.Add(-time.Hour), f.now.Add(48*time.Hour)); err != nil {
		t.Fatal(err)
	}
	parent, parentKey := f.root.Cert, f.root.Key
	roots := f.root.PEM()
	if o.intermediate {
		if f.inter, err = f.root.IssueCA("Yubico PIV Intermediate", f.now.Add(-time.Hour), f.now.Add(48*time.Hour)); err != nil {
			t.Fatal(err)
		}
		parent, parentKey = f.inter.Cert, f.inter.Key
		if o.listInter {
			roots = append(roots, f.inter.PEM()...)
		}
	}
	f.device, f.deviceKey = f.deviceCert(t, parent, parentKey)
	if o.noRoots {
		f.b.PerLoginMFA = &MFAVerifiers{}
	} else {
		anchors, err := pivattest.ParseAnchors(roots)
		if err != nil {
			t.Fatal(err)
		}
		f.b.PerLoginMFA = &MFAVerifiers{Anchors: &anchors}
	}

	f.addr, _ = serveThroughWith(t, base, ListenerLimits{MaxPendingPerSource: 16, MaxPerPrincipal: 8,
		HandshakeTimeout: 10 * time.Second}, nil, f.b.Wire)
	f.alice = f.actor(t, f.fixture.alice, true)
	f.bob = f.actor(t, f.client(t, "bob@example.com", f.now.Add(24*time.Hour)), true)
	f.aliceOtherCert = f.actor(t, f.client(t, "alice@example.com", f.now.Add(24*time.Hour)), true)
	f.oxidized = f.actor(t, f.workloadCert(t, wca, workloadID), false)
	f.touchKey, f.attestations = f.alice.touchKey, f.alice.atts

	other, otherKey := f.deviceCert(t, parent, parentKey)
	f.otherTokenTouchKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	f.otherTokenAttestations = [][]byte{
		f.slotCert(t, other, otherKey, &f.otherTokenTouchKey.PublicKey, pivattest.TouchAlways),
		other.Raw,
		f.alice.atts[2], // alice's session slot, attested by her own device
	}
	return f
}

// deviceCert is a device (f9) certificate with no basic constraints, as some
// YubiKeys' are, under parent.
func (f *mfaFixture) deviceCert(t *testing.T, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:   pkix.Name{CommonName: "YubiKey PIV Attestation F9"},
		NotBefore: f.now.Add(-time.Hour), NotAfter: f.now.Add(48 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c, key
}

// slotCert is the attestation certificate of a slot key pub, signed by the
// device, with the touch policy byte given.
func (f *mfaFixture) slotCert(t *testing.T, device *x509.Certificate, deviceKey *ecdsa.PrivateKey, pub crypto.PublicKey, touch byte) []byte {
	t.Helper()
	return f.slotCertSerial(t, device, deviceKey, pub, touch, 12345678)
}

// slotCertSerial is slotCert naming the device serial given.
func (f *mfaFixture) slotCertSerial(t *testing.T, device *x509.Certificate, deviceKey *ecdsa.PrivateKey, pub crypto.PublicKey, touch byte, deviceSerial int64) []byte {
	t.Helper()
	serial, err := asn1.Marshal(big.NewInt(deviceSerial))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "YubiKey PIV Attestation"},
		NotBefore: f.now.Add(-time.Hour), NotAfter: f.now.Add(24 * time.Hour),
		ExtraExtensions: []pkix.Extension{{Id: testOIDSerial, Value: serial},
			{Id: testOIDPolicy, Value: []byte{pivattest.PINOnce, touch}}}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, device, pub, deviceKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// newToken is a token whose session key is sess: a touch key with the touch
// policy given, and the attestations [touch slot, f9 device, session slot].
func (f *mfaFixture) newToken(t *testing.T, sess crypto.PublicKey, touch byte) (*ecdsa.PrivateKey, [][]byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key, [][]byte{f.slotCert(t, f.device, f.deviceKey, &key.PublicKey, touch), f.device.Raw,
		f.slotCert(t, f.device, f.deviceKey, sess, pivattest.TouchNever)}
}

func (f *mfaFixture) dialCert(t *testing.T, cert tls.Certificate) *mfaConn {
	t.Helper()
	c, err := tls.Dial("tcp", f.addr, &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: f.ca.Pool(),
		MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return &mfaConn{c: c, br: bufio.NewReader(c)}
}

// dial is another held connection of who's certificate.
func (f *mfaFixture) dial(t *testing.T, who *mfaActor) *mfaConn { return f.dialCert(t, who.cert) }

func (f *mfaFixture) actor(t *testing.T, cert tls.Certificate, agent bool) *mfaActor {
	t.Helper()
	a := &mfaActor{cert: cert, conn: f.dialCert(t, cert)}
	if agent {
		a.agent = newAgentSession()
	}
	a.touchKey, a.atts = f.newToken(t, cert.PrivateKey.(crypto.Signer).Public(), pivattest.TouchAlways)
	return a
}

type mfaResp struct{ api.MintResponse }

func (r mfaResp) find(device string) api.MintItem {
	for _, it := range r.Results {
		if it.Device == device {
			return it
		}
	}
	return api.MintItem{}
}

func (f *mfaFixture) mintWith(t *testing.T, who *mfaActor, agent, key, challenge string, devices ...string) mfaResp {
	t.Helper()
	body, err := json.Marshal(api.MintRequest{Devices: devices, Purpose: "test", PerLoginMFAChallenge: challenge})
	if err != nil {
		t.Fatal(err)
	}
	hdr := map[string]string{}
	if agent != "" {
		hdr[api.AgentSessionHeader] = agent
	}
	if key != "" {
		hdr["Idempotency-Key"] = key
	}
	code, raw := who.conn.post(t, "/v1/tokens", hdr, string(body))
	if code != 200 {
		t.Fatalf("POST /v1/tokens = %d %s", code, raw)
	}
	var r mfaResp
	if err := json.Unmarshal(raw, &r.MintResponse); err != nil {
		t.Fatal(err)
	}
	return r
}

func (f *mfaFixture) mint(t *testing.T, who *mfaActor, device, challenge string) mfaResp {
	t.Helper()
	return f.mintWith(t, who, who.agent, "", challenge, device)
}

func (f *mfaFixture) mintAs(t *testing.T, who *mfaActor, agent, device, challenge string) mfaResp {
	t.Helper()
	return f.mintWith(t, who, agent, "", challenge, device)
}

func (f *mfaFixture) mintWithKey(t *testing.T, who *mfaActor, device, challenge, key string) mfaResp {
	t.Helper()
	return f.mintWith(t, who, who.agent, key, challenge, device)
}

func (f *mfaFixture) mintMany(t *testing.T, who *mfaActor, devices ...string) mfaResp {
	t.Helper()
	return f.mintWith(t, who, who.agent, "", "", devices...)
}

// ask mints for the first time and returns the challenge it was given.
func (f *mfaFixture) ask(t *testing.T, who *mfaActor, device string) string {
	t.Helper()
	it := f.mint(t, who, device, "").Results[0]
	if it.PerLoginMFA == nil {
		t.Fatalf("no challenge: %+v", it)
	}
	return it.PerLoginMFA.Challenge
}

func mfaChallengeBytes(t *testing.T, ch string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(ch)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// touchSign is alice's touch key signing the challenge over an exporter value.
func (f *mfaFixture) touchSign(t *testing.T, ch string, ekm []byte) []byte {
	t.Helper()
	return f.signWith(t, f.touchKey, ch, ekm)
}

func (f *mfaFixture) signWith(t *testing.T, key *ecdsa.PrivateKey, ch string, ekm []byte) []byte {
	t.Helper()
	sig, err := api.SignRefresh(key, api.MFAMessage(mfaChallengeBytes(t, ch), ekm))
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func (f *mfaFixture) touchBody(ch string, sig []byte, atts [][]byte) string {
	req := api.MFAProofRequest{Challenge: ch, Method: "hardware_key_touch",
		Signature: base64.RawURLEncoding.EncodeToString(sig)}
	for _, a := range atts {
		req.Attestation = append(req.Attestation, base64.RawURLEncoding.EncodeToString(a))
	}
	b, _ := json.Marshal(req)
	return string(b)
}

func (f *mfaFixture) postTouchAs(t *testing.T, c *mfaConn, agent, ch string, sig []byte, atts [][]byte) (int, string) {
	t.Helper()
	hdr := map[string]string{}
	if agent != "" {
		hdr[api.AgentSessionHeader] = agent
	}
	code, raw := c.post(t, "/v1/mfa", hdr, f.touchBody(ch, sig, atts))
	return code, string(raw)
}

// postTouch is a touch post by alice's agent on c.
func (f *mfaFixture) postTouch(t *testing.T, c *mfaConn, ch string, sig []byte, atts [][]byte) int {
	t.Helper()
	code, _ := f.postTouchAs(t, c, f.alice.agent, ch, sig, atts)
	return code
}

func (f *mfaFixture) proveTouchWith(t *testing.T, who *mfaActor, ch string, key *ecdsa.PrivateKey, atts [][]byte) int {
	t.Helper()
	code, _ := f.proveTouchDetail(t, who, ch, key, atts)
	return code
}

func (f *mfaFixture) proveTouchDetail(t *testing.T, who *mfaActor, ch string, key *ecdsa.PrivateKey, atts [][]byte) (int, string) {
	t.Helper()
	return f.postTouchAs(t, who.conn, who.agent, ch, f.signWith(t, key, ch, who.conn.exporter(t)), atts)
}

func (f *mfaFixture) proveTouch(t *testing.T, who *mfaActor, ch string) int {
	t.Helper()
	return f.proveTouchWith(t, who, ch, who.touchKey, who.atts)
}

type idTokenOpts struct {
	principal string
	nonceFor  string
	amr       []string
	authTime  time.Time
	issuedAt  time.Time // zero: now
}

// idToken is a human ID token whose nonce binds nonceFor, a challenge as the
// API spells it (anything else is bound as its bytes).
func (f *mfaFixture) idToken(t *testing.T, o idTokenOpts) string {
	t.Helper()
	ch, err := base64.RawURLEncoding.DecodeString(o.nonceFor)
	if err != nil || len(ch) != api.MFAChallengeLen {
		ch = []byte(o.nonceFor)
	}
	claims := map[string]any{
		"preferred_username": o.principal, "amr": o.amr, "nonce": api.MFANonce(ch), "auth_time": o.authTime.Unix()}
	if !o.issuedAt.IsZero() {
		claims["iat"] = o.issuedAt.Unix()
	}
	return f.iss.IDToken(t, "k1", testClientID, "sub-"+o.principal, f.b.Now(), claims)
}

func (f *mfaFixture) proveIdP(t *testing.T, tok, ch string) int {
	t.Helper()
	code, _ := f.proveIdPDetail(t, tok, ch)
	return code
}

// proveIdPDetail is proveIdP with the response body, which names the cause.
func (f *mfaFixture) proveIdPDetail(t *testing.T, tok, ch string) (int, string) {
	t.Helper()
	body, _ := json.Marshal(api.MFAProofRequest{Challenge: ch, Method: "idp_mfa"})
	w := f.bearer(context.Background(), "POST", "/v1/mfa", string(body), tok)
	return w.Code, w.Body.String()
}

func (f *mfaFixture) recs(t *testing.T) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(f.logs.String()), "\n") {
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

// find is the last record of event with verdict and reason.
func (f *mfaFixture) find(t *testing.T, event, verdict, reason string) map[string]any {
	t.Helper()
	recs := f.recs(t)
	for i := len(recs) - 1; i >= 0; i-- {
		r := recs[i]
		if r["event"] == event && r["verdict"] == verdict && r["reason"] == reason {
			return r
		}
	}
	return nil
}

func (f *mfaFixture) assertRecord(t *testing.T, event, verdict, reason string) {
	t.Helper()
	if f.find(t, event, verdict, reason) == nil {
		t.Fatalf("no %s %s %s record in\n%s", event, verdict, reason, f.logs.String())
	}
}

func (f *mfaFixture) assertNoRecord(t *testing.T, event, verdict, reason string) {
	t.Helper()
	if r := f.find(t, event, verdict, reason); r != nil {
		t.Fatalf("a %s %s %s record exists: %v", event, verdict, reason, r)
	}
}

// assertMintRecordMFA wants the last mint permit record to carry the proof's
// method and whether it was reused.
func (f *mfaFixture) assertMintRecordMFA(t *testing.T, method string, reused bool) {
	t.Helper()
	r := f.find(t, "mint", "permit", "grants_matched")
	if r == nil {
		t.Fatalf("no mint permit record in\n%s", f.logs.String())
	}
	m, _ := r["per_login_mfa"].(map[string]any)
	if m == nil || m["method"] != method || (m["reused"] == true) != reused || m["proved_at"] == nil ||
		m["levels"] == nil || m["accept"] == nil || m["reuse_for_seconds"] == nil {
		t.Fatalf("mint record per_login_mfa = %v, want method %s reused %v", r["per_login_mfa"], method, reused)
	}
}

func (f *mfaFixture) assertNoToken(t *testing.T, device string) {
	t.Helper()
	cands, err := f.st.Candidates(context.Background(), store.TokenKey{NAS: device, Username: "alice"})
	if err != nil || len(cands) != 0 {
		t.Fatalf("%d tokens for alice on %s (%v), want none", len(cands), device, err)
	}
}

func (f *mfaFixture) assertLogHasNone(t *testing.T, secrets ...string) {
	t.Helper()
	log := f.logs.String()
	for _, s := range secrets {
		if s != "" && strings.Contains(log, s) {
			t.Fatalf("the decision log carries %q", s)
		}
	}
}

func TestAMintUnderARequirementAsksForAProof(t *testing.T) {
	f := newMFAFixture(t)
	resp := f.mint(t, f.alice, "core-sw01", "")
	it := resp.Results[0]
	if it.Verdict != "deny" || it.Reason != "per_login_mfa_required" || it.PerLoginMFA == nil {
		t.Fatalf("item = %+v", it)
	}
	m := it.PerLoginMFA
	if m.Device != "core-sw01" || len(m.Challenge) == 0 || !slices.Equal(m.Methods, []string{"hardware_key_touch", "idp_mfa"}) ||
		m.ReuseForSeconds != 900 || m.Levels[0].Level != "scope core" {
		t.Fatalf("requirement = %+v", m)
	}
	if !strings.Contains(it.Detail, "core-sw01 asks for a second factor at each login: scope core accepts hardware_key_touch, idp_mfa") {
		t.Fatalf("detail = %q", it.Detail)
	}
	f.assertRecord(t, "mint", "deny", "per_login_mfa_required")
	// Nothing was minted.
	f.assertNoToken(t, "core-sw01")
	// The record names the requirement and never the challenge.
	r := f.find(t, "mint", "deny", "per_login_mfa_required")
	if rm, _ := r["per_login_mfa"].(map[string]any); rm == nil || rm["accept"] == nil || rm["levels"] == nil ||
		rm["challenge_sha256"] != nil {
		t.Fatalf("record per_login_mfa = %v", r["per_login_mfa"])
	}
	f.assertLogHasNone(t, m.Challenge)
	// edge-sw01 has no requirement.
	if it := f.mint(t, f.alice, "edge-sw01", "").Results[0]; it.Verdict != "permit" || it.PerLoginMFA != nil {
		t.Fatalf("edge-sw01 = %+v", it)
	}
	// One challenge per request: two items under the requirement share it.
	// (core-sw01 alone is under one here; the batch case is below.)
}

func TestATouchProofCoversTheRetriedMintAndThenReuses(t *testing.T) {
	f := newMFAFixture(t)
	ch := f.ask(t, f.alice, "core-sw01")
	if code := f.proveTouch(t, f.alice, ch); code != 200 {
		t.Fatalf("POST /v1/mfa = %d", code)
	}
	f.assertRecord(t, "per_login_mfa", "permit", "per_login_mfa_proved")
	r := f.find(t, "per_login_mfa", "permit", "per_login_mfa_proved")
	sum := sha256.Sum256(mfaChallengeBytes(t, ch))
	if pm, _ := r["per_login_mfa"].(map[string]any); pm == nil || pm["method"] != "hardware_key_touch" ||
		pm["challenge_sha256"] != hex.EncodeToString(sum[:]) || r["principal"] != alicePrincipal {
		t.Fatalf("proof record = %v", r)
	}
	it := f.mint(t, f.alice, "core-sw01", ch).Results[0]
	if it.Verdict != "permit" {
		t.Fatalf("retried mint = %+v", it)
	}
	f.assertMintRecordMFA(t, "hardware_key_touch", false)
	// A second login within reuse_for, no challenge named: reused.
	f.clock.Advance(10 * time.Minute)
	if it := f.mint(t, f.alice, "core-sw01", "").Results[0]; it.Verdict != "permit" {
		t.Fatalf("mint within reuse_for = %+v", it)
	}
	f.assertMintRecordMFA(t, "hardware_key_touch", true)
	// Another agent session of the same person is asked, inside reuse_for.
	if it := f.mintAs(t, f.alice, f.otherAgent, "core-sw01", "").Results[0]; it.Reason != "per_login_mfa_required" {
		t.Fatalf("another agent = %+v", it)
	}
	// A caller with no agent session keeps no reusable proof either.
	if it := f.mintAs(t, f.alice, "", "core-sw01", "").Results[0]; it.Reason != "per_login_mfa_required" {
		t.Fatalf("no agent session = %+v", it)
	}
	// Past reuse_for: asked again.
	f.clock.Advance(6 * time.Minute)
	if it := f.mint(t, f.alice, "core-sw01", "").Results[0]; it.Reason != "per_login_mfa_required" {
		t.Fatalf("mint past reuse_for = %+v", it)
	}
	// Neither the challenge nor the agent session is ever logged.
	f.assertLogHasNone(t, ch, f.alice.agent, f.otherAgent)
}

func TestReuseForZeroCoversOnlyItsOwnRequest(t *testing.T) {
	f := newMFAFixture(t, withReuseFor(0))
	ch := f.ask(t, f.alice, "core-sw01")
	if code := f.proveTouch(t, f.alice, ch); code != 200 {
		t.Fatalf("POST /v1/mfa = %d", code)
	}
	if it := f.mint(t, f.alice, "core-sw01", ch).Results[0]; it.Verdict != "permit" {
		t.Fatalf("the retried mint naming the challenge = %+v", it)
	}
	f.clock.Advance(time.Second)
	if it := f.mint(t, f.alice, "core-sw01", "").Results[0]; it.Reason != "per_login_mfa_required" {
		t.Fatalf("a second mint a second later = %+v", it)
	}
	if it := f.mint(t, f.alice, "core-sw01", ch).Results[0]; it.Reason != "per_login_mfa_required" {
		t.Fatalf("the challenge named twice = %+v", it)
	}
}

func TestATouchFromAnotherTokenIsRefused(t *testing.T) {
	f := newMFAFixture(t)
	ch := f.ask(t, f.alice, "core-sw01")
	// The touch slot's attestation comes from another device certificate
	// than the session key's: an attacker's own YubiKey beside a copied
	// session key.
	if code := f.proveTouchWith(t, f.alice, ch, f.otherTokenTouchKey, f.otherTokenAttestations); code != 401 {
		t.Fatalf("POST /v1/mfa = %d, want 401", code)
	}
	f.assertRecord(t, "per_login_mfa", "deny", "per_login_mfa_refused")
	// Nothing was proved: the mint is asked again.
	if it := f.mint(t, f.alice, "core-sw01", ch).Results[0]; it.Reason != "per_login_mfa_required" {
		t.Fatalf("mint after a refused proof = %+v", it)
	}
}

func TestATouchSlotNotAlwaysIsRefused(t *testing.T) {
	f := newMFAFixture(t)
	for name, policy := range map[string]byte{"cached": pivattest.TouchCached, "never": pivattest.TouchNever} {
		ch := f.ask(t, f.alice, "core-sw01")
		key, atts := f.newToken(t, f.alice.cert.PrivateKey.(crypto.Signer).Public(), policy)
		code, detail := f.proveTouchDetail(t, f.alice, ch, key, atts)
		if code != 401 || !strings.Contains(detail, "touch policy always") {
			t.Fatalf("touch policy %s: %d %s, want 401 naming \"touch policy always\"", name, code, detail)
		}
	}
	f.assertRecord(t, "per_login_mfa", "deny", "per_login_mfa_refused")
	// The control: the same token with an always-touch slot proves.
	ch := f.ask(t, f.alice, "core-sw01")
	key, atts := f.newToken(t, f.alice.cert.PrivateKey.(crypto.Signer).Public(), pivattest.TouchAlways)
	if code := f.proveTouchWith(t, f.alice, ch, key, atts); code != 200 {
		t.Fatalf("the control: %d, want 200", code)
	}
}

// A certificate in the request is never an intermediate: the roots file is
// the operator's alone.
func TestARequestSuppliedIntermediateIsNeverTrusted(t *testing.T) {
	f := newMFAFixture(t, withDeviceUnderIntermediate(false))
	ch := f.ask(t, f.alice, "core-sw01")
	if code := f.proveTouch(t, f.alice, ch); code != 401 {
		t.Fatalf("a device under an intermediate the operator did not list: %d, want 401", code)
	}
	ch = f.ask(t, f.alice, "core-sw01")
	atts := append(slices.Clone(f.alice.atts), f.inter.Cert.Raw)
	if code := f.proveTouchWith(t, f.alice, ch, f.alice.touchKey, atts); code != 401 {
		t.Fatalf("the intermediate supplied in the request: %d, want 401", code)
	}
	atts = [][]byte{f.alice.atts[0], f.inter.Cert.Raw, f.alice.atts[2]}
	ch = f.ask(t, f.alice, "core-sw01")
	if code := f.proveTouchWith(t, f.alice, ch, f.alice.touchKey, atts); code != 401 {
		t.Fatalf("the intermediate supplied as the device certificate: %d, want 401", code)
	}
	// The control: the operator lists the intermediate.
	g := newMFAFixture(t, withDeviceUnderIntermediate(true))
	if code := g.proveTouch(t, g.alice, g.ask(t, g.alice, "core-sw01")); code != 200 {
		t.Fatalf("with the intermediate in the roots file: %d, want 200", code)
	}
}

func TestATouchProofIsBoundToItsConnection(t *testing.T) {
	f := newMFAFixture(t)
	ch := f.ask(t, f.alice, "core-sw01")
	// Signed over the exporter value of alice's other connection (a second
	// held connection of the same agent), posted on this one.
	other := f.dial(t, f.alice)
	sig := f.touchSign(t, ch, other.exporter(t))
	if code := f.postTouch(t, f.alice.conn, ch, sig, f.attestations); code != 401 {
		t.Fatalf("a signature over another connection's exporter value: %d, want 401", code)
	}
	f.assertRecord(t, "per_login_mfa", "deny", "per_login_mfa_refused")
	// The same signature posted on the connection it was made for verifies:
	// the refusal was the binding, not the signature.
	ch2 := f.ask(t, f.alice, "core-sw01")
	if code := f.postTouch(t, other, ch2, f.touchSign(t, ch2, other.exporter(t)), f.attestations); code != 200 {
		t.Fatalf("the control: %d, want 200", code)
	}
}

func TestAChallengeIsUsedOnce(t *testing.T) {
	f := newMFAFixture(t)
	ch := f.ask(t, f.alice, "core-sw01")
	// bob proves alice's challenge on his own connection: refused, and the
	// challenge is not spent by it.
	if code := f.proveTouch(t, f.bob, ch); code != 401 {
		t.Fatalf("bob proving alice's challenge: %d, want 401", code)
	}
	if code := f.proveTouch(t, f.alice, ch); code != 200 {
		t.Fatalf("alice after bob's attempt: %d, want 200 (bob must not spend it)", code)
	}
	if code := f.proveTouch(t, f.alice, ch); code != 401 {
		t.Fatalf("the same challenge proved twice: %d, want 401", code)
	}
	// A proved challenge named by another caller's mint covers nothing:
	// bob's mint, and alice's under another certificate (pre-flight minor 11).
	if it := f.mint(t, f.bob, "core-sw01", ch).Results[0]; it.Reason != "per_login_mfa_required" {
		t.Fatalf("bob's mint naming alice's proved challenge = %+v", it)
	}
	if it := f.mint(t, f.aliceOtherCert, "core-sw01", ch).Results[0]; it.Reason != "per_login_mfa_required" {
		t.Fatalf("alice's mint under another certificate naming the challenge = %+v", it)
	}
	if it := f.mint(t, f.alice, "core-sw01", ch).Results[0]; it.Verdict != "permit" {
		t.Fatalf("alice's own mint naming it = %+v (the other callers must not have spent it)", it)
	}
}

// A store that fails while a requirement is judged is store_unavailable for
// the item, never a challenge that was not stored (pre-flight minor 1).
func TestAStoreErrorIsNotARefusedProof(t *testing.T) {
	f := newMFAFixture(t)
	f.store.failOn("PutOnce", "GetMFAProof")
	it := f.mint(t, f.alice, "core-sw01", "").Results[0]
	if it.Verdict != "deny" || it.Reason != "store_unavailable" || it.PerLoginMFA != nil {
		t.Fatalf("mint with the store failing = %+v", it)
	}
	f.assertNoRecord(t, "per_login_mfa", "deny", "per_login_mfa_refused")
	f.assertNoRecord(t, "mint", "deny", "per_login_mfa_required")
	// Each failing call alone is the same.
	for _, one := range []string{"PutOnce", "GetMFAProof"} {
		f.store.failOn(one)
		if it := f.mint(t, f.alice, "core-sw01", "").Results[0]; it.Reason != "store_unavailable" || it.PerLoginMFA != nil {
			t.Fatalf("mint with only %s failing = %+v", one, it)
		}
	}
	// The store back: the mint asks for a proof as before.
	f.store.failOn()
	if it := f.mint(t, f.alice, "core-sw01", "").Results[0]; it.Reason != "per_login_mfa_required" {
		t.Fatalf("mint with the store back = %+v", it)
	}
}

// A proof the broker could not judge is store_unavailable, and the challenge
// is not blamed on the person.
func TestAStoreErrorWhileProvingIsStoreUnavailable(t *testing.T) {
	f := newMFAFixture(t)
	ch := f.ask(t, f.alice, "core-sw01")
	f.store.failOn("TakeOnce")
	if code := f.proveTouch(t, f.alice, ch); code != 503 {
		t.Fatalf("POST /v1/mfa with the store failing = %d, want 503", code)
	}
	f.assertRecord(t, "per_login_mfa", "deny", "store_unavailable")
	f.assertNoRecord(t, "per_login_mfa", "deny", "per_login_mfa_refused")
	f.store.failOn()
	if code := f.proveTouch(t, f.alice, ch); code != 200 {
		t.Fatalf("the proof after the store is back = %d, want 200 (the failed take spent nothing)", code)
	}
}

// A retried request whose answer was lost replays the token it minted, even
// though the proof that covered it is spent (pre-flight minor 2).
func TestAReplayedMintUnderReuseZeroIsReplayed(t *testing.T) {
	f := newMFAFixture(t, withReuseFor(0))
	ch := f.ask(t, f.alice, "core-sw01")
	if code := f.proveTouch(t, f.alice, ch); code != 200 {
		t.Fatalf("POST /v1/mfa = %d", code)
	}
	first := f.mintWithKey(t, f.alice, "core-sw01", ch, "idem-1")
	again := f.mintWithKey(t, f.alice, "core-sw01", ch, "idem-1")
	if first.Results[0].Verdict != "permit" || !reflect.DeepEqual(first, again) {
		t.Fatalf("replay = %+v, want the first answer %+v", again, first)
	}
}

// The broker decides replay-versus-fresh once. A replay that lapses between
// that decision and the mint (the clock crosses the first token's session
// ceiling) is not minted afresh under the requirement it skipped: the
// requirement is judged, and with no proof, asked.
func TestAReplayThatLapsesBeforeTheMintIsNotMintedWithoutAProof(t *testing.T) {
	f := newMFAFixture(t, withReuseFor(0), withShortCeiling())
	ceiling := f.clock.Now().Add(time.Hour) // alice's connection authenticated now
	// Minted half a minute before the ceiling, the token (60s) and the
	// idempotency record that replays it both end at the ceiling.
	f.clock.Advance(59*time.Minute + 30*time.Second)
	ch := f.ask(t, f.alice, "core-sw01")
	if code := f.proveTouch(t, f.alice, ch); code != 200 {
		t.Fatalf("POST /v1/mfa = %d", code)
	}
	if it := f.mintWithKey(t, f.alice, "core-sw01", ch, "idem-1").Results[0]; it.Verdict != "permit" ||
		it.SessionExpiresAt != ceiling.UTC().Format(time.RFC3339) {
		t.Fatalf("the first mint = %+v", it)
	}
	// A retry on a connection that authenticated later: its own ceiling is
	// far off, while the first token's passes between the minter's reads.
	// The minter reads its clock Reserve, Replays, the ceiling check, then
	// the replay inside Mint. Starting two seconds before the ceiling, the
	// second read is before it and the fourth is after it.
	f.clock.Advance(10 * time.Second)
	retry := f.actor(t, f.alice.cert, true)
	f.minterClock.arm(ceiling.Add(-2*time.Second), time.Second)
	it := f.mintWithKey(t, retry, "core-sw01", ch, "idem-1").Results[0]
	if it.Verdict != "deny" || it.Reason != "per_login_mfa_required" || it.PerLoginMFA == nil {
		t.Fatalf("a replay that lapsed at the mint = %+v, want asked for a proof", it)
	}
	permits := 0
	for _, r := range f.recs(t) {
		if r["event"] == "mint" && r["verdict"] == "permit" {
			permits++
		}
	}
	if permits != 1 {
		t.Fatalf("%d mint permit records, want only the first", permits)
	}
}

// The same lapse, when a proof still covers the retry (reuse_for > 0, same
// agent session): the requirement is judged after the lapse, found covered,
// and the mint is made afresh, with its own permit record naming the proof's
// method.
func TestAReplayThatLapsesIsMintedAfreshWhenAProofCoversIt(t *testing.T) {
	f := newMFAFixture(t, withShortCeiling())
	ceiling := f.clock.Now().Add(time.Hour)
	f.clock.Advance(59*time.Minute + 30*time.Second)
	ch := f.ask(t, f.alice, "core-sw01")
	if code := f.proveTouch(t, f.alice, ch); code != 200 {
		t.Fatalf("POST /v1/mfa = %d", code)
	}
	if it := f.mintWithKey(t, f.alice, "core-sw01", ch, "idem-1").Results[0]; it.Verdict != "permit" {
		t.Fatalf("the first mint = %+v", it)
	}
	f.clock.Advance(10 * time.Second)
	retry := f.actor(t, f.alice.cert, true)
	retry.agent = f.alice.agent
	// As in the test above: the second minter read is before the ceiling and
	// the fourth is after it, so the replay lapses at the mint.
	f.minterClock.arm(ceiling.Add(-2*time.Second), time.Second)
	it := f.mintWithKey(t, retry, "core-sw01", ch, "idem-1").Results[0]
	if it.Verdict != "permit" {
		t.Fatalf("a replay that lapsed under a covering proof = %+v, want a fresh permit", it)
	}
	permits := 0
	for _, r := range f.recs(t) {
		if r["event"] == "mint" && r["verdict"] == "permit" {
			permits++
		}
	}
	if permits != 2 {
		t.Fatalf("%d mint permit records, want the first and the fresh one", permits)
	}
	f.assertMintRecordMFA(t, "hardware_key_touch", true)
}

// An attacker's own token, with a full chain of its own (touch slot, f9,
// session slot), posted on someone else's held connection: every chain and
// same-device check passes, and only the session slot's key not being this
// connection's client key refuses it.
func TestAnAttackersOwnTokenOnAnotherConnectionIsRefused(t *testing.T) {
	f := newMFAFixture(t)
	ch := f.ask(t, f.alice, "core-sw01")
	attackerSession, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// The attacker's chain is its own: its own f9 under the root, its own
	// device serial, its own touch key and session key.
	device, deviceKey := f.deviceCert(t, f.root.Cert, f.root.Key)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const attackerSerial = 99999999
	atts := [][]byte{
		f.slotCertSerial(t, device, deviceKey, &key.PublicKey, pivattest.TouchAlways, attackerSerial),
		device.Raw,
		f.slotCertSerial(t, device, deviceKey, &attackerSession.PublicKey, pivattest.TouchNever, attackerSerial)}
	code, detail := f.proveTouchDetail(t, f.alice, ch, key, atts)
	if code != 401 || !strings.Contains(detail, "not this connection's client key") {
		t.Fatalf("an attacker's token on alice's connection: %d %s, want 401 naming the client key", code, detail)
	}
	f.assertRecord(t, "per_login_mfa", "deny", "per_login_mfa_refused")
	if it := f.mint(t, f.alice, "core-sw01", ch).Results[0]; it.Reason != "per_login_mfa_required" {
		t.Fatalf("mint after the refused proof = %+v", it)
	}
}

// The touch slot and the session slot are attested by one device: slot
// certificates that carry two serials are not one token.
func TestATouchAndSessionSlotsOfTwoSerialsAreRefused(t *testing.T) {
	f := newMFAFixture(t)
	ch := f.ask(t, f.alice, "core-sw01")
	atts := slices.Clone(f.alice.atts)
	atts[2] = f.slotCertSerial(t, f.device, f.deviceKey, f.alice.cert.PrivateKey.(crypto.Signer).Public(),
		pivattest.TouchNever, 87654321)
	code, detail := f.proveTouchDetail(t, f.alice, ch, f.alice.touchKey, atts)
	if code != 401 || !strings.Contains(detail, "not attested by the same device") {
		t.Fatalf("two serials: %d %s, want 401 naming the same device", code, detail)
	}
}

// The challenge is bound to the certificate and the agent session it was
// issued to: a valid touch from another certificate of the same person, or
// from another agent session, is refused on that binding alone.
func TestATouchIsBoundToTheCertificateAndAgentTheChallengeWasIssuedTo(t *testing.T) {
	f := newMFAFixture(t)
	const want = "not from the certificate and agent session"
	ch := f.ask(t, f.alice, "core-sw01")
	sig := f.signWith(t, f.aliceOtherCert.touchKey, ch, f.aliceOtherCert.conn.exporter(t))
	if code, detail := f.postTouchAs(t, f.aliceOtherCert.conn, f.alice.agent, ch, sig, f.aliceOtherCert.atts); code != 401 ||
		!strings.Contains(detail, want) {
		t.Fatalf("another certificate of alice's: %d %s, want 401 naming the binding", code, detail)
	}
	ch = f.ask(t, f.alice, "core-sw01")
	if code, detail := f.postTouchAs(t, f.alice.conn, f.otherAgent, ch, f.touchSign(t, ch, f.alice.conn.exporter(t)),
		f.alice.atts); code != 401 || !strings.Contains(detail, want) {
		t.Fatalf("another agent session: %d %s, want 401 naming the binding", code, detail)
	}
}

// A store error while judging a requirement is store_unavailable for that
// item, and its record still names the requirement (decision 45 ruling 19).
func TestAStoreUnavailableMintRecordCarriesTheRequirement(t *testing.T) {
	for _, c := range []struct {
		fail  string
		named bool
	}{{"TakeOnce", true}, {"GetMFAProof", false}, {"PutOnce", false}} {
		f := newMFAFixture(t)
		ch := ""
		if c.named {
			ch = f.ask(t, f.alice, "core-sw01")
		}
		f.store.failOn(c.fail)
		if it := f.mint(t, f.alice, "core-sw01", ch).Results[0]; it.Reason != "store_unavailable" {
			t.Fatalf("%s failing: %+v, want store_unavailable", c.fail, it)
		}
		r := f.find(t, "mint", "deny", "store_unavailable")
		if r == nil {
			t.Fatalf("%s failing: no store_unavailable mint record in\n%s", c.fail, f.logs.String())
		}
		if m, _ := r["per_login_mfa"].(map[string]any); m == nil || m["accept"] == nil || m["levels"] == nil ||
			m["reuse_for_seconds"] == nil {
			t.Errorf("%s failing: record per_login_mfa = %v, want the requirement", c.fail, r["per_login_mfa"])
		}
	}
}

func TestAnIdPProofCoversTheMint(t *testing.T) {
	f := newMFAFixture(t)
	ch := f.ask(t, f.alice, "core-sw01")
	tok := f.idToken(t, idTokenOpts{principal: "alice@example.com", nonceFor: ch, amr: []string{"pwd", "mfa"}, authTime: f.clock.Now()})
	if code := f.proveIdP(t, tok, ch); code != 200 {
		t.Fatalf("POST /v1/mfa (idp) = %d", code)
	}
	if it := f.mint(t, f.alice, "core-sw01", ch).Results[0]; it.Verdict != "permit" {
		t.Fatalf("retried mint = %+v", it)
	}
	f.assertLogHasNone(t, tok, api.MFANonce(mfaChallengeBytes(t, ch)))
	// The proof was posted with no Port49-Agent-Session (the CLI's fresh
	// connection), yet it is kept for this agent: a login within reuse_for
	// is covered without a second sign-in (re-review R2).
	f.clock.Advance(5 * time.Minute)
	if it := f.mint(t, f.alice, "core-sw01", "").Results[0]; it.Verdict != "permit" {
		t.Fatalf("mint within reuse_for after an idp proof = %+v", it)
	}
	f.assertMintRecordMFA(t, "idp_mfa", true)
	f.clock.Advance(11 * time.Minute) // past reuse_for: each mint below is asked again
	for _, bad := range []struct {
		name  string
		cause string // a phrase of the refusal that names the check that failed
		opts  func(ch string) idTokenOpts
	}{
		{"another person", "unknown, spent or expired", func(ch string) idTokenOpts {
			return idTokenOpts{principal: "bob@example.com", nonceFor: ch, amr: []string{"mfa"}, authTime: f.clock.Now()}
		}},
		{"another challenge", "nonce does not name this challenge", func(string) idTokenOpts {
			return idTokenOpts{principal: "alice@example.com", nonceFor: "another challenge", amr: []string{"mfa"}, authTime: f.clock.Now()}
		}},
		{"no second factor", "amr shows no second factor", func(ch string) idTokenOpts {
			return idTokenOpts{principal: "alice@example.com", nonceFor: ch, amr: []string{"pwd"}, authTime: f.clock.Now()}
		}},
		{"auth_time seven minutes old", "last authenticated you at", func(ch string) idTokenOpts {
			return idTokenOpts{principal: "alice@example.com", nonceFor: ch, amr: []string{"mfa"}, authTime: f.clock.Now().Add(-7 * time.Minute)}
		}},
		{"auth_time after iat plus skew", "authenticated after it issued the token", func(ch string) idTokenOpts {
			// Issued two minutes ago, authenticated now: after iat plus the
			// skew, though not ahead of the broker's clock.
			return idTokenOpts{principal: "alice@example.com", nonceFor: ch, amr: []string{"mfa"},
				authTime: f.clock.Now(), issuedAt: f.clock.Now().Add(-2 * time.Minute)}
		}},
	} {
		ch := f.ask(t, f.alice, "core-sw01")
		if code, detail := f.proveIdPDetail(t, f.idToken(t, bad.opts(ch)), ch); code != 401 || !strings.Contains(detail, bad.cause) {
			t.Errorf("%s: %d %s, want 401 saying %q", bad.name, code, detail, bad.cause)
		}
	}
	f.assertRecord(t, "per_login_mfa", "deny", "per_login_mfa_refused")
}

// The freshness limit is 5 minutes plus clock_skew, and a sign-in exactly at
// it is within it, as at POST /v1/identity/issue (issue.go uses the same
// boundary): one second past it is not.
func TestAnIdPSignInAtTheFreshnessLimitIsAccepted(t *testing.T) {
	f := newMFAFixture(t)
	limit := 5*time.Minute + oidc.DefaultTiming.ClockSkew
	ch := f.ask(t, f.alice, "core-sw01")
	tok := f.idToken(t, idTokenOpts{principal: "alice@example.com", nonceFor: ch, amr: []string{"mfa"},
		authTime: f.clock.Now().Add(-limit - time.Second)})
	if code, detail := f.proveIdPDetail(t, tok, ch); code != 401 || !strings.Contains(detail, "last authenticated you at") {
		t.Fatalf("one second past the limit: %d %s, want 401 on freshness", code, detail)
	}
	ch = f.ask(t, f.alice, "core-sw01")
	tok = f.idToken(t, idTokenOpts{principal: "alice@example.com", nonceFor: ch, amr: []string{"mfa"},
		authTime: f.clock.Now().Add(-limit)})
	if code, detail := f.proveIdPDetail(t, tok, ch); code != 200 {
		t.Fatalf("exactly at the limit: %d %s, want 200", code, detail)
	}
}

// Proof by idp spends the token: the same token posted for a second request
// bound to the same challenge is refused even where the challenge record is
// there (a fresh alice challenge is bound by its own nonce, so the token's
// SHA-256 is what is spent).
func TestAnIdPTokenIsSpent(t *testing.T) {
	f := newMFAFixture(t)
	ch := f.ask(t, f.alice, "core-sw01")
	tok := f.idToken(t, idTokenOpts{principal: "alice@example.com", nonceFor: ch, amr: []string{"mfa"}, authTime: f.clock.Now()})
	// Spend the token's hash as a first proof would, then post it.
	if ok, err := f.st.PutOnce(context.Background(), mfaTokenKey(tok), nil, time.Hour); err != nil || !ok {
		t.Fatalf("PutOnce: %v %v", ok, err)
	}
	if code, detail := f.proveIdPDetail(t, tok, ch); code != 401 || !strings.Contains(detail, "used as a proof already") {
		t.Fatalf("a spent ID token: %d %s, want 401 saying it was used already", code, detail)
	}
}

func TestUnavailableMethodsAreSaidPerDevice(t *testing.T) {
	f := newMFAFixture(t, withoutAttestationRoots(), withTouchOnlyCore())
	resp := f.mintMany(t, f.alice, "core-sw01", "edge-sw01")
	if it := resp.find("core-sw01"); it.Verdict != "deny" || it.Reason != "per_login_mfa_unavailable" {
		t.Fatalf("core-sw01 = %+v", it)
	}
	if it := resp.find("edge-sw01"); it.Verdict != "permit" {
		t.Fatalf("edge-sw01 = %+v, want minted as before", it)
	}
	f.assertRecord(t, "mint", "deny", "per_login_mfa_unavailable")
	r := f.find(t, "mint", "deny", "per_login_mfa_unavailable")
	if rm, _ := r["per_login_mfa"].(map[string]any); rm == nil || rm["accept"] == nil {
		t.Fatalf("the unavailable record omits the requirement: %v", r)
	}
}

// A batch is asked only where a requirement applies, and the proof for its
// challenge covers the retried batch.
func TestABatchAsksOnlyWhereARequirementApplies(t *testing.T) {
	f := newMFAFixture(t)
	resp := f.mintMany(t, f.alice, "core-sw01", "edge-sw01")
	core := resp.find("core-sw01")
	if core.Reason != "per_login_mfa_required" || core.PerLoginMFA == nil || resp.find("edge-sw01").Verdict != "permit" {
		t.Fatalf("batch = %+v", resp)
	}
	ch := core.PerLoginMFA.Challenge
	if code := f.proveTouch(t, f.alice, ch); code != 200 {
		t.Fatalf("POST /v1/mfa = %d", code)
	}
	resp = f.mintWith(t, f.alice, f.alice.agent, "", ch, "core-sw01", "edge-sw01")
	if resp.find("core-sw01").Verdict != "permit" || resp.find("edge-sw01").Verdict != "permit" {
		t.Fatalf("retried batch = %+v", resp)
	}
}

func TestTheCredentialCarriesTheProofIntoTheToken(t *testing.T) {
	f := newMFAFixture(t)
	ch := f.ask(t, f.alice, "core-sw01")
	provedAt := f.clock.Now()
	if code := f.proveTouch(t, f.alice, ch); code != 200 {
		t.Fatalf("POST /v1/mfa = %d", code)
	}
	if it := f.mint(t, f.alice, "core-sw01", ch).Results[0]; it.Verdict != "permit" {
		t.Fatalf("retried mint = %+v", it)
	}
	cands, err := f.st.Candidates(context.Background(), store.TokenKey{NAS: "core-sw01", Username: "alice"})
	if err != nil || len(cands) != 1 {
		t.Fatalf("%d tokens: %v", len(cands), err)
	}
	if c := cands[0].Credential; c.MFAMethod != "hardware_key_touch" || !c.MFAAt.Equal(provedAt) || c.Method != "cert" {
		t.Fatalf("credential = %+v, want the touch proof made at %s", c, provedAt)
	}
	// A device with no requirement carries none.
	if it := f.mint(t, f.alice, "edge-sw01", "").Results[0]; it.Verdict != "permit" {
		t.Fatalf("edge-sw01 = %+v", it)
	}
	cands, err = f.st.Candidates(context.Background(), store.TokenKey{NAS: "edge-sw01", Username: "alice"})
	if err != nil || len(cands) != 1 || cands[0].Credential.MFAMethod != "" || !cands[0].Credential.MFAAt.IsZero() {
		t.Fatalf("edge-sw01 credential = %+v (%v)", cands, err)
	}
}

func TestMachinesAreNotAsked(t *testing.T) {
	f := newMFAFixture(t) // core's level has no applies_to_machines
	if it := f.mint(t, f.oxidized, "core-sw01", "").Results[0]; it.Verdict != "permit" || it.PerLoginMFA != nil {
		t.Fatalf("a machine under a humans-only requirement = %+v", it)
	}
	f = newMFAFixture(t, withAppliesToMachines())
	if it := f.mint(t, f.oxidized, "core-sw01", "").Results[0]; it.Reason != "per_login_mfa_required" ||
		!slices.Equal(it.PerLoginMFA.Methods, []string{"hardware_key_touch"}) {
		t.Fatalf("a machine under applies_to_machines = %+v, want asked for a touch alone", it)
	}
}

// The API says what it verifies, and POST /v1/mfa refuses what it does not.
func TestConfigNamesTheMethodsAndTheEndpointRefusesTheOthers(t *testing.T) {
	f := newMFAFixture(t)
	var cfg api.Config
	w := f.call(context.Background(), &tls.ConnectionState{}, "GET", "/v1/config", "")
	if err := json.Unmarshal(w.Body.Bytes(), &cfg); err != nil || cfg.PerLoginMFA == nil ||
		!slices.Equal(cfg.PerLoginMFA.Methods, []string{"hardware_key_touch", "idp_mfa"}) {
		t.Fatalf("config = %s (%v)", w.Body, err)
	}
	g := newMFAFixture(t, withoutAttestationRoots())
	w = g.call(context.Background(), &tls.ConnectionState{}, "GET", "/v1/config", "")
	cfg = api.Config{}
	if err := json.Unmarshal(w.Body.Bytes(), &cfg); err != nil || cfg.PerLoginMFA == nil ||
		!slices.Equal(cfg.PerLoginMFA.Methods, []string{"idp_mfa"}) {
		t.Fatalf("config without roots = %s (%v)", w.Body, err)
	}
	ch := g.ask(t, g.alice, "core-sw01")
	if code := g.proveTouch(t, g.alice, ch); code != 400 {
		t.Fatalf("a touch where the broker verifies none: %d, want 400", code)
	}
	code, _ := g.alice.conn.post(t, "/v1/mfa", nil, `{"challenge":"`+ch+`","method":"password"}`)
	if code != 400 {
		t.Fatalf("an unknown method: %d, want 400", code)
	}
	code, _ = g.alice.conn.post(t, "/v1/mfa", nil, `{"challenge":"`+ch+`","method":"idp_mfa","extra":1}`)
	if code != 400 {
		t.Fatalf("an unknown field: %d, want 400", code)
	}
}
