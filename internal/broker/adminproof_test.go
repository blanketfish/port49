package broker

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/pivattest"
	"github.com/rhwendt/port49/internal/store"
)

// An admin-level call proves a touch bound to its own request (spec §5.1.6;
// §13 decision 54 ruling 15). The signer is a software key, and every
// certificate here is the fixture's own: nothing in these tests is real
// material. A failure names the field it found wrong, never its value.

const (
	revokePath = "/v1/tokens/revoke"
	bobBody    = `{"principal":"user:bob@example.com"}`
	carolBody  = `{"principal":"user:carol@example.com"}`
	bobKey     = "user:bob@example.com"
	carolKey   = "user:carol@example.com"
)

// adminAnswer is the 401 or 503 an admin-level call is answered with.
type adminAnswer struct {
	Error  string              `json:"error"`
	Detail string              `json:"detail"`
	Admin  *api.AdminChallenge `json:"admin"`
}

func decodeAdminAnswer(t *testing.T, raw []byte) adminAnswer {
	t.Helper()
	var a adminAnswer
	if err := json.Unmarshal(raw, &a); err != nil {
		t.Fatal("the answer is not JSON")
	}
	return a
}

// adminExporter is the connection's exporter value under the admin label.
func (c *mfaConn) adminExporter(t *testing.T) []byte {
	t.Helper()
	cs := c.c.ConnectionState()
	ekm, err := cs.ExportKeyingMaterial(api.AdminExporterLabel, nil, 32)
	if err != nil {
		t.Fatal(err)
	}
	return ekm
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// adminHeader is the Port49-Admin-Proof value for a challenge, a signature
// and the three attestations.
func adminHeader(t *testing.T, challenge string, sig []byte, atts [][]byte) string {
	t.Helper()
	p := api.AdminProof{Challenge: challenge, Signature: b64(sig)}
	for _, a := range atts {
		p.Attestation = append(p.Attestation, b64(a))
	}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return b64(raw)
}

// adminAsk sends the call with no proof and returns the challenge it is
// answered with.
func (f *mfaFixture) adminAsk(t *testing.T, c *mfaConn, path, body string) api.AdminChallenge {
	t.Helper()
	code, raw := c.post(t, path, nil, body)
	ans := decodeAdminAnswer(t, raw)
	if code != 401 || ans.Error != "admin_touch_required" || ans.Admin == nil {
		t.Fatalf("the call with no proof was answered %d %s, want 401 admin_touch_required with an admin challenge",
			code, ans.Error)
	}
	return *ans.Admin
}

// adminSign is who's touch key signing the admin message for the request
// over the exporter value given.
func (f *mfaFixture) adminSign(t *testing.T, key *ecdsa.PrivateKey, ch, method, path, body string, ekm []byte) []byte {
	t.Helper()
	sig, err := api.SignRefresh(key, api.AdminMessage(mfaChallengeBytes(t, ch),
		api.AdminRequestSHA256(method, path, []byte(body)), ekm))
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

// adminSend sends the call with header as its proof.
func (f *mfaFixture) adminSend(t *testing.T, c *mfaConn, path, body, header string) (int, []byte) {
	t.Helper()
	return c.post(t, path, map[string]string{api.AdminProofHeader: header}, body)
}

// adminCall is the whole exchange for who on c: ask, touch, retry.
func (f *mfaFixture) adminCall(t *testing.T, who *mfaActor, c *mfaConn, path, body string) (int, []byte) {
	t.Helper()
	ch := f.adminAsk(t, c, path, body)
	sig := f.adminSign(t, who.touchKey, ch.Challenge, "POST", path, body, c.adminExporter(t))
	return f.adminSend(t, c, path, body, adminHeader(t, ch.Challenge, sig, who.atts))
}

func (f *mfaFixture) marked(t *testing.T, principal string) bool {
	t.Helper()
	_, err := f.st.GetRevocation(context.Background(), store.RevocationPrincipal, principal)
	switch {
	case err == nil:
		return true
	case errors.Is(err, store.ErrNotFound):
		return false
	}
	t.Fatal(err)
	return false
}

func (f *mfaFixture) adminRecords(t *testing.T, reason string) int {
	t.Helper()
	n := 0
	for _, r := range f.recs(t) {
		if r["event"] == "admin_touch" && r["reason"] == reason {
			n++
		}
	}
	return n
}

func newAdminFixture(t *testing.T, opts ...mfaOpt) *mfaFixture {
	t.Helper()
	return newMFAFixture(t, append(opts, withAdminRight())...)
}

func TestAnAdminCallWithNoProofGetsAChallenge(t *testing.T) {
	f := newAdminFixture(t)
	code, raw := f.alice.conn.post(t, revokePath, nil, bobBody)
	ans := decodeAdminAnswer(t, raw)
	if code != 401 || ans.Error != "admin_touch_required" || ans.Admin == nil {
		t.Fatalf("answered %d %s, want 401 admin_touch_required", code, ans.Error)
	}
	if ans.Admin.Operation != "revoke_principal" || ans.Admin.Target != bobKey {
		t.Fatalf("operation %q target %q", ans.Admin.Operation, ans.Admin.Target)
	}
	if ch, err := base64.RawURLEncoding.DecodeString(ans.Admin.Challenge); err != nil || len(ch) != 32 {
		t.Fatal("the challenge is not 32 bytes of base64url")
	}
	if want := f.b.Now().Add(2 * time.Minute); ans.Admin.ExpiresAt.Sub(want).Abs() > 2*time.Second {
		t.Fatalf("expires_at is %v, want about %v", ans.Admin.ExpiresAt, want)
	}
	if f.marked(t, bobKey) {
		t.Fatal("a call with no proof left a mark")
	}
	f.assertRecord(t, "admin_touch", "deny", "admin_touch_required")
	rec := f.find(t, "admin_touch", "deny", "admin_touch_required")
	adm, _ := rec["admin"].(map[string]any)
	if adm == nil || adm["operation"] != "revoke_principal" || adm["target"] != bobKey || adm["challenge_sha256"] == nil {
		t.Fatalf("the record's admin part is %v", rec["admin"])
	}
}

func TestAProvedAdminCallRuns(t *testing.T) {
	f := newAdminFixture(t)
	code, raw := f.adminCall(t, f.alice, f.alice.conn, revokePath, bobBody)
	if code != 200 {
		t.Fatalf("the proved call was answered %d %s", code, decodeAdminAnswer(t, raw).Error)
	}
	if !f.marked(t, bobKey) {
		t.Fatal("the proved call left no mark")
	}
	f.assertRecord(t, "admin_touch", "permit", "admin_touch_proved")
	proved, revoke := -1, -1
	for i, r := range f.recs(t) {
		switch {
		case r["event"] == "admin_touch" && r["reason"] == "admin_touch_proved":
			proved = i
		case r["event"] == "revoke" && revoke < 0:
			revoke = i
		}
	}
	if proved < 0 || revoke < 0 || proved > revoke {
		t.Fatalf("admin_touch_proved is record %d and the revoke record %d: the proof must come first", proved, revoke)
	}
}

func TestAProofIsBoundToItsRequest(t *testing.T) {
	f := newAdminFixture(t)
	c := f.alice.conn
	// A proof made for bob, sent with a body naming carol.
	ch := f.adminAsk(t, c, revokePath, bobBody)
	sig := f.adminSign(t, f.alice.touchKey, ch.Challenge, "POST", revokePath, bobBody, c.adminExporter(t))
	code, raw := f.adminSend(t, c, revokePath, carolBody, adminHeader(t, ch.Challenge, sig, f.alice.atts))
	if code != 401 || decodeAdminAnswer(t, raw).Error != "admin_touch_refused" {
		t.Fatalf("a proof for another body: %d %s, want 401 admin_touch_refused", code, decodeAdminAnswer(t, raw).Error)
	}
	if f.marked(t, carolKey) || f.marked(t, bobKey) {
		t.Fatal("a proof for another body revoked someone")
	}
	// The same body at another path or query string: the request is the path
	// as well, so a query a route ignores is still bound.
	ch = f.adminAsk(t, c, revokePath, bobBody)
	sig = f.adminSign(t, f.alice.touchKey, ch.Challenge, "POST", revokePath, bobBody, c.adminExporter(t))
	code, raw = f.adminSend(t, c, revokePath+"?lift=1", bobBody, adminHeader(t, ch.Challenge, sig, f.alice.atts))
	if code != 401 || decodeAdminAnswer(t, raw).Error != "admin_touch_refused" {
		t.Fatalf("a proof for another path: %d %s, want 401 admin_touch_refused", code, decodeAdminAnswer(t, raw).Error)
	}
	if f.marked(t, bobKey) {
		t.Fatal("a proof for another path revoked bob")
	}
	if f.adminRecords(t, "admin_touch_refused") != 2 {
		t.Fatalf("%d refused records, want 2", f.adminRecords(t, "admin_touch_refused"))
	}
}

func TestAProofIsSpentOnce(t *testing.T) {
	f := newAdminFixture(t)
	c := f.alice.conn
	ch := f.adminAsk(t, c, revokePath, bobBody)
	sig := f.adminSign(t, f.alice.touchKey, ch.Challenge, "POST", revokePath, bobBody, c.adminExporter(t))
	header := adminHeader(t, ch.Challenge, sig, f.alice.atts)
	if code, _ := f.adminSend(t, c, revokePath, bobBody, header); code != 200 {
		t.Fatalf("the first send: %d", code)
	}
	code, raw := f.adminSend(t, c, revokePath, bobBody, header)
	if code != 401 || decodeAdminAnswer(t, raw).Error != "admin_touch_refused" {
		t.Fatalf("the second send: %d %s, want 401 admin_touch_refused", code, decodeAdminAnswer(t, raw).Error)
	}
	if f.adminRecords(t, "admin_touch_proved") != 1 {
		t.Fatalf("%d proved records, want 1", f.adminRecords(t, "admin_touch_proved"))
	}
}

func TestAProofIsBoundToItsConnection(t *testing.T) {
	f := newAdminFixture(t)
	first, second := f.alice.conn, f.dial(t, f.alice)
	// Proved over the first connection's exporter, sent on the second.
	ch := f.adminAsk(t, first, revokePath, carolBody)
	sig := f.adminSign(t, f.alice.touchKey, ch.Challenge, "POST", revokePath, carolBody, first.adminExporter(t))
	code, raw := f.adminSend(t, second, revokePath, carolBody, adminHeader(t, ch.Challenge, sig, f.alice.atts))
	if code != 401 || decodeAdminAnswer(t, raw).Error != "admin_touch_refused" {
		t.Fatalf("a proof sent on another connection: %d %s", code, decodeAdminAnswer(t, raw).Error)
	}
	// Signed over the second connection's exporter, for the first's challenge.
	sig = f.adminSign(t, f.alice.touchKey, ch.Challenge, "POST", revokePath, carolBody, second.adminExporter(t))
	code, raw = f.adminSend(t, second, revokePath, carolBody, adminHeader(t, ch.Challenge, sig, f.alice.atts))
	if code != 401 || decodeAdminAnswer(t, raw).Error != "admin_touch_refused" {
		t.Fatalf("another connection's exporter value: %d %s", code, decodeAdminAnswer(t, raw).Error)
	}
	if f.marked(t, carolKey) {
		t.Fatal("a proof on another connection revoked carol")
	}
}

func TestAPerLoginProofIsNotAnAdminProof(t *testing.T) {
	f := newAdminFixture(t)
	c := f.alice.conn
	sign := func(msg func(ch []byte, req [32]byte) []byte) (string, string) {
		ch := f.adminAsk(t, c, revokePath, bobBody)
		sig, err := api.SignRefresh(f.alice.touchKey, msg(mfaChallengeBytes(t, ch.Challenge),
			api.AdminRequestSHA256("POST", revokePath, []byte(bobBody))))
		if err != nil {
			t.Fatal(err)
		}
		code, raw := f.adminSend(t, c, revokePath, bobBody, adminHeader(t, ch.Challenge, sig, f.alice.atts))
		return string(rune('0'+code/100)) + "xx", decodeAdminAnswer(t, raw).Error
	}
	for name, msg := range map[string]func(ch []byte, req [32]byte) []byte{
		"the per-login message over the admin exporter value": func(ch []byte, _ [32]byte) []byte {
			return api.MFAMessage(ch, c.adminExporter(t))
		},
		"the per-login message over the per-login exporter value": func(ch []byte, _ [32]byte) []byte {
			return api.MFAMessage(ch, c.exporter(t))
		},
		"the admin message over the per-login exporter value": func(ch []byte, req [32]byte) []byte {
			return api.AdminMessage(ch, req, c.exporter(t))
		},
	} {
		if class, reason := sign(msg); class != "4xx" || reason != "admin_touch_refused" {
			t.Errorf("%s: %s %s, want 4xx admin_touch_refused", name, class, reason)
		}
	}
	if f.marked(t, bobKey) {
		t.Fatal("a per-login proof revoked bob")
	}
}

func TestABearerCannotProve(t *testing.T) {
	f := newAdminFixture(t)
	tok := f.idToken(t, idTokenOpts{principal: "alice@example.com", amr: []string{"mfa"}, authTime: f.b.Now()})
	w := f.bearer(context.Background(), "POST", revokePath, bobBody, tok)
	ans := decodeAdminAnswer(t, w.Body.Bytes())
	if w.Code != 401 || ans.Error != "admin_touch_refused" || ans.Admin != nil {
		t.Fatalf("a bearer's admin call: %d %s with a challenge: %v, want 401 admin_touch_refused and none",
			w.Code, ans.Error, ans.Admin != nil)
	}
	if !strings.Contains(ans.Detail, "client certificate") {
		t.Fatal("the answer does not say a client certificate is what proves")
	}
	if f.marked(t, bobKey) {
		t.Fatal("a bearer revoked bob")
	}
	rec := f.find(t, "admin_touch", "deny", "admin_touch_refused")
	if rec == nil {
		t.Fatal("no admin_touch_refused record")
	}
	adm, _ := rec["admin"].(map[string]any)
	if adm == nil || adm["operation"] != "revoke_principal" || adm["why"] == nil {
		t.Fatalf("the record's admin part is %v: it names the operation and why", rec["admin"])
	}
	if f.adminRecords(t, "admin_touch_required") != 0 {
		t.Fatal("a bearer was issued a challenge")
	}
}

func TestNoRootsMeansUnavailable(t *testing.T) {
	f := newAdminFixture(t, withoutAttestationRoots())
	code, raw := f.alice.conn.post(t, revokePath, nil, bobBody)
	ans := decodeAdminAnswer(t, raw)
	if code != 503 || ans.Error != "admin_touch_unavailable" || ans.Admin != nil {
		t.Fatalf("answered %d %s, want 503 admin_touch_unavailable", code, ans.Error)
	}
	if !strings.Contains(ans.Detail, "attestation_roots_file") {
		t.Fatal("the answer does not name attestation_roots_file")
	}
	f.assertRecord(t, "admin_touch", "deny", "admin_touch_unavailable")
	const line = "no attestation roots are configured " +
		"(broker.identity.per_login_mfa.hardware_key_touch.attestation_roots_file): every admin operation " +
		"will be refused until they are"
	if got := f.b.AdminTouchUnavailable(); got != line {
		t.Fatalf("the start line is %q", got)
	}
	with := newAdminFixture(t)
	if got := with.b.AdminTouchUnavailable(); got != "" {
		t.Fatalf("with roots the start line is %q, want none", got)
	}
}

// A refused proof is judged before the request takes the revocation slot,
// so a proof being judged holds nothing a principal revocation needs.
func TestARefusedProofTakesNoSlot(t *testing.T) {
	f := newAdminFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	hook := func() {
		if calls.Add(1) == 1 {
			close(entered)
			<-release
		}
	}
	f.b.admin.judging.Store(&hook)
	slow := f.alice.conn
	ch := f.adminAsk(t, slow, revokePath, bobBody)
	bad := make([]byte, 64)
	header := adminHeader(t, ch.Challenge, bad, f.alice.atts)
	var wg sync.WaitGroup
	var slowCode int
	wg.Add(1)
	go func() {
		defer wg.Done()
		slowCode, _ = f.adminSend(t, slow, revokePath, bobBody, header)
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("the refused proof was never judged")
	}
	// The slot is free while that proof is judged.
	start := time.Now()
	code, _ := f.adminCall(t, f.alice, f.dial(t, f.alice), revokePath, carolBody)
	if code != 200 || time.Since(start) > 3*time.Second {
		close(release)
		t.Fatalf("a principal revocation during a judgment: %d after %v, want 200 at once", code, time.Since(start))
	}
	close(release)
	wg.Wait()
	if slowCode != 401 {
		t.Fatalf("the refused proof was answered %d, want 401", slowCode)
	}
	if f.marked(t, bobKey) || !f.marked(t, carolKey) {
		t.Fatal("the marks are not carol's alone")
	}
}

func TestMineNeedsNoTouch(t *testing.T) {
	f := newAdminFixture(t)
	for _, body := range []string{`{"mine":true}`, `{"principal":"user:alice@example.com"}`} {
		code, raw := f.alice.conn.post(t, revokePath, nil, body)
		if code != 200 {
			t.Fatalf("%s: %d %s", body, code, decodeAdminAnswer(t, raw).Error)
		}
	}
	if n := f.adminRecords(t, "admin_touch_required"); n != 0 {
		t.Fatalf("%d challenges for a call on the caller alone", n)
	}
}

func TestARightlessCallerGetsNoChallenge(t *testing.T) {
	f := newAdminFixture(t)
	for _, body := range []string{
		carolBody,
		`{"device":"core-sw01","username":"bob"}`,
		`{"sid":"s-1"}`,
	} {
		code, raw := f.bob.conn.post(t, revokePath, nil, body)
		ans := decodeAdminAnswer(t, raw)
		if code != 403 || ans.Error != "api_right_missing" || ans.Admin != nil {
			t.Fatalf("%s: %d %s, want 403 api_right_missing and no challenge", body, code, ans.Error)
		}
	}
	for _, r := range f.recs(t) {
		if r["event"] == "admin_touch" {
			t.Fatal("a caller without the right left an admin_touch record")
		}
	}
	if n := f.b.admin.len(); n != 0 {
		t.Fatalf("%d challenges held for a caller without the right", n)
	}
}

func TestTheRecordHoldsNoProofMaterial(t *testing.T) {
	f := newAdminFixture(t)
	c := f.alice.conn
	ch := f.adminAsk(t, c, revokePath, bobBody)
	sig := f.adminSign(t, f.alice.touchKey, ch.Challenge, "POST", revokePath, bobBody, c.adminExporter(t))
	header := adminHeader(t, ch.Challenge, sig, f.alice.atts)
	if code, _ := f.adminSend(t, c, revokePath, bobBody, header); code != 200 {
		t.Fatalf("the proved call: %d", code)
	}
	// A refused one too, with a proof that carries the attestations.
	if code, _ := f.adminSend(t, c, revokePath, bobBody, header); code != 401 {
		t.Fatalf("the spent proof: %d", code)
	}
	fields := map[string]string{"the challenge": ch.Challenge, "the signature": b64(sig), "the header": header}
	for i, a := range f.alice.atts {
		fields["attestation "+string(rune('1'+i))] = b64(a)
	}
	log := f.logs.String()
	for name, v := range fields {
		if strings.Contains(log, v) {
			t.Errorf("the decision log carries %s", name)
		}
	}
	if t.Failed() {
		return
	}
	if f.adminRecords(t, "admin_touch_proved") != 1 || f.adminRecords(t, "admin_touch_refused") != 1 {
		t.Fatal("the proved and refused records are not each there once")
	}
}

// The challenge is kept two minutes.
func TestAChallengeExpires(t *testing.T) {
	f := newAdminFixture(t)
	c := f.alice.conn
	ch := f.adminAsk(t, c, revokePath, bobBody)
	sig := f.adminSign(t, f.alice.touchKey, ch.Challenge, "POST", revokePath, bobBody, c.adminExporter(t))
	f.advance(2*time.Minute + time.Second)
	code, raw := f.adminSend(t, c, revokePath, bobBody, adminHeader(t, ch.Challenge, sig, f.alice.atts))
	if code != 401 || decodeAdminAnswer(t, raw).Error != "admin_touch_refused" {
		t.Fatalf("an expired challenge: %d %s", code, decodeAdminAnswer(t, raw).Error)
	}
}

// One challenge per connection: a new one replaces the last.
func TestANewChallengeReplacesTheLastOnItsConnection(t *testing.T) {
	f := newAdminFixture(t)
	c := f.alice.conn
	first := f.adminAsk(t, c, revokePath, bobBody)
	second := f.adminAsk(t, c, revokePath, bobBody)
	if n := f.b.admin.len(); n != 1 {
		t.Fatalf("%d challenges held for one connection", n)
	}
	sig := f.adminSign(t, f.alice.touchKey, first.Challenge, "POST", revokePath, bobBody, c.adminExporter(t))
	if code, _ := f.adminSend(t, c, revokePath, bobBody, adminHeader(t, first.Challenge, sig, f.alice.atts)); code != 401 {
		t.Fatalf("the replaced challenge: %d, want 401", code)
	}
	sig = f.adminSign(t, f.alice.touchKey, second.Challenge, "POST", revokePath, bobBody, c.adminExporter(t))
	if code, _ := f.adminSend(t, c, revokePath, bobBody, adminHeader(t, second.Challenge, sig, f.alice.atts)); code != 200 {
		t.Fatalf("the newest challenge: %d, want 200", code)
	}
}

// A connection's close drops its challenge.
func TestAClosedConnectionDropsItsChallenge(t *testing.T) {
	f := newAdminFixture(t)
	c := f.dial(t, f.alice)
	f.adminAsk(t, c, revokePath, bobBody)
	if n := f.b.admin.len(); n != 1 {
		t.Fatalf("%d challenges held, want 1", n)
	}
	_ = c.c.Close()
	eventually(t, "the closed connection's challenge is dropped", func() bool { return f.b.admin.len() == 0 })
}

// The session slot's key must be the connection's client key: a touch proves
// from the token that holds the session key.
func TestAnAdminProofFromAnotherTokenIsRefused(t *testing.T) {
	f := newAdminFixture(t)
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// A token whose session slot holds another key than alice's connection's.
	touch, atts := f.newToken(t, &other.PublicKey, pivattest.TouchAlways)
	c := f.alice.conn
	ch := f.adminAsk(t, c, revokePath, bobBody)
	sig := f.adminSign(t, touch, ch.Challenge, "POST", revokePath, bobBody, c.adminExporter(t))
	code, raw := f.adminSend(t, c, revokePath, bobBody, adminHeader(t, ch.Challenge, sig, atts))
	if code != 401 || decodeAdminAnswer(t, raw).Error != "admin_touch_refused" {
		t.Fatalf("a token that does not hold the connection's key: %d %s", code, decodeAdminAnswer(t, raw).Error)
	}
	if f.marked(t, bobKey) {
		t.Fatal("a proof from another token revoked bob")
	}
}

// The store is one mutex over two maps; a spent challenge is taken by one of
// any number of racing requests.
func TestASpentChallengeIsTakenByOneOfManyRacers(t *testing.T) {
	var g adminChallenges
	now := time.Now()
	g.put("conn", "key", now.Add(time.Minute), now)
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if g.take("key", now) {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("%d takers of one challenge, want 1", wins.Load())
	}
	if g.len() != 0 {
		t.Fatalf("%d held after it was taken", g.len())
	}
}

func TestTheChallengeStoreHoldsOnePerConnectionAndForgets(t *testing.T) {
	var g adminChallenges
	now := time.Now()
	g.put("a", "k1", now.Add(time.Minute), now)
	g.put("a", "k2", now.Add(time.Minute), now)
	g.put("b", "k3", now.Add(time.Minute), now)
	if g.len() != 2 || g.take("k1", now) {
		t.Fatalf("a connection holds more than one: %d held", g.len())
	}
	g.closed("a")
	if g.len() != 1 || g.take("k2", now) {
		t.Fatal("a closed connection's challenge was kept")
	}
	if g.take("k3", now.Add(2*time.Minute)) {
		t.Fatal("an expired challenge was taken")
	}
	g.put("c", "k4", now.Add(time.Minute), now)
	g.put("d", "k5", now.Add(3*time.Minute), now.Add(2*time.Minute))
	if g.len() != 1 {
		t.Fatalf("%d held: an expired entry is dropped by the next put", g.len())
	}
}

// Keep the sha256 import honest: the record's challenge_sha256 is the hash of
// the challenge bytes.
func TestTheRecordNamesTheChallengeByItsHash(t *testing.T) {
	f := newAdminFixture(t)
	ch := f.adminAsk(t, f.alice.conn, revokePath, bobBody)
	sum := sha256.Sum256(mfaChallengeBytes(t, ch.Challenge))
	rec := f.find(t, "admin_touch", "deny", "admin_touch_required")
	adm, _ := rec["admin"].(map[string]any)
	if adm == nil || adm["challenge_sha256"] != hexOf(sum[:]) {
		t.Fatal("challenge_sha256 is not the SHA-256 of the challenge")
	}
}

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, 2*len(b))
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&15])
	}
	return string(out)
}

// skipAdminProof is a test seam: no code a process runs sets it.
func TestNothingButTestsSkipsTheAdminProof(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) == 0 {
		t.Fatal("no source files found")
	}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(src), "\n") {
			if strings.Contains(line, "skipAdminProof") && name != "adminproof.go" && name != "broker.go" {
				t.Errorf("%s:%d names skipAdminProof", name, i+1)
			}
		}
	}
}
