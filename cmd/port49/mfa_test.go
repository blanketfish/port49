package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/agent"
	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/brokercrl"
	"github.com/rhwendt/port49/internal/hwkey"
	"github.com/rhwendt/port49/internal/hwkey/hwfake"
	"github.com/rhwendt/port49/internal/oidc/oidctest"
	"github.com/rhwendt/port49/internal/pivattest"
	"github.com/rhwendt/port49/internal/testpki"
	"github.com/rhwendt/port49/internal/userconfig"
)

// core-sw01's requirement as Task 11's broker answers it.
func coreRequirement() api.PerLoginMFA {
	both := []string{"hardware_key_touch", "idp_mfa"}
	return api.PerLoginMFA{Device: "core-sw01", Challenge: "CHALLENGE", Accept: both, Methods: both,
		ReuseForSeconds: 900, ReuseFrom: "scope core",
		Levels: []api.MFALevel{{Level: "scope core", Accept: both, ReuseForSeconds: 900}}}
}

func TestDescribeMFA(t *testing.T) {
	want := "core-sw01 asks for a second factor at each login: scope core accepts hardware_key_touch, idp_mfa " +
		"(reuse 15m, from scope core)"
	if got := describeMFA(coreRequirement()); got != want {
		t.Fatalf("\n got %q\nwant %q", got, want)
	}
	r := coreRequirement()
	r.Device, r.ReuseForSeconds = "", 5400
	r.Levels = []api.MFALevel{{Level: "scope core", Accept: []string{"hardware_key_touch"}}, {Level: "role admin",
		Accept: []string{"idp_mfa"}}}
	got := describeMFA(r)
	if !strings.Contains(got, "scope core accepts hardware_key_touch; role admin accepts idp_mfa (reuse 1h30m, from scope core)") ||
		strings.HasPrefix(got, " ") || !strings.HasPrefix(got, "a device in your session asks") {
		t.Fatalf("a refresh's requirement, no one device: %q", got)
	}
}

func newTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// secretSink is every value that must reach no terminal: what the broker saw
// of a challenge, a signature, an agent session or an ID token.
type secretSink struct {
	mu   sync.Mutex
	vals map[string]bool
}

func (s *secretSink) add(v string) {
	if len(v) < 8 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.vals == nil {
		s.vals = map[string]bool{}
	}
	s.vals[v] = true
}

func (s *secretSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.vals)
}

// check fails if any text holds a value in the sink.
func (s *secretSink) check(t *testing.T, texts ...string) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, text := range texts {
		for v := range s.vals {
			if strings.Contains(text, v) {
				t.Fatalf("a challenge, a signature, an ID token or the agent session reached %d bytes of output", len(text))
			}
		}
	}
}

// mfaLab is a real broker that asks for a second factor on every device, and
// an agent in this process holding a hardware-style session key and, when
// asked, a touch key on the same fake token, with attestations the test PIV
// root signs.
type mfaLab struct {
	*labBroker
	piv     *testpki.PIV
	a       *agent.Agent
	socket  string
	touch   *hwfake.Key
	session *hwfake.Key
	sink    *secretSink
	logs    *lockedBuffer
	// posts counts POST /v1/mfa, and bearers those of them that were an
	// idp_mfa proof (an Authorization header).
	posts, bearers atomic.Int32
	// challenges are the challenges the broker saw proved.
	mu         sync.Mutex
	challenges []string
}

func (m *mfaLab) seen(r *http.Request) {
	m.sink.add(r.Header.Get(api.AgentSessionHeader))
	bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if bearer != r.Header.Get("Authorization") {
		m.sink.add(bearer)
	}
	if r.URL.Path != "/v1/mfa" {
		return
	}
	m.posts.Add(1)
	if bearer != r.Header.Get("Authorization") {
		m.bearers.Add(1)
	}
	body, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewReader(body))
	var p api.MFAProofRequest
	if json.Unmarshal(body, &p) == nil {
		m.sink.add(p.Challenge)
		m.sink.add(p.Signature)
		m.mu.Lock()
		m.challenges = append(m.challenges, p.Challenge)
		m.mu.Unlock()
	}
}

// newMFALab starts the lab. withTouch gives the agent the touch key; iss,
// when set, gives the broker that issuer's OIDC verifier beside its
// certificates (so idp_mfa is a method it verifies); acr is the acr_values it
// asks sign-ins to send.
func newMFALab(t *testing.T, withTouch bool, iss *oidctest.Issuer, acr string) *mfaLab {
	t.Helper()
	piv, err := testpki.NewPIV(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	m := &mfaLab{piv: piv, sink: &secretSink{}, logs: &lockedBuffer{}}
	o := labOpts{maxAge: 12 * time.Hour, iss: iss, keepX509: true, mfa: true, acr: acr, logs: m.logs, spy: m.seen}
	if withTouch {
		o.piv = piv
	}
	m.labBroker = newLabBrokerOpts(t, o)
	cert, err := tls.LoadX509KeyPair(filepath.Join(m.dir, testpki.LabClientCert), filepath.Join(m.dir, testpki.LabClientKey))
	if err != nil {
		t.Fatal(err)
	}
	ca, err := os.ReadFile(filepath.Join(m.dir, testpki.LabCA))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca)
	cfg := agent.Config{BrokerURL: m.url, Cert: cert, BrokerCA: pool, Now: time.Now}
	if withTouch {
		sessionKey := cert.PrivateKey.(*ecdsa.PrivateKey)
		m.session = hwfake.New(sessionKey, "/fake/module.so", "TOKEN1")
		touchKey := newTestKey(t)
		m.touch = hwfake.New(touchKey, "/fake/module.so", "TOKEN1")
		touchAtt, err := piv.Slot(&touchKey.PublicKey, pivattest.TouchAlways)
		if err != nil {
			t.Fatal(err)
		}
		sessionAtt, err := piv.Slot(&sessionKey.PublicKey, pivattest.TouchNever)
		if err != nil {
			t.Fatal(err)
		}
		m.touch.SetCertificates(sessionAtt, piv.Device, touchAtt)
		cfg.Cert.PrivateKey, cfg.TouchKey = m.session, m.touch
	}
	m.a = agent.New(cfg)
	if _, err := m.a.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	m.socket = agentStub(t, m.a.Handler())
	return m
}

func (m *mfaLab) token(args ...string) (code int, stdout, stderr string) {
	var out, errb bytes.Buffer
	code = run(append([]string{"token", "--socket", m.socket}, args...), &out, &errb)
	return code, out.String(), errb.String()
}

// withTerminal makes this process's stdin a terminal, or not, for prove.
func withTerminal(t *testing.T, is bool) {
	t.Helper()
	saved := stdinIsTerminal
	stdinIsTerminal = func() bool { return is }
	t.Cleanup(func() { stdinIsTerminal = saved })
}

// port49 token on a device that asks for a second factor prints ruling 17's
// sentence and "touch your key now" on stderr, proves the touch through the
// agent, and mints again naming the challenge: the token alone on stdout.
func TestTokenProvesATouchAndMintsAgain(t *testing.T) {
	m := newMFALab(t, true, nil, "")
	code, out, errb := m.token("leaf1")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errb)
	}
	if strings.Count(out, "\n") != 1 || len(strings.TrimSpace(out)) < 8 {
		t.Fatalf("stdout is not the token alone: %s", tokenOut(out))
	}
	if !strings.Contains(errb, "leaf1 asks for a second factor at each login: ") ||
		!strings.Contains(errb, "accepts hardware_key_touch, idp_mfa (reuse 15m, from ") ||
		strings.Count(errb, "touch your key now") != 1 {
		t.Fatalf("stderr: %q", errb)
	}
	if n := m.posts.Load(); n != 1 {
		t.Fatalf("the broker saw %d proofs, want 1", n)
	}
	if m.touch.Signs() != 1 {
		t.Fatalf("the touch key signed %d times", m.touch.Signs())
	}
	// Reused for the rest of reuse_for: the second token asks for no touch.
	code, out, errb = m.token("leaf1")
	if code != 0 || strings.Contains(errb, "touch your key") || m.posts.Load() != 1 {
		t.Fatalf("a second token inside reuse_for: exit %d stderr %q, %d proofs", code, errb, m.posts.Load())
	}
}

// A touch not made is the key's own words, exit 1, no token, and the command
// says to run it again; nothing was posted, and the key was asked once.
func TestATouchNotMadeIsExitOne(t *testing.T) {
	m := newMFALab(t, true, nil, "")
	m.touch.OnSign(func() error { return hwkey.ErrTouchTimeout })
	code, out, errb := m.token("leaf1")
	if code != 1 || out != "" || !strings.Contains(errb, "no touch within 15s; touch the key when it blinks and try again") {
		t.Fatalf("exit %d stdout %s stderr %q", code, tokenOut(out), errb)
	}
	if m.posts.Load() != 0 || m.touch.Signs() != 1 {
		t.Fatalf("%d proofs posted, the key signed %d times", m.posts.Load(), m.touch.Signs())
	}
	// Touched this time: the same command goes through.
	m.touch.OnSign(nil)
	if code, _, errb = m.token("leaf1"); code != 0 {
		t.Fatalf("the command run again: exit %d: %s", code, errb)
	}
}

// A second per_login_mfa_required is printed and the command stops: never a
// loop of challenges.
func TestASecondRequirementIsNotLooped(t *testing.T) {
	var asks atomic.Int32
	sock := agentStub(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/status":
			_ = json.NewEncoder(w).Encode(agent.Status{TouchKey: true})
		case "/mfa/touch":
			_, _ = io.WriteString(w, "{}")
		default:
			asks.Add(1)
			w.WriteHeader(http.StatusPreconditionRequired)
			_ = json.NewEncoder(w).Encode(coreRequirement())
		}
	}))
	var out, errb bytes.Buffer
	code := run([]string{"token", "--socket", sock, "core-sw01"}, &out, &errb)
	if code != 1 || out.Len() != 0 || asks.Load() != 2 {
		t.Fatalf("exit %d, %d mints, stdout %s, stderr %q", code, asks.Load(), tokenOut(out.String()), errb.String())
	}
	if !strings.Contains(errb.String(), "asks for a second factor") {
		t.Fatalf("stderr: %q", errb.String())
	}
}

// With no touch key and idp_mfa accepted, the sign-in is the proof: at a
// terminal it runs at the identity provider with nonce = MFANonce(challenge)
// and the acr_values the broker names, and its ID token is posted once as the
// bearer; with no terminal it does not run.
func TestTokenFallsBackToTheSignInWhenNoTouchKey(t *testing.T) {
	iss := oidctest.NewIssuer(t)
	m := newMFALab(t, false, iss, "phrh")
	as := iss.AuthServer(t, "port49-cli", "sub-alice",
		map[string]any{"preferred_username": "alice@example.com", "amr": []string{"mfa"}})
	as.Now = m.now
	dir := privateDir(t)
	idpCA := filepath.Join(dir, "idp-ca.pem")
	if err := os.WriteFile(idpCA, iss.CertPEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "config.yaml")
	body := "broker: " + m.url + "\nbroker_ca: " + filepath.Join(m.dir, testpki.LabCA) + "\noidc_ca: " + idpCA + "\n"
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(userconfig.EnvConfig, cfg)

	withTerminal(t, false)
	code, out, errb := m.token("leaf1")
	if code != 1 || out != "" || !strings.Contains(errb, "this device asks for a sign-in at your identity provider and "+
		"there is no terminal; run it at a terminal") || len(as.Authorizations()) != 0 {
		t.Fatalf("no terminal: exit %d stdout %s stderr %q, %d sign-ins", code, tokenOut(out), errb, len(as.Authorizations()))
	}

	withTerminal(t, true)
	savedBrowser, savedPaste := openBrowser, readPaste
	openBrowser = func(u string) error { go func() { _ = iss.Browser()(u) }(); return nil }
	readPaste = func() (string, error) { return "", io.EOF }
	t.Cleanup(func() { openBrowser, readPaste = savedBrowser, savedPaste })
	code, out, errb = m.token("leaf1")
	if code != 0 || strings.Count(out, "\n") != 1 {
		t.Fatalf("at a terminal: exit %d stdout %s stderr %q", code, tokenOut(out), errb)
	}
	if !strings.Contains(errb, "asks for a second factor at each login") {
		t.Fatalf("stderr: %q", errb)
	}
	q := as.Authorizations()
	if len(q) != 1 || q[0].Get("acr_values") != "phrh" || q[0].Get("prompt") != "login" {
		t.Fatalf("the sign-in: %v", q)
	}
	m.mu.Lock()
	challenges := append([]string(nil), m.challenges...)
	m.mu.Unlock()
	if len(challenges) != 1 || m.bearers.Load() != 1 {
		t.Fatalf("the broker saw %d proofs, %d of them bearers", len(challenges), m.bearers.Load())
	}
	raw, err := base64.RawURLEncoding.DecodeString(challenges[0])
	if err != nil || q[0].Get("nonce") != api.MFANonce(raw) {
		t.Fatalf("the sign-in's nonce is not MFANonce(challenge): %v", err)
	}
	m.sink.check(t, errb, out)
	for _, v := range as.Issued() {
		if strings.Contains(errb, v) || strings.Contains(out, v) {
			t.Fatal("an ID token reached the terminal")
		}
	}
	if code, _, errb = m.token("leaf1"); code != 0 || m.bearers.Load() != 1 {
		t.Fatalf("inside reuse_for: exit %d stderr %q, %d bearers", code, errb, m.bearers.Load())
	}
}

// pre-flight I6: a touch key that cannot prove is never tried. The agent's
// status says why; the command says it, and goes on to the sign-in when the
// device accepts it, and stops when the device accepts a touch alone.
func TestATouchKeyThatCannotProveIsNotTried(t *testing.T) {
	const why = "your session key is in the TPM; touch_key needs a session key on the same token"
	for _, tc := range []struct {
		name    string
		methods []string
		want    []string
	}{
		{"both methods", []string{"hardware_key_touch", "idp_mfa"}, []string{why, "this device asks for a sign-in at your " +
			"identity provider and there is no terminal; run it at a terminal"}},
		{"a touch alone", []string{"hardware_key_touch"}, []string{why, "this device accepts only hardware_key_touch"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var touches atomic.Int32
			req := coreRequirement()
			req.Methods = tc.methods
			sock := agentStub(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/status":
					_ = json.NewEncoder(w).Encode(agent.Status{TouchKey: false, TouchKeyUnusable: why})
				case "/mfa/touch":
					touches.Add(1)
					_, _ = io.WriteString(w, "{}")
				default:
					w.WriteHeader(http.StatusPreconditionRequired)
					_ = json.NewEncoder(w).Encode(req)
				}
			}))
			withTerminal(t, false)
			var out, errb bytes.Buffer
			code := run([]string{"token", "--socket", sock, "core-sw01"}, &out, &errb)
			if code != 1 || out.Len() != 0 || touches.Load() != 0 || strings.Contains(errb.String(), "touch your key now") {
				t.Fatalf("exit %d, %d touch posts, stdout %s, stderr %q", code, touches.Load(), tokenOut(out.String()), errb.String())
			}
			for _, w := range tc.want {
				if !strings.Contains(errb.String(), w) {
					t.Errorf("stderr lacks %q: %q", w, errb.String())
				}
			}
		})
	}
}

// port49 refresh on a session with a context under a requirement proves once
// and refreshes again: the second answer extends the device, with no clock
// advance between them and no refresh_too_soon (pre-flight I5).
func TestRefreshProvesOnceAndRefreshesAgain(t *testing.T) {
	m := newMFALab(t, true, nil, "")
	var out, errb bytes.Buffer
	if code := run([]string{"refresh", "--socket", m.socket}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if m.posts.Load() != 1 || strings.Count(errb.String(), "touch your key now") != 1 ||
		!strings.Contains(errb.String(), "asks for a second factor at each login") {
		t.Fatalf("%d proofs; stderr %q", m.posts.Load(), errb.String())
	}
	got := out.String()
	if strings.Count(got, "refreshed at ") != 2 || !strings.Contains(got, "needs a second factor") ||
		!strings.Contains(got, "leaf1 (alice)  extended to ") || strings.Contains(got, "refresh_too_soon") {
		t.Fatalf("stdout: %s", got)
	}
	m.sink.check(t, got, errb.String())
}

// ruling 14: the wire is held to read the exporter value and to post, never
// across the touch, so a revocation does not wait behind a touch nobody has
// made yet.
func TestRevokeIsNotHeldBehindATouch(t *testing.T) {
	m := newMFALab(t, true, nil, "")
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	m.touch.OnSign(func() error {
		once.Do(func() { close(entered) })
		<-release
		return nil
	})
	done := make(chan int, 1)
	go func() {
		code, _, _ := m.token("leaf1")
		done <- code
	}()
	select {
	case <-entered:
	case <-time.After(30 * time.Second):
		t.Fatal("the touch was never asked for")
	}
	revoked := make(chan int, 1)
	var out, errb bytes.Buffer
	go func() {
		revoked <- run([]string{"revoke", "--mine", "--device", "leaf1", "--username", "alice", "--agent-socket", m.socket}, &out, &errb)
	}()
	select {
	case code := <-revoked:
		if code != 0 {
			t.Fatalf("revoke exit %d: %s", code, errb.String())
		}
	case <-time.After(20 * time.Second):
		close(release)
		t.Fatal("the revocation waited behind a touch")
	}
	close(release)
	if code := <-done; code != 0 {
		t.Errorf("the token, touched at last: exit %d", code)
	}
}

// An ended touch over a connection the CLI reports in the error's own text,
// exit 1.
func TestAChangedConnectionIsSaidByTheCommand(t *testing.T) {
	sock := agentStub(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/status":
			_ = json.NewEncoder(w).Encode(agent.Status{TouchKey: true})
		case "/mfa/touch":
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(api.Error{Error: "connection_changed", Detail: agent.ErrConnectionChanged.Error()})
		default:
			w.WriteHeader(http.StatusPreconditionRequired)
			_ = json.NewEncoder(w).Encode(coreRequirement())
		}
	}))
	var out, errb bytes.Buffer
	code := run([]string{"token", "--socket", sock, "core-sw01"}, &out, &errb)
	if code != 1 || out.Len() != 0 || !strings.Contains(errb.String(), "the connection changed during the touch; run it again") {
		t.Fatalf("exit %d: %q", code, errb.String())
	}
}

// The sign-in's proof is the one POST that carries an ID token as a bearer: it
// goes to the broker named, over a connection the CRL check has passed, and a
// redirect is not followed. A broker the check refuses is the check's own
// error, never "unreachable", and nothing is sent to it.
func TestTheSignInsProofIsPostedWhereItWasMeantAndChecked(t *testing.T) {
	var elsewhere, reached atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { elsewhere.Add(1) }))
	t.Cleanup(other.Close)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Add(1)
		http.Redirect(w, r, other.URL+"/v1/mfa", http.StatusTemporaryRedirect)
	}))
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())

	err := postIdPProof(context.Background(), srv.URL, pool, nil, "ID-TOKEN-VALUE", "CHALLENGE")
	if err == nil || !strings.Contains(err.Error(), "307") || elsewhere.Load() != 0 {
		t.Fatalf("a redirected proof: %v; %d requests reached the other server", err, elsewhere.Load())
	}
	if strings.Contains(err.Error(), "ID-TOKEN-VALUE") {
		t.Fatal("the ID token is in the error")
	}

	before := reached.Load()
	revoked := &brokercrl.RevokedError{Subject: "broker", Serial: "01", List: "the CRL"}
	err = postIdPProof(context.Background(), srv.URL, pool, func(tls.ConnectionState) error { return revoked }, "ID-TOKEN-VALUE", "CHALLENGE")
	var no *brokercrl.RevokedError
	if !errors.As(err, &no) || strings.Contains(err.Error(), "unreachable") || reached.Load() != before {
		t.Fatalf("a proof to a broker the CRL check refuses: %v; %d requests reached it", err, reached.Load()-before)
	}
}

// Across the flows above, nothing secret is printed: stderr and stdout hold
// no challenge, no signature, no ID token and no agent session.
func TestNothingSecretIsPrinted(t *testing.T) {
	m := newMFALab(t, true, nil, "")
	code, out, errb := m.token("--json", "leaf1")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errb)
	}
	if m.sink.count() < 3 {
		t.Fatalf("the test saw only %d secrets: it would pass for nothing", m.sink.count())
	}
	var item api.MintItem
	if err := json.Unmarshal([]byte(out), &item); err != nil || item.PerLoginMFA != nil {
		t.Fatalf("--json: %v %+v", err, item.PerLoginMFA)
	}
	m.sink.check(t, errb, out)
	// The agent's own log, the broker's decision log: the same.
	m.sink.check(t, m.logs.String())
}
