package workload

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/testpki"
)

// fakeBroker answers /v1/config with batchMax and each /v1/tokens call with
// the next of answers (the last repeating), recording what it was sent.
type fakeBroker struct {
	mu       sync.Mutex
	batchMax int
	answers  []func(w http.ResponseWriter, req api.MintRequest)
	keys     []string
	bodies   []api.MintRequest
	presents []string // the client certificate's fingerprint, per request
}

func (f *fakeBroker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(r.TLS.PeerCertificates) > 0 {
		sum := sha256.Sum256(r.TLS.PeerCertificates[0].Raw)
		f.presents = append(f.presents, hex.EncodeToString(sum[:]))
	}
	switch r.URL.Path {
	case "/v1/config":
		_ = json.NewEncoder(w).Encode(api.Config{BatchMax: f.batchMax})
	case "/v1/identity":
		_ = json.NewEncoder(w).Encode(api.Identity{Principal: "spiffe://corp.example.com/host/oxidized-01", Method: "cert"})
	case "/v1/tokens":
		var req api.MintRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		f.keys = append(f.keys, r.Header.Get("Idempotency-Key"))
		f.bodies = append(f.bodies, req)
		i := min(len(f.keys)-1, len(f.answers)-1)
		f.answers[i](w, req)
	}
}

func permitAll(w http.ResponseWriter, req api.MintRequest) {
	resp := api.MintResponse{Principal: "spiffe://corp.example.com/host/oxidized-01", Subject: "svc_oxidized"}
	for _, d := range req.Devices {
		resp.Results = append(resp.Results, api.MintItem{Device: d, Verdict: "permit", Username: "svc-oxidized",
			Login: "TOKEN" + d})
	}
	_ = json.NewEncoder(w).Encode(resp)
}

func refuse(status int, code, retryAfter string) func(http.ResponseWriter, api.MintRequest) {
	return func(w http.ResponseWriter, _ api.MintRequest) {
		if retryAfter != "" {
			w.Header().Set("Retry-After", retryAfter)
		}
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(api.Error{Error: code, Detail: code + " detail"})
	}
}

type harness struct {
	f       *fakeBroker
	cfg     Config
	now     time.Time
	slept   []time.Duration
	ca      *testpki.CA
	dir     string
	sleepFn func(context.Context, time.Duration) error
}

// newHarness starts a TLS broker that requires a client certificate from
// ca, writes a workload certificate valid for notAfter-from-now into dir
// (0600), and a Config whose clock moves only when the client sleeps.
func newHarness(t *testing.T, f *fakeBroker, life time.Duration) *harness {
	t.Helper()
	h := &harness{f: f, now: time.Now().Truncate(time.Second), dir: t.TempDir()}
	ca, err := testpki.NewCA("workloads", h.now.Add(-time.Hour), h.now.Add(48*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	h.ca = ca
	srvCert, err := ca.Issue(testpki.Leaf{CommonName: "broker", IPs: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: h.now.Add(-time.Hour), NotAfter: h.now.Add(48 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(f)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{srvCert}, ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs: ca.Pool(), MinVersion: tls.VersionTLS13}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	h.writeCert(t, h.now.Add(-time.Minute), h.now.Add(life))
	h.cfg = Config{Broker: srv.URL, BrokerCA: ca.Pool(), CertFile: filepath.Join(h.dir, "w.pem"),
		KeyFile: filepath.Join(h.dir, "w-key.pem"), Now: func() time.Time { return h.now }}
	prevJitter := jitter
	jitter = func(d time.Duration) time.Duration { return d }
	t.Cleanup(func() { jitter = prevJitter })
	h.sleepFn = func(_ context.Context, d time.Duration) error {
		h.slept = append(h.slept, d)
		h.now = h.now.Add(d)
		return nil
	}
	return h
}

func (h *harness) writeCert(t *testing.T, notBefore, notAfter time.Time) {
	t.Helper()
	u, _ := url.Parse("spiffe://corp.example.com/host/oxidized-01")
	c, err := h.ca.Issue(testpki.Leaf{CommonName: "oxidized-01", URIs: []*url.URL{u}, Client: true,
		NotBefore: notBefore, NotAfter: notAfter})
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, err := testpki.PEMs(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.dir, "w.pem"), certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.dir, "w-key.pem"), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
}

func (h *harness) client(t *testing.T) *Client {
	t.Helper()
	c, err := New(h.cfg)
	if err != nil {
		t.Fatal(err)
	}
	c.sleep = h.sleepFn
	return c
}

func devices(n int) []string {
	var out []string
	for i := range n {
		out = append(out, "leaf"+string(rune('1'+i)))
	}
	return out
}

func TestPagesByBatchMaxEachUnderItsOwnKey(t *testing.T) {
	f := &fakeBroker{batchMax: 2, answers: []func(http.ResponseWriter, api.MintRequest){permitAll}}
	h := newHarness(t, f, 24*time.Hour)
	resp, err := h.client(t).Mint(context.Background(), MintOptions{Devices: devices(5), TTL: 15 * time.Minute})
	if err != nil || len(resp.Results) != 5 || resp.Results[4].Device != "leaf5" || resp.Subject != "svc_oxidized" {
		t.Fatalf("%d results, subject %q: %v", len(resp.Results), resp.Subject, err) // never the logins
	}
	if len(f.keys) != 3 || f.keys[0] == f.keys[1] || f.keys[1] == f.keys[2] || f.keys[0] == "" ||
		f.bodies[0].TTLSeconds != 900 || len(f.bodies[2].Devices) != 1 {
		t.Fatalf("keys %v bodies %+v", f.keys, f.bodies)
	}
}

func TestARetryReusesTheKeyAndHonoursRetryAfter(t *testing.T) {
	f := &fakeBroker{batchMax: 10, answers: []func(http.ResponseWriter, api.MintRequest){
		refuse(http.StatusServiceUnavailable, "store_unavailable", "7"),
		refuse(http.StatusConflict, "idempotency_in_progress", "1"),
		permitAll}}
	h := newHarness(t, f, 24*time.Hour)
	if _, err := h.client(t).Mint(context.Background(), MintOptions{Devices: devices(2)}); err != nil {
		t.Fatal(err)
	}
	if len(f.keys) != 3 || f.keys[0] != f.keys[1] || f.keys[1] != f.keys[2] {
		t.Fatalf("a retry under another key: %v", f.keys)
	}
	if len(h.slept) != 2 || h.slept[0] != 7*time.Second || h.slept[1] != time.Second {
		t.Fatalf("slept %v", h.slept)
	}
}

func TestTheDeadlineEndsWithTheUnmintedDevices(t *testing.T) {
	f := &fakeBroker{batchMax: 2, answers: []func(http.ResponseWriter, api.MintRequest){
		permitAll, refuse(http.StatusServiceUnavailable, "store_unavailable", "30")}}
	h := newHarness(t, f, 24*time.Hour)
	resp, err := h.client(t).Mint(context.Background(), MintOptions{Devices: devices(4)})
	var te *TemporaryError
	if !errors.As(err, &te) || !errors.Is(err, ErrTemporary) || strings.Join(te.Unminted, ",") != "leaf3,leaf4" ||
		len(resp.Results) != 2 || !strings.Contains(err.Error(), "503 store_unavailable") {
		t.Fatalf("%d results: %v", len(resp.Results), err) // never the logins
	}
	if total := sum(h.slept); total > DefaultDeadline {
		t.Fatalf("slept %v past the deadline", total)
	}
}

func TestAFinalRefusalIsNotRetried(t *testing.T) {
	f := &fakeBroker{batchMax: 10, answers: []func(http.ResponseWriter, api.MintRequest){
		refuse(http.StatusUnauthorized, "credential_revoked", "")}}
	h := newHarness(t, f, 24*time.Hour)
	_, err := h.client(t).Mint(context.Background(), MintOptions{Devices: devices(1)})
	var ae *APIError
	if !errors.As(err, &ae) || ae.Code != "credential_revoked" || len(f.keys) != 1 || len(h.slept) != 0 {
		t.Fatalf("%v keys %v", err, f.keys)
	}
}

// statusUnavailable answers as the broker does when it cannot establish a
// certificate's status, cause in its detail (certcheck.go).
func statusUnavailable(cause string) func(http.ResponseWriter, api.MintRequest) {
	next := "try again"
	if strings.HasPrefix(cause, api.UncoveredStatus) {
		next = "it stays so until a CRL or OCSP source covers this certificate"
	}
	return func(w http.ResponseWriter, _ api.MintRequest) {
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(api.Error{Error: "certificate_status_unavailable",
			Detail: "the broker cannot establish this certificate's revocation status (" + cause + "); " + next})
	}
}

// No status source covers the workload anchor: the broker answers 503 with
// Retry-After, but nothing changes until the operator adds a CRL or OCSP, so
// it is final here, never "run again" every night (Ruling 7; pre-flight I-2).
func TestAnUncoveredCertificateStatusIsFinal(t *testing.T) {
	f := &fakeBroker{batchMax: 10, answers: []func(http.ResponseWriter, api.MintRequest){
		statusUnavailable(api.UncoveredStatus + ` "CN=Workloads Issuing CA"`), permitAll}}
	h := newHarness(t, f, 24*time.Hour)
	_, err := h.client(t).Mint(context.Background(), MintOptions{Devices: devices(1)})
	var ae *APIError
	if !errors.As(err, &ae) || errors.Is(err, ErrTemporary) || ae.Code != "certificate_status_unavailable" ||
		!strings.Contains(err.Error(), api.UncoveredStatus) || len(f.keys) != 1 || len(h.slept) != 0 {
		t.Fatalf("%v; keys %v slept %v", err, f.keys, h.slept)
	}
}

// An OCSP responder that applies but is down is an outage, not an uncovered
// issuer: retried under the same key (decision 40, ruling 10).
func TestAnOCSPOutageIsRetried(t *testing.T) {
	f := &fakeBroker{batchMax: 10, answers: []func(http.ResponseWriter, api.MintRequest){
		statusUnavailable(`OCSP https://ocsp.port49.lab: did not answer; no fresh CRL covers "CN=Workloads Issuing CA"`),
		permitAll}}
	h := newHarness(t, f, 24*time.Hour)
	if _, err := h.client(t).Mint(context.Background(), MintOptions{Devices: devices(1)}); err != nil ||
		len(f.keys) != 2 || f.keys[0] != f.keys[1] || len(h.slept) != 1 {
		t.Fatalf("%v; keys %v slept %v", err, f.keys, h.slept)
	}
}

// A CRL past its next update is temporary: retried under the same key.
func TestAStaleCRLIsRetried(t *testing.T) {
	f := &fakeBroker{batchMax: 10, answers: []func(http.ResponseWriter, api.MintRequest){
		statusUnavailable("CRL workloads is past its next update, 2026-10-07T03:00:00Z"), permitAll}}
	h := newHarness(t, f, 24*time.Hour)
	if _, err := h.client(t).Mint(context.Background(), MintOptions{Devices: devices(1)}); err != nil ||
		len(f.keys) != 2 || f.keys[0] != f.keys[1] || len(h.slept) != 1 || h.slept[0] != time.Minute {
		t.Fatalf("%v; keys %v slept %v", err, f.keys, h.slept)
	}
}

func TestAnExpiredCertificateNeverConnects(t *testing.T) {
	f := &fakeBroker{batchMax: 10, answers: []func(http.ResponseWriter, api.MintRequest){permitAll}}
	h := newHarness(t, f, time.Hour)
	h.now = h.now.Add(2 * time.Hour)
	_, err := New(h.cfg)
	var ce *CertError
	if !errors.As(err, &ce) || !ce.Expired || !strings.Contains(err.Error(), "renew it against your CA (only the "+
		"first enrollment is manual)") || len(f.presents) != 0 {
		t.Fatalf("%v; requests %d", err, len(f.presents))
	}
}

func TestALateCertificateWarns(t *testing.T) {
	f := &fakeBroker{batchMax: 10, answers: []func(http.ResponseWriter, api.MintRequest){permitAll}}
	h := newHarness(t, f, 4*time.Hour)
	h.now = h.now.Add(3*time.Hour + 30*time.Minute) // about 30m of 4h left
	var warned []string
	h.cfg.Warn = func(format string, args ...any) { warned = append(warned, format) }
	h.client(t)
	if len(warned) != 1 || !strings.Contains(warned[0], "its renewal is late; renew it against your CA") {
		t.Fatalf("%v", warned)
	}
}

// Under a minute left is said in seconds, never "(in )".
func TestALateWarningUnderAMinuteSaysSeconds(t *testing.T) {
	f := &fakeBroker{batchMax: 10, answers: []func(http.ResponseWriter, api.MintRequest){permitAll}}
	h := newHarness(t, f, 4*time.Hour)
	h.now = h.now.Add(4*time.Hour - 20*time.Second)
	var warned string
	h.cfg.Warn = func(format string, args ...any) { warned = fmt.Sprintf(format, args...) }
	h.client(t)
	if !strings.Contains(warned, "(in 20s)") {
		t.Fatalf("%q", warned)
	}
}

// A renewal writes the certificate, then the key: a read in between is read
// again rather than handshaking with a pair that cannot (decision 40 ruling 10).
// The renewer's second write happens in the wait between reads, so the test
// races no clock.
func TestAMismatchedPairIsReadAgain(t *testing.T) {
	f := &fakeBroker{batchMax: 10, answers: []func(http.ResponseWriter, api.MintRequest){permitAll}}
	h := newHarness(t, f, 24*time.Hour)
	oldKey, _ := os.ReadFile(h.cfg.KeyFile)
	h.writeCert(t, h.now.Add(-time.Minute), h.now.Add(24*time.Hour))
	newKey, _ := os.ReadFile(h.cfg.KeyFile)
	if err := os.WriteFile(h.cfg.KeyFile, oldKey, 0o600); err != nil { // mid-renewal: new cert, old key
		t.Fatal(err)
	}
	waits := 0
	prev := betweenReads
	t.Cleanup(func() { betweenReads = prev })
	betweenReads = func() {
		waits++
		_ = os.WriteFile(h.cfg.KeyFile, newKey, 0o600) // the renewer's second write
	}
	if _, err := LoadCertificate(h.cfg.CertFile, h.cfg.KeyFile, h.now, nil); err != nil || waits != 1 {
		t.Fatalf("the pair was not read again: %v (waited %d times)", err, waits)
	}
}

// The files are read at each New: a renewal on disk needs no restart.
func TestARenewalOnDiskIsPresentedAtTheNextRun(t *testing.T) {
	f := &fakeBroker{batchMax: 10, answers: []func(http.ResponseWriter, api.MintRequest){permitAll}}
	h := newHarness(t, f, 24*time.Hour)
	ctx := context.Background()
	if _, err := h.client(t).Identity(ctx); err != nil {
		t.Fatal(err)
	}
	h.writeCert(t, h.now.Add(-time.Minute), h.now.Add(24*time.Hour))
	if _, err := h.client(t).Identity(ctx); err != nil {
		t.Fatal(err)
	}
	if len(f.presents) != 2 || f.presents[0] == f.presents[1] {
		t.Fatalf("presented %v", f.presents)
	}
}

func TestANilBrokerCAIsRefused(t *testing.T) {
	f := &fakeBroker{batchMax: 10, answers: []func(http.ResponseWriter, api.MintRequest){permitAll}}
	h := newHarness(t, f, 24*time.Hour)
	h.cfg.BrokerCA = nil
	if _, err := New(h.cfg); err == nil || !strings.Contains(err.Error(), "broker CA") {
		t.Fatalf("a nil broker CA was accepted: %v", err)
	}
}

func TestAnyBrokerSchemeButHTTPSIsRefused(t *testing.T) {
	f := &fakeBroker{batchMax: 10, answers: []func(http.ResponseWriter, api.MintRequest){permitAll}}
	h := newHarness(t, f, 24*time.Hour)
	for _, u := range []string{"http://127.0.0.1:1", "127.0.0.1:1", "ftp://x", "https://", ""} {
		h.cfg.Broker = u
		if _, err := New(h.cfg); err == nil || !strings.Contains(err.Error(), "https") {
			t.Fatalf("%q accepted: %v", u, err)
		}
	}
}

// A redirect is never followed: the certificate and the tokens go to the
// broker the operator named, alone.
func TestARedirectIsNotFollowed(t *testing.T) {
	f := &fakeBroker{batchMax: 10, answers: []func(http.ResponseWriter, api.MintRequest){
		func(w http.ResponseWriter, _ api.MintRequest) {
			w.Header().Set("Location", "/v1/identity")
			w.WriteHeader(http.StatusTemporaryRedirect)
		}}}
	h := newHarness(t, f, 24*time.Hour)
	_, err := h.client(t).Mint(context.Background(), MintOptions{Devices: devices(1)})
	var re *RedirectError
	var ae *APIError
	if !errors.As(err, &re) || re.Status != http.StatusTemporaryRedirect || errors.As(err, &ae) ||
		errors.Is(err, ErrTemporary) || len(f.presents) != 2 || len(h.slept) != 0 ||
		!strings.Contains(err.Error(), "the broker answered 307, a redirect; the client never follows one") {
		t.Fatalf("%v; %d requests", err, len(f.presents))
	}
}

// A redirect on a later page is final, and the pages minted before it are returned.
func TestARedirectOnALaterPageKeepsThePagesMinted(t *testing.T) {
	redirect := func(w http.ResponseWriter, _ api.MintRequest) {
		w.Header().Set("Location", "/v1/identity")
		w.WriteHeader(http.StatusTemporaryRedirect)
	}
	f := &fakeBroker{batchMax: 1, answers: []func(http.ResponseWriter, api.MintRequest){permitAll, redirect}}
	h := newHarness(t, f, 24*time.Hour)
	resp, err := h.client(t).Mint(context.Background(), MintOptions{Devices: devices(2)})
	var re *RedirectError
	if !errors.As(err, &re) || len(resp.Results) != 1 {
		t.Fatalf("%d results: %v", len(resp.Results), err)
	}
}

// jitter is applied to the connection backoff and the 5s default, never to a
// Retry-After the broker named.
func TestJitterIsAppliedToComputedWaitsOnly(t *testing.T) {
	var got []time.Duration
	record := func(d time.Duration) time.Duration { got = append(got, d); return d }
	f := &fakeBroker{batchMax: 10, answers: []func(http.ResponseWriter, api.MintRequest){
		refuse(http.StatusServiceUnavailable, "store_unavailable", "7"),
		refuse(http.StatusTooManyRequests, "rate_limited", ""), permitAll}}
	h := newHarness(t, f, 24*time.Hour)
	jitter = record
	if _, err := h.client(t).Mint(context.Background(), MintOptions{Devices: devices(1)}); err != nil ||
		len(got) != 1 || got[0] != 5*time.Second {
		t.Fatalf("%v; jitter saw %v", err, got)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h.cfg.Broker = "https://" + l.Addr().String()
	l.Close()
	got = nil
	_, _ = h.client(t).Mint(context.Background(), MintOptions{Devices: devices(1)})
	if len(got) < 2 || got[0] != time.Second || got[1] != 2*time.Second {
		t.Fatalf("jitter saw %v", got)
	}
}

func TestAGatewayErrorIsRetriedUnderTheSameKey(t *testing.T) {
	f := &fakeBroker{batchMax: 10, answers: []func(http.ResponseWriter, api.MintRequest){
		refuse(http.StatusBadGateway, "bad_gateway", ""), refuse(http.StatusGatewayTimeout, "timeout", ""), permitAll}}
	h := newHarness(t, f, 24*time.Hour)
	if _, err := h.client(t).Mint(context.Background(), MintOptions{Devices: devices(1)}); err != nil ||
		len(f.keys) != 3 || f.keys[0] != f.keys[1] || f.keys[1] != f.keys[2] {
		t.Fatalf("%v; keys %v", err, f.keys)
	}
}

func TestAGatewayTimeoutUntilTheDeadlineIsTemporary(t *testing.T) {
	f := &fakeBroker{batchMax: 10, answers: []func(http.ResponseWriter, api.MintRequest){
		refuse(http.StatusGatewayTimeout, "timeout", "")}}
	h := newHarness(t, f, 24*time.Hour)
	_, err := h.client(t).Mint(context.Background(), MintOptions{Devices: devices(2)})
	var te *TemporaryError
	if !errors.As(err, &te) || !errors.Is(err, ErrTemporary) || strings.Join(te.Unminted, ",") != "leaf1,leaf2" ||
		sum(h.slept) > DefaultDeadline {
		t.Fatalf("%v; slept %v", err, h.slept)
	}
}

func TestA429HonoursRetryAfterWithDefaultAndCap(t *testing.T) {
	f := &fakeBroker{batchMax: 10, answers: []func(http.ResponseWriter, api.MintRequest){
		refuse(http.StatusTooManyRequests, "rate_limited", "3"),
		refuse(http.StatusTooManyRequests, "rate_limited", ""),
		refuse(http.StatusTooManyRequests, "rate_limited", "3600"),
		permitAll}}
	h := newHarness(t, f, 24*time.Hour)
	if _, err := h.client(t).Mint(context.Background(), MintOptions{Devices: devices(1)}); err != nil {
		t.Fatal(err)
	}
	want := []time.Duration{3 * time.Second, 5 * time.Second, time.Minute}
	if len(h.slept) != 3 || h.slept[0] != want[0] || h.slept[1] != want[1] || h.slept[2] != want[2] {
		t.Fatalf("slept %v, want %v", h.slept, want)
	}
}

// A broker that refuses connections is backed off from (1s doubling), never
// hammered, and the deadline ends it.
func TestAFailedConnectionBacksOff(t *testing.T) {
	f := &fakeBroker{batchMax: 10, answers: []func(http.ResponseWriter, api.MintRequest){permitAll}}
	h := newHarness(t, f, 24*time.Hour)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h.cfg.Broker = "https://" + l.Addr().String()
	l.Close()
	_, err = h.client(t).Mint(context.Background(), MintOptions{Devices: devices(1)})
	if !errors.Is(err, ErrTemporary) || len(h.slept) < 2 || h.slept[0] != time.Second || h.slept[1] != 2*time.Second ||
		sum(h.slept) > DefaultDeadline {
		t.Fatalf("%v; slept %v", err, h.slept)
	}
}

func TestJitterStaysWithinAFifthAndSpreads(t *testing.T) {
	seen := map[time.Duration]bool{}
	for range 1000 {
		d := jittered(10 * time.Second)
		if d < 8*time.Second || d > 12*time.Second {
			t.Fatalf("jittered to %v", d)
		}
		seen[d] = true
	}
	if len(seen) < 100 {
		t.Fatalf("only %d distinct waits in 1000", len(seen))
	}
}

// A 200 the client cannot decode says where, never what: the body holds
// tokens when it is a mint's.
func TestADecodeFailureQuotesNothingOfTheBody(t *testing.T) {
	f := &fakeBroker{batchMax: 10, answers: []func(http.ResponseWriter, api.MintRequest){
		func(w http.ResponseWriter, _ api.MintRequest) {
			_, _ = w.Write([]byte(`{"results":[{"login":"SECRETTOKEN"} SECRETTOKEN`))
		},
		func(w http.ResponseWriter, _ api.MintRequest) { _, _ = w.Write([]byte(`{"results":"SECRETTOKEN"}`)) }}}
	h := newHarness(t, f, 24*time.Hour)
	for range 2 {
		_, err := h.client(t).Mint(context.Background(), MintOptions{Devices: devices(1)})
		if err == nil || strings.Contains(err.Error(), "SECRET") || !strings.Contains(err.Error(), "offset") {
			t.Fatalf("%v", err)
		}
	}
}

func sum(ds []time.Duration) time.Duration {
	var t time.Duration
	for _, d := range ds {
		t += d
	}
	return t
}

// A broker whose certificate is not under --broker-ca is not mended by a
// retry: final, naming the trust failure (decision 40 ruling 10).
func TestABrokerOutsideTheBrokerCAIsFinal(t *testing.T) {
	f := &fakeBroker{batchMax: 10, answers: []func(http.ResponseWriter, api.MintRequest){permitAll}}
	h := newHarness(t, f, 24*time.Hour)
	other, err := testpki.NewCA("other", h.now.Add(-time.Hour), h.now.Add(48*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	h.cfg.BrokerCA = other.Pool()
	_, err = h.client(t).Mint(context.Background(), MintOptions{Devices: devices(1)})
	var te *TLSError
	if !errors.As(err, &te) || errors.Is(err, ErrTemporary) || len(h.slept) != 0 {
		t.Fatalf("%v; slept %v", err, h.slept)
	}
	if !strings.Contains(err.Error(), "--broker-ca") {
		t.Fatalf("does not name the trust failure: %v", err)
	}
	if _, err := h.client(t).Identity(context.Background()); !errors.As(err, &te) {
		t.Fatalf("identity: %v", err)
	}
}

// A broker that refuses the workload's certificate with a TLS alert (another
// CA's) is final too.
func TestABrokerRefusingTheCertificateIsFinal(t *testing.T) {
	f := &fakeBroker{batchMax: 10, answers: []func(http.ResponseWriter, api.MintRequest){permitAll}}
	h := newHarness(t, f, 24*time.Hour)
	other, err := testpki.NewCA("other", h.now.Add(-time.Hour), h.now.Add(48*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	h.ca = other
	h.writeCert(t, h.now.Add(-time.Minute), h.now.Add(24*time.Hour))
	_, err = h.client(t).Mint(context.Background(), MintOptions{Devices: devices(1)})
	var te *TLSError
	if !errors.As(err, &te) || errors.Is(err, ErrTemporary) || len(h.slept) != 0 {
		t.Fatalf("%v; slept %v", err, h.slept)
	}
	if !strings.Contains(err.Error(), "refused") {
		t.Fatalf("does not say the broker refused the certificate: %v", err)
	}
}

// A mapped workload's broker in a DC outage past grace answers 503
// directory_unavailable (decision 41 ruling 7): retried under one key to the
// deadline, then temporary, every device unminted.
func TestADirectoryOutageIsRetriedToTheDeadline(t *testing.T) {
	f := &fakeBroker{batchMax: 10, answers: []func(http.ResponseWriter, api.MintRequest){
		refuse(http.StatusServiceUnavailable, "directory_unavailable", "30")}}
	h := newHarness(t, f, 24*time.Hour)
	_, err := h.client(t).Mint(context.Background(), MintOptions{Devices: devices(2)})
	var te *TemporaryError
	if !errors.As(err, &te) || !errors.Is(err, ErrTemporary) || len(te.Unminted) != 2 ||
		!strings.Contains(err.Error(), "503 directory_unavailable") || len(f.keys) < 2 {
		t.Fatalf("%v keys %v", err, f.keys)
	}
	for _, k := range f.keys {
		if k != f.keys[0] {
			t.Fatalf("a retry under another key: %v", f.keys)
		}
	}
}
