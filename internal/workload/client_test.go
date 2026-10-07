package workload

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
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
		t.Fatalf("%+v %v", resp, err)
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
		t.Fatalf("%+v %v", resp, err)
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
	return func(w http.ResponseWriter, _ api.MintRequest) {
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(api.Error{Error: "certificate_status_unavailable",
			Detail: "the broker cannot establish this certificate's revocation status (" + cause + "); try again"})
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

func sum(ds []time.Duration) time.Duration {
	var t time.Duration
	for _, d := range ds {
		t += d
	}
	return t
}
