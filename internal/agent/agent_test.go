package agent

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/broker"
	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/daemon/admin"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/engine"
	"github.com/rhwendt/port49/internal/policy"
	"github.com/rhwendt/port49/internal/session"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/memory"
	"github.com/rhwendt/port49/internal/testpki"
	"github.com/rhwendt/port49/internal/token"
)

// fakeBroker speaks the broker's wire format and records every mint's
// Idempotency-Key. dropFirst hangs up on the first mint without answering;
// expired answers every mint 401 session_expired; untrusted answers every
// mint 401 trust_domain_unresolved, as the broker does once the certificate
// has expired under the held connection. itemError answers a 200 whose one
// item carries that error code and no verdict, as the broker does for a fault
// on its own side; hollow answers an item with neither. inProgress answers
// that many mints 409 idempotency_in_progress first, as the broker does while
// an earlier try under the key is still minting. revoked answers every mint
// 401 credential_revoked, as the broker does once an operator revokes the
// principal or the certificate.
//
// For a refresh it issues a challenge and verifies the answer as the broker
// does, over the connection's exporter value, recording the remote address
// each refresh path was asked on. refreshRefusals answers that many
// refreshes with their refusal first, in order; tooSoon answers every
// challenge 429 refresh_too_soon; dropRefresh hangs up on that many refresh
// answers without a reply. order is every refresh path, in arrival order. certStatus answers /v1/config, every mint
// and every refresh 503 certificate_status_unavailable, as the broker does
// when it cannot establish the certificate's status (Task 10).
//
// The API's routes (/v1/identity, /v1/explain, /v1/tokens/revoke) answer
// their entry in answers, and a plain-text 404 without one, as a port49d
// older than plan 7c does.
type fakeBroker struct {
	mu         sync.Mutex
	keys       []string
	dropFirst  bool
	expired    bool
	untrusted  bool
	itemError  string
	hollow     bool
	inProgress int
	revoked    bool

	addrs           map[string][]string
	order           []string
	dropRefresh     int
	nonce           []byte
	refreshRefusals []refusal
	tooSoon         bool
	certStatus      bool
	answers         map[string]refusal
	revokeDelay     time.Duration
}

// refusal is one scripted answer: a status, an api.Error, a Retry-After.
type refusal struct {
	status     int
	e          api.Error
	retryAfter string
}

func (fb *fakeBroker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fb.mu.Lock()
	certStatus := fb.certStatus
	if fb.addrs == nil {
		fb.addrs = map[string][]string{}
	}
	fb.addrs[r.URL.Path] = append(fb.addrs[r.URL.Path], r.RemoteAddr)
	if strings.HasPrefix(r.URL.Path, "/v1/refresh") {
		fb.order = append(fb.order, r.URL.Path)
	}
	fb.mu.Unlock()
	if certStatus && r.URL.Path != "/v1/refresh/challenge" {
		w.Header().Set("Retry-After", "60") // as the broker's writeRefusal answers it
		writeJSON(w, 503, api.Error{Error: "certificate_status_unavailable",
			Detail: "the broker cannot establish this certificate's revocation status (OCSP http://ocsp.example.com: " +
				"no answer within 2s); try again"})
		return
	}
	switch r.URL.Path {
	case "/v1/identity", "/v1/explain", "/v1/tokens/revoke":
		fb.mu.Lock()
		ref, ok := fb.answers[r.URL.Path]
		delay := fb.revokeDelay
		fb.mu.Unlock()
		if r.URL.Path == "/v1/tokens/revoke" && delay > 0 {
			// A revocation slow behind a slow store: it answers after
			// delay, or not at all once the caller has gone. The body is
			// read first: only then does the server see the caller go.
			_, _ = io.Copy(io.Discard, r.Body)
			select {
			case <-time.After(delay):
			case <-r.Context().Done():
				return
			}
		}
		if !ok {
			http.NotFound(w, r)
			return
		}
		if ref.retryAfter != "" {
			w.Header().Set("Retry-After", ref.retryAfter)
		}
		writeJSON(w, ref.status, ref.e)
	case "/v1/config":
		writeJSON(w, 200, api.Config{Methods: []string{"x509"}, MaxSessionAgeSeconds: 60, BatchMax: 10,
			CeilingWarningSeconds: 1800})
	case "/v1/refresh/challenge":
		fb.mu.Lock()
		defer fb.mu.Unlock()
		if fb.tooSoon {
			w.Header().Set("Retry-After", "7")
			writeJSON(w, 429, api.Error{Error: "refresh_too_soon", Detail: "this connection refreshed moments ago; wait and retry"})
			return
		}
		fb.nonce = make([]byte, api.RefreshNonceLen)
		_, _ = rand.Read(fb.nonce)
		writeJSON(w, 200, api.RefreshChallenge{Nonce: base64.RawURLEncoding.EncodeToString(fb.nonce)})
	case "/v1/refresh":
		fb.mu.Lock()
		nonce := fb.nonce
		fb.nonce = nil
		drop := fb.dropRefresh > 0
		if drop {
			fb.dropRefresh--
		}
		var ref *refusal
		if len(fb.refreshRefusals) > 0 {
			ref = &fb.refreshRefusals[0]
			fb.refreshRefusals = fb.refreshRefusals[1:]
		}
		fb.mu.Unlock()
		if drop {
			c, _, _ := w.(http.Hijacker).Hijack()
			c.Close()
			return
		}
		if ref != nil {
			if ref.retryAfter != "" {
				w.Header().Set("Retry-After", ref.retryAfter)
			}
			writeJSON(w, ref.status, ref.e)
			return
		}
		var req api.RefreshRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		got, _ := base64.RawURLEncoding.DecodeString(req.Nonce)
		sig, _ := base64.RawURLEncoding.DecodeString(req.Signature)
		if nonce == nil || !bytes.Equal(got, nonce) {
			writeJSON(w, 401, api.Error{Error: "refresh_challenge_missing"})
			return
		}
		ekm, err := r.TLS.ExportKeyingMaterial(api.RefreshExporterLabel, nil, 32)
		leaf := r.TLS.PeerCertificates[0]
		alg, _ := api.RefreshAlgorithm(leaf.PublicKey)
		if err != nil || leaf.CheckSignature(alg, api.RefreshMessage(nonce, ekm), sig) != nil {
			writeJSON(w, 401, api.Error{Error: "trust_domain_unresolved"})
			return
		}
		at := time.Now().UTC().Truncate(time.Second)
		writeJSON(w, 200, api.RefreshResponse{AuthTime: at.Format(time.RFC3339),
			SessionEndsAt: at.Add(time.Hour).Format(time.RFC3339), Sessions: []api.RefreshedSession{}})
	case "/v1/tokens":
		fb.mu.Lock()
		fb.keys = append(fb.keys, r.Header.Get("Idempotency-Key"))
		n, drop, expired, untrusted := len(fb.keys), fb.dropFirst && len(fb.keys) == 1, fb.expired, fb.untrusted
		revoked := fb.revoked
		itemError, hollow := fb.itemError, fb.hollow
		busy := n <= fb.inProgress
		fb.mu.Unlock()
		if drop {
			c, _, _ := w.(http.Hijacker).Hijack()
			c.Close()
			return
		}
		if expired {
			writeJSON(w, 401, api.Error{Error: "session_expired"})
			return
		}
		if untrusted {
			writeJSON(w, 401, api.Error{Error: "trust_domain_unresolved",
				Detail: "broker: no trusted client certificate: the certificate is valid 2026-09-22T00:00:00Z to 2026-09-23T00:00:00Z"})
			return
		}
		if revoked {
			w.Header().Set("Connection", "close")
			writeJSON(w, 401, api.Error{Error: "credential_revoked",
				Detail: "this principal was revoked at 2026-10-01T00:00:00Z; nothing is minted for it until an operator lifts the revocation (port49 revoke --lift)"})
			return
		}
		if busy {
			w.Header().Set("Retry-After", "1")
			writeJSON(w, 409, api.Error{Error: "idempotency_in_progress"})
			return
		}
		var req api.MintRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if itemError != "" || hollow {
			item := api.MintItem{Device: req.Devices[0]}
			if itemError != "" {
				item.Error, item.Detail = itemError, "inventory gives this device no platform; tell the operator"
			}
			writeJSON(w, 200, api.MintResponse{Principal: "user:alice@example.com", Results: []api.MintItem{item}})
			return
		}
		writeJSON(w, 200, api.MintResponse{Principal: "user:alice@example.com", Results: []api.MintItem{{
			Device: req.Devices[0], Verdict: "permit", Username: "alice", Login: fmt.Sprintf("login-%02d", n)}}})
	}
}

func (fb *fakeBroker) seen() []string {
	fb.mu.Lock()
	defer fb.mu.Unlock()
	return append([]string(nil), fb.keys...)
}

type rig struct {
	a   *Agent
	fb  *fakeBroker
	srv *httptest.Server
	mu  sync.Mutex
	now time.Time
	// refuse makes the broker refuse every new handshake, as it does a
	// certificate that expired or a trust anchor that changed.
	refuse atomic.Bool
	// fault makes the broker fail every new handshake on its own side, as a
	// Go server does with internal_error when it cannot build its config.
	fault atomic.Bool
}

func (r *rig) clock() time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.now
}

func (r *rig) advance(d time.Duration) {
	r.mu.Lock()
	r.now = r.now.Add(d)
	r.mu.Unlock()
}

func newRig(t *testing.T) *rig { return newRigSigned(t, false) }

// newRigSigned builds the rig. The fake broker verifies a client certificate
// only if one is given, as the real one does (Task 10). foreign gives the
// agent a certificate from a CA the broker does not trust, and skips Connect.
func newRigSigned(t *testing.T, foreign bool) *rig { return newRigWith(t, rigOpts{foreign: foreign}) }

// rigOpts are the ways a handshake goes wrong. foreign is a client
// certificate from a CA the broker does not trust; expired is one past its
// NotAfter; wrongAnchor gives the agent a trust anchor that did not issue the
// broker's certificate. Any of them skips Connect.
type rigOpts struct{ foreign, expired, wrongAnchor bool }

func newRigWith(t *testing.T, o rigOpts) *rig {
	t.Helper()
	foreign := o.foreign
	now := time.Now()
	ca, err := testpki.NewCA("agent test ca", now.Add(-time.Hour), now.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	srvCert, err := ca.Issue(testpki.Leaf{CommonName: "broker", IPs: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	cli, err := ca.Issue(testpki.Leaf{CommonName: "alice", Emails: []string{"alice@example.com"}, Client: true,
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if foreign {
		other, err := testpki.NewCA("someone else's CA", now.Add(-time.Hour), now.Add(24*time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if cli, err = other.Issue(testpki.Leaf{CommonName: "alice", Emails: []string{"alice@example.com"}, Client: true,
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	if o.expired {
		if cli, err = ca.Issue(testpki.Leaf{CommonName: "alice", Emails: []string{"alice@example.com"}, Client: true,
			NotBefore: now.Add(-48 * time.Hour), NotAfter: now.Add(-24 * time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	anchor := ca.Pool()
	if o.wrongAnchor {
		other, err := testpki.NewCA("an old broker CA", now.Add(-time.Hour), now.Add(24*time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		anchor = other.Pool()
	}
	r := &rig{fb: &fakeBroker{}, now: now}
	r.srv = httptest.NewUnstartedServer(r.fb)
	r.srv.TLS = &tls.Config{Certificates: []tls.Certificate{srvCert}, ClientCAs: ca.Pool(),
		ClientAuth: tls.VerifyClientCertIfGiven, MinVersion: tls.VersionTLS13,
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			if r.fault.Load() {
				return nil, errors.New("fault")
			}
			return nil, nil
		},
		VerifyConnection: func(tls.ConnectionState) error {
			if r.refuse.Load() {
				return errors.New("refused")
			}
			return nil
		}}
	r.srv.StartTLS()
	t.Cleanup(r.srv.Close)
	r.a = New(Config{BrokerURL: r.srv.URL, Cert: cli, BrokerCA: anchor, Now: r.clock})
	if foreign || o.expired || o.wrongAnchor {
		return r
	}
	if _, err := r.a.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	return r
}

// A certificate the broker's anchor did not issue fails `port49 login` at the
// handshake, rather than logging in with no identity and failing at the first
// mint (plan 3, Decided 3). The broker only requests a certificate
// (VerifyClientCertIfGiven), so this holds only because the agent always
// presents its own.
func TestAnUntrustedCertificateFailsConnect(t *testing.T) {
	r := newRigSigned(t, true)
	if _, err := r.a.Connect(context.Background()); err == nil {
		t.Fatal("Connect with a certificate the broker does not trust must fail")
	}
}

// Every ask is a mint: the agent never hands back a token it handed out
// before, and every mint travels the one connection the handshake opened.
func TestEveryTokenIsAFreshMintOnTheHeldConnection(t *testing.T) {
	r := newRig(t)
	a, err := r.a.Mint(context.Background(), "leaf1", false, 0)
	if err != nil {
		t.Fatal(err)
	}
	b, err := r.a.Mint(context.Background(), "leaf1", false, 0)
	if err != nil {
		t.Fatal(err)
	}
	keys := r.fb.seen()
	if a.Login == b.Login || len(keys) != 2 || keys[0] == "" || keys[0] == keys[1] {
		t.Fatalf("two asks must be two mints under two keys: logins equal %v, keys %q", a.Login == b.Login, keys)
	}
	if n := r.a.Handshakes(); n != 1 {
		t.Fatalf("one session, one handshake; got %d", n)
	}
}

// A dropped connection is re-established on the next ask: one more handshake,
// which on a hardware key is one more touch (design §7).
func TestADroppedConnectionIsReestablished(t *testing.T) {
	r := newRig(t)
	if _, err := r.a.Mint(context.Background(), "leaf1", false, 0); err != nil {
		t.Fatal(err)
	}
	r.srv.CloseClientConnections()
	if _, err := r.a.Mint(context.Background(), "leaf1", false, 0); err != nil {
		t.Fatalf("the ask after a drop must reconnect and mint: %v", err)
	}
	if n := r.a.Handshakes(); n != 2 {
		t.Fatalf("handshakes %d, want 2", n)
	}
}

// A mint whose response was lost is retried on a new connection under the SAME
// key, so the broker replays it rather than cutting a second pair (design §17).
func TestALostResponseIsRetriedUnderTheSameKey(t *testing.T) {
	r := newRig(t)
	r.fb.mu.Lock()
	r.fb.dropFirst = true
	r.fb.mu.Unlock()
	item, err := r.a.Mint(context.Background(), "leaf1", false, 0)
	if err != nil {
		t.Fatal(err)
	}
	keys := r.fb.seen()
	if len(keys) != 2 || keys[0] != keys[1] || item.Login != "login-02" {
		t.Fatalf("keys %q item %+v", keys, item)
	}
}

// A 409 idempotency_in_progress is an earlier try under the key still
// minting at the broker: Mint waits and asks again under the SAME key, so it
// is answered from that try rather than cutting a second pair (design §17),
// and gives up, naming the code, once the wait is past the broker's bound.
func TestAnInProgressAnswerIsWaitedOutUnderTheSameKey(t *testing.T) {
	defer func(d, m time.Duration) { inProgressDelay, inProgressDelayMax = d, m }(inProgressDelay, inProgressDelayMax)
	inProgressDelay, inProgressDelayMax = 10*time.Millisecond, 10*time.Millisecond // the stub asks for 1s
	r := newRig(t)
	r.fb.mu.Lock()
	r.fb.inProgress = 2
	r.fb.mu.Unlock()
	item, err := r.a.Mint(context.Background(), "leaf1", false, 0)
	if err != nil || item.Verdict != "permit" || item.Device != "leaf1" {
		t.Fatalf("Mint: %+v %v", item, err)
	}
	keys := r.fb.seen()
	if len(keys) != 3 || keys[0] == "" || keys[0] != keys[1] || keys[1] != keys[2] {
		t.Fatalf("three requests under one key: %q", keys)
	}

	r = newRig(t)
	r.fb.mu.Lock()
	r.fb.inProgress = 1 << 30
	r.fb.mu.Unlock()
	if _, err := r.a.Mint(context.Background(), "leaf1", false, 0); err == nil ||
		!strings.Contains(err.Error(), "idempotency_in_progress") {
		t.Fatalf("a mint still in progress past the wait: %v", err)
	}
	if n := len(r.fb.seen()); n != inProgressRetries+1 {
		t.Fatalf("%d requests, want %d", n, inProgressRetries+1)
	}
}

// Mint waits out an in-progress answer by the broker's Retry-After, not
// its own delay: the stub asks for 1s, and the agent's own is 10s (Task 3
// review M7).
func TestMintWaitsByTheBrokersRetryAfter(t *testing.T) {
	defer func(d, m time.Duration) { inProgressDelay, inProgressDelayMax = d, m }(inProgressDelay, inProgressDelayMax)
	inProgressDelay, inProgressDelayMax = 10*time.Second, 10*time.Second
	r := newRig(t)
	r.fb.mu.Lock()
	r.fb.inProgress = 1
	r.fb.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	if item, err := r.a.Mint(ctx, "leaf1", false, 0); err != nil || item.Verdict != "permit" {
		t.Fatalf("Mint (waited %v): %+v %v", time.Since(start), item, err)
	}
	if waited := time.Since(start); waited < 900*time.Millisecond {
		t.Fatalf("waited %v; the broker asked for 1s", waited)
	}
}

// The broker's Retry-After sets the wait, capped so no answer parks a login
// for long; without one the agent can read, it waits its own delay.
func TestRetryAfterIsHonouredUpToACap(t *testing.T) {
	for _, tc := range []struct {
		header string
		want   time.Duration
	}{
		{"1", time.Second},
		{"3", 3 * time.Second},
		{"3600", inProgressDelayMax},
		{"", inProgressDelay},
		{"0", inProgressDelay},
		{"-2", inProgressDelay},
		{"Wed, 21 Oct 2026 07:28:00 GMT", inProgressDelay},
	} {
		h := http.Header{}
		if tc.header != "" {
			h.Set("Retry-After", tc.header)
		}
		if got := retryAfter(h); got != tc.want {
			t.Errorf("Retry-After %q: %v, want %v", tc.header, got, tc.want)
		}
	}
}

// The session ends at the first handshake plus max_session_age, whatever
// happened in between; the broker is not asked (plan 3, Decided 11).
func TestTheSessionEndsAtTheCeiling(t *testing.T) {
	r := newRig(t)
	r.advance(61 * time.Second)
	if _, err := r.a.Mint(context.Background(), "leaf1", false, 0); !errors.Is(err, ErrSessionOver) {
		t.Fatalf("past the ceiling: %v", err)
	}
	if len(r.fb.seen()) != 0 {
		t.Fatal("a session past its ceiling must not reach the broker")
	}
}

func TestTheBrokersSessionExpiredEndsTheSession(t *testing.T) {
	r := newRig(t)
	r.fb.mu.Lock()
	r.fb.expired = true
	r.fb.mu.Unlock()
	if _, err := r.a.Mint(context.Background(), "leaf1", false, 0); !errors.Is(err, ErrSessionOver) {
		t.Fatalf("401 session_expired: %v", err)
	}
	select {
	case <-r.a.Done():
	default:
		t.Fatal("the broker ending the session must close Done, so the agent exits")
	}
}

// A certificate the broker stops trusting mid-session — expired under the
// held connection, or revoked — ends the session: the agent answers
// ErrSessionOver saying why, asks the broker nothing more, and Done closes so
// the agent process exits and the next `port49 login` starts a new session
// instead of answering "already logged in" (pre-flight F10).
func TestAnUntrustedAnswerEndsTheSession(t *testing.T) {
	r := newRig(t)
	r.fb.mu.Lock()
	r.fb.untrusted = true
	r.fb.mu.Unlock()
	_, err := r.a.Mint(context.Background(), "leaf1", false, 0)
	if !errors.Is(err, ErrSessionOver) || !strings.Contains(err.Error(), "no longer trusts") {
		t.Fatalf("401 trust_domain_unresolved: %v", err)
	}
	select {
	case <-r.a.Done():
	default:
		t.Fatal("Done must close")
	}
	if _, err := r.a.Mint(context.Background(), "leaf1", false, 0); !errors.Is(err, ErrSessionOver) {
		t.Fatalf("an ended session: %v", err)
	}
	if n := len(r.fb.seen()); n != 1 {
		t.Fatalf("an ended session must not reach the broker again: %d asks", n)
	}
}

// An operator's revocation ends the session: the agent answers
// ErrSessionOver carrying the broker's detail, Done closes, and the next
// Mint asks the broker nothing (spec §5.1.4).
func TestARevocationEndsTheSession(t *testing.T) {
	r := newRig(t)
	r.fb.mu.Lock()
	r.fb.revoked = true
	r.fb.mu.Unlock()
	_, err := r.a.Mint(context.Background(), "leaf1", false, 0)
	if !errors.Is(err, ErrSessionOver) || !strings.Contains(err.Error(), "this principal was revoked at") {
		t.Fatalf("401 credential_revoked: %v", err)
	}
	// A login is refused the same way until the lift: telling the operator
	// to run it sends them round in a circle (final review M9).
	if strings.Contains(err.Error(), "port49 login") {
		t.Fatalf("a revoked session says to log in: %v", err)
	}
	select {
	case <-r.a.Done():
	default:
		t.Fatal("Done must close")
	}
	if _, err := r.a.Mint(context.Background(), "leaf1", false, 0); !errors.Is(err, ErrSessionOver) {
		t.Fatalf("an ended session: %v", err)
	}
	if n := len(r.fb.seen()); n != 1 {
		t.Fatalf("an ended session must not reach the broker again: %d asks", n)
	}
}

// A broker that accepts the TCP connection and never answers the handshake —
// a hung process, a middlebox that swallows it — fails Connect within
// connectTimeout, and the agent's log has already said where it was
// connecting, so `port49 login` has a line to show rather than an empty log
// (pre-flight F9).
func TestConnectSaysWhereAndGivesUp(t *testing.T) {
	// Never accepted: the kernel completes the TCP handshake from the
	// backlog, and the TLS handshake never starts.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	defer func(d time.Duration) { connectTimeout = d }(connectTimeout)
	connectTimeout = 200 * time.Millisecond
	var log strings.Builder
	url := "https://" + ln.Addr().String()
	a := New(Config{BrokerURL: url, Log: &log})
	start := time.Now()
	if _, err := a.Connect(context.Background()); err == nil {
		t.Fatal("a broker that never answers must fail Connect")
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("Connect took %v; connectTimeout was 200ms", took)
	}
	if !strings.Contains(log.String(), "connecting to "+url) {
		t.Fatalf("the log must say where the agent was connecting: %q", log.String())
	}
}

// shortDir is a directory under /tmp: a unix socket path is limited to about
// 108 bytes, and t.TempDir can be longer.
func shortDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "p49a")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

// The socket's directory is its access control: created 0700, and one anyone
// else can enter is refused rather than narrowed.
func TestTheSocketDirectoryIsPrivate(t *testing.T) {
	base := shortDir(t)
	p := filepath.Join(base, "s", "agent.sock")
	ln, err := Listen(p)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if fi, _ := os.Stat(filepath.Dir(p)); fi.Mode().Perm() != 0o700 {
		t.Fatalf("directory mode %v", fi.Mode().Perm())
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode %v", fi.Mode().Perm())
	}
	wide := filepath.Join(base, "wide")
	if err := os.Mkdir(wide, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(wide, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(filepath.Join(wide, "agent.sock")); err == nil || !strings.Contains(err.Error(), "0700") {
		t.Fatalf("a directory others can enter: %v", err)
	}
	// A symlink is refused even to a private directory: on the /tmp fallback,
	// whoever planted it owns where the socket lands (pre-flight F4). The
	// owner check beside it is TestADirectoryAnotherUserOwnsIsRefused.
	target := filepath.Join(base, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(filepath.Join(link, "agent.sock")); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("a symlinked directory: %v", err)
	}
}

// A socket path longer than a Unix socket address holds is refused by name,
// with what to do about it, not as a bare "bind: invalid argument". A long
// $XDG_RUNTIME_DIR or --socket is how an operator gets there (T14 review).
func TestASocketPathTooLongIsRefusedByName(t *testing.T) {
	base := shortDir(t)
	fits := filepath.Join(base, strings.Repeat("d", maxSocketPath-len(base)-len("/agent.sock")-1), "agent.sock")
	if len(fits) != maxSocketPath {
		t.Fatalf("test setup: %d bytes", len(fits))
	}
	ln, err := Listen(fits)
	if err != nil {
		t.Fatalf("a path of exactly %d bytes fits: %v", maxSocketPath, err)
	}
	ln.Close()
	long := filepath.Join(base, strings.Repeat("d", maxSocketPath-len(base)-len("/agent.sock")), "agent.sock")
	_, err = Listen(long)
	if err == nil || !strings.Contains(err.Error(), "too long") || !strings.Contains(err.Error(), "--socket") {
		t.Fatalf("a %d-byte socket path: %v", len(long), err)
	}
	if _, err := os.Stat(filepath.Dir(long)); !os.IsNotExist(err) {
		t.Fatal("a path that cannot be a socket creates no directory")
	}
}

// A real directory at 0700 that another user created first — the squatter on
// /tmp/port49-<uid> — passes every check but ownership, and ownership is what
// lets them swap the socket (pre-flight F4). Seen as another uid, the
// directory this test made is that squatter's: the agent will not listen in
// it and the client will not dial into it.
func TestADirectoryAnotherUserOwnsIsRefused(t *testing.T) {
	dir := filepath.Join(shortDir(t), "squat")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	defer func(f func() int) { getuid = f }(getuid)
	getuid = func() int { return os.Getuid() + 1 }
	p := filepath.Join(dir, "agent.sock")
	if _, err := Listen(p); err == nil || !strings.Contains(err.Error(), "not owned by you") {
		t.Fatalf("Listen in a directory another user owns: %v", err)
	}
	if _, err := NewClient(p).Token(context.Background(), TokenRequest{Device: "leaf1"}); err == nil ||
		!strings.Contains(err.Error(), "not owned by you") {
		t.Fatalf("Token through a directory another user owns: %v", err)
	}
}

func TestTheClientTalksToTheAgentOverItsSocket(t *testing.T) {
	r := newRig(t)
	base := shortDir(t)
	p := filepath.Join(base, "s", "agent.sock")
	ln, err := Listen(p)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: r.a.Handler()}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	c := NewClient(p)
	item, err := c.Token(context.Background(), TokenRequest{Device: "leaf1"})
	if err != nil || item.Login != "login-01" || item.Verdict != "permit" {
		t.Fatalf("%+v %v", item, err)
	}
	if st, err := c.Status(context.Background()); err != nil || st.Handshakes != 1 || st.SessionEndsAt == "" {
		t.Fatalf("status %+v %v", st, err)
	}
	r.advance(61 * time.Second)
	if _, err := c.Token(context.Background(), TokenRequest{Device: "leaf1"}); !errors.Is(err, ErrSessionOver) {
		t.Fatalf("an ended session through the socket: %v", err)
	}
	if _, err := NewClient(filepath.Join(base, "nobody.sock")).Token(context.Background(), TokenRequest{Device: "leaf1"}); !errors.Is(err, ErrNoAgent) {
		t.Fatalf("no agent: %v", err)
	}
}

// A handshake the broker refuses reaches the operator as its likely causes,
// not as a bare TLS alert: the broker cannot say why in TLS 1.3, so the agent
// names what to check. An expired certificate is named by its own date,
// which the agent can see without the broker.
func TestARefusedHandshakeNamesTheLikelyCauses(t *testing.T) {
	for _, c := range []struct {
		name string
		o    rigOpts
		want []string
	}{
		{"another CA", rigOpts{foreign: true}, []string{"refused this certificate", "expired", "trust anchor", "exactly one email address"}},
		{"expired", rigOpts{expired: true}, []string{"refused this certificate", "your certificate expired at"}},
		{"wrong anchor", rigOpts{wrongAnchor: true}, []string{"broker's certificate", "trust anchor"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newRigWith(t, c.o)
			_, err := r.a.Connect(context.Background())
			if err == nil {
				t.Fatal("Connect must fail")
			}
			for _, w := range c.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("%q does not say %q", err, w)
				}
			}
		})
	}
}

// A reconnect the broker refuses ends the session as its trust_domain_unresolved
// answer does (pre-flight F10): nothing this session holds will mint again, so
// the agent exits and the next `port49 login` starts fresh. It is not retried,
// and not reported as an unreachable broker.
func TestARefusedReconnectEndsTheSession(t *testing.T) {
	r := newRig(t)
	if _, err := r.a.Mint(context.Background(), "leaf1", false, 0); err != nil {
		t.Fatal(err)
	}
	r.refuse.Store(true)
	r.srv.CloseClientConnections()
	// The alert races the agent's first write (TLS 1.3): an ask on which it
	// lost both attempts is the hang-up diagnosis, and the session stays up
	// until an alert is read. Five asks make a loss on every one negligible.
	var err error
	for i := 0; i < 5; i++ {
		_, err = r.a.Mint(context.Background(), "leaf1", false, 0)
		var hup *hangUpError
		if errors.Is(err, ErrSessionOver) || !errors.As(err, &hup) {
			break
		}
	}
	if !errors.Is(err, ErrSessionOver) || !strings.Contains(err.Error(), "refused this certificate") {
		t.Fatalf("a refused reconnect: %v", err)
	}
	select {
	case <-r.a.Done():
	default:
		t.Fatal("Done must close")
	}
	if n := len(r.fb.seen()); n != 1 {
		t.Fatalf("a refused handshake reaches no handler: %d asks", n)
	}
}

// A broker that is not there is not a refused certificate: the session stays
// up, so the ask after the broker comes back mints.
func TestAnUnreachableBrokerLeavesTheSession(t *testing.T) {
	r := newRig(t)
	r.srv.Listener.Close()
	r.srv.CloseClientConnections()
	_, err := r.a.Mint(context.Background(), "leaf1", false, 0)
	if err == nil || errors.Is(err, ErrSessionOver) || !strings.Contains(err.Error(), "unreachable") {
		t.Fatalf("an unreachable broker: %v", err)
	}
	select {
	case <-r.a.Done():
		t.Fatal("an unreachable broker must not end the session")
	default:
	}
}

// An item the broker could not decide carries an error and no verdict. It is
// an error from Mint and from the socket client, naming the device and the
// code, so no caller can print an empty verdict and move on.
func TestAnItemErrorReachesTheOperator(t *testing.T) {
	r := newRig(t)
	r.fb.mu.Lock()
	r.fb.itemError = "device_unconfigured"
	r.fb.mu.Unlock()
	item, err := r.a.Mint(context.Background(), "leaf1", false, 0)
	var ie *ItemError
	if !errors.As(err, &ie) || ie.Code != "device_unconfigured" || item.Error != "device_unconfigured" {
		t.Fatalf("Mint: %+v %v", item, err)
	}
	for _, w := range []string{"leaf1", "device_unconfigured", "no platform"} {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("%q does not say %q", err, w)
		}
	}

	base := shortDir(t)
	p := filepath.Join(base, "s", "agent.sock")
	ln, err := Listen(p)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: r.a.Handler()}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	item, err = NewClient(p).Token(context.Background(), TokenRequest{Device: "leaf1"})
	if !errors.As(err, &ie) || ie.Code != "device_unconfigured" || !strings.Contains(err.Error(), "leaf1") {
		t.Fatalf("through the socket: %+v %v", item, err)
	}
}

// attribute_too_long (plan 4) is the broker refusing a session reply that
// would not fit on the wire; the operator is told that, not "could not answer".
func TestAnAttributeTooLongItemSaysWhy(t *testing.T) {
	err := &ItemError{Device: "leaf1", Code: "attribute_too_long", Detail: "tell the operator"}
	if !strings.Contains(err.Error(), "too long once filled in") || !strings.Contains(err.Error(), "leaf1") {
		t.Fatalf("%v", err)
	}
}

// attribute_unsafe is the broker refusing a session reply a substituted value
// would break with `=`, `*`, a control character or invalid UTF-8.
func TestAnAttributeUnsafeItemSaysWhy(t *testing.T) {
	err := &ItemError{Device: "leaf1", Code: "attribute_unsafe", Detail: "tell the operator"}
	if !strings.Contains(err.Error(), "a character port49 refuses") || !strings.Contains(err.Error(), "leaf1") {
		t.Fatalf("%v", err)
	}
}

// An item with neither a verdict nor an error is a broker this agent does not
// understand, and is an error rather than a silent empty answer.
func TestAnItemWithNoVerdictIsAnError(t *testing.T) {
	r := newRig(t)
	r.fb.mu.Lock()
	r.fb.hollow = true
	r.fb.mu.Unlock()
	if _, err := r.a.Mint(context.Background(), "leaf1", false, 0); err == nil {
		t.Fatal("an item with no verdict and no error must be an error")
	}
}

// The socket carries why the session ended, so `port49 token` can say it.
func TestTheSocketSaysWhyTheSessionEnded(t *testing.T) {
	r := newRig(t)
	r.fb.mu.Lock()
	r.fb.untrusted = true
	r.fb.mu.Unlock()
	base := shortDir(t)
	p := filepath.Join(base, "s", "agent.sock")
	ln, err := Listen(p)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: r.a.Handler()}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	_, err = NewClient(p).Token(context.Background(), TokenRequest{Device: "leaf1"})
	if !errors.Is(err, ErrSessionOver) || !strings.Contains(err.Error(), "no longer trusts") {
		t.Fatalf("through the socket: %v", err)
	}
}

// A revocation reaches `port49 token` through the socket still
// ErrSessionOver, saying who lifts it and not to log in (final review M9).
func TestTheSocketSaysARevocationWithoutSayingToLogIn(t *testing.T) {
	r := newRig(t)
	r.fb.mu.Lock()
	r.fb.revoked = true
	r.fb.mu.Unlock()
	base := shortDir(t)
	p := filepath.Join(base, "s", "agent.sock")
	ln, err := Listen(p)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: r.a.Handler()}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	_, err = NewClient(p).Token(context.Background(), TokenRequest{Device: "leaf1"})
	if !errors.Is(err, ErrSessionOver) || err.Error() != "agent: the session is over: this principal was revoked at "+
		"2026-10-01T00:00:00Z; nothing is minted for it until an operator lifts the revocation (port49 revoke --lift)" {
		t.Fatalf("through the socket: %v", err)
	}
}

// An alert that is not about the certificate — the broker failing on its own
// side, internal_error — is a broker that is briefly unusable, not one that
// distrusts this session: the session stays up and the ask after it recovers
// mints.
func TestATransientAlertLeavesTheSession(t *testing.T) {
	r := newRig(t)
	r.fault.Store(true)
	r.srv.CloseClientConnections()
	_, err := r.a.Mint(context.Background(), "leaf1", false, 0)
	if err == nil || errors.Is(err, ErrSessionOver) || !strings.Contains(err.Error(), "unreachable") {
		t.Fatalf("an internal_error alert: %v", err)
	}
	select {
	case <-r.a.Done():
		t.Fatal("a non-certificate alert must not end the session")
	default:
	}
	r.fault.Store(false)
	if _, err := r.a.Mint(context.Background(), "leaf1", false, 0); err != nil {
		t.Fatalf("the ask after the broker recovers: %v", err)
	}
}

// The client checks the socket's directory as the agent does before it
// dials: on the /tmp fallback another user can own the path, and whatever
// listens there would learn which device the operator is about to log in to
// (pre-flight F4). Nothing is dialed, and nothing is created.
func TestTheClientRefusesADirectoryThatIsNotPrivate(t *testing.T) {
	base := shortDir(t)
	wide := filepath.Join(base, "wide")
	if err := os.Mkdir(wide, 0o700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(wide, "agent.sock")
	ln, err := net.Listen("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	dialed := make(chan struct{}, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			dialed <- struct{}{}
			c.Close()
		}
	}()
	if err := os.Chmod(wide, 0o755); err != nil {
		t.Fatal(err)
	}
	c := NewClient(p)
	if _, err := c.Token(context.Background(), TokenRequest{Device: "leaf1"}); err == nil || !strings.Contains(err.Error(), "0700") {
		t.Fatalf("Token through a directory others can enter: %v", err)
	}
	if _, err := c.Status(context.Background()); err == nil || !strings.Contains(err.Error(), "0700") {
		t.Fatalf("Status through a directory others can enter: %v", err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(wide, link); err != nil {
		t.Fatal(err)
	}
	if _, err := NewClient(filepath.Join(link, "agent.sock")).Token(context.Background(), TokenRequest{Device: "leaf1"}); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("Token through a symlinked directory: %v", err)
	}
	select {
	case <-dialed:
		t.Fatal("the client dialed a socket in a directory it refused")
	case <-time.After(100 * time.Millisecond):
	}
	missing := filepath.Join(base, "missing", "agent.sock")
	if _, err := NewClient(missing).Token(context.Background(), TokenRequest{Device: "leaf1"}); !errors.Is(err, ErrNoAgent) {
		t.Fatalf("a directory that is not there is no agent: %v", err)
	}
	if _, err := os.Stat(filepath.Dir(missing)); !os.IsNotExist(err) {
		t.Fatal("the client must not create the directory")
	}
}

// rawBroker is a TLS listener that does, per connection, what serve says:
// the i-th connection (from 1) is handed to serve after its handshake. It
// is how a test makes the broker hang up at an exact moment.
func rawBroker(t *testing.T, serve func(i int, c *tls.Conn, raw *net.TCPConn)) (url string, ca *testpki.CA, cli tls.Certificate) {
	t.Helper()
	now := time.Now()
	ca, err := testpki.NewCA("raw broker ca", now.Add(-time.Hour), now.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	srvCert, err := ca.Issue(testpki.Leaf{CommonName: "broker", IPs: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if cli, err = ca.Issue(testpki.Leaf{CommonName: "alice", Emails: []string{"alice@example.com"}, Client: true,
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	cfg := &tls.Config{Certificates: []tls.Certificate{srvCert}, ClientCAs: ca.Pool(),
		ClientAuth: tls.VerifyClientCertIfGiven, MinVersion: tls.VersionTLS13, SessionTicketsDisabled: true}
	go func() {
		for i := 1; ; i++ {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go func(i int) {
				defer raw.Close()
				c := tls.Server(raw, cfg)
				if c.Handshake() != nil {
					return
				}
				serve(i, c, raw.(*net.TCPConn))
			}(i)
		}
	}()
	return "https://" + ln.Addr().String(), ca, cli
}

// hangUp closes a connection with no alert: reset drops it with an RST, as
// a closed socket does to a write that arrives after the close; otherwise a
// FIN, which the agent reads as EOF.
func hangUp(raw *net.TCPConn, reset bool) {
	if reset {
		_ = raw.SetLinger(0)
	}
	raw.Close()
}

// answerOne reads one request and answers it as the broker would.
func answerOne(c *tls.Conn, br *bufio.Reader) bool {
	req, err := http.ReadRequest(br)
	if err != nil {
		return false
	}
	// A week: past the client certificate's day, so a test can move the
	// agent's clock beyond the certificate without ending the session first.
	var body any = api.Config{Methods: []string{"x509"}, MaxSessionAgeSeconds: 7 * 24 * 3600, BatchMax: 10}
	if req.URL.Path == "/v1/refresh/challenge" {
		body = api.RefreshChallenge{Nonce: base64.RawURLEncoding.EncodeToString(make([]byte, api.RefreshNonceLen))}
	}
	if req.URL.Path == "/v1/tokens" {
		var mr api.MintRequest
		_ = json.NewDecoder(req.Body).Decode(&mr)
		body = api.MintResponse{Principal: "user:alice@example.com", Results: []api.MintItem{{
			Device: mr.Devices[0], Verdict: "permit", Username: "alice", Login: "login"}}}
	}
	_, _ = io.Copy(io.Discard, req.Body)
	b, _ := json.Marshal(body)
	_, err = fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", len(b), b)
	return err == nil
}

// A broker that refuses the certificate may close the connection before the
// agent reads its alert: in TLS 1.3 the client's handshake is done first, and
// its first request then meets a reset or an EOF. That is still reported as a
// likely refusal, with its causes — every time, not only when the alert wins
// the race.
func TestAHangUpAfterTheHandshakeNamesTheLikelyCauses(t *testing.T) {
	for _, reset := range []bool{true, false} {
		t.Run(fmt.Sprintf("reset=%v", reset), func(t *testing.T) {
			url, ca, cli := rawBroker(t, func(_ int, _ *tls.Conn, raw *net.TCPConn) { hangUp(raw, reset) })
			a := New(Config{BrokerURL: url, Cert: cli, BrokerCA: ca.Pool()})
			_, err := a.Connect(context.Background())
			if err == nil {
				t.Fatal("Connect must fail")
			}
			for _, w := range []string{"right after the handshake", "refused this certificate", "expired", "client_ca_file",
				"exactly one email address"} {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("%q does not say %q", err, w)
				}
			}
		})
	}
}

// Mid-session, a hang-up on a new connection is diagnosed the same way, but
// it does not end the session: only an alert says for certain that the
// certificate was refused.
func TestAHangUpOnReconnectLeavesTheSession(t *testing.T) {
	url, ca, cli := rawBroker(t, func(i int, c *tls.Conn, raw *net.TCPConn) {
		if i == 1 {
			// The session's first connection answers Connect, then drops.
			answerOne(c, bufio.NewReader(c))
		}
		hangUp(raw, true)
	})
	a := New(Config{BrokerURL: url, Cert: cli, BrokerCA: ca.Pool()})
	if _, err := a.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, err := a.Mint(context.Background(), "leaf1", false, 0)
	if err == nil || errors.Is(err, ErrSessionOver) || !strings.Contains(err.Error(), "right after the handshake") {
		t.Fatalf("a hang-up on reconnect: %v", err)
	}
	select {
	case <-a.Done():
		t.Fatal("a hang-up must not end the session")
	default:
	}
}

// A reset on a connection that has already answered is the network or a
// restarting broker, never a diagnosis about the certificate: the ask is
// retried on a new connection and mints.
func TestAResetLaterInTheSessionIsNotACertificateProblem(t *testing.T) {
	url, ca, cli := rawBroker(t, func(_ int, c *tls.Conn, raw *net.TCPConn) {
		// Every connection answers one request, then resets on the next.
		br := bufio.NewReader(c)
		if answerOne(c, br) {
			_, _ = br.Peek(1)
		}
		hangUp(raw, true)
	})
	a := New(Config{BrokerURL: url, Cert: cli, BrokerCA: ca.Pool()})
	if _, err := a.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Mint(context.Background(), "leaf1", false, 0); err != nil {
		t.Fatalf("a reset on an answered connection must be retried, not diagnosed: %v", err)
	}
	select {
	case <-a.Done():
		t.Fatal("a reset must not end the session")
	default:
	}
}

// A hang-up on reconnect when the agent's own clock says its certificate has
// expired ends the session as the alert would have: no broker will take that
// certificate again, and a session kept up would answer the next
// `port49 login` "already logged in" (pre-flight F10). Over a real network the
// RST that follows a refusal can discard the alert, so this is the common
// shape of a certificate expiring mid-session.
func TestAHangUpWithAnExpiredCertificateEndsTheSession(t *testing.T) {
	url, ca, cli := rawBroker(t, func(i int, c *tls.Conn, raw *net.TCPConn) {
		if i == 1 {
			answerOne(c, bufio.NewReader(c))
		}
		hangUp(raw, true)
	})
	var mu sync.Mutex
	now := time.Now()
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	a := New(Config{BrokerURL: url, Cert: cli, BrokerCA: ca.Pool(), Now: clock})
	if _, err := a.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	now = now.Add(25 * time.Hour) // the client certificate is good for a day
	mu.Unlock()
	_, err := a.Mint(context.Background(), "leaf1", false, 0)
	if !errors.Is(err, ErrSessionOver) || !strings.Contains(err.Error(), "your certificate expired at") {
		t.Fatalf("a hang-up with an expired certificate: %v", err)
	}
	select {
	case <-a.Done():
	default:
		t.Fatal("Done must close")
	}
}

// realRig is the agent on a real broker behind its own Listener, as port49d
// serves it, with one live context for alice on leaf1 that has 1h left. The
// broker and the agent share a clock the test moves.
type realRig struct {
	a     *Agent
	b     *broker.Broker
	st    *memory.Store
	alice tls.Certificate
	mu    sync.Mutex
	now   time.Time
}

func (r *realRig) clock() time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.now
}

func (r *realRig) advance(d time.Duration) {
	r.mu.Lock()
	r.now = r.now.Add(d)
	r.mu.Unlock()
}

const realPolicy = `
scopes: [{name: all_devices, match: {}}]
roles: [{name: r, privilege: admin, permit: ["**"]}]
subjects: [{name: s, identity: ["user:alice@example.com"], username: alice, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [r]}]
`

func newRealRig(t *testing.T) *realRig {
	t.Helper()
	r := &realRig{now: time.Now().Truncate(time.Second)}
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(realPolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	leaf1 := admission.Device{Name: "leaf1", Platform: "arista_eos", Addresses: []netip.Addr{netip.MustParseAddr("172.100.100.11")}}
	pol, err := policy.Load(path, policy.Env{Devices: []admission.Device{leaf1}})
	if err != nil {
		t.Fatal(err)
	}
	ca, err := testpki.NewCA("agent test ca", r.now.Add(-time.Hour), r.now.Add(48*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	srvCert, err := ca.Issue(testpki.Leaf{CommonName: "broker", IPs: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: r.now.Add(-time.Hour), NotAfter: r.now.Add(48 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if r.alice, err = ca.Issue(testpki.Leaf{CommonName: "alice", Emails: []string{"alice@example.com"}, Client: true,
		NotBefore: r.now.Add(-time.Hour), NotAfter: r.now.Add(48 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	r.st = memory.New(r.clock)
	log := decision.NewJSONLines(io.Discard)
	r.b = &broker.Broker{Policy: policy.NewLive(pol),
		Minter: token.NewMinter(r.st, log, rand.Reader, token.TagKey([]byte("k")), r.clock, 8),
		Store:  r.st, Log: log, Metrics: metrics.New(prometheus.NewRegistry()), Now: r.clock,
		MaxSessionAge: time.Hour, BatchMax: 4, Sessions: session.New(r.st, r.clock, time.Hour, time.Hour),
		ContextIdleTTL: time.Hour, CeilingWarning: 30 * time.Minute, GraceWindow: 5 * time.Minute}

	// alice's live context on leaf1, as a device login with her token left
	// it: authenticated now, its ceiling an hour out.
	ctx := context.Background()
	res, err := pol.Resolve("user:alice@example.com", leaf1, r.now)
	if err != nil {
		t.Fatal(err)
	}
	body, hash, err := engine.Encode(res.Blob)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.st.PutBlob(ctx, hash, body, 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	k := store.ContextKey{NAS: "leaf1", Username: "alice"}
	if err := r.st.PutContext(ctx, k, store.Context{CtxID: "ctx_leaf1", Principal: "user:alice@example.com",
		Username: "alice", PrivLvl: 1, BlobHash: hash, AuthTime: r.now, SessionExpires: r.now.Add(time.Hour),
		RefreshedAt: r.now, LastTouchedAt: r.now}, 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := r.st.IndexContext(ctx, "user:alice@example.com", "", aliceCertKey(r.alice),
		store.ContextRef{NAS: "leaf1", Username: "alice"}, 24*time.Hour); err != nil {
		t.Fatal(err)
	}

	srv, err := r.b.Server("127.0.0.1:0", srvCert, ca.Pool())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	bl := broker.NewListener(broker.Limit(raw, broker.MaxConns), srv.TLSConfig, broker.DefaultListenerLimits,
		r.b.Metrics, r.b.Now, nil)
	bl.Refused = r.b.RefusedAtBind
	go func() { _ = srv.Serve(bl) }()
	t.Cleanup(func() { _ = srv.Close() })
	r.a = New(Config{BrokerURL: "https://" + raw.Addr().String(), Cert: r.alice, BrokerCA: ca.Pool(), Now: r.clock})
	if _, err := r.a.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	return r
}

func aliceCertKey(c tls.Certificate) string {
	return store.CertKey(c.Leaf.Issuer.String(), c.Leaf.SerialNumber.Text(16))
}

// A refresh signs the broker's challenge on the held connection, and the
// broker extends the live context and the connection's own session: the
// agent's deadline becomes the broker's session_ends_at, DeadlineChanged is
// signalled so the agent process re-arms, and a mint past the first
// deadline goes through (spec §5.6; decision 33; pre-flight I6).
func TestARefreshMovesTheDeadlineToTheBrokers(t *testing.T) {
	r := newRealRig(t)
	first := r.a.SessionEndsAt()
	select {
	case <-r.a.DeadlineChanged():
		t.Fatal("DeadlineChanged before any refresh")
	default:
	}
	r.advance(30 * time.Minute)
	out, err := r.a.Refresh(context.Background())
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if len(out.Sessions) != 1 || out.Sessions[0].Device != "leaf1" || out.Sessions[0].Outcome != "extended" ||
		out.Sessions[0].SessionExpires != r.clock().Add(time.Hour).UTC().Format(time.RFC3339) {
		t.Fatalf("the broker's answer: %+v", out)
	}
	if got := r.a.SessionEndsAt().UTC().Format(time.RFC3339); got != out.SessionEndsAt || !r.a.SessionEndsAt().After(first) {
		t.Fatalf("SessionEndsAt %s, the broker said %s (first %s)", got, out.SessionEndsAt, first)
	}
	select {
	case <-r.a.DeadlineChanged():
	default:
		t.Fatal("a refresh must signal DeadlineChanged")
	}
	r.advance(40 * time.Minute) // past the first deadline, inside the new one
	if item, err := r.a.Mint(context.Background(), "leaf1", false, 0); err != nil || item.Verdict != "permit" {
		t.Fatalf("a mint past the first deadline: %+v %v", item.Verdict, err)
	}
	if n := r.a.Handshakes(); n != 1 {
		t.Fatalf("a refresh is made on the held connection: %d handshakes", n)
	}
}

// A refresh the broker refuses credential_revoked ends the session, as a
// mint's refusal does (spec §5.1.4).
func TestARevokedRefreshEndsTheSession(t *testing.T) {
	r := newRealRig(t)
	first := r.a.SessionEndsAt()
	if err := r.st.PutRevocation(context.Background(), store.Revocation{Kind: store.RevocationPrincipal,
		Key: "user:alice@example.com", At: r.clock(), Origin: "test"}); err != nil {
		t.Fatal(err)
	}
	_, err := r.a.Refresh(context.Background())
	var revoked *RevokedError
	if !errors.As(err, &revoked) || !errors.Is(err, ErrSessionOver) {
		t.Fatalf("a revoked refresh: %v", err)
	}
	select {
	case <-r.a.Done():
	default:
		t.Fatal("Done must close")
	}
	if !r.a.SessionEndsAt().Equal(first) {
		t.Fatal("a refused refresh moved the deadline")
	}
	if _, err := r.a.Refresh(context.Background()); !errors.Is(err, ErrSessionOver) {
		t.Fatalf("a refresh of an ended session: %v", err)
	}
}

// The challenge and its answer travel the one held connection: the answer
// is signed over that connection's exporter value and verifies nowhere
// else (decision 33).
func TestTheChallengeAndTheAnswerShareTheConnection(t *testing.T) {
	r := newRig(t)
	if _, err := r.a.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	r.fb.mu.Lock()
	ch, ans := r.fb.addrs["/v1/refresh/challenge"], r.fb.addrs["/v1/refresh"]
	r.fb.mu.Unlock()
	if len(ch) != 1 || len(ans) != 1 || ch[0] != ans[0] {
		t.Fatalf("challenge from %q, answer from %q", ch, ans)
	}
	if n := r.a.Handshakes(); n != 1 {
		t.Fatalf("%d handshakes", n)
	}
}

// refresh_challenge_missing, a connection dropped between the two requests
// or a hardware touch past the challenge's minute, is tried once with a new
// challenge, and only once.
func TestAMissingChallengeIsTriedOnce(t *testing.T) {
	missing := refusal{status: 401, e: api.Error{Error: "refresh_challenge_missing",
		Detail: "no live refresh challenge on this connection; ask for one and answer it within 60s"}}
	r := newRig(t)
	r.fb.mu.Lock()
	r.fb.refreshRefusals = []refusal{missing}
	r.fb.mu.Unlock()
	if _, err := r.a.Refresh(context.Background()); err != nil {
		t.Fatalf("one missing challenge, then a good one: %v", err)
	}

	r = newRig(t)
	first := r.a.SessionEndsAt()
	r.fb.mu.Lock()
	r.fb.refreshRefusals = []refusal{missing, missing, missing}
	r.fb.mu.Unlock()
	if _, err := r.a.Refresh(context.Background()); err == nil || !strings.Contains(err.Error(), "refresh_challenge_missing") {
		t.Fatalf("two missing challenges: %v", err)
	}
	r.fb.mu.Lock()
	n := len(r.fb.addrs["/v1/refresh/challenge"])
	r.fb.mu.Unlock()
	if n != 2 {
		t.Fatalf("%d challenges, want 2", n)
	}
	select {
	case <-r.a.Done():
		t.Fatal("a missing challenge ended the session")
	default:
	}
	if !r.a.SessionEndsAt().Equal(first) {
		t.Fatal("a failed refresh moved the deadline")
	}
}

// What the broker cannot answer just now ends nothing and moves nothing: a
// 503 at Connect, a mint or a refresh, and a refresh paced 429, return an
// error that says so and leave Done open (pre-flight I7). A refresh's 503
// says the broker's fixed text and its Retry-After.
func TestABrokerUnableToAnswerEndsNothing(t *testing.T) {
	open := func(t *testing.T, r *rig) {
		t.Helper()
		select {
		case <-r.a.Done():
			t.Fatal("Done closed")
		default:
		}
		select {
		case <-r.a.DeadlineChanged():
			t.Fatal("DeadlineChanged signalled")
		default:
		}
	}
	r := newRig(t)
	first := r.a.SessionEndsAt()
	r.fb.mu.Lock()
	r.fb.certStatus = true
	r.fb.mu.Unlock()
	const certText = "agent: the broker cannot establish this certificate's revocation status " +
		"(OCSP http://ocsp.example.com: no answer within 2s); try again; retry in 60s"
	if _, err := r.a.Mint(context.Background(), "leaf1", false, 0); err == nil || !strings.Contains(err.Error(), certText) {
		t.Fatalf("a mint: %v", err)
	}
	if _, err := r.a.Refresh(context.Background()); err == nil || !strings.Contains(err.Error(), certText) {
		t.Fatalf("a refresh: %v", err)
	}
	open(t, r)
	if _, err := r.a.Connect(context.Background()); err == nil || !strings.Contains(err.Error(), certText) {
		t.Fatalf("Connect: %v", err)
	}
	open(t, r)
	if !r.a.SessionEndsAt().Equal(first) {
		t.Fatal("a 503 moved the deadline")
	}

	for name, ref := range map[string]refusal{
		"before any extension": {status: 503, retryAfter: "10", e: api.Error{Error: "store_unavailable",
			Detail: "the broker could not read the revocations in force, so it extended nothing; try again"}},
		"part way": {status: 503, retryAfter: "10", e: api.Error{Error: "store_unavailable",
			Detail: "the broker could not finish extending your live sessions; some may have been extended; " +
				"retry after Retry-After and the retry reports them all"}},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			first := r.a.SessionEndsAt()
			r.fb.mu.Lock()
			r.fb.refreshRefusals = []refusal{ref}
			r.fb.mu.Unlock()
			_, err := r.a.Refresh(context.Background())
			if err == nil || !strings.Contains(err.Error(), ref.e.Detail) || !strings.Contains(err.Error(), "store_unavailable") ||
				!strings.Contains(err.Error(), "retry in 10s") {
				t.Fatalf("%v", err)
			}
			open(t, r)
			if !r.a.SessionEndsAt().Equal(first) {
				t.Fatal("a 503 moved the deadline")
			}
		})
	}

	r = newRig(t)
	r.fb.mu.Lock()
	r.fb.tooSoon = true
	r.fb.mu.Unlock()
	if _, err := r.a.Refresh(context.Background()); err == nil || !strings.Contains(err.Error(), "refresh_too_soon") ||
		!strings.Contains(err.Error(), "retry in 7s") {
		t.Fatalf("a paced refresh: %v", err)
	}
	open(t, r)
}

// The socket carries a refresh and its refusals: POST /refresh answers what
// the broker extended, a revocation comes back a *RevokedError, and /status
// says the broker's ceiling_warning.
func TestTheClientRefreshesOverTheSocket(t *testing.T) {
	r := newRig(t)
	p := filepath.Join(shortDir(t), "s", "agent.sock")
	ln, err := Listen(p)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: r.a.Handler()}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	c := NewClient(p)
	if st, err := c.Status(context.Background()); err != nil || st.CeilingWarningSeconds != 1800 ||
		st.CertFingerprint != CertFingerprint(r.a.cert) || !strings.HasPrefix(st.CertFingerprint, "sha256:") {
		t.Fatalf("status %+v %v", st, err)
	}
	out, err := c.Refresh(context.Background())
	if err != nil || out.SessionEndsAt == "" {
		t.Fatalf("%+v %v", out, err)
	}
	if st, _ := c.Status(context.Background()); st.SessionEndsAt != out.SessionEndsAt {
		t.Fatalf("status says %s, the refresh %s", st.SessionEndsAt, out.SessionEndsAt)
	}

	r.fb.mu.Lock()
	r.fb.tooSoon = true
	r.fb.mu.Unlock()
	if _, err := c.Refresh(context.Background()); err == nil || errors.Is(err, ErrSessionOver) ||
		!strings.HasPrefix(err.Error(), "agent: the broker refused a refresh challenge:") {
		t.Fatalf("a paced refresh through the socket: %v", err)
	}
	r.fb.mu.Lock()
	r.fb.tooSoon = false
	r.fb.refreshRefusals = []refusal{{status: 401, e: api.Error{Error: "credential_revoked",
		Detail: "this principal was revoked at 2026-10-01T00:00:00Z"}}}
	r.fb.mu.Unlock()
	_, err = c.Refresh(context.Background())
	var revoked *RevokedError
	if !errors.As(err, &revoked) || strings.Contains(err.Error(), "port49 login") {
		t.Fatalf("a revoked refresh through the socket: %v", err)
	}
}

// A refresh whose answer is lost in transit, the held connection dropped
// after the answer was sent, is tried once more with a new challenge on a
// new connection, and succeeds there.
func TestALostRefreshAnswerIsTriedOnANewConnection(t *testing.T) {
	r := newRig(t)
	first := r.a.SessionEndsAt()
	r.fb.mu.Lock()
	r.fb.dropRefresh = 1
	r.fb.mu.Unlock()
	if _, err := r.a.Refresh(context.Background()); err != nil {
		t.Fatalf("a lost answer, then a good one: %v", err)
	}
	r.fb.mu.Lock()
	order := append([]string(nil), r.fb.order...)
	r.fb.mu.Unlock()
	if len(order) != 4 || r.a.Handshakes() != 2 || !r.a.SessionEndsAt().After(first) {
		t.Fatalf("order %q, %d handshakes, deadline moved %v", order, r.a.Handshakes(), r.a.SessionEndsAt().After(first))
	}
}

// The connection changing between the challenge and its answer, here the
// challenge's connection closed before the answer goes out, fails closed
// at the real broker (no nonce on the new connection) and is tried once
// more on the new one, which succeeds (decision 33).
func TestAConnectionSwappedUnderARefreshIsTriedAgain(t *testing.T) {
	r := newRealRig(t)
	first := r.a.SessionEndsAt()
	r.advance(time.Minute)
	var (
		mu    sync.Mutex
		held  net.Conn
		gets  int
		swaps int
	)
	ctx := httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{
		GetConn: func(string) {
			mu.Lock()
			defer mu.Unlock()
			gets++
			if gets == 2 && held != nil {
				held.Close() // the answer's turn: the challenge's connection is gone
				swaps++
			}
		},
		GotConn: func(i httptrace.GotConnInfo) {
			mu.Lock()
			defer mu.Unlock()
			if held == nil {
				held = i.Conn
			}
		},
	})
	out, err := r.a.Refresh(ctx)
	if err != nil || len(out.Sessions) != 1 || out.Sessions[0].Outcome != "extended" {
		t.Fatalf("Refresh: %+v %v", out.Sessions, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if swaps != 1 || r.a.Handshakes() != 2 || !r.a.SessionEndsAt().After(first) {
		t.Fatalf("swaps %d, %d handshakes, deadline moved %v", swaps, r.a.Handshakes(), r.a.SessionEndsAt().After(first))
	}
}

// Concurrent refreshes run one at a time: a second challenge never replaces
// the first one's nonce before its answer.
func TestConcurrentRefreshesRunOneAtATime(t *testing.T) {
	r := newRig(t)
	var wg sync.WaitGroup
	errs := make(chan error, 4)
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := r.a.Refresh(context.Background())
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("a concurrent refresh: %v", err)
		}
	}
	r.fb.mu.Lock()
	order := append([]string(nil), r.fb.order...)
	r.fb.mu.Unlock()
	if len(order) != 8 {
		t.Fatalf("order %q", order)
	}
	for i, p := range order {
		want := "/v1/refresh/challenge"
		if i%2 == 1 {
			want = "/v1/refresh"
		}
		if p != want {
			t.Fatalf("order %q: a challenge and its answer interleaved", order)
		}
	}
}

// A refresh of a session already over, ended by the broker or past the
// agent's own deadline, asks the broker nothing.
func TestARefreshOfAnEndedSessionAsksNothing(t *testing.T) {
	r := newRig(t)
	r.fb.mu.Lock()
	r.fb.refreshRefusals = []refusal{{status: 401, e: api.Error{Error: "credential_revoked",
		Detail: "this principal was revoked at 2026-10-01T00:00:00Z"}}}
	r.fb.mu.Unlock()
	var revoked *RevokedError
	if _, err := r.a.Refresh(context.Background()); !errors.As(err, &revoked) {
		t.Fatalf("a revoked refresh: %v", err)
	}
	if _, err := r.a.Refresh(context.Background()); !errors.Is(err, ErrSessionOver) {
		t.Fatalf("a refresh of an ended session: %v", err)
	}
	r.fb.mu.Lock()
	n := len(r.fb.order)
	r.fb.mu.Unlock()
	if n != 2 {
		t.Fatalf("an ended session reached the broker: %d refresh requests, want 2", n)
	}

	r = newRig(t)
	r.advance(61 * time.Second)
	if _, err := r.a.Refresh(context.Background()); !errors.Is(err, ErrSessionOver) {
		t.Fatalf("a refresh past the deadline: %v", err)
	}
	r.fb.mu.Lock()
	n = len(r.fb.order)
	r.fb.mu.Unlock()
	if n != 0 {
		t.Fatalf("a session past its deadline reached the broker: %d refresh requests", n)
	}
}

// A refresh whose reconnect meets a hang-up with the certificate past its
// NotAfter ends the session, as a mint's does, and is not tried again: on
// the challenge's leg, and on the answer's when the connection changed
// between the two (pre-flight F10).
func TestAnExpiredHangUpDuringARefreshEndsTheSession(t *testing.T) {
	for _, leg := range []string{"challenge", "answer"} {
		t.Run(leg, func(t *testing.T) {
			var accepted atomic.Int32
			url, ca, cli := rawBroker(t, func(i int, c *tls.Conn, raw *net.TCPConn) {
				accepted.Add(1)
				switch {
				case i == 1:
					answerOne(c, bufio.NewReader(c)) // Connect's /v1/config
				case i == 2 && leg == "answer":
					// The challenge, answered; then the connection closes,
					// so the answer goes out on a new one.
					answerOne(c, bufio.NewReader(c))
					_ = c.Close()
					return
				}
				hangUp(raw, true)
			})
			var mu sync.Mutex
			now := time.Now()
			clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
			a := New(Config{BrokerURL: url, Cert: cli, BrokerCA: ca.Pool(), Now: clock})
			if _, err := a.Connect(context.Background()); err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			now = now.Add(25 * time.Hour) // the client certificate is good for a day
			mu.Unlock()
			_, err := a.Refresh(context.Background())
			if !errors.Is(err, ErrSessionOver) || !strings.Contains(err.Error(), "your certificate expired at") {
				t.Fatalf("an expired hang-up: %v", err)
			}
			select {
			case <-a.Done():
			default:
				t.Fatal("Done must close")
			}
			want := int32(2)
			if leg == "answer" {
				want = 3
			}
			if n := accepted.Load(); n != want {
				t.Fatalf("%d connections, want %d: an ended session was tried again", n, want)
			}
		})
	}
}

// A reset on the held connection, which has answered before, as the
// refresh's challenge goes out on it is the network or a restarting broker,
// as it is for a mint: the challenge is asked again on a new connection, and
// a hang-up there with the certificate past its NotAfter ends the session.
// Before, the first reset was returned as "unreachable" and the session
// stayed up, whenever the broker's close of the held connection raced the
// refresh.
func TestAResetOnTheHeldConnectionDuringARefreshIsTriedOnANewOne(t *testing.T) {
	var accepted atomic.Int32
	url, ca, cli := rawBroker(t, func(i int, c *tls.Conn, raw *net.TCPConn) {
		accepted.Add(1)
		if i == 1 {
			// Connect's /v1/config, then the challenge arrives here and the
			// connection is reset under it.
			br := bufio.NewReader(c)
			if answerOne(c, br) {
				_, _ = br.Peek(1)
			}
		}
		hangUp(raw, true)
	})
	var mu sync.Mutex
	now := time.Now()
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	a := New(Config{BrokerURL: url, Cert: cli, BrokerCA: ca.Pool(), Now: clock})
	if _, err := a.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	now = now.Add(25 * time.Hour) // the client certificate is good for a day
	mu.Unlock()
	_, err := a.Refresh(context.Background())
	if !errors.Is(err, ErrSessionOver) || !strings.Contains(err.Error(), "your certificate expired at") {
		t.Fatalf("a reset on the held connection, then an expired hang-up: %v", err)
	}
	if n := accepted.Load(); n != 2 {
		t.Fatalf("%d connections, want 2: the challenge was not asked again on a new one", n)
	}
}

// socketFor serves r's agent on a private socket and returns a Client on
// it, as TestTheClientRefreshesOverTheSocket does.
func socketFor(t *testing.T, a *Agent) *Client {
	t.Helper()
	p := filepath.Join(shortDir(t), "s", "agent.sock")
	ln, err := Listen(p)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: a.Handler()}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return NewClient(p)
}

// The agent carries identity, explain and revoke over the session's held
// connection, through its socket, and hands a broker refusal back as it
// came: 403 api_right_missing is an *APIError the CLI can name, and a
// credential_revoked ends the session as a mint's does.
func TestTheAgentCarriesTheAPI(t *testing.T) {
	r := newRealRig(t)
	ctx := context.Background()
	c := socketFor(t, r.a)
	id, err := c.Identity(ctx)
	if err != nil || id.Principal != "user:alice@example.com" {
		t.Fatalf("identity: %+v %v", id, err)
	}
	ex, err := c.Explain(ctx, api.ExplainRequest{Device: "leaf1"})
	if err != nil || ex.Verdict == "" || ex.Text == "" {
		t.Fatalf("explain: %+v %v", ex, err)
	}
	_, err = c.Explain(ctx, api.ExplainRequest{Device: "leaf1", Principal: "user:carol@example.com"})
	var ae *APIError
	if !errors.As(err, &ae) || ae.Status != 403 || ae.Code != "api_right_missing" {
		t.Fatalf("explaining another without the right: %v", err)
	}
	rv, err := c.Revoke(ctx, api.RevokeRequest{Mine: true})
	if err != nil || rv.By != "self" || rv.Standing {
		t.Fatalf("revoke mine: %+v %v", rv, err)
	}
	if _, err := c.Identity(ctx); err != nil {
		t.Fatalf("the session after a self-revocation: %v", err) // no mark: it goes on
	}
	if err := r.st.PutRevocation(ctx, store.Revocation{Kind: store.RevocationPrincipal,
		Key: "user:alice@example.com", At: r.clock(), Origin: "test"}); err != nil {
		t.Fatal(err)
	}
	_, err = c.Identity(ctx)
	var revoked *RevokedError
	if !errors.As(err, &revoked) || !errors.Is(err, ErrSessionOver) {
		t.Fatalf("identity under a mark: %v", err)
	}
	select {
	case <-r.a.Done():
	default:
		t.Fatal("a mark did not end the agent's session")
	}
}

// A CLI newer than the running agent: the agent's mux has no route for the
// call, and the client says to log in again, never "the broker refused"
// (pre-flight I9).
func TestAnOlderAgentIsNamedNotBlamedOnTheBroker(t *testing.T) {
	p := filepath.Join(shortDir(t), "s", "agent.sock")
	ln, err := Listen(p)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.NewServeMux()} // an agent with none of the new routes
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	_, err = NewClient(p).Identity(context.Background())
	var ae *APIError
	if !errors.Is(err, ErrAgentTooOld) || errors.As(err, &ae) || !strings.Contains(err.Error(), "port49 login") {
		t.Fatalf("%v", err)
	}
}

// A broker older than the agent has no route for the call: the client gets
// an *APIError naming the broker, not ErrAgentTooOld, so the two upgrade
// orders read differently (pre-flight I9). The session goes on.
func TestAnOlderBrokerIsNamedAsTheBroker(t *testing.T) {
	r := newRig(t)
	_, err := socketFor(t, r.a).Identity(context.Background())
	var ae *APIError
	if !errors.As(err, &ae) || ae.Status != 404 || ae.Code != "not_supported" || errors.Is(err, ErrAgentTooOld) ||
		!strings.Contains(ae.Detail, "older than this port49") {
		t.Fatalf("%v", err)
	}
	select {
	case <-r.a.Done():
		t.Fatal("an older broker ended the session")
	default:
	}
}

// A 503 revocation_busy, another revocation still running or the caller's
// own one still in flight, reaches the CLI as an *APIError with the broker's
// status, code and detail, and ends nothing: the operator asks again.
func TestABusyRevocationIsAnAPIErrorAndEndsNothing(t *testing.T) {
	r := newRig(t)
	busy := refusal{status: 503, retryAfter: "5", e: api.Error{Error: "revocation_busy",
		Detail: "another revocation of yours is still running, so nothing was revoked by this one; try again once it finishes"}}
	r.fb.mu.Lock()
	r.fb.answers = map[string]refusal{"/v1/tokens/revoke": busy}
	r.fb.mu.Unlock()
	check := func(what string, err error) {
		t.Helper()
		var ae *APIError
		if !errors.As(err, &ae) || ae.Status != 503 || ae.Code != "revocation_busy" || ae.Detail != busy.e.Detail ||
			ae.RetryAfter != 5*time.Second || !strings.HasSuffix(err.Error(), "; retry in 5s") ||
			errors.Is(err, ErrSessionOver) {
			t.Fatalf("%s: %v", what, err)
		}
		select {
		case <-r.a.Done():
			t.Fatalf("%s: a busy revocation ended the session", what)
		default:
		}
	}
	_, err := r.a.Revoke(context.Background(), api.RevokeRequest{Mine: true})
	check("the agent", err)
	_, err = socketFor(t, r.a).Revoke(context.Background(), api.RevokeRequest{Mine: true})
	check("through the socket", err)
	if _, err := r.a.Mint(context.Background(), "leaf1", false, 0); err != nil {
		t.Fatalf("a mint after a busy revocation: %v", err)
	}
}

// A revocation the broker is slower to answer than the agent waits is sent
// once, never again: the broker may have marked, and a second try would
// queue behind the first and answer revocation_busy, "nothing was revoked"
// (final review I1). The operator is told it may be in force and where to
// look, and the session goes on.
func TestAnUnansweredRevocationIsSentOnceAndMayBeInForce(t *testing.T) {
	defer func(d time.Duration) { revokeTimeout = d }(revokeTimeout)
	revokeTimeout = 200 * time.Millisecond
	r := newRig(t)
	r.fb.mu.Lock()
	r.fb.answers = map[string]refusal{"/v1/tokens/revoke": {status: 200}}
	r.fb.revokeDelay = 5 * time.Second
	r.fb.mu.Unlock()
	c := socketFor(t, r.a)
	for _, tc := range []struct {
		name  string
		req   api.RevokeRequest
		where string
	}{
		{"a principal", api.RevokeRequest{Principal: "user:carol@example.com"}, "it may be in force — check " +
			"`port49 revoke --list` (on port49d's host) and port49d's log before retrying"},
		{"mine", api.RevokeRequest{Mine: true},
			"it may have run — check port49d's decision log (event revoke) before retrying"},
		{"a key", api.RevokeRequest{Device: "leaf1", Username: "alice"},
			"it may have run — check port49d's decision log (event revoke) before retrying"},
	} {
		for _, via := range []string{"the agent", "the socket"} {
			r.fb.mu.Lock()
			r.fb.addrs = nil
			r.fb.mu.Unlock()
			var err error
			if via == "the agent" {
				_, err = r.a.Revoke(context.Background(), tc.req)
			} else {
				_, err = c.Revoke(context.Background(), tc.req)
			}
			r.fb.mu.Lock()
			n := len(r.fb.addrs["/v1/tokens/revoke"])
			r.fb.mu.Unlock()
			if n != 1 {
				t.Fatalf("%s through %s: the broker saw %d revocations, want exactly 1", tc.name, via, n)
			}
			var ae *APIError
			if err == nil || errors.As(err, &ae) || errors.Is(err, ErrSessionOver) ||
				!strings.Contains(err.Error(), "did not answer the revocation") || !strings.Contains(err.Error(), tc.where) ||
				strings.Contains(err.Error(), "nothing was revoked") {
				t.Fatalf("%s through %s: %v", tc.name, via, err)
			}
		}
	}
	select {
	case <-r.a.Done():
		t.Fatal("an unanswered revocation ended the session")
	default:
	}
}

// The agent's wait on a revocation outlasts the broker's worst case: the
// wait for the slot, the run port49d bounds at admin.OpTimeout, the
// revocations_file save. The socket client outlasts the agent, so the agent
// is always the side that gives up and says so (final review I1).
func TestTheRevocationWaitsOutlastTheBroker(t *testing.T) {
	if broker.DefaultRevokeTimeout > admin.OpTimeout {
		t.Fatalf("the broker's default run bound %v is past the admin.OpTimeout %v the agent waits on",
			broker.DefaultRevokeTimeout, admin.OpTimeout)
	}
	worst := api.RevokeSlotWait + admin.OpTimeout + admin.PersistTimeout
	if revokeWait <= worst || socketTimeout <= revokeWait {
		t.Fatalf("broker %v, agent %v, socket %v", worst, revokeWait, socketTimeout)
	}
}

// A revocation the agent took and then dropped without an answer is not
// "no agent": it may have reached the broker, and the CLI says so.
func TestARevocationTheAgentDroppedMayBeInForce(t *testing.T) {
	p := filepath.Join(shortDir(t), "s", "agent.sock")
	ln, err := Listen(p)
	if err != nil {
		t.Fatal(err)
	}
	var got atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("POST /revoke", func(w http.ResponseWriter, r *http.Request) {
		got.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		conn, _, _ := w.(http.Hijacker).Hijack()
		conn.Close() // an agent that died mid-revocation
	})
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	_, err = NewClient(p).Revoke(context.Background(), api.RevokeRequest{Principal: "user:carol@example.com"})
	if got.Load() != 1 || err == nil || errors.Is(err, ErrNoAgent) || !strings.Contains(err.Error(), "may be in force") ||
		!strings.Contains(err.Error(), "`port49 revoke --list`") {
		t.Fatalf("%d asked: %v", got.Load(), err)
	}
}

// A certificate_status_unavailable is said by the broker's detail alone,
// as unavailable says it, with the minute the broker asked for.
func TestAnAPICertificateStatusRefusalSaysTheDetailAlone(t *testing.T) {
	r := newRig(t)
	ref := refusal{status: 503, retryAfter: "60", e: api.Error{Error: "certificate_status_unavailable",
		Detail: "the broker cannot establish this certificate's revocation status (OCSP http://ocsp.example.com: " +
			"no answer within 2s); try again"}}
	r.fb.mu.Lock()
	r.fb.answers = map[string]refusal{"/v1/explain": ref}
	r.fb.mu.Unlock()
	_, err := socketFor(t, r.a).Explain(context.Background(), api.ExplainRequest{Device: "leaf1"})
	var ae *APIError
	if !errors.As(err, &ae) || err.Error() != "agent: "+ref.e.Detail+"; retry in 60s" {
		t.Fatalf("%v", err)
	}
}

// A 410 is the agent's own word for its session's end: one relayed from
// the broker reaches the client as a 502, never as ErrSessionOver while
// the agent's session runs on.
func TestARelayedGoneIsNotTheSessionsEnd(t *testing.T) {
	r := newRig(t)
	r.fb.mu.Lock()
	r.fb.answers = map[string]refusal{"/v1/identity": {status: 410, e: api.Error{Error: "gone", Detail: "a proxy's"}}}
	r.fb.mu.Unlock()
	_, err := socketFor(t, r.a).Identity(context.Background())
	var ae *APIError
	if !errors.As(err, &ae) || ae.Status != http.StatusBadGateway || ae.Code != "gone" || errors.Is(err, ErrSessionOver) {
		t.Fatalf("%v", err)
	}
	select {
	case <-r.a.Done():
		t.Fatal("a relayed 410 ended the session")
	default:
	}
}

// The socket's /explain and /revoke take one object and nothing after it,
// as the broker does, so a request is never narrowed in silence: trailing
// data is refused before the broker is asked.
func TestTheSocketRefusesTrailingData(t *testing.T) {
	r := newRig(t)
	c := socketFor(t, r.a)
	for path, body := range map[string]string{
		"/explain": `{"device":"leaf1"} {"device":"leaf2"}`,
		"/revoke":  `{"mine":true} {"principal":"user:bob@example.com"}`,
	} {
		resp, err := c.http.Post("http://agent"+path, "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		var e api.Error
		_ = json.NewDecoder(resp.Body).Decode(&e)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest || e.Error != "bad_request" {
			t.Fatalf("%s: %d %+v", path, resp.StatusCode, e)
		}
	}
	r.fb.mu.Lock()
	defer r.fb.mu.Unlock()
	if n := len(r.fb.addrs["/v1/explain"]) + len(r.fb.addrs["/v1/tokens/revoke"]); n != 0 {
		t.Fatalf("the broker was asked %d times", n)
	}
}
