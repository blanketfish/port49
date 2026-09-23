package agent

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/testpki"
)

// fakeBroker speaks the broker's wire format and records every mint's
// Idempotency-Key. dropFirst hangs up on the first mint without answering;
// expired answers every mint 401 session_expired; untrusted answers every
// mint 401 trust_domain_unresolved, as the broker does once the certificate
// has expired under the held connection. itemError answers a 200 whose one
// item carries that error code and no verdict, as the broker does for a fault
// on its own side; hollow answers an item with neither.
type fakeBroker struct {
	mu        sync.Mutex
	keys      []string
	dropFirst bool
	expired   bool
	untrusted bool
	itemError string
	hollow    bool
}

func (fb *fakeBroker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/v1/config":
		writeJSON(w, 200, api.Config{Methods: []string{"x509"}, MaxSessionAgeSeconds: 60, BatchMax: 10})
	case "/v1/tokens":
		fb.mu.Lock()
		fb.keys = append(fb.keys, r.Header.Get("Idempotency-Key"))
		n, drop, expired, untrusted := len(fb.keys), fb.dropFirst && len(fb.keys) == 1, fb.expired, fb.untrusted
		itemError, hollow := fb.itemError, fb.hollow
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
		t.Fatalf("two asks must be two mints under two keys: %q %q %q", a.Login, b.Login, keys)
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
