package broker

import (
	"bufio"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/rhwendt/port49/internal/agent"
	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/certstatus"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/store"
)

// fakeStatus answers a set Result per leaf serial (Good otherwise) and
// counts its calls.
type fakeStatus struct {
	mu       sync.Mutex
	bySerial map[string]certstatus.Result
	calls    int
}

func (s *fakeStatus) Check(_ context.Context, chain []*x509.Certificate) certstatus.Result {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if r, ok := s.bySerial[chain[0].SerialNumber.Text(16)]; ok {
		return r
	}
	return certstatus.Result{Verdict: certstatus.Good, Source: "crl", Name: "corp"}
}

func (s *fakeStatus) set(c tls.Certificate, r certstatus.Result) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.bySerial == nil {
		s.bySerial = map[string]certstatus.Result{}
	}
	s.bySerial[c.Leaf.SerialNumber.Text(16)] = r
}

func (s *fakeStatus) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

var (
	revokedAt     = time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	revokedByCRL  = certstatus.Result{Verdict: certstatus.Revoked, Source: "crl", Name: "corp", RevokedAt: revokedAt}
	revokedByOCSP = certstatus.Result{Verdict: certstatus.Revoked, Source: "ocsp", Name: "http://ocsp.example.com",
		RevokedAt: revokedAt}
	unknownStatus = certstatus.Result{Verdict: certstatus.Unknown, Source: "none",
		Detail: "CRL corp is past its next update, 2026-10-01T00:00:00Z"}
)

const mintBody = `{"devices":["leaf1"]}`

// withStatus gives f's broker fs and onUnavailable, and runs its revocation
// queue until the test ends; a non-nil logs takes the process log first.
func withStatus(t *testing.T, f *fixture, onUnavailable string, logs *lockedBuffer) *fakeStatus {
	t.Helper()
	if logs != nil {
		prev := log.Writer()
		log.SetOutput(logs)
		t.Cleanup(func() { log.SetOutput(prev) })
	}
	fs := &fakeStatus{}
	f.b.CertStatus, f.b.OnUnavailable = fs, onUnavailable
	runQueue(t, f)
	return fs
}

// runQueue runs f's revocation queue until the test ends.
func runQueue(t *testing.T, f *fixture) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { f.b.RunRevocationQueue(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
}

// serveWithStatus is serveThrough with Listener.Status and Broker.Conns
// wired as port49d wires them.
func serveWithStatus(t *testing.T, f *fixture, lim ListenerLimits) (string, *Listener) {
	t.Helper()
	addr, bl := serveThroughWith(t, f, lim, nil, func(l *Listener) { l.Status = f.b.BindStatus })
	f.b.Conns = bl
	return addr, bl
}

// certRevocations is how many certificate revocations have been recorded:
// counted after the record is written, so a reader that sees it may read
// the record.
func certRevocations(f *fixture) float64 {
	return testutil.ToFloat64(f.b.Metrics.Revocations.WithLabelValues(store.RevocationCert, "applied"))
}

func markOn(t *testing.T, f *fixture, c tls.Certificate) (store.Revocation, bool) {
	t.Helper()
	rv, err := f.st.GetRevocation(context.Background(), store.RevocationCert, certKey(c))
	if errors.Is(err, store.ErrNotFound) {
		return rv, false
	}
	if err != nil {
		t.Fatal(err)
	}
	return rv, true
}

// waitMark waits for the queued revocation of c and wants its origin.
func waitMark(t *testing.T, f *fixture, c tls.Certificate, origin string) {
	t.Helper()
	eventually(t, "the queued revocation", func() bool { _, ok := markOn(t, f, c); return ok })
	if rv, _ := markOn(t, f, c); rv.Origin != origin {
		t.Fatalf("the mark's origin: %q, want %q", rv.Origin, origin)
	}
}

// boundAnswer dials addr with cert, sends a mint, and returns the answer;
// the broker then closes the connection.
func boundAnswer(t *testing.T, f *fixture, addr string, cert tls.Certificate) heldAnswer {
	t.Helper()
	c, err := tls.Dial("tcp", addr, &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: f.ca.Pool(),
		MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := io.WriteString(c, mintRequest); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("a connection refused at bind was not answered: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !closedByPeer(c) {
		t.Fatal("a connection refused at bind was left open")
	}
	return heldAnswer{status: resp.StatusCode, body: string(body), retryAfter: resp.Header.Get("Retry-After")}
}

// lastRecord is the last record of event, with its reason and verdict.
func lastRecord(t *testing.T, f *fixture, event string) map[string]any {
	t.Helper()
	recs := eventsOf(f.records(t), event)
	if len(recs) == 0 {
		t.Fatalf("no %s record", event)
	}
	return recs[len(recs)-1]
}

func wantDeny(t *testing.T, rec map[string]any, reason string) {
	t.Helper()
	if rec["verdict"] != "deny" || rec["reason"] != reason || rec["principal"] != alicePrincipal {
		t.Fatalf("want deny %s for alice: %v", reason, rec)
	}
}

// A certificate its CA revoked is refused at bind, at mint and at refresh
// credential_revoked, and then revoked through Revoke, from the queue, with
// the source as its origin (spec §5.1.4; decision 33).
func TestARevokedLeafIsRefusedAndRevoked(t *testing.T) {
	t.Run("bind", func(t *testing.T) {
		f := newFixture(t, 8)
		fs := withStatus(t, f, "refuse", nil)
		addr, _ := serveWithStatus(t, f, DefaultListenerLimits)
		f.liveContext(t, "leaf1", "alice", alicePrincipal, certKey(f.alice))
		fs.set(f.alice, revokedByCRL)
		a := boundAnswer(t, f, addr, f.alice)
		if a.status != 401 || !strings.Contains(a.body, `"credential_revoked"`) ||
			!strings.Contains(a.body, "was revoked at its CA (crl corp, 2026-09-30T12:00:00Z)") {
			t.Fatalf("%s", reply(a.status, a.body))
		}
		eventually(t, "the revocation", func() bool { return certRevocations(f) == 1 })
		waitMark(t, f, f.alice, "crl corp")
		wantDeny(t, lastRecord(t, f, "mint"), "credential_revoked")
		if n := testutil.ToFloat64(f.b.Metrics.BrokerConnectionEvents.WithLabelValues("revoked_refused")); n != 1 {
			t.Fatalf("revoked_refused: %v", n)
		}
	})

	// The revocation a bind's refusal carries is queued only once bind has
	// chosen that refusal: queued sooner, the queue's mark could land
	// between the status check and bind, and the answer would be the mark's
	// ("an operator lifts the revocation") rather than the CA's, with
	// revoked_refused never counted. The status check here gives the queue
	// every chance to mark first.
	t.Run("bind answers the CA before the queue's mark", func(t *testing.T) {
		f := newFixture(t, 8)
		fs := withStatus(t, f, "refuse", nil)
		addr, bl := serveThroughWith(t, f, DefaultListenerLimits, nil, func(l *Listener) {
			l.Status = func(cs tls.ConnectionState, principal string, cred store.Credential) *BindRefusal {
				ref := f.b.BindStatus(cs, principal, cred)
				deadline := time.Now().Add(250 * time.Millisecond)
				for time.Now().Before(deadline) {
					if _, ok := markOn(t, f, f.alice); ok {
						break
					}
					time.Sleep(5 * time.Millisecond)
				}
				return ref
			}
		})
		f.b.Conns = bl // as serveWithStatus wires it: Revoke marks the listener
		f.liveContext(t, "leaf1", "alice", alicePrincipal, certKey(f.alice))
		fs.set(f.alice, revokedByCRL)
		a := boundAnswer(t, f, addr, f.alice)
		if a.status != 401 || !strings.Contains(a.body, "was revoked at its CA (crl corp, 2026-09-30T12:00:00Z)") {
			t.Fatalf("%s", reply(a.status, a.body))
		}
		waitMark(t, f, f.alice, "crl corp")
		if n := testutil.ToFloat64(f.b.Metrics.BrokerConnectionEvents.WithLabelValues("revoked_refused")); n != 1 {
			t.Fatalf("revoked_refused: %v", n)
		}
	})

	// Once the queue has marked it, the certificate's next connection is
	// answered from the mark, and the mark a CA's revocation wrote says so:
	// it never offers an operator's lift, which the CA's list would undo at
	// the next bind.
	t.Run("a CA's mark offers no lift", func(t *testing.T) {
		f := newFixture(t, 8)
		fs := withStatus(t, f, "refuse", nil)
		addr, _ := serveWithStatus(t, f, DefaultListenerLimits)
		f.liveContext(t, "leaf1", "alice", alicePrincipal, certKey(f.alice))
		fs.set(f.alice, revokedByCRL)
		boundAnswer(t, f, addr, f.alice)
		waitMark(t, f, f.alice, "crl corp")
		a := boundAnswer(t, f, addr, f.alice)
		if a.status != 401 || !strings.Contains(a.body, `"credential_revoked"`) ||
			!strings.Contains(a.body, "was revoked at its CA (crl corp)") || strings.Contains(a.body, "lift") {
			t.Fatalf("%s", reply(a.status, a.body))
		}
	})

	// A revoked certificate never takes a slot or evicts its owner's
	// renewed certificate's connections (pre-flight I1).
	t.Run("bind holds no slot", func(t *testing.T) {
		f := newFixture(t, 8)
		fs := withStatus(t, f, "refuse", nil)
		addr, _ := serveWithStatus(t, f, ListenerLimits{MaxPendingPerSource: 16, MaxPerPrincipal: 4,
			HandshakeTimeout: 10 * time.Second})
		renewed := f.client(t, "alice@example.com", f.now.Add(24*time.Hour))
		fs.set(f.alice, revokedByCRL)
		type conn struct {
			c  *tls.Conn
			br *bufio.Reader
		}
		var owner []conn
		for i := 0; i < 4; i++ {
			c, br := held(t, f, addr, renewed)
			owner = append(owner, conn{c, br})
		}
		for i := 0; i < 10; i++ {
			if a := boundAnswer(t, f, addr, f.alice); a.status != 401 {
				t.Fatalf("bind %d of the revoked certificate: %s", i, reply(a.status, a.body))
			}
		}
		for _, o := range owner {
			ask(t, o.c, o.br) // fails the test if the connection was closed
		}
		if n := testutil.ToFloat64(f.b.Metrics.BrokerConnections.WithLabelValues("held")); n != 4 {
			t.Fatalf("held gauge: %v", n)
		}
		if n := testutil.ToFloat64(f.b.Metrics.BrokerConnectionEvents.WithLabelValues("principal_cap_evicted")); n != 0 {
			t.Fatalf("principal_cap_evicted: %v", n)
		}
	})

	for _, tc := range []struct {
		name   string
		res    certstatus.Result
		origin string
	}{
		{"mint crl", revokedByCRL, "crl corp"},
		{"mint ocsp", revokedByOCSP, "ocsp http://ocsp.example.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, 8)
			fs := withStatus(t, f, "refuse", nil)
			f.liveContext(t, "leaf1", "alice", alicePrincipal, certKey(f.alice))
			fs.set(f.alice, tc.res)
			w := f.post(context.Background(), f.state(f.alice), mintBody, "k1")
			if w.Code != 401 || !strings.Contains(w.Body.String(), `"credential_revoked"`) ||
				w.Header().Get("Connection") != "close" {
				t.Fatalf("%s %v", answer(w), w.Header())
			}
			if f.live(t, "leaf1") != 0 {
				t.Fatal("a revoked certificate minted")
			}
			// The queued revocation writes the log too: read it once that is done.
			eventually(t, "the revocation", func() bool { return certRevocations(f) == 1 })
			waitMark(t, f, f.alice, tc.origin)
			wantDeny(t, lastRecord(t, f, "mint"), "credential_revoked")
		})
	}

	// On the held connection the queued revocation closes, the answer is
	// read whole first: the agent reads credential_revoked, not a hang-up.
	t.Run("mint on a held connection", func(t *testing.T) {
		f := newFixture(t, 8)
		fs := withStatus(t, f, "refuse", nil)
		addr, _ := serveWithStatus(t, f, DefaultListenerLimits)
		c, br := held(t, f, addr, f.alice)
		f.liveContext(t, "leaf1", "alice", alicePrincipal, certKey(f.alice))
		fs.set(f.alice, revokedByCRL)
		if a := postOn(t, c, br, "/v1/tokens", mintBody); a.status != 401 || !strings.Contains(a.body, `"credential_revoked"`) {
			t.Fatalf("%s", reply(a.status, a.body))
		}
		eventually(t, "the revocation", func() bool { return certRevocations(f) == 1 })
		waitMark(t, f, f.alice, "crl corp")
		if !closedByPeer(c) {
			t.Fatal("the held connection was left open")
		}
	})

	t.Run("refresh", func(t *testing.T) {
		f := newFixture(t, 8)
		fs := withStatus(t, f, "refuse", nil)
		addr, _ := serveWithStatus(t, f, DefaultListenerLimits)
		c, br := held(t, f, addr, f.alice)
		auth := f.now
		f.liveContextAt(t, "leaf1", "alice", alicePrincipal, certKey(f.alice), auth, auth.Add(time.Hour))
		fs.set(f.alice, revokedByCRL)
		nonce, text := challengeOn(t, c, br)
		if s, body := answerOn(t, c, br, c, f.alice, nonce, text); s != 401 || !strings.Contains(body, `"credential_revoked"`) {
			t.Fatalf("%s", reply(s, body))
		}
		eventually(t, "the revocation", func() bool { return certRevocations(f) == 1 })
		waitMark(t, f, f.alice, "crl corp")
		wantDeny(t, lastRecord(t, f, "refresh"), "credential_revoked")
		got, _ := f.st.GetContext(context.Background(), store.ContextKey{NAS: "leaf1", Username: "alice"})
		if !got.AuthTime.Equal(auth) {
			t.Fatalf("a revoked certificate's context was extended: auth_time %v", got.AuthTime)
		}
	})
}

// A revoked intermediate refuses the leaf, naming the intermediate, and
// marks nothing: the leaf is not what its CA revoked (pre-flight I2). A
// hold refuses and marks nothing: the CA lifts it (M13).
func TestARevokedIntermediateOrAHoldRefusesWithoutAMark(t *testing.T) {
	for _, tc := range []struct {
		name string
		res  certstatus.Result
		want string
	}{
		{"intermediate", certstatus.Result{Verdict: certstatus.Revoked, Source: "crl", Name: "root", Depth: 1,
			Subject: "CN=port49 issuing ca", RevokedAt: revokedAt},
			"this certificate's issuer, CN=port49 issuing ca, was revoked at its CA"},
		{"hold", certstatus.Result{Verdict: certstatus.Revoked, Source: "crl", Name: "corp", Hold: true,
			RevokedAt: revokedAt}, "this certificate is on hold at its CA"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, 8)
			fs := &fakeStatus{}
			f.b.CertStatus, f.b.OnUnavailable = fs, "refuse" // no queue runs: what is queued stays
			f.liveContext(t, "leaf1", "alice", alicePrincipal, certKey(f.alice))
			fs.set(f.alice, tc.res)
			w := f.post(context.Background(), f.state(f.alice), mintBody, "k1")
			if w.Code != 401 || !strings.Contains(w.Body.String(), `"credential_revoked"`) ||
				!strings.Contains(w.Body.String(), tc.want) {
				t.Fatalf("%s", answer(w))
			}
			wantDeny(t, lastRecord(t, f, "mint"), "credential_revoked")
			if f.b.revokeQueue != nil || len(f.b.queued) != 0 {
				t.Fatal("a revocation was queued")
			}
			if _, ok := markOn(t, f, f.alice); ok {
				t.Fatal("the leaf was marked")
			}
		})
	}
}

// A marked caller is answered credential_revoked at bind during a status
// outage, not 503: the outage must not keep a revoked session alive.
func TestAMarkOutranksAStatusOutageAtBind(t *testing.T) {
	f := newFixture(t, 8)
	fs := withStatus(t, f, "refuse", nil)
	addr, bl := serveWithStatus(t, f, DefaultListenerLimits)
	fs.set(f.alice, unknownStatus)
	bl.Revoked(store.Revocation{Kind: store.RevocationPrincipal, Key: alicePrincipal, At: f.now}, true)
	if a := boundAnswer(t, f, addr, f.alice); a.status != 401 || !strings.Contains(a.body, `"credential_revoked"`) {
		t.Fatalf("%s", reply(a.status, a.body))
	}
	wantDeny(t, lastRecord(t, f, "mint"), "credential_revoked")
}

// A mark lifted while the status is asked leaves no connection held
// unchecked (review M1): bind takes the status's refusal under the same lock
// it reads the marks under, so the revoked certificate is answered and holds
// no slot.
func TestAMarkLiftedDuringTheStatusCheckStillRefuses(t *testing.T) {
	f := newFixture(t, 8)
	fs := withStatus(t, f, "refuse", nil)
	mark := store.Revocation{Kind: store.RevocationCert, Key: certKey(f.alice), At: f.now}
	addr, bl := serveThroughWith(t, f, DefaultListenerLimits, nil, func(l *Listener) {
		l.Status = func(cs tls.ConnectionState, principal string, cred store.Credential) *BindRefusal {
			l.Revoked(mark, false) // the lift lands mid-check
			return f.b.BindStatus(cs, principal, cred)
		}
	})
	f.b.Conns = bl
	bl.Revoked(mark, true)
	fs.set(f.alice, revokedByCRL)
	a := boundAnswer(t, f, addr, f.alice)
	if a.status != 401 || !strings.Contains(a.body, "was revoked at its CA") {
		t.Fatalf("%s", reply(a.status, a.body))
	}
	if n := testutil.ToFloat64(f.b.Metrics.BrokerConnections.WithLabelValues("held")); n != 0 {
		t.Fatalf("held gauge: %v", n)
	}
}

// A status that cannot be established is 503 certificate_status_unavailable
// with Retry-After 60, recorded trust_domain_unresolved, at mint, at bind and
// at refresh; it ends no session (pre-flight I7). The bind is counted
// status_unavailable_refused, not revoked_refused (re-check R6).
func TestAnUnknownStatusIsUnavailable(t *testing.T) {
	t.Run("mint", func(t *testing.T) {
		f := newFixture(t, 8)
		fs := withStatus(t, f, "refuse", nil)
		fs.set(f.alice, unknownStatus)
		w := f.post(context.Background(), f.state(f.alice), mintBody, "k1")
		if w.Code != 503 || !strings.Contains(w.Body.String(), `"certificate_status_unavailable"`) ||
			!strings.Contains(w.Body.String(), "CRL corp is past its next update") ||
			w.Header().Get("Retry-After") != "60" || w.Header().Get("Connection") == "close" {
			t.Fatalf("%s %v", answer(w), w.Header())
		}
		if f.live(t, "leaf1") != 0 {
			t.Fatal("an unestablished certificate minted")
		}
		wantDeny(t, lastRecord(t, f, "mint"), "trust_domain_unresolved")
	})

	// No source covers the certificate: still 503 with Retry-After, but final
	// to port49 workload (exit 77), so it never says "try again".
	t.Run("mint, uncovered", func(t *testing.T) {
		f := newFixture(t, 8)
		fs := withStatus(t, f, "refuse", nil)
		fs.set(f.alice, certstatus.Result{Verdict: certstatus.Unknown, Source: "none",
			Detail: api.UncoveredStatus + ` "CN=corp" (CRL corp is scoped to the distribution point x)`})
		w := f.post(context.Background(), f.state(f.alice), mintBody, "k1")
		var e api.Error
		if err := json.Unmarshal(w.Body.Bytes(), &e); err != nil || w.Code != 503 ||
			e.Error != "certificate_status_unavailable" || !strings.Contains(e.Detail, api.UncoveredStatus) ||
			strings.Contains(e.Detail, "try again") || !strings.Contains(e.Detail, "until") ||
			w.Header().Get("Retry-After") != "60" {
			t.Fatalf("%s %v", answer(w), w.Header())
		}
	})

	// Through a real checker: an OCSP responder that applies but is down is
	// an outage (try again, class ocsp, retried by port49 workload); with no
	// source at all the issuer is uncovered, final (decision 40, ruling 10).
	for _, tc := range []struct {
		name, class string
		cfg         func(t *testing.T) certstatus.Config
	}{
		{"mint, the OCSP responder down", "ocsp", func(t *testing.T) certstatus.Config {
			down := httptest.NewServer(http.NotFoundHandler())
			down.Close()
			return certstatus.Config{OCSP: &certstatus.OCSPConfig{Responder: down.URL, Timeout: time.Second, Hash: crypto.SHA256}}
		}},
		{"mint, no source", "uncovered", func(*testing.T) certstatus.Config { return certstatus.Config{} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, 8)
			f.b.CertStatus = certstatus.New(tc.cfg(t), f.b.Now, metrics.New(prometheus.NewRegistry()), t.Logf)
			f.b.OnUnavailable = "refuse"
			runQueue(t, f)
			w := f.post(context.Background(), f.state(f.alice), mintBody, "k1")
			var e api.Error
			if err := json.Unmarshal(w.Body.Bytes(), &e); err != nil || w.Code != 503 ||
				e.Error != "certificate_status_unavailable" || w.Header().Get("Retry-After") != "60" {
				t.Fatalf("%s %v", answer(w), w.Header())
			}
			inner := strings.TrimPrefix(e.Detail, "the broker cannot establish this certificate's revocation status (")
			if got := unknownClass(inner); got != tc.class {
				t.Errorf("class %q, want %q: %s", got, tc.class, e.Detail)
			}
			if final := strings.Contains(e.Detail, api.UncoveredStatus); final != (tc.class == "uncovered") ||
				strings.HasSuffix(e.Detail, "; try again") == final {
				t.Errorf("final %v: %s", final, e.Detail)
			}
		})
	}

	t.Run("bind", func(t *testing.T) {
		f := newFixture(t, 8)
		fs := withStatus(t, f, "refuse", nil)
		addr, _ := serveWithStatus(t, f, DefaultListenerLimits)
		fs.set(f.alice, unknownStatus)
		a := boundAnswer(t, f, addr, f.alice)
		if a.status != 503 || !strings.Contains(a.body, `"certificate_status_unavailable"`) || a.retryAfter != "60" {
			t.Fatalf("%s %q", reply(a.status, a.body), a.retryAfter)
		}
		wantDeny(t, lastRecord(t, f, "mint"), "trust_domain_unresolved")
		ev := f.b.Metrics.BrokerConnectionEvents
		if n := testutil.ToFloat64(ev.WithLabelValues("status_unavailable_refused")); n != 1 {
			t.Fatalf("status_unavailable_refused: %v", n)
		}
		if n := testutil.ToFloat64(ev.WithLabelValues("revoked_refused")); n != 0 {
			t.Fatalf("revoked_refused: %v", n)
		}
	})

	t.Run("refresh", func(t *testing.T) {
		f := newFixture(t, 8)
		fs := withStatus(t, f, "refuse", nil)
		addr, _ := serveWithStatus(t, f, DefaultListenerLimits)
		c, br := held(t, f, addr, f.alice)
		auth := f.now
		f.liveContextAt(t, "leaf1", "alice", alicePrincipal, certKey(f.alice), auth, auth.Add(time.Hour))
		fs.set(f.alice, unknownStatus)
		f.advance(time.Minute)
		nonce, text := challengeOn(t, c, br)
		s, body, retry := answerHeaders(t, c, br, f.alice, nonce, text)
		if s != 503 || !strings.Contains(body, `"certificate_status_unavailable"`) || retry != "60" {
			t.Fatalf("%s %q", reply(s, body), retry)
		}
		wantDeny(t, lastRecord(t, f, "refresh"), "trust_domain_unresolved")
		if n := testutil.ToFloat64(f.b.Metrics.SessionRefreshes.WithLabelValues("refused")); n != 1 {
			t.Fatalf("refused refreshes: %v", n)
		}
		got, _ := f.st.GetContext(context.Background(), store.ContextKey{NAS: "leaf1", Username: "alice"})
		if !got.AuthTime.Equal(auth) {
			t.Fatalf("the context was extended: auth_time %v", got.AuthTime)
		}
		// The connection is kept, and its own clock did not move: its next
		// mint carries the handshake's auth_time (review M4).
		fs.set(f.alice, certstatus.Result{Verdict: certstatus.Good, Source: "crl", Name: "corp"})
		if a := postOn(t, c, br, "/v1/tokens", mintBody); a.status != 200 {
			t.Fatalf("the mint after the 503: %d", a.status)
		}
		toks, _ := f.st.Candidates(context.Background(), store.TokenKey{NAS: "leaf1", Username: "alice"})
		if len(toks) != 1 || !toks[0].AuthTime.Equal(auth) {
			t.Fatalf("a refused refresh moved the connection's auth_time: %d token(s), %v", len(toks), toks[0].AuthTime)
		}
	})

	// on_unavailable: allow admits, and says so once per source per ten
	// minutes, not at every check (M1).
	t.Run("allow", func(t *testing.T) {
		f := newFixture(t, 8)
		logs := &lockedBuffer{}
		fs := withStatus(t, f, "allow", logs)
		fs.set(f.alice, unknownStatus)
		for i, key := range []string{"k1", "k2"} {
			if w := f.post(context.Background(), f.state(f.alice), mintBody, key); w.Code != 200 {
				t.Fatalf("mint %d: %s", i, answer(w))
			}
			f.advance(time.Minute)
		}
		if n := strings.Count(logs.String(), "admitting a certificate whose revocation status cannot be established"); n != 1 {
			t.Fatalf("said %d times: %q", n, logs.String())
		}
		// A responder that varies its answer's text at will is still one
		// line per window (review M2).
		for i, key := range []string{"k3", "k4", "k5"} {
			fs.set(f.alice, certstatus.Result{Verdict: certstatus.Unknown, Source: "none",
				Detail: fmt.Sprintf("OCSP http://ocsp.example.com: answered 500 reason %d", i)})
			if w := f.post(context.Background(), f.state(f.alice), mintBody, key); w.Code != 200 {
				t.Fatalf("mint %s: %s", key, answer(w))
			}
		}
		if n := strings.Count(logs.String(), "admitting a certificate whose revocation status cannot be established"); n != 2 {
			t.Fatalf("said %d times: %q", n, logs.String())
		}
	})
}

// certIndexFailing fails ContextsByCert while fail is set.
type certIndexFailing struct {
	store.Store
	fail atomic.Bool
}

func (s *certIndexFailing) ContextsByCert(ctx context.Context, certKey string) ([]store.ContextRef, error) {
	if s.fail.Load() {
		return nil, errors.New("store: connection refused")
	}
	return s.Store.ContextsByCert(ctx, certKey)
}

// markUnreadable fails GetRevocation while fail is set.
type markUnreadable struct {
	store.Store
	fail atomic.Bool
}

func (s *markUnreadable) GetRevocation(ctx context.Context, kind, key string) (store.Revocation, error) {
	if s.fail.Load() {
		return store.Revocation{}, errors.New("store: connection refused")
	}
	return s.Store.GetRevocation(ctx, kind, key)
}

func (b *Broker) pendingLen() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.pending)
}

// A CRL entry revokes a certificate still present — a held connection, a
// live context, an unspent token — and nothing else; a store error leaves
// it pending, never marked, for RetryPending (pre-flight I9).
func TestACRLEntryRevokesWhatIsPresent(t *testing.T) {
	issuer := func(c tls.Certificate) string { return c.Leaf.Issuer.String() }
	serial := func(c tls.Certificate) string { return c.Leaf.SerialNumber.Text(16) }

	t.Run("held connection", func(t *testing.T) {
		f := newFixture(t, 8)
		withStatus(t, f, "refuse", nil)
		addr, _ := serveWithStatus(t, f, DefaultListenerLimits)
		c, _ := held(t, f, addr, f.alice)
		f.b.OnCRLEntry(issuer(f.alice), serial(f.alice), "corp", false)
		eventually(t, "the revocation", func() bool { return certRevocations(f) == 1 })
		waitMark(t, f, f.alice, "crl corp")
		if !closedByPeer(c) {
			t.Fatal("the held connection was left open")
		}
	})

	t.Run("live context", func(t *testing.T) {
		f := newFixture(t, 8)
		withStatus(t, f, "refuse", nil)
		f.liveContext(t, "leaf1", "alice", alicePrincipal, certKey(f.alice))
		f.b.OnCRLEntry(issuer(f.alice), serial(f.alice), "corp", false)
		eventually(t, "the revocation", func() bool { return certRevocations(f) == 1 })
		waitMark(t, f, f.alice, "crl corp")
	})

	// A restart's replay is revoked as a new entry is: only its queue line
	// is quiet. A mark missing at restart, from a revocations_file restored
	// from an older backup or a lifted mark, is put back, and the context
	// still live under the certificate is revoked (Task 11 re-review R1).
	t.Run("replay with the mark missing", func(t *testing.T) {
		f := newFixture(t, 8)
		withStatus(t, f, "refuse", nil)
		f.liveContext(t, "leaf1", "alice", alicePrincipal, certKey(f.alice))
		f.b.OnCRLEntry(issuer(f.alice), serial(f.alice), "corp", true)
		eventually(t, "the revocation", func() bool { return certRevocations(f) == 1 })
		waitMark(t, f, f.alice, "crl corp")
		eventually(t, "the live context revoked", func() bool {
			c, err := f.st.GetContext(context.Background(), store.ContextKey{NAS: "leaf1", Username: "alice"})
			return err == nil && !c.RevokedAt.IsZero()
		})
	})

	t.Run("unspent token", func(t *testing.T) {
		f := newFixture(t, 8)
		withStatus(t, f, "refuse", nil)
		if w := f.post(context.Background(), f.state(f.alice), mintBody, "k1"); w.Code != 200 {
			t.Fatal(answer(w))
		}
		f.b.OnCRLEntry(issuer(f.alice), serial(f.alice), "corp", false)
		eventually(t, "the revocation", func() bool { return certRevocations(f) == 1 })
		waitMark(t, f, f.alice, "crl corp")
		if f.live(t, "leaf1") != 0 {
			t.Fatal("the revoked certificate's token survived")
		}
	})

	// One with nothing present is passed over; a second, present, queued
	// after it shows the first was taken.
	t.Run("nothing present", func(t *testing.T) {
		f := newFixture(t, 8)
		withStatus(t, f, "refuse", nil)
		other := f.client(t, "alice@example.com", f.now.Add(24*time.Hour))
		f.liveContext(t, "leaf1", "alice", alicePrincipal, certKey(f.alice))
		f.b.OnCRLEntry(issuer(other), serial(other), "corp", false)
		f.b.OnCRLEntry(issuer(f.alice), serial(f.alice), "corp", false)
		eventually(t, "the revocation", func() bool { return certRevocations(f) == 1 })
		if _, ok := markOn(t, f, other); ok {
			t.Fatal("a certificate with nothing present was marked")
		}
	})

	t.Run("store error", func(t *testing.T) {
		f := newFixture(t, 8)
		failing := &certIndexFailing{Store: f.st}
		failing.fail.Store(true)
		f.b.Store = failing
		withStatus(t, f, "refuse", nil)
		f.liveContext(t, "leaf1", "alice", alicePrincipal, certKey(f.alice))
		f.b.OnCRLEntry(issuer(f.alice), serial(f.alice), "corp", false)
		eventually(t, "the entry pending", func() bool { return f.b.pendingLen() == 1 })
		if _, ok := markOn(t, f, f.alice); ok {
			t.Fatal("a store error marked the certificate")
		}
		failing.fail.Store(false)
		f.b.RetryPending()
		eventually(t, "the revocation", func() bool { return certRevocations(f) == 1 })
		waitMark(t, f, f.alice, "crl corp")
		if n := f.b.pendingLen(); n != 0 {
			t.Fatalf("%d still pending", n)
		}
	})

	// A mark that cannot be read is a store error too: pending, never
	// marked, never passed over as already revoked (review M3).
	t.Run("mark unreadable", func(t *testing.T) {
		f := newFixture(t, 8)
		failing := &markUnreadable{Store: f.st}
		failing.fail.Store(true)
		f.b.Store = failing
		withStatus(t, f, "refuse", nil)
		f.liveContext(t, "leaf1", "alice", alicePrincipal, certKey(f.alice))
		f.b.OnCRLEntry(issuer(f.alice), serial(f.alice), "corp", false)
		eventually(t, "the entry pending", func() bool { return f.b.pendingLen() == 1 })
		if _, ok := markOn(t, f, f.alice); ok {
			t.Fatal("a store error marked the certificate")
		}
		failing.fail.Store(false)
		f.b.RetryPending()
		eventually(t, "the revocation", func() bool { return certRevocations(f) == 1 })
		waitMark(t, f, f.alice, "crl corp")
	})

	// A restart names every entry of each list again (LoadPersisted): one
	// already marked is neither revoked, recorded nor said again.
	t.Run("restart replay", func(t *testing.T) {
		f := newFixture(t, 8)
		logs := &lockedBuffer{}
		withStatus(t, f, "refuse", logs)
		f.liveContext(t, "leaf1", "alice", alicePrincipal, certKey(f.alice))
		sentinel := f.client(t, "alice@example.com", f.now.Add(24*time.Hour))
		f.b.OnCRLEntry(issuer(f.alice), serial(f.alice), "corp", false)
		eventually(t, "the revocation", func() bool { return certRevocations(f) == 1 })
		before := len(eventsOf(f.records(t), "revoke"))
		f.liveContext(t, "nx1", "alice", alicePrincipal, certKey(sentinel))
		for i := 0; i < 3; i++ {
			f.b.OnCRLEntry(issuer(f.alice), serial(f.alice), "corp", false)
		}
		f.b.OnCRLEntry(issuer(sentinel), serial(sentinel), "corp", false)
		eventually(t, "the sentinel's revocation", func() bool { return certRevocations(f) == 2 })
		if n := len(eventsOf(f.records(t), "revoke")); n != before+1 {
			t.Fatalf("revoke records: %d, want %d", n, before+1)
		}
		if n := strings.Count(logs.String(), "names a certificate in use"); n != 2 {
			t.Fatalf("said %d times: %q", n, logs.String())
		}
	})
}

// allHeld is a listener holding a connection for every certificate.
type allHeld struct{}

func (allHeld) CloseHeld(func(principal, certKey string) bool) int { return 0 }
func (allHeld) Revoked(store.Revocation, bool)                     {}
func (allHeld) HoldsCert(string) bool                              { return true }

// 150 entries at once: the load is said once, and an operator's revocation
// made meanwhile is served between two queued ones, not after all 150
// (pre-flight I9).
func TestAQueueOfCRLEntriesYieldsToAnOperator(t *testing.T) {
	f := newFixture(t, 8)
	logs := &lockedBuffer{}
	prev := log.Writer()
	log.SetOutput(logs)
	t.Cleanup(func() { log.SetOutput(prev) })
	f.b.Conns = allHeld{}
	f.b.Persist = func(context.Context) error { time.Sleep(10 * time.Millisecond); return nil }
	iss := f.alice.Leaf.Issuer.String()
	for i := 0; i < 150; i++ {
		f.b.OnCRLEntry(iss, fmt.Sprintf("a%03x", i), "corp", false)
	}
	runQueue(t, f)
	eventually(t, "the first queued revocation", func() bool { return certRevocations(f) >= 1 })
	if _, err := f.b.Revoke(context.Background(), RevokeRequest{Principal: "user:carol@example.com", Origin: "t"}); err != nil {
		t.Fatal(err)
	}
	if n := certRevocations(f); n >= 150 {
		t.Fatalf("the operator's revocation waited for all %v queued ones", n)
	}
	eventually(t, "every queued revocation", func() bool { return certRevocations(f) == 150 })
	if n := strings.Count(logs.String(), "CRL entries are being checked against what is in use"); n != 1 {
		t.Fatalf("the load was said %d times: %q", n, logs.String())
	}
}

// A restart's replay of a kept list does not say the queue's load: nearly
// every entry is passed over, and "N are revoked in turn" would read as a
// storm (Task 11 review M3).
func TestAReplayDoesNotSayTheQueuesLoad(t *testing.T) {
	f := newFixture(t, 8)
	logs := &lockedBuffer{}
	prev := log.Writer()
	log.SetOutput(logs)
	t.Cleanup(func() { log.SetOutput(prev) })
	iss := f.alice.Leaf.Issuer.String()
	for i := 0; i < 150; i++ {
		f.b.OnCRLEntry(iss, fmt.Sprintf("b%03x", i), "corp", true)
	}
	if strings.Contains(logs.String(), "CRL entries are being checked against what is in use") {
		t.Fatalf("a replay said the load: %q", logs.String())
	}
}

// No checker, no check (port49d's disabled: true): bind, mint and refresh
// go through, and the fake is never asked.
func TestNoCheckerChecksNothing(t *testing.T) {
	f := newFixture(t, 8)
	fs := &fakeStatus{}
	fs.set(f.alice, revokedByCRL)
	addr, _ := serveWithStatus(t, f, DefaultListenerLimits)
	c, br := held(t, f, addr, f.alice)
	if w := f.post(context.Background(), f.state(f.alice), mintBody, "k1"); w.Code != 200 {
		t.Fatal(answer(w))
	}
	if s, _ := refreshOn(t, c, br, f.alice); s != 200 {
		t.Fatalf("refresh: %d", s)
	}
	if n := fs.count(); n != 0 {
		t.Fatalf("checked %d times", n)
	}
}

// A `port49 login` during a status outage: the real broker answers Connect
// 503 certificate_status_unavailable at bind, the agent says try again and
// keeps nothing ended, and the next Connect once the status returns
// succeeds (pre-flight I7).
func TestAnAgentConnectingDuringAStatusOutageIsToldToTryAgain(t *testing.T) {
	f := newFixture(t, 8)
	fs := withStatus(t, f, "refuse", nil)
	addr, _ := serveWithStatus(t, f, DefaultListenerLimits)
	fs.set(f.alice, unknownStatus)
	a := agent.New(agent.Config{BrokerURL: "https://" + addr, Cert: f.alice, BrokerCA: f.ca.Pool(), Now: f.b.Now})
	_, err := a.Connect(context.Background())
	if err == nil || errors.Is(err, agent.ErrSessionOver) || strings.Count(err.Error(), "try again") != 1 ||
		strings.Count(err.Error(), "revocation status") != 1 || !strings.HasSuffix(err.Error(), "retry in 60s") {
		t.Fatalf("Connect during the outage: %v", err)
	}
	select {
	case <-a.Done():
		t.Fatal("the outage ended the session")
	default:
	}
	fs.set(f.alice, certstatus.Result{Verdict: certstatus.Good, Source: "crl", Name: "corp"})
	if _, err := a.Connect(context.Background()); err != nil {
		t.Fatalf("Connect after the outage: %v", err)
	}
}
