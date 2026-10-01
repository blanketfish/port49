package broker

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/testpki"
)

// serveThrough serves f's broker behind a Listener with lim, its lines to
// logf (nil drops them), and returns the address and the listener.
func serveThrough(t *testing.T, f *fixture, lim ListenerLimits, logf func(string, ...any)) (string, *Listener) {
	t.Helper()
	now := f.b.Now()
	srvCert, err := f.ca.Issue(testpki.Leaf{CommonName: "broker", IPs: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := f.b.Server("127.0.0.1:0", srvCert, f.ca.Pool())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}
	bl := NewListener(Limit(raw, MaxConns), srv.TLSConfig, lim, f.b.Metrics, f.b.Now, logf)
	bl.Refused = f.b.RefusedAtBind // as port49d wires it
	go func() { _ = srv.Serve(bl) }()
	t.Cleanup(func() { _ = srv.Close() })
	return raw.Addr().String(), bl
}

func logTo(b *lockedBuffer) func(string, ...any) {
	return func(format string, args ...any) { fmt.Fprintf(b, format+"\n", args...) }
}

// eventually waits up to 5s for cond: the listener's counters move on its
// own goroutines.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("within 5s: %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// held opens a connection presenting cert and asks /v1/config on it,
// leaving it open: an agent's held connection.
func held(t *testing.T, f *fixture, addr string, cert tls.Certificate) (*tls.Conn, *bufio.Reader) {
	t.Helper()
	c, err := tls.Dial("tcp", addr, &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: f.ca.Pool(),
		MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	br := bufio.NewReader(c)
	ask(t, c, br)
	return c, br
}

func ask(t *testing.T, c *tls.Conn, br *bufio.Reader) {
	t.Helper()
	if _, err := io.WriteString(c, "GET /v1/config HTTP/1.1\r\nHost: broker\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("/v1/config on a held connection: %v %v", resp, err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
}

// closedByPeer reports whether the broker closed c: a read that fails with
// anything but a timeout.
func closedByPeer(c net.Conn) bool {
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err := c.Read(make([]byte, 1))
	var ne net.Error
	return err != nil && !(errors.As(err, &ne) && ne.Timeout())
}

// mintRequest is an agent's mint for one device, as it goes on the wire.
const mintRequest = "POST /v1/tokens HTTP/1.1\r\nHost: broker\r\nContent-Type: application/json\r\n" +
	"Idempotency-Key: k1\r\nContent-Length: 21\r\n\r\n{\"devices\":[\"leaf1\"]}"

// answeredRevoked sends a mint on c and wants the 401 credential_revoked a
// mint under rv is answered, byte for byte, with Connection: close, and then
// the broker's close (spec §5.1.4).
func answeredRevoked(t *testing.T, c *tls.Conn, rv store.Revocation) {
	t.Helper()
	if _, err := io.WriteString(c, mintRequest); err != nil {
		t.Fatalf("writing a mint to a marked connection: %v", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("a marked connection was not answered: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	want := httptest.NewRecorder()
	answerRevoked(want, rv)
	if resp.StatusCode != http.StatusUnauthorized || string(body) != want.Body.String() || !resp.Close ||
		resp.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("a marked connection's answer: %s %v %q, want 401 %q", resp.Status, resp.Header, body, want.Body)
	}
	if !closedByPeer(c) {
		t.Fatal("a marked connection was held after its answer")
	}
}

func (f *fixture) gauge(state string) float64 {
	return testutil.ToFloat64(f.b.Metrics.BrokerConnections.WithLabelValues(state))
}

// Every way a handshake fails is counted by its reason (spec §13 decision
// 32), and the first of each is said with its source and its error.
func TestHandshakeFailuresAreCountedByReason(t *testing.T) {
	f := newFixture(t, 8)
	errs := &lockedBuffer{}
	lim := DefaultListenerLimits
	lim.HandshakeTimeout = 300 * time.Millisecond
	addr, _ := serveThrough(t, f, lim, logTo(errs))
	count := func(reason string) float64 {
		return testutil.ToFloat64(f.b.Metrics.BrokerHandshakeFailures.WithLabelValues(reason))
	}
	try := func(cfg *tls.Config) {
		c, err := tls.Dial("tcp", addr, cfg)
		if err == nil {
			closedByPeer(c) // TLS 1.3: the broker refuses a client certificate after the client's Finished
			c.Close()
		}
	}
	now := f.b.Now()
	other, err := testpki.NewCA("someone else's CA", now.Add(-time.Hour), now.Add(48*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	mallory, err := other.Issue(testpki.Leaf{CommonName: "m", Emails: []string{"alice@example.com"}, Client: true,
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	try(&tls.Config{RootCAs: f.ca.Pool(), MinVersion: tls.VersionTLS13,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &mallory, nil }})
	eventually(t, "untrusted_chain counted", func() bool { return count("untrusted_chain") == 1 })

	two, err := f.ca.Issue(testpki.Leaf{CommonName: "two", Emails: []string{"a@example.com", "b@example.com"},
		Client: true, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	try(&tls.Config{Certificates: []tls.Certificate{two}, RootCAs: f.ca.Pool(), MinVersion: tls.VersionTLS13})
	eventually(t, "identity_refused counted", func() bool { return count("identity_refused") == 1 })

	try(&tls.Config{RootCAs: x509.NewCertPool(), MinVersion: tls.VersionTLS13}) // trusts no broker
	eventually(t, "server_cert_refused counted", func() bool { return count("server_cert_refused") == 1 })

	silent, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	eventually(t, "timeout counted", func() bool { return count("timeout") == 1 })

	gone, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	gone.Close()
	eventually(t, "client_closed counted", func() bool { return count("client_closed") == 1 })

	plain, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(plain, "GET /v1/config HTTP/1.1\r\nHost: broker\r\n\r\n")
	closedByPeer(plain)
	plain.Close()
	eventually(t, "protocol counted", func() bool { return count("protocol") == 1 })

	errs.waitFor(t, "failed (untrusted_chain)")
	errs.waitFor(t, "unknown authority")
	errs.waitFor(t, "2 email SANs")
}

// One reason's line is said once per 10s; the next says how many it held
// back, so a flood is one line, not a flood of lines.
func TestAReasonIsSaidOncePerTenSeconds(t *testing.T) {
	f := newFixture(t, 8)
	errs := &lockedBuffer{}
	addr, _ := serveThrough(t, f, DefaultListenerLimits, logTo(errs))
	for i := 0; i < 3; i++ {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		c.Close()
	}
	eventually(t, "three counted", func() bool {
		return testutil.ToFloat64(f.b.Metrics.BrokerHandshakeFailures.WithLabelValues("client_closed")) == 3
	})
	if n := strings.Count(errs.String(), "failed (client_closed)"); n != 1 {
		t.Fatalf("%d lines for three failures inside 10s:\n%s", n, errs.String())
	}
	f.advance(11 * time.Second)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	errs.waitFor(t, "(2 more like it since")
}

// A failure is counted only once its line is said or held back, so a
// reader that sees the count, as TestAReasonIsSaidOncePerTenSeconds does
// before it moves the clock, never races the line it implies (fixA N1).
func TestAHandshakeFailureIsSaidBeforeItIsCounted(t *testing.T) {
	f := newFixture(t, 8)
	entered, gate := make(chan struct{}), make(chan struct{})
	var once sync.Once
	addr, _ := serveThrough(t, f, DefaultListenerLimits, func(string, ...any) {
		once.Do(func() {
			close(entered)
			<-gate
		})
	})
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	<-entered
	failures := f.b.Metrics.BrokerHandshakeFailures.WithLabelValues("client_closed")
	if n := testutil.ToFloat64(failures); n != 0 {
		close(gate)
		t.Fatalf("counted %v while its line was still being said", n)
	}
	close(gate)
	eventually(t, "counted", func() bool { return testutil.ToFloat64(failures) == 1 })
}

// A source holds at most MaxPendingPerSource connections not yet bound to
// a principal; the next is reset at accept, and a slot freed is a slot
// again (spec §13 decision 32).
func TestOneSourceHoldsAtMostItsPendingCap(t *testing.T) {
	f := newFixture(t, 8)
	errs := &lockedBuffer{}
	lim := DefaultListenerLimits
	lim.MaxPendingPerSource = 2
	addr, _ := serveThrough(t, f, lim, logTo(errs))
	var raws []net.Conn
	for i := 0; i < 2; i++ {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		raws = append(raws, c)
	}
	eventually(t, "two pending", func() bool { return f.gauge("pending") == 2 })
	third, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer third.Close()
	if !closedByPeer(third) {
		t.Fatal("a third connection from the source was held, not reset")
	}
	eventually(t, "source_cap_refused counted", func() bool {
		return testutil.ToFloat64(f.b.Metrics.BrokerConnectionEvents.WithLabelValues("source_cap_refused")) == 1
	})
	errs.waitFor(t, "max_pending_conns_per_source")
	raws[0].Close()
	eventually(t, "one pending", func() bool { return f.gauge("pending") == 1 })
	c, _ := held(t, f, addr, f.alice) // admitted again, and bound: not pending
	defer c.Close()
	if f.gauge("held") != 1 {
		t.Fatalf("held %v", f.gauge("held"))
	}
}

// A principal holds at most MaxPerPrincipal held connections, and a new one
// closes its oldest, never the newest: dead connections from a laptop that
// slept must not lock its owner out. Another principal is untouched.
func TestAPrincipalPastItsCapLosesItsOldest(t *testing.T) {
	f := newFixture(t, 8)
	lim := DefaultListenerLimits
	lim.MaxPerPrincipal = 2
	addr, _ := serveThrough(t, f, lim, nil)
	carol := f.client(t, "carol@example.com", f.now.Add(time.Hour))
	cc, cbr := held(t, f, addr, carol)
	first, _ := held(t, f, addr, f.alice)
	second, sbr := held(t, f, addr, f.alice)
	third, tbr := held(t, f, addr, f.alice)
	if !closedByPeer(first) {
		t.Fatal("alice's oldest connection was not closed")
	}
	eventually(t, "principal_cap_evicted counted", func() bool {
		return testutil.ToFloat64(f.b.Metrics.BrokerConnectionEvents.WithLabelValues("principal_cap_evicted")) == 1
	})
	ask(t, second, sbr)
	ask(t, third, tbr)
	ask(t, cc, cbr)
	eventually(t, "three held", func() bool { return f.gauge("held") == 3 })
}

// A revoked certificate cannot evict its owner: past the cap the same
// certificate's oldest goes first, and once the broker has told the
// listener of the mark, the certificate's connections are closed as they
// bind, so ten of them never touch the renewed certificate's (pre-flight I3).
func TestARevokedCertificateNeverEvictsItsOwner(t *testing.T) {
	f := newFixture(t, 8)
	lim := DefaultListenerLimits
	lim.MaxPerPrincipal = 2
	addr, bl := serveThrough(t, f, lim, nil)
	renewed := f.client(t, "alice@example.com", f.now.Add(2*time.Hour))
	rc, rbr := held(t, f, addr, renewed)
	// Before any mark: the stolen certificate's flood churns its own slots.
	for i := 0; i < 5; i++ {
		held(t, f, addr, f.alice)
	}
	ask(t, rc, rbr)
	stolenKey := certKey(f.alice)
	bl.Revoked(store.Revocation{Kind: store.RevocationCert, Key: stolenKey, At: f.now}, true)
	for i := 0; i < 10; i++ {
		c, err := tls.Dial("tcp", addr, &tls.Config{Certificates: []tls.Certificate{f.alice}, RootCAs: f.ca.Pool(),
			MinVersion: tls.VersionTLS13})
		if err == nil {
			answeredRevoked(t, c, store.Revocation{Kind: store.RevocationCert, At: f.now})
			c.Close()
		}
	}
	ask(t, rc, rbr)
	if got := testutil.ToFloat64(f.b.Metrics.BrokerConnectionEvents.WithLabelValues("revoked_refused")); got != 10 {
		t.Fatalf("revoked_refused %v", got)
	}
	bl.Revoked(store.Revocation{Kind: store.RevocationCert, Key: stolenKey}, false)
	c, br := held(t, f, addr, f.alice) // lifted: it binds again
	ask(t, c, br)
}

// CloseHeld closes what its match names, by principal or by certificate,
// and nothing else; a revocation calls it (Task 8).
func TestCloseHeldClosesWhatItNames(t *testing.T) {
	f := newFixture(t, 8)
	addr, bl := serveThrough(t, f, DefaultListenerLimits, nil)
	carol := f.client(t, "carol@example.com", f.now.Add(time.Hour))
	a1, _ := held(t, f, addr, f.alice)
	a2, _ := held(t, f, addr, f.alice)
	cc, cbr := held(t, f, addr, carol)
	if n := bl.CloseHeld(func(p, _ string) bool { return p == "user:alice@example.com" }); n != 2 {
		t.Fatalf("closed %d, want alice's 2", n)
	}
	if !closedByPeer(a1) || !closedByPeer(a2) {
		t.Fatal("alice's connections are open")
	}
	ask(t, cc, cbr)
	carolKey := certKey(carol)
	if n := bl.CloseHeld(func(_, ck string) bool { return ck == carolKey }); n != 1 || !closedByPeer(cc) {
		t.Fatalf("closing carol's certificate closed %d", n)
	}
	if got := testutil.ToFloat64(f.b.Metrics.BrokerConnectionEvents.WithLabelValues("revoked_closed")); got != 3 {
		t.Fatalf("revoked_closed %v", got)
	}
	eventually(t, "none held", func() bool { return f.gauge("held") == 0 })
}

// Closing the listener closes what it has not handed over — connections
// still handshaking — and wakes Accept with net.ErrClosed, so Shutdown is not
// held by a handshake that never finishes.
func TestClosingTheListenerClosesWhatItHolds(t *testing.T) {
	f := newFixture(t, 8)
	addr, bl := serveThrough(t, f, DefaultListenerLimits, nil)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	eventually(t, "one pending", func() bool { return f.gauge("pending") == 1 })
	if err := bl.Close(); err != nil {
		t.Fatal(err)
	}
	if !closedByPeer(c) {
		t.Fatal("a handshaking connection outlived the listener")
	}
	if _, err := bl.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept after Close: %v", err)
	}
}

// TestShutdownReturnsWithEverySlotHeld, through the listener.
func TestShutdownReturnsThroughTheListenerWithEverySlotHeld(t *testing.T) {
	f := newFixture(t, 8)
	now := f.b.Now()
	srvCert, err := f.ca.Issue(testpki.Leaf{CommonName: "broker", IPs: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := f.b.Server("127.0.0.1:0", srvCert, f.ca.Pool())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan struct{})
	go func() {
		_ = srv.Serve(NewListener(Limit(raw, 2), srv.TLSConfig, DefaultListenerLimits, f.b.Metrics, f.b.Now, nil))
		close(served)
	}()
	t.Cleanup(func() { _ = srv.Close() })
	held(t, f, raw.Addr().String(), f.alice)
	held(t, f, raw.Addr().String(), f.alice)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	go func() { _ = srv.Shutdown(ctx) }()
	select {
	case <-served:
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after Shutdown with every slot held")
	}
}

// A source at its pending cap is refused alone: another address is admitted,
// handshakes, and holds a pending slot of its own (spec §13 decision 32).
func TestAFullSourceDoesNotRefuseAnother(t *testing.T) {
	f := newFixture(t, 8)
	lim := DefaultListenerLimits
	lim.MaxPendingPerSource = 2
	addr, _ := serveThrough(t, f, lim, nil)
	for i := 0; i < 2; i++ {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
	}
	eventually(t, "two pending", func() bool { return f.gauge("pending") == 2 })
	third, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer third.Close()
	if !closedByPeer(third) {
		t.Fatal("a third connection from 127.0.0.1 was held, not reset")
	}
	other := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.2")}}
	c, err := tls.DialWithDialer(other, "tcp", addr, &tls.Config{Certificates: []tls.Certificate{f.alice},
		RootCAs: f.ca.Pool(), MinVersion: tls.VersionTLS13})
	if errors.Is(err, syscall.EADDRNOTAVAIL) {
		t.Skip("cannot dial from 127.0.0.2 here")
	}
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ask(t, c, bufio.NewReader(c))
	silent, err := other.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	eventually(t, "127.0.0.2's silent connection pending", func() bool { return f.gauge("pending") == 3 })
	if f.gauge("held") != 1 {
		t.Fatalf("held %v", f.gauge("held"))
	}
	if got := testutil.ToFloat64(f.b.Metrics.BrokerConnectionEvents.WithLabelValues("source_cap_refused")); got != 1 {
		t.Fatalf("source_cap_refused %v", got)
	}
}

// The listener accepts nothing before the first Accept, so a mark handed to
// it before Serve is in place for the first connection: a certificate
// marked at start-up never binds, even one that dialled before the mark.
func TestACertificateMarkedBeforeServeNeverBinds(t *testing.T) {
	f := newFixture(t, 8)
	now := f.b.Now()
	srvCert, err := f.ca.Issue(testpki.Leaf{CommonName: "broker", IPs: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := f.b.Server("127.0.0.1:0", srvCert, f.ca.Pool())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	bl := NewListener(Limit(raw, MaxConns), srv.TLSConfig, DefaultListenerLimits, f.b.Metrics, f.b.Now, nil)
	t.Cleanup(func() { _ = srv.Close(); _ = bl.Close() })
	type dialed struct {
		c   *tls.Conn
		err error
	}
	got := make(chan dialed, 1)
	go func() {
		c, err := tls.Dial("tcp", raw.Addr().String(), &tls.Config{Certificates: []tls.Certificate{f.alice},
			RootCAs: f.ca.Pool(), MinVersion: tls.VersionTLS13})
		got <- dialed{c, err}
	}()
	// Had the listener started at NewListener, the handshake would finish and
	// bind here, before the mark.
	time.Sleep(300 * time.Millisecond)
	if f.gauge("pending") != 0 || f.gauge("held") != 0 {
		t.Fatalf("accepted before the first Accept: pending %v held %v", f.gauge("pending"), f.gauge("held"))
	}
	bl.Revoked(store.Revocation{Kind: store.RevocationCert, Key: certKey(f.alice), At: f.now}, true)
	go func() { _ = srv.Serve(bl) }()
	d := <-got
	if d.err == nil {
		defer d.c.Close()
		answeredRevoked(t, d.c, store.Revocation{Kind: store.RevocationCert, At: f.now})
	}
	eventually(t, "revoked_refused counted", func() bool {
		return testutil.ToFloat64(f.b.Metrics.BrokerConnectionEvents.WithLabelValues("revoked_refused")) == 1
	})
	if f.gauge("held") != 0 {
		t.Fatalf("held %v", f.gauge("held"))
	}
}

// A mark that lands while a handshake is under way is read at bind: the
// connection is refused there, and nothing it was charged stays charged.
func TestAMarkMidHandshakeIsRefusedAtBind(t *testing.T) {
	f := newFixture(t, 8)
	addr, bl := serveThrough(t, f, DefaultListenerLimits, nil)
	asked, release := make(chan struct{}), make(chan struct{})
	type dialed struct {
		c   *tls.Conn
		err error
	}
	got := make(chan dialed, 1)
	go func() {
		c, err := tls.Dial("tcp", addr, &tls.Config{RootCAs: f.ca.Pool(), MinVersion: tls.VersionTLS13,
			GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				close(asked)
				<-release
				return &f.alice, nil
			}})
		got <- dialed{c, err}
	}()
	select {
	case <-asked:
	case <-time.After(5 * time.Second):
		t.Fatal("the broker never asked for a client certificate")
	}
	if f.gauge("pending") != 1 {
		t.Fatalf("pending mid-handshake %v", f.gauge("pending"))
	}
	bl.Revoked(store.Revocation{Kind: store.RevocationCert, Key: certKey(f.alice), At: f.now}, true)
	close(release)
	d := <-got
	if d.err == nil {
		defer d.c.Close()
		answeredRevoked(t, d.c, store.Revocation{Kind: store.RevocationCert, At: f.now})
	}
	eventually(t, "revoked_refused counted", func() bool {
		return testutil.ToFloat64(f.b.Metrics.BrokerConnectionEvents.WithLabelValues("revoked_refused")) == 1
	})
	eventually(t, "every count back to 0", func() bool {
		bl.mu.Lock()
		open, pending, held := len(bl.open), len(bl.pending), len(bl.held)
		bl.mu.Unlock()
		return open == 0 && pending == 0 && held == 0 && f.gauge("pending") == 0 && f.gauge("held") == 0
	})
}

// dialAs opens a TLS connection to addr presenting cert.
func dialAs(t *testing.T, f *fixture, addr string, cert tls.Certificate) *tls.Conn {
	t.Helper()
	c, err := tls.Dial("tcp", addr, &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: f.ca.Pool(),
		MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// refusedLog points f's decision log at a buffer the listener's
// goroutines can write while the test reads it.
func refusedLog(f *fixture) *lockedBuffer {
	lb := &lockedBuffer{}
	f.b.Log = decision.NewJSONLines(lb)
	return lb
}

// wantRefusedRecords wants exactly one mint deny credential_revoked record
// per cert, in order, each naming alice and that certificate's fingerprint
// and nothing from the request (spec §5.7), and port49_decisions to count
// them.
func wantRefusedRecords(t *testing.T, f *fixture, lb *lockedBuffer, certs ...tls.Certificate) {
	t.Helper()
	var recs []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(lb.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatal(err)
		}
		recs = append(recs, m)
	}
	if len(recs) != len(certs) {
		t.Fatalf("%d records, want %d: %s", len(recs), len(certs), lb)
	}
	for i, cert := range certs {
		_, cred, err := Identity(f.state(cert), f.now)
		if err != nil {
			t.Fatal(err)
		}
		r := recs[i]
		auth, _ := r["auth"].(map[string]any)
		if r["event"] != "mint" || r["verdict"] != "deny" || r["reason"] != "credential_revoked" ||
			r["principal"] != "user:alice@example.com" || auth["method"] != "cert" ||
			auth["fingerprint"] != cred.Fingerprint || r["device"] != nil || len(r) != 6 {
			t.Fatalf("record %d: %v", i, r)
		}
	}
	if got := testutil.ToFloat64(f.b.Metrics.Decisions.WithLabelValues("mint", "deny", "credential_revoked")); got !=
		float64(len(certs)) {
		t.Fatalf("port49_decisions{mint,deny,credential_revoked} %v, want %d", got, len(certs))
	}
}

// A marked certificate's new connection is answered the 401
// credential_revoked a mint under the mark is answered, and closed: a bare
// close reads to the agent as a broker that restarted, and leaves its
// session up (spec §5.1.4; the vEOS lab, plan 7a). The request reaches no
// handler, and is recorded as a mint under the mark is: one mint deny
// credential_revoked (spec §5.7).
func TestAMarkedCertificateIsAnsweredCredentialRevoked(t *testing.T) {
	f := newFixture(t, 8)
	lb := refusedLog(f)
	addr, bl := serveThrough(t, f, DefaultListenerLimits, nil)
	at := f.now.Add(-time.Minute)
	bl.Revoked(store.Revocation{Kind: store.RevocationCert, Key: certKey(f.alice), At: at}, true)
	answeredRevoked(t, dialAs(t, f, addr, f.alice), store.Revocation{Kind: store.RevocationCert, At: at})
	if got := testutil.ToFloat64(f.b.Metrics.BrokerConnectionEvents.WithLabelValues("revoked_refused")); got != 1 {
		t.Fatalf("revoked_refused %v", got)
	}
	wantRefusedRecords(t, f, lb, f.alice)
	eventually(t, "nothing charged", func() bool { return f.gauge("pending") == 0 && f.gauge("held") == 0 })
}

// A marked principal's is answered the same, naming the principal: every
// certificate it holds is refused so, and each refusal recorded with its
// own certificate's fingerprint.
func TestAMarkedPrincipalIsAnsweredCredentialRevoked(t *testing.T) {
	f := newFixture(t, 8)
	lb := refusedLog(f)
	addr, bl := serveThrough(t, f, DefaultListenerLimits, nil)
	at := f.now.Add(-time.Minute)
	bl.Revoked(store.Revocation{Kind: store.RevocationPrincipal, Key: "user:alice@example.com", At: at}, true)
	renewed := f.client(t, "alice@example.com", f.now.Add(2*time.Hour))
	for _, cert := range []tls.Certificate{f.alice, renewed} {
		answeredRevoked(t, dialAs(t, f, addr, cert), store.Revocation{Kind: store.RevocationPrincipal, At: at})
	}
	if got := testutil.ToFloat64(f.b.Metrics.BrokerConnectionEvents.WithLabelValues("revoked_refused")); got != 2 {
		t.Fatalf("revoked_refused %v", got)
	}
	wantRefusedRecords(t, f, lb, f.alice, renewed)
	carol := f.client(t, "carol@example.com", f.now.Add(time.Hour))
	held(t, f, addr, carol) // anyone else binds as before
}

// A marked connection that sends nothing stays charged to its source, never
// held, until revokedAnswerTimeout, and is then closed: it is counted once,
// gives back its charge, and writes no record, since nothing was asked.
func TestASilentMarkedConnectionIsClosedAtTheDeadline(t *testing.T) {
	defer func(d time.Duration) { revokedAnswerTimeout = d }(revokedAnswerTimeout)
	revokedAnswerTimeout = 600 * time.Millisecond
	f := newFixture(t, 8)
	lb := refusedLog(f)
	errs := &lockedBuffer{}
	addr, bl := serveThrough(t, f, DefaultListenerLimits, logTo(errs))
	bl.Revoked(store.Revocation{Kind: store.RevocationCert, Key: certKey(f.alice), At: f.now}, true)
	start := time.Now()
	c := dialAs(t, f, addr, f.alice)
	eventually(t, "revoked_refused counted", func() bool {
		return testutil.ToFloat64(f.b.Metrics.BrokerConnectionEvents.WithLabelValues("revoked_refused")) == 1
	})
	if f.gauge("pending") != 1 || f.gauge("held") != 0 {
		t.Fatalf("while it is answered: pending %v held %v", f.gauge("pending"), f.gauge("held"))
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := c.Read(make([]byte, 1))
	if err == nil || n != 0 {
		t.Fatalf("a silent marked connection was sent %d bytes: %v", n, err)
	}
	if took := time.Since(start); took < 500*time.Millisecond {
		t.Fatalf("closed after %s, before the deadline", took)
	}
	eventually(t, "nothing charged", func() bool { return f.gauge("pending") == 0 && f.gauge("held") == 0 })
	if !strings.Contains(errs.String(), "credential_revoked") {
		t.Fatalf("the line: %q", errs.String())
	}
	wantRefusedRecords(t, f, lb)
}

// A marked connection's request line and headers are read for at most
// revokedRequestMax bytes: exactly that is answered, and one byte more is
// cut off unanswered and unrecorded.
func TestAnOversizedRequestOnAMarkedConnectionIsCutOff(t *testing.T) {
	f := newFixture(t, 8)
	lb := refusedLog(f)
	addr, bl := serveThrough(t, f, DefaultListenerLimits, nil)
	bl.Revoked(store.Revocation{Kind: store.RevocationCert, Key: certKey(f.alice), At: f.now}, true)
	request := func(pad int) string {
		return "POST /v1/tokens HTTP/1.1\r\nHost: broker\r\nX-Pad: " + strings.Repeat("a", pad) +
			"\r\nContent-Length: 0\r\n\r\n"
	}
	under := request(revokedRequestMax - len(request(0)))
	if len(under) != revokedRequestMax {
		t.Fatalf("under is %d bytes", len(under))
	}
	c := dialAs(t, f, addr, f.alice)
	if _, err := io.WriteString(c, under); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if resp, err := http.ReadResponse(bufio.NewReader(c), nil); err != nil || resp.StatusCode != 401 {
		t.Fatalf("a request of exactly revokedRequestMax bytes: %v %v", resp, err)
	}
	c = dialAs(t, f, addr, f.alice)
	go func() { _, _ = io.WriteString(c, request(revokedRequestMax-len(request(0))+1)) }()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if resp, err := http.ReadResponse(bufio.NewReader(c), nil); err == nil {
		t.Fatalf("an oversized request was answered: %s", resp.Status)
	} else if ne := net.Error(nil); errors.As(err, &ne) && ne.Timeout() {
		t.Fatal("an oversized request was held to the deadline")
	}
	eventually(t, "the cut-off connection closed", func() bool { return f.gauge("pending") == 0 })
	wantRefusedRecords(t, f, lb, f.alice)
}

// A batch mint's body is not the headers' bound: past revokedRequestMax,
// and past revokedBodyMax, the request is answered 401 credential_revoked
// all the same, and the body the broker never reads does not reset the
// answer away (design §17's sweep client).
func TestALargeBodyOnAMarkedConnectionIsAnswered(t *testing.T) {
	f := newFixture(t, 8)
	lb := refusedLog(f)
	addr, bl := serveThrough(t, f, DefaultListenerLimits, nil)
	at := f.now.Add(-time.Minute)
	bl.Revoked(store.Revocation{Kind: store.RevocationCert, Key: certKey(f.alice), At: at}, true)
	for _, size := range []int{2 * revokedRequestMax, 4 * revokedBodyMax} {
		names := make([]string, size/40+1) // 40 bytes each, quoted and comma'd
		for i := range names {
			names[i] = fmt.Sprintf(`"device-%030d"`, i)
		}
		body := `{"devices":[` + strings.Join(names, ",") + `]}`
		c := dialAs(t, f, addr, f.alice)
		go func() {
			_, _ = fmt.Fprintf(c, "POST /v1/tokens HTTP/1.1\r\nHost: broker\r\nContent-Type: application/json\r\n"+
				"Content-Length: %d\r\n\r\n%s", len(body), body)
		}()
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			t.Fatalf("a %d-byte body: %v", len(body), err)
		}
		got, err := io.ReadAll(resp.Body)
		if err != nil || resp.StatusCode != http.StatusUnauthorized || !strings.Contains(string(got), `"credential_revoked"`) {
			t.Fatalf("a %d-byte body: %s %q %v", len(body), resp.Status, got, err)
		}
	}
	wantRefusedRecords(t, f, lb, f.alice, f.alice)
}
