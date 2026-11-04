package broker

import (
	"bufio"
	"crypto/tls"
	"github.com/blanketfish/port49/internal/testpki"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// busy opens a connection presenting cert and starts a request whose body it does not
// send, so the broker has a request in flight on it, and wants the broker to
// count exactly active connections busy once it has: every busy one so far,
// this one included. finish completes the
// request and wants its answer.
func busy(t *testing.T, f *fixture, bl *Listener, addr string, cert tls.Certificate, active int) (c *tls.Conn, finish func()) {
	t.Helper()
	c, err := tls.Dial("tcp", addr, &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: f.ca.Pool(),
		MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	before := requestsSeen(bl).Load()
	if _, err := io.WriteString(c, "POST /v1/tokens HTTP/1.1\r\nHost: broker\r\nContent-Length: 2\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	// The connection is busy from bind, so activeHeld rising is no sign of the
	// request, and may already have risen before this helper looked. Wait for
	// the handler to see the request, then require every busy connection marked.
	eventually(t, "a request in flight", func() bool { return requestsSeen(bl).Load() > before })
	eventually(t, "every busy connection counted active", func() bool { return activeHeld(bl) == active })
	br := bufio.NewReader(c)
	return c, func() {
		t.Helper()
		if _, err := io.WriteString(c, "{}"); err != nil {
			t.Fatalf("finishing the request: %v", err)
		}
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		resp, err := http.ReadResponse(br, nil)
		if err != nil || resp.StatusCode == http.StatusServiceUnavailable {
			t.Fatalf("the busy connection's request: %v %v", resp, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}

func activeHeld(l *Listener) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, conns := range l.held {
		for _, c := range conns {
			if c.active {
				n++
			}
		}
	}
	return n
}

// heldIdle is held, then waits until the listener has marked every connection
// but the busy ones idle. A connection is marked idle from ConnState, a moment
// after its client has the answer; a bind in that gap sees no idle connection
// of its own certificate and takes the principal's oldest idle one (spec
// section 8), so a test that binds one after another and asserts which was
// closed must not race it.
func heldIdle(t *testing.T, f *fixture, bl *Listener, addr string, cert tls.Certificate, busy int) (*tls.Conn, *bufio.Reader) {
	t.Helper()
	c, br := held(t, f, addr, cert)
	eventually(t, "the connection idle", func() bool { return activeHeld(bl) <= busy })
	return c, br
}

func event(f *fixture, name string) float64 {
	return testutil.ToFloat64(f.b.Metrics.BrokerConnectionEvents.WithLabelValues(name))
}

// With every held connection busy, a new one is refused 503 with
// Retry-After and none is closed (decision 32; load cell e2).
func TestACapOfBusyConnectionsRefusesTheNewOne(t *testing.T) {
	f := newFixture(t, 8)
	lim := DefaultListenerLimits
	lim.MaxPerPrincipal = 4
	addr, bl := serveThrough(t, f, lim, nil)
	var finish []func()
	for i := 0; i < 4; i++ {
		_, fin := busy(t, f, bl, addr, f.alice, i+1)
		finish = append(finish, fin)
	}
	c, err := tls.Dial("tcp", addr, &tls.Config{Certificates: []tls.Certificate{f.alice}, RootCAs: f.ca.Pool(),
		MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = io.WriteString(c, "GET /v1/config HTTP/1.1\r\nHost: broker\r\n\r\n")
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("the refused connection was not answered: %v", err)
	}
	if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("got %d, Retry-After %q; want 503 with Retry-After", resp.StatusCode, resp.Header.Get("Retry-After"))
	}
	resp.Body.Close()
	if got := event(f, "principal_cap_refused"); got != 1 {
		t.Fatalf("principal_cap_refused %v", got)
	}
	if got := event(f, "principal_cap_evicted"); got != 0 {
		t.Fatalf("principal_cap_evicted %v: a busy connection was closed", got)
	}
	for _, fin := range finish {
		fin() // every busy connection is still alive and answers
	}
}

// One idle connection among three busy ones, not the oldest, is the one the fifth closes.
func TestTheCapClosesTheIdleConnectionAndNoBusyOne(t *testing.T) {
	f := newFixture(t, 8)
	lim := DefaultListenerLimits
	lim.MaxPerPrincipal = 4
	addr, bl := serveThrough(t, f, lim, nil)
	var finish []func()
	_, fin := busy(t, f, bl, addr, f.alice, 1) // the oldest, and busy
	finish = append(finish, fin)
	idle, _ := held(t, f, addr, f.alice)
	for i := 0; i < 2; i++ {
		_, fin := busy(t, f, bl, addr, f.alice, i+2)
		finish = append(finish, fin)
	}
	fifth, br := held(t, f, addr, f.alice)
	if !closedByPeer(idle) {
		t.Fatal("the idle connection was not closed")
	}
	ask(t, fifth, br)
	for _, fin := range finish {
		fin()
	}
	if got := event(f, "principal_cap_evicted"); got != 1 {
		t.Fatalf("principal_cap_evicted %v", got)
	}
}

// A dead connection is idle, so it never locks its owner out: an owner at the
// cap with connections that went quiet still binds a new one.
func TestDeadIdleConnectionsNeverLockTheOwnerOut(t *testing.T) {
	f := newFixture(t, 8)
	lim := DefaultListenerLimits
	lim.MaxPerPrincipal = 2
	addr, _ := serveThrough(t, f, lim, nil)
	var dead []*tls.Conn
	for i := 0; i < 2; i++ {
		c, _ := held(t, f, addr, f.alice)
		dead = append(dead, c)
	}
	for i := 0; i < 3; i++ { // the laptop wakes and reconnects, again and again
		c, br := held(t, f, addr, f.alice)
		ask(t, c, br)
	}
	if !closedByPeer(dead[0]) {
		t.Fatal("the dead connection was not closed")
	}
}

// A flood from one certificate churns only its own idle slots. Each flood
// connection is waited idle before the next binds: a connection is marked idle
// from ConnState, a moment after the client has its answer, and a bind in that
// gap finds no idle connection of its own certificate and (spec section 8) takes
// the principal's oldest idle one, which is the renewed certificate's.
func TestAFloodChurnsOnlyItsOwnIdleSlots(t *testing.T) {
	f := newFixture(t, 8)
	lim := DefaultListenerLimits
	lim.MaxPerPrincipal = 2
	addr, bl := serveThrough(t, f, lim, nil)
	renewed := f.client(t, "alice@example.com", f.now.Add(2*time.Hour))
	rc, rbr := heldIdle(t, f, bl, addr, renewed, 0)
	for i := 0; i < 6; i++ {
		heldIdle(t, f, bl, addr, f.alice, 0)
	}
	ask(t, rc, rbr)
}

// The other side of the same rule, deterministic: a bind while the flooding
// certificate's own connection is still in a request has no idle one of its
// own to take, so it takes the principal's oldest idle connection, the renewed
// certificate's. This is what TestAFloodChurnsOnlyItsOwnIdleSlots must not
// race into.
func TestABindWithNoIdleConnectionOfItsOwnTakesThePrincipalsOldestIdle(t *testing.T) {
	f := newFixture(t, 8)
	lim := DefaultListenerLimits
	lim.MaxPerPrincipal = 2
	addr, bl := serveThrough(t, f, lim, nil)
	renewed := f.client(t, "alice@example.com", f.now.Add(2*time.Hour))
	rc, _ := heldIdle(t, f, bl, addr, renewed, 0)
	_, fin := busy(t, f, bl, addr, f.alice, 1)
	held(t, f, addr, f.alice)
	if !closedByPeer(rc) {
		t.Fatal("the renewed certificate's idle connection was kept while the flooder had none idle of its own")
	}
	fin()
}

func pendingTotal(l *Listener) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, c := range l.pending {
		n += c
	}
	return n
}

// A connection refused for the cap stays charged to its source until it
// closes, so max_pending_conns_per_source still bounds a flood of them.
func TestACapRefusedConnectionStaysPendingUntilItCloses(t *testing.T) {
	f := newFixture(t, 8)
	lim := DefaultListenerLimits
	lim.MaxPerPrincipal = 4
	addr, bl := serveThrough(t, f, lim, nil)
	for i := 0; i < 4; i++ {
		busy(t, f, bl, addr, f.alice, i+1)
	}
	var refused []*tls.Conn
	for i := 0; i < 3; i++ {
		c, err := tls.Dial("tcp", addr, &tls.Config{Certificates: []tls.Certificate{f.alice}, RootCAs: f.ca.Pool(),
			MinVersion: tls.VersionTLS13})
		if err != nil {
			t.Fatal(err)
		}
		refused = append(refused, c)
	}
	eventually(t, "three refused connections pending", func() bool { return pendingTotal(bl) == 3 })
	for _, c := range refused {
		c.Close()
	}
	eventually(t, "pending given back", func() bool { return pendingTotal(bl) == 0 })
}

// A connection just bound, whose request has not arrived, is not dead: the
// cap does not close it for a newcomer.
func TestAJustBoundConnectionIsNotEvicted(t *testing.T) {
	f := newFixture(t, 8)
	lim := DefaultListenerLimits
	lim.MaxPerPrincipal = 2
	addr, _ := serveThrough(t, f, lim, nil)
	fresh, err := tls.Dial("tcp", addr, &tls.Config{Certificates: []tls.Certificate{f.alice}, RootCAs: f.ca.Pool(),
		MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	time.Sleep(200 * time.Millisecond) // bound, and the server's StateNew has fired
	idle, _ := held(t, f, addr, f.alice)
	third, tbr := held(t, f, addr, f.alice)
	if !closedByPeer(idle) {
		t.Fatal("the idle connection was not the one closed")
	}
	ask(t, fresh, bufio.NewReader(fresh)) // the just-bound connection still serves
	ask(t, third, tbr)
}

// A peer that stops reading mid-response stops counting as busy once the
// response write's deadline passes, and its principal is served again rather
// than refused until TCP gives up.
func TestAStalledResponseStopsBeingBusyWithinTheWriteBound(t *testing.T) {
	prev := writeTimeout
	writeTimeout = 300 * time.Millisecond
	t.Cleanup(func() { writeTimeout = prev })
	f := newFixture(t, 8)
	lim := DefaultListenerLimits
	lim.MaxPerPrincipal = 1
	big := make([]byte, 1<<20)
	srvCert, err := f.ca.Issue(testpki.Leaf{CommonName: "broker", IPs: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: f.now.Add(-time.Hour), NotAfter: f.now.Add(48 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := f.b.Server("127.0.0.1:0", srvCert, f.ca.Pool())
	if err != nil {
		t.Fatal(err)
	}
	srv.Handler = boundWrites(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/big" {
			for i := 0; i < 256; i++ { // 256 MiB: more than any socket buffer holds
				if _, err := w.Write(big); err != nil {
					return
				}
			}
		}
	}))
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	bl := NewListener(Limit(raw, MaxConns), srv.TLSConfig, lim, f.b.Metrics, f.b.Now, func(string, ...any) {})
	go func() { _ = srv.Serve(bl) }()
	t.Cleanup(func() { _ = srv.Close() })
	addr := raw.Addr().String()

	stalled, err := tls.Dial("tcp", addr, &tls.Config{Certificates: []tls.Certificate{f.alice}, RootCAs: f.ca.Pool(),
		MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	defer stalled.Close()
	_, _ = io.WriteString(stalled, "GET /big HTTP/1.1\r\nHost: broker\r\n\r\n") // and never reads
	eventually(t, "the stalled response in flight", func() bool { return activeHeld(bl) == 1 })
	// The write fails 300 ms in; crypto/tls then spends up to 5 s on its
	// close_notify before the connection is gone.
	served := func() bool {
		c, err := tls.Dial("tcp", addr, &tls.Config{Certificates: []tls.Certificate{f.alice}, RootCAs: f.ca.Pool(),
			MinVersion: tls.VersionTLS13})
		if err != nil {
			return false
		}
		defer c.Close()
		_, _ = io.WriteString(c, "GET /small HTTP/1.1\r\nHost: broker\r\n\r\n")
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		return err == nil && resp.StatusCode == http.StatusOK
	}
	for end := time.Now().Add(9 * time.Second); !served(); {
		if time.Now().After(end) {
			t.Fatal("the principal was still refused after the write bound")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// answerRefusal flushes its answer before it queues the revocation that closes
// the connection; the write bound's wrapper must pass the flush through.
func TestTheWriteBoundPassesTheRefusalsFlush(t *testing.T) {
	f := newFixture(t, 8)
	rec := httptest.NewRecorder()
	h := boundWrites(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.b.answerRefusal(w, r, &BindRefusal{Status: http.StatusUnauthorized, Error: "credential_revoked"})
	}))
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/v1/tokens", nil))
	if !rec.Flushed || rec.Code != http.StatusUnauthorized {
		t.Fatalf("flushed %v, status %d", rec.Flushed, rec.Code)
	}
}
