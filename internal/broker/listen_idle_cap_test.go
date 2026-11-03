package broker

import (
	"bufio"
	"crypto/tls"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// busy opens a connection presenting cert and starts a request whose body it does not
// send, so the broker has a request in flight on it. finish completes the
// request and wants its answer.
func busy(t *testing.T, f *fixture, bl *Listener, addr string, cert tls.Certificate) (c *tls.Conn, finish func()) {
	t.Helper()
	c, err := tls.Dial("tcp", addr, &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: f.ca.Pool(),
		MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	before := activeHeld(bl)
	if _, err := io.WriteString(c, "POST /v1/tokens HTTP/1.1\r\nHost: broker\r\nContent-Length: 2\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	eventually(t, "a request in flight", func() bool { return activeHeld(bl) > before })
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
		_, fin := busy(t, f, bl, addr, f.alice)
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
	_, fin := busy(t, f, bl, addr, f.alice) // the oldest, and busy
	finish = append(finish, fin)
	idle, _ := held(t, f, addr, f.alice)
	for i := 0; i < 2; i++ {
		_, fin := busy(t, f, bl, addr, f.alice)
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

// A flood from one certificate churns only its own idle slots.
func TestAFloodChurnsOnlyItsOwnIdleSlots(t *testing.T) {
	f := newFixture(t, 8)
	lim := DefaultListenerLimits
	lim.MaxPerPrincipal = 2
	addr, _ := serveThrough(t, f, lim, nil)
	renewed := f.client(t, "alice@example.com", f.now.Add(2*time.Hour))
	rc, rbr := held(t, f, addr, renewed)
	for i := 0; i < 6; i++ {
		held(t, f, addr, f.alice)
	}
	ask(t, rc, rbr)
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
		busy(t, f, bl, addr, f.alice)
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
