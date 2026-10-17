package server

import (
	"crypto/tls"
	"github.com/rhwendt/port49/internal/admission"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/rhwendt/port49/internal/devicecert"
	"github.com/rhwendt/port49/internal/tacacs/wire"
	"github.com/rhwendt/port49/internal/testpki"
)

// firstTicket is a client session cache that keeps the first ticket it is
// given and offers it at every connection: a client replaying one ticket.
type firstTicket struct {
	mu sync.Mutex
	cs *tls.ClientSessionState
}

func (c *firstTicket) Get(string) (*tls.ClientSessionState, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cs, c.cs != nil
}

func (c *firstTicket) Put(_ string, cs *tls.ClientSessionState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cs == nil && cs != nil {
		c.cs = cs
	}
}

// ticketed sets the fixture's material to issue tickets for lifetime,
// under clock now.
func ticketed(t *testing.T, f *tlsFixture, lifetime time.Duration, now func() time.Time) *TicketGuard {
	t.Helper()
	m := f.material(f.ca, false)
	g := NewTicketGuard(lifetime, now)
	if err := g.Apply(m.Config); err != nil {
		t.Fatal(err)
	}
	m.Tickets = g
	f.mat.Store(m)
	return g
}

// countingCache is a client session cache that counts the tickets the
// server issued it.
type countingCache struct {
	tls.ClientSessionCache
	issued atomic.Int32
}

func (c *countingCache) Put(k string, cs *tls.ClientSessionState) {
	if cs != nil {
		c.issued.Add(1)
	}
	c.ClientSessionCache.Put(k, cs)
}

func newCountingCache() *countingCache {
	return &countingCache{ClientSessionCache: tls.NewLRUClientSessionCache(4)}
}

// newestTicket is a client session cache that keeps the newest ticket it is
// given: a device that resumes every time.
type newestTicket struct {
	mu sync.Mutex
	cs *tls.ClientSessionState
}

func (c *newestTicket) Get(string) (*tls.ClientSessionState, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cs, c.cs != nil
}

func (c *newestTicket) Put(_ string, cs *tls.ClientSessionState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if cs != nil {
		c.cs = cs
	}
}

// resumed logs in with cache and reports whether the connection resumed.
func resumed(t *testing.T, f *tlsFixture, cert tls.Certificate, cache tls.ClientSessionCache) bool {
	t.Helper()
	c, err := f.dialTLS(t, &cert, func(cfg *tls.Config) { cfg.ClientSessionCache = cache })
	if err != nil {
		t.Fatal(err)
	}
	if err := c.send(wire.TypeAuthen, aliceLogin, wire.FlagUnencrypted); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.recv(); err != nil { // the reply; the ticket arrived with it
		t.Fatal(err)
	}
	return c.conn.ConnectionState().DidResume
}

func TestNoTicketsWhenTheLifetimeIsZero(t *testing.T) {
	f := newTLSFixture(t, &syncBuffer{}, nil)
	cert := f.deviceCert(t, nil, testpki.Leaf{})
	cache := newCountingCache()
	for i := 0; i < 2; i++ {
		if resumed(t, f, cert, cache) {
			t.Fatal("resumed with session_ticket_lifetime 0s")
		}
	}
	if n := cache.issued.Load(); n != 0 {
		t.Fatalf("%d tickets issued with session_ticket_lifetime 0s", n)
	}
}

func TestTicketsAreSingleUse(t *testing.T) {
	f := newTLSFixture(t, &syncBuffer{}, nil)
	ticketed(t, f, 10*time.Minute, time.Now)
	cert := f.deviceCert(t, nil, testpki.Leaf{})
	cache := &firstTicket{}
	if resumed(t, f, cert, cache) {
		t.Fatal("the first connection resumed")
	}
	if !resumed(t, f, cert, cache) {
		t.Fatal("an unused ticket did not resume (RFC 9887 §3.6: SHOULD allow)")
	}
	if resumed(t, f, cert, cache) {
		t.Fatal("a ticket resumed twice")
	}
	if n := testutil.ToFloat64(f.ts.metrics.TLSHandshakes.WithLabelValues(string(devicecert.Resumed))); n != 1 {
		t.Fatalf("handshakes{resumed} = %v", n)
	}
}

func TestTicketsExpire(t *testing.T) {
	f := newTLSFixture(t, &syncBuffer{}, nil)
	var skew atomic.Int64
	ticketed(t, f, time.Minute, func() time.Time { return time.Now().Add(time.Duration(skew.Load())) })
	cert := f.deviceCert(t, nil, testpki.Leaf{})
	cache := &firstTicket{}
	resumed(t, f, cert, cache)
	skew.Store(int64(2 * time.Minute))
	if resumed(t, f, cert, cache) {
		t.Fatal("a ticket older than session_ticket_lifetime resumed")
	}
}

func TestAReloadInvalidatesTickets(t *testing.T) {
	f := newTLSFixture(t, &syncBuffer{}, nil)
	ticketed(t, f, 10*time.Minute, time.Now)
	cert := f.deviceCert(t, nil, testpki.Leaf{})
	cache := &firstTicket{}
	resumed(t, f, cert, cache)
	ticketed(t, f, 10*time.Minute, time.Now) // a reload: new material, new keys
	if resumed(t, f, cert, cache) {
		t.Fatal("a ticket from before the reload resumed")
	}
}

func TestAResumptionIsVerifiedAgain(t *testing.T) {
	log := &syncBuffer{}
	f := newTLSFixture(t, log, func(d *Deps, _ *tlsFixture) { d.Limits = slowBackoff() })
	ticketed(t, f, 10*time.Minute, time.Now)
	cert := f.deviceCert(t, nil, testpki.Leaf{})
	cache := &firstTicket{}
	resumed(t, f, cert, cache)
	f.status.Store(int32(devicecert.StatusRevoked))
	c, err := f.dialTLS(t, &cert, func(cfg *tls.Config) { cfg.ClientSessionCache = cache })
	if err == nil {
		err = c.send(wire.TypeAuthen, aliceLogin, wire.FlagUnencrypted)
		if err == nil {
			_, _, err = c.recv()
		}
	}
	if err == nil {
		t.Fatal("a resumption with a revoked certificate was answered (RFC 9887 §3.6)")
	}
	if !waitFor(t, func() bool { return log.contains(`"tls_outcome":"certificate_revoked"`) }) {
		t.Fatalf("log: %s", log.String())
	}
}

// A Material whose Config has tickets on, with no guard applied, issues none:
// an unguarded ticket is multi-use and unbounded.
func TestTicketsAreForcedOffWithoutAGuard(t *testing.T) {
	f := newTLSFixture(t, &syncBuffer{}, nil)
	m := f.material(f.ca, false)                   // SessionTicketsDisabled false, no guard
	m.Config.SetSessionTicketKeys([][32]byte{{1}}) // keys that outlive a connection's clone
	f.mat.Store(m)
	cert := f.deviceCert(t, nil, testpki.Leaf{})
	cache := newCountingCache()
	for i := 0; i < 3; i++ {
		if resumed(t, f, cert, cache) {
			t.Fatal("resumed on a Config with tickets on and no ticket guard")
		}
	}
	if n := cache.issued.Load(); n != 0 {
		t.Fatalf("%d tickets issued with no ticket guard", n)
	}
}

// Hooks inherited from the base Config do not turn tickets on: only
// Material.Tickets does.
func TestInheritedHooksDoNotIssueTickets(t *testing.T) {
	f := newTLSFixture(t, &syncBuffer{}, nil)
	m := f.material(f.ca, false)
	m.Config.SetSessionTicketKeys([][32]byte{{1}})
	m.Config.WrapSession = func(cs tls.ConnectionState, ss *tls.SessionState) ([]byte, error) {
		return m.Config.EncryptTicket(cs, ss)
	}
	m.Config.UnwrapSession = func(id []byte, cs tls.ConnectionState) (*tls.SessionState, error) {
		return m.Config.DecryptTicket(id, cs)
	}
	f.mat.Store(m)
	cert := f.deviceCert(t, nil, testpki.Leaf{})
	cache := newCountingCache()
	for i := 0; i < 2; i++ {
		resumed(t, f, cert, cache)
	}
	if n := cache.issued.Load(); n != 0 {
		t.Fatalf("%d tickets issued by hooks no guard bound", n)
	}
}

// One ticket replayed by many connections at once resumes at most one.
func TestTicketsAreSingleUseUnderConcurrentReplay(t *testing.T) {
	f := newTLSFixture(t, &syncBuffer{}, nil)
	ticketed(t, f, 10*time.Minute, time.Now)
	cert := f.deviceCert(t, nil, testpki.Leaf{})
	cache := &firstTicket{}
	resumed(t, f, cert, cache)
	const n = 12
	var wins atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cfg := &tls.Config{RootCAs: f.ca.Pool(), ServerName: "tacacs.example.net", MinVersion: tls.VersionTLS13,
				Certificates: []tls.Certificate{cert}, ClientSessionCache: cache}
			raw, err := net.Dial("tcp", f.ts.addr)
			if err != nil {
				t.Error(err)
				return
			}
			defer raw.Close()
			tc := tls.Client(raw, cfg)
			tc.SetDeadline(time.Now().Add(5 * time.Second))
			<-start
			if tc.Handshake() == nil && tc.ConnectionState().DidResume {
				wins.Add(1)
			}
			io.Copy(io.Discard, tc) // the server's verdict may reset; nothing to check
		}()
	}
	close(start)
	wg.Wait()
	if w := wins.Load(); w != 1 {
		t.Fatalf("%d connections resumed one ticket, want exactly 1", w)
	}
}

// Tickets on do not admit early data: a ClientHello carrying it is refused.
func TestNoEarlyDataWithTicketsOn(t *testing.T) {
	log := &syncBuffer{}
	f := newTLSFixture(t, log, func(d *Deps, _ *tlsFixture) { d.Limits = slowBackoff() })
	ticketed(t, f, 10*time.Minute, time.Now)
	conn, err := net.Dial("tcp", f.ts.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write(clientHelloWithEarlyData(t)); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	io.ReadAll(conn)
	if !waitFor(t, func() bool { return log.contains(`"tls_outcome":"early_data_refused"`) }) {
		t.Fatalf("log: %s", log.String())
	}
}

// A ticket never skips the verdict on expiry: the certificate that expired
// since the ticket was issued is refused on resumption.
func TestAResumptionIsJudgedForExpiry(t *testing.T) {
	log := &syncBuffer{}
	f := newTLSFixture(t, log, func(d *Deps, _ *tlsFixture) { d.Limits = slowBackoff() })
	ticketed(t, f, 10*time.Minute, time.Now)
	cert := f.deviceCert(t, nil, testpki.Leaf{})
	cache := &firstTicket{}
	resumed(t, f, cert, cache)
	m := f.mat.Load()
	m.Verifier.Now = func() time.Time { return time.Now().Add(3 * time.Hour) }
	c, err := f.dialTLS(t, &cert, func(cfg *tls.Config) { cfg.ClientSessionCache = cache })
	if err == nil {
		err = c.send(wire.TypeAuthen, aliceLogin, wire.FlagUnencrypted)
		if err == nil {
			_, _, err = c.recv()
		}
	}
	if err == nil {
		t.Fatal("a resumption with an expired certificate was answered")
	}
	if !waitFor(t, func() bool { return log.contains(`"tls_outcome":"certificate_expired"`) }) {
		t.Fatalf("log: %s", log.String())
	}
}

// A chain of resumptions is bounded by the full handshake that began it: a
// ticket issued on a resumption carries the chain's origin time.
func TestAResumptionChainEndsAtTheLifetime(t *testing.T) {
	f := newTLSFixture(t, &syncBuffer{}, nil)
	var skew atomic.Int64
	ticketed(t, f, time.Minute, func() time.Time { return time.Now().Add(time.Duration(skew.Load())) })
	cert := f.deviceCert(t, nil, testpki.Leaf{})
	cache := &newestTicket{}
	if resumed(t, f, cert, cache) {
		t.Fatal("the first connection resumed")
	}
	skew.Store(int64(40 * time.Second))
	if !resumed(t, f, cert, cache) {
		t.Fatal("a ticket 40s old did not resume")
	}
	skew.Store(int64(80 * time.Second)) // the new ticket is 40s old, its chain 80s
	if resumed(t, f, cert, cache) {
		t.Fatal("a chain of resumptions outlived session_ticket_lifetime")
	}
}

// A ticket used once stays refused while it is fresh, through scans of the
// used set, and when the clock steps back.
func TestAUsedTicketStaysRefusedWhileFresh(t *testing.T) {
	f := newTLSFixture(t, &syncBuffer{}, nil)
	base := time.Now().Unix()
	var off atomic.Int64
	ticketed(t, f, time.Minute, func() time.Time { return time.Unix(base+off.Load(), 0) })
	cert := f.deviceCert(t, nil, testpki.Leaf{})
	a, b, c := &firstTicket{}, &firstTicket{}, &firstTicket{}
	resumed(t, f, cert, a)
	resumed(t, f, cert, b)
	resumed(t, f, cert, c)
	for _, step := range []struct {
		at     int64
		cache  *firstTicket
		resume bool
	}{{1, b, true}, {20, a, true}, {40, c, true}, {45, a, false}, {30, a, false}} {
		off.Store(step.at) // the last step is the wall clock stepping back
		if got := resumed(t, f, cert, step.cache); got != step.resume {
			t.Fatalf("at +%ds resumed = %v, want %v", step.at, got, step.resume)
		}
	}
}

// The used set drops a ticket once it is too old to resume anyway.
func TestTheUsedSetIsPruned(t *testing.T) {
	f := newTLSFixture(t, &syncBuffer{}, nil)
	base := time.Now().Unix()
	var off atomic.Int64
	g := ticketed(t, f, time.Minute, func() time.Time { return time.Unix(base+off.Load(), 0) })
	cert := f.deviceCert(t, nil, testpki.Leaf{})
	a, b := &firstTicket{}, &firstTicket{}
	resumed(t, f, cert, a)
	off.Store(10)
	resumed(t, f, cert, a)
	off.Store(100)
	resumed(t, f, cert, b)
	off.Store(101)
	resumed(t, f, cert, b)
	g.mu.Lock()
	n := len(g.used)
	g.mu.Unlock()
	if n != 1 {
		t.Fatalf("used set holds %d tickets, want 1 (the old one pruned)", n)
	}
}

// A ticket is bound to the device it was issued for: presented from the
// address of another tls device, it is refused as an identity mismatch.
func TestAResumptionIsBoundToTheDevice(t *testing.T) {
	log := &syncBuffer{}
	f := newTLSFixture(t, log, func(d *Deps, _ *tlsFixture) { d.Limits = slowBackoff() })
	ticketed(t, f, 10*time.Minute, time.Now)
	cert := f.deviceCert(t, nil, testpki.Leaf{})
	cache := &firstTicket{}
	resumed(t, f, cert, cache)
	other := leaf01TLS
	other.Name = "leaf-02"
	f.admit.swap(t, admission.Resolved{Device: other})
	c, err := f.dialTLS(t, &cert, func(cfg *tls.Config) { cfg.ClientSessionCache = cache })
	if err == nil {
		err = c.send(wire.TypeAuthen, aliceLogin, wire.FlagUnencrypted)
		if err == nil {
			_, _, err = c.recv()
		}
	}
	if err == nil {
		t.Fatal("a ticket for leaf-01 resumed as leaf-02")
	}
	if !waitFor(t, func() bool { return log.contains(`"tls_outcome":"identity_mismatch"`) }) {
		t.Fatalf("log: %s", log.String())
	}
}

// A stamp is the time since the guard began, read from the clock's own
// monotonic reading when it has one, so a step of the wall clock cannot move
// it. The test clock cannot model a wall step (time.Time.Add moves both
// readings), so this pins the property that makes one harmless: the stamp is
// an elapsed time, and is the same with the monotonic reading stripped.
func TestAStampIsTimeSinceTheGuardBegan(t *testing.T) {
	start := time.Now()
	var off atomic.Int64
	g := NewTicketGuard(time.Minute, func() time.Time { return start.Add(time.Duration(off.Load())) })
	off.Store(int64(40 * time.Second))
	if got := time.Duration(g.elapsed()); got != 40*time.Second {
		t.Fatalf("stamp = %v, want 40s", got)
	}
	g = NewTicketGuard(time.Minute, func() time.Time { return start.Round(0).Add(time.Duration(off.Load())) })
	off.Store(0)
	g.start = start.Round(0)
	off.Store(int64(40 * time.Second))
	if got := time.Duration(g.elapsed()); got != 40*time.Second {
		t.Fatalf("stamp without a monotonic reading = %v, want 40s", got)
	}
}
