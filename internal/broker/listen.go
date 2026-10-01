package broker

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/printsafe"
	"github.com/rhwendt/port49/internal/store"
)

// ListenerLimits are the broker listener's bounds (design §11's "per source
// before global", §17; spec §13 decision 32).
type ListenerLimits struct {
	// MaxPendingPerSource caps the connections one source address holds that
	// are not bound to a principal: handshaking, or certificate-less for
	// /v1/config. Past it the next connection from the address is reset at
	// accept. An authenticated operator's held connection is not counted, so
	// a NAT'd office is not capped by its own logged-in operators.
	MaxPendingPerSource int
	// MaxPerPrincipal caps one principal's held connections. A new one closes
	// that principal's oldest: refusing the newest would lock out an operator
	// whose laptop slept with connections the broker still holds.
	MaxPerPrincipal int
	// HandshakeTimeout bounds a TLS handshake.
	HandshakeTimeout time.Duration
}

// DefaultListenerLimits are port49d's defaults (broker.max_pending_conns_per_source,
// broker.max_conns_per_principal).
var DefaultListenerLimits = ListenerLimits{MaxPendingPerSource: 16, MaxPerPrincipal: 4,
	HandshakeTimeout: 10 * time.Second}

// ConnCloser is the listener as a revocation sees it (Broker.Conns):
// CloseHeld closes the held connections a mark names, and Revoked keeps the
// listener's in-memory copy of the marks, by (store.Revocation kind, key),
// which refuses a marked connection as it binds.
type ConnCloser interface {
	CloseHeld(match func(principal, certKey string) bool) int
	Revoked(kind, key string, on bool)
}

// sayEvery is how often one reason's line is said: a flood is one line and
// a count, never a flood of lines.
const sayEvery = 10 * time.Second

// Listener accepts from inner, completes each TLS handshake itself, and
// hands http.Server only connections whose handshake is done (spec §13
// decision 32). Doing the handshake here is what lets every failure be
// counted by its reason, a connection be charged to its source until it is
// bound to a principal, and a principal's held connections be counted,
// capped, and closed by a revocation (CloseHeld).
type Listener struct {
	inner net.Listener
	cfg   *tls.Config
	lim   ListenerLimits
	m     *metrics.Metrics
	now   func() time.Time
	logf  func(format string, args ...any)

	ready     chan *tls.Conn
	done      chan struct{}
	startOnce sync.Once
	closeOnce sync.Once

	mu sync.Mutex
	// pending is, by source, the connections not bound to a principal.
	pending map[netip.Addr]int
	// open is every connection not yet closed, true once it is handed to
	// Accept's caller, which then owns its close.
	open map[*trackedConn]bool
	// held is, by principal, its bound connections, oldest first.
	held map[string][]*trackedConn
	// marked is the broker's marks, by (kind, key), kept by Revoked.
	marked map[[2]string]bool
	lines  map[string]*lineLimit
}

// Revoked puts a mark in the listener's copy, or takes it out (on false):
// Broker.Revoke, Broker.Lift and port49d's start-up restore call it.
func (l *Listener) Revoked(kind, key string, on bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if on {
		l.marked[[2]string{kind, key}] = true
	} else {
		delete(l.marked, [2]string{kind, key})
	}
}

type lineLimit struct {
	last time.Time
	held int
}

// trackedConn is one accepted connection. principal, certKey and gone are
// under the listener's mu.
type trackedConn struct {
	net.Conn
	l          *Listener
	acceptedAt time.Time
	src        netip.Addr
	principal  string
	certKey    string
	gone       bool
	closeOnce  sync.Once
}

// NewListener accepts nothing from inner until the first Accept, so the
// marks a caller hands it (Revoked) before srv.Serve are all in place before
// any connection can bind; from then on it accepts on its own, and
// connections whose handshake is done wait for Accept. cfg is the broker's
// (Broker.Server's TLSConfig). logf says the listener's lines; nil says
// nothing.
func NewListener(inner net.Listener, cfg *tls.Config, lim ListenerLimits, m *metrics.Metrics, now func() time.Time,
	logf func(format string, args ...any)) *Listener {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	l := &Listener{inner: inner, cfg: cfg, lim: lim, m: m, now: now, logf: logf,
		ready: make(chan *tls.Conn), done: make(chan struct{}),
		pending: map[netip.Addr]int{}, open: map[*trackedConn]bool{}, held: map[string][]*trackedConn{},
		marked: map[[2]string]bool{}, lines: map[string]*lineLimit{}}
	return l
}

func (l *Listener) Addr() net.Addr { return l.inner.Addr() }

// Accept returns a connection whose handshake is done, or net.ErrClosed
// once the listener is closed. The first call starts accepting from inner.
func (l *Listener) Accept() (net.Conn, error) {
	l.startOnce.Do(func() { go l.acceptLoop() })
	select {
	case tc := <-l.ready:
		return tc, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

// Close stops accepting, closes inner (which wakes a Limit waiting for a
// slot), and closes every connection not yet handed to Accept's caller:
// http.Server's Shutdown waits for nothing it does not know about, and a
// handshake that never finishes must not outlive the listener.
func (l *Listener) Close() error {
	var err error
	l.closeOnce.Do(func() {
		close(l.done)
		err = l.inner.Close()
		l.mu.Lock()
		var stray []*trackedConn
		for c, handed := range l.open {
			if !handed {
				stray = append(stray, c)
			}
		}
		l.mu.Unlock()
		for _, c := range stray {
			_ = c.Close()
		}
	})
	return err
}

func (l *Listener) acceptLoop() {
	var delay time.Duration
	for {
		raw, err := l.inner.Accept()
		if err != nil {
			select {
			case <-l.done:
				return
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				_ = l.Close()
				return
			}
			// As net/http's Serve does for a failing Accept (EMFILE among
			// them): back off, up to a second, and go on.
			delay = min(max(2*delay, 5*time.Millisecond), time.Second)
			l.say("accept", "port49d: broker: accept failed: %v; retrying in %s", err, delay)
			time.Sleep(delay)
			continue
		}
		delay = 0
		if c := l.admit(raw); c != nil {
			go l.handshake(c)
		}
	}
}

// admit charges raw to its source, or resets it when the source already
// holds MaxPendingPerSource connections not bound to a principal.
func (l *Listener) admit(raw net.Conn) *trackedConn {
	src := sourceOf(raw.RemoteAddr())
	l.mu.Lock()
	select {
	case <-l.done:
		// Close has run, and its sweep of open may have missed this one:
		// it must not handshake on after the listener is gone.
		l.mu.Unlock()
		reset(raw)
		return nil
	default:
	}
	if l.pending[src] >= l.lim.MaxPendingPerSource {
		l.mu.Unlock()
		reset(raw)
		l.m.BrokerConnectionEvents.WithLabelValues("source_cap_refused").Inc()
		l.say("source_cap", "port49d: broker: reset a connection from %s: it holds %d connections not yet "+
			"authenticated (broker.max_pending_conns_per_source)", src, l.lim.MaxPendingPerSource)
		return nil
	}
	c := &trackedConn{Conn: raw, l: l, acceptedAt: l.now(), src: src}
	l.pending[src]++
	l.open[c] = false
	l.mu.Unlock()
	l.gauge()
	return c
}

// handshake completes c's TLS handshake within HandshakeTimeout, binds it
// to its principal when it presented a certificate, and hands it to Accept.
func (l *Listener) handshake(c *trackedConn) {
	tc := tls.Server(c, l.cfg)
	ctx, cancel := context.WithTimeout(context.Background(), l.lim.HandshakeTimeout)
	err := tc.HandshakeContext(ctx)
	cancel()
	if err != nil {
		l.refuse(c, tc, handshakeReason(err), err)
		return
	}
	if cs := tc.ConnectionState(); len(cs.PeerCertificates) > 0 {
		// The handshake's VerifyConnection ran Identity a moment ago; this
		// reads the same answer, which a clock step alone could change.
		principal, cred, err := Identity(&cs, l.now())
		if err != nil {
			l.refuse(c, tc, "identity_refused", err)
			return
		}
		if !l.bind(c, principal, store.CertKey(cred.Issuer, cred.Serial)) {
			_ = tc.Close()
			return
		}
	}
	l.mu.Lock()
	if _, ok := l.open[c]; ok {
		l.open[c] = true
	}
	l.mu.Unlock()
	select {
	case l.ready <- tc:
	case <-l.done:
		_ = tc.Close()
	}
}

// refuse counts and says a failed handshake, and closes the connection.
// The error can quote a client certificate's subject, so it is made
// printable and cut. A handshake Close cut short is not a failure: it is
// neither counted nor said, or every restart would read as an attack.
func (l *Listener) refuse(c *trackedConn, tc *tls.Conn, reason string, err error) {
	select {
	case <-l.done:
		_ = tc.Close()
		return
	default:
	}
	l.m.BrokerHandshakeFailures.WithLabelValues(reason).Inc()
	l.say("handshake_"+reason, "port49d: broker: TLS handshake from %s failed (%s): %s", c.src, reason,
		printsafe.Line(err.Error(), 300))
	_ = tc.Close()
}

// handshakeReason is the closed set of spec §13 decision 32.
func handshakeReason(err error) string {
	var verify *tls.CertificateVerificationError
	var op *net.OpError
	var ne net.Error
	switch {
	case errors.As(err, &verify):
		return "untrusted_chain"
	case errors.Is(err, ErrUntrusted):
		return "identity_refused"
	case errors.As(err, &op) && op.Op == "remote error":
		// The client sent an alert: it refused the broker's certificate.
		return "server_cert_refused"
	case errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()):
		return "timeout"
	case errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.EPIPE):
		return "client_closed"
	}
	return "protocol"
}

// bind moves c from its source's pending count to its principal's held
// connections, closing the principal's oldest past MaxPerPrincipal. It
// reports false when c was closed under it.
func (l *Listener) bind(c *trackedConn, principal, certKey string) bool {
	l.mu.Lock()
	if c.gone {
		l.mu.Unlock()
		return false
	}
	l.unpendLocked(c.src)
	c.principal, c.certKey = principal, certKey
	if l.marked[[2]string{store.RevocationPrincipal, principal}] || l.marked[[2]string{store.RevocationCert, certKey}] {
		// A revoked principal or certificate is refused here, from the
		// broker's in-memory copy of the marks (Revoked): no store read at
		// the handshake (spec §13 decision 32), and a revoked certificate
		// never gets to close its owner's connections (pre-flight I3). It
		// was never added to held, so forget, at the Close below, has
		// nothing to take back from the principal.
		c.gone = true
		delete(l.open, c)
		l.mu.Unlock()
		l.m.BrokerConnectionEvents.WithLabelValues("revoked_refused").Inc()
		l.say("revoked_refused", "port49d: broker: closed a connection from %s as it bound: %s or its "+
			"certificate is revoked", c.src, principal)
		l.gauge()
		return false
	}
	held := append(l.held[principal], c)
	var evicted *trackedConn
	if len(held) > l.lim.MaxPerPrincipal {
		// The oldest of the same certificate goes first, so a flood from one
		// certificate churns its own slots and never its owner's other
		// certificate's (pre-flight I3); otherwise the principal's oldest.
		i := 0
		for j, h := range held[:len(held)-1] {
			if h.certKey == certKey {
				i = j
				break
			}
		}
		evicted = held[i]
		held = append(held[:i:i], held[i+1:]...)
	}
	l.held[principal] = held
	l.mu.Unlock()
	if evicted != nil {
		l.m.BrokerConnectionEvents.WithLabelValues("principal_cap_evicted").Inc()
		l.say("principal_cap", "port49d: broker: %s opened more than %d held connections "+
			"(broker.max_conns_per_principal); its oldest, from %s and open since %s, is closed", principal,
			l.lim.MaxPerPrincipal, evicted.src, evicted.acceptedAt.UTC().Format(time.RFC3339))
		_ = evicted.Close()
	}
	l.gauge()
	return true
}

// CloseHeld closes every held connection match names, and returns how many
// (spec §5.1.4: a revocation reaches the held connection).
func (l *Listener) CloseHeld(match func(principal, certKey string) bool) int {
	l.mu.Lock()
	var hit []*trackedConn
	for _, conns := range l.held {
		for _, c := range conns {
			if match(c.principal, c.certKey) {
				hit = append(hit, c)
			}
		}
	}
	l.mu.Unlock()
	for _, c := range hit {
		_ = c.Close()
	}
	if len(hit) > 0 {
		l.m.BrokerConnectionEvents.WithLabelValues("revoked_closed").Add(float64(len(hit)))
	}
	return len(hit)
}

// Close closes the connection and, once, gives back what it was charged.
func (c *trackedConn) Close() error {
	err := c.Conn.Close()
	c.closeOnce.Do(func() { c.l.forget(c) })
	return err
}

func (l *Listener) forget(c *trackedConn) {
	l.mu.Lock()
	c.gone = true
	delete(l.open, c)
	if c.principal == "" {
		l.unpendLocked(c.src)
	} else {
		conns := l.held[c.principal]
		for i, h := range conns {
			if h == c {
				conns = append(conns[:i:i], conns[i+1:]...)
				break
			}
		}
		if len(conns) == 0 {
			delete(l.held, c.principal)
		} else {
			l.held[c.principal] = conns
		}
	}
	l.mu.Unlock()
	l.gauge()
}

func (l *Listener) unpendLocked(src netip.Addr) {
	if l.pending[src]--; l.pending[src] <= 0 {
		delete(l.pending, src)
	}
}

func (l *Listener) gauge() {
	l.mu.Lock()
	pending, held := 0, 0
	for _, n := range l.pending {
		pending += n
	}
	for _, conns := range l.held {
		held += len(conns)
	}
	// Set under mu: two events setting outside it could land out of order
	// and leave the gauge naming a connection that is gone.
	l.m.BrokerConnections.WithLabelValues("pending").Set(float64(pending))
	l.m.BrokerConnections.WithLabelValues("held").Set(float64(held))
	l.mu.Unlock()
}

// say logs a line at most once per reason per sayEvery; the next line says
// how many it held back.
func (l *Listener) say(reason, format string, args ...any) {
	now := l.now()
	l.mu.Lock()
	ll := l.lines[reason]
	if ll == nil {
		ll = &lineLimit{}
		l.lines[reason] = ll
	}
	if !ll.last.IsZero() && now.Sub(ll.last) < sayEvery {
		ll.held++
		l.mu.Unlock()
		return
	}
	held := ll.held
	ll.last, ll.held = now, 0
	l.mu.Unlock()
	line := fmt.Sprintf(format, args...)
	if held > 0 {
		line += fmt.Sprintf(" (%d more like it since the last such line)", held)
	}
	l.logf("%s", line)
}

// sourceOf is the connection's source address; one it cannot read is the
// zero address, which every such connection shares.
func sourceOf(a net.Addr) netip.Addr {
	if a == nil {
		return netip.Addr{}
	}
	ap, err := netip.ParseAddrPort(a.String())
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap()
}

// reset closes c with a TCP reset, as port49d refuses a TACACS+ source at
// Accept (spec §10): nothing is held, and the client learns at once. The
// outermost connection is the one closed, so Limit's slot comes back.
func reset(c net.Conn) {
	for inner := c; inner != nil; {
		if tcp, ok := inner.(*net.TCPConn); ok {
			_ = tcp.SetLinger(0)
			break
		}
		u, ok := inner.(interface{ NetConn() net.Conn })
		if !ok {
			break
		}
		inner = u.NetConn()
	}
	_ = c.Close()
}

// acceptedAt is when the listener accepted c, before its handshake: the
// connection's auth_time (plan 3, Decided 2). A connection that did not come
// through a Listener — ServeTLS in a test — is stamped now, as before.
func acceptedAt(c net.Conn, now func() time.Time) time.Time {
	if tc, ok := c.(*tls.Conn); ok {
		if t, ok := tc.NetConn().(*trackedConn); ok {
			return t.acceptedAt
		}
	}
	return now()
}
