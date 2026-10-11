package broker

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/directory"
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
	// MapTimeout bounds the directory mapping at bind (Listener.Map): port49d
	// sets the directory's query_timeout plus 1s. Zero is HandshakeTimeout.
	MapTimeout time.Duration
}

// DefaultListenerLimits are port49d's defaults (broker.max_pending_conns_per_source,
// broker.max_conns_per_principal).
var DefaultListenerLimits = ListenerLimits{MaxPendingPerSource: 16, MaxPerPrincipal: 4,
	HandshakeTimeout: 10 * time.Second}

// ConnCloser is the listener as a revocation sees it (Broker.Conns):
// CloseHeld closes the held connections a mark names, Revoked keeps the
// listener's in-memory copy of the marks, by (store.Revocation kind, key),
// which answers a marked connection credential_revoked as it binds, and
// HoldsCert says whether a certificate a CRL names holds a connection.
type ConnCloser interface {
	CloseHeld(match func(principal, certKey string) bool) int
	Revoked(mark store.Revocation, on bool)
	HoldsCert(certKey string) bool
}

// revokedAnswerTimeout bounds a marked connection's one request and its
// answer: a client that sends nothing is closed at it. Swapped in tests.
var revokedAnswerTimeout = 5 * time.Second

// revokedRequestMax bounds the bytes a marked connection's request line and
// headers are read for: an agent's are well under it, and longer ones are
// cut off unanswered.
const revokedRequestMax = 4 << 10

// revokedBodyMax bounds how much of a marked connection's request body is
// drained before it is answered, and revokedDrainMax how much more is read
// and thrown away after the answer, so a batch mint's body left unread does
// not reset the answer away.
const (
	revokedBodyMax  = 64 << 10
	revokedDrainMax = 1 << 20
)

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

	// Refused records a request refused as its connection bound, with the
	// path it asked for and the reason: credential_revoked for a mark, or
	// Status's. One deny record each, under the path's event (spec §5.7;
	// decision 34), which port49d sets to Broker.RefusedAtBind. Set it before
	// the first Accept; nil records nothing.
	Refused func(path, principal string, cred store.Credential, reason decision.Reason)
	// Status answers a certificate chain's revocation status before the
	// connection binds (spec §5.1.4): a refusal is answered, recorded
	// (Refused) and closed while the connection is still charged to its
	// source, so a revoked certificate never holds a slot or evicts its
	// owner's connections. port49d sets it to Broker.BindStatus; nil checks
	// nothing.
	Status func(cs tls.ConnectionState, principal string, cred store.Credential) *BindRefusal
	// Map maps the certificate to its directory principal once, at bind,
	// after the certificate's own marks and Status and before the principal's
	// mark (Ruling 4): its answer is pinned to the connection, and a refusal
	// is answered and closed as Status's is. port49d sets it to
	// Broker.BindMap when a directory is configured; nil keeps the email-SAN
	// principal.
	Map func(ctx context.Context, cs tls.ConnectionState, cred store.Credential) (directory.Answer, *BindRefusal)
	// Caller reads a connection's verified certificate as the broker does
	// (Broker.CertCallerOf; plan 8): a workload's principal is its SPIFFE ID,
	// never mapped. Broker.Wire sets it. Nil without Map reads a certificate
	// as before plan 8; nil with Map serves nothing (ErrUnwired).
	Caller func(cs *tls.ConnectionState, now time.Time) (CertCaller, error)

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
	// marked is the broker's marks, by (kind, key), each as Revoked was
	// given it: its origin decides how a refusal from it reads
	// (revokedError).
	marked map[[2]string]store.Revocation
	lines  map[string]*lineLimit
}

// Revoked puts a mark in the listener's copy, or takes it out (on false):
// Broker.Revoke, Broker.Lift and port49d's start-up restore call it.
func (l *Listener) Revoked(mark store.Revocation, on bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if on {
		l.marked[[2]string{mark.Kind, mark.Key}] = mark
	} else {
		delete(l.marked, [2]string{mark.Kind, mark.Key})
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
	mapped     *directory.Answer
	legacy     string // the email-SAN principal the certificate had before a directory, "" without one
	gone       bool
	closeOnce  sync.Once
}

// ErrUnwired is Accept's answer on a listener given Map without Caller: it
// would map a workload's certificate through the directory as a person's
// (decision 40 ruling 5), so it serves nothing and says why at start
// (pre-flight I-4).
var ErrUnwired = errors.New("broker: the listener has a directory Map but no Caller, so a workload certificate " +
	"would be mapped as a person's; wire it with Broker.Wire")

// Wire sets l's hooks from b: the one way port49d and port49-broker wire
// their listener (pre-flight I-4). Refused, Status and Caller always; Map
// under a directory. Caller is what keeps a workload out of Map. It must run
// before Serve (the first Accept): the hooks are read without a lock.
func (b *Broker) Wire(l *Listener) {
	l.Refused = b.RefusedAtBind
	l.Status = b.BindStatus
	l.Caller = b.CertCallerOf
	l.Map = nil
	if b.Directory != nil {
		l.Map = b.BindMap
	}
}

// NewListener accepts nothing from inner until the first Accept, so the
// marks a caller hands it (Revoked) before srv.Serve are all in place before
// any connection can bind; from then on it accepts on its own, and
// connections whose handshake is done wait for Accept. cfg is the broker's
// (Broker.Server's TLSConfig). logf says the listener's lines, each begun
// "broker: ", for the caller to begin with its process's name; nil says
// nothing.
func NewListener(inner net.Listener, cfg *tls.Config, lim ListenerLimits, m *metrics.Metrics, now func() time.Time,
	logf func(format string, args ...any)) *Listener {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	l := &Listener{inner: inner, cfg: cfg, lim: lim, m: m, now: now, logf: logf,
		ready: make(chan *tls.Conn), done: make(chan struct{}),
		pending: map[netip.Addr]int{}, open: map[*trackedConn]bool{}, held: map[string][]*trackedConn{},
		marked: map[[2]string]store.Revocation{}, lines: map[string]*lineLimit{}}
	return l
}

func (l *Listener) Addr() net.Addr { return l.inner.Addr() }

// Accept returns a connection whose handshake is done, or net.ErrClosed
// once the listener is closed. The first call starts accepting from inner.
func (l *Listener) Accept() (net.Conn, error) {
	if l.Map != nil && l.Caller == nil {
		return nil, ErrUnwired
	}
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
			l.say("accept", "broker: accept failed: %v; retrying in %s", err, delay)
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
		l.say("source_cap", "broker: reset a connection from %s: it holds %d connections not yet "+
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
		// The handshake's VerifyConnection read the certificate a moment ago;
		// this reads the same answer, which a clock step alone could change.
		cc, err := l.callerOf(&cs)
		principal, legacy, cred := cc.Principal, cc.Legacy, cc.Cred
		if errors.Is(err, ErrWorkloadUnmapped) {
			// Answered over HTTP and recorded, never a TLS alert the
			// workload's client cannot read (decision 40 ruling 3).
			l.m.BrokerConnectionEvents.WithLabelValues("identity_refused").Inc()
			l.say("identity_unmapped", "broker: answering a connection from %s identity_unmapped and closing it "+
				"before it bound: %s", c.src, printsafe.Line(err.Error(), 300))
			l.answerRefused(tc, http.StatusUnauthorized, api.Error{Error: string(decision.IdentityUnmapped),
				Detail: err.Error()}, 0, "", cred, decision.IdentityUnmapped)
			return
		}
		if err != nil {
			l.refuse(c, tc, "identity_refused", err)
			return
		}
		// A workload is never mapped: its principal is its SPIFFE ID
		// (decision 40 ruling 5). Nor is a certificate the broker issued:
		// its principal is its sign-in's (decision 43 ruling 10).
		mapped := l.Map != nil && cc.Domain != DomainMachines && cc.Issued == nil
		certKey := store.CertKey(cred.Issuer, cred.Serial)
		// The status is asked first, and bind decides under one lock: a
		// mark, then the status's refusal, then the hold. A mark lifted while
		// the status was asked leaves no connection held unchecked, and a
		// mark in force is answered credential_revoked, which a CA outage
		// must not turn into a 503 the agent keeps its session on.
		var ref *BindRefusal
		if l.Status != nil {
			ref = l.Status(cs, cmp.Or(principal, legacy), cred)
		}
		if mapped {
			// The marks the certificate itself answers to (its key, and the
			// principal its email SAN gave before a directory: pre-flight
			// I-16) are decided before the directory is asked, so a revoked
			// certificate is answered credential_revoked and never a
			// directory_unavailable the agent keeps its session on
			// (pre-flight I-4; the invariant above).
			if rv := l.markedOf(certKey, legacy); rv != nil {
				if ref != nil && ref.queue != nil {
					ref.queue()
				}
				l.m.BrokerConnectionEvents.WithLabelValues("revoked_refused").Inc()
				l.answerRefused(tc, http.StatusUnauthorized, revokedError(*rv), 0, legacy, cred,
					decision.CredentialRevoked)
				return
			}
			if ref == nil {
				timeout := cmp.Or(l.lim.MapTimeout, l.lim.HandshakeTimeout)
				mctx, cancel := context.WithTimeout(context.Background(), timeout)
				a, mref := l.Map(mctx, cs, cred)
				cancel()
				if mref != nil {
					l.m.BrokerConnectionEvents.WithLabelValues("identity_refused").Inc()
					l.say("identity_"+mref.Error, "broker: answering a connection from %s %s and closing it "+
						"before it bound", c.src, mref.Error)
					l.answerRefused(tc, mref.Status, api.Error{Error: mref.Error, Detail: mref.Detail},
						mref.RetryAfter, "", cred, mref.Reason)
					return
				}
				principal, c.mapped = a.Principal, &a
			}
		}
		rv, ok := l.bind(c, principal, legacy, certKey, ref != nil)
		// Bind has chosen the answer, so the revocation the refusal carries
		// is queued now and its mark cannot change it (BindStatus); every
		// branch queues it, as the status named the certificate whatever
		// this connection is answered.
		if ref != nil && ref.queue != nil {
			ref.queue()
		}
		switch {
		case !ok:
			_ = tc.Close()
			return
		case rv != nil:
			l.answerRefused(tc, http.StatusUnauthorized, revokedError(*rv), 0, principal, cred,
				decision.CredentialRevoked)
			return
		case ref != nil:
			// A CA outage is not a revocation on the dashboard (re-check R6).
			event := "revoked_refused"
			if ref.RetryAfter > 0 {
				event = "status_unavailable_refused"
			}
			l.m.BrokerConnectionEvents.WithLabelValues(event).Inc()
			l.say(event, "broker: answering a connection from %s %s and closing it before it "+
				"bound: %s", c.src, ref.Error, printsafe.Line(ref.Detail, 300))
			l.answerRefused(tc, ref.Status, api.Error{Error: ref.Error, Detail: ref.Detail}, ref.RetryAfter,
				principal, cred, ref.Reason)
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

// callerOf is Caller's reading of cs, or, with none (and so no Map:
// Accept refuses that), the reading before plan 8: Identity.
func (l *Listener) callerOf(cs *tls.ConnectionState) (CertCaller, error) {
	if l.Caller != nil {
		return l.Caller(cs, l.now())
	}
	p, cred, err := Identity(cs, l.now())
	return CertCaller{Domain: DomainHumans, Principal: p, Cred: cred}, err
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
	// Said before counted: a reader that sees the count sees the line
	// said or held back (fixA N1).
	l.say("handshake_"+reason, "broker: TLS handshake from %s failed (%s): %s", c.src, reason,
		printsafe.Line(err.Error(), 300))
	l.m.BrokerHandshakeFailures.WithLabelValues(reason).Inc()
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
// reports false when c was closed under it, and the mark when one names c's
// principal or certificate: c is then left charged to its source, never
// held, for answerRefused to answer and close. refused (Status refused c)
// leaves c the same way once no mark names it, and bind returns nil, true.
func (l *Listener) bind(c *trackedConn, principal, legacy, certKey string, refused bool) (*store.Revocation, bool) {
	l.mu.Lock()
	if c.gone {
		l.mu.Unlock()
		return nil, false
	}
	keys := [][2]string{{store.RevocationPrincipal, principal}, {store.RevocationCert, certKey}}
	if legacy != "" {
		keys = append(keys, [2]string{store.RevocationPrincipal, legacy})
	}
	for _, k := range keys {
		rv, marked := l.marked[k]
		if !marked {
			continue
		}
		// A revoked principal or certificate is refused here, from the
		// broker's in-memory copy of the marks (Revoked): no store read at
		// the handshake (spec §13 decision 32), and a revoked certificate
		// never gets to close its owner's connections (pre-flight I3). It
		// stays pending, so a source's flood of them meets
		// MaxPendingPerSource, and forget, at its Close, gives back only
		// that.
		l.mu.Unlock()
		l.m.BrokerConnectionEvents.WithLabelValues("revoked_refused").Inc()
		l.say("revoked_refused", "broker: answering a connection from %s credential_revoked and "+
			"closing it as it bound: %s or its certificate is revoked", c.src, principal)
		return &rv, true
	}
	if refused {
		l.mu.Unlock()
		return nil, true
	}
	l.unpendLocked(c.src)
	c.principal, c.certKey, c.legacy = principal, certKey, legacy
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
		l.say("principal_cap", "broker: %s opened more than %d held connections "+
			"(broker.max_conns_per_principal); its oldest, from %s and open since %s, is closed", principal,
			l.lim.MaxPerPrincipal, evicted.src, evicted.acceptedAt.UTC().Format(time.RFC3339))
		_ = evicted.Close()
	}
	l.gauge()
	return nil, true
}

// markedOf is the mark naming the certificate's key, else the principal its
// email SAN gave before a directory (legacy, when non-empty), or nil: the
// marks a certificate answers to before any directory is asked.
func (l *Listener) markedOf(certKey, legacy string) *store.Revocation {
	l.mu.Lock()
	defer l.mu.Unlock()
	keys := [][2]string{{store.RevocationCert, certKey}}
	if legacy != "" {
		keys = append(keys, [2]string{store.RevocationPrincipal, legacy})
	}
	for _, k := range keys {
		if rv, ok := l.marked[k]; ok {
			return &rv
		}
	}
	return nil
}

// answerRefused reads one request from a connection refused as it bound,
// its line and headers bounded by revokedRequestMax and all of it by
// revokedAnswerTimeout, answers it status and body — the 401
// credential_revoked a mint under a mark is answered, or a status
// refusal's, with Retry-After when retryAfter is set — records it (Refused,
// with reason), and closes it. The agent ends its session on a 401 (spec
// §5.1.4), where a bare close reads as a broker that restarted, and keeps it
// on a 503. The request reaches no handler and no store, and is never
// logged; a connection that sends none is closed unanswered and unrecorded.
func (l *Listener) answerRefused(tc *tls.Conn, status int, body api.Error, retryAfter int, principal string,
	cred store.Credential, reason decision.Reason) {
	defer tc.Close()
	_ = tc.SetDeadline(time.Now().Add(revokedAnswerTimeout))
	lr := &io.LimitedReader{R: tc, N: revokedRequestMax}
	req, err := http.ReadRequest(bufio.NewReader(lr))
	if err != nil {
		return
	}
	// Its body is drained to its end when that is under revokedBodyMax, so
	// the close is not a reset the answer is lost to; past it, the answer
	// goes anyway, and the rest is drained after it.
	lr.N += revokedBodyMax
	_, err = io.Copy(io.Discard, req.Body)
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return
	}
	if l.Refused != nil {
		l.Refused(req.URL.Path, principal, cred, reason)
	}
	var buf bytes.Buffer
	_ = json.NewEncoder(&buf).Encode(body)
	header := http.Header{"Content-Type": {"application/json"}}
	if retryAfter > 0 {
		header.Set("Retry-After", strconv.Itoa(retryAfter))
	}
	resp := &http.Response{StatusCode: status, ProtoMajor: 1, ProtoMinor: 1, Request: req,
		Header: header, ContentLength: int64(buf.Len()), Body: io.NopCloser(&buf), Close: true}
	if werr := resp.Write(tc); werr == nil && err != nil {
		_ = tc.CloseWrite()
		_, _ = io.Copy(io.Discard, io.LimitReader(tc, revokedDrainMax))
	}
}

// CloseHeld closes every held connection match names, and returns how many
// (spec §5.1.4: a revocation reaches the held connection).
func (l *Listener) CloseHeld(match func(principal, certKey string) bool) int {
	l.mu.Lock()
	var hit []*trackedConn
	for _, conns := range l.held {
		for _, c := range conns {
			// A mark on the principal the certificate had before a directory
			// closes it too: bind refuses on it (pre-flight I-16).
			if match(c.principal, c.certKey) || (c.legacy != "" && match(c.legacy, "")) {
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

// HoldsCert reports whether a held connection was made with certKey.
func (l *Listener) HoldsCert(certKey string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, conns := range l.held {
		for _, c := range conns {
			if c.certKey == certKey {
				return true
			}
		}
	}
	return false
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
