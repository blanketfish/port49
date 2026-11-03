package broker

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/blanketfish/port49/internal/fence"
	"github.com/blanketfish/port49/internal/keyfile"
)

// MaxConns caps the broker's open connections. Every agent holds one for its
// session, so this is the operators logged in at once, with room; the cap
// keeps a flood of connections from taking the file descriptors port49d
// answers device AAA with (pre-flight F1).
const MaxConns = 256

// Server serves the broker over mutual TLS on addr; serve it with
// srv.Serve(NewListener(Limit(ln, MaxConns), srv.TLSConfig, limits, …)), which
// completes each handshake itself and bounds each source and each principal
// (spec §13 decision 32). ServeTLS still works and bounds neither.
//
// The client certificate is requested and, when given, verified against the
// one anchor at the handshake (VerifyClientCertIfGiven): /v1/config is
// unauthenticated by necessity (design §17), and an untrusted certificate
// fails `port49 login` at once instead of at the first mint. /v1/tokens then
// checks the verified certificate again on every request (Identity).
//
// The agent's session IS the connection (design §7; spec §13, decision 17),
// so the server does not close an authenticated one for being idle before
// max_session_age: an operator who mints at 09:00 and again at 15:00 is on one
// handshake. A connection with no certificate is closed as soon as it goes
// idle (closeIdleWithoutCertificate). ConnContext stamps each connection's
// auth_time at accept, before its handshake (Decided 2; pre-flight F3): the
// Listener's accept time, read through the connection (acceptedAt).
//
// Session tickets are off: a resumed TLS 1.3 session proves nothing about the
// key, and every connection must be a handshake that uses it — which is what
// makes a reconnect one more use of the key, and on plan 9's hardware key one
// more touch (design §7; pre-flight F2). HTTP/1.1 only, enforced by a non-nil
// TLSNextProto, so a connection is one ordered stream of requests (F13).
//
// The handshake verifies validity against the broker's own clock, the one
// Identity checks per request against, so the two never disagree. A
// certificate is also put through Identity at the handshake
// (VerifyConnection): one the anchor verifies but that maps to no principal
// (no email SAN, or two) fails `port49 login` with a bad_certificate alert
// and a line in ErrorLog saying why, rather than logging in and failing every
// mint after (final review, Minor 1).
//
// ReadTimeout bounds reading one request, headers and body: a connection
// stalled mid-request never goes idle, so without it headers promising a body
// that never comes would hold a slot of the cap for good (pre-flight F1). The
// time between requests is IdleTimeout's, so a held connection is unaffected.
//
// Without a workload verifier, anchor must hold the one trust anchor. Server
// refuses a nil pool, which crypto/tls would take as the system roots — every
// public CA an anchor for the email mapping — and an empty one, which trusts
// no one. It returns the refusal rather than panicking (plan 4b): port49d now
// runs code after start that swaps policy under a live daemon, and nothing on
// a path that can run with device AAA already serving may end the process.
//
// An OIDC-only broker (NoX509, plan 7h) with no workload verifier is served
// with a nil anchor and requests no certificate, unless it issues certificates
// (plan 9b), when it requests one against its own issuing CAs.
//
// With b.Workload set (plan 8), a nil anchor is accepted: the pool is the
// workload anchor alone, and certificates are still requested
// (VerifyClientCertIfGiven). Given a human anchor, the workload anchor is
// added beside it, and the anchor a chain ends at names its domain.
func (b *Broker) Server(addr string, cert tls.Certificate, anchor *x509.CertPool) (*http.Server, error) {
	clientAuth := tls.VerifyClientCertIfGiven
	var pool *x509.CertPool
	switch {
	case anchor != nil && b.NoX509:
		return nil, errors.New("broker: an OIDC-only broker (NoX509) takes no anchor: it would still verify " +
			"client certificates")
	case anchor == nil && b.Workload != nil:
		// People by OIDC, workloads by certificate (plan 8): the one anchor
		// is the workloads'.
		pool = x509.NewCertPool()
	case anchor == nil && b.NoX509 && (b.Identity != nil || b.PasswordSignIn != nil) && b.Issuer != nil:
		// An OIDC-only or directory_password-only broker that issues (plan 9b;
		// decision 43 ruling 10; decision 47): its one anchor is its own
		// issuing CA's, added below.
		pool = x509.NewCertPool()
	case anchor == nil && b.NoX509 && b.Identity != nil:
		// An OIDC-only broker (Ruling 1): no certificate is requested, and
		// every caller authenticates by bearer.
		clientAuth = tls.NoClientCert
	case anchor == nil || anchor.Equal(x509.NewCertPool()):
		return nil, errors.New("broker: the broker trusts exactly one anchor; a nil pool would mean the system " +
			"roots, and an empty one trusts no one (a broker with no x509 verifier sets NoX509 and an OIDC or " +
			"directory_password verifier)")
	default:
		pool = anchor.Clone()
	}
	// One pool of both anchors (decision 40 ruling 2): the handshake verifies
	// against either, and the anchor a chain ends at is its domain
	// (CertCallerOf).
	if b.Workload != nil {
		pool.AddCert(b.Workload.Anchor)
	}
	// A broker that issues trusts its own CAs, for people alone (decision 43
	// ruling 10): the chain's anchor says which it is (CertCallerOf).
	if b.Issuer != nil && pool != nil {
		for _, c := range b.Issuer.Trusted {
			pool.AddCert(c)
		}
	}
	return &http.Server{
		Addr:    addr,
		Handler: b.Handler(),
		TLSConfig: &tls.Config{
			MinVersion:             tls.VersionTLS13,
			Certificates:           []tls.Certificate{cert},
			ClientCAs:              pool,
			ClientAuth:             clientAuth,
			NextProtos:             []string{"http/1.1"},
			SessionTicketsDisabled: true,
			Time:                   b.Now,
			VerifyConnection: func(cs tls.ConnectionState) error {
				if len(cs.PeerCertificates) == 0 {
					return nil // /v1/config only; /v1/tokens refuses it
				}
				// A chain is checked here; a workload naming no principal is
				// answered 401 identity_unmapped at bind, never as a TLS alert
				// the client cannot read (decision 40 ruling 3); a person
				// under a directory is mapped at bind.
				_, err := b.CertCallerOf(&cs, b.Now())
				if errors.Is(err, ErrWorkloadUnmapped) {
					return nil
				}
				return err
			},
		},
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return withHeldConn(ctx, acceptedAt(c, b.Now), mappedOf(c))
		},
		ConnState: func(c net.Conn, s http.ConnState) {
			connState(c, s)
			closeIdleWithoutCertificate(c, s)
			b.connClosed(c, s)
		},
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       readTimeout,
		IdleTimeout:       b.MaxSessionAge,
	}, nil
}

// closeIdleWithoutCertificate closes a connection that presented no client
// certificate once it has answered its request. Such a connection can reach
// /v1/config and nothing else, and held for max_session_age it is a file
// descriptor anyone who can reach the listener can pin (pre-flight F1).
func closeIdleWithoutCertificate(c net.Conn, s http.ConnState) {
	if s != http.StateIdle {
		return
	}
	if tc, ok := c.(*tls.Conn); ok && len(tc.ConnectionState().PeerCertificates) == 0 {
		_ = c.Close()
	}
}

// Limit caps how many connections ln holds open at once: Accept waits for a
// free slot, and a connection's Close gives its slot back. Hand-rolled rather
// than golang.org/x/net/netutil, because the slice takes no new dependencies.
//
// Close wakes an Accept that is waiting for a slot. http.Server's Shutdown
// closes the listener and then waits, ignoring its context, for Serve to
// return; with every slot held by an authenticated connection (held for
// max_session_age), Serve would sit in Accept and port49d would hang on
// SIGTERM with its accounting spool undrained (final review, Important 1).
func Limit(ln net.Listener, n int) net.Listener {
	return &limited{Listener: ln, slots: make(chan struct{}, n), done: make(chan struct{})}
}

type limited struct {
	net.Listener
	slots     chan struct{}
	done      chan struct{}
	closeOnce sync.Once
}

func (l *limited) Accept() (net.Conn, error) {
	select {
	case l.slots <- struct{}{}:
	case <-l.done:
		return nil, net.ErrClosed
	}
	c, err := l.Listener.Accept()
	if err != nil {
		<-l.slots
		return nil, err
	}
	return &limitedConn{Conn: c, free: func() { <-l.slots }}, nil
}

func (l *limited) Close() error {
	l.closeOnce.Do(func() { close(l.done) })
	return l.Listener.Close()
}

type limitedConn struct {
	net.Conn
	once sync.Once
	free func()
}

// NetConn is the connection under the slot, for reset's SetLinger.
func (c *limitedConn) NetConn() net.Conn { return c.Conn }

func (c *limitedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.free)
	return err
}

// LoadTLS reads the broker's server certificate and its one client trust
// anchor (design §19 step 3). The anchor file must hold exactly one
// certificate: one anchor is what pins the issuer of the email mapping
// (Identity), and a bundle would widen it without anyone deciding to.
func LoadTLS(certFile, keyFile, anchorFile string) (tls.Certificate, *x509.CertPool, error) {
	cert, anchor, err := LoadTLSAnchor(certFile, keyFile, anchorFile)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(anchor)
	return cert, pool, nil
}

// LoadTLSAnchor is LoadTLS with the anchor as the certificate it read, for
// a caller that checks other certificates against the very one it trusts
// (port49d's certificate_status issuers) rather than a second read of the
// file.
func LoadTLSAnchor(certFile, keyFile, anchorFile string) (tls.Certificate, *x509.Certificate, error) {
	// The server key is refused if it is a symlink or readable by anyone but
	// its owner (keyfile; pre-flight F14).
	cert, err := keyfile.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("broker: server certificate: %w", err)
	}
	anchor, err := ReadAnchor(anchorFile)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("broker: client_ca_file: %w", err)
	}
	return cert, anchor, nil
}

// ReadAnchor reads a trust anchor file: exactly one certificate, as
// client_ca_file and each trust_anchor_file must hold (design §19 step 3;
// plan 8 for the workload anchor).
func ReadAnchor(path string) (*x509.Certificate, error) {
	raw, err := fence.Read(path, fence.TrustFileMax, "trust anchor")
	if err != nil {
		return nil, err
	}
	var anchors []*x509.Certificate
	for rest := raw; ; {
		var blk *pem.Block
		if blk, rest = pem.Decode(rest); blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		anchors = append(anchors, c)
	}
	if len(anchors) != 1 {
		return nil, fmt.Errorf("%s holds %d certificates; exactly one trust anchor is accepted (design §19 step 3)",
			path, len(anchors))
	}
	return anchors[0], nil
}

// readTimeout is Server's ReadTimeout, swapped in tests. A mint request is a
// few hundred bytes; thirty seconds is generous for one.
var readTimeout = 30 * time.Second

// writeTimeout bounds one response write, swapped in tests. A response is a
// few kilobytes, so this is generous; it exists for a peer that vanished
// mid-answer, whose connection would otherwise count as busy to the principal
// cap until TCP gave up (about 15 minutes), and four of them would refuse
// their owner (decision 32). It is set per response, at its first byte, and
// not as the server's WriteTimeout: that one starts when the request is read
// and would have to outlast the longest handler (a mint's 10 s hold, an
// import's long body read, admin_api.go).
var writeTimeout = 15 * time.Second

// boundWrites gives each response's write a deadline of writeTimeout from
// its first byte, and a later write the same one again. The deadline is per
// Write, so it is the total bound only because every broker response is a
// single Write; a handler that streams in many writes would need a total
// bound of its own. Flush is passed through (answerRefusal flushes its answer
// before the revocation closes the connection) and Unwrap reaches the real
// writer for http.ResponseController; no other optional interface is asserted
// on a broker response writer.
func boundWrites(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(&boundedWriter{ResponseWriter: w, rc: http.NewResponseController(w)}, r)
	})
}

type boundedWriter struct {
	http.ResponseWriter
	rc *http.ResponseController
}

func (b *boundedWriter) bound() { _ = b.rc.SetWriteDeadline(time.Now().Add(writeTimeout)) }

func (b *boundedWriter) WriteHeader(code int) {
	b.bound()
	b.ResponseWriter.WriteHeader(code)
}

func (b *boundedWriter) Write(p []byte) (int, error) {
	b.bound()
	return b.ResponseWriter.Write(p)
}

func (b *boundedWriter) Flush() {
	b.bound()
	_ = b.rc.Flush()
}

func (b *boundedWriter) Unwrap() http.ResponseWriter { return b.ResponseWriter }
