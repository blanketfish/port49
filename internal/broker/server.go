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
	"os"
	"sync"
	"time"

	"github.com/rhwendt/port49/internal/keyfile"
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
// anchor must hold the one trust anchor. Server refuses a nil pool, which
// crypto/tls would take as the system roots — every public CA an anchor for
// the email mapping — and an empty one, which trusts no one. It returns the
// refusal rather than panicking (plan 4b): port49d now runs code after start
// that swaps policy under a live daemon, and nothing on a path that can run
// with device AAA already serving may end the process.
//
// An OIDC-only broker (NoX509, plan 7h) is served with a nil anchor and
// requests no certificate.
func (b *Broker) Server(addr string, cert tls.Certificate, anchor *x509.CertPool) (*http.Server, error) {
	clientAuth := tls.VerifyClientCertIfGiven
	switch {
	case anchor != nil && b.NoX509:
		return nil, errors.New("broker: an OIDC-only broker (NoX509) takes no anchor: it would still verify " +
			"client certificates")
	case anchor == nil && b.NoX509 && b.Identity != nil:
		// An OIDC-only broker (Ruling 1): no certificate is requested, and
		// every caller authenticates by bearer.
		clientAuth = tls.NoClientCert
	case anchor == nil || anchor.Equal(x509.NewCertPool()):
		return nil, errors.New("broker: the broker trusts exactly one anchor; a nil pool would mean the system " +
			"roots, and an empty one trusts no one (an OIDC-only broker sets NoX509 and Identity)")
	}
	return &http.Server{
		Addr:    addr,
		Handler: b.Handler(),
		TLSConfig: &tls.Config{
			MinVersion:             tls.VersionTLS13,
			Certificates:           []tls.Certificate{cert},
			ClientCAs:              anchor,
			ClientAuth:             clientAuth,
			NextProtos:             []string{"http/1.1"},
			SessionTicketsDisabled: true,
			Time:                   b.Now,
			VerifyConnection: func(cs tls.ConnectionState) error {
				if len(cs.PeerCertificates) == 0 {
					return nil // /v1/config only; /v1/tokens refuses it
				}
				if b.Directory != nil {
					// The chain is checked here, the mapping at bind: a leaf
					// with no email SAN is a person a directory may know.
					_, _, err := CertIdentity(&cs, b.Now())
					return err
				}
				_, _, err := Identity(&cs, b.Now())
				return err
			},
		},
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return withHeldConn(ctx, acceptedAt(c, b.Now), mappedOf(c))
		},
		ConnState:         closeIdleWithoutCertificate,
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
	raw, err := os.ReadFile(anchorFile)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("broker: client_ca_file: %w", err)
	}
	var anchors []*x509.Certificate
	rest := raw
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return tls.Certificate{}, nil, fmt.Errorf("broker: client_ca_file %s: %w", anchorFile, err)
		}
		anchors = append(anchors, c)
	}
	if len(anchors) != 1 {
		return tls.Certificate{}, nil, fmt.Errorf("broker: client_ca_file %s holds %d certificates; exactly one "+
			"trust anchor is accepted (design §19 step 3)", anchorFile, len(anchors))
	}
	return cert, anchors[0], nil
}

// readTimeout is Server's ReadTimeout, swapped in tests. A mint request is a
// few hundred bytes; thirty seconds is generous for one.
var readTimeout = 30 * time.Second
