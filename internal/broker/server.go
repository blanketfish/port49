package broker

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
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

// Server serves the broker over mutual TLS on addr; call
// ServeTLS(Limit(ln, MaxConns), "", "").
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
// auth_time at accept, before its handshake (Decided 2; pre-flight F3).
//
// Session tickets are off: a resumed TLS 1.3 session proves nothing about the
// key, and every connection must be a handshake that uses it — which is what
// makes a reconnect one more use of the key, and on plan 9's hardware key one
// more touch (design §7; pre-flight F2). HTTP/1.1 only, enforced by a non-nil
// TLSNextProto, so a connection is one ordered stream of requests (F13).
//
// The handshake verifies validity against the broker's own clock, the one
// Identity checks per request against, so the two never disagree.
func (b *Broker) Server(addr string, cert tls.Certificate, anchor *x509.CertPool) *http.Server {
	return &http.Server{
		Addr:    addr,
		Handler: b.Handler(),
		TLSConfig: &tls.Config{
			MinVersion:             tls.VersionTLS13,
			Certificates:           []tls.Certificate{cert},
			ClientCAs:              anchor,
			ClientAuth:             tls.VerifyClientCertIfGiven,
			NextProtos:             []string{"http/1.1"},
			SessionTicketsDisabled: true,
			Time:                   b.Now,
		},
		TLSNextProto:      map[string]func(*http.Server, *tls.Conn, http.Handler){},
		ConnContext:       func(ctx context.Context, _ net.Conn) context.Context { return withHeldConn(ctx, b.Now()) },
		ConnState:         closeIdleWithoutCertificate,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       b.MaxSessionAge,
	}
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
func Limit(ln net.Listener, n int) net.Listener {
	return &limited{Listener: ln, slots: make(chan struct{}, n)}
}

type limited struct {
	net.Listener
	slots chan struct{}
}

func (l *limited) Accept() (net.Conn, error) {
	l.slots <- struct{}{}
	c, err := l.Listener.Accept()
	if err != nil {
		<-l.slots
		return nil, err
	}
	return &limitedConn{Conn: c, free: func() { <-l.slots }}, nil
}

type limitedConn struct {
	net.Conn
	once sync.Once
	free func()
}

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
		return tls.Certificate{}, nil, fmt.Errorf("broker: client_ca_file %s holds %d certificates; the vertical "+
			"slice trusts exactly one anchor (design §19 step 3)", anchorFile, len(anchors))
	}
	pool := x509.NewCertPool()
	pool.AddCert(anchors[0])
	return cert, pool, nil
}
