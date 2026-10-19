package devicemock

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"sync"
	"time"
)

type TLSMaterial struct {
	Client     tls.Certificate
	ServerCAs  *x509.CertPool
	ServerIP   string
	ServerName string
}

var goCurves = map[uint16]tls.CurveID{29: tls.X25519, 23: tls.CurveP256, 24: tls.CurveP384, 25: tls.CurveP521}

// SessionConfig is the closest crypto/tls comes to the device: its versions,
// curve order (x448, which the library lacks, is left out), ALPN and client
// chain. Suite order and signature algorithms are the library's; the hello
// probe carries the device's exactly. The server's certificate is checked as
// the device was measured to (server_identity). An IP-literal SNI is never
// sent here (crypto/tls omits it), only by the probe: an engine gap each
// profile that has one lists.
func SessionConfig(s *TLSStimulus, m TLSMaterial) *tls.Config {
	cfg := &tls.Config{Certificates: []tls.Certificate{m.Client}, NextProtos: s.ClientHello.ALPN}
	// The versions the device offers bound the session: extension 43's list,
	// or the legacy version when it sends none (a 1.2-only device). crypto/tls
	// floors at 1.2, so an offer of 1.1 or 1.0 is raised to it.
	versions := s.ClientHello.SupportedVersions
	if len(versions) == 0 {
		versions = []uint16{s.ClientHello.LegacyVersion}
	}
	cfg.MinVersion, cfg.MaxVersion = tls.VersionTLS13, tls.VersionTLS12
	for _, v := range versions {
		v = max(v, tls.VersionTLS12)
		cfg.MinVersion, cfg.MaxVersion = min(cfg.MinVersion, v), max(cfg.MaxVersion, v)
	}
	cfg.MaxVersion = min(cfg.MaxVersion, tls.VersionTLS13)
	for _, g := range s.ClientHello.SupportedGroups {
		if c, ok := goCurves[g]; ok {
			cfg.CurvePreferences = append(cfg.CurvePreferences, c)
		}
	}
	cfg.InsecureSkipVerify = true // replaced by VerifyConnection: the chain always, names as measured
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("devicemock: no server certificate")
		}
		if m.ServerCAs == nil {
			return errors.New("devicemock: no server CAs; refusing to fall back to the system roots")
		}
		opts := x509.VerifyOptions{Roots: m.ServerCAs, Intermediates: x509.NewCertPool()}
		for _, c := range cs.PeerCertificates[1:] {
			opts.Intermediates.AddCert(c)
		}
		switch s.ServerIdentity {
		case "ip":
			opts.DNSName = m.ServerIP // an IP literal matches iPAddress SANs only
		case "dns":
			if m.ServerName == "" {
				return errors.New("devicemock: server_identity dns needs TLSMaterial.ServerName")
			}
			opts.DNSName = m.ServerName
		}
		_, err := cs.PeerCertificates[0].Verify(opts)
		return err
	}
	return cfg
}

type flightConn struct {
	net.Conn
	delay        time.Duration
	sleep        func(time.Duration)
	mu           sync.Mutex
	read, waited bool
}

// DelayFlight delays the first write after the first read by d: in TLS 1.3
// the client's second flight, after port49's server flight. The rest pass.
func DelayFlight(c net.Conn, d time.Duration, sleep func(time.Duration)) net.Conn {
	if sleep == nil {
		sleep = time.Sleep
	}
	return &flightConn{Conn: c, delay: d, sleep: sleep}
}

func (c *flightConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.mu.Lock()
		c.read = true
		c.mu.Unlock()
	}
	return n, err
}

func (c *flightConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	wait := c.read && !c.waited
	if wait {
		c.waited = true
	}
	c.mu.Unlock()
	if wait {
		c.sleep(c.delay)
	}
	return c.Conn.Write(b)
}
