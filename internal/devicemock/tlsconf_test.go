package devicemock

import (
	"crypto/tls"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/testpki"
)

func TestDelayFlightDelaysOnlyTheFirstWriteAfterARead(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	var slept atomic.Int64
	c := DelayFlight(a, 500*time.Millisecond, func(d time.Duration) { slept.Add(int64(d)) })
	go func() {
		buf := make([]byte, 8)
		for {
			if _, err := b.Read(buf); err != nil {
				return
			}
		}
	}()
	c.Write([]byte("hello")) // the ClientHello: no delay
	go b.Write([]byte("x"))
	c.Read(make([]byte, 1)) // the server's flight
	c.Write([]byte("fin"))  // the device's flight: delayed
	c.Write([]byte("data")) // later writes: no delay
	if got := time.Duration(slept.Load()); got != 500*time.Millisecond {
		t.Fatalf("slept %v in all, want one 500ms", got)
	}
}

// handshake runs SessionConfig's client against a Go server with cert and
// returns the client's error.
func handshake(t *testing.T, s *TLSStimulus, m TLSMaterial, server tls.Certificate) error {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{server}, MinVersion: tls.VersionTLS12,
		ClientAuth: tls.RequireAnyClientCert})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			c.(*tls.Conn).Handshake()
			c.Close()
		}
	}()
	c, err := tls.Dial("tcp", ln.Addr().String(), SessionConfig(s, m))
	if err == nil {
		c.Close()
	}
	return err
}

func material(t *testing.T, ca *testpki.CA, ip string) TLSMaterial {
	t.Helper()
	now := time.Now()
	client, err := ca.Issue(testpki.Leaf{CommonName: "device", Client: true, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	return TLSMaterial{Client: client, ServerCAs: ca.Pool(), ServerIP: ip}
}

func TestSessionConfigChecksTheServerChainAndTheNameAsMeasured(t *testing.T) {
	server, ca := selfSignedWithCA(t)
	cases := []struct {
		name     string
		identity string
		ip       string
		ca       *testpki.CA
		wantErr  bool
	}{
		{"chain_only ignores the name", "chain_only", "10.9.9.9", ca, false},
		{"ip passes for the address the certificate names", "ip", "127.0.0.1", ca, false},
		{"ip fails for another address", "ip", "10.9.9.9", ca, true},
	}
	for _, tc := range cases {
		s := &TLSStimulus{ServerIdentity: tc.identity, ClientHello: nxosHello()}
		if err := handshake(t, s, material(t, tc.ca, tc.ip), server); (err != nil) != tc.wantErr {
			t.Errorf("%s: err %v", tc.name, err)
		}
	}
	// A certificate from a CA the device was not given fails whatever the identity.
	other, _ := selfSignedWithCA(t)
	s := &TLSStimulus{ServerIdentity: "chain_only", ClientHello: nxosHello()}
	if err := handshake(t, s, material(t, ca, "127.0.0.1"), other); err == nil {
		t.Error("a server certificate from an unknown CA was accepted")
	}
}

func TestSessionConfigFollowsTheDevicesVersionsAndCurves(t *testing.T) {
	s := &TLSStimulus{ClientHello: nxosHello()}
	s.ClientHello.ALPN = []string{"h2"}
	cfg := SessionConfig(s, TLSMaterial{})
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("a device that offers only 1.3 got min version %x", cfg.MinVersion)
	}
	// 29 23 30 25 24: x448 (30) has no crypto/tls id and is left out.
	want := []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP521, tls.CurveP384}
	if len(cfg.CurvePreferences) != len(want) {
		t.Fatalf("%v", cfg.CurvePreferences)
	}
	for i := range want {
		if cfg.CurvePreferences[i] != want[i] {
			t.Fatalf("%v", cfg.CurvePreferences)
		}
	}
	if len(cfg.NextProtos) != 1 || cfg.NextProtos[0] != "h2" {
		t.Errorf("%v", cfg.NextProtos)
	}
	s.ClientHello.SupportedVersions = []uint16{772, 771}
	if SessionConfig(s, TLSMaterial{}).MinVersion != tls.VersionTLS12 {
		t.Error("a device that offers 1.2 too must be allowed it")
	}
}
