package server

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/devicecert"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/memory"
	"github.com/rhwendt/port49/internal/tacacs/wire"
	"github.com/rhwendt/port49/internal/testpki"
)

var loopback = netip.MustParseAddr("127.0.0.1")

// tlsFixture is a server on the RFC 9887 listener: leaf-01 at 127.0.0.1
// with transport tls, a device CA, a server certificate for
// tacacs.example.net, and a status the test sets. admit is server_test.go's
// swapAdmitter (:1898), swapped as a reload does.
type tlsFixture struct {
	ts          *testServer
	ca          *testpki.CA
	server      tls.Certificate
	status      atomic.Int32 // a devicecert.Status
	statusCalls atomic.Int32 // how often either status question was asked
	allow       bool
	mat         atomic.Pointer[Material]
	admit       *swapAdmitter
}

var leaf01TLS = admission.Device{Name: "leaf-01", Platform: "arista_eos", Transport: admission.TransportTLS,
	Addresses: []netip.Addr{loopback}}

func seededStore(t *testing.T) store.Store {
	t.Helper()
	st := memory.New(time.Now)
	if _, err := st.PutToken(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"},
		store.Token{ID: "e2e", Secret: []byte("p49_e2e"), Kind: store.KindLogin, Principal: "user:alice@example.com",
			ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	return st
}

func newTLSFixture(t *testing.T, log *syncBuffer, adjust func(*Deps, *tlsFixture)) *tlsFixture {
	t.Helper()
	now := time.Now()
	ca, err := testpki.NewCA("Device CA", now.Add(-time.Hour), now.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	srv, err := ca.Issue(testpki.Leaf{CommonName: "port49", DNSNames: []string{"tacacs.example.net"},
		IPs: testpki.Loopback(), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	f := &tlsFixture{ca: ca, server: srv, admit: &swapAdmitter{}}
	f.admit.swap(t, admission.Resolved{Device: leaf01TLS})
	f.mat.Store(f.material(ca, true))
	f.ts = newTestServerWith(t, log, seededStore(t), nil, func(d *Deps) {
		d.Admission = f.admit
		d.TLS = &TLS{Material: f.mat.Load, ServerNames: []string{"tacacs.example.net"}, HandshakeTimeout: 2 * time.Second}
		if adjust != nil {
			adjust(d, f)
		}
	})
	return f
}

// material is a load of the listener's files with anchor as the device CA;
// ticketsOff is session_ticket_lifetime: 0s. Both status questions answer
// f.status and count in f.statusCalls.
func (f *tlsFixture) material(anchor *testpki.CA, ticketsOff bool) *Material {
	status := func() (devicecert.Status, string) {
		f.statusCalls.Add(1)
		return devicecert.Status(f.status.Load()), "test status source"
	}
	return &Material{
		Config: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{f.server},
			ClientAuth: tls.RequireAnyClientCert, SessionTicketsDisabled: ticketsOff},
		Verifier: &devicecert.Verifier{Anchors: anchor.Pool(), Rule: devicecert.Rule{DNSName: true, IPAddress: true},
			AllowUnknown: f.allow, Now: time.Now,
			Status:       func(context.Context, []*x509.Certificate) (devicecert.Status, string) { return status() },
			CachedStatus: func([]*x509.Certificate) (devicecert.Status, string) { return status() }}}
}

// deviceCert is a client certificate from ca: by default leaf-01's, valid
// for an hour.
func (f *tlsFixture) deviceCert(t *testing.T, ca *testpki.CA, l testpki.Leaf) tls.Certificate {
	t.Helper()
	if ca == nil {
		ca = f.ca
	}
	if l.DNSNames == nil && l.IPs == nil {
		l.DNSNames = []string{"leaf-01"}
	}
	if l.NotAfter.IsZero() {
		l.NotBefore, l.NotAfter = time.Now().Add(-time.Minute), time.Now().Add(time.Hour)
	}
	if !l.NoExtKeyUsage {
		l.Client = true
	}
	c, err := ca.Issue(l)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// tlsClient is a device on the RFC 9887 listener: no obfuscation, and the
// flags each send names.
type tlsClient struct {
	conn *tls.Conn
	sid  uint32
	seq  uint8
}

// dialTLS opens a TLS connection as a device presenting cert (nil: none).
// In TLS 1.3 the server's verdict on the client certificate arrives after
// the client's Finished, so a refusal shows at the first read.
func (f *tlsFixture) dialTLS(t *testing.T, cert *tls.Certificate, adjust func(*tls.Config)) (*tlsClient, error) {
	t.Helper()
	cfg := &tls.Config{RootCAs: f.ca.Pool(), ServerName: "tacacs.example.net", MinVersion: tls.VersionTLS12}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	if adjust != nil {
		adjust(cfg)
	}
	raw, err := net.Dial("tcp", f.ts.addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { raw.Close() })
	tc := tls.Client(raw, cfg)
	tc.SetDeadline(time.Now().Add(5 * time.Second))
	if err := tc.Handshake(); err != nil {
		return nil, err
	}
	return &tlsClient{conn: tc, sid: 0xabcd1234, seq: 1}, nil
}

func (c *tlsClient) send(typ wire.Type, body []byte, flags uint8) error {
	h := wire.Header{MajorVersion: 0xc, Type: typ, SeqNo: c.seq, Flags: flags, SessionID: c.sid, Length: uint32(len(body))}
	c.seq += 2
	_, err := c.conn.Write(append(h.Encode(), body...))
	return err
}

func (c *tlsClient) recv() (wire.Header, []byte, error) {
	hb := make([]byte, wire.HeaderLen)
	if _, err := io.ReadFull(c.conn, hb); err != nil {
		return wire.Header{}, nil, err
	}
	h, _ := wire.DecodeHeader(hb)
	body := make([]byte, h.Length)
	_, err := io.ReadFull(c.conn, body)
	return h, body, err
}

var aliceLogin = wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
	Service: wire.AuthenServiceLogin, User: []byte("alice"), Data: []byte("p49_e2e")}.Encode()

// login dials as cert and logs alice in; any refusal is the error.
func (f *tlsFixture) login(t *testing.T, cert *tls.Certificate, adjust func(*tls.Config)) (wire.Header, wire.AuthenReply, error) {
	t.Helper()
	c, err := f.dialTLS(t, cert, adjust)
	if err != nil {
		return wire.Header{}, wire.AuthenReply{}, err
	}
	if err := c.send(wire.TypeAuthen, aliceLogin, wire.FlagUnencrypted); err != nil {
		return wire.Header{}, wire.AuthenReply{}, err
	}
	h, body, err := c.recv()
	if err != nil {
		return h, wire.AuthenReply{}, err
	}
	r, err := wire.DecodeAuthenReply(body)
	return h, r, err
}

func TestTLSLoginPassesAndRecordsTheCertificate(t *testing.T) {
	log := &syncBuffer{}
	f := newTLSFixture(t, log, nil)
	cert := f.deviceCert(t, nil, testpki.Leaf{})
	h, r, err := f.login(t, &cert, nil)
	if err != nil || r.Status != wire.AuthenStatusPass {
		t.Fatalf("login: %v status %d; log %s", err, r.Status, log.String())
	}
	if h.Flags&wire.FlagUnencrypted == 0 {
		t.Fatalf("a reply over TLS without the unencrypted flag (RFC 9887 §4): %#x", h.Flags)
	}
	if !waitFor(t, func() bool { return log.contains(`"event":"redeem"`) }) {
		t.Fatalf("no redeem: %s", log.String())
	}
	for _, rec := range log.records(t) {
		if rec["event"] != "redeem" {
			continue
		}
		dev, _ := rec["device"].(map[string]any)
		if dev["transport"] != "tls" || dev["cert_sha256"] != devicecert.Fingerprint(cert.Leaf) || dev["key_ref"] != nil {
			t.Fatalf("redeem device block: %v", dev)
		}
	}
	if n := testutil.ToFloat64(f.ts.metrics.TLSHandshakes.WithLabelValues("ok")); n != 1 {
		t.Fatalf("handshakes{ok} = %v", n)
	}
}

func TestTLSSingleConnectCarriesTwoExchanges(t *testing.T) {
	log := &syncBuffer{}
	f := newTLSFixture(t, log, nil)
	cert := f.deviceCert(t, nil, testpki.Leaf{})
	c, err := f.dialTLS(t, &cert, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		c.seq, c.sid = 1, uint32(0x100+i)
		if err := c.send(wire.TypeAuthen, aliceLogin, wire.FlagUnencrypted|wire.FlagSingleConnect); err != nil {
			t.Fatal(err)
		}
		h, _, err := c.recv()
		if err != nil {
			t.Fatalf("exchange %d: %v", i, err)
		}
		if h.Flags != wire.FlagUnencrypted|wire.FlagSingleConnect {
			t.Fatalf("exchange %d: reply flags %#x", i, h.Flags)
		}
	}
}

// refusedAtHandshake dials and logs in; it wants the attempt to fail, the
// record to say outcome, and the source struck or declined as struck says.
func refusedAtHandshake(t *testing.T, f *tlsFixture, log *syncBuffer, cert *tls.Certificate, adjust func(*tls.Config),
	outcome devicecert.Outcome, struck bool) {
	t.Helper()
	if _, _, err := f.login(t, cert, adjust); err == nil {
		t.Fatalf("%s: the login was answered", outcome)
	}
	if !waitFor(t, func() bool { return log.contains(`"tls_outcome":"` + string(outcome) + `"`) }) {
		t.Fatalf("%s: no record: %s", outcome, log.String())
	}
	if !log.contains(`"diagnosis":"tls_refused"`) || !log.contains(`"transport":"tls"`) {
		t.Fatalf("%s: record: %s", outcome, log.String())
	}
	if n := testutil.ToFloat64(f.ts.metrics.TLSHandshakes.WithLabelValues(string(outcome))); n != 1 {
		t.Fatalf("%s: handshakes = %v", outcome, n)
	}
	if got := f.ts.limits.Holding(loopback); got != struck {
		t.Fatalf("%s: struck %v, want %v", outcome, got, struck)
	}
	if !struck && !f.ts.limits.Declined(loopback) {
		t.Fatalf("%s: not struck, so declined", outcome)
	}
}

func TestTLSRefusesAtTheHandshake(t *testing.T) {
	otherCA, err := testpki.NewCA("Other", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		cert    func(*tlsFixture) *tls.Certificate
		adjust  func(*tls.Config)
		outcome devicecert.Outcome
	}{
		"TLS 1.2 only": {func(f *tlsFixture) *tls.Certificate { c := f.deviceCert(t, nil, testpki.Leaf{}); return &c },
			func(c *tls.Config) { c.MaxVersion = tls.VersionTLS12 }, devicecert.VersionRefused},
		"no certificate": {func(*tlsFixture) *tls.Certificate { return nil }, nil, devicecert.NoClientCertificate},
		"another CA": {func(f *tlsFixture) *tls.Certificate { c := f.deviceCert(t, otherCA, testpki.Leaf{}); return &c },
			nil, devicecert.UnknownCA},
		"expired": {func(f *tlsFixture) *tls.Certificate {
			c := f.deviceCert(t, nil, testpki.Leaf{NotBefore: time.Now().Add(-2 * time.Hour), NotAfter: time.Now().Add(-time.Hour)})
			return &c
		}, nil, devicecert.CertificateExpired},
		"another device": {func(f *tlsFixture) *tls.Certificate {
			c := f.deviceCert(t, nil, testpki.Leaf{DNSNames: []string{"leaf-02"}})
			return &c
		}, nil, devicecert.IdentityMismatch},
		"a server name not configured": {func(f *tlsFixture) *tls.Certificate { c := f.deviceCert(t, nil, testpki.Leaf{}); return &c },
			func(c *tls.Config) { c.ServerName = "other.example.net"; c.InsecureSkipVerify = true }, devicecert.SNIMismatch},
	} {
		t.Run(name, func(t *testing.T) {
			log := &syncBuffer{}
			f := newTLSFixture(t, log, func(d *Deps, _ *tlsFixture) { d.Limits = slowBackoff() })
			refusedAtHandshake(t, f, log, c.cert(f), c.adjust, c.outcome, true)
		})
	}
}

func TestTLSRevokedIsStruck(t *testing.T) {
	log := &syncBuffer{}
	f := newTLSFixture(t, log, func(d *Deps, _ *tlsFixture) { d.Limits = slowBackoff() })
	f.status.Store(int32(devicecert.StatusRevoked))
	cert := f.deviceCert(t, nil, testpki.Leaf{})
	refusedAtHandshake(t, f, log, &cert, nil, devicecert.CertificateRevoked, true)
}

// A status that cannot be established declines, with no strike, and its
// window stands: the next dial inside it is reset at Accept, before any TLS
// byte, with no second handshake and no second record, though leaf-01 is
// admitted on this listener (decision 50 ruling 8).
func TestTLSStatusUnavailableIsDeclinedNotStruck(t *testing.T) {
	log := &syncBuffer{}
	f := newTLSFixture(t, log, func(d *Deps, _ *tlsFixture) { d.Limits = slowBackoff() })
	f.status.Store(int32(devicecert.StatusUnknown))
	cert := f.deviceCert(t, nil, testpki.Leaf{})
	refusedAtHandshake(t, f, log, &cert, nil, devicecert.StatusUnavailable, false)
	declinedBefore := testutil.ToFloat64(f.ts.metrics.ConnectionEvents.WithLabelValues("declined_refused"))
	acceptRefused(t, f.ts.addr)
	if got := testutil.ToFloat64(f.ts.metrics.ConnectionEvents.WithLabelValues("declined_refused")); got != declinedBefore+1 {
		t.Fatalf("declined_refused %v, want %v: the window did not stand", got, declinedBefore+1)
	}
	if n := strings.Count(log.String(), `"tls_outcome":"status_unavailable"`); n != 1 {
		t.Fatalf("%d status_unavailable records, want 1: the second dial ran a handshake", n)
	}
	if f.ts.limits.Holding(loopback) {
		t.Fatal("struck")
	}
}

// A peer that holds only a device's public certificate (not its key) fails
// the handshake at CertificateVerify, struck as an impostor. It never
// reaches the status check, which runs only once possession is proven, so
// a CRL outage gives it no unstruck decline (decision 50 ruling 8;
// pre-flight I1).
func TestTLSAPublicCertificateAloneNeverReachesTheStatusCheck(t *testing.T) {
	log := &syncBuffer{}
	f := newTLSFixture(t, log, func(d *Deps, _ *tlsFixture) { d.Limits = slowBackoff() })
	f.status.Store(int32(devicecert.StatusUnknown)) // an outage: the old order would decline it unstruck
	real := f.deviceCert(t, nil, testpki.Leaf{})
	other := f.deviceCert(t, nil, testpki.Leaf{})
	impostor := tls.Certificate{Certificate: real.Certificate, Leaf: real.Leaf, PrivateKey: other.PrivateKey}
	refusedAtHandshake(t, f, log, &impostor, nil, devicecert.HandshakeFailed, true)
	if n := f.statusCalls.Load(); n != 0 {
		t.Fatalf("the status was asked %d times for a peer that proved nothing", n)
	}
	if log.contains(`"tls_outcome":"status_unavailable"`) {
		t.Fatalf("an impostor was declined, not struck: %s", log.String())
	}
}

// clientHelloWithEarlyData is a TLS 1.3 ClientHello carrying the early_data
// extension, which no Go client sends: RFC 9887 §5.1.2's case. crypto/tls
// aborts it with unsupported_extension, "tls: client sent unexpected early
// data" (handshake_server_tls13.go, Go 1.26).
func clientHelloWithEarlyData(t *testing.T) []byte {
	t.Helper()
	u16 := func(b []byte, v int) []byte { return append(b, byte(v>>8), byte(v)) }
	ext := func(b []byte, typ int, data []byte) []byte { return append(u16(u16(b, typ), len(data)), data...) }
	random, share := make([]byte, 32), make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(share); err != nil {
		t.Fatal(err)
	}
	var exts []byte
	exts = ext(exts, 0x002b, []byte{2, 0x03, 0x04})                              // supported_versions: TLS 1.3
	exts = ext(exts, 0x000a, []byte{0, 2, 0x00, 0x1d})                           // supported_groups: x25519
	exts = ext(exts, 0x000d, []byte{0, 2, 0x04, 0x03})                           // signature_algorithms: ecdsa_secp256r1_sha256
	exts = ext(exts, 0x0033, append([]byte{0, 36, 0x00, 0x1d, 0, 32}, share...)) // key_share: x25519
	exts = ext(exts, 0x002a, nil)                                                // early_data
	body := append([]byte{0x03, 0x03}, random...)
	body = append(body, 0)                // legacy_session_id: empty
	body = append(body, 0, 2, 0x13, 0x01) // cipher_suites: TLS_AES_128_GCM_SHA256
	body = append(body, 1, 0)             // legacy_compression_methods: null
	body = append(u16(body, len(exts)), exts...)
	hs := append([]byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	return append(u16([]byte{0x16, 0x03, 0x01}, len(hs)), hs...)
}

func TestTLSEarlyDataIsRefused(t *testing.T) {
	log := &syncBuffer{}
	f := newTLSFixture(t, log, func(d *Deps, _ *tlsFixture) { d.Limits = slowBackoff() })
	conn, err := net.Dial("tcp", f.ts.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write(clientHelloWithEarlyData(t)); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	io.ReadAll(conn) // the alert, then the reset
	if !waitFor(t, func() bool { return log.contains(`"tls_outcome":"early_data_refused"`) }) {
		t.Fatalf("log: %s", log.String())
	}
	if !f.ts.limits.Holding(loopback) {
		t.Fatal("early data is struck")
	}
}

func TestTLSAllowUnknownAdmits(t *testing.T) {
	log := &syncBuffer{}
	f := newTLSFixture(t, log, func(_ *Deps, f *tlsFixture) { f.allow = true; f.mat.Store(f.material(f.ca, true)) })
	f.status.Store(int32(devicecert.StatusUnknown))
	cert := f.deviceCert(t, nil, testpki.Leaf{})
	if _, r, err := f.login(t, &cert, nil); err != nil || r.Status != wire.AuthenStatusPass {
		t.Fatalf("on_unavailable: allow: %v %d", err, r.Status)
	}
}

// acceptRefused dials raw TCP and wants the connection ended with no byte
// from the server: nothing TLS was exchanged.
func acceptRefused(t *testing.T, addr string) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := conn.Read(make([]byte, 1))
	if n != 0 || err == nil || errors.Is(err, net.ErrClosed) {
		t.Fatalf("read %d bytes, %v: want the connection ended with nothing sent", n, err)
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatal("the server held the connection instead of ending it at Accept")
	}
}

func TestTLSDecidesAtAcceptBeforeAnyTLSByte(t *testing.T) {
	tcpDev := admission.Device{Name: "leaf-01", Platform: "arista_eos", Transport: admission.TransportTCP,
		Addresses: []netip.Addr{loopback}}
	for name, c := range map[string]struct {
		set    func(*testing.T, *tlsFixture)
		quar   bool
		diag   string
		struck bool
	}{
		"not in the inventory": {func(t *testing.T, f *tlsFixture) { f.admit.swap(t) }, false, "unadmitted_source", true},
		"refused admission": {func(t *testing.T, f *tlsFixture) {
			f.admit.swap(t, admission.Resolved{Device: admission.Device{Name: "leaf-01", Transport: "udp",
				Addresses: []netip.Addr{loopback}}, Refused: `has transport "udp"`, Refusal: admission.RefusedTransport})
		}, false, "admission_refused", false},
		"a tcp device": {func(t *testing.T, f *tlsFixture) {
			f.admit.swap(t, admission.Resolved{Device: tcpDev, KeyRef: "prod_key"})
		},
			false, "transport_mismatch", false},
		"quarantined": {func(*testing.T, *tlsFixture) {}, true, "device_quarantined", false},
	} {
		t.Run(name, func(t *testing.T) {
			log := &syncBuffer{}
			f := newTLSFixture(t, log, func(d *Deps, _ *tlsFixture) {
				d.Limits = slowBackoff()
				if c.quar {
					d.Quarantined = func(string, time.Time) (string, bool) { return "a grant expired", true }
				}
			})
			c.set(t, f)
			acceptRefused(t, f.ts.addr)
			if !waitFor(t, func() bool { return log.contains(`"diagnosis":"` + c.diag + `"`) }) {
				t.Fatalf("no %s record: %s", c.diag, log.String())
			}
			// No header was read: its fields are zero, and type 0 is no
			// TACACS+ type (decision 50 ruling 5).
			if !log.contains(`"transport":"tls"`) || !log.contains(`"type":0,"seq_no":0,"session_id":0,"length":0`) {
				t.Fatalf("an Accept record has transport tls and zero header fields: %s", log.String())
			}
			var total float64
			for _, o := range append([]devicecert.Outcome{devicecert.OK}, devicecert.Outcomes...) {
				total += testutil.ToFloat64(f.ts.metrics.TLSHandshakes.WithLabelValues(string(o)))
			}
			if total != 0 {
				t.Fatalf("%v handshakes counted: a refusal at Accept runs none", total)
			}
			if got := f.ts.limits.Holding(loopback); got != c.struck {
				t.Fatalf("struck %v, want %v", got, c.struck)
			}
		})
	}
}

func TestTLSObfuscatedPacketGetsAnErrorAndAClose(t *testing.T) {
	log := &syncBuffer{}
	f := newTLSFixture(t, log, func(d *Deps, _ *tlsFixture) { d.Limits = slowBackoff() })
	cert := f.deviceCert(t, nil, testpki.Leaf{})
	c, err := f.dialTLS(t, &cert, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.send(wire.TypeAuthor, []byte("anything at all"), 0); err != nil {
		t.Fatal(err)
	}
	h, body, err := c.recv()
	if err != nil {
		t.Fatalf("no ERROR reply: %v", err)
	}
	r, err := wire.DecodeAuthorResponse(body)
	if err != nil || r.Status != wire.AuthorStatusError || h.Flags != wire.FlagUnencrypted || h.SeqNo != 2 {
		t.Fatalf("reply %+v %+v %v", h, r, err)
	}
	if _, _, err := c.recv(); !errors.Is(err, io.EOF) {
		t.Fatalf("after the ERROR the connection closes: %v", err)
	}
	if !waitFor(t, func() bool { return log.contains(`"diagnosis":"obfuscated_over_tls"`) }) {
		t.Fatalf("log: %s", log.String())
	}
	if log.contains("body_sha256") || f.ts.limits.Holding(loopback) {
		t.Fatalf("a body hash, or a strike: %s", log.String())
	}
	if !log.contains(`"name":"leaf-01"`) {
		t.Fatalf("the record names the device: %s", log.String())
	}
}

func TestTLSHandshakeTimeoutIsStruck(t *testing.T) {
	log := &syncBuffer{}
	f := newTLSFixture(t, log, func(d *Deps, _ *tlsFixture) {
		d.Limits = slowBackoff()
		d.TLS.HandshakeTimeout = time.Second
	})
	conn, err := net.Dial("tcp", f.ts.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	start := time.Now()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("the server sent something to a silent peer")
	}
	if d := time.Since(start); d < 900*time.Millisecond || d > 3*time.Second {
		t.Fatalf("closed after %v, want about handshake_timeout (1s)", d)
	}
	if !waitFor(t, func() bool { return log.contains(`"tls_outcome":"handshake_timeout"`) }) || !f.ts.limits.Holding(loopback) {
		t.Fatalf("log: %s", log.String())
	}
}

func TestTLSRecordsNeverHoldABody(t *testing.T) {
	log := &syncBuffer{}
	f := newTLSFixture(t, log, nil)
	cert := f.deviceCert(t, nil, testpki.Leaf{})
	c, err := f.dialTLS(t, &cert, nil)
	if err != nil {
		t.Fatal(err)
	}
	// seq_no 255 is a protocol error after the header passed.
	c.seq = 255
	if err := c.send(wire.TypeAuthen, aliceLogin, wire.FlagUnencrypted); err != nil {
		t.Fatal(err)
	}
	c.recv()
	if !waitFor(t, func() bool { return log.contains(`"diagnosis":"malformed_after_validation"`) }) {
		t.Fatalf("log: %s", log.String())
	}
	if log.contains("body_sha256") || strings.Contains(log.String(), "p49_e2e") {
		t.Fatalf("a TLS record held a body or a credential: %s", log.String())
	}
}

// A packet with seq_no 255 cannot be answered (the reply would be 256): the
// session closes with close_notify and no reply. An Author request is
// answered at any sequence number, so only the check itself stops it.
func TestTLSSeqNo255ClosesWithoutAReply(t *testing.T) {
	log := &syncBuffer{}
	f := newTLSFixture(t, log, nil)
	cert := f.deviceCert(t, nil, testpki.Leaf{})
	c, err := f.dialTLS(t, &cert, nil)
	if err != nil {
		t.Fatal(err)
	}
	c.seq = 255
	req := wire.AuthorRequest{AuthenMethod: 6, PrivLvl: 1, AuthenType: wire.AuthenTypePAP, Service: 1,
		User: []byte("alice"), Port: []byte("tty1"), RemAddr: []byte("10.0.0.1"), Args: [][]byte{[]byte("service=shell")}}
	if err := c.send(wire.TypeAuthor, req.Encode(), wire.FlagUnencrypted); err != nil {
		t.Fatal(err)
	}
	if h, body, err := c.recv(); err == nil || len(body) != 0 || h.Length != 0 {
		t.Fatalf("a reply to seq_no 255: %+v %d bytes, %v", h, len(body), err)
	}
	if !waitFor(t, func() bool { return log.contains(`"diagnosis":"malformed_after_validation"`) }) {
		t.Fatalf("log: %s", log.String())
	}
}

// An admitted tls device that reaches the RFC 8907 listener is declined with
// the diagnosis that names why, not struck as a key miss.
func TestTLSDeviceOnTheTCPListenerIsDeclined(t *testing.T) {
	log := &syncBuffer{}
	adm := &swapAdmitter{}
	adm.swap(t, admission.Resolved{Device: leaf01TLS, KeyRef: "prod_key"})
	ts := newTestServerWith(t, log, seededStore(t), nil, func(d *Deps) { d.Admission = adm; d.Limits = slowBackoff() })
	c := dial(t, ts.addr, []byte("k2"))
	c.send(t, wire.TypeAuthen, aliceLogin, 0)
	closedAtOnce(t, c)
	if !waitFor(t, func() bool { return log.contains(`"diagnosis":"transport_mismatch"`) }) {
		t.Fatalf("log: %s", log.String())
	}
	if ts.limits.Holding(loopback) || !ts.limits.Declined(loopback) {
		t.Fatalf("struck %v declined %v", ts.limits.Holding(loopback), ts.limits.Declined(loopback))
	}
}

// The handshake's Detail is the verdict's own bounded line: a failure
// crypto/tls reports carries a fixed line, never its error text.
func TestTLSDetailNeverCarriesRawErrorText(t *testing.T) {
	log := &syncBuffer{}
	f := newTLSFixture(t, log, func(d *Deps, _ *tlsFixture) { d.Limits = slowBackoff() })
	real := f.deviceCert(t, nil, testpki.Leaf{})
	other := f.deviceCert(t, nil, testpki.Leaf{})
	impostor := tls.Certificate{Certificate: real.Certificate, Leaf: real.Leaf, PrivateKey: other.PrivateKey}
	refusedAtHandshake(t, f, log, &impostor, nil, devicecert.HandshakeFailed, true)
	for _, rec := range log.records(t) {
		u, _ := rec["unvalidated"].(map[string]any)
		if u == nil || u["tls_outcome"] != "handshake_failed" {
			continue
		}
		if d, _ := u["detail"].(string); d != handshakeFailedDetail || strings.Contains(d, "tls:") {
			t.Fatalf("detail %q, want the fixed line", d)
		}
	}
}

// A tls device the loaded material cannot tell apart is decided at Accept,
// from its address alone: no TLS byte, no handshake, no strike. Its window
// stands while it stays in the map, whoever dials, so a peer holding only
// the device's public certificate gets nothing from the server either.
func TestTLSUnidentifiableDeviceIsDecidedAtAccept(t *testing.T) {
	log := &syncBuffer{}
	f := newTLSFixture(t, log, func(d *Deps, f *tlsFixture) {
		d.Limits = slowBackoff()
		m := f.material(f.ca, true)
		m.Unidentifiable = map[string]string{"leaf-01": "shares its name with leaf-09 under dns_suffixes"}
		f.mat.Store(m)
	})
	real := f.deviceCert(t, nil, testpki.Leaf{})
	other := f.deviceCert(t, nil, testpki.Leaf{})
	impostor := tls.Certificate{Certificate: real.Certificate, Leaf: real.Leaf, PrivateKey: other.PrivateKey}
	for i, cert := range []*tls.Certificate{&real, &impostor, &impostor} {
		if _, _, err := f.login(t, cert, nil); err == nil {
			t.Fatalf("dial %d was answered", i)
		}
	}
	if !waitFor(t, func() bool { return log.contains(`"tls_outcome":"identity_mismatch"`) }) ||
		!log.contains("shares its name with leaf-09") || !log.contains(`"type":0,"seq_no":0,"session_id":0,"length":0`) {
		t.Fatalf("record: %s", log.String())
	}
	if f.ts.limits.Holding(loopback) || !f.ts.limits.Declined(loopback) {
		t.Fatalf("struck %v declined %v", f.ts.limits.Holding(loopback), f.ts.limits.Declined(loopback))
	}
	if n := f.statusCalls.Load(); n != 0 {
		t.Fatalf("status asked %d times", n)
	}
	for _, o := range append([]devicecert.Outcome{devicecert.OK}, devicecert.Outcomes...) {
		if n := testutil.ToFloat64(f.ts.metrics.TLSHandshakes.WithLabelValues(string(o))); n != 0 {
			t.Fatalf("a handshake ran: %s %v", o, n)
		}
	}
	// One record: the window stood for the later dials.
	if n := strings.Count(log.String(), `"tls_outcome":"identity_mismatch"`); n != 1 {
		t.Fatalf("%d records, want 1", n)
	}
}

// A later packet is judged again. A refusal there is a reset with no strike
// (ruling 9), and not a handshake.
func TestTLSRecheckRefusesLaterPacketsWithoutAStrike(t *testing.T) {
	otherCA, err := testpki.NewCA("Other", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		change  func(*tlsFixture)
		outcome devicecert.Outcome
		status  bool
	}{
		"revoked after the handshake":  {func(f *tlsFixture) { f.status.Store(int32(devicecert.StatusRevoked)) }, devicecert.CertificateRevoked, false},
		"status lost":                  {func(f *tlsFixture) { f.status.Store(int32(devicecert.StatusUnknown)) }, devicecert.StatusUnavailable, true},
		"anchors replaced by a reload": {func(f *tlsFixture) { f.mat.Store(f.material(otherCA, true)) }, devicecert.UnknownCA, false},
		"device made unidentifiable by a reload": {func(f *tlsFixture) {
			m := f.material(f.ca, true)
			m.Unidentifiable = map[string]string{"leaf-01": "a reload cannot tell it apart"}
			f.mat.Store(m)
		}, devicecert.IdentityMismatch, false},
	} {
		t.Run(name, func(t *testing.T) {
			log := &syncBuffer{}
			f := newTLSFixture(t, log, func(d *Deps, _ *tlsFixture) { d.Limits = slowBackoff() })
			cert := f.deviceCert(t, nil, testpki.Leaf{})
			cl, err := f.dialTLS(t, &cert, nil)
			if err != nil {
				t.Fatal(err)
			}
			flags := uint8(wire.FlagUnencrypted | wire.FlagSingleConnect)
			if err := cl.send(wire.TypeAuthen, aliceLogin, flags); err != nil {
				t.Fatal(err)
			}
			if _, _, err := cl.recv(); err != nil {
				t.Fatalf("the first exchange: %v", err)
			}
			c.change(f)
			cl.seq, cl.sid = 1, 0x200
			if err := cl.send(wire.TypeAuthen, aliceLogin, flags); err != nil {
				t.Fatal(err)
			}
			if _, body, err := cl.recv(); err == nil || len(body) != 0 {
				t.Fatalf("the packet was answered: %v", err)
			} else if errors.Is(err, io.EOF) || strings.Contains(err.Error(), "remote error") {
				t.Fatalf("close_notify or an alert before the reset: %v", err)
			}
			if !waitFor(t, func() bool { return log.contains(`"tls_outcome":"` + string(c.outcome) + `"`) }) {
				t.Fatalf("no %s record: %s", c.outcome, log.String())
			}
			if f.ts.limits.Holding(loopback) {
				t.Fatal("a refusal at a later packet is struck")
			}
			if got := f.ts.limits.Declined(loopback); got != c.status {
				t.Fatalf("declined %v, want %v: only a lost status keeps a window", got, c.status)
			}
			if n := testutil.ToFloat64(f.ts.metrics.ConnectionEvents.WithLabelValues("admission_closed")); n != 1 {
				t.Fatalf("admission_closed = %v", n)
			}
			if got := f.ts.limits.DeclinedForStatus(loopback); got != c.status {
				t.Fatalf("declined for status %v, want %v", got, c.status)
			}
			if n := testutil.ToFloat64(f.ts.metrics.TLSHandshakes.WithLabelValues(string(c.outcome))); n != 0 {
				t.Fatalf("a packet refusal counted as a handshake: %v", n)
			}
		})
	}
}

// The status is asked exactly once per handshake, when it completes. (The
// impostor test pins that it is never asked before.)
func TestTLSStatusIsAskedExactlyOncePerHandshake(t *testing.T) {
	log := &syncBuffer{}
	f := newTLSFixture(t, log, nil)
	cert := f.deviceCert(t, nil, testpki.Leaf{})
	if _, err := f.dialTLS(t, &cert, nil); err != nil {
		t.Fatal(err)
	}
	if !waitFor(t, func() bool { return f.statusCalls.Load() >= 1 }) {
		t.Fatal("the status was never asked")
	}
	time.Sleep(100 * time.Millisecond)
	if n := f.statusCalls.Load(); n != 1 {
		t.Fatalf("the status was asked %d times, want 1", n)
	}
}

// A device configured by IP sends no SNI (ruling 10): it is accepted, and
// a name is matched case-insensitively.
func TestTLSAbsentSNIIsAcceptedAndNamesFoldCase(t *testing.T) {
	log := &syncBuffer{}
	f := newTLSFixture(t, log, nil)
	cert := f.deviceCert(t, nil, testpki.Leaf{})
	noSNI := func(c *tls.Config) { c.ServerName = ""; c.InsecureSkipVerify = true }
	if _, r, err := f.login(t, &cert, noSNI); err != nil || r.Status != wire.AuthenStatusPass {
		t.Fatalf("no SNI: %v", err)
	}
	upper := func(c *tls.Config) { c.ServerName = "TACACS.example.net"; c.InsecureSkipVerify = true }
	if _, r, err := f.login(t, &cert, upper); err != nil || r.Status != wire.AuthenStatusPass {
		t.Fatalf("upper-case SNI: %v", err)
	}
}

// Material with weaker settings is still forced to TLS 1.3 and a client
// certificate.
func TestTLSForcesVersionAndClientAuth(t *testing.T) {
	log := &syncBuffer{}
	f := newTLSFixture(t, log, func(d *Deps, f *tlsFixture) {
		d.Limits = slowBackoff()
		m := f.material(f.ca, true)
		m.Config.MinVersion, m.Config.ClientAuth = tls.VersionTLS12, tls.NoClientCert
		f.mat.Store(m)
	})
	cert := f.deviceCert(t, nil, testpki.Leaf{})
	if _, _, err := f.login(t, &cert, func(c *tls.Config) { c.MaxVersion = tls.VersionTLS12 }); err == nil {
		t.Fatal("a TLS 1.2 client was served")
	}
	if !waitFor(t, func() bool { return log.contains(`"tls_outcome":"version_refused"`) }) {
		t.Fatalf("log: %s", log.String())
	}
	f2 := newTLSFixture(t, &syncBuffer{}, func(d *Deps, f *tlsFixture) {
		m := f.material(f.ca, true)
		m.Config.ClientAuth = tls.NoClientCert
		f.mat.Store(m)
	})
	if _, _, err := f2.login(t, nil, nil); err == nil {
		t.Fatal("a client with no certificate was served")
	}
}

// A tls device on the RFC 8907 listener sends its first header within the
// short unadmitted bound (5s), not the configured idle timeout.
func TestTLSDeviceOnTheTCPListenerGetsTheShortHeaderBound(t *testing.T) {
	log := &syncBuffer{}
	adm := &swapAdmitter{}
	adm.swap(t, admission.Resolved{Device: leaf01TLS, KeyRef: "prod_key"})
	ts := newTestServerWith(t, log, seededStore(t), nil, func(d *Deps) { d.Admission = adm; d.IdleTimeout = time.Minute })
	conn, err := net.Dial("tcp", ts.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	start := time.Now()
	conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("the server sent something to a silent peer")
	}
	if d := time.Since(start); d > 8*time.Second {
		t.Fatalf("closed after %v, want about 5s", d)
	}
}
