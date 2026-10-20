package devicemock

import (
	"crypto/tls"
	"encoding/binary"
	"errors"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/testpki"
)

func nxosHello() Hello {
	return Hello{LegacyVersion: 771, SupportedVersions: []uint16{772}, CipherSuites: []uint16{4866, 4867, 4865, 255},
		SupportedGroups:     []uint16{29, 23, 30, 25, 24},
		SignatureAlgorithms: []uint16{1027, 1283, 1539, 2055, 2056, 2057, 2058, 2059, 2052, 2053, 2054, 1025, 1281, 1537},
		PSKModes:            []uint8{1}, Extensions: []uint16{11, 10, 35, 22, 23, 13, 43, 45, 51}}
}

func equalU16(a, b []uint16) bool { return slices.Equal(a, b) }

// selfSigned is a server certificate for 127.0.0.1 from a throwaway CA; the
// key lives in memory only.
func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	cert, _ := selfSignedWithCA(t)
	return cert
}

func selfSignedWithCA(t *testing.T) (tls.Certificate, *testpki.CA) {
	t.Helper()
	now := time.Now()
	ca, err := testpki.NewCA("probe", now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ca.Issue(testpki.Leaf{IPs: testpki.Loopback(), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	return cert, ca
}

// parseClientHelloForTest reads the fields BuildClientHello wrote: the record
// header, the handshake header, version, random, session id, suites,
// compression, then each extension's type, with the host from extension 0 and
// the algorithms from extension 27.
func parseClientHelloForTest(raw []byte) (Hello, error) {
	var h Hello
	bad := errors.New("short ClientHello")
	if len(raw) < 5+4+2+32+1 || raw[0] != 22 || raw[5] != 1 {
		return h, bad
	}
	p := raw[5+4:]
	h.LegacyVersion, p = binary.BigEndian.Uint16(p), p[2+32:]
	if len(p) < 1+int(p[0])+2 {
		return h, bad
	}
	p = p[1+int(p[0]):] // session id
	n := int(binary.BigEndian.Uint16(p))
	if len(p) < 2+n+1 {
		return h, bad
	}
	for s := p[2 : 2+n]; len(s) >= 2; s = s[2:] {
		h.CipherSuites = append(h.CipherSuites, binary.BigEndian.Uint16(s))
	}
	p = p[2+n:]
	if len(p) < 1+int(p[0])+2 {
		return h, bad
	}
	p = p[1+int(p[0]):] // compression
	n = int(binary.BigEndian.Uint16(p))
	if len(p) < 2+n {
		return h, bad
	}
	for e := p[2 : 2+n]; len(e) >= 4; {
		id, l := binary.BigEndian.Uint16(e), int(binary.BigEndian.Uint16(e[2:]))
		if len(e) < 4+l {
			return h, bad
		}
		body := e[4 : 4+l]
		h.Extensions = append(h.Extensions, id)
		switch id {
		case 0: // list length, name type, name length, name
			if len(body) >= 5 {
				h.SNI = string(body[5:])
			}
		case 27: // one-byte length, then two-byte ids
			for a := body[1:]; len(a) >= 2; a = a[2:] {
				h.CompressCertAlgs = append(h.CompressCertAlgs, binary.BigEndian.Uint16(a))
			}
		}
		e = e[4+l:]
	}
	return h, nil
}

func TestBuildClientHelloKeepsTheDevicesOrderAndIsFreshEachTime(t *testing.T) {
	a, err := BuildClientHello(nxosHello(), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := BuildClientHello(nxosHello(), "127.0.0.1")
	if slices.Equal(a, b) {
		t.Fatal("two hellos are byte-identical: the random and the key share must be fresh")
	}
	// record 5 + handshake 4 + version 2 = 11: the 32-byte random, then the
	// session id's length octet and its 32 bytes.
	if slices.Equal(a[11:43], b[11:43]) || slices.Equal(a[44:76], b[44:76]) {
		t.Fatal("the random and the session id must each be fresh")
	}
	got, err := parseClientHelloForTest(a)
	if err != nil {
		t.Fatal(err)
	}
	if !equalU16(got.CipherSuites, nxosHello().CipherSuites) || !equalU16(got.Extensions, nxosHello().Extensions) || got.SNI != "" {
		t.Fatalf("%+v", got)
	}
}

func TestBuildClientHelloSendsALiteralAddressAsSNIWhenTheDeviceDoes(t *testing.T) {
	h := nxosHello()
	h.SNI, h.Extensions = "{server_ip}", append([]uint16{0}, h.Extensions...)
	raw, _ := BuildClientHello(h, "172.100.100.1")
	if got, _ := parseClientHelloForTest(raw); got.SNI != "172.100.100.1" {
		t.Fatalf("Junos sends the literal address (L73 cell c): %q", got.SNI)
	}
}

func TestBuildClientHelloBuildsCompressCertificate(t *testing.T) {
	h := nxosHello()
	h.Extensions, h.CompressCertAlgs = append(h.Extensions, 27), []uint16{2, 1}
	raw, err := BuildClientHello(h, "")
	if err != nil {
		t.Fatalf("cEOS sends extension 27 (L73-arista_ceos evidence): %v", err)
	}
	if got, _ := parseClientHelloForTest(raw); !equalU16(got.CompressCertAlgs, []uint16{2, 1}) {
		t.Fatalf("%+v", got)
	}
}

func TestBuildClientHelloRefusesAnExtensionItCannotBuild(t *testing.T) {
	h := nxosHello()
	// pre_shared_key: cEOS offered one on a resumption (L73-arista_ceos, cell g);
	// the mock never resumes, and genprofile takes a full handshake's hello.
	h.Extensions = append(h.Extensions, 41)
	_, err := BuildClientHello(h, "")
	if !errors.Is(err, ErrNoBuilder) {
		t.Fatalf("an extension with no builder is an engine gap, named, never skipped: %v", err)
	}
}

// The suite crypto/tls picks for the N9Kv's offer is AES-128-GCM on a runner
// with AES hardware (hosted x86, Apple arm64); ChaCha20 would be chosen
// without it, which no supported runner lacks.
func TestProbeReadsAGoServersChoice(t *testing.T) {
	cert := selfSigned(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})
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
	sh, err := Probe(t.Context(), &net.Dialer{}, ln.Addr().String(), nxosHello(), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if sh.SelectedVersion != 772 || sh.CipherSuite != 4865 || sh.HelloRetryRequest {
		t.Fatalf("%+v", sh)
	}
}

// A device that leads with X25519MLKEM768 sends that share, so a Go server,
// which prefers the hybrid, answers without a HelloRetryRequest.
func TestProbeOfAHybridFirstOfferGetsNoRetry(t *testing.T) {
	cert := selfSigned(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})
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
	h := nxosHello()
	h.SupportedGroups = []uint16{4588, 29, 23}
	sh, err := Probe(t.Context(), &net.Dialer{}, ln.Addr().String(), h, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if sh.HelloRetryRequest {
		t.Fatalf("a hybrid-first offer carried no hybrid share: %+v", sh)
	}
}
