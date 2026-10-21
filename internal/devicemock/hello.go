package devicemock

import (
	"context"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// ErrNoBuilder marks a ClientHello extension the engine cannot build: an
// engine gap to list in the profile, never skipped silently.
var ErrNoBuilder = errors.New("devicemock: no builder for this extension")

// hrrRandom is RFC 8446 §4.1.3's HelloRetryRequest random.
var hrrRandom = sha256.Sum256([]byte("HelloRetryRequest"))

func u16(b []byte, v uint16) []byte { return binary.BigEndian.AppendUint16(b, v) }
func vec16(b, body []byte) []byte   { return append(u16(b, uint16(len(body))), body...) }
func vec8(b, body []byte) []byte    { return append(append(b, byte(len(body))), body...) }

func u16s(xs []uint16) []byte {
	var b []byte
	for _, x := range xs {
		b = u16(b, x)
	}
	return b
}

func curve(g uint16) ecdh.Curve {
	switch g {
	case 29:
		return ecdh.X25519()
	case 23:
		return ecdh.P256()
	case 24:
		return ecdh.P384()
	case 25:
		return ecdh.P521()
	}
	return nil
}

// hybridMLKEM is X25519MLKEM768 (draft-ietf-tls-ecdhe-mlkem; IANA TLS
// Supported Groups 4588): its key share is the ML-KEM-768 encapsulation key
// then the X25519 public key.
const hybridMLKEM = 4588

// share is one fresh key share for group g, or ok false when the standard
// library cannot generate g.
func share(g uint16) (b []byte, ok bool, err error) {
	if g == hybridMLKEM {
		mk, err := mlkem.GenerateKey768()
		if err != nil {
			return nil, true, err
		}
		xk, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return nil, true, err
		}
		return vec16(u16(nil, g), append(mk.EncapsulationKey().Bytes(), xk.PublicKey().Bytes()...)), true, nil
	}
	c := curve(g)
	if c == nil {
		return nil, false, nil
	}
	k, err := c.GenerateKey(rand.Reader)
	if err != nil {
		return nil, true, err
	}
	return vec16(u16(nil, g), k.PublicKey().Bytes()), true, nil
}

// keyShares is the key_share body. With the device's key_share groups recorded,
// it is exactly those shares in its order, and a group with no builder is an
// engine gap. Without them (a summary that predates them) it is one share, for
// the first offered group the standard library can generate. A device that
// leads with X25519MLKEM768 sends that share alone (cEOS 4.36.3M:
// L73-arista_ceos and its QUAL capture), so no X25519 share is added: one would
// spare port49 a HelloRetryRequest the device itself would get.
func keyShares(h Hello) ([]byte, error) {
	if len(h.KeyShareGroups) > 0 {
		var out []byte
		for _, g := range h.KeyShareGroups {
			b, ok, err := share(g)
			if err != nil {
				return nil, err
			}
			if !ok {
				return nil, fmt.Errorf("%w: key_share for group %d", ErrNoBuilder, g)
			}
			out = append(out, b...)
		}
		return out, nil
	}
	for _, g := range h.SupportedGroups {
		b, ok, err := share(g)
		if err != nil || ok {
			return b, err
		}
	}
	return nil, fmt.Errorf("%w: key_share for groups %v", ErrNoBuilder, h.SupportedGroups)
}

// BuildClientHello writes h as one handshake record, extensions in h's order,
// with a fresh random, session id and key share (for the first offered group
// the standard library can generate): the device's offer, never its bytes.
func BuildClientHello(h Hello, serverIP string) ([]byte, error) {
	var exts []byte
	for _, id := range h.Extensions {
		var body []byte
		switch id {
		case 0:
			name := strings.ReplaceAll(h.SNI, "{server_ip}", serverIP)
			if name == "" {
				return nil, errors.New("devicemock: extension 0 listed with no sni")
			}
			body = vec16(nil, vec16([]byte{0}, []byte(name)))
		case 10:
			body = vec16(nil, u16s(h.SupportedGroups))
		case 11:
			body = []byte{1, 0}
		case 13, 50:
			body = vec16(nil, u16s(h.SignatureAlgorithms))
		case 16:
			var l []byte
			for _, p := range h.ALPN {
				l = vec8(l, []byte(p))
			}
			body = vec16(nil, l)
		case 22, 23, 35, 49:
			body = nil
		case 27:
			if len(h.CompressCertAlgs) == 0 {
				return nil, fmt.Errorf("%w: 27 with no compress_certificate_algorithms", ErrNoBuilder)
			}
			body = vec8(nil, u16s(h.CompressCertAlgs))
		case 43:
			body = vec8(nil, u16s(h.SupportedVersions))
		case 45:
			body = vec8(nil, h.PSKModes)
		case 51:
			shares, err := keyShares(h)
			if err != nil {
				return nil, err
			}
			body = vec16(nil, shares)
		case 65281:
			body = []byte{0}
		default:
			return nil, fmt.Errorf("%w: %d", ErrNoBuilder, id)
		}
		exts = vec16(u16(exts, id), body)
	}
	random, sid := make([]byte, 32), make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return nil, err
	}
	if _, err := rand.Read(sid); err != nil {
		return nil, err
	}
	ch := u16(nil, h.LegacyVersion)
	ch = append(ch, random...)
	ch = vec8(ch, sid)
	ch = vec16(ch, u16s(h.CipherSuites))
	ch = append(ch, 1, 0) // compression: null only
	ch = vec16(ch, exts)
	hs := append([]byte{1, byte(len(ch) >> 16), byte(len(ch) >> 8), byte(len(ch))}, ch...)
	return vec16([]byte{22, 3, 1}, hs), nil
}

// Probe sends the device's ClientHello, reads port49's ServerHello and closes.
// port49 counts the abandoned handshake against the source, so a probe runs
// on a daemon of its own (spec §13 decisions 50 and 52).
func Probe(ctx context.Context, d *net.Dialer, addr string, h Hello, serverIP string) (ServerHello, error) {
	hello, err := BuildClientHello(h, serverIP)
	if err != nil {
		return ServerHello{}, err
	}
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return ServerHello{}, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write(hello); err != nil {
		return ServerHello{}, err
	}
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return ServerHello{}, fmt.Errorf("devicemock: no ServerHello: %w", err)
	}
	if hdr[0] == 21 {
		// level then description (RFC 8446 §6), in the clear before any key is agreed
		var alert [2]byte
		if _, err := io.ReadFull(c, alert[:]); err != nil {
			return ServerHello{}, errors.New("devicemock: port49 answered the hello with an alert")
		}
		level := "fatal"
		if alert[0] != 2 {
			// TLS 1.3 sends no warning here; one is reported as what it is, not as a refusal.
			level = "warning"
		}
		return ServerHello{}, fmt.Errorf("devicemock: port49 answered the hello with %s alert %d", level, alert[1])
	}
	body := make([]byte, binary.BigEndian.Uint16(hdr[3:]))
	if _, err := io.ReadFull(c, body); err != nil {
		return ServerHello{}, err
	}
	return readServerHello(body)
}

func readServerHello(b []byte) (ServerHello, error) {
	if len(b) < 4+2+32+1 || b[0] != 2 {
		return ServerHello{}, errors.New("devicemock: not a ServerHello")
	}
	p := b[4:]
	var sh ServerHello
	sh.SelectedVersion = binary.BigEndian.Uint16(p)
	sh.HelloRetryRequest = [32]byte(p[2:34]) == hrrRandom
	p = p[34:]
	if len(p) < 1+int(p[0]) {
		return ServerHello{}, errors.New("devicemock: short ServerHello")
	}
	p = p[1+int(p[0]):] // session id
	if len(p) < 5 {
		return ServerHello{}, errors.New("devicemock: short ServerHello")
	}
	sh.CipherSuite = binary.BigEndian.Uint16(p)
	p = p[3:] // suite and compression
	n := int(binary.BigEndian.Uint16(p))
	p = p[2:]
	if n > len(p) {
		return ServerHello{}, errors.New("devicemock: ServerHello extensions run past the record")
	}
	for p = p[:n]; len(p) >= 4; {
		id, l := binary.BigEndian.Uint16(p), int(binary.BigEndian.Uint16(p[2:]))
		if 4+l > len(p) {
			break
		}
		if id == 43 && l == 2 {
			sh.SelectedVersion = binary.BigEndian.Uint16(p[4:])
		}
		p = p[4+l:]
	}
	return sh, nil
}
