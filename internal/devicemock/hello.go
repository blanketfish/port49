package devicemock

import (
	"context"
	"crypto/ecdh"
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
			var share []byte
			for _, g := range h.SupportedGroups {
				if c := curve(g); c != nil {
					k, err := c.GenerateKey(rand.Reader)
					if err != nil {
						return nil, err
					}
					share = vec16(u16(nil, g), k.PublicKey().Bytes())
					break
				}
			}
			if share == nil {
				return nil, fmt.Errorf("%w: key_share for groups %v", ErrNoBuilder, h.SupportedGroups)
			}
			body = vec16(nil, share)
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
		return ServerHello{}, errors.New("devicemock: port49 answered the hello with an alert")
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
