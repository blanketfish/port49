package api

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// The bounds on GET /v1/config's broker_ca_bundle (spec §13 decision 43
// ruling 25): the CA in use and the next one through a rotation, with room
// to spare, and never a file of the system's roots.
const (
	MaxCABundleBytes = 64 << 10
	MaxCABundleCerts = 4
)

// ParseCABundle reads a broker CA bundle: 1 to MaxCABundleCerts PEM
// certificates, each a CA, in at most MaxCABundleBytes, holding nothing
// else. Both ends read it so: the broker the file it sends, the client what
// it is sent.
func ParseCABundle(raw []byte) ([]*x509.Certificate, error) {
	if len(raw) > MaxCABundleBytes {
		return nil, fmt.Errorf("the CA bundle is %d bytes, over %d", len(raw), MaxCABundleBytes)
	}
	// pem.Decode skips text before a block and a block it cannot parse, so
	// what it consumed is checked: whitespace, then exactly one block.
	// Errors say a block's place and what is wrong, never its bytes: the
	// client reads a body from the network with this.
	var out []*x509.Certificate
	rest := raw
	for n := 1; ; n++ {
		before := rest
		var b *pem.Block
		if b, rest = pem.Decode(rest); b == nil {
			break
		}
		consumed := bytes.TrimSpace(before[:len(before)-len(rest)])
		if !bytes.HasPrefix(consumed, []byte("-----BEGIN ")) || bytes.Count(consumed, []byte("-----BEGIN ")) != 1 {
			return nil, fmt.Errorf("the CA bundle holds something other than PEM certificates before block %d", n)
		}
		if b.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("the CA bundle's block %d is not a CERTIFICATE block; it holds certificates alone", n)
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, fmt.Errorf("the CA bundle's block %d does not parse as a certificate", n)
		}
		if !c.BasicConstraintsValid || !c.IsCA {
			return nil, fmt.Errorf("the CA bundle's block %d is not a CA", n)
		}
		if out = append(out, c); len(out) > MaxCABundleCerts {
			return nil, fmt.Errorf("the CA bundle holds over %d certificates", MaxCABundleCerts)
		}
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("the CA bundle holds something other than PEM certificates")
	}
	if len(out) == 0 {
		return nil, errors.New("the CA bundle holds no certificate")
	}
	return out, nil
}

// EncodeCABundle is certs as PEM, nothing else.
func EncodeCABundle(certs []*x509.Certificate) []byte {
	var b bytes.Buffer
	for _, c := range certs {
		_ = pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}
	return b.Bytes()
}

// CAFingerprints names certs as a log line does: "sha256:" and the hex
// SHA-256 of each one's DER, comma-separated.
func CAFingerprints(certs []*x509.Certificate) string {
	fps := make([]string, len(certs))
	for i, c := range certs {
		sum := sha256.Sum256(c.Raw)
		fps[i] = "sha256:" + hex.EncodeToString(sum[:])
	}
	return strings.Join(fps, ", ")
}
