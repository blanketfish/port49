// Package clientkey opens the client key a reference names: a path to a key
// file, tpm:file= or tpm:handle= for a TPM, pkcs11: for a token,
// secure-enclave:label= for a Mac's Secure Enclave (experimental). It is a
// package of its own, not hwkey: the backends import hwkey for State and the
// errors, so an opener in hwkey importing them would be an import cycle (plan
// 9c, re-review R3).
//
// The pkcs11: and secure-enclave: arms are in open_dlopen.go, built only with
// the hwkey_dlopen tag; the static build, the container image's, refuses both
// by name (open_static.go, ruling 22).
package clientkey

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/blanketfish/port49/internal/hwkey"
	"github.com/blanketfish/port49/internal/hwkey/pkcs11"
	"github.com/blanketfish/port49/internal/hwkey/tpm"
	"github.com/blanketfish/port49/internal/keyfile"
)

// AskWhenTriesLow is whether a person is there to type a PIN. `port49 login`
// sets it to its stdin being a terminal; every other caller leaves it false.
// A pkcs11: key whose pin-source PIN is not tried because the token reports
// few tries left (pkcs11.ErrPINTriesLow) is then opened without it, Locked, so
// the caller asks the person: a typed success is what clears the token's
// tries-low flag, and a file the person has fixed never can (re-review N1).
var AskWhenTriesLow = func() bool { return false }

// Open opens the key a reference names; pin may be nil (the key is then
// Locked where the token needs one). Open zeroes pin.
func Open(ref string, pin []byte) (hwkey.Key, error) {
	switch {
	case strings.HasPrefix(ref, "tpm:"):
		clear(pin)
		return openTPM(ref)
	case strings.HasPrefix(ref, "pkcs11:"), strings.HasPrefix(ref, "secure-enclave:"):
		return openToken(ref, pin)
	}
	clear(pin)
	scheme, _, _ := strings.Cut(ref, ":")
	return nil, fmt.Errorf("clientkey: %q is not a key reference port49 knows: it starts with pkcs11:, tpm: or secure-enclave:", scheme+":")
}

// CanonicalRef is ref in the one form the agent reports and `port49 login`
// compares (pkcs11.URI.String for a pkcs11: reference, never a PIN); any
// other reference, or one that does not parse, is returned as written.
func CanonicalRef(ref string) string {
	if strings.HasPrefix(ref, "pkcs11:") {
		if u, err := pkcs11.ParseURI(ref); err == nil {
			return u.String()
		}
	}
	return ref
}

// openTPM opens tpm:file=PATH, a TSS2 key file, or tpm:handle=0x81000001, a
// persistent key.
func openTPM(ref string) (hwkey.Key, error) {
	spec := strings.TrimPrefix(ref, "tpm:")
	name, raw, ok := strings.Cut(spec, "=")
	val, err := url.PathUnescape(raw)
	if !ok || raw == "" || err != nil {
		return nil, fmt.Errorf("clientkey: %q: a TPM key is tpm:file=PATH or tpm:handle=0x81000001", ref)
	}
	switch name {
	case "file":
		s, err := tpm.Open(val)
		if err != nil {
			return nil, err
		}
		return s, nil
	case "handle":
		h, err := strconv.ParseUint(val, 0, 32)
		if err != nil {
			return nil, fmt.Errorf("clientkey: %q: the handle %q is not a number such as 0x81000001", ref, val)
		}
		s, err := tpm.OpenHandle(uint32(h))
		if err != nil {
			return nil, err
		}
		return s, nil
	}
	return nil, fmt.Errorf("clientkey: %q: a TPM key is tpm:file=PATH or tpm:handle=0x81000001", ref)
}

// certified is a key that can show the certificate stored beside it, as a
// PKCS#11 token's key can.
type certified interface {
	Certificate() (*x509.Certificate, error)
}

// LoadPair is keyfile.LoadOwnX509KeyPair for a key that may be a reference: a
// path goes to keyfile unchanged; a reference is opened, and certPath ""
// takes the token's certificate for a pkcs11 key. The certificate's public
// key must be the key's.
func LoadPair(certPath, keyRef string, pin []byte) (tls.Certificate, error) {
	return loadPair(certPath, keyRef, pin, keyfile.LoadOwnX509KeyPair)
}

// LoadMountedPair is LoadPair for a key its operator mounts (a workload's, from a Kubernetes Secret
// volume or a secrets agent): a path is read under the secret-file rule within its own directory
// (keyfile.LoadX509KeyPair, decision 54 ruling 16) rather than the owner-only rule of a user's own
// key. A reference is opened as LoadPair opens it.
func LoadMountedPair(certPath, keyRef string, pin []byte) (tls.Certificate, error) {
	return loadPair(certPath, keyRef, pin, keyfile.LoadX509KeyPair)
}

func loadPair(certPath, keyRef string, pin []byte, loadFile func(cert, key string) (tls.Certificate, error)) (tls.Certificate, error) {
	if !hwkey.IsRef(keyRef) {
		clear(pin)
		return loadFile(certPath, keyRef)
	}
	key, err := Open(keyRef, pin)
	if err != nil {
		return tls.Certificate{}, err
	}
	chain, err := chainFor(certPath, key)
	if err != nil {
		key.Close()
		return tls.Certificate{}, err
	}
	leaf := chain[0]
	pub, ok := key.Public().(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !pub.Equal(leaf.PublicKey) {
		key.Close()
		return tls.Certificate{}, errors.New("clientkey: the certificate's public key is not the key's: the certificate belongs to another key")
	}
	out := tls.Certificate{PrivateKey: key, Leaf: leaf}
	for _, c := range chain {
		out.Certificate = append(out.Certificate, c.Raw)
	}
	return out, nil
}

// chainFor is the certificate chain, leaf first: certPath's PEM, or the
// certificate the key's own token holds when certPath is "".
func chainFor(certPath string, key hwkey.Key) ([]*x509.Certificate, error) {
	if certPath == "" {
		c, ok := key.(certified)
		if !ok {
			return nil, errors.New("clientkey: this key holds no certificate: name one with cert:")
		}
		leaf, err := c.Certificate()
		if err != nil {
			return nil, err
		}
		return []*x509.Certificate{leaf}, nil
	}
	raw, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	var chain []*x509.Certificate
	for {
		var b *pem.Block
		if b, raw = pem.Decode(raw); b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, fmt.Errorf("clientkey: %s: %w", certPath, err)
		}
		chain = append(chain, c)
	}
	if len(chain) == 0 {
		return nil, fmt.Errorf("clientkey: %s holds no PEM certificate", certPath)
	}
	return chain, nil
}
