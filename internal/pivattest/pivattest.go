// Package pivattest checks a YubiKey PIV attestation: that the slot's
// attestation certificate was signed by the device's f9 certificate, that the
// f9 certificate chains to a Yubico root the operator trusts, and what PIN and
// touch policy the key was generated under. Every check fails closed, and the
// extensions are read only after the chain and the signature have verified.
package pivattest

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"math/big"
	"time"
)

// Touch policies, as the attestation extension encodes them.
const (
	TouchNever  = 0x01
	TouchAlways = 0x02
	TouchCached = 0x03
)

// PIN policies, as the attestation extension encodes them. The set is closed;
// L60 measures what a YubiKey Bio reports (yubikey-manager's 0x04 and 0x05, PIN
// match once and always), which would be refused until added here.
const (
	PINNever  = 0x01
	PINOnce   = 0x02
	PINAlways = 0x03
)

// Refusals the tests pin by identity.
var (
	errNoRoots        = errors.New("pivattest: no attestation roots")
	errNoClock        = errors.New("pivattest: no clock")
	errIssuerMismatch = errors.New("pivattest: the slot certificate's issuer is not the device certificate's subject")
)

// Yubico's PIV attestation extensions (1.3.6.1.4.1.41482.3).
var (
	oidSerial = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 7}
	oidPolicy = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 8}
)

// Attestation is what a YubiKey's attestation certificate for one slot
// says (Yubico's PIV attestation, the extensions under 1.3.6.1.4.1.41482.3).
type Attestation struct {
	Key         crypto.PublicKey
	Serial      uint32
	PINPolicy   byte
	TouchPolicy byte
	Device      *x509.Certificate // the f9 certificate it is signed by
}

// Anchors is attestation_roots_file read: its self-signed certificates are
// Roots and the rest Intermediates, so a hierarchy with an intermediate
// under a newer Yubico root verifies (pre-flight I14).
type Anchors struct {
	Roots, Intermediates *x509.CertPool
	// NumRoots counts the self-signed certificates in Roots, so a reload can say how many
	// roots are in force now and how many were.
	NumRoots int
}

// ParseAnchors reads every PEM certificate in b. Text outside the PEM blocks
// (comments before, between or after) is ignored, as openssl does, so a note
// appended to the bundle cannot take hardware_key_touch away fleet-wide. A PEM
// block that is not a CERTIFICATE is an error, and so are a certificate that
// does not parse, a BEGIN line with no END, and a bundle with no self-signed
// root.
func ParseAnchors(b []byte) (Anchors, error) {
	a := Anchors{Roots: x509.NewCertPool(), Intermediates: x509.NewCertPool()}
	roots, blocks := 0, 0
	// A file saved with a UTF-8 byte order mark would hide its first BEGIN
	// line from pem.Decode, and that block would be dropped without a word.
	b = bytes.TrimPrefix(b, []byte("\xef\xbb\xbf"))
	rest := b
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		blocks++
		if blk.Type != "CERTIFICATE" {
			return Anchors{}, fmt.Errorf("pivattest: anchors hold a %q block, not a certificate", blk.Type)
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return Anchors{}, fmt.Errorf("pivattest: anchors hold a certificate that does not parse: %w", err)
		}
		if selfSigned(c) {
			a.Roots.AddCert(c)
			roots++
		} else {
			a.Intermediates.AddCert(c)
		}
	}
	// pem.Decode steps over a BEGIN line with no matching END, as it does
	// over any text, so a truncated block would be dropped without a word.
	// More BEGIN lines than blocks decoded is that block; its contents are
	// not echoed.
	if bytes.Count(append([]byte("\n"), b...), []byte("\n-----BEGIN ")) > blocks {
		return Anchors{}, errors.New("pivattest: anchors hold a PEM block that is not terminated or not well formed")
	}
	if roots == 0 {
		return Anchors{}, errors.New("pivattest: anchors hold no self-signed root certificate")
	}
	a.NumRoots = roots
	return a, nil
}

// selfSigned: the subject is the issuer and the certificate's own key signed
// it. The CA bit is not asked for; trust comes from the operator listing it.
func selfSigned(c *x509.Certificate) bool {
	return bytes.Equal(c.RawSubject, c.RawIssuer) &&
		c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil
}

// Verify checks slot against device and device against the anchors at now,
// and reads slot's policy. device's signature over slot is checked directly:
// some f9 certificates carry no basic constraints, which x509.Verify
// refuses for an intermediate (go-piv v2.6.0 piv/key.go:241-247).
func Verify(a Anchors, device, slot *x509.Certificate, now time.Time) (Attestation, error) {
	if device == nil || slot == nil {
		return Attestation{}, errors.New("pivattest: no attestation certificate")
	}
	// A nil pool would make x509.Verify fall back to the system roots.
	if a.Roots == nil {
		return Attestation{}, errNoRoots
	}
	if now.IsZero() {
		return Attestation{}, errNoClock
	}
	if !bytes.Equal(slot.RawIssuer, device.RawSubject) {
		return Attestation{}, errIssuerMismatch
	}
	if _, err := device.Verify(x509.VerifyOptions{Roots: a.Roots, Intermediates: a.Intermediates,
		CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return Attestation{}, fmt.Errorf("pivattest: the device certificate does not chain to an attestation root: %w", err)
	}
	if err := device.CheckSignature(slot.SignatureAlgorithm, slot.RawTBSCertificate, slot.Signature); err != nil {
		return Attestation{}, fmt.Errorf("pivattest: the slot certificate is not signed by the device certificate: %w", err)
	}
	if now.Before(slot.NotBefore) || now.After(slot.NotAfter) {
		// Certificate times, not secrets: a clock-skewed host shows its cause.
		return Attestation{}, fmt.Errorf("pivattest: the slot certificate is outside its validity: now %s, not before %s, not after %s",
			now.UTC().Format(time.RFC3339), slot.NotBefore.UTC().Format(time.RFC3339), slot.NotAfter.UTC().Format(time.RFC3339))
	}
	serial, err := readSerial(slot)
	if err != nil {
		return Attestation{}, err
	}
	pin, touch, err := readPolicy(slot)
	if err != nil {
		return Attestation{}, err
	}
	return Attestation{Key: slot.PublicKey, Serial: serial, PINPolicy: pin, TouchPolicy: touch, Device: device}, nil
}

// extension returns the value of the one extension with oid; absent or
// repeated is an error.
func extension(c *x509.Certificate, oid asn1.ObjectIdentifier, what string) ([]byte, error) {
	var val []byte
	found := false
	for _, e := range c.Extensions {
		if !e.Id.Equal(oid) {
			continue
		}
		if found {
			return nil, fmt.Errorf("pivattest: the slot certificate carries the %s twice", what)
		}
		found, val = true, e.Value
	}
	if !found {
		return nil, fmt.Errorf("pivattest: the slot certificate carries no %s", what)
	}
	return val, nil
}

func readSerial(c *x509.Certificate) (uint32, error) {
	raw, err := extension(c, oidSerial, "device serial")
	if err != nil {
		return 0, err
	}
	var n *big.Int
	rest, err := asn1.Unmarshal(raw, &n)
	if err != nil || len(rest) != 0 || n == nil {
		return 0, errors.New("pivattest: the device serial is not one ASN.1 integer")
	}
	if n.Sign() < 0 || !n.IsUint64() || n.Uint64() > math.MaxUint32 {
		return 0, errors.New("pivattest: the device serial is outside 0 to 2^32-1")
	}
	return uint32(n.Uint64()), nil
}

// SlotCNPrefix begins the subject common name of a YubiKey's slot attestation
// certificate ("YubiKey PIV Attestation 9a"), which tells it from the slot's
// own certificate, the f9 device certificate and anything else on the token.
const SlotCNPrefix = "YubiKey PIV Attestation"

// KeyPolicy is the PIN and touch policy a slot attestation certificate names
// (the Yubico key policy extension, 1.3.6.1.4.1.41482.3.8). It verifies
// nothing: it is for a message to the operator, never for a decision that
// grants anything. Verify is the check that the certificate is Yubico's.
func KeyPolicy(c *x509.Certificate) (pin, touch byte, err error) {
	return readPolicy(c)
}

func readPolicy(c *x509.Certificate) (pin, touch byte, err error) {
	raw, err := extension(c, oidPolicy, "key policy")
	if err != nil {
		return 0, 0, err
	}
	if len(raw) != 2 {
		return 0, 0, fmt.Errorf("pivattest: the key policy is %d bytes, not 2", len(raw))
	}
	pin, touch = raw[0], raw[1]
	switch pin {
	case PINNever, PINOnce, PINAlways:
	default:
		return 0, 0, fmt.Errorf("pivattest: unknown PIN policy %#02x", pin)
	}
	switch touch {
	case TouchNever, TouchAlways, TouchCached:
	default:
		return 0, 0, fmt.Errorf("pivattest: unknown touch policy %#02x", touch)
	}
	return pin, touch, nil
}
