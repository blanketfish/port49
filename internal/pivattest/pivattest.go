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

// PIN policies, as the attestation extension encodes them.
const (
	PINNever  = 0x01
	PINOnce   = 0x02
	PINAlways = 0x03
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
type Anchors struct{ Roots, Intermediates *x509.CertPool }

// ParseAnchors reads every PEM certificate in b; none is an error, and so is
// anything in b that is not a certificate or has no self-signed root among
// them.
func ParseAnchors(b []byte) (Anchors, error) {
	a := Anchors{Roots: x509.NewCertPool(), Intermediates: x509.NewCertPool()}
	roots := 0
	rest := b
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
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
	if len(bytes.TrimSpace(rest)) != 0 {
		return Anchors{}, errors.New("pivattest: anchors hold text that is not a PEM certificate")
	}
	if roots == 0 {
		return Anchors{}, errors.New("pivattest: anchors hold no self-signed root certificate")
	}
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
	if a.Roots == nil {
		return Attestation{}, errors.New("pivattest: no attestation roots")
	}
	if now.IsZero() {
		return Attestation{}, errors.New("pivattest: no clock")
	}
	if _, err := device.Verify(x509.VerifyOptions{Roots: a.Roots, Intermediates: a.Intermediates,
		CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return Attestation{}, fmt.Errorf("pivattest: the device certificate does not chain to an attestation root: %w", err)
	}
	if err := device.CheckSignature(slot.SignatureAlgorithm, slot.RawTBSCertificate, slot.Signature); err != nil {
		return Attestation{}, fmt.Errorf("pivattest: the slot certificate is not signed by the device certificate: %w", err)
	}
	if now.Before(slot.NotBefore) || now.After(slot.NotAfter) {
		return Attestation{}, errors.New("pivattest: the slot certificate is outside its validity")
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
