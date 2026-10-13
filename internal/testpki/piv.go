package testpki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"time"
)

// Yubico's PIV attestation extensions, as pivattest reads them.
var (
	oidSerial = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 7}
	oidPolicy = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 8}
)

// PIV is a test attestation hierarchy: a root standing for Yubico's, and one
// device (f9) certificate under it, with no basic constraints as some
// YubiKeys' are. Slot makes the attestation certificate of a key on that
// device; every slot it makes names the device serial DeviceSerial.
type PIV struct {
	Root   *CA
	Device *x509.Certificate

	deviceKey *ecdsa.PrivateKey
	now       time.Time
}

// DeviceSerial is the serial every slot certificate of a PIV names.
const DeviceSerial = 12345678

// pinOnce and touch policies, as pivattest encodes them.
const pinOnce = 0x02

// NewPIV makes the hierarchy, valid around now.
func NewPIV(now time.Time) (*PIV, error) {
	root, err := NewCA("Yubico PIV Root", now.Add(-time.Hour), now.Add(48*time.Hour))
	if err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{SerialNumber: sn, Subject: pkix.Name{CommonName: "Yubico PIV Attestation"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, root.Cert, &key.PublicKey, root.Key)
	if err != nil {
		return nil, err
	}
	device, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &PIV{Root: root, Device: device, deviceKey: key, now: now}, nil
}

// Anchors is the root as attestation_roots_file holds it, PEM.
func (p *PIV) Anchors() []byte { return p.Root.PEM() }

// Slot is the attestation certificate of the slot key pub, signed by the
// device, carrying the touch policy byte given (pivattest.TouchNever,
// TouchAlways or TouchCached).
func (p *PIV) Slot(pub crypto.PublicKey, touch byte) (*x509.Certificate, error) {
	ser, err := asn1.Marshal(big.NewInt(DeviceSerial))
	if err != nil {
		return nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{SerialNumber: sn, Subject: pkix.Name{CommonName: "YubiKey PIV Attestation 9a"},
		NotBefore: p.now.Add(-time.Hour), NotAfter: p.now.Add(24 * time.Hour),
		ExtraExtensions: []pkix.Extension{{Id: oidSerial, Value: ser}, {Id: oidPolicy, Value: []byte{pinOnce, touch}}}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.Device, pub, p.deviceKey)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}
