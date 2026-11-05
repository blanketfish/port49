package testpki

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"time"
)

// Yubico's PIV attestation extensions: the serial and the policy as pivattest
// reads them, and the others a real YubiKey 5 carries (firmware version, form
// factor, and the f9 certificate's own), so these certificates have the shape
// of the SER8 token's (tests/lab/l91fixture; internal/hwkeysetup's
// TestTestPKIMatchesTheL91Shape).
var (
	oidFirmware   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 3}
	oidSerial     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 7}
	oidPolicy     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 8}
	oidFormFactor = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 9}
	oidDeviceF9   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 10}
)

// firmware is the version the extension reports, 5.4.3 as raw bytes.
var firmware = []byte{5, 4, 3}

// PIV is a test attestation hierarchy: a root standing for Yubico's, and one
// device (f9) certificate under it with an RSA key, as a YubiKey's is. Slot makes the attestation certificate of a key on that
// device; every slot it makes names the device serial DeviceSerial.
type PIV struct {
	Root   *CA
	Device *x509.Certificate

	deviceKey *rsa.PrivateKey
	now       time.Time
}

// DeviceSerial is the serial every slot certificate of a PIV names.
const DeviceSerial = 12345678

// pinOnce and touch policies, as pivattest encodes them.
const pinOnce = 0x02

// NewPIV makes the hierarchy, valid around now.
func NewPIV(now time.Time) (*PIV, error) {
	root, err := NewCA("Yubico PIV Root CA Serial 263751", now.Add(-time.Hour), now.Add(48*time.Hour))
	if err != nil {
		return nil, err
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	// Basic constraints present and not a CA, as the token's f9 has them: no
	// subject key id is made, and no authority key id is taken from the root.
	tmpl := &x509.Certificate{SerialNumber: sn, Subject: pkix.Name{CommonName: "Yubico PIV Attestation"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), BasicConstraintsValid: true,
		ExtraExtensions: []pkix.Extension{{Id: oidFirmware, Value: firmware}, {Id: oidDeviceF9, Value: []byte{0x01}}}}
	parent := *root.Cert
	parent.SubjectKeyId = nil
	der, err := x509.CreateCertificate(rand.Reader, tmpl, &parent, &key.PublicKey, root.Key)
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
		ExtraExtensions: []pkix.Extension{{Id: oidFirmware, Value: firmware}, {Id: oidSerial, Value: ser},
			{Id: oidPolicy, Value: []byte{pinOnce, touch}}, {Id: oidFormFactor, Value: []byte{0x01}}}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.Device, pub, p.deviceKey)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}
