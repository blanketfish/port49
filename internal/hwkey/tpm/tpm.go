// Package tpm is a client key held by a TPM 2.0 (plan 9c, ruling 7): a P-256
// signing key under the ECC storage root key, kept as a TSS2 key file, or a
// persistent handle. It speaks to /dev/tpmrm0 through go-tpm, which is pure
// Go, so this package is in every build, the static one included; nothing here
// imports purego (ruling 22).
//
// No handle outlives a call. Each operation dials, makes the SRK, loads the
// key, signs, flushes both handles and closes, so a TPM reset or a
// resource-manager restart costs nothing that was held.
package tpm

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"os"
	"sync"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/blanketfish/port49/internal/hwkey"
	"github.com/blanketfish/port49/internal/keyfile"
)

const devicePath = "/dev/tpmrm0"

// Dial opens the TPM: /dev/tpmrm0. A var so the hwkey tests dial swtpm.
var Dial = func() (transport.TPMCloser, error) { return linuxtpm.Open(devicePath) }

// errNoAccess is a TPM the user may not open. The TPM is there, so this is not
// ErrKeyAbsent: replugging nothing will fix it.
var errNoAccess = errors.New("port49 cannot open the TPM (" + devicePath + "): add this user to the tss group, then log in again")

// errForeign is a key file the TPM cannot load because its parent is not this
// TPM's SRK: it was made by another TPM, or this TPM was cleared since, which
// makes a new SRK. TPM_RC_INTEGRITY says no more than that.
var errForeign = errors.New("tpm: this key file was made by another TPM, or this machine's TPM was cleared since it was made; make a key here")

// errParentAuth is the TPM refusing the empty auth port49 gives the storage
// root key.
var errParentAuth = errors.New("tpm: the TPM refused the empty auth port49 gives its storage root key: the owner hierarchy has a password, " +
	"which port49 does not supply")

// isAuth is a TPM refusing an authorization value.
func isAuth(err error) bool {
	return errors.Is(err, tpm2.TPMRCAuthFail) || errors.Is(err, tpm2.TPMRCBadAuth)
}

// dial opens the TPM. A TPM that cannot be reached is absent; one the user may
// not open is a different error.
func dial() (transport.TPMCloser, error) {
	t, err := Dial()
	switch {
	case err == nil:
		return t, nil
	case errors.Is(err, fs.ErrPermission):
		return nil, errNoAccess
	}
	return nil, fmt.Errorf("%w: %v", hwkey.ErrKeyAbsent, err)
}

// Available says whether this user can open a TPM at all, and why not: the
// tss group's advice for one the user may not open, "no TPM" for one that is
// not there. It makes no key and runs no command, so a TPM that opens but
// refuses the storage root key's auth is found by Generate, not here.
func Available() error {
	t, err := Dial()
	switch {
	case err == nil:
		t.Close()
		return nil
	case errors.Is(err, fs.ErrPermission):
		return errNoAccess
	}
	return fmt.Errorf("no TPM answers at %s: %v", devicePath, err)
}

// Refused is whether err from Generate is the TPM being absent or refusing to
// make a key: a device that is missing or that the user may not open, or an
// authorization, hierarchy or lockout refusal.
func Refused(err error) bool { return RefusalOf(err) != NotRefused }

// DevicePath is the TPM device port49 opens.
const DevicePath = devicePath

// Refusal is why a TPM would not make a key, for a caller whose advice differs
// by cause.
type Refusal int

const (
	NotRefused Refusal = iota
	// RefusedOwnerAuth is the TPM refusing an authorization or hierarchy: the
	// owner hierarchy has a password.
	RefusedOwnerAuth
	// RefusedLockout is dictionary-attack lockout.
	RefusedLockout
	// RefusedDevice is a device that is missing, stopped answering, or that
	// the user may not open.
	RefusedDevice
)

// RefusalOf is why err from Generate is Refused, or NotRefused.
func RefusalOf(err error) Refusal {
	switch {
	case err == nil:
		return NotRefused
	case errors.Is(err, tpm2.TPMRCLockout):
		return RefusedLockout
	case errors.Is(err, errParentAuth) || isAuth(err) || errors.Is(err, tpm2.TPMRCHierarchy):
		return RefusedOwnerAuth
	case errors.Is(err, hwkey.ErrKeyAbsent) || errors.Is(err, errNoAccess):
		return RefusedDevice
	}
	return NotRefused
}

// answered turns an error from a TPM command into the error a caller sees.
// A response code is the TPM answering, so it stays as it is; anything else
// is the transport failing, which is the TPM gone.
func answered(err error) error {
	var rc tpm2.TPMRC
	if err == nil || errors.As(err, &rc) {
		return err
	}
	return fmt.Errorf("%w: %v", hwkey.ErrKeyAbsent, err)
}

// keyTemplate is the key made under the SRK: a P-256 ECDSA signing key that
// cannot leave this TPM (FixedTPM, FixedParent), whose private half the TPM
// generated (SensitiveDataOrigin), usable with the empty auth (UserWithAuth).
// NoDA: the auth is empty, so dictionary-attack protection guards nothing, and
// a lockout tripped by anything else on the machine must not stop port49's
// keys. It is not a decryption key.
func keyTemplate() tpm2.TPMTPublic {
	return tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			NoDA:                true,
			SignEncrypt:         true,
		},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
			Scheme: tpm2.TPMTECCScheme{
				Scheme: tpm2.TPMAlgECDSA,
				Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSigSchemeECDSA{
					HashAlg: tpm2.TPMAlgSHA256,
				}),
			},
			CurveID: tpm2.TPMECCNistP256,
		}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
			X: tpm2.TPM2BECCParameter{Buffer: make([]byte, 32)},
			Y: tpm2.TPM2BECCParameter{Buffer: make([]byte, 32)},
		}),
	}
}

var ecdsaSHA256 = tpm2.TPMTSigScheme{
	Scheme:  tpm2.TPMAlgECDSA,
	Details: tpm2.NewTPMUSigScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSchemeHash{HashAlg: tpm2.TPMAlgSHA256}),
}

// Signer is one TPM key; it implements hwkey.Key.
type Signer struct {
	mu     sync.Mutex
	path   string // the TSS2 file, "" for a persistent handle
	handle tpm2.TPMHandle
	name   []byte // the persistent key's Name at open; nil while opening
	pub    tpm2.TPM2BPublic
	priv   tpm2.TPM2BPrivate
	key    *ecdsa.PublicKey
	state  hwkey.State
	closed bool
	// refused latches the TPM refusing the key's auth: no further try.
	refused error
}

var _ hwkey.Key = (*Signer)(nil)

func flush(t transport.TPM, h tpm2.TPMHandle) {
	_, _ = tpm2.FlushContext{FlushHandle: h}.Execute(t)
}

var noAuth = tpm2.PasswordAuth(nil)

// srk makes the ECC storage root key under the owner hierarchy. It is the
// same key every time on one TPM and another on any other.
func srk(t transport.TPM) (tpm2.AuthHandle, error) {
	rsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.ECCSRKTemplate),
	}.Execute(t)
	if isAuth(err) {
		return tpm2.AuthHandle{}, errParentAuth
	}
	if err != nil {
		return tpm2.AuthHandle{}, answered(err)
	}
	return tpm2.AuthHandle{Handle: rsp.ObjectHandle, Name: rsp.Name, Auth: noAuth}, nil
}

// load puts the key file's key under parent.
func (s *Signer) load(t transport.TPM, parent tpm2.AuthHandle) (tpm2.AuthHandle, error) {
	rsp, err := tpm2.Load{ParentHandle: parent, InPrivate: s.priv, InPublic: s.pub}.Execute(t)
	switch {
	case err == nil:
		return tpm2.AuthHandle{Handle: rsp.ObjectHandle, Name: rsp.Name, Auth: noAuth}, nil
	case errors.Is(err, tpm2.TPMRCIntegrity):
		return tpm2.AuthHandle{}, errForeign
	case isAuth(err): // only the parent's session: the SRK, with its empty auth
		return tpm2.AuthHandle{}, errParentAuth
	}
	return tpm2.AuthHandle{}, answered(err)
}

// withKey dials, brings the key to a handle, runs fn with it, and lets go of
// every handle it made.
func (s *Signer) withKey(fn func(transport.TPM, tpm2.AuthHandle) error) error {
	t, err := dial()
	if err != nil {
		return err
	}
	defer t.Close()
	if s.handle != 0 {
		rp, err := tpm2.ReadPublic{ObjectHandle: s.handle}.Execute(t)
		if errors.Is(err, tpm2.TPMRCHandle) {
			// Not ErrKeyAbsent: the TPM answers, and no re-probe of it brings
			// the key back.
			return fmt.Errorf("tpm: no persistent key at handle %#x on this TPM: it was removed, or the TPM was cleared", uint32(s.handle))
		}
		if err != nil {
			return answered(err)
		}
		// The Name is the hash of the public area. A different key at the handle
		// would sign under a public key nobody trusts, and might take a password,
		// which a Sign would spend a lockout try finding out.
		if s.name != nil && !bytes.Equal(s.name, rp.Name.Buffer) {
			return fmt.Errorf("tpm: the key at handle %#x changed since port49 opened it: it was replaced; restart port49 to use the new key", uint32(s.handle))
		}
		return fn(t, tpm2.AuthHandle{Handle: s.handle, Name: rp.Name, Auth: noAuth})
	}
	root, err := srk(t)
	if err != nil {
		return err
	}
	defer flush(t, root.Handle)
	key, err := s.load(t, root)
	if err != nil {
		return err
	}
	defer flush(t, key.Handle)
	return fn(t, key)
}

// publicKey is the ECDSA public key a TPM public blob holds; it refuses a
// key that is not a P-256 signing key.
func publicKey(pub tpm2.TPM2BPublic) (*ecdsa.PublicKey, error) {
	c, err := pub.Contents()
	if err != nil {
		return nil, fmt.Errorf("tpm: the key's public blob: %w", err)
	}
	if c.Type != tpm2.TPMAlgECC || !c.ObjectAttributes.SignEncrypt {
		return nil, errors.New("tpm: the key is not an ECC signing key; port49 signs with a P-256 key")
	}
	// TPM2_Sign with no hash-check ticket fails on a restricted key, so every
	// Sign would.
	if c.ObjectAttributes.Restricted {
		return nil, errors.New("tpm: the key is restricted, which only signs TPM-made digests; port49 needs an unrestricted signing key")
	}
	// A key port49 did not make must still be bound to this TPM, and usable
	// with the empty auth port49 gives it.
	for _, a := range []struct {
		name string
		set  bool
	}{
		{"FixedTPM", c.ObjectAttributes.FixedTPM},
		{"FixedParent", c.ObjectAttributes.FixedParent},
		{"SensitiveDataOrigin", c.ObjectAttributes.SensitiveDataOrigin},
		{"UserWithAuth", c.ObjectAttributes.UserWithAuth},
	} {
		if !a.set {
			return nil, fmt.Errorf("tpm: the key lacks the %s attribute, so it is not a hardware-bound key port49 can use; "+
				"make one with port49", a.name)
		}
	}
	parms, err := c.Parameters.ECCDetail()
	if err != nil {
		return nil, fmt.Errorf("tpm: the key's parameters: %w", err)
	}
	if parms.CurveID != tpm2.TPMECCNistP256 {
		return nil, errors.New("tpm: the key's curve is not P-256")
	}
	point, err := c.Unique.ECC()
	if err != nil {
		return nil, fmt.Errorf("tpm: the key's point: %w", err)
	}
	return tpm2.ECDSAPub(parms, point)
}

// Generate makes a P-256 signing key under the ECC SRK and writes it to path
// as a TSS2 key file, mode 0600. It refuses a path that exists: a key file
// overwritten is a key lost.
func Generate(path string) (*Signer, error) {
	s := &Signer{path: path, state: hwkey.Present}
	err := func() error {
		t, err := dial()
		if err != nil {
			return err
		}
		defer t.Close()
		root, err := srk(t)
		if err != nil {
			return err
		}
		defer flush(t, root.Handle)
		rsp, err := tpm2.Create{
			ParentHandle: root,
			InSensitive:  tpm2.TPM2BSensitiveCreate{Sensitive: &tpm2.TPMSSensitiveCreate{}},
			InPublic:     tpm2.New2B(keyTemplate()),
		}.Execute(t)
		if err != nil {
			return answered(err)
		}
		s.pub, s.priv = rsp.OutPublic, rsp.OutPrivate
		return nil
	}()
	if err != nil {
		return nil, err
	}
	if s.key, err = publicKey(s.pub); err != nil {
		return nil, err
	}
	file, err := EncodeTSS2(s.pub, s.priv)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("tpm: writing the key file: %w", err)
	}
	if _, err := f.Write(file); err != nil {
		f.Close()
		os.Remove(path)
		return nil, fmt.Errorf("tpm: writing the key file: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return nil, fmt.Errorf("tpm: writing the key file: %w", err)
	}
	return s, nil
}

// Open reads a TSS2 key file and loads it once, so a file made by another
// machine's TPM is refused here and not at the first signature.
func Open(path string) (*Signer, error) {
	// Owner-only: every port49 user is in tss, and the key has an empty auth, so
	// the file's mode is all that keeps another user from signing as its owner.
	file, err := keyfile.ReadOwn(path)
	if err != nil {
		return nil, fmt.Errorf("tpm: %w", err)
	}
	pub, priv, err := DecodeTSS2(file)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	s := &Signer{path: path, pub: pub, priv: priv, state: hwkey.Present}
	if s.key, err = publicKey(pub); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := s.withKey(func(transport.TPM, tpm2.AuthHandle) error { return nil }); err != nil {
		return nil, err
	}
	return s, nil
}

// OpenHandle opens a persistent key, one of 0x81000000–0x81FFFFFF.
func OpenHandle(handle uint32) (*Signer, error) {
	if handle < 0x81000000 || handle > 0x81FFFFFF {
		return nil, fmt.Errorf("tpm: handle %#x is not a persistent handle (0x81000000-0x81FFFFFF)", handle)
	}
	s := &Signer{handle: tpm2.TPMHandle(handle), state: hwkey.Present}
	err := s.withKey(func(t transport.TPM, _ tpm2.AuthHandle) error {
		rp, err := tpm2.ReadPublic{ObjectHandle: s.handle}.Execute(t)
		if err != nil {
			return answered(err)
		}
		s.pub = rp.OutPublic
		s.name = bytes.Clone(rp.Name.Buffer)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if s.key, err = publicKey(s.pub); err != nil {
		return nil, fmt.Errorf("tpm: handle %#x: %w", handle, err)
	}
	// A password is not in the public area, and the only way to find one is a
	// Sign, which on a DA-protected key spends a lockout try: a process that
	// starts from a timer would lock the whole TPM out after a few starts, every
	// other key on the host with it. So only a NoDA key is probed, where the
	// probe costs nothing; and with an empty auth, DA protection guards nothing.
	if c, err := s.pub.Contents(); err != nil || !c.ObjectAttributes.NoDA {
		return nil, fmt.Errorf("tpm: the key at handle %#x is subject to dictionary-attack lockout (NoDA is clear): "+
			"port49 cannot check it for a password without spending a lockout try, and a lockout caused by anything on this machine would stop it; "+
			"make the key with the attributes noda|fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign and an empty auth "+
			"(tpm2_create -a, then tpm2_evictcontrol)", handle)
	}
	// A refusal latches in Sign and the key is never tried again. Any other
	// failure is not a refusal; it shows at the first real Sign.
	digest := make([]byte, 32)
	if _, err := s.Sign(nil, digest, crypto.SHA256); s.refused != nil {
		return nil, err
	}
	return s, nil
}

// Public is the key's public half.
func (s *Signer) Public() crypto.PublicKey { return s.key }

// Sign signs a SHA-256 digest with ECDSA and returns the DER signature. The
// TPM being gone is hwkey.ErrKeyAbsent and the state Absent.
func (s *Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts == nil || opts.HashFunc() != crypto.SHA256 || len(digest) != 32 {
		return nil, errors.New("tpm: the key signs a SHA-256 digest")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, hwkey.ErrKeyAbsent
	}
	if s.refused != nil {
		return nil, s.refused
	}
	var der []byte
	err := s.withKey(func(t transport.TPM, key tpm2.AuthHandle) error {
		rsp, err := tpm2.Sign{
			KeyHandle: key,
			Digest:    tpm2.TPM2BDigest{Buffer: digest},
			InScheme:  ecdsaSHA256,
			Validation: tpm2.TPMTTKHashCheck{
				Tag:       tpm2.TPMSTHashCheck,
				Hierarchy: tpm2.TPMRHNull,
			},
		}.Execute(t)
		if isAuth(err) {
			// A NoDA key's refusal costs no lockout try, but it is still no use
			// to repeat it.
			s.refused = fmt.Errorf("tpm: %s has a password, which port49 does not supply (it uses keys with an empty auth); "+
				"use a key made by port49", s.where())
			return s.refused
		}
		if err != nil {
			return answered(err)
		}
		sig, err := rsp.Signature.Signature.ECDSA()
		if err != nil {
			return fmt.Errorf("tpm: the signature: %w", err)
		}
		var b cryptobyte.Builder
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1BigInt(new(big.Int).SetBytes(sig.SignatureR.Buffer))
			b.AddASN1BigInt(new(big.Int).SetBytes(sig.SignatureS.Buffer))
		})
		der, err = b.Bytes()
		return err
	})
	if errors.Is(err, hwkey.ErrKeyAbsent) {
		s.state = hwkey.Absent
	}
	if err != nil {
		return nil, err
	}
	s.state = hwkey.Present
	return der, nil
}

// where names the key for an operator.
func (s *Signer) where() string {
	if s.handle != 0 {
		return fmt.Sprintf("the TPM key at handle %#x", uint32(s.handle))
	}
	return "the TPM key in " + s.path
}

// State is Present until a call fails as absent. While it is Absent it
// re-probes with no Sign: a dial and a GetCapability, Present when both
// answer, so a TPM that is back is seen before anything signs (decision 45
// ruling 8).
func (s *Signer) State() hwkey.State {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == hwkey.Absent && !s.closed && probe() {
		s.state = hwkey.Present
	}
	return s.state
}

// probe reports whether the TPM answers.
func probe() bool {
	t, err := dial()
	if err != nil {
		return false
	}
	defer t.Close()
	_, err = tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTFamilyIndicator),
		PropertyCount: 1,
	}.Execute(t)
	return err == nil
}

// Unlock does nothing but zero pin: the key has an empty auth.
func (s *Signer) Unlock(pin []byte) error {
	clear(pin)
	return nil
}

// Close ends the Signer. It holds no handle, so there is nothing to release.
func (s *Signer) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	s.state = hwkey.Absent
	return nil
}
