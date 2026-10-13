//go:build darwin && hwkey_dlopen

package secureenclave

import (
	"crypto"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/rhwendt/port49/internal/hwkey"
	"github.com/rhwendt/port49/internal/hwkey/secureenclave/secapi"
)

// Signer is one Secure Enclave key; it implements hwkey.Key. It holds the
// SecKeyRef it was opened or made with until Close.
type Signer struct {
	mu     sync.Mutex
	label  string
	ref    secapi.Key
	pub    *ecdsa.PublicKey
	state  hwkey.State
	closed bool
}

var _ hwkey.Key = (*Signer)(nil)

var (
	available   = secapi.Load
	openKey     = openLabel
	generateKey = generateLabel
	hostID      = secapi.HostID
)

// only is the one key labeled label: none is ErrNotFound, two or more are a
// refusal naming the count, never the first one (as a pkcs11: reference that
// matches two keys is refused, ruling 2).
func only(label string) (secapi.Key, *ecdsa.PublicKey, error) {
	keys, err := secapi.FindKeys(label, true)
	if secapi.NotFound(err) {
		return 0, nil, fmt.Errorf("%w: %s (%v)", ErrNotFound, label, err)
	}
	if err != nil {
		return 0, nil, err
	}
	if len(keys) != 1 {
		for _, k := range keys {
			secapi.Release(k)
		}
		return 0, nil, fmt.Errorf("secureenclave: %d Secure Enclave keys are labeled %s; port49 uses one, and will not "+
			"choose: remove the others with Keychain Access", len(keys), label)
	}
	pub, err := secapi.PublicKey(keys[0])
	if err != nil {
		secapi.Release(keys[0])
		return 0, nil, err
	}
	return keys[0], pub, nil
}

func openLabel(label string) (*Signer, error) {
	ref, pub, err := only(label)
	if err != nil {
		return nil, err
	}
	return &Signer{label: label, ref: ref, pub: pub}, nil
}

// generateLabel makes a permanent key labeled label, refusing when one is
// labeled so already: two keys under one label would make every open refuse.
func generateLabel(label string) (*Signer, error) {
	keys, err := secapi.FindKeys(label, true)
	switch {
	case err == nil:
		for _, k := range keys {
			secapi.Release(k)
		}
		return nil, fmt.Errorf("secureenclave: a Secure Enclave key is already labeled %s; port49 makes a key only "+
			"under a label no key has", label)
	case !secapi.NotFound(err):
		return nil, err
	}
	ref, err := secapi.CreateKey(label, true, true)
	if err != nil {
		return nil, err
	}
	pub, err := secapi.PublicKey(ref)
	if err != nil {
		secapi.Release(ref)
		return nil, err
	}
	return &Signer{label: label, ref: ref, pub: pub}, nil
}

// Delete removes the Secure Enclave key labeled label, for the darwin test
// and an operator's own cleanup; port49's login never calls it.
func Delete(label string) error {
	if err := CheckLabel(label); err != nil {
		return err
	}
	return secapi.DeleteKeys(label, true)
}

// Label is the key's label.
func (s *Signer) Label() string { return s.label }

func (s *Signer) Public() crypto.PublicKey { return s.pub }

// Sign signs digest in the Secure Enclave. A key no longer in the keychain
// (errSecItemNotFound) is hwkey.ErrKeyAbsent and the state Absent; any other
// failure is an error naming its OSStatus, and the state is left as it was.
func (s *Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, errors.New("secureenclave: the key is closed")
	}
	sig, err := secapi.Sign(s.ref, digest, opts.HashFunc())
	if secapi.NotFound(err) {
		s.state = hwkey.Absent
		return nil, fmt.Errorf("%w: %v", hwkey.ErrKeyAbsent, err)
	}
	if err != nil {
		return nil, err
	}
	s.state = hwkey.Present
	return sig, nil
}

// State is Present, or Absent once a sign found the key gone; while Absent it
// looks again for a key with this label and this public key, so a key put
// back (a keychain restored) is seen without a sign.
func (s *Signer) State() hwkey.State {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != hwkey.Absent || s.closed {
		return s.state
	}
	ref, pub, err := only(s.label)
	if err != nil {
		return s.state
	}
	if !pub.Equal(s.pub) {
		secapi.Release(ref)
		return s.state
	}
	secapi.Release(s.ref)
	s.ref, s.state = ref, hwkey.Present
	return s.state
}

// Unlock is a no-op: the key takes no PIN. pin is zeroed.
func (s *Signer) Unlock(pin []byte) error {
	clear(pin)
	return nil
}

// Close releases the SecKeyRef; the key stays in the Secure Enclave.
func (s *Signer) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.closed = true
		secapi.Release(s.ref)
		s.ref = 0
	}
	return nil
}
