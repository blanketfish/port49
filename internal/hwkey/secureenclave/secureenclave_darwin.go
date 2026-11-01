//go:build darwin && hwkey_dlopen

package secureenclave

import (
	"crypto"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/blanketfish/port49/internal/hwkey"
	"github.com/blanketfish/port49/internal/hwkey/secureenclave/secapi"
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
	deleteKey   = deleteLabel
)

// only is the one key labeled label: none is ErrNotFound, two or more are a
// *DuplicateError, never the first one.
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
		return 0, nil, &DuplicateError{Label: label, Count: len(keys)}
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
		// The key is kept in the keychain already: left there, every later
		// open would fail the same way, so it goes.
		secapi.Release(ref)
		if derr := secapi.DeleteKeys(label, true); derr != nil {
			return nil, fmt.Errorf("%w; and the key just made could not be deleted: %v", err, derr)
		}
		return nil, err
	}
	return &Signer{label: label, ref: ref, pub: pub}, nil
}

// deleteLabel removes every Secure Enclave key labeled label; none is
// ErrNotFound.
func deleteLabel(label string) error {
	err := secapi.DeleteKeys(label, true)
	if secapi.NotFound(err) {
		return fmt.Errorf("%w: %s (%v)", ErrNotFound, label, err)
	}
	return err
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
	if opts == nil {
		return nil, errors.New("secureenclave: Sign needs the digest's hash in opts")
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
