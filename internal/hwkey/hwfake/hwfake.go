// Package hwfake is a hardware key for tests that must not touch a token: an
// ECDSA key that is a hwkey.Key, names a module and a token serial as
// pkcs11.Signer does (agent.TokenKey), and lists the certificate objects its
// token would show (the attestations). It is never built into port49.
package hwfake

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"io"
	"sync"

	"github.com/blanketfish/port49/internal/hwkey"
)

// Key is a present, unlocked key on a fake token.
type Key struct {
	*ecdsa.PrivateKey
	module, serial string

	mu      sync.Mutex
	certs   []*x509.Certificate
	onSign  func() error
	signs   int
	state   hwkey.State // the zero State is Present
	closed  bool
	pinSeen int
	// pulled is a token taken out that State has not yet seen: as a PKCS#11
	// Signer's, State keeps its last state until a Probe or a Sign looks.
	pulled bool
	probes int
}

// New is k on the token serial of module.
func New(k *ecdsa.PrivateKey, module, serial string) *Key {
	return &Key{PrivateKey: k, module: module, serial: serial}
}

// SetCertificates sets the certificate objects the token lists.
func (k *Key) SetCertificates(certs ...*x509.Certificate) {
	k.mu.Lock()
	k.certs = certs
	k.mu.Unlock()
}

// OnSign sets f, which runs at the start of each Sign without the key's lock
// held: it may block (a touch not yet made) or fail (a touch that timed out,
// a key that was pulled). A nil error lets the Sign go on.
func (k *Key) OnSign(f func() error) {
	k.mu.Lock()
	k.onSign = f
	k.mu.Unlock()
}

// Signs is how many times Sign was called.
func (k *Key) Signs() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.signs
}

// Unlocks is how many times Unlock was called: a setup or status that reads
// the token must leave it at 0 (no PIN is ever given).
func (k *Key) Unlocks() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.pinSeen
}

// Sign counts the call, runs the OnSign hook and signs. A pulled token
// signs nothing: ErrKeyAbsent, and State says Absent from then on.
func (k *Key) Sign(rd io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	k.mu.Lock()
	k.signs++
	f := k.onSign
	if k.pulled {
		k.state = hwkey.Absent
		k.mu.Unlock()
		return nil, hwkey.ErrKeyAbsent
	}
	k.mu.Unlock()
	if f != nil {
		if err := f(); err != nil {
			return nil, err
		}
	}
	return k.PrivateKey.Sign(rd, digest, opts)
}

// SetState sets what State reports (Present until set).
func (k *Key) SetState(s hwkey.State) {
	k.mu.Lock()
	k.state = s
	k.mu.Unlock()
}

// State is what SetState set, Present at first.
func (k *Key) State() hwkey.State {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.state
}

// Pull takes the token out (true) or puts it back (false) without State
// seeing it, as a real token's pull is not seen until something looks. Put
// back, State stays what it last was: SetState says what the return finds.
func (k *Key) Pull(out bool) {
	k.mu.Lock()
	k.pulled = out
	k.mu.Unlock()
}

// Probe looks for the token now (hwkey.Prober): Absent while it is pulled,
// and State says so from then on; else State.
func (k *Key) Probe() hwkey.State {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.probes++
	if k.pulled {
		k.state = hwkey.Absent
	}
	return k.state
}

// Probes is how many times Probe was called.
func (k *Key) Probes() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.probes
}

// Unlock counts the PIN it was given and clears it.
func (k *Key) Unlock(pin []byte) error {
	defer clear(pin)
	k.mu.Lock()
	k.pinSeen++
	k.mu.Unlock()
	return nil
}

// Close marks the key closed.
func (k *Key) Close() error {
	k.mu.Lock()
	k.closed = true
	k.mu.Unlock()
	return nil
}

// ModulePath and TokenSerial name the fake token.
func (k *Key) ModulePath() string  { return k.module }
func (k *Key) TokenSerial() string { return k.serial }

// Certificates is the token's certificate objects.
func (k *Key) Certificates() ([]*x509.Certificate, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return append([]*x509.Certificate(nil), k.certs...), nil
}
