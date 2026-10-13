// Package hwkey is the one shape every hardware-backed client key has: a
// crypto.Signer that says whether it can sign now, takes a PIN, and lets go
// of its token (plan 9c, ruling 1). It is a leaf: the backends (pkcs11, tpm,
// secureenclave) import it for State, the errors and PINError, and the opener
// that dispatches to them is internal/clientkey.
package hwkey

import (
	"crypto"
	"errors"
	"strings"
)

// State is whether a key can sign now.
type State int

const (
	Present State = iota // the key signs
	Absent               // the token or TPM is gone; insert it
	Locked               // the token is back and needs its PIN (Unlock)
)

func (s State) String() string {
	switch s {
	case Present:
		return "present"
	case Absent:
		return "absent"
	case Locked:
		return "locked"
	}
	return "unknown"
}

// Key is every hardware key: a crypto.Signer that says whether it can sign
// now, takes a PIN, and lets go of its token.
type Key interface {
	crypto.Signer
	State() State
	Unlock(pin []byte) error
	Close() error
}

var (
	ErrKeyAbsent = errors.New("hwkey: the key is not present")
	ErrLocked    = errors.New("hwkey: the key needs its PIN")

	// ErrTouchTimeout is a touch-policy key that was not touched in time. The
	// key stays unlocked: the PIN is not the problem and the next Sign may try
	// again.
	ErrTouchTimeout = errors.New("hwkey: no touch within 15s; touch the key when it blinks and try again")
)

// PINError is a PIN the token refused. Low and Final are the token's own
// flags (CKF_USER_PIN_COUNT_LOW, CKF_USER_PIN_FINAL_TRY). Blocked is the
// token's CKF_USER_PIN_LOCKED: the PIN can take no more tries, this one
// included, and only the token's own unblock procedure (its PUK) clears it.
// A blocked PIN is never an invitation to try again.
type PINError struct{ Low, Final, Blocked bool }

func (e *PINError) Error() string {
	switch {
	case e.Blocked:
		return "hwkey: the key's PIN is blocked; unblock it with its PUK before trying again"
	case e.Final:
		return "hwkey: the token refused the PIN; one try left before the key locks"
	case e.Low:
		return "hwkey: the token refused the PIN; few tries are left before the key locks"
	}
	return "hwkey: the token refused the PIN"
}

// TokenInfo is the public description of a token that is present: what its
// own fields say, never a PIN or an object.
type TokenInfo struct{ Label, Serial, Manufacturer string }

// NoMatchError is a key reference that no present token matches, with the
// tokens that are present (none when none is in any slot). It is
// ErrKeyAbsent: the key is to be put back, or the reference is wrong.
type NoMatchError struct{ Present []TokenInfo }

func (e *NoMatchError) Error() string { return ErrKeyAbsent.Error() }
func (e *NoMatchError) Unwrap() error { return ErrKeyAbsent }

// PINBlockedWords is what the operator is told when a PIN is blocked: the way
// out, and that another try is not it.
const PINBlockedWords = "the key's PIN is blocked; unblock it with its PUK (ykman piv access unblock-pin) before trying again"

// Blocker is a key that can say its token's PIN is blocked (pkcs11.Signer).
type Blocker interface{ PINBlocked() bool }

// MarkBlocked sets Blocked on err's *PINError when k reports its PIN blocked,
// which the token says (CKF_USER_PIN_LOCKED) both when a login is refused as
// CKR_PIN_LOCKED and when the wrong PIN that just failed was the last try.
// It returns err's PINError, or nil when err is not one.
func MarkBlocked(k any, err error) *PINError {
	var pe *PINError
	if !errors.As(err, &pe) {
		return nil
	}
	if b, ok := k.(Blocker); ok && b.PINBlocked() {
		pe.Blocked = true
	}
	return pe
}

// IsRef reports whether s is a key reference (pkcs11:, tpm:, secure-enclave:)
// rather than a path.
func IsRef(s string) bool {
	for _, p := range []string{"pkcs11:", "tpm:", "secure-enclave:"} {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}
