package agent

import (
	"crypto"
	"errors"
	"io"
	"sync"

	"github.com/rhwendt/port49/internal/hwkey"
)

// KeyError is a failed use of the session's hardware key: a touch that did
// not come in time, a key that wants its PIN, or a key that is gone. It is not
// the broker's failure and not the network's, so it is never retried (a retry
// would blink the key again for a touch nobody was there for) and never read
// as an outage. It ends nothing: the operator touches, unlocks or plugs in
// the key and asks again.
//
// Err is the hwkey sentinel (possibly wrapped), so errors.Is finds it. On the
// socket the error travels as its own code (KeyCode), and the client rebuilds
// it with the agent's words in text.
type KeyError struct {
	Err  error
	text string
}

func (e *KeyError) Error() string {
	if e.text != "" {
		return e.text
	}
	words := "agent: " + e.Err.Error()
	if errors.Is(e.Err, hwkey.ErrLocked) {
		words += "; run `port49 login` to give the key its PIN"
	}
	return words
}

func (e *KeyError) Unwrap() error { return e.Err }

// Socket codes for a KeyError, snake_case like the socket's others.
const (
	codeTouchTimeout = "touch_timeout"
	codeKeyLocked    = "key_locked"
	codeKeyAbsent    = "key_absent"
)

// keyFault is the sentinel err carries when it is one of the three failures
// of the key a KeyError reports, and nil for any other error.
func keyFault(err error) error {
	for _, s := range []error{hwkey.ErrTouchTimeout, hwkey.ErrLocked, hwkey.ErrKeyAbsent} {
		if errors.Is(err, s) {
			return s
		}
	}
	return nil
}

// KeyCode is the socket code for a KeyError, or "" for any other error.
func KeyCode(err error) string {
	var ke *KeyError
	if !errors.As(err, &ke) {
		return ""
	}
	switch {
	case errors.Is(ke.Err, hwkey.ErrTouchTimeout):
		return codeTouchTimeout
	case errors.Is(ke.Err, hwkey.ErrLocked):
		return codeKeyLocked
	case errors.Is(ke.Err, hwkey.ErrKeyAbsent):
		return codeKeyAbsent
	}
	return ""
}

// keyErrorFromCode rebuilds a KeyError from the socket's code and the agent's
// words; nil for a code that is not one of the three.
func keyErrorFromCode(code, detail string) error {
	var s error
	switch code {
	case codeTouchTimeout:
		s = hwkey.ErrTouchTimeout
	case codeKeyLocked:
		s = hwkey.ErrLocked
	case codeKeyAbsent:
		s = hwkey.ErrKeyAbsent
	default:
		return nil
	}
	return &KeyError{Err: s, text: detail}
}

// signRecorder wraps the key the TLS handshake signs with and remembers its
// last Sign error. crypto/tls flattens a signer's error to text, so the
// dialer reads the error here instead of matching words. The error is held
// only until the next success or the next dial and is never logged by the
// recorder; what the caller does with its message is the caller's.
type signRecorder struct {
	crypto.Signer
	mu   sync.Mutex
	last error
}

func (r *signRecorder) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	sig, err := r.Signer.Sign(rand, digest, opts)
	r.mu.Lock()
	r.last = err // nil on success clears an earlier failure
	r.mu.Unlock()
	return sig, err
}

// reset forgets the last error: a new dial attributes nothing to an old Sign.
func (r *signRecorder) reset() {
	r.mu.Lock()
	r.last = nil
	r.mu.Unlock()
}

// keyError is the *KeyError for the last Sign error when it is one of the
// three key failures, else nil.
func (r *signRecorder) keyError() error {
	r.mu.Lock()
	err := r.last
	r.mu.Unlock()
	if keyFault(err) == nil {
		return nil
	}
	return &KeyError{Err: err}
}
