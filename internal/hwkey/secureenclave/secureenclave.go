// Package secureenclave is a client key in the macOS Secure Enclave, through
// Security.framework under purego (plan 9c, decision 45 ruling 6). It is
// experimental and opt-in: it was built without a Mac to run it on, and L63
// (whether an unsigned port49 may make and keep such a key at all) is open.
// It is chosen only by name, a secure-enclave:label=NAME reference or
// issued_key_store: secure_enclave, and a process that opens or makes a key
// says so in one line, once. Every Security.framework failure is a refusal
// naming its OSStatus; nothing here falls back to another store.
//
// The backend is secureenclave_darwin.go, built on macOS under hwkey_dlopen
// (ruling 22); everywhere else secureenclave_other.go refuses. The calls
// themselves are in secapi, which the L63 spike shares.
package secureenclave

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
)

// RefPrefix starts every Secure Enclave key reference (ruling 2: the scheme is
// secure-enclave: while the config word is secure_enclave).
const RefPrefix = "secure-enclave:"

// maxLabel bounds a label: a broker's host and port, a machine name and
// port49's prefix fit with room to spare.
const maxLabel = 255

// ExperimentalWords is the line the first open or generate in a process
// prints (ruling 6).
const ExperimentalWords = "the Secure Enclave backend is experimental and untested (L63); report results at the " +
	"port49 issue tracker"

// Warnings is where ExperimentalWords goes: the process's stderr.
var Warnings io.Writer = os.Stderr

// ErrNotFound is no Secure Enclave key having the label (errSecItemNotFound
// at an open). It is not hwkey.ErrKeyAbsent: a key that is not there is to be
// made, not plugged in.
var ErrNotFound = errors.New("secureenclave: no Secure Enclave key has this label")

// CheckLabel refuses a label that is not 1 to 255 of A-Z, a-z, 0-9, '.', '_'
// and '-': a plain name, which needs no escaping in a reference and cannot
// carry a second attribute or a query.
func CheckLabel(label string) error {
	if label == "" || len(label) > maxLabel || strings.IndexFunc(label, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-')
	}) >= 0 {
		return fmt.Errorf("secureenclave: a Secure Enclave label is 1 to %d of A-Z, a-z, 0-9, '.', '_' and '-'", maxLabel)
	}
	return nil
}

// ParseRef is the label a secure-enclave:label=NAME reference names.
func ParseRef(ref string) (string, error) {
	spec, ok := strings.CutPrefix(ref, RefPrefix)
	name, label, isAttr := strings.Cut(spec, "=")
	if !ok || !isAttr || name != "label" {
		return "", errors.New("secureenclave: a Secure Enclave key is secure-enclave:label=NAME")
	}
	if err := CheckLabel(label); err != nil {
		return "", err
	}
	return label, nil
}

// Ref is the reference to the key labeled label.
func Ref(label string) string { return RefPrefix + "label=" + label }

// Available is nil when this build on this system can use the Secure Enclave:
// macOS, in the client build, with Security.framework loaded. Otherwise it
// is why not.
func Available() error { return available() }

// HostID is this Mac's 8-hex-digit name for a per-machine label (ruling 7):
// the first 8 hex digits of the SHA-256 of its host UUID.
func HostID() (string, error) { return hostID() }

// Open opens the Secure Enclave key labeled label. None is ErrNotFound.
func Open(label string) (*Signer, error) {
	if err := CheckLabel(label); err != nil {
		return nil, err
	}
	if err := available(); err != nil {
		return nil, err
	}
	sayExperimental()
	return openKey(label)
}

// Generate makes a permanent P-256 key labeled label in the Secure Enclave,
// refusing when a key has that label already.
func Generate(label string) (*Signer, error) {
	if err := CheckLabel(label); err != nil {
		return nil, err
	}
	if err := available(); err != nil {
		return nil, err
	}
	sayExperimental()
	return generateKey(label)
}

// experimental is ExperimentalWords said once per process (ruling 6): a login
// that opens the held key, opens it again and makes one says it once, and the
// agent, its own process, once in its log. A pointer, so a test starts afresh.
var experimental = new(sync.Once)

func sayExperimental() {
	experimental.Do(func() { fmt.Fprintln(Warnings, ExperimentalWords) })
}

// DuplicateError is Count keys, two or more, under Label: refused, never a
// choice of one (as a pkcs11: reference that matches two keys is refused,
// ruling 2). The caller that knows whose label it is names how to remove them.
type DuplicateError struct {
	Label string
	Count int
}

func (e *DuplicateError) Error() string {
	return fmt.Sprintf("secureenclave: %d Secure Enclave keys are labeled %s; port49 uses one, and will not choose",
		e.Count, e.Label)
}

// Delete removes every Secure Enclave key labeled label. None is ErrNotFound.
// port49's sign-in never calls it; `port49 login --delete-key` does.
func Delete(label string) error {
	if err := CheckLabel(label); err != nil {
		return err
	}
	if err := available(); err != nil {
		return err
	}
	return deleteKey(label)
}

// platformRefusal is why goos, in a build without the darwin backend, cannot
// use the Secure Enclave: it is macOS's, or on macOS this is the static build
// (ruling 22).
func platformRefusal(goos string) error {
	if goos == "darwin" {
		return errors.New("secureenclave: this port49 was built without Secure Enclave support (the static build); " +
			"use the client release")
	}
	return fmt.Errorf("secureenclave: the Secure Enclave is macOS's, and this is %s", goos)
}
