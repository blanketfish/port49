//go:build hwkey_dlopen

package clientkey

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/rhwendt/port49/internal/hwkey"
	"github.com/rhwendt/port49/internal/hwkey/pkcs11"
	"github.com/rhwendt/port49/internal/keyfile"
)

// HasPKCS11 is whether this build carries the purego backends (the
// hwkey_dlopen tag, ruling 22): true here.
const HasPKCS11 = true

// maxPINSource bounds a pin-source file: a PIN is at most 64 bytes.
const maxPINSource = 64

func openToken(ref string, pin []byte) (hwkey.Key, error) {
	if strings.HasPrefix(ref, "secure-enclave:") {
		clear(pin)
		return nil, errors.New("clientkey: secure-enclave: keys arrive with plan 9c's Task 14, behind its gate; " +
			"this build cannot open one yet")
	}
	u, err := pkcs11.ParseURI(ref)
	if err != nil {
		clear(pin)
		return nil, fmt.Errorf("clientkey: %w", err)
	}
	// A PIN given wins over the file the URI names.
	if len(pin) == 0 && u.PINSource != "" {
		if pin, err = readPINSource(u.PINSource); err != nil {
			return nil, err
		}
	}
	s, err := pkcs11.Open(u, pin)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// readPINSource reads the PIN from the file a pin-source file:///path names,
// through keyfile.ReadSecret's checks (owner-only, no symlink).
func readPINSource(src string) ([]byte, error) {
	pu, err := url.Parse(src)
	if err != nil || pu.Scheme != "file" || pu.Path == "" {
		return nil, fmt.Errorf("clientkey: pin-source %q: it is file:///path", src)
	}
	raw, err := keyfile.ReadSecret(pu.Path)
	if err != nil {
		return nil, fmt.Errorf("clientkey: pin-source: %w", err)
	}
	pin := bytes.TrimRight(raw, "\r\n")
	if len(pin) == 0 || len(pin) > maxPINSource {
		clear(raw)
		return nil, fmt.Errorf("clientkey: pin-source %s holds no PIN of 1 to %d bytes", pu.Path, maxPINSource)
	}
	return pin, nil
}
