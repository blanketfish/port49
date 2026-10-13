//go:build !darwin || !hwkey_dlopen

package secureenclave

import (
	"runtime"

	"github.com/rhwendt/port49/internal/hwkey"
)

// Signer is never made in this build: Open and Generate refuse. It embeds a
// hwkey.Key only so a test can stand one in for a Mac's.
type Signer struct{ hwkey.Key }

var (
	available   = func() error { return platformRefusal(runtime.GOOS) }
	openKey     = func(string) (*Signer, error) { return nil, available() }
	generateKey = func(string) (*Signer, error) { return nil, available() }
	hostID      = func() (string, error) { return "", available() }
	deleteKey   = func(string) error { return available() }
)
