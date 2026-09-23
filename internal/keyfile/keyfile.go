// Package keyfile loads a TLS certificate and its private key, and refuses a
// key file anyone but its owner could have read (plan 3, pre-flight F14). The
// broker's server key and the operator's client key are both read through it.
package keyfile

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
)

// LoadX509KeyPair is tls.LoadX509KeyPair with the key file's own checks: it is
// opened without following a symlink — whoever can plant one decides what
// port49 loads — and it must be a regular file with no group or other
// permission bits, which is ssh's rule for a private key. It is opened
// non-blocking too, so a named pipe is refused rather than hanging start-up
// until something writes to it.
func LoadX509KeyPair(certFile, keyFile string) (tls.Certificate, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM, err := readPrivate(keyFile)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}

func readPrivate(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, syscall.ELOOP) {
		return nil, fmt.Errorf("keyfile: %s: %w (a symlink is refused: name the key file itself)", path, err)
	}
	if err != nil {
		return nil, fmt.Errorf("keyfile: %w", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("keyfile: %s is not a regular file", path)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("keyfile: %s is mode %v; a private key must be readable by its owner alone - "+
			"chmod 600 it", path, perm)
	}
	return io.ReadAll(f)
}
