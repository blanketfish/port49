// Package keyfile loads a TLS certificate and its private key, and refuses a
// key file anyone but its owner could have read (plan 3, pre-flight F14).
//
// There are two rules, by who put the file there. A key the operator
// provisions (the broker's server key, the etcd client keys, the directory's
// keytab, the inventory service's keys) is read under the secret-file rule of
// spec §13 decision 53, fence.ReadSecret: a Kubernetes Secret volume arrives
// as name -> ..data/name behind two links, root:<fsGroup> 0440, which an
// owner-only rule can never accept. A file port49 writes itself (the issuing
// CA key, a TPM key blob, the operator's own CLI key and PIN file) keeps
// ssh's rule, ReadOwn and LoadOwnX509KeyPair: no link, owner-only, owned by the
// user or root, so a 0440 issuing CA key is refused.
package keyfile

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"github.com/rhwendt/port49/internal/fence"
)

// LoadX509KeyPair is tls.LoadX509KeyPair for an operator-provisioned pair:
// the key is read under fence.ReadSecret's rule, within the key's own
// directory (see Read). The certificate and the key are two reads, and the
// atomic writer behind a mounted volume can swap generations between them,
// which tls refuses as a mismatch: the pair is read again once, so it comes
// from one generation or not at all.
func LoadX509KeyPair(certFile, keyFile string) (tls.Certificate, error) {
	var err error
	for attempt := 0; ; attempt++ {
		var certPEM, keyPEM []byte
		if certPEM, err = readCert(certFile); err != nil {
			if attempt == 0 && errors.Is(err, fs.ErrNotExist) {
				continue // the atomic writer removed the old generation under the read
			}
			return tls.Certificate{}, err
		}
		afterCert()
		if keyPEM, err = ReadSecret(keyFile); err != nil {
			return tls.Certificate{}, err
		}
		var pair tls.Certificate
		if pair, err = tls.X509KeyPair(certPEM, keyPEM); err == nil || attempt > 0 {
			return pair, err
		}
	}
}

// readCert is os.ReadFile, swapped in tests to fail the certificate's read once.
var readCert = os.ReadFile

// afterCert runs between LoadX509KeyPair's two reads: a test seam for a swap of the volume's
// generation in between.
var afterCert = func() {}

// LoadOwnX509KeyPair is LoadX509KeyPair for a pair port49 or its operator holds for itself (the
// CLI's own client key): the key is read with ReadOwn's rule.
func LoadOwnX509KeyPair(certFile, keyFile string) (tls.Certificate, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM, err := ReadOwn(keyFile)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}

// maxKeySize bounds the read: a PEM private key is a few kilobytes at most.
const maxKeySize = 1 << 20

// geteuid is os.Geteuid, swapped in tests: CI has no second uid to own a file.
var geteuid = os.Geteuid

// ReadSecret reads an operator-provisioned secret (the directory's keytab,
// a mounted key) under the secret-file rule, fence.ReadSecret: a link is
// followed while it stays inside the file's own directory, every directory
// holding a link is held to the fence's rule, and the file must be owned by
// the user or root, writable by its owner alone, not world-readable, and, if
// group-readable, of a group this process is in. At most 1 MiB. A target that
// vanishes between the resolve and the open (the atomic writer removed the
// old generation) is resolved once more.
func ReadSecret(path string) ([]byte, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("keyfile: %w", err)
	}
	within := filepath.Dir(abs)
	b, err := fence.ReadSecret(abs, within, maxKeySize)
	if errors.Is(err, fs.ErrNotExist) {
		b, err = fence.ReadSecret(abs, within, maxKeySize)
	}
	if err != nil {
		return nil, fmt.Errorf("keyfile: %w", err)
	}
	return b, nil
}

// ReadOwn reads a file port49 writes itself, or the operator holds for
// itself: opened without following a symlink, a regular file with no group
// or other mode bit, owned by the user port49 runs as or by root (ssh's rule
// for a private key), at most 1 MiB. It is opened non-blocking, so a named
// pipe is refused rather than hanging start-up. The issuing CA's key and a
// TPM key blob are read through it.
func ReadOwn(path string) ([]byte, error) { return readPrivate(path) }

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
	if st, ok := fi.Sys().(*syscall.Stat_t); !ok {
		return nil, fmt.Errorf("keyfile: %s: cannot read the file's owner", path)
	} else if euid := geteuid(); st.Uid != uint32(euid) && st.Uid != 0 {
		return nil, fmt.Errorf("keyfile: %s is owned by uid %d; a private key must belong to the user port49 runs "+
			"as (uid %d) or to root - chown it", path, st.Uid, euid)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("keyfile: %s is mode %v; a private key must be readable by its owner alone - "+
			"chmod 600 it", path, perm)
	}
	key, err := io.ReadAll(io.LimitReader(f, maxKeySize+1))
	if err != nil {
		return nil, fmt.Errorf("keyfile: %w", err)
	}
	if len(key) > maxKeySize {
		return nil, fmt.Errorf("keyfile: %s is larger than %d bytes; it is not a private key", path, maxKeySize)
	}
	return key, nil
}
