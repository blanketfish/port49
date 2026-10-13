package main

import (
	"bufio"
	"cmp"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/rhwendt/port49/internal/hwkey"
	"github.com/rhwendt/port49/internal/hwkey/secureenclave"
	"github.com/rhwendt/port49/internal/userconfig"
)

// heldSEPair is the held pair a named secure_enclave looks for. Off macOS, or
// in the static build, there is no label to look for: no held pair, and the
// sign-in refuses, naming why. On a Mac, a label that cannot be made is that
// error, before any sign-in prompt.
func heldSEPair(sf *sessionFlags) (issuedPair, error) {
	if seAvailable() != nil {
		return issuedPair{store: storeEncl}, nil
	}
	p, _, err := issuedTarget(storeEncl, sf)
	return p, err
}

// issuedSEKey is the sign-in's Secure Enclave key: the one labeled for this
// broker and Mac, made once when no key has the label and kept across
// sign-ins, as a token's is, so no failed sign-in costs the held pair its key.
// Keys under the label anyway are refused naming port49's way to remove them.
// Any other failure is a refusal, never another store (ruling 6).
func issuedSEKey(sf *sessionFlags) (hwkey.Key, error) {
	label, err := seLabel(sf)
	if err != nil {
		return nil, fmt.Errorf("issued_key_store is secure_enclave, and %v", err)
	}
	k, err := openSE(label)
	if errors.Is(err, secureenclave.ErrNotFound) {
		k, err = generateSELocked(sf, label)
	}
	var dup *secureenclave.DuplicateError
	if errors.As(err, &dup) {
		return nil, fmt.Errorf("issued_key_store is secure_enclave, and %s: delete them with `port49 login "+
			"--delete-key` and log in again, which makes one", strings.TrimPrefix(dup.Error(), "secureenclave: "))
	}
	if err != nil {
		return nil, fmt.Errorf("issued_key_store is secure_enclave, and the Secure Enclave refused: %w", err)
	}
	return k, nil
}

// generateSELocked makes the Secure Enclave key labeled label, holding an
// exclusive flock on <label>.lock beside the held pair in ~/.port49/issued,
// and looks for the key again once it holds the lock: two first sign-ins at
// once would otherwise both find none and make two keys under one label, which
// the keychain allows and every later open refuses. The directory is judged
// (and made 0700 if missing) before the lock file is made in it.
func generateSELocked(sf *sessionFlags, label string) (hwkey.Key, error) {
	fc, _, err := userconfig.IssuedPaths(sf.broker)
	if err != nil {
		return nil, err
	}
	dir, err := userconfig.PrivateDir(filepath.Dir(fc), "port49-issued key lock")
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, label+".lock"), os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return nil, fmt.Errorf("locking %s: %w", f.Name(), err)
	}
	defer func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }()
	k, err := openSE(label)
	if errors.Is(err, secureenclave.ErrNotFound) {
		return generateSE(label)
	}
	return k, err
}

// deleteSecureEnclaveKey is `port49 login --delete-key`: port49's own way to
// remove the Secure Enclave keys under this Mac's label for sf's broker (two
// of them refuse every sign-in), and the certificate held for them, which no
// key would open. It asks first on a terminal, as revoke does; none there is
// not a failure. The next sign-in makes one key.
func deleteSecureEnclaveKey(sf *sessionFlags, stdout, stderr io.Writer) int {
	if sf.issuedKeyStore != storeEncl {
		fmt.Fprintf(stderr, "port49 login: --delete-key deletes the key of issued_key_store: secure_enclave, and "+
			"issued_key_store is %s here\n", cmp.Or(sf.issuedKeyStore, storeAuto))
		return 2
	}
	if err := seAvailable(); err != nil {
		fmt.Fprintln(stderr, "port49 login:", err)
		return 1
	}
	pair, _, err := issuedTarget(storeEncl, sf)
	if err != nil {
		fmt.Fprintln(stderr, "port49 login:", err)
		return 1
	}
	label, err := secureenclave.ParseRef(pair.key)
	if err != nil {
		fmt.Fprintln(stderr, "port49 login:", err)
		return 1
	}
	if confirmTTY() && !confirmDeleteKey(label, stderr) {
		fmt.Fprintln(stderr, "port49 login: nothing deleted")
		return 1
	}
	switch err := deleteSE(label); {
	case errors.Is(err, secureenclave.ErrNotFound):
		fmt.Fprintf(stdout, "port49: no Secure Enclave key is labeled %s\n", label)
	case err != nil:
		fmt.Fprintln(stderr, "port49 login: deleting the Secure Enclave keys:", err)
		return 1
	default:
		fmt.Fprintf(stdout, "port49: deleted the Secure Enclave keys labeled %s\n", label)
	}
	removeIssued(pair.cert, pair.key)
	fmt.Fprintln(stdout, "port49: the next login makes one key")
	return 0
}

// confirmDeleteKey asks whether to delete the keys labeled label, in one
// line on stderr: y or yes goes on, anything else does not.
func confirmDeleteKey(label string, stderr io.Writer) bool {
	fmt.Fprintf(stderr, "delete every Secure Enclave key labeled %s, and the certificate held for it? [y/N] ", label)
	line, _ := bufio.NewReader(confirmIn).ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	}
	return false
}
