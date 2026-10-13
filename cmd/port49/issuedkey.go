package main

import (
	"cmp"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"runtime"
	"strings"

	"github.com/rhwendt/port49/internal/clientkey"
	"github.com/rhwendt/port49/internal/hwkey"
	"github.com/rhwendt/port49/internal/hwkey/tpm"
	"github.com/rhwendt/port49/internal/issuer"
	"github.com/rhwendt/port49/internal/userconfig"
)

// The stores a sign-in's key can go into (decision 45 ruling 7).
const (
	storeFile  = "file"
	storeTPM   = "tpm"
	storePKCS  = "pkcs11"
	storeAuto  = "auto"
	storeEncl  = "secure_enclave"
	tpmFileRef = "tpm:file="
)

// issuedPair is one certificate port49 issued and the key it is for: key is a
// file path (store "file") or a key reference (store "tpm" or "pkcs11").
type issuedPair struct{ store, cert, key string }

// tpmRef is the reference to the TSS2 key file at path.
func tpmRef(path string) string { return tpmFileRef + strings.ReplaceAll(path, "%", "%25") }

// saidError is a failure the login has already said in full: the caller ends
// with its code and prints nothing more.
type saidError struct{}

func (saidError) Error() string { return "" }

// heldKeyError is a held certificate whose key cannot be opened: the
// certificate is readable and is port49's, and the key is not there (a token
// out, a TPM gone) or not usable (a TPM that was cleared). The certificate is
// returned beside it.
type heldKeyError struct {
	ref string
	err error
}

func (e *heldKeyError) Error() string { return e.err.Error() }
func (e *heldKeyError) Unwrap() error { return e.err }

// absent is whether the key is out, to be put back, rather than gone for
// good: a token's key, whatever the module said, and a TPM that does not
// answer.
func (e *heldKeyError) absent() bool {
	return strings.HasPrefix(e.ref, "pkcs11:") || errors.Is(e.err, hwkey.ErrKeyAbsent)
}

// store names the key's store in the words the login uses.
func (e *heldKeyError) store() string {
	if strings.HasPrefix(e.ref, "pkcs11:") {
		return storePKCS
	}
	return storeTPM
}

// tpmUsable is whether a key can be made in this machine's TPM by this user,
// and if not, why: the TPM is Linux's, it is there and the user may open it,
// and the machine has the id its key file is named for.
func tpmUsable() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("port49 uses a TPM on Linux only, and this is %s", runtime.GOOS)
	}
	if err := tpm.Available(); err != nil {
		return err
	}
	if _, err := userconfig.MachineID(); err != nil {
		return err
	}
	return nil
}

// pkcs11Wanted is whether issued_key is a token's key `auto` may use: both
// touch_key and issued_key set, so the session key sits on the token a touch
// proves from (ruling 12), and issued_key a pkcs11: reference.
func pkcs11Wanted(sf *sessionFlags) bool {
	return sf.touchKey != "" && strings.HasPrefix(sf.issuedKey, "pkcs11:")
}

// chooseIssuedStore is the store a sign-in's key goes into (decision 45 ruling
// 7), chosen before the sign-in so a store that cannot be used costs no
// password: "file", "tpm", "secure_enclave" or "pkcs11". A named store that
// cannot be used is a refusal. `auto` passes over one that cannot be used
// and says which it took in one line; a store that is named says nothing.
func chooseIssuedStore(sf *sessionFlags, stderr io.Writer) (store string, err error) {
	switch named := cmp.Or(sf.issuedKeyStore, storeAuto); named {
	case storeFile:
		return storeFile, nil
	case storeTPM:
		if err := tpmUsable(); err != nil {
			return "", fmt.Errorf("issued_key_store is tpm, and %v", err)
		}
		return storeTPM, nil
	case storePKCS:
		switch {
		case sf.issuedKey == "":
			return "", errors.New("issued_key_store is pkcs11, and issued_key names no key: set issued_key to the " +
				"pkcs11: reference of a key you made on the token with its own tool (ykman piv keys generate); " +
				"port49 never makes a key on a token")
		case !strings.HasPrefix(sf.issuedKey, "pkcs11:"):
			return "", fmt.Errorf("issued_key_store is pkcs11, and issued_key %q is not a pkcs11: reference", sf.issuedKey)
		case !clientkey.HasPKCS11:
			return "", errors.New("issued_key_store is pkcs11, and this port49 was built without PKCS#11 support (the " +
				"static build, as in the container image); use the client release")
		}
		return storePKCS, nil
	case storeEncl:
		return "", errors.New("issued_key_store is secure_enclave, and the Secure Enclave is macOS's: this port49 " +
			"cannot keep a key there; use auto, tpm, file or pkcs11")
	}
	var passed string
	if pkcs11Wanted(sf) {
		if clientkey.HasPKCS11 {
			fmt.Fprintf(stderr, "port49 login: the key is the one issued_key names, on your token\n")
			return storePKCS, nil
		}
		passed = "this port49 was built without PKCS#11 support, so issued_key is not used; use the client release for it; "
	}
	if err := tpmUsable(); err != nil {
		fmt.Fprintf(stderr, "port49 login: %sno TPM this user can use (%v); the key is a file\n", passed, err)
		return storeFile, nil
	}
	fmt.Fprintf(stderr, "port49 login: %sthe key is made in this machine's TPM\n", passed)
	return storeTPM, nil
}

// issuedTarget is where a pair kept in store is written for broker: the
// certificate, the key file (none for a token's key: port49 writes nothing to
// the token), and the reference the agent opens the key by.
func issuedTarget(store string, sf *sessionFlags) (pair issuedPair, keyFile string, err error) {
	fc, fk, err := userconfig.IssuedPaths(sf.broker)
	if err != nil {
		return issuedPair{}, "", err
	}
	switch store {
	case storeTPM:
		tc, tk, err := userconfig.IssuedTPMPaths(sf.broker)
		if err != nil {
			return issuedPair{}, "", err
		}
		return issuedPair{storeTPM, tc, tpmRef(tk)}, tk, nil
	case storePKCS:
		return issuedPair{storePKCS, fc, sf.issuedKey}, "", nil
	}
	return issuedPair{storeFile, fc, fk}, fk, nil
}

// newIssuedKey is the sign-in's key in store: for "file" an ECDSA P-256 key
// generated in memory, written with the certificate as today; for "tpm" a key
// generated in tpmPath; for "pkcs11" the key sf.issuedKey names, which the
// user made once on the token and port49 only opens and signs with. The func
// is the key file's bytes to keep with the certificate, nil for a token's
// key. A TPM key is generated to a name of its own beside tpmPath, read, and
// removed, so a login that fails after it leaves no key file and the one
// written with the certificate goes in by the same rename order as any pair
// (the key first, the certificate last).
func newIssuedKey(store string, sf *sessionFlags, tpmPath string) (crypto.Signer, func() ([]byte, error), error) {
	switch store {
	case storeTPM:
		staged := tpmPath + ".new"
		_ = os.Remove(staged) // ours, from a login that died
		s, err := tpm.Generate(staged)
		if err != nil {
			return nil, nil, err
		}
		raw, err := os.ReadFile(staged)
		_ = os.Remove(staged)
		if err != nil {
			s.Close()
			return nil, nil, err
		}
		return s, func() ([]byte, error) { return raw, nil }, nil
	case storePKCS:
		k, err := clientkey.Open(sf.issuedKey, nil)
		if err != nil {
			return nil, nil, fmt.Errorf("issued_key %s: %s; port49 never makes a key on a token: make one with the "+
				"token's own tool (for a YubiKey, `ykman piv keys generate`) and name it with issued_key",
				pkcs11Name(sf.issuedKey), unprefixed(err))
		}
		return k, nil, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return key, func() ([]byte, error) {
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
	}, nil
}

// pkcs11Name is a pkcs11: reference with its query dropped (it may carry a
// pin-source path), for a message.
func pkcs11Name(ref string) string {
	if u, err := url.Parse(ref); err == nil && u.Opaque != "" {
		return "pkcs11:" + u.Opaque
	}
	name, _, _ := strings.Cut(ref, "?")
	return name
}

// pickHeldPair is the pair this login looks for: the file pair when its key
// is there, else this machine's TPM pair when its key file is, else, with a
// token named for the issued key, the certificate beside that reference.
// Another machine's .tpmkey is not looked at, so it reads as no pair and is
// never removed or overwritten (pre-flight I12). With none, the file pair,
// which findHeld reports as not there.
func pickHeldPair(sf *sessionFlags) (issuedPair, error) {
	fc, fk, err := userconfig.IssuedPaths(sf.broker)
	if err != nil {
		return issuedPair{}, err
	}
	if _, err := os.Lstat(fk); err == nil {
		return issuedPair{storeFile, fc, fk}, nil
	}
	if tc, tk, err := userconfig.IssuedTPMPaths(sf.broker); err == nil {
		if _, err := os.Lstat(tk); err == nil {
			return issuedPair{storeTPM, tc, tpmRef(tk)}, nil
		}
	}
	if sf.issuedKey != "" && (sf.issuedKeyStore == storePKCS || pkcs11Wanted(sf) && clientkey.HasPKCS11) {
		return issuedPair{storePKCS, fc, sf.issuedKey}, nil
	}
	return issuedPair{storeFile, fc, fk}, nil
}

// findHeld is the pair a broker issued this user, with the sign-in its
// certificate carries. None is fs.ErrNotExist; a certificate whose key cannot
// be opened comes back with a *heldKeyError and the certificate.
func findHeld(sf *sessionFlags) (issuedPair, tls.Certificate, issuer.SignIn, error) {
	pair, err := pickHeldPair(sf)
	if err != nil {
		return issuedPair{}, tls.Certificate{}, issuer.SignIn{}, err
	}
	c, s, err := heldCertificate(pair.cert, pair.key)
	return pair, c, s, err
}

// readLeaf is the first certificate of a PEM file.
func readLeaf(path string) (*x509.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	for {
		var b *pem.Block
		if b, raw = pem.Decode(raw); b == nil {
			return nil, fmt.Errorf("%s holds no PEM certificate", path)
		}
		if b.Type == "CERTIFICATE" {
			return x509.ParseCertificate(b.Bytes)
		}
	}
}

// removeIssued removes a pair that is no use again: the certificate, and the
// key when it is a file or a TPM key file. A token's key is never touched.
func removeIssued(cert, key string) {
	_ = os.Remove(cert)
	switch {
	case !hwkey.IsRef(key):
		_ = os.Remove(key)
	case strings.HasPrefix(key, tpmFileRef):
		if p, err := url.PathUnescape(strings.TrimPrefix(key, tpmFileRef)); err == nil && p != "" {
			_ = os.Remove(p)
		}
	}
}

// unlockIssuedKey asks the PIN of a held token key once, for the agent
// startIssued runs: the login opens the key, unlocks it here so a wrong PIN
// is found here and costs one try, lets go of the token, and keeps the PIN in
// sf.pin as unlockForAgent does. Any other key needs none. False is a login
// that has said why.
func unlockIssuedKey(sf *sessionFlags, ref string, stderr io.Writer) bool {
	if !strings.HasPrefix(ref, "pkcs11:") || len(sf.pin) > 0 {
		return true
	}
	k, err := clientkey.Open(ref, nil)
	if err != nil {
		fmt.Fprintln(stderr, "port49 login:", unprefixed(err))
		return false
	}
	defer k.Close()
	return unlockForAgent(sf, k, stderr)
}
