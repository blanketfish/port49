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
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/clientkey"
	"github.com/rhwendt/port49/internal/hwkey"
	"github.com/rhwendt/port49/internal/hwkey/pkcs11"
	"github.com/rhwendt/port49/internal/hwkey/tpm"
	"github.com/rhwendt/port49/internal/issuer"
	"github.com/rhwendt/port49/internal/printsafe"
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

// generateTPM is tpm.Generate, a var so a test makes the TPM fail as it
// chooses.
var generateTPM = tpm.Generate

// tpmRefused is a TPM that is absent or will not make a key, the one failure
// `auto` goes on from to a file (decision 45 ruling 7); any other is an error.
type tpmRefused struct{ err error }

func (e *tpmRefused) Error() string { return e.err.Error() }
func (e *tpmRefused) Unwrap() error { return e.err }

// ignoredClause is what `auto` says it passed over, to lead the store's line:
// "" when it passed over nothing. It passes over a token's issued_key in the
// static build, and a lone issued_key, one without touch_key, in any build.
func ignoredClause(sf *sessionFlags) string {
	switch {
	case !strings.HasPrefix(sf.issuedKey, "pkcs11:"):
		return ""
	case sf.touchKey == "":
		return "issued_key is used only with touch_key, or with issued_key_store: pkcs11; "
	case !clientkey.HasPKCS11:
		return "this port49 was built without PKCS#11 support, so issued_key is not used; use the client release for it; "
	}
	return ""
}

// fileKeyPath is where a file key for sf's broker goes, for a message.
func fileKeyPath(sf *sessionFlags) string {
	if _, fk, err := userconfig.IssuedPaths(sf.broker); err == nil {
		return fk
	}
	return "its .key file"
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
// cannot be used is a refusal. `auto` that passes over a store and takes a
// file says why and which file in one line, here; when it takes the TPM or the
// token the line is the caller's, said once the key is made, so a TPM that
// then refuses to make one does not leave two lines that contradict. A store
// that is named says nothing.
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
	if pkcs11Wanted(sf) && clientkey.HasPKCS11 {
		fmt.Fprintf(stderr, "port49 login: the key is the one issued_key names, on your token\n")
		return storePKCS, nil
	}
	if err := tpmUsable(); err != nil {
		fmt.Fprintf(stderr, "port49 login: %sno TPM this user can use (%v); the key is a file (%s)\n",
			ignoredClause(sf), err, fileKeyPath(sf))
		return storeFile, nil
	}
	return storeTPM, nil
}

// tpmRefusalAdvice is what to do about a TPM that refused to make a key, by
// the cause: an owner password is cleared (or the store is not named), a
// lockout is waited out or reset, a device that is missing or closed to the
// user is named with its group.
func tpmRefusalAdvice(err error) string {
	switch tpm.RefusalOf(err) {
	case tpm.RefusedOwnerAuth:
		return "the owner hierarchy has a password, which port49 does not supply: clear it with the TPM's own tools, " +
			"or use issued_key_store: auto or file"
	case tpm.RefusedLockout:
		return "the TPM is in dictionary-attack lockout: wait for it to clear, or reset it with `tpm2_dictionarylockout -c`"
	case tpm.RefusedDevice:
		return fmt.Sprintf("the TPM device %s is missing, has stopped answering, or this user may not open it: "+
			"check that it is there and that this user is in the tss group", tpm.DevicePath)
	}
	return unprefixed(err)
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
		tc, err := tokenTarget(sf)
		if err != nil {
			return issuedPair{}, "", err
		}
		return issuedPair{storePKCS, tc, sf.issuedKey}, "", nil
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
		// A name of this login's own, so two logins on one machine never
		// remove each other's. Generate wants a path that does not exist.
		f, err := os.CreateTemp(filepath.Dir(tpmPath), filepath.Base(tpmPath)+".new-*")
		if err != nil {
			return nil, nil, err
		}
		staged := f.Name()
		f.Close()
		_ = os.Remove(staged)
		s, err := generateTPM(staged)
		if err != nil {
			if tpm.Refused(err) {
				return nil, nil, &tpmRefused{err}
			}
			return nil, nil, fmt.Errorf("the TPM could not make a key: %w", err)
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
		if errors.Is(err, hwkey.ErrKeyAbsent) {
			// Out, not missing: the slot may hold the key, and generating one
			// there would replace it. With other tokens in, the reference may be
			// the thing that is wrong, and they are named so the difference is
			// seen (label, serial and manufacturer only).
			var nm *hwkey.NoMatchError
			if errors.As(err, &nm) && len(nm.Present) > 0 {
				return nil, nil, fmt.Errorf("issued_key: no token present matches %s (present: %s); the reference may be wrong, "+
					"or insert the token holding it and log in again", pkcs11Name(sf.issuedKey), presentTokens(nm.Present))
			}
			return nil, nil, fmt.Errorf("issued_key: the token is not present: insert the token holding %s and log in again",
				pkcs11Name(sf.issuedKey))
		}
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

// presentTokens lists tokens for a message, each as the selectors a pkcs11:
// reference would use. The fields come from the device, so they are printed
// safe.
func presentTokens(ts []hwkey.TokenInfo) string {
	parts := make([]string, len(ts))
	for i, t := range ts {
		parts[i] = fmt.Sprintf("token=%s serial=%s manufacturer=%s", printsafe.Line(t.Label, 64),
			printsafe.Line(t.Serial, 32), printsafe.Line(t.Manufacturer, 64))
	}
	return strings.Join(parts, "; ")
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

// tokenKeyName is the canonical form of an issued_key reference, without its
// query (which may carry a module path or a pin-source): one key in any
// spelling, so a changed spelling does not cost a sign-in. A reference that
// does not parse (Open would refuse it) is named as written.
func tokenKeyName(ref string) string {
	if u, err := pkcs11.ParseURI(ref); err == nil {
		name, _, _ := strings.Cut(u.String(), "?")
		return name
	}
	return pkcs11Name(ref)
}

// tokenTarget is the certificate kept for the token key sf.issuedKey names,
// named for the key (decision 45 ruling 7, amended): its canonical pkcs11:
// name without the query.
func tokenTarget(sf *sessionFlags) (string, error) {
	return userconfig.IssuedTokenPaths(sf.broker, tokenKeyName(sf.issuedKey))
}

// pickHeldPair is the pair this login looks for. When issued_key_store names a
// store, only that store's pair (decision 45 ruling 7, amended): a named tpm
// host with no TPM pair of its own is not run on the file .key, which is the
// operator's choice of hardware bypassed, and a pair that is not there reads
// as no held pair (a sign-in). Under `auto`, the pair of the store `auto`
// would choose now: the token's certificate when a token is wanted and that
// file is there, else this machine's TPM pair when the TPM is usable and its
// key file is there, unless that pair would need a sign-in and the file pair
// would need less, else the file pair when its key is. The
// unnamed .key comes last: on a home shared by a TPM host and a file host it
// is the file host's, and the TPM host must not pick it up or remove it, or
// each sign-in of one forces the other to sign in. Another machine's .tpmkey
// is not looked at, so it reads as no pair and is never removed or overwritten
// (pre-flight I12). With none, the file pair, which findHeld reports as not
// there.
func pickHeldPair(sf *sessionFlags) (issuedPair, error) {
	fc, fk, err := userconfig.IssuedPaths(sf.broker)
	if err != nil {
		return issuedPair{}, err
	}
	// A TPM pair whose key file is not there carries the plain path, not a
	// reference, so findHeld reads it as no held pair.
	tpmPair := func() issuedPair {
		tc, tk, err := userconfig.IssuedTPMPaths(sf.broker)
		if err != nil {
			return issuedPair{store: storeTPM}
		}
		if _, err := os.Lstat(tk); err != nil {
			return issuedPair{storeTPM, tc, tk}
		}
		return issuedPair{storeTPM, tc, tpmRef(tk)}
	}
	tokenPair := func() (issuedPair, error) {
		tc, err := tokenTarget(sf)
		if err != nil {
			return issuedPair{}, err
		}
		return issuedPair{storePKCS, tc, sf.issuedKey}, nil
	}
	switch sf.issuedKeyStore {
	case storeTPM:
		return tpmPair(), nil
	case storePKCS:
		if sf.issuedKey == "" {
			return issuedPair{store: storePKCS}, nil
		}
		return tokenPair()
	case storeFile, storeEncl:
		return issuedPair{storeFile, fc, fk}, nil
	}
	// The pair of the store `auto` would choose now comes first, or a host
	// whose old pair is not usable signs in at every login: the token when it
	// is wanted and its certificate is there, then the TPM when it is usable.
	if pkcs11Wanted(sf) && clientkey.HasPKCS11 {
		p, err := tokenPair()
		if err != nil {
			return issuedPair{}, err
		}
		if _, err := os.Lstat(p.cert); err == nil {
			return p, nil
		}
	}
	// A TPM pair that would need a sign-in anyway gives way to a file pair
	// that needs less: a TPM that opens but will not make a key leaves the
	// file pair `auto` fell back to, and taking the stale TPM pair again would
	// sign in at every login (task 7 A3). When the file pair needs a sign-in
	// too, the TPM pair is kept, and that sign-in tries the TPM again.
	file := issuedPair{storeFile, fc, fk}
	if tpmUsable() == nil {
		if p := tpmPair(); hwkey.IsRef(p.key) {
			now := time.Now()
			if s := heldStanding(p, now); s == heldValid || s >= heldStanding(file, now) {
				return p, nil
			}
		}
	}
	return file, nil
}

// How much a held pair is worth to a login: none (not there, not loadable, or
// expired), a certificate in late renewal, which signs in but is used if the
// sign-in fails, or a valid one, used with no sign-in. These are the tests
// login makes of the pair it holds.
const (
	heldNone = iota
	heldLate
	heldValid
)

func heldStanding(p issuedPair, now time.Time) int {
	c, _, err := heldCertificate(p.cert, p.key)
	switch {
	case err != nil || !now.Before(c.Leaf.NotAfter):
		return heldNone
	case api.LateRenewal(c.Leaf, now):
		return heldLate
	}
	return heldValid
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
