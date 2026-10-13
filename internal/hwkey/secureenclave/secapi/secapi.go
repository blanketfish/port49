//go:build darwin

// Package secapi is the Security.framework and CoreFoundation calls a Secure
// Enclave key needs, through purego with no cgo (decision 45 ruling 6). It is
// one set of registrations shared by the backend (internal/hwkey/secureenclave,
// which imports it only under hwkey_dlopen, so the static build carries no
// purego: ruling 22) and the L63 spike (tests/spike/secureenclave, which a Mac
// user runs with a plain `go run`, no tag).
//
// It is written without a Mac to run it on. Every registration below cites the
// header it follows; a CFTypeRef is a uintptr, and the Create and Copy rule
// decides which ones this package releases: a function named Create or Copy
// hands its caller a reference to release, and so does a CFErrorRef out
// parameter; a Get function or a constant is never released.
package secapi

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
)

// OSStatus values port49 reads (Security/SecBase.h).
const (
	ErrSecItemNotFound       = -25300 // errSecItemNotFound
	ErrSecDuplicateItem      = -25299 // errSecDuplicateItem
	ErrSecMissingEntitlement = -34018 // errSecMissingEntitlement
)

// Error is a Security.framework failure: the OSStatus (or a CFError's code,
// which for these calls is the OSStatus) and the system's description of it.
type Error struct {
	Op          string
	Code        int64
	Description string
}

func (e *Error) Error() string {
	return fmt.Sprintf("secureenclave: %s: OSStatus %d %s", e.Op, e.Code, e.Description)
}

// NotFound is whether err is errSecItemNotFound: no key has the label.
func NotFound(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Code == ErrSecItemNotFound
}

// CoreFoundation constants (CFString.h, CFNumber.h).
const (
	kCFStringEncodingUTF8 = 0x08000100 // CFStringBuiltInEncodings
	kCFNumberSInt32Type   = 3          // CFNumberType
)

// kSecAccessControlPrivateKeyUsage is SecAccessControlCreateFlags 1<<30
// (Security/SecAccessControl.h): the key may sign, the one use the Secure
// Enclave requires its keys to name.
const kSecAccessControlPrivateKeyUsage = 1 << 30

const (
	securityPath       = "/System/Library/Frameworks/Security.framework/Security"
	coreFoundationPath = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
	libSystemPath      = "/usr/lib/libSystem.B.dylib"
)

// The functions, each with the C prototype it is registered from. CFIndex is
// signed long and CFOptionFlags unsigned long: eight bytes on macOS's arm64
// and amd64, so int and uint. CFStringEncoding and OSStatus are 32-bit, and
// Boolean (MacTypes.h) is an unsigned char, so uint8.
var (
	// CoreFoundation/CFBase.h: void CFRelease(CFTypeRef cf);
	cfRelease func(cf uintptr)
	// CoreFoundation/CFBase.h: CFTypeRef CFRetain(CFTypeRef cf);
	cfRetain func(cf uintptr) uintptr
	// CoreFoundation/CFDictionary.h: CFMutableDictionaryRef CFDictionaryCreateMutable(
	//   CFAllocatorRef allocator, CFIndex capacity,
	//   const CFDictionaryKeyCallBacks *keyCallBacks, const CFDictionaryValueCallBacks *valueCallBacks);
	cfDictionaryCreateMutable func(allocator uintptr, capacity int, keyCallBacks, valueCallBacks uintptr) uintptr
	// CoreFoundation/CFDictionary.h: void CFDictionarySetValue(CFMutableDictionaryRef theDict,
	//   const void *key, const void *value);
	cfDictionarySetValue func(dict, key, value uintptr)
	// CoreFoundation/CFString.h: CFStringRef CFStringCreateWithCString(CFAllocatorRef alloc,
	//   const char *cStr, CFStringEncoding encoding);
	cfStringCreateWithCString func(alloc uintptr, cStr string, encoding uint32) uintptr
	// CoreFoundation/CFString.h: Boolean CFStringGetCString(CFStringRef theString, char *buffer,
	//   CFIndex bufferSize, CFStringEncoding encoding);
	cfStringGetCString func(s uintptr, buffer *byte, bufferSize int, encoding uint32) uint8
	// CoreFoundation/CFNumber.h: CFNumberRef CFNumberCreate(CFAllocatorRef allocator,
	//   CFNumberType theType, const void *valuePtr);
	cfNumberCreate func(allocator uintptr, theType int, valuePtr *int32) uintptr
	// CoreFoundation/CFData.h: CFDataRef CFDataCreate(CFAllocatorRef allocator, const UInt8 *bytes,
	//   CFIndex length);
	cfDataCreate func(allocator uintptr, bytes *byte, length int) uintptr
	// CoreFoundation/CFData.h: CFIndex CFDataGetLength(CFDataRef theData);
	cfDataGetLength func(data uintptr) int
	// CoreFoundation/CFData.h: const UInt8 *CFDataGetBytePtr(CFDataRef theData);
	cfDataGetBytePtr func(data uintptr) *byte
	// CoreFoundation/CFArray.h: CFIndex CFArrayGetCount(CFArrayRef theArray);
	cfArrayGetCount func(array uintptr) int
	// CoreFoundation/CFArray.h: const void *CFArrayGetValueAtIndex(CFArrayRef theArray, CFIndex idx);
	cfArrayGetValueAtIndex func(array uintptr, idx int) uintptr
	// CoreFoundation/CFError.h: CFIndex CFErrorGetCode(CFErrorRef err);
	cfErrorGetCode func(err uintptr) int
	// CoreFoundation/CFError.h: CFStringRef CFErrorCopyDescription(CFErrorRef err);
	cfErrorCopyDescription func(err uintptr) uintptr

	// Security/SecKey.h: SecKeyRef SecKeyCreateRandomKey(CFDictionaryRef parameters, CFErrorRef *error);
	secKeyCreateRandomKey func(parameters uintptr, cfErr *uintptr) uintptr
	// Security/SecKey.h: SecKeyRef SecKeyCopyPublicKey(SecKeyRef key);
	secKeyCopyPublicKey func(key uintptr) uintptr
	// Security/SecKey.h: CFDataRef SecKeyCopyExternalRepresentation(SecKeyRef key, CFErrorRef *error);
	secKeyCopyExternalRepresentation func(key uintptr, cfErr *uintptr) uintptr
	// Security/SecKey.h: CFDataRef SecKeyCreateSignature(SecKeyRef key, SecKeyAlgorithm algorithm,
	//   CFDataRef dataToSign, CFErrorRef *error);  (SecKeyAlgorithm is a CFStringRef)
	secKeyCreateSignature func(key, algorithm, dataToSign uintptr, cfErr *uintptr) uintptr
	// Security/SecItem.h: OSStatus SecItemCopyMatching(CFDictionaryRef query, CFTypeRef *result);
	secItemCopyMatching func(query uintptr, result *uintptr) int32
	// Security/SecItem.h: OSStatus SecItemDelete(CFDictionaryRef query);
	secItemDelete func(query uintptr) int32
	// Security/SecAccessControl.h: SecAccessControlRef SecAccessControlCreateWithFlags(
	//   CFAllocatorRef allocator, CFTypeRef protection, SecAccessControlCreateFlags flags, CFErrorRef *error);
	//   (SecAccessControlCreateFlags is CFOptionFlags)
	secAccessControlCreateWithFlags func(allocator, protection uintptr, flags uint, cfErr *uintptr) uintptr
	// Security/SecBase.h: CFStringRef SecCopyErrorMessageString(OSStatus status, void *reserved);
	secCopyErrorMessageString func(status int32, reserved uintptr) uintptr

	// unistd.h: int gethostuuid(uuid_t id, const struct timespec *wait);  (uuid_t is unsigned char[16])
	gethostuuid func(id *[16]byte, wait *timespec) int32
)

// timespec is struct timespec on macOS's LP64: time_t and long.
type timespec struct{ sec, nsec int64 }

// The constants, read through purego.Dlsym. Each is an `extern const
// CFStringRef` (or CFBooleanRef) in the header named: Dlsym gives the address
// of the variable, which holds the reference.
var (
	// CoreFoundation/CFNumber.h: const CFBooleanRef kCFBooleanTrue, kCFBooleanFalse;
	kCFBooleanTrue, kCFBooleanFalse uintptr
	// CoreFoundation/CFDictionary.h: const CFDictionaryKeyCallBacks kCFTypeDictionaryKeyCallBacks;
	// const CFDictionaryValueCallBacks kCFTypeDictionaryValueCallBacks;  (structs: their addresses
	// are what CFDictionaryCreateMutable takes, so these are not dereferenced)
	kCFTypeDictionaryKeyCallBacks, kCFTypeDictionaryValueCallBacks uintptr

	// Security/SecItem.h (kSecUseDataProtectionKeychain since macOS 10.15)
	kSecClass, kSecClassKey, kSecAttrKeyClass, kSecAttrKeyClassPrivate, kSecAttrKeyType,
	kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeySizeInBits, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave,
	kSecAttrIsPermanent, kSecAttrLabel, kSecPrivateKeyAttrs, kSecAttrAccessControl, kSecReturnRef,
	kSecMatchLimit, kSecMatchLimitAll, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
	kSecUseDataProtectionKeychain uintptr
	// Security/SecKey.h: const SecKeyAlgorithm kSecKeyAlgorithmECDSASignatureDigestX962SHA256 (and 384, 512)
	kSecKeyAlgorithmECDSASignatureDigestX962SHA256, kSecKeyAlgorithmECDSASignatureDigestX962SHA384,
	kSecKeyAlgorithmECDSASignatureDigestX962SHA512 uintptr
)

var (
	loadOnce sync.Once
	loadErr  error
)

// Load opens the frameworks and registers every call and constant, once.
func Load() error {
	loadOnce.Do(func() { loadErr = load() })
	return loadErr
}

func load() error {
	sec, err := purego.Dlopen(securityPath, purego.RTLD_LAZY|purego.RTLD_LOCAL)
	if err != nil {
		return fmt.Errorf("secureenclave: loading Security.framework: %w", err)
	}
	cf, err := purego.Dlopen(coreFoundationPath, purego.RTLD_LAZY|purego.RTLD_LOCAL)
	if err != nil {
		return fmt.Errorf("secureenclave: loading CoreFoundation: %w", err)
	}
	libc, err := purego.Dlopen(libSystemPath, purego.RTLD_LAZY|purego.RTLD_LOCAL)
	if err != nil {
		return fmt.Errorf("secureenclave: loading libSystem: %w", err)
	}
	fns := []struct {
		lib  uintptr
		fptr any
		name string
	}{
		{cf, &cfRelease, "CFRelease"},
		{cf, &cfRetain, "CFRetain"},
		{cf, &cfDictionaryCreateMutable, "CFDictionaryCreateMutable"},
		{cf, &cfDictionarySetValue, "CFDictionarySetValue"},
		{cf, &cfStringCreateWithCString, "CFStringCreateWithCString"},
		{cf, &cfStringGetCString, "CFStringGetCString"},
		{cf, &cfNumberCreate, "CFNumberCreate"},
		{cf, &cfDataCreate, "CFDataCreate"},
		{cf, &cfDataGetLength, "CFDataGetLength"},
		{cf, &cfDataGetBytePtr, "CFDataGetBytePtr"},
		{cf, &cfArrayGetCount, "CFArrayGetCount"},
		{cf, &cfArrayGetValueAtIndex, "CFArrayGetValueAtIndex"},
		{cf, &cfErrorGetCode, "CFErrorGetCode"},
		{cf, &cfErrorCopyDescription, "CFErrorCopyDescription"},
		{sec, &secKeyCreateRandomKey, "SecKeyCreateRandomKey"},
		{sec, &secKeyCopyPublicKey, "SecKeyCopyPublicKey"},
		{sec, &secKeyCopyExternalRepresentation, "SecKeyCopyExternalRepresentation"},
		{sec, &secKeyCreateSignature, "SecKeyCreateSignature"},
		{sec, &secItemCopyMatching, "SecItemCopyMatching"},
		{sec, &secItemDelete, "SecItemDelete"},
		{sec, &secAccessControlCreateWithFlags, "SecAccessControlCreateWithFlags"},
		{sec, &secCopyErrorMessageString, "SecCopyErrorMessageString"},
		{libc, &gethostuuid, "gethostuuid"},
	}
	for _, f := range fns {
		// Dlsym first: RegisterLibFunc panics on a missing symbol, and a
		// missing one is an error to report, not a crash.
		sym, err := purego.Dlsym(f.lib, f.name)
		if err != nil {
			return fmt.Errorf("secureenclave: %s: %w", f.name, err)
		}
		purego.RegisterFunc(f.fptr, sym)
	}
	consts := []struct {
		lib   uintptr
		dst   *uintptr
		name  string
		deref bool
	}{
		{cf, &kCFBooleanTrue, "kCFBooleanTrue", true},
		{cf, &kCFBooleanFalse, "kCFBooleanFalse", true},
		{cf, &kCFTypeDictionaryKeyCallBacks, "kCFTypeDictionaryKeyCallBacks", false},
		{cf, &kCFTypeDictionaryValueCallBacks, "kCFTypeDictionaryValueCallBacks", false},
		{sec, &kSecClass, "kSecClass", true},
		{sec, &kSecClassKey, "kSecClassKey", true},
		{sec, &kSecAttrKeyClass, "kSecAttrKeyClass", true},
		{sec, &kSecAttrKeyClassPrivate, "kSecAttrKeyClassPrivate", true},
		{sec, &kSecAttrKeyType, "kSecAttrKeyType", true},
		{sec, &kSecAttrKeyTypeECSECPrimeRandom, "kSecAttrKeyTypeECSECPrimeRandom", true},
		{sec, &kSecAttrKeySizeInBits, "kSecAttrKeySizeInBits", true},
		{sec, &kSecAttrTokenID, "kSecAttrTokenID", true},
		{sec, &kSecAttrTokenIDSecureEnclave, "kSecAttrTokenIDSecureEnclave", true},
		{sec, &kSecAttrIsPermanent, "kSecAttrIsPermanent", true},
		{sec, &kSecAttrLabel, "kSecAttrLabel", true},
		{sec, &kSecPrivateKeyAttrs, "kSecPrivateKeyAttrs", true},
		{sec, &kSecAttrAccessControl, "kSecAttrAccessControl", true},
		{sec, &kSecReturnRef, "kSecReturnRef", true},
		{sec, &kSecMatchLimit, "kSecMatchLimit", true},
		{sec, &kSecMatchLimitAll, "kSecMatchLimitAll", true},
		{sec, &kSecAttrAccessibleWhenUnlockedThisDeviceOnly, "kSecAttrAccessibleWhenUnlockedThisDeviceOnly", true},
		{sec, &kSecUseDataProtectionKeychain, "kSecUseDataProtectionKeychain", true},
		{sec, &kSecKeyAlgorithmECDSASignatureDigestX962SHA256, "kSecKeyAlgorithmECDSASignatureDigestX962SHA256", true},
		{sec, &kSecKeyAlgorithmECDSASignatureDigestX962SHA384, "kSecKeyAlgorithmECDSASignatureDigestX962SHA384", true},
		{sec, &kSecKeyAlgorithmECDSASignatureDigestX962SHA512, "kSecKeyAlgorithmECDSASignatureDigestX962SHA512", true},
	}
	for _, c := range consts {
		addr, err := purego.Dlsym(c.lib, c.name)
		if err != nil {
			return fmt.Errorf("secureenclave: %s: %w", c.name, err)
		}
		if !c.deref {
			*c.dst = addr
			continue
		}
		// addr is the address of an `extern const CFStringRef`: the reference
		// is the word stored there. Read through a pointer to addr, so no
		// uintptr is turned into an unsafe.Pointer.
		*c.dst = **(**uintptr)(unsafe.Pointer(&addr))
		if *c.dst == 0 {
			return fmt.Errorf("secureenclave: %s is NULL", c.name)
		}
	}
	return nil
}

// Key is a SecKeyRef this package handed out: the caller releases it.
type Key uintptr

// Release lets go of k. Releasing 0 does nothing.
func Release(k Key) {
	if k != 0 {
		cfRelease(uintptr(k))
	}
}

// release is CFRelease of a reference that may be NULL.
func release(ref uintptr) {
	if ref != 0 {
		cfRelease(ref)
	}
}

// goString is the text of a CFStringRef (not released here).
func goString(s uintptr) string {
	if s == 0 {
		return ""
	}
	buf := make([]byte, 1024)
	if cfStringGetCString(s, &buf[0], len(buf), kCFStringEncodingUTF8) == 0 {
		return "(a description longer than port49 reads)"
	}
	for i, b := range buf {
		if b == 0 {
			return string(buf[:i])
		}
	}
	return string(buf)
}

// cfError is the Error for a CFErrorRef out parameter, which it releases (the
// caller owns it: the Create rule). A NULL one is an Error with no code.
func cfError(op string, e uintptr) error {
	if e == 0 {
		return &Error{Op: op, Code: 0, Description: "the call failed and gave no CFError"}
	}
	defer cfRelease(e)
	desc := cfErrorCopyDescription(e) // Copy: ours
	defer release(desc)
	return &Error{Op: op, Code: int64(cfErrorGetCode(e)), Description: goString(desc)}
}

// statusError is the Error for an OSStatus, with SecCopyErrorMessageString's
// words for it.
func statusError(op string, status int32) error {
	msg := secCopyErrorMessageString(status, 0) // Copy: ours
	defer release(msg)
	desc := goString(msg)
	if desc == "" {
		desc = "(no description)"
	}
	return &Error{Op: op, Code: int64(status), Description: desc}
}

// cfString is a new CFStringRef for s: the caller releases it.
func cfString(s string) uintptr { return cfStringCreateWithCString(0, s, kCFStringEncodingUTF8) }

// dict is a mutable dictionary that retains its keys and values, so every
// value this package creates is released once it is set.
type dict struct{ ref uintptr }

func newDict() *dict {
	return &dict{cfDictionaryCreateMutable(0, 0, kCFTypeDictionaryKeyCallBacks, kCFTypeDictionaryValueCallBacks)}
}

func (d *dict) set(key, value uintptr) { cfDictionarySetValue(d.ref, key, value) }

// setOwned sets value and releases this package's reference to it: the
// dictionary holds its own.
func (d *dict) setOwned(key, value uintptr) {
	d.set(key, value)
	release(value)
}

func (d *dict) close() { release(d.ref) }

// keyQuery is the query for the private keys labeled label: in the Secure
// Enclave, or (enclave false, the spike's control) in software.
func keyQuery(label string, enclave bool) *dict {
	q := newDict()
	q.set(kSecClass, kSecClassKey)
	q.set(kSecAttrKeyClass, kSecAttrKeyClassPrivate)
	q.set(kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom)
	q.setOwned(kSecAttrLabel, cfString(label))
	if enclave {
		// A Secure Enclave key is kept in the data protection keychain, not
		// the file-based one (Apple TN3137); without this key, macOS searches
		// the file-based keychain.
		q.set(kSecAttrTokenID, kSecAttrTokenIDSecureEnclave)
		q.set(kSecUseDataProtectionKeychain, kCFBooleanTrue)
	}
	return q
}

// CreateKey makes a P-256 key labeled label: in the Secure Enclave when
// enclave is true (with an access control that lets it sign, the one the
// Secure Enclave requires), else in software (the spike's control); kept in
// the keychain when permanent. The caller releases the key.
func CreateKey(label string, enclave, permanent bool) (Key, error) {
	if err := Load(); err != nil {
		return 0, err
	}
	params := newDict()
	defer params.close()
	priv := newDict()
	defer priv.close()

	var size int32 = 256
	params.set(kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom)
	params.setOwned(kSecAttrKeySizeInBits, cfNumberCreate(0, kCFNumberSInt32Type, &size))
	if enclave {
		params.set(kSecAttrTokenID, kSecAttrTokenIDSecureEnclave)
		params.set(kSecUseDataProtectionKeychain, kCFBooleanTrue)
		var cfErr uintptr
		ac := secAccessControlCreateWithFlags(0, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
			kSecAccessControlPrivateKeyUsage, &cfErr)
		if ac == 0 {
			return 0, cfError("SecAccessControlCreateWithFlags", cfErr)
		}
		priv.setOwned(kSecAttrAccessControl, ac)
	}
	if permanent {
		priv.set(kSecAttrIsPermanent, kCFBooleanTrue)
	} else {
		priv.set(kSecAttrIsPermanent, kCFBooleanFalse)
	}
	priv.setOwned(kSecAttrLabel, cfString(label))
	params.set(kSecPrivateKeyAttrs, priv.ref)

	var cfErr uintptr
	k := secKeyCreateRandomKey(params.ref, &cfErr) // Create: ours
	if k == 0 {
		return 0, cfError("SecKeyCreateRandomKey", cfErr)
	}
	return Key(k), nil
}

// FindKeys is every private key labeled label (in the Secure Enclave when
// enclave is true). None is an Error with ErrSecItemNotFound. The caller
// releases each key.
func FindKeys(label string, enclave bool) ([]Key, error) {
	if err := Load(); err != nil {
		return nil, err
	}
	q := keyQuery(label, enclave)
	defer q.close()
	q.set(kSecReturnRef, kCFBooleanTrue)
	q.set(kSecMatchLimit, kSecMatchLimitAll)
	var result uintptr
	if st := secItemCopyMatching(q.ref, &result); st != 0 {
		return nil, statusError("SecItemCopyMatching", st)
	}
	// Copy: the CFArrayRef is ours; the keys in it are the array's (Get), so
	// each is retained before the array is released.
	defer release(result)
	n := cfArrayGetCount(result)
	if n == 0 {
		return nil, statusError("SecItemCopyMatching", ErrSecItemNotFound)
	}
	keys := make([]Key, 0, n)
	for i := range n {
		keys = append(keys, Key(cfRetain(cfArrayGetValueAtIndex(result, i))))
	}
	return keys, nil
}

// DeleteKeys removes every private key labeled label (in the Secure Enclave
// when enclave is true). None is an Error with ErrSecItemNotFound.
func DeleteKeys(label string, enclave bool) error {
	if err := Load(); err != nil {
		return err
	}
	q := keyQuery(label, enclave)
	defer q.close()
	if st := secItemDelete(q.ref); st != 0 {
		return statusError("SecItemDelete", st)
	}
	return nil
}

// dataBytes copies a CFDataRef's bytes (not released here).
func dataBytes(d uintptr) []byte {
	n := cfDataGetLength(d)
	if n <= 0 {
		return nil
	}
	return append([]byte(nil), unsafe.Slice(cfDataGetBytePtr(d), n)...)
}

// PublicKey is k's public key, read from SecKeyCopyPublicKey's external
// representation (ANSI X9.63: an uncompressed P-256 point).
func PublicKey(k Key) (*ecdsa.PublicKey, error) {
	if err := Load(); err != nil {
		return nil, err
	}
	pub := secKeyCopyPublicKey(uintptr(k)) // Copy: ours
	if pub == 0 {
		return nil, &Error{Op: "SecKeyCopyPublicKey", Description: "the key has no public key"}
	}
	defer cfRelease(pub)
	var cfErr uintptr
	data := secKeyCopyExternalRepresentation(pub, &cfErr) // Copy: ours
	if data == 0 {
		return nil, cfError("SecKeyCopyExternalRepresentation", cfErr)
	}
	defer cfRelease(data)
	p, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), dataBytes(data))
	if err != nil {
		return nil, fmt.Errorf("secureenclave: the key's public key is not a P-256 point: %w", err)
	}
	return p, nil
}

// Sign is an ASN.1 DER ECDSA signature (X9.62, as crypto/ecdsa writes) of
// digest, a hash of kind h, by k.
func Sign(k Key, digest []byte, h crypto.Hash) ([]byte, error) {
	if err := Load(); err != nil {
		return nil, err
	}
	var alg uintptr
	switch h {
	case crypto.SHA256:
		alg = kSecKeyAlgorithmECDSASignatureDigestX962SHA256
	case crypto.SHA384:
		alg = kSecKeyAlgorithmECDSASignatureDigestX962SHA384
	case crypto.SHA512:
		alg = kSecKeyAlgorithmECDSASignatureDigestX962SHA512
	default:
		return nil, fmt.Errorf("secureenclave: a Secure Enclave key signs SHA-256, SHA-384 or SHA-512 digests, not %v", h)
	}
	if len(digest) != h.Size() || len(digest) == 0 {
		return nil, fmt.Errorf("secureenclave: a %v digest is %d bytes, not %d", h, h.Size(), len(digest))
	}
	in := cfDataCreate(0, &digest[0], len(digest)) // Create: ours
	if in == 0 {
		return nil, &Error{Op: "CFDataCreate", Description: "out of memory"}
	}
	defer cfRelease(in)
	var cfErr uintptr
	sig := secKeyCreateSignature(uintptr(k), alg, in, &cfErr) // Create: ours
	if sig == 0 {
		return nil, cfError("SecKeyCreateSignature", cfErr)
	}
	defer cfRelease(sig)
	return dataBytes(sig), nil
}

// HostID is this Mac's 8-hex-digit name, the first 8 digits of the SHA-256 of
// its host UUID (gethostuuid, the hardware UUID): the Secure Enclave's
// counterpart of the machine-id name a TPM key file carries (decision 45
// ruling 7).
func HostID() (string, error) {
	if err := Load(); err != nil {
		return "", err
	}
	var id [16]byte
	wait := timespec{sec: 5}
	if gethostuuid(&id, &wait) != 0 {
		return "", errors.New("secureenclave: gethostuuid did not name this Mac")
	}
	sum := sha256.Sum256(id[:])
	return fmt.Sprintf("%x", sum[:4]), nil
}
