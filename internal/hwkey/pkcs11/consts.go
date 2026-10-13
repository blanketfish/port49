// Package pkcs11 is port49's PKCS#11 client key: the RFC 7512 URI and the
// DER conversion build everywhere; the binding to a module (dlopen through
// purego) builds only under the tag hwkey_dlopen (plan 9c, ruling 22), so the
// static build never links the system loader.
package pkcs11

import "fmt"

// Function-list indexes: the order of CK_FUNCTION_LIST in the PKCS#11 v2.40
// header (pkcs11f.h).
const (
	fnInitialize        = 0
	fnFinalize          = 1
	fnGetSlotList       = 4
	fnGetTokenInfo      = 6
	fnOpenSession       = 12
	fnCloseSession      = 13
	fnGetSessionInfo    = 15
	fnLogin             = 18
	fnLogout            = 19
	fnCreateObject      = 20
	fnGetAttributeValue = 24
	fnFindObjectsInit   = 26
	fnFindObjects       = 27
	fnFindObjectsFinal  = 28
	fnSignInit          = 42
	fnSign              = 43
	fnGenerateKeyPair   = 59

	functionCount = 68
)

// Return values (CK_RV), PKCS#11 v2.40 §3.
const (
	ckrOK                         = 0x00
	ckrSlotIDInvalid              = 0x03
	ckrDeviceError                = 0x30
	ckrDeviceRemoved              = 0x32
	ckrAttributeSensitive         = 0x11
	ckrAttributeTypeInvalid       = 0x12
	ckrObjectHandleInvalid        = 0x82
	ckrPINIncorrect               = 0xA0
	ckrPINLocked                  = 0xA4
	ckrSessionClosed              = 0xB1
	ckrSessionHandleInvalid       = 0xB3
	ckrTokenNotPresent            = 0xE0
	ckrTokenNotRecognized         = 0xE1
	ckrUserAlreadyLoggedIn        = 0x100
	ckrUserNotLoggedIn            = 0x101
	ckrBufferTooSmall             = 0x150
	ckrCryptokiAlreadyInitialized = 0x191
)

var rvNames = map[uint]string{
	ckrOK:                         "CKR_OK",
	ckrSlotIDInvalid:              "CKR_SLOT_ID_INVALID",
	ckrDeviceError:                "CKR_DEVICE_ERROR",
	ckrDeviceRemoved:              "CKR_DEVICE_REMOVED",
	ckrAttributeSensitive:         "CKR_ATTRIBUTE_SENSITIVE",
	ckrAttributeTypeInvalid:       "CKR_ATTRIBUTE_TYPE_INVALID",
	ckrObjectHandleInvalid:        "CKR_OBJECT_HANDLE_INVALID",
	ckrPINIncorrect:               "CKR_PIN_INCORRECT",
	ckrPINLocked:                  "CKR_PIN_LOCKED",
	ckrSessionClosed:              "CKR_SESSION_CLOSED",
	ckrSessionHandleInvalid:       "CKR_SESSION_HANDLE_INVALID",
	ckrTokenNotPresent:            "CKR_TOKEN_NOT_PRESENT",
	ckrTokenNotRecognized:         "CKR_TOKEN_NOT_RECOGNIZED",
	ckrUserAlreadyLoggedIn:        "CKR_USER_ALREADY_LOGGED_IN",
	ckrUserNotLoggedIn:            "CKR_USER_NOT_LOGGED_IN",
	ckrBufferTooSmall:             "CKR_BUFFER_TOO_SMALL",
	ckrCryptokiAlreadyInitialized: "CKR_CRYPTOKI_ALREADY_INITIALIZED",
}

// rvError is a PKCS#11 function's refusal.
type rvError struct {
	fn string
	rv uint
}

func (e *rvError) Error() string {
	if n, ok := rvNames[e.rv]; ok {
		return fmt.Sprintf("pkcs11: %s: %s (0x%x)", e.fn, n, e.rv)
	}
	return fmt.Sprintf("pkcs11: %s: CK_RV 0x%x", e.fn, e.rv)
}

// Object classes (CKO_*), key types (CKK_*), certificate types (CKC_*).
const (
	ckoCertificate = 0x01
	ckoPublicKey   = 0x02
	ckoPrivateKey  = 0x03

	ckkRSA       = 0x00
	ckkEC        = 0x03
	ckkECEdwards = 0x40
	ckcX509      = 0x00
)

// Attributes (CKA_*).
const (
	ckaClass           = 0x000
	ckaToken           = 0x001
	ckaPrivate         = 0x002
	ckaLabel           = 0x003
	ckaValue           = 0x011
	ckaCertificateType = 0x080
	ckaKeyType         = 0x100
	ckaSubject         = 0x101
	ckaID              = 0x102
	ckaSensitive       = 0x103
	ckaSign            = 0x108
	ckaVerify          = 0x10A
	ckaModulus         = 0x120
	ckaPublicExponent  = 0x122
	ckaExtractable     = 0x162
	ckaECParams        = 0x180
	ckaECPoint         = 0x181
)

// Mechanisms (CKM_*) and mask generation functions (CKG_*).
const (
	ckmECKeyPairGen = 0x1040
	ckmECDSA        = 0x1041
	ckmRSAPKCSPSS   = 0x0D
	ckmEdDSA        = 0x1057
	ckmSHA256       = 0x250
	ckgMGF1SHA256   = 0x02
)

// Flags (CKF_*) and users (CKU_*).
const (
	ckfRWSession     = 0x02
	ckfSerialSession = 0x04
	ckfOSLockingOK   = 0x02
	ckfLoginRequired = 0x04
	ckfUserPINLocked = 0x40 // CKF_USER_PIN_LOCKED
	ckfPINCountLow   = 0x10000
	ckfPINFinalTry   = 0x20000
	ckuUser          = 1
)
