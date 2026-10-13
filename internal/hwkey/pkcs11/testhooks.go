//go:build hwkey && hwkey_dlopen

package pkcs11

import (
	"sync/atomic"
	"unsafe"
)

// The test harness's view of the module (re-review R4). The hwkey tag is set
// only by `make test-hw`, so no release build carries these. They are a
// non-test file because hwtest and cmd/port49's tests import this package and
// a _test.go file is seen by this package's own tests alone.

// LoginCalls is how many C_Login calls the process has made.
func LoginCalls() int64 { return loginCalls.Load() }

// OpenCalls is how many times Open has run.
func OpenCalls() int64 { return openCalls.Load() }

// GenerateKeyPairCalls is how many C_GenerateKeyPair calls the process has made.
func GenerateKeyPairCalls() int64 { return generateKeyPairCalls.Load() }

// CreateObjectCalls is how many C_CreateObject calls the process has made.
func CreateObjectCalls() int64 { return createObjectCalls.Load() }

// OpenSessions is how many sessions this process's Signers hold open on every
// module it has loaded, so a test can see that a process let go of its token.
func OpenSessions() int {
	modulesMu.Lock()
	defer modulesMu.Unlock()
	n := 0
	for _, m := range modules {
		m.sessMu.Lock()
		for _, o := range m.owners {
			if o != nil {
				n++
			}
		}
		m.sessMu.Unlock()
	}
	return n
}

// SessionHandle is the session number s holds (0 when it holds none), so a
// test can check that the module reused a lost Signer's number for another's
// new session instead of assuming it.
func SessionHandle(s *Signer) uint {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.session
}

// SessMuHeldDuringClose has fn told, just before every C_CloseSession,
// whether the module's session lock is held: closeOwned must delete the owner
// entry under the lock and call C_CloseSession after releasing it. The
// returned func removes the probe.
func SessMuHeldDuringClose(fn func(held bool)) (restore func()) {
	probe := func(m *Module) {
		if m.sessMu.TryLock() {
			m.sessMu.Unlock()
			fn(false)
			return
		}
		fn(true)
	}
	closeProbeFn.Store(&probe)
	return func() { closeProbeFn.Store(nil) }
}

// BlockPIN makes every token read as one whose user PIN is blocked: its
// token info carries CKF_USER_PIN_LOCKED, which is all a wrong PIN that was
// the last try shows; and, with answerLocked, C_Login answers CKR_PIN_LOCKED
// without reaching the token, as a blocked token does even for the right PIN.
// SoftHSM2 never blocks a PIN however many are refused, so this stands in for
// a token that has. The returned func removes it.
func BlockPIN(answerLocked bool) (restore func()) {
	pinBlockedFake.Store(true)
	loginLockedFake.Store(answerLocked)
	return func() { pinBlockedFake.Store(false); loginLockedFake.Store(false) }
}

// BlockPINWithoutFlag makes C_Login answer CKR_PIN_LOCKED while the token info
// shows no CKF_USER_PIN_LOCKED: a module that reports the lock by its return
// code alone. The returned func removes it.
func BlockPINWithoutFlag() (restore func()) {
	loginLockedFake.Store(true)
	return func() { loginLockedFake.Store(false) }
}

// PINTriesLow makes every token read as one that refused a PIN since the last
// success: its token info carries CKF_USER_PIN_COUNT_LOW, and with final
// CKF_USER_PIN_FINAL_TRY as well. SoftHSM2 sets neither. The returned func
// removes it.
func PINTriesLow(final bool) (restore func()) {
	flags := uint(ckfPINCountLow)
	if final {
		flags |= ckfPINFinalTry
	}
	pinLowFake.Store(uint64(flags))
	return func() { pinLowFake.Store(0) }
}

var pinBlockedFake, loginLockedFake atomic.Bool

var pinLowFake atomic.Uint64

func fakeTokenFlags() uint {
	flags := uint(pinLowFake.Load())
	if pinBlockedFake.Load() {
		flags |= ckfUserPINLocked
	}
	return flags
}

func fakeLoginRV() (uint, bool) {
	if loginLockedFake.Load() {
		return ckrPINLocked, true
	}
	return 0, false
}

// closeProbeFn is the probe SessMuHeldDuringClose sets; atomic, since a
// Signer may close on any goroutine while a test sets or removes it.
var closeProbeFn atomic.Pointer[func(m *Module)]

// closeProbe runs the probe, if one is set, just before C_CloseSession.
func closeProbe(m *Module) {
	if p := closeProbeFn.Load(); p != nil {
		(*p)(m)
	}
}

// Finalize calls C_Finalize on m and returns its CK_RV.
func Finalize(m *Module) uint { return m.call(fnFinalize, 0) }

// SlotList is C_GetSlotList(tokenPresent) on m.
func SlotList(m *Module) ([]uint, error) { return m.slotList() }

// Rescan finalizes m and initializes it again. SoftHSM2 reads its token
// directory at C_Initialize only, so this is how a test sees a token that
// another process changed, and how it "unplugs" one: every session is
// invalid afterwards.
func Rescan(m *Module) error {
	if rv := m.call(fnFinalize, 0); rv != ckrOK {
		return &rvError{"C_Finalize", rv}
	}
	args := &ckInitializeArgs{flags: ckfOSLockingOK}
	var p pins
	defer p.Unpin()
	if rv := m.call(fnInitialize, p.ptr(args, unsafe.Pointer(args))); rv != ckrOK {
		return &rvError{"C_Initialize", rv}
	}
	return nil
}

// ResetModules empties the one-Module-per-path cache, so the next Load
// initializes the module again.
func ResetModules() {
	modulesMu.Lock()
	defer modulesMu.Unlock()
	clear(modules)
}
