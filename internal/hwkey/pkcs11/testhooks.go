//go:build hwkey && hwkey_dlopen

package pkcs11

import "unsafe"

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

// SessionHandle is the session number s holds (0 when it holds none), so a
// test can check that the module reused a lost Signer's number for another's
// new session instead of assuming it.
func SessionHandle(s *Signer) uint {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.session
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
