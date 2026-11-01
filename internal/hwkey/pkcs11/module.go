//go:build hwkey_dlopen

package pkcs11

import (
	"encoding/binary"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/ebitengine/purego"

	"github.com/blanketfish/port49/internal/userconfig"
)

// CK_ULONG is eight bytes on the LP64 systems port49's client builds for
// (Linux and macOS, amd64 and arm64); this fails to compile anywhere else.
const _ = uint(unsafe.Sizeof(uint(0)) - 8)

// Calls counted for the test harness (testhooks.go reads them): port49 sends
// a PIN once, and never generates a key or writes an object on a token
// (decision 45 ruling 7).
var (
	loginCalls           atomic.Int64
	openCalls            atomic.Int64
	generateKeyPairCalls atomic.Int64
	createObjectCalls    atomic.Int64
)

// ckFunctionList is CK_FUNCTION_LIST on LP64 Linux and macOS: a CK_VERSION
// (two bytes, padded to the pointer's alignment), then the functions in the
// header's order. Windows packs it to one byte and is not a port49 client.
type ckFunctionList struct {
	version [2]byte
	_       [6]byte
	fns     [functionCount]uintptr
}

// ckInitializeArgs is CK_C_INITIALIZE_ARGS.
type ckInitializeArgs struct {
	createMutex, destroyMutex, lockMutex, unlockMutex unsafe.Pointer
	flags                                             uint
	reserved                                          unsafe.Pointer
}

// ckTokenInfo is CK_TOKEN_INFO.
type ckTokenInfo struct {
	label, manufacturer [32]byte
	model, serial       [16]byte
	flags               uint
	maxSession, session, maxRWSession, rwSession,
	maxPINLen, minPINLen,
	totalPublic, freePublic, totalPrivate, freePrivate uint
	hardwareVersion, firmwareVersion [2]byte
	utcTime                          [16]byte
}

// ckAttribute is CK_ATTRIBUTE.
type ckAttribute struct {
	typ    uint
	value  unsafe.Pointer
	length uint
}

// ckMechanism is CK_MECHANISM.
type ckMechanism struct {
	mechanism uint
	param     unsafe.Pointer
	paramLen  uint
}

// ckPSSParams is CK_RSA_PKCS_PSS_PARAMS.
type ckPSSParams struct{ hashAlg, mgf, sLen uint }

// Module is one loaded PKCS#11 module, initialized once per process.
type Module struct {
	path   string
	handle uintptr
	list   ckFunctionList

	// owners records who holds each session number the module gave out: a
	// Signer, or nil while a probe's candidate has not been claimed. A module
	// may give a lost session's number to another session, so a Signer acts on
	// its number only while the entry still names it. Guarded by sessMu.
	sessMu sync.Mutex
	owners map[uint]*Signer
}

var (
	modulesMu sync.Mutex
	modules   = map[string]*Module{}
)

// Load opens the module at path: it checks the module's ownership and
// directories (userconfig.CheckOwned: it is code the agent runs), dlopens it,
// reads its function list and initializes it. A process keeps one Module per
// path. C_Initialize gets CKF_OS_LOCKING_OK and no mutex callbacks, so the
// module never calls into Go.
func Load(path string) (*Module, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("pkcs11: module-path %q must be absolute", path)
	}
	modulesMu.Lock()
	defer modulesMu.Unlock()
	if m, ok := modules[path]; ok {
		return m, nil
	}
	if err := userconfig.CheckOwned(path); err != nil {
		return nil, fmt.Errorf("pkcs11 module %s: %w", path, err)
	}
	h, err := purego.Dlopen(path, purego.RTLD_NOW|purego.RTLD_LOCAL)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: loading %s: %w", path, err)
	}
	sym, err := purego.Dlsym(h, "C_GetFunctionList")
	if err != nil {
		return nil, fmt.Errorf("pkcs11: %s has no C_GetFunctionList: %w", path, err)
	}
	var out struct{ list unsafe.Pointer }
	var pin runtime.Pinner
	pin.Pin(&out)
	r, _, _ := purego.SyscallN(sym, uintptr(unsafe.Pointer(&out.list)))
	pin.Unpin()
	if r != ckrOK || out.list == nil {
		return nil, &rvError{"C_GetFunctionList", uint(r)}
	}
	m := &Module{path: path, handle: h, list: *(*ckFunctionList)(out.list), owners: map[uint]*Signer{}}
	if m.list.fns[fnInitialize] == 0 {
		return nil, fmt.Errorf("pkcs11: %s has no C_Initialize", path)
	}
	args := &ckInitializeArgs{flags: ckfOSLockingOK}
	pin.Pin(args)
	rv := m.call(fnInitialize, uintptr(unsafe.Pointer(args)))
	pin.Unpin()
	if rv != ckrOK && rv != ckrCryptokiAlreadyInitialized {
		return nil, &rvError{"C_Initialize", rv}
	}
	modules[path] = m
	return m, nil
}

// call runs one PKCS#11 function and returns its CK_RV. Every pointer
// argument points at heap memory pinned by the caller for the call.
func (m *Module) call(fn int, args ...uintptr) uint {
	r, _, _ := purego.SyscallN(m.list.fns[fn], args...)
	return uint(r)
}

// pins holds what one call has pinned.
type pins struct{ runtime.Pinner }

func (p *pins) ptr(v any, addr unsafe.Pointer) uintptr {
	p.Pin(v)
	return uintptr(addr)
}

// bytes pins b's backing array and returns its address (0 for an empty one).
func (p *pins) bytes(b []byte) uintptr {
	if len(b) == 0 {
		return 0
	}
	p.Pin(&b[0])
	return uintptr(unsafe.Pointer(&b[0]))
}

// attr is one attribute of a template, its value bytes owned by the caller.
type attr struct {
	typ uint
	val []byte
}

func uintBytes(v uint) []byte {
	b := make([]byte, 8)
	binary.NativeEndian.PutUint64(b, uint64(v))
	return b
}

func boolBytes(v bool) []byte {
	if v {
		return []byte{1}
	}
	return []byte{0}
}

// template builds a CK_ATTRIBUTE array over attrs, pinned, and returns its
// address.
func (p *pins) template(attrs []attr) uintptr {
	if len(attrs) == 0 {
		return 0
	}
	t := make([]ckAttribute, len(attrs))
	for i, a := range attrs {
		t[i].typ = a.typ
		if len(a.val) > 0 {
			p.Pin(&a.val[0])
			t[i].value = unsafe.Pointer(&a.val[0])
		}
		t[i].length = uint(len(a.val))
	}
	p.Pin(&t[0])
	return uintptr(unsafe.Pointer(&t[0]))
}

func (m *Module) slotList() ([]uint, error) {
	var p pins
	defer p.Unpin()
	n := new(uint)
	pn := p.ptr(n, unsafe.Pointer(n))
	if rv := m.call(fnGetSlotList, 1, 0, pn); rv != ckrOK {
		return nil, &rvError{"C_GetSlotList", rv}
	}
	if *n == 0 {
		return nil, nil
	}
	slots := make([]uint, *n)
	p.Pin(&slots[0])
	if rv := m.call(fnGetSlotList, 1, uintptr(unsafe.Pointer(&slots[0])), pn); rv != ckrOK {
		return nil, &rvError{"C_GetSlotList", rv}
	}
	return slots[:*n], nil
}

func (m *Module) tokenInfo(slot uint) (*ckTokenInfo, error) {
	var p pins
	defer p.Unpin()
	ti := new(ckTokenInfo)
	if rv := m.call(fnGetTokenInfo, uintptr(slot), p.ptr(ti, unsafe.Pointer(ti))); rv != ckrOK {
		return nil, &rvError{"C_GetTokenInfo", rv}
	}
	ti.flags |= fakeTokenFlags()
	return ti, nil
}

// ckSessionInfo is CK_SESSION_INFO.
type ckSessionInfo struct {
	slotID, state, flags, deviceError uint
}

// CKS_RO_USER_FUNCTIONS and CKS_RW_USER_FUNCTIONS: the user is logged in.
const (
	cksROUserFunctions = 1
	cksRWUserFunctions = 3
)

// userLoggedIn is whether the token's login, which is shared by every session
// an application has on it, shows on session (C_GetSessionInfo).
func (m *Module) userLoggedIn(session uint) (bool, error) {
	var p pins
	defer p.Unpin()
	si := new(ckSessionInfo)
	if rv := m.call(fnGetSessionInfo, uintptr(session), p.ptr(si, unsafe.Pointer(si))); rv != ckrOK {
		return false, &rvError{"C_GetSessionInfo", rv}
	}
	return si.state == cksROUserFunctions || si.state == cksRWUserFunctions, nil
}

func (m *Module) openSession(slot uint, rw bool) (uint, error) {
	var p pins
	defer p.Unpin()
	flags := uint(ckfSerialSession)
	if rw {
		flags |= ckfRWSession
	}
	h := new(uint)
	if rv := m.call(fnOpenSession, uintptr(slot), uintptr(flags), 0, 0, p.ptr(h, unsafe.Pointer(h))); rv != ckrOK {
		return 0, &rvError{"C_OpenSession", rv}
	}
	m.sessMu.Lock()
	m.owners[*h] = nil // a number the module reuses is no longer its old holder's
	m.sessMu.Unlock()
	return *h, nil
}

// claim hands the unclaimed session h to s.
func (m *Module) claim(h uint, s *Signer) {
	m.sessMu.Lock()
	defer m.sessMu.Unlock()
	if owner, ok := m.owners[h]; ok && owner == nil {
		m.owners[h] = s
	}
}

// holds reports whether s still owns session h.
func (m *Module) holds(h uint, s *Signer) bool {
	m.sessMu.Lock()
	defer m.sessMu.Unlock()
	owner, ok := m.owners[h]
	return h != 0 && ok && owner == s
}

// closeSession closes a session no Signer has claimed (a probe's candidate, or
// the harness's own).
func (m *Module) closeSession(h uint) { m.closeOwned(h, nil) }

// closeOwned closes session h only while owner still holds it; the result is
// ignored: a session on a token already gone is already closed. Handle 0 is
// CK_INVALID_HANDLE, and a number someone else holds now is not the caller's
// to close, so neither is sent.
//
// The owner entry goes under sessMu and C_CloseSession is called after it is
// released: a module may block in C_CloseSession (a token pulled mid-call),
// and sessMu is every Signer's gate. The number cannot be given to another
// session before the close returns, since only the close frees it.
func (m *Module) closeOwned(h uint, owner *Signer) {
	if h == 0 {
		return
	}
	m.sessMu.Lock()
	if o, ok := m.owners[h]; !ok || o != owner {
		m.sessMu.Unlock()
		return
	}
	delete(m.owners, h)
	m.sessMu.Unlock()
	closeProbe(m)
	m.call(fnCloseSession, uintptr(h))
}

// login is one C_Login; the caller owns pin and zeroes it.
func (m *Module) login(session uint, user uint, pin []byte) uint {
	var p pins
	defer p.Unpin()
	loginCalls.Add(1)
	if rv, ok := fakeLoginRV(); ok {
		return rv
	}
	return m.call(fnLogin, uintptr(session), uintptr(user), p.bytes(pin), uintptr(len(pin)))
}

func (m *Module) findObjects(session uint, attrs []attr) ([]uint, error) {
	var p pins
	defer p.Unpin()
	if rv := m.call(fnFindObjectsInit, uintptr(session), p.template(attrs), uintptr(len(attrs))); rv != ckrOK {
		return nil, &rvError{"C_FindObjectsInit", rv}
	}
	defer m.call(fnFindObjectsFinal, uintptr(session))
	var all []uint
	for {
		const batch = 16
		buf := make([]uint, batch)
		n := new(uint)
		p.Pin(&buf[0])
		rv := m.call(fnFindObjects, uintptr(session), uintptr(unsafe.Pointer(&buf[0])), batch, p.ptr(n, unsafe.Pointer(n)))
		if rv != ckrOK {
			return nil, &rvError{"C_FindObjects", rv}
		}
		all = append(all, buf[:*n]...)
		if *n < batch {
			return all, nil
		}
	}
}

var errAttributeUnavailable = errors.New("pkcs11: the attribute is not readable")

// attrValue reads one attribute of obj; a sensitive or absent one is
// errAttributeUnavailable.
func (m *Module) attrValue(session, obj uint, typ uint) ([]byte, error) {
	var p pins
	defer p.Unpin()
	t := []ckAttribute{{typ: typ}}
	p.Pin(&t[0])
	rv := m.call(fnGetAttributeValue, uintptr(session), uintptr(obj), uintptr(unsafe.Pointer(&t[0])), 1)
	if rv == ckrAttributeSensitive || rv == ckrAttributeTypeInvalid {
		return nil, errAttributeUnavailable
	}
	if rv != ckrOK {
		return nil, &rvError{"C_GetAttributeValue", rv}
	}
	if t[0].length == ^uint(0) {
		return nil, errAttributeUnavailable
	}
	buf := make([]byte, t[0].length)
	if len(buf) == 0 {
		return buf, nil
	}
	p.Pin(&buf[0])
	t[0].value = unsafe.Pointer(&buf[0])
	rv = m.call(fnGetAttributeValue, uintptr(session), uintptr(obj), uintptr(unsafe.Pointer(&t[0])), 1)
	if rv != ckrOK {
		return nil, &rvError{"C_GetAttributeValue", rv}
	}
	return buf[:t[0].length], nil
}

// sign is C_SignInit and C_Sign with mech, and returns the token's signature.
func (m *Module) sign(session uint, mech uint, param []byte, key uint, data []byte) ([]byte, error) {
	var p pins
	defer p.Unpin()
	mc := &ckMechanism{mechanism: mech}
	if len(param) > 0 {
		p.Pin(&param[0])
		mc.param = unsafe.Pointer(&param[0])
		mc.paramLen = uint(len(param))
	}
	if rv := m.call(fnSignInit, uintptr(session), p.ptr(mc, unsafe.Pointer(mc)), uintptr(key)); rv != ckrOK {
		return nil, &rvError{"C_SignInit", rv}
	}
	sig := make([]byte, 1024)
	n := new(uint)
	*n = uint(len(sig))
	p.Pin(&sig[0])
	rv := m.call(fnSign, uintptr(session), p.bytes(data), uintptr(len(data)),
		uintptr(unsafe.Pointer(&sig[0])), p.ptr(n, unsafe.Pointer(n)))
	if rv != ckrOK {
		return nil, &rvError{"C_Sign", rv}
	}
	return sig[:*n], nil
}
