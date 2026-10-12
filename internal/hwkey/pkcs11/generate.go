//go:build hwkey && hwkey_dlopen

// Harness only: the hwkey tag is set by `make test-hw` alone, so the release
// client (hwkey_dlopen) carries no code that generates a key or writes an
// object (decision 45 ruling 7).

package pkcs11

import (
	"crypto/x509"
	"errors"
	"fmt"
	"unsafe"
)

// prime256v1 as DER, CKA_EC_PARAMS.
var p256Params = []byte{0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07}

// rwSession opens a read-write session on the one token u names and logs the
// user in with pin. Only the harness-side functions below use it: port49
// never generates a key or writes an object on a token (decision 45 ruling
// 7), so the product's Open takes read-only sessions alone.
func rwSession(u URI, pin []byte) (*Module, uint, error) {
	m, err := Load(u.ModulePath)
	if err != nil {
		return nil, 0, err
	}
	slots, err := m.slotList()
	if err != nil {
		return nil, 0, err
	}
	var slot uint
	n := 0
	for _, s := range slots {
		if ti, err := m.tokenInfo(s); err == nil && u.matches(s, ti) {
			slot, n = s, n+1
		}
	}
	if n != 1 {
		return nil, 0, fmt.Errorf("pkcs11: %d tokens match %s; a harness write needs exactly one", n, u)
	}
	session, err := m.openSession(slot, true)
	if err != nil {
		return nil, 0, err
	}
	if rv := m.login(session, ckuUser, pin); rv != ckrOK && rv != ckrUserAlreadyLoggedIn {
		m.closeSession(session)
		return nil, 0, &rvError{"C_Login", rv}
	}
	return m, session, nil
}

// Generate makes a P-256 key pair (CKM_EC_KEY_PAIR_GEN, CKA_ID u.ID) on the
// token u names and opens it. Only the SoftHSM2 harness calls it: port49
// never generates a key or writes an object on a token (decision 45 ruling
// 7).
func Generate(u URI, pin []byte) (*Signer, error) {
	defer clear(pin)
	if len(u.ID) == 0 {
		return nil, errors.New("pkcs11: Generate needs an id")
	}
	login := append([]byte(nil), pin...)
	defer clear(login)
	m, session, err := rwSession(u, login)
	if err != nil {
		return nil, err
	}
	pubT := []attr{
		{ckaToken, boolBytes(true)}, {ckaPrivate, boolBytes(false)}, {ckaVerify, boolBytes(true)},
		{ckaECParams, p256Params}, {ckaID, u.ID},
	}
	privT := []attr{
		{ckaToken, boolBytes(true)}, {ckaPrivate, boolBytes(true)}, {ckaSensitive, boolBytes(true)},
		{ckaExtractable, boolBytes(false)}, {ckaSign, boolBytes(true)}, {ckaID, u.ID},
	}
	if u.Object != "" {
		pubT = append(pubT, attr{ckaLabel, []byte(u.Object)})
		privT = append(privT, attr{ckaLabel, []byte(u.Object)})
	}
	var p pins
	mech := &ckMechanism{mechanism: ckmECKeyPairGen}
	pubH, privH := new(uint), new(uint)
	generateKeyPairCalls.Add(1)
	rv := m.call(fnGenerateKeyPair, uintptr(session), p.ptr(mech, unsafe.Pointer(mech)),
		p.template(pubT), uintptr(len(pubT)), p.template(privT), uintptr(len(privT)),
		p.ptr(pubH, unsafe.Pointer(pubH)), p.ptr(privH, unsafe.Pointer(privH)))
	p.Unpin()
	m.closeSession(session)
	if rv != ckrOK {
		return nil, &rvError{"C_GenerateKeyPair", rv}
	}
	return Open(u, append([]byte(nil), pin...))
}

// StoreCertificate writes cert as a certificate object with CKA_ID u.ID on
// the token u names. Harness only (decision 45 ruling 7).
func StoreCertificate(u URI, cert *x509.Certificate, pin []byte) error {
	defer clear(pin)
	id := u.ID
	m, session, err := rwSession(u, pin)
	if err != nil {
		return err
	}
	defer m.closeSession(session)
	t := []attr{
		{ckaClass, uintBytes(ckoCertificate)}, {ckaToken, boolBytes(true)}, {ckaPrivate, boolBytes(false)},
		{ckaCertificateType, uintBytes(ckcX509)}, {ckaID, id}, {ckaSubject, cert.RawSubject}, {ckaValue, cert.Raw},
	}
	var p pins
	defer p.Unpin()
	obj := new(uint)
	createObjectCalls.Add(1)
	if rv := m.call(fnCreateObject, uintptr(session), p.template(t), uintptr(len(t)), p.ptr(obj, unsafe.Pointer(obj))); rv != ckrOK {
		return &rvError{"C_CreateObject", rv}
	}
	return nil
}
