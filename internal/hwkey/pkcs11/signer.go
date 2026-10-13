//go:build hwkey_dlopen

package pkcs11

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/rhwendt/port49/internal/hwkey"
)

// Signer is one private key object on one token; it implements hwkey.Key.
type Signer struct {
	mu            sync.Mutex
	m             *Module
	uri           URI
	slot          uint
	session       uint
	handle        uint // the private key; 0 while the token is locked and hides it
	id            []byte
	pub           crypto.PublicKey
	keyType       uint
	sigSize       int // an EC key's r and s, each this long
	loginRequired bool
	serial        string
	label         string
	state         hwkey.State
	closed        bool
	now           func() time.Time // the clock; nil is time.Now (tests inject one)
}

// touchTimeoutMin is how long a C_Sign that answers CKR_USER_NOT_LOGGED_IN
// must have taken to be read as a touch timeout. libykcs11 reports an untouched
// sign that way after about 14.4s although the token stays logged in (L60,
// 2026-10-13); a genuine not-logged-in answers at once.
const touchTimeoutMin = 5 * time.Second

// signFault, set only by the test harness (FakeSign), stands in for the
// module's C_SignInit and C_Sign: it returns the CK_RV to report.
var signFault func(s *Signer) (rv uint)

func (s *Signer) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

var _ hwkey.Key = (*Signer)(nil)

// trimField is a blank-padded CK_UTF8CHAR field without its padding.
func trimField(b []byte) string { return strings.TrimRight(string(b), " \x00") }

// matches reports whether the token in slot is one the URI names. A field the
// URI leaves out matches anything.
func (u URI) matches(slot uint, ti *ckTokenInfo) bool {
	for _, f := range []struct {
		want string
		got  []byte
	}{
		{u.Token, ti.label[:]}, {u.Manufacturer, ti.manufacturer[:]},
		{u.Serial, ti.serial[:]}, {u.Model, ti.model[:]},
	} {
		if f.want != "" && f.want != trimField(f.got) {
			return false
		}
	}
	return u.SlotID == nil || *u.SlotID == slot
}

// selector is the template that finds objects of class by the URI's id and
// object attributes (id overrides u.ID when the key's own CKA_ID is known).
func (u URI) selector(class uint, id []byte) []attr {
	t := []attr{{ckaClass, uintBytes(class)}}
	if len(id) > 0 {
		t = append(t, attr{ckaID, id})
	}
	if u.Object != "" && (class == ckoPrivateKey || len(id) == 0) {
		t = append(t, attr{ckaLabel, []byte(u.Object)})
	}
	return t
}

// candidate is one token that holds the key.
type candidate struct {
	slot          uint
	ti            *ckTokenInfo
	session       uint
	handle        uint
	id            []byte
	loginRequired bool
	shown         crypto.PublicKey // the public half a locked token shows for the id, if it does
}

func (c *candidate) name() string { return fmt.Sprintf("%q", trimField(c.ti.label[:])) }

// probe looks for the key on the token in slot with a session of its own.
// The private key is found directly when the token shows it; a token that
// hides it until login is a candidate when a public key or certificate with
// the key's id is visible.
func (m *Module) probe(u URI, slot uint, ti *ckTokenInfo) (*candidate, error) {
	session, err := m.openSession(slot, false)
	if err != nil {
		return nil, err
	}
	c := &candidate{slot: slot, ti: ti, session: session, loginRequired: ti.flags&ckfLoginRequired != 0, id: u.ID}
	keys, err := m.findObjects(session, u.selector(ckoPrivateKey, u.ID))
	if err != nil {
		m.closeSession(session)
		return nil, err
	}
	switch {
	case len(keys) > 1:
		m.closeSession(session)
		return nil, fmt.Errorf("pkcs11: more than one private key on token %s matches %s; add id or object", c.name(), u)
	case len(keys) == 1:
		c.handle = keys[0]
		if id, err := m.attrValue(session, c.handle, ckaID); err == nil && len(id) > 0 {
			c.id = id
		}
		return c, nil
	}
	if c.loginRequired {
		for _, class := range []uint{ckoPublicKey, ckoCertificate} {
			objs, err := m.findObjects(session, u.selector(class, u.ID))
			if err == nil && len(objs) > 0 {
				if id, err := m.attrValue(session, objs[0], ckaID); err == nil && len(id) > 0 {
					c.id = id
				}
				c.shown = m.shownPublic(session, class, objs[0])
				return c, nil
			}
		}
	}
	m.closeSession(session)
	return nil, nil
}

// shownPublic is the public key a public key object or a certificate shows,
// or nil when it cannot be read.
func (m *Module) shownPublic(session, class, obj uint) crypto.PublicKey {
	if class == ckoPublicKey {
		if pub, _, err := m.publicFromKeyObject(session, obj); err == nil {
			return pub
		}
		return nil
	}
	der, err := m.attrValue(session, obj, ckaValue)
	if err != nil {
		return nil
	}
	if c, err := x509.ParseCertificate(der); err == nil {
		return c.PublicKey
	}
	return nil
}

// blankToken reports whether err says the slot's token cannot be opened
// because it is not initialized or not there.
func blankToken(err error) bool {
	var re *rvError
	return errors.As(err, &re) && (re.rv == ckrTokenNotRecognized || re.rv == ckrTokenNotPresent)
}

// Open finds the key u names and opens a session on its token. Two tokens
// that both hold it are an error naming both. A token that needs login and a
// nil pin gives a Signer in the Locked state; a pin is sent once (C_Login)
// and zeroed.
func Open(u URI, pin []byte) (*Signer, error) {
	defer clear(pin)
	openCalls.Add(1)
	if u.Type != "" && u.Type != "private" {
		return nil, fmt.Errorf("pkcs11: type=%s names no private key; port49 signs with a private key", u.Type)
	}
	m, err := Load(u.ModulePath)
	if err != nil {
		return nil, err
	}
	slots, err := m.slotList()
	if err != nil {
		return nil, err
	}
	var found []*candidate
	closeAll := func() {
		for _, c := range found {
			m.closeSession(c.session)
		}
	}
	for _, slot := range slots {
		ti, err := m.tokenInfo(slot)
		if err != nil || !u.matches(slot, ti) {
			continue
		}
		c, err := m.probe(u, slot, ti)
		if blankToken(err) {
			continue // a slot whose token is blank or gone holds no key
		}
		if err != nil {
			closeAll()
			return nil, err
		}
		if c != nil {
			found = append(found, c)
		}
	}
	switch len(found) {
	case 0:
		return nil, fmt.Errorf("pkcs11: no token holds a key matching %s", u)
	case 1:
	default:
		names := make([]string, len(found))
		for i, c := range found {
			names[i] = c.name()
		}
		closeAll()
		return nil, fmt.Errorf("pkcs11: tokens %s all hold a key matching %s; add token= or serial= to pick one",
			strings.Join(names, " and "), u)
	}
	c := found[0]
	s := &Signer{m: m, uri: u, slot: c.slot, session: c.session, handle: c.handle, id: c.id,
		loginRequired: c.loginRequired, serial: trimField(c.ti.serial[:]), label: trimField(c.ti.label[:]),
		state: hwkey.Present}
	m.claim(s.session, s)
	if s.loginRequired {
		// Even a token that shows the key without login, as a PIV applet
		// does, wants the PIN to sign.
		s.state = hwkey.Locked
	}
	if err := s.readPublic(); err != nil {
		s.dropSession()
		return nil, err
	}
	if len(pin) > 0 && s.state == hwkey.Locked {
		if err := s.unlock(pin); err != nil {
			s.dropSession()
			return nil, err
		}
	}
	return s, nil
}

// readPublic fills pub, keyType and sigSize from the token's public key
// object, else its certificate, else (RSA) the private key's own attributes.
func (s *Signer) readPublic() error {
	m, sess := s.m, s.session
	if objs, err := m.findObjects(sess, s.uri.selector(ckoPublicKey, s.id)); err == nil && len(objs) > 0 {
		if pub, kt, err := m.publicFromKeyObject(sess, objs[0]); err == nil {
			return s.setPublic(pub, kt)
		}
	}
	if certs, err := s.certificatesLocked(s.id); err == nil && len(certs) > 0 {
		switch pub := certs[0].PublicKey.(type) {
		case *ecdsa.PublicKey:
			return s.setPublic(pub, ckkEC)
		case *rsa.PublicKey:
			return s.setPublic(pub, ckkRSA)
		case ed25519.PublicKey:
			return s.setPublic(pub, ckkECEdwards)
		}
	}
	if s.handle != 0 {
		if pub, kt, err := m.publicFromKeyObject(sess, s.handle); err == nil {
			return s.setPublic(pub, kt)
		}
	}
	return fmt.Errorf("pkcs11: the token shows no public key or certificate for %s; port49 needs one to know the key's type", s.uri)
}

func (s *Signer) setPublic(pub crypto.PublicKey, keyType uint) error {
	s.pub, s.keyType = pub, keyType
	if k, ok := pub.(*ecdsa.PublicKey); ok {
		s.sigSize = (k.Curve.Params().BitSize + 7) / 8
	}
	return nil
}

var oidECPublicKey = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}

// publicFromKeyObject reads a key object's public half.
func (m *Module) publicFromKeyObject(session, obj uint) (crypto.PublicKey, uint, error) {
	kt, err := m.attrValue(session, obj, ckaKeyType)
	if err != nil || len(kt) != 8 {
		return nil, 0, errors.New("pkcs11: the key's type is unreadable")
	}
	keyType := uint(binary.NativeEndian.Uint64(kt))
	switch keyType {
	case ckkRSA:
		n, err1 := m.attrValue(session, obj, ckaModulus)
		e, err2 := m.attrValue(session, obj, ckaPublicExponent)
		if err1 != nil || err2 != nil {
			return nil, 0, errors.New("pkcs11: the RSA key's modulus is unreadable")
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}, keyType, nil
	case ckkEC, ckkECEdwards:
		params, err1 := m.attrValue(session, obj, ckaECParams)
		point, err2 := m.attrValue(session, obj, ckaECPoint)
		if err1 != nil || err2 != nil {
			return nil, 0, errors.New("pkcs11: the EC key's point is unreadable")
		}
		pub, err := ecPublic(keyType, params, point)
		return pub, keyType, err
	}
	return nil, 0, fmt.Errorf("pkcs11: key type 0x%x is not one port49 signs with", keyType)
}

// ecPublic builds the public key from CKA_EC_PARAMS and CKA_EC_POINT. The
// point is a DER OCTET STRING per the standard, and a raw point from some
// modules; both are tried.
func ecPublic(keyType uint, params, point []byte) (crypto.PublicKey, error) {
	if keyType == ckkECEdwards {
		raw := point
		if len(raw) != ed25519.PublicKeySize {
			var inner []byte
			if rest, err := asn1.Unmarshal(point, &inner); err != nil || len(rest) != 0 {
				return nil, errors.New("pkcs11: the Ed25519 point is unreadable")
			}
			raw = inner
		}
		if len(raw) != ed25519.PublicKeySize {
			return nil, errors.New("pkcs11: the Ed25519 point is not 32 bytes")
		}
		return ed25519.PublicKey(append([]byte(nil), raw...)), nil
	}
	spki := func(pt []byte) (crypto.PublicKey, error) {
		der, err := asn1.Marshal(struct {
			Algorithm pkix.AlgorithmIdentifier
			Key       asn1.BitString
		}{
			pkix.AlgorithmIdentifier{Algorithm: oidECPublicKey, Parameters: asn1.RawValue{FullBytes: params}},
			asn1.BitString{Bytes: pt, BitLength: 8 * len(pt)},
		})
		if err != nil {
			return nil, err
		}
		return x509.ParsePKIXPublicKey(der)
	}
	if pub, err := spki(point); err == nil {
		return pub, nil
	}
	var inner []byte
	if rest, err := asn1.Unmarshal(point, &inner); err == nil && len(rest) == 0 {
		if pub, err := spki(inner); err == nil {
			return pub, nil
		}
	}
	return nil, errors.New("pkcs11: the EC point is not on the key's curve")
}

// Public is the key's public half.
func (s *Signer) Public() crypto.PublicKey { return s.pub }

// TokenSerial is the token's CK_TOKEN_INFO serial, trimmed (decision 45
// ruling 12's same-token check).
func (s *Signer) TokenSerial() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.serial
}

// TokenLabel is the token's CK_TOKEN_INFO label, trimmed: what a PIN prompt
// names the token by.
func (s *Signer) TokenLabel() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.label
}

// ModulePath is the PKCS#11 module the key was opened through: with
// TokenSerial, which token it is on (the agent's same-token check).
func (s *Signer) ModulePath() string { return s.m.path }

// Close lets go of the token's session. The module stays loaded: it is the
// process's.
func (s *Signer) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	s.dropSession()
	s.state = hwkey.Absent
	return nil
}

// State is the key's state. While the cached state is Absent it re-probes,
// with no PIN: C_GetSlotList(tokenPresent) and C_GetTokenInfo matched by the
// URI, then reopen. So a re-inserted key is seen with nothing signing first
// (decision 45 ruling 8): the held connection never needs a handshake.
func (s *Signer) State() hwkey.State {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.checkSession()
	if s.state == hwkey.Absent && !s.closed {
		s.reopenLocked()
	}
	return s.state
}

// dropSession closes the session while s still owns it and forgets its number
// (CK_INVALID_HANDLE): a module may give a lost session's number to another
// Signer's new one, which a close of the stale number would end.
func (s *Signer) dropSession() {
	s.m.closeOwned(s.session, s)
	s.session = 0
}

// checkSession turns a Signer whose session number another Signer now holds
// (or the module no longer knows) into an Absent one with no module call: the
// number is not its to use or close. The caller holds s.mu.
func (s *Signer) checkSession() {
	if s.state != hwkey.Absent && !s.m.holds(s.session, s) {
		s.session, s.handle, s.state = 0, 0, hwkey.Absent
	}
}

// absent records that the token is gone.
func (s *Signer) absent() {
	s.dropSession()
	s.state, s.handle = hwkey.Absent, 0
}

// reopenLocked looks for the token again after it was gone: C_CloseSession
// is ignored, the slot is found by the URI and a session opened; Locked if
// the token needs login, else Present. A different key under the same URI is
// not this one: the public half is compared when the token will show it.
func (s *Signer) reopenLocked() {
	slots, err := s.m.slotList()
	if err != nil {
		return
	}
	type match struct {
		slot uint
		ti   *ckTokenInfo
	}
	var loose []match
	for _, slot := range slots {
		if ti, err := s.m.tokenInfo(slot); err == nil && s.uri.matches(slot, ti) {
			loose = append(loose, match{slot, ti})
		}
	}
	if len(loose) > 1 {
		var same []match
		for _, c := range loose {
			if trimField(c.ti.serial[:]) == s.serial {
				same = append(same, c)
			}
		}
		if len(same) == 1 {
			loose = same
		}
	}
	var chosen *candidate
	// One token by its info fields is this one only when its serial says so
	// (it is the serial the Signer opened on, or the URI names one): a label
	// alone also fits a stranger's token, and Unlock would spend a PIN try
	// on it. Any other token must show the key, as Open requires.
	if len(loose) == 1 && (trimField(loose[0].ti.serial[:]) == s.serial || s.uri.Serial != "") {
		c := &candidate{slot: loose[0].slot, ti: loose[0].ti, id: s.id,
			loginRequired: loose[0].ti.flags&ckfLoginRequired != 0}
		c.session, err = s.m.openSession(c.slot, false)
		if err == nil {
			chosen = c
		}
	} else {
		for _, c := range loose {
			if p, err := s.m.probe(s.uri, c.slot, c.ti); err == nil && p != nil {
				// A token that shows another key under the id is a
				// stranger's: no PIN try is spent on it.
				if s.pub != nil && p.shown != nil && !samePublic(p.shown, s.pub) {
					s.m.closeSession(p.session)
					continue
				}
				if chosen != nil {
					s.m.closeSession(chosen.session)
					s.m.closeSession(p.session)
					return // two tokens could be this one: stay absent
				}
				chosen = p
			}
		}
	}
	if chosen == nil {
		return
	}
	s.slot, s.session, s.handle = chosen.slot, chosen.session, 0
	s.m.claim(s.session, s)
	s.loginRequired = chosen.loginRequired
	s.serial, s.label = trimField(chosen.ti.serial[:]), trimField(chosen.ti.label[:])
	if s.loginRequired {
		s.state = hwkey.Locked
		return
	}
	if !s.findKeyLocked() {
		s.absent()
		return
	}
	s.state = hwkey.Present
}

// findKeyLocked finds the private key on the open session and checks that it
// is the key this Signer was opened for.
func (s *Signer) findKeyLocked() bool {
	keys, err := s.m.findObjects(s.session, s.uri.selector(ckoPrivateKey, s.id))
	if err != nil || len(keys) != 1 {
		return false
	}
	s.handle = keys[0]
	if s.pub != nil {
		if objs, err := s.m.findObjects(s.session, s.uri.selector(ckoPublicKey, s.id)); err == nil && len(objs) > 0 {
			if pub, _, err := s.m.publicFromKeyObject(s.session, objs[0]); err == nil && !samePublic(pub, s.pub) {
				return false
			}
		}
	}
	return true
}

func samePublic(a, b crypto.PublicKey) bool {
	x, err1 := x509.MarshalPKIXPublicKey(a)
	y, err2 := x509.MarshalPKIXPublicKey(b)
	return err1 == nil && err2 == nil && bytes.Equal(x, y)
}

// Unlock logs the user in with pin, once, and zeroes pin. A refused PIN is a
// *hwkey.PINError carrying the token's own tries-left flags.
func (s *Signer) Unlock(pin []byte) error {
	defer clear(pin)
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.unlock(pin)
}

func (s *Signer) unlock(pin []byte) error {
	s.checkSession()
	if s.state == hwkey.Absent && !s.closed {
		s.reopenLocked()
	}
	switch s.state {
	case hwkey.Absent:
		return hwkey.ErrKeyAbsent
	case hwkey.Present:
		return nil
	}
	switch rv := s.m.login(s.session, ckuUser, pin); rv {
	case ckrOK, ckrUserAlreadyLoggedIn:
	case ckrPINIncorrect, ckrPINLocked:
		e := &hwkey.PINError{}
		if ti, err := s.m.tokenInfo(s.slot); err == nil {
			e.Low, e.Final = ti.flags&ckfPINCountLow != 0, ti.flags&ckfPINFinalTry != 0
		}
		if rv == ckrPINLocked {
			return fmt.Errorf("pkcs11: the token's PIN is locked; it needs the token's own unblock procedure: %w", e)
		}
		return e
	default:
		return s.classify("C_Login", &rvError{"C_Login", rv})
	}
	if !s.findKeyLocked() {
		return fmt.Errorf("pkcs11: after login the token shows no private key matching %s", s.uri)
	}
	s.state = hwkey.Present
	return nil
}

// classify turns a refusal that means the token is gone, or locked, into the
// hwkey errors and moves the state with it.
func (s *Signer) classify(fn string, err error) error {
	var re *rvError
	if !errors.As(err, &re) {
		return err
	}
	switch re.rv {
	case ckrDeviceRemoved, ckrTokenNotPresent, ckrSessionHandleInvalid, ckrSessionClosed,
		ckrDeviceError, ckrSlotIDInvalid, ckrObjectHandleInvalid, ckrTokenNotRecognized:
		s.absent()
		return fmt.Errorf("%w (%s)", hwkey.ErrKeyAbsent, re)
	case ckrUserNotLoggedIn:
		s.state = hwkey.Locked
		return fmt.Errorf("%w (%s)", hwkey.ErrLocked, re)
	}
	return err
}

// mechanism picks the token's mechanism for the key and the options.
func (s *Signer) mechanism(opts crypto.SignerOpts) (mech uint, param []byte, err error) {
	switch s.keyType {
	case ckkEC:
		return ckmECDSA, nil, nil
	case ckkECEdwards:
		if opts != nil && opts.HashFunc() != 0 {
			return 0, nil, errors.New("pkcs11: an Ed25519 key signs the message itself, not a digest")
		}
		return ckmEdDSA, nil, nil
	case ckkRSA:
		pss, ok := opts.(*rsa.PSSOptions)
		if !ok || opts.HashFunc() != crypto.SHA256 {
			return 0, nil, errors.New("pkcs11: an RSA key signs only RSA-PSS with SHA-256 (TLS 1.3 and the refresh signature use no other)")
		}
		if pss.SaltLength != rsa.PSSSaltLengthEqualsHash && pss.SaltLength != rsa.PSSSaltLengthAuto && pss.SaltLength != 32 {
			return 0, nil, fmt.Errorf("pkcs11: RSA-PSS salt length %d is not the hash's 32 bytes", pss.SaltLength)
		}
		param = make([]byte, 24)
		binary.NativeEndian.PutUint64(param[0:], ckmSHA256)
		binary.NativeEndian.PutUint64(param[8:], ckgMGF1SHA256)
		binary.NativeEndian.PutUint64(param[16:], 32)
		return ckmRSAPKCSPSS, param, nil
	}
	return 0, nil, fmt.Errorf("pkcs11: key type 0x%x is not one port49 signs with", s.keyType)
}

// Sign signs digest with the token's key: ECDSA (CKM_ECDSA, the raw r‖s
// turned into DER), RSA-PSS with SHA-256 (CKM_RSA_PKCS_PSS), or Ed25519
// (CKM_EDDSA over the message). A token gone is hwkey.ErrKeyAbsent, and the
// key's state Absent until State or Sign finds it again (reopen).
func (s *Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, hwkey.ErrKeyAbsent
	}
	s.checkSession()
	if s.state == hwkey.Absent {
		s.reopenLocked()
	}
	switch s.state {
	case hwkey.Absent:
		return nil, hwkey.ErrKeyAbsent
	case hwkey.Locked:
		return nil, hwkey.ErrLocked
	}
	mech, param, err := s.mechanism(opts)
	if err != nil {
		return nil, err
	}
	start := s.clock()
	var sig []byte
	if signFault != nil {
		err = &rvError{"C_Sign", signFault(s)}
	} else {
		sig, err = s.m.sign(s.session, mech, param, s.handle, digest)
	}
	if err != nil {
		var re *rvError
		if errors.As(err, &re) && re.fn == "C_Sign" && re.rv == ckrUserNotLoggedIn && s.clock().Sub(start) >= touchTimeoutMin {
			// A touch timeout: the token is still logged in, so the state stays.
			return nil, hwkey.ErrTouchTimeout
		}
		return nil, s.classify("C_Sign", err)
	}
	if s.keyType == ckkEC {
		return rawECDSAToDER(sig, s.sigSize)
	}
	return sig, nil
}

// certificatesLocked is every certificate object with CKA_ID id (every one
// on the token when id is empty).
func (s *Signer) certificatesLocked(id []byte) ([]*x509.Certificate, error) {
	t := []attr{{ckaClass, uintBytes(ckoCertificate)}}
	if len(id) > 0 {
		t = append(t, attr{ckaID, id})
	}
	objs, err := s.m.findObjects(s.session, t)
	if err != nil {
		return nil, err
	}
	var out []*x509.Certificate
	for _, o := range objs {
		der, err := s.m.attrValue(s.session, o, ckaValue)
		if err != nil {
			continue
		}
		if c, err := x509.ParseCertificate(der); err == nil {
			out = append(out, c)
		}
	}
	return out, nil
}

// Certificate is the token's certificate object with the key's CKA_ID.
func (s *Signer) Certificate() (*x509.Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.readyLocked(); err != nil {
		return nil, err
	}
	certs, err := s.certificatesLocked(s.id)
	if err != nil {
		return nil, s.classify("C_FindObjects", err)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("pkcs11: token %q holds no certificate with the key's CKA_ID", s.label)
	}
	return certs[0], nil
}

// Certificates is every certificate object on the key's token.
func (s *Signer) Certificates() ([]*x509.Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.readyLocked(); err != nil {
		return nil, err
	}
	certs, err := s.certificatesLocked(nil)
	if err != nil {
		return nil, s.classify("C_FindObjects", err)
	}
	return certs, nil
}

func (s *Signer) readyLocked() error {
	if s.closed {
		return hwkey.ErrKeyAbsent
	}
	s.checkSession()
	if s.state == hwkey.Absent {
		s.reopenLocked()
	}
	if s.state == hwkey.Absent {
		return hwkey.ErrKeyAbsent
	}
	return nil
}
