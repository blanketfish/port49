//go:build hwkey

package tpm_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"

	"github.com/rhwendt/port49/internal/hwkey"
	"github.com/rhwendt/port49/internal/hwkey/hwtest"
	"github.com/rhwendt/port49/internal/hwkey/tpm"
)

const persistent tpm2.TPMHandle = 0x81000010

// template is port49's key template, with mod applied: a test makes the keys
// port49 does not make (a password, a duplicable key) by changing it.
func template(mod func(*tpm2.TPMTPublic)) tpm2.TPMTPublic {
	p := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM: true, FixedParent: true, SensitiveDataOrigin: true, UserWithAuth: true, SignEncrypt: true,
		},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
			Scheme: tpm2.TPMTECCScheme{
				Scheme:  tpm2.TPMAlgECDSA,
				Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA256}),
			},
			CurveID: tpm2.TPMECCNistP256,
		}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
			X: tpm2.TPM2BECCParameter{Buffer: make([]byte, 32)},
			Y: tpm2.TPM2BECCParameter{Buffer: make([]byte, 32)},
		}),
	}
	if mod != nil {
		mod(&p)
	}
	return p
}

// onTPM runs fn on a connection of its own, closed on return: swtpm serves one
// connection at a time, so a test must not hold one while port49 dials.
func onTPM(t *testing.T, fn func(transport.TPM)) {
	t.Helper()
	c, err := tpm.Dial()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fn(c)
}

// rawKey makes a key under the SRK by hand and returns it loaded, with its
// blobs; the caller flushes nothing, the swtpm is thrown away with the test.
func rawKey(t *testing.T, c transport.TPM, mod func(*tpm2.TPMTPublic), auth []byte) (tpm2.TPM2BPublic, tpm2.TPM2BPrivate, tpm2.AuthHandle) {
	t.Helper()
	root, err := tpm2.CreatePrimary{PrimaryHandle: tpm2.TPMRHOwner, InPublic: tpm2.New2B(tpm2.ECCSRKTemplate)}.Execute(c)
	if err != nil {
		t.Fatal(err)
	}
	parent := tpm2.AuthHandle{Handle: root.ObjectHandle, Name: root.Name, Auth: tpm2.PasswordAuth(nil)}
	made, err := tpm2.Create{
		ParentHandle: parent,
		InSensitive:  tpm2.TPM2BSensitiveCreate{Sensitive: &tpm2.TPMSSensitiveCreate{UserAuth: tpm2.TPM2BAuth{Buffer: auth}}},
		InPublic:     tpm2.New2B(template(mod)),
	}.Execute(c)
	if err != nil {
		t.Fatal(err)
	}
	ld, err := tpm2.Load{ParentHandle: parent, InPrivate: made.OutPrivate, InPublic: made.OutPublic}.Execute(c)
	if err != nil {
		t.Fatal(err)
	}
	// swtpm has no resource manager: a handle left loaded is object memory gone.
	_, _ = tpm2.FlushContext{FlushHandle: root.ObjectHandle}.Execute(c)
	return made.OutPublic, made.OutPrivate, tpm2.AuthHandle{Handle: ld.ObjectHandle, Name: ld.Name, Auth: tpm2.PasswordAuth(auth)}
}

func flushKey(c transport.TPM, k tpm2.AuthHandle) {
	_, _ = tpm2.FlushContext{FlushHandle: k.Handle}.Execute(c)
}

// persist makes a key and keeps it at the persistent handle. It is NoDA unless
// mod says otherwise, as a key made with tpm2_create -a noda|... is.
func persist(t *testing.T, c transport.TPM, mod func(*tpm2.TPMTPublic), auth []byte) {
	t.Helper()
	_, _, key := rawKey(t, c, func(p *tpm2.TPMTPublic) {
		p.ObjectAttributes.NoDA = true
		if mod != nil {
			mod(p)
		}
	}, auth)
	if _, err := (tpm2.EvictControl{
		Auth:             tpm2.TPMRHOwner,
		ObjectHandle:     &tpm2.NamedHandle{Handle: key.Handle, Name: key.Name},
		PersistentHandle: persistent,
	}).Execute(c); err != nil {
		t.Fatal(err)
	}
	flushKey(c, key)
}

// evict removes the key at the persistent handle.
func evict(t *testing.T, c transport.TPM) {
	t.Helper()
	rp, err := tpm2.ReadPublic{ObjectHandle: persistent}.Execute(c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (tpm2.EvictControl{
		Auth:             tpm2.TPMRHOwner,
		ObjectHandle:     &tpm2.NamedHandle{Handle: persistent, Name: rp.Name},
		PersistentHandle: persistent,
	}).Execute(c); err != nil {
		t.Fatal(err)
	}
}

// daCounter is the TPM's count of failed authorizations.
func daCounter(t *testing.T, c transport.TPM) uint32 {
	t.Helper()
	rsp, err := tpm2.GetCapability{
		Capability: tpm2.TPMCapTPMProperties, Property: uint32(tpm2.TPMPTLockoutCounter), PropertyCount: 1,
	}.Execute(c)
	if err != nil {
		t.Fatal(err)
	}
	props, err := rsp.CapabilityData.Data.TPMProperties()
	if err != nil || len(props.TPMProperty) == 0 {
		t.Fatalf("lockout counter: %v", err)
	}
	return props.TPMProperty[0].Value
}

func verifies(t *testing.T, s *tpm.Signer) {
	t.Helper()
	digest := sha256.Sum256([]byte("a message"))
	sig, err := s.Sign(nil, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !ecdsa.VerifyASN1(s.Public().(*ecdsa.PublicKey), digest[:], sig) {
		t.Fatal("the signature does not verify")
	}
}

func TestAPersistentKeySignsAndSurvivesAStop(t *testing.T) {
	sim := hwtest.SWTPM(t)
	onTPM(t, func(c transport.TPM) { persist(t, c, nil, nil) })
	s, err := tpm.OpenHandle(uint32(persistent))
	if err != nil {
		t.Fatal(err)
	}
	verifies(t, s)
	sim.Stop()
	digest := sha256.Sum256([]byte("x"))
	if _, err := s.Sign(nil, digest[:], crypto.SHA256); !errors.Is(err, hwkey.ErrKeyAbsent) || s.State() != hwkey.Absent {
		t.Fatalf("Sign with swtpm stopped = %v, state %v", err, s.State())
	}
	sim.Restart()
	if got := s.State(); got != hwkey.Present {
		t.Fatalf("State after restart = %v, want Present", got)
	}
	verifies(t, s)
}

func wantDACounter(t *testing.T, want uint32) {
	t.Helper()
	onTPM(t, func(c transport.TPM) {
		if n := daCounter(t, c); n != want {
			t.Fatalf("the DA counter is %d, want %d: port49 spent a lockout try", n, want)
		}
	})
}

func TestAPersistentKeyWithAPasswordIsRefusedWithoutSpendingATry(t *testing.T) {
	hwtest.SWTPM(t)
	onTPM(t, func(c transport.TPM) { persist(t, c, nil, []byte("hunter2")) })
	for i := 0; i < 5; i++ {
		if _, err := tpm.OpenHandle(uint32(persistent)); err == nil || !strings.Contains(err.Error(), "password") {
			t.Fatalf("OpenHandle %d on a key with a password = %v, want refused naming the password", i, err)
		}
	}
	wantDACounter(t, 0)
}

func TestAPersistentKeyWithoutNoDAIsRefusedBeforeAnyTry(t *testing.T) {
	hwtest.SWTPM(t)
	onTPM(t, func(c transport.TPM) {
		persist(t, c, func(p *tpm2.TPMTPublic) { p.ObjectAttributes.NoDA = false }, []byte("hunter2"))
	})
	for i := 0; i < 5; i++ {
		_, err := tpm.OpenHandle(uint32(persistent))
		if err == nil || !strings.Contains(err.Error(), "0x81000010") || !strings.Contains(err.Error(), "noda|fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign") {
			t.Fatalf("OpenHandle %d on a DA-protected key = %v, want refused naming the handle and the attributes", i, err)
		}
	}
	wantDACounter(t, 0)
}

func TestANoDAPersistentKeyWithAnEmptyAuthOpensAndSigns(t *testing.T) {
	hwtest.SWTPM(t)
	onTPM(t, func(c transport.TPM) { persist(t, c, nil, nil) })
	s, err := tpm.OpenHandle(uint32(persistent))
	if err != nil {
		t.Fatal(err)
	}
	verifies(t, s)
	wantDACounter(t, 0)
}

func TestAPersistentKeyReplacedByAnotherIsRefusedBeforeAnyTry(t *testing.T) {
	hwtest.SWTPM(t)
	onTPM(t, func(c transport.TPM) { persist(t, c, nil, nil) })
	s, err := tpm.OpenHandle(uint32(persistent))
	if err != nil {
		t.Fatal(err)
	}
	// Someone replaces the key at the handle with a different one, here with a
	// password.
	onTPM(t, func(c transport.TPM) {
		evict(t, c)
		persist(t, c, nil, []byte("hunter2"))
	})
	digest := sha256.Sum256([]byte("x"))
	for i := 0; i < 3; i++ {
		if _, err := s.Sign(nil, digest[:], crypto.SHA256); err == nil || !strings.Contains(err.Error(), "changed since port49 opened it") {
			t.Fatalf("Sign %d = %v, want the changed-key message", i, err)
		}
	}
	wantDACounter(t, 0)
}

func TestARestrictedKeyIsRefused(t *testing.T) {
	hwtest.SWTPM(t)
	restricted := func(p *tpm2.TPMTPublic) { p.ObjectAttributes.Restricted = true }
	onTPM(t, func(c transport.TPM) { persist(t, c, restricted, nil) })
	if _, err := tpm.OpenHandle(uint32(persistent)); err == nil || !strings.Contains(err.Error(), "restricted") {
		t.Fatalf("OpenHandle on a restricted key = %v, want refused naming restricted", err)
	}
	var pub tpm2.TPM2BPublic
	var priv tpm2.TPM2BPrivate
	onTPM(t, func(c transport.TPM) {
		var key tpm2.AuthHandle
		pub, priv, key = rawKey(t, c, restricted, nil)
		flushKey(c, key)
	})
	file, err := tpm.EncodeTSS2(pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "r.tpmkey")
	if err := os.WriteFile(path, file, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := tpm.Open(path); err == nil || !strings.Contains(err.Error(), "restricted") {
		t.Fatalf("Open on a restricted key = %v, want refused naming restricted", err)
	}
}

func TestAMissingPersistentHandleIsNamedAndNotAbsent(t *testing.T) {
	hwtest.SWTPM(t)
	_, err := tpm.OpenHandle(uint32(persistent))
	if err == nil || !strings.Contains(err.Error(), "0x81000010") || strings.Contains(err.Error(), "TPM_RC") {
		t.Fatalf("OpenHandle with no key there = %v, want a plain message naming the handle", err)
	}
	if errors.Is(err, hwkey.ErrKeyAbsent) {
		t.Fatal("a handle that is not on a TPM that answers is not ErrKeyAbsent: re-probing the TPM cannot bring it back")
	}
}

func TestAPersistentKeyThatCouldLeaveTheTPMIsRefused(t *testing.T) {
	hwtest.SWTPM(t)
	onTPM(t, func(c transport.TPM) {
		persist(t, c, func(p *tpm2.TPMTPublic) {
			p.ObjectAttributes.FixedTPM = false
			p.ObjectAttributes.FixedParent = false
		}, nil)
	})
	if _, err := tpm.OpenHandle(uint32(persistent)); err == nil || !strings.Contains(err.Error(), "FixedTPM") {
		t.Fatalf("OpenHandle on a duplicable key = %v, want refused naming FixedTPM", err)
	}
}

func TestAKeyFileThatCouldLeaveTheTPMIsRefused(t *testing.T) {
	hwtest.SWTPM(t)
	var pub tpm2.TPM2BPublic
	var priv tpm2.TPM2BPrivate
	onTPM(t, func(c transport.TPM) {
		var key tpm2.AuthHandle
		pub, priv, key = rawKey(t, c, func(p *tpm2.TPMTPublic) {
			p.ObjectAttributes.FixedTPM = false
			p.ObjectAttributes.FixedParent = false
		}, nil)
		flushKey(c, key)
	})
	file, err := tpm.EncodeTSS2(pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "dup.tpmkey")
	if err := os.WriteFile(path, file, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := tpm.Open(path); err == nil || !strings.Contains(err.Error(), "FixedTPM") {
		t.Fatalf("Open on a duplicable key = %v, want refused naming FixedTPM", err)
	}
}

func TestAKeyFileOthersCanReadIsRefused(t *testing.T) {
	hwtest.SWTPM(t)
	path := filepath.Join(t.TempDir(), "k.tpmkey")
	if _, err := tpm.Generate(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := tpm.Open(path); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("Open on a 0644 key file = %v, want refused with the chmod advice", err)
	}
}

func TestAClearedTPMIsNotBlamedOnAnotherMachineAlone(t *testing.T) {
	hwtest.SWTPM(t)
	path := filepath.Join(t.TempDir(), "k.tpmkey")
	if _, err := tpm.Generate(path); err != nil {
		t.Fatal(err)
	}
	onTPM(t, func(c transport.TPM) {
		if _, err := (tpm2.Clear{AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHLockout, Auth: tpm2.PasswordAuth(nil)}}).Execute(c); err != nil {
			t.Fatal(err)
		}
	})
	if _, err := tpm.Open(path); err == nil || !strings.Contains(err.Error(), "was cleared") {
		t.Fatalf("Open after TPM2_Clear = %v, want the cleared-TPM possibility named", err)
	}
}

func TestADictionaryAttackLockoutDoesNotStopAGeneratedKey(t *testing.T) {
	hwtest.SWTPM(t)
	path := filepath.Join(t.TempDir(), "k.tpmkey")
	s, err := tpm.Generate(path)
	if err != nil {
		t.Fatal(err)
	}
	// Another user of the TPM trips dictionary-attack lockout with wrong auths
	// on a key that has a password.
	var lockedOut bool
	onTPM(t, func(c transport.TPM) {
		_, _, locked := rawKey(t, c, nil, []byte("hunter2"))
		locked.Auth = tpm2.PasswordAuth([]byte("wrong"))
		for i := 0; i < 10 && !lockedOut; i++ {
			_, err := tpm2.Sign{
				KeyHandle:  locked,
				Digest:     tpm2.TPM2BDigest{Buffer: make([]byte, 32)},
				InScheme:   tpm2.TPMTSigScheme{Scheme: tpm2.TPMAlgECDSA, Details: tpm2.NewTPMUSigScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSchemeHash{HashAlg: tpm2.TPMAlgSHA256})},
				Validation: tpm2.TPMTTKHashCheck{Tag: tpm2.TPMSTHashCheck, Hierarchy: tpm2.TPMRHNull},
			}.Execute(c)
			lockedOut = errors.Is(err, tpm2.TPMRCLockout)
		}
		flushKey(c, locked)
	})
	if !lockedOut {
		t.Fatal("the TPM never went into lockout; the test proves nothing")
	}
	verifies(t, s)
	again, err := tpm.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	verifies(t, again)
}
