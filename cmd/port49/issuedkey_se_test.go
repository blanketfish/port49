package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"syscall"
	"testing"

	"github.com/rhwendt/port49/internal/hwkey"
	"github.com/rhwendt/port49/internal/hwkey/hwfake"
	"github.com/rhwendt/port49/internal/hwkey/secureenclave"
	"github.com/rhwendt/port49/internal/userconfig"
)

// playMac makes this test's machine a Mac whose Secure Enclave is usable and
// named host, with open and generate as given (nil leaves them as they are).
func playMac(t *testing.T, host string, open, generate func(string) (hwkey.Key, error)) {
	t.Helper()
	pa, ph, po, pg := seAvailable, seHostID, openSE, generateSE
	t.Cleanup(func() { seAvailable, seHostID, openSE, generateSE = pa, ph, po, pg })
	seAvailable = func() error { return nil }
	seHostID = func() (string, error) { return host, nil }
	if open != nil {
		openSE = open
	}
	if generate != nil {
		generateSE = generate
	}
}

func fakeSEKey(t *testing.T) *hwfake.Key {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return hwfake.New(k, "", "")
}

// `auto` never picks the Secure Enclave, even on a Mac where it is usable:
// it is opt-in by name until L63 closes (decision 45 rulings 6 and 7). Named,
// on such a Mac, it is the store.
func TestAutoNeverPicksTheSecureEnclave(t *testing.T) {
	playMac(t, "aaaaaaaa", nil, nil)
	machineIs(t, "aaaaaaaa")
	noTPM := &fs.PathError{Op: "stat", Path: "/dev/tpmrm0", Err: syscall.ENOENT}
	for _, dialErr := range []error{nil, noTPM} {
		dialTPM(t, dialErr)
		for _, named := range []string{"", "auto"} {
			var out bytes.Buffer
			got, err := chooseIssuedStore(&sessionFlags{issuedKeyStore: named}, &out)
			if err != nil || got == storeEncl {
				t.Errorf("auto (%q, TPM %v): %q %v", named, dialErr, got, err)
			}
		}
	}
	var out bytes.Buffer
	if got, err := chooseIssuedStore(&sessionFlags{issuedKeyStore: "secure_enclave"}, &out); err != nil ||
		got != storeEncl || out.Len() != 0 {
		t.Fatalf("named on a Mac: %q %v said %q", got, err, out.String())
	}
}

// A Secure Enclave pair is this Mac's key, labeled for the broker and the
// machine, and the certificate named for that reference (decision 45 ruling
// 7): two Macs sharing a home keep a pair each, and a named store looks only
// for its own.
func TestASecureEnclavePairIsThisMachinesLabel(t *testing.T) {
	t.Setenv("HOME", privateDir(t))
	const broker = "https://broker.example:8443"
	const ref = "secure-enclave:label=port49.broker.example_8443.aaaaaaaa"
	playMac(t, "aaaaaaaa", nil, nil)
	fc, fk, _ := userconfig.IssuedPaths(broker)
	writePair(t, fc, fk)
	sf := &sessionFlags{broker: broker, issuedKeyStore: "secure_enclave"}
	got, err := pickHeldPair(sf)
	want, _ := userconfig.IssuedTokenPaths(broker, ref)
	if err != nil || got.store != storeEncl || got.key != ref || got.cert != want || got.cert == fc {
		t.Fatalf("the held pair: %+v %v; want %s and %s", got, err, want, ref)
	}
	if target, keyFile, err := issuedTarget(storeEncl, sf); err != nil || target != got || keyFile != "" {
		t.Fatalf("the target: %+v %q %v; want %+v and no key file", target, keyFile, err, got)
	}
	// With only the file pair on the home, a named secure_enclave has no held pair.
	if _, _, _, err := findHeld(sf); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("with only a .key: %v", err)
	}
	// Another Mac on the same home names another key and another certificate.
	playMac(t, "bbbbbbbb", nil, nil)
	other, err := pickHeldPair(sf)
	if err != nil || other.cert == got.cert || other.key == got.key {
		t.Fatalf("another Mac: %+v %v", other, err)
	}
	// Under auto the Secure Enclave's certificate is never the held pair.
	writePair(t, got.cert, fk)
	if p, err := pickHeldPair(&sessionFlags{broker: broker}); err != nil || p.store == storeEncl {
		t.Fatalf("auto: %+v %v", p, err)
	}
}

// Off macOS a named secure_enclave has no held pair, never an error: the
// sign-in that follows refuses, naming macOS.
func TestASecureEnclavePairOffMacOSIsNone(t *testing.T) {
	t.Setenv("HOME", privateDir(t))
	ph := seHostID
	t.Cleanup(func() { seHostID = ph })
	seHostID = func() (string, error) { return "", errors.New("secureenclave: the Secure Enclave is macOS's") }
	sf := &sessionFlags{broker: "https://broker.example:8443", issuedKeyStore: "secure_enclave"}
	got, err := pickHeldPair(sf)
	if err != nil || got.store != storeEncl {
		t.Fatalf("%+v %v", got, err)
	}
	if _, _, _, err := findHeld(sf); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("findHeld: %v", err)
	}
}

// The sign-in's Secure Enclave key is the one labeled for this broker and
// Mac, made once when no key has the label and kept across sign-ins as a
// token's is. Any other failure, an OSStatus among them, is a refusal and
// never a fallback to another store (ruling 6).
func TestTheSecureEnclaveKeyIsOpenedOrMadeOnce(t *testing.T) {
	const label = "port49.broker.example_8443.aaaaaaaa"
	sf := &sessionFlags{broker: "https://broker.example:8443", issuedKeyStore: "secure_enclave"}
	osStatus := errors.New("secureenclave: SecKeyCreateRandomKey: OSStatus -34018 A required entitlement isn't present.")
	notFound := fmt.Errorf("%w: %s", secureenclave.ErrNotFound, label)
	for _, c := range []struct {
		name             string
		openErr, genErr  error
		opened, made     int
		wantErr          error
		wantGeneratedKey bool
	}{
		{name: "held", opened: 1},
		{name: "none yet", openErr: notFound, opened: 1, made: 1, wantGeneratedKey: true},
		{name: "none, and the Enclave refuses", openErr: notFound, genErr: osStatus, opened: 1, made: 1, wantErr: osStatus},
		{name: "an open that fails otherwise", openErr: osStatus, opened: 1, wantErr: osStatus},
	} {
		t.Run(c.name, func(t *testing.T) {
			held, made := fakeSEKey(t), fakeSEKey(t)
			var opened, generated []string
			playMac(t, "aaaaaaaa",
				func(l string) (hwkey.Key, error) {
					opened = append(opened, l)
					if c.openErr != nil {
						return nil, c.openErr
					}
					return held, nil
				},
				func(l string) (hwkey.Key, error) {
					generated = append(generated, l)
					if c.genErr != nil {
						return nil, c.genErr
					}
					return made, nil
				})
			key, keyBytes, err := newIssuedKey(storeEncl, sf, "")
			if len(opened) != c.opened || len(generated) != c.made {
				t.Fatalf("opened %v generated %v", opened, generated)
			}
			for _, l := range append(opened, generated...) {
				if l != label {
					t.Errorf("label %q, want %q", l, label)
				}
			}
			if c.wantErr != nil {
				if key != nil || err == nil || !errors.Is(err, c.wantErr) {
					t.Fatalf("key %v err %v; want %v", key, err, c.wantErr)
				}
				return
			}
			want := held
			if c.wantGeneratedKey {
				want = made
			}
			if err != nil || keyBytes != nil || key != any(want) {
				t.Fatalf("key %v bytes %v err %v", key, keyBytes != nil, err)
			}
		})
	}
}

// A held Secure Enclave key that does not open is said as the Secure
// Enclave's, and a key that is gone is not "insert your key": it is made
// again at the sign-in.
func TestAHeldSecureEnclaveKeyErrorNamesItsStore(t *testing.T) {
	e := &heldKeyError{ref: "secure-enclave:label=x", err: fmt.Errorf("%w: x", secureenclave.ErrNotFound)}
	if e.store() != storeEncl || e.absent() {
		t.Fatalf("store %q absent %v", e.store(), e.absent())
	}
}
