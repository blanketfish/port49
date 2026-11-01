package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/hwkey"
	"github.com/blanketfish/port49/internal/hwkey/hwfake"
	"github.com/blanketfish/port49/internal/hwkey/secureenclave"
	"github.com/blanketfish/port49/internal/userconfig"
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
		// None is looked for again under the lock before one is made.
		{name: "none yet", openErr: notFound, opened: 2, made: 1, wantGeneratedKey: true},
		{name: "none, and the Enclave refuses", openErr: notFound, genErr: osStatus, opened: 2, made: 1, wantErr: osStatus},
		{name: "an open that fails otherwise", openErr: osStatus, opened: 1, wantErr: osStatus},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("HOME", privateDir(t))
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

// Two first sign-ins at once on one Mac make one key, not two under one label
// (which would refuse every sign-in after): making it is serialised by a lock
// beside the held pair, and the second, once it holds the lock, looks again
// and opens the key the first made.
func TestTwoFirstSignInsAtOnceMakeOneKey(t *testing.T) {
	home := privateDir(t)
	t.Setenv("HOME", home)
	const label = "port49.broker.example_8443.aaaaaaaa"
	sf := &sessionFlags{broker: "https://broker.example:8443", issuedKeyStore: "secure_enclave"}
	spare := []hwkey.Key{fakeSEKey(t), fakeSEKey(t)}
	var (
		mu       sync.Mutex
		keychain []hwkey.Key
		opens    atomic.Int32
		looked   sync.WaitGroup
	)
	looked.Add(2)
	playMac(t, "aaaaaaaa",
		func(l string) (hwkey.Key, error) {
			if opens.Add(1) <= 2 {
				// Both sign-ins have looked and found none before either makes one.
				looked.Done()
				looked.Wait()
			}
			mu.Lock()
			defer mu.Unlock()
			switch len(keychain) {
			case 0:
				return nil, fmt.Errorf("%w: %s", secureenclave.ErrNotFound, l)
			case 1:
				return keychain[0], nil
			}
			return nil, &secureenclave.DuplicateError{Label: l, Count: len(keychain)}
		},
		func(l string) (hwkey.Key, error) {
			// The window in which a second sign-in would make a second key.
			time.Sleep(100 * time.Millisecond)
			mu.Lock()
			defer mu.Unlock()
			k := spare[len(keychain)]
			keychain = append(keychain, k)
			return k, nil
		})
	var wg sync.WaitGroup
	keys := make([]crypto.Signer, 2)
	errs := make([]error, 2)
	for i := range 2 {
		wg.Go(func() { keys[i], _, errs[i] = newIssuedKey(storeEncl, sf, "") })
	}
	wg.Wait()
	if len(keychain) != 1 || errs[0] != nil || errs[1] != nil || keys[0] != keys[1] || keys[0] != any(keychain[0]) {
		t.Fatalf("%d keys made; errors %v; keys the same: %v", len(keychain), errs, keys[0] == keys[1])
	}
	lock := filepath.Join(home, ".port49", "issued", label+".lock")
	if fi, err := os.Lstat(lock); err != nil || fi.Mode() != 0o600 {
		t.Fatalf("the lock beside the held pair: %v %v", fi, err)
	}
}

// Keys found under this broker's label anyway (made before the lock, or by
// another tool) are refused naming the label, the count and port49's own way
// to remove them, never a tool whose behavior with these keys is unmeasured.
func TestKeysUnderTheIssuedLabelNamePort49sRemedy(t *testing.T) {
	t.Setenv("HOME", privateDir(t))
	const label = "port49.broker.example_8443.aaaaaaaa"
	sf := &sessionFlags{broker: "https://broker.example:8443", issuedKeyStore: "secure_enclave"}
	dup := &secureenclave.DuplicateError{Label: label, Count: 2}
	var generated int
	playMac(t, "aaaaaaaa",
		func(string) (hwkey.Key, error) { return nil, dup },
		func(string) (hwkey.Key, error) { generated++; return nil, errors.New("not called") })
	key, _, err := newIssuedKey(storeEncl, sf, "")
	if key != nil || err == nil || generated != 0 {
		t.Fatalf("key %v err %v generated %d", key, err, generated)
	}
	for _, w := range []string{label, "2 Secure Enclave keys", "port49 login --delete-key", "log in again"} {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("%q is not in %q", w, err.Error())
		}
	}
	if strings.Contains(err.Error(), "Keychain Access") {
		t.Errorf("an unmeasured remedy: %q", err.Error())
	}
}

// `port49 login --delete-key` deletes this Mac's Secure Enclave keys for the
// broker, and the certificate held for them, after one line asking; the next
// sign-in makes one key. No is no, and a store that is not secure_enclave is
// refused before anything is asked.
func TestLoginDeleteKeyRemovesThisMacsKeysAfterAsking(t *testing.T) {
	t.Setenv("HOME", privateDir(t))
	const broker = "https://broker.example:8443"
	const label = "port49.broker.example_8443.aaaaaaaa"
	playMac(t, "aaaaaaaa", nil, nil)
	pd := deleteSE
	t.Cleanup(func() { deleteSE = pd })
	defer func(in io.Reader, tty func() bool) { confirmIn, confirmTTY = in, tty }(confirmIn, confirmTTY)
	confirmTTY = func() bool { return true }
	var deleted []string
	var deleteErr error
	deleteSE = func(l string) error { deleted = append(deleted, l); return deleteErr }
	conf := func(store string) string {
		cfg := filepath.Join(privateDir(t), "config.yaml")
		if err := os.WriteFile(cfg, []byte("broker: "+broker+"\nissued_key_store: "+store+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return cfg
	}
	cert, _ := userconfig.IssuedTokenPaths(broker, secureenclave.Ref(label))
	held := func() bool { _, err := os.Lstat(cert); return err == nil }
	login := func(answer, store string) (int, string, string) {
		t.Helper()
		confirmIn = strings.NewReader(answer)
		var out, errb bytes.Buffer
		code := run([]string{"login", "--delete-key", "--config", conf(store)}, &out, &errb)
		return code, out.String(), errb.String()
	}

	writePair(t, cert, cert+".unused")
	if code, out, errb := login("n\n", "secure_enclave"); code != 1 || len(deleted) != 0 || !held() ||
		!strings.Contains(errb, label) || !strings.Contains(errb, "[y/N]") || out != "" {
		t.Fatalf("no: code %d deleted %v held %v stdout %q stderr %q", code, deleted, held(), out, errb)
	}
	if code, out, errb := login("y\n", "secure_enclave"); code != 0 || len(deleted) != 1 || deleted[0] != label ||
		held() || !strings.Contains(out, label) {
		t.Fatalf("yes: code %d deleted %v held %v stdout %q stderr %q", code, deleted, held(), out, errb)
	}
	// None there is not a failure: the certificate held for them goes too.
	writePair(t, cert, cert+".unused")
	deleted, deleteErr = nil, fmt.Errorf("%w: %s", secureenclave.ErrNotFound, label)
	if code, out, errb := login("y\n", "secure_enclave"); code != 0 || len(deleted) != 1 || held() {
		t.Fatalf("none: code %d deleted %v held %v stdout %q stderr %q", code, deleted, held(), out, errb)
	}
	// A refusal keeps the certificate and says the OSStatus.
	writePair(t, cert, cert+".unused")
	deleted, deleteErr = nil, errors.New("secureenclave: SecItemDelete: OSStatus -34018 A required entitlement isn't present.")
	if code, _, errb := login("y\n", "secure_enclave"); code != 1 || !held() || !strings.Contains(errb, "-34018") {
		t.Fatalf("refused: code %d held %v stderr %q", code, held(), errb)
	}
	deleted, deleteErr = nil, nil
	for _, store := range []string{"file", "auto", "tpm"} {
		if code, _, errb := login("y\n", store); code != 2 || len(deleted) != 0 ||
			!strings.Contains(errb, "issued_key_store: secure_enclave") || strings.Contains(errb, "[y/N]") {
			t.Fatalf("%s: code %d deleted %v stderr %q", store, code, deleted, errb)
		}
	}
}

// On a Mac, a named secure_enclave whose label cannot be made (gethostuuid
// failing) is that error, not "no held pair" and a sign-in prompt wasted
// before the same error refuses it. Only "this is not macOS" reads as none.
func TestASecureEnclavePairOnAMacThatCannotBeNamedIsAnError(t *testing.T) {
	t.Setenv("HOME", privateDir(t))
	playMac(t, "aaaaaaaa", nil, nil)
	seHostID = func() (string, error) { return "", errors.New("secureenclave: gethostuuid did not name this Mac") }
	sf := &sessionFlags{broker: "https://broker.example:8443", issuedKeyStore: "secure_enclave"}
	if got, err := pickHeldPair(sf); err == nil || !strings.Contains(err.Error(), "gethostuuid") {
		t.Fatalf("%+v %v", got, err)
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
