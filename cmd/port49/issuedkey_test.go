package main

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"github.com/google/go-tpm/tpm2/transport"

	"github.com/rhwendt/port49/internal/clientkey"
	"github.com/rhwendt/port49/internal/hwkey/tpm"
	"github.com/rhwendt/port49/internal/userconfig"
)

// fakeTPM is a TPM that opens and answers nothing.
type fakeTPM struct{}

func (fakeTPM) Send([]byte) ([]byte, error) {
	return nil, errors.New("this fake TPM answers no command")
}
func (fakeTPM) Close() error { return nil }

// dialTPM makes tpm.Dial return err for the test, or a TPM that opens when err
// is nil.
func dialTPM(t *testing.T, err error) {
	t.Helper()
	prev := tpm.Dial
	tpm.Dial = func() (transport.TPMCloser, error) {
		if err != nil {
			return nil, err
		}
		return fakeTPM{}, nil
	}
	t.Cleanup(func() { tpm.Dial = prev })
}

// machineIs makes this machine's name id for the test.
func machineIs(t *testing.T, id string) {
	t.Helper()
	prev := userconfig.MachineID
	userconfig.MachineID = func() (string, error) { return id, nil }
	t.Cleanup(func() { userconfig.MachineID = prev })
}

const tokenRef = "pkcs11:token=lab;id=%10?module-path=/usr/lib/softhsm/libsofthsm2.so"

// The store is chosen before the sign-in, so one that cannot be used costs no
// password (decision 45 ruling 7). Every case that depends on the build reads
// clientkey.HasPKCS11, so the test holds under make test and make test-hw.
func TestChooseIssuedStore(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the TPM is Linux's")
	}
	noTPM := &fs.PathError{Op: "stat", Path: "/dev/tpmrm0", Err: syscall.ENOENT}
	machineIs(t, "aaaaaaaa")
	type tc struct {
		name    string
		sf      sessionFlags
		dialErr error
		want    string   // the store, "" for a refusal
		say     []string // in the line said, or in the refusal
	}
	cases := []tc{
		{name: "auto with no TPM is a file", dialErr: noTPM, want: "file",
			say: []string{"no TPM this user can use (", "no TPM answers", "); the key is a file"}},
		{name: "auto with a TPM is the TPM", want: "tpm", say: []string{"the key is made in this machine's TPM"}},
		{name: "auto with a TPM the user may not open names the group", dialErr: &fs.PathError{Op: "open", Err: syscall.EACCES},
			want: "file", say: []string{"add this user to the tss group", "the key is a file"}},
		{name: "file is a file and says nothing", sf: sessionFlags{issuedKeyStore: "file"}, want: "file"},
		{name: "tpm named with no TPM refuses", sf: sessionFlags{issuedKeyStore: "tpm"}, dialErr: noTPM,
			say: []string{"issued_key_store is tpm", "no TPM answers"}},
		{name: "tpm named with a TPM is the TPM", sf: sessionFlags{issuedKeyStore: "tpm"}, want: "tpm"},
		{name: "pkcs11 named without issued_key refuses", sf: sessionFlags{issuedKeyStore: "pkcs11"},
			say: []string{"issued_key"}},
		{name: "secure_enclave on Linux refuses", sf: sessionFlags{issuedKeyStore: "secure_enclave"},
			say: []string{"secure_enclave"}},
		{name: "a TPM reference is no issued_key for pkcs11", sf: sessionFlags{issuedKeyStore: "pkcs11", issuedKey: "tpm:handle=0x81000001"},
			say: []string{"issued_key", "pkcs11:"}},
	}
	if clientkey.HasPKCS11 {
		cases = append(cases,
			tc{name: "auto with touch_key and issued_key is the token", sf: sessionFlags{touchKey: tokenRef, issuedKey: tokenRef},
				want: "pkcs11", say: []string{"the key is the one issued_key names, on your token"}},
			tc{name: "pkcs11 named is the token", sf: sessionFlags{issuedKeyStore: "pkcs11", issuedKey: tokenRef}, want: "pkcs11"},
			tc{name: "auto with issued_key alone does not pick the token", sf: sessionFlags{issuedKey: tokenRef}, want: "tpm"})
	} else {
		cases = append(cases,
			tc{name: "auto with touch_key and issued_key passes over pkcs11 and uses the TPM",
				sf: sessionFlags{touchKey: tokenRef, issuedKey: tokenRef}, want: "tpm",
				say: []string{"built without PKCS#11 support, so issued_key is not used", "use the client release", "TPM"}},
			tc{name: "auto with touch_key and issued_key passes over pkcs11 and uses the file",
				sf: sessionFlags{touchKey: tokenRef, issuedKey: tokenRef}, dialErr: noTPM, want: "file",
				say: []string{"built without PKCS#11 support, so issued_key is not used", "the key is a file"}},
			tc{name: "pkcs11 named in the static build refuses naming the client release",
				sf:  sessionFlags{issuedKeyStore: "pkcs11", issuedKey: tokenRef},
				say: []string{"built without PKCS#11 support", "client release"}})
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dialTPM(t, c.dialErr)
			var out bytes.Buffer
			got, err := chooseIssuedStore(&c.sf, &out)
			text := out.String()
			if err != nil {
				text += err.Error()
			}
			if (c.want == "") != (err != nil) || got != c.want {
				t.Fatalf("store %q, err %v (said %q); want %q", got, err, out.String(), c.want)
			}
			for _, s := range c.say {
				if !strings.Contains(text, s) {
					t.Errorf("%q is not in %q", s, text)
				}
			}
			if c.want == "file" && c.sf.issuedKeyStore == "file" && out.Len() != 0 {
				t.Errorf("a file named says nothing: %q", out.String())
			}
			if strings.Count(out.String(), "\n") > 1 {
				t.Errorf("the login says which store in one line: %q", out.String())
			}
		})
	}
}

// A store that cannot be used refuses before the browser opens and the
// provider is asked for a sign-in, so no password is spent (decision 43
// ruling 18's rule).
func TestANamedStoreThatCannotBeUsedRefusesBeforeTheSignIn(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the TPM is Linux's")
	}
	o := newOIDCLab(t, true)
	driveBrowser(t, o.iss)
	dialTPM(t, errors.New("no tpm here"))
	machineIs(t, "aaaaaaaa")
	cfg := filepath.Join(privateDir(t), "config.yaml")
	if err := os.WriteFile(cfg, []byte("issued_key_store: tpm\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sock := privateSocket(t)
	t.Cleanup(func() { stopAgentAt(sock) })
	t.Setenv(runCLIEnv, "1")
	var out, errb bytes.Buffer
	code := run(append([]string{"login", "--config", cfg}, o.flags(sock)...), &out, &errb)
	if code == 0 || !strings.Contains(errb.String(), "issued_key_store is tpm") {
		t.Fatalf("code %d stdout %q stderr %q", code, out.String(), errb.String())
	}
	if n := len(o.as.Authorizations()); n != 0 {
		t.Fatalf("%d sign-ins were started; the refusal comes first", n)
	}
	certPath, keyPath := o.issuedPaths(t)
	for _, p := range []string{certPath, keyPath} {
		if _, err := os.Lstat(p); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s: %v", p, err)
		}
	}
}

// A TPM that opens but cannot make a key (an owner password on the storage
// hierarchy, say) must not make `auto` fail for good: the login says so and
// the key is a file.
func TestAutoFallsBackToAFileWhenTheTPMCannotMakeAKey(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the TPM is Linux's")
	}
	o := newOIDCLab(t, true)
	driveBrowser(t, o.iss)
	dialTPM(t, nil)
	machineIs(t, "aaaaaaaa")
	sock := privateSocket(t)
	t.Cleanup(func() { stopAgentAt(sock) })
	t.Setenv(runCLIEnv, "1")
	var out, errb bytes.Buffer
	if code := run(append([]string{"login"}, o.flags(sock)...), &out, &errb); code != 0 ||
		!strings.Contains(errb.String(), "the TPM could not make a key") || !strings.Contains(errb.String(), "the key is a file") {
		t.Fatalf("code %d stdout %q stderr %q", code, out.String(), errb.String())
	}
	certPath, keyPath := o.issuedPaths(t)
	for _, p := range []string{certPath, keyPath} {
		if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v %v", p, fi, err)
		}
	}
}

// writePair writes a placeholder certificate and key file where a login
// keeps them.
func writePair(t *testing.T, cert, key string) {
	t.Helper()
	for _, p := range []string{cert, key} {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("placeholder "+filepath.Base(p)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// A held TPM pair is found by its key file, with no .key beside it (ruling 7:
// "a held pair is found by either key file"), and read as a reference.
func TestAHeldTPMPairIsFound(t *testing.T) {
	machineIs(t, "aaaaaaaa")
	home := privateDir(t)
	t.Setenv("HOME", home)
	const broker = "https://broker.example:8443"
	tc, tk, err := userconfig.IssuedTPMPaths(broker)
	if err != nil {
		t.Fatal(err)
	}
	writePair(t, tc, tk)
	got, err := pickHeldPair(&sessionFlags{broker: broker})
	if err != nil || got.store != "tpm" || got.cert != tc || got.key != "tpm:file="+tk {
		t.Fatalf("the held pair: %+v %v", got, err)
	}
	// A .key beside it comes first: the file pair is the older one, and a login
	// that issues into the TPM removes it.
	fc, fk, _ := userconfig.IssuedPaths(broker)
	writePair(t, fc, fk)
	if got, err = pickHeldPair(&sessionFlags{broker: broker}); err != nil || got.store != "file" || got.key != fk {
		t.Fatalf("with a .key too: %+v %v", got, err)
	}
}

// A pkcs11 issued_key names the held key: the certificate is the .pem, the
// key is the reference.
func TestAHeldPKCS11PairIsTheReference(t *testing.T) {
	home := privateDir(t)
	t.Setenv("HOME", home)
	const broker = "https://broker.example:8443"
	fc, _, _ := userconfig.IssuedPaths(broker)
	writePair(t, fc, filepath.Join(filepath.Dir(fc), "unrelated"))
	sf := &sessionFlags{broker: broker, issuedKeyStore: "pkcs11", issuedKey: tokenRef}
	got, err := pickHeldPair(sf)
	if err != nil || got.store != "pkcs11" || got.cert != fc || got.key != tokenRef {
		t.Fatalf("the held pair: %+v %v", got, err)
	}
	// Without the store named, the certificate alone is no pair.
	if _, _, _, err := findHeld(&sessionFlags{broker: broker}); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a certificate with no key: %v", err)
	}
}

// Another machine's TPM key on a shared home is not looked at: no held pair
// (a sign-in), never an error (pre-flight I12).
func TestAnotherMachinesTPMKeyIsNoHeldPair(t *testing.T) {
	home := privateDir(t)
	t.Setenv("HOME", home)
	const broker = "https://broker.example:8443"
	machineIs(t, "bbbbbbbb")
	bc, bk, err := userconfig.IssuedTPMPaths(broker)
	if err != nil {
		t.Fatal(err)
	}
	writePair(t, bc, bk)
	machineIs(t, "aaaaaaaa")
	if _, _, _, err := findHeld(&sessionFlags{broker: broker}); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("another machine's pair: %v, want no held pair", err)
	}
	ac, ak, _ := userconfig.IssuedTPMPaths(broker)
	if ac == bc || ak == bk {
		t.Fatalf("both machines name %s", ac)
	}
}

// A pair is removed as the login that kept it keeps it: a key file by its
// path, a TPM key by the file its reference names, a token's key never.
func TestRemoveIssuedLeavesTheTokenAlone(t *testing.T) {
	dir := privateDir(t)
	cert, tk := filepath.Join(dir, "c.pem"), filepath.Join(dir, "c.tpmkey")
	writePair(t, cert, tk)
	removeIssued(cert, "tpm:file="+tk)
	for _, p := range []string{cert, tk} {
		if _, err := os.Lstat(p); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s was not removed: %v", p, err)
		}
	}
	writePair(t, cert, filepath.Join(dir, "unrelated"))
	removeIssued(cert, tokenRef)
	if _, err := os.Lstat(cert); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the certificate was not removed: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "unrelated")); err != nil {
		t.Errorf("a pkcs11 reference removed a file: %v", err)
	}
}
