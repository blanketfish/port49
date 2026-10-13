package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"

	"github.com/rhwendt/port49/internal/clientkey"
	"github.com/rhwendt/port49/internal/hwkey"
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
			say: []string{"no TPM this user can use (", "no TPM answers", "); the key is a file ("}},
		{name: "auto with a TPM is the TPM and says nothing yet", want: "tpm"},
		{name: "auto with a lone issued_key says it is ignored", sf: sessionFlags{issuedKey: tokenRef}, dialErr: noTPM, want: "file",
			say: []string{"issued_key is used only with touch_key", "the key is a file"}},
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
				sf: sessionFlags{touchKey: tokenRef, issuedKey: tokenRef}, want: "tpm"},
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
	dialTPM(t, nil)
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
	// A .key beside it is another machine's on a shared home, or an older
	// one's: this machine's own pair comes first and the .key is left alone
	// (decision 45 ruling 7).
	fc, fk, _ := userconfig.IssuedPaths(broker)
	writePair(t, fc, fk)
	if got, err = pickHeldPair(&sessionFlags{broker: broker}); err != nil || got.store != "tpm" || got.key != "tpm:file="+tk {
		t.Fatalf("with a .key too: %+v %v", got, err)
	}
	// Without a TPM pair of its own, the file pair is the one.
	if err := os.Remove(tk); err != nil {
		t.Fatal(err)
	}
	if got, err = pickHeldPair(&sessionFlags{broker: broker}); err != nil || got.store != "file" || got.key != fk {
		t.Fatalf("with the .key alone: %+v %v", got, err)
	}
}

// Under `auto` the held pair is the one of the store `auto` would choose now
// (decision 45 ruling 7): a host that gained touch_key and issued_key while
// holding a TPM pair resolves to its token certificate once that exists, so it
// does not sign in at every login.
func TestAutoLooksForTheHeldPairOfTheStoreItWouldChoose(t *testing.T) {
	if !clientkey.HasPKCS11 {
		t.Skip("the token store is in the client build only (make test-hw)")
	}
	machineIs(t, "aaaaaaaa")
	dialTPM(t, nil)
	t.Setenv("HOME", privateDir(t))
	const broker = "https://broker.example:8443"
	tc, tk, _ := userconfig.IssuedTPMPaths(broker)
	writePair(t, tc, tk)
	sf := &sessionFlags{broker: broker, touchKey: tokenRef, issuedKey: tokenRef}
	if got, err := pickHeldPair(sf); err != nil || got.store != "tpm" {
		t.Fatalf("with only the TPM pair: %+v %v", got, err)
	}
	tokc, err := tokenTarget(sf)
	if err != nil {
		t.Fatal(err)
	}
	writePair(t, tokc, filepath.Join(filepath.Dir(tokc), "unrelated"))
	got, err := pickHeldPair(sf)
	if err != nil || got.store != "pkcs11" || got.cert != tokc || got.key != tokenRef {
		t.Fatalf("with both: %+v %v", got, err)
	}
	// Without touch_key the token is not what auto would choose.
	sf.touchKey = ""
	if got, err := pickHeldPair(sf); err != nil || got.store != "tpm" {
		t.Fatalf("without touch_key: %+v %v", got, err)
	}
}

// Under `auto` a held TPM pair is passed over when the TPM cannot be used, as
// a new sign-in would pass over it: the file pair, so --sign-in is not needed
// at every login.
func TestAutoPassesOverAHeldTPMPairWhenTheTPMIsGone(t *testing.T) {
	machineIs(t, "aaaaaaaa")
	t.Setenv("HOME", privateDir(t))
	const broker = "https://broker.example:8443"
	tc, tk, _ := userconfig.IssuedTPMPaths(broker)
	writePair(t, tc, tk)
	fc, fk, _ := userconfig.IssuedPaths(broker)
	writePair(t, fc, fk)
	sf := &sessionFlags{broker: broker}
	dialTPM(t, nil)
	if got, err := pickHeldPair(sf); err != nil || got.store != "tpm" {
		t.Fatalf("with a TPM: %+v %v", got, err)
	}
	dialTPM(t, &fs.PathError{Op: "stat", Path: "/dev/tpmrm0", Err: syscall.ENOENT})
	if got, err := pickHeldPair(sf); err != nil || got.store != "file" || got.key != fk {
		t.Fatalf("without a TPM: %+v %v", got, err)
	}
	// A named tpm is still the TPM pair: the operator chose it.
	sf.issuedKeyStore = "tpm"
	if got, err := pickHeldPair(sf); err != nil || got.store != "tpm" {
		t.Fatalf("tpm named without a TPM: %+v %v", got, err)
	}
}

// Under `auto` a held TPM pair that would need a sign-in anyway is passed over
// for a file pair that would not: a TPM that opens but will not make a key
// leaves the file pair the fallback wrote, and that pair is found next time
// (task 7 A3). With no such file pair the TPM pair is still the one, and a
// named tpm never looks at the file pair.
func TestAutoPassesOverAHeldTPMPairThatWouldNeedASignIn(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the TPM is Linux's")
	}
	t.Setenv("HOME", privateDir(t))
	o := newOIDCLab(t, true)
	dialTPM(t, nil)
	machineIs(t, "aaaaaaaa")
	tc, tk, _ := userconfig.IssuedTPMPaths(o.url)
	writePair(t, tc, tk) // a TPM pair whose certificate does not load
	sf := &sessionFlags{broker: o.url}
	if got, err := pickHeldPair(sf); err != nil || got.store != "tpm" {
		t.Fatalf("with no file pair: %+v %v", got, err)
	}
	o.holdCertificate(t, time.Now(), 12*time.Hour)
	_, fk := o.issuedPaths(t)
	if got, err := pickHeldPair(sf); err != nil || got.store != "file" || got.key != fk {
		t.Fatalf("with a valid file pair: %+v %v", got, err)
	}
	sf.issuedKeyStore = "tpm"
	if got, err := pickHeldPair(sf); err != nil || got.store != "tpm" {
		t.Fatalf("tpm named: %+v %v", got, err)
	}
}

// One key is one certificate name, however its reference is spelled.
func TestOneTokenKeyIsOneCertificateName(t *testing.T) {
	t.Setenv("HOME", privateDir(t))
	const broker = "https://broker.example:8443"
	var first string
	for _, ref := range []string{
		"pkcs11:token=lab;id=%10?module-path=/x.so",
		"pkcs11:id=%10;token=lab?module-path=/x.so",
		"pkcs11:token=%6c%61%62;id=%10?module-path=/x.so",
		"pkcs11:token=lab;id=%10;?module-path=/x.so",
		"pkcs11:token=lab;id=%10?module-path=/y.so&pin-source=file:/x",
	} {
		got, err := tokenTarget(&sessionFlags{broker: broker, issuedKey: ref})
		if err != nil {
			t.Fatal(err)
		}
		if first == "" {
			first = got
		} else if got != first {
			t.Errorf("%s: %s, want %s", ref, got, first)
		}
	}
	other, _ := tokenTarget(&sessionFlags{broker: broker, issuedKey: "pkcs11:token=lab;id=%11?module-path=/x.so"})
	if other == first {
		t.Errorf("another key shares %s", first)
	}
	// A reference that does not parse is still named, by its text.
	if bad, err := tokenTarget(&sessionFlags{broker: broker, issuedKey: "pkcs11:id=%zz"}); err != nil || bad == first {
		t.Errorf("an unparsable reference: %q %v", bad, err)
	}
}

// A token named for the issued key is this login's pair before a .key that
// sits beside the certificate, as the TPM's is.
func TestAHeldTokenPairComesBeforeTheFileKey(t *testing.T) {
	home := privateDir(t)
	t.Setenv("HOME", home)
	const broker = "https://broker.example:8443"
	fc, fk, _ := userconfig.IssuedPaths(broker)
	writePair(t, fc, fk)
	sf := &sessionFlags{broker: broker, issuedKeyStore: "pkcs11", issuedKey: tokenRef}
	if got, err := pickHeldPair(sf); err != nil || got.store != "pkcs11" || got.key != tokenRef {
		t.Fatalf("the held pair: %+v %v", got, err)
	}
}

// A lone issued_key under `auto` is ignored, and the line says so in a clause
// (ruling 7), where touch_key with it is used or, in the static build, said to
// be passed over.
func TestAutoSaysWhenALoneIssuedKeyIsIgnored(t *testing.T) {
	if got := ignoredClause(&sessionFlags{issuedKey: tokenRef}); !strings.Contains(got, "issued_key is used only with touch_key") ||
		!strings.Contains(got, "issued_key_store: pkcs11") {
		t.Errorf("a lone issued_key: %q", got)
	}
	if got := ignoredClause(&sessionFlags{}); got != "" {
		t.Errorf("no issued_key: %q", got)
	}
	if got := ignoredClause(&sessionFlags{issuedKey: "tpm:handle=0x81000001"}); got != "" {
		t.Errorf("a TPM issued_key is not a token's: %q", got)
	}
	if clientkey.HasPKCS11 {
		if got := ignoredClause(&sessionFlags{issuedKey: tokenRef, touchKey: tokenRef}); got != "" {
			t.Errorf("touch_key and issued_key are used: %q", got)
		}
	} else if got := ignoredClause(&sessionFlags{issuedKey: tokenRef, touchKey: tokenRef}); !strings.Contains(got, "built without PKCS#11 support") {
		t.Errorf("the static build: %q", got)
	}
}

// Two logins on one machine stage their TPM key under names of their own, and
// neither removes what the other staged.
func TestTPMKeyStagingNamesAreUniquePerLogin(t *testing.T) {
	dir := privateDir(t)
	tk := filepath.Join(dir, "b_1.aaaaaaaa.tpmkey")
	var staged []string
	prev := generateTPM
	generateTPM = func(path string) (*tpm.Signer, error) {
		staged = append(staged, path)
		return nil, errors.New("stop here")
	}
	t.Cleanup(func() { generateTPM = prev })
	other := tk + ".new" // a login that died, or one still running
	if err := os.WriteFile(other, []byte("another login's"), 0o600); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		_, _, _ = newIssuedKey("tpm", &sessionFlags{}, tk)
	}
	if len(staged) != 2 || staged[0] == staged[1] || staged[0] == other || staged[1] == other {
		t.Fatalf("staged at %v", staged)
	}
	for _, p := range staged {
		if filepath.Dir(p) != dir || !strings.HasPrefix(filepath.Base(p), filepath.Base(tk)) {
			t.Errorf("%s is not staged beside %s", p, tk)
		}
		if _, err := os.Lstat(p); err == nil {
			t.Errorf("%s was left behind", p)
		}
	}
	if b, err := os.ReadFile(other); err != nil || string(b) != "another login's" {
		t.Errorf("another login's staged file: %q %v", b, err)
	}
}

// A refused TPM key is an `auto` fallback only when the TPM is absent or
// refuses to make a key; any other failure is an error, and the login says so
// once and signs in for nothing.
func TestAutoFallsBackToAFileOnlyWhenTheTPMRefuses(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the TPM is Linux's")
	}
	cases := []struct {
		name string
		err  error
		file bool // the key is a file; false is an error
	}{
		{"absent", fmt.Errorf("%w: connection refused", hwkey.ErrKeyAbsent), true},
		{"authorization failure", fmt.Errorf("tpm: create: %w", tpm2.TPMRCAuthFail), true},
		{"bad auth", fmt.Errorf("tpm: create: %w", tpm2.TPMRCBadAuth), true},
		{"hierarchy", fmt.Errorf("tpm: create: %w", tpm2.TPMRCHierarchy), true},
		{"lockout", fmt.Errorf("tpm: create: %w", tpm2.TPMRCLockout), true},
		{"an I/O error", errors.New("tpm: writing the key file: input/output error"), false},
		{"a TPM internal error", fmt.Errorf("tpm: create: %w", tpm2.TPMRCFailure), false},
		{"a corrupt key file", errors.New("tpm: the key file is corrupt"), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := newOIDCLab(t, true)
			driveBrowser(t, o.iss)
			dialTPM(t, nil)
			machineIs(t, "aaaaaaaa")
			prev := generateTPM
			generateTPM = func(string) (*tpm.Signer, error) { return nil, c.err }
			t.Cleanup(func() { generateTPM = prev })
			sock := privateSocket(t)
			t.Cleanup(func() { stopAgentAt(sock) })
			t.Setenv(runCLIEnv, "1")
			var out, errb bytes.Buffer
			code := run(append([]string{"login"}, o.flags(sock)...), &out, &errb)
			certPath, keyPath := o.issuedPaths(t)
			lines := strings.Count(errb.String(), "the key is a file") + strings.Count(errb.String(), "the key is made in")
			if c.file {
				if code != 0 || lines != 1 || !strings.Contains(errb.String(), "the key is a file ("+keyPath+")") ||
					!strings.Contains(errb.String(), "the TPM could not make a key") {
					t.Fatalf("code %d stdout %q stderr %q", code, out.String(), errb.String())
				}
				return
			}
			if code == 0 || lines != 0 || !strings.Contains(errb.String(), "TPM") || len(o.as.Authorizations()) != 0 {
				t.Fatalf("code %d stderr %q (%d sign-ins)", code, errb.String(), len(o.as.Authorizations()))
			}
			for _, p := range []string{certPath, keyPath} {
				if _, err := os.Lstat(p); !errors.Is(err, fs.ErrNotExist) {
					t.Errorf("%s: %v", p, err)
				}
			}
		})
	}
}

// A named issued_key_store: tpm is the TPM or an error, never a file (decision
// 45 ruling 7): a TPM that opens but cannot make a key refuses, naming the TPM
// and the fix, before the sign-in.
func TestANamedTPMStoreNeverFallsBackToAFile(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the TPM is Linux's")
	}
	o := newOIDCLab(t, true)
	driveBrowser(t, o.iss)
	dialTPM(t, nil) // opens, and answers no command: no key can be made
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
	for _, want := range []string{"issued_key_store is tpm", "the TPM could not make a key", tpm.DevicePath, "tss"} {
		if !strings.Contains(errb.String(), want) {
			t.Errorf("%q is not in %q", want, errb.String())
		}
	}
	if code == 0 || strings.Contains(errb.String(), "the key is a file") || len(o.as.Authorizations()) != 0 {
		t.Fatalf("code %d stdout %q stderr %q (%d sign-ins)", code, out.String(), errb.String(), len(o.as.Authorizations()))
	}
	certPath, keyPath := o.issuedPaths(t)
	for _, p := range []string{certPath, keyPath} {
		if _, err := os.Lstat(p); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s: %v", p, err)
		}
	}
}

// A pkcs11 issued_key names the held key: the certificate is the .pem, the
// key is the reference.
func TestAHeldPKCS11PairIsTheReference(t *testing.T) {
	home := privateDir(t)
	t.Setenv("HOME", home)
	const broker = "https://broker.example:8443"
	fc, _, _ := userconfig.IssuedPaths(broker)
	tc, _ := userconfig.IssuedTokenPaths(broker, tokenKeyName(tokenRef))
	writePair(t, tc, filepath.Join(filepath.Dir(tc), "unrelated"))
	sf := &sessionFlags{broker: broker, issuedKeyStore: "pkcs11", issuedKey: tokenRef}
	got, err := pickHeldPair(sf)
	if err != nil || got.store != "pkcs11" || got.cert != tc || got.cert == fc || got.key != tokenRef {
		t.Fatalf("the held pair: %+v %v", got, err)
	}
	// The query (a module path, a pin-source) does not name the key.
	sf.issuedKey = tokenRef + "&pin-source=file:/x"
	if got, err = pickHeldPair(sf); err != nil || got.cert != tc {
		t.Fatalf("with another query: %+v %v", got, err)
	}
	// Without the store named, the token's certificate is no pair.
	if _, _, _, err := findHeld(&sessionFlags{broker: broker}); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a certificate with no key: %v", err)
	}
}

// A named issued_key_store looks only for its own pair (decision 45 ruling 7,
// amended): a named tpm never runs on the file .key, nor a named file on the
// TPM's key, and the pair that is not there reads as no held pair. Under
// `auto` the file .key is acceptable.
func TestANamedStoreLooksOnlyForItsOwnPair(t *testing.T) {
	machineIs(t, "aaaaaaaa")
	dialTPM(t, nil) // never this machine's TPM
	t.Setenv("HOME", privateDir(t))
	const broker = "https://broker.example:8443"
	fc, fk, _ := userconfig.IssuedPaths(broker)
	writePair(t, fc, fk)
	for _, store := range []string{"tpm", "pkcs11"} {
		sf := &sessionFlags{broker: broker, issuedKeyStore: store, issuedKey: tokenRef}
		got, _, _, err := findHeld(sf)
		if !errors.Is(err, fs.ErrNotExist) || got.store != store {
			t.Errorf("%s named with only a .key: %+v %v, want no held pair in that store", store, got, err)
		}
	}
	if got, err := pickHeldPair(&sessionFlags{broker: broker, issuedKeyStore: "auto"}); err != nil || got.store != "file" {
		t.Errorf("auto with a .key: %+v %v", got, err)
	}
	// With this machine's TPM pair too, tpm is the TPM pair and file the file pair.
	tc, tk, _ := userconfig.IssuedTPMPaths(broker)
	writePair(t, tc, tk)
	if got, err := pickHeldPair(&sessionFlags{broker: broker, issuedKeyStore: "tpm"}); err != nil || got.store != "tpm" || got.key != "tpm:file="+tk {
		t.Errorf("tpm named with both: %+v %v", got, err)
	}
	if got, err := pickHeldPair(&sessionFlags{broker: broker, issuedKeyStore: "file"}); err != nil || got.store != "file" || got.key != fk {
		t.Errorf("file named with both: %+v %v", got, err)
	}
}

// A named tpm host that holds no TPM key for this machine but sees a file
// key on its home signs in and says why in one line, not "your held
// certificate is not used" (decision 45 ruling 7, amended).
func TestANamedTPMHostWithNoTPMKeySaysSo(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the TPM is Linux's")
	}
	o := newOIDCLab(t, true)
	driveBrowser(t, o.iss)
	dialTPM(t, nil)
	machineIs(t, "aaaaaaaa")
	fc, fk := o.issuedPaths(t)
	writePair(t, fc, fk) // a file host's pair on the shared home
	generateTPMReturns(t, hwkey.ErrKeyAbsent)
	cfg := filepath.Join(privateDir(t), "config.yaml")
	if err := os.WriteFile(cfg, []byte("issued_key_store: tpm\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sock := privateSocket(t)
	t.Cleanup(func() { stopAgentAt(sock) })
	t.Setenv(runCLIEnv, "1")
	var out, errb bytes.Buffer
	run(append([]string{"login", "--config", cfg}, o.flags(sock)...), &out, &errb)
	if !strings.Contains(errb.String(), "no TPM key for this machine yet") ||
		strings.Contains(errb.String(), "your held certificate is not used") ||
		strings.Contains(out.String(), "using your certificate") {
		t.Fatalf("stdout %q stderr %q", out.String(), errb.String())
	}
}

// generateTPMReturns makes the TPM key generation fail with err.
func generateTPMReturns(t *testing.T, err error) {
	t.Helper()
	prev := generateTPM
	generateTPM = func(string) (*tpm.Signer, error) { return nil, err }
	t.Cleanup(func() { generateTPM = prev })
}

// The named-tpm refusal gives the advice for its cause: an owner password is
// cleared, a lockout is waited out or reset, a device that is missing or
// closed names the device and the tss group, and anything else is the error
// itself, with none of those hints.
func TestANamedTPMRefusalAdviceFollowsTheCause(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the TPM is Linux's")
	}
	for _, tc := range []struct {
		name     string
		err      error
		want     []string
		wantNone []string
	}{
		{"owner auth", fmt.Errorf("create: %w", tpm2.TPMRCAuthFail),
			[]string{"owner hierarchy has a password", "clear it", "issued_key_store: auto or file"}, []string{"tpm2_dictionarylockout", "tss"}},
		{"hierarchy", fmt.Errorf("create: %w", tpm2.TPMRCHierarchy),
			[]string{"owner hierarchy has a password", "clear it"}, []string{"tpm2_dictionarylockout", "tss"}},
		{"lockout", fmt.Errorf("create: %w", tpm2.TPMRCLockout),
			[]string{"dictionary-attack lockout", "wait", "tpm2_dictionarylockout -c"}, []string{"clear it", "tss"}},
		{"device", fmt.Errorf("%w: gone", hwkey.ErrKeyAbsent),
			[]string{tpm.DevicePath, "tss"}, []string{"clear it", "tpm2_dictionarylockout"}},
		{"other", errors.New("tpm: something unforeseen"),
			[]string{"something unforeseen"}, []string{"clear it", "tpm2_dictionarylockout", "tss"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := newOIDCLab(t, true)
			driveBrowser(t, o.iss)
			dialTPM(t, nil)
			machineIs(t, "aaaaaaaa")
			generateTPMReturns(t, tc.err)
			cfg := filepath.Join(privateDir(t), "config.yaml")
			if err := os.WriteFile(cfg, []byte("issued_key_store: tpm\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			sock := privateSocket(t)
			t.Cleanup(func() { stopAgentAt(sock) })
			t.Setenv(runCLIEnv, "1")
			var out, errb bytes.Buffer
			code := run(append([]string{"login", "--config", cfg}, o.flags(sock)...), &out, &errb)
			if code == 0 || len(o.as.Authorizations()) != 0 {
				t.Fatalf("code %d stderr %q (%d sign-ins)", code, errb.String(), len(o.as.Authorizations()))
			}
			for _, w := range tc.want {
				if !strings.Contains(errb.String(), w) {
					t.Errorf("%q is not in %q", w, errb.String())
				}
			}
			for _, w := range tc.wantNone {
				if strings.Contains(errb.String(), w) {
					t.Errorf("%q is in %q", w, errb.String())
				}
			}
		})
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
