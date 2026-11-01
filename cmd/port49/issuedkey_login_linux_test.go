package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"

	"github.com/blanketfish/port49/internal/hwkey"
	"github.com/blanketfish/port49/internal/hwkey/tpm"
	"github.com/blanketfish/port49/internal/userconfig"
)

// The issued-key tests that drive a whole login against the OIDC lab, whose
// helpers are Linux's (issue_login_linux_test.go); kept apart so the package's
// tests still compile, and vet, for darwin.

// A store that cannot be used refuses before the browser opens and the
// provider is asked for a sign-in, so no password is spent (decision 43
// ruling 18's rule).
func TestANamedStoreThatCannotBeUsedRefusesBeforeTheSignIn(t *testing.T) {
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
	code := run(append([]string{"login", "--config", cfg}, o.flags(t, sock)...), &out, &errb)
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
	o := newOIDCLab(t, true)
	driveBrowser(t, o.iss)
	dialTPM(t, nil)
	machineIs(t, "aaaaaaaa")
	sock := privateSocket(t)
	t.Cleanup(func() { stopAgentAt(sock) })
	t.Setenv(runCLIEnv, "1")
	var out, errb bytes.Buffer
	if code := run(append([]string{"login"}, o.flags(t, sock)...), &out, &errb); code != 0 ||
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

// Under `auto` a held TPM pair that would need a sign-in anyway is passed over
// for a file pair that would not: a TPM that opens but will not make a key
// leaves the file pair the fallback wrote, and that pair is found next time
// (task 7 A3). With no such file pair the TPM pair is still the one, and a
// named tpm never looks at the file pair.
func TestAutoPassesOverAHeldTPMPairThatWouldNeedASignIn(t *testing.T) {
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

// A refused TPM key is an `auto` fallback only when the TPM is absent or
// refuses to make a key; any other failure is an error, and the login says so
// once and signs in for nothing.
func TestAutoFallsBackToAFileOnlyWhenTheTPMRefuses(t *testing.T) {
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
			code := run(append([]string{"login"}, o.flags(t, sock)...), &out, &errb)
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
	code := run(append([]string{"login", "--config", cfg}, o.flags(t, sock)...), &out, &errb)
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

// A named tpm host that holds no TPM key for this machine but sees a file
// key on its home signs in and says why in one line, not "your held
// certificate is not used" (decision 45 ruling 7, amended).
func TestANamedTPMHostWithNoTPMKeySaysSo(t *testing.T) {
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
	run(append([]string{"login", "--config", cfg}, o.flags(t, sock)...), &out, &errb)
	if !strings.Contains(errb.String(), "no TPM key for this machine yet") ||
		strings.Contains(errb.String(), "your held certificate is not used") ||
		strings.Contains(out.String(), "using your certificate") {
		t.Fatalf("stdout %q stderr %q", out.String(), errb.String())
	}
}

// The named-tpm refusal gives the advice for its cause: an owner password is
// cleared, a lockout is waited out or reset, a device that is missing or
// closed names the device and the tss group, and anything else is the error
// itself, with none of those hints.
func TestANamedTPMRefusalAdviceFollowsTheCause(t *testing.T) {
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
			code := run(append([]string{"login", "--config", cfg}, o.flags(t, sock)...), &out, &errb)
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
