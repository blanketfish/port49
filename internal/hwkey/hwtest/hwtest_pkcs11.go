//go:build hwkey && hwkey_dlopen

package hwtest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/rhwendt/port49/internal/hwkey/pkcs11"
)

// The test tokens' PINs. They belong to throwaway tokens in a temporary
// directory and nowhere else.
const (
	SoftHSMUserPIN = "123456"
	softHSMSOPIN   = "12345678"
)

var (
	softHSMDir  string // SoftHSMMain's directory; "" before it runs
	lastModule  string // the module path the last SoftHSM* call used
	tokenNumber atomic.Int64
)

// SoftHSMMain is called from TestMain in each package that uses SoftHSM:
// it makes one SOFTHSM2_CONF and token directory for the test binary and
// sets the variable before any module loads, then runs m and removes the
// directory.
func SoftHSMMain(m *testing.M) int {
	dir, err := os.MkdirTemp("", "port49-softhsm-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "hwtest:", err)
		return 1
	}
	defer os.RemoveAll(dir)
	tokens := filepath.Join(dir, "tokens")
	if err := os.Mkdir(tokens, 0o700); err != nil {
		fmt.Fprintln(os.Stderr, "hwtest:", err)
		return 1
	}
	conf := filepath.Join(dir, "softhsm2.conf")
	body := "directories.tokendir = " + tokens + "\nobjectstore.backend = file\nlog.level = ERROR\nslots.removable = false\n"
	if err := os.WriteFile(conf, []byte(body), 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "hwtest:", err)
		return 1
	}
	os.Setenv("SOFTHSM2_CONF", conf)
	softHSMDir = dir
	return m.Run()
}

// softHSMModule is the module path: $PORT49_TEST_PKCS11_MODULE, else the
// package's usual one.
func softHSMModule(t testing.TB) string {
	t.Helper()
	module := os.Getenv("PORT49_TEST_PKCS11_MODULE")
	if module == "" {
		module = "/usr/lib/softhsm/libsofthsm2.so"
	}
	if _, err := exec.LookPath("softhsm2-util"); err != nil {
		Missing(t, "softhsm2-util is not installed (apt-get install softhsm2)")
	}
	if _, err := os.Stat(module); err != nil {
		Missing(t, "the SoftHSM2 module "+module+" is not there (set PORT49_TEST_PKCS11_MODULE)")
	}
	if softHSMDir == "" {
		t.Fatal("hwtest: SoftHSMMain did not run; call it from TestMain")
	}
	lastModule = module
	return module
}

func softHSMUtil(t testing.TB, args ...string) string {
	t.Helper()
	cmd := exec.Command("softhsm2-util", args...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("softhsm2-util %s: %v\n%s", args[0], err, out.String())
	}
	return out.String()
}

// SoftHSMBare initializes a fresh token for one test, labelled
// "port49-test-<n>" (returned), with no key on it. The token is deleted when
// the test ends.
func SoftHSMBare(t *testing.T) (module, label string) {
	t.Helper()
	module = softHSMModule(t)
	label = fmt.Sprintf("port49-test-%d", tokenNumber.Add(1))
	softHSMUtil(t, "--init-token", "--free", "--label", label, "--pin", SoftHSMUserPIN, "--so-pin", softHSMSOPIN)
	t.Cleanup(func() {
		cmd := exec.Command("softhsm2-util", "--delete-token", "--token", label)
		_ = cmd.Run()
	})
	rescan(t, module)
	return module, label
}

// rescan makes the module read the token directory again. SoftHSM2 reads it
// at C_Initialize only, and softhsm2-util is another process, so a token or
// key it made is seen by the next initialization: the module is finalized
// and initialized again. Every session of the module is invalid afterwards,
// which is also how a test "unplugs" a token SoftHSM2 would otherwise keep
// in memory.
func rescan(t testing.TB, module string) {
	t.Helper()
	m, err := pkcs11.Load(module)
	if err != nil {
		t.Fatalf("hwtest: loading %s: %v", module, err)
	}
	if err := pkcs11.Rescan(m); err != nil {
		t.Fatalf("hwtest: %v", err)
	}
}

// SoftHSM initializes a fresh token for one test, labelled
// "port49-test-<n>" (returned) with user PIN 123456 and SO PIN 12345678,
// in SoftHSMMain's directory, with a P-256 key (CKA_ID 01) on it, and returns
// the module path from $PORT49_TEST_PKCS11_MODULE (default
// /usr/lib/softhsm/libsofthsm2.so). With $PORT49_TEST_HW_REQUIRED set, a
// missing softhsm2-util or module fails the test instead of skipping it, so
// CI cannot go green by skipping.
func SoftHSM(t *testing.T) (module, label string) {
	t.Helper()
	module, label = SoftHSMBare(t)
	u := pkcs11.URI{Token: label, ID: []byte{1}, ModulePath: module}
	s, err := pkcs11.Generate(u, []byte(SoftHSMUserPIN))
	if err != nil {
		t.Fatalf("generating the test key: %v", err)
	}
	s.Close()
	return module, label
}

// SoftHSMLoginAttempts is how many C_Login calls the module has seen in this
// process (a counter at port49's call site, not SoftHSM's logs); each test
// reads it before and after.
func SoftHSMLoginAttempts(t testing.TB) int { return int(pkcs11.LoginCalls()) }

// SoftHSMImport imports key (PKCS#8) into the token label with CKA_ID 01.
func SoftHSMImport(t testing.TB, label string, key *ecdsa.PrivateKey) {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(f, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	softHSMUtil(t, "--import", f, "--token", label, "--label", "port49-imported", "--id", "01", "--pin", SoftHSMUserPIN)
	rescan(t, lastModule)
}

// SoftHSMReinit initializes a token with label again, as plugging in a
// token that carries nothing yet; the earlier one must be gone (SoftHSMUnplug).
func SoftHSMReinit(t testing.TB, label string) {
	t.Helper()
	softHSMUtil(t, "--init-token", "--free", "--label", label, "--pin", SoftHSMUserPIN, "--so-pin", softHSMSOPIN)
	rescan(t, lastModule)
}

// SoftHSMUnplug takes the token label away as unplugging it would: its
// directory is deleted from the harness's token directory and the module
// re-reads the directory, since SoftHSM2 keeps a token it has read in memory.
// A held session then answers a session error, which Signer reads as Absent.
func SoftHSMUnplug(t testing.TB, label string) {
	t.Helper()
	dir := softHSMTokenDir(t, label)
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	rescan(t, lastModule)
}

// SoftHSMObjects is what the token label holds, as text: every object file of
// its directory by name and SHA-256, in name order, and the generation counter
// SoftHSM2 bumps on a write, so a test can see that something wrote an object
// or changed one. Reading an object changes none. token.object is left out: it
// holds the token's own state, which a PIN login rewrites (its try counters).
func SoftHSMObjects(t testing.TB, label string) string {
	t.Helper()
	root := softHSMTokenDir(t, label)
	var lines []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || strings.HasSuffix(path, ".lock") || filepath.Base(path) == "token.object" {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		lines = append(lines, fmt.Sprintf("%s %x", rel, sha256.Sum256(raw)))
		return nil
	})
	if err != nil {
		t.Fatalf("hwtest: listing the token's objects: %v", err)
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

// softHSMTokenDir is the token's directory under the harness's: SoftHSM2 names
// it for a UUID whose last sixteen hex digits are the token's serial.
func softHSMTokenDir(t testing.TB, label string) string {
	t.Helper()
	out := softHSMUtil(t, "--show-slots")
	var serial string
	var cur string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if s, ok := strings.CutPrefix(line, "Serial number:"); ok {
			cur = strings.TrimSpace(s)
		}
		if l, ok := strings.CutPrefix(line, "Label:"); ok && strings.TrimSpace(l) == label {
			serial = cur
		}
	}
	if serial == "" {
		t.Fatalf("hwtest: no token labelled %s", label)
	}
	entries, err := os.ReadDir(filepath.Join(softHSMDir, "tokens"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(strings.ReplaceAll(e.Name(), "-", ""), serial) {
			return filepath.Join(softHSMDir, "tokens", e.Name())
		}
	}
	t.Fatalf("hwtest: no directory for token %s (serial %s)", label, serial)
	return ""
}
