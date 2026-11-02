package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/agent"
	"github.com/blanketfish/port49/internal/broker/api"
	"github.com/blanketfish/port49/internal/hwkey"
	"github.com/blanketfish/port49/internal/hwkey/hwfake"
	"github.com/blanketfish/port49/internal/hwkey/pkcs11"
	"github.com/blanketfish/port49/internal/hwkey/serialmask"
	"github.com/blanketfish/port49/internal/hwkeysetup"
	"github.com/blanketfish/port49/internal/pivattest"
	"github.com/blanketfish/port49/internal/testpki"
	"github.com/blanketfish/port49/internal/userconfig"
)

const hwSerial = "12345678"

// hwLab is one run's world: a home with a config, a module tree standing for
// "/", the fake token behind the openToken and listTokens seams, and a roots file.
type hwLab struct {
	t        *testing.T
	home     string
	cfg      string
	root     string
	module   string // the first probe candidate under root
	piv      *testpki.PIV
	keys     map[byte]*hwfake.Key // CKA_ID of the slot to its key
	rootsPEM string
	pins     [][]byte
	opened   int
	listed   int
	tokens   []pkcs11.Token
}

func newHWLab(t *testing.T, touchPolicy byte) *hwLab {
	t.Helper()
	home := privateDir(t)
	t.Setenv("HOME", home)
	t.Setenv("PORT49_CONFIG", "")
	if err := os.Mkdir(filepath.Join(home, ".port49"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PORT49_TEST_AGENT_SOCKET", filepath.Join(home, "no-agent.sock"))
	savedSys, savedOwner := userconfig.SystemPath, userconfig.SystemOwner
	userconfig.SystemPath = filepath.Join(home, "no-system.yaml")
	t.Cleanup(func() { userconfig.SystemPath, userconfig.SystemOwner = savedSys, savedOwner })
	withTerminal(t, false)

	l := &hwLab{t: t, home: home, cfg: filepath.Join(home, ".port49", "config.yaml"), keys: map[byte]*hwfake.Key{}}
	l.root = privateDir(t)
	l.module = hwkeysetup.ModuleCandidates(l.root, runtime.GOOS, runtime.GOARCH)[0]
	l.installModule(l.module)
	savedRoot := moduleRoot
	moduleRoot = l.root
	t.Cleanup(func() { moduleRoot = savedRoot })

	now := time.Now()
	piv, err := testpki.NewPIV(now)
	if err != nil {
		t.Fatal(err)
	}
	l.piv = piv
	mk := func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	sk, tk := mk(), mk()
	a9, _ := piv.Slot(&sk.PublicKey, pivattest.TouchNever)
	a9c, _ := piv.Slot(&tk.PublicKey, touchPolicy)
	for id, k := range map[byte]*ecdsa.PrivateKey{0x01: sk, 0x02: tk} {
		fk := hwfake.New(k, l.module, hwSerial)
		fk.SetCertificates(piv.Device, a9, a9c)
		l.keys[id] = fk
	}
	l.rootsPEM = string(piv.Anchors())
	l.tokens = []pkcs11.Token{l.token("YubiKey 5C", hwSerial)}

	savedOpen, savedList := openToken, listTokens
	openToken = func(u pkcs11.URI, pin []byte) (hwkey.Key, error) {
		l.opened++
		l.pins = append(l.pins, pin)
		if len(u.ID) != 1 || l.keys[u.ID[0]] == nil {
			return nil, fmt.Errorf("no key with that id on %s", u.Token)
		}
		return l.keys[u.ID[0]], nil
	}
	listTokens = func(string) ([]pkcs11.Token, error) { l.listed++; return l.tokens, nil }
	t.Cleanup(func() { openToken, listTokens = savedOpen, savedList })
	return l
}

func (l *hwLab) token(model, serial string) pkcs11.Token {
	label := "YubiKey PIV #" + serial
	return pkcs11.Token{Label: label, MaskedLabel: serialmask.MaskSerial(label), Model: model, MaskedSerial: "<serial>"}
}

// installModule makes a module file under the tree, safe by CheckOwned's rule.
func (l *hwLab) installModule(path string) {
	l.t.Helper()
	dir := filepath.Dir(path)
	for d := dir; d != l.root; d = filepath.Dir(d) {
		defer os.Chmod(d, 0o755)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		l.t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("ELF"), 0o755); err != nil {
		l.t.Fatal(err)
	}
}

func (l *hwLab) roots() string {
	p := filepath.Join(l.home, "roots.pem")
	if err := os.WriteFile(p, []byte(l.rootsPEM), 0o600); err != nil {
		l.t.Fatal(err)
	}
	return p
}

func (l *hwLab) writeConfig(body string) {
	l.t.Helper()
	if err := os.WriteFile(l.cfg, []byte(body), 0o600); err != nil {
		l.t.Fatal(err)
	}
}

func (l *hwLab) config() string {
	b, err := os.ReadFile(l.cfg)
	if err != nil {
		return ""
	}
	return string(b)
}

func hwRun(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := hwkeyCmd(args, &out, &errb)
	return code, out.String(), errb.String()
}

func noSerial(t *testing.T, texts ...string) {
	t.Helper()
	for _, s := range texts {
		if strings.Contains(s, hwSerial) {
			t.Errorf("the serial is in the output:\n%s", s)
		}
	}
}

func TestSetupWritesBothKeysWhenReady(t *testing.T) {
	l := newHWLab(t, pivattest.TouchAlways)
	before := "# my config\nbroker: https://b.example:8443\n\nbroker_crl:    'off'   # quoted, odd spacing\ncert: \"c.pem\"\n"
	l.writeConfig(before)
	code, out, errb := hwRun("setup", "--roots", l.roots())
	if code != 0 {
		t.Fatalf("exit %d\n%s%s", code, out, errb)
	}
	got := l.config()
	if !strings.HasPrefix(got, before) {
		t.Fatalf("the file's own lines changed:\n%s", got)
	}
	f, _, err := userconfig.Load(l.cfg)
	if err != nil {
		t.Fatal(err)
	}
	u, err := pkcs11.ParseURI(f.IssuedKey)
	if err != nil || len(u.ID) != 1 || u.ID[0] != 0x01 || u.ModulePath != l.module {
		t.Fatalf("issued_key = %q (%v)", f.IssuedKey, err)
	}
	if u, err = pkcs11.ParseURI(f.TouchKey); err != nil || u.ID[0] != 0x02 {
		t.Fatalf("touch_key = %q (%v)", f.TouchKey, err)
	}
	noSerial(t, out, errb)
	if !strings.HasPrefix(out, "roots: --roots ") {
		t.Errorf("the output does not start with the roots line:\n%s", out)
	}
}

func TestSetupChangesNothingWhenTheyMatch(t *testing.T) {
	l := newHWLab(t, pivattest.TouchAlways)
	l.writeConfig("broker: https://b.example:8443\n")
	if code, out, errb := hwRun("setup", "--roots", l.roots()); code != 0 {
		t.Fatalf("exit %d\n%s%s", code, out, errb)
	}
	past := time.Now().Add(-time.Hour).Truncate(time.Second)
	if err := os.Chtimes(l.cfg, past, past); err != nil {
		t.Fatal(err)
	}
	before := l.config()
	code, out, _ := hwRun("setup", "--roots", l.roots())
	fi, _ := os.Stat(l.cfg)
	if code != 0 || l.config() != before || !fi.ModTime().Equal(past) || !strings.Contains(out, "nothing changed") {
		t.Fatalf("exit %d, mtime %v, out:\n%s", code, fi.ModTime(), out)
	}
}

func TestSetupAsksBeforeChangingADifferentKey(t *testing.T) {
	l := newHWLab(t, pivattest.TouchAlways)
	l.writeConfig("touch_key: \"pkcs11:token=other;id=%09\"\n")
	before := l.config()
	code, out, _ := hwRun("setup", "--roots", l.roots())
	if code != 1 || l.config() != before || !strings.Contains(out, "pkcs11:token=other") {
		t.Fatalf("no terminal: exit %d, file changed=%v\n%s", code, l.config() != before, out)
	}
	withTerminal(t, true)
	saved := hwkeyStdin
	hwkeyStdin = strings.NewReader("n\n")
	t.Cleanup(func() { hwkeyStdin = saved })
	if code, _, _ := hwRun("setup", "--roots", l.roots()); code != 1 || l.config() != before {
		t.Fatalf("answered no: exit %d, file changed=%v", code, l.config() != before)
	}
	hwkeyStdin = strings.NewReader("y\n")
	if code, out, _ := hwRun("setup", "--roots", l.roots()); code != 0 || !strings.Contains(l.config(), "id=%02") {
		t.Fatalf("answered yes: exit %d\n%s\n%s", code, out, l.config())
	}
}

func TestSetupReportsAnOverlaidKey(t *testing.T) {
	l := newHWLab(t, pivattest.TouchAlways)
	sys := filepath.Join(l.home, "system.yaml")
	if err := os.WriteFile(sys, []byte("touch_key: \"pkcs11:token=site;id=%0a\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	userconfig.SystemPath, userconfig.SystemOwner = sys, uint32(os.Getuid())
	l.writeConfig("broker: https://b.example:8443\n")
	before := l.config()
	code, out, _ := hwRun("setup", "--roots", l.roots())
	if code != 1 || l.config() != before || !strings.Contains(out, "comes from the system config") {
		t.Fatalf("exit %d, changed=%v\n%s", code, l.config() != before, out)
	}
}

func TestModuleSourceOrder(t *testing.T) {
	l := newHWLab(t, pivattest.TouchAlways)
	flagMod := filepath.Join(l.root, "flag", "libykcs11.so")
	keyMod := filepath.Join(l.root, "key", "libykcs11.so")
	l.installModule(flagMod)
	l.installModule(keyMod)
	l.writeConfig("issued_key: \"pkcs11:token=x;id=%01?module-path=" + keyMod + "\"\n")
	_, out, _ := hwRun("status", "--roots", l.roots(), "--module", flagMod)
	if !strings.Contains(out, "module: "+flagMod+"\n") {
		t.Errorf("--module did not win:\n%s", out)
	}
	_, out, _ = hwRun("status", "--roots", l.roots())
	if !strings.Contains(out, "module: "+keyMod+"\n") {
		t.Errorf("the key's module-path did not win over the probe:\n%s", out)
	}
	l.writeConfig("")
	_, out, _ = hwRun("status", "--roots", l.roots())
	if !strings.Contains(out, "module: "+l.module+" (found)\n") {
		t.Errorf("the probe:\n%s", out)
	}
}

func TestTheProbeOrder(t *testing.T) {
	l := newHWLab(t, pivattest.TouchAlways)
	c := hwkeysetup.ModuleCandidates(l.root, runtime.GOOS, runtime.GOARCH)
	if len(c) < 2 {
		t.Skip("one candidate on this platform")
	}
	l.installModule(c[1])
	_, out, _ := hwRun("status", "--roots", l.roots())
	if !strings.Contains(out, "module: "+c[0]+" (found)") {
		t.Errorf("the earlier candidate was not used:\n%s", out)
	}
}

func TestAMissingCandidateIsSilent(t *testing.T) {
	l := newHWLab(t, pivattest.TouchAlways)
	_, out, errb := hwRun("status", "--roots", l.roots())
	if strings.Contains(out+errb, "skipping") || strings.Count(out, "module:") != 1 {
		t.Errorf("a line for a candidate that is not there:\n%s%s", out, errb)
	}
}

func TestAnUnsafeFlagModuleIsRefused(t *testing.T) {
	l := newHWLab(t, pivattest.TouchAlways)
	bad := filepath.Join(l.root, "bad", "libykcs11.so")
	l.installModule(bad)
	if err := os.Chmod(bad, 0o775); err != nil {
		t.Fatal(err)
	}
	code, _, errb := hwRun("status", "--roots", l.roots(), "--module", bad)
	if code != 2 || !strings.Contains(errb, bad) || l.listed != 0 || l.opened != 0 {
		t.Fatalf("--module: exit %d, listed %d, opened %d\n%s", code, l.listed, l.opened, errb)
	}
	l.writeConfig("touch_key: \"pkcs11:token=x;id=%02?module-path=" + bad + "\"\n")
	code, _, errb = hwRun("status", "--roots", l.roots())
	if code != 2 || !strings.Contains(errb, bad) || l.listed != 0 || l.opened != 0 {
		t.Fatalf("module-path: exit %d, listed %d, opened %d\n%s", code, l.listed, l.opened, errb)
	}
}

func TestAGroupWritableCandidateIsSkipped(t *testing.T) {
	l := newHWLab(t, pivattest.TouchAlways)
	c := hwkeysetup.ModuleCandidates(l.root, runtime.GOOS, runtime.GOARCH)
	if len(c) < 2 {
		t.Skip("one candidate on this platform")
	}
	l.installModule(c[1])
	if err := os.Chmod(c[0], 0o664); err != nil {
		t.Fatal(err)
	}
	_, out, errb := hwRun("status", "--roots", l.roots())
	if !strings.Contains(errb, "skipping "+c[0]) || !strings.Contains(out, "module: "+c[1]+" (found)") {
		t.Errorf("out:\n%s\nerr:\n%s", out, errb)
	}
}

func TestNoModuleFoundExits2(t *testing.T) {
	l := newHWLab(t, pivattest.TouchAlways)
	if err := os.Remove(l.module); err != nil {
		t.Fatal(err)
	}
	for _, cmd := range []string{"setup", "status"} {
		code, _, errb := hwRun(cmd, "--roots", l.roots())
		if code != 2 || !strings.Contains(errb, "no libykcs11 found; install yubico-piv-tool or pass --module") {
			t.Errorf("%s: exit %d\n%s", cmd, code, errb)
		}
	}
}

func TestSetupWritesTheProbedModule(t *testing.T) {
	l := newHWLab(t, pivattest.TouchAlways)
	if code, out, errb := hwRun("setup", "--roots", l.roots()); code != 0 {
		t.Fatalf("exit %d\n%s%s", code, out, errb)
	}
	f, _, _ := userconfig.Load(l.cfg)
	for _, ref := range []string{f.IssuedKey, f.TouchKey} {
		if u, err := pkcs11.ParseURI(ref); err != nil || u.ModulePath != l.module {
			t.Errorf("%q: module-path %q (%v), want %q", ref, u.ModulePath, err, l.module)
		}
	}
}

func TestTwoTokensNeedTheTokenFlag(t *testing.T) {
	l := newHWLab(t, pivattest.TouchAlways)
	l.tokens = append(l.tokens, l.token("YubiKey 5 NFC", "87654321"))
	code, out, errb := hwRun("status", "--roots", l.roots())
	if code != 2 || !strings.Contains(errb, "1  YubiKey 5C") || !strings.Contains(errb, "2  YubiKey 5 NFC") {
		t.Fatalf("exit %d\n%s%s", code, out, errb)
	}
	noSerial(t, out, errb)
	if strings.Contains(out+errb, "87654321") {
		t.Error("the second serial is printed")
	}
	if code, out, errb = hwRun("status", "--roots", l.roots(), "--token", "2"); strings.Contains(errb, "tokens are present") {
		t.Fatalf("--token 2: exit %d\n%s%s", code, out, errb)
	}
	if !strings.Contains(out, "token: YubiKey PIV #<serial>") {
		t.Errorf("token line:\n%s", out)
	}
}

func TestAnOpenErrorIsMasked(t *testing.T) {
	l := newHWLab(t, pivattest.TouchAlways)
	openToken = func(u pkcs11.URI, pin []byte) (hwkey.Key, error) {
		return nil, fmt.Errorf("tokens YubiKey PIV #12345678 and YubiKey PIV #87654321 both match")
	}
	code, out, errb := hwRun("status", "--roots", l.roots())
	if code != 1 {
		t.Fatalf("exit %d\n%s%s", code, out, errb)
	}
	for _, s := range []string{out, errb} {
		noSerial(t, s)
		if strings.Contains(s, "87654321") {
			t.Errorf("the other serial is printed:\n%s", s)
		}
	}
	code, out, _ = hwRun("status", "--json", "--roots", l.roots())
	if strings.Contains(out, hwSerial) || strings.Contains(out, "87654321") || code != 1 {
		t.Errorf("json (exit %d):\n%s", code, out)
	}
}

// openToken is called with a nil PIN: the keys open Locked, and no login is made.
func TestTheRealOpenGetsNoPIN(t *testing.T) {
	l := newHWLab(t, pivattest.TouchAlways)
	if code, out, errb := hwRun("status", "--roots", l.roots()); code == 2 {
		t.Fatalf("exit %d\n%s%s", code, out, errb)
	}
	if l.opened < 2 {
		t.Fatalf("opened %d keys", l.opened)
	}
	for i, p := range l.pins {
		if p != nil {
			t.Errorf("open %d was given a PIN", i)
		}
	}
}

func TestSetupNeverOpensTheTokenForWriting(t *testing.T) {
	l := newHWLab(t, pivattest.TouchAlways)
	for _, cmd := range []string{"setup", "status"} {
		hwRun(cmd, "--roots", l.roots())
	}
	for id, k := range l.keys {
		if k.Signs() != 0 || k.Unlocks() != 0 {
			t.Errorf("key %#x: %d signs, %d unlocks", id, k.Signs(), k.Unlocks())
		}
	}
}

func TestATPMSessionKeyNamesIdpMFA(t *testing.T) {
	l := newHWLab(t, pivattest.TouchAlways)
	l.writeConfig("issued_key_store: tpm\n")
	for _, cmd := range []string{"setup", "status"} {
		code, out, _ := hwRun(cmd, "--roots", l.roots())
		if code != 1 || !strings.Contains(out, "`idp_mfa`") || !strings.Contains(out, "not on a token") || l.listed != 0 {
			t.Errorf("%s: exit %d, listed %d\n%s", cmd, code, l.listed, out)
		}
		// one plain statement: no ykman line (it would replace a key in a slot the user did not mean) and no
		// pointer to setup, which refuses this case too
		if strings.Contains(out, "ykman") || strings.Contains(out, "hwkey setup") || strings.Contains(out, "FAIL") {
			t.Errorf("%s printed more than the statement:\n%s", cmd, out)
		}
	}
}

func TestStatusNeverWrites(t *testing.T) {
	l := newHWLab(t, pivattest.TouchCached)
	l.writeConfig("broker: https://b.example:8443\n")
	before := l.config()
	for _, args := range [][]string{{"--roots", l.roots()}, {"--roots", l.roots(), "--json"}} {
		code, out, errb := hwRun(append([]string{"status"}, args...)...)
		if code != 1 || l.config() != before || strings.Contains(out+errb, "ykman") {
			t.Errorf("%v: exit %d, changed=%v\n%s%s", args, code, l.config() != before, out, errb)
		}
	}
	if _, err := os.Stat(filepath.Join(l.home, ".port49", "config.yaml")); err != nil {
		t.Fatal(err)
	}
	os.Remove(l.cfg)
	hwRun("status", "--roots", l.roots())
	if _, err := os.Stat(l.cfg); err == nil {
		t.Error("status made a config file")
	}
}

func TestSetupSaysWhatToRunWhenTheTouchPolicyIsWrong(t *testing.T) {
	l := newHWLab(t, pivattest.TouchCached)
	code, out, _ := hwRun("setup", "--roots", l.roots())
	if code != 1 || !strings.Contains(out, "--touch-policy ALWAYS") || strings.Contains(l.config(), "issued_key") {
		t.Fatalf("exit %d\n%s", code, out)
	}
}

func TestStatusReadsTheAgent(t *testing.T) {
	l := newHWLab(t, pivattest.TouchAlways)
	sock := agentStub(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(agent.Status{TouchKeyUnusable: "locked", SessionKeyStore: "pkcs11"})
	}))
	t.Setenv("PORT49_TEST_AGENT_SOCKET", sock)
	code, out, _ := hwRun("status", "--roots", l.roots())
	if code != 1 || !strings.Contains(out, "FAIL  agent: touch_key_unusable: locked") {
		t.Fatalf("exit %d\n%s", code, out)
	}
}

// statusReady writes a config naming the fake token's slots, so the status checks
// that read it pass.
func (l *hwLab) statusReady(extra string) {
	l.t.Helper()
	tok := l.token("YubiKey 5C", hwSerial)
	issued, _ := hwkeysetup.SlotURI(l.module, tok.Label, "9a")
	touch, _ := hwkeysetup.SlotURI(l.module, tok.Label, "9c")
	l.writeConfig("broker: https://b.example:8443\nissued_key: \"" + issued + "\"\ntouch_key: \"" + touch + "\"\n" + extra)
}

func (l *hwLab) heldCertificate(pub *ecdsa.PublicKey, notAfter time.Time) {
	l.t.Helper()
	ca := testCA(l.t)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "alice"},
		NotBefore: time.Now().Add(-2 * time.Hour), NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, pub, ca.Key)
	if err != nil {
		l.t.Fatal(err)
	}
	c := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	f, _, _ := userconfig.Load(l.cfg)
	p, err := userconfig.IssuedTokenPaths("https://b.example:8443", tokenKeyName(f.IssuedKey))
	if err != nil {
		l.t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		l.t.Fatal(err)
	}
	if err := os.WriteFile(p, c, 0o600); err != nil {
		l.t.Fatal(err)
	}
}

func TestStatusCertificateKeyMustMatchTheSlot(t *testing.T) {
	l := newHWLab(t, pivattest.TouchAlways)
	l.statusReady("")
	code, out, _ := hwRun("status", "--roots", l.roots())
	if code != 0 || !strings.Contains(out, "ok    issued_certificate: no certificate yet") {
		t.Fatalf("no certificate: exit %d\n%s", code, out)
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	l.heldCertificate(&other.PublicKey, time.Now().Add(time.Hour))
	code, out, _ = hwRun("status", "--roots", l.roots())
	if code != 1 || !strings.Contains(out, "FAIL  issued_certificate") {
		t.Fatalf("another key's certificate: exit %d\n%s", code, out)
	}
	l.heldCertificate(l.keys[0x01].Public().(*ecdsa.PublicKey), time.Now().Add(time.Hour))
	code, out, _ = hwRun("status", "--roots", l.roots())
	if code != 0 || !strings.Contains(out, "ok    certificate_expiry: expires in") {
		t.Fatalf("its own certificate: exit %d\n%s", code, out)
	}
}

func TestStatusExpiredCertificateFails(t *testing.T) {
	l := newHWLab(t, pivattest.TouchAlways)
	l.statusReady("")
	l.heldCertificate(l.keys[0x01].Public().(*ecdsa.PublicKey), time.Now().Add(-time.Minute))
	code, out, _ := hwRun("status", "--roots", l.roots())
	if code != 1 || !strings.Contains(out, "FAIL  certificate_expiry: expired") {
		t.Fatalf("exit %d\n%s", code, out)
	}
}

func TestStatusJSONIsSnakeCaseAndMasked(t *testing.T) {
	l := newHWLab(t, pivattest.TouchAlways)
	l.statusReady("")
	code, out, _ := hwRun("status", "--json", "--roots", l.roots())
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	noSerial(t, out)
	var generic map[string]any
	if err := json.Unmarshal([]byte(out), &generic); err != nil {
		t.Fatal(err)
	}
	snake := regexp.MustCompile(`^[a-z_]+$`)
	for k, v := range generic {
		if !snake.MatchString(k) {
			t.Errorf("key %q", k)
		}
		if k == "checks" {
			for _, c := range v.([]any) {
				for ck := range c.(map[string]any) {
					if !snake.MatchString(ck) {
						t.Errorf("check key %q", ck)
					}
				}
			}
		}
	}
	// the closed set of check names (pre-flight F12): no pin_policy
	var rep hwkeysetup.Report
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatal(err)
	}
	if len(rep.Checks) != len(hwkeysetup.CheckNames) {
		t.Errorf("%d checks, want all %d names", len(rep.Checks), len(hwkeysetup.CheckNames))
	}
	for _, c := range rep.Checks {
		if !slices.Contains(hwkeysetup.CheckNames, c.Name) || c.Name == "pin_policy" {
			t.Errorf("check name %q is outside the closed set", c.Name)
		}
	}
	for _, k := range []string{"token", "roots", "ready", "checks"} {
		if _, ok := generic[k]; !ok {
			t.Errorf("no %q", k)
		}
	}
	if generic["token"] != "YubiKey PIV #<serial>" {
		t.Errorf("token = %v", generic["token"])
	}
}

func TestStatusSaysWhichRootsItUsed(t *testing.T) {
	l := newHWLab(t, pivattest.TouchAlways)
	rf := l.roots()
	_, out, _ := hwRun("status", "--roots", rf)
	if !strings.HasPrefix(out, "roots: --roots "+rf+"\n") {
		t.Errorf("flag:\n%s", out)
	}
	srv, _ := brokerServing(t, l, l.rootsPEM)
	l.writeConfig("broker: " + srv.URL + "\nbroker_ca: ca.pem\n")
	_, out, errb := hwRun("status")
	host := strings.TrimPrefix(srv.URL, "https://")
	if !strings.HasPrefix(out, "roots: from broker "+host+"\n") {
		t.Errorf("broker:\n%s%s", out, errb)
	}
}

// brokerServing is a TLS broker whose /v1/config serves rootsPEM (none when
// empty) under a CA written to the home as ca.pem.
func brokerServing(t *testing.T, l *hwLab, rootsPEM string) (*httptest.Server, *testpki.CA) {
	t.Helper()
	ca := testCA(t)
	now := time.Now()
	leaf, err := ca.Issue(testpki.Leaf{CommonName: "broker", IPs: testpki.Loopback(), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conf := api.Config{}
		if rootsPEM != "" {
			conf.HardwareKeyTouch = &api.HardwareKeyTouchConfig{AttestationRootsPEM: rootsPEM}
		}
		json.NewEncoder(w).Encode(conf)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{leaf}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	if err := os.WriteFile(filepath.Join(l.home, ".port49", "ca.pem"), ca.PEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	return srv, ca
}

func TestBrokerFetchUsesThePinnedPool(t *testing.T) {
	l := newHWLab(t, pivattest.TouchAlways)
	srv, _ := brokerServing(t, l, l.rootsPEM)
	// the configured CA is another one: the broker is reachable and not trusted
	other := testCA(t)
	if err := os.WriteFile(filepath.Join(l.home, ".port49", "ca.pem"), other.PEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	l.writeConfig("broker: " + srv.URL + "\nbroker_ca: ca.pem\n")
	code, _, errb := hwRun("status")
	if code != 2 || !strings.Contains(errb, "did not present a certificate from the configured broker CA") ||
		strings.Contains(errb, "unreachable") {
		t.Fatalf("exit %d\n%s", code, errb)
	}
}

func TestExitCodes(t *testing.T) {
	good := newHWLab(t, pivattest.TouchAlways)
	good.statusReady("")
	cached := func() *hwLab { return newHWLab(t, pivattest.TouchCached) }
	cases := []struct {
		name string
		args []string
		want int
	}{{"status ready", []string{"status"}, 0}, {"setup ready", []string{"setup"}, 0}}
	for _, c := range cases {
		args := append([]string{c.args[0], "--roots", good.roots()}, c.args[1:]...)
		if code, out, errb := hwRun(args...); code != c.want {
			t.Errorf("%s: exit %d\n%s%s", c.name, code, out, errb)
		}
	}
	bad := cached()
	for _, cmd := range []string{"status", "setup"} {
		if code, _, _ := hwRun(cmd, "--roots", bad.roots()); code != 1 {
			t.Errorf("%s with the wrong touch policy: exit %d", cmd, code)
		}
		if code, _, _ := hwRun(cmd, "--bogus"); code != 2 {
			t.Errorf("%s with a bad flag: exit %d", cmd, code)
		}
		if code, _, _ := hwRun(cmd); code != 2 { // no roots: no flag, no broker
			t.Errorf("%s with no roots: exit %d", cmd, code)
		}
		bad.writeConfig("broker: https://127.0.0.1:1\nbroker_ca: ca.pem\n")
		if err := os.WriteFile(filepath.Join(bad.home, ".port49", "ca.pem"), testCA(t).PEM(), 0o600); err != nil {
			t.Fatal(err)
		}
		if code, _, errb := hwRun(cmd); code != 2 || !strings.Contains(errb, "is unreachable") {
			t.Errorf("%s with a closed port: exit %d\n%s", cmd, code, errb)
		}
	}
	if code, _, _ := hwRun(); code != 2 {
		t.Errorf("no subcommand: exit %d", code)
	}
}

func TestNoRootsFromTheBrokerExits2(t *testing.T) {
	l := newHWLab(t, pivattest.TouchAlways)
	srv, _ := brokerServing(t, l, "")
	l.writeConfig("broker: " + srv.URL + "\nbroker_ca: ca.pem\n")
	code, _, errb := hwRun("status")
	if code != 2 || !strings.Contains(errb, "--roots") || !strings.Contains(errb, "attestation_roots_file") {
		t.Fatalf("exit %d\n%s", code, errb)
	}
}

// The agent is told which store holds the session key, as one word of the closed
// set: port49 hwkey status and the remedy lines read it from agent.Status.
func TestTheSessionConfigNamesTheKeyStore(t *testing.T) {
	dir := privateDir(t)
	if err := testpki.WriteLab(dir, "alice@example.com", time.Now()); err != nil {
		t.Fatal(err)
	}
	sf := &sessionFlags{broker: configBroker, cert: filepath.Join(dir, testpki.LabClientCert),
		key: filepath.Join(dir, testpki.LabClientKey), brokerCA: filepath.Join(dir, testpki.LabCA), brokerCRL: "off"}
	cfg, err := sf.config(io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.KeyStore != "file" {
		t.Errorf("KeyStore = %q, want file", cfg.KeyStore)
	}
}

// A module error that names tokens (it can) is masked on the lines that print it
// raw, not only in the checks' text.
func TestAModuleErrorIsMasked(t *testing.T) {
	l := newHWLab(t, pivattest.TouchAlways)
	listTokens = func(string) ([]pkcs11.Token, error) {
		return nil, fmt.Errorf("C_GetTokenInfo: YubiKey PIV #12345678, serial 87654321")
	}
	code, out, errb := hwRun("status", "--roots", l.roots())
	if code != 2 || strings.Contains(out+errb, "12345678") || strings.Contains(out+errb, "87654321") {
		t.Fatalf("exit %d\n%s%s", code, out, errb)
	}
}

// closeProbe records the config's text at the moment its key is closed.
type closeProbe struct {
	*hwfake.Key
	atClose func()
}

func (c closeProbe) Close() error { c.atClose(); return c.Key.Close() }

// Setup closes the token's keys before it writes the config (the brief's order):
// when the first key is closed the file still holds no issued_key.
func TestSetupClosesTheKeysBeforeTheConfigWrite(t *testing.T) {
	l := newHWLab(t, pivattest.TouchAlways)
	l.writeConfig("broker: https://b.example:8443\n")
	var atClose []string
	inner := openToken
	openToken = func(u pkcs11.URI, pin []byte) (hwkey.Key, error) {
		k, err := inner(u, pin)
		if err != nil {
			return nil, err
		}
		return closeProbe{k.(*hwfake.Key), func() { atClose = append(atClose, l.config()) }}, nil
	}
	if code, out, errb := hwRun("setup", "--roots", l.roots()); code != 0 {
		t.Fatalf("exit %d\n%s%s", code, out, errb)
	}
	if len(atClose) != 2 {
		t.Fatalf("%d keys closed, want 2", len(atClose))
	}
	for i, c := range atClose {
		if strings.Contains(c, "issued_key") {
			t.Errorf("key %d was closed after the config was written", i)
		}
	}
}
