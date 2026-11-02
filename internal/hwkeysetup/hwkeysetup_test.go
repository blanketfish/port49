package hwkeysetup

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/broker/api"
	"github.com/blanketfish/port49/internal/hwkey/hwfake"
	"github.com/blanketfish/port49/internal/hwkey/pkcs11"
	"github.com/blanketfish/port49/internal/pivattest"
	"github.com/blanketfish/port49/internal/testpki"
)

const (
	fakeModule = "/usr/lib/x86_64-linux-gnu/libykcs11.so"
	fakeSerial = "12345678" // testpki.DeviceSerial, as the token names it
)

func key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// token is one fake YubiKey: a device hierarchy and the keys in 9a and 9c.
type token struct {
	piv            *testpki.PIV
	session, touch *hwfake.Key
}

// newToken makes a token whose 9a carries touch never and whose 9c carries
// touchPolicy; both fakes list the token's three certificate objects.
func newToken(t *testing.T, now time.Time, touchPolicy byte, serial string) *token {
	t.Helper()
	piv, err := testpki.NewPIV(now)
	if err != nil {
		t.Fatal(err)
	}
	sk, tk := key(t), key(t)
	a9, err := piv.Slot(&sk.PublicKey, pivattest.TouchNever)
	if err != nil {
		t.Fatal(err)
	}
	a9c, err := piv.Slot(&tk.PublicKey, touchPolicy)
	if err != nil {
		t.Fatal(err)
	}
	tok := &token{piv: piv, session: hwfake.New(sk, fakeModule, serial), touch: hwfake.New(tk, fakeModule, serial)}
	tok.session.SetCertificates(piv.Device, a9, a9c)
	tok.touch.SetCertificates(piv.Device, a9, a9c)
	return tok
}

func anchorsOf(t *testing.T, piv *testpki.PIV) *pivattest.Anchors {
	t.Helper()
	a, err := pivattest.ParseAnchors(piv.Anchors())
	if err != nil {
		t.Fatal(err)
	}
	return &a
}

func (tok *token) keys() Keys {
	return Keys{Session: tok.session, Touch: tok.touch, SessionSlot: "9a", RootsFrom: "from broker broker.example.com"}
}

func checkOf(t *testing.T, r Report, name string) Check {
	t.Helper()
	for _, c := range r.Checks {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no check %q in %+v", name, r.Checks)
	return Check{}
}

func TestAGoodTokenIsReady(t *testing.T) {
	now := time.Now()
	tok := newToken(t, now, pivattest.TouchAlways, fakeSerial)
	r := Inspect(tok.keys(), anchorsOf(t, tok.piv), now)
	if !r.Ready {
		t.Fatalf("not ready: %+v", r.Checks)
	}
	for _, c := range r.Checks {
		if !c.OK || c.Why != "" {
			t.Errorf("check %+v", c)
		}
	}
	want := []string{CheckSessionSlot, CheckTouchSlot, CheckAttestationRoots, CheckSessionAttested, CheckTouchAttested,
		CheckTouchPolicy, CheckSameToken}
	if len(r.Checks) != len(want) {
		t.Fatalf("%d checks, want %d", len(r.Checks), len(want))
	}
	for i, n := range want {
		if r.Checks[i].Name != n {
			t.Errorf("check %d is %q, want %q", i, r.Checks[i].Name, n)
		}
	}
	if len(Advice(r, "9a")) != 0 {
		t.Error("a ready token gets advice")
	}
}

// Every check name Inspect and Advice use is in the closed set; pin_policy is
// not (VerifyPair has no PIN word, pre-flight F12).
func TestTheCheckSetIsClosed(t *testing.T) {
	now := time.Now()
	tok := newToken(t, now, pivattest.TouchCached, fakeSerial)
	for _, r := range []Report{
		Inspect(tok.keys(), anchorsOf(t, tok.piv), now),
		Inspect(Keys{}, nil, now),
	} {
		for _, c := range r.Checks {
			found := false
			for _, n := range CheckNames {
				found = found || n == c.Name
			}
			if !found || c.Name == "pin_policy" {
				t.Errorf("check name %q is outside the closed set", c.Name)
			}
		}
	}
	if len(CheckNames) != 12 {
		t.Errorf("%d check names, want 12", len(CheckNames))
	}
}

func TestATouchKeyWithoutAlwaysIsNotReady(t *testing.T) {
	now := time.Now()
	tok := newToken(t, now, pivattest.TouchCached, fakeSerial)
	r := Inspect(tok.keys(), anchorsOf(t, tok.piv), now)
	if r.Ready || !r.Failed(CheckTouchPolicy) || r.Failed(CheckSessionAttested) || r.Failed(CheckTouchAttested) {
		t.Fatalf("%+v", r.Checks)
	}
	found := false
	for _, l := range Advice(r, "9a") {
		found = found || strings.Contains(l, "--pin-policy ONCE --touch-policy ALWAYS 9c")
	}
	if !found {
		t.Fatalf("no 9c generate line with touch policy ALWAYS: %q", Advice(r, "9a"))
	}
}

func TestTwoTokensAreRefused(t *testing.T) {
	now := time.Now()
	a := newToken(t, now, pivattest.TouchAlways, fakeSerial)
	b := newToken(t, now, pivattest.TouchAlways, "99999999")
	// The 9c key is the second device's, though its token claims the first's.
	k := Keys{Session: a.session, Touch: b.touch, SessionSlot: "9a"}
	r := Inspect(k, anchorsOf(t, a.piv), now)
	if r.Ready || !r.Failed(CheckSameToken) {
		t.Fatalf("%+v", r.Checks)
	}
	// And with the same module and serial claimed, the devices still differ.
	b2 := newToken(t, now, pivattest.TouchAlways, fakeSerial)
	r = Inspect(Keys{Session: a.session, Touch: b2.touch}, anchorsOf(t, a.piv), now)
	if r.Ready || !r.Failed(CheckSameToken) {
		t.Fatalf("two devices under one claimed serial: %+v", r.Checks)
	}
}

func TestAWrongRootFailsTheChain(t *testing.T) {
	now := time.Now()
	tok := newToken(t, now, pivattest.TouchAlways, fakeSerial)
	other := newToken(t, now, pivattest.TouchAlways, fakeSerial)
	k := tok.keys()
	k.RootsFrom = "--roots /tmp/other-roots.pem"
	r := Inspect(k, anchorsOf(t, other.piv), now)
	if r.Ready || !r.Failed(CheckSessionAttested) || !r.Failed(CheckTouchAttested) {
		t.Fatalf("%+v", r.Checks)
	}
	if why := checkOf(t, r, CheckTouchAttested).Why; !strings.Contains(why, "--roots /tmp/other-roots.pem") {
		t.Fatalf("the message does not name the roots' source: %q", why)
	}
}

func TestAMissingSlotAdvisesItsGenerateLine(t *testing.T) {
	now := time.Now()
	tok := newToken(t, now, pivattest.TouchAlways, fakeSerial)
	k := tok.keys()
	k.Touch = nil
	r := Inspect(k, anchorsOf(t, tok.piv), now)
	if r.Ready || !r.Failed(CheckTouchSlot) {
		t.Fatalf("%+v", r.Checks)
	}
	found := false
	for _, l := range Advice(r, "9a") {
		found = found || strings.Contains(l, "ykman piv keys generate --algorithm ECCP256 --pin-policy ONCE --touch-policy ALWAYS 9c port49-9c.pub.pem")
	}
	if !found {
		t.Fatalf("%q", Advice(r, "9a"))
	}
	// A site that keeps the session key in 9e is told 9e.
	k = tok.keys()
	k.Session = nil
	for _, l := range Advice(Inspect(k, anchorsOf(t, tok.piv), now), "9e") {
		if strings.Contains(l, "generate") && !strings.Contains(l, "--touch-policy NEVER 9e port49-9e.pub.pem") && strings.Contains(l, "NEVER") {
			t.Errorf("a 9e site is told %q", l)
		}
	}
}

// No Advice line, under any fixture, names the serial, a PIN, a PUK or a
// management key.
func TestNoAdviceNamesASecretOrSerial(t *testing.T) {
	now := time.Now()
	tok := newToken(t, now, pivattest.TouchCached, fakeSerial)
	missing := tok.keys()
	missing.Session, missing.Touch = nil, nil
	var all []string
	for _, r := range []Report{
		Inspect(tok.keys(), anchorsOf(t, tok.piv), now),
		Inspect(missing, anchorsOf(t, tok.piv), now),
		Inspect(missing, nil, now),
	} {
		all = append(all, Advice(r, "9a")...)
		all = append(all, Advice(r, "9e")...)
		for _, c := range r.Checks {
			all = append(all, c.Why)
		}
	}
	if len(all) == 0 {
		t.Fatal("no advice at all")
	}
	for _, l := range all {
		for _, bad := range []string{fakeSerial, "management", "PIN", "PUK", "--management-key"} {
			if strings.Contains(l, bad) {
				t.Errorf("%q names %q", l, bad)
			}
		}
	}
}

func TestLoadRootsPrefersTheFlag(t *testing.T) {
	piv, err := testpki.NewPIV(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(t.TempDir(), "roots.pem")
	if err := os.WriteFile(f, piv.Anchors(), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := LoadRoots(context.Background(), f, "https://broker.example.com:4433", func(context.Context) (api.Config, error) {
		t.Fatal("fetch was called with --roots set")
		return api.Config{}, nil
	})
	if err != nil || r.Source != "--roots "+f || r.Anchors.Roots == nil {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestLoadRootsFromTheBroker(t *testing.T) {
	piv, err := testpki.NewPIV(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	r, err := LoadRoots(context.Background(), "", "https://broker.example.com:4433", func(context.Context) (api.Config, error) {
		return api.Config{HardwareKeyTouch: &api.HardwareKeyTouchConfig{AttestationRootsPEM: string(piv.Anchors())}}, nil
	})
	if err != nil || r.Source != "from broker broker.example.com:4433" {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestNoRootsIsAnError(t *testing.T) {
	_, err := LoadRoots(context.Background(), "", "https://broker.example.com:4433", func(context.Context) (api.Config, error) {
		return api.Config{}, nil
	})
	if !errors.Is(err, ErrNoRoots) || !strings.Contains(err.Error(), "--roots") ||
		!strings.Contains(err.Error(), "hardware_key_touch.attestation_roots_file") {
		t.Fatalf("%v", err)
	}
}

func TestAnUnreachableBrokerIsItsOwnError(t *testing.T) {
	_, err := LoadRoots(context.Background(), "", "https://broker.example.com:4433", func(context.Context) (api.Config, error) {
		return api.Config{}, &net.OpError{Op: "dial", Err: errors.New("connection refused")}
	})
	if !errors.Is(err, ErrBrokerUnreachable) || errors.Is(err, ErrBrokerUntrusted) ||
		err.Error() != "the broker broker.example.com:4433 is unreachable, so the attestation roots could not be fetched: retry, or pass --roots FILE" {
		t.Fatalf("%v", err)
	}
}

// A certificate from another CA is a trust failure, not an outage (F21).
func TestABrokerFromAnotherCAIsNotUnreachable(t *testing.T) {
	_, err := LoadRoots(context.Background(), "", "https://broker.example.com:4433", func(context.Context) (api.Config, error) {
		return api.Config{}, x509.UnknownAuthorityError{}
	})
	if !errors.Is(err, ErrBrokerUntrusted) || errors.Is(err, ErrBrokerUnreachable) ||
		!strings.Contains(err.Error(), "did not present a certificate from the configured broker CA") {
		t.Fatalf("%v", err)
	}
}

func TestSlotIDsAreL60s(t *testing.T) {
	for slot, want := range map[string]byte{"9a": 0x01, "9c": 0x02, "9e": 0x04} {
		if SlotIDs[slot] != want {
			t.Errorf("slot %s is %#x, want %#x", slot, SlotIDs[slot], want)
		}
	}
	s, err := SlotURI(fakeModule, "YubiKey PIV #<token>", "9a")
	if err != nil {
		t.Fatal(err)
	}
	u, err := pkcs11.ParseURI(s)
	if err != nil || len(u.ID) != 1 || u.ID[0] != 0x01 || u.Token != "YubiKey PIV #<token>" || u.ModulePath != fakeModule ||
		!strings.Contains(s, "id=%01") {
		t.Fatalf("%q -> %+v %v", s, u, err)
	}
	if _, err := SlotURI(fakeModule, "x", "9z"); err == nil {
		t.Error("a slot that is not PIV's was accepted")
	}
}

func TestTheProbeOrderAndTheCheck(t *testing.T) {
	root := t.TempDir()
	mk := func(p string) {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mk("usr/lib64/libykcs11.so.2")
	mk("usr/lib/x86_64-linux-gnu/libykcs11.so")
	var said []string
	pass := func(string) error { return nil }
	got, err := FindModule(root, "linux", "amd64", pass, func(s string) { said = append(said, s) })
	if err != nil || got != filepath.Join(root, "usr/lib/x86_64-linux-gnu/libykcs11.so") || len(said) != 0 {
		t.Fatalf("%q %v %q", got, err, said)
	}
	// The first existing candidate fails the check: skipped with one line.
	refuse := func(p string) error {
		if strings.Contains(p, "x86_64-linux-gnu") {
			return errors.New("group-writable")
		}
		return nil
	}
	got, err = FindModule(root, "linux", "amd64", refuse, func(s string) { said = append(said, s) })
	if err != nil || got != filepath.Join(root, "usr/lib64/libykcs11.so.2") || len(said) != 1 ||
		!strings.Contains(said[0], "libykcs11.so") {
		t.Fatalf("%q %v %q", got, err, said)
	}
	// Nothing found.
	if _, err := FindModule(t.TempDir(), "linux", "amd64", pass, func(string) { t.Error("a missing path was reported") }); !errors.Is(err, ErrNoModule) {
		t.Fatalf("%v", err)
	}
	if ErrNoModule.Error() != "no libykcs11 found; install yubico-piv-tool or pass --module" {
		t.Fatalf("%q", ErrNoModule)
	}
	// Only paths a package's published file list shows (2026-11-02): Debian and Ubuntu's ykcs11,
	// Fedora's yubico-piv-tool. No macOS path is listed: neither Homebrew's formula nor Yubico's
	// installer could be confirmed to install a libykcs11.dylib at a fixed path, so a Mac passes --module.
	want := []string{"/usr/lib/x86_64-linux-gnu/libykcs11.so.2", "/usr/lib/x86_64-linux-gnu/libykcs11.so", "/usr/lib64/libykcs11.so.2"}
	if got := ModuleCandidates("", "linux", "amd64"); !slices.Equal(got, want) {
		t.Errorf("linux/amd64 candidates %q, want %q", got, want)
	}
	if got := ModuleCandidates("", "darwin", "arm64"); len(got) != 0 {
		t.Errorf("darwin candidates %q: none is confirmed", got)
	}
	for _, p := range ModuleCandidates("", "linux", "amd64") {
		if strings.Contains(p, "/usr/local/") {
			t.Errorf("linux candidate %q is a source-build path", p)
		}
	}
}

// A reason that reaches a check from outside (an open error can name other
// tokens) is masked: no check's Why holds a serial.
func TestAReasonFromOutsideIsMasked(t *testing.T) {
	now := time.Now()
	tok := newToken(t, now, pivattest.TouchAlways, fakeSerial)
	k := tok.keys()
	k.Session, k.Touch = nil, nil
	k.SessionWhy = `pkcs11: tokens "YubiKey PIV #12345678" and "YubiKey PIV #87654321" serial 12345678`
	k.TouchWhy = "token YubiKey PIV #12345678"
	for _, c := range Inspect(k, anchorsOf(t, tok.piv), now).Checks {
		if strings.Contains(c.Why, "12345678") || strings.Contains(c.Why, "87654321") {
			t.Errorf("check %q leaks a serial: %q", c.Name, c.Why)
		}
	}
}
