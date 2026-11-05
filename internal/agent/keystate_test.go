package agent

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/blanketfish/port49/internal/hwkey"
)

// fakeKey is a hardware key as the backends behave: its state is cached, and
// only State()'s probe or a Sign moves it, so a test sets the device's
// presence and the agent sees it at the next probe. Unlock records the PIN it
// was given.
type fakeKey struct {
	*ecdsa.PrivateKey
	mu      sync.Mutex
	present bool
	state   hwkey.State
	pins    []string
	closed  bool
	// signErr, when set, is what every Sign returns; signs counts the calls.
	signErr error
	signs   int
	// blocked is a token whose PIN is blocked: Unlock answers as a
	// CKR_PIN_LOCKED does, and PINBlocked says so.
	blocked bool
	// backFree is a key that comes back from Absent needing no PIN; by
	// default it comes back Locked. probes counts State() calls.
	backFree bool
	probes   int
}

func (k *fakeKey) nSigns() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.signs
}

func (k *fakeKey) nProbes() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.probes
}

func (k *fakeKey) PINBlocked() bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.blocked
}

func newFakeKey(t *testing.T, state hwkey.State) *fakeKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeKey{PrivateKey: k, present: state != hwkey.Absent, state: state}
}

func (k *fakeKey) setPresent(p bool) {
	k.mu.Lock()
	k.present = p
	k.mu.Unlock()
}

func (k *fakeKey) State() hwkey.State {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.probes++
	// As the backends do: a cached state moves only when a call fails (Sign
	// or Unlock, to Absent), and a probe re-reads the device only from Absent.
	if k.state == hwkey.Absent && k.present {
		k.state = hwkey.Locked // back, and wants its PIN
		if k.backFree {
			k.state = hwkey.Present
		}
	}
	return k.state
}

func (k *fakeKey) Sign(rd io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	k.mu.Lock()
	k.signs++
	switch {
	case k.signErr != nil:
		err := k.signErr
		k.mu.Unlock()
		return nil, err
	case !k.present:
		k.state = hwkey.Absent
		k.mu.Unlock()
		return nil, hwkey.ErrKeyAbsent
	case k.state != hwkey.Present:
		k.mu.Unlock()
		return nil, hwkey.ErrLocked
	}
	k.mu.Unlock()
	return k.PrivateKey.Sign(rd, digest, opts)
}

func (k *fakeKey) Unlock(pin []byte) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.pins = append(k.pins, string(pin))
	defer clear(pin)
	if !k.present {
		k.state = hwkey.Absent
		return hwkey.ErrKeyAbsent
	}
	if k.blocked {
		// As pkcs11.Signer answers CKR_PIN_LOCKED: the PINError wrapped.
		return fmt.Errorf("pkcs11: the token's PIN is locked; it needs the token's own unblock procedure: %w", &hwkey.PINError{})
	}
	if string(pin) != "123456" {
		return &hwkey.PINError{Low: true}
	}
	k.state = hwkey.Present
	return nil
}

func (k *fakeKey) Close() error {
	k.mu.Lock()
	k.closed = true
	k.mu.Unlock()
	return nil
}

func (k *fakeKey) tried() []string {
	k.mu.Lock()
	defer k.mu.Unlock()
	return append([]string(nil), k.pins...)
}

// fakeToken is a fakeKey on a PKCS#11 token: it names its module and the
// token's serial, as pkcs11.Signer does.
type fakeToken struct {
	*fakeKey
	module, serial string
}

func (k *fakeToken) ModulePath() string  { return k.module }
func (k *fakeToken) TokenSerial() string { return k.serial }

func agentWith(t *testing.T, cfg Config) (*Agent, *Client) {
	t.Helper()
	cfg.BrokerURL = "https://127.0.0.1:1"
	a := New(cfg)
	return a, socketFor(t, a)
}

// GET /status says what the key can do now, and Unlock gives the token its
// PIN once and puts it nowhere else.
func TestStatusSaysTheKeyState(t *testing.T) {
	key := newFakeKey(t, hwkey.Locked)
	var log bytes.Buffer
	a, c := agentWith(t, Config{Cert: tls.Certificate{PrivateKey: key, Certificate: [][]byte{{1, 2, 3}}}, Log: &log,
		KeyRef: "pkcs11:id=%01?module-path=/m.so"})
	_ = a
	ctx := context.Background()
	st, err := c.Status(ctx)
	if err != nil || st.KeyState != "locked" || st.KeyRef != "pkcs11:id=%01?module-path=/m.so" {
		t.Fatalf("%+v %v", st, err)
	}
	if err := c.Unlock(ctx, []byte("123456")); err != nil {
		t.Fatal(err)
	}
	if st, err = c.Status(ctx); err != nil || st.KeyState != "present" {
		t.Fatalf("after Unlock: %+v %v", st, err)
	}
	if got := key.tried(); len(got) != 1 || got[0] != "123456" {
		t.Fatalf("the PIN reached the key %d times", len(got))
	}
	if strings.Contains(log.String(), "123456") {
		t.Fatalf("the agent's log holds the PIN: %q", log.String())
	}
	key.setPresent(false)
	// The cached state moves when a call fails, not at a probe.
	_, _ = key.Sign(rand.Reader, make([]byte, 32), crypto.SHA256)
	if st, _ = c.Status(ctx); st.KeyState != "absent" {
		t.Fatalf("the key was pulled: %+v", st)
	}
}

// A file key has nothing to unlock: present, and no key_ref.
func TestAFileKeyIsAlwaysPresent(t *testing.T) {
	r := newRig(t)
	c := socketFor(t, r.a)
	st, err := c.Status(context.Background())
	if err != nil || st.KeyState != "present" || st.KeyRef != "" || st.TouchKey {
		t.Fatalf("%+v %v", st, err)
	}
}

// A refused PIN comes back as the *hwkey.PINError the token raised, flags
// kept, and a body that is not a PIN is refused without being echoed.
func TestAWrongPINComesBackAsAPINError(t *testing.T) {
	key := newFakeKey(t, hwkey.Locked)
	_, c := agentWith(t, Config{Cert: tls.Certificate{PrivateKey: key, Certificate: [][]byte{{1}}}})
	err := c.Unlock(context.Background(), []byte("654321"))
	var pe *hwkey.PINError
	if !errors.As(err, &pe) || !pe.Low || pe.Final {
		t.Fatalf("%v", err)
	}
	if strings.Contains(err.Error(), "654321") {
		t.Fatalf("the error holds the PIN: %v", err)
	}
	if st, _ := c.Status(context.Background()); st.KeyState != "locked" {
		t.Fatalf("%+v", st)
	}
	// A PIN with a quote and a backslash survives the hand-built body.
	if err := c.Unlock(context.Background(), []byte(`a"b\c`)); err == nil {
		t.Fatal("the fake key accepts only 123456")
	}
	if got := key.tried(); len(got) != 2 || got[1] != `a"b\c` {
		t.Fatalf("the escaped PIN arrived as %q", got)
	}
}

// A blocked PIN comes back as a *hwkey.PINError with Blocked set, under its
// own code, and the agent's words never call it a refusal that invites another
// try. The key's own state is untouched.
func TestABlockedPINComesBackAsBlocked(t *testing.T) {
	key := newFakeKey(t, hwkey.Locked)
	key.blocked = true
	var log bytes.Buffer
	_, c := agentWith(t, Config{Cert: tls.Certificate{PrivateKey: key, Certificate: [][]byte{{1}}}, Log: &log})
	err := c.Unlock(context.Background(), []byte("123456"))
	var pe *hwkey.PINError
	if !errors.As(err, &pe) || !pe.Blocked {
		t.Fatalf("%v, want a blocked *hwkey.PINError", err)
	}
	if strings.Contains(err.Error(), "refused the PIN; ") || !strings.Contains(err.Error(), "blocked") {
		t.Fatalf("the error invites another try: %v", err)
	}
	if strings.Contains(log.String(), "123456") {
		t.Fatalf("the agent's log holds the PIN: %q", log.String())
	}
	if st, _ := c.Status(context.Background()); st.KeyState != "blocked" {
		t.Fatalf("%+v, want key_state blocked", st)
	}
	// The raw answer carries its own code and the way out.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/unlock", strings.NewReader(`{"pin":"123456"}`))
	New(Config{Cert: tls.Certificate{PrivateKey: key, Certificate: [][]byte{{1}}}}).Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), `"error":"pin_blocked"`) ||
		!strings.Contains(rec.Body.String(), "PUK") {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
}

// ruling 12, pre-flight I6: the touch key is the agent's only on the session
// key's own token; in every other case the agent starts and says why not.
func TestTouchKeyIsReportedOnlyOnTheSessionToken(t *testing.T) {
	session := &fakeToken{fakeKey: newFakeKey(t, hwkey.Present), module: "/usr/lib/libykcs11.so", serial: "123"}
	cert := func(k any) tls.Certificate { return tls.Certificate{PrivateKey: k, Certificate: [][]byte{{1}}} }
	for _, tc := range []struct {
		name    string
		session any
		touch   hwkey.Key
		want    bool
		why     string
	}{
		{"same token", session, &fakeToken{fakeKey: newFakeKey(t, hwkey.Present), module: "/usr/lib/libykcs11.so", serial: "123"}, true, ""},
		{"another token", session, &fakeToken{fakeKey: newFakeKey(t, hwkey.Present), module: "/usr/lib/libykcs11.so", serial: "999"}, false, "another token"},
		{"another module", session, &fakeToken{fakeKey: newFakeKey(t, hwkey.Present), module: "/usr/lib/other.so", serial: "123"}, false, "another token"},
		{"a TPM session key", newFakeKey(t, hwkey.Present), &fakeToken{fakeKey: newFakeKey(t, hwkey.Present), module: "/m.so", serial: "123"}, false, "not on a PKCS#11 token"},
		{"a file session key", nil, &fakeToken{fakeKey: newFakeKey(t, hwkey.Present), module: "/m.so", serial: "123"}, false, "not on a PKCS#11 token"},
		{"a touch key that is no token key", session, newFakeKey(t, hwkey.Present), false, "not a PKCS#11 key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var key any = tc.session
			if key == nil {
				k := newFakeKey(t, hwkey.Present)
				key = k.PrivateKey
			}
			_, c := agentWith(t, Config{Cert: cert(key), TouchKey: tc.touch})
			st, err := c.Status(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if st.TouchKey != tc.want || (tc.why == "") != (st.TouchKeyUnusable == "") ||
				!strings.Contains(st.TouchKeyUnusable, tc.why) {
				t.Fatalf("%+v, want touch_key %v and %q", st, tc.want, tc.why)
			}
		})
	}
	// An open failure main reports is the reason, and no touch key is held.
	_, c := agentWith(t, Config{Cert: cert(session), TouchKeyUnusable: "touch_key: no token matches"})
	if st, _ := c.Status(context.Background()); st.TouchKey || st.TouchKeyUnusable != "touch_key: no token matches" {
		t.Fatalf("%+v", st)
	}
	// With no touch_key configured, nothing is said.
	_, c = agentWith(t, Config{Cert: cert(session)})
	if st, _ := c.Status(context.Background()); st.TouchKey || st.TouchKeyUnusable != "" {
		t.Fatalf("%+v", st)
	}
}

// Unlock reaches the touch key too, when it is usable and only then.
func TestUnlockReachesAUsableTouchKeyOnly(t *testing.T) {
	session := &fakeToken{fakeKey: newFakeKey(t, hwkey.Locked), module: "/m.so", serial: "1"}
	same := &fakeToken{fakeKey: newFakeKey(t, hwkey.Locked), module: "/m.so", serial: "1"}
	_, c := agentWith(t, Config{Cert: tls.Certificate{PrivateKey: session, Certificate: [][]byte{{1}}}, TouchKey: same})
	if err := c.Unlock(context.Background(), []byte("123456")); err != nil {
		t.Fatal(err)
	}
	if len(same.tried()) != 1 {
		t.Fatalf("the touch key on the same token was tried %d times", len(same.tried()))
	}
	other := &fakeToken{fakeKey: newFakeKey(t, hwkey.Locked), module: "/m.so", serial: "2"}
	session2 := &fakeToken{fakeKey: newFakeKey(t, hwkey.Locked), module: "/m.so", serial: "1"}
	_, c = agentWith(t, Config{Cert: tls.Certificate{PrivateKey: session2, Certificate: [][]byte{{1}}}, TouchKey: other})
	if err := c.Unlock(context.Background(), []byte("123456")); err != nil {
		t.Fatal(err)
	}
	if n := len(other.tried()); n != 0 {
		t.Fatalf("the PIN went to a key on another token (%d tries)", n)
	}
}

// Status carries the store the session key sits in, one word of a closed set
// and never a reference: `port49 hwkey` and the login's remedy lines choose by
// it, not by matching a message (decision 55 ruling 16).
func TestStatusCarriesTheSessionKeyStore(t *testing.T) {
	session := newFakeKey(t, hwkey.Present)
	cert := func(k any) tls.Certificate { return tls.Certificate{PrivateKey: k, Certificate: [][]byte{{1}}} }
	for _, store := range []string{"pkcs11", "tpm", "file", "secure_enclave"} {
		_, c := agentWith(t, Config{Cert: cert(session.PrivateKey), KeyStore: store, KeyRef: "pkcs11:token=x;id=%01"})
		st, err := c.Status(context.Background())
		if err != nil || st.SessionKeyStore != store {
			t.Fatalf("store %q: status %+v err %v", store, st, err)
		}
	}
	_, c := agentWith(t, Config{Cert: cert(session.PrivateKey)})
	if st, err := c.Status(context.Background()); err != nil || st.SessionKeyStore != "" {
		t.Fatalf("an agent told no store reports one: %+v %v", st, err)
	}
}
