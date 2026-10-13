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
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/rhwendt/port49/internal/hwkey"
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
	switch {
	case !k.present:
		k.state = hwkey.Absent
	case k.state == hwkey.Absent:
		k.state = hwkey.Locked // back, and wants its PIN
	}
	return k.state
}

func (k *fakeKey) Sign(rd io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	k.mu.Lock()
	switch {
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
		return hwkey.ErrKeyAbsent
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
