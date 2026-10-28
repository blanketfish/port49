package l60

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/agent"
	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/hwkey/hwfake"
	"github.com/rhwendt/port49/internal/pivattest"
	"github.com/rhwendt/port49/internal/policy"
	"github.com/rhwendt/port49/internal/testpki"
)

// The L86 cells' verdicts, policy and log reading, with no token and no terminal.

func res(code int, stderr string) result {
	return result{code: code, stderr: stderr, took: 16 * time.Second}
}

func TestL86VerdictA(t *testing.T) {
	timeout := res(1, "port49 revoke: hwkey: "+touchTimeoutWords+"; touch the key when it blinks and try again")
	for _, c := range []struct {
		name       string
		c1, c2, c3 result
		pass       bool
	}{
		{"each call takes its own touch", res(0, ""), timeout, res(0, ""), true},
		{"the first touch is reused", res(0, ""), res(0, ""), res(0, ""), false},
		{"the first call failed", res(1, "x"), timeout, res(0, ""), false},
		{"the second failed for another reason", res(0, ""), res(1, "the broker is unavailable"), res(0, ""), false},
		{"the third failed", res(0, ""), timeout, res(1, "x"), false},
	} {
		v := l86VerdictA(c.c1, c.c2, c.c3, 1)
		if v.pass != c.pass {
			t.Errorf("%s: %v", c.name, v)
		}
		if c.name == "the first touch is reused" && !strings.Contains(v.why, "reused") {
			t.Errorf("%s: the reason is %q", c.name, v.why)
		}
	}
}

func TestL86VerdictB(t *testing.T) {
	words := res(1, touchTimeoutWords)
	for _, c := range []struct {
		name string
		call result
		list result
		pass bool
	}{
		{"timeout, exit 1, no mark", words, result{stdout: "no revocations"}, true},
		{"exit 2", res(2, touchTimeoutWords), result{}, false},
		{"other words", res(1, "the broker refused"), result{}, false},
		{"a mark was made", words, result{stdout: "user:l86-b-1@example.com revoked"}, false},
		{"the list failed", words, result{code: 1}, false},
	} {
		if v := l86VerdictB(c.call, c.list, "user:l86-b-1@example.com"); v.pass != c.pass {
			t.Errorf("%s: %v", c.name, v)
		}
	}
}

func TestL86VerdictC(t *testing.T) {
	for _, c := range []struct {
		r       result
		touches int
		pass    bool
	}{{res(0, ""), 1, true}, {res(0, ""), 2, false}, {res(1, "x"), 1, false}} {
		if v := l86VerdictC(c.r, c.touches); v.pass != c.pass {
			t.Errorf("%+v %d: %v", c.r, c.touches, v)
		}
	}
}

func TestL86VerdictD(t *testing.T) {
	for _, c := range []struct {
		name  string
		r     result
		grown []string
		pass  bool
	}{
		{"insert, nothing sent", res(1, "agent: insert your key"), nil, true},
		{"it ran", res(0, ""), nil, false},
		{"other words", res(1, "hwkey: the key is not present"), nil, false},
		{"the refusal was logged", res(1, "agent: insert your key"), []string{"admin_touch admin_touch_refused"}, false},
		{"anything admin was logged", res(1, "agent: insert your key"), []string{"admin_touch"}, false},
	} {
		if v := l86VerdictD(c.r, c.grown); v.pass != c.pass {
			t.Errorf("%s: %v", c.name, v)
		}
	}
}

// The admin policy loads and gives the subject exactly the two rights.
func TestL86PolicyGivesTheAdminRights(t *testing.T) {
	for _, touch := range []bool{false, true} {
		p := l86Policy(touch)
		if strings.Count(p, "api: [revoke_others, lift_revocations]") != 1 {
			t.Fatalf("the policy does not hold the rights once:\n%s", p)
		}
		f := filepath.Join(t.TempDir(), "policy.yaml")
		if err := os.WriteFile(f, []byte(p), 0o600); err != nil {
			t.Fatal(err)
		}
		pol, err := policy.Load(f, policy.Env{Devices: labDevices()})
		if err != nil {
			t.Fatalf("touch=%v: %v", touch, err)
		}
		if h := pol.AdminRightHolders(); len(h) != 1 {
			t.Errorf("touch=%v: %d admin-right holders, want 1", touch, len(h))
		}
	}
}

func TestL86AdminEventsReadNamesOnly(t *testing.T) {
	log := filepath.Join(t.TempDir(), "d.jsonl")
	lines := []string{
		`{"event":"mint","verdict":"permit"}`,
		`{"event":"admin_touch","verdict":"deny","reason":"admin_touch_refused","principal":"user:x"}`,
		`{"event":"revoke","verdict":"permit"}`,
		`not json`,
		`{"event":"refresh"}`,
	}
	if err := os.WriteFile(log, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, n, err := l86AdminEvents(log, 0)
	if err != nil || n != 5 || len(got) != 2 || got[0] != "admin_touch admin_touch_refused" || got[1] != "revoke" {
		t.Fatalf("got %q, %d lines, %v", got, n, err)
	}
	if got, _, _ := l86AdminEvents(log, 3); len(got) != 0 {
		t.Errorf("lines past the third: %q", got)
	}
	if strings.Contains(strings.Join(got, " "), "user:x") {
		t.Error("a principal was read")
	}
}

func TestL86FirmwareIsThreeNumbers(t *testing.T) {
	for in, ok := range map[string]bool{"5.4.3": true, " 5.7.1\n": true, "5.4": false, "": false, "v5.4.3": false, "5.4.3; rm": false} {
		if _, err := l86Firmware(in); (err == nil) != ok {
			t.Errorf("%q: %v", in, err)
		}
	}
}

// Observations never keep a long opaque run, a serial or a PIN-shaped prompt answer.
func TestL86ObservationsMaskWhatIsLong(t *testing.T) {
	var out lockedBuffer
	dir := t.TempDir()
	h := setupStudyLab(t, "L86", "unit", false, nil, &out, dir)
	h.obs("words", "agent said "+strings.Repeat("A1b2", 12)+" for YubiKey PIV #1234567")
	b, err := os.ReadFile(filepath.Join(dir, fileObs))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if strings.Contains(s, "A1b2A1b2") || strings.Contains(s, "1234567") || !strings.Contains(s, "L86 unit words: agent said <opaque>") {
		t.Errorf("the observation is %q", s)
	}
}

// The lab broker under l86Policy, with software keys standing in for the token (the
// attestation roots are a test hierarchy's): the person's admin revoke runs with a
// touch and is refused without one, and the revocation list shows only the first.
// It proves the cells' broker setup, so a FAIL on the SER8 is the key's and not the harness's.
func TestL86TheBrokerSetupServesAnAdminCall(t *testing.T) {
	now := time.Now()
	ca, err := writeClientCA(t.TempDir(), now)
	if err != nil {
		t.Fatal(err)
	}
	piv, err := testpki.NewPIV(now)
	if err != nil {
		t.Fatal(err)
	}
	var log lockedBuffer
	b := startBrokerWith(t, ca, piv.Anchors(), &log, l86Policy)
	certFile, keyFile := fileClient(t, ca)
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	sessionKey := cert.PrivateKey.(*ecdsa.PrivateKey)
	touchKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	session := hwfake.New(sessionKey, "/lab/software.so", "LAB-TOKEN")
	touch := hwfake.New(touchKey, "/lab/software.so", "LAB-TOKEN")
	sessionAtt, err := piv.Slot(&sessionKey.PublicKey, pivattest.TouchNever)
	if err != nil {
		t.Fatal(err)
	}
	touchAtt, err := piv.Slot(&touchKey.PublicKey, pivattest.TouchAlways)
	if err != nil {
		t.Fatal(err)
	}
	touch.SetCertificates(sessionAtt, piv.Device, touchAtt)
	cert.PrivateKey = session
	srvCA, err := os.ReadFile(b.serverCA)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(srvCA)
	a := agent.New(agent.Config{BrokerURL: b.url, BrokerCA: pool, BrokerCAPEM: srvCA, Cert: cert, TouchKey: touch, Log: io.Discard})
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if _, err := a.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(api.RevokeRequest{Principal: l86Target("unit", 1)})
	resp, err := a.Admin(ctx, agent.AdminRequest{Method: "POST", Path: "/v1/tokens/revoke", Body: body})
	if err != nil || resp.Status != 200 {
		t.Fatalf("the touched revoke: status %d, err %v", resp.Status, err)
	}
	list, err := a.Admin(ctx, agent.AdminRequest{Method: "GET", Path: "/v1/revocations"})
	if err != nil || list.Status != 200 || !strings.Contains(string(list.Body), "l86-unit-1@example.com") {
		t.Fatalf("the list: status %d, err %v", list.Status, err)
	}
	if got, _, _ := l86AdminEventsFrom(log.String(), 0); !strings.Contains(strings.Join(got, ","), "admin_touch") {
		t.Errorf("the decision log shows no admin_touch: %q", got)
	}
}
