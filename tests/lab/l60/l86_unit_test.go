package l60

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/agent"
	"github.com/rhwendt/port49/internal/broker"
	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/hwkey/hwfake"
	"github.com/rhwendt/port49/internal/oidc"
	"github.com/rhwendt/port49/internal/pivattest"
	"github.com/rhwendt/port49/internal/policy"
	"github.com/rhwendt/port49/internal/testpki"
	"github.com/rhwendt/port49/internal/userconfig"
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
		{"timeout, exit 1, no mark", words, result{stdout: "no revocation is in force\n"}, true},
		{"another mark, not the target's", words, result{stdout: "principal user:other@example.com revoked\n"}, false},
		{"a list format that says nothing", words, result{stdout: "no revocations"}, false},
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
	login := result{code: 0, stdout: "port49 login: signed in as user:alice@corp.example.com" + signedInWords + "2026-10-28T10:00:00Z",
		stderr: "port49 login: " + tokenKeyWords + "\n"}
	ok := res(0, "")
	for _, c := range []struct {
		name    string
		login   result
		call    result
		issued  bool
		touches int
		pass    bool
	}{
		{"the OIDC path, one touch", login, ok, true, 1, true},
		{"two touches", login, ok, true, 2, false},
		{"no touch counted", login, ok, true, 0, false},
		{"the call failed", login, res(1, "x"), true, 1, false},
		{"the login failed", res(1, "x"), ok, true, 1, false},
		{"no issued-certificate words: a held certificate, not a sign-in", result{stderr: login.stderr}, ok, true, 1, false},
		{"the key is not the token's issued_key", result{stdout: login.stdout, stderr: "port49 login: a file key"}, ok, true, 1, false},
		{"the broker issued nothing", login, ok, false, 1, false},
	} {
		if v := l86VerdictC(c.login, c.call, c.issued, c.touches); v.pass != c.pass {
			t.Errorf("%s: %v", c.name, v)
		}
	}
}

// The proxy's verdict says it does not close (c), and it is not the real cell's.
func TestL86VerdictC9eIsAProxy(t *testing.T) {
	if v := l86VerdictC9e(res(0, ""), 1); !v.pass || !strings.Contains(v.String(), "does not close (c)") {
		t.Errorf("%v", v)
	}
	for _, c := range []struct {
		r       result
		touches int
	}{{res(1, "x"), 1}, {res(0, ""), 2}} {
		if v := l86VerdictC9e(c.r, c.touches); v.pass {
			t.Errorf("%+v %d: %v", c.r, c.touches, v)
		}
	}
}

func TestL86VerdictD(t *testing.T) {
	for _, c := range []struct {
		name    string
		r       result
		grown   []string
		refused int
		pass    bool
	}{
		{"insert, nothing sent", res(1, "agent: insert your key"), nil, 0, true},
		{"it ran", res(0, ""), nil, 0, false},
		{"other words", res(1, "hwkey: the key is not present"), nil, 0, false},
		{"the refusal was logged", res(1, "agent: insert your key"), []string{"admin_touch admin_touch_refused"}, 1, false},
		// The by-name check stands alone: a refusal under an event the admin filter
		// does not name is still the row's failure.
		{"the refusal by name alone", res(1, "agent: insert your key"), nil, 1, false},
		{"anything admin was logged", res(1, "agent: insert your key"), []string{"admin_touch"}, 0, false},
	} {
		v := l86VerdictD(c.r, c.grown, c.refused)
		if v.pass != c.pass {
			t.Errorf("%s: %v", c.name, v)
		}
		if c.refused > 0 && !strings.Contains(v.String(), refusedReason) {
			t.Errorf("%s: the verdict does not name %s: %v", c.name, refusedReason, v)
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

// The by-name reads: a refusal under any event, past the first lines only; an issue
// record only when permitted; neither reads a principal.
func TestL86LogReadsByName(t *testing.T) {
	text := strings.Join([]string{
		`{"event":"admin_touch","verdict":"deny","reason":"admin_touch_refused","principal":"user:x"}`,
		`{"event":"revoke","verdict":"permit"}`,
		`{"event":"something_else","verdict":"deny","reason":"admin_touch_refused"}`,
		`{"event":"admin_touch","verdict":"permit","reason":"admin_touch_proved"}`,
		`not json`,
	}, "\n") + "\n"
	if n := l86Refused(text, 0); n != 2 {
		t.Errorf("refused counted %d, want 2 (any event)", n)
	}
	if n := l86Refused(text, 1); n != 1 {
		t.Errorf("past the first line: %d, want 1", n)
	}
	if n := l86Refused(text, 3); n != 0 {
		t.Errorf("past the third line: %d, want 0", n)
	}
	for _, c := range []struct {
		text string
		want bool
	}{
		{`{"event":"issue","verdict":"permit"}`, true},
		{`{"event":"issue","verdict":"deny","reason":"trust_domain_unresolved"}`, false},
		{`{"event":"mint","verdict":"permit"}`, false},
		{"", false},
	} {
		if got := l86Issued(c.text + "\n"); got != c.want {
			t.Errorf("%q: issued %v, want %v", c.text, got, c.want)
		}
	}
}

// Keycloak's image here is compose.yaml's, byte for byte, as the lab's own test holds
// oidc_test.go's.
func TestL86KeycloakImageIsComposes(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "tests", "lab", "oidc", "compose.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "image: "+kcImage+"\n") {
		t.Errorf("tests/lab/oidc/compose.yaml's image is not kcImage (%s)", kcImage)
	}
}

func TestL86HostsEntry(t *testing.T) {
	for _, c := range []struct {
		addrs []string
		want  bool
	}{{[]string{"127.0.0.1"}, true}, {[]string{"10.0.0.5", "127.0.0.1"}, true}, {[]string{"10.0.0.5"}, false}, {nil, false}} {
		if got := l86HostsOK(c.addrs); got != c.want {
			t.Errorf("%v: %v", c.addrs, got)
		}
	}
}

// The login's recorded words never hold the authorization address.
func TestL86LoginWordsDropTheAddress(t *testing.T) {
	got := l86LoginWords("port49 login: open this address:\n  https://keycloak.port49.lab:18443/realms/port49-lab/x?state=abc&nonce=def\ndone\n")
	if strings.Contains(got, "https://") || strings.Contains(got, "state=") || !strings.Contains(got, "done") ||
		!strings.Contains(got, "open this address") {
		t.Errorf("%q", got)
	}
}

// The cell's config is one the CLI loads: the keys cell (c) names, in the form
// userconfig.File reads, and the OIDC subject is the policy's.
func TestL86ConfigLoads(t *testing.T) {
	home := privateDir(t, "l86cfg") // 0700, as the cell's HOME is
	cfg := l86Config{broker: "https://127.0.0.1:9", redirectPort: kcRedirectPort,
		touchKey: "pkcs11:id=%02?module-path=/m.so", issuedKey: "pkcs11:id=%04?module-path=/m.so"}
	if err := cfg.writeConfig(home); err != nil {
		t.Fatal(err)
	}
	f, ok, err := userconfig.Load(filepath.Join(home, ".port49", "config.yaml"))
	if err != nil || !ok {
		t.Fatalf("the config does not load: ok %v, %v", ok, err)
	}
	if f.Method != "oidc" || f.IssuedKeyStore != "pkcs11" || f.IssuedKey != cfg.issuedKey || f.TouchKey != cfg.touchKey ||
		f.OIDCRedirectPort != kcRedirectPort || f.Broker != cfg.broker {
		t.Errorf("read back %+v", f)
	}
	if !strings.Contains(l86OIDCPolicy(true), "user:"+l86OIDCEmail) || strings.Contains(l86OIDCPolicy(true), labEmail) {
		t.Error("the OIDC policy does not name the OIDC subject alone")
	}
	pol := l86OIDCPolicy(true)
	if !strings.Contains(pol, "revoke_others") || !strings.Contains(pol, "lift_revocations") {
		t.Error("the OIDC subject has no admin rights")
	}
}

// The broker the cell serves is OIDC-only and issues: /v1/config lists the realm as a
// human provider (the client id and the email scope) and says issuance is available,
// to a client with no certificate.
func TestL86OIDCBrokerOffersTheRealmAndIssuance(t *testing.T) {
	b := startBrokerWire(t, nil, nil, nil, l86OIDCPolicy, func(br *broker.Broker, now func() time.Time) bool {
		ks := oidc.NewKeySet(oidc.KeySetConfig{Issuer: kcIssuer(), Client: http.DefaultClient, Now: now, M: br.Metrics})
		return l86WireOIDC(t, br, now, ks)
	})
	srvCA, err := os.ReadFile(b.serverCA)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(srvCA)
	cl := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}},
		Timeout: 10 * time.Second}
	resp, err := cl.Get(b.url + "/v1/config")
	if err != nil {
		t.Fatalf("/v1/config with no certificate: %v", err)
	}
	defer resp.Body.Close()
	var c api.Config
	if err := json.NewDecoder(resp.Body).Decode(&c); err != nil {
		t.Fatal(err)
	}
	if len(c.OIDC) != 1 || c.OIDC[0].Issuer != kcIssuer() || c.OIDC[0].ClientID != kcClientID ||
		!slices.Contains(c.OIDC[0].Scopes, "email") {
		t.Errorf("providers %+v", c.OIDC)
	}
	if c.Issuance == nil || c.Issuance.Available == nil || !*c.Issuance.Available {
		t.Errorf("issuance %+v", c.Issuance)
	}
}

// guardLab is a lab with no terminal and a fake agent: a `sleep` child recorded as the
// cell's agent by its pid, which the guard must stop.
func guardLab(t *testing.T) (*lab, *exec.Cmd, *bool) {
	t.Helper()
	h := setupLab(t, "guard", false, nil, io.Discard, privateDir(t, "l86guard"))
	agent := exec.Command("sleep", "120")
	if err := agent.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = agent.Process.Kill(); _ = agent.Wait() })
	h.agents[filepath.Join(t.TempDir(), "no-such.sock")] = agent.Process.Pid
	killed := new(bool)
	h.onKill = append(h.onKill, func() { *killed = true })
	return h, agent, killed
}

// A killed cell stops its agent by pid, runs what else it must undo, and exits non-zero.
func TestL86GuardCleansUpOnASignal(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGTERM, syscall.SIGINT} {
		h, agent, killed := guardLab(t)
		exit := make(chan int, 1)
		h.l86Guard(func(c int) { exit <- c }, time.Time{})
		if err := syscall.Kill(os.Getpid(), sig); err != nil {
			t.Fatal(err)
		}
		select {
		case c := <-exit:
			if c == 0 {
				t.Errorf("%v: exit code 0 for a killed cell", sig)
			}
		case <-time.After(30 * time.Second):
			t.Fatalf("%v: the guard did not clean up and exit", sig)
		}
		if h.agentsRunning() != 0 {
			t.Errorf("%v: the agent is still recorded as running", sig)
		}
		if err := agent.Process.Signal(syscall.Signal(0)); err == nil {
			// still signalable: give the reaper a moment, then it must be gone
			done := make(chan struct{})
			go func() { _ = agent.Wait(); close(done) }()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Errorf("%v: the agent process was not stopped", sig)
			}
		}
		if !*killed {
			t.Errorf("%v: the extra clean-up (Keycloak, the lock) did not run", sig)
		}
	}
}

// The test binary's own deadline, which panics without running t.Cleanup, is a trigger too.
func TestL86GuardCleansUpBeforeTheDeadline(t *testing.T) {
	old := l86KillGrace
	l86KillGrace = 100 * time.Millisecond
	defer func() { l86KillGrace = old }()
	h, _, killed := guardLab(t)
	exit := make(chan int, 1)
	h.l86Guard(func(c int) { exit <- c }, time.Now().Add(300*time.Millisecond))
	select {
	case <-exit:
	case <-time.After(30 * time.Second):
		t.Fatal("the guard did not clean up before the deadline")
	}
	if !*killed || h.agentsRunning() != 0 {
		t.Error("the deadline clean-up did not run")
	}
}

// A cell that ends normally drops the guard: no exit, and a later signal is not its business.
func TestL86GuardIsDroppedWhenTheCellEnds(t *testing.T) {
	exit := make(chan int, 1)
	t.Run("cell", func(t *testing.T) {
		h := setupLab(t, "guard", false, nil, io.Discard, privateDir(t, "l86guard"))
		h.l86Guard(func(c int) { exit <- c }, time.Time{})
	})
	time.Sleep(200 * time.Millisecond)
	select {
	case c := <-exit:
		t.Fatalf("the guard exited (%d) for a cell that ended normally", c)
	default:
	}
}

func TestL86MissingSlot9cStopsTheCell(t *testing.T) {
	if err := l86CheckSlot(func() error { return nil }); err != nil {
		t.Fatalf("a present slot was refused: %v", err)
	}
	err := l86CheckSlot(func() error { return fmt.Errorf("no object with CKA_ID 02") })
	if err == nil || !strings.Contains(err.Error(), "INVALID") || !strings.Contains(err.Error(), "never create, reset or overwrite") ||
		!strings.Contains(err.Error(), "tell the lead") {
		t.Fatalf("a missing slot: %v", err)
	}
}

// A killed cell lets the lab lock go before it exits, by name, not only by dying.
func TestL86KilledCellReleasesTheLabLock(t *testing.T) {
	probe, err := os.OpenFile(labLockFile, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Skipf("the lab lock file: %v", err)
	}
	defer probe.Close()
	if err := syscall.Flock(int(probe.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Skip("the lab is occupied; this test never takes a lock someone holds")
	}
	_ = syscall.Flock(int(probe.Fd()), syscall.LOCK_UN)
	h := setupLab(t, "lock", false, nil, io.Discard, privateDir(t, "l86lock"))
	h.l86Lock(t, "x")
	if err := syscall.Flock(int(probe.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err == nil {
		t.Fatal("the cell did not hold the lab lock")
	}
	for _, f := range h.onKill {
		f()
	}
	if err := syscall.Flock(int(probe.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatalf("the kill clean-up did not release the lab lock: %v", err)
	}
	_ = syscall.Flock(int(probe.Fd()), syscall.LOCK_UN)
}
