//go:build lab

package lab

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/go-ldap/ldap/v3"
	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/directory"
	"github.com/rhwendt/port49/internal/oidc"
	"github.com/rhwendt/port49/internal/testpki"
	"github.com/rhwendt/port49/internal/totp"
	"github.com/rhwendt/port49/internal/userconfig"
)

// L67's cells are lettered a to g in the plan; the harness runs the table, so a
// cell dropped from it is a cell no run measures.
func TestL67CellTableNamesEveryCell(t *testing.T) {
	var ids []string
	for _, c := range l67Cells {
		if c.Name == "" || c.Claim == "" {
			t.Errorf("cell %q has no name or no claim", c.ID)
		}
		ids = append(ids, c.ID)
	}
	if got := strings.Join(ids, ""); got != "abcdefg" {
		t.Fatalf("the cells are %q; plan 9e Task 13 names a to g, each once and in order", got)
	}
}

func TestL67PasswordIsGeneratedAndMeetsTheDirectoriesRules(t *testing.T) {
	a, err := l67Password()
	if err != nil {
		t.Fatal(err)
	}
	b, err := l67Password()
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("two generated passwords are equal")
	}
	if len(a) != 24 {
		t.Fatalf("a generated password has %d characters, want 24", len(a))
	}
	var upper, lower, digit, symbol bool
	for _, r := range a {
		switch {
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsLower(r):
			lower = true
		case unicode.IsDigit(r):
			digit = true
		default:
			symbol = true
		}
	}
	if !upper || !lower || !digit || !symbol {
		t.Fatal("a generated password lacks one of the four classes Samba and Windows complexity ask for")
	}
	// The password travels in an env file, a shell, sed's replacement and
	// PowerShell's stdin: none of these characters may be in it.
	if strings.ContainsAny(a, " \t\n\\'\"`$&|;<>#%{}()*?[]!~^") {
		t.Fatal("a generated password holds a character a shell, sed or an env file would read")
	}
}

func TestL67EvidenceNeverHoldsTheGeneratedPassword(t *testing.T) {
	pw, err := l67Password()
	if err != nil {
		t.Fatal(err)
	}
	d := &directories{out: t.TempDir()}
	ev := evidence(t, d, "L67-unit")
	ev.hide(pw)
	// The password in a label, in an error a directory library wrapped around
	// the bind, in a data field and in a filter.
	ev.mark("alice signs in with %s", pw)
	ev.bind("simple", fmt.Errorf("LDAP Result Code 49 %q: Invalid Credentials for %s", "Invalid Credentials", pw), time.Millisecond)
	ev.add(evidenceLine{Event: "l67_check", Label: "wrong " + pw, Data: "52e " + pw, Filter: "(userPassword=" + pw + ")"})
	raw, err := os.ReadFile(ev.Path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), pw) {
		t.Fatal("the evidence file holds the generated password")
	}
	if !strings.Contains(string(raw), "<alice's password>") {
		t.Fatalf("the evidence does not say where the password was; want the placeholder:\n%s", raw)
	}
	ev.assertClean(t, pw)
}

func TestL67RecordKeepsTheResultAndTheData(t *testing.T) {
	d := &directories{out: t.TempDir()}
	ev := evidence(t, d, "L67-unit")
	for _, c := range []struct {
		err        error
		kind, data string
		result     int
	}{
		{nil, "ok", "", 0},
		{&directory.PasswordRefusal{Result: 49, Data: "532"}, "refused", "532", 49},
		{&directory.PasswordRefusal{Result: 49, Data: "account_locked"}, "refused", "account_locked", 49},
		{&directory.PasswordRefusal{Result: 0, Data: "change_after_reset"}, "refused", "change_after_reset", 0},
		{directory.ErrEmptyPassword, "empty_password", "", 0},
		{fmt.Errorf("%w: ldaps://x: down", directory.ErrUnavailable), "unavailable", "", 0},
	} {
		got := l67Classify(c.err)
		if got.Kind != c.kind || got.Result != c.result || got.Data != c.data {
			t.Errorf("l67Classify(%v) = %+v, want kind %s result %d data %q", c.err, got, c.kind, c.result, c.data)
		}
		l67Record(ev, "unit", c.err)
	}
	raw, _ := os.ReadFile(ev.Path)
	for _, want := range []string{`"data":"532"`, `"data":"account_locked"`, `"data":"change_after_reset"`, `"result_code":49`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("the evidence lacks %s:\n%s", want, raw)
		}
	}
}

func TestL67ClassifiesALDAPRefusalThatIsNotACheckPasswordOne(t *testing.T) {
	// A raw go-ldap bind: the result code and the AD data code in the
	// diagnostic are what the evidence keeps; the message itself is not.
	err := &ldap.Error{ResultCode: 49, Err: errors.New("80090308: LdapErr: DSID-0C0903A9, comment: AcceptSecurityContext error, data 52e, v1db1")}
	got := l67Classify(err)
	if got.Kind != "ldap" || got.Result != 49 || got.Data != "52e" {
		t.Fatalf("%+v", got)
	}
	if l67Classify(&ldap.Error{ResultCode: 0}).Kind != "ok" {
		t.Fatal("result 0 is a success")
	}
}

// The step a sign-in takes is strictly after the last one taken, and the broker
// accepts one step either side of its clock: the next step is usable from one
// step before it begins.
func TestL67NextStep(t *testing.T) {
	at := func(step int64, into time.Duration) time.Time {
		return time.Unix(step*30, 0).Add(into)
	}
	for _, c := range []struct {
		name string
		last int64
		now  time.Time
		want int64
		wait time.Duration
	}{
		{"the next step is within reach now", 100, at(100, 5*time.Second), 101, 0},
		{"the step after next is one step off", 101, at(100, 5*time.Second), 102, 25 * time.Second},
		{"two ahead waits for the boundary", 103, at(100, 0), 104, 90 * time.Second},
		{"far behind the clock takes the clock's own earliest step", 90, at(100, 5*time.Second), 99, 0},
	} {
		step, wait := l67NextStep(c.last, c.now)
		if step != c.want || wait != c.wait {
			t.Errorf("%s: l67NextStep(%d) = step %d, wait %v; want step %d, wait %v", c.name, c.last, step, wait, c.want, c.wait)
		}
	}
}

// The authenticator's code for a step is the one totp.Check takes for it.
func TestL67CodeForAStepIsTheBrokersToCheck(t *testing.T) {
	secret := []byte("12345678901234567890")
	now := time.Unix(30*1000+7, 0)
	step, wait := l67NextStep(999, now)
	if wait != 0 {
		t.Fatalf("wait %v", wait)
	}
	code, err := l67CodeAt(secret, step)
	if err != nil {
		t.Fatal(err)
	}
	got, err := totp.Check(secret, code, now, 999)
	if err != nil || got != step {
		t.Fatalf("totp.Check took step %d, %v; the harness meant %d", got, err, step)
	}
}

// Nine wrong passwords straddling a window boundary reach the directory, four
// before it and five after it, each side within port49's per-principal limit,
// one under the directories' lockout threshold of ten (I11).
func TestL67TheStraddleStaysUnderTheThresholdByOne(t *testing.T) {
	if l67Before+l67After != l67Threshold-1 {
		t.Fatalf("%d + %d wrong passwords against a threshold of %d: the margin the plan records is one", l67Before, l67After, l67Threshold)
	}
	if l67Before >= oidc.DefaultFailuresPerPrincipal || l67After > oidc.DefaultFailuresPerPrincipal {
		t.Fatalf("a side of the straddle (%d, %d) is over port49's per-principal limit %d, so it would be throttled, not sent",
			l67Before, l67After, oidc.DefaultFailuresPerPrincipal)
	}
	if l67Defaults != oidc.DefaultFailuresPerPrincipal {
		t.Fatalf("the default-limits cell sends %d, port49's default is %d", l67Defaults, oidc.DefaultFailuresPerPrincipal)
	}
}

func TestL67Unchanged(t *testing.T) {
	// base is what reading the count itself costs (a Windows reader's own ssh
	// is a TCP connection the DC accepts); the action may add nothing to it.
	for _, c := range []struct {
		before, after, base int
		want                bool
	}{
		{10, 10, 0, true}, {10, 11, 0, false}, {10, 11, 1, true}, {10, 12, 1, false}, {10, 10, 1, false},
	} {
		if got := l67Unchanged(c.before, c.after, c.base); got != c.want {
			t.Errorf("l67Unchanged(%d, %d, %d) = %v, want %v", c.before, c.after, c.base, got, c.want)
		}
	}
}

func TestL67TheWindowsScriptIsRegisteredAndItsPasswordIsASecret(t *testing.T) {
	params, ok := winScripts["l67"]
	if !ok {
		t.Fatal("l67.ps1 is not in winScripts")
	}
	if strings.Join(params, ",") != "step,person_password,name" {
		t.Fatalf("l67's parameters are %v", params)
	}
	secret := false
	for _, p := range winSecretParams {
		secret = secret || p == "person_password"
	}
	if !secret {
		t.Fatal("person_password is not in winSecretParams, so no script is checked for writing it")
	}
	if _, err := winScriptFS.ReadFile("directory/windows/scripts/l67.ps1"); err != nil {
		t.Fatal(err)
	}
}

// The note's run line carries the variable that un-skips the Windows test.
func TestL67RunLineNamesTheWindowsGate(t *testing.T) {
	if got := dirRunLine("^TestL67Windows$"); !strings.Contains(got, "PORT49_LAB_L67_WINDOWS=1 go test") {
		t.Errorf("the Windows run line is %q, want it to start with PORT49_LAB_L67_WINDOWS=1", got)
	}
	if got := dirRunLine("^TestL67$"); strings.Contains(got, "PORT49_LAB_L67_WINDOWS") {
		t.Errorf("the container run line is %q, want no Windows gate", got)
	}
}

// A wrong code is one totp.Check reads as no step at all, whenever it is asked.
func TestL67WrongCodeIsNeverAccepted(t *testing.T) {
	secret := []byte("12345678901234567890")
	for _, now := range []time.Time{time.Unix(30*1000, 0), time.Unix(30*1000+29, 0), time.Unix(30*987654+13, 0)} {
		code, err := l67WrongCode(secret, now)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := totp.Check(secret, code, now, 0); !errors.Is(err, totp.ErrWrongCode) {
			t.Errorf("at %v the \"wrong\" code was read as %v, want ErrWrongCode (not a skew, not a step)", now, err)
		}
	}
}

// A directory as the broker's configuration names it, with no files behind it
// but the CA the config loader reads.
func l67TestDir(t *testing.T, name string) *labDir {
	t.Helper()
	ca := filepath.Join(t.TempDir(), "l67-unit-ca.pem")
	if err := os.WriteFile(ca, []byte("-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	d := &directories{pki: &dirPKI{caFile: ca}, password: "unit-test-bind-password"}
	if name == platOpenLDAP {
		return &labDir{name: name, d: d, uri: "ldaps://localhost:10636", bindDN: "cn=port49,ou=Svc,dc=corp,dc=example,dc=com",
			userFilter: "(objectClass=inetOrgPerson)", groupFilter: "(objectClass=groupOfNames)", usernameAttr: "uid",
			baseDN: "dc=corp,dc=example,dc=com", groupsBaseDN: "ou=G,dc=corp,dc=example,dc=com"}
	}
	return &labDir{name: name, d: d, uri: "ldaps://localhost:20636", bindDN: "CN=port49,OU=Svc," + dirBase,
		userFilter: "(&(objectCategory=person)(objectClass=user))", groupFilter: "(objectClass=group)",
		usernameAttr: "sAMAccountName", baseDN: dirBase, groupsBaseDN: "OU=G," + dirBase}
}

// What reading the connection count costs: a container's reader must cost
// nothing twice in a row (or the count is noisy and says so); the DC's costs its
// own ssh, so the least of several reads is its base.
func TestL67BaseCost(t *testing.T) {
	for _, tc := range []struct {
		name    string
		costs   []int
		windows bool
		base    int
		quiet   bool
	}{
		{"container quiet", []int{1, 0, 0}, false, 0, true},
		{"container noisy", []int{1, 0, 1, 0}, false, 0, false},
		{"container always one", []int{1, 1, 1}, false, 1, false},
		{"dc least", []int{3, 2, 4, 2, 5}, true, 2, true},
		{"no reads", nil, false, 0, false},
	} {
		base, quiet := l67BaseCost(tc.costs, tc.windows)
		if base != tc.base || quiet != tc.quiet {
			t.Errorf("%s: base %d quiet %v, want %d and %v", tc.name, base, quiet, tc.base, tc.quiet)
		}
	}
}

// The control for a state requires the account to be in that state and in none
// of the others (an "expired" account that is also must-change answers as the
// must-change one).
func TestL67OtherFlags(t *testing.T) {
	for _, tc := range []struct {
		s     l67State
		state string
		want  string
	}{
		{l67State{Expired: true}, "expired", ""},
		{l67State{Expired: true, MustChange: true}, "expired", "must_change"},
		{l67State{MustChange: true, Disabled: true}, "must change", "disabled"},
		{l67State{Locked: true, Expired: true, MustChange: true}, "locked", "expired, must_change"},
		{l67State{Disabled: true}, "disabled", ""},
	} {
		if got := strings.Join(l67OtherFlags(tc.s, tc.state), ", "); got != tc.want {
			t.Errorf("%+v as %s: other flags %q, want %q", tc.s, tc.state, got, tc.want)
		}
	}
}

// A raw bind keeps what CheckPassword filters: the result code, any AD data
// code (the allow-list of internal/directory does not apply) and whether the
// ppolicy control came back and with which error.
func TestL67RawBind(t *testing.T) {
	ad := func(code int, data string) error {
		return ldap.NewError(uint16(code), errors.New("80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, data "+data+", v4563"))
	}
	withControl := func(e int8) *ldap.SimpleBindResult {
		c := ldap.NewControlBeheraPasswordPolicy()
		c.Error = e
		return &ldap.SimpleBindResult{Controls: []ldap.Control{c}}
	}
	for _, tc := range []struct {
		name string
		res  *ldap.SimpleBindResult
		err  error
		want l67Raw
	}{
		{"success, no control", &ldap.SimpleBindResult{}, nil, l67Raw{Result: 0, Control: "absent"}},
		{"AD wrong password", &ldap.SimpleBindResult{}, ad(49, "52e"), l67Raw{Result: 49, Data: "52e", Control: "absent"}},
		{"AD data outside any allow-list", &ldap.SimpleBindResult{}, ad(49, "9ab"), l67Raw{Result: 49, Data: "9ab", Control: "absent"}},
		{"ppolicy locked", withControl(1), ldap.NewError(49, errors.New("Account locked")), l67Raw{Result: 49, Control: "error_1"}},
		{"ppolicy present, no error", withControl(-1), nil, l67Raw{Result: 0, Control: "present_no_error"}},
		{"must change, success with the control", withControl(2), nil, l67Raw{Result: 0, Control: "error_2"}},
	} {
		if got := l67RawOf(tc.res, tc.err); got != tc.want {
			t.Errorf("%s: %+v, want %+v", tc.name, got, tc.want)
		}
	}
}

// The leak check sees a TOTP secret in any of its forms, and a code only as a
// whole number (a 6-digit run inside a timestamp is not a leak).
func TestL67SecretsLeakChecks(t *testing.T) {
	var s l67Secrets
	secret := []byte("12345678901234567890")
	s.addSecret(secret)
	s.addCode("493821")
	b32 := l67Base32(secret)
	for _, tc := range []struct {
		name, text string
		leaks      bool
	}{
		{"the secret", "key " + b32 + " end", true},
		{"the secret in lower case", strings.ToLower(b32), true},
		{"the secret grouped", b32[:4] + " " + b32[4:8] + " " + b32[8:12] + " " + b32[12:16] + " " + b32[16:20] + " " + b32[20:24] + " " + b32[24:28] + " " + b32[28:32], true},
		{"the code", `{"data":"493821"}`, true},
		{"the code in a timestamp", "2026-10-15T20261015493821x", false},
		{"the code inside a longer number", "1493821", false},
		{"nothing", "a refused bind, result 49", false},
	} {
		if got := s.leaksIn(tc.text); got != tc.leaks {
			t.Errorf("%s: leaksIn = %v, want %v", tc.name, got, tc.leaks)
		}
	}
}

// A lab CLI's home names the file key store, so port49 never probes the
// machine's TPM: the file is the user's own config, private, and it loads.
func TestPinFileKeyStore(t *testing.T) {
	home := t.TempDir()
	if err := os.Chmod(home, 0o700); err != nil { // os.MkdirTemp's mode, as the lab's homes are made
		t.Fatal(err)
	}
	if err := pinFileKeyStore(home); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(home, ".port49")
	for p, want := range map[string]os.FileMode{dir: 0o700, filepath.Join(dir, "config.yaml"): 0o600} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != want {
			t.Errorf("%s is %v, want %v", p, fi.Mode().Perm(), want)
		}
	}
	f, ok, err := userconfig.Load(filepath.Join(dir, "config.yaml"))
	if err != nil || !ok || f.IssuedKeyStore != "file" {
		t.Fatalf("the config loads as %+v, %v, %v; want issued_key_store file", f, ok, err)
	}
}

// A login's screen that says it found no TPM means the key store was left to
// auto, which probes the real device.
func TestL67ProbedTheTPM(t *testing.T) {
	if !l67ProbedTheTPM("port49 login: no TPM this user can use (port49 cannot open the TPM (/dev/tpmrm0))") {
		t.Error("the TPM line is not seen")
	}
	if l67ProbedTheTPM("password: code from your authenticator (empty if you have none yet):") {
		t.Error("a screen with no TPM line is read as a probe")
	}
}

// The compose stack's broker, as l67Files makes it, loads with directory_password
// as its only human verifier: no client_ca_file, no certificate_status.
func TestL67ComposeBrokerLoads(t *testing.T) {
	read := func(name string) string {
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	files, err := composeLabFiles(read("port49d-lab.yaml"), read(filepath.Join("slice", "broker.yaml")),
		read(filepath.Join("slice", "policy.yaml")), read("inventory-lab.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := l67Files(files); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	t.Setenv("PORT49_LAB_KEY", "labsecret")
	t.Setenv("PORT49_LAB_ENC_KEY", labEncKeyDefault)
	for _, d := range []string{"etc/etcd", "etc/broker", "directory", "run", "state", "spool"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{"etc/etcd/ca.pem", "etc/etcd/port49d.pem", "etc/etcd/port49d-key.pem", "etc/etcd/port49-broker.pem",
		"etc/etcd/port49-broker-key.pem", "etc/broker/broker.pem", "etc/broker/broker-key.pem", "etc/broker/broker-ca.pem",
		"directory/users-ca.pem", "directory/directory-ca.pem", "directory/directory-client.pem",
		"directory/directory-client-key.pem"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	moved := func(s string) string {
		s = strings.ReplaceAll(s, e2eDirDir, filepath.Join(dir, "directory"))
		s = strings.ReplaceAll(s, "/etc/port49", filepath.Join(dir, "etc"))
		s = strings.ReplaceAll(s, "/var/lib/port49-broker", filepath.Join(dir, "state"))
		s = strings.ReplaceAll(s, "/var/spool/port49d", filepath.Join(dir, "spool"))
		return strings.ReplaceAll(s, "/run/port49", filepath.Join(dir, "run"))
	}
	for name, body := range files {
		if strings.HasSuffix(name, ".yaml") {
			if err := os.WriteFile(filepath.Join(dir, "etc", name), []byte(moved(body)), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	b, err := config.LoadBroker(filepath.Join(dir, "etc", "port49-broker.yaml"))
	if err != nil {
		t.Fatalf("the compose broker's config does not load: %v\n%s", err, moved(files["port49-broker.yaml"]))
	}
	if b.Broker.ClientCAFile != "" || b.Broker.Identity == nil || b.Broker.Identity.PasswordSignIn == nil || b.Broker.Identity.Issuance == nil {
		t.Fatalf("the compose broker: client_ca_file %q, identity %+v", b.Broker.ClientCAFile, b.Broker.Identity)
	}
}

// The configuration the harness's broker starts on loads: a key it misspells
// is a start that fails at 3am of Task 14, not here.
func TestL67BrokerConfigLoads(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PORT49_LAB_KEY", labKeyDefault)
	t.Setenv("PORT49_LAB_ENC_KEY", labEncKeyDefault)
	t.Setenv("LAB_DIRECTORY_BIND_PASSWORD", "unit-test-bind-password")
	for name, d := range map[string]*labDir{"openldap": l67TestDir(t, platOpenLDAP), "samba": l67TestDir(t, platSamba)} {
		for _, window := range []time.Duration{0, 2 * time.Minute} {
			sub := filepath.Join(dir, fmt.Sprintf("%s-%v", name, window))
			if err := os.MkdirAll(sub, 0o700); err != nil {
				t.Fatal(err)
			}
			files := l67BrokerFiles(sub, filepath.Join(sub, "pki"), d, l67BrokerOpts{Window: window})
			for fname, body := range files {
				if err := os.WriteFile(filepath.Join(sub, fname), []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			cfg, err := config.Load(filepath.Join(sub, "port49d.yaml"))
			if err != nil {
				t.Fatalf("%s window %v: %v\n%s", name, window, err, files["port49d.yaml"])
			}
			// The one x509 verifier is the on-call's, who unlocks by certificate.
			if want := filepath.Join(sub, "pki", testpki.LabCA); cfg.Broker.ClientCAFile != want {
				t.Fatalf("%s: the x509 anchor is %q, want the lab CA %q", name, cfg.Broker.ClientCAFile, want)
			}
			if m := cfg.Broker.Identity.PerLoginMFA; m == nil || m.AttestationRootsFile != filepath.Join(sub, adminRolesFile) {
				t.Fatalf("%s: per_login_mfa is %+v; the broker must read the run's attestation roots", name, m)
			}
			ps := cfg.Broker.Identity.PasswordSignIn
			if ps == nil || len(ps.PrincipalDomains) != 1 || ps.PrincipalDomains[0] != "corp.example.com" {
				t.Fatalf("%s: the directory_password verifier is %+v", name, ps)
			}
			wantWindow := window
			if wantWindow == 0 {
				wantWindow = oidc.DefaultSignInWindow
			}
			if ps.Window != wantWindow || ps.FailuresPerPrincipal != oidc.DefaultFailuresPerPrincipal {
				t.Fatalf("%s: window %v, per-principal %d; want %v and the default %d", name, ps.Window, ps.FailuresPerPrincipal,
					wantWindow, oidc.DefaultFailuresPerPrincipal)
			}
		}
	}
}

// The etcd half waits for the broker's start mint gate (decision 36) before its
// first mint. The wait matches the line that says the gate opened, and not the
// line that says mints wait.
func TestL67MintsOpenMatchesOnlyTheOpenLine(t *testing.T) {
	wait := "port49-broker: policy: mints wait for a takeover to judge bundle sha256:ab (meta/judged: none recorded): until this replica's runner or another's is done, POST /v1/token answers 503 store_unavailable"
	open := "port49-broker: policy: mints open: this replica's takeover is done"
	if l67MintsOpen("port49-broker: listening on [::]:8443\n" + wait + "\n") {
		t.Errorf("the mints-wait line was read as the gate being open")
	}
	if !l67MintsOpen("port49-broker: listening on [::]:8443\n" + wait + "\n" + open + "\n") {
		t.Errorf("the mints-open line was not found")
	}
	if l67MintsOpen("") {
		t.Errorf("empty logs were read as the gate being open")
	}
}

// The wait polls until the marker shows, reports how long it took, and gives up
// at the limit with the last logs so the INVALID names what the broker said.
func TestL67WaitForMintsOpen(t *testing.T) {
	calls := 0
	read := func() (string, error) {
		calls++
		if calls >= 3 {
			return "policy: mints open: this replica's takeover is done\n", nil
		}
		return "policy: mints wait for a takeover\n", nil
	}
	took, err := l67WaitForMintsOpen(read, time.Second, time.Millisecond)
	if err != nil || calls != 3 {
		t.Fatalf("took %v, err %v after %d reads, want the gate seen on the 3rd read", took, err, calls)
	}
	if took <= 0 {
		t.Errorf("the wait reported %v, want a measured duration", took)
	}

	never := func() (string, error) { return "runner: waiting for the keyspace\n", nil }
	_, err = l67WaitForMintsOpen(never, 20*time.Millisecond, time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "runner: waiting for the keyspace") {
		t.Errorf("a gate that never opens gave err %v, want one naming the broker's last log", err)
	}

	// A log that cannot be read is a fault, not "still closed": it surfaces at the limit.
	broken := func() (string, error) { return "", errors.New("compose logs failed") }
	_, err = l67WaitForMintsOpen(broken, 20*time.Millisecond, time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "compose logs failed") {
		t.Errorf("an unreadable log gave err %v, want one naming the read failure", err)
	}
}

// The OpenLDAP note says L67 ran with ssf=56 and the ppolicy overlay, not the
// 7g note's tls=1 alone (N1); the other directories' notes do not.
func TestL67NoteSaysHowOpenLDAPWasConfigured(t *testing.T) {
	x := &l67X{dir: &labDir{name: platOpenLDAP}, ev: &evidenceLog{}}
	n := x.note()
	for _, want := range []string{"ssf=56", "ppolicy", "olcPPolicyUseLockout TRUE"} {
		if !strings.Contains(n, want) {
			t.Errorf("the OpenLDAP note does not say %q:\n%s", want, n)
		}
	}
	y := &l67X{dir: &labDir{name: platSamba}, ev: &evidenceLog{}}
	if strings.Contains(y.note(), "ssf=56") {
		t.Errorf("the Samba note names OpenLDAP's ssf")
	}
}

// A cell that needs a person an INVALID or skipped cell should have enrolled says so, instead of
// dereferencing nil and killing the binary with every later cell unreported.
func TestL67APersonNoCellEnrolledIsAnInvalidNotAPanic(t *testing.T) {
	x := &l67X{}
	if p, err := x.person("carol"); p != nil || err == nil ||
		!strings.Contains(err.Error(), "carol was not enrolled (an earlier cell did not complete)") {
		t.Fatalf("a person nobody enrolled: %v %v", p, err)
	}
	x.people = map[string]*l67Person{"carol": {name: "carol"}}
	if p, err := x.person("carol"); err != nil || p == nil || p.name != "carol" {
		t.Fatalf("an enrolled person: %v %v", p, err)
	}
	if _, err := x.person("dave"); err == nil {
		t.Fatal("a person nobody enrolled was found")
	}
}

// A failure line quotes where the raw text is kept, never the text, and the file is the user's alone.
func TestL67KeptWritesThePrivateFileAndQuotesOnlyItsPath(t *testing.T) {
	raw := "a line the log must never carry: " + labKeyDefault
	path := l67Kept("unit", raw)
	t.Cleanup(func() { os.Remove(path) })
	if strings.Contains(path, raw) || strings.Contains(path, labKeyDefault) {
		t.Fatalf("the quoted path carries the text: %q", path)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v, want 0600", fi.Mode().Perm())
	}
	if got, _ := os.ReadFile(path); string(got) != raw {
		t.Errorf("the file does not hold the text")
	}
}
