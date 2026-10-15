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
	"github.com/rhwendt/port49/internal/totp"
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
func l67TestDir(name string) *labDir {
	ca := filepath.Join(os.TempDir(), "l67-unit-ca.pem")
	_ = os.WriteFile(ca, []byte("-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n"), 0o600)
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

// The configuration the harness's broker starts on loads: a key it misspells
// is a start that fails at 3am of Task 14, not here.
func TestL67BrokerConfigLoads(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PORT49_LAB_KEY", labKeyDefault)
	t.Setenv("PORT49_LAB_ENC_KEY", labEncKeyDefault)
	t.Setenv("LAB_DIRECTORY_BIND_PASSWORD", "unit-test-bind-password")
	for name, d := range map[string]*labDir{"openldap": l67TestDir(platOpenLDAP), "samba": l67TestDir(platSamba)} {
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
