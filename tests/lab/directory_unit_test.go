//go:build lab

package lab

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/rhwendt/port49/internal/directory"
)

// docker's arguments reach `sg docker -c` as one string: each is quoted, so
// a space or a quote in one is never read by the shell.
func TestDirectoryDockerArgsAreQuoted(t *testing.T) {
	got := dockerArgs("compose", "exec", "a b", "it's")
	if want := `docker 'compose' 'exec' 'a b' 'it'\''s'`; got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestDirectoryParseObjectSID(t *testing.T) {
	out := "dn: CN=alice,OU=Staff,DC=corp,DC=example,DC=com\nobjectSid: S-1-5-21-111-222-333-1105\n\n"
	if got := parseObjectSID(out); got != "S-1-5-21-111-222-333-1105" {
		t.Fatalf("got %q", got)
	}
	for _, none := range []string{"", "objectSid: not a sid", "xobjectSid: S-1-5-21-1-2-3-4"} {
		if got := parseObjectSID(none); got != "" {
			t.Errorf("%q gave %q", none, got)
		}
	}
}

// The krb5.conf the lab writes points the realm at the published KDC, over
// TCP, and maps the URI's host to the realm.
func TestDirectoryKrb5ConfNamesTheKDC(t *testing.T) {
	c := krb5Conf(dirKDC)
	for _, want := range []string{"default_realm = CORP.EXAMPLE.COM", "kdc = 127.0.0.1:20088", "udp_preference_limit = 1",
		"localhost = CORP.EXAMPLE.COM"} {
		if !strings.Contains(c, want) {
			t.Errorf("krb5.conf lacks %q", want)
		}
	}
}

// Every LAB_* variable a container's script reads is one lab.env writes, and
// the env file holds names and values the scripts expect.
func TestDirectoryEnvCoversWhatTheScriptsRead(t *testing.T) {
	env := labEnv("Aa1!pw", "X509:<I>x<SR>1", 1000, 1000)
	for _, f := range []string{"openldap/entrypoint.sh", "samba/entrypoint.sh", "samba/seed.sh"} {
		b, err := os.ReadFile(filepath.Join("directory", f))
		if err != nil {
			t.Fatal(err)
		}
		for _, v := range regexp.MustCompile(`\$\{?(LAB_[A-Z0-9_]+)`).FindAllStringSubmatch(string(b), -1) {
			if !strings.Contains(env, v[1]+"=") {
				t.Errorf("%s reads %s, which lab.env does not set", f, v[1])
			}
		}
	}
	if !strings.Contains(env, "LAB_UID=1000\n") || !strings.Contains(env, "LAB_PORT49_PASSWORD=Aa1!pw\n") {
		t.Errorf("lab.env: %q", strings.ReplaceAll(env, "Aa1!pw", "<pw>"))
	}
}

// The PKI the lab writes is the shape the claim needs: the users CA's DER
// carries DC= RDNs, so issuer_serial and the issuer pin meet them; the
// broker's certificate loads as the broker's own, with the subject slapd's
// authz-regexp matches; a SID extension reads back as the SID it was given.
func TestDirectoryPKIShape(t *testing.T) {
	dir := t.TempDir()
	p, err := writeDirectoryPKI(dir, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if got := directory.ADIssuerSerial(p.alice); !strings.HasPrefix(got, "X509:<I>DC=com,DC=example,DC=corp,CN=lab-users-CA<SR>") {
		t.Errorf("issuer_serial form: %s", got)
	}
	m := directory.Mapping{Kind: directory.MapSANEmail, Attribute: "mail", AllowWeak: true, Issuers: []string{dirUsersCAIssuer}}
	if l, err := m.Lookup(p.alice, "(objectClass=person)"); err != nil || !strings.Contains(l.Filter, "alice@corp.example.com") {
		t.Errorf("the pin on the users CA's DC= issuer: %+v %v", l, err)
	}
	cr, err := directory.LoadCredentials(directory.Bind{Mechanism: "external", TLSCertFile: p.brokerCert, TLSKeyFile: p.brokerKey}, nil)
	if err != nil {
		t.Fatalf("the broker's certificate and key do not load as port49 loads them: %v", err)
	}
	if got := cr.Who(); got != "CN=port49-broker,O=port49 lab" {
		t.Errorf("broker subject %q", got)
	}
	cert, _, err := p.personCert("alice", "alice@corp.example.com", "S-1-5-21-1-2-3-1105", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if sid, err := directory.SIDOf(cert); err != nil || sid != "S-1-5-21-1-2-3-1105" {
		t.Errorf("SID extension reads back %q, %v", sid, err)
	}
	fi, err := os.Stat(p.brokerKey)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("broker key mode: %v %v", fi, err)
	}
}

// The evidence is one snake_case JSON object per line, and holds what was
// asked and what came back.
func TestDirectoryEvidenceLines(t *testing.T) {
	f, err := os.Create(filepath.Join(t.TempDir(), "x.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	e := &evidenceLog{f: f, Path: f.Name()}
	code := 0
	e.add(evidenceLine{Event: "search", Base: "dc=corp", Scope: scopeName(ldap.ScopeWholeSubtree), Filter: "(uid=alice)",
		DNs: []string{"uid=alice,ou=Staff,dc=corp"}, ResultCode: &code, DurationMS: 1.5})
	e.mark("L42 alice %s", "in_chain")
	b, _ := os.ReadFile(e.Path)
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 2 {
		t.Fatalf("%d lines: %s", len(lines), b)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"event", "base", "scope", "filter", "dns", "result_code", "duration_ms"} {
		if _, ok := m[k]; !ok {
			t.Errorf("evidence line lacks %q: %s", k, lines[0])
		}
	}
	if m["scope"] != "sub" {
		t.Errorf("scope %v", m["scope"])
	}
}

func TestDirectoryLDAPCode(t *testing.T) {
	if got := ldapCode(&ldap.Error{ResultCode: 49}); got != 49 {
		t.Errorf("49: %d", got)
	}
	if got := ldapCode(nil); got != 0 {
		t.Errorf("nil: %d", got)
	}
	if got := ldapCode(os.ErrClosed); got != -1 {
		t.Errorf("non-LDAP: %d", got)
	}
}
