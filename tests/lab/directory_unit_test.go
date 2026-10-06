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
			// the end-to-end overlay's, not lab.env's (TestDirectoryE2EOverlayNamesWhatTheTestWrites)
			if v[1] != "LAB_OPENLDAP_WRITER" && !strings.Contains(env, v[1]+"=") {
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
	if p.ca == nil || !p.ca.Cert.IsCA {
		t.Fatal("dirPKI keeps no CA")
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

// The run line names the selection the note came from, so an L44 note never
// claims L42's command.
func TestDirectoryRunLineNamesTheSelection(t *testing.T) {
	if got := dirRunLine("TestL44"); !strings.Contains(got, "-run 'TestL44'") {
		t.Fatalf("%s", got)
	}
}

// The containers' notes keep the lines they were written with: the refactor
// for a third platform changes nothing a committed L42 or L43 note says.
func TestDirectoryNoteKeepsTheContainersLines(t *testing.T) {
	out := t.TempDir()
	d := &directories{out: out, password: "Aa1!pw", runSel: "TestL42|TestL43"}
	l := &labDir{name: platSamba, where: containerWhere, d: d}
	writeResult(t, d, "L42", l, "claim", "v", "obs", "tests/lab/evidence/x.json")
	b, err := os.ReadFile(filepath.Join(out, "tests", "lab", "results", "L42-samba_ad.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"- **Platform:** samba_ad, as a container on `tests/lab/directory/compose.yaml` (no network device)\n",
		"- **Credentials:** none appear here or in the evidence. The bind password is generated for each run and never printed; the keytab and every ticket stay on the host that ran it.\n",
		"-run 'TestL42|TestL43'",
	} {
		if !strings.Contains(string(b), want) {
			t.Errorf("note lacks %q", want)
		}
	}
}

// A note naming any of the run's secrets is refused, whichever secret it is.
func TestDirectoryNoteHoldsSecret(t *testing.T) {
	if !noteHoldsSecret("x Aa1!b y", "", "Aa1!b") || noteHoldsSecret("clean", "Aa1!b", "") {
		t.Fatal("noteHoldsSecret")
	}
}

// objectSid's binary form reads back as the SID string AD prints.
func TestDirectoryLabSIDString(t *testing.T) {
	b := []byte{1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 111, 0, 0, 0, 222, 0, 0, 0, 77, 1, 0, 0, 81, 4, 0, 0}
	if got, err := labSIDString(b); err != nil || got != "S-1-5-21-111-222-333-1105" {
		t.Fatalf("%q %v", got, err)
	}
	if _, err := labSIDString([]byte{1, 2, 0}); err == nil {
		t.Fatal("a short objectSid read as a SID")
	}
	if _, err := labSIDString([]byte{2, 1, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0}); err == nil {
		t.Fatal("revision 2 read as a SID")
	}
	if _, err := labSIDString(append(append([]byte{}, b...), 0)); err == nil {
		t.Fatal("an objectSid with a trailing byte read as a SID")
	}
}

// A platform's own Platform, Credentials and Run lines reach the note, and a
// secret of the run's extra set in the observation is caught.
func TestDirectoryNoteTakesThePlatformsLinesAndRefusesExtraSecrets(t *testing.T) {
	d := &directories{password: "Aa1!pw", runSel: "TestL44", extra: []string{"dc-secret-1"}}
	l := &labDir{name: "x", where: "W", credentials: "C", d: d}
	note, held := noteText(d, "L44", l, "claim", "v", "obs", "e.json")
	if held {
		t.Fatal("a clean note read as holding a secret")
	}
	for _, want := range []string{"- **Platform:** x, W\n", "- **Credentials:** C\n", "-run 'TestL44'"} {
		if !strings.Contains(note, want) {
			t.Errorf("note lacks %q", want)
		}
	}
	for _, secret := range []string{"Aa1!pw", "dc-secret-1"} {
		if _, held := noteText(d, "L44", l, "claim", "v", "saw "+secret, "e.json"); !held {
			t.Errorf("a note holding %q was not caught", secret)
		}
	}
}
