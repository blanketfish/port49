//go:build lab

package lab

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode"

	"github.com/go-ldap/ldap/v3"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/directory"
	"github.com/rhwendt/port49/internal/store/memory"
	"github.com/rhwendt/port49/internal/testpki"
	"github.com/rhwendt/port49/tests/lab/labcreds"
)

// The directory lab (plan 7g, Task 17): OpenLDAP and Samba AD as containers on
// their own compose project, no network devices. L42 and L43 run on it. What
// it measures is each directory's answer to port49's own queries and binds,
// made through internal/directory exactly as the broker makes them.
//
// Files are under tests/lab/logs/directory (git-ignored): pki/ (the CA, the
// directories' server certificate, the broker's certificate), out/ (the
// keytab Samba exports and the krb5.conf the test writes), lab.env (the
// passwords the containers read, mode 0600) and one log per service.
const (
	dirProject = "port49labdir"
	dirBase    = "DC=corp,DC=example,DC=com"
	dirRealm   = "CORP.EXAMPLE.COM"

	// dirUsersCAIssuer is the users CA's subject as an RFC 4514 string: the
	// pin a weak mapping names. Its DER carries the DC= RDNs, as AD CS's does.
	dirUsersCAIssuer = "CN=lab-users-CA,DC=corp,DC=example,DC=com"

	dirKDC = "127.0.0.1:20088"
)

// Platform names, as the notes' file names carry them.
const (
	platOpenLDAP = "openldap"
	platSamba    = "samba_ad"
)

// containerWhere is the Platform line of the two containers' notes.
const containerWhere = "as a container on `tests/lab/directory/compose.yaml` (no network device)"

// labDir is one directory in the lab and the shape its entries take.
type labDir struct {
	name, service string
	uri, plainURI string
	startTLS      bool // uri is an ldap:// server that is upgraded with StartTLS
	bindDN        string
	userFilter    string
	groupFilter   string
	usernameAttr  string
	baseDN        string
	groupsBaseDN  string // OU=G: where the fixture's groups live and one name each is unique
	image         string
	d             *directories

	where       string // the note's Platform line after the name: what ran, and on what
	credentials string // the note's Credentials line; "" is the containers' line
	keytabFile  string // the broker's keytab for GSSAPI
	krb5File    string // the client krb5.conf naming the platform's KDC
	loopRefused string // the directory's refusal to make L42's loop, when it refused
	win         *winDC // the Windows DC's runner (L44); nil for the containers
}

// directories is the running pair and what the run wrote for them.
type directories struct {
	dir      string // tests/lab/logs/directory
	compose  string // tests/lab/directory/compose.yaml
	out      string // the root notes and evidence are written under
	pki      *dirPKI
	password string // port49's bind password in both; generated for this run
	mu       sync.Mutex
	said     []string
	runSel   string   // the -run selection the notes name (dirRunLine)
	extra    []string // other secrets a note or the evidence must never hold (the Windows DC's)
	openldap *labDir
	samba    *labDir
}

func (d *directories) all() []*labDir { return []*labDir{d.openldap, d.samba} }

// dirPKI is the lab's certificates: the CA that issues the directories' server
// certificate and the broker's, and the users CA, whose subject has DC= RDNs,
// that issues the people's.
type dirPKI struct {
	dir                   string
	ca                    *testpki.CA // the lab CA: it signs the directories' server certificates
	caFile                string
	brokerCert, brokerKey string
	usersCA               *x509.Certificate
	usersKey              *ecdsa.PrivateKey
	alice, eve            *x509.Certificate
	aliceKey, eveKey      *ecdsa.PrivateKey
}

// directoryOut is the root the notes and evidence are written under: the
// repository's, or PORT49_LAB_DIRECTORY_OUT, so a dry run of the harness
// writes nothing a commit could pick up.
func directoryOut() (string, error) {
	if o := os.Getenv("PORT49_LAB_DIRECTORY_OUT"); o != "" {
		return filepath.Abs(o)
	}
	return repoRoot()
}

// newDirectories writes the run's PKI, bind password, lab.env and krb5.conf
// under a fresh tests/lab/logs/directory and describes the two containers,
// starting nothing: L44 builds its DC on the same PKI and password.
func newDirectories(t *testing.T) *directories {
	t.Helper()
	repo, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	out, err := directoryOut()
	if err != nil {
		t.Fatal(err)
	}
	d := &directories{dir: filepath.Join(repo, "tests", "lab", "logs", "directory"),
		compose: filepath.Join(repo, "tests", "lab", "directory", "compose.yaml"), out: out, runSel: "TestL42|TestL43"}
	// A fresh tree each run: keys are 0600 and written fresh, and a keytab
	// or an env file from an earlier run never serves this one.
	if err := os.RemoveAll(d.dir); err != nil {
		t.Fatal(err)
	}
	for _, sub := range []string{"pki", "out"} {
		if err := os.MkdirAll(filepath.Join(d.dir, sub), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if d.pki, err = writeDirectoryPKI(filepath.Join(d.dir, "pki"), time.Now()); err != nil {
		t.Fatalf("the directory lab's PKI: %v", err)
	}
	pw := make([]byte, 16)
	if _, err := rand.Read(pw); err != nil {
		t.Fatal(err)
	}
	// "Aa1!" first: Samba's complexity rule wants all four classes.
	d.password = "Aa1!" + hex.EncodeToString(pw)
	if err := os.WriteFile(filepath.Join(d.dir, "lab.env"),
		[]byte(labEnv(d.password, directory.ADIssuerSerial(d.pki.alice), os.Getuid(), os.Getgid())), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d.dir, "out", "krb5.conf"), []byte(krb5Conf(dirKDC)), 0o600); err != nil {
		t.Fatal(err)
	}
	d.openldap = &labDir{name: platOpenLDAP, service: "openldap", uri: "ldaps://localhost:10636",
		plainURI: "ldap://localhost:10389", bindDN: "cn=port49,ou=Svc," + strings.ToLower(dirBase),
		userFilter: "(objectClass=inetOrgPerson)", groupFilter: "(objectClass=groupOfNames)", usernameAttr: "uid",
		baseDN: strings.ToLower(dirBase), groupsBaseDN: "ou=G," + strings.ToLower(dirBase),
		image: "port49lab/openldap:bookworm", d: d, where: containerWhere,
		keytabFile: filepath.Join(d.dir, "out", "port49.keytab"), krb5File: filepath.Join(d.dir, "out", "krb5.conf")}
	d.samba = &labDir{name: platSamba, service: "samba", uri: "ldaps://localhost:20636",
		plainURI: "ldap://localhost:20389", bindDN: "CN=port49,OU=Svc," + dirBase,
		userFilter: "(&(objectCategory=person)(objectClass=user))", groupFilter: "(objectClass=group)",
		usernameAttr: "sAMAccountName", baseDN: dirBase, groupsBaseDN: "OU=G," + dirBase,
		image: "port49lab/samba:bookworm", d: d, where: containerWhere,
		keytabFile: filepath.Join(d.dir, "out", "port49.keytab"), krb5File: filepath.Join(d.dir, "out", "krb5.conf")}
	return d
}

// startDirectories writes the PKI, brings both directories up, waits for the
// fixture and for each LDAPS port, and registers the cleanup that keeps the
// logs and takes both down. A precondition that fails here is the harness's
// fault, not a measurement.
func startDirectories(t *testing.T) *directories {
	t.Helper()
	d := newDirectories(t)
	if os.Getenv("PORT49_LAB_DIRECTORY_KEEP") == "" {
		t.Cleanup(func() { d.down(t) })
	}
	// Whatever an earlier run (or a KEEP) left: a directory's volumes hold
	// its database, the old password and the old certificate mapping.
	_ = d.dockerCompose("down", "-v", "--remove-orphans", "-t", "5").Run()
	cmd := d.dockerCompose("up", "-d", "--build")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("docker compose up: %v\n%s", err, tailOf(string(b), 3000))
	}
	for _, dir := range d.all() {
		d.waitFixture(t, dir, 3*time.Minute)
	}
	for _, dir := range d.all() {
		dir.checkFixture(t)
	}
	return d
}

// labEnv is lab.env: the passwords the two containers read, port49's
// certificate-mapping value for alice, and the uid the keytab is chowned to.
// The directory's administrators' password is another random one: the lab
// never uses it.
func labEnv(password, aliceAltSecID string, uid, gid int) string {
	admin := make([]byte, 12)
	_, _ = rand.Read(admin)
	return fmt.Sprintf("LAB_LDAP_PASSWORD=%s\nLAB_PORT49_PASSWORD=%s\nLAB_ADMIN_PASSWORD=Aa1!%s\nLAB_ALICE_ALTSECID=%s\nLAB_UID=%d\nLAB_GID=%d\n",
		password, password, hex.EncodeToString(admin), aliceAltSecID, uid, gid)
}

// krb5Conf is the client's Kerberos configuration: CORP.EXAMPLE.COM's KDC at
// the address the compose project publishes it on, TCP only, and localhost
// mapped to the realm because the lab's URIs name localhost.
func krb5Conf(kdc string) string {
	return fmt.Sprintf(`[libdefaults]
  default_realm = %[1]s
  dns_lookup_kdc = false
  dns_lookup_realm = false
  udp_preference_limit = 1
  default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
  default_tgs_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96

[realms]
  %[1]s = {
    kdc = %[2]s
  }

[domain_realm]
  localhost = %[1]s
  .corp.example.com = %[1]s
`, dirRealm, kdc)
}

// dockerArgs is the command line `sg docker -c` runs for docker's args: each
// one single-quoted, so no argument is read by the shell.
func dockerArgs(args ...string) string {
	q := make([]string, len(args))
	for i, a := range args {
		q[i] = shellQuote(a)
	}
	return "docker " + strings.Join(q, " ")
}

// dockerCmd is `docker args...` under `sg docker`, for a shell that is not
// in the docker group.
func dockerCmd(args ...string) *exec.Cmd {
	return exec.Command("sg", "docker", "-c", dockerArgs(args...))
}

func (d *directories) dockerCompose(args ...string) *exec.Cmd {
	return dockerCmd(append([]string{"compose", "-p", dirProject, "-f", d.compose}, args...)...)
}

// exec runs argv in dir's container and returns its combined output.
func (l *labDir) exec(argv ...string) (string, error) {
	b, err := l.d.dockerCompose(append([]string{"exec", "-T", l.service}, argv...)...).CombinedOutput()
	return string(b), err
}

func tailOf(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "..." + s[len(s)-n:]
}

// down keeps each service's log and takes the project down, volumes included.
func (d *directories) down(t *testing.T) {
	t.Helper()
	for _, dir := range d.all() {
		if b, err := d.dockerCompose("logs", "--no-color", dir.service).CombinedOutput(); err == nil {
			_ = os.WriteFile(filepath.Join(d.dir, dir.service+".log"), b, 0o600)
		}
	}
	if b, err := d.dockerCompose("down", "-v", "--remove-orphans", "-t", "5").CombinedOutput(); err != nil {
		t.Errorf("docker compose down: %v\n%s", err, tailOf(string(b), 2000))
	}
}

// waitFixture waits for the container to say its fixture is loaded, and then
// for its LDAPS port to answer a root DSE read.
func (d *directories) waitFixture(t *testing.T, dir *labDir, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	marker := "lab: " + map[string]string{platOpenLDAP: "openldap", platSamba: "samba"}[dir.name] + " fixture loaded"
	for {
		b, _ := d.dockerCompose("logs", "--no-color", dir.service).CombinedOutput()
		if strings.Contains(string(b), marker) {
			break
		}
		if up, _ := d.dockerCompose("ps", "--status", "running", "-q", dir.service).Output(); strings.TrimSpace(string(up)) == "" {
			t.Fatalf("%s: the container is not running; last log:\n%s", dir.name, tailOf(string(b), 2500))
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: no %q within %s; last log:\n%s", dir.name, marker, within, tailOf(string(b), 2500))
		}
		time.Sleep(2 * time.Second)
	}
	for {
		err := d.rootDSE(dir)
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: LDAPS never answered a root DSE read within %s: %v", dir.name, within, err)
		}
		time.Sleep(2 * time.Second)
	}
}

// rootDSE reads the root DSE of dir over LDAPS, anonymously, verifying the
// server's certificate against the lab CA.
func (d *directories) rootDSE(dir *labDir) error {
	tc, err := d.pki.clientTLS(dir.uri)
	if err != nil {
		return err
	}
	c, err := ldap.DialURL(dir.uri, ldap.DialWithTLSConfig(tc), ldap.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}))
	if err != nil {
		return err
	}
	defer c.Close()
	c.SetTimeout(10 * time.Second)
	_, err = c.Search(ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 5, false,
		"(objectClass=*)", []string{"supportedLDAPVersion"}, nil))
	return err
}

func (p *dirPKI) clientTLS(uri string) (*tls.Config, error) {
	pem, err := os.ReadFile(p.caFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	host, _, _ := net.SplitHostPort(strings.TrimPrefix(strings.TrimPrefix(uri, "ldaps://"), "ldap://"))
	return &tls.Config{RootCAs: pool, ServerName: host, MinVersion: tls.VersionTLS12}, nil
}

// checkFixture is the harness's precondition, never a measurement: the
// broker's simple bind works and the fixture's people and groups are there.
func (l *labDir) checkFixture(t *testing.T) {
	t.Helper()
	r := l.resolver(t, "direct")
	count := func(filter string) int {
		n := 0
		_, err := r.Pool.Do(context.Background(), func(s directory.Searcher) error {
			res, err := s.SearchWithPaging(ldap.NewSearchRequest(l.baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
				0, 20, false, filter, []string{"1.1"}, nil), 100)
			if res != nil {
				n = len(res.Entries)
			}
			return err
		})
		if err != nil {
			t.Fatalf("%s fixture check %s: %v", l.name, filter, err)
		}
		return n
	}
	if got := count(l.userFilter); got < 6 {
		t.Fatalf("%s: the fixture holds %d people under %s, want at least alice, bob, carol, dave, eve and eve2", l.name, got, l.baseDN)
	}
	if got := count(fmt.Sprintf("(&%s(cn=netops-oncall))", l.groupFilter)); got != 2 {
		t.Fatalf("%s: the fixture holds %d groups named netops-oncall, want 2 (one under OU=G, one under OU=Users-Can-Create)", l.name, got)
	}
}

// dirIssue signs tmpl with parent and signer and returns the parsed
// certificate and its key.
func dirIssue(parent *x509.Certificate, signer *ecdsa.PrivateKey, tmpl *x509.Certificate) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, signer)
	if err != nil {
		return nil, nil, err
	}
	c, err := x509.ParseCertificate(der)
	return c, key, err
}

func dirSerial() *big.Int {
	// At least 40 bits, so the serial's byte reversal in altSecurityIdentities
	// is visible in the value.
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	return n.Add(n, new(big.Int).Lsh(big.NewInt(1), 40))
}

var (
	oidDirDC  = asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}
	oidDirCN  = asn1.ObjectIdentifier{2, 5, 4, 3}
	oidSIDExt = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 25, 2}
	oidSIDVal = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 25, 2, 1}
)

// usersCASubject is CN=lab-users-CA,DC=corp,DC=example,DC=com as DER, most
// significant RDN first, as AD CS writes it and Go's pkix.Name cannot.
func usersCASubject() ([]byte, error) {
	return asn1.Marshal(pkix.RDNSequence{
		{{Type: oidDirDC, Value: "com"}}, {{Type: oidDirDC, Value: "example"}}, {{Type: oidDirDC, Value: "corp"}},
		{{Type: oidDirCN, Value: "lab-users-CA"}}})
}

// sidExtension is szOID_NTDS_CA_SECURITY_EXT as AD CS writes it: a
// GeneralNames holding one otherName (1.3.6.1.4.1.311.25.2.1) whose value is
// the SID string as an OCTET STRING.
func sidExtension(sid string) (pkix.Extension, error) {
	inner, err := asn1.Marshal([]byte(sid))
	if err != nil {
		return pkix.Extension{}, err
	}
	other, err := asn1.Marshal(struct {
		ID    asn1.ObjectIdentifier
		Value asn1.RawValue
	}{oidSIDVal, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: inner}})
	if err != nil {
		return pkix.Extension{}, err
	}
	other[0] = 0xa0 // [0] IMPLICIT, constructed: the GeneralName otherName choice
	names, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: other})
	return pkix.Extension{Id: oidSIDExt, Value: names}, err
}

// personCert issues a client certificate for a person from the users CA.
func (p *dirPKI) personCert(cn, email, sid string, now time.Time) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	tmpl := &x509.Certificate{SerialNumber: dirSerial(), Subject: pkix.Name{CommonName: cn}, EmailAddresses: []string{email},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	if sid != "" {
		ext, err := sidExtension(sid)
		if err != nil {
			return nil, nil, err
		}
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, ext)
	}
	return dirIssue(p.usersCA, p.usersKey, tmpl)
}

// writeDirectoryPKI writes the lab CA, the directories' server certificate
// (localhost, the loopback address and the containers' names), the broker's
// client certificate (CN=port49-broker,O=port49 lab, which slapd's
// authz-regexp maps to port49's account) and the users CA with alice's and
// eve's certificates. Keys are 0600; everything lasts a day.
func writeDirectoryPKI(dir string, now time.Time) (*dirPKI, error) {
	nb, na := now.Add(-time.Hour), now.Add(24*time.Hour)
	ca, err := testpki.NewCA("port49 lab directory CA", nb, na)
	if err != nil {
		return nil, err
	}
	srv, err := ca.Issue(testpki.Leaf{CommonName: "port49 lab directory", NotBefore: nb, NotAfter: na,
		DNSNames: []string{"localhost", "openldap", "samba", "dc1", "dc1.corp.example.com"}, IPs: testpki.Loopback()})
	if err != nil {
		return nil, err
	}
	brokerTmpl := &x509.Certificate{SerialNumber: dirSerial(),
		Subject:   pkix.Name{CommonName: "port49-broker", Organization: []string{"port49 lab"}},
		NotBefore: nb, NotAfter: na, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	broker, brokerKey, err := dirIssue(ca.Cert, ca.Key, brokerTmpl)
	if err != nil {
		return nil, err
	}
	raw, err := usersCASubject()
	if err != nil {
		return nil, err
	}
	usersKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), RawSubject: raw, NotBefore: nb, NotAfter: na, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &usersKey.PublicKey, usersKey)
	if err != nil {
		return nil, err
	}
	usersCA, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	p := &dirPKI{dir: dir, ca: ca, caFile: filepath.Join(dir, "ca.pem"), brokerCert: filepath.Join(dir, "broker.pem"),
		brokerKey: filepath.Join(dir, "broker-key.pem"), usersCA: usersCA, usersKey: usersKey}
	if p.alice, p.aliceKey, err = p.personCert("alice", "alice@corp.example.com", "", now); err != nil {
		return nil, err
	}
	if p.eve, p.eveKey, err = p.personCert("eve", "eve@corp.example.com", "", now); err != nil {
		return nil, err
	}
	srvCert, srvKey, err := testpki.PEMs(srv)
	if err != nil {
		return nil, err
	}
	brokerPEM, brokerKeyPEM, err := testpki.PEMs(tls.Certificate{Certificate: [][]byte{broker.Raw}, PrivateKey: brokerKey})
	if err != nil {
		return nil, err
	}
	for name, body := range map[string][]byte{"ca.pem": ca.PEM(), "server.pem": srvCert, "server-key.pem": srvKey,
		"broker.pem": brokerPEM, "broker-key.pem": brokerKeyPEM} {
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
			return nil, err
		}
	}
	return p, nil
}

// objectSIDRe reads the SID `samba-tool user show --attributes=objectSid`
// prints.
var objectSIDRe = regexp.MustCompile(`(?m)^objectSid: (S-1-\d+(?:-\d+)+)\s*$`)

// parseObjectSID is the SID in samba-tool's output, "" when it holds none.
func parseObjectSID(out string) string {
	if m := objectSIDRe.FindStringSubmatch(out); m != nil {
		return m[1]
	}
	return ""
}

// aliceSID is alice's objectSid on Samba, read back from the DC.
func (l *labDir) aliceSID(t *testing.T) string {
	t.Helper()
	if l.name == platWindows {
		return l.ldapObjectSID(t, "(sAMAccountName=alice)")
	}
	out, err := l.exec("samba-tool", "user", "show", "alice", "--attributes=objectSid")
	if err != nil {
		t.Fatalf("reading alice's objectSid: %v\n%s", err, tailOf(out, 500))
	}
	sid := parseObjectSID(out)
	if sid == "" {
		t.Fatalf("no objectSid in samba-tool's answer: %q", tailOf(out, 500))
	}
	return sid
}

// ---------------------------------------------------------------------------
// Configuration, the broker's way: directory.Config, NewDialer, Pool, Resolver
// ---------------------------------------------------------------------------

// getenvOf is the lookup LoadCredentials reads a simple bind's password
// through: the run's generated password under the name the config gives.
func getenvOf(password string) func(string) string {
	return func(name string) string {
		if name == "LAB_DIRECTORY_BIND_PASSWORD" {
			return password
		}
		return ""
	}
}

// bindSimple is the broker's simple bind over LDAPS.
func (l *labDir) bindSimple() directory.Bind {
	return directory.Bind{Mechanism: "simple", BindDN: l.bindDN, PasswordEnv: "LAB_DIRECTORY_BIND_PASSWORD"}
}

// viaStartTLS is l as port49 reaches it over StartTLS on the plain LDAP port.
// [MS-ADTS] 5.1.1.2: Active Directory authenticates a client certificate at
// the LDAPS handshake and rejects an EXTERNAL bind there; over StartTLS an
// EXTERNAL bind maps the certificate.
func (l *labDir) viaStartTLS() *labDir {
	c := *l
	c.uri, c.startTLS = l.plainURI, true
	return &c
}

func (l *labDir) bindExternal() directory.Bind {
	return directory.Bind{Mechanism: "external", TLSCertFile: l.d.pki.brokerCert, TLSKeyFile: l.d.pki.brokerKey}
}

func (l *labDir) bindGSSAPI() directory.Bind {
	return directory.Bind{Mechanism: "gssapi", KeytabFile: l.keytabFile, Principal: "port49@" + dirRealm, KRB5Conf: l.krb5File}
}

// sanEmail is the weak mapping pinned to the users CA.
func sanEmail() directory.Mapping {
	return directory.Mapping{Kind: directory.MapSANEmail, Attribute: "mail", AllowWeak: true,
		Issuers: []string{dirUsersCAIssuer}}
}

// config is the broker.directory block for l under mode: the principal is the
// mail attribute on both directories, a name the fixture gives each person.
func (l *labDir) config(mode directory.Nested, groupsBase string, bind directory.Bind, m directory.Mapping) directory.Config {
	if m.Attribute == "" {
		m.Attribute = m.Kind.DefaultAttribute()
	}
	return directory.Config{
		Servers: []directory.Server{{URI: l.uri, Priority: 100, StartTLS: l.startTLS}}, CAFile: l.d.pki.caFile, Bind: bind,
		BaseDN: l.baseDN, GroupsBaseDN: groupsBase, UserFilter: l.userFilter, GroupFilter: l.groupFilter,
		PrincipalAttribute: "mail", UsernameAttribute: l.usernameAttr, GroupNameAttribute: "cn", MemberAttribute: "member",
		Mapping: m, Nested: mode, MaxDepth: 16, QueryTimeout: 15 * time.Second, HealthInterval: 30 * time.Second,
		HealthTimeout: 5 * time.Second, FailureThreshold: 3, ProbeInterval: time.Minute, StabilityWindow: time.Minute,
		Grace: 4 * time.Hour,
	}
}

// resolver is the broker's resolver on l over a memory store: a simple bind,
// the san_email mapping and groups under OU=G.
func (l *labDir) resolver(t *testing.T, mode directory.Nested) *directory.Resolver {
	t.Helper()
	return l.resolverWith(t, l.config(mode, l.groupsBaseDN, l.bindSimple(), sanEmail()), l.d.password, nil)
}

// resolverWith builds a resolver from cfg whose bind password is password,
// recording every search to ev when ev is not nil.
func (l *labDir) resolverWith(t *testing.T, cfg directory.Config, password string, ev *evidenceLog) *directory.Resolver {
	t.Helper()
	cr, err := directory.LoadCredentials(cfg.Bind, getenvOf(password))
	if err != nil {
		t.Fatalf("%s: loading the %s bind's credentials: %v", l.name, cfg.Bind.Mechanism, err)
	}
	dial, err := directory.NewDialer(cfg, cr)
	if err != nil {
		t.Fatalf("%s: %v", l.name, err)
	}
	if ev != nil {
		dial = recordingDialer(dial, ev, string(cfg.Bind.Mechanism))
	}
	m := metrics.New(prometheus.NewRegistry())
	say := func(format string, args ...any) {
		l.d.mu.Lock()
		l.d.said = append(l.d.said, fmt.Sprintf(format, args...))
		l.d.mu.Unlock()
	}
	return &directory.Resolver{Cfg: cfg, Pool: directory.NewPool(cfg, dial, directory.RootDSE, time.Now, m, say),
		Store: memory.New(time.Now), Now: time.Now, M: m, Say: say}
}

// takeSaid is the lines the broker's code has said since the last call.
func (d *directories) takeSaid() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := d.said
	d.said = nil
	return out
}

// principal is the principal of one of the fixture's people.
func (l *labDir) principal(user string) string { return "user:" + user + "@corp.example.com" }

// memberOf is the values of user's memberOf attribute, sorted, read through
// the broker's pool.
func (l *labDir) memberOf(t *testing.T, user string) []string {
	t.Helper()
	r := l.resolver(t, "direct")
	var out []string
	_, err := r.Pool.Do(context.Background(), func(s directory.Searcher) error {
		res, err := s.Search(ldap.NewSearchRequest(l.baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 15, false,
			fmt.Sprintf("(&%s(%s=%s))", l.userFilter, l.usernameAttr, ldap.EscapeFilter(user)), []string{"memberOf"}, nil))
		if err == nil && len(res.Entries) == 1 {
			out = res.Entries[0].GetAttributeValues("memberOf")
		}
		return err
	})
	if err != nil {
		t.Fatalf("%s: memberOf of %s: %v", l.name, user, err)
	}
	slices.Sort(out)
	return out
}

// version is what the directory says it is, the image it runs and the base
// image's digest.
func (l *labDir) version(t *testing.T) string {
	t.Helper()
	var ver string
	switch l.name {
	case platOpenLDAP:
		out, _ := l.exec("slapd", "-VV")
		ver = strings.TrimSpace(strings.SplitN(strings.TrimSpace(out), "\n", 2)[0])
	case platWindows:
		return l.win.version()
	default:
		out, _ := l.exec("samba", "--version")
		ver = "Samba " + strings.TrimSpace(out)
	}
	return fmt.Sprintf("%s; image `%s` (%s), built on %s", ver, l.image, imageID(l.image), imageID("debian:bookworm-slim"))
}

// imageID is an image's content digest for a note: its repo digest when it
// has one, else its id.
func imageID(image string) string {
	for _, f := range []string{"{{index .RepoDigests 0}}", "{{.Id}}"} {
		if b, err := dockerCmd("image", "inspect", "--format", f, image).Output(); err == nil && strings.TrimSpace(string(b)) != "" {
			return strings.TrimSpace(string(b))
		}
	}
	return "digest unknown"
}

// ldapCode is the LDAP result code in err, 0 for none and -1 for an error
// that carries none (a dial failure, a Kerberos refusal).
func ldapCode(err error) int {
	if err == nil {
		return 0
	}
	var le *ldap.Error
	if errors.As(err, &le) {
		return int(le.ResultCode)
	}
	return -1
}

func errOrOK(err error) string {
	if err == nil {
		return "ok"
	}
	return oneLineMax(err.Error(), 200)
}

func oneLineMax(s string, n int) string {
	// AD ends an LDAP diagnosticMessage with a NUL; no control character
	// belongs in a note (grep calls the file binary).
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > n {
		s = s[:n] + "..."
	}
	return s
}

// ---------------------------------------------------------------------------
// Evidence: LDAPS is encrypted, so what a reader can follow is what the
// broker's code asked and what it was told.
// ---------------------------------------------------------------------------

// evidenceLog is one file of JSON lines at tests/lab/evidence/<name>.json.
// A line is a search, a bind or a mark; none holds a password, a keytab or a
// ticket, and a bind line holds the error text port49 itself wrote.
type evidenceLog struct {
	mu   sync.Mutex
	f    *os.File
	Path string
}

type evidenceLine struct {
	Event      string   `json:"event"`
	Label      string   `json:"label,omitempty"`
	Base       string   `json:"base,omitempty"`
	Scope      string   `json:"scope,omitempty"`
	Filter     string   `json:"filter,omitempty"`
	DNs        []string `json:"dns,omitempty"`
	Entries    *int     `json:"entries,omitempty"`
	Mechanism  string   `json:"mechanism,omitempty"`
	ResultCode *int     `json:"result_code,omitempty"`
	Error      string   `json:"error,omitempty"`
	DurationMS float64  `json:"duration_ms,omitempty"`
	DCEvents   []string `json:"dc_events,omitempty"`
	AuthzID    string   `json:"authz_id,omitempty"`
}

// evidenceDir is where evidence file name goes under the output root: the
// committed evidence directory, except for the Windows bring-up's, which is no
// measurement and goes under the git-ignored logs.
func evidenceDir(out, name string) string {
	if name == "L44-bringup" {
		return filepath.Join(out, "tests", "lab", "logs", "windows")
	}
	return filepath.Join(out, "tests", "lab", "evidence")
}

// evidence opens evidenceDir's <name>.json under the run's output root,
// truncating whatever an earlier run left.
func evidence(t *testing.T, d *directories, name string) *evidenceLog {
	t.Helper()
	dir := evidenceDir(d.out, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(filepath.Join(dir, name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	e := &evidenceLog{f: f, Path: f.Name()}
	t.Cleanup(func() { f.Close() })
	return e
}

// assertClean fails the test, without printing either, when the evidence
// holds any of secrets.
func (e *evidenceLog) assertClean(t *testing.T, secrets ...string) {
	t.Helper()
	b, err := os.ReadFile(e.Path)
	if err != nil {
		t.Fatal(err)
	}
	if noteHoldsSecret(string(b), secrets...) {
		t.Fatalf("%s holds a credential; it must hold none", e.Path)
	}
}

func (e *evidenceLog) add(l evidenceLine) {
	// Not escaped for HTML: a filter's & stays a &, which is what a reader greps.
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(l); err != nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	_, _ = e.f.WriteString(b.String())
}

// mark says what the lines after it belong to.
func (e *evidenceLog) mark(format string, args ...any) {
	e.add(evidenceLine{Event: "mark", Label: fmt.Sprintf(format, args...)})
}

// whoami records a WhoAmI observation: the authorization ID (a principal name,
// never a secret) or the error. Both arrive scrubbed.
func (e *evidenceLog) whoami(label, authzID string, err error) {
	l := evidenceLine{Event: "whoami", Label: label, AuthzID: authzID}
	if err != nil {
		l.Error = oneLineMax(err.Error(), 400)
	}
	e.add(l)
}

// bind records one bind attempt's outcome.
func (e *evidenceLog) bind(mechanism string, err error, took time.Duration) {
	code := ldapCode(err)
	l := evidenceLine{Event: "bind", Mechanism: mechanism, ResultCode: &code, DurationMS: ms(took)}
	if err != nil {
		l.Error = oneLineMax(err.Error(), 400)
	}
	e.add(l)
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

func scopeName(s int) string {
	switch s {
	case ldap.ScopeBaseObject:
		return "base"
	case ldap.ScopeSingleLevel:
		return "one"
	}
	return "sub"
}

// recordingClient logs each search it passes on.
type recordingClient struct {
	directory.Client
	ev *evidenceLog
}

func (r recordingClient) SearchContext(ctx context.Context, req *ldap.SearchRequest, paging uint32) (*ldap.SearchResult, error) {
	start := time.Now()
	res, err := r.Client.SearchContext(ctx, req, paging)
	code := ldapCode(err)
	l := evidenceLine{Event: "search", Base: req.BaseDN, Scope: scopeName(req.Scope), Filter: req.Filter, ResultCode: &code,
		DurationMS: ms(time.Since(start))}
	if res != nil {
		for _, e := range res.Entries {
			l.DNs = append(l.DNs, e.DN)
		}
	}
	if err != nil {
		l.Error = oneLineMax(err.Error(), 300)
	}
	r.ev.add(l)
	return res, err
}

// recordingDialer returns inner's connections wrapped in a recorder, and records
// a dial that fails (a refused bind) as a bind line.
func recordingDialer(inner directory.Dialer, ev *evidenceLog, mechanism string) directory.Dialer {
	return func(ctx context.Context, s directory.Server) (directory.Client, error) {
		start := time.Now()
		c, err := inner(ctx, s)
		if err != nil {
			ev.bind(mechanism, err, time.Since(start))
			return nil, err
		}
		return recordingClient{Client: c, ev: ev}, nil
	}
}

// ---------------------------------------------------------------------------
// The note
// ---------------------------------------------------------------------------

// dirRunLine is the commit the run was made at and the test selection.
func dirRunLine(sel string) string {
	sha := "unknown"
	if root, err := repoRoot(); err == nil {
		if out, err := exec.Command("git", "-C", root, "rev-parse", "HEAD").Output(); err == nil {
			sha = strings.TrimSpace(string(out))
		}
	}
	env := ""
	if strings.Contains(sel, "TestL44") {
		env = "PORT49_LAB_L44=1 " // without it L44's tests skip
	}
	return fmt.Sprintf("commit `%s`, `%sgo test -tags lab ./tests/lab/ -run '%s'`", sha, env, sel)
}

// noteHoldsSecret reports whether note holds any non-empty secret.
func noteHoldsSecret(note string, secrets ...string) bool {
	for _, s := range secrets {
		if s != "" && strings.Contains(note, s) {
			return true
		}
	}
	return false
}

// writeResult writes tests/lab/results/<row>-<platform>.md under the run's
// output root in the form spec §15 rule 3 requires: the platform, the image
// version, the claim, the observation and a pointer to the evidence. The
// whole note passes through labcreds.RedactNote, as every lab note does.
func writeResult(t *testing.T, d *directories, row string, l *labDir, claim, version, observation, evidencePath string) {
	t.Helper()
	dir := filepath.Join(d.out, "tests", "lab", "results")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("results directory: %v", err)
	}
	note, held := noteText(d, row, l, claim, version, observation, evidencePath)
	if held {
		t.Fatalf("the %s-%s note holds a credential; it must hold none", row, l.name)
	}
	path := filepath.Join(dir, fmt.Sprintf("%s-%s.md", row, l.name))
	if err := os.WriteFile(path, []byte(labcreds.RedactNote(note)), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	t.Logf("wrote %s", path)
}

// noteText is the note's text, and whether it holds the run's bind password
// or any of d.extra.
func noteText(d *directories, row string, l *labDir, claim, version, observation, evidencePath string) (string, bool) {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s — %s\n\n", row, l.name)
	fmt.Fprintf(&b, "- **Date measured:** %s\n", time.Now().UTC().Format("2006-01-02"))
	fmt.Fprintf(&b, "- **Platform:** %s, %s\n", l.name, l.where)
	fmt.Fprintf(&b, "- **Image version:** %s\n", version)
	fmt.Fprintf(&b, "- **Run:** %s\n", dirRunLine(d.runSel))
	wire := "LDAPS"
	if l.name == platWindows {
		wire = "TLS (LDAPS or StartTLS)" // L44's EXTERNAL cells run over StartTLS
	}
	fmt.Fprintf(&b, "- **Capture:** `%s`: one JSON line per search, bind and step, with the base, scope, filter, the DNs returned, "+
		"the LDAP result code and the duration, recorded by the broker's own client (the wire is %s, so a pcap would be "+
		"encrypted).\n", evidencePath, wire)
	if l.credentials != "" {
		fmt.Fprintf(&b, "- **Credentials:** %s\n", l.credentials)
	} else {
		fmt.Fprintf(&b, "- **Credentials:** none appear here or in the evidence. The bind password is generated for each run and "+
			"never printed; the keytab and every ticket stay on the host that ran it.\n")
	}
	fmt.Fprintf(&b, "\n## Claim\n\n%s\n\n## Observation\n\n%s\n", claim, observation)
	return b.String(), noteHoldsSecret(b.String(), append([]string{d.password}, d.extra...)...)
}

// configNote is what the directory was configured to do that a note's rows
// depend on: the lab's accommodations, which a reader of the note alone must
// see. None is evidence about a Windows DC (L44).
func (l *labDir) configNote() string {
	if l.name == platWindows {
		return l.win.configNote()
	}
	if l.name == platOpenLDAP {
		return "### How this directory was configured\n\n" +
			"- `olcSecurity: tls=1` (every operation must be under TLS), set after the seed was loaded over ldapi.\n" +
			"- `olcTLSVerifyClient: try`: a client certificate is requested and verified when presented.\n" +
			"- `olcAuthzRegexp: \"^cn=port49-broker,o=port49 lab$\" -> cn=port49,ou=Svc,dc=corp,dc=example,dc=com`.\n" +
			"- The `memberof` overlay with `olcMemberOfRefInt: TRUE`; the seed was loaded with `ldapadd` so the overlay ran.\n" +
			"- `cn=port49` has read access to everything; anonymous has none beyond the root DSE and authentication.\n\n"
	}
	return "### How this directory was configured\n\n" +
		"- `ldap server require strong auth` is `yes` at start; L43's GSSAPI and plain-LDAP cells are measured under it and again " +
		"under the setting that permits SASL over TLS, each row naming the value in force.\n" +
		"- TLS from the lab PKI (`tls certfile`, `tls keyfile`, `tls cafile`); sysvol ACLs in `user.NTACL` (a lab accommodation).\n" +
		"- The DC's account `DC1$` carries the extra SPN `ldap/localhost`, because port49 binds GSSAPI to `ldap/<the URI's host>` and the " +
		"lab's URIs name `localhost`; the client `krb5.conf` maps `localhost` to `CORP.EXAMPLE.COM` and reaches the KDC at 127.0.0.1:20088 over TCP.\n" +
		"- `port49` is an ordinary domain user with its default rights.\n\n"
}

// setStrongAuth switches the DC's `ldap server require strong auth` to value,
// restarts it and waits for LDAPS; it returns the value testparm then reports.
func (l *labDir) setStrongAuth(t *testing.T, value string) string {
	t.Helper()
	if out, err := l.exec("sed", "-i", "s/^\\(\\s*ldap server require strong auth\\s*=\\s*\\).*/\\1"+value+"/", "/etc/samba/smb.conf"); err != nil {
		t.Fatalf("setting ldap server require strong auth: %v\n%s", err, tailOf(out, 400))
	}
	if b, err := l.d.dockerCompose("restart", "-t", "5", l.service).CombinedOutput(); err != nil {
		t.Fatalf("restarting %s: %v\n%s", l.service, err, tailOf(string(b), 400))
	}
	deadline := time.Now().Add(2 * time.Minute)
	for {
		err := l.d.rootDSE(l)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: LDAPS did not answer after the restart: %v", l.name, err)
		}
		time.Sleep(2 * time.Second)
	}
	got, err := l.exec("sh", "-c", "testparm -s --parameter-name='ldap server require strong auth' 2>/dev/null")
	if err != nil {
		t.Fatalf("reading the setting back: %v\n%s", err, tailOf(got, 400))
	}
	return "ldap server require strong auth = " + strings.TrimSpace(got)
}

// certRequested says whether l's LDAPS asked a connecting client for a
// certificate, and how many CA names it listed: without a request, Go's TLS
// client sends none, and an EXTERNAL bind has nothing to map.
func (l *labDir) certRequested(t *testing.T) string {
	t.Helper()
	tc, err := l.d.pki.clientTLS(l.uri)
	if err != nil {
		t.Fatal(err)
	}
	asked, names := false, 0
	tc.GetClientCertificate = func(ri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		asked, names = true, len(ri.AcceptableCAs)
		return &tls.Certificate{}, nil
	}
	host := strings.TrimPrefix(l.uri, "ldaps://")
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", host, tc)
	if err != nil {
		return "the probe's handshake failed: " + oneLineMax(err.Error(), 120)
	}
	conn.Close()
	if !asked {
		return "the server sent no CertificateRequest, so a client certificate is never presented to it"
	}
	return fmt.Sprintf("the server sent a CertificateRequest listing %d acceptable CA name(s)", names)
}

// capabilities is the root DSE's supportedCapabilities, sorted, read through
// the broker's pool over LDAPS (plan 7g's carried question a).
func (l *labDir) capabilities(t *testing.T) []string {
	t.Helper()
	r := l.resolver(t, "direct")
	var out []string
	_, err := r.Pool.Do(context.Background(), func(s directory.Searcher) error {
		res, err := s.Search(ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 15, false,
			"(objectClass=*)", []string{"supportedCapabilities"}, nil))
		if err == nil && len(res.Entries) == 1 {
			out = res.Entries[0].GetAttributeValues("supportedCapabilities")
		}
		return err
	})
	if err != nil {
		t.Fatalf("%s: the root DSE's supportedCapabilities: %v", l.name, err)
	}
	slices.Sort(out)
	return out
}

// setAttr replaces one attribute of one entry: by the DC's own tools on Samba,
// by Set-ADObject on Windows. The value is never printed.
func (l *labDir) setAttr(t *testing.T, dn, attr, value string) {
	t.Helper()
	switch l.name {
	case platSamba:
		if out, err := l.exec("/lab/set-attr.sh", dn, attr, value); err != nil {
			t.Fatalf("setting %s on %s: %v\n%s", attr, dn, err, tailOf(out, 400))
		}
	case platWindows:
		l.win.setValues(t, dn, attr, []string{value})
	default:
		t.Fatalf("%s: setAttr is for directories with altSecurityIdentities", l.name)
	}
}

// ldapObjectSID is the objectSid of the one entry filter finds, read as bytes
// over LDAPS through the broker's pool: the attribute port49's sid mapping
// compares.
func (l *labDir) ldapObjectSID(t *testing.T, filter string) string {
	t.Helper()
	r := l.resolver(t, "direct")
	var raw []byte
	_, err := r.Pool.Do(context.Background(), func(s directory.Searcher) error {
		res, err := s.Search(ldap.NewSearchRequest(l.baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 15, false,
			filter, []string{"objectSid"}, nil))
		if err == nil && len(res.Entries) == 1 {
			raw = res.Entries[0].GetRawAttributeValue("objectSid")
		}
		return err
	})
	if err != nil || len(raw) == 0 {
		t.Fatalf("%s: objectSid of %s: %v (%d bytes)", l.name, filter, err, len(raw))
	}
	sid, err := labSIDString(raw)
	if err != nil {
		t.Fatalf("%s: objectSid of %s: %v", l.name, filter, err)
	}
	return sid
}

// labSIDString is objectSid's binary form as a SID string: revision 1, the
// count, the 48-bit authority big-endian, each sub-authority little-endian.
func labSIDString(b []byte) (string, error) {
	if len(b) < 8 || b[0] != 1 || len(b) != 8+4*int(b[1]) {
		return "", errors.New("a malformed objectSid")
	}
	var auth uint64
	for i := 0; i < 6; i++ {
		auth = auth<<8 | uint64(b[2+i])
	}
	s := fmt.Sprintf("S-1-%d", auth)
	for i := 0; i < int(b[1]); i++ {
		s += fmt.Sprintf("-%d", binary.LittleEndian.Uint32(b[8+4*i:]))
	}
	return s, nil
}

// waitLDAPS waits for l's LDAPS to answer a root DSE read under the lab CA.
func (l *labDir) waitLDAPS(t *testing.T, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		err := l.d.rootDSE(l)
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: LDAPS did not answer within %s: %v", l.name, within, err)
		}
		time.Sleep(2 * time.Second)
	}
}
