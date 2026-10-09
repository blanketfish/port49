//go:build lab

package lab

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf16"

	"golang.org/x/crypto/ssh"

	"github.com/go-ldap/ldap/v3"
	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/krberror"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/rhwendt/port49/internal/directory"
)

// A secret prints as its key names whatever the verb, so a log line that
// formats the struct leaks nothing.
func TestWindowsSecretsPrintAsNames(t *testing.T) {
	s, err := newWinSecrets()
	if err != nil {
		t.Fatal(err)
	}
	// Every verb, on the pointer and on the value.
	var out string
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d"} {
		out += fmt.Sprintf(verb+" "+verb+" ", s, *s)
	}
	for i, v := range s.all() {
		if v == "" || strings.Contains(out, v) {
			t.Fatalf("secret %d is empty or printed", i)
		}
	}
	if !strings.Contains(out, "admin_password") || !strings.Contains(out, "dsrm_password") {
		t.Fatalf("%s", out)
	}
}

// Every generated password meets Windows' complexity rule: four classes, and
// long enough for any domain policy this lab meets.
func TestWindowsPasswordMeetsComplexity(t *testing.T) {
	p, err := winPassword()
	if err != nil {
		t.Fatal(err)
	}
	if len(p) < 20 || !strings.ContainsAny(p, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") || !strings.ContainsAny(p, "abcdefghijklmnopqrstuvwxyz") ||
		!strings.ContainsAny(p, "0123456789") || !strings.ContainsAny(p, "!") {
		t.Fatalf("password of %d chars misses a class", len(p))
	}
	q, _ := winPassword()
	if p == q {
		t.Fatal("two passwords are the same")
	}
}

func TestWindowsEnvFile(t *testing.T) {
	s := &winSecrets{AdminPassword: "Aa1!x"}
	if got := winEnv(s); got != "USERNAME=Docker\nPASSWORD=Aa1!x\n" {
		t.Fatalf("the env file is %d bytes and differs from the expected form", len(got))
	}
}

// The command line is the bootstrap and nothing else: no parameter, so no
// secret, ever reaches a process list.
func TestWindowsCommandIsTheBootstrapAlone(t *testing.T) {
	cmd := winCommand()
	const pre = "powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand "
	if !strings.HasPrefix(cmd, pre) {
		t.Fatalf("%s", cmd)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(cmd, pre))
	if err != nil || len(raw)%2 != 0 {
		t.Fatalf("%v", err)
	}
	u := make([]uint16, len(raw)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(raw[2*i:])
	}
	if got := string(utf16.Decode(u)); got != winBootstrap {
		t.Fatalf("decoded %q", got)
	}
}

// The payload carries the script and its params as JSON; the result is the
// last line of output, or the error the script threw.
func TestWindowsPayloadAndResult(t *testing.T) {
	b, err := winPayload("param($a) @{ b = $a }", map[string]any{"a": "x"})
	if err != nil {
		t.Fatal(err)
	}
	var p struct {
		Script string         `json:"script"`
		Params map[string]any `json:"params"`
	}
	if json.Unmarshal(b, &p) != nil || p.Script == "" || p.Params["a"] != "x" {
		t.Fatalf("%s", b)
	}
	if r, err := winResult([]byte("noise\r\n{\"b\":\"x\"}\r\n")); err != nil || string(r) != `{"b":"x"}` {
		t.Fatalf("%s %v", r, err)
	}
	var thrown *winThrownError
	if _, err := winResult([]byte(`{"error":"Access is denied."}`)); err == nil || err.Error() != "Access is denied." || !errors.As(err, &thrown) {
		t.Fatalf("%v", err)
	}
	if _, err := winResult([]byte("\r\n")); err == nil || errors.As(err, &thrown) {
		t.Fatal("no output read as a result, or as the script's own error")
	}
	if _, err := winResult([]byte("Access is denied.\r\n")); err == nil || errors.As(err, &thrown) {
		t.Fatal("a last line that is not JSON read as a result, or as the script's own error")
	}
}

func TestWindowsScrub(t *testing.T) {
	got := winScrub("ktpass -pass Aa1!s3cret failed for Aa1!s3cret; dsrm Aa1!other", "Aa1!s3cret", "", "Aa1!other")
	if strings.Contains(got, "s3cret") || strings.Contains(got, "other") || !strings.Contains(got, "<secret>") {
		t.Fatalf("a secret survived the scrub (%d bytes)", len(got))
	}
	// An empty secret is skipped: replacing "" would shred the text.
	if want := "ktpass -pass <secret> failed for <secret>; dsrm <secret>"; got != want {
		t.Fatalf("the scrub changed more than the secrets: %q", got)
	}
}

// The ISO is the pinned one by size and SHA-256, or it is refused.
func TestWindowsISOCheck(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.iso")
	if err := os.WriteFile(p, []byte("abc"), 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("abc"))
	good := hex.EncodeToString(sum[:])
	if err := winISOOK(p, 3, good); err != nil {
		t.Fatalf("the right file refused: %v", err)
	}
	if winISOOK(p, 4, good) == nil || winISOOK(p, 3, strings.Repeat("0", 64)) == nil || winISOOK(p+"x", 3, good) == nil {
		t.Fatal("a wrong size, a wrong sum or a missing file accepted")
	}
}

func TestWindowsQuote(t *testing.T) {
	for in, want := range map[string]string{
		"plain": "plain", "a,b": `"a,b"`, `say "hi"`: `"say ""hi"""`, " lead": `" lead"`, "trail ": `"trail "`,
		"a+b": `"a+b"`, "a=b": `"a=b"`, "a#b": `"a#b"`, "a;b": `"a;b"`, "a<b": `"a<b"`, "a>b": `"a>b"`, `a\b`: `"a\b"`, "a/b": `"a/b"`, "": `""`, "a\nb": "\"a\nb\"",
	} {
		if got := winQuote(in); got != want {
			t.Errorf("winQuote(%q) = %q, want %q", in, got, want)
		}
	}
}

// RFC 4514's backslash form: the third way a Windows DC may want a comma in
// <I> written (pre-flight I6).
func TestWindowsEscape(t *testing.T) {
	for in, want := range map[string]string{
		"plain": "plain", "a,b": `a\,b`, `say "hi"`: `say \"hi\"`, "a+b": `a\+b`, "a=b": `a\=b`, "a;b": `a\;b`,
		"a<b>": `a\<b\>`, `a\b`: `a\\b`, "#lead": `\#lead`, "a#b": "a#b", " lead": `\ lead`, "trail ": `trail\ `,
	} {
		if got := winEscape(in); got != want {
			t.Errorf("winEscape(%q) = %q, want %q", in, got, want)
		}
	}
}

// control-ski's mapping is the certificate's own SubjectKeyId in hex; a
// certificate with none gives no control, never an empty mapping.
func TestWindowsAltSecSKI(t *testing.T) {
	if got, err := winAltSecSKI(&x509.Certificate{SubjectKeyId: []byte{0xab, 0x01, 0xff}}); err != nil || got != "X509:<SKI>ab01ff" {
		t.Fatalf("%q %v", got, err)
	}
	if _, err := winAltSecSKI(&x509.Certificate{}); err == nil {
		t.Fatal("a certificate with no SubjectKeyId gave a mapping")
	}
}

// Each offered form differs from port49's in the one respect it names, and
// the lab's reading of the issuer is port49's own.
func TestWindowsAltSecForms(t *testing.T) {
	now := time.Now()
	ca, caKey, err := winCA("lab-users, comma-CA", 2, now)
	if err != nil {
		t.Fatal(err)
	}
	c, _, err := winPersonCert(ca, caKey, "alice", "alice@corp.example.com", new(big.Int).SetBytes([]byte{0x80, 0x01, 0x02}), now)
	if err != nil {
		t.Fatal(err)
	}
	const issuer = "DC=com,DC=example,DC=corp,CN=lab-users, comma-CA"
	const quotedIssuer = `DC=com,DC=example,DC=corp,CN="lab-users, comma-CA"`
	for name, tc := range map[string]struct {
		f    func(*x509.Certificate) (string, error)
		want string
	}{
		"port49":     {winForm{quoted: true, signByte: true}.of, "X509:<I>" + quotedIssuer + "<SR>02018000"},
		"forward":    {winAltSecForward, "X509:<I>CN=lab-users, comma-CA,DC=corp,DC=example,DC=com<SR>020180"},
		"unreversed": {winAltSecUnreversed, "X509:<I>" + issuer + "<SR>800102"},
		"quoted":     {winAltSecQuoted, `X509:<I>DC=com,DC=example,DC=corp,CN="lab-users, comma-CA"<SR>020180`},
		"escaped":    {winAltSecEscaped, `X509:<I>DC=com,DC=example,DC=corp,CN=lab-users\, comma-CA<SR>020180`},
		"signbyte":   {winAltSecSignByte, "X509:<I>" + issuer + "<SR>02018000"},
	} {
		if got, err := tc.f(c); err != nil || got != tc.want {
			t.Errorf("%s: %q %v, want %q", name, got, err, tc.want)
		}
	}
	if got, _ := (winForm{quoted: true, signByte: true}).of(c); got != directory.ADIssuerSerial(c) {
		t.Errorf("the lab's port49 form %q is not directory.ADIssuerSerial's %q", got, directory.ADIssuerSerial(c))
	}
}

// The UPN SAN reads back through port49's own san_upn lookup.
func TestWindowsUPNExtensionReadsBack(t *testing.T) {
	p, err := writeDirectoryPKI(t.TempDir(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	c, key, err := winPersonCert(p.usersCA, p.usersKey, "alice", "alice@corp.example.com", winHighBitSerial(), time.Now())
	if err != nil || key.N.BitLen() != 2048 {
		t.Fatalf("%v", err)
	}
	l, err := directory.Mapping{Kind: directory.MapSANUPN, Attribute: "userPrincipalName"}.Lookup(c, "(objectClass=user)")
	if err != nil || !strings.Contains(l.Filter, "alice@corp.example.com") {
		t.Fatalf("%+v %v", l, err)
	}
	if _, err := directory.SIDOf(c); err == nil {
		t.Fatal("a person certificate from the harness carries a SID extension")
	}
}

func TestWindowsCSR(t *testing.T) {
	b, key, err := winCSR("alice", "alice@corp.example.com")
	if err != nil {
		t.Fatal(err)
	}
	csr, err := winParseCSR(b)
	if err != nil || csr.CheckSignature() != nil || csr.Subject.CommonName != "alice" || key.N.BitLen() != 2048 {
		t.Fatalf("%v", err)
	}
	found := false
	for _, e := range csr.Extensions {
		if e.Id.Equal(winOIDSAN) {
			found = true
			want, err := winUPNExtension("alice@corp.example.com")
			if err != nil || !slices.Equal(e.Value, want.Value) {
				t.Fatal("the request's SAN is not the UPN it was given")
			}
		}
	}
	if !found {
		t.Fatal("the request carries no SAN")
	}
	// No UPN, no SAN: the DC's own request names none.
	b, _, err = winCSR("dc", "")
	if err != nil {
		t.Fatal(err)
	}
	if csr, err = winParseCSR(b); err != nil || len(csr.Extensions) != 0 {
		t.Fatalf("a request with no UPN carries extensions: %v", err)
	}
}

// The DC's LDAPS certificate is signed by the lab CA for the names the lab's
// URIs and the DC use, on the key the DC generated.
func TestWindowsSignServerCSR(t *testing.T) {
	p, err := writeDirectoryPKI(t.TempDir(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	b, key, err := winCSR(winDCHost, "")
	if err != nil {
		t.Fatal(err)
	}
	certPEM, err := p.signServerCSR(b, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	c, err := winParsePEMCert(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"localhost", winDCHost, "127.0.0.1"} {
		if _, err := c.Verify(x509.VerifyOptions{Roots: p.ca.Pool(), DNSName: name, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if !key.PublicKey.Equal(c.PublicKey) {
		t.Error("the certificate is not on the request's key")
	}
	// A request whose signature does not verify is refused.
	blk, _ := pem.Decode(b)
	blk.Bytes[len(blk.Bytes)-1] ^= 0xff
	if _, err := p.signServerCSR(pem.EncodeToMemory(blk), time.Now()); err == nil {
		t.Error("a request with a bad signature was signed")
	}
}

func TestWindowsHighBitSerial(t *testing.T) {
	s := winHighBitSerial().Bytes()
	if len(s) != 9 || s[0]&0x80 == 0 {
		t.Fatalf("% x", s)
	}
}

func TestWindowsParseKinit(t *testing.T) {
	ok := "[7] 1.2: Received error from KDC: -1765328359/Additional pre-authentication required\nlab: kinit exit 0\n" +
		"Ticket cache: FILE:/tmp/krb5cc_0\n  krbtgt/CORP.EXAMPLE.COM@CORP.EXAMPLE.COM\n"
	if r := winParseKinit(ok); !r.ok || r.kdcSaid() != "—" {
		t.Fatalf("%+v %q", r, r.kdcSaid())
	}
	// A TGT needs both kinit's own success and the ticket in the cache.
	if winParseKinit("lab: kinit exit 0\nklist: No credentials cache found\n").ok ||
		winParseKinit("lab: kinit exit 1\n  krbtgt/CORP.EXAMPLE.COM@CORP.EXAMPLE.COM\n").ok {
		t.Fatal("a TGT read from only half of its evidence")
	}
	bad := "[7] 1.2: Received error from KDC: -1765328359/Additional pre-authentication required\n" +
		"[7] 1.3: Received error from KDC: -1765328360/Preauthentication failed\n" +
		"kinit: Preauthentication failed while getting initial credentials\nlab: kinit exit 1\nklist: No credentials cache found\n"
	r := winParseKinit(bad)
	if r.ok || !strings.Contains(r.kdcSaid(), "-1765328360/Preauthentication failed") || strings.Contains(r.kdcSaid(), "-1765328359") ||
		!strings.Contains(r.kdcSaid(), "kinit: Preauthentication failed") {
		t.Fatalf("%+v %q", r, r.kdcSaid())
	}
	if !r.kdcRefused() || len(r.setupCodes()) != 0 {
		t.Fatalf("the KDC's own refusal (24) read as no refusal or as a setup failure: %+v", r)
	}
	if winParseKinit(ok).kdcRefused() {
		t.Fatal("preauth-required alone, the ordinary first answer, read as a refusal")
	}
	// The client failed on its own side: MIT could not verify the KDC's
	// certificate, and the KDC sent nothing past preauth-required. That is
	// no refusal, so the cell is INVALID, never "refused" (pre-flight C3).
	client := "[7] 1.2: Received error from KDC: -1765328359/Additional pre-authentication required\n" +
		"kinit: Certificate verification failed while verifying KDC certificate\nlab: kinit exit 1\nklist: No credentials cache found\n"
	if c := winParseKinit(client); c.ok || c.kdcRefused() {
		t.Fatalf("a client-side failure read as the KDC's refusal: %+v", c)
	}
	// "Response too big for UDP" (52) is the transport asking for TCP, not a
	// refusal: with a client-side failure after it, the cell is INVALID.
	big := "[7] 1.2: Received error from KDC: -1765328359/Additional pre-authentication required\n" +
		"[7] 1.3: Received error from KDC: -1765328332/Response too big for UDP, retry with TCP\n" +
		"kinit: Certificate verification failed while verifying KDC certificate\nlab: kinit exit 1\n"
	if c := winParseKinit(big); c.ok || c.kdcRefused() || strings.Contains(c.kdcSaid(), "-1765328332") {
		t.Fatalf("a UDP size retry read as the KDC's refusal: %+v", c)
	}
	// The skip is per line: a real refusal in the same trace still counts.
	bigThenMismatch := "[7] 1.2: Received error from KDC: -1765328359/Additional pre-authentication required\n" +
		"[7] 1.3: Received error from KDC: -1765328332/Response too big for UDP, retry with TCP\n" +
		"[7] 1.4: Received error from KDC: -1765328318/KDC_ERR_CERTIFICATE_MISMATCH\nlab: kinit exit 1\n"
	if c := winParseKinit(bigThenMismatch); !c.kdcRefused() || !strings.Contains(c.kdcSaid(), "-1765328318") ||
		strings.Contains(c.kdcSaid(), "-1765328332") {
		t.Fatalf("a UDP size retry hid the KDC's refusal (66): %+v", c)
	}
	// A PKINIT certificate-validation code from the KDC is a setup failure;
	// 66, CERTIFICATE_MISMATCH, is the mapping's verdict.
	trust := "[7] 1.3: Received error from KDC: -1765328322/Client not trusted\nlab: kinit exit 1\n"
	if c := winParseKinit(trust); !c.kdcRefused() || !slices.Equal(c.setupCodes(), []int{62}) {
		t.Fatalf("CLIENT_NOT_TRUSTED (62): %+v %v", c, c.setupCodes())
	}
	mismatch := "[7] 1.3: Received error from KDC: -1765328318/KDC_ERR_CERTIFICATE_MISMATCH\nlab: kinit exit 1\n"
	if c := winParseKinit(mismatch); !c.kdcRefused() || len(c.setupCodes()) != 0 {
		t.Fatalf("CERTIFICATE_MISMATCH (66) read as a setup failure: %+v", c)
	}
	if n, ok := winKDCErrCode("-1765328318/KDC_ERR_CERTIFICATE_MISMATCH"); !ok || n != 66 {
		t.Fatalf("%d %v", n, ok)
	}
	if _, ok := winKDCErrCode("garbage"); ok {
		t.Fatal("a line with no code read as one")
	}
}

func TestWindowsPKINITConf(t *testing.T) {
	c := winPKINITConf(winKDCInNet)
	for _, want := range []string{"default_realm = CORP.EXAMPLE.COM", "kdc = 172.30.44.10:88", "pkinit_anchors = FILE:/l44/adcs-root.pem",
		"pkinit_anchors = FILE:/l44/lab-users-ca.pem", "pkinit_anchors = FILE:/l44/lab-users-comma-ca.pem",
		"pkinit_kdc_hostname = dc1.corp.example.com", "udp_preference_limit = 1", "dns_lookup_kdc = false"} {
		if !strings.Contains(c, want) {
			t.Errorf("lacks %q", want)
		}
	}
}

// MIT verifies its own certificate's chain before it asks the KDC, so it needs
// the issuer as an anchor: the lab users CA and the per-run comma CA sign the
// comma and highbit certificates directly. perRun writes each one where the
// client's krb5.conf anchors it.
func TestWindowsPKINITAnchorsTheLabCAs(t *testing.T) {
	b, err := os.ReadFile("windows_test.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	if !strings.Contains(src, `winWriteFile0600(t, filepath.Join(w.dir, "pkinit", ca.name+".pem"), winPEMCert(ca.c))`) {
		t.Error("perRun does not write each lab CA into the pkinit directory")
	}
	names := []string{"lab-users-ca"}
	for _, q := range winQuirks {
		names = append(names, q.file())
	}
	if !strings.Contains(src, `[]trustCA{{"lab-users-ca", d.pki.usersCA, ""}}`) || !strings.Contains(src, "trustCA{q.file(), q.cert, q.slug}") {
		t.Error("perRun does not trust the lab users CA and every quirk CA")
	}
	for _, name := range names {
		if !strings.Contains(winPKINITConf(winKDCInNet), "FILE:/l44/"+name+".pem") {
			t.Errorf("krb5.conf does not anchor %s", name)
		}
	}
}

func TestWindowsJudges(t *testing.T) {
	for id, want := range map[int]bool{19: true, 21: true, 29: true, 39: false, 40: false, 41: false, 48: false, 49: false} {
		if winKDCPrecondition(id) != want {
			t.Errorf("event %d", id)
		}
	}
	for code, want := range map[int]bool{62: true, 63: true, 64: true, 65: true, 66: false, 70: true, 71: true, 72: true,
		73: true, 74: true, 75: true, 76: true, 77: true, 78: true, 24: false, 6: false, 18: false} {
		if winKDCSetupCode(code) != want {
			t.Errorf("KDC error %d", code)
		}
	}
	now := time.Now()
	if !winSkewOK(now.Add(59*time.Second), now, time.Minute) || winSkewOK(now.Add(-61*time.Second), now, time.Minute) ||
		winSkewOK(now.Add(61*time.Second), now, time.Minute) || !winSkewOK(now.Add(-59*time.Second), now, time.Minute) {
		t.Error("skew")
	}
	created := now.Add(-time.Hour)
	young := &x509.Certificate{NotBefore: now.Add(-time.Minute)}
	old := &x509.Certificate{NotBefore: now.Add(-2 * time.Hour)}
	if winIssuedAfter(created, &x509.Certificate{NotBefore: created}) == nil {
		t.Error("a certificate issued the instant the account was created reads as after it")
	}
	if winIssuedAfter(created, young) != nil || winIssuedAfter(created, young, old) == nil {
		t.Error("backdating")
	}
	if !winOnlyValue([]string{"X509:<I>A<SR>01"}, "x509:<i>a<sr>01") || winOnlyValue([]string{"a", "b"}, "a") ||
		!winOnlyValue(nil, "") || winOnlyValue([]string{"a"}, "") {
		t.Error("winOnlyValue")
	}
}

// The DC's image is pinned by digest, the ISO is mounted read-only from the
// verified cache, and every published port is on loopback.
func TestWindowsComposePinsTheImage(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("directory", "windows", "compose.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.Contains(s, "image: "+winImage+"\n") || !strings.Contains(s, ":/custom.iso:ro") {
		t.Fatal("compose.yaml does not pin the image or mount the ISO read-only")
	}
	if !strings.Contains(s, "image: port49lab/pkinit:fedora43\n") {
		t.Error("compose.yaml does not tag the pkinit image fedora43")
	}
	for _, line := range strings.Split(s, "\n") {
		if m := regexp.MustCompile(`^\s+- "(\S+)"$`).FindStringSubmatch(line); m != nil && regexp.MustCompile(`^\d`).MatchString(m[1]) {
			if !strings.HasPrefix(m[1], "127.0.0.1:") {
				t.Errorf("a port published beyond loopback: %s", m[1])
			}
		}
	}
}

var (
	winPSParamRe = regexp.MustCompile(`(?m)^param\(([^)]*)\)\s*$`)
	winPSNameRe  = regexp.MustCompile(`\$([a-z0-9_]+)`) // port49_password has a digit
)

// Every script is in winScripts with the params its param() block declares,
// in order, and stops on its first error.
func TestWindowsScriptsTakeTheirParams(t *testing.T) {
	ents, err := winScriptFS.ReadDir("directory/windows/scripts")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, e := range ents {
		name := strings.TrimSuffix(e.Name(), ".ps1")
		src, _ := winScriptFS.ReadFile("directory/windows/scripts/" + e.Name())
		want, ok := winScripts[name]
		if !ok {
			t.Errorf("%s is not in winScripts", name)
			continue
		}
		seen[name] = true
		m := winPSParamRe.FindSubmatchIndex(src)
		if m == nil {
			t.Errorf("%s: no param() line", name)
			continue
		}
		var got []string
		for _, n := range winPSNameRe.FindAllStringSubmatch(string(src[m[2]:m[3]]), -1) {
			got = append(got, n[1])
		}
		if !slices.Equal(got, want) {
			t.Errorf("%s declares %v, winScripts says %v", name, got, want)
		}
		if !strings.HasPrefix(strings.TrimLeft(string(src[m[1]:]), "\r\n"), "$ErrorActionPreference = 'Stop'") {
			t.Errorf("%s: the line after param() is not $ErrorActionPreference = 'Stop'", name)
		}
	}
	for name := range winScripts {
		if !seen[name] {
			t.Errorf("winScripts names %s, which has no script", name)
		}
	}
}

var (
	// winPSAssign is a variable (or one of its members or elements) assigned on
	// one line: its name and right side.
	winPSAssign = regexp.MustCompile(`^\s*\$([A-Za-z0-9_:]+)(?:\.\w+|\[[^\]]*\])*\s*\+?=\s*(.*)$`)
	winPSMkr    = regexp.MustCompile(`New-Lab(?:Secret|Plain)`)
	// winPSConsumes starts an expression whose result is not its arguments:
	// what these cmdlets are given does not come back out.
	winPSConsumes = regexp.MustCompile(`^(?:Invoke-Command|Set-ADAccountPassword|New-ADUser|Install-ADDSForest)\b`)
	// winPSIndirect reaches a variable by a name or through the call, so the
	// scan cannot see which one: no script does.
	winPSIndirect = regexp.MustCompile(`(?i)PSBoundParameters|MyInvocation|Get-Variable|\bgv\b|variable:|\$args\b|\$input\b|` +
		`Invoke-Expression|\biex\b|ExecutionContext|PSVariable|GetValue|ExpandString|\[scriptblock\]::Create|NewScriptBlock`)
	winPSFnDef = regexp.MustCompile(`^function (New-Lab(?:Secret|Plain)) \{$`)
)

// winJoinContinued joins each line that ends in a backtick or a pipe onto the
// next, so a statement is scanned whole; a joined line sits at its first
// line's index and the lines it ate are empty.
func winJoinContinued(lines []string) []string {
	out := make([]string, len(lines))
	for i := 0; i < len(lines); i++ {
		l := strings.TrimRight(lines[i], " \t\r")
		j := i
		for j+1 < len(lines) && (strings.HasSuffix(l, "`") || strings.HasSuffix(l, "|")) {
			j++
			if strings.HasSuffix(l, "`") {
				l = strings.TrimSuffix(l, "`")
			}
			l += " " + strings.TrimSpace(lines[j])
			l = strings.TrimRight(l, " \t\r")
		}
		out[i] = l
		i = j
	}
	return out
}

// winUseRe finds a use of any of vars, in any case (PowerShell's names are
// case-insensitive): $v, ${v}, or $using:v, $script:v and the like. Group 1 is
// the name as written.
func winUseRe(vars []string) *regexp.Regexp {
	q := make([]string, len(vars))
	for i, v := range vars {
		q[i] = regexp.QuoteMeta(v)
	}
	return regexp.MustCompile(`(?i)\$\{?(?:(?:using|script|global|local|private):)?(` + strings.Join(q, "|") + `)\b`)
}

// winSecretVars is the variables of a script that hold a secret: its secret
// parameters, whatever is assigned from New-LabSecret or New-LabPlain, and
// whatever is assigned from any expression that uses one of those (a
// concatenation, a conversion, a member), except the result of a cmdlet that
// only consumes it.
func winSecretVars(lines []string) []string {
	lines = winJoinContinued(lines)
	vars := append([]string(nil), winSecretParams...)
	for changed := true; changed; {
		changed = false
		use := winUseRe(vars)
		for _, l := range lines {
			m := winPSAssign.FindStringSubmatch(l)
			if m == nil || slices.Contains(vars, strings.ToLower(m[1])) {
				continue
			}
			if winPSConsumes.MatchString(strings.TrimLeft(m[2], "( ")) {
				continue
			}
			if winPSMkr.MatchString(m[2]) || use.MatchString(m[2]) {
				vars = append(vars, strings.ToLower(m[1]))
				changed = true
			}
		}
	}
	return vars
}

// winSecretForm is a line shape a secret may appear in, and how many uses of a
// secret (a secret variable, or a New-Lab call) the line has.
type winSecretForm struct {
	re   *regexp.Regexp
	uses int
}

// winSecretForms are the eight shapes the scripts use a secret in; {S} is a
// secret variable. Each hands the secret to a cmdlet or exe that consumes it and
// cannot print it; anything else that touches one is refused, so a new use is
// reviewed and added here on purpose.
func winSecretForms(sv string) []winSecretForm {
	var out []winSecretForm
	for _, f := range []struct {
		re   string
		uses int
	}{
		{`^\$\w+ = New-LabPlain$`, 1},
		{`^\$\w+ = ConvertTo-SecureString {S} -AsPlainText -Force$`, 1},
		{`^Set-ADAccountPassword (?:\$user|port49) -Reset -NewPassword {S}$`, 1},
		{`^Set-ADAccountPassword \$user -Reset -NewPassword \(ConvertTo-SecureString \(New-LabPlain\) -AsPlainText -Force\)$`, 1},
		{`^\$\w+ = New-Object Management\.Automation\.PSCredential \("CORP\\\$user", {S}\)$`, 1},
		{`^\$\w+ = Invoke-Command [^{|;]*-Credential {S} [^{|;]*-ScriptBlock \{$`, 1},
		{`^& ktpass\.exe [^|;>]*-pass {S} [^|;>]*\*> \$null$`, 1},
		{`^Install-ADDSForest [^|;>]*-SafeModeAdministratorPassword {S} [^|;>]*\| Out-Null$`, 1},
		{`^New-ADUser [^|;>]*-AccountPassword (?:{S}|\(New-LabSecret\))(?: [^|;>]*)?$`, 1},
		// L50's: l50_seed.ps1 resets an actor's password; write_as.ps1 makes a
		// credential from one and hands it to Set-ADObject, which consumes it.
		{`^Set-ADAccountPassword -Identity \$name -Reset -NewPassword {S}$`, 1},
		{`^\$\w+ = New-Object System\.Management\.Automation\.PSCredential\("\$nb\\\$user", \(ConvertTo-SecureString {S} -AsPlainText -Force\)\)$`, 1},
		{`^Set-ADObject -Identity \$dn -Replace @\{ \$attribute = \$value \} -Credential {S} -Server localhost$`, 1},
		// l50_dacl.ps1 hands the credential to New-ADUser and to an AD drive,
		// which consume it.
		{`^New-ADUser -Name \$name -SamAccountName \$name -Path \$ou -Server localhost -Credential {S}$`, 1},
		{`^New-PSDrive -Name L50 -PSProvider ActiveDirectory -Root '//RootDSE/' -Server localhost -Credential {S} \| Out-Null$`, 1},
	} {
		out = append(out, winSecretForm{regexp.MustCompile("(?i)" + strings.ReplaceAll(f.re, "{S}", sv)), f.uses})
	}
	return out
}

func winVarName(v string) string {
	if v == "New-Lab*" {
		return v
	}
	return "$" + v
}

// winSecretLeaks names each line of a script (by number and variable name,
// never by content) that uses a secret, or a variable built from one, in a form
// no winSecretForms entry allows. The bodies of New-LabSecret and New-LabPlain
// make the secret, so each must be exactly its reviewed text.
func winSecretLeaks(src string) []string {
	src = strings.ReplaceAll(src, "\r\n", "\n")
	raw := strings.Split(src, "\n")
	vars := winSecretVars(raw)
	use := winUseRe(vars)
	q := make([]string, len(vars))
	for i, v := range vars {
		q[i] = regexp.QuoteMeta(v)
	}
	forms := winSecretForms(`\$(?:` + strings.Join(q, "|") + `)\b`)
	var out []string
	pinned := map[string]string{"New-LabSecret": winLabSecretFn, "New-LabPlain": winLabPlainFn}
	exempt := map[int]bool{}
	for i := 0; i < len(raw); i++ {
		m := winPSFnDef.FindStringSubmatch(strings.TrimRight(raw[i], " \t"))
		if m == nil {
			continue
		}
		j := i
		for j+1 < len(raw) && strings.TrimRight(raw[j], " \t") != "}" {
			j++
		}
		if strings.Join(raw[i:j+1], "\n")+"\n" != pinned[m[1]] {
			out = append(out, fmt.Sprintf("line %d: %s is not its reviewed text", i+1, m[1]))
		}
		for k := i; k <= j; k++ {
			exempt[k] = true
		}
		i = j
	}
	for i, l := range winJoinContinued(raw) {
		tl := strings.TrimSpace(l)
		if exempt[i] || strings.HasPrefix(tl, "param(") || strings.HasPrefix(tl, "#") {
			continue
		}
		if winPSIndirect.MatchString(l) {
			out = append(out, fmt.Sprintf("line %d reaches a variable by name or through the call", i+1))
			continue
		}
		rhs := l
		if m := winPSAssign.FindStringSubmatch(l); m != nil {
			rhs = m[2]
		}
		uses := use.FindAllStringSubmatch(rhs, -1)
		n := len(uses) + len(winPSMkr.FindAllString(rhs, -1))
		if n == 0 {
			continue
		}
		ok := false
		for _, f := range forms {
			ok = ok || f.uses == n && f.re.MatchString(tl)
		}
		if !ok {
			v := "New-Lab*"
			if len(uses) > 0 {
				v = uses[0][1]
			}
			out = append(out, fmt.Sprintf("line %d uses %s in a form no approved pattern allows", i+1, winVarName(v)))
		}
	}
	return out
}

// No script writes a secret anywhere: not to the output, a file, a result key
// or an exception's text. Per-user passwords are made inside the VM, where the
// host can never scrub them, so this is the only guard they have.
func TestWindowsScriptsNeverEchoASecret(t *testing.T) {
	ents, _ := winScriptFS.ReadDir("directory/windows/scripts")
	for _, e := range ents {
		src, _ := winScriptFS.ReadFile("directory/windows/scripts/" + e.Name())
		for _, leak := range winSecretLeaks(string(src)) {
			t.Errorf("%s: %s", e.Name(), leak)
		}
	}
}

// The two functions that make a secret, as the scripts carry them. The scan
// compares each body with these, so a change to one (a debugging Write-Host,
// say) fails and is reviewed.
const (
	winLabSecretFn = `function New-LabSecret {
  $b = New-Object byte[] 12
  [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
  ConvertTo-SecureString ('Aa1!' + (($b | ForEach-Object { $_.ToString('x2') }) -join '')) -AsPlainText -Force
}
`
	winLabPlainFn = `function New-LabPlain {
  $b = New-Object byte[] 12
  [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
  'Aa1!' + (($b | ForEach-Object { $_.ToString('x2') }) -join '')
}
`
)

// The scan finds the variables the scripts make secret, passes the eight forms
// the scripts use a secret in, and fails any other use of a secret or of a
// variable built from one.
func TestWindowsSecretScanFlagsALeak(t *testing.T) {
	src, _ := winScriptFS.ReadFile("directory/windows/scripts/enroll_as.ps1")
	got := winSecretVars(strings.Split(string(src), "\n"))
	for _, want := range []string{"plain", "sec", "cred"} {
		if !slices.Contains(got, want) {
			t.Errorf("enroll_as: $%s is not seen as a secret", want)
		}
	}
	// $p and $s are secrets (made, and built from one); $port49_password is a param.
	base := "param([string]$port49_password)\n$ErrorActionPreference = 'Stop'\n$p = New-LabPlain\n" +
		"$s = ConvertTo-SecureString $p -AsPlainText -Force\n"
	if got := winSecretLeaks(base); len(got) != 0 {
		t.Fatalf("the base of the table leaks: %v", got)
	}
	for _, c := range []struct {
		line string
		bad  bool
	}{
		// What the first deny-list scan caught.
		{"Write-Output $port49_password", true},
		{"Write-Host $p", true},
		{"$p | Out-File C:\\x", true},
		{"throw \"bad: $s\"", true},
		{"$m = \"pw=$p\"", true},
		{"@{ password = $s }", true},
		{"@{ a = 1; b = New-LabPlain }", true},
		// What the second caught.
		{"$p", true},
		{"$p.Length; $p", true},
		{"$p > C:\\x.txt", true},
		{"$p >> C:\\x.txt", true},
		{"[Console]::Out.WriteLine($p)", true},
		{"$host.UI.WriteLine($p)", true},
		{"[IO.File]::WriteAllText('C:\\x', $p)", true},
		{"[IO.File]::AppendAllText('C:\\x', $p)", true},
		{"$PSCmdlet.WriteObject($p)", true},
		{"$p | ConvertTo-Json", true},
		{"Export-Clixml -InputObject $p", true},
		{"Out-Default -InputObject $p", true},
		{"New-ItemProperty -Path HKLM:\\x -Name n -Value $p", true},
		{"$r = @{}\n$r.pw = $p\n$r", true},
		{"Write-Output `\n$p", true},
		{"$p |\nOut-File C:\\x", true},
		{"$x = 'pw' + $p\n@{ k = $x }", true},
		{"$x = 'pw' + $p\n$x", true},
		{"return $p", true},
		// What only an allow-list catches.
		{"($p)", true},
		{"@($p)", true},
		{",$p", true},
		{"[string]$p", true},
		{"\"{0}\" -f $p", true},
		{"'{0}' -f $p", true},
		{"write $p", true},
		{"sc C:\\x $p", true},
		{"if ($true) { $p }", true},
		{"& { $p }", true},
		{"foreach ($c in $p.ToCharArray()) { $c }", true},
		{"[Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($s))", true},
		{"$s", true},
		{"write $s", true},
		{"function f($x) { $x }\nf $p", true},
		{"$x = Invoke-Command { $using:p }\n@{ k = $x }", true},
		{"Invoke-Command { param($a) $a } -ArgumentList $p", true},
		{"Set-ADUser alice -Description $p", true},
		{"Set-ADUser alice -Description $s", true},
		{"${p}", true},
		{"$script:p", true},
		{"Write-Output $PSBoundParameters", true},
		{"(Get-Variable p).Value", true},
		{"$x = Invoke-Command -ComputerName c -Credential $s -ArgumentList $p -ScriptBlock {", true},
		// The eight forms.
		{"$q = New-LabPlain", false},
		{"$q = ConvertTo-SecureString $p -AsPlainText -Force", false},
		{"Set-ADAccountPassword $user -Reset -NewPassword $s", false},
		{"Set-ADAccountPassword port49 -Reset -NewPassword $s", false},
		{"Set-ADAccountPassword $user -Reset -NewPassword (ConvertTo-SecureString (New-LabPlain) -AsPlainText -Force)", false},
		{"$c = New-Object Management.Automation.PSCredential (\"CORP\\$user\", $s)", false},
		{"$pem = Invoke-Command -ComputerName c -Credential $s -Authentication Credssp -ScriptBlock {\n}", false},
		{"& ktpass.exe -pass $port49_password -out $o *> $null", false},
		{"& ktpass.exe `\n  -pass $port49_password *> $null", false},
		{"Install-ADDSForest -DomainName x -SafeModeAdministratorPassword $s -Force | Out-Null", false},
		{"New-ADUser -Name a -AccountPassword $s -Enabled $true", false},
		{"New-ADUser -Name a -AccountPassword (New-LabSecret) -Enabled $true", false},
		{"@{ ok = $true }", false},
		{winLabSecretFn, false},
		{winLabPlainFn, false},
		{"$Q = New-LabPlain", false},
		{"set-adaccountpassword $USER -Reset -NewPassword $S", false},
		// Round 3: case, reaching a variable without naming it, the two function bodies.
		{"Write-Output $P", true},
		{"Write-Output $PORT49_PASSWORD", true},
		{"$S | ConvertFrom-SecureString", true},
		{"$q = New-LabPlain\n$Q", true},
		{"$q = New-LabPlain\nWrite-Output $Q", true},
		{"$ExecutionContext.SessionState.PSVariable.GetValue('p')", true},
		{"$ExecutionContext.InvokeCommand.ExpandString('$' + 'p')", true},
		{"& ([scriptblock]::Create('$' + 'p'))", true},
		{"Get-Item variable:p", true},
		{"Invoke-Expression '$p'", true},
		{"iex '$p'", true},
		{"function New-LabSecret {\n  Write-Output $port49_password\n}", true},
		{"function New-LabPlain {\n  [Console]::WriteLine($p)\n}", true},
		{strings.Replace(winLabPlainFn, "12", "13", 1), true},
		{winLabSecretFn + "Write-Output $p", true},
	} {
		if got := winSecretLeaks(base + c.line + "\n"); (len(got) > 0) != c.bad {
			t.Errorf("%q: flagged=%v, want %v", c.line, len(got) > 0, c.bad)
		}
	}
}

// ktpass runs in a child scope that does not stop on its first stderr line (it
// does under Windows PowerShell 5.1), all its text is thrown away unread, and
// success is its exit code and the file: no text of ktpass's, which can carry
// the derived key, reaches a variable, the result or an exception.
func TestWindowsKeytabDiscardsKtpassText(t *testing.T) {
	b, _ := winScriptFS.ReadFile("directory/windows/scripts/keytab.ps1")
	src := strings.ReplaceAll(string(b), "\r\n", "\n")
	joined := strings.Join(winJoinContinued(strings.Split(src, "\n")), "\n")
	var kt string
	for _, l := range strings.Split(joined, "\n") {
		if strings.Contains(l, "ktpass.exe") && !strings.HasPrefix(strings.TrimSpace(l), "#") {
			kt = l
		}
	}
	if kt == "" {
		t.Fatal("keytab.ps1 does not run ktpass.exe")
	}
	if !strings.HasPrefix(strings.TrimSpace(kt), "& ktpass.exe") || !strings.HasSuffix(strings.TrimSpace(kt), "*> $null") {
		t.Error("ktpass's call is not a bare statement ending in *> $null: its output could reach a variable or the result")
	}
	scope := strings.Index(src, "& {")
	cont := strings.Index(src, "$ErrorActionPreference = 'Continue'")
	if scope < 0 || cont < scope || cont > strings.Index(src, "ktpass.exe -princ") {
		t.Error("ktpass does not run in a child scope with $ErrorActionPreference = 'Continue'")
	}
	for _, want := range []string{"$LASTEXITCODE", "Test-Path $out"} {
		if !strings.Contains(src, want) {
			t.Errorf("keytab.ps1 does not judge ktpass by %s", want)
		}
	}
	for _, l := range strings.Split(src, "\n") {
		m := regexp.MustCompile(`throw\s+("[^"]*"|'[^']*')`).FindStringSubmatch(l)
		if m == nil {
			continue
		}
		for _, v := range winPSNameRe.FindAllStringSubmatch(strings.ToLower(m[1]), -1) {
			if v[1] != "code" {
				t.Errorf("keytab.ps1 throws with $%s, not only ktpass's exit code", v[1])
			}
		}
	}
}

// Every native command's exit code is checked within the lines after it.
func TestWindowsScriptsCheckNativeExitCodes(t *testing.T) {
	ents, _ := winScriptFS.ReadDir("directory/windows/scripts")
	native := regexp.MustCompile(`^\s*(?:&\s*)?[a-z]+\.exe\b`)
	for _, e := range ents {
		b, _ := winScriptFS.ReadFile("directory/windows/scripts/" + e.Name())
		lines := strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n")
		for i, l := range lines {
			if !native.MatchString(l) {
				continue
			}
			ok := false
			for _, n := range lines[i+1 : min(i+4, len(lines))] {
				ok = ok || strings.Contains(n, "LASTEXITCODE")
			}
			if !ok {
				t.Errorf("%s:%d: no $LASTEXITCODE check follows the native command", e.Name(), i+1)
			}
		}
	}
}

// The DC's name resolves to 127.0.0.1 in this process, in any case, and no
// other name resolves by way of it; localhost still comes from /etc/hosts.
func TestWindowsResolveDC(t *testing.T) {
	winResolveDC(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, name := range []string{winDCHost, strings.ToUpper(winDCHost)} {
		if got, err := net.DefaultResolver.LookupHost(ctx, name); err != nil || len(got) != 1 || got[0] != "127.0.0.1" {
			t.Errorf("%s resolves to %v (%v), want [127.0.0.1]", name, got, err)
		}
	}
	if got, err := net.DefaultResolver.LookupHost(ctx, "dc2.corp.example.com"); err == nil {
		t.Errorf("dc2.corp.example.com resolves to %v, want no such host", got)
	}
	if got, err := net.DefaultResolver.LookupHost(ctx, "localhost"); err != nil || len(got) == 0 {
		t.Errorf("localhost resolves to %v (%v)", got, err)
	}
}

// The Windows URIs name the DC, and no script adds an SPN for another name:
// port49's GSSAPI bind asks for ldap/<the URI's host>.
func TestWindowsURIsNameTheDC(t *testing.T) {
	src, _ := os.ReadFile("windows_test.go")
	for _, want := range []string{`uri: "ldaps://" + winDCHost + ":30636"`, `plainURI: "ldap://" + winDCHost + ":30389"`} {
		if !strings.Contains(string(src), want) {
			t.Errorf("windows_test.go does not set %s", want)
		}
	}
	run, res := strings.Index(string(src), "winResolveDC(t)"), strings.Index(string(src), "l := &labDir{name: platWindows")
	if run < 0 || res < 0 || run > res {
		t.Error("startWindowsDC does not call winResolveDC before it makes the Windows labDir")
	}
	ents, _ := winScriptFS.ReadDir("directory/windows/scripts")
	for _, e := range ents {
		b, _ := winScriptFS.ReadFile("directory/windows/scripts/" + e.Name())
		if strings.Contains(string(b), "ldap/localhost") {
			t.Errorf("%s adds ldap/localhost, which the DC does not keep", e.Name())
		}
	}
}

// Every certreq -submit writes to names of its own and removes them: certreq
// refuses an output file that exists (0x80070050), so a fixed name fails every
// try after the first (measured, gate run 8's enroll_as).
func TestWindowsCertreqSubmitUsesFreshNames(t *testing.T) {
	for _, name := range []string{"enroll_as.ps1", "issue.ps1"} {
		b, _ := winScriptFS.ReadFile("directory/windows/scripts/" + name)
		s := string(b)
		if !strings.Contains(s, "certreq.exe -submit") {
			t.Fatalf("%s runs no certreq -submit", name)
		}
		if !strings.Contains(s, "[guid]::NewGuid()") || !strings.Contains(s, "Remove-Item $in, $out, $rsp") {
			t.Errorf("%s does not name its request files by a fresh GUID and remove them", name)
		}
	}
}

// enroll_as registers the DC's WSMAN SPNs before it turns CredSSP on: without
// them CredSSP refuses the DC as an untrusted target (measured, gate run 5).
func TestWindowsEnrollAsRegistersWSMANSPNsFirst(t *testing.T) {
	b, _ := winScriptFS.ReadFile("directory/windows/scripts/enroll_as.ps1")
	s := string(b)
	spn, credssp := strings.Index(s, `"WSMAN/$env:COMPUTERNAME", "WSMAN/$fqdn"`), strings.Index(s, "Enable-WSManCredSSP")
	if spn < 0 || !strings.Contains(s, "setspn.exe -S $s $env:COMPUTERNAME") {
		t.Fatal("enroll_as.ps1 does not register WSMAN/<host> and WSMAN/<fqdn>")
	}
	if credssp < 0 || spn > credssp {
		t.Error("enroll_as.ps1 registers the WSMAN SPNs after it enables CredSSP")
	}
}

// A file is read as a plain string, never with Get-Content, which decorates
// what it returns with PSPath, PSProvider and the rest, and Windows
// PowerShell 5.1's ConvertTo-Json serializes those notes to -Depth 8: measured
// on the L44 DC, one CSR's Get-Content -Raw ran the bootstrap's ConvertTo-Json
// past 285 CPU seconds and 4.8 GB, where [IO.File]::ReadAllText took 18 ms.
// winGetContentRe is Get-Content, or its 5.1 aliases gc, cat and type, used as
// a command: at the line's start or after ( = | ; or {.
var winGetContentRe = regexp.MustCompile(`(?i)(?:^|[(=|;{])\s*(?:get-content|gc|cat|type)(?:\s|$)`)

func TestWindowsScriptResultsAreNotGetContent(t *testing.T) {
	for _, l := range []string{"Get-Content $out -Raw", "  @{ x = (gc $out -Raw) }", "$t = cat $f", "x | type", "{ type $p }"} {
		if !winGetContentRe.MatchString(l) {
			t.Errorf("the pattern misses %q", l)
		}
	}
	for _, l := range []string{"'RequestType = PKCS10'", "-PropertyType DWord", "$ca.Subject", "Set-Content $in $csr"} {
		if winGetContentRe.MatchString(l) {
			t.Errorf("the pattern flags %q", l)
		}
	}
	ents, _ := winScriptFS.ReadDir("directory/windows/scripts")
	for _, e := range ents {
		b, _ := winScriptFS.ReadFile("directory/windows/scripts/" + e.Name())
		for i, l := range strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n") {
			if strings.HasPrefix(strings.TrimSpace(l), "#") {
				continue
			}
			if winGetContentRe.MatchString(l) {
				t.Errorf("%s:%d: a file is read with Get-Content or an alias of it; read it with [IO.File]::ReadAllText", e.Name(), i+1)
			}
		}
	}
}

// A cleared attribute reads back as no values, not one empty string: a
// single-valued attribute that is unset is $null, and $null piped to
// ForEach-Object still runs once.
func TestWindowsSetAttrReadsBackNoValues(t *testing.T) {
	b, _ := winScriptFS.ReadFile("directory/windows/scripts/set_attr.ps1")
	if !strings.Contains(string(b), "Where-Object { $null -ne $_ } | ForEach-Object") {
		t.Error("set_attr.ps1 does not drop a $null attribute before it stringifies the values")
	}
}

// install.bat puts Windows in the UTC time zone, so a kept DC's container
// restart does not put it hours out (harness review M5), and never sets
// RealTimeIsUniversal, which put a fresh DC 7h behind.
func TestWindowsInstallBatSetsTheTimeZoneUTC(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("directory", "windows", "oem", "install.bat"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "Set-TimeZone -Id 'UTC'") {
		t.Error("install.bat does not set the UTC time zone")
	}
	if strings.Contains(string(b), "-Name RealTimeIsUniversal") {
		t.Error("install.bat sets RealTimeIsUniversal")
	}
}

// install.bat is a batch file: cmd.exe wants CRLF, and git keeps it so.
func TestWindowsInstallBatIsCRLF(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("directory", "windows", "oem", "install.bat"))
	if err != nil {
		t.Fatal(err)
	}
	if bare := strings.Count(strings.ReplaceAll(string(b), "\r\n", ""), "\n"); bare != 0 {
		t.Errorf("install.bat has %d lines without CR", bare)
	}
	ga, err := os.ReadFile(filepath.Join("..", "..", ".gitattributes"))
	if err != nil || !strings.Contains(string(ga), "tests/lab/directory/windows/oem/*.bat text eol=crlf") {
		t.Error(".gitattributes does not pin the oem batch files to CRLF")
	}
}

// The PKINIT image records the MIT Kerberos versions it was built with, in
// a file the note reads: the packages are not pinned, so the run must say.
func TestWindowsPKINITImageRecordsItsVersions(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("directory", "windows", "pkinit", "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "krb5-workstation krb5-pkinit krb5-libs > /etc/pkinit-versions") || !strings.Contains(string(b), "rpm -q --qf") {
		t.Error("the pkinit Dockerfile does not record the installed versions in /etc/pkinit-versions")
	}
}

// Windows Server 2025's KDC refuses FFDH PKINIT without MS-PKCA's paChecksum2
// (KDC error 79), which MIT added in 1.22 (commit 310793b). Debian stable has
// 1.20 and 1.21: the image must be one that ships 1.22 or later, pinned by digest.
func TestWindowsPKINITImageIsMIT122(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("directory", "windows", "pkinit", "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !regexp.MustCompile(`(?m)^FROM fedora:43@sha256:[0-9a-f]{64}$`).MatchString(s) {
		t.Error("the pkinit image is not Fedora 43 pinned by digest")
	}
	for _, want := range []string{"krb5-workstation", "krb5-pkinit", "paChecksum2", "310793b"} {
		if !strings.Contains(s, want) {
			t.Errorf("the pkinit Dockerfile lacks %q", want)
		}
	}
	if strings.Contains(s, "debian") || strings.Contains(s, "apt-get") {
		t.Error("the pkinit Dockerfile still builds on Debian")
	}
}

// The DC's password is in its container's environment (dockur reads it there),
// which docker's inspect and compose's config would print, and a command run in
// the container could print too. No lab code does any of them: docker on the lab
// box is root-equivalent and the lab single-occupant, so what is left is a
// careless print.
func TestLabNeverPrintsAContainerEnvironment(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	for _, f := range files {
		b, _ := os.ReadFile(f)
		if m := winLabEnvPrint.FindIndex(b); m != nil {
			t.Errorf("%s:%d prints a container environment", f, 1+strings.Count(string(b[:m[0]]), "\n"))
		}
	}
}

// The guard's pattern finds each way to print one, and passes the docker calls
// the lab does make. (Written with single quotes for double, so this file does
// not match itself.)
func TestLabEnvPrintPattern(t *testing.T) {
	q := func(s string) string { return strings.ReplaceAll(s, "'", "\"") }
	for _, c := range []struct {
		src string
		bad bool
	}{
		{"sg docker -c 'docker\tinspect c'", true},
		{"sg docker -c 'docker\tcompose -p x config'", true},
		{"exec.Command('docker', 'inspect', c)", true},
		{"dockerCmd('inspect', c)", true},
		{"dockerCmd('container', 'inspect', c)", true},
		{"d.dockerCompose('config')", true},
		{"w.dockerCompose('--profile', 'tools', 'config')", true},
		{"dockerCompose('-p', x, 'config', '--no-interpolate')", true},
		{"dockerCmd('compose', '-p', x, 'config')", true},
		{"dockerCmd('exec', c, 'env')", true},
		{"dockerCmd('exec', c, 'printenv', 'PASSWORD')", true},
		{"dockerCmd('exec', c, 'set')", true},
		{"dockerCmd('exec', '-i', c, 'sh', '-c', 'env')", true},
		{"d.dockerCompose('exec', 'dc', 'printenv')", true},
		{"exec.Command('docker', 'exec', c, 'env')", true},
		{"run('docker\texec c printenv PASSWORD')", true},
		{"run('docker\texec c env')", true},
		{"d.dockerCompose('convert')", true},
		{"sg docker -c 'docker\tcompose\tconvert'", true},
		{"dockerCmd('compose', '-p', x, 'convert')", true},
		{"dockerCmd('exec', c, 'cat', '/proc/1/" + "environ')", true},
		{"run('docker\texec c cat /proc/self/" + "environ')", true},
		{"dockerCmd('image', 'inspect', '--format', f, image)", false},
		{"exec.Command('docker', 'image', 'inspect', image)", false},
		{"exec.Command('sudo', '-n', 'containerlab', 'inspect', '-t', topo)", false},
		{"d.dockerCompose('up', '-d', '--wait')", false},
		{"d.dockerCompose('config_files')", false},
		{"dockerCmd('exec', c, 'cat', '/etc/pkinit-versions')", false},
		{"os.ReadFile('/proc/meminfo')", false},
		{"dockerCmd('exec', c, 'sh', '-c', 'cat /etc/hosts')", false},
		{"cfg := loadConfig('config')", false},
	} {
		if got := winLabEnvPrint.MatchString(q(c.src)); got != c.bad {
			t.Errorf("%q: matched=%v, want %v", c.src, got, c.bad)
		}
	}
}

// winLabEnvPrint is each way a lab file could print a container's environment:
// docker's inspect (not an image's), compose's config or its alias convert, a
// read of the process environment under /proc, or env, printenv or set run in the container by exec.
var winLabEnvPrint = regexp.MustCompile(`docker\s+inspect|docker\s+compose\b[^\n'"]*\b(?:config|convert)\b|compose\s+(?:config|convert)\b|/proc/[^"'\s]*environ|` +
	`docker\s+exec\b[^\n'"]*\b(?:printenv|env|set)\b|` +
	`[dD]ocker\w*\(\s*(?:"container",\s*)?"inspect"|"docker",\s*"inspect"|` +
	`[dD]ocker\w*\([^)\n]*"(?:config|convert)"|"compose"[^\n)]*"(?:config|convert)"|` +
	`"exec"[^)\n]*"(?:printenv|env|set)(?:\s[^"]*)?"`)

// The payload is one line, ended: the bootstrap reads up to the newline and
// never waits for stdin's end, which Windows OpenSSH lost in gate run 6 (the
// install step's powershell sat idle before its script began). A PEM's
// newlines travel escaped inside the JSON.
func TestWindowsPayloadIsOneEndedLine(t *testing.T) {
	b, err := winPayload("param($a)\r\n@{ b = $a }\n", map[string]any{"a": "-----BEGIN-----\nx\n-----END-----\n"})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(b, []byte("\n")) || bytes.Count(b, []byte("\n")) != 1 || bytes.ContainsRune(b, '\r') {
		t.Errorf("the payload is not one line ended by a newline: %d newlines", bytes.Count(b, []byte("\n")))
	}
	if !strings.Contains(winBootstrap, "[Console]::In.ReadLine()") || strings.Contains(winBootstrap, "ReadToEnd") {
		t.Error("the bootstrap does not read its payload as one line with [Console]::In.ReadLine()")
	}
}

// Windows PowerShell 5.1 writes [Console]::Out in the OEM code page, so the
// bootstrap sets UTF-8 (without a BOM, which would precede the JSON) before
// anything is read or written (stdin carries the params in the same page). Setting it throws without a console, so the line
// carries its own silent try/catch: a missing console must not stop a script.
func TestWindowsBootstrapSetsUTF8Output(t *testing.T) {
	set := "try { [Console]::OutputEncoding = New-Object Text.UTF8Encoding $false; " +
		"[Console]::InputEncoding = New-Object Text.UTF8Encoding $false } catch { }"
	i := strings.Index(winBootstrap, set)
	if i < 0 {
		t.Fatal("the bootstrap does not set [Console]::OutputEncoding and InputEncoding to UTF-8 without a BOM, in one try/catch { }")
	}
	for _, first := range []string{"WriteLine", "ReadLine"} {
		if w := strings.Index(winBootstrap, first); w >= 0 && w < i {
			t.Errorf("the bootstrap reaches %s before it sets the encodings", first)
		}
	}
}

// The script runs in a child scope, which reads its caller's variables: every
// one the bootstrap sets before it runs the script holds the params, secrets
// included, so each is private, and none is filled in a ForEach-Object block
// (a child scope of its own).
func TestWindowsBootstrapHidesTheParamsFromTheScript(t *testing.T) {
	run := strings.Index(winBootstrap, "$r = & $sb @p")
	if run < 0 {
		t.Fatal("the bootstrap does not run the script as $r = & $sb @p")
	}
	before := winBootstrap[:run]
	for _, m := range regexp.MustCompile(`(?m)^\s*\$(?:private:)?(\w+)\s*=`).FindAllStringSubmatch(before, -1) {
		switch m[1] {
		case "ErrorActionPreference", "ProgressPreference":
			continue
		}
		if !strings.Contains(before, "$private:"+m[1]+" =") {
			t.Errorf("$%s is set before the script runs, and is not private", m[1])
		}
	}
	for _, name := range []string{"in", "p", "prop", "sb"} {
		if !strings.Contains(before, "$private:"+name+" =") {
			t.Errorf("$%s is not declared private", name)
		}
	}
	if strings.Contains(winBootstrap, "ForEach-Object") || strings.Contains(winBootstrap, "$_.Name") {
		t.Error("the bootstrap fills the params in a ForEach-Object block")
	}
}

// $Error holds every record a redirected native command made, ktpass's text
// included: the bootstrap must never serialize or print it.
func TestWindowsBootstrapNeverTouchesError(t *testing.T) {
	if regexp.MustCompile(`(?i)\$error\b|\$global:error|Get-Variable|\$_\.(?:ErrorRecord|InvocationInfo|ScriptStackTrace)`).MatchString(winBootstrap) {
		t.Error("the bootstrap uses $Error or an error record's detail: only Exception.Message may leave")
	}
	if !strings.Contains(winBootstrap, "$_.Exception.Message") {
		t.Error("the bootstrap's error line is not just $_.Exception.Message")
	}
}

// The DC's runner holds every password and private key of the run; no format
// verb may print one (pre-flight M11), as a value or a pointer, and none may
// print a secret the runner reaches through its fields.
func TestWindowsDCPrintsNoSecret(t *testing.T) {
	secrets := []string{"Aa1!admin", "Aa1!dsrm", "Aa1!port49"}
	w := &winDC{sec: &winSecrets{AdminPassword: secrets[0], DSRMPassword: secrets[1]}, port49: secrets[2],
		invalid: []string{"sid: x"}}
	var out string
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d"} {
		out += fmt.Sprintf(verb+" "+verb+" ", w, *w)
	}
	for _, s := range secrets {
		if strings.Contains(out, s) || strings.Contains(out, hex.EncodeToString([]byte(s))) {
			t.Fatal("a secret printed")
		}
	}
	if !strings.Contains(out, winProject) {
		t.Fatalf("the runner does not print as its project: %s", out)
	}
}

// dockur's log is scrubbed of the run's secrets before it is cut: "never a
// password" in it is unmeasured, and cutting first could leave half of one.
func TestWindowsLogTailScrubsBeforeItTruncates(t *testing.T) {
	secrets := []string{"Aa1!adminpw0000", "Aa1!dsrmpw00000", "Aa1!port49pw000"}
	w := &winDC{sec: &winSecrets{AdminPassword: secrets[0], DSRMPassword: secrets[1]}, port49: secrets[2]}
	raw := "setup done\nPASSWORD=" + secrets[0] + "\nrestart " + secrets[1] + " ok\nsvc bind " + secrets[2]
	for n := 1; n <= len(raw)+1; n++ {
		got := w.scrubbedTail(raw, n)
		for _, s := range secrets {
			for i := 0; i+5 <= len(s); i++ {
				if strings.Contains(got, s[i:i+5]) {
					t.Fatalf("tail of %d bytes holds a piece of a secret", n)
				}
			}
		}
	}
	if got := w.scrubbedTail(raw, 1000); !strings.Contains(got, "setup done") || !strings.Contains(got, "<secret>") {
		t.Errorf("the tail lost the log or its marker: %q", got)
	}
}

// pkinit's /etc/pkinit-versions is rpm's "name<TAB>version-release" lines: the
// note records the versions the run measured, and drops any other text.
func TestWindowsMITVersions(t *testing.T) {
	got := winMITVersions("krb5-workstation\t1.22.2-4.fc43\nkrb5-pkinit\t1.22.2-4.fc43\nkrb5-libs\t1.22.2-4.fc43\n")
	want := "krb5-workstation 1.22.2-4.fc43, krb5-pkinit 1.22.2-4.fc43, krb5-libs 1.22.2-4.fc43"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if got := winMITVersions("cat: /etc/pkinit-versions: No such file or directory\n"); got != "" {
		t.Errorf("an error's text is not a version: %q", got)
	}
	if got := winMITVersions("package krb5-pkinit is not installed\n"); got != "" {
		t.Errorf("rpm's complaint is not a version: %q", got)
	}
	if got := winMITVersions(""); got != "" {
		t.Errorf("nothing read is not a version: %q", got)
	}
}

// A failed step's text is scrubbed before it is cut: cut first and half a
// password survives the scrub. Every oneLineMax in the DC's runner takes a
// winScrub, but the two that read the KDC's trace (no secret in it), and the
// only tailOf is the one inside scrubbedTail, which scrubs first (so logTail,
// the compose failures and down all go through it).
func TestWindowsScrubsBeforeItCuts(t *testing.T) {
	b, err := os.ReadFile("windows_test.go")
	if err != nil {
		t.Fatal(err)
	}
	var seen, tails int
	inScrubbedTail := false
	for i, l := range strings.Split(string(b), "\n") {
		trim := strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(l, "func (w *winDC) scrubbedTail("):
			inScrubbedTail = true
		case l == "}":
			inScrubbedTail = false
		}
		if strings.HasPrefix(trim, "//") {
			continue
		}
		if strings.Contains(l, "tailOf(") && !strings.HasPrefix(l, "func tailOf") {
			if tails++; !inScrubbedTail {
				t.Errorf("windows_test.go:%d: tailOf cuts text outside scrubbedTail", i+1)
			}
		}
		_, rest, ok := strings.Cut(l, "oneLineMax(")
		if !ok || strings.HasPrefix(trim, "func oneLineMax") {
			continue
		}
		if seen++; strings.HasPrefix(rest, "m[1], ") || strings.HasPrefix(rest, "s, ") || strings.HasPrefix(rest, "winScrub(") {
			continue
		}
		t.Errorf("windows_test.go:%d: oneLineMax is not given a winScrub", i+1)
	}
	if seen == 0 || tails == 0 {
		t.Error("the scan found no oneLineMax or tailOf call: it checks nothing")
	}
}

// A password sshd refuses is not the VM still starting: it never mends. A
// refusal that lasts ten minutes fails the wait at once; any other error, or
// a refusal after one, starts the count again.
func TestWindowsAuthWatch(t *testing.T) {
	refused := errors.New("windows clock: ssh: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain")
	other := errors.New("windows clock: ssh: dial tcp 127.0.0.1:30022: connect: connection refused")
	t0 := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	a := winAuthWatch{stall: winAuthStall}
	if a.observe(refused, t0) || a.observe(refused, t0.Add(9*time.Minute+59*time.Second)) {
		t.Error("a refusal under ten minutes stalls the wait")
	}
	if !a.observe(refused, t0.Add(10*time.Minute)) {
		t.Error("a refusal of ten minutes does not stall the wait")
	}
	a = winAuthWatch{stall: winAuthStall}
	a.observe(refused, t0)
	a.observe(other, t0.Add(5*time.Minute)) // the VM is not answering at all: not a refusal
	if a.observe(refused, t0.Add(10*time.Minute)) || a.observe(refused, t0.Add(19*time.Minute)) {
		t.Error("another error did not start the count again")
	}
	if !a.observe(refused, t0.Add(20*time.Minute)) {
		t.Error("ten minutes after the first refusal since the other error is not a stall")
	}
	if a.observe(nil, t0.Add(time.Hour)) || a.observe(refused, t0.Add(time.Hour+time.Minute)) {
		t.Error("a success did not reset the count")
	}
	// After the promotion's reboot the password is proved: no stall at all.
	a = winAuthWatch{}
	if a.observe(refused, t0) || a.observe(refused, t0.Add(time.Hour)) {
		t.Error("a wait with no stall set stalled on a refusal")
	}
}

// A session the reboot cut (no exit status) is not a bootstrap that wrote
// nothing; one that exited (with a status) and wrote nothing is.
func TestWindowsSessionCut(t *testing.T) {
	for _, c := range []struct {
		err  error
		cut  bool
		name string
	}{{nil, false, "ran to the end"}, {&ssh.ExitError{}, false, "exited with a status"},
		{&ssh.ExitMissingError{}, true, "ended without a status"}, {io.EOF, true, "the connection dropped"}} {
		if got := winSessionCut(c.err); got != c.cut {
			t.Errorf("%s: cut = %v, want %v", c.name, got, c.cut)
		}
	}
	for _, c := range []struct {
		e      winScriptErr
		broken bool
	}{{winScriptErr{}, true}, {winScriptErr{thrown: true}, false}, {winScriptErr{cut: true}, false}} {
		if got := c.e.bootstrapBroke(); got != c.broken {
			t.Errorf("%+v: bootstrapBroke = %v, want %v", c.e, got, c.broken)
		}
	}
}

// A dependent that will not start at once does not end registry.ps1: measured,
// Restart-Service NTDS -Force threw when DNS would not start just after NTDS,
// which left the KDC stopped and broke the next SSH logon. The restart's own
// errors are caught, and each service that was running is started inside the
// wait, again on every pass, until it runs or the deadline passes.
func TestWindowsRegistryStartsEveryServiceAgain(t *testing.T) {
	b, _ := winScriptFS.ReadFile("directory/windows/scripts/registry.ps1")
	s := string(b)
	if !strings.Contains(s, "try { Restart-Service $svc -Force } catch { }") {
		t.Error("registry.ps1's Restart-Service can end the script when a dependent will not start")
	}
	loop := strings.Index(s, "while ((Get-Service $s).Status -ne 'Running') {")
	start := strings.Index(s, "try { Start-Service $s } catch { }")
	if loop < 0 || start < loop {
		t.Error("registry.ps1 does not start each service again inside its wait")
	}
}

// An NTDS setting reboots the DC and never restarts NTDS: measured, lsass
// crashed in ntdsai.dll 15s after NTDS restarted on LdapEnforceChannelBinding
// 2. Both the change and its restore wait for a later boot than the one the
// change was made in, and the wait never fails fatally (a restore may run
// while a failure unwinds).
func TestWindowsRegistryRebootsForNTDS(t *testing.T) {
	b, _ := winScriptFS.ReadFile("directory/windows/scripts/registry.ps1")
	s := string(b)
	reboot := strings.Index(s, "if ($svc -eq 'NTDS') {")
	restart := strings.Index(s, "Restart-Service $svc")
	if reboot < 0 || restart < reboot || !strings.Contains(s[reboot:restart], "shutdown.exe /r /t 15") ||
		!strings.Contains(s[reboot:restart], "return @{") || !strings.Contains(s[reboot:restart], "boot = $boot") {
		t.Error("registry.ps1 must answer with the boot time and reboot for an NTDS setting before any Restart-Service")
	}
	if regexp.MustCompile(`(?i)restart-service\s+(-name\s+)?['"]?ntds`).MatchString(s) {
		t.Error("registry.ps1 restarts NTDS by name")
	}
	r, _ := winScriptFS.ReadFile("directory/windows/scripts/ready.ps1")
	if !strings.Contains(string(r), "boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime") {
		t.Error("ready.ps1 does not answer its boot time, so a reboot cannot be told from the boot before it")
	}
	src := func(file, fn string) string {
		b, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		s := string(b)
		i := strings.Index(s, ") "+fn+"(")
		if i < 0 {
			t.Fatalf("no func %s in %s", fn, file)
		}
		s = s[i:]
		if end := strings.Index(s, "\n}\n"); end >= 0 {
			s = s[:end]
		}
		return s
	}
	for _, c := range []struct{ file, fn string }{{"windows_test.go", "setRegistry"}, {"l44_test.go", "l44GuardRegistry"}} {
		body := src(c.file, c.fn)
		if !strings.Contains(body, `if r.Restarted == "reboot" {`) || !strings.Contains(body, "awaitReboot(t, r.Boot, winRebootWithin)") {
			t.Errorf("%s does not wait out the reboot an NTDS setting starts", c.fn)
		}
	}
	if aw := src("windows_test.go", "awaitReboot"); strings.Contains(aw, "Fatal") || !strings.Contains(aw, "winBootChanged(before, r.Boot)") {
		t.Error("awaitReboot must never fail fatally, and must wait for a boot other than the one before")
	}
}

// A reboot is a boot at least a minute later: LastBootUpTime moves when the
// clock is stepped within one boot, and an unreadable time proves nothing.
func TestWindowsBootChanged(t *testing.T) {
	const b = "2026-10-07T00:34:28.1234567Z"
	for _, c := range []struct {
		now  string
		want bool
	}{
		{b, false},
		{"2026-10-07T00:34:28.6234567Z", false},
		{"2026-10-07T00:34:58.1234567Z", false},
		{"2026-10-07T02:34:28.1234567Z", true},
		{"2026-10-07T00:36:00Z", true},
		{"2026-10-06T22:34:28Z", false},
		{"", false},
		{"not a time", false},
	} {
		if got := winBootChanged(b, c.now); got != c.want {
			t.Errorf("winBootChanged(%s, %q) = %v, want %v", b, c.now, got, c.want)
		}
	}
	if winBootChanged("garbage", "2026-10-07T02:34:28Z") {
		t.Error("an unreadable before proved a reboot")
	}
}

// The cells under LdapEnforceChannelBinding 2 keep their rows only when the
// DC's boot was read on both sides of them and did not change.
func TestL44RowsUnder2(t *testing.T) {
	cells := []l44Cell{{"gssapi under 2", "| gssapi under 2 | refused | 49 | 1s |\n"}, {"simple | under 2", "| simple | ok | 0 | 1s |\n"}}
	const b, later = "2026-10-07T00:34:28Z", "2026-10-07T00:40:00Z"
	rows, reason := l44RowsUnder2(cells, b, b, nil)
	if reason != "" || rows != cells[0].row+cells[1].row {
		t.Errorf("same boot: reason %q, rows %q", reason, rows)
	}
	for name, c := range map[string]struct {
		after string
		err   error
	}{"rebooted": {later, nil}, "unread": {"", errors.New("ssh: handshake failed: EOF")},
		"both unread": {"", errors.Join(errors.New("windows ready: ssh: EOF"), errors.New("windows ready: line one\nline two"))}} {
		rows, reason := l44RowsUnder2(cells, b, c.after, c.err)
		if reason == "" || strings.Count(rows, "INVALID (R6)") != 2 || strings.Contains(rows, "refused") ||
			!strings.Contains(rows, `simple \| under 2`) || strings.Count(rows, "\n") != 2 {
			t.Errorf("%s: reason %q, rows %q", name, reason, rows)
		}
	}
}

// events.ps1 asks only for providers this build registered: measured,
// Get-WinEvent threw "The parameter is incorrect" past -ErrorAction for the
// older KDC names, and the whole events read failed.
func TestWindowsEventsAskOnlyRegisteredProviders(t *testing.T) {
	b, _ := winScriptFS.ReadFile("directory/windows/scripts/events.ps1")
	s := string(b)
	list := strings.Index(s, "Get-WinEvent -ListProvider $names")
	if list < 0 || !strings.Contains(s, "foreach ($p in $registered) { @{ LogName = 'System'; ProviderName = $p;") {
		t.Error("events.ps1 does not filter by the providers -ListProvider found")
	}
	if regexp.MustCompile(`ProviderName\s*=\s*'`).MatchString(s) {
		t.Error("events.ps1 names a provider in a filter without checking it is registered")
	}
}

// No fatal step runs between the boot reads around the cells under 2: a DC
// going down there must make the cells INVALID, not end the run first.
func TestL44NothingFatalBetweenTheBootReads(t *testing.T) {
	body := l44Func(t, "l44Binds")
	i, j := strings.Index(body, "bootBefore, berr := w.bootNow()"), strings.Index(body, "bootAfter, aerr := w.bootNow()")
	if i < 0 || j < i {
		t.Fatal("l44Binds does not read the boot around the cells under 2")
	}
	for _, fatal := range []string{"setAltSec(", "w.run(", "Fatal", "setRegistry(", "waitLDAPS("} {
		if strings.Contains(body[i:j], fatal) {
			t.Errorf("l44Binds runs %s between the boot reads", fatal)
		}
	}
}

// registry.ps1 waits up to N minutes for the KDC itself; the Go side outlasts it,
// or a cell would read a DC that is still restarting.
func TestWindowsRegistryDeadlineOutlastsTheScript(t *testing.T) {
	b, _ := winScriptFS.ReadFile("directory/windows/scripts/registry.ps1")
	m := regexp.MustCompile(`AddMinutes\((\d+)\)`).FindSubmatch(b)
	if m == nil {
		t.Fatal("registry.ps1 has no AddMinutes deadline to compare")
	}
	n, _ := strconv.Atoi(string(m[1]))
	if winRegistryWithin < time.Duration(n+2)*time.Minute {
		t.Errorf("registry's deadline %s does not outlast the script's %d minutes by two", winRegistryWithin, n)
	}
}

// A kept DC holds each earlier run's LDAPS certificate: ldaps.ps1 removes the
// ones the lab CA issued from the NTDS store, by name and never the rest, before
// it installs the new one.
func TestWindowsLDAPSRemovesEarlierLabCertificates(t *testing.T) {
	b, _ := winScriptFS.ReadFile("directory/windows/scripts/ldaps.ps1")
	src := strings.ReplaceAll(string(b), "\r\n", "\n")
	after := strings.Index(src, "$t = ")
	rm := strings.Index(src[after:], "Remove-Item") + after
	cp := strings.Index(src, "Invoke-Bounded 'reg_copy'")
	if after < 0 || rm < after || cp < rm {
		t.Fatal("ldaps.ps1 does not remove earlier certificates before it copies the new one")
	}
	block := src[strings.LastIndex(src[:cp], "Get-ChildItem"):cp]
	for _, want := range []string{"Cert:\\LocalMachine\\My", "$_.Issuer -eq $labCA.Subject", "$_.Thumbprint -ne $t",
		"Services\\NTDS\\SystemCertificates\\My\\Certificates\\$($_.Thumbprint)"} {
		if !strings.Contains(block, want) {
			t.Errorf("the removal does not hold %q", want)
		}
	}
}

// The VM's disk lives in Docker's data root, which may be another filesystem
// than the repository's: its free space is read from the nearest directory
// that can be read (the root itself is not world-readable).
func TestWindowsStatfsUp(t *testing.T) {
	dir := t.TempDir()
	free, at, err := winStatfsUp(filepath.Join(dir, "no", "such", "dir"))
	if err != nil || free == 0 || at != dir {
		t.Errorf("free %d at %q (want %q), err %v", free, at, dir, err)
	}
}

// The ISO's download fails on its deadline, or when no byte comes for idle;
// a slow download that keeps moving goes on; it says how far it got.
func TestWindowsDownloadStallsAndLogs(t *testing.T) {
	body := strings.Repeat("x", 3000)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/silent" {
			w.Header().Set("Content-Length", "100000")
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			return
		}
		if r.URL.Path == "/slow" {
			for i := 0; i < 6; i++ {
				_, _ = w.Write([]byte("y"))
				w.(http.Flusher).Flush()
				time.Sleep(100 * time.Millisecond)
			}
			return
		}
		if r.URL.Path == "/stall" {
			w.Header().Set("Content-Length", "100000")
			_, _ = w.Write([]byte("start"))
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	part := filepath.Join(t.TempDir(), "x.part")
	var logs []string
	logf := func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) }
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := winDownloadTo(ctx, srv.URL+"/stall", part, 1000, time.Hour, logf); err == nil || time.Since(start) > 5*time.Second {
		t.Errorf("a stalled download did not fail at its deadline: %v after %s", err, time.Since(start))
	}
	start = time.Now()
	if err := winDownloadTo(context.Background(), srv.URL+"/stall", part, 1000, 300*time.Millisecond, logf); err == nil ||
		!strings.Contains(err.Error(), "no byte for") || time.Since(start) > 5*time.Second {
		t.Errorf("a stalled download did not fail when idle: %v after %s", err, time.Since(start))
	}
	start = time.Now()
	if err := winDownloadTo(context.Background(), srv.URL+"/silent", part, 1000, 300*time.Millisecond, logf); err == nil ||
		!strings.Contains(err.Error(), "no byte for") || time.Since(start) > 5*time.Second {
		t.Errorf("a download that never sent a byte did not fail when idle: %v after %s", err, time.Since(start))
	}
	// Slow but moving: a byte every 100ms for 600ms, with idle 300ms, completes.
	start = time.Now()
	if err := winDownloadTo(context.Background(), srv.URL+"/slow", part, 1000, 300*time.Millisecond, logf); err != nil {
		t.Errorf("a slow download that kept moving failed: %v after %s", err, time.Since(start))
	}
	if err := winDownloadTo(context.Background(), srv.URL+"/ok", part, 1000, time.Hour, logf); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(part); string(got) != body {
		t.Errorf("the download wrote %d bytes, want %d", len(got), len(body))
	}
	if len(logs) == 0 {
		t.Error("the download logged no progress")
	}
}

func TestL44EventsCell(t *testing.T) {
	evs := []winEvent{{ID: 39, Provider: "Microsoft-Windows-Kerberos-Key-Distribution-Center", Message: "No strong | mapping for alice"},
		{ID: 3075, Provider: "Microsoft-Windows-ActiveDirectory_DomainService", Message: "x"}}
	got := l44EventsCell(evs)
	if !strings.Contains(got, "KDC 39: No strong \\| mapping") || !strings.Contains(got, "DS 3075") || strings.Contains(got, " | ") {
		t.Fatalf("%q", got)
	}
	if l44EventsCell(nil) != "(none)" {
		t.Fatal("none")
	}
	if ids := l44PreconditionIDs([]winEvent{{ID: 21, Provider: "Microsoft-Windows-Kerberos-Key-Distribution-Center"}, {ID: 21, Provider: "Schannel"}}); len(ids) != 1 {
		t.Fatalf("%v: only a KDC's 19, 21 or 29 is a setup failure", ids)
	}
}

func TestL44MatrixRow(t *testing.T) {
	r := winPKINITResult{ok: false, kdcErrs: []string{"-1765328359/Additional pre-authentication required", "-1765328318/KDC_ERR_CERTIFICATE_MISMATCH"},
		last: "kinit: Certificate mismatch while getting initial credentials", took: 1500 * time.Millisecond}
	row := l44MatrixRow("2", "AD CS `OfflineRouter`", "", l44Judge(r, nil, ""), r, nil)
	for _, want := range []string{"| 2 | AD CS `OfflineRouter` | (none) | refused |", "KDC_ERR_CERTIFICATE_MISMATCH", "| (none) | 1.5s |"} {
		if !strings.Contains(row, want) {
			t.Errorf("row lacks %q: %s", want, row)
		}
	}
	ok := winPKINITResult{ok: true}
	if !strings.Contains(l44MatrixRow("absent", "x", "X509:<I>A<SR>01", l44Judge(ok, nil, ""), ok, nil), "**TGT issued**") {
		t.Error("an accepted cell does not say so")
	}
}

// A refusal is the KB5014754 verdict only when its cause is proven: the
// block's control got a TGT, the KDC itself refused, and nothing it said or
// logged is a setup failure. Anything else is INVALID, never "refused"
// (pre-flight C3).
func TestL44Judge(t *testing.T) {
	pre := "-1765328359/Additional pre-authentication required"
	big := "-1765328332/Response too big for UDP, retry with TCP"
	mismatch := winPKINITResult{kdcErrs: []string{pre, "-1765328318/KDC_ERR_CERTIFICATE_MISMATCH"}}
	client := winPKINITResult{kdcErrs: []string{pre}, last: "kinit: Certificate verification failed while verifying KDC certificate"}
	trust := winPKINITResult{kdcErrs: []string{pre, "-1765328322/Client not trusted"}}
	retryThenRefused := winPKINITResult{kdcErrs: []string{pre, big, pre, "-1765328318/KDC_ERR_CERTIFICATE_MISMATCH"}}
	retryOnly := winPKINITResult{kdcErrs: []string{pre, big}, last: "kinit: Cannot contact any KDC"}
	retryThenTGT := winPKINITResult{ok: true, kdcErrs: []string{pre, big}}
	kdc21 := []winEvent{{ID: 21, Provider: "Microsoft-Windows-Kerberos-Key-Distribution-Center"}}
	for name, tc := range map[string]struct {
		r       winPKINITResult
		evs     []winEvent
		control string
		want    string
	}{
		"verdict":                {mismatch, nil, "", "refused"},
		"tgt":                    {winPKINITResult{ok: true}, nil, "", "**TGT issued**"},
		"client side":            {client, nil, "", "INVALID (R6): the KDC refused nothing"},
		"validation code":        {trust, nil, "", "INVALID (R6): KDC error 62"},
		"setup event":            {mismatch, kdc21, "", "INVALID (R6): the KDC logged [21]"},
		"control failed":         {mismatch, nil, "control-ski got no TGT", "INVALID (R6): control-ski got no TGT"},
		"tgt, control failed":    {winPKINITResult{ok: true}, nil, "control-ski got no TGT", "INVALID (R6): control-ski got no TGT"},
		"udp retry then refused": {retryThenRefused, nil, "", "refused"},
		"udp retry alone":        {retryOnly, nil, "", "INVALID (R6): the KDC refused nothing"},
		"udp retry then tgt":     {retryThenTGT, nil, "", "**TGT issued**"},
	} {
		if got := l44Judge(tc.r, tc.evs, tc.control); !strings.HasPrefix(got, tc.want) {
			t.Errorf("%s: %q, want a prefix %q", name, got, tc.want)
		}
	}
	if got := l44Judge(mismatch, nil, ""); got != "refused" {
		t.Errorf("a verdict is exactly %q, got %q", "refused", got)
	}
}

// An EXTERNAL cell says why it is INVALID, or what the DC mapped the
// certificate to when it bound (pre-flight I2, M12).
func TestL44ExtRow(t *testing.T) {
	x := l44Ext{l43Cell: l43Cell{mech: "external", code: -1}, invalid: "the certificate was never presented: the server sent no CertificateRequest"}
	if row := l44ExtRow("e1", x); !strings.Contains(row, "| e1 | INVALID (R6): the certificate was never presented") {
		t.Errorf("%s", row)
	}
	b := l44Ext{l43Cell: l43Cell{mech: "external", ok: true, read: 1}, authzID: `u:CORP\port49`}
	if row := l44ExtRow("e1", b); !strings.Contains(row, "accepted") || !strings.Contains(row, "WhoAmI `u:CORP\\port49`") {
		t.Errorf("%s", row)
	}
}

func TestL44ExternalRow(t *testing.T) {
	evs := []winEvent{{ID: 39, Provider: "KDC", Message: "m"}}
	inv := l44Ext{l43Cell: l43Cell{mech: "external", code: -1}, invalid: "bound, but WhoAmI says \"x|y\""}
	if row := l44ExternalRow("2", inv, nil); !strings.Contains(row, "| INVALID (R6): bound, but WhoAmI says \"x\\|y\" |") {
		t.Errorf("an invalid cell, its pipe escaped: %s", row)
	}
	bound := l44Ext{l43Cell: l43Cell{mech: "external", ok: true}, authzID: `u:CORP\port49`}
	if row := l44ExternalRow("2", bound, evs); !strings.Contains(row, "**bound** as `u:CORP\\port49`") || !strings.Contains(row, "KDC 39: m") {
		t.Errorf("%s", row)
	}
	refused := l44Ext{l43Cell: l43Cell{mech: "external", code: 1, text: "bind external: LDAP result 1"}}
	if row := l44ExternalRow("2", refused, nil); !strings.Contains(row, "| refused, LDAP result 1 |") {
		t.Errorf("%s", row)
	}
}

// OR-1: a KDC-down answer shows something about the KDC only when the same
// mapped bind succeeded with it up, before (e1) and after (e6).
func TestL44KDCDownInvalid(t *testing.T) {
	good := l44Ext{l43Cell: l43Cell{ok: true}}
	refused := l44Ext{l43Cell: l43Cell{code: 1}}
	invalid := l44Ext{l43Cell: l43Cell{ok: true}, invalid: "bound, but WhoAmI says x"}
	for name, tc := range map[string]struct {
		e1, e6 l44Ext
		bad    bool
	}{
		"both up":         {good, good, false},
		"e1 refused":      {refused, good, true},
		"e6 refused":      {good, refused, true},
		"e1 invalid":      {invalid, good, true},
		"e6 invalid":      {good, invalid, true},
		"neither is fine": {refused, refused, true},
	} {
		if got := l44KDCDownInvalid(tc.e1, tc.e6); (got != "") != tc.bad {
			t.Errorf("%s: %q", name, got)
		}
	}
}

// What a failed kinit or an event says may carry a secret: it is scrubbed, then
// cut, before it reaches a cell, the evidence or a log (pre-flight, Tasks 2-4).
func TestL44CleanScrubs(t *testing.T) {
	const sec = "Aa1!SecretValueForTest"
	evs := l44CleanEvents([]winEvent{{ID: 21, Provider: "KDC", Message: "pw " + sec + " " + strings.Repeat("x", 300)}}, sec)
	if got := l44EventsCell(evs); strings.Contains(got, sec) || !strings.Contains(got, "<secret>") {
		t.Errorf("an event cell holds the secret or lost its mark: %d bytes", len(got))
	}
	// A secret that straddles the cut is scrubbed whole, not cut in half.
	evs = l44CleanEvents([]winEvent{{ID: 21, Provider: "KDC", Message: strings.Repeat("y", 150) + sec}}, sec)
	if got := l44EventsCell(evs); strings.Contains(got, sec[:8]) {
		t.Error("a secret that straddles the cut was cut, not scrubbed")
	}
	r := l44CleanResult(winPKINITResult{kdcErrs: []string{"-1765328318/mismatch " + sec}, last: "kinit: " + sec}, sec)
	if got := r.kdcSaid(); strings.Contains(got, sec) || !strings.Contains(got, "<secret>") {
		t.Errorf("what the KDC said holds the secret or lost its mark: %d bytes", len(got))
	}
}

// The scan of windows_test.go (TestWindowsScrubsBeforeItCuts), over l44_test.go:
// every oneLineMax is given a winScrub, so no secret is cut in half before it
// is scrubbed.
func TestL44ScrubsBeforeItCuts(t *testing.T) {
	b, err := os.ReadFile("l44_test.go")
	if err != nil {
		t.Fatal(err)
	}
	var seen int
	for i, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "//") {
			continue
		}
		if strings.Contains(l, "tailOf(") {
			t.Errorf("l44_test.go:%d: tailOf cuts text outside scrubbedTail", i+1)
		}
		_, rest, ok := strings.Cut(l, "oneLineMax(")
		if !ok {
			continue
		}
		if seen++; !strings.HasPrefix(rest, "winScrub(") {
			t.Errorf("l44_test.go:%d: oneLineMax is not given a winScrub", i+1)
		}
	}
	if seen == 0 {
		t.Error("the scan found no oneLineMax call: it checks nothing")
	}
}

// A setting is restored to the value the facts table recorded, not deleted:
// "absent" is the only value that means delete (fix round 1, M2).
func TestL44AsInstalled(t *testing.T) {
	for in, want := range map[string]int{"absent": -1, "": -1, "0": 0, "1": 1, "2": 2, "garbage": -1} {
		if got := l44AsInstalled(in); got != want {
			t.Errorf("%q: %d, want %d", in, got, want)
		}
	}
}

// l44Func is the source of the top-level function name in l44_test.go.
func l44Func(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("l44_test.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	i := strings.Index(s, "\nfunc "+name+"(")
	if i < 0 {
		i = strings.Index(s, ") "+name+"(")
		if i < 0 {
			t.Fatalf("no func %s in l44_test.go", name)
		}
	}
	rest := s[i+1:]
	if end := strings.Index(rest, "\n}\n"); end >= 0 {
		return rest[:end]
	}
	return rest
}

// An SSH logon to the DC fails while its KDC is down, so the start cannot come
// over SSH. service.ps1's stop registers a one-shot SYSTEM task that starts the
// KDC, before it stops it, and throws (leaving the KDC up) if it cannot; its
// check state, run once SSH answers, reports the task and removes it.
func TestWindowsServiceScriptSchedulesItsOwnStart(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("directory", "windows", "scripts", "service.ps1"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	reg, stop := strings.Index(s, "Register-ScheduledTask"), strings.Index(s, "Stop-Service Kdc")
	if reg < 0 || stop < 0 || reg > stop {
		t.Errorf("the start task must be registered before the KDC is stopped: register at %d, stop at %d", reg, stop)
	}
	for _, want := range []string{`NT AUTHORITY\SYSTEM`, "$restart_after", "-ne 'Kdc'", "'check'", "Unregister-ScheduledTask",
		"LastTaskResult", "task_left", "stopped_at", "C:\\l44\\kdc-start.ps1", "Start-Service Kdc"} {
		if !strings.Contains(s, want) {
			t.Errorf("service.ps1 lacks %q", want)
		}
	}
	if strings.Contains(s, "$state -eq 'start'") {
		t.Error("service.ps1 still has a start state, which needs the SSH logon the stopped KDC refuses")
	}
	if !regexp.MustCompile(`\$restart_after -lt \d+\) \{ throw`).MatchString(s) {
		t.Error("service.ps1 does not refuse a restart_after too short to outlast the stop")
	}
	// The task is the KDC's only way back without a logon: it repeats, and
	// check removes it only once the KDC runs and the task is not running.
	if !strings.Contains(s, "-RepetitionInterval (New-TimeSpan -Minutes 2) -RepetitionDuration (New-TimeSpan -Minutes 30)") {
		t.Error("the start task does not repeat, so one failed start strands the DC")
	}
	guard, unreg := strings.Index(s, "if ($r.status -eq 'Running' -and -not $busy) {"), strings.LastIndex(s, "Unregister-ScheduledTask")
	if guard < 0 || unreg < guard {
		t.Error("check removes the start task before the KDC runs or while the task is running")
	}
}

// OR-1's KDC-stopped cell is valid only if its bind ended well before the
// KDC's scheduled start: a bind that ran into the start shows nothing.
func TestL44KDCTooNear(t *testing.T) {
	for name, tc := range map[string]struct {
		elapsed time.Duration
		bad     bool
	}{
		"quick":           {2 * time.Second, false},
		"at the margin":   {l44KDCDown - l44KDCMargin, false},
		"past the margin": {l44KDCDown - l44KDCMargin + time.Second, true},
		"after the start": {l44KDCDown + time.Second, true},
	} {
		if got := l44KDCTooNear(tc.elapsed); (got != "") != tc.bad {
			t.Errorf("%s: %q", name, got)
		}
	}
}

// The KDC counts as recovered when check says it is Running, the task ended
// with 0, the task is gone, and the task ran no earlier than the stop (the
// Task Scheduler cuts a trigger to the whole second).
func TestL44KDCRecovered(t *testing.T) {
	ok := l44KDCCheck{Status: "Running", TaskRan: "2026-10-07T08:31:20.0000000Z", TaskResult: "0"}
	const stopped = "2026-10-07T08:30:21.6300000Z"
	for name, tc := range map[string]struct {
		mod func(*l44KDCCheck)
		bad bool
	}{
		"recovered":           {func(*l44KDCCheck) {}, false},
		"stopped":             {func(c *l44KDCCheck) { c.Status = "Stopped" }, true},
		"task failed":         {func(c *l44KDCCheck) { c.TaskResult = "1" }, true},
		"task never ran":      {func(c *l44KDCCheck) { c.TaskResult = "" }, true},
		"task left":           {func(c *l44KDCCheck) { c.TaskLeft = true }, true},
		"ran before stop":     {func(c *l44KDCCheck) { c.TaskRan = "2026-10-07T08:00:00.0000000Z" }, true},
		"ran at the stop":     {func(c *l44KDCCheck) { c.TaskRan = "2026-10-07T08:30:20.0000000Z" }, false},
		"ran time unreadable": {func(c *l44KDCCheck) { c.TaskRan = "never" }, true},
	} {
		c := ok
		tc.mod(&c)
		if got := l44KDCRecovered(c, stopped); (got != "") != tc.bad {
			t.Errorf("%s: %q", name, got)
		}
	}
	if got := l44KDCRecovered(ok, ""); got != "" {
		t.Errorf("with no stop time to compare, a clean check is recovered: %q", got)
	}
	// A stop that never happened (its task was not registered) leaves a
	// running KDC and no task: nothing to wait for.
	if got := l44KDCRecovered(l44KDCCheck{Status: "Running"}, ""); got != "" {
		t.Errorf("a stop that never happened is not recovered: %q", got)
	}
	for name, c := range map[string]l44KDCCheck{"stopped, no task": {Status: "Stopped"}, "task left": {Status: "Running", TaskLeft: true}} {
		if l44KDCRecovered(c, "") == "" {
			t.Errorf("%s counts as recovered with no stop time", name)
		}
	}
	if l44KDCRecovered(l44KDCCheck{Status: "Running"}, "2026-10-07T08:30:21Z") == "" {
		t.Error("a stop that happened is recovered without its task having run")
	}
}

// OR-1 stops the KDC, and an SSH logon fails while it is down: the stop's own
// task starts it, OR-1 runs after everything else needs the KDC, its wait for
// the KDC is non-fatal and calls nothing before the scheduled start, and a
// deferred wait is registered before the stop (fix round 1, I1).
func TestL44OR1RunsLastAndStartsNonFatally(t *testing.T) {
	top := l44Func(t, "TestL44WindowsAD")
	or1, matrix := strings.Index(top, "l44OR1("), strings.Index(top, "l44Matrix(")
	if or1 < 0 || matrix < 0 || or1 < matrix {
		t.Fatalf("OR-1 must run after the matrix: l44OR1 at %d, l44Matrix at %d", or1, matrix)
	}
	if after := top[or1:]; strings.Contains(after[strings.Index(after, "\n"):], "obs.WriteString(dc.") {
		t.Error("a section runs after OR-1")
	}
	b, _ := os.ReadFile("l44_test.go")
	if strings.Contains(string(b), `"state": "start"`) || strings.Contains(string(b), "l44StartKDC") {
		t.Error("the KDC is started over SSH, which its stop breaks: the stop's own task starts it")
	}
	await := l44Func(t, "l44AwaitKDC")
	if !strings.Contains(await, "w.try(") || strings.Contains(await, "Fatal") || strings.Contains(await, "w.run(") {
		t.Error("l44AwaitKDC must use w.try and never fail the test fatally")
	}
	// Nothing calls the DC from the stop to the scheduled start: the wait comes first.
	if w, p := strings.Index(await, "time.Sleep(time.Until(t0.Add(l44KDCDown"), strings.Index(await, "w.try("); w < 0 || p < 0 || w > p {
		t.Errorf("l44AwaitKDC must wait out l44KDCDown before it calls the DC: wait at %d, call at %d", w, p)
	}
	body := l44Func(t, "l44OR1")
	d, s := strings.Index(body, "defer "), strings.Index(body, "w.stopKDC(")
	if d < 0 || s < 0 || d > s {
		t.Errorf("the deferred restart must be registered before the stop: defer at %d, stop at %d", d, s)
	}
	// e5 is the only DC call between the stop and the wait, and it is measured.
	e5, aw := strings.Index(body, `"external, KDC stopped"`), strings.LastIndex(body, "l44AwaitKDC(t, t0")
	if e5 < s || aw < e5 {
		t.Errorf("OR-1 order must be stop, e5, await: stop %d, e5 %d, await %d", s, e5, aw)
	}
	if between := body[s:aw]; strings.Contains(between, "w.try(") || strings.Contains(between, "w.run(") || strings.Contains(between, "setAltSec(") {
		t.Error("something calls the DC between the stop and the scheduled start")
	}
	if !strings.Contains(body, "l44KDCTooNear(") {
		t.Error("OR-1 does not mark e5 INVALID when its bind ends too near the scheduled start")
	}
	if !strings.Contains(body, "the KDC did not come back") {
		t.Error("a KDC that does not come back does not mark e6 INVALID")
	}
}

// Every registry change is guarded by a deferred restore registered before
// it, and a guard never fails fatally (it may run while a failure unwinds).
func TestL44RegistryChangesAreGuarded(t *testing.T) {
	g := l44Func(t, "l44GuardRegistry")
	if strings.Contains(g, "Fatal") || strings.Contains(g, "setRegistry(") || strings.Contains(g, "w.run(") {
		t.Error("l44GuardRegistry must restore with w.try and never fail fatally")
	}
	for _, fn := range []string{"l44Binds", "l44Matrix"} {
		body := l44Func(t, fn)
		for _, name := range []string{"LdapEnforceChannelBinding", "StrongCertificateBindingEnforcement", "UseCachedCRLOnlyAndIgnoreRevocationUnknownErrors"} {
			set := strings.Index(body, `setRegistry(t, "`+name+`", `)
			if set < 0 {
				continue
			}
			guard := strings.Index(body, `l44GuardRegistry(t, "`+name+`"`)
			if guard < 0 || guard > set {
				t.Errorf("%s: %s is changed before its restore is guarded", fn, name)
			}
			if i := strings.Index(body, `l44GuardRegistry(t, "`+name+`"`); i >= 0 && !strings.Contains(body[i:], "defer ") {
				t.Errorf("%s: %s's restore is not deferred", fn, name)
			}
			if name != "UseCachedCRLOnlyAndIgnoreRevocationUnknownErrors" && !strings.Contains(body[guard:guard+strings.Index(body[guard:], "\n")], "l44AsInstalled(") {
				t.Errorf("%s: %s's guard does not restore the value the facts table recorded", fn, name)
			}
			if strings.Contains(body, `setRegistry(t, "`+name+`", -1)`) {
				t.Errorf("%s: %s is restored by deleting it, not to the value installed", fn, name)
			}
		}
	}
}

// A fresh run must not start on a running DC (it would `down -v` it), and a
// REUSE run is meant to find one.
func TestWinLabHeld(t *testing.T) {
	for _, c := range []struct {
		reused bool
		ps     string
		want   bool
	}{
		{false, "", false}, {false, "\n", false}, {false, "3f2a9c\n", true}, {true, "3f2a9c\n", false}, {true, "", false},
	} {
		if got := winLabHeld(c.reused, c.ps); got != c.want {
			t.Errorf("reused=%v ps=%q: %v, want %v", c.reused, c.ps, got, c.want)
		}
	}
}

// Both lab tests that start the DC check PORT49_LAB_L44 as their first
// statement, so no pattern can start a lab by accident.
func TestL44LabTestsCheckTheOptInFirst(t *testing.T) {
	for _, name := range []string{"TestL44Bringup", "TestL44WindowsAD"} {
		body := l44Func(t, name)
		lines := strings.Split(body, "\n")
		if len(lines) < 2 || strings.TrimSpace(lines[1]) != "l44RequireOptIn(t)" {
			t.Errorf("%s: the first statement is not l44RequireOptIn(t)", name)
		}
	}
	if g := l44Func(t, "l44RequireOptIn"); !strings.Contains(g, `"PORT49_LAB_L44"`) || !strings.Contains(g, "t.Skip(") {
		t.Error("l44RequireOptIn does not skip on PORT49_LAB_L44")
	}
}

// startWindowsDC checks for a held lab before it touches the tree or compose.
func TestStartWindowsDCChecksHeldLabFirst(t *testing.T) {
	b, err := os.ReadFile("windows_test.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	i := strings.Index(s, "\nfunc startWindowsDC(")
	body := s[i:]
	held := strings.Index(body, "\t\tif winLabHeld(w.reused, string(up)) {\n\t\t\tt.Fatalf(")
	rm, comp := strings.Index(body, "os.RemoveAll("), strings.Index(body, "dockerCompose(")
	if held < 0 || held > rm || held > comp {
		t.Errorf("winLabHeld at %d must precede RemoveAll (%d) and dockerCompose (%d)", held, rm, comp)
	}
	if !strings.Contains(body, "another L44 run holds the lab (%s dc is running)") {
		t.Error("the refusal text is missing")
	}
}

// A second lock on the same path, through its own fd, fails while the first is
// held and succeeds after its release. Uses a temp path: the real lock may be held.
func TestWinLock(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sub", "windows.lock")
	rel, err := winLock(p)
	if err != nil {
		t.Fatal(err)
	}
	if rel2, err := winLock(p); err == nil {
		rel2()
		t.Fatal("a second lock on a held path succeeded")
	}
	rel()
	rel3, err := winLock(p)
	if err != nil {
		t.Fatalf("the lock is not free after its release: %v", err)
	}
	rel3()
}

// startWindowsDC takes the lock before it checks for a held DC or touches docker.
func TestStartWindowsDCLocksFirst(t *testing.T) {
	b, err := os.ReadFile("windows_test.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(b)[strings.Index(string(b), "\nfunc startWindowsDC("):]
	lock, held, ps := strings.Index(body, "winLock("), strings.Index(body, "winLabHeld("), strings.Index(body, "dockerCmd(")
	if lock < 0 || lock > held || lock > ps {
		t.Errorf("winLock at %d must precede winLabHeld (%d) and docker (%d)", lock, held, ps)
	}
	if !strings.Contains(body, "another L44 run holds the lab (windows.lock)") {
		t.Error("the lock refusal text is missing")
	}
}

// After the KDC wait in OR-1, a fatal SSH call (run, stopKDC, setAltSec) may
// run only in the branch where the KDC came back: otherwise it loses the note.
func TestL44OR1NothingFatalAfterAFailedStart(t *testing.T) {
	body := l44Func(t, "l44OR1")
	i := strings.LastIndex(body, "l44AwaitKDC(t, t0") // the backstop defer has its own
	if i < 0 {
		t.Fatal("no l44AwaitKDC call in l44OR1")
	}
	after := body[i:]
	back := strings.Index(after, "} else {")
	if back < 0 {
		t.Fatal("no KDC-is-back branch")
	}
	for _, call := range []string{"w.run(", "w.stopKDC(", "setAltSec("} {
		for off, rest := 0, after; ; {
			j := strings.Index(rest, call)
			if j < 0 {
				break
			}
			if off+j < back {
				t.Errorf("%s runs before the KDC-is-back branch", call)
			}
			off, rest = off+j+len(call), rest[j+len(call):]
		}
		if !strings.Contains(after[back:], call) && call == "setAltSec(" {
			t.Error("the mapping is never cleared")
		}
	}
	// the cleanup after the branch must not call them either
	if end := strings.Index(after[back:], "\n\t}\n"); end >= 0 {
		for _, call := range []string{"w.run(", "w.stopKDC(", "setAltSec("} {
			if strings.Contains(after[back+end:], call) {
				t.Errorf("%s runs after the branches", call)
			}
		}
	}
}

// AD ends an LDAP diagnosticMessage with a NUL, and no control character
// belongs in a note (grep calls a file with one binary): oneLineMax turns each
// into a space, and the whitespace collapses.
func TestOneLineMaxDropsControlCharacters(t *testing.T) {
	for name, tc := range map[string]struct{ in, want string }{
		"ad error":  {"80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, data 0, v65f4\x00", "80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, data 0, v65f4"},
		"mid nul":   {"a\x00b", "a b"},
		"escape":    {"a\x1b[0mb", "a [0mb"},
		"tab, crlf": {"a\tb\r\nc", "a b c"},
		"plain":     {"a b", "a b"},
	} {
		if got := oneLineMax(tc.in, 400); got != tc.want {
			t.Errorf("%s: %q, want %q", name, got, tc.want)
		}
		if got := oneLineMax(tc.in, 400); strings.ContainsFunc(got, unicode.IsControl) {
			t.Errorf("%s: a control character survives: %q", name, got)
		}
	}
}

// [MS-ADTS] 5.1.1.2: on the LDAPS port the certificate authenticates the
// connection and an EXTERNAL bind is rejected (result 7); over StartTLS an
// EXTERNAL bind maps it. The harness measures EXTERNAL over StartTLS.
func TestLabDirViaStartTLS(t *testing.T) {
	l := &labDir{uri: "ldaps://dc1.corp.example.com:30636", plainURI: "ldap://dc1.corp.example.com:30389", d: &directories{pki: &dirPKI{}}}
	s := l.viaStartTLS()
	if s.uri != l.plainURI || !s.startTLS {
		t.Errorf("the StartTLS server is %q (start_tls %v)", s.uri, s.startTLS)
	}
	if srv := s.config(directory.Nested("direct"), "", directory.Bind{}, directory.Mapping{}).Servers[0]; srv.URI != l.plainURI || !srv.StartTLS {
		t.Errorf("its config names %+v", srv)
	}
	if srv := l.config(directory.Nested("direct"), "", directory.Bind{}, directory.Mapping{}).Servers[0]; srv.URI != l.uri || srv.StartTLS {
		t.Errorf("the LDAPS server changed: %+v", srv)
	}
}

// Every EXTERNAL cell goes through l44External, which measures over StartTLS;
// the one LDAPS EXTERNAL row is the documented observation.
func TestL44ExternalIsMeasuredOverStartTLS(t *testing.T) {
	if !strings.Contains(l44Func(t, "l44External"), "viaStartTLS()") {
		t.Error("l44External does not measure over StartTLS")
	}
	if !strings.Contains(l44Func(t, "l44External"), "l44ExternalOn(t, ev, label, bind, mapped)") {
		t.Error("l44External does not hand its cell to l44ExternalOn")
	}
	for _, fn := range []string{"l44Binds", "l44Matrix", "l44OR1"} {
		body := l44Func(t, fn)
		if strings.Contains(body, `tryBind(t, ev, "external`) {
			t.Errorf("%s binds EXTERNAL without l44External", fn)
		}
		if strings.Contains(body, "l44ExternalOn(") && fn != "l44Binds" {
			t.Errorf("%s measures EXTERNAL on a chosen server", fn)
		}
		if strings.Contains(body, "SASL EXTERNAL over LDAPS") && !(fn == "l44Binds" && strings.Contains(body, "documented observation")) {
			t.Errorf("%s labels an EXTERNAL row as LDAPS", fn)
		}
	}
	if !strings.Contains(l44Func(t, "l44Binds"), "l44LDAPSNoBind(") || !strings.Contains(l44Func(t, "l44Binds"), "l.l44ExternalOn(") {
		t.Error("l44Binds records no LDAPS observation")
	}
	if !strings.Contains(l44Func(t, "certPresented"), "l.dialTLS(") {
		t.Error("certPresented does not follow the server's StartTLS")
	}
}

// Over StartTLS an unmapped certificate is refused with 49, not 7.
func TestL44ExternalRowsOverStartTLS(t *testing.T) {
	refused := l44Ext{l43Cell: l43Cell{mech: "external", code: 49, text: "bind external: LDAP result 49"}}
	if row := l44ExtRow("e2", refused); !strings.Contains(row, "| 49 |") {
		t.Errorf("%s", row)
	}
	if row := l44ExternalRow("absent", refused, nil); !strings.Contains(row, "refused, LDAP result 49") || !strings.Contains(row, "over StartTLS") || strings.Contains(row, "over LDAPS") {
		t.Errorf("%s", row)
	}
}

// A refused EXTERNAL cell is a refusal only when port49's own bind said so with
// the directory's code; a failure before the bind or a timeout is INVALID.
func TestL44ConnFailed(t *testing.T) {
	// The shapes port49 returns (internal/directory/conn.go): bind wraps the
	// directory's answer in an *ldap.Error whose cause names the mechanism; a
	// StartTLS or TLS failure comes back unwrapped.
	bindErr := func(code uint16, cause string) error {
		return &ldap.Error{ResultCode: code, Err: fmt.Errorf("bind external as CN=port49-broker: %s", cause)}
	}
	for name, tc := range map[string]struct {
		err error
		bad bool
	}{
		"bind refusal 49":      {bindErr(49, "LDAP result 49"), false},
		"bind refusal 7":       {bindErr(7, "LDAP result 7"), false},
		"startls refused, 52":  {ldap.NewError(52, errors.New("00002028: the server is shutting down")), true},
		"bind timeout":         {fmt.Errorf("bind external as CN=port49-broker: %w", context.DeadlineExceeded), true},
		"tls failure, 200+":    {bindErr(200, "LDAP result 200: tls: handshake failure"), true},
		"tls error, unwrapped": {errors.New("tls: failed to verify certificate"), true},
		"connect refused":      {ldap.NewError(ldap.ErrorNetwork, errors.New("connection refused")), true},
	} {
		c := l43Cell{code: ldapCode(tc.err), text: tc.err.Error(), fromBind: l44FromBind(tc.err, "external")}
		if got := l44ConnFailed(c); (got != "") != tc.bad {
			t.Errorf("%s: %q (text %q)", name, got, c.text)
		}
	}
	if !strings.Contains(l44Func(t, "l44ExternalOn"), "l44ConnFailed(") {
		t.Error("l44ExternalOn does not judge a failed bind with l44ConnFailed")
	}
	if !strings.Contains(l44L43Src(t), "l44FromBind(err, string(bind.Mechanism))") {
		t.Error("tryBind does not record whether the error is port49's bind error")
	}
}

// asExchangeRefused is gokrb5's message for a KRB-ERROR to the AS exchange
// (ASExchange.go); the TGS exchange's ends "... from KDC when requesting for
// <spn>" (TGSExchange.go).
const asExchangeRefused = "AS Exchange Error: kerberos error response from KDC"

// kdcRefusal is the error conn.go's bind returns when the KDC answers a
// gokrb5 exchange with a KRB-ERROR: gokrb5's own wrapping (krberror.Errorf
// over messages.KRBError, as ASExchange.go and TGSExchange.go build it),
// flattened to text under ErrBindRefused. format is gokrb5's message.
func kdcRefusal(code int32, format string, args ...any) error {
	kerr := krberror.Errorf(messages.KRBError{ErrorCode: code}, krberror.KDCError, format, args...)
	return fmt.Errorf("bind gssapi as port49@CORP.LAB refused: %w (%v)", directory.ErrBindRefused, kerr)
}

// A GSSAPI cell is a refusal only when AD answered the bind with a code or
// port49's own KDC classification says the principal was refused; a KDC that
// does not answer, a timeout or a network error is INVALID, as for EXTERNAL.
func TestL44GSSAPIFailed(t *testing.T) {
	// The shapes conn.go's bind returns: the directory's answer as an
	// *ldap.Error naming the mechanism; the KDC refusing the principal wrapped
	// in ErrBindRefused; a KDC that does not answer as the flattened gokrb5
	// error under "bind gssapi as ...", which carries no LDAP code.
	bindErr := func(code uint16, cause string) error {
		return &ldap.Error{ResultCode: code, Err: fmt.Errorf("bind gssapi as port49@CORP.LAB: %s", cause)}
	}
	for name, tc := range map[string]struct {
		err error
		bad bool
	}{
		"AD refusal 49": {bindErr(49, "LDAP result 49"), false},
		"AD refusal 8":  {bindErr(8, "LDAP result 8"), false},
		// AD's answer to a wrong key (ASExchange.go: the retry with pre-auth).
		"KDC refused the key":              {kdcRefusal(errorcode.KDC_ERR_PREAUTH_FAILED, asExchangeRefused), false},
		"KDC refused the client principal": {kdcRefusal(errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN, asExchangeRefused), false},
		"KDC revoked the client":           {kdcRefusal(errorcode.KDC_ERR_CLIENT_REVOKED, asExchangeRefused), false},
		// The service ticket and the clock are the lab's setup failing (gate
		// runs 8 and 9: ldap/localhost off DC1$), not AD refusing port49.
		"KDC does not know the service": {kdcRefusal(errorcode.KDC_ERR_S_PRINCIPAL_UNKNOWN,
			"TGS Exchange Error: kerberos error response from KDC when requesting for %s", "ldap/dc1.corp.example.com"), true},
		"clock skew": {kdcRefusal(errorcode.KRB_AP_ERR_SKEW, asExchangeRefused), true},
		"KDC does not answer": {fmt.Errorf("bind gssapi as port49@CORP.LAB: %w",
			errors.New("[Root cause: Networking_Error] dial tcp 127.0.0.1:30088: connect: connection refused")), true},
		"network error code":              {ldap.NewError(ldap.ErrorNetwork, errors.New("connection reset")), true},
		"bind client code":                {bindErr(200, "LDAP result 200: tls: handshake failure"), true},
		"deadline in the bind":            {fmt.Errorf("bind gssapi as port49@CORP.LAB: %w", context.DeadlineExceeded), true},
		"deadline, wrapped by the dialer": {fmt.Errorf("dial: %w", context.DeadlineExceeded), true},
	} {
		c := l43Cell{code: ldapCode(tc.err), text: tc.err.Error(), fromBind: l44FromBind(tc.err, "gssapi"),
			kdcRefused: errors.Is(tc.err, directory.ErrBindRefused)}
		if got := l44GSSAPIFailed(c); (got != "") != tc.bad {
			t.Errorf("%s: %q (text %q)", name, got, c.text)
		}
		row, invalid := l44GSSAPIRow("what", c)
		if tc.bad && (invalid == "" || !strings.Contains(row, "INVALID (R6): the connection or the KDC failed before the bind")) {
			t.Errorf("%s: row %q, invalid %q", name, row, invalid)
		}
		if !tc.bad && (invalid != "" || strings.Contains(row, "INVALID")) {
			t.Errorf("%s: a refusal read as INVALID: %q", name, row)
		}
	}
	if !strings.Contains(l44Func(t, "l44Binds"), "l44GSSAPIRow(") {
		t.Error("l44Binds does not judge a failed GSSAPI bind with l44GSSAPIRow")
	}
	if !strings.Contains(l44L43Src(t), "errors.Is(err, directory.ErrBindRefused)") {
		t.Error("tryBind does not record the KDC's own refusal")
	}
}

func l44L43Src(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("l43_test.go")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestL44NoBindRow(t *testing.T) {
	for name, r := range map[string]string{"id": l44NoBindRow(`u:CORP\port49`, nil), "err": l44NoBindRow("", errors.New("boom")), "anon": l44NoBindRow("", nil)} {
		if n := strings.Count(r, "|"); n != 5 {
			t.Errorf("%s: %d pipes, want 5 (four columns): %s", name, n, r)
		}
	}
	if r := l44NoBindRow(`u:CORP\port49`, nil); !strings.Contains(r, "`u:CORP\\port49`") || !strings.Contains(r, "no bind") {
		t.Errorf("%s", r)
	}
	if r := l44NoBindRow("", errors.New("boom")); !strings.Contains(r, "failed") || !strings.Contains(r, "boom") {
		t.Errorf("%s", r)
	}
	if r := l44NoBindRow("", nil); !strings.Contains(r, "anonymous") {
		t.Errorf("an empty WhoAmI is anonymous: %s", r)
	}
}

func TestWindowsNoteCitesWhyStartTLS(t *testing.T) {
	n := (&winDC{}).configNote()
	for _, want := range []string{"[MS-ADTS] 5.1.1.2", "rejects an EXTERNAL bind", "EXTERNAL is measured over StartTLS"} {
		if !strings.Contains(n, want) {
			t.Errorf("the note does not say %q", want)
		}
	}
}

// The Binds table is one block: nothing but rows is written between its
// header and its end, so the sentence for an LDAPS acceptance follows it.
func TestL44BindsTableIsNotSplit(t *testing.T) {
	body := l44Func(t, "l44Binds")
	head, end := strings.Index(body, "### Binds"), strings.Index(body, "l44BindsTail(")
	if head < 0 || end < head {
		t.Fatal("l44Binds does not write l44BindsTail after the table header")
	}
	if strings.Contains(body[head:end], `WriteString("\nLDAPS accepted`) {
		t.Error("the LDAPS acceptance sentence is written inside the table")
	}
	tail := l44BindsTail("req", true)
	if !strings.Contains(tail, "LDAPS accepted EXTERNAL here, contrary to [MS-ADTS] 5.1.1.2.") || !strings.HasPrefix(tail, "\nWhether") {
		t.Errorf("%q", tail)
	}
	if strings.Contains(l44BindsTail("req", false), "accepted") {
		t.Error("the sentence appears when LDAPS refused")
	}
}

// Each quirk CA's subject reads back as CN=<its cn> under the DCs, its files
// and rows are named by a slug that is safe in a path, a krb5.conf line and a
// kinit label, and no two CAs share a name, a key or a serial.
func TestWindowsQuirkCAs(t *testing.T) {
	cas, err := winQuirkCAs(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(cas) != len(winQuirks) || len(cas) < 6 {
		t.Fatalf("%d CAs for %d quirks", len(cas), len(winQuirks))
	}
	safe := regexp.MustCompile(`^[a-z]+$`)
	slugs, cns, serials := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, ca := range cas {
		if !safe.MatchString(ca.slug) || slugs[ca.slug] || cns[ca.cn] || serials[ca.cert.SerialNumber.String()] {
			t.Errorf("%q: an unsafe or repeated slug, CN or serial", ca.slug)
		}
		slugs[ca.slug], cns[ca.cn], serials[ca.cert.SerialNumber.String()] = true, true, true
		rdns, err := winRDNs(ca.cert.RawSubject)
		if err != nil || len(rdns) != 4 || rdns[3] != [2]string{"CN", ca.cn} {
			t.Errorf("%s: subject %v %v", ca.slug, rdns, err)
		}
		if ca.cert.Subject.CommonName != ca.cn {
			t.Errorf("%s: parsed CN %q", ca.slug, ca.cert.Subject.CommonName)
		}
		if ca.file() != "lab-users-"+ca.slug+"-ca" {
			t.Errorf("%s: file %q", ca.slug, ca.file())
		}
	}
	for _, want := range []string{"comma", "back", "slash", "plus", "quote", "lead"} {
		if !slugs[want] {
			t.Errorf("no %s CA", want)
		}
	}
	if !strings.Contains(winQuirks[1].cn, `\`) || !strings.Contains(winQuirks[2].cn, "/") || !strings.Contains(winQuirks[3].cn, "+") ||
		!strings.Contains(winQuirks[4].cn, `"`) || !strings.HasPrefix(winQuirks[5].cn, " ") {
		t.Error("a quirk CA's CN lacks the character it is for")
	}
}

// The forms offered for each quirk CA, as an operator would write them, and
// port49's is directory.ADIssuerSerial's.
func TestWindowsQuirkForms(t *testing.T) {
	cas, err := winQuirkCAs(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	const pre = "X509:<I>DC=com,DC=example,DC=corp,CN="
	want := map[string]struct{ port49, quoted, escaped, raw string }{
		"back":  {`lab-users\back-CA`, `"lab-users\back-CA"`, `lab-users\\back-CA`, `lab-users\back-CA`},
		"slash": {`lab-users/slash-CA`, `"lab-users/slash-CA"`, `lab-users/slash-CA`, `lab-users/slash-CA`},
		"plus":  {`"lab-users+plus-CA"`, `"lab-users+plus-CA"`, `lab-users\+plus-CA`, `lab-users+plus-CA`},
		"quote": {`"lab-users ""q"" CA"`, `"lab-users ""q"" CA"`, `lab-users \"q\" CA`, `lab-users "q" CA`},
		"lead":  {`" lab-users lead-CA"`, `" lab-users lead-CA"`, `\ lab-users lead-CA`, ` lab-users lead-CA`},
	}
	for _, ca := range cas {
		if ca.slug == "comma" {
			continue
		}
		leaf, _, err := winPersonCert(ca.cert, ca.key, "alice", "alice@corp.example.com", dirSerial(), time.Now())
		if err != nil {
			t.Fatal(err)
		}
		w := want[ca.slug]
		got := func(f func(*x509.Certificate) (string, error)) string {
			v, err := f(leaf)
			if err != nil {
				t.Fatal(err)
			}
			return strings.TrimPrefix(strings.SplitN(v, "<SR>", 2)[0], pre)
		}
		if g := got(func(c *x509.Certificate) (string, error) { return directory.ADIssuerSerial(c), nil }); g != w.port49 {
			t.Errorf("%s: port49 %q, want %q", ca.slug, g, w.port49)
		}
		for name, tc := range map[string]struct {
			f    func(*x509.Certificate) (string, error)
			want string
		}{"quoted": {winAltSecQuoted, w.quoted}, "escaped": {winAltSecEscaped, w.escaped}, "raw": {winAltSecRaw, w.raw}} {
			if g := got(tc.f); g != tc.want {
				t.Errorf("%s: %s %q, want %q", ca.slug, name, g, tc.want)
			}
		}
	}
}

// Port49's form is one the DC issued a TGT for: every port49 cell is true, and
// for each quirk CA the string directory.ADIssuerSerial writes equals the
// string of at least one other form whose cell is true. A regression in
// adQuote fails here, not only in a lab run.
func TestL44QuirkPort49FormIsMeasured(t *testing.T) {
	cas, err := winQuirkCAs(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	forms := map[string]func(*x509.Certificate) (string, error){
		"quoted": winAltSecQuoted, "escaped": winAltSecEscaped, "raw": winAltSecRaw}
	issuer := func(v string) string { return strings.SplitN(v, "<SR>", 2)[0] }
	for slug, cells := range winQuirkWant {
		if !cells["port49"] {
			t.Errorf("winQuirkWant[%s][port49] is false: port49's form is expected refused", slug)
		}
	}
	for _, ca := range cas {
		leaf, _, err := winPersonCert(ca.cert, ca.key, "alice", "alice@corp.example.com", dirSerial(), time.Now())
		if err != nil {
			t.Fatal(err)
		}
		p49 := issuer(directory.ADIssuerSerial(leaf))
		matched := false
		for name, f := range forms {
			v, err := f(leaf)
			if err != nil {
				t.Fatal(err)
			}
			if tgt, ok := winQuirkWant[ca.slug][name]; ok && tgt && issuer(v) == p49 {
				matched = true
			}
		}
		if !matched {
			t.Errorf("%s: port49's form %q equals no form measured to get a TGT", ca.slug, p49)
		}
	}
}

// The matrix has every quirk CA's rows once: port49's, quoted and escaped, and
// the as-is row for each CA but the comma's; each row's label is a safe file
// name (the kinit files carry it) and has a measured verdict in winQuirkWant.
func TestL44QuirkCases(t *testing.T) {
	c := winCerts{quirk: map[string]winQuirkCert{}}
	for _, q := range winQuirks {
		c.quirk[q.slug] = winQuirkCert{cert: &x509.Certificate{}}
	}
	form := func(*x509.Certificate) (string, error) { return "", nil }
	cases := l44QuirkCases(c, form)
	if want := 3 + 4*(len(winQuirks)-1); len(cases) != want {
		t.Fatalf("%d cases, want %d", len(cases), want)
	}
	seen := map[string]bool{}
	safe := regexp.MustCompile(`^[a-z]+-(port49|quoted|escaped|raw)$`)
	for _, cs := range cases {
		if seen[cs.label] || !safe.MatchString(cs.label) || cs.cert != c.quirk[l44QuirkSlug(cs.label)].cert {
			t.Errorf("%q: repeated, unsafe, or another CA's certificate", cs.label)
		}
		seen[cs.label] = true
		if strings.Contains(cs.what, "recorded, not asserted") {
			t.Errorf("%q: still says it is recorded, not asserted", cs.label)
		}
		if _, ok := l44QuirkWant(cs.label); !ok {
			t.Errorf("%q: no measured verdict in winQuirkWant", cs.label)
		}
	}
	for slug, forms := range winQuirkWant {
		for form := range forms {
			if !seen[slug+"-"+form] {
				t.Errorf("winQuirkWant has %s-%s, no case generates it", slug, form)
			}
		}
	}
	for want, label := range map[string]string{"**TGT issued**": "back-raw", "refused": "back-quoted"} {
		if got, ok := l44QuirkWant(label); !ok || got != want {
			t.Errorf("l44QuirkWant(%q) = %q, %v, want %q", label, got, ok, want)
		}
	}
	if _, ok := l44QuirkWant("control-ski"); ok {
		t.Error("control-ski has a quirk verdict")
	}
	for _, q := range winQuirks {
		for _, f := range []string{"port49", "quoted", "escaped"} {
			if !seen[q.slug+"-"+f] {
				t.Errorf("no %s-%s row", q.slug, f)
			}
		}
		if raw := seen[q.slug+"-raw"]; raw != (q.slug != "comma") {
			t.Errorf("%s-raw present: %v", q.slug, raw)
		}
	}
	for label, want := range map[string]string{"back-raw": "back", "comma-port49": "comma", "control-ski": "", "adcs-port49": "",
		"sid-none": "", "highbit-port49": "", "highbit-signbyte": ""} {
		if got := l44QuirkSlug(label); got != want {
			t.Errorf("l44QuirkSlug(%q) = %q, want %q", label, got, want)
		}
	}
}
