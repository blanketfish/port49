//go:build lab

package lab

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

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
		"a+b": `"a+b"`, "a=b": `"a=b"`, "a#b": `"a#b"`, "a;b": `"a;b"`, "a<b": `"a<b"`, "a>b": `"a>b"`, `a\b`: `"a\b"`, "": `""`, "a\nb": "\"a\nb\"",
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
	ca, caKey, err := winCommaCA(now)
	if err != nil {
		t.Fatal(err)
	}
	c, _, err := winPersonCert(ca, caKey, "alice", "alice@corp.example.com", new(big.Int).SetBytes([]byte{0x80, 0x01, 0x02}), now)
	if err != nil {
		t.Fatal(err)
	}
	const issuer = "DC=com,DC=example,DC=corp,CN=lab-users, comma-CA"
	for name, tc := range map[string]struct {
		f    func(*x509.Certificate) (string, error)
		want string
	}{
		"port49":     {winForm{}.of, "X509:<I>" + issuer + "<SR>020180"},
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
	if got, _ := (winForm{}).of(c); got != directory.ADIssuerSerial(c) {
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
		"pkinit_kdc_hostname = dc1.corp.example.com", "udp_preference_limit = 1", "dns_lookup_kdc = false"} {
		if !strings.Contains(c, want) {
			t.Errorf("lacks %q", want)
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

// A cleared attribute reads back as no values, not one empty string: a
// single-valued attribute that is unset is $null, and $null piped to
// ForEach-Object still runs once.
func TestWindowsSetAttrReadsBackNoValues(t *testing.T) {
	b, _ := winScriptFS.ReadFile("directory/windows/scripts/set_attr.ps1")
	if !strings.Contains(string(b), "Where-Object { $null -ne $_ } | ForEach-Object") {
		t.Error("set_attr.ps1 does not drop a $null attribute before it stringifies the values")
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
	if !strings.Contains(string(b), "dpkg-query -W krb5-user krb5-pkinit libkrb5-3 > /etc/pkinit-versions") {
		t.Error("the pkinit Dockerfile does not record the installed versions in /etc/pkinit-versions")
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
		if m := labEnvPrint.FindIndex(b); m != nil {
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
		if got := labEnvPrint.MatchString(q(c.src)); got != c.bad {
			t.Errorf("%q: matched=%v, want %v", c.src, got, c.bad)
		}
	}
}

// labEnvPrint is each way a lab file could print a container's environment:
// docker's inspect (not an image's), compose's config or its alias convert, a
// read of the process environment under /proc, or env, printenv or set run in the container by exec.
var labEnvPrint = regexp.MustCompile(`docker\s+inspect|docker\s+compose\b[^\n'"]*\b(?:config|convert)\b|compose\s+(?:config|convert)\b|/proc/[^"'\s]*environ|` +
	`docker\s+exec\b[^\n'"]*\b(?:printenv|env|set)\b|` +
	`[dD]ocker\w*\(\s*(?:"container",\s*)?"inspect"|"docker",\s*"inspect"|` +
	`[dD]ocker\w*\([^)\n]*"(?:config|convert)"|"compose"[^\n)]*"(?:config|convert)"|` +
	`"exec"[^)\n]*"(?:printenv|env|set)(?:\s[^"]*)?"`)

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
	for _, first := range []string{"WriteLine", "ReadToEnd"} {
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
