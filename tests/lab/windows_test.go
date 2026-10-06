//go:build lab

package lab

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/asn1"
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
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/rhwendt/port49/internal/testpki"
)

// The Windows Server AD lab (L44): Windows Server 2025 Standard Evaluation as a
// KVM VM in dockur/windows on its own compose project, the first DC of
// corp.example.com, set up over SSH by the PowerShell scripts in
// directory/windows/scripts and measured by port49's own client and by MIT
// kinit's PKINIT.
const (
	platWindows = "windows_ad"
	winProject  = "port49labwin"
	// winImage is dockur/windows v6.06 (source commit 013ea27498e0), by digest.
	winImage = "dockurr/windows:6.06@sha256:16fd7c39a3e48bb946d29c59dc6015942e5b900a1fa5d7e5552053bfc48ee2ea"
	// The Windows Server 2025 evaluation ISO, build 26100.32230 (January 2026):
	// Microsoft's URL, as dockur's define.sh names it, and its size and SHA-256.
	winISOURL    = "https://software-static.download.prss.microsoft.com/dbazure/998969d5-f34g-4e03-ac9d-1f9786c66749/26100.32230.260111-0550.lt_release_svc_refresh_SERVER_EVAL_x64FRE_en-us.iso"
	winISOSHA256 = "7b052573ba7894c9924e3e87ba732ccd354d18cb75a883efa9b900ea125bfd51"
	winISOSize   = 8152356864

	winSSH      = "127.0.0.1:30022" // the VM's sshd, published on loopback
	winKDC      = "127.0.0.1:30088" // the KDC, for port49's GSSAPI
	winKDCInNet = "172.30.44.10:88" // the KDC as the pkinit container reaches it
	winDCHost   = "dc1.corp.example.com"
	winCAName   = "corp-L44-CA"
)

// winScriptFS holds every setup and measurement step the DC runs.
//
//go:embed directory/windows/scripts/*.ps1
var winScriptFS embed.FS

// winScripts is each script's parameters, in the order its param() names
// them: ps refuses a parameter a script does not declare.
var winScripts = map[string][]string{
	"clock": nil, "promote": {"dsrm_password"}, "ready": nil, "seed": {"port49_password"},
	"reset": {"port49_password", "alice_altsecid"}, "adcs": nil, "ldaps": {"step", "cert_pem", "lab_ca_pem"},
	"keytab": {"port49_password"}, "trust": {"ca_pem", "name"}, "issue": {"csr_pem", "template"},
	"enroll_as": {"csr_pem", "user"}, "set_attr": {"dn", "attribute", "values"}, "registry": {"name", "value"},
	"service": {"name", "state"}, "events": {"since"}, "facts": nil,
}

// winSecretParams are the parameters that carry a secret: no script may
// write one (TestWindowsScriptsNeverEchoASecret).
var winSecretParams = []string{"dsrm_password", "port49_password"}

// winSecrets is every password the DC is built with, generated for the run.
// It prints as its key names only, so no format verb can leak a value.
type winSecrets struct {
	AdminPassword string `json:"admin_password"` // the local, then the domain, Administrator's: dockur's PASSWORD
	DSRMPassword  string `json:"dsrm_password"`  // Directory Services Restore Mode
}

// Value receivers, so a value prints as names as well as a pointer.
func (s winSecrets) String() string             { return "windows secrets: admin_password, dsrm_password" }
func (s winSecrets) GoString() string           { return s.String() }
func (s winSecrets) Format(f fmt.State, _ rune) { fmt.Fprint(f, s.String()) }
func (s winSecrets) all() []string              { return []string{s.AdminPassword, s.DSRMPassword} }

// winPassword is a password Windows' complexity rule accepts: the four
// classes first, then 24 random hex digits.
func winPassword() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "Aa1!" + hex.EncodeToString(b), nil
}

func newWinSecrets() (*winSecrets, error) {
	a, err := winPassword()
	if err != nil {
		return nil, err
	}
	d, err := winPassword()
	if err != nil {
		return nil, err
	}
	return &winSecrets{AdminPassword: a, DSRMPassword: d}, nil
}

// winEnv is windows.env, the file compose hands dockur: the account Setup
// makes and the password it and the built-in Administrator get.
func winEnv(s *winSecrets) string { return "USERNAME=Docker\nPASSWORD=" + s.AdminPassword + "\n" }

// winBootstrap is the one command the SSH session runs. It reads
// {"script": ..., "params": {...}} from stdin, runs the script with the params
// splatted, and writes its result as one line of JSON, or {"error": ...} and
// exit 1. Params, secrets included, travel on stdin only.
const winBootstrap = `$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
try {
  $in = [Console]::In.ReadToEnd() | ConvertFrom-Json
  $p = @{}
  if ($in.params) { $in.params.psobject.Properties | ForEach-Object { $p[$_.Name] = $_.Value } }
  $r = & ([scriptblock]::Create($in.script)) @p
  [Console]::Out.WriteLine((ConvertTo-Json -InputObject $r -Depth 8 -Compress))
} catch {
  [Console]::Out.WriteLine((ConvertTo-Json -InputObject @{ error = $_.Exception.Message } -Compress))
  exit 1
}`

// winCommand is the bootstrap as powershell.exe's -EncodedCommand takes it:
// UTF-16LE, base64.
func winCommand() string {
	u := utf16.Encode([]rune(winBootstrap))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2*i:], c)
	}
	return "powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand " +
		base64.StdEncoding.EncodeToString(b)
}

// winPayload is the stdin document for script with params.
func winPayload(script string, params map[string]any) ([]byte, error) {
	return json.Marshal(struct {
		Script string         `json:"script"`
		Params map[string]any `json:"params"`
	}{script, params})
}

// winThrownError is the error a script itself threw, as the bootstrap
// reported it: the script ran, so the VM, sshd and the bootstrap all work.
type winThrownError struct{ msg string }

func (e *winThrownError) Error() string { return e.msg }

// winResult reads the bootstrap's answer, the last non-empty line: the
// script's result, or the error it threw (a *winThrownError).
func winResult(out []byte) (json.RawMessage, error) {
	var line string
	for _, l := range strings.Split(strings.ReplaceAll(string(out), "\r\n", "\n"), "\n") {
		if s := strings.TrimSpace(l); s != "" {
			line = s
		}
	}
	if line == "" {
		return nil, errors.New("the script wrote nothing")
	}
	var e struct {
		Error *string `json:"error"`
	}
	if json.Unmarshal([]byte(line), &e) == nil && e.Error != nil {
		return nil, &winThrownError{*e.Error}
	}
	if !json.Valid([]byte(line)) {
		return nil, fmt.Errorf("the script's last line is not JSON (%d bytes)", len(line))
	}
	return json.RawMessage(line), nil
}

// winScrub replaces every secret in s with <secret>: what a failed step's
// text may carry before it reaches a log, a t.Fatalf or a file.
func winScrub(s string, secrets ...string) string {
	for _, sec := range secrets {
		if sec != "" {
			s = strings.ReplaceAll(s, sec, "<secret>")
		}
	}
	return s
}

// winISOOK reports whether path is the pinned ISO: its size, then its SHA-256.
func winISOOK(path string, size int64, sum string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if fi.Size() != size {
		return fmt.Errorf("%s is %d bytes, want %d", path, fi.Size(), size)
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != sum {
		return fmt.Errorf("%s has SHA-256 %s, want %s", path, got, sum)
	}
	return nil
}

// winRDNTypes names the attribute types a CA's subject in this lab carries,
// as port49's ADIssuerSerial and Windows both write them.
var winRDNTypes = map[string]string{"2.5.4.3": "CN", "0.9.2342.19200300.100.1.25": "DC", "2.5.4.10": "O", "2.5.4.11": "OU",
	"2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "S"}

// winRDNs is a DER name's (type, value) pairs, most significant first.
func winRDNs(raw []byte) ([][2]string, error) {
	var seq pkix.RDNSequence
	if rest, err := asn1.Unmarshal(raw, &seq); err != nil || len(rest) > 0 {
		return nil, errors.New("a malformed name")
	}
	var out [][2]string
	for _, rdn := range seq {
		for _, atv := range rdn {
			name, ok := winRDNTypes[atv.Type.String()]
			if !ok {
				name = "OID." + atv.Type.String()
			}
			out = append(out, [2]string{name, fmt.Sprint(atv.Value)})
		}
	}
	return out, nil
}

// winQuote is an RDN value as CertNameToStr (CERT_X500_NAME_STR) writes it:
// quoted when it is empty, starts or ends with white space, or holds
// , + = " \ < > # ; or a newline, an inner quote doubled (Microsoft's
// CertNameToStrW reference).
func winQuote(v string) string {
	if v == "" || strings.ContainsAny(v, ",+=\"\\<>#;\n") || strings.TrimSpace(v) != v {
		return `"` + strings.ReplaceAll(v, `"`, `""`) + `"`
	}
	return v
}

// winEscape is an RDN value in RFC 4514's backslash form: , + " \ < > ; =
// escaped, and a leading # or space and a trailing space.
func winEscape(v string) string {
	var b strings.Builder
	for i, r := range v {
		if strings.ContainsRune(",+\"\\<>;=", r) || (i == 0 && (r == '#' || r == ' ')) || (i == len(v)-1 && r == ' ') {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// winForm is an altSecurityIdentities X509IssuerSerialNumber value with each
// way it may differ from port49's own: the zero winForm is port49's form.
type winForm struct{ forward, quoted, escaped, unreversed, signByte bool }

func (f winForm) of(c *x509.Certificate) (string, error) {
	rdns, err := winRDNs(c.RawIssuer)
	if err != nil {
		return "", err
	}
	if f.forward {
		slices.Reverse(rdns)
	}
	parts := make([]string, len(rdns))
	for i, r := range rdns {
		v := r[1]
		switch {
		case f.quoted:
			v = winQuote(v)
		case f.escaped:
			v = winEscape(v)
		}
		parts[i] = r[0] + "=" + v
	}
	b := c.SerialNumber.Bytes()
	if f.signByte && len(b) > 0 && b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	if !f.unreversed {
		b = slices.Clone(b)
		slices.Reverse(b)
	}
	return "X509:<I>" + strings.Join(parts, ",") + "<SR>" + strings.ToUpper(hex.EncodeToString(b)), nil
}

// The forms the DC is offered beside port49's, each differing in one respect.
var (
	winAltSecForward    = winForm{forward: true}.of    // the issuer least significant RDN first, as Windows' UI prints it
	winAltSecUnreversed = winForm{unreversed: true}.of // the serial in certificate byte order
	winAltSecQuoted     = winForm{quoted: true}.of     // values quoted as CertNameToStr quotes them
	winAltSecEscaped    = winForm{escaped: true}.of    // values escaped as RFC 4514 escapes them
	winAltSecSignByte   = winForm{signByte: true}.of   // the serial with its DER sign byte
)

// winAltSecSKI is KB5014754's strong X509SKI mapping for c, the hex of its
// SubjectKeyId as the KB's example writes it: control-ski's mapping, which
// no part of L44's claim is about.
func winAltSecSKI(c *x509.Certificate) (string, error) {
	if len(c.SubjectKeyId) == 0 {
		return "", errors.New("the certificate has no SubjectKeyId")
	}
	return "X509:<SKI>" + hex.EncodeToString(c.SubjectKeyId), nil
}

var (
	winOIDSAN = asn1.ObjectIdentifier{2, 5, 29, 17}
	winOIDUPN = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}
)

// winUPNExtension is a subjectAltName holding one UPN otherName, a
// UTF8String, as AD CS writes it.
func winUPNExtension(upn string) (pkix.Extension, error) {
	inner, err := asn1.MarshalWithParams(upn, "utf8")
	if err != nil {
		return pkix.Extension{}, err
	}
	other, err := asn1.Marshal(struct {
		ID    asn1.ObjectIdentifier
		Value asn1.RawValue
	}{winOIDUPN, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: inner}})
	if err != nil {
		return pkix.Extension{}, err
	}
	other[0] = 0xa0 // [0] IMPLICIT, constructed: the GeneralName otherName choice
	names, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: other})
	return pkix.Extension{Id: winOIDSAN, Value: names}, err
}

// winCSR is a PKCS #10 request for cn, with a UPN SAN when upn is not "", on
// a new RSA-2048 key. RSA, because the User template and MIT's PKINIT client
// both take it, and the key type is no part of L44's claim.
func winCSR(cn, upn string) ([]byte, *rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}
	if upn != "" {
		ext, err := winUPNExtension(upn)
		if err != nil {
			return nil, nil, err
		}
		tmpl.ExtraExtensions = []pkix.Extension{ext}
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), key, nil
}

func winParseCSR(b []byte) (*x509.CertificateRequest, error) {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("no PEM block")
	}
	return x509.ParseCertificateRequest(blk.Bytes)
}

func winParsePEMCert(b []byte) (*x509.Certificate, error) {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("no PEM block")
	}
	return x509.ParseCertificate(blk.Bytes)
}

func winPEMCert(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

func winPEMKey(k *rsa.PrivateKey) []byte {
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// winLoopback is the loopback addresses the DC's LDAPS certificate names.
func winLoopback() []net.IP { return testpki.Loopback() }

// signServerCSR is the DC's LDAPS certificate: the lab CA signs the key the
// DC generated, for the names the lab's URIs and the DC itself use, whatever
// the request asked for.
func (p *dirPKI) signServerCSR(csrPEM []byte, now time.Time) ([]byte, error) {
	csr, err := winParseCSR(csrPEM)
	if err != nil {
		return nil, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{SerialNumber: dirSerial(), Subject: pkix.Name{CommonName: winDCHost},
		DNSNames: []string{"localhost", winDCHost}, IPAddresses: winLoopback(), NotBefore: now.Add(-time.Hour),
		NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.ca.Cert, csr.PublicKey, p.ca.Key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// winCommaCA is a CA named CN=lab-users\, comma-CA,DC=corp,DC=example,DC=com,
// written in DER most significant first: plan 7g's carried question, whether a
// Windows DC wants a `,` in <I> quoted.
func winCommaCA(now time.Time) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	raw, err := asn1.Marshal(pkix.RDNSequence{
		{{Type: oidDirDC, Value: "com"}}, {{Type: oidDirDC, Value: "example"}}, {{Type: oidDirDC, Value: "corp"}},
		{{Type: oidDirCN, Value: "lab-users, comma-CA"}}})
	if err != nil {
		return nil, nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), RawSubject: raw, NotBefore: now.Add(-time.Hour),
		NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	c, err := x509.ParseCertificate(der)
	return c, key, err
}

// winPersonCert is a client certificate for a person from parent: RSA-2048,
// clientAuth, a UPN SAN, NotBefore a minute ago (after the account exists:
// KB5014754's backdating check is no part of the claim), with serial.
func winPersonCert(parent *x509.Certificate, signer crypto.Signer, cn, upn string, serial *big.Int, now time.Time) (*x509.Certificate, *rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	ext, err := winUPNExtension(upn)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: cn}, NotBefore: now.Add(-time.Minute),
		NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, ExtraExtensions: []pkix.Extension{ext}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, signer)
	if err != nil {
		return nil, nil, err
	}
	c, err := x509.ParseCertificate(der)
	return c, key, err
}

// winHighBitSerial is a 9-byte serial whose top bit is set: DER encodes it
// with a leading 00, and the question is whether <SR> keeps it.
func winHighBitSerial() *big.Int {
	b := make([]byte, 9)
	_, _ = rand.Read(b)
	b[0] |= 0x80
	return new(big.Int).SetBytes(b)
}

// winPKINITResult is one kinit: whether the KDC issued a TGT and, if not, what
// it said, from MIT's trace and kinit's own last line.
type winPKINITResult struct {
	ok      bool
	kdcErrs []string // "<code>/<text>" from each "Received error from KDC", in order
	last    string   // kinit's own last line
	took    time.Duration
}

var winKDCErrRe = regexp.MustCompile(`Received error from KDC: (-?\d+/[^\r\n]*)`)

// winPreauthRequired is the KDC's ordinary first answer to an AS-REQ, on
// success too.
const winPreauthRequired = "-1765328359/"

// winResponseTooBig is the KDC's "Response too big for UDP, retry with TCP":
// the transport asking for TCP, not a refusal. The client config forces TCP,
// so it should not appear, and it is no verdict if it does.
const winResponseTooBig = "-1765328332/"

// winKDCOrdinary reports whether a trace entry is one the KDC sends on a
// success or a transport retry, so it says nothing about the mapping.
func winKDCOrdinary(e string) bool {
	return strings.HasPrefix(e, winPreauthRequired) || strings.HasPrefix(e, winResponseTooBig)
}

func winParseKinit(out string) winPKINITResult {
	r := winPKINITResult{ok: strings.Contains(out, "lab: kinit exit 0") && strings.Contains(out, "krbtgt/"+dirRealm+"@"+dirRealm)}
	for _, m := range winKDCErrRe.FindAllStringSubmatch(out, -1) {
		r.kdcErrs = append(r.kdcErrs, oneLineMax(m[1], 160))
	}
	for _, line := range strings.Split(out, "\n") {
		if s := strings.TrimSpace(line); strings.HasPrefix(s, "kinit: ") {
			r.last = oneLineMax(s, 200)
		}
	}
	return r
}

// kdcSaid is what a cell shows: the KDC's errors past the ordinary first
// one, and kinit's last line on a failure; "—" when there is nothing.
func (r winPKINITResult) kdcSaid() string {
	var parts []string
	for _, e := range r.kdcErrs {
		if !winKDCOrdinary(e) {
			parts = append(parts, e)
		}
	}
	if !r.ok && r.last != "" {
		parts = append(parts, r.last)
	}
	if len(parts) == 0 {
		return "—"
	}
	return strings.Join(parts, "; ")
}

// kdcRefused reports whether the KDC itself sent an error past the ordinary
// preauth-required and the UDP size retry. A failed kinit without one failed on the client's side
// (the KDC's certificate unverified, a DH or etype mismatch, a missing file):
// the KDC refused nothing, and the cell is INVALID (R6).
func (r winPKINITResult) kdcRefused() bool {
	for _, e := range r.kdcErrs {
		if !winKDCOrdinary(e) {
			return true
		}
	}
	return false
}

// setupCodes is each KDC error among r's that is a PKINIT certificate-
// validation failure (winKDCSetupCode): the run's setup, not the mapping.
func (r winPKINITResult) setupCodes() []int {
	var out []int
	for _, e := range r.kdcErrs {
		if n, ok := winKDCErrCode(e); ok && winKDCSetupCode(n) {
			out = append(out, n)
		}
	}
	return out
}

// winKDCErrCode is the RFC 4120 error number in one of MIT's
// "<com_err code>/<text>" entries: MIT numbers KDC error n as
// -1765328384 + n.
func winKDCErrCode(e string) (int, bool) {
	num, _, ok := strings.Cut(e, "/")
	if !ok {
		return 0, false
	}
	n, err := strconv.Atoi(num)
	if err != nil {
		return 0, false
	}
	return n + 1765328384, true
}

// winPKINITConf is the PKINIT client's krb5.conf: the realm's KDC on the
// project network, AD CS's root as the anchor, and pkinit_kdc_hostname, the
// one setting MIT's documentation names for an Active Directory KDC.
func winPKINITConf(kdc string) string {
	return fmt.Sprintf(`[libdefaults]
  default_realm = %[1]s
  dns_lookup_kdc = false
  dns_lookup_realm = false
  udp_preference_limit = 1

[realms]
  %[1]s = {
    kdc = %[2]s
    pkinit_anchors = FILE:/l44/adcs-root.pem
    pkinit_kdc_hostname = %[3]s
  }
`, dirRealm, kdc, winDCHost)
}

// winEvent is one event the DC logged.
type winEvent struct {
	ID       int    `json:"id"`
	Provider string `json:"provider"`
	Time     string `json:"time"`
	Message  string `json:"message"`
}

// winKDCPrecondition reports whether a KDC event says the run's setup failed
// rather than the mapping: 19 and 29 (the KDC has no certificate for PKINIT)
// and 21 (the client certificate did not validate: its chain or revocation).
func winKDCPrecondition(id int) bool { return id == 19 || id == 21 || id == 29 }

// winKDCSetupCode reports whether a KDC error is a PKINIT certificate-
// validation failure (RFC 4556 and RFC 4120's 62–78 range), which says the
// run's trust, chain, revocation or names are wrong rather than the mapping:
// 62 CLIENT_NOT_TRUSTED, 63 KDC_NOT_TRUSTED, 64 INVALID_SIG, 65
// DH_KEY_PARAMETERS_NOT_ACCEPTED, 70 CANT_VERIFY_CERTIFICATE, 71
// INVALID_CERTIFICATE, 72 REVOKED_CERTIFICATE, 73 REVOCATION_STATUS_UNKNOWN,
// 74 REVOCATION_STATUS_UNAVAILABLE, 75 CLIENT_NAME_MISMATCH, 76
// KDC_NAME_MISMATCH, 77 INCONSISTENT_KEY_PURPOSE, 78
// DIGEST_IN_CERT_NOT_ACCEPTED. 66 CERTIFICATE_MISMATCH is the mapping's
// verdict and is not one.
func winKDCSetupCode(code int) bool {
	return (code >= 62 && code <= 65) || (code >= 70 && code <= 78)
}

// winSkewOK reports whether the DC's clock is within limit of ours: past five
// minutes Kerberos refuses everything, and a skewed run would read that as a
// mapping's verdict.
func winSkewOK(dc, host time.Time, limit time.Duration) bool {
	d := dc.Sub(host)
	return d <= limit && d >= -limit
}

// winIssuedAfter is an error naming each certificate whose NotBefore is not
// after created, alice's whenCreated.
func winIssuedAfter(created time.Time, certs ...*x509.Certificate) error {
	var bad []string
	for _, c := range certs {
		if !c.NotBefore.After(created) {
			bad = append(bad, fmt.Sprintf("%q from %s", c.Subject.CommonName, c.NotBefore.UTC().Format(time.RFC3339)))
		}
	}
	if len(bad) > 0 {
		return fmt.Errorf("certificates that predate the account (%s): %s", created.UTC().Format(time.RFC3339), strings.Join(bad, ", "))
	}
	return nil
}

// winOnlyValue reports whether vals is exactly want (none when want is ""),
// compared as AD compares altSecurityIdentities, case-insensitively.
func winOnlyValue(vals []string, want string) bool {
	if want == "" {
		return len(vals) == 0
	}
	return len(vals) == 1 && strings.EqualFold(vals[0], want)
}
