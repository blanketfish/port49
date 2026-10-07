//go:build lab

package lab

import (
	"bytes"
	"context"
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
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unicode/utf16"

	"golang.org/x/crypto/ssh"

	"github.com/rhwendt/port49/internal/directory"
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
	"service": {"name", "state", "restart_after"}, "events": {"since"}, "facts": nil,
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
// {"script": ..., "params": {...}} from stdin as one line (never to stdin's
// end: Windows OpenSSH can lose the end, and gate run 6's install step sat
// idle waiting for it), runs the script with the params
// splatted, and writes its result as one line of JSON, or {"error": ...} and
// exit 1. Params, secrets included, travel on stdin only. Every variable that
// holds them is private, so the script, run in a child scope, cannot read
// them by name; a foreach statement fills $p in this scope, where a
// ForEach-Object block would not.
const winBootstrap = `$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = New-Object Text.UTF8Encoding $false; [Console]::InputEncoding = New-Object Text.UTF8Encoding $false } catch { }
$ProgressPreference = 'SilentlyContinue'
try {
  $private:in = [Console]::In.ReadLine() | ConvertFrom-Json
  $private:p = @{}
  $private:prop = $null
  if ($in.params) { foreach ($prop in $in.params.psobject.Properties) { $p[$prop.Name] = $prop.Value } }
  $private:sb = [scriptblock]::Create($in.script)
  $r = & $sb @p
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

// winPayload is the stdin document for script with params: one line of JSON
// (which escapes every newline in it) and the newline the bootstrap reads to.
func winPayload(script string, params map[string]any) ([]byte, error) {
	b, err := json.Marshal(struct {
		Script string         `json:"script"`
		Params map[string]any `json:"params"`
	}{script, params})
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
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
// project network, AD CS's root and the lab's two client CAs as anchors, and pkinit_kdc_hostname, the
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
    pkinit_anchors = FILE:/l44/lab-users-ca.pem
    pkinit_anchors = FILE:/l44/lab-users-comma-ca.pem
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

// winDC is the Windows Server DC the L44 run measures: a KVM VM in a dockur
// container on the compose project port49labwin, set up over SSH as the
// domain's Administrator, every step one script from directory/windows/scripts.
type winDC struct {
	dir, compose string // tests/lab/logs/windows; tests/lab/directory/windows/compose.yaml
	sec          *winSecrets
	port49       string // port49's password: the run's d.password
	reused       bool
	state        winState
	facts        winFacts
	certs        winCerts
	adcsRoot     *x509.Certificate
	invalid      []string // "<area>: <scrubbed error>" for each setup step that failed three times (R6)
}

// winState is what a built DC keeps between runs (state.json, no secret).
type winState struct {
	Built        bool      `json:"built"`
	AliceCreated time.Time `json:"alice_created"`
	Loop         string    `json:"loop"`
}

// winFacts is what facts.ps1 answers.
type winFacts struct {
	Caption          string            `json:"caption"`
	Version          string            `json:"version"`
	Build            string            `json:"build"`
	DisplayVersion   string            `json:"display_version"`
	Edition          string            `json:"edition"`
	Hotfixes         []string          `json:"hotfixes"`
	DomainMode       string            `json:"domain_mode"`
	ForestMode       string            `json:"forest_mode"`
	UTCNow           string            `json:"utc_now"`
	StrongBinding    string            `json:"strong_certificate_binding_enforcement"`
	Backdating       string            `json:"certificate_backdating_compensation"`
	MappingMethods   string            `json:"certificate_mapping_methods"`
	NTDSLDAP         map[string]string `json:"ntds_ldap_settings"`
	LockoutThreshold int               `json:"lockout_threshold"`
	MIT              string            `json:"-"` // the PKINIT client's measured versions, read from its image
}

// winCerts is the run's client certificates, each key on this host only.
type winCerts struct {
	brokerADCS, aliceADCS, aliceSID, aliceComma, aliceHighBit, dcKDC     *x509.Certificate
	brokerKey, aliceADCSKey, aliceSIDKey, aliceCommaKey, aliceHighBitKey *rsa.PrivateKey
	brokerCertFile, brokerKeyFile                                        string
}

// winDC holds every password and private key of the run, so it prints as its
// project's name whatever the verb, as a value or a pointer.
func (w winDC) String() string             { return "windows dc (" + winProject + ")" }
func (w winDC) GoString() string           { return w.String() }
func (w winDC) Format(f fmt.State, _ rune) { fmt.Fprint(f, w.String()) }

// invalidFor is why area's cells are INVALID (R6), or "" when its setup
// step succeeded.
func (w *winDC) invalidFor(area string) string {
	for _, s := range w.invalid {
		if rest, ok := strings.CutPrefix(s, area+": "); ok {
			return rest
		}
	}
	return ""
}

// winScriptErr is a script that ran: the SSH session opened and the command
// returned, so the VM and sshd are up and what failed is the script or the
// bootstrap. thrown is the script's own error ({"error": ...}); otherwise the
// bootstrap wrote no result at all. msg is scrubbed.
type winScriptErr struct {
	name   string
	thrown bool
	cut    bool // the session ended without an exit status: the VM was going down, not the bootstrap failing
	msg    string
}

// bootstrapBroke reports whether the bootstrap itself failed: it ran to an
// exit and wrote no result, which no wait mends.
func (e *winScriptErr) bootstrapBroke() bool { return !e.thrown && !e.cut }

// winSessionCut reports whether a finished session ended without an exit
// status (the connection dropped or the server closed it), as a reboot does.
func winSessionCut(err error) bool {
	var exit *ssh.ExitError
	return err != nil && !errors.As(err, &exit)
}

// winAuthStall is how long sshd may keep refusing the Administrator's password
// before the wait gives up: the transient refusals after the promotion's reboot
// end well within it, and a refusal that outlasts it never mends.
const winAuthStall = 10 * time.Minute

// winAuthWatch tells a password sshd refuses for good from a VM that is still
// starting: since is the first of an unbroken run of refusals, and stall how
// long they may go on (zero: never a stall, once a session has proved the
// password).
type winAuthWatch struct {
	since time.Time
	stall time.Duration
}

// observe takes each attempt's error and the time, true when refusals have
// gone on for a.stall. Any other outcome starts the count again.
func (a *winAuthWatch) observe(err error, now time.Time) bool {
	if err == nil || !strings.Contains(err.Error(), "unable to authenticate") {
		a.since = time.Time{}
		return false
	}
	if a.since.IsZero() {
		a.since = now
	}
	return a.stall > 0 && now.Sub(a.since) >= a.stall
}

// winRegistryWithin outlasts registry.ps1's own five-minute wait for the KDC.
const winRegistryWithin = 8 * time.Minute

// winRebootWithin is how long the DC may take to answer again after
// registry.ps1 reboots it for an NTDS setting.
const winRebootWithin = 20 * time.Minute

func (e *winScriptErr) Error() string { return "windows " + e.name + ": " + e.msg }

func (w *winDC) dockerCompose(args ...string) *exec.Cmd {
	return dockerCmd(append([]string{"compose", "-p", winProject, "-f", w.compose, "--env-file",
		filepath.Join(w.dir, "compose.env")}, args...)...)
}

func (w *winDC) secrets() []string { return append(w.sec.all(), w.port49) }

// dial is one SSH connection as the Administrator, with a deadline on the
// handshake too. The host key is not checked: the VM is new each run and is
// reached only on loopback.
func (w *winDC) dial(timeout time.Duration) (*ssh.Client, error) {
	nc, err := net.DialTimeout("tcp", winSSH, timeout)
	if err != nil {
		return nil, err
	}
	_ = nc.SetDeadline(time.Now().Add(timeout))
	pw := w.sec.AdminPassword
	cfg := &ssh.ClientConfig{User: "Administrator", HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: timeout,
		Auth: []ssh.AuthMethod{ssh.Password(pw), ssh.KeyboardInteractive(func(_, _ string, q []string, _ []bool) ([]string, error) {
			a := make([]string, len(q))
			for i := range a {
				a[i] = pw
			}
			return a, nil
		})}}
	c, chans, reqs, err := ssh.NewClientConn(nc, winSSH, cfg)
	if err != nil {
		nc.Close()
		return nil, err
	}
	_ = nc.SetDeadline(time.Time{})
	return ssh.NewClient(c, chans, reqs), nil
}

// ps runs one script on the DC with params on stdin and returns its result.
// Every error it returns has had the run's secrets scrubbed from it.
func (w *winDC) ps(ctx context.Context, name string, params map[string]any) (json.RawMessage, error) {
	want, ok := winScripts[name]
	if !ok {
		return nil, fmt.Errorf("no windows script %q", name)
	}
	for k := range params {
		if !slices.Contains(want, k) {
			return nil, fmt.Errorf("windows script %s takes no %q", name, k)
		}
	}
	src, err := winScriptFS.ReadFile("directory/windows/scripts/" + name + ".ps1")
	if err != nil {
		return nil, err
	}
	body, err := winPayload(string(src), params)
	if err != nil {
		return nil, err
	}
	c, err := w.dial(30 * time.Second)
	if err != nil {
		return nil, fmt.Errorf("windows %s: ssh: %s", name, winScrub(err.Error(), w.secrets()...))
	}
	defer c.Close()
	s, err := c.NewSession()
	if err != nil {
		return nil, fmt.Errorf("windows %s: session: %s", name, winScrub(err.Error(), w.secrets()...))
	}
	defer s.Close()
	var out, errb bytes.Buffer
	s.Stdin, s.Stdout, s.Stderr = bytes.NewReader(body), &out, &errb
	done := make(chan error, 1)
	go func() { done <- s.Run(winCommand()) }()
	select {
	case err = <-done:
	case <-ctx.Done():
		c.Close()
		return nil, fmt.Errorf("windows %s: %w", name, ctx.Err())
	}
	// From here the session ran the command: every error is a *winScriptErr.
	res, rerr := winResult(out.Bytes())
	if rerr != nil {
		var thrown *winThrownError
		return nil, &winScriptErr{name: name, thrown: errors.As(rerr, &thrown), cut: winSessionCut(err), msg: fmt.Sprintf("%s (stderr: %s)",
			winScrub(rerr.Error(), w.secrets()...), oneLineMax(winScrub(errb.String(), w.secrets()...), 300))}
	}
	if err != nil {
		return nil, &winScriptErr{name: name, msg: winScrub(err.Error(), w.secrets()...)}
	}
	return res, nil
}

// try is ps under a deadline, saying every two minutes that the step is
// still running (a promotion or AD CS install is silent for up to half an
// hour, and the watchdog must not read that as a stall). It never fails the
// test; into, when not nil, receives the result.
func (w *winDC) try(t *testing.T, name string, params map[string]any, within time.Duration, into any) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), within)
	defer cancel()
	start, done := time.Now(), make(chan struct{})
	defer close(done)
	go func() {
		tick := time.NewTicker(2 * time.Minute)
		defer tick.Stop()
		for {
			select {
			case <-done:
				return
			case <-tick.C:
				t.Logf("windows: %s still running (%s)", name, time.Since(start).Round(time.Second))
			}
		}
	}()
	res, err := w.ps(ctx, name, params)
	if err != nil {
		return err
	}
	if into != nil {
		if err := json.Unmarshal(res, into); err != nil {
			return fmt.Errorf("windows %s: reading its result: %v", name, err)
		}
	}
	return nil
}

// run is try, fatal on error: a setup step's failure is the harness's, never
// a measurement.
func (w *winDC) run(t *testing.T, name string, params map[string]any, within time.Duration, into any) {
	t.Helper()
	if err := w.try(t, name, params, within, into); err != nil {
		t.Fatalf("%v", err)
	}
}

// winKDCStop is what service.ps1's stop answers: the KDC's state, when it
// stopped, and when the task it registered will start it again (all on the
// DC's clock).
type winKDCStop struct {
	Status    string `json:"status"`
	StoppedAt string `json:"stopped_at"`
	StartAt   string `json:"start_at"`
}

// stopKDC stops the DC's KDC (service.ps1), fatal unless it stopped. The stop
// registers its own start restartAfter later: an SSH logon fails while the
// KDC is down, so nothing may call the DC until then.
func (w *winDC) stopKDC(t *testing.T, restartAfter time.Duration) winKDCStop {
	t.Helper()
	var r winKDCStop
	w.run(t, "service", map[string]any{"name": "Kdc", "state": "stop", "restart_after": int(restartAfter / time.Second)}, 5*time.Minute, &r)
	if r.Status != "Stopped" {
		t.Fatalf("windows: Kdc is %s after stop, want Stopped", r.Status)
	}
	return r
}

// scrubbedTail is raw's last n bytes with the run's secrets scrubbed first:
// cutting first could leave half of a password that the scrub no longer
// matches.
func (w *winDC) scrubbedTail(raw string, n int) string {
	return tailOf(strings.TrimSpace(winScrub(raw, w.secrets()...)), n)
}

// logTail is dockur's last n bytes of log: install progress. That it never
// holds a password is unmeasured, so it is scrubbed like any other output.
func (w *winDC) logTail(n int) string {
	b, _ := w.dockerCompose("logs", "--no-color", "--tail", "20", "dc").CombinedOutput()
	return w.scrubbedTail(string(b), n)
}

// waitSSH waits for the VM's sshd to take the Administrator's password and
// run a script, saying every two minutes what dockur last said: Windows
// Setup is silent for long stretches. A script that ran and failed means
// the VM is up and the bootstrap is broken, which no wait mends: three in a
// row fail the run at once, not after the whole wait. authStall is how long a
// refused password may last (winAuthWatch); after the promotion's reboot the
// password is proved, so that wait passes zero and never stalls on it.
func (w *winDC) waitSSH(t *testing.T, within, authStall time.Duration) {
	t.Helper()
	deadline, next, ran := time.Now().Add(within), time.Now(), 0
	auth := winAuthWatch{stall: authStall}
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		_, err := w.ps(ctx, "clock", nil)
		cancel()
		if err == nil {
			return
		}
		if auth.observe(err, time.Now()) {
			t.Fatalf("windows: sshd has refused the Administrator's password for %s: dockur's PASSWORD (windows.env) may not "+
				"reach the built-in Administrator; see dockur's log: %s", authStall, w.logTail(1500))
		}
		var se *winScriptErr
		if errors.As(err, &se) && !se.cut {
			if ran++; ran >= 3 {
				t.Fatalf("windows: the VM answers SSH but the bootstrap fails, three times in a row: %v", err)
			}
		} else {
			ran = 0
		}
		if up, _ := w.dockerCompose("ps", "--status", "running", "-q", "dc").Output(); strings.TrimSpace(string(up)) == "" {
			t.Fatalf("windows: the dc container is not running; dockur: %s", w.logTail(1500))
		}
		if time.Now().After(deadline) {
			t.Fatalf("windows: no SSH session within %s (%s); dockur: %s", within,
				oneLineMax(winScrub(err.Error(), w.secrets()...), 200), w.logTail(1500))
		}
		if time.Now().After(next) {
			refused := ""
			if !auth.since.IsZero() {
				refused = fmt.Sprintf(" (refused auth since %s ago)", time.Since(auth.since).Round(time.Second))
			}
			t.Logf("windows: waiting for SSH%s; dockur: %s", refused, oneLineMax(winScrub(w.logTail(300), w.secrets()...), 300))
			next = time.Now().Add(2 * time.Minute)
		}
		time.Sleep(15 * time.Second)
	}
}

// waitReady waits for AD DS to answer after the promotion's reboot. ready.ps1
// throws while AD Web Services starts, which is the wait's own business; a
// bootstrap that wrote no result at all, three times in a row, is broken and
// fails the run at once (waitSSH's rule, for the bootstrap only).
func (w *winDC) waitReady(t *testing.T, within time.Duration) {
	t.Helper()
	deadline, broken := time.Now().Add(within), 0
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		_, err := w.ps(ctx, "ready", nil)
		cancel()
		if err == nil {
			return
		}
		var se *winScriptErr
		if errors.As(err, &se) && se.bootstrapBroke() {
			if broken++; broken >= 3 {
				t.Fatalf("windows: the bootstrap wrote no result three times in a row after the reboot: %v", err)
			}
		} else {
			broken = 0
		}
		if time.Now().After(deadline) {
			t.Fatalf("windows: AD DS did not answer within %s of the promotion's reboot: %v", within, err)
		}
		time.Sleep(15 * time.Second)
	}
}

// awaitReboot waits for the DC to come back from the reboot registry.ps1's
// timer starts: until ready.ps1 answers from a boot other than before. It never
// fails the test, because a registry restore may call it while a failure
// unwinds; it says every two minutes that it is still waiting.
func (w *winDC) awaitReboot(t *testing.T, before string, within time.Duration) error {
	t.Helper()
	start := time.Now()
	deadline, next := start.Add(within), start.Add(2*time.Minute)
	time.Sleep(30 * time.Second) // the timer is 15s; a probe before it fires reads the old boot
	var last error
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		res, err := w.ps(ctx, "ready", nil)
		cancel()
		if err == nil {
			var r struct {
				Boot string `json:"boot"`
			}
			if err = json.Unmarshal(res, &r); err == nil && winBootChanged(before, r.Boot) {
				t.Logf("windows: the DC is back from its reboot after %s", time.Since(start).Round(time.Second))
				return nil
			}
			if err == nil {
				err = errors.New("ready.ps1 still answers from the boot before the reboot")
			}
		}
		last = err
		if time.Now().After(deadline) {
			return fmt.Errorf("the DC was not back from its reboot within %s: %v", within, last)
		}
		if time.Now().After(next) {
			t.Logf("windows: waiting for the DC to come back from its reboot (%s)", time.Since(start).Round(time.Second))
			next = time.Now().Add(2 * time.Minute)
		}
		time.Sleep(15 * time.Second)
	}
}

// winBootChanged is whether now is a later boot than before, both as
// ready.ps1 and registry.ps1 answer them (RFC 3339, UTC). LastBootUpTime is
// derived, and moves when the clock is stepped within one boot, so a string
// that differs is not enough: a reboot is at least a minute after the boot it
// ends. An unreadable time is no proof of a reboot.
func winBootChanged(before, now string) bool {
	b, err := time.Parse(time.RFC3339Nano, before)
	if err != nil {
		return false
	}
	n, err := time.Parse(time.RFC3339Nano, now)
	if err != nil {
		return false
	}
	return n.Sub(b) > time.Minute
}

// bootNow is the boot ready.ps1 answers from, never failing the test.
func (w *winDC) bootNow() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	res, err := w.ps(ctx, "ready", nil)
	if err != nil {
		return "", err
	}
	var r struct {
		Boot string `json:"boot"`
	}
	if err := json.Unmarshal(res, &r); err != nil {
		return "", fmt.Errorf("ready.ps1's answer: %v", err)
	}
	if _, err := time.Parse(time.RFC3339Nano, r.Boot); err != nil {
		return "", fmt.Errorf("ready.ps1's boot %q: %v", r.Boot, err)
	}
	return r.Boot, nil
}

// winWriteFile0600 writes body to path, owner-only.
func winWriteFile0600(t *testing.T, path string, body []byte) {
	t.Helper()
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
}

func winWriteJSON0600(t *testing.T, path string, v any) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	winWriteFile0600(t, path, b)
}

// loadKept reads a kept DC's secrets and state, true when both are there, it
// was built, and its container runs.
func (w *winDC) loadKept() bool {
	var s winSecrets
	b, err := os.ReadFile(filepath.Join(w.dir, "secrets.json"))
	if err != nil || json.Unmarshal(b, &s) != nil {
		return false
	}
	st, err := os.ReadFile(filepath.Join(w.dir, "state.json"))
	if err != nil || json.Unmarshal(st, &w.state) != nil || !w.state.Built {
		return false
	}
	w.sec = &s
	up, _ := w.dockerCompose("ps", "--status", "running", "-q", "dc").Output()
	return strings.TrimSpace(string(up)) != ""
}

// winEnsureISO is the pinned evaluation ISO's path in the cache
// (PORT49_LAB_ISO_DIR, default ~/.cache/port49-lab/iso), downloaded from
// Microsoft on first use and checked by size and SHA-256 every time: a file
// that does not match is never handed to the VM.
func winEnsureISO(t *testing.T) string {
	t.Helper()
	dir := os.Getenv("PORT49_LAB_ISO_DIR")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			t.Fatal(err)
		}
		dir = filepath.Join(home, ".cache", "port49-lab", "iso")
	}
	path := filepath.Join(dir, "windows-server-2025-eval-26100.32230.iso")
	if winISOOK(path, winISOSize, winISOSHA256) == nil {
		return path
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	part := path + ".part"
	t.Logf("windows: downloading the evaluation ISO (%d bytes) to %s, within %s, failing after %s without a byte",
		winISOSize, dir, winISODeadline, winISOIdle)
	ctx, cancel := context.WithTimeout(context.Background(), winISODeadline)
	defer cancel()
	if err := winDownloadTo(ctx, winISOURL, part, 1<<30, winISOIdle, t.Logf); err != nil {
		_ = os.Remove(part)
		t.Fatalf("windows: fetching the ISO: %v", err)
	}
	if err := winISOOK(part, winISOSize, winISOSHA256); err != nil {
		_ = os.Remove(part)
		t.Fatalf("windows: the downloaded ISO is not the pinned one: %v", err)
	}
	if err := os.Rename(part, path); err != nil {
		t.Fatal(err)
	}
	return path
}

// winISODeadline bounds the 8 GB download as a whole, long enough for a slow
// line (about 5 Mbit/s); winISOIdle is how long it may go without a byte, so
// a stall fails the run in minutes and a slow but moving download does not.
const (
	winISODeadline = 4 * time.Hour
	winISOIdle     = 2 * time.Minute
)

// winDownloadTo fetches url to part under ctx, saying every `every` bytes how
// far it is: a read that brings nothing for idle ends the download, as does
// ctx, so a stall ends and never hangs.
func winDownloadTo(ctx context.Context, url, part string, every int64, idle time.Duration, logf func(string, ...any)) error {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	stalled := fmt.Errorf("no byte for %s", idle)
	timer := time.AfterFunc(idle, func() { cancel(stalled) })
	defer timer.Stop()
	err := winDownloadBody(ctx, url, part, every, logf, func() { timer.Reset(idle) })
	if c := context.Cause(ctx); err != nil && c != nil && errors.Is(c, stalled) {
		return fmt.Errorf("%w (%v)", c, err)
	}
	return err
}

// winDownloadBody is winDownloadTo's transfer; moved runs after each read
// that brought bytes.
func winDownloadBody(ctx context.Context, url, part string, every int64, logf func(string, ...any), moved func()) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %s", resp.Status)
	}
	f, err := os.Create(part)
	if err != nil {
		return err
	}
	var n int64
	next := every
	buf := make([]byte, 1<<20)
	for {
		k, rerr := resp.Body.Read(buf)
		if k > 0 {
			moved()
			if _, err := f.Write(buf[:k]); err != nil {
				f.Close()
				return err
			}
			n += int64(k)
			if n >= next {
				logf("windows: ISO %d MiB downloaded", n>>20)
				next += every
			}
		}
		if rerr == io.EOF {
			return f.Close()
		}
		if rerr != nil {
			f.Close()
			return rerr
		}
	}
}

// winStatfsUp is the free space (GiB) of the filesystem holding p, read at the
// nearest ancestor that can be read: Docker's data root is not readable by the
// lab's user, though its filesystem is the one the VM's disk fills.
func winStatfsUp(p string) (uint64, string, error) {
	for {
		var st syscall.Statfs_t
		err := syscall.Statfs(p, &st)
		if err == nil {
			return st.Bavail * uint64(st.Bsize) >> 30, p, nil
		}
		parent := filepath.Dir(p)
		if parent == p {
			return 0, "", err
		}
		p = parent
	}
}

// winDiskCheck fails the run when the filesystem under dir, or Docker's data
// root (where the VM's disk lives, which may be another one), has less than
// need GiB free (Lab rules).
func winDiskCheck(t *testing.T, dir string, need uint64) {
	t.Helper()
	paths := []string{dir}
	if b, err := dockerCmd("info", "-f", "{{.DockerRootDir}}").Output(); err == nil && strings.TrimSpace(string(b)) != "" {
		paths = append(paths, strings.TrimSpace(string(b)))
	} else {
		t.Logf("windows: Docker's data root was not read (%v); only %s is checked for space", err, dir)
	}
	for _, p := range paths {
		free, at, err := winStatfsUp(p)
		if err != nil {
			t.Fatal(err)
		}
		if free < need {
			t.Fatalf("windows: %d GiB free on the filesystem of %s, the run needs %d (stop and report: Lab rules)", free, at, need)
		}
	}
}

// winLock takes the exclusive, non-blocking lock on path (made 0600 with its
// directory) and returns its release.
func winLock(path string) (func(), error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, err
	}
	return func() { _ = f.Close() }, nil
}

// winLabHeld is whether a fresh run must refuse to start: the project's dc
// container is running (psOut is `docker ps -q` of it) and the run is not a
// REUSE of a kept DC, which is meant to find it up.
func winLabHeld(reused bool, psOut string) bool {
	return !reused && strings.TrimSpace(psOut) != ""
}

// startWindowsDC builds the DC on d's PKI and password and returns it as a
// directory. With PORT49_LAB_WINDOWS_REUSE set and a kept DC up, it re-runs
// only the per-run steps (R7: a reused DC never closes L44).
func startWindowsDC(t *testing.T, d *directories) *labDir {
	t.Helper()
	// First: before G2 and before any docker or compose call. The kernel drops
	// it if the process dies; the cleanup drops it when the test ends.
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	release, err := winLock(filepath.Join(home, ".cache", "port49-lab", "windows.lock"))
	if err != nil {
		t.Fatalf("another L44 run holds the lab (windows.lock): %v", err)
	}
	t.Cleanup(release)
	repo, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	w := &winDC{dir: filepath.Join(repo, "tests", "lab", "logs", "windows"),
		compose: filepath.Join(repo, "tests", "lab", "directory", "windows", "compose.yaml"), port49: d.password}
	w.reused = os.Getenv("PORT49_LAB_WINDOWS_REUSE") != "" && w.loadKept()
	// Before the fresh tree below, and before any compose command: both would
	// destroy a DC another run is using.
	if !w.reused {
		up, _ := dockerCmd("ps", "--filter", "label=com.docker.compose.project="+winProject,
			"--filter", "label=com.docker.compose.service=dc", "--filter", "status=running", "-q").Output()
		if winLabHeld(w.reused, string(up)) {
			t.Fatalf("another L44 run holds the lab (%s dc is running); stop it with `docker compose -p %s down -v` if it is a leftover", winProject, winProject)
		}
	}
	if !w.reused {
		// A fresh tree: no secret, key or state of an earlier run serves this one.
		if err := os.RemoveAll(w.dir); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(w.dir, "pkinit"), 0o700); err != nil {
			t.Fatal(err)
		}
		if w.sec, err = newWinSecrets(); err != nil {
			t.Fatal(err)
		}
		winWriteJSON0600(t, filepath.Join(w.dir, "secrets.json"), w.sec)
		winWriteFile0600(t, filepath.Join(w.dir, "windows.env"), []byte(winEnv(w.sec)))
		// Registered at once, so a failed disk check or ISO download leaves no
		// secret behind; down repeats it. Not with KEEP: a kept DC needs them.
		if os.Getenv("PORT49_LAB_WINDOWS_KEEP") == "" {
			t.Cleanup(w.removeSecrets)
		}
		// Before the ISO: a first run downloads 8.2 GB.
		winDiskCheck(t, w.dir, 66)
	}
	d.extra = append(d.extra, w.sec.all()...)
	iso := winEnsureISO(t)
	winWriteFile0600(t, filepath.Join(w.dir, "compose.env"), []byte("PORT49_LAB_WINDOWS_ISO="+iso+"\n"))
	if os.Getenv("PORT49_LAB_WINDOWS_KEEP") == "" {
		t.Cleanup(func() { w.down(t) })
	}
	if !w.reused {
		_ = w.dockerCompose("--profile", "tools", "down", "-v", "--remove-orphans", "-t", "120").Run()
		if b, err := w.dockerCompose("--profile", "tools", "build", "pkinit").CombinedOutput(); err != nil {
			t.Fatalf("building the pkinit image: %v\n%s", err, w.scrubbedTail(string(b), 2000))
		}
		if b, err := w.dockerCompose("up", "-d", "dc").CombinedOutput(); err != nil {
			t.Fatalf("docker compose up dc: %v\n%s", err, w.scrubbedTail(string(b), 2000))
		}
		w.waitSSH(t, 150*time.Minute, winAuthStall)
		w.run(t, "promote", map[string]any{"dsrm_password": w.sec.DSRMPassword}, 30*time.Minute, nil)
		time.Sleep(90 * time.Second) // promote.ps1's timer reboots the VM 15s after it answers
		w.waitSSH(t, 40*time.Minute, 0)
		w.waitReady(t, 20*time.Minute)
		var seed struct {
			Loop         string    `json:"loop"`
			AliceCreated time.Time `json:"alice_created"`
		}
		w.run(t, "seed", map[string]any{"port49_password": w.port49}, 15*time.Minute, &seed)
		w.state = winState{Built: true, AliceCreated: seed.AliceCreated, Loop: seed.Loop}
		winWriteJSON0600(t, filepath.Join(w.dir, "state.json"), w.state)
	}
	// The URIs name the DC, as an operator's would; this process resolves that
	// name to the published ports (windows_resolve_test.go says why).
	winResolveDC(t)
	l := &labDir{name: platWindows, service: "dc", uri: "ldaps://" + winDCHost + ":30636", plainURI: "ldap://" + winDCHost + ":30389",
		bindDN: "CN=port49,OU=Svc," + dirBase, userFilter: "(&(objectCategory=person)(objectClass=user))",
		groupFilter: "(objectClass=group)", usernameAttr: "sAMAccountName", baseDN: dirBase, groupsBaseDN: "OU=G," + dirBase,
		image: winImage, d: d, win: w,
		where: "Windows Server 2025 Standard Evaluation as a KVM VM in `dockurr/windows`, on " +
			"`tests/lab/directory/windows/compose.yaml` (no network device)",
		credentials: "none appear here or in the evidence. The Administrator, DSRM and port49 passwords are generated for " +
			"each run, held only in 0600 files under `tests/lab/logs/windows`, and reach the VM on an SSH session's stdin, " +
			"never on a host command line; the one command line that carries one is `ktpass`'s own, inside the VM, which " +
			"is destroyed at the end of the run. Alice's is made on the DC and never leaves it. The keytab and every " +
			"private key stay on the host that ran it, 0600, and are removed at the end of the run.",
		keytabFile: filepath.Join(w.dir, "port49.keytab"), krb5File: filepath.Join(w.dir, "krb5.conf")}
	if w.state.Loop != "made" {
		l.loopRefused = w.state.Loop
	}
	w.perRun(t, l)
	l.waitLDAPS(t, 3*time.Minute)
	l.checkFixture(t)
	return l
}

// perRun is what every run does, on a fresh DC or a kept one: the clock
// checked, port49's password and alice's mapping set, AD CS ensured, LDAPS on
// the run's certificate, the keytab, the run's CAs trusted, the client
// certificates issued, the facts read.
func (w *winDC) perRun(t *testing.T, l *labDir) {
	t.Helper()
	d := l.d
	w.checkSkew(t)
	w.run(t, "reset", map[string]any{"port49_password": w.port49,
		"alice_altsecid": directory.ADIssuerSerial(d.pki.alice)}, 5*time.Minute, nil)
	var adcs struct {
		CAPEM  string `json:"ca_pem"`
		KDCPEM string `json:"kdc_pem"`
	}
	w.run(t, "adcs", nil, 30*time.Minute, &adcs)
	var err error
	if w.adcsRoot, err = winParsePEMCert([]byte(adcs.CAPEM)); err != nil {
		t.Fatalf("windows: the enterprise CA's certificate: %v", err)
	}
	if w.certs.dcKDC, err = winParsePEMCert([]byte(adcs.KDCPEM)); err != nil {
		t.Fatalf("windows: the DC's KDC certificate: %v", err)
	}
	var req struct {
		CSRPEM string `json:"csr_pem"`
	}
	w.run(t, "ldaps", map[string]any{"step": "request"}, 5*time.Minute, &req)
	certPEM, err := d.pki.signServerCSR([]byte(req.CSRPEM), time.Now())
	if err != nil {
		t.Fatalf("windows: signing the DC's LDAPS request: %v", err)
	}
	w.run(t, "ldaps", map[string]any{"step": "install", "cert_pem": string(certPEM), "lab_ca_pem": string(d.pki.ca.PEM())},
		5*time.Minute, nil)
	// The keytab: three tries, then the GSSAPI cells are INVALID (R6) and the
	// run goes on to the cells that need no keytab. keytab.ps1 reports only
	// ktpass's exit code, and that is all a failure says here.
	var kerr error
	for try := 0; try < 3; try++ {
		var kt struct {
			KeytabB64 string `json:"keytab_b64"`
		}
		if kerr = w.try(t, "keytab", map[string]any{"port49_password": w.port49}, 5*time.Minute, &kt); kerr == nil {
			raw, err := base64.StdEncoding.DecodeString(kt.KeytabB64)
			if err == nil && len(raw) > 0 {
				winWriteFile0600(t, l.keytabFile, raw)
				break
			}
			kerr = fmt.Errorf("the keytab did not come back (%d bytes)", len(raw))
		}
		t.Logf("windows: keytab, try %d of 3: %s", try+1, oneLineMax(winScrub(kerr.Error(), w.secrets()...), 300))
	}
	if kerr != nil {
		w.invalid = append(w.invalid, "keytab: "+oneLineMax(winScrub(kerr.Error(), w.secrets()...), 300))
	}
	winWriteFile0600(t, l.krb5File, []byte(krb5Conf(winKDC)))
	comma, commaKey, err := winCommaCA(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, ca := range []struct {
		name string
		c    *x509.Certificate
	}{{"lab-users-ca", d.pki.usersCA}, {"lab-users-comma-ca", comma}} {
		w.run(t, "trust", map[string]any{"ca_pem": string(winPEMCert(ca.c)), "name": ca.name}, 5*time.Minute, nil)
		// The PKINIT client must anchor its own certificate's issuer, or MIT
		// fails before it asks the KDC ("unable to get local issuer certificate").
		winWriteFile0600(t, filepath.Join(w.dir, "pkinit", ca.name+".pem"), winPEMCert(ca.c))
	}
	winWriteFile0600(t, filepath.Join(w.dir, "pkinit", "krb5.conf"), []byte(winPKINITConf(winKDCInNet)))
	winWriteFile0600(t, filepath.Join(w.dir, "pkinit", "adcs-root.pem"), winPEMCert(w.adcsRoot))
	w.issueCerts(t, d, comma, commaKey)
	w.run(t, "facts", nil, 5*time.Minute, &w.facts)
	w.facts.MIT = w.mitVersions(t)
}

// mitVersions is the MIT Kerberos the PKINIT client really runs: the versions
// its image recorded when it was built (the packages are not pinned).
func (w *winDC) mitVersions(t *testing.T) string {
	t.Helper()
	b, err := w.dockerCompose("--profile", "tools", "run", "--rm", "-T", "pkinit", "cat", "/etc/pkinit-versions").Output()
	v := winMITVersions(string(b))
	if err != nil || v == "" {
		t.Logf("windows: the PKINIT image's versions were not read: %v", err)
		return "not read"
	}
	return v
}

// winMITVersions is /etc/pkinit-versions (rpm's "name<TAB>version-release"
// lines) as "name version, ...": any other line is dropped, so an error's
// text never stands for a version.
func winMITVersions(out string) string {
	var parts []string
	for _, l := range strings.Split(out, "\n") {
		if f := strings.Split(strings.TrimSpace(l), "\t"); len(f) == 2 && f[0] != "" && f[1] != "" && !strings.Contains(l, " ") {
			parts = append(parts, f[0]+" "+f[1])
		}
	}
	return strings.Join(parts, ", ")
}

// issueCerts issues the run's client certificates (R5) and checks none
// predates alice's account.
func (w *winDC) issueCerts(t *testing.T, d *directories, comma *x509.Certificate, commaKey *ecdsa.PrivateKey) {
	t.Helper()
	// AD CS backdates NotBefore ten minutes. A certificate older than alice's
	// account meets KB5014754's backdating check, which is no part of the claim.
	if wait := time.Until(w.state.AliceCreated.Add(11 * time.Minute)); wait > 0 {
		t.Logf("windows: waiting %s so AD CS's certificates do not predate alice's account", wait.Round(time.Second))
		time.Sleep(wait)
	}
	c := &w.certs
	c.brokerADCS, c.brokerKey = w.issue(t, "port49-broker", "", "OfflineRouter")
	c.aliceADCS, c.aliceADCSKey = w.issue(t, "alice", "alice@corp.example.com", "OfflineRouter")
	c.aliceSID, c.aliceSIDKey = w.enrollAs(t, "alice")
	now := time.Now()
	var err error
	if c.aliceComma, c.aliceCommaKey, err = winPersonCert(comma, commaKey, "alice", "alice@corp.example.com", dirSerial(), now); err != nil {
		t.Fatal(err)
	}
	if c.aliceHighBit, c.aliceHighBitKey, err = winPersonCert(d.pki.usersCA, d.pki.usersKey, "alice", "alice@corp.example.com",
		winHighBitSerial(), now); err != nil {
		t.Fatal(err)
	}
	people := []*x509.Certificate{c.aliceADCS, c.aliceComma, c.aliceHighBit}
	if c.aliceSID != nil { // nil when enroll_as failed three times: the sid cells are INVALID
		people = append(people, c.aliceSID)
	}
	if err := winIssuedAfter(w.state.AliceCreated, people...); err != nil {
		t.Fatalf("windows: precondition: %v", err)
	}
	c.brokerCertFile = filepath.Join(w.dir, "broker-adcs.pem")
	c.brokerKeyFile = filepath.Join(w.dir, "broker-adcs-key.pem")
	winWriteFile0600(t, c.brokerCertFile, winPEMCert(c.brokerADCS))
	winWriteFile0600(t, c.brokerKeyFile, winPEMKey(c.brokerKey))
}

// issue has the enterprise CA sign a request for cn (and upn) under template,
// the key made here.
func (w *winDC) issue(t *testing.T, cn, upn, template string) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	csr, key, err := winCSR(cn, upn)
	if err != nil {
		t.Fatal(err)
	}
	var r struct {
		CertPEM string `json:"cert_pem"`
	}
	w.run(t, "issue", map[string]any{"csr_pem": string(csr), "template": template}, 5*time.Minute, &r)
	c, err := winParsePEMCert([]byte(r.CertPEM))
	if err != nil {
		t.Fatalf("windows: the %s certificate for %s: %v", template, cn, err)
	}
	return c, key
}

// enrollAs is user's own User certificate, requested as user (enroll_as.ps1).
// It is the riskiest step: after three failed tries it returns nil, nil and
// records why in w.invalid, so the sid cells are INVALID (R6) and the run goes
// on to every cell that does not need the certificate.
func (w *winDC) enrollAs(t *testing.T, user string) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	var err error
	for try := 0; try < 3; try++ {
		var csr []byte
		var key *rsa.PrivateKey
		if csr, key, err = winCSR(user, ""); err != nil {
			t.Fatal(err)
		}
		var r struct {
			CertPEM string `json:"cert_pem"`
		}
		if err = w.try(t, "enroll_as", map[string]any{"csr_pem": string(csr), "user": user}, 10*time.Minute, &r); err == nil {
			var c *x509.Certificate
			if c, err = winParsePEMCert([]byte(r.CertPEM)); err == nil {
				return c, key
			}
		}
		t.Logf("windows: enroll_as %s, try %d of 3: %s", user, try+1, oneLineMax(winScrub(err.Error(), w.secrets()...), 300))
	}
	w.invalid = append(w.invalid, "sid: enroll_as: "+oneLineMax(winScrub(err.Error(), w.secrets()...), 300))
	return nil, nil
}

// clock is the DC's UTC time, ISO 8601: the "since" of an events read, on
// the DC's own clock.
func (w *winDC) clock(t *testing.T) string {
	t.Helper()
	var r struct {
		UTCNow string `json:"utc_now"`
	}
	w.run(t, "clock", nil, time.Minute, &r)
	return r.UTCNow
}

// checkSkew fails the run, as a precondition, when the DC's clock is more
// than 60s from ours (R6).
func (w *winDC) checkSkew(t *testing.T) {
	t.Helper()
	dc, err := time.Parse(time.RFC3339Nano, w.clock(t))
	if err != nil {
		t.Fatalf("windows: the DC's clock: %v", err)
	}
	if now := time.Now(); !winSkewOK(dc, now, time.Minute) {
		t.Fatalf("windows: precondition: the DC's clock is %s from ours", dc.Sub(now).Round(time.Second))
	}
}

// events is what the DC logged since (its own clock).
func (w *winDC) events(t *testing.T, since string) []winEvent {
	t.Helper()
	var r struct {
		Events []winEvent `json:"events"`
	}
	w.run(t, "events", map[string]any{"since": since}, 2*time.Minute, &r)
	return r.Events
}

// setValues replaces attr on dn with vals (clears it when vals holds none)
// and asserts the DC holds exactly that afterwards (Review Focus 3).
func (w *winDC) setValues(t *testing.T, dn, attr string, vals []string) {
	t.Helper()
	var r struct {
		Values []string `json:"values"`
	}
	w.run(t, "set_attr", map[string]any{"dn": dn, "attribute": attr, "values": vals}, 2*time.Minute, &r)
	want := ""
	if len(vals) == 1 {
		want = vals[0]
	}
	if !winOnlyValue(r.Values, want) {
		t.Fatalf("windows: %s on %s holds %d value(s) after the set, not exactly the one asked", attr, dn, len(r.Values))
	}
}

// setAltSec gives dn exactly value as altSecurityIdentities, or none for "".
func (w *winDC) setAltSec(t *testing.T, dn, value string) {
	t.Helper()
	var vals []string
	if value != "" {
		vals = []string{value}
	}
	w.setValues(t, dn, "altSecurityIdentities", vals)
}

// winRegistryResult is what registry.ps1 answers.
type winRegistryResult struct {
	Value     string `json:"value"`
	Restarted string `json:"restarted"` // "Kdc", or "reboot" for an NTDS setting
	Boot      string `json:"boot"`      // the boot the change was made in
}

// setRegistry sets one of the DC settings the run varies (-1 deletes it),
// waits out the reboot and for LDAPS when the setting is NTDS's, and returns
// the value in force.
func (l *labDir) setRegistry(t *testing.T, name string, value int) string {
	t.Helper()
	var r winRegistryResult
	l.win.run(t, "registry", map[string]any{"name": name, "value": value}, winRegistryWithin, &r)
	if r.Restarted == "reboot" {
		if err := l.win.awaitReboot(t, r.Boot, winRebootWithin); err != nil {
			t.Fatalf("windows: after setting %s: %v", name, err)
		}
		l.waitLDAPS(t, 5*time.Minute)
	}
	return r.Value
}

// kinit asks the DC's KDC for principal's TGT by PKINIT with c and key, from
// the Fedora container on the project network, and reads the answer from
// MIT's trace, which is parsed and never printed. The key file is 0600 and
// removed after.
func (w *winDC) kinit(t *testing.T, label, principal string, c *x509.Certificate, key *rsa.PrivateKey) winPKINITResult {
	t.Helper()
	base := filepath.Join(w.dir, "pkinit", label)
	winWriteFile0600(t, base+".pem", winPEMCert(c))
	winWriteFile0600(t, base+"-key.pem", winPEMKey(key))
	defer os.Remove(base + "-key.pem")
	script := fmt.Sprintf(`export KRB5_CONFIG=/l44/krb5.conf; KRB5_TRACE=/dev/stdout kinit -X X509_user_identity=FILE:/l44/%[1]s.pem,/l44/%[1]s-key.pem %[2]s </dev/null 2>&1; echo "lab: kinit exit $?"; klist 2>&1`,
		label, principal)
	start := time.Now()
	out, _ := w.dockerCompose("--profile", "tools", "run", "--rm", "-T", "pkinit", "sh", "-c", script).CombinedOutput()
	r := winParseKinit(string(out))
	r.took = time.Since(start)
	return r
}

// down keeps dockur's log (0600, scrubbed: that it prints no password is
// unmeasured) and takes the project down with its volumes, the VM's disk
// among them. Without PORT49_LAB_WINDOWS_KEEP it also removes every secret
// and key the run wrote.
func (w *winDC) down(t *testing.T) {
	t.Helper()
	if b, err := w.dockerCompose("logs", "--no-color", "dc").CombinedOutput(); err == nil {
		_ = os.WriteFile(filepath.Join(w.dir, "dc.log"), []byte(winScrub(string(b), w.secrets()...)), 0o600)
	}
	if b, err := w.dockerCompose("--profile", "tools", "down", "-v", "--remove-orphans", "-t", "120").CombinedOutput(); err != nil {
		t.Errorf("docker compose down (windows): %v\n%s", err, w.scrubbedTail(string(b), 2000))
	}
	w.removeSecrets()
}

// removeSecrets removes every secret, key and keytab the run wrote, and the
// kept DC's state. It is safe to call twice.
func (w *winDC) removeSecrets() {
	for _, f := range []string{"pkinit", "port49.keytab", "broker-adcs-key.pem", "secrets.json", "windows.env", "state.json"} {
		_ = os.RemoveAll(filepath.Join(w.dir, f))
	}
}

// version is the note's image line: the build the DC reports, the ISO and the image.
func (w *winDC) version() string {
	f := w.facts
	return fmt.Sprintf("%s (%s), build %s; ISO `%s` (SHA-256 `%s`); image `%s`%s", f.Caption, f.Edition, f.Build,
		path.Base(winISOURL), winISOSHA256, winImage, map[bool]string{true: "; **a reused DC (not a closing run, R7)**"}[w.reused])
}

// factsSection is the note's table of what the DC was, as the run found it.
func (w *winDC) factsSection() string {
	f := w.facts
	keys := make([]string, 0, len(f.NTDSLDAP))
	for k := range f.NTDSLDAP {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	var ldapSet []string
	for _, k := range keys {
		ldapSet = append(ldapSet, fmt.Sprintf("`%s` = %s", k, f.NTDSLDAP[k]))
	}
	if len(ldapSet) == 0 {
		ldapSet = []string{"none set"}
	}
	var b strings.Builder
	b.WriteString("### The DC, as the run found it\n\n| fact | value |\n|---|---|\n")
	fmt.Fprintf(&b, "| build | %s %s (%s), %s |\n", f.Caption, f.DisplayVersion, f.Edition, f.Build)
	fmt.Fprintf(&b, "| updates | %s |\n", strings.Join(f.Hotfixes, ", "))
	fmt.Fprintf(&b, "| domain and forest modes | %s, %s |\n", f.DomainMode, f.ForestMode)
	fmt.Fprintf(&b, "| `StrongCertificateBindingEnforcement` as installed | %s |\n", f.StrongBinding)
	fmt.Fprintf(&b, "| `CertificateBackdatingCompensation` | %s |\n", f.Backdating)
	fmt.Fprintf(&b, "| Schannel `CertificateMappingMethods` | %s |\n", f.MappingMethods)
	fmt.Fprintf(&b, "| NTDS LDAP settings in the registry | %s |\n", strings.Join(ldapSet, "; "))
	fmt.Fprintf(&b, "| account lockout threshold | %d |\n", f.LockoutThreshold)
	fmt.Fprintf(&b, "| PKINIT client (MIT Kerberos 1.22+, Fedora 43), as installed in its image | %s |\n\n", f.MIT)
	return b.String()
}

// configNote is what the DC was set up to do that the note's rows depend on.
func (w *winDC) configNote() string {
	return "### How this directory was configured\n\n" +
		"- Windows Server 2025 Standard Evaluation, installed unattended by `dockurr/windows` from the pinned ISO into a " +
		"KVM VM (6 GB, 4 vCPUs), and promoted to the first DC of a new forest `corp.example.com` by `Install-ADDSForest` " +
		"with this build's defaults.\n" +
		"- Set up only over OpenSSH (installed by Windows, started by `oem/install.bat`) as the domain's Administrator. The " +
		"Windows firewall is off and Windows Update disabled, so the build measured is the ISO's. Ports are published on " +
		"127.0.0.1 only.\n" +
		"- L42's fixture, made by `scripts/seed.ps1` with global security groups; the second `netops-oncall` is renamed in, " +
		"as on Samba.\n" +
		"- SASL EXTERNAL is measured over StartTLS on `ldap://dc1.corp.example.com:30389`, port49's own `start_tls` " +
		"connection. [MS-ADTS] 5.1.1.2: on the LDAPS port the DC authenticates the connection as the client certificate's " +
		"identity at the handshake and rejects an EXTERNAL bind there; over StartTLS it maps the certificate when an EXTERNAL " +
		"bind follows. One LDAPS EXTERNAL row is kept as an observation, with what the run read of that connection: its " +
		"result code, and WhoAmI with no bind.\n" +
		"- LDAPS serves a certificate from the lab CA (`localhost`, `dc1.corp.example.com`, 127.0.0.1), placed in the NTDS " +
		"service's own store; the lab CA is in the DC's Root store.\n" +
		"- The URIs name the DC, `dc1.corp.example.com`, which the test process alone resolves to 127.0.0.1, so port49's " +
		"GSSAPI bind asks for `ldap/dc1.corp.example.com`, an SPN the DC keeps itself. `ldap/localhost`, added to `DC1$` " +
		"as on Samba, left the account within minutes twice, with no 4742 event naming who removed it. The client " +
		"`krb5.conf` reaches the KDC at 127.0.0.1:30088 over TCP.\n" +
		"- `port49` is an ordinary domain user, AES only; its keytab is made with `ktpass` (AES256-SHA1, " +
		"`-mapuser CORP\\port49`), which also sets its UPN. `ktpass` takes the password on its own command line inside " +
		"the VM, the one place a secret is on a command line.\n" +
		"- AD CS: an enterprise root CA `corp-L44-CA` on the DC, `OfflineRouter` published for requests whose subject the " +
		"harness supplies, and the DC's `KerberosAuthentication` certificate enrolled for PKINIT. The lab users CA and a " +
		"second CA whose CN holds a comma are in the DC's Root store and in NTAuth.\n" +
		"- Each KB5014754 block starts with a control, `control-ski`: alice's AD CS certificate under the strong " +
		"`X509:<SKI>` mapping, which no part of the claim is about. A block whose control got no TGT is INVALID.\n" +
		"- Each `LdapEnforceChannelBinding` change reboots the DC, and the next cell waits for LDAPS. Restarting NTDS " +
		"after setting 2 instead was followed, once, in an earlier run on its own fresh DC, by `lsass.exe` crashing (an " +
		"access violation in `ntdsai.dll` 15 seconds after NTDS came back) and Windows restarting the VM; whether the " +
		"restart or the binds under 2 that followed set it off was not separated. The DC's boot is read before and after " +
		"the cells under 2, and a change makes them INVALID.\n" +
		"- The KDC is stopped for one EXTERNAL cell (OR-1) and started again by a task the stop registered; the next cell repeats the mapped " +
		"bind to show the DC recovered.\n" +
		"- Alice's `User` certificate is requested as alice over WinRM with CredSSP, under a session configuration only she " +
		"may use; all of it is removed after, and her password for it is made on the DC, used once and replaced. " +
		"`enroll_as` first registers `WSMAN/DC1` and `WSMAN/dc1.corp.example.com` on `DC1$` (this build's WinRM had " +
		"registered none, and without them CredSSP refuses the DC as a target); they stay on the lab DC.\n" +
		"- During the KB5014754 table only, `UseCachedCRLOnlyAndIgnoreRevocationUnknownErrors = 1` on the KDC: the " +
		"harness's own CAs publish no CRL, and revocation is no part of the claim. Removed after.\n" +
		"- LDAP interface diagnostics at level 2 (`16 LDAP Interface Events`), so the DC logs bind and channel-binding events.\n" +
		"- PKINIT's client is MIT Kerberos (`kinit` from Fedora 43's `krb5-workstation` and `krb5-pkinit`, the versions its image recorded are in " +
		"the facts table) on the project network, with `pkinit_kdc_hostname`, as MIT documents for an Active Directory KDC. " +
		"MIT 1.22 or later is required: Windows Server 2025's KDC answers FFDH PKINIT without MS-PKCA's `paChecksum2` with " +
		"KDC error 79 (\"Checksum must be included\"), and MIT added the field in 1.22 (krb5 commit 310793b); MIT 1.20 (Debian stable's, measured on this DC) failed every cell with it; 1.21 lacks the commit.\n\n" +
		"### Running it again\n\n" +
		"- From a worktree pinned at the commit under test: `PORT49_LAB_L44=1 go test -tags lab ./tests/lab/ -run '^TestL44WindowsAD$' " +
		"-count=1 -v -timeout 240m`. It needs `/dev/kvm`, Docker with Compose v2.24.4+, 6 GB of RAM and 66 GiB free; a " +
		"fresh run takes 1.5 to 2.5 hours. Windows Setup can be watched at `http://127.0.0.1:8006`.\n" +
		"- The evaluation ISO is cached in `PORT49_LAB_ISO_DIR` (default `~/.cache/port49-lab/iso`), checked by size and " +
		"SHA-256 on every run, and never committed or redistributed.\n" +
		"- `PORT49_LAB_WINDOWS_KEEP` leaves the DC and its secrets up; `PORT49_LAB_WINDOWS_REUSE` runs on a kept DC. Both " +
		"are for developing the harness: a note from a reused DC says so and never closes L44.\n" +
		"- Under `tests/lab/logs/windows`, `windows.env`, `secrets.json`, `port49.keytab`, `broker-adcs-key.pem` and " +
		"`pkinit/*-key.pem` hold secrets: never print them. The run removes them unless `PORT49_LAB_WINDOWS_KEEP` is set.\n" +
		"- Never print the project's resolved compose file or inspect its containers: both show the " +
		"Administrator's password from the environment.\n\n"
}
