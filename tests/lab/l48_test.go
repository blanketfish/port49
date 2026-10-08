//go:build lab

package lab

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/tests/lab/labcreds"
)

// L48 (policy engine spec §15): a workload CA's behaviour with port49's
// workload verifier, measured on step-ca. The claim is the row's text, word
// for word (a unit test holds the two equal).
const l48Claim = "A workload CA's behaviour with port49's workload verifier (plan 8). On step-ca: whether a certificate " +
	"requested for a SPIFFE ID carries it as its one URI SAN, with `clientAuth`, not a CA; whether `step ca renew` keeps " +
	"the ID and the key and changes the serial, and port49 mints for the renewed certificate with no change; when " +
	"`step ca renew --daemon` renews, as a fraction of the lifetime; with step-ca stopped, whether port49 mints until " +
	"`NotAfter` and refuses after, and when the late-renewal line comes; whether step-ca's CRL (`crl.enabled`) is DER, " +
	"issued by the intermediate, and loaded by port49's `certificate_status` over https with the broker trusting " +
	"step-ca's root (`SSL_CERT_FILE`), and whether a `step ca revoke` reaches port49 within `refresh_interval` and " +
	"stops a renewal of the revoked certificate; whether a provisioner's x509 name policy allowing one URI refuses a " +
	"request for another SPIFFE ID."

const (
	// stepCACRLURL is the CRL as the broker fetches it. step-ca's certificate
	// carries the name localhost (stepCA.client reaches it as that), so the
	// broker's fetch names it too; a name mismatch would be a TLS fault, INVALID.
	stepCACRLURL = "https://localhost:19000/1.0/crl"
	// l48Other is the SPIFFE ID the name-policy cell asks for.
	l48Other = "spiffe://port49.lab/host/other"
	// lateMarker is in both the broker's and the CLI's late-renewal lines.
	lateMarker = "its renewal is late"
)

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

// certFacts is what L48 records about a certificate. A certificate is public,
// so its PEM goes in the evidence with it.
type certFacts struct {
	Subject   string   `json:"subject"`
	Issuer    string   `json:"issuer"`
	URIs      []string `json:"uri_sans"`
	DNS       []string `json:"dns_sans"`
	EKUs      []string `json:"ekus"`
	IsCA      bool     `json:"is_ca"`
	Serial    string   `json:"serial"`
	NotBefore string   `json:"not_before"`
	NotAfter  string   `json:"not_after"`
	Lifetime  string   `json:"lifetime"`
	PEM       string   `json:"pem"`
}

func factsOf(c *x509.Certificate) certFacts {
	f := certFacts{Subject: c.Subject.String(), Issuer: c.Issuer.String(), DNS: c.DNSNames, EKUs: ekuNames(c.ExtKeyUsage),
		IsCA: c.IsCA, Serial: c.SerialNumber.Text(16), NotBefore: c.NotBefore.UTC().Format(time.RFC3339),
		NotAfter: c.NotAfter.UTC().Format(time.RFC3339), Lifetime: c.NotAfter.Sub(c.NotBefore).String(),
		PEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))}
	for _, u := range c.URIs {
		f.URIs = append(f.URIs, u.String())
	}
	for _, oid := range c.UnknownExtKeyUsage {
		f.EKUs = append(f.EKUs, oid.String())
	}
	return f
}

// ekuNames names extended key usages as RFC 5280 does, lower camel case.
func ekuNames(ekus []x509.ExtKeyUsage) []string {
	names := map[x509.ExtKeyUsage]string{x509.ExtKeyUsageAny: "any", x509.ExtKeyUsageServerAuth: "serverAuth",
		x509.ExtKeyUsageClientAuth: "clientAuth", x509.ExtKeyUsageCodeSigning: "codeSigning",
		x509.ExtKeyUsageEmailProtection: "emailProtection", x509.ExtKeyUsageTimeStamping: "timeStamping",
		x509.ExtKeyUsageOCSPSigning: "ocspSigning"}
	var out []string
	for _, e := range ekus {
		if n, ok := names[e]; ok {
			out = append(out, n)
		} else {
			out = append(out, fmt.Sprintf("unknown(%d)", int(e)))
		}
	}
	return out
}

// samePublicKey says whether two certificates certify one public key.
func samePublicKey(a, b *x509.Certificate) bool {
	return bytes.Equal(a.RawSubjectPublicKeyInfo, b.RawSubjectPublicKeyInfo)
}

// tokenRun is one `port49 workload token` run as the evidence keeps it: its
// exit and its stderr. It has no field for stdout, which holds the token.
type tokenRun struct {
	Exit      int    `json:"exit"`
	Stderr    string `json:"stderr"`
	AtSeconds int    `json:"at_seconds"`
}

func newTokenRun(exit int, stderr string, at time.Duration) tokenRun {
	return tokenRun{Exit: exit, Stderr: oneLineMax(stderr, 600), AtSeconds: int(at.Seconds())}
}

// stepEvidence is a run's evidence: an ordered list of named steps, written as
// one JSON document.
type stepEvidence struct{ steps []evidenceStep }

type evidenceStep struct {
	Step  string `json:"step"`
	Value any    `json:"value"`
}

func (e *stepEvidence) add(step string, v any) { e.steps = append(e.steps, evidenceStep{step, v}) }

// encode is the document, or an error when it holds key material, a compact
// JWS or one of secrets: nothing is written then.
func (e *stepEvidence) encode(secrets []string) ([]byte, error) {
	b, err := json.MarshalIndent(e.steps, "", "  ")
	if err != nil {
		return nil, err
	}
	if lerr := stepLeak(string(b), secrets); lerr != nil {
		return nil, fmt.Errorf("the evidence is not written: %w", lerr)
	}
	return append(b, '\n'), nil
}

// keySecrets are the strings that identify a PEM private key in text: each of
// its base64 body lines long enough to search for, and the body joined. A file
// with no private key gives none.
func keySecrets(raw []byte) []string {
	if block, _ := pem.Decode(raw); block == nil || !strings.Contains(block.Type, "PRIVATE KEY") {
		return nil
	}
	var out, body []string
	for _, ln := range strings.Split(string(raw), "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "-----") || strings.Contains(ln, ":") {
			continue
		}
		body = append(body, ln)
		if len(ln) >= 16 {
			out = append(out, ln)
		}
	}
	if joined := strings.Join(body, ""); len(joined) >= 16 && len(body) > 1 {
		out = append(out, joined)
	}
	return out
}

// statusLines are the lines of the broker's stderr about certificate status.
func statusLines(said string) []string {
	var out []string
	for _, ln := range strings.Split(said, "\n") {
		if strings.Contains(ln, "certificate status") {
			out = append(out, ln)
		}
	}
	return out
}

// crlTLSFailure says whether the broker's certificate-status lines name a TLS
// failure: the CRL fetch could not verify the server. That is a harness fault
// (INVALID), never a measured "step-ca's CRL is unusable".
func crlTLSFailure(said string) bool {
	for _, ln := range statusLines(said) {
		for _, m := range []string{"certificate signed by unknown authority", "cannot validate certificate",
			"failed to verify certificate", "certificate verify failed", "certificate is valid for",
			"certificate has expired or is not yet valid", "tls:"} {
			if strings.Contains(ln, m) {
				return true
			}
		}
	}
	return false
}

// crlFacts is what L48 records about step-ca's CRL.
type crlFacts struct {
	DER                  bool   `json:"der"`
	Issuer               string `json:"issuer"`
	IssuerIsIntermediate bool   `json:"issuer_is_intermediate"`
	SignatureOK          bool   `json:"signature_ok"`
	ThisUpdate           string `json:"this_update"`
	NextUpdate           string `json:"next_update"`
	Entries              int    `json:"entries"`
}

// crlFactsOf describes rl, which was parsed from raw as served; inter is the
// intermediate that should have issued it.
func crlFactsOf(raw []byte, rl *x509.RevocationList, inter *x509.Certificate) crlFacts {
	block, _ := pem.Decode(raw)
	return crlFacts{DER: block == nil, Issuer: rl.Issuer.String(), IssuerIsIntermediate: bytes.Equal(rl.RawIssuer, inter.RawSubject),
		SignatureOK: rl.CheckSignatureFrom(inter) == nil, ThisUpdate: rl.ThisUpdate.UTC().Format(time.RFC3339),
		NextUpdate: rl.NextUpdate.UTC().Format(time.RFC3339), Entries: len(rl.RevokedCertificateEntries)}
}

func crlHasSerial(rl *x509.RevocationList, serial *big.Int) bool {
	for _, e := range rl.RevokedCertificateEntries {
		if e.SerialNumber.Cmp(serial) == 0 {
			return true
		}
	}
	return false
}

// workloadRunLine is runLine for a test that brings up no platform (root is
// unset then): the commit under test and the test run.
func workloadRunLine(repo string) string {
	sha := "unknown"
	if out, err := exec.Command("git", "-C", repo, "rev-parse", "HEAD").Output(); err == nil {
		sha = strings.TrimSpace(string(out))
	}
	return fmt.Sprintf("commit `%s`, `make lab-workload` (`-run TestL48`)", sha)
}

// describeCounts is a count map as "key xN, key xN", sorted by key.
func describeCounts(m map[string]int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = fmt.Sprintf("%s x%d", k, m[k])
	}
	return strings.Join(parts, ", ")
}

// ---------------------------------------------------------------------------
// The cells
// ---------------------------------------------------------------------------

// l48Run is the state of one TestL48StepCA: the CA, the broker the cells
// currently talk to, the evidence and the observation being written.
type l48Run struct {
	t      *testing.T
	s      *stepCA
	broker *localBroker
	ev     stepEvidence
	obs    strings.Builder
	keys   []string // the workload keys' material, never printed
	inter  *x509.Certificate
	anchor string // the intermediate's PEM file, the broker's workload anchor
	cert   string // the workload's certificate and key on the host
	key    string
}

func (r *l48Run) say(format string, a ...any) { fmt.Fprintf(&r.obs, format+"\n", a...) }

func (r *l48Run) secrets() []string { return append(append([]string(nil), r.s.secrets...), r.keys...) }

// files copies the workload's certificate and key to the host again, and
// registers the key's material as a secret.
func (r *l48Run) files() {
	r.t.Helper()
	cert, key, err := r.s.workloadFiles()
	if err != nil {
		r.t.Fatalf("copying the workload's files (INVALID, not a measured no): %v", err)
	}
	raw, err := os.ReadFile(key)
	if err != nil {
		r.t.Fatal(err)
	}
	r.keys = append(r.keys, keySecrets(raw)...)
	r.cert, r.key = cert, key
}

// token is one `workload token` run, kept in the evidence under label.
func (r *l48Run) token(label string, at time.Duration) tokenRun {
	code, _, errs := r.broker.workloadToken(r.cert, r.key)
	tr := newTokenRun(code, errs, at)
	r.ev.add(label, tr)
	return tr
}

// mustIssue is s.issue, where a refusal is a setup fault: INVALID, not a cell.
func (r *l48Run) mustIssue(id string, life time.Duration) *x509.Certificate {
	r.t.Helper()
	c, err := r.s.issue(id, life)
	if err != nil {
		r.t.Fatalf("step-ca issued no certificate for %s (INVALID, not a measured no): %v", id, err)
	}
	return c
}

func (r *l48Run) cell1Issue() {
	cert := r.mustIssue(l48ID, 24*time.Hour)
	f := factsOf(cert)
	r.ev.add("issue", f)
	r.files()
	// The workload anchor is step-ca's intermediate.
	r.broker = startLocalBroker(r.t, filepath.Join(filepath.Dir(r.s.dir), "local-broker"), r.anchor, "", "", "")
	idCode, idOut, idErr := r.broker.workloadIdentity(r.cert, r.key)
	r.ev.add("workload_identity", newTokenRun(idCode, idErr, 0)) // stdout is a SPIFFE ID, kept in the note
	tr := r.token("token_after_issue", 0)
	r.say("- **1. Issue** (`step ca certificate`, 24h, `--san %s`):", l48ID)
	r.say("  - URI SANs `%v` (exactly the requested ID, alone: %s); DNS SANs `%v`; EKUs `%v`; IsCA `%v`.", f.URIs,
		yesNo(reflect.DeepEqual(f.URIs, []string{l48ID})), f.DNS, f.EKUs, f.IsCA)
	r.say("  - Issuer `%s`; lifetime %s (`%s` to `%s`); serial `%s`.", f.Issuer, f.Lifetime, f.NotBefore, f.NotAfter, f.Serial)
	r.say("  - The broker, anchored on the intermediate with `certificate_status` disabled: `workload identity` exit %d, "+
		"prints `%s`; `workload token` exit %d.", idCode, oneLineMax(strings.TrimSpace(idOut), 200), tr.Exit)
}

func (r *l48Run) cell2Renew() {
	before, err := r.s.leaf()
	if err != nil {
		r.t.Fatal(err)
	}
	after, err := r.s.renew()
	if err != nil {
		r.say("- **2. Renew** (`step ca renew --force`): FAILED, step ca renew answered: %s", oneLineMax(err.Error(), 400))
		r.ev.add("renew", map[string]string{"error": oneLineMax(err.Error(), 400)})
		return
	}
	r.ev.add("renewed", factsOf(after))
	r.files()
	tr := r.token("token_after_renew", 0)
	b, a := factsOf(before), factsOf(after)
	r.say("- **2. Renew** (`step ca renew --force`, the same broker, no change to port49):")
	r.say("  - Same URI SAN: %s (`%v`); same public key: %s; serial `%s` to `%s` (new serial: %s).",
		yesNo(reflect.DeepEqual(b.URIs, a.URIs)), a.URIs, yesNo(samePublicKey(before, after)), b.Serial, a.Serial,
		yesNo(b.Serial != a.Serial))
	r.say("  - `workload token` exit %d.", tr.Exit)
}

func (r *l48Run) cell3Daemon() {
	cert := r.mustIssue(l48ID, 15*time.Minute)
	r.ev.add("issue_15m", factsOf(cert))
	r.files()
	stop, err := r.s.renewDaemon()
	if err != nil {
		r.t.Fatalf("step ca renew --daemon did not start (INVALID, not a measured no): %v", err)
	}
	started := time.Now()
	var renewed *x509.Certificate
	var renewedAt time.Time
	for time.Since(started) < 16*time.Minute {
		if c, err := r.s.leaf(); err == nil && c.SerialNumber.Cmp(cert.SerialNumber) != 0 {
			renewed, renewedAt = c, time.Now()
			break
		}
		time.Sleep(5 * time.Second)
	}
	stop()
	if renewed == nil {
		r.say("- **3. Daemon timing** (`step ca renew --daemon` on a 15m certificate): the certificate was not renewed within 16m.")
		r.ev.add("daemon", map[string]string{"renewed": "no, within 16m"})
		return
	}
	r.ev.add("daemon", map[string]any{"detected_after_seconds": int(renewedAt.Sub(started).Seconds()), "renewed": factsOf(renewed)})
	r.files()
	r.say("- **3. Daemon timing** (`step ca renew --daemon` on a 15m certificate, polled every 5s):")
	r.say("  - Renewed %s after the daemon started, at %.2f of the lifetime (detected at %s of `%s` to `%s`); the new "+
		"certificate's NotBefore is at %.2f of the old one's lifetime.", renewedAt.Sub(started).Round(time.Second),
		renewFraction(cert.NotBefore, cert.NotAfter, renewedAt), renewedAt.UTC().Format(time.RFC3339),
		cert.NotBefore.UTC().Format(time.RFC3339), cert.NotAfter.UTC().Format(time.RFC3339),
		renewFraction(cert.NotBefore, cert.NotAfter, renewed.NotBefore))
}

func (r *l48Run) cell4CADown() {
	cert := r.mustIssue(l48ID, 6*time.Minute)
	r.ev.add("issue_6m", factsOf(cert))
	r.files()
	lateBefore := strings.Count(r.broker.said(), lateMarker)
	t0 := time.Now()
	if err := r.s.stopCA(); err != nil {
		r.t.Fatalf("step-ca did not stop (INVALID, not a measured no): %v", err)
	}
	_, rerr := r.s.renew()
	r.ev.add("renew_with_ca_down", map[string]string{"error": oneLineMax(fmt.Sprint(rerr), 400)})
	cliLate, brokerLate, firstFail := time.Duration(-1), time.Duration(-1), time.Duration(-1)
	var failExit int
	var failErr string
	var lastOK time.Duration = -1
	for n := 0; ; n++ {
		target := 30 * time.Second * time.Duration(n)
		if target > 7*time.Minute {
			break
		}
		time.Sleep(time.Until(t0.Add(target)))
		at := time.Since(t0)
		tr := r.token("token_ca_down", at)
		if tr.Exit == 0 {
			lastOK = at
		}
		if cliLate < 0 && strings.Contains(tr.Stderr, lateMarker) {
			cliLate = at
		}
		if brokerLate < 0 && strings.Count(r.broker.said(), lateMarker) > lateBefore {
			brokerLate = at
		}
		if firstFail < 0 && tr.Exit != 0 {
			firstFail, failExit, failErr = at, tr.Exit, tr.Stderr
		}
	}
	if err := r.s.startCA(); err != nil {
		r.t.Fatalf("step-ca did not start again (INVALID, not a measured no): %v", err)
	}
	when := func(d time.Duration) string {
		if d < 0 {
			return "never within 7m"
		}
		return d.Round(time.Second).String()
	}
	r.say("- **4. The CA down** (a 6m certificate, `NotAfter` %s after the first run; step-ca stopped, "+
		"`workload token` every 30s to 7m):", cert.NotAfter.Sub(t0).Round(time.Second))
	r.say("  - `step ca renew` with the CA stopped: `%s`.", oneLineMax(fmt.Sprint(rerr), 300))
	r.say("  - The broker's \"its renewal is late\" line first appeared: %s. The CLI's warning first appeared: %s.",
		when(brokerLate), when(cliLate))
	r.say("  - The last run that exited 0 was at %s. The first exit that was not 0: %s, exit %d, stderr `%s`.",
		when(lastOK), when(firstFail), failExit, failErr)
}

func (r *l48Run) cell5CRL() {
	if err := r.s.enableCRL(); err != nil {
		r.t.Fatalf("enabling step-ca's CRL (INVALID, not a measured no): %v", err)
	}
	r.say("- **5. The CRL** (`crl: {enabled: true, generateOnRevoke: true}`):")
	rl, raw, err := r.s.crl()
	var cf crlFacts
	if err != nil {
		r.say("  - `GET /1.0/crl` FAILED: %s", oneLineMax(err.Error(), 300))
		r.ev.add("crl", map[string]string{"error": oneLineMax(err.Error(), 300)})
	} else {
		cf = crlFactsOf(raw, rl, r.inter)
		r.ev.add("crl", map[string]any{"facts": cf, "as_served_base64": base64.StdEncoding.EncodeToString(raw)})
		r.say("  - DER: %s; issuer `%s` (the intermediate: %s; signature verifies against it: %s); next update `%s`; "+
			"%d entries.", yesNo(cf.DER), cf.Issuer, yesNo(cf.IssuerIsIntermediate), yesNo(cf.SignatureOK), cf.NextUpdate, cf.Entries)
	}

	cert := r.mustIssue(l48ID, 24*time.Hour)
	r.ev.add("issue_for_crl", factsOf(cert))
	r.files()
	// The CRL is fetched over https under step-ca's private root: the broker
	// trusts it through SSL_CERT_FILE (pre-flight I-3).
	r.broker = startLocalBroker(r.t, filepath.Join(filepath.Dir(r.s.dir), "local-broker-crl"), r.anchor, stepCACRLURL, r.anchor,
		r.s.root())
	deadline := time.Now().Add(45 * time.Second)
	for !strings.Contains(r.broker.said(), "loaded") && !crlTLSFailure(r.broker.said()) && time.Now().Before(deadline) {
		time.Sleep(time.Second)
	}
	lines := statusLines(r.broker.said())
	r.ev.add("broker_certificate_status_lines", lines)
	if crlTLSFailure(r.broker.said()) {
		r.t.Fatalf("the broker's CRL fetch failed TLS: a harness fault (INVALID, not a measured \"step-ca's CRL is unusable\"):\n%s",
			strings.Join(lines, "\n"))
	}
	r.say("  - The broker, trusting step-ca's root through `SSL_CERT_FILE` (`%s`), `refresh_interval: 1m`, started with: `%s`.",
		stepCACRLURL, oneLineMax(strings.Join(lines, " | "), 800))
	pre := r.token("token_before_revoke", 0)
	r.say("  - `workload token` before the revocation: exit %d.", pre.Exit)

	if err := r.s.revoke(); err != nil {
		r.say("  - `step ca revoke` FAILED: %s", oneLineMax(err.Error(), 300))
		r.ev.add("revoke", map[string]string{"error": oneLineMax(err.Error(), 300)})
		return
	}
	revokedAt := time.Now()
	listed := "not checked"
	if rl2, _, err := r.s.crl(); err == nil {
		listed = yesNo(crlHasSerial(rl2, cert.SerialNumber))
	}
	reached := time.Duration(-1)
	var lastRun tokenRun
	for time.Since(revokedAt) < 3*time.Minute {
		at := time.Since(revokedAt)
		lastRun = r.token("token_after_revoke", at)
		if lastRun.Exit == 77 && strings.Contains(lastRun.Stderr, "credential_revoked") {
			reached = at
			break
		}
		time.Sleep(10 * time.Second)
	}
	if reached < 0 {
		r.say("  - After `step ca revoke` (step-ca's CRL lists the serial: %s), `workload token` did not exit 77 with "+
			"`credential_revoked` within 3m; the last run: exit %d, stderr `%s`.", listed, lastRun.Exit, lastRun.Stderr)
	} else {
		r.say("  - After `step ca revoke` (step-ca's CRL lists the serial: %s), `workload token` first exited 77 with "+
			"`credential_revoked` %s later (polled every 10s).", listed, reached.Round(time.Second))
	}
	_, rerr := r.s.renew()
	r.ev.add("renew_revoked", map[string]string{"error": oneLineMax(fmt.Sprint(rerr), 400)})
	if rerr == nil {
		r.say("  - `step ca renew` of the revoked certificate: it was renewed (not refused).")
	} else {
		r.say("  - `step ca renew` of the revoked certificate: refused, `%s`.", oneLineMax(rerr.Error(), 400))
	}
}

func (r *l48Run) cell6NamePolicy() {
	if err := r.s.allowURI(l48ID); err != nil {
		r.t.Fatalf("setting step-ca's name policy (INVALID, not a measured no): %v", err)
	}
	r.say("- **6. The name policy** (the provisioner's x509 `allow: {uri: [%s]}`):", l48ID)
	own, err := r.s.issue(l48ID, 24*time.Hour)
	if err != nil {
		r.say("  - A request for the allowed ID FAILED: %s", oneLineMax(err.Error(), 400))
		r.ev.add("policy_allowed", map[string]string{"error": oneLineMax(err.Error(), 400)})
	} else {
		r.ev.add("policy_allowed", factsOf(own))
		r.say("  - A request for the allowed ID was issued (serial `%s`).", factsOf(own).Serial)
	}
	other, err := r.s.issue(l48Other, 24*time.Hour)
	if err != nil {
		r.ev.add("policy_other", map[string]string{"error": oneLineMax(err.Error(), 600)})
		r.say("  - A request for `%s`: refused, step-ca answered `%s`.", l48Other, oneLineMax(err.Error(), 600))
		return
	}
	r.ev.add("policy_other", factsOf(other))
	r.say("  - A request for `%s` was ISSUED (not refused).", l48Other)
}

// stepVersion is step-ca's version line and the image id, for the note.
func stepVersion(s *stepCA) (string, error) {
	for _, args := range [][]string{{"version"}, {"--version"}} {
		out, err := s.dc(append([]string{"exec", "-T", "step-ca", "step-ca"}, args...)...).CombinedOutput()
		if line, _, _ := strings.Cut(strings.TrimSpace(string(out)), "\n"); err == nil && line != "" {
			return fmt.Sprintf("%s; image `%s` (%s)", line, stepCAImage, imageID(stepCAImage)), nil
		}
	}
	return "", fmt.Errorf("step-ca reports no version")
}

// TestL48StepCA measures L48 (policy engine spec §15) on step-ca and a local
// bin/port49d. Its cells are a measurement whatever they find: a step that ran
// and did not do what the claim says is recorded as a failed cell. A fault in
// the setup is t.Fatal, INVALID, before any note.
func TestL48StepCA(t *testing.T) {
	s := startStepCA(t)
	version, err := stepVersion(s)
	if err != nil {
		t.Fatalf("step-ca's version (INVALID, not a measured no): %v", err)
	}
	r := &l48Run{t: t, s: s, inter: s.intermediate()}
	if err := os.MkdirAll(s.hostW, 0o700); err != nil {
		t.Fatal(err)
	}
	r.anchor = filepath.Join(s.hostW, "intermediate_ca.crt")
	if err := os.WriteFile(r.anchor, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: r.inter.Raw}), 0o644); err != nil {
		t.Fatal(err)
	}
	r.ev.add("intermediate", factsOf(r.inter))
	t.Cleanup(func() {
		// The host copy holds the workload's key.
		_ = os.RemoveAll(s.hostW)
	})

	r.cell1Issue()
	r.cell2Renew()
	r.cell3Daemon()
	r.cell4CADown()
	r.cell5CRL()
	r.cell6NamePolicy()

	out, err := directoryOut()
	if err != nil {
		t.Fatal(err)
	}
	evPath := filepath.Join("tests", "lab", "evidence", "L48-step_ca.json")
	body, err := r.ev.encode(r.secrets())
	if err != nil {
		t.Fatal(err)
	}
	note := workloadNote("L48", "step_ca", l48Claim, r.obs.String(), evPath, workloadRunLine(out), version)
	if lerr := stepLeak(note, r.secrets()); lerr != nil {
		t.Fatalf("the note is not written: %v", lerr)
	}
	for _, d := range []string{"evidence", "results"} {
		if err := os.MkdirAll(filepath.Join(out, "tests", "lab", d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(out, evPath), body, 0o644); err != nil {
		t.Fatal(err)
	}
	notePath := filepath.Join(out, "tests", "lab", "results", "L48-step_ca.md")
	if err := os.WriteFile(notePath, []byte(labcreds.RedactNote(note)), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %s and %s", notePath, filepath.Join(out, evPath))
}
