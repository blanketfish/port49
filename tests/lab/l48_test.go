//go:build lab

package lab

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
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
	// l48OtherDomain is the SPIFFE ID cell 6 asks for besides l48ID: in another
	// trust domain, so a policy matching by host refuses it too.
	l48OtherDomain = "spiffe://elsewhere.lab/host/other"
	// lateMarker is in both the broker's and the CLI's late-renewal lines.
	lateMarker = "its renewal is late"
	// Cell 4 runs `workload token` every cell4Every from 0 to cell4Span; cell 5
	// every cell5Every for cell5Span after the revocation. Neither redeems.
	cell4Every, cell4Span = 30 * time.Second, 7 * time.Minute
	cell5Every, cell5Span = 10 * time.Second, 3 * time.Minute
)

// polls is the most `workload token` runs a cell makes, polling every every
// from 0 to span.
func polls(every, span time.Duration) int { return int(span/every) + 1 }

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
			"certificate has expired or is not yet valid", "tls:", "connect:", "connection refused"} {
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

// crlFetchSaid is a certificate-status line that is the outcome of a CRL
// fetch: loaded, or failed. The start line ("not loaded yet") is neither.
var crlFetchSaid = regexp.MustCompile(`certificate status: CRL step_ca( loaded|: )`)

func crlFetchOutcome(said string) bool { return crlFetchSaid.MatchString(said) }

// identityPrincipal is the principal `port49 workload identity` printed: the
// second field of its `principal  <id> (<method> <fingerprint>)` line.
func identityPrincipal(out string) string {
	for _, ln := range strings.Split(out, "\n") {
		if f := strings.Fields(ln); len(f) >= 2 && f[0] == "principal" {
			return f[1]
		}
	}
	return ""
}

// tokenSecrets are the tokens in a `workload token` TSV output: its token
// column alone, so the device, address and username are not registered.
func tokenSecrets(tsv string) []string { return routerDBSecrets(tsv) }

// renewIsFault says whether a failed one-off docker run is docker's, not
// step's: it did not run at all, exited 125-127 (docker's own codes), or
// printed docker's or compose's error.
func renewIsFault(err error, out string) bool {
	if err == nil {
		return false
	}
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		return true
	}
	if c := ee.ExitCode(); c >= 125 && c <= 127 {
		return true
	}
	return dockerFault(out)
}

// dockerFault says whether a command's output is docker's or compose's own
// error, not the answer of the program run in the container.
func dockerFault(out string) bool {
	for _, m := range []string{"is not running", "No such container", "Cannot connect to the Docker daemon",
		"Error response from daemon", "docker: "} {
		if strings.Contains(out, m) {
			return true
		}
	}
	return false
}

// untilExpiry is how long before notAfter an event at (t0 + at) happened;
// negative after expiry.
func untilExpiry(notAfter, t0 time.Time, at time.Duration) time.Duration {
	return notAfter.Sub(t0.Add(at))
}

// daemonWaitBound is how long cell 3 waits for the renew daemon: until
// notAfter, plus 3m. step-ca backdates NotBefore, so a certificate asked for
// 15m lives about 16m; a fixed bound would stop the wait inside its life.
func daemonWaitBound(notAfter, now time.Time) time.Duration {
	return max(notAfter.Sub(now), 0) + 3*time.Minute
}

// renewTimingWords says when at fell relative to a certificate's NotBefore
// and NotAfter.
func renewTimingWords(notBefore, notAfter, at time.Time) string {
	rel := func(d time.Duration, ref string) string {
		if d >= 0 {
			return d.Round(time.Second).String() + " before " + ref
		}
		return (-d).Round(time.Second).String() + " after " + ref
	}
	return at.Sub(notBefore).Round(time.Second).String() + " after NotBefore and " + rel(notAfter.Sub(at), "NotAfter")
}

// renewFromHost is `step ca renew --force` of w/ from a one-off container
// that reaches the published port, so it still runs when the step-ca
// container is stopped (compose exec would answer "service is not running",
// which is not step-ca's answer). Docker's own errors are returned as a
// fault; step's output, with step's exit, as the answer.
func (s *stepCA) renewFromHost() (answer string, fault error) {
	uid, err := dockerCmd("run", "--rm", "--entrypoint", "id", stepCAImage, "-u", "step").Output()
	if err != nil {
		return "", fmt.Errorf("step-ca's uid: %w", err)
	}
	b, rerr := dockerCmd("run", "--rm", "--network", "host", "--user", strings.TrimSpace(string(uid)), "-v", s.dir+":/home/step",
		"--entrypoint", "step", stepCAImage, "ca", "renew", stepCAWCert, stepCAWKey, "--force", "--ca-url",
		"https://localhost:19000", "--root", stepCARoot).CombinedOutput()
	out := string(b)
	if lerr := stepLeak(out, s.secrets); lerr != nil {
		return "(output withheld: " + lerr.Error() + ")", nil
	}
	if renewIsFault(rerr, out) {
		return out, fmt.Errorf("docker, not step: %s", tailOf(out, 300))
	}
	if rerr == nil {
		return "renewed", nil
	}
	return out, nil
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
	code, out, errs := r.broker.workloadToken(r.cert, r.key)
	// The token is a secret before any check: a leak of it into stderr is caught.
	r.keys = append(r.keys, tokenSecrets(out)...)
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
		"prints the principal `%s` (the requested ID: %s); `workload token` exit %d.", idCode,
		oneLineMax(identityPrincipal(idOut), 200), yesNo(identityPrincipal(idOut) == l48ID), tr.Exit)
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
	stop, exited, err := r.s.renewDaemon()
	if err != nil {
		r.t.Fatalf("step ca renew --daemon did not start (INVALID, not a measured no): %v", err)
	}
	started := time.Now()
	var renewed *x509.Certificate
	var renewedAt time.Time
	bound := daemonWaitBound(cert.NotAfter, started)
	for time.Since(started) < bound {
		if c, err := r.s.leaf(); err == nil && c.SerialNumber.Cmp(cert.SerialNumber) != 0 {
			renewed, renewedAt = c, time.Now()
			break
		}
		// A daemon that is gone renews nothing: waiting on would record a
		// "not renewed" that measured no daemon (run set 3).
		if exited() {
			stop()
			r.t.Fatalf("step ca renew --daemon exited %s after it started (INVALID, not a measured no); "+
				"tests/lab/logs/workload/renew-daemon.log says why", time.Since(started).Round(time.Second))
		}
		time.Sleep(5 * time.Second)
	}
	stop()
	if renewed == nil {
		r.say("- **3. Daemon timing** (`step ca renew --daemon` on a 15m certificate, `%s` to `%s`): the certificate was not renewed "+
			"within %s of the daemon's start (its NotAfter plus 3m): a measurement.", cert.NotBefore.UTC().Format(time.RFC3339),
			cert.NotAfter.UTC().Format(time.RFC3339), bound.Round(time.Second))
		r.ev.add("daemon", map[string]any{"renewed": "no", "waited_seconds": int(bound.Seconds()),
			"not_before": cert.NotBefore.UTC().Format(time.RFC3339), "not_after": cert.NotAfter.UTC().Format(time.RFC3339)})
		return
	}
	r.ev.add("daemon", map[string]any{"detected_after_seconds": int(renewedAt.Sub(started).Seconds()), "renewed": factsOf(renewed),
		"relative_to_old_certificate": renewTimingWords(cert.NotBefore, cert.NotAfter, renewedAt)})
	r.files()
	r.say("- **3. Daemon timing** (`step ca renew --daemon` on a 15m certificate, polled every 5s):")
	r.say("  - Renewed %s after the daemon started, at %.2f of the lifetime (detected at %s of `%s` to `%s`); the new "+
		"certificate's NotBefore is at %.2f of the old one's lifetime.", renewedAt.Sub(started).Round(time.Second),
		renewFraction(cert.NotBefore, cert.NotAfter, renewedAt), renewedAt.UTC().Format(time.RFC3339),
		cert.NotBefore.UTC().Format(time.RFC3339), cert.NotAfter.UTC().Format(time.RFC3339),
		renewFraction(cert.NotBefore, cert.NotAfter, renewed.NotBefore))
	r.say("  - Detected %s.", renewTimingWords(cert.NotBefore, cert.NotAfter, renewedAt))
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
	// From a one-off container: compose exec into the stopped container would
	// answer with docker's error, not step-ca's.
	renewAnswer, fault := r.s.renewFromHost()
	if fault != nil {
		r.t.Fatalf("the renewal could not be tried from a one-off container (INVALID, not a measured no): %v", fault)
	}
	r.ev.add("renew_with_ca_down", map[string]string{"answer": oneLineMax(renewAnswer, 400)})
	cliLate, brokerLate, firstFail := time.Duration(-1), time.Duration(-1), time.Duration(-1)
	var failExit int
	var failErr string
	var lastOK time.Duration = -1
	for n := 0; ; n++ {
		target := cell4Every * time.Duration(n)
		if target > cell4Span {
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
	// Each time is also given as the time left before NotAfter and as a fraction
	// of the certificate's actual lifetime: step-ca backdates NotBefore by 1m
	// (its default), so a "6m" certificate lives about 7m and the late-renewal
	// line (a quarter left) comes about 4m15s after issue, not at 4.5m.
	when := func(d time.Duration) string {
		if d < 0 {
			return "never within 7m"
		}
		return fmt.Sprintf("%s (%s before NotAfter, %.2f of the lifetime)", d.Round(time.Second),
			untilExpiry(cert.NotAfter, t0, d).Round(time.Second), renewFraction(cert.NotBefore, cert.NotAfter, t0.Add(d)))
	}
	r.say("- **4. The CA down** (a 6m certificate: its lifetime is %s, as step-ca backdates NotBefore by 1m; `NotAfter` %s after "+
		"the first run; step-ca stopped, `workload token` every 30s to 7m, times from the first run):",
		cert.NotAfter.Sub(cert.NotBefore).Round(time.Second), cert.NotAfter.Sub(t0).Round(time.Second))
	r.say("  - The local broker's `token.candidate_cap` is %d (port49's default is %d): the %d runs, none redeemed, stay under "+
		"it, so a refusal here is the CA's absence or the certificate's expiry, never the cap.", l48CandidateCap,
		l48DefaultCandidateCap, polls(cell4Every, cell4Span))
	r.say("  - `step ca renew` from a one-off container with the CA stopped: `%s`.", oneLineMax(renewAnswer, 300))
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
	r.broker.stop() // cell 1's broker, so one port49d runs
	b, refusal := launchLocalBroker(r.t, filepath.Join(filepath.Dir(r.s.dir), "local-broker-crl"), r.anchor, stepCACRLURL,
		r.anchor, r.s.root())
	if b == nil {
		// port49d refused the CRL source at start (its issuer is not under an
		// anchor, or is not a CA): a fact about step-ca's intermediate.
		r.say("  - port49d refused to start with step-ca's intermediate as the CRL's issuer: `%s`.", oneLineMax(refusal, 600))
		r.ev.add("broker_start_refused", refusal)
		r.revokeAndRenew(cert, false)
		return
	}
	r.broker = b
	deadline := time.Now().Add(60 * time.Second)
	for !crlFetchOutcome(r.broker.said()) && time.Now().Before(deadline) {
		time.Sleep(time.Second)
	}
	lines := statusLines(r.broker.said())
	r.ev.add("broker_certificate_status_lines", lines)
	if !crlFetchOutcome(r.broker.said()) {
		r.t.Fatalf("the broker said nothing about its first CRL fetch in 60s (INVALID, not a measured no):\n%s",
			strings.Join(lines, "\n"))
	}
	if crlTLSFailure(r.broker.said()) {
		r.t.Fatalf("the broker's CRL fetch failed TLS: a harness fault (INVALID, not a measured \"step-ca's CRL is unusable\"):\n%s",
			strings.Join(lines, "\n"))
	}
	r.say("  - The broker, trusting step-ca's root through `SSL_CERT_FILE` (`%s`), `refresh_interval: 1m`, started with: `%s`.",
		stepCACRLURL, oneLineMax(strings.Join(lines, " | "), 800))
	pre := r.token("token_before_revoke", 0)
	r.say("  - `workload token` before the revocation: exit %d.", pre.Exit)
	r.revokeAndRenew(cert, true)
}

// revokeAndRenew is the end of cell 5: `step ca revoke`, whether the broker
// (when one runs on the CRL) refuses the certificate within 3m, and the
// renewal of the revoked certificate. They need step-ca alone, so they are
// recorded when the broker refused to start too.
func (r *l48Run) revokeAndRenew(cert *x509.Certificate, brokerUp bool) {
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
	if !brokerUp {
		r.say("  - After `step ca revoke` (step-ca's CRL lists the serial: %s): no broker ran on the CRL, so no refusal was tried.", listed)
	} else {
		reached := time.Duration(-1)
		var lastRun tokenRun
		for time.Since(revokedAt) < cell5Span {
			at := time.Since(revokedAt)
			lastRun = r.token("token_after_revoke", at)
			if lastRun.Exit == 77 && strings.Contains(lastRun.Stderr, "credential_revoked") {
				reached = at
				break
			}
			time.Sleep(cell5Every)
		}
		// A refresh can fail TLS too: that is a harness fault, not a revocation that never came.
		if crlTLSFailure(r.broker.said()) {
			r.t.Fatalf("a CRL refresh failed TLS (INVALID, not a measured no):\n%s", strings.Join(statusLines(r.broker.said()), "\n"))
		}
		if reached < 0 {
			r.say("  - After `step ca revoke` (step-ca's CRL lists the serial: %s), `workload token` did not exit 77 with "+
				"`credential_revoked` within 3m; the last run: exit %d, stderr `%s`.", listed, lastRun.Exit, lastRun.Stderr)
		} else {
			r.say("  - After `step ca revoke` (step-ca's CRL lists the serial: %s), `workload token` first exited 77 with "+
				"`credential_revoked` %s later (polled every 10s).", listed, reached.Round(time.Second))
		}
	}
	_, rerr := r.s.renew()
	r.ev.add("renew_revoked", map[string]string{"error": oneLineMax(fmt.Sprint(rerr), 400)})
	if rerr == nil {
		r.say("  - `step ca renew` of the revoked certificate: it was renewed (not refused).")
	} else {
		r.say("  - `step ca renew` of the revoked certificate: refused, `%s`.", oneLineMax(rerr.Error(), 400))
	}
}

// cell6NamePolicy measures three ways to hold a provisioner to one SPIFFE ID
// (run set 3 found the first ignored): the provisioner's x509 allow list in
// ca.json, the authority's allow list naming the full URI, and a provisioner
// x509 template fixing the URI. Each starts from the ca.json the cell found.
func (r *l48Run) cell6NamePolicy() {
	pristine, err := r.s.read(caJSONPath)
	if err != nil {
		r.t.Fatalf("reading ca.json (INVALID, not a measured no): %v", err)
	}
	r.say("- **6. Holding a provisioner to one SPIFFE ID** (`%s`; the other request is `%s`, another trust domain):", l48ID,
		l48OtherDomain)

	// 1. The provisioner's options.x509.allow.
	if err := r.s.editCAJSON(func(raw []byte) ([]byte, error) { return caJSONProvisionerAllowURI(raw, stepCAProv, l48ID) }); err != nil {
		r.t.Fatalf("setting the provisioner's allow list (INVALID, not a measured no): %v", err)
	}
	r.say("  - The provisioner's x509 `allow: {uri: [%s]}` in ca.json (step-ca restarted on it):", l48ID)
	r.policyRequests("policy_provisioner_allow", "")

	// 2. The authority's policy naming the full URI.
	body, err := caJSONAuthorityAllowURI([]byte(pristine), l48ID)
	if err != nil {
		r.t.Fatal(err)
	}
	started, refusal, err := r.s.tryCAJSON(string(body))
	if err != nil {
		r.t.Fatalf("restarting step-ca on the authority's policy (INVALID, not a measured no): %v", err)
	}
	r.ev.add("policy_authority_full_uri", map[string]any{"started": started, "refusal": refusal})
	if started {
		r.say("  - The authority's x509 `allow: {uri: [%s]}`: step-ca started on it.", l48ID)
		r.policyRequests("policy_authority_full_uri", "")
	} else {
		r.say("  - The authority's x509 `allow: {uri: [%s]}`: step-ca refused to start, `%s`.", l48ID, oneLineMax(refusal, 400))
	}
	if err := r.s.restoreCAJSON(pristine); err != nil {
		r.t.Fatalf("putting ca.json back (INVALID, not a measured no): %v", err)
	}

	// 3. A provisioner x509 template with the URI fixed.
	if err := r.s.editCAJSON(func(raw []byte) ([]byte, error) { return caJSONProvisionerTemplate(raw, stepCAProv, l48ID) }); err != nil {
		r.t.Fatalf("setting the provisioner's template (INVALID, not a measured no): %v", err)
	}
	r.say("  - The provisioner's x509 template with `uris: [%s]` fixed (step-ca restarted on it):", l48ID)
	r.policyRequests("policy_template", l48ID)
}

// policyRequests asks for l48ID and l48OtherDomain and records each answer
// under step: refused, issued with the asked ID, or issued with another (a
// template that rewrote it). pinned, when set, is the ID a template fixes.
// The issues write new keys into the container's w/; they never leave it (no
// workloadFiles copy), so nothing here needs registering.
func (r *l48Run) policyRequests(step, pinned string) {
	for _, id := range []string{l48ID, l48OtherDomain} {
		c, err := r.s.issue(id, 24*time.Hour)
		if err != nil {
			r.ev.add(step, map[string]string{"asked": id, "error": oneLineMax(err.Error(), 600)})
			r.say("    - `%s`: refused, step-ca answered `%s`.", id, oneLineMax(stripANSI(err.Error()), 400))
			continue
		}
		f := factsOf(c)
		r.ev.add(step, map[string]any{"asked": id, "issued": f})
		switch {
		case reflect.DeepEqual(f.URIs, []string{id}):
			r.say("    - `%s`: ISSUED as asked (URI SANs `%v`).", id, f.URIs)
		case pinned != "" && reflect.DeepEqual(f.URIs, []string{pinned}):
			r.say("    - `%s`: issued with the pinned ID instead (URI SANs `%v`, subject `%s`): not refused, rewritten.", id,
				f.URIs, f.Subject)
		default:
			r.say("    - `%s`: issued with URI SANs `%v` (subject `%s`).", id, f.URIs, f.Subject)
		}
	}
}

// ansiShape is a terminal colour sequence, as step prints around its checks.
var ansiShape = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func stripANSI(s string) string { return ansiShape.ReplaceAllString(s, "") }

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
