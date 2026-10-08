//go:build lab

package lab

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// The pure helpers of the L48 and L49 cells (plan 8, Task 14). Nothing here
// starts a container.

// testCA is a self-signed CA certificate and its key.
func testCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	return testCANamed(t, "Lab Intermediate CA")
}

func testCANamed(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c, key
}

// testLeaf is a certificate issued by ca for pub, with the given serial.
func testLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, pub *ecdsa.PublicKey, serial int64) *x509.Certificate {
	t.Helper()
	id, _ := url.Parse("spiffe://port49.lab/host/oxidized-01")
	tpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "oxidized-01"},
		NotBefore: time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC),
		URIs: []*url.URL{id}, DNSNames: []string{"oxidized-01.lab"}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca, pub, caKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// a certificate's facts are the ones L48's first cell records.
func TestFactsOfReportsTheCellsFields(t *testing.T) {
	ca, caKey := testCA(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	f := factsOf(testLeaf(t, ca, caKey, &key.PublicKey, 42))
	if !reflect.DeepEqual(f.URIs, []string{"spiffe://port49.lab/host/oxidized-01"}) ||
		!reflect.DeepEqual(f.DNS, []string{"oxidized-01.lab"}) || !reflect.DeepEqual(f.EKUs, []string{"clientAuth"}) {
		t.Errorf("SANs or EKUs: %+v", f)
	}
	if f.IsCA || f.Serial != "2a" || f.Lifetime != "24h0m0s" || !strings.Contains(f.Issuer, "Lab Intermediate CA") ||
		!strings.HasPrefix(f.PEM, "-----BEGIN CERTIFICATE-----") {
		t.Errorf("facts: %+v", f)
	}
	if got := ekuNames([]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageCodeSigning, x509.ExtKeyUsage(99)}); !reflect.DeepEqual(got,
		[]string{"serverAuth", "codeSigning", "unknown(99)"}) {
		t.Errorf("ekuNames = %v", got)
	}
}

// a renewal keeps the key when the public keys are equal and not otherwise.
func TestSamePublicKey(t *testing.T) {
	ca, caKey := testCA(t)
	k1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	k2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	a, b, c := testLeaf(t, ca, caKey, &k1.PublicKey, 1), testLeaf(t, ca, caKey, &k1.PublicKey, 2), testLeaf(t, ca, caKey, &k2.PublicKey, 3)
	if !samePublicKey(a, b) || samePublicKey(a, c) {
		t.Error("samePublicKey does not tell one key from two")
	}
}

// evidence keeps a certificate's PEM and refuses key material, a compact JWS and a registered secret.
func TestEvidenceLogRefusesWhatMustNotBeKept(t *testing.T) {
	ca, caKey := testCA(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	var ev stepEvidence
	ev.add("issue", factsOf(testLeaf(t, ca, caKey, &key.PublicKey, 7)))
	ev.add("token", newTokenRun(77, "the certificate x expired at y: renew it against your CA", 6*time.Minute))
	out, err := ev.encode([]string{"hunter2-hunter2"})
	if err != nil {
		t.Fatalf("a clean log was refused: %v", err)
	}
	var back []map[string]any
	if err := json.Unmarshal(out, &back); err != nil || len(back) != 2 || back[0]["step"] != "issue" {
		t.Fatalf("not a JSON array of steps: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "BEGIN CERTIFICATE") {
		t.Error("the certificate's PEM was not kept")
	}
	for _, bad := range []string{"-----BEGIN EC PRIVATE KEY-----", "hunter2-hunter2",
		"eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJlLXNpZ25hdHVyZQ"} {
		var e stepEvidence
		e.add("x", map[string]string{"v": "before " + bad + " after"})
		if _, err := e.encode([]string{"hunter2-hunter2"}); err == nil {
			t.Errorf("%q was kept", bad)
		}
	}
}

// the workload token run has no field for stdout: a token cannot be put there.
func TestTokenRunHasNoStdout(t *testing.T) {
	b, _ := json.Marshal(newTokenRun(0, "warn", 30*time.Second))
	if strings.Contains(strings.ToLower(string(b)), "stdout") || !strings.Contains(string(b), `"exit":0`) ||
		!strings.Contains(string(b), `"at_seconds":30`) {
		t.Errorf("token run = %s", b)
	}
	if _, has := reflect.TypeOf(tokenRun{}).FieldByName("Stdout"); has {
		t.Error("tokenRun has a Stdout field")
	}
}

// a key's secrets are its base64 body lines and the body joined; its armor is not one.
func TestKeySecretsAreTheBase64Body(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	raw := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	secrets := keySecrets(raw)
	if len(secrets) < 2 {
		t.Fatalf("secrets = %v", secrets)
	}
	for _, s := range secrets {
		if strings.Contains(s, "BEGIN") || strings.Contains(s, "END") || strings.Contains(s, "\n") {
			t.Errorf("secret %q holds armor or a newline", s)
		}
		if len(s) < 16 {
			t.Errorf("secret %q is too short to be safe to search for", s)
		}
	}
	if err := leakIn("line: "+string(raw), secrets); err == nil {
		t.Error("the key itself is not caught by its secrets")
	}
	if got := keySecrets([]byte("not a key")); len(got) != 0 {
		t.Errorf("a non-PEM file gave secrets %v", got)
	}
}

// a CRL fetch that failed TLS is INVALID; one that failed otherwise is a measurement.
func TestCRLTLSFailure(t *testing.T) {
	for _, tc := range []struct {
		said string
		want bool
	}{
		{"port49d: broker: certificate status: CRL step_ca loaded (next update 2026-10-09T00:00:00Z)\n", false},
		{"port49d: broker: certificate status: CRL step_ca: Get \"https://localhost:19000/1.0/crl\": tls: failed to verify certificate: x509: certificate signed by unknown authority\n", true},
		{"port49d: broker: certificate status: CRL step_ca: fetch: x509: cannot validate certificate for 127.0.0.1 because it doesn't contain any IP SANs\n", true},
		{"port49d: broker: certificate status: CRL step_ca: parse: x509: malformed crl\n", false},
		{"port49d: other: x509: certificate signed by unknown authority\n", false},
		{"port49d: broker: certificate status: CRL step_ca: Get ...: remote error: tls: bad certificate\n", true},
	} {
		if got := crlTLSFailure(tc.said); got != tc.want {
			t.Errorf("crlTLSFailure(%q) = %v, want %v", tc.said, got, tc.want)
		}
	}
}

// a CRL's facts: DER or PEM, who signed it, when it ends, how many entries.
func TestCRLFactsOf(t *testing.T) {
	ca, caKey := testCA(t)
	other, _ := testCANamed(t, "Another CA")
	next := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second)
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: time.Now().Add(-time.Minute),
		NextUpdate: next, RevokedCertificateEntries: []x509.RevocationListEntry{{SerialNumber: big.NewInt(42), RevocationTime: time.Now()}}},
		ca, caKey)
	if err != nil {
		t.Fatal(err)
	}
	rl, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatal(err)
	}
	f := crlFactsOf(der, rl, ca)
	if !f.DER || !f.IssuerIsIntermediate || !f.SignatureOK || f.Entries != 1 || f.NextUpdate != next.Format(time.RFC3339) {
		t.Errorf("DER CRL facts: %+v", f)
	}
	armored := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})
	if f := crlFactsOf(armored, rl, ca); f.DER {
		t.Errorf("a PEM-armored CRL was called DER: %+v", f)
	}
	if f := crlFactsOf(der, rl, other); f.IssuerIsIntermediate || f.SignatureOK {
		t.Errorf("another CA's CRL was called the intermediate's: %+v", f)
	}
	if !crlHasSerial(rl, big.NewInt(42)) || crlHasSerial(rl, big.NewInt(43)) {
		t.Error("crlHasSerial")
	}
}

func decisionRec(event, verdict, reason string, extra map[string]any) map[string]any {
	m := map[string]any{"event": event, "verdict": verdict, "reason": reason}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

// redeem records are counted with their verdict and reason; others are not.
func TestRedeemSummary(t *testing.T) {
	recs := []map[string]any{
		decisionRec("redeem", "permit", "token_redeemed", nil),
		decisionRec("authorize_session", "permit", "role_permits", nil),
		decisionRec("redeem", "deny", "token_not_found", nil),
		decisionRec("redeem", "deny", "token_not_found", nil),
	}
	n, by := redeemSummary(recs)
	if n != 3 || by["permit/token_redeemed"] != 1 || by["deny/token_not_found"] != 2 || len(by) != 2 {
		t.Errorf("n=%d by=%v", n, by)
	}
	if n, by := redeemSummary(nil); n != 0 || len(by) != 0 {
		t.Errorf("no records: %d %v", n, by)
	}
	if got := describeCounts(by); got != "deny/token_not_found x2, permit/token_redeemed x1" {
		t.Errorf("describeCounts = %q", got)
	}
}

// the mint records' principals, in order, once each.
func TestMintPrincipals(t *testing.T) {
	recs := []map[string]any{
		decisionRec("mint", "permit", "x", map[string]any{"principal": "spiffe://port49.lab/host/oxidized-01"}),
		decisionRec("redeem", "permit", "x", map[string]any{"principal": "ignored"}),
		decisionRec("mint", "permit", "x", map[string]any{"principal": "spiffe://port49.lab/host/oxidized-01"}),
		decisionRec("mint", "deny", "x", map[string]any{"principal": "spiffe://port49.lab/host/other"}),
		decisionRec("mint", "permit", "x", nil),
	}
	want := []string{"spiffe://port49.lab/host/oxidized-01", "spiffe://port49.lab/host/other"}
	if got := mintPrincipals(recs); !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// every authorize_command record of a user is a row, in order; denied ones are listed once.
func TestCommandVerdictsAndDenied(t *testing.T) {
	rec := func(user, verdict, reason string, vector ...string) map[string]any {
		v := make([]any, len(vector))
		for i, w := range vector {
			v[i] = w
		}
		return map[string]any{"event": "authorize_command", "verdict": verdict, "reason": reason,
			"session": map[string]any{"username": user}, "request": map[string]any{"vector": v}}
	}
	recs := []map[string]any{
		rec("svc-oxidized", "permit", "role_permits", "show", "version"),
		rec("other", "deny", "no_permit", "reload"),
		rec("svc-oxidized", "deny", "no_permit", "show", "inventory"),
		rec("svc-oxidized", "deny", "no_permit", "show", "inventory"),
		rec("svc-oxidized", "permit", "role_permits", "show", "version"),
		decisionRec("redeem", "permit", "token_redeemed", nil),
	}
	got := commandVerdicts(recs, "svc-oxidized")
	if len(got) != 4 || got[0] != (commandVerdict{"show version", "permit", "role_permits"}) ||
		got[1] != (commandVerdict{"show inventory", "deny", "no_permit"}) {
		t.Errorf("rows = %+v", got)
	}
	if d := deniedCommands(got); !reflect.DeepEqual(d, []string{"show inventory"}) {
		t.Errorf("denied = %v", d)
	}
	if len(commandVerdicts(recs, "nobody")) != 0 {
		t.Error("a user with no records has rows")
	}
}

// a device's hostname line, in a flat or a Junos configuration.
func TestHostnameLine(t *testing.T) {
	for _, tc := range []struct{ name, cfg, want string }{
		{"eos", "! Command: show running-config\nhostname leaf1\n!\ninterface Ethernet1\n", "hostname leaf1"},
		{"junos", "system {\n    host-name vjunos1;\n    login {\n", "host-name vjunos1;"},
		{"indented", "  hostname  spine \n", "hostname  spine"},
		{"none", "interface Ethernet1\n description hostname-like\n", ""},
	} {
		if got := hostnameLine(tc.cfg); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
}

// phase B's stack gets the receipt_idle_ttl key at the top level, once.
func TestWithReceiptIdleTTL(t *testing.T) {
	files := map[string]string{"port49d.yaml": "listen: \"0.0.0.0:49\"\nbroker: {}"}
	if err := withReceiptIdleTTL(files, "2m"); err != nil {
		t.Fatal(err)
	}
	if got := files["port49d.yaml"]; got != "listen: \"0.0.0.0:49\"\nbroker: {}\nreceipt_idle_ttl: 2m\n" {
		t.Errorf("port49d.yaml = %q", got)
	}
	if err := withReceiptIdleTTL(files, "2m"); err == nil {
		t.Error("a second receipt_idle_ttl was added")
	}
	if err := withReceiptIdleTTL(map[string]string{}, "2m"); err == nil {
		t.Error("a stack with no port49d.yaml was accepted")
	}
}

// the claim constants are the spec's §15 rows' text, word for word.
func TestClaimsAreTheSpecRowsText(t *testing.T) {
	spec, err := os.ReadFile(filepath.Join("..", "..", "docs", "design", "2026-08-23-policy-engine-spec.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ row, claim string }{{"L48", l48Claim}, {"L49", l49Claim}} {
		var cell string
		for _, ln := range strings.Split(string(spec), "\n") {
			if rest, ok := strings.CutPrefix(ln, "| **"+tc.row+"** | "); ok {
				cell, _, _ = strings.Cut(rest, " | ")
				break
			}
		}
		if cell == "" {
			t.Fatalf("§15 has no %s row", tc.row)
		}
		if cell != tc.claim {
			t.Errorf("%s's claim constant is not the §15 row's text:\n got %q\nwant %q", tc.row, tc.claim, cell)
		}
	}
}

// the broker's certificate-status lines, and only those.
func TestStatusLines(t *testing.T) {
	said := "port49d: broker listening on 127.0.0.1:1\nport49d: broker: certificate status: CRL step_ca loaded\nother\n" +
		"port49d: broker: certificate status: x\n"
	if got := statusLines(said); len(got) != 2 || !strings.Contains(got[0], "loaded") {
		t.Errorf("statusLines = %q", got)
	}
}

// only the records of the user's own session.
func TestRecordsFor(t *testing.T) {
	recs := []map[string]any{
		{"event": "redeem", "session": map[string]any{"username": "svc-oxidized"}},
		{"event": "redeem", "session": map[string]any{"username": "breakglass"}},
		{"event": "mint"},
	}
	if got := recordsFor(recs, "svc-oxidized"); len(got) != 1 || got[0]["event"] != "redeem" {
		t.Errorf("recordsFor = %v", got)
	}
}

// the wait for the CRL's first fetch ends on the fetch's own outcome, not on the start line.
func TestCRLFetchOutcome(t *testing.T) {
	for _, tc := range []struct {
		said string
		want bool
	}{
		{"port49d: broker: certificate status from CRL step_ca (not loaded yet); a status that cannot be established is refused\n", false},
		{"port49d: broker: certificate status: CRL step_ca loaded (next update 2026-10-09T00:00:00Z)\n", true},
		{"port49d: broker: certificate status: CRL step_ca loaded, but its next update, x, has passed: y\n", true},
		{"port49d: broker: certificate status: CRL step_ca: Get \"https://localhost:19000/1.0/crl\": tls: x; the list in force stays until its next update\n", true},
		{"port49d: broker: certificate status: CRL other loaded\n", false},
		{"", false},
	} {
		if got := crlFetchOutcome(tc.said); got != tc.want {
			t.Errorf("crlFetchOutcome(%q) = %v, want %v", tc.said, got, tc.want)
		}
	}
}

// a start that port49d refused over the CRL source is a measurement; any other exit is a fault.
func TestStartRefusal(t *testing.T) {
	line := "port49d: broker.certificate_status.crls[0].issuer_file /x/intermediate_ca.crt: CN=Y is neither a trust anchor's certificate nor signed by one"
	for _, tc := range []struct {
		name, said, want string
	}{
		{"refusal", "port49d: config ok\n" + line + "\n", line},
		{"yaml", "port49d: config: yaml: line 3: did not find expected key\n", ""},
		{"unrelated", "port49d: listen tcp 127.0.0.1:49: address already in use\n", ""},
		{"empty", "", ""},
	} {
		if got := startRefusal(tc.said); got != tc.want {
			t.Errorf("%s: startRefusal = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// settleRecordsFn waits for the wanted records, then for the log to be quiet.
func TestSettleRecordsFn(t *testing.T) {
	calls := 0
	read := func() []map[string]any {
		calls++
		n := min(calls, 4) // grows for four reads, then stops
		return make([]map[string]any, n)
	}
	want := func(rs []map[string]any) bool { return len(rs) >= 2 }
	start := time.Now()
	recs, ok := settleRecordsFn(read, want, 120*time.Millisecond, 5*time.Second)
	if !ok || len(recs) != 4 {
		t.Errorf("got %d records, ok=%v; want 4 and true (the log kept growing after the wanted records)", len(recs), ok)
	}
	if time.Since(start) < 120*time.Millisecond {
		t.Error("returned before the quiet period")
	}
	start = time.Now()
	recs, ok = settleRecordsFn(func() []map[string]any { return nil }, want, 50*time.Millisecond, 300*time.Millisecond)
	if ok || len(recs) != 0 || time.Since(start) < 300*time.Millisecond {
		t.Errorf("a wait that is never satisfied: ok=%v, %d records, after %s", ok, len(recs), time.Since(start))
	}
}

// the events a phase waits for, for the user alone.
func TestWantsEvents(t *testing.T) {
	rec := func(event, user string) map[string]any {
		return map[string]any{"event": event, "session": map[string]any{"username": user}}
	}
	recs := []map[string]any{rec("redeem", "svc-oxidized"), rec("authorize_command", "someone")}
	if wantsEvents("svc-oxidized", "redeem")(recs) != true || wantsEvents("svc-oxidized", "redeem", "authorize_command")(recs) {
		t.Error("wantsEvents does not require every event for the user")
	}
}

// a minted login: the TSV the CLI writes has the user and the token in the 4th and 5th columns.
func TestParseMintedLogin(t *testing.T) {
	user, tok, err := parseMintedLogin("leaf1\tx\tarista_eos\tsvc-oxidized\tsecrettoken123\n")
	if err != nil || user != "svc-oxidized" || tok != "secrettoken123" {
		t.Errorf("got %q %q %v", user, tok, err)
	}
	for _, bad := range []string{"", "leaf1\tx\n", "a\tb\tc\td\t\n"} {
		if _, _, err := parseMintedLogin(bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}

// docker's or compose's own errors are not step's answer.
func TestDockerFault(t *testing.T) {
	for _, tc := range []struct {
		out  string
		want bool
	}{
		{"service \"step-ca\" is not running", true},
		{"Error response from daemon: No such container: x", true},
		{"docker: Error response from daemon: pull access denied", true},
		{"Cannot connect to the Docker daemon at unix:///var/run/docker.sock", true},
		{"error renewing certificate: client GET https://localhost:19000/health failed: connection refused", false},
		{"", false},
	} {
		if got := dockerFault(tc.out); got != tc.want {
			t.Errorf("dockerFault(%q) = %v, want %v", tc.out, got, tc.want)
		}
	}
}

// the principal is the second field of the line `principal  <id> (<method> <fp>)` of printIdentity.
func TestIdentityPrincipal(t *testing.T) {
	out := "principal  spiffe://port49.lab/host/oxidized-01 (x509 ab:cd)\nsubject    svc_oxidized\ngrants     all_devices [oxidized_all] max_privilege admin\n"
	if got := identityPrincipal(out); got != l48ID {
		t.Errorf("identityPrincipal = %q", got)
	}
	for _, bad := range []string{"", "subject    x\n", "principal\n"} {
		if got := identityPrincipal(bad); got != "" {
			t.Errorf("identityPrincipal(%q) = %q", bad, got)
		}
	}
}

// a token run's stdout registers its token column alone: not the device, the address or the user.
func TestTokenSecretsAreTheTokenColumnAlone(t *testing.T) {
	out := "leaf1\t10.0.0.1\tarista_eos\tsvc-oxidized\tTOKEN-leaf1\t2026-10-08T03:00:00Z\n"
	got := tokenSecrets(out)
	if !reflect.DeepEqual(got, []string{"TOKEN-leaf1"}) {
		t.Errorf("tokenSecrets = %q", got)
	}
	if tokenSecrets("") != nil {
		t.Error("an empty output registered a secret")
	}
}

// a failure to run docker at all, or an exit of docker's own (125-127), is a fault, not step's answer.
func TestRenewIsFault(t *testing.T) {
	exit := func(code string) error { return exec.Command("sh", "-c", "exit "+code).Run() }
	for _, tc := range []struct {
		name string
		err  error
		out  string
		want bool
	}{
		{"success", nil, "renewed", false},
		{"step refused", exit("1"), "error renewing certificate: connection refused", false},
		{"docker 125", exit("125"), "", true},
		{"docker 126", exit("126"), "", true},
		{"docker 127", exit("127"), "", true},
		{"docker message", exit("1"), "service \"step-ca\" is not running", true},
		{"not an exit error", &os.PathError{Op: "fork/exec", Path: "docker", Err: os.ErrNotExist}, "", true},
	} {
		if got := renewIsFault(tc.err, tc.out); got != tc.want {
			t.Errorf("%s: renewIsFault = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// a CRL fetch that could not connect is a harness fault too.
func TestCRLConnectFailureIsATLSLikeFault(t *testing.T) {
	for _, said := range []string{
		"port49d: broker: certificate status: CRL step_ca: Get \"https://localhost:19000/1.0/crl\": dial tcp 127.0.0.1:19000: connect: connection refused; the list in force stays\n",
		"port49d: broker: certificate status: CRL step_ca: Get \"x\": connection refused\n",
	} {
		if !crlTLSFailure(said) {
			t.Errorf("%q is not a fault", said)
		}
	}
	if crlTLSFailure("port49d: broker: certificate status: CRL step_ca: parse: malformed crl\n") {
		t.Error("a parse failure is a fault")
	}
}

func TestEndedWordAndUntilExpiry(t *testing.T) {
	if endedWord(true, 5*time.Minute) != "ended" || endedWord(false, 5*time.Minute) != "did not end within 5m0s" {
		t.Errorf("endedWord: %q %q", endedWord(true, time.Minute), endedWord(false, 5*time.Minute))
	}
	t0 := time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)
	if got := untilExpiry(t0.Add(6*time.Minute), t0, 270*time.Second); got != 90*time.Second {
		t.Errorf("untilExpiry = %s", got)
	}
}
