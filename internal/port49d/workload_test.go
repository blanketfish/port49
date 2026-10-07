package port49d

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/certstatus"
	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/directory"
	"github.com/rhwendt/port49/internal/oidc"
	"github.com/rhwendt/port49/internal/policy"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/memory"
	"github.com/rhwendt/port49/internal/testpki"
)

// withWorkloadAnchor writes ca as the workload anchor of cfg's broker, for
// corp.example.com, beside the human anchor brokerConfig wrote.
func withWorkloadAnchor(t *testing.T, cfg *config.Config, ca *testpki.CA) string {
	t.Helper()
	path := filepath.Join(filepath.Dir(cfg.Broker.ClientCAFile), "workloads-ca.pem")
	if err := os.WriteFile(path, ca.PEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Broker.WorkloadCAFile = path
	cfg.Broker.Identity = &oidc.Config{X509AnchorFile: cfg.Broker.ClientCAFile, Timing: oidc.DefaultTiming,
		X509Machine: &oidc.X509Machine{AnchorFile: path, TrustDomains: []string{"corp.example.com"}}}
	return path
}

// workloadPolicyBody is minimalPolicy with a workload subject naming id.
func workloadPolicyBody(id string) string {
	return strings.NewReplacer(
		`subjects: [{name: s, identity: ["user:alice@example.com"], username: alice, token_ttl: 60s}]`,
		`subjects: [{name: s, identity: ["user:alice@example.com"], username: alice, token_ttl: 60s},
           {name: svc, identity: ["`+id+`"], username: svc-oxidized, token_ttl: 60s}]`,
		`grants: [{subject: s, scope: all_devices, roles: [r]}]`,
		`grants: [{subject: s, scope: all_devices, roles: [r]}, {subject: svc, scope: all_devices, roles: [r]}]`,
	).Replace(minimalPolicy)
}

func TestAWorkloadBrokerBuildsAndSaysWhatItTrusts(t *testing.T) {
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	cfg := brokerConfig(t, workloadPolicyBody("spiffe://lab.example.net/host/x"))
	ca, err := testpki.NewCA("Workloads Issuing CA", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	path := withWorkloadAnchor(t, &cfg, ca)
	_, b, anchors, err := buildBrokerAnchor(cfg, "inventory_file "+cfg.InventoryFile, memory.New(time.Now), seedMinter(),
		decision.NewJSONLines(io.Discard), newMetrics())
	if err != nil {
		t.Fatal(err)
	}
	if b.Workload == nil || !b.Workload.Anchor.Equal(ca.Cert) || len(anchors) != 2 ||
		anchors[1].key != "broker.identity.machines[].trust_anchor_file" {
		t.Fatalf("workload %+v anchors %+v", b.Workload, anchors)
	}
	for _, want := range []string{
		"identity: machines: x509 (trust anchor " + path + "; SPIFFE trust domains corp.example.com; principal: the certificate's one URI SAN)",
		"identity: workload certificates are issued and renewed by your CA, never by port49",
		"policy: 1 workload identities mint for no one: spiffe://lab.example.net/host/x (subject svc): no machines x509 verifier lists trust domain lab.example.net",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in:\n%s", want, out.String())
		}
	}
}

// With no workload verifier, a spiffe:// identity mints for no one, said so.
func TestASpiffeIdentityWithNoWorkloadVerifierIsSaid(t *testing.T) {
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	cfg := brokerConfig(t, workloadPolicyBody("spiffe://corp.example.com/host/oxidized-01"))
	if err := buildWith(cfg); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "mint for no one: spiffe://corp.example.com/host/oxidized-01 (subject svc): no "+
		"broker.identity.machines x509 verifier is configured") {
		t.Fatalf("%s", out.String())
	}
}

func TestTheSameAnchorTwiceRefusesTheStart(t *testing.T) {
	cfg := brokerConfig(t, minimalPolicy)
	raw, err := os.ReadFile(cfg.Broker.ClientCAFile)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "copy.pem")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Broker.WorkloadCAFile = path
	cfg.Broker.Identity = &oidc.Config{X509AnchorFile: cfg.Broker.ClientCAFile, Timing: oidc.DefaultTiming,
		X509Machine: &oidc.X509Machine{AnchorFile: path, TrustDomains: []string{"corp.example.com"}}}
	if err := buildWith(cfg); err == nil || !strings.Contains(err.Error(), "holds the same certificate as") {
		t.Fatalf("got %v", err)
	}
}

// An unreadable anchor file is named by its key, then the error, each
// separated as an operator reads them.
func TestAnUnreadableAnchorNamesItsKey(t *testing.T) {
	cfg := brokerConfig(t, minimalPolicy)
	ca, err := testpki.NewCA("Workloads Issuing CA", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	withWorkloadAnchor(t, &cfg, ca)
	missing := filepath.Join(t.TempDir(), "gone.pem")
	cfg.Broker.WorkloadCAFile = missing
	if err := buildWith(cfg); err == nil || !strings.Contains(err.Error(),
		"broker.identity.machines[].trust_anchor_file "+missing+": open "+missing) {
		t.Fatalf("workload anchor: %v", err)
	}
	cfg.Broker.WorkloadCAFile = ""
	cfg.Broker.ClientCAFile = missing
	if err := buildWith(cfg); err == nil || !strings.Contains(err.Error(), "client_ca_file: open "+missing) {
		t.Fatalf("human anchor: %v", err)
	}
}

func TestAnAnchorSignedByTheOtherRefusesTheStart(t *testing.T) {
	root, err := testpki.NewCA("Corp Root", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	sub, err := root.IssueCA("Workloads Issuing CA", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct{ human, workload *x509.Certificate }{
		"the human anchor signs the workload anchor": {root.Cert, sub.Cert},
		"the workload anchor signs the human anchor": {sub.Cert, root.Cert},
	} {
		err := distinctAnchors(namedAnchor{key: "broker.client_ca_file", cert: c.human},
			namedAnchor{key: "broker.identity.machines[].trust_anchor_file", cert: c.workload})
		if err == nil || !strings.Contains(err.Error(), "chains to both anchors and is refused at every request; anchor each "+
			"list at its own issuing CA") {
			t.Errorf("%s: %v", name, err)
		}
	}
	other, _ := testpki.NewCA("Other", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err := distinctAnchors(namedAnchor{cert: root.Cert}, namedAnchor{cert: other.Cert}); err != nil {
		t.Fatalf("two unrelated anchors: %v", err)
	}
}

// A CRL under either anchor is a source; one under neither is refused; an
// anchor no source covers is said (decision 40 ruling 7).
func TestCertificateStatusCoversBothAnchors(t *testing.T) {
	human, _ := testpki.NewCA("Users CA", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	work, _ := testpki.NewCA("Workloads CA", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	stranger, _ := testpki.NewCA("Stranger CA", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	dir := t.TempDir()
	write := func(name string, ca *testpki.CA) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, ca.PEM(), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cs := config.CertificateStatusConfig{CRLs: []config.CertificateStatusCRL{
		{Name: "users", File: "/x", IssuerFile: write("users.pem", human)}}}
	ccfg, err := certStatusConfig(cs, []*x509.Certificate{human.Cert, work.Cert}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if uncoveredAnchor(ccfg, human.Cert) || !uncoveredAnchor(ccfg, work.Cert) {
		t.Fatal("coverage: the users' anchor is covered and the workloads' is not")
	}
	wa := namedAnchor{key: "broker.identity.machines[].trust_anchor_file", cert: work.Cert}
	// What the start says follows on_unavailable: refuse answers 503, allow
	// admits the certificate unchecked.
	line := anchorCoverLine(wa, ccfg, "refuse")
	if !strings.Contains(line, "every certificate under CN=Workloads CA (broker.identity.machines[].trust_anchor_file) "+
		"will be refused (503, retried)") || !strings.Contains(line, "turn the CA's CRL on") {
		t.Fatalf("uncovered, refuse: %q", line)
	}
	line = anchorCoverLine(wa, ccfg, "allow")
	if !strings.Contains(line, "every certificate under CN=Workloads CA (broker.identity.machines[].trust_anchor_file) "+
		"will be admitted with its revocation status unchecked (on_unavailable: allow)") ||
		strings.Contains(line, "refused") || !strings.Contains(line, "turn the CA's CRL on") {
		t.Fatalf("uncovered, allow: %q", line)
	}
	// OCSP alone is said as unchecked for the anchor, never as cover
	// (pre-flight M-18).
	ccfg.OCSP = &certstatus.OCSPConfig{}
	if line := anchorCoverLine(wa, ccfg, "refuse"); !strings.Contains(line, "are covered by OCSP alone, unchecked for this "+
		"anchor: one with no OCSP URL, or one its responder does not answer for, is refused (503, retried)") {
		t.Fatalf("OCSP alone, refuse: %q", line)
	}
	if line := anchorCoverLine(wa, ccfg, "allow"); !strings.Contains(line, "are covered by OCSP alone, unchecked for this "+
		"anchor: one with no OCSP URL, or one its responder does not answer for, is admitted unchecked (on_unavailable: allow)") ||
		strings.Contains(line, "refused") {
		t.Fatalf("OCSP alone, allow: %q", line)
	}
	cs.CRLs = append(cs.CRLs, config.CertificateStatusCRL{Name: "work", File: "/y", IssuerFile: write("work.pem", work)})
	if ccfg, err = certStatusConfig(cs, []*x509.Certificate{human.Cert, work.Cert}, dir); err != nil ||
		uncoveredAnchor(ccfg, work.Cert) || anchorCoverLine(wa, ccfg, "refuse") != "" {
		t.Fatalf("a CRL under the workload anchor: %v", err)
	}
	cs.CRLs = append(cs.CRLs, config.CertificateStatusCRL{Name: "stranger", File: "/z", IssuerFile: write("s.pem", stranger)})
	if _, err := certStatusConfig(cs, []*x509.Certificate{human.Cert, work.Cert}, dir); err == nil ||
		!strings.Contains(err.Error(), "is neither a trust anchor's certificate nor signed by one") {
		t.Fatalf("a CRL under neither anchor: %v", err)
	}
}

// workloadRunConfig is writeRunConfig(b) with the human anchor and a
// workload anchor at workPath as broker.identity's two x509 verifiers
// (corp.example.com), in place of client_ca_file.
func workloadRunConfig(t *testing.T, b *config.BrokerConfig, workPath string) string {
	t.Helper()
	cfgPath := writeRunConfig(t, b)
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	was := "  client_ca_file: " + b.ClientCAFile + "\n"
	if !bytes.Contains(raw, []byte(was)) {
		t.Fatalf("writeRunConfig no longer writes %q", was)
	}
	now := "  identity:\n    humans: [{type: x509, trust_anchor_file: " + b.ClientCAFile + "}]\n" +
		"    machines: [{type: x509, trust_anchor_file: " + workPath + ", spiffe_trust_domains: [corp.example.com]}]\n"
	if err := os.WriteFile(cfgPath, bytes.Replace(raw, []byte(was), []byte(now), 1), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfgPath
}

// workloadMint posts a one-device mint as leaf, trusting the server
// certificate's CA at serverCAFile. The body is returned only for an answer
// that is not a 200: a mint answer carries tokens and is never printed.
func workloadMint(t *testing.T, brokerAddr, serverCAFile string, leaf tls.Certificate) (int, string) {
	t.Helper()
	caPEM, err := os.ReadFile(serverCAFile)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		Certificates: []tls.Certificate{leaf}, RootCAs: roots, MinVersion: tls.VersionTLS13}}}
	req, err := http.NewRequest(http.MethodPost, "https://"+brokerAddr+"/v1/tokens", strings.NewReader(`{"devices":["leaf1"]}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("workload mint: %v%s", err, brokerLines())
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusOK {
		return resp.StatusCode, ""
	}
	return resp.StatusCode, string(body)
}

// A CRL under the workload anchor refuses a workload leaf it names at mint,
// and one it does not name still mints: certificate status covers both
// anchors (decision 40 ruling 7).
func TestACRLUnderTheWorkloadAnchorRefusesAWorkloadLeaf(t *testing.T) {
	out := captureStderr(t)
	const id = "spiffe://corp.example.com/host/oxidized-01"
	b := brokerConfig(t, workloadPolicyBody(id)).Broker
	pkiDir := filepath.Dir(b.ClientCAFile)
	now := time.Now().UTC().Truncate(time.Second)
	ca, err := testpki.NewCA("Workloads Issuing CA", now.Add(-time.Hour), now.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	workPath := writeFile(t, pkiDir, "workloads-ca.pem", ca.PEM())
	u, _ := url.Parse(id)
	issue := func(serial int64) tls.Certificate {
		leaf, err := ca.Issue(testpki.Leaf{CommonName: "oxidized-01", URIs: []*url.URL{u}, Client: true,
			NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), Serial: big.NewInt(serial)})
		if err != nil {
			t.Fatal(err)
		}
		return leaf
	}
	b.CertificateStatus = &config.CertificateStatusConfig{CRLs: []config.CertificateStatusCRL{{Name: "workloads_ca",
		File:       writeFile(t, t.TempDir(), "work.crl", crl(t, ca, now.Add(-time.Minute), now.Add(2*time.Hour), big.NewInt(0xbad))),
		IssuerFile: workPath}}}
	addr, stop := startDaemon(t, workloadRunConfig(t, b, workPath), out)
	defer stop()
	deadline := time.Now().Add(10 * time.Second)
	var status int
	var body string
	for {
		if status, body = workloadMint(t, addr, b.ClientCAFile, issue(0xbad)); status != http.StatusServiceUnavailable ||
			time.Now().After(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if status != http.StatusUnauthorized || !strings.Contains(body, `"credential_revoked"`) ||
		!strings.Contains(body, "at its CA (crl workloads_ca") {
		t.Fatalf("the revoked workload leaf: %d %s", status, body)
	}
	if status, body := workloadMint(t, addr, b.ClientCAFile, issue(0x900d)); status != http.StatusOK {
		t.Fatalf("a workload leaf the list does not name: %d %s", status, body)
	}
}

// With a directory and a workload verifier both configured, the listener
// port49d builds has Map and Caller both set: a person binds through the
// directory, a workload binds without reaching it (plan 8; pre-flight I-4).
func TestAWorkloadBindsThroughTheListenerWithoutTheDirectory(t *testing.T) {
	var out syncBuffer
	e, o, h := stderr, stdout, openDirectoryHook
	t.Cleanup(func() { stderr, stdout, openDirectoryHook = e, o, h })
	stderr, stdout = &out, io.Discard
	var lookups atomic.Int64
	openDirectoryHook = func(_ config.Config, st store.Store, _ *policy.Live, _ *metrics.Metrics,
		_ func(string, ...any)) (*directory.Resolver, error) {
		return directory.ForTestsFuncResolver(st, func(principal string) (directory.Answer, error) {
			lookups.Add(1)
			return directory.Answer{Source: directory.Grace, Membership: store.Membership{
				Principal: principal, EntryID: "dn:cn=alice", Username: "corp_alice", VerifiedAt: time.Now()}}, nil
		}), nil
	}
	const id = "spiffe://corp.example.com/host/oxidized-01"
	b := brokerConfig(t, workloadPolicyBody(id)).Broker
	pkiDir := filepath.Dir(b.ClientCAFile)
	ca, err := testpki.NewCA("Workloads Issuing CA", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	workPath := filepath.Join(pkiDir, "workloads-ca.pem")
	if err := os.WriteFile(workPath, ca.PEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := workloadRunConfig(t, b, workPath)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfgPath) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
		}
	})
	waitFor(t, &out, "port49d: broker listening on ")
	addrs := regexp.MustCompile(`listening on (127\.0\.0\.1:\d+)`).FindAllStringSubmatch(out.String(), -1)
	if len(addrs) != 2 {
		t.Fatalf("stderr: %q", out.String())
	}
	brokerAddr := addrs[1][1]

	// The workload, bound by its certificate: it mints, and the directory is
	// not asked.
	u, _ := url.Parse(id)
	leaf, err := ca.Issue(testpki.Leaf{CommonName: "oxidized-01", URIs: []*url.URL{u}, Client: true,
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if status, body := workloadMint(t, brokerAddr, b.ClientCAFile, leaf); status != http.StatusOK {
		t.Fatalf("workload mint: status %d, %s%s", status, body, brokerLines())
	}
	if n := lookups.Load(); n != 0 {
		t.Fatalf("the workload reached the directory %d time(s)", n)
	}

	// A person on the same listener still goes through the directory.
	mint(t, brokerAddr, pkiDir, "leaf1")
	if lookups.Load() == 0 {
		t.Fatal("a person bound without the directory: Map is not set")
	}
}
