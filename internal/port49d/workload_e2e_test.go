package port49d

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/directory"
	"github.com/rhwendt/port49/internal/policy"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/tacacs/wire"
	"github.com/rhwendt/port49/internal/testpki"
	"github.com/rhwendt/port49/internal/workload"
)

const (
	e2eWorkloadID  = "spiffe://port49.test/host/oxidized-01"
	e2eWorkload2ID = "spiffe://port49.test/host/oxidized-02"
)

// aliceEntryClient is a directory connection holding one entry, alice's, which
// answers the searches that name her (the mapping lookup and the two
// uniqueness checks) and finds no groups.
type aliceEntryClient struct{ alice *ldap.Entry }

func (c aliceEntryClient) SearchContext(_ context.Context, req *ldap.SearchRequest, _ uint32) (*ldap.SearchResult, error) {
	if strings.Contains(req.Filter, "alice@example.com") || strings.Contains(req.Filter, "(sAMAccountName=corp_alice)") {
		return &ldap.SearchResult{Entries: []*ldap.Entry{c.alice}}, nil
	}
	return &ldap.SearchResult{}, nil
}

func (aliceEntryClient) Close() error { return nil }

// mintAsAliceThroughADirectory runs port49d over a real resolver whose one
// server holds alice's entry with extra attributes, with the workload mapping
// wm (nil: none), and returns the status and body of alice's mint.
func mintAsAliceThroughADirectory(t *testing.T, wm *directory.WorkloadMapping, extra map[string][]string) (int, string) {
	t.Helper()
	var out syncBuffer
	e, o, h := stderr, stdout, openDirectoryHook
	t.Cleanup(func() { stderr, stdout, openDirectoryHook = e, o, h })
	stderr, stdout = &out, io.Discard
	attrs := map[string][]string{"userPrincipalName": {"alice@example.com"}, "sAMAccountName": {"corp_alice"},
		"mail": {"alice@example.com"}}
	maps.Copy(attrs, extra)
	client := aliceEntryClient{alice: ldap.NewEntry("CN=Al Lee,OU=Staff,DC=corp", attrs)}
	openDirectoryHook = func(_ config.Config, st store.Store, _ *policy.Live, m *metrics.Metrics,
		say func(string, ...any)) (*directory.Resolver, error) {
		cfg := *directoryCfg("simple")
		cfg.Servers = []directory.Server{{URI: "ldaps://dc-01", Priority: 100}}
		cfg.Site, cfg.Nested = "", "direct"
		cfg.BaseDN, cfg.GroupsBaseDN = "DC=corp", "OU=G,DC=corp"
		cfg.UserFilter, cfg.GroupFilter, cfg.GroupNameAttribute, cfg.MemberAttribute =
			"(objectClass=person)", "(objectClass=group)", "cn", "member"
		cfg.Mapping = directory.Mapping{Kind: directory.MapSANEmail, Attribute: "mail", AllowWeak: true}
		cfg.Workload = wm
		dial := func(context.Context, directory.Server) (directory.Client, error) { return client, nil }
		noCheck := func(context.Context, directory.Searcher) error { return nil }
		pool := directory.NewPool(cfg, dial, noCheck, time.Now, m, say)
		return &directory.Resolver{Cfg: cfg, Pool: pool, Store: st, Now: time.Now, M: m, Say: say}, nil
	}
	b := brokerConfig(t, minimalPolicy).Broker
	pki := filepath.Dir(b.ClientCAFile)
	cfgPath := writeRunConfig(t, b)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfgPath) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("run did not return")
		}
	})
	waitFor(t, &out, "port49d: broker listening on ")
	addr := regexp.MustCompile(`port49d: broker listening on (\S+)`).FindStringSubmatch(out.String())[1]
	status, body, err := postAsAlice(pki, addr)
	if err != nil {
		t.Fatal(err)
	}
	return status, body
}

// A person whose directory entry holds a SPIFFE ID in the workload mapping's
// attribute is refused identity_unmapped (one entry, one domain: decision 41
// ruling 4); with no mapping the same entry binds as before.
func TestAPersonWhoseEntryHoldsASPIFFEIDIsRefusedUnderTheWorkloadMapping(t *testing.T) {
	uid := map[string][]string{"uid": {"spiffe://corp.example.com/host/oxidized-01"}}
	status, body := mintAsAliceThroughADirectory(t, workloadMapping(), uid)
	if status == http.StatusOK || !strings.Contains(body, "identity_unmapped") {
		t.Fatalf("under the mapping: %d %s", status, body)
	}
	if status, body := mintAsAliceThroughADirectory(t, nil, uid); status != http.StatusOK {
		t.Fatalf("without the mapping: %d %s", status, body)
	}
	if status, body := mintAsAliceThroughADirectory(t, workloadMapping(), nil); status != http.StatusOK {
		t.Fatalf("under the mapping, no SPIFFE ID in her entry: %d %s", status, body)
	}
}

// writeWorkloadRunConfig is writeRunConfig with broker.identity: the lab
// anchor for people and the workload anchor in pki for machines, and a
// policy giving the workload svc-oxidized on leaf1.
func writeWorkloadRunConfig(t *testing.T, b *config.BrokerConfig, pki string) string {
	t.Helper()
	cfgPath := writeRunConfig(t, b)
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	identity := fmt.Sprintf("  identity:\n    humans: [{type: x509, trust_anchor_file: %s}]\n"+
		"    machines: [{type: x509, trust_anchor_file: %s, spiffe_trust_domains: [port49.test]}]\n",
		b.ClientCAFile, filepath.Join(pki, testpki.WorkloadCA))
	text := strings.Replace(string(raw), fmt.Sprintf("  client_ca_file: %s\n", b.ClientCAFile), identity, 1)
	if err := os.WriteFile(cfgPath, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfgPath
}

const e2eWorkloadPolicy = `
scopes: [{name: all_devices, match: {}}]
roles: [{name: r, privilege: admin, permit: ["**"]}]
subjects:
  - {name: s, identity: ["user:alice@example.com"], username: alice, token_ttl: 60s}
  - {name: svc, identity: ["` + e2eWorkloadID + `", "` + e2eWorkload2ID + `"], username: svc-oxidized,
     token_ttl: 600s}
grants: [{subject: s, scope: all_devices, roles: [r]}, {subject: svc, scope: all_devices, roles: [r]}]
` + runKeys

// startWorkloadDaemon runs port49d with a workload verifier; out is its
// stderr and recs its decision log (stdout).
func startWorkloadDaemon(t *testing.T) (brokerAddr, tacacsAddr, pki, workDir string, out, recs *syncBuffer) {
	t.Helper()
	brokerAddr, tacacsAddr, pki, workDir, out, recs, _, _ = startWorkloadDaemonAt(t)
	return brokerAddr, tacacsAddr, pki, workDir, out, recs
}

// startWorkloadDaemonAt is startWorkloadDaemon that also returns the config's
// path and a stop, which ends the run and waits for it (the cleanup does too).
func startWorkloadDaemonAt(t *testing.T) (brokerAddr, tacacsAddr, pki, workDir string, out, recs *syncBuffer, cfgPath string, stop func()) {
	t.Helper()
	out, recs = &syncBuffer{}, &syncBuffer{}
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o })
	stderr, stdout = out, recs
	b := brokerConfig(t, e2eWorkloadPolicy).Broker
	pki = filepath.Dir(b.ClientCAFile)
	workDir = t.TempDir()
	if err := testpki.WriteWorkloadLab(workDir, e2eWorkloadID, time.Now()); err != nil {
		t.Fatal(err)
	}
	cfgPath = writeWorkloadRunConfig(t, b, workDir)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfgPath) }()
	stopped := false
	stop = func() {
		if stopped {
			return
		}
		stopped = true
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("run did not return")
		}
	}
	t.Cleanup(stop)
	waitForCount(t, out, "port49d: broker listening on ", 1)
	brokerAddr = regexp.MustCompile(`port49d: broker listening on (\S+)`).FindStringSubmatch(out.String())[1]
	tacacsAddr = regexp.MustCompile(`port49d: listening on ([^,\s]+),`).FindStringSubmatch(out.String())[1]
	return brokerAddr, tacacsAddr, pki, workDir, out, recs, cfgPath, stop
}

func workloadClient(t *testing.T, brokerAddr, pki, workDir string) *workload.Client {
	t.Helper()
	caPEM, err := os.ReadFile(filepath.Join(pki, testpki.LabCA))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	c, err := workload.New(workload.Config{Broker: "https://" + brokerAddr, BrokerCA: pool,
		CertFile: filepath.Join(workDir, testpki.WorkloadCert), KeyFile: filepath.Join(workDir, testpki.WorkloadKey)})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// A workload certificate mints through port49d's real listener, its token
// logs in on the TACACS+ side under the declared username, and alice's
// certificate still mints beside it (decision 40; spec §14).
func TestAWorkloadMintsAndLogsInThroughPort49d(t *testing.T) {
	brokerAddr, tacacsAddr, pki, workDir, out, _ := startWorkloadDaemon(t)
	for _, want := range []string{"identity: machines: x509 (trust anchor ", "SPIFFE trust domains port49.test"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("the start lines lack %q:\n%s", want, out.String())
		}
	}
	resp, err := workloadClient(t, brokerAddr, pki, workDir).Mint(context.Background(),
		workload.MintOptions{Devices: []string{"leaf1"}})
	if err != nil || resp.Principal != e2eWorkloadID || len(resp.Results) != 1 || resp.Results[0].Login == "" {
		t.Fatalf("%+v %v", resp, err)
	}
	dev := tacacsClient{t: t, addr: tacacsAddr, key: []byte("run-test-secret")}
	if st := dev.login("svc-oxidized", resp.Results[0].Login); st != wire.AuthenStatusPass {
		t.Fatalf("the workload's login: status %d", st)
	}
	if status, body, err := postAsAlice(pki, brokerAddr); err != nil || status != 200 {
		t.Fatalf("alice beside it: %d %s %v", status, body, err)
	}
}

// A renewal on disk is the same principal at the next run: nothing in port49
// changes (decision 40 ruling 8).
func TestARenewedCertificateMintsAsTheSamePrincipal(t *testing.T) {
	brokerAddr, _, pki, workDir, _, _ := startWorkloadDaemon(t)
	first, err := workloadClient(t, brokerAddr, pki, workDir).Identity(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := testpki.RenewWorkload(workDir, e2eWorkloadID, time.Now()); err != nil {
		t.Fatal(err)
	}
	renewed, err := workloadClient(t, brokerAddr, pki, workDir).Identity(context.Background())
	if err != nil || first.Principal != e2eWorkloadID || renewed.Principal != e2eWorkloadID ||
		renewed.Fingerprint == first.Fingerprint {
		t.Fatalf("first %+v renewed %+v %v", first, renewed, err)
	}
}

// A mark by certificate (issuer, serial) refuses that certificate and nothing
// that follows it: the renewal, the same ID under a new serial, still mints as
// the same principal (decision 40 ruling 8). Revoking the principal is the
// mark that follows a renewal.
func TestAMarkOnAWorkloadCertificateDoesNotFollowItsRenewal(t *testing.T) {
	brokerAddr, _, pki, workDir, out, _, cfgPath, stop := startWorkloadDaemonAt(t)
	ctx := context.Background()
	opts := workload.MintOptions{Devices: []string{"leaf1"}}
	if _, err := workloadClient(t, brokerAddr, pki, workDir).Mint(ctx, opts); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(workDir, testpki.WorkloadCert))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatal("no certificate in the workload cert file")
	}
	old, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	// The mark is made with port49d stopped, the break-glass form, and the
	// next start loads it from broker.revocations_file before it serves.
	stop()
	var rout, rerr bytes.Buffer
	if code := offlineRevokeDaemon([]string{"--offline", "--config", cfgPath, "--cert-issuer", old.Issuer.String(),
		"--cert-serial", old.SerialNumber.Text(16)}, &rout, &rerr); code != 0 {
		t.Fatalf("revoke --offline: exit %d: %s", code, rerr.String())
	}
	rctx, rcancel := context.WithCancel(context.Background())
	rdone := make(chan error, 1)
	go func() { rdone <- run(rctx, cfgPath) }()
	t.Cleanup(func() {
		rcancel()
		select {
		case <-rdone:
		case <-time.After(10 * time.Second):
			t.Error("the restarted run did not return")
		}
	})
	waitForCount(t, out, "port49d: broker listening on ", 2)
	addrs := regexp.MustCompile(`port49d: broker listening on (\S+)`).FindAllStringSubmatch(out.String(), -1)
	brokerAddr = addrs[len(addrs)-1][1]
	var apiErr *workload.APIError
	if _, err := workloadClient(t, brokerAddr, pki, workDir).Mint(ctx, opts); !errors.As(err, &apiErr) ||
		apiErr.Status != http.StatusUnauthorized || apiErr.Code != "credential_revoked" {
		t.Fatalf("the marked certificate: %v", err)
	}
	if err := testpki.RenewWorkload(workDir, e2eWorkloadID, time.Now()); err != nil {
		t.Fatal(err)
	}
	resp, err := workloadClient(t, brokerAddr, pki, workDir).Mint(ctx, opts)
	if err != nil || resp.Principal != e2eWorkloadID || len(resp.Results) != 1 {
		t.Fatalf("the renewed certificate: %+v %v", resp, err)
	}
}

// Two identities of one subject log in to one device: they mint one
// username, the second login replaces the first's context, the redeem record
// says so, and a command is still the subject's to run (decision 40 ruling
// 11; spec §5.6).
func TestTwoIdentitiesOfOneSubjectShareTheDevice(t *testing.T) {
	brokerAddr, tacacsAddr, pki, workDir, _, recs := startWorkloadDaemon(t)
	other := t.TempDir()
	if err := testpki.WriteWorkloadLabFrom(workDir, other, e2eWorkload2ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	a, err := workloadClient(t, brokerAddr, pki, workDir).Mint(ctx, workload.MintOptions{Devices: []string{"leaf1"}})
	if err != nil {
		t.Fatal(err)
	}
	b, err := workloadClient(t, brokerAddr, pki, other).Mint(ctx, workload.MintOptions{Devices: []string{"leaf1"}})
	if err != nil {
		t.Fatal(err)
	}
	if a.Subject != "svc" || b.Subject != "svc" || b.Principal != e2eWorkload2ID ||
		a.Results[0].Username != b.Results[0].Username {
		t.Fatalf("%+v %+v", a, b)
	}
	dev := tacacsClient{t: t, addr: tacacsAddr, key: []byte("run-test-secret")}
	if dev.login("svc-oxidized", a.Results[0].Login) != wire.AuthenStatusPass ||
		dev.login("svc-oxidized", b.Results[0].Login) != wire.AuthenStatusPass {
		t.Fatal("a login failed")
	}
	// The device asks for the session first and so reaches priv-lvl 15, as
	// vEOS does (run_test.go's authorize); a command asked before that is above
	// the login's level.
	if r := dev.authorize("svc-oxidized"); r.Status != wire.AuthorStatusPassAdd {
		t.Fatalf("session authorization after the replace: %+v", r)
	}
	if !dev.permits("svc-oxidized", "show", "running-config") {
		t.Fatal("the subject's command was refused after the replace")
	}
	waitFor(t, recs, `"replaced_ctx_id"`)
}
