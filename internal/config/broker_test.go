package config

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"
)

const brokerBlock = `broker:
  listen: "127.0.0.1:8449"
  tls_cert_file: /etc/port49/broker.pem
  tls_key_file: /etc/port49/broker-key.pem
  client_ca_file: /etc/port49/clients-ca.pem
  policy_file: /etc/port49/policy.yaml
  revocations_file: /var/lib/port49/revocations.json
  certificate_status: {disabled: true}
`

func loadWith(t *testing.T, extra string) (Config, error) {
	t.Helper()
	setKeyEnv(t)
	body := fmt.Sprintf(sample, write(t, "inv.yaml", inv)) + extra
	if strings.Contains(extra, "broker:") || strings.Contains(extra, "policy:") {
		body = withPolicy(body)
	}
	return Load(write(t, "port49d.yaml", body))
}

func TestNoBrokerBlockIsNoBroker(t *testing.T) {
	c, err := loadWith(t, "")
	if err != nil || c.Broker != nil {
		t.Fatalf("broker %+v err %v", c.Broker, err)
	}
}

func TestABrokerBlockLoads(t *testing.T) {
	c, err := loadWith(t, brokerBlock)
	if err != nil {
		t.Fatal(err)
	}
	if b := c.Broker; b == nil || b.Listen != "127.0.0.1:8449" || b.PolicyFile != "/etc/port49/policy.yaml" || b.BatchMax != 100 ||
		b.PolicyWatchInterval != 5*time.Second {
		t.Fatalf("broker: %+v", c.Broker)
	}
}

// Every file is required: a broker with no trust anchor is not a broker that
// trusts nobody, it is a config mistake, and it is refused at start.
func TestABrokerBlockMissingAKeyIsRefused(t *testing.T) {
	for _, key := range []string{"listen", "tls_cert_file", "tls_key_file", "client_ca_file", "policy_file",
		"revocations_file"} {
		var kept []string
		for _, line := range strings.Split(brokerBlock, "\n") {
			if !strings.HasPrefix(strings.TrimSpace(line), key+":") {
				kept = append(kept, line)
			}
		}
		if _, err := loadWith(t, strings.Join(kept, "\n")); err == nil || !strings.Contains(err.Error(), "broker."+key) {
			t.Errorf("without %s: %v", key, err)
		}
	}
}

func TestBatchMaxIsBounded(t *testing.T) {
	if _, err := loadWith(t, brokerBlock+"  batch_max: 5000\n"); err == nil || !strings.Contains(err.Error(), "batch_max") {
		t.Fatalf("batch_max 5000: %v", err)
	}
}

// The watch reads the policy file on a timer. Faster than a second is a disk
// read loop, and slower than five minutes is an edit an operator thinks is
// live and is not; both are refused rather than clamped.
func TestPolicyWatchIntervalIsBounded(t *testing.T) {
	for _, v := range []string{"500ms", "10m"} {
		if _, err := loadWith(t, brokerBlock+"  policy_watch_interval: "+v+"\n"); err == nil ||
			!strings.Contains(err.Error(), "broker.policy_watch_interval") {
			t.Errorf("policy_watch_interval %s: %v", v, err)
		}
	}
	c, err := loadWith(t, brokerBlock+"  policy_watch_interval: 30s\n")
	if err != nil || c.Broker.PolicyWatchInterval != 30*time.Second {
		t.Fatalf("30s: %+v %v", c.Broker, err)
	}
}

// The two caps default, and are bounded rather than clamped (spec §13
// decision 32).
func TestTheBrokerConnectionCapsAreBounded(t *testing.T) {
	c, err := loadWith(t, brokerBlock)
	if err != nil || c.Broker.MaxConnsPerPrincipal != 4 || c.Broker.MaxPendingConnsPerSource != 16 {
		t.Fatalf("defaults: %+v %v", c.Broker, err)
	}
	for _, extra := range []string{"  max_conns_per_principal: 65\n", "  max_conns_per_principal: -1\n",
		"  max_pending_conns_per_source: 257\n", "  max_pending_conns_per_source: -1\n"} {
		key := strings.TrimSpace(strings.SplitN(extra, ":", 2)[0])
		if _, err := loadWith(t, brokerBlock+extra); err == nil || !strings.Contains(err.Error(), "broker."+key) {
			t.Errorf("%q: %v", extra, err)
		}
	}
}

// The revocations file is port49d's own state: it may be no other path
// port49d reads or writes, compared as absolute paths (pre-flight M13).
func TestTheRevocationsFileIsItsOwn(t *testing.T) {
	for _, other := range []string{"/etc/port49/policy.yaml", "/etc/port49/broker-key.pem",
		"/etc/port49/broker.pem", "/etc/port49/clients-ca.pem", "/etc/port49/../port49/policy.yaml"} {
		block := strings.Replace(brokerBlock, "/var/lib/port49/revocations.json", other, 1)
		if _, err := loadWith(t, block); err == nil || !strings.Contains(err.Error(), "broker.revocations_file") {
			t.Errorf("revocations_file %s: %v", other, err)
		}
	}
	block := strings.Replace(brokerBlock, "/var/lib/port49/revocations.json", "/var/lib/port49/acct.jsonl", 1)
	if _, err := loadWith(t, block+"accounting: {spool_path: /var/lib/port49/acct.jsonl}\n"); err == nil {
		t.Error("revocations_file is the accounting spool")
	}
}

// Nor may it sit where the inventory service's state or mirror is kept: the
// service and port49d rewrite those directories' files (pre-flight M13).
func TestTheRevocationsFileIsOutsideTheServicesDirectories(t *testing.T) {
	block := serviceBlock(t) + "    mirror_dir: /srv/mirror\n"
	for path, want := range map[string]string{
		"/var/lib/port49/inventory/revocations.json":  "inside inventory.service.state_dir",
		"/srv/mirror/revocations.json":                "inside inventory.service.mirror_dir",
		"/var/lib/port49/inventory-revocations.json":  "",
		"/var/lib/port49/inventory/../revocations.js": "",
	} {
		b := strings.Replace(brokerBlock, "/var/lib/port49/revocations.json", path, 1)
		_, err := loadService(t, false, false, b+block)
		if want == "" && err != nil {
			t.Errorf("%s: %v", path, err)
		}
		if want != "" && (err == nil || !strings.Contains(err.Error(), "broker.revocations_file") ||
			!strings.Contains(err.Error(), want)) {
			t.Errorf("%s: got %v, want %q", path, err, want)
		}
	}
}

// inventory.service's trust files are paths port49d reads too, and so is
// none of them the revocations file or its marker (Task 9 review M5).
func TestTheRevocationsFileIsNotAServiceTrustFile(t *testing.T) {
	block := serviceBlock(t)
	pub := regexp.MustCompile(`verify_key_files: \[(\S+)\]`).FindStringSubmatch(block)[1]
	for _, other := range []string{"/etc/port49/inventory-ca.pem", "/etc/port49/port49d.pem",
		"/etc/port49/port49d-key.pem", pub} {
		b := strings.Replace(brokerBlock, "/var/lib/port49/revocations.json", other, 1)
		if _, err := loadService(t, false, false, b+block); err == nil ||
			!strings.Contains(err.Error(), "broker.revocations_file is port49d's own state") {
			t.Errorf("revocations_file %s: %v", other, err)
		}
	}
	b := strings.Replace(brokerBlock, "/var/lib/port49/revocations.json", "/etc/port49/port49d", 1)
	if _, err := loadService(t, false, false, b+strings.Replace(block, "/etc/port49/port49d.pem",
		"/etc/port49/port49d.created", 1)); err == nil || !strings.Contains(err.Error(), "marker") {
		t.Errorf("a marker that is the service's certificate: %v", err)
	}
}

// withStatus is brokerBlock with block in place of its certificate_status.
func withStatus(block string) string {
	return strings.Replace(brokerBlock, "  certificate_status: {disabled: true}\n", block, 1)
}

const goodStatus = `  certificate_status:
    crls:
      - {name: corp_issuing, url: http://pki.example.com/corp.crl, issuer_file: /etc/port49/corp-issuing-ca.pem}
      - {name: corp_root, file: /etc/port49/root.crl, issuer_file: /etc/port49/clients-ca.pem}
    ocsp: {responder: http://ocsp.example.com}
`

// broker.certificate_status is required with a broker, and each refusal
// names its key (plan 7b; spec §5.1.4).
func TestTheCertificateStatusBlockIsChecked(t *testing.T) {
	crl := func(entry string) string {
		return "  certificate_status:\n    crls:\n      - " + entry + "\n"
	}
	for _, c := range []struct{ name, block, key string }{
		{"absent", "", "broker.certificate_status is required with any x509 verifier"},
		{"disabled beside a CRL", "  certificate_status:\n    disabled: true\n    crls: [{name: a, file: /a.crl, " +
			"issuer_file: /a.pem}]\n", "broker.certificate_status.disabled"},
		{"disabled beside OCSP", "  certificate_status: {disabled: true, ocsp: {use_aia: true}}\n",
			"broker.certificate_status.disabled"},
		{"disabled beside on_unavailable", "  certificate_status: {disabled: true, on_unavailable: allow}\n",
			"beside broker.certificate_status.on_unavailable,"},
		{"disabled beside refresh_interval and an empty crls", "  certificate_status: {disabled: true, " +
			"refresh_interval: 1h, crls: []}\n", "beside broker.certificate_status.crls, " +
			"broker.certificate_status.refresh_interval,"},
		{"no source", "  certificate_status: {refresh_interval: 10m}\n", "broker.certificate_status:"},
		{"file and url", crl("{name: a, file: /a.crl, url: http://x/a.crl, issuer_file: /a.pem}"),
			"broker.certificate_status.crls[0]"},
		{"neither file nor url", crl("{name: a, issuer_file: /a.pem}"), "broker.certificate_status.crls[0]"},
		{"no issuer_file", crl("{name: a, file: /a.crl}"), "broker.certificate_status.crls[0].issuer_file"},
		{"ftp url", crl("{name: a, url: ftp://x/a.crl, issuer_file: /a.pem}"), "broker.certificate_status.crls[0].url"},
		{"file url", crl("{name: a, url: 'file:///a.crl', issuer_file: /a.pem}"),
			"broker.certificate_status.crls[0].url"},
		{"url without a host", crl("{name: a, url: 'http:///a.crl', issuer_file: /a.pem}"),
			"broker.certificate_status.crls[0].url"},
		{"no name", crl("{file: /a.crl, issuer_file: /a.pem}"), "broker.certificate_status.crls[0].name"},
		{"upper case name", crl("{name: Corp, file: /a.crl, issuer_file: /a.pem}"),
			"broker.certificate_status.crls[0].name"},
		{"name with a slash", crl("{name: a/../b, file: /a.crl, issuer_file: /a.pem}"),
			"broker.certificate_status.crls[0].name"},
		{"name starting with a digit", crl("{name: 1a, file: /a.crl, issuer_file: /a.pem}"),
			"broker.certificate_status.crls[0].name"},
		{"name too long", crl("{name: a" + strings.Repeat("b", 64) + ", file: /a.crl, issuer_file: /a.pem}"),
			"broker.certificate_status.crls[0].name"},
		{"duplicate name", "  certificate_status:\n    crls:\n      - {name: a, file: /a.crl, issuer_file: /a.pem}\n" +
			"      - {name: a, file: /b.crl, issuer_file: /b.pem}\n", "broker.certificate_status.crls[1].name"},
		{"md5", "  certificate_status: {ocsp: {use_aia: true, hash: md5}}\n", "broker.certificate_status.ocsp.hash"},
		{"refresh 30s", "  certificate_status: {ocsp: {use_aia: true}, refresh_interval: 30s}\n",
			"broker.certificate_status.refresh_interval"},
		{"refresh 25h", "  certificate_status: {ocsp: {use_aia: true}, refresh_interval: 25h}\n",
			"broker.certificate_status.refresh_interval"},
		{"timeout 50ms", "  certificate_status: {ocsp: {use_aia: true, timeout: 50ms}}\n",
			"broker.certificate_status.ocsp.timeout"},
		{"timeout 11s", "  certificate_status: {ocsp: {use_aia: true, timeout: 11s}}\n",
			"broker.certificate_status.ocsp.timeout"},
		{"OCSP with no responder", "  certificate_status: {ocsp: {timeout: 2s}}\n", "broker.certificate_status.ocsp"},
		{"responder not http", "  certificate_status: {ocsp: {responder: 'ldap://x'}}\n",
			"broker.certificate_status.ocsp.responder"},
		{"on_unavailable maybe", "  certificate_status: {ocsp: {use_aia: true}, on_unavailable: maybe}\n",
			"broker.certificate_status.on_unavailable"},
		{"a kept list over revocations_file", crl("{name: x, file: /a.crl, issuer_file: /a.pem}"),
			"broker.certificate_status.crls[0].name"},
	} {
		block := withStatus(c.block)
		if c.name == "a kept list over revocations_file" {
			block = strings.Replace(block, "/var/lib/port49/revocations.json", "/var/lib/port49/crl-x.der", 1)
		}
		if _, err := loadWith(t, block); err == nil || !strings.Contains(err.Error(), c.key) {
			t.Errorf("%s: got %v, want %q", c.name, err, c.key)
		}
	}
}

// A configuration error never repeats a URL, which may carry a credential.
func TestACertificateStatusRefusalDoesNotEchoTheURL(t *testing.T) {
	_, err := loadWith(t, withStatus("  certificate_status:\n    crls:\n      - {name: a, "+
		"url: 'ftp://user:hunter2@x/a.crl?token=s3cret', issuer_file: /a.pem}\n"))
	if err == nil || strings.Contains(err.Error(), "hunter2") || strings.Contains(err.Error(), "s3cret") {
		t.Fatalf("got %v", err)
	}
}

func TestAWellFormedCertificateStatusLoadsWithItsDefaults(t *testing.T) {
	c, err := loadWith(t, withStatus(goodStatus))
	if err != nil {
		t.Fatal(err)
	}
	cs := c.Broker.CertificateStatus
	if cs == nil || cs.Disabled || len(cs.CRLs) != 2 || cs.CRLs[0].Name != "corp_issuing" ||
		cs.CRLs[0].URL != "http://pki.example.com/corp.crl" || cs.CRLs[0].IssuerFile != "/etc/port49/corp-issuing-ca.pem" ||
		cs.CRLs[1].File != "/etc/port49/root.crl" {
		t.Fatalf("certificate_status: %+v", cs)
	}
	if cs.RefreshInterval != 10*time.Minute || cs.OnUnavailable != "refuse" || cs.OCSP == nil ||
		cs.OCSP.Timeout != 2*time.Second || cs.OCSP.Hash != "sha256" || cs.OCSP.Responder != "http://ocsp.example.com" {
		t.Fatalf("defaults: %+v %+v", cs, cs.OCSP)
	}
	for _, extra := range []string{"    on_unavailable: allow\n", "    refresh_interval: 1m\n", "    refresh_interval: 24h\n"} {
		if _, err := loadWith(t, withStatus(goodStatus+extra)); err != nil {
			t.Errorf("%q: %v", extra, err)
		}
	}
	for _, ocsp := range []string{"{use_aia: true, hash: sha1}", "{use_aia: true, timeout: 100ms}",
		"{responder: 'https://ocsp.example.com/x', timeout: 10s}"} {
		if _, err := loadWith(t, withStatus("  certificate_status: {ocsp: "+ocsp+"}\n")); err != nil {
			t.Errorf("ocsp %s: %v", ocsp, err)
		}
	}
	c, err = loadWith(t, brokerBlock)
	if err != nil || !c.Broker.CertificateStatus.Disabled {
		t.Fatalf("disabled: %+v %v", c.Broker.CertificateStatus, err)
	}
}
