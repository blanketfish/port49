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
`

func loadWith(t *testing.T, extra string) (Config, error) {
	t.Helper()
	setKeyEnv(t)
	return Load(write(t, "port49d.yaml", fmt.Sprintf(sample, write(t, "inv.yaml", inv))+extra))
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
