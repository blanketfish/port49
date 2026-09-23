package config

import (
	"fmt"
	"strings"
	"testing"
)

const brokerBlock = `broker:
  listen: "127.0.0.1:8449"
  tls_cert_file: /etc/port49/broker.pem
  tls_key_file: /etc/port49/broker-key.pem
  client_ca_file: /etc/port49/clients-ca.pem
  policy_file: /etc/port49/policy.yaml
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
	if b := c.Broker; b == nil || b.Listen != "127.0.0.1:8449" || b.PolicyFile != "/etc/port49/policy.yaml" || b.BatchMax != 100 {
		t.Fatalf("broker: %+v", c.Broker)
	}
}

// Every file is required: a broker with no trust anchor is not a broker that
// trusts nobody, it is a config mistake, and it is refused at start.
func TestABrokerBlockMissingAKeyIsRefused(t *testing.T) {
	for _, key := range []string{"listen", "tls_cert_file", "tls_key_file", "client_ca_file", "policy_file"} {
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
