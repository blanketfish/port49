package kind

import (
	"strings"
	"testing"
)

// store-roles refuses two components with one CN, and both rendered configs name the same client
// certificate path: the bring-up's pod must read the broker's config with its own Secret's path.
func TestBrokerConfigForRolesNamesTheBrokersOwnSecret(t *testing.T) {
	got, err := brokerConfigForRoles("etcd:\n  cert_file: /etc/port49/etcd/tls.crt\n  key_file: /etc/port49/etcd/tls.key\n  ca_file: /etc/port49/etcd-ca/ca.crt\n")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"/etc/port49/etcd-broker/tls.crt", "/etc/port49/etcd-broker/tls.key", "/etc/port49/etcd-ca/ca.crt"} {
		if !strings.Contains(got, want) {
			t.Errorf("the config lacks %s:\n%s", want, got)
		}
	}
	if strings.Contains(got, "/etc/port49/etcd/") {
		t.Errorf("the config still names the daemon's directory:\n%s", got)
	}
	if _, err := brokerConfigForRoles("etcd: {}\n"); err == nil {
		t.Error("a config with no client certificate is accepted")
	}
}

func TestOptionsDefaultsAreTheSmokesOwn(t *testing.T) {
	var o Options
	if o.kindConfig() != "kind.yaml" || o.serviceValues() != "service: {type: NodePort}\n" {
		t.Errorf("the defaults are %q and %q", o.kindConfig(), o.serviceValues())
	}
	o = Options{KindConfig: "kind-l85.yaml", Service: "service:\n  type: LoadBalancer\n"}
	if o.kindConfig() != "kind-l85.yaml" || !strings.HasPrefix(o.serviceValues(), "service:\n") {
		t.Errorf("the options' own values are ignored: %q %q", o.kindConfig(), o.serviceValues())
	}
}
