package sdtest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rhwendt/port49/tests/kind/kindtest"
	"gopkg.in/yaml.v3"
)

func shipped(t *testing.T, rel ...string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(append([]string{kindtest.Root(), "deploy", "systemd"}, rel...)...))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func withoutComments(s string) string {
	var keep []string
	for _, l := range strings.Split(s, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(l), "#") {
			keep = append(keep, l)
		}
	}
	return strings.Join(keep, "\n")
}

func TestMemberRewritesEachExampleToItsOwnPorts(t *testing.T) {
	seen := map[string]bool{}
	for n := 1; n <= 3; n++ {
		out, err := Member(shipped(t, "examples", "etcd-"+string(rune('0'+n))+".yaml"), n)
		if err != nil {
			t.Fatal(err)
		}
		if live := withoutComments(out); strings.Contains(live, "example.com") || strings.Contains(live, "0.0.0.0") {
			t.Errorf("member %d keeps a name it cannot use in one container:\n%s", n, out)
		}
		var doc map[string]any
		if err := yaml.Unmarshal([]byte(out), &doc); err != nil {
			t.Fatal(err)
		}
		c, p := ClientPort(n), PeerPort(n)
		if doc["listen-client-urls"] != "https://127.0.0.1:"+itoa(c) || doc["listen-peer-urls"] != "https://127.0.0.1:"+itoa(p) {
			t.Errorf("member %d listens on %v / %v, want %d / %d", n, doc["listen-client-urls"], doc["listen-peer-urls"], c, p)
		}
		if doc["advertise-client-urls"] != "https://localhost:"+itoa(c) {
			t.Errorf("member %d advertises %v", n, doc["advertise-client-urls"])
		}
		ic, _ := doc["initial-cluster"].(string)
		for m := 1; m <= 3; m++ {
			if !strings.Contains(ic, "etcd-"+itoa(m)+"=https://localhost:"+itoa(PeerPort(m))) {
				t.Errorf("member %d's initial-cluster lacks member %d's peer port: %s", n, m, ic)
			}
		}
		if seen[itoa(c)] {
			t.Errorf("client port %d is used twice", c)
		}
		seen[itoa(c)] = true
	}
	if ClientPort(1) != 2379 || PeerPort(1) != 2380 || ClientPort(2) != 2479 || PeerPort(2) != 2480 || ClientPort(3) != 2579 || PeerPort(3) != 2580 {
		t.Error("the ports are not the brief's 2379/2380, 2479/2480, 2579/2580")
	}
	if _, err := Member("name: etcd-1\n", 1); err == nil {
		t.Error("a member file with nothing to rewrite was accepted")
	}
}

func TestEndpointsNamesEveryMemberByItsPort(t *testing.T) {
	for _, f := range []string{"port49d.yaml", "port49-broker.yaml"} {
		out, err := Endpoints(shipped(t, "config", f))
		if err != nil {
			t.Fatal(err)
		}
		for n := 1; n <= 3; n++ {
			if !strings.Contains(out, "https://localhost:"+itoa(ClientPort(n))) {
				t.Errorf("%s lacks member %d's URL", f, n)
			}
		}
		if strings.Contains(withoutComments(out), "example.com") {
			t.Errorf("%s keeps example.com", f)
		}
	}
	if _, err := Endpoints("stores: {}\n"); err == nil {
		t.Error("a config with no endpoints was accepted")
	}
}

func TestPolicyIsKeyedKAndAdmitsTheSubnet(t *testing.T) {
	out, err := Policy(shipped(t, "config", "policy.yaml"), "172.31.49.0/24")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		KeyGroups []struct {
			Match  struct{ CIDR string } `yaml:"match"`
			KeyRef string                `yaml:"key_ref"`
		} `yaml:"key_groups"`
		Keys map[string]struct {
			Current struct {
				SecretRef string `yaml:"secret_ref"`
			} `yaml:"current"`
		} `yaml:"keys"`
	}
	if err := yaml.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.KeyGroups) != 1 || doc.KeyGroups[0].Match.CIDR != "172.31.49.0/24" || doc.KeyGroups[0].KeyRef != "k" {
		t.Errorf("key_groups: %+v", doc.KeyGroups)
	}
	if doc.Keys["k"].Current.SecretRef != "file:/etc/port49/keys/tacacs_v1" {
		t.Errorf("keys.k: %+v", doc.Keys)
	}
}

func TestNoKeysDropsTheKeysBlockOnly(t *testing.T) {
	p, _ := Policy(shipped(t, "config", "policy.yaml"), "172.31.49.0/24")
	out, err := NoKeys(p)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	if _, ok := doc["keys"]; ok {
		t.Error("keys: is still there")
	}
	if _, ok := doc["key_groups"]; !ok {
		t.Error("key_groups was dropped with it: the refusal would be a different one")
	}
	if _, err := NoKeys("scopes: []\n"); err == nil {
		t.Error("a policy with no keys: was accepted")
	}
}

func TestBrokerForATrialAndMetricsOnTheBridge(t *testing.T) {
	b, err := Broker(shipped(t, "config", "port49-broker.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b, "certificate_status: {disabled: true}") || !strings.Contains(b, `metrics_listen: ":9050"`) || strings.Contains(b, "use_aia") {
		t.Errorf("broker config:\n%s", b)
	}
	d, err := Daemon(shipped(t, "config", "port49d.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(d, `metrics_listen: ":9049"`) {
		t.Errorf("port49d config:\n%s", d)
	}
	if _, err := Daemon("listen: \":49\"\n"); err == nil {
		t.Error("a daemon config with no metrics_listen was accepted")
	}
}

func TestParseShow(t *testing.T) {
	m := ParseShow("NRestarts=3\nActiveState=activating\nExecMainStartTimestamp=Wed 2026-10-28 10:00:00 UTC\nEmpty=\n")
	if m["NRestarts"] != "3" || m["ActiveState"] != "activating" || m["ExecMainStartTimestamp"] != "Wed 2026-10-28 10:00:00 UTC" {
		t.Errorf("%v", m)
	}
	if v, ok := m["Empty"]; !ok || v != "" {
		t.Errorf("an empty value: %q %v", v, ok)
	}
}

func TestRefusalNamesTheDirectory(t *testing.T) {
	line := "port49d: config: /etc is mode drwxrwxr-x, writable by others than its owner; whoever can write it decides who gets access - chmod go-w it"
	if !Refusal(line, "/etc") {
		t.Error("the fence's line is not recognised")
	}
	if Refusal(line, "/var/spool") || Refusal("port49d: /etc is mode drwxr-xr-x; fine", "/etc") {
		t.Error("a line about another directory, or one that is not a refusal, was recognised")
	}
}
