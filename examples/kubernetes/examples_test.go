// Package kubernetes_test checks the Kubernetes example's manifests agree with
// each other and load through port49's own loaders (plan 10, Task 9). The
// cluster side is lab L69's (tests/lab).
package kubernetes_test

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/policy"
)

// cronJob is the fields of backup-cronjob.yaml's CronJob the example's claims
// rest on.
type cronJob struct {
	Spec struct {
		JobTemplate struct {
			Spec struct {
				Template struct {
					Spec struct {
						AutomountServiceAccountToken *bool  `yaml:"automountServiceAccountToken"`
						ServiceAccountName           string `yaml:"serviceAccountName"`
						Containers                   []struct {
							Command      []string `yaml:"command"`
							VolumeMounts []struct {
								Name      string `yaml:"name"`
								MountPath string `yaml:"mountPath"`
							} `yaml:"volumeMounts"`
						} `yaml:"containers"`
						Volumes []struct {
							Name      string `yaml:"name"`
							Projected struct {
								Sources []struct {
									ServiceAccountToken struct {
										Audience          string `yaml:"audience"`
										ExpirationSeconds int    `yaml:"expirationSeconds"`
										Path              string `yaml:"path"`
									} `yaml:"serviceAccountToken"`
								} `yaml:"sources"`
							} `yaml:"projected"`
						} `yaml:"volumes"`
					} `yaml:"spec"`
				} `yaml:"template"`
			} `yaml:"spec"`
		} `yaml:"jobTemplate"`
	} `yaml:"spec"`
	Metadata struct {
		Namespace string `yaml:"namespace"`
	} `yaml:"metadata"`
}

type identitySnippet struct {
	Broker struct {
		Identity struct {
			Machines []struct {
				Type       string   `yaml:"type"`
				Cluster    string   `yaml:"cluster"`
				Audience   string   `yaml:"audience"`
				Namespaces []string `yaml:"namespaces"`
			} `yaml:"machines"`
		} `yaml:"identity"`
	} `yaml:"broker"`
}

// The CronJob's token volume asks for the audience the identity snippet names,
// a lifetime the broker keeps accepting through the kubelet's refresh (decision
// 49 ruling 6), and runs port49 workload with --token-file on that path.
func TestTheCronJobMatchesTheIdentitySnippet(t *testing.T) {
	var cj cronJob
	readSecond(t, "backup-cronjob.yaml", &cj)
	pod := cj.Spec.JobTemplate.Spec.Template.Spec
	if pod.AutomountServiceAccountToken == nil || *pod.AutomountServiceAccountToken {
		t.Fatal("the default API token is mounted: the example never mounts it (L69 (h))")
	}
	if len(pod.Volumes) == 0 || len(pod.Volumes[0].Projected.Sources) == 0 || len(pod.Containers) == 0 {
		t.Fatalf("the pod has no projected token volume or no container: %+v", pod)
	}
	sat := pod.Volumes[0].Projected.Sources[0].ServiceAccountToken
	if sat.Audience != "port49" || sat.ExpirationSeconds != 3600 || sat.Path != "token" {
		t.Fatalf("%+v", sat)
	}
	cmd := strings.Join(pod.Containers[0].Command, " ")
	if !strings.Contains(cmd, "workload token") || !strings.Contains(cmd, "--token-file /var/run/secrets/port49/token") {
		t.Fatalf("%s", cmd)
	}
	mounted := false
	for _, m := range pod.Containers[0].VolumeMounts {
		mounted = mounted || (m.Name == pod.Volumes[0].Name && m.MountPath == "/var/run/secrets/port49")
	}
	if !mounted {
		t.Fatal("the token volume is not mounted where --token-file reads it")
	}
	var id identitySnippet
	read(t, "port49d-identity.yaml", &id)
	ms := id.Broker.Identity.Machines
	if len(ms) < 2 {
		t.Fatalf("%d verifiers: the example shows two regions", len(ms))
	}
	// Every region's verifier names its cluster, asks the CronJob's audience
	// and lists netops: one manifest, every cluster (decision 49 ruling 4).
	for _, m := range ms {
		if m.Type != "k8s" || m.Cluster == "" || m.Audience != sat.Audience || !slices.Contains(m.Namespaces, "netops") {
			t.Fatalf("%+v", m)
		}
	}
}

// The snippet is a real broker config's identity: it loads through port49d's
// own loader, both verifiers resolve, and both vouch for the CronJob's
// namespace.
func TestTheIdentitySnippetLoads(t *testing.T) {
	dir := t.TempDir()
	raw, err := os.ReadFile("port49d-identity.yaml")
	if err != nil {
		t.Fatal(err)
	}
	// ca_file must be readable at load: point each at a file in dir.
	body := string(raw)
	for _, name := range []string{"us-east", "eu-west"} {
		ca := filepath.Join(dir, name+"-cluster-ca.pem")
		writeFile(t, ca, "x")
		body = strings.ReplaceAll(body, "/etc/port49/"+name+"-cluster-ca.pem", ca)
	}
	var doc map[string]map[string]any
	if err := yaml.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatal(err)
	}
	doc["broker"]["listen"] = "127.0.0.1:8449"
	doc["broker"]["tls_cert_file"] = "/etc/port49/broker.pem"
	doc["broker"]["tls_key_file"] = "/etc/port49/broker-key.pem"
	doc["broker"]["policy_file"] = "/etc/port49/policy.yaml"
	doc["broker"]["revocations_file"] = "/var/lib/port49/revocations.json"
	broker, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	inv := filepath.Join(dir, "inventory.yaml")
	writeFile(t, inv, "devices:\n  - {name: leaf-01, platform: arista_eos, addresses: [127.0.0.1]}\n"+
		"key_groups:\n  - {match: {cidr: 127.0.0.0/8}, key_ref: prod_key}\n")
	// Obviously fake secrets: nothing here opens a real record.
	t.Setenv("EXAMPLE_PROD_V1", "fake-shared-secret")
	t.Setenv("EXAMPLE_ENC_V1", "22222222222222222222222222222222")
	cfgPath := filepath.Join(dir, "port49d.yaml")
	writeFile(t, cfgPath, fmt.Sprintf("listen: \":4949\"\ninventory_file: %s\nkeys:\n  prod_key:\n"+
		"    current: {version: 1, secret_env: EXAMPLE_PROD_V1}\nencryption:\n  current: {id: v1, secret_env: EXAMPLE_ENC_V1}\n%s",
		inv, broker))
	c, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if c.Broker == nil || c.Broker.Identity == nil || len(c.Broker.Identity.K8s) != 2 {
		t.Fatalf("broker identity: %+v", c.Broker)
	}
	for _, v := range c.Broker.Identity.K8s {
		if v.Cluster == "" || !slices.Contains(v.Namespaces, "netops") {
			t.Fatalf("%+v", v)
		}
	}
}

// The policy loads through the policy loader and names the CronJob's service
// account, as its principal: system:serviceaccount:<namespace>:<name>.
func TestThePolicyNamesTheCronJobsServiceAccount(t *testing.T) {
	var cj cronJob
	readSecond(t, "backup-cronjob.yaml", &cj)
	want := "system:serviceaccount:" + cj.Metadata.Namespace + ":" + cj.Spec.JobTemplate.Spec.Template.Spec.ServiceAccountName
	var pol struct {
		Subjects []struct {
			Identity []string `yaml:"identity"`
			Username string   `yaml:"username"`
		} `yaml:"subjects"`
	}
	read(t, "policy.yaml", &pol)
	if len(pol.Subjects) != 1 || !slices.Equal(pol.Subjects[0].Identity, []string{want}) || pol.Subjects[0].Username == "" {
		t.Fatalf("want one subject for %s with a username: %+v", want, pol.Subjects)
	}
	if _, err := policy.Load("policy.yaml", policy.Env{}); err != nil {
		t.Fatal(err)
	}
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, file string, v any) {
	t.Helper()
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(b, v); err != nil {
		t.Fatal(err)
	}
}

// readSecond decodes the file's second YAML document into v.
func readSecond(t *testing.T, file string, v any) {
	t.Helper()
	f, err := os.Open(file)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	d := yaml.NewDecoder(f)
	var first map[string]any
	if err := d.Decode(&first); err != nil {
		t.Fatal(err)
	}
	if err := d.Decode(v); err != nil {
		t.Fatal(err)
	}
}
