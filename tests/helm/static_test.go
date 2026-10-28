package helm

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/rhwendt/port49/tests/ci/versions"
)

func TestTheChartVersionsAgreeWithTheReleaseArtifacts(t *testing.T) {
	v, err := versions.Read(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if v.Chart == "" || v.ChartApp == "" {
		t.Fatalf("Chart.yaml has version %q appVersion %q", v.Chart, v.ChartApp)
	}
	if got := versions.Check(v, ""); len(got) != 0 {
		t.Errorf("versions disagree: %v", got)
	}
}

// helm enforces the schema; where helm is not installed these pin the parts the plan names.
func TestTheSchemaRequiresEveryMemberAndTheSecrets(t *testing.T) {
	var s map[string]any
	if err := json.Unmarshal([]byte(read(t, "deploy/helm/port49/values.schema.json")), &s); err != nil {
		t.Fatal(err)
	}
	ep := at(s, "properties", "etcd", "properties", "endpoints")
	if str(at(ep, "minItems")) != "3" || at(ep, "uniqueItems") != true {
		t.Errorf("etcd.endpoints schema is %v, want minItems 3 and uniqueItems", ep)
	}
	for path, want := range map[string][]string{
		"":     {"keys", "encryption", "etcd", "broker"},
		"etcd": {"endpoints", "caSecret", "port49d", "broker"},
	} {
		node := any(s)
		if path != "" {
			node = at(s, "properties", path)
		}
		have := map[string]bool{}
		for _, r := range list(at(node, "required")) {
			have[str(r)] = true
		}
		for _, w := range want {
			if !have[w] {
				t.Errorf("the schema does not require %s.%s", path, w)
			}
		}
	}
	for _, p := range [][]string{{"keys"}, {"encryption"}, {"etcd", "port49d"}, {"etcd", "broker"}} {
		node := any(s)
		for _, k := range p {
			node = at(node, "properties", k)
		}
		if str(at(node, "properties", "existingSecret", "minLength")) != "1" {
			t.Errorf("%v.existingSecret may be empty in the schema", p)
		}
	}
}

func TestTheDefaultsAreTheDocumentedOnes(t *testing.T) {
	v := parseValuesFile(t, filepath.Join(chartDir, "values.yaml"))
	for path, want := range map[string]string{
		"port49d.replicas": "2", "broker.replicas": "2", "issuerDiscovery.enabled": "false",
		"autoscaling.enabled": "false", "tlsListener.enabled": "false", "service.externalTrafficPolicy": "Local",
		"encryption.id": "c1",
	} {
		var n any = v
		for _, k := range strings.Split(path, ".") {
			n = at(n, k)
		}
		if str(n) != want {
			t.Errorf("values.yaml %s is %v, want %s", path, n, want)
		}
	}
	for _, p := range []string{"keys.existingSecret", "encryption.existingSecret", "etcd.caSecret"} {
		var n any = v
		for _, k := range strings.Split(p, ".") {
			n = at(n, k)
		}
		if n != "" {
			t.Errorf("values.yaml %s defaults to %v: a Secret name is required, never defaulted", p, n)
		}
	}
	if n := list(at(v, "etcd", "endpoints")); len(n) != 0 {
		t.Errorf("values.yaml defaults etcd.endpoints to %v", n)
	}
}

// Secrets are files: no container of either pod has a secret in its environment, and nothing is
// mounted by subPath (the kubelet updates a whole mount in place; a subPath mount never sees it).
func checkNoEnvSecretNoSubPath(t *testing.T, r renderer) {
	docs := render(t, r, "broker: {site: hq}\n")
	for _, name := range []string{"t-port49d", "t-broker"} {
		for _, c := range containers(pod(one(t, docs, "StatefulSet", name))) {
			for _, e := range list(at(c, "env")) {
				if str(at(e, "name")) != "PORT49_SITE" || at(e, "valueFrom") != nil {
					t.Errorf("%s container %s has environment entry %v: a secret is a file", name, str(at(c, "name")), at(e, "name"))
				}
			}
			for _, m := range list(at(c, "volumeMounts")) {
				if at(m, "subPath") != nil || at(m, "subPathExpr") != nil {
					t.Errorf("%s container %s mounts %v by subPath", name, str(at(c, "name")), at(m, "name"))
				}
			}
		}
	}
}

func TestNoSecretInAnEnvironmentAndNoSubPath(t *testing.T) { checkNoEnvSecretNoSubPath(t, goRender) }

var versionedKey = regexp.MustCompile(`^[a-z0-9_]+_v[0-9]+$`)

func TestTheExternalSecretOneKeyPerVersion(t *testing.T) {
	var es doc
	found := false
	dec := yaml.NewDecoder(strings.NewReader(read(t, "deploy/helm/port49/examples/external-secret.yaml")))
	for {
		var d doc
		if err := dec.Decode(&d); err != nil {
			break
		}
		if kindOf(d) == "ExternalSecret" {
			es, found = d, true
		}
	}
	if !found || str(es["apiVersion"]) != "external-secrets.io/v1" {
		t.Fatalf("no external-secrets.io/v1 ExternalSecret in the example: %v", es["apiVersion"])
	}
	keys, remotes := map[string]bool{}, map[string]bool{}
	for _, d := range list(at(es, "spec", "data")) {
		k, r := str(at(d, "secretKey")), str(at(d, "remoteRef", "key"))
		if !versionedKey.MatchString(k) {
			t.Errorf("secretKey %q is not <ref>_v<N>", k)
		}
		if keys[k] || remotes[r] || r == "" {
			t.Errorf("secretKey %q or remote key %q repeats: one key per version", k, r)
		}
		keys[k], remotes[r] = true, true
	}
	if len(keys) < 2 {
		t.Errorf("the example has %d versions, want at least two to show a rotation", len(keys))
	}
	if str(at(es, "spec", "target", "deletionPolicy")) != "Retain" || str(at(es, "spec", "refreshInterval")) != "1h" {
		t.Errorf("target %v, refreshInterval %v", at(es, "spec", "target"), at(es, "spec", "refreshInterval"))
	}
	m := regexp.MustCompile(`--set keys\.existingSecret=(\S+)`).FindStringSubmatch(read(t, "deploy/helm/port49/README.md"))
	if m == nil || m[1] != str(at(es, "spec", "target", "name")) {
		t.Errorf("the README's keys.existingSecret example is %v, want the ExternalSecret's target %q", m, str(at(es, "spec", "target", "name")))
	}
}

// Every example decodes, and none sets a secret in an environment.
func TestTheExamplesDecode(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join(chartDir, "examples", "*.yaml"))
	more, _ := filepath.Glob(filepath.Join(chartDir, "examples", "etcd", "*.yaml"))
	files = append(files, more...)
	if len(files) < 6 {
		t.Fatalf("found %d example files", len(files))
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		dec := yaml.NewDecoder(strings.NewReader(string(b)))
		n := 0
		for {
			var d map[string]any
			if err := dec.Decode(&d); err != nil {
				if err.Error() != "EOF" {
					t.Errorf("%s: %v", f, err)
				}
				break
			}
			n++
		}
		if n == 0 {
			t.Errorf("%s holds no document", f)
		}
		if strings.Contains(string(b), "admin_socket") {
			t.Errorf("%s names admin_socket", f)
		}
	}
	for _, f := range more {
		if strings.Contains(f, "statefulset") {
			var d map[string]any
			b, _ := os.ReadFile(f)
			_ = yaml.Unmarshal(b, &d)
			for _, c := range list(at(d, "spec", "template", "spec", "containers")) {
				for _, e := range list(at(c, "env")) {
					if n := str(at(e, "name")); secretNameRE.MatchString(n) && !strings.HasSuffix(n, "_FILE") && n != "ETCD_INITIAL_CLUSTER_TOKEN" {
						t.Errorf("%s sets %s in a container's environment", f, str(at(e, "name")))
					}
				}
			}
		}
	}
}

// a name ending _FILE holds a path, and ETCD_INITIAL_CLUSTER_TOKEN a public cluster name
var secretNameRE = regexp.MustCompile(`(?i)(SECRET|PASSWORD|PASSWD|PASSPHRASE|TOKEN|CREDENTIAL|PRIVATE|KEY)`)

func TestTheScriptsAreSoundBash(t *testing.T) {
	for _, name := range []string{"lib.sh", "copy-issuer.sh", "revoke-offline.sh"} {
		p := filepath.Join(chartDir, "scripts", name)
		if out, err := exec.Command("bash", "-n", p).CombinedOutput(); err != nil {
			t.Errorf("bash -n %s: %v\n%s", name, err, out)
		}
		raw := read(t, "deploy/helm/port49/scripts/"+name)
		if regexp.MustCompile(`(?m)^\s*set\s+-[a-z]*x`).MatchString(raw) {
			t.Errorf("%s sets -x: a trace would print what it handles", name)
		}
		if name != "lib.sh" {
			if !strings.Contains(raw, "set -euo pipefail") {
				t.Errorf("%s does not set -euo pipefail", name)
			}
			if info, err := os.Stat(filepath.Join(chartDir, "scripts", name)); err != nil || info.Mode()&0o100 == 0 {
				t.Errorf("%s is not executable", name)
			}
		}
	}
}
