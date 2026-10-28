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
	"github.com/rhwendt/port49/tests/kind/kindtest"
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

// A ClusterSecretStore with no conditions lets an ExternalSecret in any namespace read the device
// keys through the store's Vault role (Task 10 review I-2). The default example is a namespaced
// SecretStore, and the cluster-wide one names the release's namespace.
func TestNoExampleStoreIsOpenToEveryNamespace(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join(chartDir, "examples", "external-secret*.yaml"))
	if len(files) < 2 {
		t.Fatalf("found %d external-secret examples, want the namespaced default and the cluster-wide option", len(files))
	}
	kinds := map[string]bool{}
	for _, f := range files {
		dec := yaml.NewDecoder(strings.NewReader(read(t, "deploy/helm/port49/examples/"+filepath.Base(f))))
		for {
			var d doc
			if err := dec.Decode(&d); err != nil {
				break
			}
			switch kindOf(d) {
			case "ClusterSecretStore":
				c := list(at(d, "spec", "conditions"))
				if len(c) == 0 {
					t.Errorf("%s: a ClusterSecretStore with no spec.conditions is open to every namespace", filepath.Base(f))
				}
				for _, cond := range c {
					if ns := list(at(cond, "namespaces")); len(ns) != 1 || str(ns[0]) != "port49" {
						t.Errorf("%s: a condition's namespaces are %v, want exactly the release namespace port49", filepath.Base(f), ns)
					}
				}
			case "SecretStore":
				if at(d, "metadata", "namespace") == nil {
					continue // applied into the release namespace by `kubectl -n`
				}
			case "ExternalSecret":
				kinds[str(at(d, "spec", "secretStoreRef", "kind"))+":"+filepath.Base(f)] = true
			}
		}
	}
	if !kinds["SecretStore:external-secret.yaml"] {
		t.Errorf("the default example's ExternalSecret does not use a namespaced SecretStore: %v", kinds)
	}
}

// No pod an example makes calls the Kubernetes API except the workload CronJob, whose token is projected
// for another audience: every other one drops the default token (review m-6).
func TestExamplePodsDropTheServiceAccountToken(t *testing.T) {
	for _, f := range []string{"backup-cronjob.yaml", "etcd/statefulset.yaml", "etcd/etcd-init-job.yaml"} {
		var d doc
		if err := yaml.Unmarshal([]byte(read(t, "deploy/helm/port49/examples/"+f)), &d); err != nil {
			t.Fatal(err)
		}
		spec := at(d, "spec", "template", "spec")
		if kindOf(d) == "CronJob" {
			spec = at(d, "spec", "jobTemplate", "spec", "template", "spec")
		}
		if at(spec, "automountServiceAccountToken") != false {
			t.Errorf("%s: automountServiceAccountToken is %v, want false", f, at(spec, "automountServiceAccountToken"))
		}
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

// Both backups follow one pattern (plan 12b, Task 10 ruling): a stale-check that fails loudly, a
// writer that makes `<name>.new` 0600 (the port49 image with --out, the etcd image with etcdctl
// snapshot save), and an alpine finish step that does umask 077, renames to a dated name and prunes
// after 14 days. Neither image has a shell, and nothing sealed goes to a log.
func TestTheBackupCronJobsFollowOnePattern(t *testing.T) {
	const alpine = "alpine:3.22@sha256:"
	// The snapshot is an example; the enrollments CronJob is the chart's own (backup.enrollments).
	var rendered doc
	for _, d := range render(t, goRender, "backup: {enrollments: {enabled: true, claimName: port49-backups}}\n") {
		if kindOf(d) == "CronJob" {
			rendered = d
		}
	}
	for file, w := range map[string]struct{ image, name string }{
		"backup-cronjob.yaml":     {"gcr.io/etcd-development/etcd:v3.6.15@sha256:", "etcd-snapshot"},
		"enrollments (the chart)": {"ghcr.io/rhwendt/port49:", "enrollments"},
	} {
		var cj doc
		if file == "backup-cronjob.yaml" {
			if err := yaml.Unmarshal([]byte(read(t, "deploy/helm/port49/examples/"+file)), &cj); err != nil {
				t.Fatalf("%s: %v", file, err)
			}
		} else {
			cj = rendered
		}
		job := at(cj, "spec", "jobTemplate", "spec")
		p := at(job, "template", "spec")
		if kindOf(cj) != "CronJob" || str(at(cj, "spec", "concurrencyPolicy")) != "Forbid" {
			t.Errorf("%s: not a CronJob with concurrencyPolicy Forbid", file)
		}
		if str(at(job, "backoffLimit")) != "0" || str(at(p, "restartPolicy")) != "Never" {
			t.Errorf("%s: a failed run must stay failed (backoffLimit 0, restartPolicy Never)", file)
		}
		// Secret files are root-owned 0440: only fsGroup lets uid 65532 read them.
		if str(at(p, "securityContext", "fsGroup")) != "65532" || str(at(p, "securityContext", "runAsUser")) != "65532" {
			t.Errorf("%s: the pod's securityContext %v, want runAsUser and fsGroup 65532 so the Secret mounts are readable", file, at(p, "securityContext"))
		}
		inits := list(at(p, "initContainers"))
		var stale, writer = -1, -1
		for i, c := range inits {
			switch str(at(c, "name")) {
			case "stale-check":
				stale = i
				if !strings.HasPrefix(str(at(c, "image")), alpine) {
					t.Errorf("%s: stale-check is %s, want the pinned alpine", file, str(at(c, "image")))
				}
				script := str(at(c, "command", 2))
				if !strings.Contains(script, "/backup/"+w.name+".new") || !strings.Contains(script, "exit 1") {
					t.Errorf("%s: stale-check does not refuse /backup/%s.new: %q", file, w.name, script)
				}
			case "snapshot", "export":
				writer = i
				if !strings.HasPrefix(str(at(c, "image")), w.image) {
					t.Errorf("%s: the writer is %s, want %s...", file, str(at(c, "image")), w.image)
				}
				var parts []string
				for _, a := range append(list(at(c, "command")), list(at(c, "args"))...) {
					parts = append(parts, str(a))
				}
				joined := strings.Join(parts, " ")
				if strings.Contains(joined, "sh -c") || strings.Contains(joined, ">") {
					t.Errorf("%s: the writer uses a shell or a redirect: %s", file, joined)
				}
				if !strings.Contains(joined, "/backup/"+w.name+".new") {
					t.Errorf("%s: the writer does not write /backup/%s.new: %s", file, w.name, joined)
				}
				if w.name == "enrollments" && !strings.Contains(joined, "--out /backup/enrollments.new") {
					t.Errorf("%s: the export does not use --out: %s", file, joined)
				}
			}
		}
		if stale < 0 || writer < 0 || stale > writer {
			t.Errorf("%s: the stale-check must exist and run before the writer (stale %d, writer %d)", file, stale, writer)
		}
		fin := at(p, "containers", 0)
		script := str(at(fin, "command", 2))
		for _, want := range []string{"umask 077", "mv \"$new\" \"$dated\"", "-mtime +14 -delete", "/backup/" + w.name + ".new", "chmod 0600"} {
			if !strings.Contains(script, want) {
				t.Errorf("%s: the finish step lacks %q:\n%s", file, want, script)
			}
		}
		if !strings.HasPrefix(str(at(fin, "image")), alpine) || len(list(at(p, "containers"))) != 1 {
			t.Errorf("%s: the one main container is %s, want the pinned alpine", file, str(at(fin, "image")))
		}
		// Neither pod calls the API; the snapshot pod holds etcd's root key (review m-6).
		if at(p, "automountServiceAccountToken") != false {
			t.Errorf("%s: automountServiceAccountToken is %v, want false", file, at(p, "automountServiceAccountToken"))
		}
		for _, c := range append(inits, list(at(p, "containers"))...) {
			if at(c, "env") != nil {
				t.Errorf("%s: container %s sets env: secrets are files", file, str(at(c, "name")))
			}
			if at(c, "securityContext", "readOnlyRootFilesystem") != true {
				t.Errorf("%s: container %s has no readOnlyRootFilesystem: true (the backup steps write only to their volumes)", file, str(at(c, "name")))
			}
		}
	}
}

// The kind smoke's post-renderer (tests/kind/kindtest.OldRoot) rewrites the chart's own rendered
// init command. If the chart's text drifts from the pattern, the RED run of the fsGroup cell would
// stop meaning anything: this fails first.
func TestTheKindPostRendererMatchesTheChartsInitCommands(t *testing.T) {
	var all strings.Builder
	for _, d := range render(t, goRender, "") {
		if kindOf(d) == "StatefulSet" {
			b, err := yaml.Marshal(d)
			if err != nil {
				t.Fatal(err)
			}
			all.Write(b)
		}
	}
	out, err := kindtest.OldRoot([]byte(all.String()))
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(out), "&& chmod g-w "); n != 2 {
		t.Errorf("the post-renderer rewrote %d init commands, want both pods'", n)
	}
	if strings.Contains(string(out), "chmod 3770") {
		t.Error("a 3770 root survived the post-renderer")
	}
}
