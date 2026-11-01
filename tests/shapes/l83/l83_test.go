package l83

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/blanketfish/port49/tests/shapes/l82"
)

// sts is the chart's port49d StatefulSet as `kubectl get sts -o json` prints it, cut to what the
// variants touch.
const sts = `{"apiVersion":"apps/v1","kind":"StatefulSet","metadata":{"name":"t-port49d","resourceVersion":"42"},
"spec":{"replicas":2,"template":{"metadata":{"labels":{"app.kubernetes.io/component":"port49d"},
"annotations":{"checksum/config":"abc"}},
"spec":{"serviceAccountName":"t-port49d","automountServiceAccountToken":false,
"securityContext":{"runAsUser":65532,"runAsGroup":65532,"fsGroup":65532,"fsGroupChangePolicy":"OnRootMismatch"},
"initContainers":[{"name":"data-init","image":"port49-setup:dev"}],
"containers":[{"name":"port49d","image":"port49:dev","args":["--config","/etc/port49/config/port49d.yaml"],
"securityContext":{"allowPrivilegeEscalation":false,"readOnlyRootFilesystem":true},
"volumeMounts":[{"name":"config","mountPath":"/etc/port49/config","readOnly":true},
{"name":"keys","mountPath":"/run/port49/keys","readOnly":true},
{"name":"encryption","mountPath":"/etc/port49/secrets","readOnly":true}]}],
"volumes":[{"name":"config","configMap":{"name":"t-port49d"}},
{"name":"keys","secret":{"secretName":"port49-device-keys","defaultMode":288}},
{"name":"encryption","secret":{"secretName":"port49-encryption","defaultMode":288}}]}}}}`

func tmpl(t *testing.T, c Config, v2 bool) obj {
	t.Helper()
	b, err := Template([]byte(sts), c, v2)
	if err != nil {
		t.Fatal(err)
	}
	var ops []struct {
		Op, Path string
		Value    obj
	}
	if err := json.Unmarshal(b, &ops); err != nil {
		t.Fatal(err)
	}
	if len(ops) != 1 || ops[0].Op != "replace" || ops[0].Path != "/spec/template" {
		t.Fatalf("the patch is %s, want one replace of /spec/template", b)
	}
	return ops[0].Value
}

func annotations(tp obj) obj {
	a, _ := tp["metadata"].(obj)["annotations"].(obj)
	return a
}

func volumes(tp obj) []obj { return list(tp["spec"].(obj)["volumes"]) }

func list(v any) []obj {
	var out []obj
	for _, x := range v.([]any) {
		out = append(out, x.(obj))
	}
	return out
}

func named(l []obj, name string) obj {
	for _, o := range l {
		if o["name"] == name {
			return o
		}
	}
	return nil
}

func port49d(tp obj) obj {
	return named(list(tp["spec"].(obj)["containers"]), "port49d")
}

func TestTheInjectorTemplate(t *testing.T) {
	tp := tmpl(t, Configs[0], false)
	a := annotations(tp)
	want := map[string]string{
		"vault.hashicorp.com/agent-inject":                  "true",
		"vault.hashicorp.com/role":                          "port49d",
		"vault.hashicorp.com/agent-inject-secret-core_v1":   "secret/data/port49/devices/core-v1",
		"vault.hashicorp.com/agent-inject-perms-core_v1":    "0440",
		"vault.hashicorp.com/secret-volume-path-core_v1":    "/run/port49/keys",
		"checksum/config":                                   "abc",
		"vault.hashicorp.com/agent-inject-template-core_v1": `{{- with secret "secret/data/port49/devices/core-v1" -}}{{- .Data.data.value -}}{{- end -}}`,
	}
	for k, v := range want {
		if a[k] != v {
			t.Errorf("annotation %s = %v, want %q", k, a[k], v)
		}
	}
	if _, ok := a["vault.hashicorp.com/agent-run-as-same-user"]; ok {
		t.Error("the default variant sets agent-run-as-same-user")
	}
	for k := range a {
		if strings.Contains(k, "core_v2") {
			t.Errorf("a variant without version 2 has %s", k)
		}
	}
	if named(volumes(tp), "keys") != nil {
		t.Error("the keys Secret volume is still there: the injector mounts the key directory")
	}
	for _, m := range list(port49d(tp)["volumeMounts"]) {
		if m["name"] == "keys" {
			t.Error("port49d still mounts the keys Secret volume")
		}
	}
	if len(volumes(tp)) != 2 || len(list(port49d(tp)["volumeMounts"])) != 2 {
		t.Error("the variant changed volumes other than keys")
	}
	if tp["spec"].(obj)["automountServiceAccountToken"] != true {
		t.Error("the agent authenticates with the pod's service account: it must be mounted")
	}
}

func TestTheSameUserVariantAndVersion2(t *testing.T) {
	a := annotations(tmpl(t, Configs[1], true))
	if a["vault.hashicorp.com/agent-run-as-same-user"] != "true" {
		t.Error("agent-run-as-same-user is not true")
	}
	if a["vault.hashicorp.com/agent-inject-secret-core_v2"] != "secret/data/port49/devices/core-v2" ||
		a["vault.hashicorp.com/agent-inject-perms-core_v2"] != "0440" ||
		a["vault.hashicorp.com/secret-volume-path-core_v2"] != "/run/port49/keys" {
		t.Errorf("version 2 is not rendered like version 1: %v", a)
	}
}

func TestTheCSITemplate(t *testing.T) {
	tp := tmpl(t, Configs[2], true)
	k := named(volumes(tp), "keys")
	csi, _ := k["csi"].(obj)
	if csi["driver"] != "secrets-store.csi.k8s.io" || csi["readOnly"] != true ||
		csi["volumeAttributes"].(obj)["secretProviderClass"] != "port49-keys" {
		t.Errorf("the keys volume is %v", k)
	}
	if _, ok := k["secret"]; ok {
		t.Error("the keys volume is still a Secret")
	}
	var mount obj
	for _, m := range list(port49d(tp)["volumeMounts"]) {
		if m["name"] == "keys" {
			mount = m
		}
	}
	if mount == nil || mount["mountPath"] != "/run/port49/keys" || mount["readOnly"] != true {
		t.Errorf("port49d's keys mount is %v", mount)
	}
	if _, ok := mount["subPath"]; ok {
		t.Error("a subPath mount")
	}
	for k := range annotations(tp) {
		if strings.HasPrefix(k, "vault.hashicorp.com/") {
			t.Errorf("a CSI variant carries %s", k)
		}
	}
	if tp["spec"].(obj)["automountServiceAccountToken"] != false {
		t.Error("the CSI variant changed the service account mount")
	}
}

func TestTemplateRefusesAChartItDoesNotKnow(t *testing.T) {
	for name, doc := range map[string]string{
		"no keys volume": strings.Replace(sts, `{"name":"keys","secret":{"secretName":"port49-device-keys","defaultMode":288}},`, "", 1),
		"no keys mount":  strings.Replace(sts, `{"name":"keys","mountPath":"/run/port49/keys","readOnly":true},`, "", 1),
		"no port49d":     strings.Replace(sts, `"name":"port49d"`, `"name":"other"`, 1),
		"not json":       "not json",
	} {
		if doc == sts {
			t.Fatalf("%s: the fixture was not changed", name)
		}
		for _, c := range Configs {
			if _, err := Template([]byte(doc), c, false); err == nil {
				t.Errorf("%s, %s: no error", name, c.ID)
			}
		}
	}
}

func TestTheProbeSharesTheTemplate(t *testing.T) {
	for _, c := range Configs {
		b, err := Probe([]byte(sts), c, "l83-probe", "alpine:test", true)
		if err != nil {
			t.Fatal(err)
		}
		var p obj
		if err := json.Unmarshal(b, &p); err != nil {
			t.Fatal(err)
		}
		spec := p["spec"].(obj)
		ctr := list(spec["containers"])
		if len(ctr) != 1 || ctr[0]["image"] != "alpine:test" || ctr[0]["name"] != "probe" {
			t.Errorf("%s: containers %v", c.ID, ctr)
		}
		if _, ok := ctr[0]["args"]; ok {
			t.Errorf("%s: the probe runs port49d's args", c.ID)
		}
		if ctr[0]["securityContext"].(obj)["readOnlyRootFilesystem"] != true {
			t.Errorf("%s: not port49d's container securityContext", c.ID)
		}
		if spec["securityContext"].(obj)["fsGroup"] != float64(65532) || spec["serviceAccountName"] != "t-port49d" {
			t.Errorf("%s: not port49d's pod securityContext and service account", c.ID)
		}
		if _, ok := spec["initContainers"]; ok {
			t.Errorf("%s: the probe has port49d's init containers", c.ID)
		}
		if p["metadata"].(obj)["name"] != "l83-probe" {
			t.Errorf("%s: name", c.ID)
		}
		if p["metadata"].(obj)["labels"].(obj)[ConfigLabel] != c.ID {
			t.Errorf("%s: the probe does not carry its configuration's label", c.ID)
		}
		if spec["terminationGracePeriodSeconds"] != float64(0) {
			t.Errorf("%s: a deleted probe would sit Terminating for the default grace period", c.ID)
		}
		a, _ := p["metadata"].(obj)["annotations"].(obj)
		if _, ok := a["checksum/config"]; ok {
			t.Errorf("%s: the probe carries the config checksum", c.ID)
		}
		if c.Mechanism == Injector {
			if a["vault.hashicorp.com/agent-inject-perms-core_v2"] != "0440" || spec["automountServiceAccountToken"] != true {
				t.Errorf("%s: the injector's annotations are not the template's", c.ID)
			}
			if _, ok := spec["volumes"]; ok {
				t.Errorf("%s: volumes %v", c.ID, spec["volumes"])
			}
		} else {
			vs := list(spec["volumes"])
			if len(vs) != 1 || vs[0]["name"] != "keys" || vs[0]["csi"] == nil {
				t.Errorf("%s: volumes %v", c.ID, vs)
			}
			if m := list(ctr[0]["volumeMounts"]); len(m) != 1 || m[0]["mountPath"] != "/run/port49/keys" {
				t.Errorf("%s: mounts %v", c.ID, m)
			}
		}
		for k, v := range p["metadata"].(obj)["labels"].(obj) {
			if k == "app.kubernetes.io/component" {
				t.Errorf("%s: the probe carries the label %s=%v that port49d's Service selects", c.ID, k, v)
			}
		}
	}
}

func TestTheSecretProviderClass(t *testing.T) {
	b, err := SecretProviderClass("port49", Configs[2], false)
	if err != nil {
		t.Fatal(err)
	}
	var d obj
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatal(err)
	}
	if d["kind"] != "SecretProviderClass" || d["metadata"].(obj)["name"] != "port49-keys" || d["metadata"].(obj)["namespace"] != "port49" {
		t.Errorf("metadata %v", d["metadata"])
	}
	spec := d["spec"].(obj)
	par := spec["parameters"].(obj)
	if spec["provider"] != "vault" || par["roleName"] != "port49d" || par["vaultAddress"] != "http://vault.vault:8200" {
		t.Errorf("spec %v", spec)
	}
	objs := par["objects"].(string)
	if !strings.Contains(objs, `objectName: "core_v1"`) || !strings.Contains(objs, `secretPath: "secret/data/port49/devices/core-v1"`) ||
		!strings.Contains(objs, `secretKey: "value"`) {
		t.Errorf("objects:\n%s", objs)
	}
	if strings.Contains(objs, "core_v2") || strings.Contains(objs, "filePermission") {
		t.Errorf("the default variant's objects:\n%s", objs)
	}
	b, _ = SecretProviderClass("port49", Configs[3], true)
	json.Unmarshal(b, &d)
	objs = d["spec"].(obj)["parameters"].(obj)["objects"].(string)
	if strings.Count(objs, "filePermission: 0440") != 2 || !strings.Contains(objs, `objectName: "core_v2"`) {
		t.Errorf("the 0440 variant with version 2:\n%s", objs)
	}
	if _, err := SecretProviderClass("port49", Configs[0], false); err == nil {
		t.Error("a SecretProviderClass for an injector variant")
	}
}

func TestTheVerdicts(t *testing.T) {
	if JudgeStart(true, 0) != l82.Pass || JudgeStart(true, 1) != l82.Fail || JudgeStart(false, 0) != l82.Fail {
		t.Error("JudgeStart")
	}
	ok := Rotation{InForce: true, Delay: 299 * time.Second}
	if JudgeRotation(ok) != l82.Pass {
		t.Error("in force in 299 s with no restart is not a PASS")
	}
	for name, r := range map[string]Rotation{
		"late":      {InForce: true, Delay: 301 * time.Second},
		"never":     {Delay: 10 * time.Second},
		"restarted": {InForce: true, Delay: time.Second, Restarted: true},
	} {
		if JudgeRotation(r) != l82.Fail {
			t.Errorf("%s is not a FAIL", name)
		}
	}
	if JudgeRotation(Rotation{InForce: true, Delay: 300 * time.Second}) != l82.Pass {
		t.Error("the bound is inclusive")
	}
}

func TestTheOrderPairsEachConfigWithItsRotationCell(t *testing.T) {
	var want []string
	for _, c := range Configs {
		want = append(want, c.ID)
	}
	for _, c := range Configs {
		want = append(want, "c-"+c.ID)
	}
	if strings.Join(Order, " ") != strings.Join(want, " ") {
		t.Errorf("Order = %v, want %v", Order, want)
	}
	for _, id := range Order {
		if title(id) == "" {
			t.Errorf("no title for %s", id)
		}
	}
}

func env() Env {
	return Env{Date: "2026-10-30", Runner: "ubuntu24 20261020.1", Run: "run 1", Docker: "28.0", Kernel: "6.8",
		Kind: "kind v0.29.0", NodeImage: "kindest/node:v1.33.1", Kubectl: "v1.33.1", Helm: "v3.22.0",
		VaultChart: "0.34.1", VaultApp: "2.0.4", Injector: "1.7.6", Provider: "1.7.4", CSIChart: "1.6.1", CSIApp: "1.6.1",
		Rotation: "enabled, poll 15s"}
}

func TestResultsRecordTheVersionsAndEveryCell(t *testing.T) {
	cells := []l82.Cell{{ID: "a1", Verdict: l82.Pass, Rows: []l82.Row{{Case: "the directory", Observation: "100:65532 2750 directory ."}}}}
	out, err := Results(env(), cells)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Vault: chart 0.34.1, app 2.0.4", "injector 1.7.6", "CSI provider 1.7.4",
		"Secrets Store CSI driver: chart 1.6.1, app 1.6.1", "rotation: enabled, poll 15s", "GitHub-hosted runner", "100:65532 2750"} {
		if !strings.Contains(out, want) {
			t.Errorf("the results lack %q", want)
		}
	}
	if strings.Count(out, "NOT RUN") < 7 {
		t.Errorf("the seven cells never run are not NOT RUN:\n%s", out)
	}
	for _, id := range Order {
		if !strings.Contains(out, title(id)) {
			t.Errorf("no section for %s", id)
		}
	}
}

func TestResultsRefuseAnythingThatLooksLikeASecret(t *testing.T) {
	for name, obs := range map[string]string{
		"a long run":  strings.Repeat("A", 24),
		"the word":    "the root token is x",
		"a jwt":       "eyJhbGciOi",
		"a password":  "password",
		"the service": "automountServiceAccountToken",
	} {
		cells := []l82.Cell{{ID: "a1", Verdict: l82.Pass, Rows: []l82.Row{{Case: "x", Observation: obs}}}}
		if out, err := Results(env(), cells); err == nil || out != "" {
			t.Errorf("%s: written", name)
		}
	}
	for _, c := range Configs {
		for _, s := range []string{c.Describe(), title("a1"), title("c-b2")} {
			if why := l82.Leak(s); why != "" {
				t.Errorf("%q holds %s", s, why)
			}
		}
	}
}

func TestVaultSetupNeverNamesTheRootToken(t *testing.T) {
	s := VaultSetup()
	for _, want := range []string{"vault auth enable kubernetes", "auth/kubernetes/role/port49d", "bound_service_account_names=t-port49d",
		"bound_service_account_namespaces=port49", `secret/data/port49/devices/*`} {
		if !strings.Contains(s, want) {
			t.Errorf("the setup lacks %q", want)
		}
	}
	// the root token reaches the commands only as the vault pod's own variable
	if !strings.Contains(s, `VAULT_TOKEN="$L83_ROOT"`) || strings.Contains(strings.ToLower(strings.ReplaceAll(s, `VAULT_TOKEN="$L83_ROOT"`, "")), "token") {
		t.Error("the setup does not take the root token from the pod's own variable, or names one otherwise")
	}
}

func TestPutCommandReadsTheValueFromStdin(t *testing.T) {
	c := PutCommand(2)
	for _, want := range []string{`VAULT_TOKEN="$L83_ROOT"`, "vault kv put -mount=secret port49/devices/core-v2 value=-"} {
		if !strings.Contains(c, want) {
			t.Errorf("%q lacks %q", c, want)
		}
	}
	if strings.Contains(c, "core-v1") || strings.Contains(c, "value=") && !strings.HasSuffix(c, "value=-") {
		t.Errorf("the command carries a value on its command line: %q", c)
	}
}

func TestAPodReplacedIsNotAContainerRestartAndFailsRotation(t *testing.T) {
	a := PodIdent{UID: "u1", Restarts: 0, StartedAt: "t1"}
	if r, c := Change(a, PodIdent{UID: "u2", StartedAt: "t2"}); !r || c {
		t.Errorf("a new uid: replaced %v restarted %v, want true false", r, c)
	}
	if r, c := Change(a, PodIdent{UID: "u1", Restarts: 1, StartedAt: "t1"}); r || !c {
		t.Errorf("a restart count: replaced %v restarted %v, want false true", r, c)
	}
	if r, c := Change(a, a); r || c {
		t.Errorf("no change read as replaced %v restarted %v", r, c)
	}
	if got := JudgeRotation(Rotation{InForce: true, Delay: time.Second, Replaced: true}); got != l82.Fail {
		t.Errorf("a replaced pod judged %q, want FAIL", got)
	}
}

func TestEachConfigurationHasItsOwnProbeAndItIsCheckedBeforeItsRowsAreRead(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range Configs {
		n := ProbeName(c)
		if seen[n] {
			t.Errorf("configuration %s shares probe name %s", c.ID, n)
		}
		seen[n] = true
	}
	a1, a2 := Configs[0], Configs[1]
	if err := ProbeCurrent("uid-1||"+a2.ID, a2); err != nil {
		t.Errorf("a live probe of its own configuration: %v", err)
	}
	if err := ProbeCurrent("uid-1|2026-10-30T23:00:00Z|"+a1.ID, a1); err == nil {
		t.Error("a terminating probe was accepted")
	}
	if err := ProbeCurrent("uid-1||"+a1.ID, a2); err == nil {
		t.Error("another configuration's probe was accepted")
	}
	if err := ProbeCurrent("", a1); err == nil {
		t.Error("an unreadable probe was accepted")
	}
}
