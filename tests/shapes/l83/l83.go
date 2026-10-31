// Package l83 holds the pure parts of lab entry L83 (spec §15): Vault Agent's injector and the
// Secrets Store CSI driver with the Vault provider rendering port49d's keys, on kind. The four
// configurations, the pod templates and manifests they are made of, the verdicts and the results
// file. The harness (tests/lab/l83_test.go, tag lab) measures and records; this package decides and
// renders, so a results file is built from the cells and never typed by hand.
//
// The results file is an uploaded CI artifact and will be public: stat lines, delays, PASS or FAIL
// and versions, and Results refuses any text that looks like a key, a token or a password. Nothing
// here names Vault's root token: it exists as a file the harness makes, a Secret made from that file
// and the vault pod's own environment variable.
package l83

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/rhwendt/port49/tests/shapes/l82"
)

// The mechanisms.
const (
	Injector = "injector"
	CSI      = "csi"
)

// NA is the verdict of (c) for a configuration that failed (a) or (b): there is nothing to rotate.
const NA = "N/A"

// Fixed names the harness and the manifests share.
const (
	Role    = "port49d"     // the Vault Kubernetes-auth role, bound to port49d's service account
	SPCName = "port49-keys" // the SecretProviderClass
	KeyDir  = "/run/port49/keys"
	Within  = 300 * time.Second // (c): a version added at the store is in force with no restart
)

// Config is one configuration under test.
type Config struct {
	ID             string
	Mechanism      string
	SameUser       bool   // injector: agent-run-as-same-user
	FilePermission string // CSI: the provider's filePermission; empty is its default
}

// Configs are the four cells of (a) and (b), in order.
var Configs = []Config{
	{ID: "a1", Mechanism: Injector},
	{ID: "a2", Mechanism: Injector, SameUser: true},
	{ID: "b1", Mechanism: CSI},
	{ID: "b2", Mechanism: CSI, FilePermission: "0440"},
}

// Describe is the configuration in words, for the results.
func (c Config) Describe() string {
	switch {
	case c.Mechanism == Injector && c.SameUser:
		return `injector, perms "0440", agent-run-as-same-user "true"`
	case c.Mechanism == Injector:
		return `injector, perms "0440", the agent's default user`
	case c.FilePermission != "":
		return "Secrets Store CSI driver with the Vault provider, filePermission " + c.FilePermission
	}
	return "Secrets Store CSI driver with the Vault provider, the provider's default file permission"
}

// Order is the cells' order in the results: (a) and (b) for each configuration, then (c) for each.
var Order = func() []string {
	var o []string
	for _, c := range Configs {
		o = append(o, c.ID)
	}
	for _, c := range Configs {
		o = append(o, "c-"+c.ID)
	}
	return o
}()

func title(id string) string {
	for _, c := range Configs {
		switch id {
		case c.ID:
			kind := "(a)"
			if c.Mechanism == CSI {
				kind = "(b)"
			}
			return kind + " " + c.Describe() + ": port49d starts with the key"
		case "c-" + c.ID:
			return "(c) " + c.Describe() + ": a version added at the store is in force with no restart"
		}
	}
	return ""
}

// SecretPath is the KV v2 path of device key version n (the dev server's secret/ mount).
func SecretPath(n int) string { return fmt.Sprintf("secret/data/port49/devices/core-v%d", n) }

func versions(withV2 bool) []int {
	if withV2 {
		return []int{1, 2}
	}
	return []int{1}
}

type obj = map[string]any

// variant is the StatefulSet's pod template made into c: the injector's annotations and no keys
// volume, or the keys volume as a CSI volume. sts is the chart's StatefulSet as kubectl prints it.
func variant(sts []byte, c Config, withV2 bool) (obj, error) {
	var doc obj
	if err := json.Unmarshal(sts, &doc); err != nil {
		return nil, fmt.Errorf("l83: the StatefulSet is not JSON: %w", err)
	}
	tp, _ := dig(doc, "spec", "template").(obj)
	spec, _ := tp["spec"].(obj)
	if spec == nil {
		return nil, errors.New("l83: the StatefulSet has no pod template")
	}
	var ctr obj
	for _, x := range anys(spec["containers"]) {
		if o, _ := x.(obj); o != nil && o["name"] == "port49d" {
			ctr = o
		}
	}
	if ctr == nil {
		return nil, errors.New("l83: the pod template has no port49d container")
	}
	vols, keysAt := anys(spec["volumes"]), -1
	for i, v := range vols {
		if o, _ := v.(obj); o != nil && o["name"] == "keys" {
			keysAt = i
		}
	}
	mounts, mountAt := anys(ctr["volumeMounts"]), -1
	for i, m := range mounts {
		if o, _ := m.(obj); o != nil && o["name"] == "keys" {
			mountAt = i
		}
	}
	if keysAt < 0 || mountAt < 0 {
		return nil, errors.New("l83: the port49d pod has no keys volume and mount")
	}
	switch c.Mechanism {
	case CSI:
		vols[keysAt] = obj{"name": "keys", "csi": obj{"driver": "secrets-store.csi.k8s.io", "readOnly": true,
			"volumeAttributes": obj{"secretProviderClass": SPCName}}}
	case Injector:
		spec["volumes"] = without(vols, keysAt)
		ctr["volumeMounts"] = without(mounts, mountAt)
		// The chart does not mount a service account credential; the agent authenticates with one.
		spec["automountServiceAccountToken"] = true
		meta, _ := tp["metadata"].(obj)
		if meta == nil {
			meta = obj{}
			tp["metadata"] = meta
		}
		ann, _ := meta["annotations"].(obj)
		if ann == nil {
			ann = obj{}
			meta["annotations"] = ann
		}
		const p = "vault.hashicorp.com/"
		ann[p+"agent-inject"], ann[p+"role"] = "true", Role
		if c.SameUser {
			ann[p+"agent-run-as-same-user"] = "true"
		}
		for _, n := range versions(withV2) {
			name := fmt.Sprintf("core_v%d", n)
			ann[p+"agent-inject-secret-"+name] = SecretPath(n)
			ann[p+"agent-inject-perms-"+name] = "0440"
			ann[p+"secret-volume-path-"+name] = KeyDir
			ann[p+"agent-inject-template-"+name] = fmt.Sprintf(`{{- with secret %q -}}{{- .Data.data.value -}}{{- end -}}`, SecretPath(n))
		}
	default:
		return nil, fmt.Errorf("l83: no mechanism %q", c.Mechanism)
	}
	return tp, nil
}

func dig(m obj, path ...string) any {
	var cur any = m
	for _, p := range path {
		o, _ := cur.(obj)
		cur = o[p]
	}
	return cur
}

func anys(v any) []any { l, _ := v.([]any); return l }

func without(l []any, i int) []any {
	out := append([]any{}, l[:i]...)
	return append(out, l[i+1:]...)
}

// Template is the JSON patch that makes the StatefulSet's pod template c, replacing it whole so that
// the previous configuration leaves nothing behind. withV2 adds version 2 to the injector's
// annotations (the SecretProviderClass carries it for the CSI driver).
func Template(sts []byte, c Config, withV2 bool) ([]byte, error) {
	tp, err := variant(sts, c, withV2)
	if err != nil {
		return nil, err
	}
	return json.Marshal([]obj{{"op": "replace", "path": "/spec/template", "value": tp}})
}

// Probe is a pod with port49d's service account, securityContext and key mount for c, whose one
// container is image running sleep: the harness runs stat in it. The injector adds its own agent to
// it as it does to port49d's pod.
func Probe(sts []byte, c Config, name, image string, withV2 bool) ([]byte, error) {
	tp, err := variant(sts, c, withV2)
	if err != nil {
		return nil, err
	}
	spec := tp["spec"].(obj)
	var src obj
	for _, x := range anys(spec["containers"]) {
		if o := x.(obj); o["name"] == "port49d" {
			src = o
		}
	}
	ctr := obj{"name": "probe", "image": image, "command": []string{"sh", "-c", "sleep 3600"}, "securityContext": src["securityContext"]}
	for _, m := range anys(src["volumeMounts"]) {
		if m.(obj)["name"] == "keys" {
			ctr["volumeMounts"] = []any{m}
		}
	}
	podSpec := obj{"restartPolicy": "Never", "serviceAccountName": spec["serviceAccountName"],
		"automountServiceAccountToken": spec["automountServiceAccountToken"],
		"securityContext":              spec["securityContext"], "containers": []any{ctr}}
	for _, v := range anys(spec["volumes"]) {
		if v.(obj)["name"] == "keys" {
			podSpec["volumes"] = []any{v}
		}
	}
	// terminationGracePeriodSeconds 0: the probe's sleep is PID 1 and ignores SIGTERM, so a deleted
	// probe would sit Terminating for the default 30 s (lab run 41142675001).
	podSpec["terminationGracePeriodSeconds"] = 0
	meta := obj{"name": name, "labels": obj{"l83": "probe", ConfigLabel: c.ID}}
	ann := obj{}
	for k, v := range dig(tp, "metadata", "annotations").(obj) {
		if strings.HasPrefix(k, "vault.hashicorp.com/") {
			ann[k] = v
		}
	}
	if len(ann) > 0 {
		meta["annotations"] = ann
	}
	return json.Marshal(obj{"apiVersion": "v1", "kind": "Pod", "metadata": meta, "spec": podSpec})
}

// ConfigLabel is the probe pod's label naming the configuration it was made for.
const ConfigLabel = "l83-config"

// ProbeName is the probe pod's name for c: one per configuration, so a probe still terminating from
// the last configuration is never the pod the next one's apply lands on.
func ProbeName(c Config) string { return "l83-probe-" + strings.ToLower(c.ID) }

// ProbeCurrent checks `uid|deletionTimestamp|label` read from the probe pod after it was Ready: it
// must not be terminating and must carry c's label, or its stat rows are another configuration's.
func ProbeCurrent(read string, c Config) error {
	f := strings.Split(strings.TrimSpace(read), "|")
	switch {
	case len(f) != 3 || f[0] == "":
		return fmt.Errorf("the probe pod could not be identified: %q", read)
	case f[1] != "":
		return fmt.Errorf("the probe pod %s is terminating (deleted at %s)", f[0], f[1])
	case f[2] != c.ID:
		return fmt.Errorf("the probe pod %s was made for configuration %q, not %q", f[0], f[2], c.ID)
	}
	return nil
}

// PodIdent is what (c) records of port49d's pod before and after the configuration changes.
type PodIdent struct {
	UID       string
	Restarts  int
	StartedAt string
}

// Change tells a pod replaced (its uid changed: the injector's template change is a rollout) from a
// container restarted (the same pod, a new restart count or start time: a crash).
func Change(before, after PodIdent) (replaced, restarted bool) {
	if before.UID != after.UID {
		return true, false
	}
	return false, before.Restarts != after.Restarts || before.StartedAt != after.StartedAt
}

// SecretProviderClass is the CSI variant's class, in namespace ns, naming the versions in force.
func SecretProviderClass(ns string, c Config, withV2 bool) ([]byte, error) {
	if c.Mechanism != CSI {
		return nil, errors.New("l83: a SecretProviderClass is for the CSI driver")
	}
	var objs strings.Builder
	for _, n := range versions(withV2) {
		fmt.Fprintf(&objs, "- objectName: %q\n  secretPath: %q\n  secretKey: \"value\"\n", fmt.Sprintf("core_v%d", n), SecretPath(n))
		if c.FilePermission != "" {
			fmt.Fprintf(&objs, "  filePermission: %s\n", c.FilePermission)
		}
	}
	return json.Marshal(obj{"apiVersion": "secrets-store.csi.x-k8s.io/v1", "kind": "SecretProviderClass",
		"metadata": obj{"name": SPCName, "namespace": ns},
		"spec": obj{"provider": "vault", "parameters": obj{
			"vaultAddress": "http://vault.vault:8200", "roleName": Role, "objects": objs.String()}}})
}

// VaultSetup is the shell script that configures the dev server through its own pod's environment:
// Kubernetes auth, a read-only policy on the device keys' paths and the role port49d's service
// account logs in with. The root token is the pod's variable, never an argument or output of the
// harness.
func VaultSetup() string {
	return `set -eu
export VAULT_ADDR=http://127.0.0.1:8200
VAULT_TOKEN="$L83_ROOT" vault auth enable kubernetes
VAULT_TOKEN="$L83_ROOT" vault write auth/kubernetes/config kubernetes_host=https://kubernetes.default.svc.cluster.local:443
VAULT_TOKEN="$L83_ROOT" vault policy write port49-keys - <<'POLICY'
path "secret/data/port49/devices/*" { capabilities = ["read"] }
POLICY
VAULT_TOKEN="$L83_ROOT" vault write auth/kubernetes/role/` + Role + ` bound_service_account_names=t-port49d bound_service_account_namespaces=port49 policies=port49-keys ttl=1h
`
}

// PutCommand is the shell command, run in the vault pod, that writes device key version n there:
// the key's bytes arrive on stdin, never in an argument.
func PutCommand(n int) string {
	return fmt.Sprintf(`VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN="$L83_ROOT" vault kv put -mount=secret port49/devices/core-v%d value=-`, n)
}

// JudgeStart is (a) and (b): port49d is Ready on the mechanism's files and never restarted.
func JudgeStart(ready bool, restarts int) string {
	if ready && restarts == 0 {
		return l82.Pass
	}
	return l82.Fail
}

// Rotation is what (c) saw.
type Rotation struct {
	InForce   bool          // a login keyed with version 2 passed
	Delay     time.Duration // from the configuration's gaining version 2 to that login
	Restarted bool          // the container restarted or its start time changed in the same pod
	Replaced  bool          // the pod was replaced (a new uid): a rollout, apart from a crash
}

// JudgeRotation is (c): in force within Within, with no restart and no pod replaced.
func JudgeRotation(r Rotation) string {
	if r.InForce && !r.Restarted && !r.Replaced && r.Delay <= Within {
		return l82.Pass
	}
	return l82.Fail
}

// Env is what the results record about the run.
type Env struct {
	Date, Runner, Run, Docker, Kernel, Kind, NodeImage, Kubectl, Helm string
	VaultChart, VaultApp, Injector, Provider, CSIChart, CSIApp        string
	Rotation                                                          string // the CSI driver's rotation feature, enabled or not
}

func nz(s string) string {
	if strings.TrimSpace(s) == "" {
		return "not recorded"
	}
	return s
}

func cell(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "|", "\\|"), "\n", " ")
}

func verdict(cells []l82.Cell, id string) string {
	for _, c := range cells {
		if c.ID == id && c.Verdict != "" {
			return c.Verdict
		}
	}
	return l82.NotRun
}

// Results is the results file for the CI artifact, built from cells and nothing else. It fails,
// writing nothing, if any text in it looks like a key.
func Results(env Env, cells []l82.Cell) (string, error) {
	var b strings.Builder
	b.WriteString("# L83: Vault Agent's injector and the Secrets Store CSI driver, rendering port49d's keys, on kind\n\n")
	b.WriteString("Generated by `make lab-l83` (tests/lab/l83_test.go) from the cells below; edit the harness, not this file.\n\n")
	fmt.Fprintf(&b, "- Date: %s\n- Platform: GitHub-hosted runner, %s\n- Run: %s\n- Docker: %s\n- Kernel: %s\n- kind: %s\n- Node image: %s\n- kubectl: %s\n- helm: %s\n",
		nz(env.Date), nz(env.Runner), nz(env.Run), nz(env.Docker), nz(env.Kernel), nz(env.Kind), nz(env.NodeImage), nz(env.Kubectl), nz(env.Helm))
	fmt.Fprintf(&b, "- Vault: chart %s, app %s; injector %s; CSI provider %s\n- Secrets Store CSI driver: chart %s, app %s; rotation: %s\n\n",
		nz(env.VaultChart), nz(env.VaultApp), nz(env.Injector), nz(env.Provider), nz(env.CSIChart), nz(env.CSIApp), nz(env.Rotation))
	b.WriteString("## Verdicts\n\n| Cell | Verdict |\n|---|---|\n")
	for _, id := range Order {
		fmt.Fprintf(&b, "| %s | %s |\n", title(id), verdict(cells, id))
	}
	b.WriteString("\n")
	for _, id := range Order {
		fmt.Fprintf(&b, "## %s: %s\n\n", title(id), verdict(cells, id))
		var rows []l82.Row
		for _, c := range cells {
			if c.ID == id {
				rows = c.Rows
			}
		}
		if len(rows) == 0 {
			b.WriteString("No observation.\n\n")
			continue
		}
		b.WriteString("| Case | Observation |\n|---|---|\n")
		for _, r := range rows {
			fmt.Fprintf(&b, "| %s | %s |\n", cell(r.Case), cell(r.Observation))
		}
		b.WriteString("\n")
	}
	b.WriteString("The register row closes only when every cell has a PASS, a FAIL or an N/A; a FAIL is a measured answer.\n")
	out := b.String()
	if why := l82.Leak(out); why != "" {
		return "", fmt.Errorf("l83: the results hold %s: nothing is written", why)
	}
	return out, nil
}
