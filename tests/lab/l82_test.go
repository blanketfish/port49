//go:build lab

package lab

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/tacacs/wire"
	"github.com/rhwendt/port49/internal/testpki"
	kindstack "github.com/rhwendt/port49/tests/kind"
	"github.com/rhwendt/port49/tests/kind/kindtest"
	"github.com/rhwendt/port49/tests/shapes/l82"
	"github.com/rhwendt/port49/tests/shapes/shapetest"
)

// TestL82 measures spec §15 L82: Kubernetes Secret volumes as port49d's key directory, on kind,
// with the External Secrets Operator. `make lab-l82` runs it, and in CI only: kind's nodes are
// privileged containers, so shapetest.RefuseOnKeyHost refuses on a host with a TPM or a security
// key, and the lab lock is not taken (there is no shared lab host to hold). Cells:
//
//	(a) the owner, group and mode of the key directory, its ..data link and each file, through a pod
//	    with the chart's securityContext; PASS iff port49d starts with the key
//	(b) the delay from a Secret update that adds a key to its appearance in a whole-volume mount
//	(c) a subPath mount of the same Secret after the update, 180 s later
//	(d) the shipped ExternalSecret example (creationPolicy: Owner, only its store's name changed, fake
//	    provider) gains core_v2: the delay to a login keyed with it, with the policy naming it and no
//	    restart; the operator has made and owns the key Secret since before port49d started
//
// Every cell ends PASS or FAIL against the register's condition, and a FAIL is a measured answer,
// not a test failure. A cell that could not be measured is NOT RUN and fails the test. The results
// (PORT49_LAB_OUT, or a temp directory) are built by tests/shapes/l82 from the cells and nothing
// else, and are an artifact that will be public: stat lines, delays, verdicts and versions only.
//
// No key is printed, logged or written: the fake device keys are random per run, travel in files and
// stdin, and a Secret is only ever read for its key names. A failure's dump goes through the secret
// filter and never reads a Secret or the vault namespace.
func TestL82(t *testing.T) {
	if os.Getenv("PORT49_LAB_L82") != "1" {
		t.Skip("PORT49_LAB_L82=1 runs L82 (make lab-l82); `make lab` does not")
	}
	out := os.Getenv("PORT49_LAB_OUT")
	if out == "" {
		out = t.TempDir()
	}
	cells := []l82.Cell{{ID: "a"}, {ID: "b"}, {ID: "c"}, {ID: "d"}}
	env := l82Env(t)
	// The results are written whatever happened, so a run that died in cell (d) still says (a) to (c).
	defer func() {
		text, err := l82.Results(env, cells)
		if err != nil {
			t.Errorf("INVALID: %v", err)
			return
		}
		if err := os.MkdirAll(out, 0o755); err != nil {
			t.Errorf("INVALID: %v", err)
			return
		}
		if err := os.WriteFile(filepath.Join(out, "l82-results.md"), []byte(text), 0o644); err != nil {
			t.Errorf("INVALID: %v", err)
		}
		if err := l82.Save(filepath.Join(out, "l82-cells.json"), cells); err != nil {
			t.Errorf("INVALID: %v", err)
		}
		for _, c := range cells {
			t.Logf("L82 cell %s: %s", c.ID, l82Verdict(c))
		}
	}()

	// The key Secret is the shipped External Secrets example's, made and owned by the operator.
	v2 := l82Random(t)
	var esoImage string
	stack := kindstack.BringUpWith(t, "port49l82", kindstack.Options{KeysFrom: l82KeysFromESO(t, v2, &esoImage)})
	stack.Run(t, "a_key_directory", func(t *testing.T) { l82CellA(t, stack, &cells[0]) })
	stack.Run(t, "b_c_whole_mount_and_subpath", func(t *testing.T) { l82CellsBC(t, stack, &cells[1], &cells[2]) })
	stack.Run(t, "d_external_secrets", func(t *testing.T) { l82CellD(t, stack, v2, esoImage, &cells[3]) })
}

func l82Verdict(c l82.Cell) string {
	if c.Verdict == "" {
		return l82.NotRun
	}
	return c.Verdict
}

func l82Row(c *l82.Cell, what, observation string) {
	c.Rows = append(c.Rows, l82.Row{Case: what, Observation: observation})
}

// l82Run is a command's first line of output, "unavailable" if it fails.
func l82Run(name string, args ...string) string {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return "unavailable"
	}
	return strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0])
}

var l82NodeImage = regexp.MustCompile(`image:\s*(kindest/node:\S+)`)

// l82Env is what the results record. The runner's image version, the run id and the chart's
// versions come from the environment GitHub and the Makefile set; nothing is typed here.
func l82Env(t *testing.T) l82.Env {
	t.Helper()
	cfg, err := os.ReadFile(filepath.Join(kindtest.Root(), "tests", "kind", "kind.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	node := ""
	if m := l82NodeImage.FindSubmatch(cfg); m != nil {
		node = string(m[1])
	}
	runner := strings.TrimSpace(os.Getenv("ImageOS") + " " + os.Getenv("ImageVersion"))
	run := ""
	if id := os.Getenv("GITHUB_RUN_ID"); id != "" {
		run = "run " + id + ", attempt " + os.Getenv("GITHUB_RUN_ATTEMPT")
	}
	return l82.Env{
		Date:      time.Now().UTC().Format("2006-01-02"),
		Runner:    runner,
		Run:       run,
		Docker:    l82Run("docker", "version", "--format", "{{.Server.Version}}"),
		Kernel:    l82Run("uname", "-r"),
		Kind:      l82Run(kindtest.Bin(t, "KIND_BIN"), "version"),
		NodeImage: node,
		Kubectl:   l82Run(kindtest.Bin(t, "KUBECTL_BIN"), "version", "--client"),
		Helm:      l82Run(kindtest.Bin(t, "HELM_BIN"), "version", "--short"),
		ESOChart:  os.Getenv("ESO_CHART_VERSION"),
		ESOApp:    os.Getenv("ESO_APP_VERSION"),
	}
}

const l82Alpine = "alpine:3.22@sha256:2e0b81d60597f449baa56dc25d355367869d2dca4cd57e866f1e2b52af3eb55f"

// l82Secured is the chart's pod securityContext and port49d's container securityContext.
var (
	l82PodSecurity = map[string]any{"runAsUser": 65532, "runAsGroup": 65532, "fsGroup": 65532, "fsGroupChangePolicy": "OnRootMismatch"}
	l82CtrSecurity = map[string]any{"allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true,
		"capabilities": map[string]any{"drop": []string{"ALL"}}, "seccompProfile": map[string]any{"type": "RuntimeDefault"}}
)

// l82Pod is a pod with the chart's securityContext, the Secret mounted whole at mount with
// defaultMode 0440, and sh -c script.
func l82Pod(name, secret, mount, script string, mounts ...map[string]any) string {
	vm := append([]map[string]any{{"name": "keys", "mountPath": mount, "readOnly": true}}, mounts...)
	b, err := json.Marshal(map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": map[string]any{"name": name},
		"spec": map[string]any{"restartPolicy": "Never", "securityContext": l82PodSecurity,
			"containers": []map[string]any{{"name": "x", "image": l82Alpine, "command": []string{"sh", "-c", script},
				"securityContext": l82CtrSecurity, "volumeMounts": vm}},
			"volumes": []map[string]any{{"name": "keys", "secret": map[string]any{"secretName": secret, "defaultMode": 0o440}}}}})
	if err != nil {
		panic(err)
	}
	return string(b)
}

func l82Random(t *testing.T) string {
	t.Helper()
	s, err := testpki.RandomSecret(32)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// Cell (a): the stat lines of the mount, and whether port49d, which mounts the same Secret the same
// way, started with the key.
func l82CellA(t *testing.T, stack *kindstack.Stack, cell *l82.Cell) {
	c, ns := stack.Cluster(), stack.Namespace()
	// Names are relative to the mount: the results never hold a long path.
	script := `cd /run/port49/keys && for f in . ..data; do stat -c '%U %G %a %F %n' "$f"; done; ` +
		`for f in *; do stat -c '%U %G %a %F %n' "$f"; stat -L -c '%U %G %a %F %n' "$f"; done`
	t.Cleanup(func() { c.KubectlTry("", "-n", ns, "delete", "pod", "l82-stat", "--ignore-not-found", "--wait=false") })
	if _, err := c.KubectlTry(l82Pod("l82-stat", "port49-device-keys", "/run/port49/keys", script), "-n", ns, "apply", "-f", "-"); err != nil {
		t.Fatal(err)
	}
	shapetest.WaitFor(t, "the stat pod to finish", 3*time.Minute, func() bool {
		p, err := c.Pod(ns, "l82-stat")
		return err == nil && (p.Phase == "Succeeded" || p.Phase == "Failed")
	})
	lines := strings.Split(strings.TrimSpace(c.Kubectl("-n", ns, "logs", "l82-stat")), "\n")
	if len(lines) < 4 {
		t.Fatalf("the stat pod printed %d lines, want the directory, ..data and a link and a file for each key", len(lines))
	}
	for i, ln := range lines {
		norm, err := l82.StatLine(ln)
		if err != nil {
			t.Fatal(err)
		}
		what := "the directory"
		switch {
		case i == 1:
			what = "the ..data link"
		case i >= 2 && i%2 == 0:
			what = "a key file's link"
		case i >= 2:
			what = "that key file, followed"
		}
		l82Row(cell, what, norm)
	}
	p, err := c.Pod(ns, "t-port49d-0")
	if err != nil {
		t.Fatal(err)
	}
	l82Row(cell, "port49d's pod, which mounts the Secret as the chart does", fmt.Sprintf("Ready %v, restarts %d", p.Ready, p.Restarts))
	cell.Verdict = l82.JudgeStart(p.Ready, p.Restarts)
}

func l82Patch(t *testing.T, stack *kindstack.Stack, kind, name string, doc any) {
	t.Helper()
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	f := stack.WriteTemp("patch.json", string(b), 0o600)
	stack.Cluster().Kubectl("-n", stack.Namespace(), "patch", kind, name, "--type", "merge", "--patch-file", f)
}

// Cells (b) and (c): one probe Secret mounted whole and by subPath; one update adds tacacs_v2 and
// changes tacacs_v1. (b) is the delay to tacacs_v2 in the whole mount. (c) compares both mounts'
// tacacs_v1 by hash, inside the pod, 180 s after the update. The probe's values are fake, random per
// run and only ever compared, never printed. The real keys are not touched.
func l82CellsBC(t *testing.T, stack *kindstack.Stack, b, c *l82.Cell) {
	cl, ns := stack.Cluster(), stack.Namespace()
	v1, v1b, v2 := l82Random(t), l82Random(t), l82Random(t)
	cl.Kubectl("-n", ns, "create", "secret", "generic", "l82-probe", "--from-file=tacacs_v1="+stack.WriteTemp("probe-v1", v1, 0o600))
	t.Cleanup(func() {
		cl.KubectlTry("", "-n", ns, "delete", "pod", "l82-probe", "--ignore-not-found", "--wait=false")
	})
	pod := l82Pod("l82-probe", "l82-probe", "/whole", "sleep 900",
		map[string]any{"name": "keys", "mountPath": "/sub/tacacs_v1", "subPath": "tacacs_v1", "readOnly": true})
	if _, err := cl.KubectlTry(pod, "-n", ns, "apply", "-f", "-"); err != nil {
		t.Fatal(err)
	}
	cl.WaitReady(ns, "l82-probe", 3*time.Minute)
	hashes := func() (whole, sub string) {
		out := cl.Kubectl("-n", ns, "exec", "l82-probe", "--", "sh", "-c", "sha256sum /whole/tacacs_v1 /sub/tacacs_v1 | cut -d' ' -f1")
		f := strings.Fields(out)
		if len(f) != 2 {
			t.Fatalf("sha256sum in the probe printed %d hashes", len(f))
		}
		return f[0], f[1]
	}
	w0, s0 := hashes()
	enc := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	t0 := time.Now()
	l82Patch(t, stack, "secret", "l82-probe", map[string]any{"data": map[string]string{"tacacs_v1": enc(v1b), "tacacs_v2": enc(v2)}})
	var d time.Duration
	appeared := false
	for time.Since(t0) < 5*time.Minute {
		out, err := cl.KubectlTry("", "-n", ns, "exec", "l82-probe", "--", "sh", "-c", "test -f /whole/tacacs_v2 && echo yes || echo no")
		if err == nil && strings.TrimSpace(out) == "yes" {
			appeared, d = true, time.Since(t0)
			break
		}
		time.Sleep(2 * time.Second)
	}
	if appeared {
		l82Row(b, "delay from the Secret update to the new key's file in a whole mount", d.Round(time.Second).String())
	} else {
		l82Row(b, "the new key's file in a whole mount", "not seen in 5m0s")
	}
	b.Verdict = l82.JudgeWholeMountDelay(appeared, d)

	if wait := l82.SubPathWait - time.Since(t0); wait > 0 {
		time.Sleep(wait)
	}
	w1, s1 := hashes()
	l82Row(c, fmt.Sprintf("after %s: the whole mount's file changed", l82.SubPathWait), fmt.Sprint(w0 != w1))
	l82Row(c, fmt.Sprintf("after %s: the subPath file changed", l82.SubPathWait), fmt.Sprint(s0 != s1))
	c.Verdict = l82.JudgeSubPath(w0 != w1, s0 != s1)
}

// l82Manifest is a manifest as JSON on stdin: the fake provider's values are in it, and it is never
// printed.
func l82Manifest(t *testing.T, doc any) string {
	t.Helper()
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

const l82Store = "l82-fake"

// l82Example is the shipped External Secrets example, which cell (d) applies as an operator would.
func l82Example(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(kindtest.Root(), "deploy", "helm", "port49", "examples", "external-secret.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// l82KeysFromESO is the stack's KeysFrom: the operator installed from the pinned chart, a namespaced
// SecretStore with the fake provider holding port49/devices/core-v1 (the stack's version 1 key) and
// core-v2 (random per run), and the shipped example's ExternalSecret less its core_v2 entry, which
// creates and owns port49-device-keys (creationPolicy: Owner) before anything mounts it. The
// operator's image tag is returned through image.
func l82KeysFromESO(t *testing.T, v2 string, image *string) func(*kindtest.Cluster, string, []byte) {
	return func(cl *kindtest.Cluster, ns string, v1 []byte) {
		chart := kindtest.Bin(t, "ESO_CHART")
		helm := exec.Command(kindtest.Bin(t, "HELM_BIN"), "--kubeconfig", cl.Kubeconfig, "--kube-context", cl.Context(),
			"upgrade", "--install", "external-secrets", chart, "-n", "external-secrets", "--create-namespace",
			"--set", "installCRDs=true", "--set", "bitwarden-sdk-server.enabled=false", "--wait", "--timeout", "6m")
		if out, err := helm.CombinedOutput(); err != nil {
			t.Fatalf("helm install of the External Secrets Operator: %v\n%s", err, kindtest.Filter(string(out)))
		}
		if img, err := cl.KubectlTry("", "-n", "external-secrets", "get", "deploy", "external-secrets", "-o",
			"jsonpath={.spec.template.spec.containers[0].image}"); err == nil {
			*image = shapetest.ImageTag(img)
		}
		store := l82Manifest(t, map[string]any{"apiVersion": "external-secrets.io/v1", "kind": "SecretStore",
			"metadata": map[string]any{"name": l82Store, "namespace": ns},
			"spec": map[string]any{"provider": map[string]any{"fake": map[string]any{"data": []map[string]any{
				{"key": "port49/devices/core-v1", "value": string(v1)},
				{"key": "port49/devices/core-v2", "value": v2}}}}}})
		// The operator's webhook takes a moment after its pods are Ready.
		shapetest.WaitFor(t, "the SecretStore to be accepted", 3*time.Minute, func() bool {
			_, err := cl.KubectlTry(store, "apply", "-f", "-")
			return err == nil
		})
		l82ApplyES(t, cl, ns, false)
		cl.Kubectl("-n", ns, "wait", "--for=condition=Ready", "externalsecret/port49-device-keys", "--timeout=180s")
	}
}

// l82ApplyES applies the example's ExternalSecret, with the store's name changed and nothing else.
func l82ApplyES(t *testing.T, cl *kindtest.Cluster, ns string, withV2 bool) {
	t.Helper()
	b, err := l82.ExternalSecretFromExample(l82Example(t), l82Store, withV2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cl.KubectlTry(string(b), "-n", ns, "apply", "-f", "-"); err != nil {
		t.Fatal(err)
	}
}

// Cell (d): the shipped example, creationPolicy: Owner as shipped, has made and owns the key Secret
// since before the pods started (l82KeysFromESO), so port49d started on it. The policy names
// version 2 while its file is absent; then the whole example is applied, which adds core_v2. The
// delay runs from that edit to a login keyed with version 2, with port49d's container neither
// restarted nor started again. If the example cannot work as written, that is this cell's FAIL and
// a chart bug, not something to route around.
func l82CellD(t *testing.T, stack *kindstack.Stack, v2, image string, cell *l82.Cell) {
	cl, ns := stack.Cluster(), stack.Namespace()
	if image != "" {
		l82Row(cell, "the operator's image tag", image)
	}
	l82Row(cell, "the key Secret's creationPolicy, as the example ships it", "Owner")
	next, err := shapetest.WithAcceptV2(stack.Policy(), "/run/port49/keys")
	if err != nil {
		t.Fatal(err)
	}
	// the example's key file for version 2 is core_v2
	next = []byte(strings.ReplaceAll(string(next), "keys/tacacs_v2", "keys/core_v2"))
	if err := stack.PatchPolicy(next); err != nil {
		t.Fatalf("writing the policy with version 2 named: %v", err)
	}
	broker := stack.Forward("svc/"+stack.Release()+"-broker", 8443)
	mint := stack.Mint(broker)
	dev := stack.Device("t-port49d-0")
	tok := mint()
	shapetest.WaitFor(t, "a login keyed with version 1 while the policy names version 2", 60*time.Second, func() bool {
		st, err := dev.TryLogin("alice", tok)
		return err == nil && st == wire.AuthenStatusPass
	})
	before, err := cl.Pod(ns, "t-port49d-0")
	if err != nil {
		t.Fatal(err)
	}

	t0 := time.Now()
	l82ApplyES(t, cl, ns, true)
	gained := false
	var tSecret time.Duration
	keys := `go-template={{range $k, $v := .data}}{{$k}} {{end}}`
	for time.Since(t0) < 6*time.Minute {
		out, err := cl.KubectlTry("", "-n", ns, "get", "secret", "port49-device-keys", "-o", keys)
		if err == nil && strings.Contains(" "+out, " core_v2 ") {
			gained, tSecret = true, time.Since(t0)
			break
		}
		time.Sleep(2 * time.Second)
	}
	res := l82.ESOResult{SecretGained: gained}
	if gained {
		l82Row(cell, "delay from the ExternalSecret's edit to the Secret holding the new key", tSecret.Round(time.Second).String())
		dv2 := shapetest.Device{T: t, Addr: dev.Addr, Key: []byte(v2)}
		tok = mint()
		for time.Since(t0) < 8*time.Minute {
			if st, err := dv2.TryLogin("alice", tok); err == nil && st == wire.AuthenStatusPass {
				res.LoginPassed, res.Delay = true, time.Since(t0)
				break
			}
			time.Sleep(3 * time.Second)
		}
	}
	if res.LoginPassed {
		l82Row(cell, "delay from the ExternalSecret's edit to a login keyed with version 2", res.Delay.Round(time.Second).String())
	} else {
		l82Row(cell, "a login keyed with version 2", "never passed")
	}
	after, err := cl.Pod(ns, "t-port49d-0")
	if err != nil {
		t.Fatal(err)
	}
	res.Restarted = after.Restarts != before.Restarts || after.StartedAt != before.StartedAt
	l82Row(cell, "port49d's container restarted or started again", fmt.Sprint(res.Restarted))
	cell.Verdict = l82.JudgeESO(res)
	// Informational, after the verdict: a new version is a new file, so no held file's bytes changed.
	metrics := stack.Forward("pod/t-port49d-0", 9049)
	l82Row(cell, "the gauge of key Secret files rewritten in place (key secret files changed)", fmt.Sprint(shapetest.Gauge(t, metrics, "port49_key_secret_files_changed")))
}
