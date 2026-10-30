//go:build lab

package lab

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/tacacs/wire"
	kindstack "github.com/rhwendt/port49/tests/kind"
	"github.com/rhwendt/port49/tests/kind/kindtest"
	"github.com/rhwendt/port49/tests/shapes/l82"
	"github.com/rhwendt/port49/tests/shapes/l83"
	"github.com/rhwendt/port49/tests/shapes/shapetest"
)

// TestL83 measures spec §15 L83: Vault Agent's injector and the Secrets Store CSI driver with the
// Vault provider rendering port49d's keys, on kind. `make lab-l83` runs it, in CI only (see
// TestL82). Vault is its chart in dev mode with the injector and the CSI provider, and the driver is
// its own chart, each pinned by sha256. The chart's port49d StatefulSet is switched, one
// configuration at a time, to read its key directory from the mechanism (tests/shapes/l83 builds
// the pod template), and a probe pod with the same service account, securityContext, annotations
// or volume and an Alpine image is what `stat` runs in. Cells:
//
//	a1, a2  the injector with perms "0440", without and with agent-run-as-same-user: stat of the
//	        rendered directory and file, the agent's uid, and whether port49d starts with the key
//	b1, b2  the CSI driver with the provider's default permission and with filePermission 0440:
//	        stat, and whether port49d starts
//	c-*     for each configuration that passed: core-v2 is written at Vault and the configuration
//	        gains it; PASS iff a login keyed with it works within 300 s with no restart
//
// A FAIL is a measured answer; a cell that could not be measured is NOT RUN and fails the test.
// The results are an artifact that will be public: stat lines, delays, verdicts and versions.
//
// Vault's root token is random per run. It exists as a file in a temp directory, as a Secret made
// from that file in the vault namespace, and as the vault pod's own environment variable; every
// command that needs it runs inside that pod. It is never an argument, never logged and never in
// the results, and a failure's dump (which never reads Secrets) skips the vault namespace.
func TestL83(t *testing.T) {
	out := os.Getenv("PORT49_LAB_OUT")
	if out == "" {
		out = t.TempDir()
	}
	cells := make([]l82.Cell, len(l83.Order))
	for i, id := range l83.Order {
		cells[i].ID = id
	}
	env := l83Env(t)
	defer func() {
		text, err := l83.Results(*env, cells)
		if err != nil {
			t.Errorf("INVALID: %v", err)
			return
		}
		if err := os.MkdirAll(out, 0o755); err != nil {
			t.Errorf("INVALID: %v", err)
			return
		}
		if err := os.WriteFile(filepath.Join(out, "l83-results.md"), []byte(text), 0o644); err != nil {
			t.Errorf("INVALID: %v", err)
		}
		if err := l82.Save(filepath.Join(out, "l83-cells.json"), cells); err != nil {
			t.Errorf("INVALID: %v", err)
		}
		for _, c := range cells {
			t.Logf("L83 cell %s: %s", c.ID, l82Verdict(c))
		}
	}()

	v2 := l82Random(t)
	stack := kindstack.BringUpWith(t, "port49l83", kindstack.Options{KeysFrom: l83Install(t, v2, env)})
	sts := stack.Cluster().Kubectl("-n", stack.Namespace(), "get", "sts", stack.Release()+"-port49d", "-o", "json")
	base := stack.Policy()
	for i, cfg := range l83.Configs {
		a, c := &cells[i], &cells[len(l83.Configs)+i]
		stack.Run(t, cfg.ID+"_starts", func(t *testing.T) { l83Start(t, stack, []byte(sts), base, cfg, a) })
		stack.Run(t, "c_"+cfg.ID+"_rotation", func(t *testing.T) {
			if a.Verdict != l82.Pass {
				l82Row(c, "not measured", "the configuration did not pass "+a.ID+": port49d did not start with its key")
				c.Verdict = l83.NA
				return
			}
			l83Rotation(t, stack, []byte(sts), cfg, v2, c)
		})
	}
}

func l83Env(t *testing.T) *l83.Env {
	t.Helper()
	e := l82Env(t)
	return &l83.Env{Date: e.Date, Runner: e.Runner, Run: e.Run, Docker: e.Docker, Kernel: e.Kernel, Kind: e.Kind,
		NodeImage: e.NodeImage, Kubectl: e.Kubectl, Helm: e.Helm,
		VaultChart: os.Getenv("VAULT_CHART_VERSION"), CSIChart: os.Getenv("CSI_CHART_VERSION")}
}

// l83Tag is an image reference's tag, "not recorded" if the lookup failed.
func l83Tag(img string, err error) string {
	if err != nil {
		return ""
	}
	return shapetest.ImageTag(img)
}

func l83Helm(t *testing.T, cl *kindtest.Cluster, release, chart, ns, values string) {
	t.Helper()
	cmd := exec.Command(kindtest.Bin(t, "HELM_BIN"), "--kubeconfig", cl.Kubeconfig, "--kube-context", cl.Context(),
		"upgrade", "--install", release, chart, "-n", ns, "-f", values, "--wait", "--timeout", "8m")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("helm install of %s: %v\n%s", release, err, kindtest.Filter(string(out)))
	}
}

// l83Install is the stack's KeysFrom: the CSI driver with its rotation feature, Vault in dev mode
// with the injector and the provider, Kubernetes auth and a policy for port49d's service account,
// version 1 of the key at Vault, and the key Secret the chart mounts for the stack's own start.
func l83Install(t *testing.T, v2 string, env *l83.Env) func(*kindtest.Cluster, string, []byte) {
	return func(cl *kindtest.Cluster, ns string, v1 []byte) {
		dir := t.TempDir()
		write := func(name, body string) string {
			p := filepath.Join(dir, name)
			if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			return p
		}
		// The root token: random, in a file, made a Secret from that file, and never anywhere else.
		root := l82Random(t)
		cl.Kubectl("create", "namespace", "vault")
		cl.Kubectl("-n", "vault", "create", "secret", "generic", "vault-root", "--from-file=token="+write("root", root))

		l83Helm(t, cl, "csi-secrets-store", kindtest.Bin(t, "CSI_CHART"), "kube-system", write("csi.yaml",
			"enableSecretRotation: true\nrotationPollInterval: 15s\n"))
		l83Helm(t, cl, "vault", kindtest.Bin(t, "VAULT_CHART"), "vault", write("vault.yaml", `server:
  dev: {enabled: true, devRootToken: unused}
  extraArgs: '-dev-root-token-id="$L83_ROOT"'
  extraSecretEnvironmentVars: [{envName: L83_ROOT, secretName: vault-root, secretKey: token}]
injector: {enabled: true}
csi: {enabled: true}
`))

		for _, r := range []struct {
			into *string
			args []string
		}{
			{&env.VaultApp, []string{"-n", "vault", "get", "sts", "vault", "-o", "jsonpath={.spec.template.spec.containers[0].image}"}},
			{&env.Injector, []string{"-n", "vault", "get", "deploy", "vault-agent-injector", "-o", "jsonpath={.spec.template.spec.containers[0].image}"}},
			{&env.Provider, []string{"-n", "vault", "get", "ds", "vault-csi-provider", "-o", "jsonpath={.spec.template.spec.containers[0].image}"}},
			{&env.CSIApp, []string{"-n", "kube-system", "get", "ds", "csi-secrets-store-secrets-store-csi-driver", "-o", "jsonpath={.spec.template.spec.containers[0].image}"}},
		} {
			img, err := cl.KubectlTry("", r.args...)
			*r.into = l83Tag(img, err)
		}
		args, err := cl.KubectlTry("", "-n", "kube-system", "get", "ds", "csi-secrets-store-secrets-store-csi-driver", "-o", "jsonpath={.spec.template.spec.containers[*].args}")
		switch {
		case err != nil:
			env.Rotation = "not read"
		case strings.Contains(args, "--enable-secret-rotation=true"):
			env.Rotation = "enabled, poll interval 15s"
		default:
			env.Rotation = "not enabled"
		}

		if out, err := cl.KubectlTry(l83.VaultSetup(), "-n", "vault", "exec", "-i", "vault-0", "--", "sh", "-s"); err != nil {
			t.Fatalf("configuring Vault: %v\n%s", err, kindtest.Filter(out))
		}
		l83Put(t, cl, 1, string(v1))

		// The Secret the chart mounts, so that the stack starts as every stack does; the first
		// configuration replaces that volume.
		cl.Kubectl("-n", ns, "create", "secret", "generic", "port49-device-keys", "--from-file=core_v1="+write("core_v1", string(v1)))
	}
}

// l83Put writes device key version n at Vault from stdin, inside the vault pod.
func l83Put(t *testing.T, cl *kindtest.Cluster, n int, key string) {
	t.Helper()
	if out, err := cl.KubectlTry(key, "-n", "vault", "exec", "-i", "vault-0", "--", "sh", "-c", l83.PutCommand(n)); err != nil {
		t.Fatalf("writing key version %d at Vault: %v\n%s", n, err, kindtest.Filter(out))
	}
}

func l83Patch(t *testing.T, stack *kindstack.Stack, sts []byte, cfg l83.Config, withV2 bool) {
	t.Helper()
	cl, ns := stack.Cluster(), stack.Namespace()
	if cfg.Mechanism == l83.CSI {
		spc, err := l83.SecretProviderClass(ns, cfg, withV2)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := cl.KubectlTry(string(spc), "apply", "-f", "-"); err != nil {
			t.Fatalf("applying the SecretProviderClass: %v", err)
		}
	}
	patch, err := l83.Template(sts, cfg, withV2)
	if err != nil {
		t.Fatal(err)
	}
	f := stack.WriteTemp("template-patch.json", string(patch), 0o600)
	if _, err := cl.KubectlTry("", "-n", ns, "patch", "sts", stack.Release()+"-port49d", "--type", "json", "--patch-file", f); err != nil {
		t.Fatalf("patching the StatefulSet: %v", err)
	}
}

// l83Pods is whether both port49d pods are Ready and their restarts in all.
func l83Pods(cl *kindtest.Cluster, ns string) (ready bool, restarts int, waiting string) {
	ready = true
	for _, n := range []string{"t-port49d-0", "t-port49d-1"} {
		p, err := cl.Pod(ns, n)
		if err != nil {
			return false, restarts, "absent"
		}
		ready = ready && p.Ready
		restarts += p.Restarts
		if waiting == "" {
			waiting = p.InitWaiting
		}
		if waiting == "" {
			waiting = p.Waiting
		}
	}
	return
}

// Cells (a) and (b): the configuration is applied to port49d's StatefulSet and rolled; the probe pod
// shows what the pod sees.
func l83Start(t *testing.T, stack *kindstack.Stack, sts, base []byte, cfg l83.Config, cell *l82.Cell) {
	cl, ns := stack.Cluster(), stack.Namespace()
	l82Row(cell, "configuration", cfg.Describe())
	// every configuration starts from the policy that names version 1 only
	if err := stack.PatchPolicy(base); err != nil {
		t.Fatal(err)
	}
	l83Patch(t, stack, sts, cfg, false)
	_, rolled := cl.KubectlTry("", "-n", ns, "rollout", "status", "sts/"+stack.Release()+"-port49d", "--timeout=240s")
	// Give a crash a moment to show: Ready is the question, and Ready may flap.
	time.Sleep(10 * time.Second)
	ready, restarts, waiting := l83Pods(cl, ns)
	if rolled != nil {
		l82Row(cell, "the rollout", "did not finish in 4m0s")
	}
	obs := fmt.Sprintf("both Ready %v, restarts %d", ready, restarts)
	if waiting != "" {
		obs += ", waiting: " + waiting
	}
	l82Row(cell, "port49d's pods, which read their key directory from the mechanism", obs)
	cell.Verdict = l83.JudgeStart(ready, restarts)

	l83Probe(t, stack, sts, cfg, cell)
}

// l83Probe runs stat as port49d's user in a pod configured as port49d's is.
func l83Probe(t *testing.T, stack *kindstack.Stack, sts []byte, cfg l83.Config, cell *l82.Cell) {
	cl, ns := stack.Cluster(), stack.Namespace()
	name := l83.ProbeName(cfg)
	pod, err := l83.Probe(sts, cfg, name, l82Alpine, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cl.KubectlTry("", "-n", ns, "delete", "pod", name, "--ignore-not-found", "--wait=false")
	})
	// Never apply onto a pod still on its way out: wait for the name to be free.
	cl.KubectlTry("", "-n", ns, "delete", "pod", name, "--ignore-not-found", "--wait=true", "--timeout=2m")
	if _, err := cl.KubectlTry(string(pod), "-n", ns, "apply", "-f", "-"); err != nil {
		t.Fatalf("applying the probe pod: %v", err)
	}
	var p kindtest.Pod
	deadline := time.Now().Add(2 * time.Minute)
	for time.Now().Before(deadline) {
		if p, err = cl.Pod(ns, name); err == nil && p.Ready {
			break
		}
		time.Sleep(3 * time.Second)
	}
	if !p.Ready {
		w := p.InitWaiting
		if w == "" {
			w = p.Waiting
		}
		l82Row(cell, "the probe pod", "not Ready in 2m0s, waiting: "+w)
		cl.KubectlTry("", "-n", ns, "delete", "pod", name, "--ignore-not-found", "--wait=false")
		return
	}
	idOut, _ := cl.KubectlTry("", "-n", ns, "get", "pod", name, "-o",
		"jsonpath={.metadata.uid}|{.metadata.deletionTimestamp}|{.metadata.labels."+l83.ConfigLabel+"}")
	if err := l83.ProbeCurrent(idOut, cfg); err != nil {
		l82Row(cell, "the probe pod", "not this configuration's, so its rows are not recorded: "+err.Error())
		cell.Verdict = l82.Fail
		return
	}
	inPod := func(container, script string) (string, error) {
		return cl.KubectlTry("", "-n", ns, "exec", name, "-c", container, "--", "sh", "-c", script)
	}
	if out, err := inPod("probe", `echo $(id -u):$(id -g)`); err == nil {
		l82Row(cell, "the probe's uid:gid, port49d's", strings.TrimSpace(out))
	}
	if cfg.Mechanism == l83.Injector {
		out, err := inPod("vault-agent", `id -u`)
		l82Row(cell, "the agent's uid", map[bool]string{true: strings.TrimSpace(out), false: "not read"}[err == nil])
	}
	stat := `cd ` + l83.KeyDir + ` && stat -c '%u %g %a %F %n' . && for f in *; do stat -c '%u %g %a %F %n' "$f"; stat -L -c '%u %g %a %F %n' "$f"; done`
	out, err := inPod("probe", stat)
	if err != nil {
		l82Row(cell, "stat in the key directory", "failed: "+kindtest.Filter(strings.SplitN(out, "\n", 2)[0]))
	}
	for i, ln := range strings.Split(strings.TrimSpace(out), "\n") {
		norm, err := l82.StatLine(ln)
		if err != nil {
			continue
		}
		what := "an entry"
		switch {
		case i == 0:
			what = "the key directory"
		case i%2 == 1:
			what = "an entry, itself"
		default:
			what = "that entry, followed"
		}
		l82Row(cell, what, norm)
	}
	read, err := inPod("probe", `head -c 1 `+l83.KeyDir+`/core_v1 >/dev/null 2>&1 && echo yes || echo no`)
	l82Row(cell, "the probe, as port49d's user, reads core_v1", map[bool]string{true: strings.TrimSpace(read), false: "not read"}[err == nil])
	cl.KubectlTry("", "-n", ns, "delete", "pod", name, "--ignore-not-found", "--wait=false")
}

// Cell (c): the policy names version 2 while its file is absent; version 2 is written at Vault; the
// configuration gains it. The delay runs from that change to a login keyed with version 2; a pod
// replaced, a container restarted or a start time changed is a restart.
func l83Rotation(t *testing.T, stack *kindstack.Stack, sts []byte, cfg l83.Config, v2 string, cell *l82.Cell) {
	cl, ns := stack.Cluster(), stack.Namespace()
	l82Row(cell, "configuration", cfg.Describe())
	next, err := shapetest.WithAcceptV2(stack.Policy(), l83.KeyDir)
	if err != nil {
		t.Fatal(err)
	}
	next = []byte(strings.ReplaceAll(string(next), "keys/tacacs_v2", "keys/core_v2"))
	if err := stack.PatchPolicy(next); err != nil {
		t.Fatalf("writing the policy with version 2 named: %v", err)
	}
	broker := stack.Forward("svc/"+stack.Release()+"-broker", 8443)
	mint := stack.Mint(broker)
	dev := stack.Device("t-port49d-0")
	tok := mint()
	shapetest.WaitFor(t, "a login keyed with version 1 while the policy names version 2", 90*time.Second, func() bool {
		st, err := dev.TryLogin("alice", tok)
		return err == nil && st == wire.AuthenStatusPass
	})
	ident := func() l83.PodIdent {
		uid, _ := cl.KubectlTry("", "-n", ns, "get", "pod", "t-port49d-0", "-o", "jsonpath={.metadata.uid}")
		p, _ := cl.Pod(ns, "t-port49d-0")
		return l83.PodIdent{UID: strings.TrimSpace(uid), Restarts: p.Restarts, StartedAt: p.StartedAt}
	}
	before := ident()

	l83Put(t, cl, 2, v2)
	t0 := time.Now()
	l83Patch(t, stack, sts, cfg, true)
	res := l83.Rotation{}
	// the pod may be gone for a while: look again at its node and port every time
	for time.Since(t0) < l83.Within+60*time.Second {
		p, err := cl.Pod(ns, "t-port49d-0")
		if err == nil && p.Ready && p.HostIP != "" {
			d := stack.Device("t-port49d-0")
			d.Key = []byte(v2)
			if st, err := d.TryLogin("alice", tok); err == nil && st == wire.AuthenStatusPass {
				res.InForce, res.Delay = true, time.Since(t0)
				break
			}
		}
		time.Sleep(3 * time.Second)
	}
	res.Replaced, res.Restarted = l83.Change(before, ident())
	if res.InForce {
		l82Row(cell, "delay from the configuration gaining version 2 to a login keyed with it", res.Delay.Round(time.Second).String())
	} else {
		l82Row(cell, "a login keyed with version 2", fmt.Sprintf("never passed in %s", (l83.Within+60*time.Second).Round(time.Second)))
	}
	l82Row(cell, "port49d's pod replaced (a new uid: a rollout, as the injector's template change is)", fmt.Sprint(res.Replaced))
	l82Row(cell, "port49d's container restarted or its start time changed, in the same pod", fmt.Sprint(res.Restarted))
	cell.Verdict = l83.JudgeRotation(res)
}
