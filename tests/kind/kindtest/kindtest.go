// Package kindtest is the kind cluster's bring-up, teardown and read side for the Kubernetes
// smokes (plan 12b, Task 11; Tasks 13-16 reuse it). Nothing in it runs unless a test calls Up, and
// Up needs the pinned binaries named by KIND_BIN and KUBECTL_BIN (make kind-smoke builds them into
// bin/): it fails, never skips, without them. UNVERIFIED until kind runs: nothing that execs kind,
// kubectl or helm here has been run. What does not need a cluster (the parsers, the post-renderer,
// the namespace filter) is unit-tested.
package kindtest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// Root is the repository root.
func Root() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "..")
}

// Bin is the binary an environment variable names, or a failure: the pinned tool is built by the
// Makefile, and a missing one must not read as a pass.
func Bin(t *testing.T, env string) string {
	t.Helper()
	p := os.Getenv(env)
	if p == "" {
		t.Fatalf("%s is not set: run this through make kind-smoke, which builds the pinned tools", env)
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("%s names %s, which is absent: run make kind-smoke", env, p)
	}
	return p
}

// Cluster is one kind cluster.
type Cluster struct {
	T          *testing.T
	Name       string
	Kubeconfig string
	kubectl    string
	kind       string
	// Guard runs the kill functions when the run is killed; a test registers each process it
	// starts (OnKill with StopPID) beside the cluster's own deletion.
	Guard *Guard
}

// Up creates the cluster from tests/kind/kind.yaml. A stale cluster of the same name (a killed
// earlier run) is deleted first, and the deletion is registered before the create, so a cluster
// made halfway is deleted too and it is always deleted, failed or not. A SIGINT, a SIGTERM or the
// test's own deadline a grace period away runs the same deletion and the guard's other kill
// functions (Guard), because the testing package runs no t.Cleanup on any of them.
func Up(t *testing.T, name string) *Cluster {
	t.Helper()
	kind := Bin(t, "KIND_BIN")
	c := &Cluster{T: t, Name: name, Kubeconfig: filepath.Join(t.TempDir(), "kubeconfig"), kubectl: Bin(t, "KUBECTL_BIN"), kind: kind}
	deadline, _ := t.Deadline()
	c.Guard = NewGuard(t, exitFn, deadline, KillGrace)
	c.Guard.OnKill(func() { _ = exec.Command(kind, "delete", "cluster", "--name", name).Run() })
	c.deleteCluster(t, "stale")
	t.Cleanup(func() {
		if t.Failed() {
			c.Dump(t)
		}
		c.deleteCluster(t, "")
	})
	cfg := filepath.Join(Root(), "tests", "kind", "kind.yaml")
	if out, err := exec.Command(kind, "create", "cluster", "--name", name, "--config", cfg,
		"--kubeconfig", c.Kubeconfig, "--wait", "180s").CombinedOutput(); err != nil {
		t.Fatalf("kind create cluster: %v\n%s", err, Filter(string(out)))
	}
	return c
}

func (c *Cluster) deleteCluster(t *testing.T, what string) {
	out, err := exec.Command(c.kind, "delete", "cluster", "--name", c.Name).CombinedOutput()
	if err != nil {
		t.Logf("kind delete cluster %s %s: %v\n%s", what, c.Name, err, Filter(string(out)))
	}
}

// exitFn is os.Exit, a variable so a unit test can see the guard's exit.
var exitFn = os.Exit

// KillGrace is how long before the test binary's own deadline the guard cleans up and exits.
var KillGrace = 45 * time.Second

// Guard makes a killed run clean up what t.Cleanup would. Go's testing package runs no t.Cleanup on
// a signal or on its -timeout panic, so a Ctrl-C, a SIGTERM or a deadline a grace period away runs
// every OnKill function, last registered first, then calls exit(2). It is dropped when the test
// ends normally.
type Guard struct {
	mu   sync.Mutex
	kill []func()
}

// OnKill registers a function the guard runs when the run is killed: stopping a process by its
// recorded pid, deleting the cluster.
func (g *Guard) OnKill(f func()) {
	g.mu.Lock()
	g.kill = append(g.kill, f)
	g.mu.Unlock()
}

// NewGuard starts the guard. A zero deadline arms no timer.
func NewGuard(t *testing.T, exit func(int), deadline time.Time, grace time.Duration) *Guard {
	t.Helper()
	g := &Guard{}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	done := make(chan struct{})
	var timeout <-chan time.Time
	if !deadline.IsZero() {
		tm := time.NewTimer(time.Until(deadline) - grace)
		timeout = tm.C
		t.Cleanup(func() { tm.Stop() })
	}
	t.Cleanup(func() { signal.Stop(sig); close(done) })
	go func() {
		var why string
		select {
		case s := <-sig:
			why = "got " + s.String()
		case <-timeout:
			why = "the test's own deadline is " + grace.String() + " away"
		case <-done:
			return
		}
		fmt.Fprintf(os.Stderr, "\n  kind smoke: %s; deleting the cluster and stopping what it started, then exiting\n", why)
		g.mu.Lock()
		kill := append([]func(){}, g.kill...)
		g.mu.Unlock()
		for i := len(kill) - 1; i >= 0; i-- {
			kill[i]()
		}
		exit(2)
	}()
	return g
}

// StopPID kills the process with a recorded pid, for a guard's OnKill: by pid, never by name.
func StopPID(pid int) func() {
	return func() { _ = syscall.Kill(pid, syscall.SIGKILL) }
}

// CheckLocalPV reads `kubectl get pv -o json` and fails unless the volume is a `local` PV and not
// a hostPath one, naming the StorageClass: the kubelet applies fsGroup to a local volume and never
// to a hostPath one, so on a hostPath class the fsGroup cell would pass without proving anything.
func CheckLocalPV(raw []byte) error {
	var pv struct {
		Spec struct {
			StorageClassName string
			HostPath         *json.RawMessage
			Local            *struct{ Path string }
		}
	}
	if err := json.Unmarshal(raw, &pv); err != nil {
		return fmt.Errorf("kindtest: not a PV: %w", err)
	}
	class := pv.Spec.StorageClassName
	switch {
	case pv.Spec.HostPath != nil:
		return fmt.Errorf("the StorageClass %q gave a hostPath volume: the kubelet never applies fsGroup to it, so the fsGroup cell would pass vacuously", class)
	case pv.Spec.Local == nil || pv.Spec.Local.Path == "":
		return fmt.Errorf("the StorageClass %q gave a volume with no .spec.local: the fsGroup cell needs a local PV", class)
	}
	return nil
}

// RequireLocalPV fails the test unless the PVC is bound to a local PV (CheckLocalPV).
func (c *Cluster) RequireLocalPV(ns, pvc string) {
	c.T.Helper()
	vol, err := c.KubectlTry("", "-n", ns, "get", "pvc", pvc, "-o", "jsonpath={.spec.volumeName}")
	if err != nil || strings.TrimSpace(vol) == "" {
		c.T.Fatalf("pvc %s/%s is not bound to a volume: %v", ns, pvc, err)
	}
	raw, err := c.KubectlTry("", "get", "pv", strings.TrimSpace(vol), "-o", "json")
	if err != nil {
		c.T.Fatalf("pv %s: %v", vol, err)
	}
	if err := CheckLocalPV([]byte(raw)); err != nil {
		c.T.Fatalf("pvc %s/%s: %v", ns, pvc, err)
	}
}

// PermitMint reports whether logs holds a decision record of a permitted mint for principal: the
// JSON line internal/token/minter.go:557 emits (keys event, verdict, principal of
// internal/decision/log.go:19-22). A deny record naming the principal does not count.
func PermitMint(logs, principal string) bool {
	for _, l := range strings.Split(logs, "\n") {
		var r struct{ Event, Verdict, Principal string }
		if i := strings.Index(l, "{"); i >= 0 && json.Unmarshal([]byte(l[i:]), &r) == nil &&
			r.Event == "mint" && r.Verdict == "permit" && r.Principal == principal {
			return true
		}
	}
	return false
}

// Context is the kubectl context kind names for the cluster.
func (c *Cluster) Context() string { return "kind-" + c.Name }

func (c *Cluster) cmd(args ...string) *exec.Cmd {
	return exec.Command(c.kubectl, append([]string{"--kubeconfig", c.Kubeconfig, "--context", c.Context()}, args...)...)
}

// KubectlTry runs kubectl and returns its stdout, and the error with the (filtered) stderr.
func (c *Cluster) KubectlTry(stdin string, args ...string) (string, error) {
	cmd := c.cmd(args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return out.String(), fmt.Errorf("kubectl %s: %w\n%s", Redact(args), err, Filter(errb.String()))
	}
	return out.String(), nil
}

// Kubectl runs kubectl and fails the test on an error.
func (c *Cluster) Kubectl(args ...string) string {
	c.T.Helper()
	out, err := c.KubectlTry("", args...)
	if err != nil {
		c.T.Fatal(err)
	}
	return out
}

// Apply applies a manifest from stdin.
func (c *Cluster) Apply(manifest string) {
	c.T.Helper()
	if _, err := c.KubectlTry(manifest, "apply", "-f", "-"); err != nil {
		c.T.Fatal(err)
	}
}

// Redact is the arguments for an error line, without any that follow --from-literal: a Secret is
// made with --from-file only, so this is a belt.
func Redact(args []string) string {
	var out []string
	for _, a := range args {
		if strings.HasPrefix(a, "--from-literal") {
			a = "--from-literal=<redacted>"
		}
		out = append(out, a)
	}
	return strings.Join(out, " ")
}

// Filter is tests/qual/secret-filter.sh on s: every failure dump goes through it.
func Filter(s string) string {
	cmd := exec.Command("bash", filepath.Join(Root(), "tests", "qual", "secret-filter.sh"))
	cmd.Stdin = strings.NewReader(s)
	out, err := cmd.Output()
	if err != nil {
		return "<the secret filter failed: nothing printed>"
	}
	return string(out)
}

// DumpNamespaces is the namespaces a failure dump reads: every one but vault.
func DumpNamespaces(all []string) []string {
	var out []string
	for _, n := range all {
		if n != "vault" && n != "" {
			out = append(out, n)
		}
	}
	return out
}

// Dump logs, through the secret filter, each namespace's pods, their descriptions and logs. It
// never reads a Secret, and never the vault namespace.
func (c *Cluster) Dump(t *testing.T) {
	t.Helper()
	nsOut, err := c.KubectlTry("", "get", "ns", "-o", "jsonpath={.items[*].metadata.name}")
	if err != nil {
		t.Logf("dump: %v", err)
		return
	}
	var b strings.Builder
	for _, ns := range DumpNamespaces(strings.Fields(nsOut)) {
		for _, args := range [][]string{
			{"-n", ns, "get", "pods", "-o", "wide"},
			{"-n", ns, "describe", "pods"},
			{"-n", ns, "logs", "--all-containers", "--prefix", "--tail=60", "-l", "app.kubernetes.io/name"},
		} {
			out, _ := c.KubectlTry("", args...)
			fmt.Fprintf(&b, "== %s\n%s\n", ns+" "+strings.Join(args[2:], " "), out)
		}
	}
	t.Logf("cluster dump (filtered):\n%s", Filter(b.String()))
}

// Pod is what a test asks of a pod's status.
type Pod struct {
	Phase, Node, HostIP string
	Ready               bool
	Restarts            int
	StartedAt           string
	Waiting             string // the first container's waiting reason, e.g. CrashLoopBackOff
	InitWaiting         string
}

// ParsePod reads `kubectl get pod -o json`.
func ParsePod(raw []byte) (Pod, error) {
	var d struct {
		Spec   struct{ NodeName string }
		Status struct {
			Phase, HostIP     string
			Conditions        []struct{ Type, Status string }
			ContainerStatuses []struct {
				RestartCount int
				State        struct {
					Running struct {
						StartedAt string
					}
					Waiting struct{ Reason string }
				}
			}
			InitContainerStatuses []struct {
				State struct{ Waiting struct{ Reason string } }
			}
		}
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		return Pod{}, fmt.Errorf("kindtest: not a pod: %w", err)
	}
	p := Pod{Phase: d.Status.Phase, Node: d.Spec.NodeName, HostIP: d.Status.HostIP}
	for _, c := range d.Status.Conditions {
		if c.Type == "Ready" {
			p.Ready = c.Status == "True"
		}
	}
	if len(d.Status.ContainerStatuses) > 0 {
		cs := d.Status.ContainerStatuses[0]
		p.Restarts, p.StartedAt, p.Waiting = cs.RestartCount, cs.State.Running.StartedAt, cs.State.Waiting.Reason
	}
	for _, c := range d.Status.InitContainerStatuses {
		if r := c.State.Waiting.Reason; r != "" {
			p.InitWaiting = r
		}
	}
	return p, nil
}

// Pod reads a pod.
func (c *Cluster) Pod(ns, name string) (Pod, error) {
	out, err := c.KubectlTry("", "-n", ns, "get", "pod", name, "-o", "json")
	if err != nil {
		return Pod{}, err
	}
	return ParsePod([]byte(out))
}

// WaitReady waits for the pod to be Ready, failing on timeout. The failure names the container's
// waiting reason, so a CrashLoopBackOff reads as one.
func (c *Cluster) WaitReady(ns, name string, within time.Duration) {
	c.T.Helper()
	deadline := time.Now().Add(within)
	var last Pod
	for time.Now().Before(deadline) {
		if p, err := c.Pod(ns, name); err == nil {
			last = p
			if p.Ready {
				return
			}
		}
		time.Sleep(3 * time.Second)
	}
	c.T.Fatalf("pod %s/%s is not Ready after %s: phase %q, restarts %d, waiting %q, init waiting %q", ns, name, within,
		last.Phase, last.Restarts, last.Waiting, last.InitWaiting)
}

// WaitCrashLoop waits for the pod's container to be in CrashLoopBackOff (or to have restarted at
// least twice), which is the RED outcome of the fsGroup cell. It returns false on timeout.
func (c *Cluster) WaitCrashLoop(ns, name string, within time.Duration) bool {
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if p, err := c.Pod(ns, name); err == nil && (p.Waiting == "CrashLoopBackOff" || p.Restarts >= 2) {
			return true
		}
		time.Sleep(3 * time.Second)
	}
	return false
}

// Stat is one line of `stat -c '%a %u %g %n'`.
type Stat struct {
	Mode     string
	UID, GID int
	Path     string
}

// ParseStat reads `stat -c '%a %u %g %n'` output.
func ParseStat(out string) ([]Stat, error) {
	var res []Stat
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		f := strings.Fields(l)
		if len(f) != 4 {
			return nil, fmt.Errorf("kindtest: stat line %q is not 'mode uid gid path'", l)
		}
		u, err1 := strconv.Atoi(f[1])
		g, err2 := strconv.Atoi(f[2])
		if err1 != nil || err2 != nil || !regexp.MustCompile(`^[0-7]{3,4}$`).MatchString(f[0]) {
			return nil, fmt.Errorf("kindtest: stat line %q is not numeric", l)
		}
		res = append(res, Stat{f[0], u, g, f[3]})
	}
	return res, nil
}

// Want checks one Stat against mode, uid and gid ("" for any mode).
func (s Stat) Want(mode string, uid, gid int) error {
	if s.Mode != mode || s.UID != uid || s.GID != gid {
		return fmt.Errorf("%s is %s %d:%d, want %s %d:%d", s.Path, s.Mode, s.UID, s.GID, mode, uid, gid)
	}
	return nil
}

// StateDirRefusal is the line the broker prints when the fence refuses its state directory: the
// RED run of the fsGroup cell must match this exactly (internal/config/config.go, the broker's
// state_dir check; kindtest_test.go pins the format against that source).
var StateDirRefusal = regexp.MustCompile(`config: broker\.state_dir /var/lib/port49-broker/state is writable by its group or others \(mode 0[0-7](?:[2367][0-7]|[0-7][2367])\)`)

// OldRootRE is the 3770 init command's text, which OldRoot rewrites to the first design's.
var oldRootRE = regexp.MustCompile(`chown 0:65532 ([^\s"]+) && chmod 3770 [^\s"]+ && (install -d -m 0700 -o 65532 -g 65532 [^\s"]+) && chown -R 65532:65532 [^\s"]+ && chmod -R go-rwx [^\s"]+ && chmod -R g-s [^\s"]+ && chmod 0700 [^\s"]+`)

// OldRoot is helm's post-renderer for the RED run, test-only and never shipped in the chart: it
// rewrites each data-dir init command to the first design (5e88550c), the root made 2755 by
// `chmod g-w`, which the kubelet's OnRootMismatch walks at every later mount. It fails when it
// finds no command to rewrite, so a chart that changed its init text breaks the cell loudly rather
// than leaving it a green run of the new design under the old one's name.
func OldRoot(rendered []byte) ([]byte, error) {
	n := 0
	out := oldRootRE.ReplaceAllFunc(rendered, func(m []byte) []byte {
		n++
		sub := oldRootRE.FindSubmatch(m)
		return []byte(string(sub[2]) + " && chmod g-w " + string(sub[1]))
	})
	if n == 0 {
		return nil, errors.New("kindtest: no data-dir init command to rewrite: the chart's init text changed")
	}
	return out, nil
}
