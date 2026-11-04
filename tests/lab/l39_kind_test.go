//go:build lab

package lab

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	kindstack "github.com/blanketfish/port49/tests/kind"
	"github.com/blanketfish/port49/tests/kind/kindtest"
	"github.com/blanketfish/port49/tests/shapes/l39"
	"github.com/blanketfish/port49/tests/shapes/l82"
	"github.com/blanketfish/port49/tests/shapes/shapetest"
)

// L39's fixed names. The device is a container on the kind network, outside every node.
const l39Client = "port49l39-client"

// TestL39 measures spec §15 L39 (b) and (c): which source address port49d sees when a device dials it
// behind a Kubernetes NodePort Service, and on the host network. `make lab-l39` runs it, locally or in
// CI (lab-kind.yml). The cluster has a control plane and two workers; the chart is installed as the
// kind stack installs it, then port49d is cut to one replica and pinned to the worker its volume is on. The
// device is a container on the kind network whose address is the inventory's one device, and its
// client is tests/lab/l85client, copied in. Each dial is a fresh login, and the verdict is port49d's
// decision log: token_redeemed, or the refusal, with the source address port49d recorded.
//
//	(b1) externalTrafficPolicy: Cluster, dialled at the node running the pod
//	(b2) Cluster, dialled at the other worker
//	(b3) Local, dialled at the node running the pod
//	(b4) Local, dialled at the other worker (an observation, recorded either way)
//	(c)  hostNetwork: true on a namespace relabelled privileged for this cell, dialled at its node
//
// The host-network change is a patch the harness applies; the chart offers no host networking (spec
// §13 decision 54 ruling 5). A FAIL is a measured answer; a cell that could not be measured is NOT RUN
// and fails the test. The results are an artifact that will be public. The device's key is the
// stack's and the login credential is minted per dial; both travel on stdin and are never printed.
func TestL39(t *testing.T) {
	if os.Getenv("PORT49_LAB_L39") != "1" {
		t.Skip("PORT49_LAB_L39=1 runs L39 (make lab-l39); `make lab` does not")
	}
	shapetest.RefuseOnKeyHost(t)
	out := os.Getenv("PORT49_LAB_OUT")
	if out == "" {
		out = t.TempDir()
	}
	cells := []l82.Cell{{ID: "b1"}, {ID: "b2"}, {ID: "b3"}, {ID: "b4"}, {ID: "c"}}
	env := l39Env(t)
	defer func() {
		text, err := l39.Results(*env, cells)
		if err != nil {
			t.Errorf("INVALID: %v", err)
			return
		}
		if err := os.MkdirAll(out, 0o755); err != nil {
			t.Errorf("INVALID: %v", err)
			return
		}
		if err := os.WriteFile(filepath.Join(out, "l39-results.md"), []byte(text), 0o644); err != nil {
			t.Errorf("INVALID: %v", err)
		}
		if err := l82.Save(filepath.Join(out, "l39-cells.json"), cells); err != nil {
			t.Errorf("INVALID: %v", err)
		}
		for _, c := range cells {
			t.Logf("L39 cell %s: %s", c.ID, l82Verdict(c))
			if c.Verdict == "" {
				t.Errorf("L39 cell %s was not measured", c.ID)
			}
		}
	}()

	r := &l39Run{t: t, env: env, bin: l85Build(t)}
	svc, err := l39.ServiceValues("Cluster")
	if err != nil {
		t.Fatal(err)
	}
	stack := kindstack.BringUpWith(t, "port49l39", kindstack.Options{
		KindConfig: "kind-l39.yaml", Service: svc, Before: r.before, DeviceFrom: r.deviceFrom,
	})
	r.stack = stack
	broker := stack.Forward("svc/"+stack.Release()+"-broker", 8443)
	r.mint = stack.Mint(broker)
	key, err := os.ReadFile(stack.PKIFile("keys/tacacs_v1"))
	if err != nil {
		t.Fatal(err)
	}
	r.key = key
	r.pinOneReplica(t)

	stack.Run(t, "b1_cluster_pod_node", func(t *testing.T) { r.cellB(t, &cells[0], "Cluster", true) })
	stack.Run(t, "b2_cluster_other_node", func(t *testing.T) { r.cellB(t, &cells[1], "Cluster", false) })
	stack.Run(t, "b3_local_pod_node", func(t *testing.T) { r.cellB(t, &cells[2], "Local", true) })
	stack.Run(t, "b4_local_other_node", func(t *testing.T) { r.cellB(t, &cells[3], "Local", false) })
	stack.Run(t, "c_host_network", func(t *testing.T) { r.cellC(t, &cells[4]) })
}

// l39Run is the lab's state: the stack, the device and its credentials.
type l39Run struct {
	t       *testing.T
	env     *l39.Env
	stack   *kindstack.Stack
	bin     string // the device client, linux
	devAddr string // the device's address on the kind network
	mint    func() string
	key     []byte
	workers []string          // the worker nodes' names
	addrs   map[string]string // node name to InternalIP
}

func l39Env(t *testing.T) *l39.Env {
	t.Helper()
	e := l82Env(t)
	mem := l82Run("sh", "-c", `awk '/MemTotal/ {printf "%.0f GB", $2/1048576}' /proc/meminfo`)
	runner := "GitHub-hosted runner, " + e.Runner
	if e.Run == "" {
		runner = "a local host"
	}
	return &l39.Env{Date: e.Date, Runner: fmt.Sprintf("%s, %d vCPU, %s memory", runner, runtime.NumCPU(), mem), Run: e.Run,
		Docker: e.Docker, Kernel: e.Kernel, Kind: e.Kind, NodeImage: e.NodeImage, Kubectl: e.Kubectl, Helm: e.Helm}
}

// before makes the device on the kind network, outside every node. The kind network assigns its
// address, which deviceFrom then hands the stack. Whatever the result, the container is removed.
func (r *l39Run) before(cl *kindtest.Cluster, subnet, gateway string) {
	t := r.t
	t.Helper()
	remove := func() { exec.Command("docker", "rm", "-f", l39Client).Run() }
	remove()
	t.Cleanup(remove)
	if out, err := l85Docker(t, "", "run", "-d", "--name", l39Client, "--network", "kind", l82Alpine, "sleep", "7200"); err != nil {
		t.Fatalf("starting the device: %v\n%s", err, out)
	}
	if _, err := l85Docker(t, "", "cp", r.bin, l39Client+":/l85client"); err != nil {
		t.Fatal(err)
	}
	ip, err := l85Docker(t, "", "inspect", "-f", `{{(index .NetworkSettings.Networks "kind").IPAddress}}`, l39Client)
	if err != nil {
		t.Fatal(err)
	}
	r.devAddr = strings.TrimSpace(ip)
	if r.devAddr == "" {
		t.Fatal("the device has no address on the kind network")
	}
}

// deviceFrom is the inventory's device: this one address alone, not the network.
func (r *l39Run) deviceFrom() (string, string) { return r.devAddr, r.devAddr + "/32" }

// pinOneReplica cuts port49d to one replica on the worker its volume is on and waits for it, then records the
// nodes' addresses.
func (r *l39Run) pinOneReplica(t *testing.T) {
	t.Helper()
	cl, ns := r.stack.Cluster(), r.stack.Namespace()
	list := cl.Kubectl("get", "nodes", "-l", "!node-role.kubernetes.io/control-plane", "-o",
		`go-template={{range .items}}{{.metadata.name}} {{range .status.addresses}}{{if eq .type "InternalIP"}}{{.address}}{{end}}{{end}}{{"\n"}}{{end}}`)
	r.addrs = map[string]string{}
	for _, ln := range strings.Split(strings.TrimSpace(list), "\n") {
		f := strings.Fields(ln)
		if len(f) != 2 {
			t.Fatalf("a node line has %d fields", len(f))
		}
		r.workers = append(r.workers, f[0])
		r.addrs[f[0]] = f[1]
	}
	if len(r.workers) != 2 {
		t.Fatalf("the cluster has %d workers, want 2", len(r.workers))
	}
	sts := "statefulset/" + r.stack.Release() + "-port49d"
	cl.Kubectl("-n", ns, "scale", sts, "--replicas=1")
	// pod 0's volume is a local PV on the node the pod first ran on (WaitForFirstConsumer), so the pod
	// is pinned to that node, not to a chosen one: a pin elsewhere never schedules (run 41838617627).
	r.pinTo(t, r.podNode(t))
	if v, err := cl.KubectlTry("", "-n", "kube-system", "get", "cm", "kube-proxy", "-o", "jsonpath={.data.config\\.conf}"); err == nil {
		mode := "iptables (the default)"
		if m := regexp.MustCompile(`(?m)^mode:\s*"?([a-z]+)"?`).FindStringSubmatch(v); m != nil {
			mode = m[1]
		}
		r.env.KubeProxy = mode
	}
}

// pinTo patches the pod template to node and waits for the rollout and the pod.
func (r *l39Run) pinTo(t *testing.T, node string) {
	t.Helper()
	cl, ns := r.stack.Cluster(), r.stack.Namespace()
	patch, err := l39.PinToNode(node)
	if err != nil {
		t.Fatal(err)
	}
	sts := "statefulset/" + r.stack.Release() + "-port49d"
	cl.Kubectl("-n", ns, "patch", sts, "--type=strategic", "-p", patch)
	r.rolled(t, sts)
}

func (r *l39Run) rolled(t *testing.T, sts string) {
	t.Helper()
	cl, ns := r.stack.Cluster(), r.stack.Namespace()
	if _, err := cl.KubectlTry("", "-n", ns, "rollout", "status", sts, "--timeout=8m"); err != nil {
		t.Fatalf("the rollout of %s: %v", sts, err)
	}
	cl.WaitReady(ns, "t-port49d-0", 4*time.Minute)
}

// podNode is the worker that runs the pod.
func (r *l39Run) podNode(t *testing.T) string {
	t.Helper()
	p, err := r.stack.Cluster().Pod(r.stack.Namespace(), "t-port49d-0")
	if err != nil || p.HostIP == "" {
		t.Fatalf("t-port49d-0 has no node: %v", err)
	}
	for n, ip := range r.addrs {
		if ip == p.HostIP {
			return n
		}
	}
	t.Fatalf("the pod's node address is not a worker's")
	return ""
}

var l39Answer = regexp.MustCompile(`^(pass|fail:[a-z_0-9]+)$`)

// dial is one fresh login from the device to addr, and what port49d's log says of it.
func (r *l39Run) dial(t *testing.T, addr string) l39.Outcome {
	t.Helper()
	cl, ns := r.stack.Cluster(), r.stack.Namespace()
	creds, err := json.Marshal(map[string]string{"key": string(r.key), "token": r.mint(), "user": "alice"})
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Now().UTC().Add(-time.Second)
	ans, _ := l85Docker(t, string(creds), "exec", "-i", l39Client, "/l85client", "probe", "-addr", addr)
	ans = strings.TrimSpace(ans)
	if !l39Answer.MatchString(ans) {
		ans = "fail:error"
	}
	o := l39.Outcome{Client: ans}
	// the record is written as the reply goes; a dial that never arrives writes none, so the wait is bounded
	for deadline := time.Now().Add(8 * time.Second); ; time.Sleep(time.Second) {
		logs, _ := cl.KubectlTry("", "-n", ns, "logs", "t-port49d-0", "-c", "port49d", "--since-time="+t0.Format(time.RFC3339))
		o.Reasons, o.Sources = l39.ParseLog(logs)
		o.Redeemed = l39.Redeemed(o.Reasons)
		if len(o.Reasons) > 0 || time.Now().After(deadline) {
			return o
		}
	}
}

func (r *l39Run) record(cell *l82.Cell, o l39.Outcome, target string) {
	l82Row(cell, "the device's address (the inventory's one device)", r.devAddr)
	l82Row(cell, "dialled", target)
	l82Row(cell, "the device's client", o.Client)
	l82Row(cell, "port49d's decision log: reasons", l39.Words(o.Reasons))
	l82Row(cell, l39.SourceCase, l39.Addrs(o.Sources))
	seen := "no"
	for _, s := range o.Sources {
		if s == r.devAddr {
			seen = "yes"
		}
	}
	l82Row(cell, "the source port49d recorded is the device's own address", seen)
	cell.Verdict = l39.Judge(cell.ID, o)
}

// cellB dials the NodePort under policy, at the node running the pod or at the other worker.
func (r *l39Run) cellB(t *testing.T, cell *l82.Cell, policy string, atPodNode bool) {
	cl, ns := r.stack.Cluster(), r.stack.Namespace()
	svc := "svc/" + r.stack.Release() + "-port49d"
	cl.Kubectl("-n", ns, "patch", svc, "-p", `{"spec":{"externalTrafficPolicy":"`+policy+`"}}`)
	got := strings.TrimSpace(cl.Kubectl("-n", ns, "get", svc, "-o", "jsonpath={.spec.externalTrafficPolicy}"))
	if got != policy {
		t.Fatalf("the Service's externalTrafficPolicy is %q, want %q", got, policy)
	}
	port := strings.TrimSpace(cl.Kubectl("-n", ns, "get", svc, "-o", "jsonpath={.spec.ports[0].nodePort}"))
	node := r.podNode(t)
	which := "the node running the pod"
	if !atPodNode {
		which = "a worker not running the pod"
		for _, w := range r.workers {
			if w != node {
				node = w
			}
		}
	}
	time.Sleep(5 * time.Second) // kube-proxy programs the change
	l82Row(cell, "externalTrafficPolicy", policy)
	l82Row(cell, "dialled at", which)
	r.record(cell, r.dial(t, r.addrs[node]+":"+port), r.addrs[node]+":"+port+" (the Service's NodePort)")
}

// cellC puts port49d on the host network of its node and dials the node at port 49.
func (r *l39Run) cellC(t *testing.T, cell *l82.Cell) {
	cl, ns := r.stack.Cluster(), r.stack.Namespace()
	cl.Kubectl("label", "namespace", ns, "pod-security.kubernetes.io/enforce=privileged", "--overwrite")
	sts := "statefulset/" + r.stack.Release() + "-port49d"
	cl.Kubectl("-n", ns, "patch", sts, "--type=strategic", "-p", l39.HostNetwork())
	r.rolled(t, sts)
	node := r.podNode(t)
	hn := strings.TrimSpace(cl.Kubectl("-n", ns, "get", "pod", "t-port49d-0", "-o", "jsonpath={.spec.hostNetwork}"))
	if hn != "true" {
		t.Fatalf("the pod is not on the host network: %q", hn)
	}
	l82Row(cell, "the pod's spec.hostNetwork", hn)
	l82Row(cell, "the namespace's Pod Security level for this cell only", "privileged (the chart's is baseline)")
	time.Sleep(3 * time.Second)
	r.record(cell, r.dial(t, r.addrs[node]+":49"), r.addrs[node]+":49 (the pod's own port on its node)")
}
