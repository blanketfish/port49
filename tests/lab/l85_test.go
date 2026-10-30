//go:build lab

package lab

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	kindstack "github.com/rhwendt/port49/tests/kind"
	"github.com/rhwendt/port49/tests/kind/kindtest"
	"github.com/rhwendt/port49/tests/shapes/l82"
	"github.com/rhwendt/port49/tests/shapes/l85"
	"github.com/rhwendt/port49/tests/shapes/shapetest"
)

// L85's fixed names and addresses. The device network and the anycast address are private ranges
// outside the kind network's, so that the only route to the address is the router's.
const (
	l85DevNet    = "port49l85dev"
	l85FRR       = "port49l85-frr"
	l85Client    = "port49l85-client"
	l85DevCIDR   = "172.31.85.0/24"
	l85FRRDev    = "172.31.85.2"
	l85ClientIP  = "172.31.85.10"
	l85VIP       = "10.85.85.1"
	l85FRRAS     = 64512
	l85MetalLBAS = 64500
	// FRR is pinned by digest (the manifest list of the tag); MetalLB by its chart's sha256.
	l85FRRImage = "quay.io/frrouting/frr:10.5.3@sha256:37b42d2b340c322edc5f20dc4598373adb6e813e95cc9d4a18f64f9a37c98a4c"
)

// TestL85 measures spec §15 L85: MetalLB in BGP mode as an anycast address for port49d, on kind with
// an FRR router. `make lab-l85` runs it, in CI only (see TestL82). The cluster has a control plane
// and three workers; port49d has two pods, so one worker must not advertise. FRR runs in a container
// on the kind network, peers with every node over eBGP and forwards over equal paths. The device is a
// container on a second network behind FRR, whose only route to the address is FRR, and nodes route
// the device network back through FRR; its client is tests/lab/l85client, copied in. The chart is
// installed with the TACACS+ Service as a LoadBalancer with externalTrafficPolicy: Local and
// MetalLB's address annotation, by values alone: the chart's own anycast option does not exist until
// all four cells pass (spec §13 decision 54 ruling 12).
//
//	(a) a login from the device's own address passes (port49d admits by source address, so it saw
//	    that address) and the router's own address, not the device's, is refused
//	(b) the router's next hops for the address are exactly the nodes with a ready port49d pod
//	(c) a pod deleted: the withdrawal time; four single-connection sessions and a per-transaction
//	    client are watched; PASS iff withdrawn within 10 s and the next login passes
//	(d) a rolling restart with one login a second: PASS iff none fails past one retry
//
// A FAIL is a measured answer; a cell that could not be measured is NOT RUN and fails the test. The
// results are an artifact that will be public. The device's key is the stack's and the login token
// is minted for the run; both travel on stdin and are never printed.
func TestL85(t *testing.T) {
	shapetest.RefuseOnKeyHost(t)
	out := os.Getenv("PORT49_LAB_OUT")
	if out == "" {
		out = t.TempDir()
	}
	cells := []l82.Cell{{ID: "a"}, {ID: "b"}, {ID: "c"}, {ID: "d"}}
	env := l85Env(t)
	defer func() {
		text, err := l85.Results(*env, cells)
		if err != nil {
			t.Errorf("INVALID: %v", err)
			return
		}
		if err := os.MkdirAll(out, 0o755); err != nil {
			t.Errorf("INVALID: %v", err)
			return
		}
		if err := os.WriteFile(filepath.Join(out, "l85-results.md"), []byte(text), 0o644); err != nil {
			t.Errorf("INVALID: %v", err)
		}
		if err := l82.Save(filepath.Join(out, "l85-cells.json"), cells); err != nil {
			t.Errorf("INVALID: %v", err)
		}
		for _, c := range cells {
			t.Logf("L85 cell %s: %s", c.ID, l82Verdict(c))
		}
	}()

	bin := l85Build(t)
	l85Devices(t, bin)
	r := &l85Run{t: t, env: env, bin: bin}
	stack := kindstack.BringUpWith(t, "port49l85", kindstack.Options{
		KindConfig: "kind-l85.yaml", Service: l85.ServiceValues(l85VIP),
		DeviceAddr: l85ClientIP, DeviceNet: l85DevCIDR, Before: r.before,
	})
	r.stack = stack
	broker := stack.Forward("svc/"+stack.Release()+"-broker", 8443)
	r.mint = stack.Mint(broker)
	key, err := os.ReadFile(stack.PKIFile("keys/tacacs_v1"))
	if err != nil {
		t.Fatal(err)
	}
	r.key = key

	stack.Run(t, "b_nodes_advertising", func(t *testing.T) { r.cellB(t, &cells[1]) })
	stack.Run(t, "a_source_address", func(t *testing.T) { r.cellA(t, &cells[0]) })
	stack.Run(t, "c_pod_deleted", func(t *testing.T) { r.cellC(t, &cells[2]) })
	stack.Run(t, "d_rolling_restart", func(t *testing.T) { r.cellD(t, &cells[3]) })
}

// l85Run is the lab's state: the stack, the router's address on the kind network and the device's
// credentials.
type l85Run struct {
	t       *testing.T
	env     *l85.Env
	stack   *kindstack.Stack
	frrKind string            // FRR's address on the kind network
	nodes   map[string]string // node name by address
	mint    func() string
	key     []byte
	bin     string // the device client, linux
}

func l85Docker(t *testing.T, stdin string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command("docker", args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var o, e bytes.Buffer
	cmd.Stdout, cmd.Stderr = &o, &e
	if err := cmd.Run(); err != nil {
		return o.String(), fmt.Errorf("docker %s: %w\n%s", args[0], err, kindtest.Filter(e.String()))
	}
	return o.String(), nil
}

// l85Build is the device client for linux, built static; its path is returned.
func l85Build(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "l85client")
	cmd := exec.Command("go", "build", "-o", p, "./tests/lab/l85client")
	cmd.Dir = kindtest.Root()
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+runtime.GOARCH)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building the device client: %v\n%s", err, out)
	}
	return p
}

// l85Devices makes the device network and the device, behind where FRR will be. Whatever the result,
// the two containers and the network are removed afterwards, by their fixed names.
func l85Devices(t *testing.T, bin string) {
	t.Helper()
	remove := func() {
		for _, c := range []string{l85FRR, l85Client} {
			exec.Command("docker", "rm", "-f", c).Run()
		}
		exec.Command("docker", "network", "rm", l85DevNet).Run()
	}
	remove()
	t.Cleanup(remove)
	if out, err := l85Docker(t, "", "network", "create", "--subnet", l85DevCIDR, l85DevNet); err != nil {
		t.Fatalf("creating the device network: %v\n%s", err, out)
	}
	if _, err := l85Docker(t, "", "run", "-d", "--name", l85Client, "--network", l85DevNet, "--ip", l85ClientIP,
		"--cap-add", "NET_ADMIN", l82Alpine, "sleep", "3600"); err != nil {
		t.Fatalf("starting the device: %v", err)
	}
	if _, err := l85Docker(t, "", "cp", bin, l85Client+":/l85client"); err != nil {
		t.Fatal(err)
	}
}

func l85Env(t *testing.T) *l85.Env {
	t.Helper()
	e := l82Env(t)
	mem := l82Run("sh", "-c", `awk '/MemTotal/ {printf "%.0f GB", $2/1048576}' /proc/meminfo`)
	return &l85.Env{Date: e.Date, Runner: fmt.Sprintf("%s, %d vCPU, %s memory", e.Runner, runtime.NumCPU(), mem), Run: e.Run,
		Docker: e.Docker, Kernel: e.Kernel, Kind: e.Kind, NodeImage: e.NodeImage, Kubectl: e.Kubectl, Helm: e.Helm,
		MetalLBChart: os.Getenv("METALLB_CHART_VERSION"), VIP: l85VIP}
}

// before is the stack's Before: MetalLB, the router and the routes, in place before the chart.
func (r *l85Run) before(cl *kindtest.Cluster, subnet, gateway string) {
	t := r.t
	t.Helper()
	cmd := exec.Command(kindtest.Bin(t, "HELM_BIN"), "--kubeconfig", cl.Kubeconfig, "--kube-context", cl.Context(),
		"upgrade", "--install", "metallb", kindtest.Bin(t, "METALLB_CHART"), "-n", "metallb-system", "--create-namespace",
		"--wait", "--timeout", "8m")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("helm install of MetalLB: %v\n%s", err, kindtest.Filter(string(out)))
	}
	img, err := cl.KubectlTry("", "-n", "metallb-system", "get", "deploy", "metallb-controller", "-o", "jsonpath={.spec.template.spec.containers[0].image}")
	r.env.MetalLB = l83Tag(img, err)

	// FRR: on the device network first, then the kind network. It forwards, and hashes equal paths by
	// the connection's ports.
	if _, err := l85Docker(t, "", "run", "-d", "--name", l85FRR, "--network", l85DevNet, "--ip", l85FRRDev,
		"--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW", "--cap-add", "SYS_ADMIN",
		"--sysctl", "net.ipv4.ip_forward=1", "--sysctl", "net.ipv4.fib_multipath_hash_policy=1", l85FRRImage); err != nil {
		t.Fatalf("starting FRR: %v", err)
	}
	if _, err := l85Docker(t, "", "network", "connect", "kind", l85FRR); err != nil {
		t.Fatalf("connecting FRR to the kind network: %v", err)
	}
	if _, err := l85Docker(t, "", "cp", r.bin, l85FRR+":/l85client"); err != nil {
		t.Fatal(err)
	}
	pfx := netip.MustParsePrefix(subnet)
	addrs, err := l85Docker(t, "", "exec", l85FRR, "ip", "-4", "-o", "addr", "show")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range strings.Fields(addrs) {
		if a, err := netip.ParsePrefix(f); err == nil && pfx.Contains(a.Addr()) {
			r.frrKind = a.Addr().String()
		}
	}
	if r.frrKind == "" {
		t.Fatalf("FRR has no address in the kind network %s", subnet)
	}
	if v, err := l85Docker(t, "", "exec", l85FRR, "vtysh", "-c", "show version"); err == nil {
		r.env.FRR = strings.TrimSpace(strings.SplitN(v, "\n", 2)[0])
	}

	// every node: its name and address, a route back to the device network through FRR
	list := cl.Kubectl("get", "nodes", "-o", `go-template={{range .items}}{{.metadata.name}} {{range .status.addresses}}{{if eq .type "InternalIP"}}{{.address}}{{end}}{{end}}{{"\n"}}{{end}}`)
	r.nodes = map[string]string{}
	var ips []string
	for _, ln := range strings.Split(strings.TrimSpace(list), "\n") {
		f := strings.Fields(ln)
		if len(f) != 2 {
			t.Fatalf("a node line has %d fields", len(f))
		}
		r.nodes[f[1]] = f[0]
		ips = append(ips, f[1])
		if _, err := l85Docker(t, "", "exec", f[0], "ip", "route", "replace", l85DevCIDR, "via", r.frrKind); err != nil {
			t.Fatalf("routing the device network through FRR on %s: %v", f[0], err)
		}
	}
	sort.Strings(ips)
	// FRR may still be starting its daemons
	shapetest.WaitFor(t, "FRR's vtysh", 2*time.Minute, func() bool {
		_, err := l85Docker(t, "", "exec", l85FRR, "vtysh", "-c", "show bgp summary")
		return err == nil
	})
	if out, err := l85Docker(t, l85.FRRConfig(l85FRRAS, l85MetalLBAS, ips), "exec", "-i", l85FRR, "vtysh"); err != nil {
		t.Fatalf("configuring FRR: %v\n%s", err, out)
	}
	// the device sends everything for the address to FRR
	if _, err := l85Docker(t, "", "exec", l85Client, "ip", "route", "replace", "default", "via", l85FRRDev); err != nil {
		t.Fatalf("the device's default route: %v", err)
	}

	docs, err := l85.MetalLB(l85VIP, r.frrKind, l85MetalLBAS, l85FRRAS)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range docs {
		// the controller's webhook takes a moment after its pods are Ready
		shapetest.WaitFor(t, "a MetalLB resource to be accepted", 3*time.Minute, func() bool {
			_, err := cl.KubectlTry(string(d), "apply", "-f", "-")
			return err == nil
		})
	}
}

// client runs the device client in container with the key and a fresh token on stdin.
func (r *l85Run) creds() string {
	b, err := json.Marshal(map[string]string{"key": string(r.key), "token": r.mint(), "user": "alice"})
	if err != nil {
		r.t.Fatal(err)
	}
	return string(b)
}

// client is `l85client args` in container, to completion.
func (r *l85Run) client(container string, args ...string) (string, error) {
	return l85Docker(r.t, r.creds(), append([]string{"exec", "-i", container, "/l85client"}, args...)...)
}

// background starts the client and returns a function that stops it and returns what it printed. A
// last line cut off by the stop is dropped.
func (r *l85Run) background(container string, args ...string) func() string {
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, "docker", append([]string{"exec", "-i", container, "/l85client"}, args...)...)
	cmd.Stdin = strings.NewReader(r.creds())
	var out bytes.Buffer
	var mu sync.Mutex
	cmd.Stdout = lockedWriter{&out, &mu}
	if err := cmd.Start(); err != nil {
		cancel()
		r.t.Fatalf("starting the device client: %v", err)
	}
	done := make(chan struct{})
	go func() { cmd.Wait(); close(done) }()
	return func() string {
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			cancel()
			<-done
		}
		mu.Lock()
		defer mu.Unlock()
		s := out.String()
		if i := strings.LastIndex(s, "\n"); i >= 0 {
			return s[:i+1]
		}
		return ""
	}
}

type lockedWriter struct {
	b  *bytes.Buffer
	mu *sync.Mutex
}

func (w lockedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(p)
}

func (r *l85Run) vtysh(args ...string) string {
	out, _ := l85Docker(r.t, "", append([]string{"exec", l85FRR, "vtysh"}, args...)...)
	return out
}

// bgpHops are FRR's next hops for the address, from its BGP table.
func (r *l85Run) bgpHops() []string {
	h, err := l85.ParseBGPNextHops(r.vtysh("-c", "show ip bgp "+l85VIP+"/32 json"))
	if err != nil {
		return nil
	}
	return h
}

// readyNodes are the addresses of the nodes running a ready port49d pod.
func (r *l85Run) readyNodes() []string {
	var out []string
	for _, p := range []string{"t-port49d-0", "t-port49d-1"} {
		if pod, err := r.stack.Cluster().Pod(r.stack.Namespace(), p); err == nil && pod.Ready && pod.HostIP != "" {
			out = append(out, pod.HostIP)
		}
	}
	sort.Strings(out)
	return out
}

func (r *l85Run) names(ips []string) string {
	var out []string
	for _, ip := range ips {
		out = append(out, ip+" ("+r.nodes[ip]+")")
	}
	return strings.Join(out, ", ")
}

// settle waits for FRR's next hops to be exactly the ready pods' nodes.
func (r *l85Run) settle(t *testing.T, within time.Duration) ([]string, []string) {
	t.Helper()
	var hops, ready []string
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		hops, ready = r.bgpHops(), r.readyNodes()
		if l85.JudgeNodes(hops, ready) == l82.Pass && len(ready) == 2 {
			break
		}
		time.Sleep(2 * time.Second)
	}
	return hops, ready
}

// Cell (b): the next hops FRR holds are the nodes running a ready pod, and no others.
func (r *l85Run) cellB(t *testing.T, cell *l82.Cell) {
	hops, ready := r.settle(t, 5*time.Minute)
	l82Row(cell, "nodes running a ready port49d pod", r.names(ready))
	l82Row(cell, "FRR's next hops for "+l85VIP+" (show ip bgp)", r.names(hops))
	if rt, err := l85.ParseRouteNextHops(r.vtysh("-c", "show ip route "+l85VIP+"/32 json")); err == nil {
		l82Row(cell, "FRR's forwarding next hops (show ip route)", r.names(rt))
	}
	l82Row(cell, "worker nodes in the cluster", fmt.Sprint(len(r.nodes)-1))
	cell.Verdict = l85.JudgeNodes(hops, ready)
}

// Cell (a): the device's own address is admitted, another address is not.
func (r *l85Run) cellA(t *testing.T, cell *l82.Cell) {
	addr := l85VIP + ":49"
	own, err := r.client(l85Client, "probe", "-addr", addr)
	if err != nil {
		t.Fatalf("running the device client: %v", err)
	}
	own = strings.TrimSpace(own)
	l82Row(cell, "a login from the device, "+l85ClientIP+", to the address", own)
	// the router's own source, which the inventory's key group does not admit
	stranger, err := r.client(l85FRR, "probe", "-addr", addr)
	stranger = strings.TrimSpace(stranger)
	l82Row(cell, "a login from the router's own address, which the inventory does not name", stranger)
	if err != nil {
		t.Fatal(err)
	}
	cell.Verdict = l85.JudgeSource(own == "pass", stranger == "fail:reset" || stranger == "fail:closed")
}

// Cell (c): four single-connection sessions and a per-transaction loop run while a pod is deleted.
func (r *l85Run) cellC(t *testing.T, cell *l82.Cell) {
	cl, ns := r.stack.Cluster(), r.stack.Namespace()
	hops, _ := r.settle(t, 3*time.Minute)
	victim, err := cl.Pod(ns, "t-port49d-0")
	if err != nil || victim.HostIP == "" {
		t.Fatalf("t-port49d-0 has no node: %v", err)
	}
	addr := l85VIP + ":49"
	var stops []func() string
	for i := 0; i < 4; i++ {
		stops = append(stops, r.background(l85Client, "session", "-addr", addr, "-for", "75s"))
	}
	loop := r.background(l85Client, "loop", "-addr", addr, "-for", "75s")
	time.Sleep(5 * time.Second)

	t0 := time.Now()
	cl.Kubectl("-n", ns, "delete", "pod", "t-port49d-0", "--wait=false")
	var w l85.Withdrawal
	for time.Since(t0) < 60*time.Second {
		if !contains(r.bgpHops(), victim.HostIP) {
			w.Withdrawn, w.Delay = true, time.Since(t0)
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if w.Withdrawn {
		l82Row(cell, "delay from the pod's deletion to its node leaving FRR's next hops", w.Delay.Round(100*time.Millisecond).String())
		got, _ := r.client(l85Client, "probe", "-addr", addr)
		got = strings.TrimSpace(got)
		l82Row(cell, "a per-transaction client's next login, after the withdrawal", got)
		w.NextLoginPassed = got == "pass"
	} else {
		l82Row(cell, "the deleted pod's node in FRR's next hops", "still there after 1m0s")
	}
	l82Row(cell, "next hops before the deletion", r.names(hops))
	l82Row(cell, "the deleted pod's node", r.names([]string{victim.HostIP}))

	ended := map[string]int{}
	for _, stop := range stops {
		s, err := l85.ParseSession(stop())
		if err != nil {
			l82Row(cell, "a single-connection session", "output not understood")
			continue
		}
		ended[fmt.Sprintf("%s after %d logins", s.End, s.Logins)]++
	}
	var keys []string
	for k := range ended {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		l82Row(cell, "single-connection sessions (4 started) that ended", fmt.Sprintf("%d: %s", ended[k], k))
	}
	if ls, err := l85.ParseLoop(loop()); err == nil {
		l82Row(cell, "per-transaction logins in the same window", fmt.Sprintf("%d: %d passed first, %d on the retry, %d failed past it", ls.Seconds, ls.PassFirst, ls.PassOnRetry, ls.FailedPastRetry))
	}
	cell.Verdict = l85.JudgeWithdrawal(w)
	// the pod comes back and its node advertises again before the next cell
	r.settle(t, 4*time.Minute)
}

// Cell (d): a rolling restart with one login a second from the device.
func (r *l85Run) cellD(t *testing.T, cell *l82.Cell) {
	cl, ns := r.stack.Cluster(), r.stack.Namespace()
	r.settle(t, 3*time.Minute)
	stop := r.background(l85Client, "loop", "-addr", l85VIP+":49", "-for", "900s")
	time.Sleep(5 * time.Second)
	t0 := time.Now()
	cl.Kubectl("-n", ns, "rollout", "restart", "statefulset/"+r.stack.Release()+"-port49d")
	_, rerr := cl.KubectlTry("", "-n", ns, "rollout", "status", "statefulset/"+r.stack.Release()+"-port49d", "--timeout=8m")
	r.settle(t, 3*time.Minute)
	time.Sleep(10 * time.Second)
	took := time.Since(t0)
	ls, err := l85.ParseLoop(stop())
	if err != nil {
		t.Fatalf("the device client's output: %v", err)
	}
	if rerr != nil {
		l82Row(cell, "the rollout", "did not finish in 8m0s")
	}
	l82Row(cell, "from the restart to the pods Ready and the address's next hops settled", took.Round(time.Second).String())
	l82Row(cell, "logins, one a second", fmt.Sprint(ls.Seconds))
	l82Row(cell, "passed on the first attempt", fmt.Sprint(ls.PassFirst))
	l82Row(cell, "passed on the one retry", fmt.Sprint(ls.PassOnRetry))
	l82Row(cell, "failed past the retry", fmt.Sprint(ls.FailedPastRetry))
	cell.Verdict = l85.JudgeRollout(ls)
}
