//go:build kind

// Package kind is the Kubernetes shape's smoke (plan 12b, Task 11): deploy/helm/port49 on a kind
// cluster, with port49's own three-member etcd. `make kind-smoke` runs it; `go test ./...` never
// builds it. UNVERIFIED until kind runs: nothing in this package has been run; the unit tests of
// what it uses (kindtest, testpki.WriteKind) are what has. A cell the cluster cannot answer is a
// failure naming it, never a skip.
//
// Secrets are made with --from-file only, from files in a 0700 temp directory, and no step prints
// one: a failure names the Secret or the field, and the dump goes through tests/qual/secret-filter.sh
// and never reads the vault namespace.
package kind

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/tacacs/wire"
	"github.com/rhwendt/port49/internal/testpki"
	"github.com/rhwendt/port49/tests/kind/kindtest"
	"github.com/rhwendt/port49/tests/shapes/shapetest"
)

const (
	ns      = "port49"
	release = "t"
	scName  = "port49-fsgroup"
)

// smoke carries the cluster and the files every cell reads.
type smoke struct {
	t         *testing.T
	c         *kindtest.Cluster
	root      string // the repository
	pki       string // testpki.WriteKind's directory
	chart     string
	helm      string
	policy    string
	gateway   string // the kind network's gateway: the source a host-side device presents
	subnet    string
	values    string // the values file helm installs with
	brokerDir string // testpki.WriteKind's broker/ directory: the lab CA and the people's certificates
}

// oldRoot is the red run of the fsGroup cell: KIND_OLD_ROOT=1 installs the first design's chart.
func oldRoot() bool { return os.Getenv("KIND_OLD_ROOT") == "1" }

func (s *smoke) helmRun(extra ...string) string {
	s.t.Helper()
	args := append([]string{"--kubeconfig", s.c.Kubeconfig, "--kube-context", s.c.Context(), "-n", ns}, extra...)
	out, err := exec.Command(kindtest.Bin(s.t, "HELM_BIN"), args...).CombinedOutput()
	if err != nil {
		s.t.Fatalf("helm %s: %v\n%s", strings.Join(extra[:1], " "), err, kindtest.Filter(string(out)))
	}
	return string(out)
}

func (s *smoke) install(extra ...string) {
	s.t.Helper()
	args := []string{"upgrade", "--install", release, s.chart, "-f", s.values,
		"--set-file", "policy=" + s.policy, "--set-file", "inventory=" + filepath.Join(filepath.Dir(s.policy), "inventory.yaml"),
		"--wait=false"}
	if oldRoot() {
		// The fsGroup cell's red run: the first design's 2755 volume root, by a post-renderer that
		// lives in tests/kind/cmd/oldroot and is never part of the chart.
		args = append(args, "--post-renderer", kindtest.Bin(s.t, "OLDROOT_BIN"))
	}
	s.helmRun(append(args, extra...)...)
}

// secretFrom creates a Secret from files only: no value is ever on a command line.
func (s *smoke) secretFrom(name string, files map[string]string) {
	s.t.Helper()
	args := []string{"-n", ns, "create", "secret", "generic", name}
	for k, p := range files {
		args = append(args, "--from-file="+k+"="+p)
	}
	s.c.Kubectl(args...)
}

func (s *smoke) pkiFile(rel string) string { return filepath.Join(s.pki, rel) }

func (s *smoke) writeTemp(name, body string, mode os.FileMode) string {
	s.t.Helper()
	p := filepath.Join(s.t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), mode); err != nil {
		s.t.Fatal(err)
	}
	return p
}

// dockerKindNetwork reads the kind network's IPv4 subnet and gateway.
func dockerKindNetwork(t *testing.T) (subnet, gateway string) {
	t.Helper()
	out, err := exec.Command("docker", "network", "inspect", "kind", "-f",
		`{{range .IPAM.Config}}{{.Subnet}} {{.Gateway}}{{"\n"}}{{end}}`).Output()
	if err != nil {
		t.Fatalf("docker network inspect kind: %v", err)
	}
	for _, l := range strings.Split(string(out), "\n") {
		f := strings.Fields(l)
		if len(f) == 2 {
			if ip := net.ParseIP(f[1]); ip != nil && ip.To4() != nil {
				return f[0], f[1]
			}
		}
	}
	t.Fatalf("the kind network has no IPv4 gateway: %q", out)
	return "", ""
}

// debugPod runs one root pod on pvc's volume with sh -c script, waits for it to finish, returns
// its log, and always deletes it. The image is the pinned alpine the chart's init uses.
func (s *smoke) debugPod(name, pvc, script string, readOnly bool) string {
	s.t.Helper()
	spec := fmt.Sprintf(`{"apiVersion":"v1","kind":"Pod","metadata":{"name":%q},"spec":{"restartPolicy":"Never",
"containers":[{"name":"x","image":"alpine:3.22@sha256:2e0b81d60597f449baa56dc25d355367869d2dca4cd57e866f1e2b52af3eb55f",
"command":["sh","-c",%q],"volumeMounts":[{"name":"v","mountPath":"/v","readOnly":%t}]}],
"volumes":[{"name":"v","persistentVolumeClaim":{"claimName":%q}}]}}`, name, script, readOnly, pvc)
	s.t.Cleanup(func() { s.c.KubectlTry("", "-n", ns, "delete", "pod", name, "--ignore-not-found", "--wait=false") })
	s.c.KubectlTry("", "-n", ns, "delete", "pod", name, "--ignore-not-found")
	if _, err := s.c.KubectlTry(spec, "-n", ns, "apply", "-f", "-"); err != nil {
		s.t.Fatal(err)
	}
	shapetest.WaitFor(s.t, "debug pod "+name+" to finish", 3*time.Minute, func() bool {
		p, err := s.c.Pod(ns, name)
		return err == nil && (p.Phase == "Succeeded" || p.Phase == "Failed")
	})
	out := s.c.Kubectl("-n", ns, "logs", name)
	s.c.KubectlTry("", "-n", ns, "delete", "pod", name, "--wait=false")
	return out
}

func (s *smoke) statOn(pvc string, paths ...string) []kindtest.Stat {
	s.t.Helper()
	script := "stat -c '%a %u %g %n'"
	for _, p := range paths {
		script += " " + p
	}
	out := s.debugPod("stat-"+pvc, pvc, script, true)
	st, err := kindtest.ParseStat(out)
	if err != nil {
		s.t.Fatalf("stat on %s: %v", pvc, err)
	}
	return st
}

func sha(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func TestKindSmoke(t *testing.T) {
	root := kindtest.Root()
	s := &smoke{t: t, root: root, chart: filepath.Join(root, "deploy", "helm", "port49"), helm: "helm"}
	s.subnet, s.gateway = dockerKindNetwork(t)
	s.pki = t.TempDir()
	if err := testpki.WriteKind(s.pki, ns, 3, "alice@example.com", time.Now()); err != nil {
		t.Fatal(err)
	}
	brokerDir := filepath.Join(s.pki, "broker")
	s.brokerDir = brokerDir
	rootsFile, subject := shapetest.AdminSetup(t, brokerDir)

	s.c = kindtest.Up(t, "port49smoke")
	for _, img := range []string{"port49:dev", "port49-setup:dev"} {
		if out, err := exec.Command(kindtest.Bin(t, "KIND_BIN"), "load", "docker-image", img, "--name", s.c.Name).CombinedOutput(); err != nil {
			t.Fatalf("kind load %s: %v\n%s", img, err, kindtest.Filter(string(out)))
		}
	}

	// A StorageClass whose volumes are `local` PVs, not hostPath: the kubelet applies fsGroup to a
	// local volume (volume_linux.go via local.go's SetUp) and never to kind's default hostPath class
	// (host_path.go), so only this class can show the two-generation cell red or green.
	s.c.Apply(`apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: ` + scName + `
  annotations: {defaultVolumeType: local}
provisioner: rancher.io/local-path
volumeBindingMode: WaitForFirstConsumer
reclaimPolicy: Delete
`)
	s.c.Kubectl("create", "namespace", ns)
	s.c.Kubectl("label", "namespace", ns, "pod-security.kubernetes.io/enforce=baseline", "--overwrite")

	// The Secrets, from files only: one etcd identity each, the CA certificate alone, the keys.
	etcdTLS := map[string]string{"ca.crt": s.pkiFile("etcd/ca.pem")}
	for i := 0; i < 3; i++ {
		etcdTLS[fmt.Sprintf("etcd-%d.crt", i)] = s.pkiFile(fmt.Sprintf("etcd/etcd-%d.pem", i))
		etcdTLS[fmt.Sprintf("etcd-%d.key", i)] = s.pkiFile(fmt.Sprintf("etcd/etcd-%d-key.pem", i))
	}
	s.secretFrom("etcd-tls", etcdTLS)
	s.secretFrom("port49-etcd-ca", map[string]string{"ca.crt": s.pkiFile("etcd/ca.pem")})
	s.secretFrom("port49-etcd-port49d", map[string]string{"tls.crt": s.pkiFile("etcd/port49d.pem"), "tls.key": s.pkiFile("etcd/port49d-key.pem")})
	s.secretFrom("port49-etcd-broker", map[string]string{"tls.crt": s.pkiFile("etcd/port49-broker.pem"), "tls.key": s.pkiFile("etcd/port49-broker-key.pem")})
	s.secretFrom("port49-etcd-root", map[string]string{"ca.crt": s.pkiFile("etcd/ca.pem"), "tls.crt": s.pkiFile("etcd/root.pem"), "tls.key": s.pkiFile("etcd/root-key.pem")})
	s.secretFrom("port49-device-keys", map[string]string{"tacacs_v1": s.pkiFile("keys/tacacs_v1")})
	s.secretFrom("port49-encryption", map[string]string{"encryption.key": s.pkiFile("secrets/port49d-encryption.key")})
	s.secretFrom("port49-broker-tls", map[string]string{"tls.crt": filepath.Join(brokerDir, testpki.LabServerCert),
		"tls.key": filepath.Join(brokerDir, testpki.LabServerKey), "ca.crt": filepath.Join(brokerDir, testpki.LabCA)})

	// The cluster's CA beside the attestation roots, in the one ConfigMap the chart mounts: the
	// broker's k8s verifier reads the API server's keys over it (cell 8).
	clusterCA := s.clusterCA()
	s.c.Kubectl("-n", ns, "create", "configmap", "port49-attestation",
		"--from-file=attestation-roots.pem="+rootsFile, "--from-file=cluster-ca.pem="+clusterCA)

	// etcd: examples/etcd with its namespace made port49 (the PKI's SANs name .port49.svc).
	s.applyExample("examples/etcd/service.yaml", nil)
	s.applyExample("examples/etcd/statefulset.yaml", nil)
	for i := 0; i < 3; i++ {
		s.c.WaitReady(ns, fmt.Sprintf("etcd-%d", i), 3*time.Minute)
	}

	// The policy and the inventory. The device is the host, which the kind network presents as its gateway.
	cfgDir := t.TempDir()
	pol := readFile(t, filepath.Join(root, "deploy", "compose", "config", "policy.yaml"))
	pol = strings.ReplaceAll(pol, "172.30.49.0/24", s.subnet)
	pol = shapetest.AdminPolicy(t, pol, subject+"\n  - {name: svc_backup, identity: [\"system:serviceaccount:"+ns+":oxidized\"], username: svc-backup, token_ttl: 900s}")
	pol = strings.Replace(pol, "\ngrants:\n", "\ngrants:\n  - {subject: svc_backup, scope: all_devices, roles: [network_admin]}\n", 1)
	s.policy = filepath.Join(cfgDir, "policy.yaml")
	writeFile(t, s.policy, pol)
	writeFile(t, filepath.Join(cfgDir, "inventory.yaml"),
		"devices:\n  - {name: smoke1, platform: arista_eos, addresses: ["+s.gateway+"]}\n")
	endpoints := ""
	for i := 0; i < 3; i++ {
		endpoints += fmt.Sprintf("    - https://etcd-%d.etcd.%s.svc:2379\n", i, ns)
	}
	// The cluster's issuer, as its tokens carry it (kind's default), and the in-cluster API address.
	s.values = filepath.Join(cfgDir, "values.yaml")
	writeFile(t, s.values, `image: {repository: port49, tag: dev, pullPolicy: Never}
keys: {existingSecret: port49-device-keys}
encryption: {id: c1, existingSecret: port49-encryption}
broker:
  tls: {existingSecret: port49-broker-tls}
  attestationRootsConfigMap: port49-attestation
  state: {storageClassName: `+scName+`}
port49d:
  spool: {storageClassName: `+scName+`}
etcd:
  endpoints:
`+endpoints+`  caSecret: port49-etcd-ca
  port49d: {existingSecret: port49-etcd-port49d}
  broker: {existingSecret: port49-etcd-broker}
service: {type: NodePort}
issuerDiscovery: {enabled: true}
config:
  broker:
    broker:
      certificate_status: {disabled: true}
      identity:
        machines:
          - {type: k8s, cluster: kind, issuer: https://kubernetes.default.svc.cluster.local,
             jwks: https://kubernetes.default.svc.cluster.local/openid/v1/jwks,
             ca_file: /etc/port49/attestation/cluster-ca.pem, audience: port49, namespaces: [`+ns+`]}
`)
	s.install()

	// store-roles from the rendered configs, in one pod that mounts what the broker's does, then
	// etcd-init applies them. The roles are etcdctl commands naming roles and key prefixes.
	s.applyRoles()
	s.c.Kubectl("-n", ns, "wait", "--for=condition=complete", "job/etcd-init", "--timeout=300s")

	if oldRoot() {
		s.cellFSGroupRed()
		return
	}

	// The issuing CA, once, then every broker is the same CA (cell 6 asserts it).
	script := filepath.Join(s.chart, "scripts", "copy-issuer.sh")
	cmd := exec.Command("bash", script, ns, release)
	cmd.Env = append(os.Environ(), "KUBECONFIG="+s.c.Kubeconfig, "PATH="+filepath.Dir(kindtest.Bin(t, "KUBECTL_BIN"))+":"+os.Getenv("PATH"))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("copy-issuer.sh: %v\n%s", err, kindtest.Filter(string(out)))
	}
	for _, p := range []string{"t-port49d-0", "t-port49d-1", "t-broker-0", "t-broker-1"} {
		s.c.WaitReady(ns, p, 4*time.Minute)
	}

	// Each cell is a subtest whose own t every helper reports to.
	cell := func(name string, f func(*testing.T)) {
		t.Run(name, func(t *testing.T) {
			prev, prevC := s.t, s.c.T
			s.t, s.c.T = t, t
			defer func() { s.t, s.c.T = prev, prevC }()
			f(t)
		})
	}
	cell("login", s.cellLogin)
	cell("restart", s.cellRestart)
	cell("rotate", s.cellRotate)
	cell("subpath", s.cellSubPath)
	cell("issuer_copy", s.cellIssuerCopy)
	cell("revoke", func(t *testing.T) { s.cellRevoke(brokerDir) })
	cell("backups", s.cellBackups)
	cell("workload_cronjob", s.cellWorkload)
	cell("fsgroup_generations", s.cellFSGroup)
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func writeFile(t *testing.T, p, body string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (s *smoke) clusterCA() string {
	out := s.c.Kubectl("config", "view", "--raw", "--minify", "-o", "jsonpath={.clusters[0].cluster.certificate-authority-data}")
	pem, err := base64.StdEncoding.DecodeString(strings.TrimSpace(out))
	if err != nil || len(pem) == 0 {
		s.t.Fatal("the kubeconfig holds no cluster CA")
	}
	return s.writeTemp("cluster-ca.pem", string(pem), 0o600)
}

// applyExample applies a chart example with port49-etcd made the smoke's namespace and the other
// replacements given (old -> new).
func (s *smoke) applyExample(rel string, repl map[string]string) {
	s.t.Helper()
	body := readFile(s.t, filepath.Join(s.chart, rel))
	body = strings.ReplaceAll(body, "port49-etcd.svc", ns+".svc")
	body = strings.ReplaceAll(body, "namespace: port49-etcd", "namespace: "+ns)
	for o, n := range repl {
		body = strings.ReplaceAll(body, o, n)
	}
	s.c.Apply(body)
}

// applyRoles makes the ConfigMap port49-etcd-roles from `port49d store-roles` run in a pod that
// mounts the rendered configs and the secrets the broker's and port49d's pods do, then applies
// examples/etcd/etcd-init-job.yaml.
func (s *smoke) applyRoles() {
	s.t.Helper()
	pod := `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"store-roles"},"spec":{"restartPolicy":"Never",
"securityContext":{"runAsUser":65532,"runAsGroup":65532,"fsGroup":65532},
"containers":[{"name":"x","image":"port49:dev","imagePullPolicy":"Never","command":["/usr/local/bin/port49d"],
"args":["store-roles","--config","/etc/port49/config/port49d.yaml","--broker-config","/etc/port49/broker-config/port49-broker.yaml"],
"volumeMounts":[{"name":"d","mountPath":"/etc/port49/config"},{"name":"b","mountPath":"/etc/port49/broker-config"},
{"name":"enc","mountPath":"/etc/port49/secrets"},{"name":"ca","mountPath":"/etc/port49/etcd-ca"},
{"name":"ep","mountPath":"/etc/port49/etcd"},{"name":"tls","mountPath":"/etc/port49/broker"},{"name":"att","mountPath":"/etc/port49/attestation"},
{"name":"keys","mountPath":"/run/port49/keys"}]}],
"volumes":[{"name":"d","configMap":{"name":"t-port49d"}},{"name":"b","configMap":{"name":"t-broker"}},
{"name":"enc","secret":{"secretName":"port49-encryption","defaultMode":288}},{"name":"ca","secret":{"secretName":"port49-etcd-ca","defaultMode":288}},
{"name":"ep","secret":{"secretName":"port49-etcd-port49d","defaultMode":288}},{"name":"tls","secret":{"secretName":"port49-broker-tls","defaultMode":288}},
{"name":"att","configMap":{"name":"port49-attestation"}},{"name":"keys","secret":{"secretName":"port49-device-keys","defaultMode":288}}]}}`
	s.t.Cleanup(func() {
		s.c.KubectlTry("", "-n", ns, "delete", "pod", "store-roles", "--ignore-not-found", "--wait=false")
	})
	if _, err := s.c.KubectlTry(pod, "-n", ns, "apply", "-f", "-"); err != nil {
		s.t.Fatal(err)
	}
	shapetest.WaitFor(s.t, "store-roles to finish", 3*time.Minute, func() bool {
		p, err := s.c.Pod(ns, "store-roles")
		return err == nil && (p.Phase == "Succeeded" || p.Phase == "Failed")
	})
	roles := s.c.Kubectl("-n", ns, "logs", "store-roles")
	if p, _ := s.c.Pod(ns, "store-roles"); p.Phase != "Succeeded" || !strings.Contains(roles, "etcdctl") {
		s.t.Fatalf("store-roles did not produce etcdctl commands (phase %s)", p.Phase)
	}
	s.c.Kubectl("-n", ns, "create", "configmap", "port49-etcd-roles", "--from-file=roles.sh="+s.writeTemp("roles.sh", roles, 0o600))
	s.applyExample("examples/etcd/etcd-init-job.yaml", nil)
}

// target is where a device reaches the port49d pod: its node's container address and the NodePort,
// read again after every restart (a node may change, and only a node running port49d answers under
// externalTrafficPolicy: Local).
func (s *smoke) target(pod string) string {
	s.t.Helper()
	p, err := s.c.Pod(ns, pod)
	if err != nil || p.HostIP == "" {
		s.t.Fatalf("pod %s has no host address: %v", pod, err)
	}
	port := strings.TrimSpace(s.c.Kubectl("-n", ns, "get", "svc", release+"-port49d", "-o", "jsonpath={.spec.ports[0].nodePort}"))
	return net.JoinHostPort(p.HostIP, port)
}

// forward starts kubectl port-forward and returns the local address; it is stopped at cleanup.
func (s *smoke) forward(target string, remote int) string {
	s.t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		s.t.Fatal(err)
	}
	local := l.Addr().(*net.TCPAddr).Port
	l.Close()
	cmd := exec.Command(kindtest.Bin(s.t, "KUBECTL_BIN"), "--kubeconfig", s.c.Kubeconfig, "--context", s.c.Context(), "-n", ns,
		"port-forward", target, fmt.Sprintf("%d:%d", local, remote))
	if err := cmd.Start(); err != nil {
		s.t.Fatal(err)
	}
	s.t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	addr := fmt.Sprintf("127.0.0.1:%d", local)
	shapetest.WaitFor(s.t, "the port-forward to "+target, 30*time.Second, func() bool {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			c.Close()
		}
		return err == nil
	})
	return addr
}

func (s *smoke) device(pod string) shapetest.Device {
	key, err := os.ReadFile(s.pkiFile("keys/tacacs_v1"))
	if err != nil {
		s.t.Fatal(err)
	}
	return shapetest.Device{T: s.t, Addr: s.target(pod), Key: key}
}

func (s *smoke) mint(brokerAddr string) func() string {
	return func() string { return shapetest.Mint(s.t, filepath.Join(s.pki, "broker"), brokerAddr, "smoke1") }
}

// Cell 2: the login. The source is the kind network's gateway, which the inventory lists; refused
// device_unknown is L39 (b)'s question (kube-proxy rewrote it), and 12c owns that row.
func (s *smoke) cellLogin(t *testing.T) {
	brokerAddr := s.forward("svc/"+release+"-broker", 8443)
	dev := s.device("t-port49d-0")
	if st := dev.Login("alice", s.mint(brokerAddr)()); st != wire.AuthenStatusPass {
		t.Fatalf("a device login through the NodePort: status %d. If the log says device_unknown the source address was rewritten: that is L39 (b), owned by 12c", st)
	}
	logs := s.c.Kubectl("-n", ns, "logs", "t-port49d-0")
	shapetest.FloorLine(t, logs, []string{"https://etcd-0.etcd." + ns + ".svc:2379", "https://etcd-1.etcd." + ns + ".svc:2379", "https://etcd-2.etcd." + ns + ".svc:2379"})
}

// Cell 3: delete both pods, wait Ready; the next command is permitted; the broker says no
// state_dir refusal; the state directory is still 65532 65532 700 on its PVC.
func (s *smoke) cellRestart(t *testing.T) {
	brokerAddr := s.forward("svc/"+release+"-broker", 8443)
	dev := s.device("t-port49d-0")
	if st := dev.Login("alice", s.mint(brokerAddr)()); st != wire.AuthenStatusPass {
		t.Fatalf("login before the restart: %d", st)
	}
	s.c.Kubectl("-n", ns, "delete", "pod", "t-port49d-0", "t-broker-0")
	s.c.WaitReady(ns, "t-port49d-0", 4*time.Minute)
	s.c.WaitReady(ns, "t-broker-0", 4*time.Minute)
	dev = s.device("t-port49d-0") // looked up again
	if !dev.Permits("alice", "show", "version") {
		t.Fatal("the session's next command after the restart was refused")
	}
	if logs := s.c.Kubectl("-n", ns, "logs", "t-broker-0"); kindtest.StateDirRefusal.MatchString(logs) {
		t.Fatal("the restarted broker refused its state_dir")
	}
	st := s.statOn("data-t-broker-0", "/v/state")
	if err := st[0].Want("700", 65532, 65532); err != nil {
		t.Fatal(err)
	}
}

// Cell 4: add a key version with no restart, through the Secret and the policy ConfigMaps.
type kindRotator struct {
	s      *smoke
	policy []byte
}

func (r kindRotator) KeyDir() string     { return "/run/port49/keys" }
func (r kindRotator) BasePolicy() []byte { return r.policy }

func (r kindRotator) WritePolicy(p []byte) error {
	patch, err := json.Marshal(map[string]any{"data": map[string]string{"policy.yaml": string(p)}})
	if err != nil {
		return err
	}
	f := r.s.writeTemp("policy-patch.json", string(patch), 0o600)
	for _, cm := range []string{"t-port49d", "t-broker"} {
		if _, err := r.s.c.KubectlTry("", "-n", ns, "patch", "configmap", cm, "--type", "merge", "--patch-file", f); err != nil {
			return err
		}
	}
	return nil
}

func (r kindRotator) WriteKey(name string, secret []byte) error {
	patch, err := json.Marshal(map[string]any{"data": map[string]string{name: base64.StdEncoding.EncodeToString(secret)}})
	if err != nil {
		return err
	}
	f := r.s.writeTemp("key-patch.json", string(patch), 0o600)
	_, err = r.s.c.KubectlTry("", "-n", ns, "patch", "secret", "port49-device-keys", "--type", "merge", "--patch-file", f)
	return err
}

// StartedAt is the container's start time and restart count: neither may change.
func (r kindRotator) StartedAt() string {
	p, err := r.s.c.Pod(ns, "t-port49d-0")
	if err != nil {
		r.s.t.Fatal(err)
	}
	return fmt.Sprintf("%s/%d", p.StartedAt, p.Restarts)
}

func (s *smoke) cellRotate(t *testing.T) {
	brokerAddr := s.forward("svc/"+release+"-broker", 8443)
	metrics := s.forward("pod/t-port49d-0", 9049)
	dev := s.device("t-port49d-0")
	pol := []byte(readFile(t, s.policy))
	// 180 s: the kubelet's sync period plus the 30 s the key-file retry takes (L82 (b) and (d)).
	shapetest.RotateCell(t, dev, "alice", s.mint(brokerAddr), metrics, 180*time.Second, kindRotator{s: s, policy: pol})
}

// Cell 5 (L82 (c)): a subPath mount does not see a Secret's update, a whole mount does. Only the
// probe's own Secret copy is patched, never the real keys; both files are compared by sha256
// inside the pod.
func (s *smoke) cellSubPath(t *testing.T) {
	probe := s.writeTemp("probe-v1", "not-a-real-key-probe-value-1-0123", 0o600)
	s.secretFrom("port49-subpath-probe", map[string]string{"tacacs_v1": probe})
	pod := `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"subpath-probe"},"spec":{"restartPolicy":"Never",
"containers":[{"name":"x","image":"alpine:3.22@sha256:2e0b81d60597f449baa56dc25d355367869d2dca4cd57e866f1e2b52af3eb55f","command":["sleep","900"],
"volumeMounts":[{"name":"whole","mountPath":"/whole"},{"name":"whole","mountPath":"/sub/tacacs_v1","subPath":"tacacs_v1"}]}],
"volumes":[{"name":"whole","secret":{"secretName":"port49-subpath-probe"}}]}}`
	t.Cleanup(func() {
		s.c.KubectlTry("", "-n", ns, "delete", "pod", "subpath-probe", "--ignore-not-found", "--wait=false")
	})
	if _, err := s.c.KubectlTry(pod, "-n", ns, "apply", "-f", "-"); err != nil {
		t.Fatal(err)
	}
	s.c.WaitReady(ns, "subpath-probe", 3*time.Minute)
	hashes := func() (whole, sub string) {
		out := s.c.Kubectl("-n", ns, "exec", "subpath-probe", "--", "sh", "-c", "sha256sum /whole/tacacs_v1 /sub/tacacs_v1 | cut -d' ' -f1")
		f := strings.Fields(out)
		if len(f) != 2 {
			t.Fatalf("sha256sum in the probe printed %d hashes", len(f))
		}
		return f[0], f[1]
	}
	w0, s0 := hashes()
	next := base64.StdEncoding.EncodeToString([]byte("not-a-real-key-probe-value-2-0123"))
	patch := s.writeTemp("probe-patch.json", `{"data":{"tacacs_v1":"`+next+`"}}`, 0o600)
	s.c.Kubectl("-n", ns, "patch", "secret", "port49-subpath-probe", "--type", "merge", "--patch-file", patch)
	time.Sleep(180 * time.Second)
	w1, s1 := hashes()
	t.Logf("L82 (c) observation: whole mount changed %v; subPath file changed %v", w0 != w1, s0 != s1)
	if w0 == w1 {
		t.Fatal("the whole mount did not see the Secret's update in 180 s: a key version added as a file is not in force")
	}
}

// Cell 6: the issuing CA is the same on every broker's PVC, and the key is 600 65532.
func (s *smoke) cellIssuerCopy(t *testing.T) {
	var sums []string
	for _, pvc := range []string{"data-t-broker-0", "data-t-broker-1"} {
		out := s.debugPod("ca-"+pvc, pvc, "sha256sum /v/state/issuing-ca.pem | cut -d' ' -f1", true)
		sums = append(sums, strings.TrimSpace(out))
		st := s.statOn(pvc, "/v/state/issuing-ca.key")
		if err := st[0].Want("600", 65532, 65532); err != nil {
			t.Error(err)
		}
	}
	if len(sums) != 2 || sums[0] == "" || sums[0] != sums[1] {
		t.Fatalf("issuing-ca.pem differs between the brokers' volumes: %v", sums)
	}
}

// Cell 7: an unproved revoke is 401 (the roots are in a ConfigMap, the subject in the policy), then
// the break-glass revoke-offline.sh exits 0, the brokers come back, and OfflineRevoked holds.
func (s *smoke) cellRevoke(brokerDir string) {
	t := s.t
	addr := s.forward("svc/"+release+"-broker", 8443)
	const bob = "user:bob@example.com"
	shapetest.AdminNeedsTouch(t, brokerDir, addr, bob)
	cmd := exec.Command("bash", filepath.Join(s.chart, "scripts", "revoke-offline.sh"), ns, release, "--", "--principal", bob)
	cmd.Env = append(os.Environ(), "KUBECONFIG="+s.c.Kubeconfig, "PATH="+filepath.Dir(kindtest.Bin(t, "KUBECTL_BIN"))+":"+os.Getenv("PATH"))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("revoke-offline.sh: %v\n%s", err, kindtest.Filter(string(out)))
	}
	for _, p := range []string{"t-broker-0", "t-broker-1"} {
		s.c.WaitReady(ns, p, 4*time.Minute)
	}
	addr = s.forward("svc/"+release+"-broker", 8443) // the old forward died with the pods
	shapetest.OfflineRevoked(t, brokerDir, addr, bob)
}

// jobOutcome waits for the Job to succeed or fail and says which.
func (s *smoke) jobOutcome(name string, within time.Duration) string {
	s.t.Helper()
	var out string
	shapetest.WaitFor(s.t, "job "+name+" to succeed or fail", within, func() bool {
		r, err := s.c.KubectlTry("", "-n", ns, "get", "job", name, "-o", "jsonpath={.status.succeeded}/{.status.failed}")
		if err != nil {
			return false
		}
		succ, failed, _ := strings.Cut(strings.TrimSpace(r), "/")
		switch {
		case succ == "1":
			out = "succeeded"
		case failed != "" && failed != "0":
			out = "failed"
		}
		return out != ""
	})
	return out
}

// example reads a chart or repository example and rewrites it to the smoke's names: the namespace,
// the image the cluster holds, and the release's ConfigMap.
func (s *smoke) example(path string, repl ...string) string {
	s.t.Helper()
	body := readFile(s.t, path)
	body = strings.ReplaceAll(body, "port49-etcd.svc", ns+".svc")
	body = strings.ReplaceAll(body, "ghcr.io/rhwendt/port49:0.1.0", "port49:dev")
	body = strings.ReplaceAll(body, "{name: port49-broker}", "{name: "+release+"-broker}")
	for i := 0; i+1 < len(repl); i += 2 {
		body = strings.ReplaceAll(body, repl[i], repl[i+1])
	}
	if !strings.Contains(body, "namespace:") {
		body = strings.Replace(body, "kind: CronJob\nmetadata:\n", "kind: CronJob\nmetadata:\n  namespace: "+ns+"\n", 1)
	}
	return body
}

// backup triggers cronjob once as job and waits for the outcome.
func (s *smoke) backup(cronjob, job string) string {
	s.c.Kubectl("-n", ns, "create", "job", job, "--from=cronjob/"+cronjob)
	return s.jobOutcome(job, 5*time.Minute)
}

// Cell 7b: each backup CronJob, once. A dated file, 0600, is on the PVC; then a stale .new makes the
// next run fail loudly in stale-check, with the file named in its log, and nothing new is written.
func (s *smoke) cellBackups(t *testing.T) {
	s.c.Apply(`apiVersion: v1
kind: PersistentVolumeClaim
metadata: {name: port49-backups, namespace: ` + ns + `}
spec:
  accessModes: [ReadWriteOnce]
  storageClassName: ` + scName + `
  resources: {requests: {storage: 1Gi}}
`)
	chart := s.chart
	s.c.Apply(s.example(filepath.Join(chart, "examples", "backup-cronjob.yaml")))
	s.c.Apply(s.example(filepath.Join(chart, "examples", "backup-enrollments-cronjob.yaml")))
	for _, b := range []struct{ cron, glob, stale string }{
		{"port49-etcd-snapshot", "etcd-snapshot-*.db", "etcd-snapshot.new"},
		{"port49-enrollments-export", "enrollments-*.json", "enrollments.new"},
	} {
		if got := s.backup(b.cron, b.cron+"-run1"); got != "succeeded" {
			t.Fatalf("%s: the first run %s", b.cron, got)
		}
		out := s.debugPod("ls-"+b.cron, "port49-backups", "stat -c '%a %u %g %n' /v/"+b.glob, true)
		st, err := kindtest.ParseStat(out)
		if err != nil || len(st) != 1 {
			t.Fatalf("%s: want one dated file %s, got %q (%v)", b.cron, b.glob, out, err)
		}
		if err := st[0].Want("600", 65532, 65532); err != nil {
			t.Errorf("%s: %v", b.cron, err)
		}
		// A run that did not finish: the next run stops in stale-check and writes nothing.
		s.debugPod("stale-"+b.cron, "port49-backups", "umask 077; : > /v/"+b.stale+"; chown 65532:65532 /v/"+b.stale, false)
		if got := s.backup(b.cron, b.cron+"-run2"); got != "failed" {
			t.Fatalf("%s: a stale %s did not fail the job (%s)", b.cron, b.stale, got)
		}
		logs, _ := s.c.KubectlTry("", "-n", ns, "logs", "job/"+b.cron+"-run2", "-c", "stale-check")
		if !strings.Contains(logs, "/backup/"+b.stale+" is left from a run that did not finish") {
			t.Errorf("%s: stale-check's log does not name %s", b.cron, b.stale)
		}
		after := s.debugPod("count-"+b.cron, "port49-backups", "ls /v/"+b.glob+" | wc -l", true)
		if strings.TrimSpace(after) != "1" {
			t.Errorf("%s: %s dated files after the failed run, want the one from the first", b.cron, strings.TrimSpace(after))
		}
		s.debugPod("clear-"+b.cron, "port49-backups", "rm -f /v/"+b.stale, false)
	}
}

// Cell 8: a CronJob mints with its projected service account token, inside the cluster against the
// broker's Service and outside against a host broker through the kind gateway. Pass: the Job completes
// and the broker's log names the service account principal.
func (s *smoke) cellWorkload(t *testing.T) {
	const principal = "system:serviceaccount:" + ns + ":oxidized"
	ca := readFile(t, filepath.Join(s.brokerDir, testpki.LabCA))
	file := filepath.Join(s.root, "examples", "kubernetes", "backup-cronjob.yaml")
	apply := func(broker, cmName string) string {
		body := s.example(file, "namespace: netops", "namespace: "+ns,
			"https://port49-broker.netops.svc:8443", broker, "port49:local", "port49:dev",
			"configMap: {name: port49-backup}", "configMap: {name: "+cmName+"}")
		s.c.Apply(body)
		return "port49-backup-tokens"
	}
	config := func(name string) {
		cmd := exec.Command(kindtest.Bin(t, "KUBECTL_BIN"), "--kubeconfig", s.c.Kubeconfig, "--context", s.c.Context(), "-n", ns,
			"create", "configmap", name, "--from-file=broker-ca.pem="+s.writeTemp(name+"-ca.pem", ca, 0o600),
			"--from-file=devices="+s.writeTemp(name+"-devices", "smoke1\n", 0o600))
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("configmap %s: %v\n%s", name, err, kindtest.Filter(string(out)))
		}
	}

	// Inside.
	config("port49-backup")
	cron := apply("https://"+release+"-broker."+ns+".svc:8443", "port49-backup")
	if got := s.backup(cron, "inside-1"); got != "succeeded" {
		t.Fatalf("the CronJob's Job against the in-cluster broker %s", got)
	}
	logs := s.c.Kubectl("-n", ns, "logs", "t-broker-0") + s.c.Kubectl("-n", ns, "logs", "t-broker-1")
	if !strings.Contains(logs, principal) {
		t.Errorf("neither broker's log names %s", principal)
	}

	// Outside: a host port49d with the broker block and the memory store (port49-broker runs on etcd
	// alone, spec §12), listening on the kind gateway, reading the cluster's keys over its API address.
	dir := t.TempDir()
	out := filepath.Join(dir, "pki")
	gw := net.ParseIP(s.gateway)
	if err := testpki.WriteLabAt(out, "alice@example.com", nil, []net.IP{gw}, time.Now()); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", net.JoinHostPort(s.gateway, "0"))
	if err != nil {
		t.Fatalf("the kind gateway %s cannot be listened on: %v", s.gateway, err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	server := strings.TrimSpace(s.c.Kubectl("config", "view", "--raw", "--minify", "-o", "jsonpath={.clusters[0].cluster.server}"))
	writeFile(t, filepath.Join(dir, "inventory.yaml"), "devices:\n  - {name: smoke1, platform: arista_eos, addresses: ["+s.gateway+"]}\n")
	writeFile(t, filepath.Join(dir, "policy.yaml"), `scopes: [{name: all_devices, match: {}}]
roles: [{name: network_admin, privilege: admin, permit: ["**"]}]
subjects:
  - {name: svc_backup, identity: ["`+principal+`"], username: svc-backup, token_ttl: 900s}
grants:
  - {subject: svc_backup, scope: all_devices, roles: [network_admin], max_privilege: admin}
key_groups: [{match: {cidr: `+s.subnet+`}, key_ref: k}]
keys:
  k:
    current: {version: 1, secret_ref: file:`+s.pkiFile("keys/tacacs_v1")+`}
`)
	writeFile(t, filepath.Join(dir, "port49d.yaml"), `listen: "127.0.0.1:0"
metrics_listen: "127.0.0.1:0"
inventory_file: `+filepath.Join(dir, "inventory.yaml")+`
encryption:
  current: {id: c1, secret_ref: file:`+s.pkiFile("secrets/port49d-encryption.key")+`}
key_secret_refs: {file_dir: `+s.pkiFile("keys")+`}
accounting: {spool_path: `+filepath.Join(dir, "acct.jsonl")+`}
broker:
  listen: "`+net.JoinHostPort(s.gateway, fmt.Sprint(port))+`"
  tls_cert_file: `+filepath.Join(out, testpki.LabServerCert)+`
  tls_key_file: `+filepath.Join(out, testpki.LabServerKey)+`
  identity:
    humans:
      - {type: x509, trust_anchor_file: `+filepath.Join(out, testpki.LabCA)+`}
    machines:
      - {type: k8s, cluster: kind, issuer: https://kubernetes.default.svc.cluster.local,
         jwks: `+server+`/openid/v1/jwks, ca_file: `+s.clusterCA()+`, audience: port49, namespaces: [`+ns+`]}
  policy_file: `+filepath.Join(dir, "policy.yaml")+`
  revocations_file: `+filepath.Join(dir, "revocations.json")+`
  policy_watch_interval: 1s
  certificate_status: {disabled: true}
`)
	bin := filepath.Join(s.root, "bin", "port49d")
	cfg := filepath.Join(dir, "port49d.yaml")
	if o, err := exec.Command(bin, "init-revocations", "--config", cfg).CombinedOutput(); err != nil {
		t.Fatalf("init-revocations: %v\n%s", err, kindtest.Filter(string(o)))
	}
	errf, err := os.Create(filepath.Join(dir, "port49d.err"))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "-config", cfg)
	cmd.Stderr, cmd.Stdout = errf, errf
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait(); errf.Close() })
	shapetest.WaitFor(t, "the host broker to listen on the gateway", 30*time.Second, func() bool {
		c, err := net.DialTimeout("tcp", net.JoinHostPort(s.gateway, fmt.Sprint(port)), time.Second)
		if err == nil {
			c.Close()
		}
		return err == nil
	})
	ca = readFile(t, filepath.Join(out, testpki.LabCA)) // the host broker's CA, for config() below
	config("port49-backup-outside")
	apply("https://"+net.JoinHostPort(s.gateway, fmt.Sprint(port)), "port49-backup-outside")
	if got := s.backup(cron, "outside-1"); got != "succeeded" {
		t.Fatalf("the CronJob's Job against the host broker %s", got)
	}
	said, _ := os.ReadFile(filepath.Join(dir, "port49d.err"))
	if !strings.Contains(string(said), principal) {
		t.Errorf("the host broker's log does not name %s", principal)
	}
}

// brokerPod is the StatefulSet pod the fsGroup cells regenerate.
const brokerPod = "t-broker-0"

// Cell 9, green: two more pod generations on the one PVC. After each the broker is Ready, with no
// state_dir refusal, state/ is 700 and issuing-ca.key 600 owned by 65532; the second generation
// follows a forced kubelet walk (the volume root's group set back to 0, so the mount is a mismatch
// and the kubelet walks) that the init container's every-start repair must undo.
func (s *smoke) cellFSGroup(t *testing.T) {
	const pvc = "data-" + brokerPod
	want := func(when string) {
		st := s.statOn(pvc, "/v/state", "/v/state/issuing-ca.key")
		if err := st[0].Want("700", 65532, 65532); err != nil {
			t.Errorf("%s: %v", when, err)
		}
		if err := st[1].Want("600", 65532, 65532); err != nil {
			t.Errorf("%s: %v", when, err)
		}
	}
	regen := func(when string) {
		s.c.Kubectl("-n", ns, "delete", "pod", brokerPod)
		s.c.WaitReady(ns, brokerPod, 4*time.Minute)
		if logs := s.c.Kubectl("-n", ns, "logs", brokerPod); kindtest.StateDirRefusal.MatchString(logs) {
			t.Fatalf("%s: the broker refused its state_dir", when)
		}
		want(when)
	}
	want("before")
	regen("second generation")
	s.debugPod("chgrp-root", pvc, "chgrp 0 /v", false)
	regen("third generation after a forced walk")
	// The kubelet says which: skipped on the unforced mounts, walked on the forced one. The line comes
	// from the node's kubelet log, which this smoke does not read (UNVERIFIED which node text a
	// kind kubelet prints); the assertions above are on the result, not the log.
}

// Cell 9, red (KIND_OLD_ROOT=1): the first design's 2755 root. Generation one starts (its init has
// run); generation two is a kubelet walk, which leaves state/ group-writable, and the broker refuses
// it, by the line of internal/config/config.go, and crash-loops.
func (s *smoke) cellFSGroupRed() {
	t := s.t
	shapetest.WaitFor(t, brokerPod+"'s init container to finish", 5*time.Minute, func() bool {
		p, err := s.c.Pod(ns, brokerPod)
		return err == nil && p.Phase == "Running" && p.InitWaiting == ""
	})
	s.c.Kubectl("-n", ns, "delete", "pod", brokerPod)
	if !s.c.WaitCrashLoop(ns, brokerPod, 4*time.Minute) {
		t.Fatalf("%s did not crash-loop on its second generation: the old 2755 root was expected to fail (a green here means the red is not red)", brokerPod)
	}
	logs, _ := s.c.KubectlTry("", "-n", ns, "logs", brokerPod, "--previous")
	if more, err := s.c.KubectlTry("", "-n", ns, "logs", brokerPod); err == nil {
		logs += more
	}
	if !kindtest.StateDirRefusal.MatchString(logs) {
		t.Fatalf("%s crash-looped, but not on the state_dir refusal; the broker's log is %d bytes, filtered:\n%s",
			brokerPod, len(logs), kindtest.Filter(logs))
	}
	t.Logf("RED as expected: the 2755 root's second generation crash-loops on the state_dir refusal")
}
