// The kind smoke's stack: the chart on a kind cluster with port49's own three-member etcd, the
// helpers every cell uses, and the exported hand-off the lab's L82 (tests/lab/l82_test.go, tag lab)
// builds on. It is a plain file, not a _test.go one, so another package can import it; it runs
// nothing until a test calls BringUp or the smoke's bringUp. It needs the pinned tools the Makefile
// builds (KIND_BIN, KUBECTL_BIN, HELM_BIN) and fails, never skips, without them.
//
// Secrets are made with --from-file only, from files in a 0700 temp directory, and no step prints
// one: a failure names the Secret or the field, and the dump goes through tests/qual/secret-filter.sh
// and never reads the vault namespace.
package kind

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/testpki"
	"github.com/blanketfish/port49/tests/kind/kindtest"
	"github.com/blanketfish/port49/tests/shapes/shapetest"
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
	// rolesSecret is a Secret store-roles' pod mounts at /etc/port49/directory (Options.StoreRolesSecret).
	rolesSecret string
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
	// Both components' configs name /etc/port49/etcd/tls.crt, because each pod mounts its own Secret
	// there. store-roles reads both certificates' CNs, so its pod mounts the broker's Secret apart
	// and reads a copy of the broker's config that names it.
	brokerCfg := s.c.Kubectl("-n", ns, "get", "configmap", "t-broker", "-o", `jsonpath={.data.port49-broker\.yaml}`)
	forRoles, err := brokerConfigForRoles(brokerCfg)
	if err != nil {
		s.t.Fatal(err)
	}
	s.c.Kubectl("-n", ns, "create", "configmap", "store-roles-broker", "--from-file=port49-broker.yaml="+s.writeTemp("store-roles-broker.yaml", forRoles, 0o600))
	pod := `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"store-roles"},"spec":{"restartPolicy":"Never",
"securityContext":{"runAsUser":65532,"runAsGroup":65532,"fsGroup":65532},
"containers":[{"name":"x","image":"port49:dev","imagePullPolicy":"Never","command":["/usr/local/bin/port49d"],
"args":["store-roles","--config","/etc/port49/config/port49d.yaml","--broker-config","/etc/port49/broker-config/port49-broker.yaml"],
"volumeMounts":[{"name":"d","mountPath":"/etc/port49/config"},{"name":"b","mountPath":"/etc/port49/broker-config"},{"name":"eb","mountPath":"/etc/port49/etcd-broker"},
{"name":"enc","mountPath":"/etc/port49/secrets"},{"name":"ca","mountPath":"/etc/port49/etcd-ca"},
{"name":"ep","mountPath":"/etc/port49/etcd"},{"name":"tls","mountPath":"/etc/port49/broker"},{"name":"att","mountPath":"/etc/port49/attestation"},
{"name":"keys","mountPath":"/run/port49/keys"}]}],
"volumes":[{"name":"d","configMap":{"name":"t-port49d"}},{"name":"b","configMap":{"name":"store-roles-broker"}},{"name":"eb","secret":{"secretName":"port49-etcd-broker","defaultMode":288}},
{"name":"enc","secret":{"secretName":"port49-encryption","defaultMode":288}},{"name":"ca","secret":{"secretName":"port49-etcd-ca","defaultMode":288}},
{"name":"ep","secret":{"secretName":"port49-etcd-port49d","defaultMode":288}},{"name":"tls","secret":{"secretName":"port49-broker-tls","defaultMode":288}},
{"name":"att","configMap":{"name":"port49-attestation"}},{"name":"keys","secret":{"secretName":"port49-device-keys","defaultMode":288}}]}}`
	if s.rolesSecret != "" {
		pod = strings.Replace(pod, `{"name":"keys","mountPath":"/run/port49/keys"}]`,
			`{"name":"keys","mountPath":"/run/port49/keys"},{"name":"dir","mountPath":"/etc/port49/directory"}]`, 1)
		pod = strings.Replace(pod, `{"name":"keys","secret":{"secretName":"port49-device-keys","defaultMode":288}}]`,
			`{"name":"keys","secret":{"secretName":"port49-device-keys","defaultMode":288}},{"name":"dir","secret":{"secretName":"`+s.rolesSecret+`","defaultMode":288}}]`, 1)
		if strings.Count(pod, `"name":"dir"`) != 2 {
			s.t.Fatal("the store-roles pod's volume lists changed: the directory Secret was not mounted")
		}
	}
	s.t.Cleanup(func() {
		s.c.KubectlTry("", "-n", ns, "delete", "pod", "store-roles", "--ignore-not-found", "--wait=false")
		s.c.KubectlTry("", "-n", ns, "delete", "configmap", "store-roles-broker", "--ignore-not-found")
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
		s.t.Fatalf("store-roles did not produce etcdctl commands (phase %s)\n%s", p.Phase, s.c.PodReport(ns, "store-roles"))
	}
	s.c.Kubectl("-n", ns, "create", "configmap", "port49-etcd-roles", "--from-file=roles.sh="+s.writeTemp("roles.sh", roles, 0o600))
	s.applyExample("examples/etcd/etcd-init-job.yaml", map[string]string{"<setup-image>": "port49-setup:dev"})
}

// brokerConfigForRoles is the broker's config with its etcd client files named in the directory
// where store-roles' pod mounts the broker's own Secret.
func brokerConfigForRoles(cfg string) (string, error) {
	const from, to = "/etc/port49/etcd/", "/etc/port49/etcd-broker/"
	if !strings.Contains(cfg, from+"tls.crt") {
		return "", fmt.Errorf("the broker's config names no client certificate under %s", from)
	}
	return strings.ReplaceAll(cfg, from, to), nil
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

// bringUp makes the cluster named name and installs the chart on it with port49's etcd, through
// store-roles and the etcd-init job. The caller has refused on a key host already.
func bringUp(t *testing.T, name string, o Options) *smoke {
	t.Helper()
	root := kindtest.Root()
	s := &smoke{t: t, root: root, chart: filepath.Join(root, "deploy", "helm", "port49"), helm: "helm", rolesSecret: o.StoreRolesSecret}
	s.pki = t.TempDir()
	if err := testpki.WriteKind(s.pki, ns, 3, "alice@example.com", time.Now()); err != nil {
		t.Fatal(err)
	}
	brokerDir := filepath.Join(s.pki, "broker")
	s.brokerDir = brokerDir
	rootsFile, subject := shapetest.AdminSetup(t, brokerDir)

	s.c = kindtest.UpWith(t, name, o.kindConfig())
	// the kind network exists only once kind has made the cluster
	s.subnet, s.gateway = dockerKindNetwork(t)
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
	if o.Before != nil {
		o.Before(s.c, s.subnet, s.gateway)
	}

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
	if o.KeysFrom == nil {
		s.secretFrom("port49-device-keys", map[string]string{"tacacs_v1": s.pkiFile("keys/tacacs_v1")})
	} else {
		v1, err := os.ReadFile(s.pkiFile("keys/tacacs_v1"))
		if err != nil {
			t.Fatal(err)
		}
		o.KeysFrom(s.c, ns, v1)
		if _, err := s.c.KubectlTry("", "-n", ns, "get", "secret", "port49-device-keys", "-o", "name"); err != nil {
			t.Fatalf("KeysFrom returned and the Secret port49-device-keys does not exist: %v", err)
		}
	}
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
	etcdSTS := map[string]string{}
	if o.EtcdOnLocalVolumes {
		etcdSTS["accessModes: [ReadWriteOnce]"] = "accessModes: [ReadWriteOnce]\n        storageClassName: " + scName
	}
	s.applyExample("examples/etcd/statefulset.yaml", etcdSTS)
	for i := 0; i < 3; i++ {
		s.c.WaitReady(ns, fmt.Sprintf("etcd-%d", i), 3*time.Minute)
	}

	// The policy and the inventory. The device is the host, which the kind network presents as its gateway.
	cfgDir := t.TempDir()
	pol := readFile(t, filepath.Join(root, "deploy", "compose", "config", "policy.yaml"))
	deviceNet, deviceAddr := s.subnet, s.gateway
	if o.DeviceFrom != nil {
		o.DeviceAddr, o.DeviceNet = o.DeviceFrom()
	}
	if o.DeviceAddr != "" {
		deviceNet, deviceAddr = o.DeviceNet, o.DeviceAddr
	}
	pol = strings.ReplaceAll(pol, "172.30.49.0/24", deviceNet)
	pol = shapetest.AdminPolicy(t, pol, subject+"\n  - {name: svc_backup, identity: [\"system:serviceaccount:"+ns+":oxidized\"], username: svc-backup, token_ttl: 900s}")
	if o.KeysFrom != nil {
		// the shipped ESO example names its key files core_v1 and core_v2
		pol = strings.ReplaceAll(pol, "keys/tacacs_v1", "keys/core_v1")
	}
	pol = strings.Replace(pol, "\ngrants:\n", "\ngrants:\n  - {subject: svc_backup, scope: all_devices, roles: [network_admin]}\n", 1)
	if o.Policy != nil {
		pol = o.Policy(deviceNet)
	}
	s.policy = filepath.Join(cfgDir, "policy.yaml")
	writeFile(t, s.policy, pol)
	writeFile(t, filepath.Join(cfgDir, "inventory.yaml"),
		"devices:\n  - {name: smoke1, platform: arista_eos, addresses: ["+deviceAddr+"]}\n")
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
`+o.serviceValues()+`issuerDiscovery: {enabled: true}
config:
  broker:
    broker:
      certificate_status: {disabled: true}
      identity:
        humans:
          - {type: x509, trust_anchor_file: /etc/port49/broker/ca.crt}
          - {type: oidc, issuer: https://idp.smoke.example, client_id: port49-cli, principal_claim: email,
             principal_domains: [example.com]}
        issuance: {}
        machines:
          - {type: k8s, cluster: kind, issuer: https://kubernetes.default.svc.cluster.local,
             jwks: https://kubernetes.default.svc.cluster.local/openid/v1/jwks,
             ca_file: /etc/port49/attestation/cluster-ca.pem, audience: port49, namespaces: [`+ns+`]}
`)
	if o.Values != "" {
		s.install("-f", s.writeTemp("values-extra.yaml", o.Values, 0o600))
	} else {
		s.install()
	}

	// store-roles from the rendered configs, in one pod that mounts what the broker's does, then
	// etcd-init applies them. The roles are etcdctl commands naming roles and key prefixes.
	s.applyRoles()
	s.c.Kubectl("-n", ns, "wait", "--for=condition=complete", "job/etcd-init", "--timeout=300s")

	return s
}

// copyIssuer makes the issuing CA on broker-0 and copies it to the rest, so that every broker is the
// same CA (cell 6 asserts it).
func (s *smoke) copyIssuer() {
	t := s.t
	t.Helper()
	script := filepath.Join(s.chart, "scripts", "copy-issuer.sh")
	cmd := exec.Command("bash", script, ns, release, "--from", "0")
	cmd.Env = append(os.Environ(), "KUBECONFIG="+s.c.Kubeconfig, "PATH="+filepath.Dir(kindtest.Bin(t, "KUBECTL_BIN"))+":"+os.Getenv("PATH"))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("copy-issuer.sh: %v\n%s", err, kindtest.Filter(string(out)))
	}
}

// issuerAndPods copies the issuing CA once and waits for both port49d pods and both brokers.
func (s *smoke) issuerAndPods() {
	t := s.t
	t.Helper()
	s.copyIssuer()
	for _, p := range []string{"t-port49d-0", "t-port49d-1", "t-broker-0", "t-broker-1"} {
		s.c.WaitReady(ns, p, 4*time.Minute)
	}
}

// run is one cell as a subtest whose own t every helper reports to.
func (s *smoke) run(t *testing.T, name string, f func(*testing.T)) {
	t.Run(name, func(t *testing.T) {
		prev, prevC := s.t, s.c.T
		s.t, s.c.T = t, t
		defer func() { s.t, s.c.T = prev, prevC }()
		f(t)
	})
}

// patchPolicy replaces the policy in both ConfigMaps: port49d reads it at its watch interval.
func (s *smoke) patchPolicy(p []byte) error {
	patch, err := json.Marshal(map[string]any{"data": map[string]string{"policy.yaml": string(p)}})
	if err != nil {
		return err
	}
	f := s.writeTemp("policy-patch.json", string(patch), 0o600)
	for _, cm := range []string{"t-port49d", "t-broker"} {
		if _, err := s.c.KubectlTry("", "-n", ns, "patch", "configmap", cm, "--type", "merge", "--patch-file", f); err != nil {
			return err
		}
	}
	return nil
}

// Stack is the bring-up's result for another package (the lab's L82, tests/lab): the cluster, with
// the chart installed and every pod Ready, and the few helpers a measurement needs. The smoke's own
// cells use the unexported helpers.
type Stack struct{ s *smoke }

// BringUp refuses on a key host, makes the cluster named name, installs the chart and waits for
// every pod. The cluster is deleted when t ends (kindtest.Up).
func BringUp(t *testing.T, name string) *Stack { return BringUpWith(t, name, Options{}) }

// Options changes the bring-up.
type Options struct {
	// KeysFrom makes the device-key Secret port49-device-keys itself: the stack does not create it,
	// and calls KeysFrom (cluster up, namespace made, nothing yet mounting the Secret) with the
	// namespace and the version 1 key, which it must leave existing; the key's file is then core_v1,
	// as in the shipped External Secrets example, and the policy names that. Version 1's bytes are
	// never printed.
	KeysFrom func(c *kindtest.Cluster, ns string, v1 []byte)
	// Before runs once the cluster is up and the namespace exists, before anything is installed in
	// it, with the kind network's subnet and gateway: a LoadBalancer Service needs its address
	// provider in place first, or helm's wait never ends.
	Before func(c *kindtest.Cluster, subnet, gateway string)
	// EtcdOnLocalVolumes puts etcd's volume claims on the stack's `local` StorageClass, as the chart's are.
	// kind's default class provisions hostPath volumes, which Velero's file-system backup skips (L89).
	EtcdOnLocalVolumes bool
	// KindConfig is the cluster's config under tests/kind; empty is kind.yaml.
	KindConfig string
	// Service is the chart values' `service:` block, with its newline; empty is a NodePort Service.
	Service string
	// DeviceAddr and DeviceNet make the inventory's one device that address, and the key group
	// that admits it that network, in place of the kind network's gateway: a device behind a router.
	DeviceAddr, DeviceNet string
	// DeviceFrom, when set, is called after Before and gives DeviceAddr and DeviceNet: a device made in
	// Before, whose address the kind network assigned, is known only then.
	DeviceFrom func() (addr, net string)
	// Values is YAML helm installs with after the stack's own values file: a map merges into the
	// stack's, a list replaces it.
	Values string
	// Policy, when set, is the policy in place of the stack's: it is given the network the device key
	// group admits. A policy for a broker with a directory declares no human usernames.
	Policy func(deviceNet string) string
	// StoreRolesSecret, when set, is a Secret store-roles' pod mounts at /etc/port49/directory, where the
	// chart mounts the broker's directory Secret: a broker config that reads files there loads in that pod too.
	StoreRolesSecret string
}

func (o Options) kindConfig() string {
	if o.KindConfig == "" {
		return "kind.yaml"
	}
	return o.KindConfig
}

func (o Options) serviceValues() string {
	if o.Service == "" {
		return "service: {type: NodePort}\n"
	}
	return o.Service
}

// BringUpWith is BringUp with options.
func BringUpWith(t *testing.T, name string, o Options) *Stack {
	t.Helper()
	shapetest.RefuseOnKeyHost(t)
	s := bringUp(t, name, o)
	s.issuerAndPods()
	return &Stack{s}
}

// Cluster is the kind cluster.
func (k *Stack) Cluster() *kindtest.Cluster { return k.s.c }

// Namespace is the release's namespace; Release is the Helm release name.
func (k *Stack) Namespace() string { return ns }
func (k *Stack) Release() string   { return release }

// Policy is the policy the chart was installed with.
func (k *Stack) Policy() []byte { return []byte(readFile(k.s.t, k.s.policy)) }

// PatchPolicy replaces the policy in the ConfigMaps both pods read.
func (k *Stack) PatchPolicy(p []byte) error { return k.s.patchPolicy(p) }

// WriteTemp writes a file in a temp directory of the current test.
func (k *Stack) WriteTemp(name, body string, mode os.FileMode) string {
	return k.s.writeTemp(name, body, mode)
}

// PKIFile is a file of the run's generated PKI; its content is never printed.
func (k *Stack) PKIFile(rel string) string { return k.s.pkiFile(rel) }

// Forward starts a kubectl port-forward and returns the local address.
func (k *Stack) Forward(target string, remote int) string { return k.s.forward(target, remote) }

// Device is a TACACS+ device that reaches pod's port49d, keyed with version 1.
func (k *Stack) Device(pod string) shapetest.Device { return k.s.device(pod) }

// Mint is a function giving a fresh token for the broker at brokerAddr.
func (k *Stack) Mint(brokerAddr string) func() string { return k.s.mint(brokerAddr) }

// DebugPod runs one root pod on pvc's volume (mounted at /v) with sh -c script, and returns its log.
func (k *Stack) DebugPod(name, pvc, script string, readOnly bool) string {
	return k.s.debugPod(name, pvc, script, readOnly)
}

// StatOn is `stat -c '%a %u %g %n'` of paths on pvc's volume, which is mounted at /v.
func (k *Stack) StatOn(pvc string, paths ...string) []kindtest.Stat { return k.s.statOn(pvc, paths...) }

// Run is one cell as a subtest.
func (k *Stack) Run(t *testing.T, name string, f func(*testing.T)) { k.s.run(t, name, f) }
