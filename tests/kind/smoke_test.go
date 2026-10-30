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

func sha(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func TestKindSmoke(t *testing.T) {
	shapetest.RefuseOnKeyHost(t) // kind's nodes are privileged containers
	s := bringUp(t, "port49smoke", Options{})
	if oldRoot() {
		s.cellFSGroupRed()
		return
	}
	s.issuerAndPods()
	// The fsGroup cell is vacuous on a hostPath volume (the kubelet never walks one): refuse that
	// class now, naming it, before any cell runs.
	s.c.RequireLocalPV(ns, "data-"+brokerPod)

	cell := s.run
	cell(t, "login", s.cellLogin)
	cell(t, "restart", s.cellRestart)
	cell(t, "rotate", s.cellRotate)
	cell(t, "subpath", s.cellSubPath)
	cell(t, "issuer_copy", s.cellIssuerCopy)
	cell(t, "revoke", func(t *testing.T) { s.cellRevoke(s.brokerDir) })
	cell(t, "backups", s.cellBackups)
	cell(t, "workload_cronjob", s.cellWorkload)
	cell(t, "fsgroup_generations", s.cellFSGroup)
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
	// The session authorization raises the held level to 15 (spec 5.3: the login START carries 1);
	// without it the command at 15 is denied privilege_exceeded with or without a restart.
	if !dev.Permits("alice") {
		t.Fatal("the session's authorization before the restart was refused")
	}
	s.c.Kubectl("-n", ns, "delete", "pod", "t-port49d-0", "t-broker-0")
	s.c.WaitReady(ns, "t-port49d-0", 4*time.Minute)
	s.c.WaitReady(ns, "t-broker-0", 4*time.Minute)
	dev = s.device("t-port49d-0") // looked up again
	if !dev.Permits("alice", "show", "version") {
		t.Fatal("the session's next command after the restart was refused: its context, and the level the session authorization raised, did not survive in etcd")
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

func (r kindRotator) WritePolicy(p []byte) error { return r.s.patchPolicy(p) }

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
	// Run again, it changes nothing: the target holds the same CA, so it is skipped (review I-1). Run from
	// the other broker, it is the same CA too. (The refusal of a different CA is the fake-kubectl tests'.)
	for _, from := range []string{"0", "1"} {
		cmd := exec.Command("bash", filepath.Join(s.chart, "scripts", "copy-issuer.sh"), ns, release, "--from", from)
		cmd.Env = append(os.Environ(), "KUBECONFIG="+s.c.Kubeconfig, "PATH="+filepath.Dir(kindtest.Bin(t, "KUBECTL_BIN"))+":"+os.Getenv("PATH"))
		out, err := cmd.CombinedOutput()
		if err != nil || !strings.Contains(string(out), "already holds this issuing CA") {
			t.Fatalf("copy-issuer.sh --from %s again: %v\n%s", from, err, kindtest.Filter(string(out)))
		}
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
	// The enrollment store exists only once init-enrollments has made it; the export of a store that
	// was never made is refused ("lost"), which the CronJob would show as a failed first run.
	s.c.Kubectl("-n", ns, "exec", "t-broker-0", "-c", "port49-broker", "--", "/usr/local/bin/port49-broker",
		"init-enrollments", "--config", "/etc/port49/config/port49-broker.yaml")
	chart := s.chart
	s.c.Apply(s.example(filepath.Join(chart, "examples", "backup-cronjob.yaml")))
	// The enrollments export is the chart's own CronJob (backup.enrollments), from the same volumes template.
	s.install("--set", "backup.enrollments.enabled=true", "--set", "backup.enrollments.claimName=port49-backups")
	for _, b := range []struct{ cron, glob, stale string }{
		{"port49-etcd-snapshot", "etcd-snapshot-*.db", "etcd-snapshot.new"},
		{release + "-enrollments-export", "enrollments-*.json", "enrollments.new"},
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
	// The decision record of a permitted mint: event mint, verdict permit, principal (minter.go:557;
	// a deny record naming the principal does not count). The records are JSON on the broker's stdout.
	if !kindtest.PermitMint(logs, principal) {
		t.Errorf("neither broker's log holds a permit mint record for %s", principal)
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
	reaped := s.c.Guard.Process(cmd) // a killed run stops it by its recorded pid, until it is reaped
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait(); reaped(); errf.Close() })
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
	if !kindtest.PermitMint(string(said), principal) {
		t.Errorf("the host broker's log holds no permit mint record for %s", principal)
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
	// A probe the init container never touches (it repairs state/ and the root only): root-owned,
	// group 0, in the volume root. Only the kubelet's walk can give it group 65532, so the group
	// afterwards is the proof that the walk happened on the forced generation.
	s.debugPod("walk-probe", pvc, "echo probe > /v/walk-probe && chown 0:0 /v/walk-probe && chmod 0600 /v/walk-probe", false)
	if err := s.statOn(pvc, "/v/walk-probe")[0].Want("600", 0, 0); err != nil {
		t.Fatalf("the walk probe was not set up: %v", err)
	}
	s.debugPod("chgrp-root", pvc, "chgrp 0 /v", false)
	regen("third generation after a forced walk")
	if st := s.statOn(pvc, "/v/walk-probe")[0]; st.GID != 65532 {
		t.Errorf("the kubelet did not walk the volume on the forced generation: %s is still group %d (fsGroup 65532 expected); "+
			"the cell passed on the init repair alone", st.Path, st.GID)
	}
}

// Cell 9, red (KIND_OLD_ROOT=1): the first design's 2755 root, with issuance on and the issuing CA
// copied in. Every mount under that root is a kubelet walk (the old init puts the root back to 2755
// at each start), and the walk gives issuing-ca.key group write, which the old init does not undo
// below the data directory. The strict reader refuses the key, and the broker, which never fails to
// start over its CA, says so and issues nothing. A generation after the copy shows it; one more is
// tried if the copy's own restart did not. (The broker does not crash-loop: the old init's
// `install -d -m 0700` still repairs state/, which this cell's first version expected to be refused.)
// The green cell's `want` is the same file at 600.
func (s *smoke) cellFSGroupRed() {
	t := s.t
	shapetest.WaitFor(t, brokerPod+"'s init container to finish", 5*time.Minute, func() bool {
		p, err := s.c.Pod(ns, brokerPod)
		return err == nil && p.Phase == "Running" && p.InitWaiting == ""
	})
	s.c.RequireLocalPV(ns, "data-"+brokerPod)
	s.copyIssuer()
	var log string
	for gen := 1; gen <= 2; gen++ {
		if gen > 1 {
			s.c.Kubectl("-n", ns, "delete", "pod", brokerPod)
		}
		s.c.WaitReady(ns, brokerPod, 4*time.Minute)
		log, _ = s.c.KubectlTry("", "-n", ns, "logs", brokerPod)
		if kindtest.IssuerWalked.MatchString(log) && !kindtest.IssuerIssuing.MatchString(log) {
			// The reason, not only the line: the key is 0660, as the walk leaves it.
			if err := s.statOn("data-"+brokerPod, "/v/state/issuing-ca.key")[0].Want("660", 65532, 65532); err != nil {
				t.Fatalf("the broker refused the key, but not for the walk's mode: %v", err)
			}
			t.Logf("RED as expected: the 2755 root's walk leaves issuing-ca.key unusable (generation %d after the copy)", gen)
			return
		}
	}
	t.Fatalf("%s still issues after two generations under the old 2755 root: the walk was expected to leave "+
		"issuing-ca.key unusable (a green here means the red is not red); its log, filtered:\n%s", brokerPod, kindtest.Filter(log))
}
