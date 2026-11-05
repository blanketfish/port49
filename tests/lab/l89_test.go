//go:build lab

package lab

import (
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/tacacs/wire"
	kindstack "github.com/blanketfish/port49/tests/kind"
	"github.com/blanketfish/port49/tests/kind/kindtest"
	"github.com/blanketfish/port49/tests/shapes/l82"
	"github.com/blanketfish/port49/tests/shapes/l89"
	"github.com/blanketfish/port49/tests/shapes/shapetest"
)

// L89's fixed names: the object store's namespace, its bucket and the backup and restore.
const (
	l89Store   = "l89-store"
	l89Bucket  = "velero"
	l89Backup  = "l89-backup"
	l89Restore = "l89-restore"
	l89Region  = "us-east-1"
)

// l89Fence is what the fence's refusals say: the broker's and port49d's data directory writable by a
// group or owned by the wrong uid (internal/config, internal/fence), and the two init containers' refusals
// (templates/_helpers.tpl: a symlink, a volume not owned by uid 65532, a chmod that failed).
var l89Fence = regexp.MustCompile(`data-dir(-owner)?: |writable by its group or others|is owned by uid|not owned by uid 65532`)

// TestL89 measures spec §15 L89: a Velero file-system backup (node agent) of a chart release's volumes,
// on kind with an S3-compatible store in the cluster. `make lab-l89` runs it in CI (lab-kind.yml); kind
// targets refuse on a key host. The stack is the kind smoke's, with issuance on and copy-issuer.sh run.
// The Velero Schedule is the chart's own example (deploy/helm/port49/examples/velero), applied as it is
// and run by `velero backup create --from-schedule`.
//
//	(a) back up, delete the namespace, restore: both StatefulSets ready with no fence refusal, the
//	    issuing CA's fingerprint unchanged; the owner, group and mode of state/, issuing-ca.key and the
//	    spool directory are recorded before and after
//	(b) after the restore, a mint and a login
//	(c) the Velero README's restore order, steps run from its own text: the namespace restored with both
//	    StatefulSets at 0 replicas (the resource modifier) and the README's volume check, a Completed pod
//	    volume restore for each of the chart's four data volumes by name; with both StatefulSets at 0, each
//	    broker's marks.json and CA certificate and each spool's sentinel (written by (a) before the backup)
//	    have the sha256 they had; then the token delete, revoke-offline.sh and the scale-up, the CA
//	    unchanged and no broker logging that it had no marks.json
//	(d) the same checks after the README's fallback order, for when (c) fails: the pods run for the volume
//	    restore and are scaled to 0 before the token delete (the lab's etcd shares the namespace, so it
//	    cannot be held down apart; see the rows)
//
// The backup holds issuing-ca.key. The store's credentials and the repository key are generated per
// run, written 0600 in the test's temp directory and handed over by file; they are never printed, never
// in an argument list, and the velero and object-store namespaces are never dumped (kindtest.DumpNamespaces).
// A FAIL is a measured answer; a cell that could not be measured is NOT RUN and fails the test.
func TestL89(t *testing.T) {
	if os.Getenv("PORT49_LAB_L89") != "1" {
		t.Skip("PORT49_LAB_L89=1 runs L89 (make lab-l89); `make lab` does not")
	}
	shapetest.RefuseOnKeyHost(t)
	out := os.Getenv("PORT49_LAB_OUT")
	if out == "" {
		out = t.TempDir()
	}
	cells := []l82.Cell{{ID: "a"}, {ID: "b"}, {ID: "c"}, {ID: "d"}}
	env := l89Env(t)
	defer func() {
		text, err := l89.Results(*env, cells)
		if err != nil {
			t.Errorf("INVALID: %v", err)
			return
		}
		if err := os.MkdirAll(out, 0o755); err != nil {
			t.Errorf("INVALID: %v", err)
			return
		}
		if err := os.WriteFile(filepath.Join(out, "l89-results.md"), []byte(text), 0o644); err != nil {
			t.Errorf("INVALID: %v", err)
		}
		if err := l82.Save(filepath.Join(out, "l89-cells.json"), cells); err != nil {
			t.Errorf("INVALID: %v", err)
		}
		for _, c := range cells {
			t.Logf("L89 cell %s: %s", c.ID, l82Verdict(c))
			if c.Verdict == "" {
				t.Errorf("L89 cell %s was not measured", c.ID)
			}
		}
	}()

	stack := kindstack.BringUpWith(t, "port49l89", kindstack.Options{EtcdOnLocalVolumes: true})
	r := &l89Run{t: t, env: env, stack: stack, dir: t.TempDir(), out: out}
	r.installStoreAndVelero()
	r.first = &cells[0]
	stack.Run(t, "a_backup_delete_restore", func(t *testing.T) { r.cellA(t, &cells[0]) })
	stack.Run(t, "b_mint_and_login", func(t *testing.T) { r.cellB(t, &cells[1]) })
	stack.Run(t, "c_readme_restore_order", func(t *testing.T) { r.cellOrder(t, &cells[2], false) })
	stack.Run(t, "d_readme_fallback_order", func(t *testing.T) { r.cellOrder(t, &cells[3], true) })
}

type l89Run struct {
	t         *testing.T
	env       *l89.Env
	stack     *kindstack.Stack
	dir       string // a 0700 temp directory: the credential files live here
	out       string // the results directory: the diagnosis of a failed cell goes here
	first     *l82.Cell
	bucketLog string   // the last curl attempt at the bucket
	own       []string // the store credentials, which a diagnosis line must not hold
	key       string   // the generated repository key, compared with the cluster's and never printed
	// the sha256 of each file in l89Hashed when the backup was taken (cells c and d compare against them)
	hashesBefore map[string]string
}

func l89Env(t *testing.T) *l89.Env {
	t.Helper()
	e := l82Env(t)
	return &l89.Env{Date: e.Date, Runner: e.Runner, Run: e.Run, Docker: e.Docker, Kernel: e.Kernel, Kind: e.Kind,
		NodeImage: e.NodeImage, Kubectl: e.Kubectl, Helm: e.Helm, Velero: os.Getenv("VELERO_VERSION"),
		VeleroImage: os.Getenv("VELERO_IMAGE"), AWSPlugin: os.Getenv("VELERO_AWS_PLUGIN_IMAGE") + "@" + os.Getenv("VELERO_AWS_PLUGIN_DIGEST"), ObjectStore: os.Getenv("OBJECT_STORE_IMAGE")}
}

// file writes a 0600 file in the credentials' directory and returns its path.
func (r *l89Run) file(name, body string) string {
	r.t.Helper()
	p := filepath.Join(r.dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		r.t.Fatal(err)
	}
	return p
}

// velero runs the pinned client against the cluster. Its output is filtered and shown only on failure.
func (r *l89Run) velero(args ...string) string {
	t := r.t
	t.Helper()
	c := r.stack.Cluster()
	full := append([]string{"--kubeconfig", c.Kubeconfig, "--kubecontext", c.Context(), "-n", "velero"}, args...)
	out, err := exec.Command(kindtest.Bin(t, "VELERO_BIN"), full...).CombinedOutput()
	if err != nil {
		t.Fatalf("velero %s: %v\n%s", args[0], err, kindtest.Filter(string(out)))
	}
	return string(out)
}

// forward is kubectl port-forward to a Service in any namespace (the stack's own is the chart's).
func (r *l89Run) forward(ns, target string, remote int) string {
	t := r.t
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	local := l.Addr().(*net.TCPAddr).Port
	l.Close()
	c := r.stack.Cluster()
	cmd := exec.Command(kindtest.Bin(t, "KUBECTL_BIN"), "--kubeconfig", c.Kubeconfig, "--context", c.Context(), "-n", ns,
		"port-forward", target, fmt.Sprintf("%d:%d", local, remote))
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	addr := fmt.Sprintf("127.0.0.1:%d", local)
	shapetest.WaitFor(t, "the port-forward to "+target, 30*time.Second, func() bool {
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			conn.Close()
		}
		return err == nil
	})
	return addr
}

// installStoreAndVelero makes the object store with generated credentials and its bucket, installs
// Velero with the node agent, and makes the repository key Secret. Nothing here is printed.
func (r *l89Run) installStoreAndVelero() {
	t := r.t
	t.Helper()
	c := r.stack.Cluster()
	// a failure while setting up leaves a diagnosis too
	defer func() {
		if t.Failed() {
			r.diagnose()
		}
	}()
	id, err := l89.Random(10)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := l89.Random(16)
	if err != nil {
		t.Fatal(err)
	}
	r.own = []string{id, secret}
	cfg, err := l89.StoreConfig(id, secret)
	if err != nil {
		t.Fatal(err)
	}
	creds, err := l89.AWSCredentials(id, secret)
	if err != nil {
		t.Fatal(err)
	}
	image := os.Getenv("OBJECT_STORE_IMAGE")
	if !strings.Contains(image, "@sha256:") {
		t.Fatalf("OBJECT_STORE_IMAGE must be pinned by digest: %q", image)
	}
	c.Kubectl("create", "namespace", l89Store)
	c.Kubectl("-n", l89Store, "create", "secret", "generic", "store-config", "--from-file=s3.json="+r.file("s3.json", cfg))
	c.Apply(`apiVersion: apps/v1
kind: Deployment
metadata: {name: seaweed, namespace: ` + l89Store + `}
spec:
  replicas: 1
  selector: {matchLabels: {app: seaweed}}
  template:
    metadata: {labels: {app: seaweed}}
    spec:
      containers:
        - name: seaweed
          image: ` + image + `
          args: [server, -dir=/data, -s3, -s3.config=/cfg/s3.json, -s3.port=8333, -master.volumeSizeLimitMB=64, -volume.max=30]
          ports: [{containerPort: 8333}]
          readinessProbe: {tcpSocket: {port: 8333}, periodSeconds: 3}
          volumeMounts:
            - {name: data, mountPath: /data}
            - {name: cfg, mountPath: /cfg, readOnly: true}
      volumes:
        - {name: data, emptyDir: {}}
        - {name: cfg, secret: {secretName: store-config}}
---
apiVersion: v1
kind: Service
metadata: {name: seaweed, namespace: ` + l89Store + `}
spec:
  selector: {app: seaweed}
  ports: [{port: 8333, targetPort: 8333}]
`)
	c.Kubectl("-n", l89Store, "rollout", "status", "deployment/seaweed", "--timeout=5m")

	// the bucket, made by a signed PUT whose credentials are in a 0600 curl config, never in its arguments
	addr := r.forward(l89Store, "svc/seaweed", 8333)
	curlCfg, err := l89.CurlConfig(id, secret, "http://"+addr+"/"+l89Bucket, l89Region)
	if err != nil {
		t.Fatal(err)
	}
	kfile := r.file("bucket.curl", curlCfg)
	// curl's own message (show-error) is kept: the cause of a refusal is in it, and it holds no credential
	var last string
	shapetest.WaitFor(t, "the bucket (last curl: see the diagnosis)", 4*time.Minute, func() bool {
		out, err := exec.Command("curl", "-K", kfile).CombinedOutput()
		last = strings.TrimSpace(string(out))
		if err != nil {
			last += " (" + err.Error() + ")"
		}
		r.bucketLog = last
		return err == nil
	})

	// The repository key first (ruling 10): Velero writes its well-known default into this Secret itself
	// when it starts and finds none, and a repository made under that key keeps it.
	key, err := l89.Random(32)
	if err != nil {
		t.Fatal(err)
	}
	r.key = key
	r.own = append(r.own, key)
	c.Kubectl("create", "namespace", "velero")
	c.Kubectl("-n", "velero", "create", "secret", "generic", "velero-repo-credentials", "--from-file=repository-password="+r.file("repository-password", key))

	// no --default-volumes-to-fs-backup: the example Schedule's own setting is what is tested
	r.velero("install", "--provider", "aws", "--plugins", os.Getenv("VELERO_AWS_PLUGIN_IMAGE"), "--image", os.Getenv("VELERO_IMAGE"),
		"--bucket", l89Bucket, "--secret-file", r.file("velero-credentials", creds),
		"--backup-location-config", "region="+l89Region+",s3ForcePathStyle=true,s3Url=http://seaweed."+l89Store+".svc:8333,publicUrl=http://"+addr,
		"--use-node-agent", "--use-volume-snapshots=false", "--wait")
	c.Kubectl("-n", "velero", "rollout", "status", "daemonset/node-agent", "--timeout=5m")
	r.checkRepositoryKey()
	r.checkImages()
	shapetest.WaitFor(t, "the backup location to be available", 3*time.Minute, func() bool {
		ph, err := c.KubectlTry("", "-n", "velero", "get", "backupstoragelocation", "default", "-o", "jsonpath={.status.phase}")
		return err == nil && strings.TrimSpace(ph) == "Available"
	})
}

// checkImages fails unless every running Velero server and node agent container is the pinned server
// digest, and every init container (the AWS plugin's) the pinned plugin digest.
// The plugin is installed by tag (a digest in --plugins makes an invalid init container name), so the
// pin is checked here, on the imageID the kubelet reports.
func (r *l89Run) checkImages() {
	t := r.t
	t.Helper()
	c := r.stack.Cluster()
	ids := func(selector, field string) []string {
		out := c.Kubectl("-n", "velero", "get", "pods", "-l", selector, "-o", "jsonpath={range .items[*]}{."+field+"[*].imageID}{\"\\n\"}{end}")
		return strings.Fields(out)
	}
	server := l89.ImageDigest(os.Getenv("VELERO_IMAGE"))
	if err := l89.CheckDigest("the Velero server and node agent", ids("component=velero", "status.containerStatuses"), server); err != nil {
		t.Fatal(err)
	}
	if err := l89.CheckDigest("the Velero AWS plugin", ids("component=velero", "status.initContainerStatuses"), os.Getenv("VELERO_AWS_PLUGIN_DIGEST")); err != nil {
		t.Fatal(err)
	}
}

// checkRepositoryKey fails unless the Secret holds the generated key. The comparison is made here and
// nothing of either value is printed.
func (r *l89Run) checkRepositoryKey() {
	t := r.t
	t.Helper()
	b64 := r.stack.Cluster().Kubectl("-n", "velero", "get", "secret", "velero-repo-credentials", "-o", `jsonpath={.data.repository-password}`)
	got, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil || string(got) != r.key {
		t.Fatalf("the repository key in the cluster is not the one this run generated (decode error: %v)", err)
	}
}

// runREADMEChecks runs the chart README's two backup checks, extracted verbatim (l89.Command), with the
// pinned kubectl first on the PATH. No pipefail: grep exits 1 when the hostPath check finds nothing, and a
// broken command prints its error, which is not "nothing". Right after the backup both must print nothing. Then a claim that no
// pod mounts is made, which the per-claim check must name and nothing else: the check has teeth.
func (r *l89Run) runREADMEChecks(t *testing.T, cell *l82.Cell) {
	t.Helper()
	c, ns := r.stack.Cluster(), r.stack.Namespace()
	doc, err := os.ReadFile(filepath.Join(kindtest.Root(), "deploy", "helm", "port49", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	host, err := l89.Command(string(doc), "hostpath")
	if err != nil {
		t.Fatal(err)
	}
	claims, err := l89.Command(string(doc), "claims")
	if err != nil {
		t.Fatal(err)
	}
	if claims, err = l89.Fill(claims, l89Backup); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	if err := os.Symlink(kindtest.Bin(t, "KUBECTL_BIN"), filepath.Join(bin, "kubectl")); err != nil {
		t.Fatal(err)
	}
	run := func(script string) string {
		cmd := exec.Command("bash", "-c", script)
		cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "KUBECONFIG="+c.Kubeconfig)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("a README command failed: %v\n%s", err, kindtest.Filter(string(out)))
		}
		return string(out)
	}
	if out := run(host); strings.TrimSpace(out) != "" {
		t.Fatalf("the README's hostPath check lists volumes (etcd is on local volumes):\n%s", kindtest.Filter(out))
	}
	l82Row(cell, "the README's hostPath check (run verbatim) printed", "nothing")
	if out := run(claims); strings.TrimSpace(out) != "" {
		t.Fatalf("the README's per-claim check names claims with no completed pod volume backup:\n%s", kindtest.Filter(out))
	}
	l82Row(cell, "the README's per-claim check (run verbatim) printed", "nothing")

	// the counter-case: a claim no pod mounts is never copied, and the check must say so
	c.Apply(`apiVersion: v1
kind: PersistentVolumeClaim
metadata: {name: l89-orphan, namespace: ` + ns + `}
spec:
  accessModes: [ReadWriteOnce]
  storageClassName: port49-fsgroup
  resources: {requests: {storage: 1Mi}}
`)
	got := strings.TrimSpace(run(claims))
	c.Kubectl("-n", ns, "delete", "pvc", "l89-orphan", "--wait=false")
	if got != ns+"/l89-orphan" {
		t.Fatalf("the per-claim check on a claim no pod mounts printed %q, want %q", got, ns+"/l89-orphan")
	}
	l82Row(cell, "the README's per-claim check with a claim no pod mounts printed", "that claim and nothing else")
}

// diagnose keeps what explains a failed backup or restore, each piece through Scrub and the standard
// filter: Velero's own descriptions and logs, the pod volume operations' messages, and the server's and
// node agent's logs. No Secret is read, and the velero namespace is still never dumped.
func (r *l89Run) diagnose() {
	t := r.t
	c := r.stack.Cluster()
	var b strings.Builder
	add := func(what, out string) {
		fmt.Fprintf(&b, "== %s\n%s\n", what, l89.ScrubWith(kindtest.Filter(out), r.own...))
	}
	add("the last attempt at the bucket", r.bucketLog)
	// the object store's own pod: events, description and logs (no Secret is read)
	for _, args := range [][]string{
		{"-n", l89Store, "get", "pods,events", "-o", "wide"},
		{"-n", l89Store, "describe", "pods"},
		{"-n", l89Store, "logs", "deploy/seaweed", "--all-containers=true", "--tail=300"},
		{"-n", l89Store, "logs", "deploy/seaweed", "--all-containers=true", "--previous", "--tail=100"},
	} {
		out, _ := c.KubectlTry("", args...)
		add(strings.Join(args[2:], " "), out)
	}
	vel := func(args ...string) string {
		full := append([]string{"--kubeconfig", c.Kubeconfig, "--kubecontext", c.Context(), "-n", "velero"}, args...)
		out, _ := exec.Command(os.Getenv("VELERO_BIN"), full...).CombinedOutput()
		return string(out)
	}
	// the release's own namespace: why a pod is not ready (no Secret is read)
	for _, args := range [][]string{
		{"-n", "port49", "get", "pods,pvc,pv,events", "-o", "wide"},
		{"-n", "port49", "describe", "pods"},
	} {
		out, _ := c.KubectlTry("", args...)
		add("port49 "+strings.Join(args[2:], " "), out)
	}
	for _, p := range []string{"t-port49d-0", "t-port49d-1", "t-broker-0", "etcd-0"} {
		for _, extra := range [][]string{{}, {"--previous"}} {
			out, _ := c.KubectlTry("", append([]string{"-n", "port49", "logs", p, "--all-containers=true", "--tail=100"}, extra...)...)
			add("logs of "+p+" "+strings.Join(extra, " "), out)
		}
	}
	add("velero backup describe --details", vel("backup", "describe", l89Backup, "--details"))
	add("velero backup logs", vel("backup", "logs", l89Backup))
	add("velero restore describe --details", vel("restore", "describe", l89Restore, "--details"))
	add("velero restore logs", vel("restore", "logs", l89Restore))
	for _, kind := range []string{"podvolumebackups", "podvolumerestores"} {
		out, _ := c.KubectlTry("", "-n", "velero", "get", kind, "-o",
			`jsonpath={range .items[*]}{.metadata.name} {.status.phase} {.spec.pod.name} {.spec.volume}: {.status.message}{"\n"}{end}`)
		add(kind, out)
	}
	for _, sel := range []string{"component=velero"} { // the server and the node agent
		out, _ := c.KubectlTry("", "-n", "velero", "logs", "-l", sel, "--all-containers=true", "--tail=300", "--prefix=true")
		add("logs of "+sel, out)
	}
	text := b.String()
	if err := os.MkdirAll(r.out, 0o755); err == nil {
		_ = os.WriteFile(filepath.Join(r.out, "l89-diagnosis.txt"), []byte(text), 0o644)
	}
	t.Logf("L89 diagnosis (scrubbed):\n%s", text)
}

// chart's volumes and the paths whose owner, group and mode the cell records.
var l89Volumes = []struct {
	pvc   string
	paths []string
}{
	{"data-t-broker-0", []string{"/v/state", "/v/state/issuing-ca.key"}},
	{"data-t-broker-1", []string{"/v/state", "/v/state/issuing-ca.key"}},
	{"data-t-port49d-0", []string{"/v/data"}},
	{"data-t-port49d-1", []string{"/v/data"}},
}

// snapshot is the stat lines of every volume's paths and the sha256 of each broker's issuing CA
// certificate (a certificate, never the key).
func (r *l89Run) snapshot() (map[string][]l89.Stat, []string) {
	t := r.t
	t.Helper()
	stats := map[string][]l89.Stat{}
	for _, v := range l89Volumes {
		for _, s := range r.stack.StatOn(v.pvc, v.paths...) {
			stats[v.pvc] = append(stats[v.pvc], l89.Stat{Path: s.Path, Mode: s.Mode, UID: s.UID, GID: s.GID})
		}
	}
	var fps []string
	for _, pvc := range []string{"data-t-broker-0", "data-t-broker-1"} {
		out := r.stack.DebugPod("l89-ca-"+pvc, pvc, "sha256sum /v/state/issuing-ca.pem | cut -d' ' -f1", true)
		fps = append(fps, strings.TrimSpace(out))
	}
	return stats, fps
}

func (r *l89Run) cellA(t *testing.T, cell *l82.Cell) {
	c, ns := r.stack.Cluster(), r.stack.Namespace()
	defer func() {
		if t.Failed() || cell.Verdict != l82.Pass {
			r.diagnose()
		}
	}()
	r.checkRepositoryKey()
	l82Row(cell, "the repository key in the cluster is the one generated for this run", "yes")
	before, fpBefore := r.snapshot()
	logBefore := l89.LogFingerprint(c.Kubectl("-n", ns, "logs", "t-broker-0", "-c", "port49-broker"))
	if fpBefore[0] == "" || fpBefore[0] != fpBefore[1] {
		t.Fatalf("the brokers do not hold one CA before the backup")
	}

	// the chart's example, as shipped
	// but for etcd's namespace: the kind stack runs etcd in the release's (l89.LabSchedule)
	shipped, err := os.ReadFile(filepath.Join(kindtest.Root(), "deploy", "helm", "port49", "examples", "velero", "schedule.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	sched, err := l89.LabSchedule(string(shipped))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.KubectlTry(sched, "apply", "-f", "-"); err != nil {
		t.Fatal(err)
	}
	// skipImmediately must have been honoured. The CRD drops a field it does not know (the read-back would
	// be empty), and Velero's schedule controller resets the field to false once it has skipped the first
	// run, recording status.lastSkipped: so the proof is a known field plus lastSkipped, and no backup.
	var spec, skipped string
	shapetest.WaitFor(t, "the schedule controller to skip the immediate run", 90*time.Second, func() bool {
		spec = strings.TrimSpace(c.Kubectl("-n", "velero", "get", "schedule", "port49-daily", "-o", "jsonpath={.spec.skipImmediately}"))
		skipped = strings.TrimSpace(c.Kubectl("-n", "velero", "get", "schedule", "port49-daily", "-o", "jsonpath={.status.lastSkipped}"))
		return skipped != ""
	})
	if spec != "true" && spec != "false" {
		t.Fatalf("the Schedule's skipImmediately reads %q: the field was dropped or renamed", spec)
	}
	if n := strings.Fields(c.Kubectl("-n", "velero", "get", "backups", "-l", "velero.io/schedule-name=port49-daily", "-o", "name")); len(n) != 0 {
		t.Fatalf("the Schedule started %d backup(s) before the test asked for one: skipImmediately was not honoured", len(n))
	}
	l82Row(cell, "applying the example Schedule started no backup (skipImmediately skipped the first run)", "yes")
	l82Row(cell, "the lab's etcd shares the release's namespace", "yes: the Schedule names both namespaces, the lab applies it with the one")
	// what cells (c) and (d) compare with the restored volumes, taken just before the backup: a sentinel in
	// each spool, and each broker's marks.json and CA certificate. One absent cannot be compared, so the
	// cell stops (NOT RUN: the setup failed, nothing was measured).
	r.writeSentinels()
	r.hashesBefore = r.hashes()
	for _, k := range l89HashKeys() {
		if r.hashesBefore[k] == "" {
			t.Fatalf("%s is absent before the backup: cells (c) and (d) cannot compare it", k)
		}
	}
	l82Row(cell, "files hashed before the backup (each spool's sentinel, each broker's marks.json and CA certificate)", l89HashText(r.hashesBefore))
	r.velero("backup", "create", l89Backup, "--from-schedule", "port49-daily", "--wait")
	phase := strings.TrimSpace(c.Kubectl("-n", "velero", "get", "backup", l89Backup, "-o", "jsonpath={.status.phase}"))
	l82Row(cell, "the backup's phase", phase)
	if phase != "Completed" {
		t.Fatalf("the backup ended %s: nothing to restore", phase)
	}
	// which volumes the node agent backed up, by pod and volume name, and how
	pvb := c.Kubectl("-n", "velero", "get", "podvolumebackups", "-l", "velero.io/backup-name="+l89Backup, "-o",
		`jsonpath={range .items[*]}{.status.phase} {.spec.pod.name} {.spec.volume}{"\n"}{end}`)
	data, all := 0, 0
	for _, ln := range strings.Split(strings.TrimSpace(pvb), "\n") {
		f := strings.Fields(ln)
		if len(f) != 3 || f[0] != "Completed" {
			continue
		}
		all++
		if f[2] == "data" && (strings.HasPrefix(f[1], "t-broker-") || strings.HasPrefix(f[1], "t-port49d-")) {
			data++
		}
	}
	r.env.VolumeBackups = fmt.Sprintf("%d of the chart's 4 data volumes, %d in all", data, all)
	l82Row(cell, "pod volume backups completed", r.env.VolumeBackups)
	// every volume claim in the namespace must be in the backup, etcd's too: Velero skips a hostPath volume
	// with a warning and the restore then holds an empty store
	pvcs := len(strings.Fields(c.Kubectl("-n", ns, "get", "pvc", "-o", "name")))
	if all != pvcs {
		t.Fatalf("the node agent backed up %d of the namespace's %d volume claims (see the backup's warnings in the diagnosis)", all, pvcs)
	}
	if data == 0 || data != len(l89Volumes) {
		t.Fatalf("the node agent backed up %d of the chart's %d data volumes in backup %s", data, len(l89Volumes), l89Backup)
	}

	r.runREADMEChecks(t, cell)

	// delete the namespace, and wait for its volumes to go before restoring over the names
	c.Kubectl("delete", "namespace", ns, "--wait=true", "--timeout=5m")
	shapetest.WaitFor(t, "the namespace's volumes to be deleted", 5*time.Minute, func() bool {
		out, err := c.KubectlTry("", "get", "pv", "-o", `jsonpath={range .items[*]}{.spec.claimRef.namespace}{"\n"}{end}`)
		return err == nil && !strings.Contains(out, ns)
	})
	l82Row(cell, "the namespace was deleted", "yes, and its volumes")

	r.velero("restore", "create", l89Restore, "--from-backup", l89Backup, "--wait")
	rphase := strings.TrimSpace(c.Kubectl("-n", "velero", "get", "restore", l89Restore, "-o", "jsonpath={.status.phase}"))
	l82Row(cell, "the restore's phase", rphase)

	// ready: both StatefulSets, with the time the restore of the volumes takes inside it
	a := l89.A{FingerprintBefore: l89.Short(fpBefore[0])}
	ready := true
	for _, sts := range []string{"statefulset/t-broker", "statefulset/t-port49d"} {
		if _, err := c.KubectlTry("", "-n", ns, "rollout", "status", sts, "--timeout=8m"); err != nil {
			ready = false
			l82Row(cell, sts+" became ready", "no")
		}
	}
	a.Ready = ready
	if ready {
		l82Row(cell, "both StatefulSets became ready", "yes")
	}

	// the fence: every pod's logs and its init containers', this run's and the previous one's
	refusal := false
	for _, p := range []string{"t-broker-0", "t-broker-1", "t-port49d-0", "t-port49d-1"} {
		for _, args := range [][]string{
			{"logs", p, "--all-containers=true"},
			{"logs", p, "--all-containers=true", "--previous"},
		} {
			logs, _ := c.KubectlTry("", append([]string{"-n", ns}, args...)...)
			if l89Fence.MatchString(logs) {
				refusal = true
			}
		}
	}
	a.FenceRefusal = refusal
	l82Row(cell, "a fence refusal in a pod's log (the data directory writable by a group, or not owned by uid 65532)", map[bool]string{true: "yes", false: "no"}[refusal])

	if ready {
		after, fpAfter := r.snapshot()
		a.FingerprintAfter = l89.Short(fpAfter[0])
		a.LogBefore = logBefore
		a.LogAfter = l89.LogFingerprint(c.Kubectl("-n", ns, "logs", "t-broker-0", "-c", "port49-broker"))
		l82Row(cell, "the fingerprint the broker's \"issuing as\" line prints (first 12), before and after",
			fmt.Sprintf("%s, %s", l89.FingerprintText(a.LogBefore), l89.FingerprintText(a.LogAfter)))
		same := fpAfter[0] == fpBefore[0] && fpAfter[1] == fpBefore[1]
		if !same {
			a.FingerprintAfter = "changed: " + l89.Short(fpAfter[0])
		}
		l82Row(cell, "the issuing CA's fingerprint (first 12 hex) before the backup, and after the restore", fmt.Sprintf("%s, %s", l89.Short(fpBefore[0]), l89.Short(fpAfter[0])))
		for _, v := range l89Volumes {
			d := l89.Differences(before[v.pvc], after[v.pvc])
			obs := "unchanged"
			if len(d) > 0 {
				obs = strings.Join(d, "; ")
			}
			var was []string
			for _, s := range before[v.pvc] {
				was = append(was, s.String())
			}
			l82Row(cell, v.pvc+": before the backup", strings.Join(was, "; "))
			l82Row(cell, v.pvc+": after the restore", obs)
		}
	}
	cell.Verdict = l89.JudgeA(a)
}

func (r *l89Run) cellB(t *testing.T, cell *l82.Cell) {
	// a restore that was never read leaves this cell NOT RUN, which fails the test: FAIL is a measured answer
	read := false
	for _, row := range r.first.Rows {
		if row.Case == "the restore's phase" {
			read = true
		}
	}
	if !read {
		t.Errorf("cell (a) never read a restore, so a mint and a login after one cannot be measured")
		return
	}
	// FAIL stands until both succeed: a refused mint ends the subtest in shapetest.Mint
	cell.Verdict = l82.Fail
	broker := r.stack.Forward("svc/"+r.stack.Release()+"-broker", 8443)
	minted := false
	token := r.stack.Mint(broker)()
	minted = token != ""
	l82Row(cell, "a mint after the restore", map[bool]string{true: "succeeded", false: "failed"}[minted])
	st, err := r.stack.Device("t-port49d-0").TryLogin("alice", token)
	login := err == nil && st == wire.AuthenStatusPass
	l82Row(cell, "a login after the restore", map[bool]string{true: "succeeded", false: fmt.Sprintf("failed, status %d", st)}[login])
	cell.Verdict = l89.JudgeB(minted, login)
}
