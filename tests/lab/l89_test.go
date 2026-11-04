//go:build lab

package lab

import (
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
// group (internal/config), and the owner init's refusal of a volume not owned by uid 65532.
var l89Fence = regexp.MustCompile(`writable by its group or others|not owned by uid 65532`)

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
	cells := []l82.Cell{{ID: "a"}, {ID: "b"}}
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

	stack := kindstack.BringUp(t, "port49l89")
	r := &l89Run{t: t, env: env, stack: stack, dir: t.TempDir()}
	r.installStoreAndVelero()
	stack.Run(t, "a_backup_delete_restore", func(t *testing.T) { r.cellA(t, &cells[0]) })
	stack.Run(t, "b_mint_and_login", func(t *testing.T) { r.cellB(t, &cells[1]) })
}

type l89Run struct {
	t     *testing.T
	env   *l89.Env
	stack *kindstack.Stack
	dir   string // a 0700 temp directory: the credential files live here
}

func l89Env(t *testing.T) *l89.Env {
	t.Helper()
	e := l82Env(t)
	return &l89.Env{Date: e.Date, Runner: e.Runner, Run: e.Run, Docker: e.Docker, Kernel: e.Kernel, Kind: e.Kind,
		NodeImage: e.NodeImage, Kubectl: e.Kubectl, Helm: e.Helm, Velero: os.Getenv("VELERO_VERSION"),
		VeleroImage: os.Getenv("VELERO_IMAGE"), AWSPlugin: os.Getenv("VELERO_AWS_PLUGIN_IMAGE"), ObjectStore: os.Getenv("OBJECT_STORE_IMAGE")}
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
	id, err := l89.Random(10)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := l89.Random(16)
	if err != nil {
		t.Fatal(err)
	}
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
	shapetest.WaitFor(t, "the bucket", 2*time.Minute, func() bool {
		return exec.Command("curl", "-K", kfile).Run() == nil
	})

	r.velero("install", "--provider", "aws", "--plugins", os.Getenv("VELERO_AWS_PLUGIN_IMAGE"), "--image", os.Getenv("VELERO_IMAGE"),
		"--bucket", l89Bucket, "--secret-file", r.file("velero-credentials", creds),
		"--backup-location-config", "region="+l89Region+",s3ForcePathStyle=true,s3Url=http://seaweed."+l89Store+".svc:8333",
		"--use-node-agent", "--default-volumes-to-fs-backup", "--use-volume-snapshots=false", "--wait")
	c.Kubectl("-n", "velero", "rollout", "status", "daemonset/node-agent", "--timeout=5m")

	// The repository key, from a Secret, before the first backup (ruling 10): Velero's default is well known.
	key, err := l89.Random(32)
	if err != nil {
		t.Fatal(err)
	}
	c.Kubectl("-n", "velero", "create", "secret", "generic", "velero-repo-credentials", "--from-file=repository-password="+r.file("repository-password", key))
	shapetest.WaitFor(t, "the backup location to be available", 3*time.Minute, func() bool {
		ph, err := c.KubectlTry("", "-n", "velero", "get", "backupstoragelocation", "default", "-o", "jsonpath={.status.phase}")
		return err == nil && strings.TrimSpace(ph) == "Available"
	})
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
	before, fpBefore := r.snapshot()
	if fpBefore[0] == "" || fpBefore[0] != fpBefore[1] {
		t.Fatalf("the brokers do not hold one CA before the backup")
	}

	// the chart's example, as shipped
	example := filepath.Join(kindtest.Root(), "deploy", "helm", "port49", "examples", "velero", "schedule.yaml")
	c.Kubectl("apply", "-f", example)
	r.velero("backup", "create", l89Backup, "--from-schedule", "port49-daily", "--wait")
	phase := strings.TrimSpace(c.Kubectl("-n", "velero", "get", "backup", l89Backup, "-o", "jsonpath={.status.phase}"))
	l82Row(cell, "the backup's phase", phase)
	if phase != "Completed" {
		t.Fatalf("the backup ended %s: nothing to restore", phase)
	}
	// which volumes the node agent backed up, by pod and volume name, and how
	pvb := c.Kubectl("-n", "velero", "get", "podvolumebackups", "-o",
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
	if data != 4 {
		t.Fatalf("the node agent backed up %d of the chart's 4 data volumes", data)
	}

	// delete the namespace, and wait for its volumes to go before restoring over the names
	c.Kubectl("delete", "namespace", ns, "--wait=true", "--timeout=10m")
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
		if _, err := c.KubectlTry("", "-n", ns, "rollout", "status", sts, "--timeout=10m"); err != nil {
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
