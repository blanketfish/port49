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

	"github.com/blanketfish/port49/tests/kind/kindtest"
	"github.com/blanketfish/port49/tests/shapes/l82"
	"github.com/blanketfish/port49/tests/shapes/l89"
	"github.com/blanketfish/port49/tests/shapes/shapetest"
)

// l89Sentinel is the file cell (a) writes in each port49d spool before the backup: the spool holds no
// accounting record in the lab, and port49d writes restore.json there at every start, so a listing of
// the directory cannot tell a restored spool from an empty one.
const l89Sentinel = "/v/data/l89-sentinel"

// l89Hashed is the files cells (c) and (d) compare with the backup, by claim: each broker's marks.json and
// issuing CA certificate (never the key), and each spool's sentinel.
var l89Hashed = []struct {
	pvc   string
	paths []string
}{
	{"data-t-broker-0", []string{"/v/state/marks.json", "/v/state/issuing-ca.pem"}},
	{"data-t-broker-1", []string{"/v/state/marks.json", "/v/state/issuing-ca.pem"}},
	{"data-t-port49d-0", []string{l89Sentinel}},
	{"data-t-port49d-1", []string{l89Sentinel}},
}

// l89HashKeys is every "claim:path" of l89Hashed.
func l89HashKeys() []string {
	var keys []string
	for _, v := range l89Hashed {
		for _, p := range v.paths {
			keys = append(keys, v.pvc+":"+p)
		}
	}
	return keys
}

// writeSentinels writes a random sentinel, owned by uid 65532 and mode 0600 as the init containers
// require, in each port49d's spool. Its content is never printed; only its hash's first characters are.
func (r *l89Run) writeSentinels() {
	t := r.t
	t.Helper()
	script := "umask 077 && head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \\n' > " + l89Sentinel +
		" && chown 65532:65532 " + l89Sentinel + " && echo written"
	for _, pvc := range []string{"data-t-port49d-0", "data-t-port49d-1"} {
		if out := strings.TrimSpace(r.stack.DebugPod("l89-sentinel-"+pvc, pvc, script, false)); out != "written" {
			t.Fatalf("the sentinel was not written on %s: %q", pvc, kindtest.Filter(out))
		}
	}
}

// hashes is the sha256 of each file of l89Hashed ("" for one absent or empty), keyed "claim:path".
func (r *l89Run) hashes() map[string]string {
	got := map[string]string{}
	for _, v := range l89Hashed {
		out := r.stack.DebugPod("l89-hash-"+v.pvc, v.pvc, l89.HashScript(v.paths...), true)
		for k, h := range l89.ParseHashes(v.pvc, out) {
			got[k] = h
		}
	}
	return got
}

// l89HashText is the hashes for a results row: the first characters of each, or "absent".
func l89HashText(h map[string]string) string {
	var parts []string
	for _, k := range l89HashKeys() {
		v, ok := h[k]
		switch {
		case !ok:
			v = "not read"
		case v == "":
			v = "absent"
		default:
			v = l89.Short(v)
		}
		parts = append(parts, k+" "+v)
	}
	return strings.Join(parts, "; ")
}

// cellOrder is cells (c) and (d): the Velero README's steps run from its own text (the marked blocks,
// l89.Steps), after the namespace is deleted once more and the backup of cell (a) is restored.
//
// The lab's etcd shares the release's namespace, so the README's step 1 (etcd alone, in its own namespace)
// cannot be run apart from the rest: (c) restores the namespace once, with the README's resource modifier
// limited to the release's two StatefulSets, and waits for etcd as step 1 does. (d), the fallback, runs
// step 1's restore, which in the one namespace restores the release too with its pods running (so the node
// agent can restore their volumes), and scales the two StatefulSets to 0 before the token delete. Both run
// the README's volume check, and stop as it says when a volume did not come back. Then, with both
// StatefulSets at 0, the files cell (a) hashed are compared, and the README's token delete,
// revoke-offline.sh and scale-up run; after them the CA is the one it was and no broker started a fresh
// copy of the marks.
//
// A README command that fails, or a check that does not hold, is a measured FAIL. A failure of the
// harness's own setup (a kubectl call of its own, a debug pod) leaves the verdict empty: NOT RUN, which
// fails the test and is never written as a measurement.
func (r *l89Run) cellOrder(t *testing.T, cell *l82.Cell, fallback bool) {
	c, ns := r.stack.Cluster(), r.stack.Namespace()
	defer func() {
		if t.Failed() && cell.Verdict == "" {
			l82Row(cell, "the harness's own setup failed: not a measurement", "see the test log and l89-diagnosis.txt")
		}
		if t.Failed() || cell.Verdict != l82.Pass {
			r.diagnose()
		}
	}()
	if len(r.hashesBefore) == 0 {
		t.Fatalf("cell (a) never hashed the files before the backup, so they cannot be compared")
	}
	doc, err := os.ReadFile(filepath.Join(kindtest.Root(), "deploy", "helm", "port49", "examples", "velero", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	steps, err := l89.Steps(string(doc), ns, r.stack.Release(), l89Backup, 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	example := filepath.Join(kindtest.Root(), "deploy", "helm", "port49", "examples", "velero")

	// the files the README's commands read from the working directory: the examples, for the lab's
	// namespace (and, for the modifier, the lab's one namespace)
	work := t.TempDir()
	token, err := os.ReadFile(filepath.Join(example, "restore-token-delete.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	tok := strings.ReplaceAll(strings.ReplaceAll(string(token), "port49-etcd.svc", ns+".svc"), "namespace: port49-etcd", "namespace: "+ns)
	if strings.Contains(tok, "port49-etcd") {
		t.Fatalf("restore-token-delete.yaml names port49-etcd in a way the lab does not rewrite")
	}
	mod, err := os.ReadFile(filepath.Join(example, "restore-scale-zero.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	labMod, err := l89.LabModifier(string(mod), r.stack.Release())
	if err != nil {
		t.Fatal(err)
	}
	for f, body := range map[string]string{"restore-token-delete.yaml": tok, "restore-scale-zero.yaml": labMod} {
		if err := os.WriteFile(filepath.Join(work, f), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	// kubectl and velero as the README writes them, pointed at the lab's cluster
	bin := t.TempDir()
	if err := os.Symlink(kindtest.Bin(t, "KUBECTL_BIN"), filepath.Join(bin, "kubectl")); err != nil {
		t.Fatal(err)
	}
	wrapper := fmt.Sprintf("#!/bin/sh\nexec %q --kubeconfig %q --kubecontext %q -n velero \"$@\"\n", kindtest.Bin(t, "VELERO_BIN"), c.Kubeconfig, c.Context())
	if err := os.WriteFile(filepath.Join(bin, "velero"), []byte(wrapper), 0o755); err != nil {
		t.Fatal(err)
	}
	// readme runs one README step. Its failure is the measurement: the cell is a FAIL and ends.
	readme := func(what, dir, script string) string {
		cmd := exec.Command("bash", "-ec", script)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "KUBECONFIG="+c.Kubeconfig)
		out, err := cmd.CombinedOutput()
		if err != nil {
			l82Row(cell, what, "its command failed ("+err.Error()+"); the output is in the test log")
			cell.Verdict = l82.Fail
			t.Fatalf("%s: a README command failed: %v\n%s", what, err, kindtest.Filter(l89.Scrub(string(out))))
		}
		return string(out)
	}
	// measured ends the cell with a measured FAIL on a check that does not hold
	measured := func(what, observation string) {
		l82Row(cell, what, observation)
		cell.Verdict = l82.Fail
		t.FailNow()
	}
	// noPort49Pods waits until no port49 pod is left, so the volumes are read with nothing running on them
	noPort49Pods := func() {
		shapetest.WaitFor(t, "no port49 pod to be left", 3*time.Minute, func() bool {
			out, err := c.KubectlTry("", "-n", ns, "get", "pods", "-l", "app.kubernetes.io/name=port49", "-o", "name")
			return err == nil && strings.TrimSpace(out) == ""
		})
	}

	_, fpBefore := r.snapshot()
	if fpBefore[0] == "" || fpBefore[0] != fpBefore[1] {
		t.Fatalf("the brokers do not hold one CA before the restore")
	}

	// the README's first command: both namespaces deleted (the lab has one), and its volumes gone
	c.Kubectl("delete", "namespace", ns, "--wait=true", "--timeout=5m")
	shapetest.WaitFor(t, "the namespace's volumes to be deleted", 5*time.Minute, func() bool {
		out, err := c.KubectlTry("", "get", "pv", "-o", `jsonpath={range .items[*]}{.spec.claimRef.namespace}{"\n"}{end}`)
		return err == nil && !strings.Contains(out, ns)
	})
	l82Row(cell, "the namespace was deleted", "yes, and its volumes")

	if !fallback {
		l82Row(cell, "the resource modifier as the lab runs it", "restore-scale-zero.yaml with a resourceNameRegex the lab adds (its etcd shares the namespace), so the shipped file is not run as shipped")
		c.Kubectl("-n", "velero", "delete", "configmap", "restore-scale-zero", "--ignore-not-found")
		readme("README step 3 (the restore with the resource modifier, both StatefulSets at 0 replicas)", work, steps["restorezero"])
		l82Row(cell, "README step 3 (the restore with the resource modifier, both StatefulSets at 0 replicas) ran from its own text", "yes")
		readme("README step 1's wait for etcd (the lab's etcd is restored by step 3's restore)", work,
			fmt.Sprintf("kubectl -n %s wait --for=condition=Ready pod -l app.kubernetes.io/name=etcd --timeout=5m", ns))
		l82Row(cell, "README step 1's wait for etcd (the lab's etcd is restored by step 3's restore)", "ready")
		replicas := strings.TrimSpace(c.Kubectl("-n", ns, "get", "statefulset", "t-broker", "t-port49d", "-o", `jsonpath={range .items[*]}{.spec.replicas} {end}`))
		if replicas != "0 0" {
			measured("the two StatefulSets' replicas after the restore (the resource modifier did not apply)", replicas)
		}
		l82Row(cell, "the two StatefulSets' replicas after the restore", replicas)
	} else {
		readme("README step 1's restore", work, steps["etcdrestore"])
		l82Row(cell, "README step 1's restore ran from its own text, etcd's namespace the lab's one", "yes: in the lab it restores the release too, normally, so its pods ran against the restored store before the token delete")
		l82Row(cell, "what (d) cannot show", "that port49 pods restored while etcd is held at 0 (the README's fallback steps 3 to 7) are harmless: the lab's etcd cannot be held down apart from the release")
	}

	// the README's volume check, once Velero has finished with the volumes
	phaseWait(t, c)
	phase, vols := l89.ParseVolumes(readme("the README's volume check", work, steps["volumes"]))
	cs := l89.C{RestorePhase: phase, Volumes: vols, FingerprintBefore: l89.Short(fpBefore[0]), Before: r.hashesBefore}
	for _, v := range l89Volumes {
		cs.Want = append(cs.Want, strings.TrimPrefix(v.pvc, "data-")+"/data")
	}
	l82Row(cell, "the restore's phase, as the README's volume check prints it", phase)
	complete := phase == "Completed"
	for _, w := range cs.Want {
		got := vols[w]
		if got == "" {
			got = "no pod volume restore"
		}
		complete = complete && got == "Completed"
		l82Row(cell, "the pod volume restore of "+w, got)
	}

	if fallback {
		// the README's fallback step 6, run by the lab: the volumes are back, the StatefulSets go to 0
		c.Kubectl("-n", ns, "scale", "statefulset/t-broker", "statefulset/t-port49d", "--replicas=0")
		l82Row(cell, "both port49 StatefulSets scaled to 0 after the volume check (the fallback's step 6)", "yes")
	}
	noPort49Pods()
	cs.AtZero = r.hashes()
	l82Row(cell, "files hashed before the backup", l89HashText(r.hashesBefore))
	l82Row(cell, "the same files with both StatefulSets at 0, before the scale-up", l89HashText(cs.AtZero))
	if !complete {
		// the README: never run step 5 while a volume is not Completed; the operator stops here, and so does the cell
		cell.Verdict = l89.JudgeC(cs)
		l82Row(cell, "the README says never to scale up while a volume is not Completed", "so the cell stopped before steps 2, 4 and 5, as an operator would")
		return
	}

	readme("README step 2 (the token delete Job)", work, steps["tokendelete"])
	l82Row(cell, "README step 2 (the token delete Job) ran from its own text and completed", "yes")
	readme("README step 4 (revoke-offline.sh)", kindtest.Root(), steps["revoke"])
	l82Row(cell, "README step 4 (revoke-offline.sh) ran from its own text", "yes")
	readme("README step 5 (the scale-up)", work, steps["scaleup"])
	l82Row(cell, "README step 5 (the scale-up, brokers then port49d) ran from its own text and both rolled out", "yes")

	_, fpAfter := r.snapshot()
	cs.FingerprintAfter = l89.Short(fpAfter[0])
	l82Row(cell, "the issuing CA's fingerprint (first 12 hex) before the namespace was deleted, and after the scale-up", fmt.Sprintf("%s, %s", l89.Short(fpBefore[0]), l89.Short(fpAfter[0])))
	for _, p := range []string{"t-broker-0", "t-broker-1"} {
		logs := c.Kubectl("-n", ns, "logs", p, "-c", "port49-broker")
		fresh := strings.Contains(logs, l89.FreshCopyLine)
		cs.FreshCopy = cs.FreshCopy || fresh
		l82Row(cell, p+"'s log after the scale-up says it had no marks.json at this start", map[bool]string{true: "yes", false: "no"}[fresh])
	}
	cell.Verdict = l89.JudgeC(cs)
}

// restoreName is the name of the restore the README's command made: Velero names it
// <backup>-<timestamp> when no name is given, so it is read as the newest restore of the backup.
func restoreName(c *kindtest.Cluster, backup string) string {
	out := c.Kubectl("-n", "velero", "get", "restores", "--sort-by=.metadata.creationTimestamp", "-o",
		`jsonpath={range .items[*]}{.spec.backupName} {.metadata.name}{"\n"}{end}`)
	got := ""
	for _, ln := range strings.Split(strings.TrimSpace(out), "\n") {
		if f := strings.Fields(ln); len(f) == 2 && f[0] == backup {
			got = f[1]
		}
	}
	return got
}

// phaseWait waits until the newest restore has ended and none of its pod volume restores is still
// running, so the README's volume check reads where they ended. A restore that made none at all (the
// suspected failure of cell c) ends too, and the check then lists nothing.
func phaseWait(t *testing.T, c *kindtest.Cluster) {
	t.Helper()
	name := restoreName(c, l89Backup)
	if name == "" {
		t.Fatalf("no restore of %s to wait for", l89Backup)
	}
	ended := map[string]bool{"Completed": true, "PartiallyFailed": true, "Failed": true, "FailedValidation": true}
	shapetest.WaitFor(t, "the restore and its pod volume restores to end", 10*time.Minute, func() bool {
		ph, err := c.KubectlTry("", "-n", "velero", "get", "restore", name, "-o", "jsonpath={.status.phase}")
		if err != nil || !ended[strings.TrimSpace(ph)] {
			return false
		}
		out, err := c.KubectlTry("", "-n", "velero", "get", "podvolumerestores", "-l", "velero.io/restore-name="+name, "-o", `jsonpath={range .items[*]}{.status.phase} {end}`)
		if err != nil {
			return false
		}
		for _, p := range strings.Fields(out) {
			if p != "Completed" && p != "Failed" && p != "Canceled" {
				return false
			}
		}
		return true
	})
}
