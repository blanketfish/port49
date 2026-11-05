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

// spools is each port49d spool directory's listing (names only), joined: "t-port49d-0: a b; t-port49d-1: ...".
func (r *l89Run) spools() string {
	var parts []string
	for _, pvc := range []string{"data-t-port49d-0", "data-t-port49d-1"} {
		out := r.stack.DebugPod("l89-spool-"+pvc, pvc, "ls -A /v/data | tr '\\n' ' '", true)
		parts = append(parts, pvc+": "+strings.TrimSpace(out))
	}
	return strings.Join(parts, "; ")
}

// cellOrder is cells (c) and (d): the Velero README's steps run from its own text (the marked blocks,
// l89.Command), after the namespace is deleted once more and the backup of cell (a) is restored.
//
// The lab's etcd shares the release's namespace, so the README's step 1 (etcd alone, in its own namespace)
// cannot be run apart from the rest: (c) restores the namespace once, with the README's resource modifier
// limited to the release's two StatefulSets, and waits for etcd as step 1 does. (d), the fallback, restores
// the namespace normally (the pods run, so the node agent can restore their volumes) and scales the two
// StatefulSets to 0 before the token delete. Both then run the README's token delete, revoke-offline.sh and
// scale-up, and check that every pod volume restore Completed, the CA is the one it was, marks.json is
// there and the spools hold what they held.
func (r *l89Run) cellOrder(t *testing.T, cell *l82.Cell, fallback bool) {
	c, ns := r.stack.Cluster(), r.stack.Namespace()
	defer func() {
		if t.Failed() || cell.Verdict != l82.Pass {
			r.diagnose()
		}
	}()
	// FAIL stands until the checks pass: a step that fails ends the subtest, and that is a measured answer
	cell.Verdict = l82.Fail
	if r.spoolBefore == "" {
		t.Errorf("cell (a) never recorded the spools, so they cannot be compared")
		cell.Verdict = ""
		return
	}
	doc, err := os.ReadFile(filepath.Join(kindtest.Root(), "deploy", "helm", "port49", "examples", "velero", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	step := func(marker string, repl map[string]string) string {
		cmd, err := l89.Command(string(doc), marker)
		if err != nil {
			t.Fatal(err)
		}
		if cmd, err = l89.Subst(cmd, repl); err != nil {
			t.Fatal(err)
		}
		return cmd
	}
	backup := map[string]string{"<backup>": l89Backup}
	example := filepath.Join(kindtest.Root(), "deploy", "helm", "port49", "examples", "velero")

	// the files the README's commands read from the working directory: the examples, for the lab's
	// namespace (and, for the modifier, the lab's one namespace)
	work := t.TempDir()
	token, err := os.ReadFile(filepath.Join(example, "restore-token-delete.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	tok := strings.ReplaceAll(strings.ReplaceAll(string(token), "port49-etcd.svc", ns+".svc"), "namespace: port49-etcd", "namespace: "+ns)
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
	run := func(dir, script string) string {
		cmd := exec.Command("bash", "-ec", script)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "KUBECONFIG="+c.Kubeconfig)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("a README command failed: %v\n%s", err, kindtest.Filter(l89.Scrub(string(out))))
		}
		return string(out)
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

	waitEtcd := fmt.Sprintf("kubectl -n %s wait --for=condition=Ready pod -l app.kubernetes.io/name=etcd --timeout=5m", ns)
	if !fallback {
		c.Kubectl("-n", "velero", "delete", "configmap", "restore-scale-zero", "--ignore-not-found")
		run(work, step("restorezero", backup))
		l82Row(cell, "README step 3 (the restore with the resource modifier, both StatefulSets at 0 replicas) ran from its own text", "yes")
		run(work, waitEtcd)
		l82Row(cell, "README step 1's wait for etcd (the lab's etcd is restored by the same restore)", "ready")
		replicas := strings.TrimSpace(c.Kubectl("-n", ns, "get", "statefulset", "t-broker", "t-port49d", "-o", `jsonpath={range .items[*]}{.spec.replicas} {end}`))
		l82Row(cell, "the two StatefulSets' replicas after the restore", replicas)
		if replicas != "0 0" {
			t.Fatalf("the StatefulSets were restored at %q replicas, not 0 0: the resource modifier did not apply", replicas)
		}
	} else {
		run(work, step("etcdrestore", backup))
		l82Row(cell, "README step 1's restore command ran from its own text; in the lab it restores the whole namespace, so the pods ran against the restored store before the token delete", "yes")
		phaseWait(t, c)
		c.Kubectl("-n", ns, "scale", "statefulset/t-broker", "statefulset/t-port49d", "--replicas=0")
		_, _ = c.KubectlTry("", "-n", ns, "wait", "--for=delete", "pod", "-l", "app.kubernetes.io/name=port49", "--timeout=3m")
		l82Row(cell, "both port49 StatefulSets scaled to 0 once the volumes were restored", "yes")
	}

	// the volumes: the restore's pod volume restores, by pod and volume
	pvr := c.Kubectl("-n", "velero", "get", "podvolumerestores", "-l", "velero.io/restore-name="+restoreName(c, l89Backup), "-o",
		`jsonpath={range .items[*]}{.status.phase} {.spec.pod.name} {.spec.volume}{"\n"}{end}`)
	cs := l89.C{FingerprintBefore: l89.Short(fpBefore[0]), SpoolBefore: r.spoolBefore}
	for _, ln := range strings.Split(strings.TrimSpace(pvr), "\n") {
		f := strings.Fields(ln)
		if len(f) != 3 {
			continue
		}
		cs.Volumes++
		if f[0] != "Completed" {
			cs.NotCompleted++
			l82Row(cell, "a pod volume restore of "+f[1]+"/"+f[2], f[0])
		}
	}
	l82Row(cell, "pod volume restores made, and not Completed", fmt.Sprintf("%d, %d", cs.Volumes, cs.NotCompleted))
	if cs.Volumes == 0 || cs.NotCompleted > 0 {
		// the rest cannot be measured on volumes that did not come back, but the README's steps still run
		l82Row(cell, "the volumes did not all come back", "the remaining steps ran anyway, to see what an operator would see")
	}

	run(work, step("tokendelete", nil))
	l82Row(cell, "README step 2 (the token delete Job) ran from its own text and completed", "yes")
	run(kindtest.Root(), step("revoke", map[string]string{"<release>": r.stack.Release()}))
	l82Row(cell, "README step 4 (revoke-offline.sh) ran from its own text", "yes")
	run(work, step("scaleup", map[string]string{"<release>": r.stack.Release(), "<brokers>": "2", "<port49d>": "2"}))
	l82Row(cell, "README step 5 (the scale-up, brokers then port49d) ran from its own text and both rolled out", "yes")

	_, fpAfter := r.snapshot()
	cs.FingerprintAfter = l89.Short(fpAfter[0])
	l82Row(cell, "the issuing CA's fingerprint (first 12 hex) before the namespace was deleted, and after the scale-up", fmt.Sprintf("%s, %s", l89.Short(fpBefore[0]), l89.Short(fpAfter[0])))
	marks := strings.TrimSpace(r.stack.DebugPod("l89-marks", "data-t-broker-0", "test -s /v/state/marks.json && echo present || echo missing", true))
	cs.MarksPresent = marks == "present"
	l82Row(cell, "state/marks.json on data-t-broker-0 after the scale-up", marks)
	cs.SpoolAfter = r.spools()
	l82Row(cell, "the spools before the backup", r.spoolBefore)
	l82Row(cell, "the spools after the scale-up", cs.SpoolAfter)
	cell.Verdict = l89.JudgeC(cs)
}

// restoreName is the name of the restore the README's command made: Velero names it
// <backup>-<timestamp> when --restore-name is not given, so it is read as the newest restore of the backup.
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

// phaseWait waits until every pod volume restore of the newest restore has left New and InProgress, so the
// StatefulSets are not scaled to 0 under a copy that is still running.
func phaseWait(t *testing.T, c *kindtest.Cluster) {
	t.Helper()
	label := "velero.io/restore-name=" + restoreName(c, l89Backup)
	shapetest.WaitFor(t, "the pod volume restores to end", 10*time.Minute, func() bool {
		out, err := c.KubectlTry("", "-n", "velero", "get", "podvolumerestores", "-l", label, "-o", `jsonpath={range .items[*]}{.status.phase} {end}`)
		if err != nil || strings.TrimSpace(out) == "" {
			return false
		}
		return !strings.Contains(out, "New") && !strings.Contains(out, "InProgress") && !strings.Contains(out, "Prepared") && !strings.Contains(out, "Accepted")
	})
}
