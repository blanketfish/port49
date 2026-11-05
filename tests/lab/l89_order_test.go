//go:build lab

package lab

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blanketfish/port49/tests/kind/kindtest"
	"github.com/blanketfish/port49/tests/shapes/l82"
	"github.com/blanketfish/port49/tests/shapes/l89"
)

// l89Revoked is the principal cell (a) revokes before the backup, so each broker's marks.json exists and
// holds a mark the restore must bring back. README step 4 revokes the same principal again.
const l89Revoked = "user:bob@example.com"

// l89Lab is the kind cluster as l89.BeforeBackup sees it: revoke-offline.sh, and debug pods on the claims.
type l89Lab struct{ r *l89Run }

func (l l89Lab) Revoke(principal string) error {
	t, c, ns := l.r.t, l.r.stack.Cluster(), l.r.stack.Namespace()
	script := fmt.Sprintf("exec bash %q %q %q -- --principal %q\n",
		filepath.Join(kindtest.Root(), "deploy", "helm", "port49", "scripts", "revoke-offline.sh"), ns, l.r.stack.Release(), principal)
	env := append(os.Environ(), "KUBECONFIG="+c.Kubeconfig, "PATH="+filepath.Dir(kindtest.Bin(t, "KUBECTL_BIN"))+":"+os.Getenv("PATH"))
	within, _ := l.r.bound(6 * time.Minute)
	out, timedOut, err := l89.RunBounded(kindtest.Root(), env, script, within)
	if err != nil {
		t.Logf("revoke-offline.sh:\n%s", kindtest.Filter(l89.Scrub(out)))
		if timedOut {
			return fmt.Errorf("revoke-offline.sh did not end within %v", within.Round(time.Second))
		}
		return fmt.Errorf("revoke-offline.sh: %v", err)
	}
	// the script scales the brokers back to the count it found; wait for them to be back
	c.Kubectl("-n", ns, "rollout", "status", "statefulset/"+l.r.stack.Release()+"-broker", l.r.kubectlTimeout(4*time.Minute))
	for _, p := range []string{"t-broker-0", "t-broker-1"} {
		c.WaitReady(ns, p, 4*time.Minute)
	}
	return nil
}

// Read is cat of a file on the claim. Only marks.json is read so: principals and certificate keys, no secret.
func (l l89Lab) Read(pvc, path string) string {
	return l.r.stack.DebugPod("l89-read-"+pvc, pvc, "cat "+path+" 2>/dev/null || true", true)
}

// WriteSentinel writes a random sentinel, owned by uid 65532 and mode 0600 as the init containers require.
// Its content is never printed; only its hash's first characters are.
func (l l89Lab) WriteSentinel(pvc, path string) error {
	script := "umask 077 && head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \\n' > " + path +
		" && chown 65532:65532 " + path + " && echo written"
	if out := strings.TrimSpace(l.r.stack.DebugPod("l89-sentinel-"+pvc, pvc, script, false)); out != "written" {
		return fmt.Errorf("the debug pod printed %q", kindtest.Filter(out))
	}
	return nil
}

func (l l89Lab) Hashes(pvc string, paths []string) map[string]string {
	return l89.ParseHashes(pvc, l.r.stack.DebugPod("l89-hash-"+pvc, pvc, l89.HashScript(paths...), true))
}

func (l l89Lab) Eventually(what string, cond func() bool) bool {
	within, _ := l.r.bound(3 * time.Minute)
	for deadline := time.Now().Add(within); ; time.Sleep(5 * time.Second) {
		if cond() {
			return true
		}
		if time.Now().After(deadline) {
			l.r.t.Logf("%s: not within %v", what, within.Round(time.Second))
			return false
		}
	}
}

// hashes is the sha256 of each file of l89.Hashed ("" for one absent or empty), keyed "claim:path".
func (r *l89Run) hashes() map[string]string {
	got := map[string]string{}
	for _, f := range l89.Hashed {
		for k, h := range (l89Lab{r}).Hashes(f.PVC, f.Paths) {
			got[k] = h
		}
	}
	return got
}

// marks is each broker's decoded marks.json, by claim.
func (r *l89Run) marks() map[string][]l89.Mark {
	got := map[string][]l89.Mark{}
	for _, pvc := range []string{"data-t-broker-0", "data-t-broker-1"} {
		m, err := l89.DecodeMarks((l89Lab{r}).Read(pvc, l89.MarksPath))
		if err != nil {
			r.t.Logf("%s: %v", pvc, err)
		}
		got[pvc] = m
	}
	return got
}

// l89HashText is the hashes for a results row: the first characters of each, or "absent".
func l89HashText(h map[string]string) string {
	var parts []string
	for _, k := range l89.HashKeys() {
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

// l89MarksText is each broker's marks for a results row: kind and key, never more.
func l89MarksText(m map[string][]l89.Mark) string {
	var parts []string
	for _, pvc := range []string{"data-t-broker-0", "data-t-broker-1"} {
		var ks []string
		for _, mk := range m[pvc] {
			ks = append(ks, mk.Kind+" "+mk.Key)
		}
		if len(ks) == 0 {
			ks = []string{"none"}
		}
		parts = append(parts, pvc+": "+strings.Join(ks, ", "))
	}
	return strings.Join(parts, "; ")
}

// cellOrder is cells (c) and (d): the Velero README's steps run from its own text (the marked blocks,
// l89.Steps), after the namespace is deleted once more and the backup of cell (a) is restored.
//
// The lab's etcd shares the release's namespace, so the README's step 1 (etcd alone, in its own namespace)
// cannot be run apart from the rest: (c) restores the namespace once, with the README's resource modifier
// limited to the release's two StatefulSets, and waits for etcd as step 1 does. (d), the fallback, runs
// the fallback's restore of port49, which in the one namespace restores etcd too, with the pods running
// (so the node agent can restore their volumes), then the fallback's scale to 0, before the token delete.
// Both run the README's volume check on their named restore, and stop as it says when a volume did not
// come back. Then, with both StatefulSets at 0, the files cell (a) hashed and the marks it read are
// compared, and the README's token delete, revoke-offline.sh and scale-up run; after them the CA is the
// one it was and no broker started a fresh copy of the marks.
//
// A README command that fails, or a check that does not hold, is a measured FAIL; the row names the
// failed command (l89.FailedCommand). A failure of the harness's own setup (a kubectl call of its own, a
// debug pod) leaves the verdict empty: NOT RUN, which fails the test and is never written as a measurement.
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
	if len(r.before.Hashes) == 0 || len(r.before.Marks) == 0 {
		t.Fatalf("cell (a) never recorded the files and marks before the backup, so they cannot be compared")
	}
	doc, err := os.ReadFile(filepath.Join(kindtest.Root(), "deploy", "helm", "port49", "examples", "velero", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	restore := l89RestoreC
	if fallback {
		restore = l89RestoreD
	}
	steps, err := l89.Steps(string(doc), ns, r.stack.Release(), l89Backup, restore, 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	example := filepath.Join(kindtest.Root(), "deploy", "helm", "port49", "examples", "velero")

	// the files the README's commands read from the working directory: the examples, for the lab's
	// namespace (and, for the modifier, the lab's one namespace)
	work := t.TempDir()
	tokenFile, err := os.ReadFile(filepath.Join(example, "restore-token-delete.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	tok := strings.ReplaceAll(strings.ReplaceAll(string(tokenFile), "port49-etcd.svc", ns+".svc"), "namespace: port49-etcd", "namespace: "+ns)
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
	// readme runs one README step, bounded by own (l89.RunBounded, inside the cell's end). Its failure is
	// the measurement: the row names the command the ERR trap caught and the exit status, the output goes
	// to the test log, and the cell is a FAIL and ends. A step past its own bound is a measured FAIL too,
	// its row naming the command it was in; a step stopped by the cell's end is the budget, NOT RUN.
	readme := func(what, dir, script string, own time.Duration) string {
		within, capped := r.bound(own)
		env := append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "KUBECONFIG="+c.Kubeconfig)
		out, timedOut, err := l89.RunBounded(dir, env, l89.StepScript(script), within)
		switch {
		case timedOut && capped:
			l82Row(cell, what+": stopped when the cell's time ran out, not a measurement", "it was in: "+l89.RunningCommand(out))
			t.Fatalf("%s: stopped at the cell's end, after %v\n%s", what, within.Round(time.Second), kindtest.Filter(l89.Scrub(out)))
		case timedOut:
			l82Row(cell, what+": did not end within "+within.Round(time.Second).String(), "it was in: "+l89.RunningCommand(out))
			cell.Verdict = l82.Fail
			t.Fatalf("%s: a README command did not end within %v\n%s", what, within.Round(time.Second), kindtest.Filter(l89.Scrub(out)))
		case err != nil:
			l82Row(cell, what+": the README command that failed, and how", l89.FailedCommand(out)+" ("+err.Error()+")")
			cell.Verdict = l82.Fail
			t.Fatalf("%s: a README command failed: %v\n%s", what, err, kindtest.Filter(l89.Scrub(out)))
		}
		return l89.StepOutput(out)
	}
	// measured ends the cell with a measured FAIL on a check that does not hold
	measured := func(what, observation string) {
		l82Row(cell, what, observation)
		cell.Verdict = l82.Fail
		t.FailNow()
	}

	_, fpBefore := r.snapshot()
	if fpBefore[0] == "" || fpBefore[0] != fpBefore[1] {
		t.Fatalf("the brokers do not hold one CA before the restore")
	}

	// the README's first command: both namespaces deleted (the lab has one), and its volumes gone
	c.Kubectl("delete", "namespace", ns, "--wait=true", r.kubectlTimeout(5*time.Minute))
	r.waitFor(t, cell, "the namespace's volumes to be deleted", 5*time.Minute, func() bool {
		out, err := c.KubectlTry("", "get", "pv", "-o", `jsonpath={range .items[*]}{.spec.claimRef.namespace}{"\n"}{end}`)
		return err == nil && !strings.Contains(out, ns)
	})
	l82Row(cell, "the namespace was deleted", "yes, and its volumes")

	// each README step's own bound: a velero --wait has none, and a restore whose pod volume restores wait
	// on pods that are gone (the suspected failure of c) would otherwise wait out the test
	const restoreBound, etcdBound, checkBound, zeroBound, deleteBound, revokeBound, scaleBound = 8 * time.Minute,
		6 * time.Minute, time.Minute, 4 * time.Minute, 4 * time.Minute, 6 * time.Minute, 10 * time.Minute
	if !fallback {
		l82Row(cell, "the resource modifier as the lab runs it", "restore-scale-zero.yaml with a resourceNameRegex the lab adds (its etcd shares the namespace), so the shipped file is not run as shipped")
		c.Kubectl("-n", "velero", "delete", "configmap", "restore-scale-zero", "--ignore-not-found")
		readme("README step 3 (the restore with the resource modifier)", work, steps["restorezero"], restoreBound)
		l82Row(cell, "README step 3 (the restore "+restore+" with the resource modifier, both StatefulSets at 0 replicas) ran from its own text", "yes")
		readme("README step 1's wait for etcd", work,
			fmt.Sprintf("kubectl -n %s wait --for=condition=Ready pod -l app.kubernetes.io/name=etcd --timeout=5m", ns), etcdBound)
		l82Row(cell, "README step 1's wait for etcd (the lab's etcd is restored by step 3's restore)", "ready")
		replicas := strings.TrimSpace(c.Kubectl("-n", ns, "get", "statefulset", "t-broker", "t-port49d", "-o", `jsonpath={range .items[*]}{.spec.replicas} {end}`))
		if replicas != "0 0" {
			measured("the two StatefulSets' replicas after the restore (the resource modifier did not apply)", replicas)
		}
		l82Row(cell, "the two StatefulSets' replicas after the restore", replicas)
	} else {
		readme("README fallback step 4 (the restore of port49)", work, steps["fallbackrestore"], restoreBound)
		l82Row(cell, "README fallback step 4 (the restore "+restore+" of port49, normally) ran from its own text", "yes: in the lab it restores etcd too, which is never held at 0, so the pods ran against the restored store before the delete Job of step 2")
		l82Row(cell, "what (d) cannot show", "that port49 pods restored while etcd is held at 0 (the README's fallback steps 3 to 7) are harmless: the lab's etcd cannot be held down apart from the release")
		readme("README step 1's wait for etcd", work,
			fmt.Sprintf("kubectl -n %s wait --for=condition=Ready pod -l app.kubernetes.io/name=etcd --timeout=5m", ns), etcdBound)
		l82Row(cell, "README step 1's wait for etcd (the lab's etcd is restored by the fallback's restore)", "ready")
	}

	// the README's volume check on the named restore, once Velero has finished with the volumes
	r.phaseWait(t, cell, restore)
	phase, vols := l89.ParseVolumes(readme("the README's volume check", work, steps["volumes"], checkBound))
	cs := l89.C{RestorePhase: phase, Volumes: vols, FingerprintBefore: l89.Short(fpBefore[0]), Before: r.before.Hashes,
		MarksBefore: r.before.Marks, Fallback: fallback}
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
		readme("README fallback step 6 (both StatefulSets to 0)", work, steps["fallbackzero"], zeroBound)
		l82Row(cell, "README fallback step 6 (both StatefulSets scaled to 0, the pods gone) ran from its own text", "yes")
	} else {
		// a restore at 0 replicas whose pods outlive it: the README's order relies on there being none
		var left string
		within, capped := r.bound(3 * time.Minute)
		gone := (l89Lab{r}).Eventually("no port49 pod to be left", func() bool {
			out, err := c.KubectlTry("", "-n", ns, "get", "pods", "-l", "app.kubernetes.io/name=port49", "-o", "name")
			left = strings.Join(strings.Fields(out), " ")
			return err == nil && left == ""
		})
		switch {
		case !gone && capped:
			l82Row(cell, "the harness's wait for no port49 pod to be left", "stopped when the cell's time ran out, after "+within.Round(time.Second).String()+": not a measurement")
			t.Fatalf("port49 pods still there when the cell's time ran out: %s", left)
		case !gone:
			measured("port49 pods still there 3 minutes after the restore at 0 replicas", left)
		}
		l82Row(cell, "port49 pods left after the restore at 0 replicas", "none")
	}
	cs.AtZero = r.hashes()
	cs.MarksAtZero = r.marks()
	l82Row(cell, "files hashed before the backup", l89HashText(r.before.Hashes))
	l82Row(cell, "the same files with both StatefulSets at 0, before the scale-up", l89HashText(cs.AtZero))
	if fallback {
		l82Row(cell, "marks.json is compared by its marks here", "the brokers ran before the check, and a broker rewrites the file when the store and its copy disagree")
	}
	l82Row(cell, "each broker's marks before the backup", l89MarksText(r.before.Marks))
	l82Row(cell, "each broker's marks with both StatefulSets at 0", l89MarksText(cs.MarksAtZero))
	if !complete {
		// the README: never run step 5 while a volume is not Completed; the operator stops here, and so does the cell
		cell.Verdict = l89.JudgeC(cs)
		l82Row(cell, "the README says never to scale up while a volume is not Completed", "so the cell stopped before steps 2, 4 and 5, as an operator would")
		return
	}

	readme("README step 2 (the delete Job of design 13 step 3)", work, steps["tokendelete"], deleteBound)
	l82Row(cell, "README step 2 (the delete Job of design 13 step 3) ran from its own text and completed", "yes")
	readme("README step 4 (revoke-offline.sh)", kindtest.Root(), steps["revoke"], revokeBound)
	l82Row(cell, "README step 4 (revoke-offline.sh) ran from its own text", "yes")
	readme("README step 5 (the scale-up)", work, steps["scaleup"], scaleBound)
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

// phaseWait waits until the restore has ended and none of its pod volume restores is still running, so
// the README's volume check reads where they ended. A restore that made none at all (the suspected
// failure of cell c) ends too, and the check then lists nothing.
func (r *l89Run) phaseWait(t *testing.T, cell *l82.Cell, name string) {
	t.Helper()
	c := r.stack.Cluster()
	ended := map[string]bool{"Completed": true, "PartiallyFailed": true, "Failed": true, "FailedValidation": true}
	r.waitFor(t, cell, "the restore and its pod volume restores to end", 5*time.Minute, func() bool {
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
