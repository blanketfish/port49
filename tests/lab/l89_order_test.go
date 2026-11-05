//go:build lab

package lab

import (
	"errors"
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
// cannot be run apart from the rest. (c) restores the namespace once at 0 replicas, with the resource
// modifier the README once shipped (now the lab's input, limited to the release's two StatefulSets), and
// waits for etcd as step 1 does. (d), the README's order, first runs the README's recovery from (c)'s
// restore when it is there, then its restore of port49, which in the one namespace restores etcd too,
// with the pods running (so the node agent can restore their volumes), then its scale to 0, before the
// token delete. Both run the README's volume check on their named restore, and stop as it says when a
// volume did not come back. Then, with both StatefulSets at 0, the files cell (a) hashed and the marks it
// read are compared, and the README's token delete, revoke-offline.sh and scale-up run; after them the CA
// is the one cell (a) read before the backup and no broker started a fresh copy of the marks.
//
// A README command that fails, or a check that does not hold, is a measured FAIL; the row names the
// failed command (l89.FailedCommand). A failure of the harness's own setup (a kubectl call of its own, a
// debug pod) leaves the verdict empty: NOT RUN, which fails the test and is never written as a measurement.
func (r *l89Run) cellOrder(t *testing.T, cell *l82.Cell, fallback bool) {
	c, ns := r.stack.Cluster(), r.stack.Namespace()
	defer func() {
		if t.Failed() && cell.Verdict == "" && !l89SetupRowed(cell) {
			l82Row(cell, l89SetupRow, "see the test log and l89-diagnosis.txt")
		}
		if t.Failed() || cell.Verdict != l82.Pass {
			r.diagnose()
		}
	}()
	if len(r.before.Hashes) == 0 || len(r.before.Marks) == 0 {
		r.setupFail(t, cell, "cell (a) never recorded the files and marks before the backup, so they cannot be compared")
	}
	doc, err := os.ReadFile(filepath.Join(kindtest.Root(), "deploy", "helm", "port49", "examples", "velero", "README.md"))
	if err != nil {
		r.setupFail(t, cell, "%v", err)
	}
	restore := l89RestoreC
	if fallback {
		restore = l89RestoreD
	}
	steps, err := l89.Steps(string(doc), ns, r.stack.Release(), l89Backup, restore, 2, 2)
	if err != nil {
		r.setupFail(t, cell, "%v", err)
	}
	example := filepath.Join(kindtest.Root(), "deploy", "helm", "port49", "examples", "velero")

	// the files the README's commands read from the working directory: the examples, for the lab's
	// namespace (and, for the modifier, the lab's one namespace)
	work := t.TempDir()
	// the messages name the delete Job, never its file: the job log's filter drops every line with the
	// file's name in it, and run 42047911635 lost this cell's reason that way
	deleteFile, err := os.ReadFile(filepath.Join(example, "restore-token-delete.yaml"))
	if err != nil {
		r.setupFail(t, cell, "reading the delete Job's example: %v", errors.Unwrap(err))
	}
	tok, err := l89.LabDeleteJob(string(deleteFile), ns)
	if err != nil {
		r.setupFail(t, cell, "%v", err)
	}
	// (c)'s resource modifier, which the README no longer ships (run 42053716808 measured it hanging)
	mod, err := os.ReadFile(filepath.Join(kindtest.Root(), "tests", "shapes", "l89", "testdata", "restore-scale-zero.yaml"))
	if err != nil {
		r.setupFail(t, cell, "%v", err)
	}
	labMod, err := l89.LabModifier(string(mod), r.stack.Release())
	if err != nil {
		r.setupFail(t, cell, "%v", err)
	}
	for f, body := range map[string]string{"restore-token-delete.yaml": tok, "restore-scale-zero.yaml": labMod} {
		if err := os.WriteFile(filepath.Join(work, f), []byte(body), 0o600); err != nil {
			r.setupFail(t, cell, "writing an example into the working directory: %v", errors.Unwrap(err))
		}
	}

	// kubectl and velero as the README writes them, pointed at the lab's cluster
	bin := t.TempDir()
	if err := os.Symlink(kindtest.Bin(t, "KUBECTL_BIN"), filepath.Join(bin, "kubectl")); err != nil {
		r.setupFail(t, cell, "%v", err)
	}
	wrapper := fmt.Sprintf("#!/bin/sh\nexec %q --kubeconfig %q --kubecontext %q -n velero \"$@\"\n", kindtest.Bin(t, "VELERO_BIN"), c.Kubeconfig, c.Context())
	if err := os.WriteFile(filepath.Join(bin, "velero"), []byte(wrapper), 0o755); err != nil {
		r.setupFail(t, cell, "%v", err)
	}
	// readme runs one README step, by its name in steps, bounded by l89.StepBounds (inside the cell's
	// end). Its failure is the measurement: the row names the command the ERR trap caught and the exit
	// status, the output goes to the test log, and the cell is a FAIL and ends. A README --timeout that
	// runs out fails its command, so it is that FAIL too. A step past the harness's own bound (a backstop,
	// never under the README's timeouts) is NOT RUN, with the command it was in; for a restore's --wait,
	// which has no timeout of its own, r.hung reads why first, and a cause the README owns is a FAIL.
	readme := func(what, dir, step string) string {
		own, ok := l89.StepBounds[step]
		if !ok {
			r.setupFail(t, cell, "README step %s has no bound", step)
		}
		within, capped := r.bound(own)
		env := append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "KUBECONFIG="+c.Kubeconfig)
		out, timedOut, err := l89.RunBounded(dir, env, l89.StepScript(steps[step]), within)
		switch {
		case timedOut && capped:
			l82Row(cell, what+": stopped when the cell's time ran out, not a measurement", "it was in: "+l89.RunningCommand(out))
			t.Fatalf("%s: stopped at the cell's end, after %v\n%s", what, within.Round(time.Second), kindtest.Filter(l89.Scrub(out)))
		case timedOut:
			l82Row(cell, what+": did not end within the harness's own bound of "+within.Round(time.Second).String()+", not a measurement", "it was in: "+l89.RunningCommand(out))
			if step == "restorezero" || step == "restore" {
				r.hung(t, cell, dir, env, restore)
			}
			t.Fatalf("%s: did not end within the harness's bound of %v\n%s", what, within.Round(time.Second), kindtest.Filter(l89.Scrub(out)))
		case err != nil:
			l82Row(cell, what+": the README command that failed, and how", l89.FailedCommand(out)+" ("+err.Error()+")")
			l82SetVerdict(cell, l82.Fail)
			t.Fatalf("%s: a README command failed: %v\n%s", what, err, kindtest.Filter(l89.Scrub(out)))
		}
		return l89.StepOutput(out)
	}
	// measured ends the cell with a measured FAIL on a check that does not hold
	measured := func(what, observation string) {
		l82Row(cell, what, observation)
		l82SetVerdict(cell, l82.Fail)
		t.FailNow()
	}

	// the CA cell (a) read before the backup, not the cluster's now: (c) leaves the release's volumes
	// empty when its restore hangs, and run 42053716808's (d) stopped reading them (a broker's state/ was
	// not there)
	fpBefore := r.fpBefore
	if fpBefore[0] == "" || fpBefore[0] != fpBefore[1] {
		r.setupFail(t, cell, "cell (a) never recorded one CA for both brokers before the backup")
	}

	// (d) after (c): (c)'s restore at 0 replicas hangs (run 42053716808) and holds Velero, which restores
	// one at a time, so (d) first runs the README's recovery from it, whatever (c) ended with
	if fallback {
		if _, err := c.KubectlTry("", "-n", "velero", "get", "restore", l89RestoreC); err == nil {
			stuck := strings.TrimSpace(r.kubectl(t, cell, "-n", "velero", "get", "restore", l89RestoreC, "-o", "jsonpath={.status.phase}"))
			l82Row(cell, "cell (c)'s restore "+l89RestoreC+" before the recovery", "phase "+stuck)
			rec, err := l89.Recover(string(doc), l89RestoreC)
			if err != nil {
				r.setupFail(t, cell, "%v", err)
			}
			steps["recover"] = rec
			readme("the README's recovery from a restore at 0 replicas (on cell (c)'s restore)", work, "recover")
			l82Row(cell, "the README's recovery from a restore at 0 replicas ran from its own text, and the restore is gone", "yes")
			r.waitFor(t, cell, "no restore of Velero's to be New or InProgress", 2*time.Minute, func() bool {
				out, err := c.KubectlTry("", "-n", "velero", "get", "restores", "-o", `jsonpath={range .items[*]}{.status.phase} {end}`)
				return err == nil && !strings.Contains(out, "InProgress") && !strings.Contains(out, "New")
			})
			l82Row(cell, "Velero's restores after the recovery", "none New or InProgress")
		} else {
			l82Row(cell, "cell (c)'s restore before (d)", "none: the README's recovery was not needed")
		}
	}

	// the README's first command: both namespaces deleted (the lab has one), and its volumes gone
	r.kubectl(t, cell, "delete", "namespace", ns, "--wait=true", r.kubectlTimeout(5*time.Minute))
	r.waitFor(t, cell, "the namespace's volumes to be deleted", 5*time.Minute, func() bool {
		out, err := c.KubectlTry("", "get", "pv", "-o", `jsonpath={range .items[*]}{.spec.claimRef.namespace}{"\n"}{end}`)
		return err == nil && !strings.Contains(out, ns)
	})
	l82Row(cell, "the namespace was deleted", "yes, and its volumes")

	if !fallback {
		l82Row(cell, "the resource modifier as the lab runs it", "the README's former restore-scale-zero.yaml (the lab's input now) with a resourceNameRegex the lab adds (its etcd shares the namespace)")
		r.kubectl(t, cell, "-n", "velero", "delete", "configmap", "restore-scale-zero", "--ignore-not-found")
		readme("the restore at 0 replicas (the README's former step 3)", work, "restorezero")
		l82Row(cell, "the restore "+restore+" with the resource modifier, both StatefulSets at 0 replicas, ran from the README's former text", "yes")
		readme("README step 1's wait for etcd", work, "etcdwait")
		l82Row(cell, "README step 1's wait for etcd (the lab's etcd is restored with the release)", "ready")
		replicas := strings.TrimSpace(r.kubectl(t, cell, "-n", ns, "get", "statefulset", "t-broker", "t-port49d", "-o", `jsonpath={range .items[*]}{.spec.replicas} {end}`))
		if replicas != "0 0" {
			measured("the two StatefulSets' replicas after the restore (the resource modifier did not apply)", replicas)
		}
		l82Row(cell, "the two StatefulSets' replicas after the restore", replicas)
	} else {
		readme("README step 4 (the restore of port49)", work, "restore")
		l82Row(cell, "README step 4 (the restore "+restore+" of port49, its pods running) ran from its own text", "yes: in the lab it restores etcd too, which is never held at 0, so the pods ran against the restored store before the delete Job of step 2")
		l82Row(cell, "what (d) cannot show", "that port49 pods restored while etcd is held at 0 (the README's steps 3 to 7) are harmless: the lab's etcd cannot be held down apart from the release")
		readme("README step 1's wait for etcd", work, "etcdwait")
		l82Row(cell, "README step 1's wait for etcd (the lab's etcd is restored with the release)", "ready")
	}

	// the README's volume check on the named restore, once Velero has finished with the volumes
	r.phaseWait(t, cell, restore)
	phase, vols := l89.ParseVolumes(readme("the README's volume check", work, "volumes"))
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
		readme("README step 6 (both StatefulSets to 0)", work, "scalezero")
		l82Row(cell, "README step 6 (both StatefulSets scaled to 0, the pods gone) ran from its own text", "yes")
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
		l82SetVerdict(cell, l89.JudgeC(cs))
		l82Row(cell, "the README says never to go on while a volume is not Completed", "so the cell stopped before the delete Job, the revocations and the scale-up, as an operator would")
		return
	}

	readme("README step 2 (the delete Job of design 13 step 3)", work, "deletejob")
	l82Row(cell, "README step 2 (the delete Job of design 13 step 3) ran from its own text and completed", "yes")
	readme("README step 8 (revoke-offline.sh)", kindtest.Root(), "revoke")
	l82Row(cell, "README step 8 (revoke-offline.sh) ran from its own text", "yes")
	readme("README step 9 (the scale-up)", work, "scaleup")
	l82Row(cell, "README step 9 (the scale-up, brokers then port49d) ran from its own text and both rolled out", "yes")

	_, fpAfter := r.snapshot()
	cs.FingerprintAfter = l89.Short(fpAfter[0])
	l82Row(cell, "the issuing CA's fingerprint (first 12 hex) before the namespace was deleted, and after the scale-up", fmt.Sprintf("%s, %s", l89.Short(fpBefore[0]), l89.Short(fpAfter[0])))
	for _, p := range []string{"t-broker-0", "t-broker-1"} {
		logs := r.kubectl(t, cell, "-n", ns, "logs", p, "-c", "port49-broker")
		fresh := strings.Contains(logs, l89.FreshCopyLine)
		cs.FreshCopy = cs.FreshCopy || fresh
		l82Row(cell, p+"'s log after the scale-up says it had no marks.json at this start", map[bool]string{true: "yes", false: "no"}[fresh])
	}
	l82SetVerdict(cell, l89.JudgeC(cs))
}

// phaseWait waits until the restore has ended and none of its pod volume restores is still running, so
// the README's volume check reads where they ended. A restore that made none at all (the suspected
// failure of cell c) ends too, and the check then lists nothing.
// hung reads why a restore's --wait did not end within the harness's bound (l89.HangProbe, bounded at
// 30s inside the cell): a pod volume restore not yet ended whose pod does not exist is the README's
// outcome, a measured FAIL with those rows (l89.HangCause); anything else leaves the cell NOT RUN, with
// the rows. The probe prints only phases and pod and volume names; its output reaches the log filtered.
func (r *l89Run) hung(t *testing.T, cell *l82.Cell, dir string, env []string, restore string) {
	within, _ := r.bound(30 * time.Second)
	out, timedOut, err := l89.RunBounded(dir, env, l89.HangProbe(r.stack.Namespace(), restore), within)
	if timedOut || err != nil {
		l82Row(cell, "the harness's read of the restore when its wait was stopped", "failed: not a measurement")
		t.Logf("the hang probe: %v\n%s", err, kindtest.Filter(l89.Scrub(out)))
		return
	}
	pvrs, pods, phase := l89.ParseHang(out)
	if phase == "" {
		phase = "unset"
	}
	l82Row(cell, "the restore's phase when its wait was stopped", phase)
	measured, rows := l89.HangCause(pvrs, pods)
	for _, row := range rows {
		l82Row(cell, row.Case, row.Observation)
	}
	if measured {
		l82Row(cell, "the restore's wait cannot end", "a pod volume restore waits on a pod that does not exist: the README's outcome, measured")
		l82SetVerdict(cell, l82.Fail)
	}
}

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
