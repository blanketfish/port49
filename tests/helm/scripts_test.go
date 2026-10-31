package helm

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A kubectl that answers from fixtures and records every call, so the scripts' command sequences
// and the pods they apply are checked without a cluster. Nothing here is a real kubectl.
const fakeKubectl = `#!/usr/bin/env bash
echo "$*" >> "$FAKE_DIR/log"
if [ "$1" = -n ]; then shift 2; fi
cmd=$1; shift
jp=""
for a in "$@"; do case $a in jsonpath=*) jp=${a#jsonpath=} ;; esac; done
case "$cmd" in
  get)
    case "$1:$jp" in
      statefulset:'{.spec.replicas}') echo -n "${FAKE_REPLICAS:-2}" ;;
      statefulset:'{.spec.template.spec.containers[0].image}') echo -n "ghcr.io/example/port49:0.1.0" ;;
      statefulset:'{.spec.template.spec.volumes}') echo -n '[{"name":"config","configMap":{"name":"t-broker"}}]' ;;
      statefulset:'{.spec.template.spec.containers[0].volumeMounts}') echo -n '[{"name":"config","mountPath":"/etc/port49/config"},{"name":"data","mountPath":"/var/lib/port49-broker"}]' ;;
      statefulset:'{.spec.template.spec.securityContext}') echo -n '{"runAsUser":65532,"fsGroup":65532}' ;;
      statefulset:'{.spec.template.spec.containers[0].securityContext}') echo -n '{"runAsUser":65532,"runAsNonRoot":true}' ;;
      statefulset:'{.spec.template.spec.initContainers}') echo -n '[{"name":"data-dir","image":"alpine:3.22","volumeMounts":[{"name":"data","mountPath":"/var/lib/port49-broker"}]}]' ;;
      statefulset:'{.spec.template.spec.initContainers[0].image}') echo -n "alpine:3.22" ;;
      pod:'{.spec.nodeName}') case "$2" in t-broker-0) echo -n node-a ;; t-broker-1) echo -n node-b ;; esac ;;
      pod:'{.status.phase}') echo -n "${FAKE_PHASE:-Succeeded}" ;;
      pods:*) i=0; [ ! -f "$FAKE_DIR/gone" ] || FAKE_BROKER_PODS=0; while [ "$i" -lt "${FAKE_BROKER_PODS:-2}" ]; do echo "pod/t-broker-$i"; i=$((i + 1)); done ;;
    esac ;;
  wait) [ "$FAKE_HANG" != wait ] || sleep 30
        # the pods vanish between the count and the wait, and wait errors
        if [ -n "$FAKE_WAITRACE" ]; then touch "$FAKE_DIR/gone"; exit 1; fi
        # the pods are still there and the wait timed out
        if [ -n "$FAKE_WAITFAIL" ]; then exit 1; fi ;;
  apply)
    n=$(ls "$FAKE_DIR" | grep -c '^apply-')
    cat > "$FAKE_DIR/apply-$n.json"
    # an init-issuer pod makes a CA on the PVC it mounts
    if grep -q '"init-issuer"' "$FAKE_DIR/apply-$n.json"; then
      o=$(grep -o 'data-t-broker-[0-9]*' "$FAKE_DIR/apply-$n.json" | head -1 | sed 's/.*-//')
      echo -n INITSHA > "$FAKE_DIR/CA_$o"
    fi ;;
  exec)
    case "$*" in
      *"tar c -C /s/state"*)
        # the source side of a copy: a real tar of placeholder files named by the arguments
        all="$*"; names=${all##*"tar c -C /s/state "}
        mkdir -p "$FAKE_DIR/src"
        for n in $names; do
          rm -f "$FAKE_DIR/src/$n"
          if [ "$n" = "$FAKE_SRC_LINK" ]; then echo victim > "$FAKE_DIR/victim"; ln -s "$FAKE_DIR/victim" "$FAKE_DIR/src/$n"; else echo "placeholder-$n" > "$FAKE_DIR/src/$n"; fi
        done
        tar c -C "$FAKE_DIR/src" $names ;;
      *.copy-issuer*)
        # the destination side: its script, run here against a local /d with chown stubbed and
        # install without -o and -g; FAKE_DST_HAS names files already in the target's state/
        d=$FAKE_DIR/d; mkdir -p "$d/state" "$FAKE_DIR/stub"
        for f in $FAKE_DST_HAS; do echo existing > "$d/state/$f"; done
        printf '#!/bin/sh\nexit 0\n' > "$FAKE_DIR/stub/chown"
        printf '#!/bin/sh\na=; while [ $# -gt 0 ]; do case $1 in -o|-g) shift 2 ;; *) a="$a $1"; shift ;; esac; done\nexec /usr/bin/install $a\n' > "$FAKE_DIR/stub/install"
        chmod +x "$FAKE_DIR/stub/chown" "$FAKE_DIR/stub/install"
        script=$(printf '%s' "${@: -1}" | sed "s#/d/state#$d/state#g")
        PATH="$FAKE_DIR/stub:$PATH" sh -c "$script"
        exit $? ;;
      *inspect-*)
        # the inspection of broker N's volume: the sha256 lines the fixtures name
        o=$(echo "$*" | grep -o 'inspect-[0-9]*' | head -1 | sed 's/.*-//')
        [ "$FAKE_READFAIL" != "$o" ] || exit 1
        var=FAKE_CA_$o; pv=FAKE_PREV_$o
        sum=${!var}; [ ! -f "$FAKE_DIR/CA_$o" ] || sum=$(cat "$FAKE_DIR/CA_$o")
        [ -z "$sum" ] || echo "$sum  /s/state/issuing-ca.pem"
        [ -z "${!pv}" ] || echo "${!pv}  /s/state/issuing-ca-previous.pem" ;;
      *) case "$1" in -i) cat >/dev/null ;; esac ;;
    esac ;;
  logs) echo "fake log: issuing CA sha256:0000" ;;
esac
exit 0
`

type fakeRun struct {
	dir      string
	log      []string
	applied  []map[string]any
	exitCode int
	out      string
}

func runScript(t *testing.T, script string, env []string, args ...string) fakeRun {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "kubectl"), []byte(fakeKubectl), 0o755); err != nil {
		t.Fatal(err)
	}
	abs, err := filepath.Abs(filepath.Join(chartDir, "scripts", script))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", append([]string{abs}, args...)...)
	cmd.Env = append(os.Environ(), append(env, "PATH="+bin+":"+os.Getenv("PATH"), "FAKE_DIR="+dir)...)
	out, err := cmd.CombinedOutput()
	r := fakeRun{dir: dir, out: string(out)}
	if ee, ok := err.(*exec.ExitError); ok {
		r.exitCode = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(dir, "log")); err == nil {
		r.log = strings.Split(strings.TrimSpace(string(b)), "\n")
	}
	files, _ := filepath.Glob(filepath.Join(dir, "apply-*.json"))
	for i := range files {
		b, err := os.ReadFile(filepath.Join(dir, "apply-"+itoa(i)+".json"))
		if err != nil {
			t.Fatal(err)
		}
		var pod map[string]any
		if err := json.Unmarshal(b, &pod); err != nil {
			t.Fatalf("%s applied a pod that is not JSON: %v\n%s", script, err, b)
		}
		r.applied = append(r.applied, pod)
	}
	return r
}

func itoa(i int) string { return strings.TrimSpace(strings.Repeat(" ", 0) + string(rune('0'+i))) }

func (r fakeRun) calls(prefix string) []string {
	var out []string
	for _, l := range r.log {
		l = strings.TrimPrefix(l, "-n ns ")
		if strings.HasPrefix(l, prefix) {
			out = append(out, l)
		}
	}
	return out
}

// every pod the script applied was deleted by name.
func (r fakeRun) assertAllPodsDeleted(t *testing.T) {
	t.Helper()
	deleted := strings.Join(r.calls("delete pod"), "\n")
	for _, p := range r.applied {
		name := str(at(p, "metadata", "name"))
		if !strings.Contains(deleted, name) {
			t.Errorf("pod %s was started and never deleted:\n%s", name, strings.Join(r.log, "\n"))
		}
	}
}

func volumeClaim(pod map[string]any, volume string) (claim string, readOnly any) {
	for _, v := range list(at(pod, "spec", "volumes")) {
		if str(at(v, "name")) == volume {
			return str(at(v, "persistentVolumeClaim", "claimName")), at(v, "persistentVolumeClaim", "readOnly")
		}
	}
	return "", nil
}

func (r fakeRun) joined() string { return strings.Join(r.log, "\n") }

// podsMounting is the applied pods whose volume v claims claim.
func (r fakeRun) podsMounting(claim string) []map[string]any {
	var out []map[string]any
	for _, p := range r.applied {
		if c, _ := volumeClaim(p, "v"); c == claim {
			out = append(out, p)
		} else if c, _ := volumeClaim(p, "data"); c == claim {
			out = append(out, p)
		}
	}
	return out
}

func (r fakeRun) initPods() []map[string]any {
	var out []map[string]any
	for _, p := range r.applied {
		if strings.Contains(str(at(p, "spec", "containers", 0, "args")), "init-issuer") {
			out = append(out, p)
		}
	}
	return out
}

func (r fakeRun) tarStreams() []string { return r.calls("exec t-broker-copy-src") }

const sumA = "aaaa1111aaaa1111"
const sumB = "bbbb2222bbbb2222"

func TestCopyIssuerOnAFreshInstallMakesTheCAOnTheSourceAndCopiesStaged(t *testing.T) {
	r := runScript(t, "copy-issuer.sh", nil, "ns", "t", "--from", "0")
	if r.exitCode != 0 {
		t.Fatalf("exit %d:\n%s\n%s", r.exitCode, r.out, r.joined())
	}
	for _, l := range r.calls("exec") {
		if regexp.MustCompile(`exec (-i )?t-broker-[0-9]+ `).MatchString(l) {
			t.Errorf("exec into a broker pod: %q", l)
		}
	}
	inits := r.initPods()
	if len(inits) != 1 {
		t.Fatalf("%d init-issuer pods, want one", len(inits))
	}
	init := inits[0]
	if claim, _ := volumeClaim(init, "data"); claim != "data-t-broker-0" || str(at(init, "spec", "nodeName")) != "node-a" {
		t.Errorf("init-issuer mounts %q on %q, want broker-0's claim on node-a", claim, str(at(init, "spec", "nodeName")))
	}
	if got := str(at(init, "spec", "containers", 0, "args")); got != "[init-issuer --config /etc/port49/config/port49-broker.yaml]" {
		t.Errorf("init-issuer args %s", got)
	}
	if len(list(at(init, "spec", "initContainers"))) != 1 || str(at(init, "spec", "securityContext", "fsGroup")) != "65532" {
		t.Errorf("the one-shot pod does not mirror the broker's pod spec: %v", init["spec"])
	}
	// every broker's volume is looked at first, read-only
	for _, ord := range []string{"0", "1"} {
		ins := r.podsMounting("data-t-broker-" + ord)
		found := false
		for _, p := range ins {
			if c, ro := volumeClaim(p, "v"); c != "" && ro == true && strings.Contains(str(at(p, "metadata", "name")), "inspect") {
				found = true
			}
		}
		if !found {
			t.Errorf("no read-only inspection pod on broker-%s's volume", ord)
		}
	}
	joined := r.joined()
	for _, want := range []string{
		"-- tar c -C /s/state issuing-ca.pem issuing-ca.key",
		`rm -rf "$s"`, "tar x -C \"$s\"", "exists: not replaced", `chmod 0600 "$s/issuing-ca.key"`,
		"rollout restart statefulset/t-broker",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("the log has no %q:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "tar x -C /d/state") {
		t.Error("the stream is written straight into state/, not into a staging directory")
	}
	r.assertAllPodsDeleted(t)
	r.assertPodHygiene(t)
	if !strings.Contains(r.out, "issuing CA") {
		t.Errorf("no issuing CA line is printed:\n%s", r.out)
	}
}

// Every pod a script applies: no service account token, a deadline in minutes, and the helper pods
// root only where they must be.
func (r fakeRun) assertPodHygiene(t *testing.T) {
	t.Helper()
	for _, p := range r.applied {
		name := str(at(p, "metadata", "name"))
		if at(p, "spec", "automountServiceAccountToken") != false {
			t.Errorf("pod %s mounts a service account token (automountServiceAccountToken is %v)", name, at(p, "spec", "automountServiceAccountToken"))
		}
		d := at(p, "spec", "activeDeadlineSeconds")
		n, _ := d.(float64)
		if n <= 0 || n > 600 {
			t.Errorf("pod %s has activeDeadlineSeconds %v, want a deadline of minutes (at most 600)", name, d)
		}
	}
}

func TestCopyIssuerNeverMakesASecondCA(t *testing.T) {
	// broker-0's volume was lost; broker-1 holds the CA. `--from 0` would init a new CA: refused.
	r := runScript(t, "copy-issuer.sh", []string{"FAKE_CA_1=" + sumA}, "ns", "t", "--from", "0")
	if r.exitCode == 0 {
		t.Fatalf("copy-issuer.sh --from 0 succeeded with broker-1 holding the CA:\n%s", r.joined())
	}
	if len(r.initPods()) != 0 {
		t.Error("an init-issuer pod was started though another broker holds a CA")
	}
	if !strings.Contains(r.out, "broker-1") || !strings.Contains(r.out, sumA) || !strings.Contains(r.out, "--from 1") {
		t.Errorf("the refusal does not name broker-1, its CA and the way out:\n%s", r.out)
	}
	if len(r.tarStreams()) != 0 {
		t.Error("a copy ran")
	}
	r.assertAllPodsDeleted(t)
}

func TestCopyIssuerRestoresALostBrokerFromAnother(t *testing.T) {
	r := runScript(t, "copy-issuer.sh", []string{"FAKE_CA_1=" + sumA}, "ns", "t", "--from", "1", "--to", "0")
	if r.exitCode != 0 {
		t.Fatalf("exit %d:\n%s\n%s", r.exitCode, r.out, r.joined())
	}
	if len(r.initPods()) != 0 {
		t.Error("init-issuer ran though the source holds the CA")
	}
	var src, dst map[string]any
	for _, p := range r.applied {
		n := str(at(p, "metadata", "name"))
		if strings.Contains(n, "copy-src") {
			src = p
		}
		if strings.Contains(n, "copy-dst") {
			dst = p
		}
	}
	if src == nil || dst == nil {
		t.Fatalf("no copy pods applied:\n%s", r.joined())
	}
	if c, ro := volumeClaim(src, "v"); c != "data-t-broker-1" || ro != true {
		t.Errorf("source mounts %q readOnly %v, want broker-1's claim read-only", c, ro)
	}
	if c, ro := volumeClaim(dst, "v"); c != "data-t-broker-0" || ro != false {
		t.Errorf("destination mounts %q readOnly %v, want broker-0's claim writable", c, ro)
	}
	if str(at(src, "spec", "nodeName")) != "node-b" || str(at(dst, "spec", "nodeName")) != "node-a" {
		t.Errorf("each side is on its PVC's node: source %v, destination %v", at(src, "spec", "nodeName"), at(dst, "spec", "nodeName"))
	}
	for _, p := range []map[string]any{src, dst} {
		if str(at(p, "spec", "containers", 0, "securityContext", "runAsUser")) != "0" {
			t.Errorf("a copy pod is not root: %v", at(p, "spec", "containers", 0, "securityContext"))
		}
	}
	r.assertAllPodsDeleted(t)
	r.assertPodHygiene(t)
}

func TestCopyIssuerRefusesToOverwriteADifferentCA(t *testing.T) {
	r := runScript(t, "copy-issuer.sh", []string{"FAKE_CA_0=" + sumA, "FAKE_CA_1=" + sumB}, "ns", "t", "--from", "0")
	if r.exitCode == 0 {
		t.Fatal("copy-issuer.sh overwrote a different CA")
	}
	for _, want := range []string{"broker-0", "broker-1", sumA, sumB, "never overwritten", "forget-issuer"} {
		if !strings.Contains(r.out, want) {
			t.Errorf("the refusal lacks %q:\n%s", want, r.out)
		}
	}
	if len(r.tarStreams()) != 0 || len(r.calls("rollout")) != 0 {
		t.Errorf("something was copied or restarted:\n%s", r.joined())
	}
	if len(r.initPods()) != 0 {
		t.Error("init-issuer ran")
	}
	r.assertAllPodsDeleted(t)
}

// The destination's own guard, run for real against a local directory: a name that exists is not
// replaced, nothing is moved, and the script says so (review n-1).
func TestCopyIssuerDestinationRefusesToReplaceAFile(t *testing.T) {
	r := runScript(t, "copy-issuer.sh", []string{"FAKE_CA_0=" + sumA, "FAKE_DST_HAS=issuing-ca.key"}, "ns", "t", "--from", "0")
	if r.exitCode == 0 {
		t.Fatalf("a copy over an existing key succeeded:\n%s", r.out)
	}
	if !strings.Contains(r.out, "exists: not replaced") {
		t.Errorf("the refusal is not said:\n%s", r.out)
	}
	if b, _ := os.ReadFile(filepath.Join(r.dir, "d", "state", "issuing-ca.key")); string(b) != "existing\n" {
		t.Errorf("the existing key was changed: %q", b)
	}
	if _, err := os.Stat(filepath.Join(r.dir, "d", "state", "issuing-ca.pem")); err == nil {
		t.Error("the certificate was moved in beside a key that was refused")
	}
	if len(r.calls("rollout")) != 0 {
		t.Error("the brokers were restarted after a refused copy")
	}
}

// The destination script runs as root over what the source's tar sent: a link in the stream is
// refused before anything is chowned, chmodded or moved, so root never follows it to another file.
func TestCopyIssuerDestinationRefusesALinkInTheStream(t *testing.T) {
	r := runScript(t, "copy-issuer.sh", []string{"FAKE_CA_0=" + sumA, "FAKE_SRC_LINK=issuing-ca.key"}, "ns", "t", "--from", "0")
	if r.exitCode == 0 {
		t.Fatalf("a copy with a symbolic link in the stream succeeded:\n%s", r.out)
	}
	if !strings.Contains(r.out, "is a symbolic link: not copied") {
		t.Errorf("the refusal is not said:\n%s", r.out)
	}
	st := filepath.Join(r.dir, "d", "state")
	for _, n := range []string{"issuing-ca.key", "issuing-ca.pem"} {
		if _, err := os.Lstat(filepath.Join(st, n)); err == nil {
			t.Errorf("%s was placed beside a refused link", n)
		}
	}
	if len(r.calls("rollout")) != 0 {
		t.Error("the brokers were restarted after a refused copy")
	}
}

// And the same script when nothing is in the way: the files land, the key 0600, the staging gone.
func TestCopyIssuerDestinationPlacesTheStagedFiles(t *testing.T) {
	r := runScript(t, "copy-issuer.sh", []string{"FAKE_CA_0=" + sumA}, "ns", "t", "--from", "0")
	if r.exitCode != 0 {
		t.Fatalf("exit %d:\n%s", r.exitCode, r.out)
	}
	st := filepath.Join(r.dir, "d", "state")
	for _, n := range []string{"issuing-ca.pem", "issuing-ca.key"} {
		if b, err := os.ReadFile(filepath.Join(st, n)); err != nil || string(b) != "placeholder-"+n+"\n" {
			t.Errorf("%s: %q %v", n, b, err)
		}
	}
	if fi, err := os.Stat(filepath.Join(st, "issuing-ca.key")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("the key's mode is %v (%v), want 0600", fi.Mode().Perm(), err)
	}
	if _, err := os.Stat(filepath.Join(st, ".copy-issuer")); err == nil {
		t.Error("the staging directory is left behind")
	}
}

// A volume that cannot be read is an error naming the broker, never "no CA here" (review n-2).
func TestCopyIssuerStopsWhenAVolumeCannotBeRead(t *testing.T) {
	r := runScript(t, "copy-issuer.sh", []string{"FAKE_READFAIL=1", "FAKE_CA_0=" + sumA}, "ns", "t", "--from", "0")
	if r.exitCode == 0 || !strings.Contains(r.out, "broker-1") {
		t.Fatalf("exit %d, want a failure naming broker-1:\n%s", r.exitCode, r.out)
	}
	if len(r.tarStreams()) != 0 || len(r.initPods()) != 0 {
		t.Error("something was copied or initialised after a failed read")
	}
	r.assertAllPodsDeleted(t)
}

func TestCopyIssuerChecksEveryTargetBeforeCopyingAny(t *testing.T) {
	// three brokers: broker-1 is empty, broker-2 holds a different CA: nothing may be copied to broker-1.
	r := runScript(t, "copy-issuer.sh", []string{"FAKE_REPLICAS=3", "FAKE_CA_0=" + sumA, "FAKE_CA_2=" + sumB}, "ns", "t", "--from", "0")
	if r.exitCode == 0 || len(r.tarStreams()) != 0 {
		t.Fatalf("exit %d, %d copies; want a refusal before any copy:\n%s", r.exitCode, len(r.tarStreams()), r.joined())
	}
}

func TestCopyIssuerSkipsATargetThatHoldsTheSameCA(t *testing.T) {
	r := runScript(t, "copy-issuer.sh", []string{"FAKE_CA_0=" + sumA, "FAKE_CA_1=" + sumA}, "ns", "t", "--from", "0")
	if r.exitCode != 0 || len(r.tarStreams()) != 0 || len(r.calls("rollout")) != 0 {
		t.Fatalf("exit %d, %d copies, %d rollouts:\n%s", r.exitCode, len(r.tarStreams()), len(r.calls("rollout")), r.joined())
	}
	if !strings.Contains(r.out, "already holds this issuing CA") {
		t.Errorf("the skip is not said:\n%s", r.out)
	}
}

func TestCopyIssuerCopiesThePreviousCAAndRefusesADifferentOne(t *testing.T) {
	r := runScript(t, "copy-issuer.sh", []string{"FAKE_CA_0=" + sumA, "FAKE_PREV_0=" + sumB, "FAKE_CA_1=" + sumA}, "ns", "t", "--from", "0")
	if r.exitCode != 0 {
		t.Fatalf("exit %d:\n%s", r.exitCode, r.joined())
	}
	streams := r.tarStreams()
	if len(streams) != 1 || !strings.HasSuffix(streams[0], "tar c -C /s/state issuing-ca-previous.pem") {
		t.Errorf("want only the previous certificate streamed to a broker that holds the current one: %v", streams)
	}
	r = runScript(t, "copy-issuer.sh", []string{"FAKE_CA_0=" + sumA, "FAKE_PREV_0=" + sumB, "FAKE_CA_1=" + sumA, "FAKE_PREV_1=" + sumA}, "ns", "t", "--from", "0")
	if r.exitCode == 0 || len(r.tarStreams()) != 0 || !strings.Contains(r.out, "previous") {
		t.Errorf("a different previous CA was not refused: exit %d\n%s", r.exitCode, r.out)
	}
}

func TestCopyIssuerInitFailureCopiesNothingAndDeletesItsPods(t *testing.T) {
	r := runScript(t, "copy-issuer.sh", []string{"FAKE_PHASE=Failed"}, "ns", "t", "--from", "0")
	if r.exitCode == 0 {
		t.Fatal("copy-issuer.sh succeeded though init-issuer failed")
	}
	if len(r.tarStreams()) != 0 {
		t.Errorf("a copy ran after init-issuer failed")
	}
	r.assertAllPodsDeleted(t)
}

func TestCopyIssuerUsage(t *testing.T) {
	for _, args := range [][]string{nil, {"ns", "t"}, {"ns", "t", "--to", "1"}, {"ns", "t", "--from"}, {"ns", "t", "--from", "x"}, {"ns", "t", "--from", "0", "extra"}} {
		r := runScript(t, "copy-issuer.sh", nil, args...)
		if r.exitCode != 2 || len(r.applied) != 0 {
			t.Errorf("%v: exit %d, %d pods; want a usage error (2) before any pod", args, r.exitCode, len(r.applied))
		}
	}
	if r := runScript(t, "copy-issuer.sh", nil, "ns", "t", "--from", "5"); r.exitCode == 0 {
		t.Error("--from beyond the replica count was accepted")
	}
	if r := runScript(t, "copy-issuer.sh", nil, "ns", "t", "--from", "0", "--to", "0"); r.exitCode == 0 {
		t.Error("--to the source was accepted")
	}
}

// A signal ends the script and every pod it started is still deleted (the trap in lib.sh).
func TestCopyIssuerDeletesItsPodsOnSIGTERM(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "kubectl"), []byte(fakeKubectl), 0o755); err != nil {
		t.Fatal(err)
	}
	abs, _ := filepath.Abs(filepath.Join(chartDir, "scripts", "copy-issuer.sh"))
	cmd := exec.Command("bash", abs, "ns", "t", "--from", "0")
	cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "FAKE_DIR="+dir, "FAKE_HANG=wait")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	logged := func() string { b, _ := os.ReadFile(filepath.Join(dir, "log")); return string(b) }
	deadline := time.Now().Add(20 * time.Second)
	for !strings.Contains(logged(), " wait ") && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if !strings.Contains(logged(), " wait ") {
		t.Fatalf("the script never reached its first wait:\n%s", logged())
	}
	syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	cmd.Wait()
	if !strings.Contains(logged(), "delete pod t-broker-inspect-0-") {
		t.Errorf("a SIGTERM left its pod behind:\n%s", logged())
	}
}

func TestRevokeOfflineStopsTheBrokersAndAlwaysScalesBack(t *testing.T) {
	for _, phase := range []string{"Succeeded", "Failed"} {
		t.Run(phase, func(t *testing.T) {
			r := runScript(t, "revoke-offline.sh", []string{"FAKE_PHASE=" + phase}, "ns", "t", "--", "--principal", `user:bob@example.com`, "--lift")
			if (phase == "Succeeded") != (r.exitCode == 0) {
				t.Fatalf("phase %s, exit %d:\n%s", phase, r.exitCode, r.out)
			}
			scale := r.calls("scale")
			if len(scale) != 2 || !strings.Contains(scale[0], "--replicas=0") || !strings.Contains(scale[1], "--replicas=2") {
				t.Fatalf("scale calls %v, want to 0 and back to 2", scale)
			}
			zero, apply, back := -1, -1, -1
			for i, l := range r.log {
				switch {
				case strings.Contains(l, "--replicas=0"):
					zero = i
				case strings.HasPrefix(strings.TrimPrefix(l, "-n ns "), "apply"):
					apply = i
				case strings.Contains(l, "--replicas=2"):
					back = i
				}
			}
			if !(zero < apply && apply < back) {
				t.Errorf("order: scale to 0 at %d, the pod applied at %d, scale back at %d", zero, apply, back)
			}
			// The one-shot pod is deleted, and waited for, before the brokers come back (review m-1).
			del := -1
			for i, l := range r.log {
				if strings.HasPrefix(strings.TrimPrefix(l, "-n ns "), "delete pod") {
					del = i
					if !strings.Contains(l, "--wait=true") {
						t.Errorf("a pod is deleted without waiting for it: %q", l)
					}
				}
			}
			if del < 0 || del > back {
				t.Errorf("the pod's delete is at %d, after the scale back at %d", del, back)
			}
			if len(r.applied) != 1 {
				t.Fatalf("%d pods applied", len(r.applied))
			}
			p := r.applied[0]
			if got := str(at(p, "spec", "containers", 0, "args")); got != "[revoke --offline --config /etc/port49/config/port49-broker.yaml --principal user:bob@example.com --lift]" {
				t.Errorf("args %s", got)
			}
			if c, _ := volumeClaim(p, "data"); c != "data-t-broker-0" {
				t.Errorf("mounts %q, want broker-0's claim", c)
			}
			r.assertAllPodsDeleted(t)
		})
	}
}

// With the brokers already at zero no pod matches, and some kubectl versions fail `wait --for=delete`
// on no match: the script must not call it (review m-9).
func TestRevokeOfflineWithNoBrokerPodsDoesNotWaitForTheirDeletion(t *testing.T) {
	r := runScript(t, "revoke-offline.sh", []string{"FAKE_BROKER_PODS=0"}, "ns", "t", "--", "--list")
	if r.exitCode != 0 {
		t.Fatalf("exit %d:\n%s\n%s", r.exitCode, r.out, r.joined())
	}
	if w := r.calls("wait --for=delete"); len(w) != 0 {
		t.Errorf("waited for pods that do not exist: %v", w)
	}
	r = runScript(t, "revoke-offline.sh", nil, "ns", "t", "--", "--list")
	if w := r.calls("wait --for=delete"); len(w) != 1 {
		t.Errorf("with two broker pods, want one wait for their deletion, got %v", w)
	}
	r.assertPodHygiene(t)
}

// The pods can vanish between wait_none's count and its wait; kubectl then errors, and the script
// must go on when none are left (review n-4).
func TestRevokeOfflineSurvivesPodsVanishingBeforeTheWait(t *testing.T) {
	r := runScript(t, "revoke-offline.sh", []string{"FAKE_WAITRACE=1"}, "ns", "t", "--", "--list")
	if r.exitCode != 0 {
		t.Fatalf("exit %d:\n%s\n%s", r.exitCode, r.out, r.joined())
	}
	if len(r.applied) != 1 {
		t.Errorf("%d pods applied, want the one-shot revoke", len(r.applied))
	}
}

// ...but when the wait fails with the pods still there, the script stops before it runs anything.
func TestRevokeOfflineStopsWhenBrokerPodsStayUp(t *testing.T) {
	r := runScript(t, "revoke-offline.sh", []string{"FAKE_WAITFAIL=1"}, "ns", "t", "--", "--list")
	if r.exitCode == 0 || len(r.applied) != 0 {
		t.Fatalf("exit %d with %d pods applied, want a failure before the one-shot pod", r.exitCode, len(r.applied))
	}
	if len(r.calls("scale")) < 2 {
		t.Errorf("the brokers were not scaled back:\n%s", r.joined())
	}
}

func TestRevokeOfflineQuotesItsArguments(t *testing.T) {
	r := runScript(t, "revoke-offline.sh", nil, "ns", "t", "--", "--principal", `user:a"b\c@example.com`)
	if r.exitCode != 0 || len(r.applied) != 1 {
		t.Fatalf("exit %d, %d pods:\n%s", r.exitCode, len(r.applied), r.out)
	}
	if got := str(at(r.applied[0], "spec", "containers", 0, "args", 5)); got != `user:a"b\c@example.com` {
		t.Errorf("the argument came through as %q", got)
	}
}

func TestRevokeOfflineWantsDashDashAndFlags(t *testing.T) {
	for _, args := range [][]string{{"ns", "t"}, {"ns", "t", "--principal", "x"}, {"ns", "t", "--"}} {
		r := runScript(t, "revoke-offline.sh", nil, args...)
		if r.exitCode != 2 {
			t.Errorf("%v: exit %d, want 2", args, r.exitCode)
		}
		if len(r.calls("scale")) != 0 {
			t.Errorf("%v: scaled the brokers on a usage error", args)
		}
	}
}
