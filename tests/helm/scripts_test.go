package helm

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
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
    esac ;;
  apply)
    n=$(ls "$FAKE_DIR" | grep -c '^apply-')
    cat > "$FAKE_DIR/apply-$n.json" ;;
  exec)
    case "$1" in -i) cat >/dev/null ;; esac
    echo -n TARBYTES ;;
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

func TestCopyIssuerMakesOnePodPerStepAndNeverExecsIntoABroker(t *testing.T) {
	r := runScript(t, "copy-issuer.sh", nil, "ns", "t")
	if r.exitCode != 0 {
		t.Fatalf("exit %d:\n%s\n%s", r.exitCode, r.out, strings.Join(r.log, "\n"))
	}
	for _, l := range r.calls("exec") {
		if regexp.MustCompile(`exec (-i )?t-broker-[0-9]+ `).MatchString(l) {
			t.Errorf("exec into a broker pod: %q", l)
		}
	}
	if len(r.applied) != 3 {
		t.Fatalf("%d pods applied, want the init-issuer pod and one source and one destination", len(r.applied))
	}
	init := r.applied[0]
	if claim, _ := volumeClaim(init, "data"); claim != "data-t-broker-0" {
		t.Errorf("init-issuer mounts %q, want data-t-broker-0", claim)
	}
	if str(at(init, "spec", "nodeName")) != "node-a" {
		t.Errorf("init-issuer is on node %q, want broker-0's node-a", str(at(init, "spec", "nodeName")))
	}
	if got := str(at(init, "spec", "containers", 0, "args")); got != "[init-issuer --config /etc/port49/config/port49-broker.yaml]" {
		t.Errorf("init-issuer args %s", got)
	}
	if len(list(at(init, "spec", "initContainers"))) != 1 || str(at(init, "spec", "securityContext", "fsGroup")) != "65532" {
		t.Errorf("the one-shot pod does not mirror the broker's pod spec: %v", init["spec"])
	}
	src, dst := r.applied[1], r.applied[2]
	if c, ro := volumeClaim(src, "v"); c != "data-t-broker-0" || ro != true {
		t.Errorf("source mounts %q readOnly %v, want broker-0's claim read-only", c, ro)
	}
	if c, ro := volumeClaim(dst, "v"); c != "data-t-broker-1" || ro != false {
		t.Errorf("destination mounts %q readOnly %v, want broker-1's claim writable", c, ro)
	}
	if str(at(dst, "spec", "nodeName")) != "node-b" || str(at(src, "spec", "nodeName")) != "node-a" {
		t.Errorf("each side must be on its PVC's node: source %v, destination %v", at(src, "spec", "nodeName"), at(dst, "spec", "nodeName"))
	}
	for _, p := range []map[string]any{src, dst} {
		if str(at(p, "spec", "containers", 0, "securityContext", "runAsUser")) != "0" {
			t.Errorf("a copy pod is not root: %v", at(p, "spec", "containers", 0, "securityContext"))
		}
	}
	joined := strings.Join(r.log, "\n")
	for _, want := range []string{
		"-- tar c -C /s/state issuing-ca.pem issuing-ca.key",
		"install -d -o 65532 -g 65532 -m 0700 /d/state && tar x -C /d/state && chown 65532:65532 /d/state/issuing-ca.* && chmod 0600 /d/state/issuing-ca.key",
		"rollout restart statefulset/t-broker",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("the log has no %q:\n%s", want, joined)
		}
	}
	r.assertAllPodsDeleted(t)
	if !strings.Contains(r.out, "issuing CA") {
		t.Errorf("no issuing CA line is printed:\n%s", r.out)
	}
}

func TestCopyIssuerFailureCopiesNothingAndDeletesItsPods(t *testing.T) {
	r := runScript(t, "copy-issuer.sh", []string{"FAKE_PHASE=Failed"}, "ns", "t")
	if r.exitCode == 0 {
		t.Fatal("copy-issuer.sh succeeded though init-issuer failed")
	}
	if len(r.calls("exec")) != 0 {
		t.Errorf("a copy ran after init-issuer failed: %v", r.calls("exec"))
	}
	if len(r.applied) != 1 {
		t.Errorf("%d pods applied, want only the init-issuer pod", len(r.applied))
	}
	r.assertAllPodsDeleted(t)
}

func TestCopyIssuerUsage(t *testing.T) {
	if r := runScript(t, "copy-issuer.sh", nil); r.exitCode == 0 {
		t.Error("no arguments succeeded")
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
