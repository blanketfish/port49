package kindtest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rhwendt/port49/tests/shapes/shapetest"
)

const podJSON = `{"spec":{"nodeName":"kind-worker"},"status":{"phase":"Running","hostIP":"172.18.0.3",
"conditions":[{"type":"Initialized","status":"True"},{"type":"Ready","status":"True"}],
"containerStatuses":[{"restartCount":2,"state":{"running":{"startedAt":"2026-10-28T10:00:00Z"}}}]}}`

const crashJSON = `{"spec":{"nodeName":"kind-worker2"},"status":{"phase":"Running","hostIP":"172.18.0.4",
"conditions":[{"type":"Ready","status":"False"}],
"containerStatuses":[{"restartCount":4,"state":{"waiting":{"reason":"CrashLoopBackOff"}}}],
"initContainerStatuses":[{"state":{"terminated":{"exitCode":0}}}]}}`

func TestParsePod(t *testing.T) {
	p, err := ParsePod([]byte(podJSON))
	if err != nil || !p.Ready || p.Restarts != 2 || p.StartedAt != "2026-10-28T10:00:00Z" || p.HostIP != "172.18.0.3" ||
		p.Node != "kind-worker" || p.Waiting != "" {
		t.Fatalf("%+v %v", p, err)
	}
	p, err = ParsePod([]byte(crashJSON))
	if err != nil || p.Ready || p.Waiting != "CrashLoopBackOff" || p.Restarts != 4 {
		t.Fatalf("%+v %v", p, err)
	}
	if _, err := ParsePod([]byte("not json")); err == nil {
		t.Error("garbage parsed as a pod")
	}
}

func TestParseStat(t *testing.T) {
	ss, err := ParseStat("700 65532 65532 /v/state\n600 65532 65532 /v/state/issuing-ca.key\n")
	if err != nil || len(ss) != 2 {
		t.Fatalf("%v %v", ss, err)
	}
	if err := ss[1].Want("600", 65532, 65532); err != nil {
		t.Error(err)
	}
	if err := ss[1].Want("660", 65532, 65532); err == nil || !strings.Contains(err.Error(), "issuing-ca.key") {
		t.Errorf("a 600 key passed for 660: %v", err)
	}
	for _, bad := range []string{"", "700 x 1 /p", "9 1 1 /p", "700 1 1", "700 1 1 /a /b"} {
		if _, err := ParseStat(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}

const newInit = `command: [sh, -c, "chown 0:65532 /var/lib/port49-broker && chmod 3770 /var/lib/port49-broker && install -d -m 0700 -o 65532 -g 65532 /var/lib/port49-broker/state && chown -R 65532:65532 /var/lib/port49-broker/state && chmod -R go-rwx /var/lib/port49-broker/state && chmod -R g-s /var/lib/port49-broker/state && chmod 0700 /var/lib/port49-broker/state"]`

func TestOldRootRewritesToTheFirstDesign(t *testing.T) {
	out, err := OldRoot([]byte("a: 1\n" + newInit + "\nb: 2\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := `"install -d -m 0700 -o 65532 -g 65532 /var/lib/port49-broker/state && chmod g-w /var/lib/port49-broker"`
	if !strings.Contains(string(out), want) || strings.Contains(string(out), "3770") || !strings.Contains(string(out), "a: 1") {
		t.Fatalf("rewritten text:\n%s", out)
	}
	// Both pods' commands are rewritten.
	two := newInit + "\n" + strings.ReplaceAll(newInit, "/var/lib/port49-broker", "/var/spool/port49d")
	out, err = OldRoot([]byte(two))
	if err != nil || strings.Count(string(out), "chmod g-w") != 2 {
		t.Fatalf("%v:\n%s", err, out)
	}
	// Nothing to rewrite is an error: a changed chart must break the cell, not make it green.
	if _, err := OldRoot([]byte("kind: StatefulSet\n")); err == nil {
		t.Error("a manifest with no init command was accepted")
	}
}

func TestStateDirRefusalMatchesTheBrokersLine(t *testing.T) {
	line := "config: broker.state_dir /var/lib/port49-broker/state is writable by its group or others (mode 0770): port49-broker's own state"
	if !StateDirRefusal.MatchString(line) {
		t.Fatal("the refusal pattern does not match the broker's line")
	}
	for _, other := range []string{
		"config: broker.state_dir /var/lib/port49-broker/state must be a directory that exists",
		"config: broker.state_dir /tmp/x is writable by its group or others (mode 0770)",
		"config: broker.state_dir /var/lib/port49-broker/state is writable by its group or others (mode 0750)",
		"config: broker.state_dir /var/lib/port49-broker/state is writable by its group or others (mode 0700)",
	} {
		if StateDirRefusal.MatchString(other) {
			t.Errorf("matched %q", other)
		}
	}
	for _, mode := range []string{"0770", "0775", "0720", "0702"} {
		if !StateDirRefusal.MatchString("config: broker.state_dir /var/lib/port49-broker/state is writable by its group or others (mode " + mode + "): x") {
			t.Errorf("mode %s is not matched", mode)
		}
	}
	// And the pattern is the source's format, not a guess.
	src, err := os.ReadFile(filepath.Join(Root(), "internal", "config", "config.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), `"config: broker.state_dir %s is writable by its group or others (mode %04o): "`) {
		t.Error("internal/config/config.go no longer prints the state_dir refusal this pattern matches")
	}
}

func TestDumpNeverReadsTheVaultNamespace(t *testing.T) {
	got := DumpNamespaces([]string{"default", "vault", "port49", "", "kube-system"})
	if strings.Join(got, ",") != "default,port49,kube-system" {
		t.Fatalf("%v", got)
	}
}

func TestRedactHidesALiteral(t *testing.T) {
	r := Redact([]string{"create", "secret", "generic", "x", "--from-literal=k=SECRETVALUE", "--from-file=a=b"})
	if strings.Contains(r, "SECRETVALUE") || !strings.Contains(r, "--from-file=a=b") {
		t.Fatal(r)
	}
}

func TestFilterDropsALineNamingASecret(t *testing.T) {
	out := Filter("pod ready\nthe token is abc\nkeep this line\n")
	if strings.Contains(out, "abc") || !strings.Contains(out, "keep this line") {
		t.Fatalf("%q", out)
	}
}

const localPV = `{"spec":{"storageClassName":"port49-fsgroup","local":{"path":"/var/local-path-provisioner/pvc-1"}}}`
const hostPathPV = `{"spec":{"storageClassName":"standard","hostPath":{"path":"/var/local-path-provisioner/pvc-1","type":"DirectoryOrCreate"}}}`

func TestCheckLocalPV(t *testing.T) {
	if err := CheckLocalPV([]byte(localPV)); err != nil {
		t.Errorf("a local PV was refused: %v", err)
	}
	err := CheckLocalPV([]byte(hostPathPV))
	if err == nil || !strings.Contains(err.Error(), `"standard"`) || !strings.Contains(err.Error(), "hostPath") {
		t.Errorf("a hostPath PV: %v, want a refusal naming the class and hostPath", err)
	}
	// both set is still hostPath
	if CheckLocalPV([]byte(`{"spec":{"storageClassName":"x","hostPath":{"path":"/a"},"local":{"path":"/b"}}}`)) == nil {
		t.Error("a PV with hostPath and local passed")
	}
	for _, bad := range []string{`{"spec":{"storageClassName":"nfs","nfs":{"server":"s"}}}`, `{"spec":{"local":{"path":""}}}`, `not json`} {
		if CheckLocalPV([]byte(bad)) == nil {
			t.Errorf("%s passed as a local PV", bad)
		}
	}
}

func TestPermitMintMatchesTheRecordNotASubstring(t *testing.T) {
	const p = "system:serviceaccount:port49:oxidized"
	permit := `{"ts":"2026-10-28T10:00:00Z","event":"mint","verdict":"permit","reason":"grants_matched","principal":"` + p + `"}`
	deny := `{"event":"mint","verdict":"deny","reason":"no_grants_matched","principal":"` + p + `"}`
	other := `{"event":"mint","verdict":"permit","principal":"system:serviceaccount:port49:other"}`
	login := `{"event":"login","verdict":"permit","principal":"` + p + `"}`
	noise := "level=info msg=\"serving " + p + "\""
	if !PermitMint("starting\n"+noise+"\n"+permit+"\n", p) {
		t.Error("a permit mint record was not found")
	}
	if !PermitMint("pod/t-broker-0 "+permit, p) {
		t.Error("a permit mint record behind a prefix was not found")
	}
	for name, logs := range map[string]string{"deny": deny, "other principal": other, "other event": login, "noise": noise, "empty": ""} {
		if PermitMint(logs, p) {
			t.Errorf("%s satisfied the permit-mint check", name)
		}
	}
}

// Up deletes a stale cluster before the create, and deletes again at the end; against a fake kind.
func TestUpDeletesAStaleClusterFirstAndAgainAtTheEnd(t *testing.T) {
	dir := t.TempDir()
	logf := filepath.Join(dir, "log")
	fake := filepath.Join(dir, "kind")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\necho \"$*\" >> "+logf+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	defer func(r string) { shapetest.KeyHostRoot = r }(shapetest.KeyHostRoot)
	shapetest.KeyHostRoot = t.TempDir() // the fake tree has no TPM; this host may
	t.Setenv("KIND_BIN", fake)
	t.Setenv("KUBECTL_BIN", fake)
	t.Run("run", func(t *testing.T) { Up(t, "stalecheck") })
	b, _ := os.ReadFile(logf)
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 3 || lines[0] != "delete cluster --name stalecheck" || !strings.HasPrefix(lines[1], "create cluster --name stalecheck") ||
		lines[2] != "delete cluster --name stalecheck" {
		t.Errorf("kind was called as %q, want delete, create, delete", lines)
	}
}

func TestPodCommandsCoverEveryPodWithoutReadingSecrets(t *testing.T) {
	got := PodCommands("port49", []string{"pod/store-roles", "t-broker-0"})
	want := [][]string{
		{"-n", "port49", "describe", "pod", "store-roles"},
		{"-n", "port49", "logs", "--all-containers", "--prefix", "--tail=60", "store-roles"},
		{"-n", "port49", "describe", "pod", "t-broker-0"},
		{"-n", "port49", "logs", "--all-containers", "--prefix", "--tail=60", "t-broker-0"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if strings.Join(got[i], " ") != strings.Join(want[i], " ") {
			t.Errorf("command %d = %v, want %v", i, got[i], want[i])
		}
		for _, a := range got[i] {
			if a == "secret" || a == "secrets" {
				t.Errorf("command %d reads a Secret", i)
			}
		}
	}
	if got := PodCommands("x", nil); len(got) != 0 {
		t.Errorf("no pods, commands %v", got)
	}
}

func TestNamespaceCommandsShowLabelsEventsAndWorkloadsWithoutSecrets(t *testing.T) {
	var all []string
	for _, c := range NamespaceCommands("port49") {
		all = append(all, strings.Join(c, " "))
		for _, a := range c {
			if a == "secret" || a == "secrets" || strings.Contains(a, "secret,") || strings.Contains(a, ",secret") {
				t.Errorf("%v reads a Secret", c)
			}
		}
	}
	text := strings.Join(all, "\n")
	for _, want := range []string{"get namespace port49 --show-labels", "-n port49 get events --sort-by=.lastTimestamp",
		"-n port49 get statefulset,job,pvc -o wide", "-n port49 describe statefulset", "-n port49 describe job"} {
		if !strings.Contains(text, want) {
			t.Errorf("the namespace commands lack %q:\n%s", want, text)
		}
	}
}
