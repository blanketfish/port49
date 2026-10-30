package helm

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// initRun runs one command in the init image against a named volume, mounted where the chart mounts
// it, with the container's securityContext from the rendered chart: the user, the capability set,
// no new privileges, a read-only root. It returns the combined output and the exit error.
func initRun(vol, mount, user string, caps []string, script string) (string, error) {
	args := []string{"run", "--rm", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
		"--user", user, "-v", vol + ":" + mount}
	for _, c := range caps {
		args = append(args, "--cap-add", c)
	}
	args = append(args, "alpine:3.22", "sh", "-c", script)
	cmd := exec.Command("docker", args...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.String(), err
}

// The two data-dir init containers, run as the chart gives them (root with the three capabilities,
// then 65532 with none) on a real volume: the fresh volume ends root:65532 3770 with a 0700 65532
// directory; a tree below it left group-writable and setgid is repaired by the owner init alone; and
// a file another uid owns stops the owner init, which names the path and the one chown to run.
func TestTheDataDirInitsRunInTheirContainers(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("no docker")
	}
	if err := exec.Command("docker", "image", "inspect", "alpine:3.22").Run(); err != nil {
		if out, err := exec.Command("docker", "pull", "alpine:3.22").CombinedOutput(); err != nil {
			t.Skipf("alpine:3.22 is not available: %v\n%s", err, out)
		}
	}
	const mount, dir = "/var/lib/port49-broker", "/var/lib/port49-broker/state"
	docs := render(t, goRender, "")
	p := pod(one(t, docs, "StatefulSet", "t-broker"))
	rootCmd := str(at(p, "initContainers", 0, "command", 2))
	ownerCmd := str(at(p, "initContainers", 1, "command", 2))
	rootCaps := strs(at(p, "initContainers", 0, "securityContext", "capabilities", "add"))

	vol := fmt.Sprintf("port49-initscript-%d", time.Now().UnixNano())
	if out, err := exec.Command("docker", "volume", "create", vol).CombinedOutput(); err != nil {
		t.Fatalf("docker volume create: %v\n%s", err, out)
	}
	defer exec.Command("docker", "volume", "rm", "-f", vol).Run()
	// Fixtures and stat run as a root with every capability: the test's hands, not the chart's.
	fixture := func(script string) string {
		t.Helper()
		out, err := initRun(vol, mount, "0", []string{"ALL"}, script)
		if err != nil {
			t.Fatalf("fixture %q: %v\n%s", script, err, out)
		}
		return out
	}
	stat := func() string {
		return fixture("stat -c '%a %u:%g %n' " + mount + " " + dir + " " + dir + "/* 2>&1 | sort -k3")
	}

	// 1. A fresh volume.
	if out, err := initRun(vol, mount, "0", rootCaps, rootCmd); err != nil {
		t.Fatalf("the root init on a fresh volume: %v\n%s", err, out)
	}
	if out, err := initRun(vol, mount, "65532:65532", nil, ownerCmd); err != nil {
		t.Fatalf("the owner init on a fresh volume: %v\n%s", err, out)
	}
	got := stat()
	for _, want := range []string{"3770 0:65532 " + mount, "700 65532:65532 " + dir} {
		if !strings.Contains(got, want) {
			t.Errorf("after both inits the volume lacks %q:\n%s", want, got)
		}
	}

	// 2. A tree the kubelet's walk (or a restore as the owner) left group-writable and setgid.
	fixture("mkdir -p " + dir + "/sub && echo x > " + dir + "/sub/f && chown -R 65532:65532 " + dir +
		" && chmod 2770 " + dir + " " + dir + "/sub && chmod 0660 " + dir + "/sub/f")
	for _, c := range []struct {
		user, script string
		caps         []string
	}{{"0", rootCmd, rootCaps}, {"65532:65532", ownerCmd, nil}} {
		if out, err := initRun(vol, mount, c.user, c.caps, c.script); err != nil {
			t.Fatalf("an init on a walked tree: %v\n%s", err, out)
		}
	}
	got = stat()
	for _, want := range []string{"700 65532:65532 " + dir, "700 65532:65532 " + dir + "/sub"} {
		if !strings.Contains(got, want) {
			t.Errorf("the walked tree was not repaired, lacks %q:\n%s", want, got)
		}
	}
	if out := fixture("stat -c '%a' " + dir + "/sub/f"); strings.TrimSpace(out) != "600" {
		t.Errorf("sub/f is mode %s, want 600", strings.TrimSpace(out))
	}

	// 3. A file another uid owns (a restore done as root): the owner init cannot chown it, so it
	// stops, names the path and the one command, and changes nothing.
	fixture("echo y > " + dir + "/sub/restored && chmod 0664 " + dir + "/sub/restored")
	out, err := initRun(vol, mount, "65532:65532", nil, ownerCmd)
	if err == nil {
		t.Fatalf("the owner init passed over a file owned by another uid:\n%s", out)
	}
	for _, want := range []string{dir + "/sub/restored", "chown -R 65532:65532 " + dir} {
		if !strings.Contains(out, want) {
			t.Errorf("the owner init's failure lacks %q:\n%s", want, out)
		}
	}
	if m := fixture("stat -c '%a' " + dir + "/sub/restored"); strings.TrimSpace(m) != "664" {
		t.Errorf("the refused file's mode changed to %s", strings.TrimSpace(m))
	}
	// The operator runs the printed command; the next run goes through.
	fixture("chown -R 65532:65532 " + dir)
	if out, err := initRun(vol, mount, "65532:65532", nil, ownerCmd); err != nil {
		t.Fatalf("the owner init after the chown: %v\n%s", err, out)
	}
	if m := fixture("stat -c '%a' " + dir + "/sub/restored"); strings.TrimSpace(m) != "600" {
		t.Errorf("after the chown the file is mode %s, want 600", strings.TrimSpace(m))
	}
}
