package shapes

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// What can be checked about the packages without building them: .goreleaser.yaml's sources
// exist, its scripts are the repo's, and the install and remove scripts do what the review
// asked, run against stub systemd commands. Everything that reads dist/ is tests/packages.

type nfpm struct {
	ID         string   `yaml:"id"`
	Recommends []string `yaml:"recommends"`
	Contents   []struct {
		Src  string `yaml:"src"`
		Dst  string `yaml:"dst"`
		Type string `yaml:"type"`
	} `yaml:"contents"`
	Scripts map[string]string `yaml:"scripts"`
}

func goreleaser(t *testing.T) map[string]nfpm {
	t.Helper()
	var g struct {
		NFPMs []nfpm `yaml:"nfpms"`
	}
	if err := yaml.Unmarshal([]byte(read(t, ".goreleaser.yaml")), &g); err != nil {
		t.Fatal(err)
	}
	out := map[string]nfpm{}
	for _, n := range g.NFPMs {
		out[n.ID] = n
	}
	return out
}

func TestTheGoreleaserPackagesNameRealFiles(t *testing.T) {
	pk := goreleaser(t)
	if len(pk) != 2 {
		t.Fatalf("%d nfpm packages, want port49-server and port49", len(pk))
	}
	for id, n := range pk {
		dst := map[string]bool{}
		for _, c := range n.Contents {
			if _, err := os.Stat(filepath.Join("..", "..", c.Src)); err != nil {
				t.Errorf("%s: %s does not exist", id, c.Src)
			}
			if dst[c.Dst] {
				t.Errorf("%s: %s is installed twice", id, c.Dst)
			}
			dst[c.Dst] = true
		}
		for kind, path := range n.Scripts {
			fi, err := os.Stat(filepath.Join("..", "..", path))
			if err != nil || fi.Mode().Perm()&0o111 == 0 {
				t.Errorf("%s: the %s script %s is missing or not executable (%v)", id, kind, path, err)
			}
		}
	}
	srv := pk["port49-server"]
	if srv.Scripts["postinstall"] != "packaging/server/postinstall.sh" || srv.Scripts["preremove"] != "packaging/server/preremove.sh" {
		t.Errorf("the server package's scripts are %v", srv.Scripts)
	}
	have := map[string]bool{}
	for _, c := range srv.Contents {
		have[c.Dst] = true
	}
	for _, want := range []string{"/usr/share/doc/port49-server/README.systemd.md", "/usr/share/doc/port49-server/examples/config/",
		"/usr/share/doc/port49-server/examples/systemd/", "/usr/share/doc/port49-server/examples/stores/"} {
		if !have[want] {
			t.Errorf("the server package does not install %s", want)
		}
	}
	if r := pk["port49"].Recommends; len(r) != 1 || r[0] != "python3" {
		t.Errorf("the client package recommends %v, want python3", r)
	}
	for _, c := range pk["port49"].Contents {
		if c.Dst == "/etc/port49/config.yaml" && c.Type != "config|noreplace" {
			t.Errorf("/etc/port49/config.yaml is type %q, want config|noreplace", c.Type)
		}
	}
}

func TestLocalPackagesDoNotSignOrPublish(t *testing.T) {
	if !strings.Contains(read(t, "Makefile"), "release --snapshot --clean --skip=publish,sign") {
		t.Error("make packages does not skip publish and sign")
	}
}

// stubs makes a PATH of commands that record their arguments, with the named ones failing.
func stubs(t *testing.T, fail ...string) (path, log string) {
	t.Helper()
	dir := t.TempDir()
	log = filepath.Join(dir, "calls")
	for _, c := range []string{"systemd-sysusers", "systemd-tmpfiles", "systemctl"} {
		body := "#!/bin/sh\necho \"" + c + " $*\" >> " + log + "\n"
		for _, f := range fail {
			if f == c {
				body += "exit 1\n"
			}
		}
		if err := os.WriteFile(filepath.Join(dir, c), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return dir + ":/usr/bin:/bin", log
}

// runScript runs a packaging script with the stub PATH; running says whether systemd is the
// init (the hook's directory exists).
func runScript(t *testing.T, script, path string, running bool, args ...string) error {
	_, err := runScriptOut(t, script, path, running, args...)
	return err
}

func runScriptOut(t *testing.T, script, path string, running bool, args ...string) (string, error) {
	t.Helper()
	run := filepath.Join(t.TempDir(), "absent")
	if running {
		run = t.TempDir()
	}
	cmd := exec.Command("sh", append([]string{filepath.Join("..", "..", "packaging", "server", script)}, args...)...)
	cmd.Env = []string{"PATH=" + path, "PORT49_PKG_SYSTEMD_RUN=" + run}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func calls(t *testing.T, log string) string {
	b, _ := os.ReadFile(log)
	return string(b)
}

func TestThePostinstallFailsLoudlyAndStartsNothing(t *testing.T) {
	path, log := stubs(t)
	if err := runScript(t, "postinstall.sh", path, true, "configure"); err != nil {
		t.Fatal(err)
	}
	got := calls(t, log)
	for _, want := range []string{"systemd-sysusers port49.conf", "systemd-tmpfiles --create port49.conf", "systemctl daemon-reload"} {
		if !strings.Contains(got, want) {
			t.Errorf("the postinstall did not run %q (calls: %q)", want, got)
		}
	}
	for _, bad := range []string{"enable", "start", "restart"} {
		if strings.Contains(got, "systemctl "+bad) {
			t.Errorf("the postinstall ran systemctl %s", bad)
		}
	}
	for _, f := range []string{"systemd-sysusers", "systemd-tmpfiles"} {
		path, _ := stubs(t, f)
		if err := runScript(t, "postinstall.sh", path, true); err == nil {
			t.Errorf("a failed %s does not fail the install", f)
		}
	}
	// no systemd running (a container or a chroot): users and directories, but no reload
	path, log = stubs(t)
	if err := runScript(t, "postinstall.sh", path, false); err != nil {
		t.Fatal(err)
	}
	if got := calls(t, log); strings.Contains(got, "systemctl") || !strings.Contains(got, "systemd-sysusers") {
		t.Errorf("with no systemd running the postinstall ran %q", got)
	}
}

func TestThePreremoveStopsOnRemovalOnly(t *testing.T) {
	for arg, stops := range map[string]bool{"remove": true, "0": true, "upgrade": false, "1": false, "": false} {
		path, log := stubs(t)
		var args []string
		if arg != "" {
			args = []string{arg}
		}
		if err := runScript(t, "preremove.sh", path, true, args...); err != nil {
			t.Fatalf("preremove %q: %v", arg, err)
		}
		got := calls(t, log)
		if stops != strings.Contains(got, "systemctl disable --now port49d.service port49-broker.service") {
			t.Errorf("preremove %q: stops=%v, calls %q", arg, stops, got)
		}
	}
	path, log := stubs(t)
	if err := runScript(t, "preremove.sh", path, false, "remove"); err != nil || calls(t, log) != "" {
		t.Errorf("with no systemd running the preremove ran %q (%v)", calls(t, log), err)
	}
	path, _ = stubs(t, "systemctl")
	out, err := runScriptOut(t, "preremove.sh", path, true, "remove")
	if err != nil {
		t.Errorf("a unit that will not stop blocks the removal: %v", err)
	}
	if !strings.Contains(out, "stop and disable port49d and port49-broker yourself") {
		t.Errorf("a unit that will not stop is not said: %q", out)
	}
}
