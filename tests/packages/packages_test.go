//go:build packages

// Package packages checks the built deb and rpm packages and the archives in dist/ (plan 12b,
// Task 8). Run `make packages` first; `make packages-check` runs both. It is behind the packages
// tag, so `make test` never counts a missing dist/ as a pass: here it is a failure, never a skip.
package packages

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// ansibleCore is the ansible-core the client package's collection is tried under, as the python
// workflow's real-ansible job pins it.
const ansibleCore = "2.21.4"

type entry struct{ mode, owner string }

func dist(t *testing.T, pattern string) string {
	t.Helper()
	m, err := filepath.Glob(filepath.Join("..", "..", "dist", pattern))
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 1 {
		t.Fatalf("dist/%s matched %d files, want exactly 1: run `make packages` first (%v)", pattern, len(m), m)
	}
	return m[0]
}

func run(t *testing.T, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		t.Fatalf("%s %s: %v: %s", name, strings.Join(args, " "), err, errb.String())
	}
	return out.String()
}

// debFiles is `dpkg-deb -c`: path to mode and owner.
func debFiles(t *testing.T, deb string) map[string]entry {
	t.Helper()
	out := map[string]entry{}
	for _, ln := range strings.Split(run(t, "dpkg-deb", "-c", deb), "\n") {
		f := strings.Fields(ln)
		if len(f) < 6 {
			continue
		}
		out[strings.TrimPrefix(f[5], ".")] = entry{f[0], f[1]}
	}
	return out
}

// rpmFiles is `rpm -qlpv`: path to mode and owner.
func rpmFiles(t *testing.T, rpm string) map[string]entry {
	t.Helper()
	out := map[string]entry{}
	for _, ln := range strings.Split(run(t, "rpm", "-qlpv", rpm), "\n") {
		f := strings.Fields(ln)
		if len(f) < 9 {
			continue
		}
		out[f[len(f)-1]] = entry{f[0], f[2] + "/" + f[3]}
	}
	return out
}

func want(t *testing.T, files map[string]entry, path, mode string) {
	t.Helper()
	e, ok := files[path]
	switch {
	case !ok:
		t.Errorf("%s is not in the package", path)
	case e.mode != mode || e.owner != "root/root":
		t.Errorf("%s is %s %s, want %s root/root", path, e.mode, e.owner, mode)
	}
}

// noSpecialBits fails each file with a setuid or setgid bit.
func noSpecialBits(t *testing.T, files map[string]entry) {
	t.Helper()
	for p, e := range files {
		if len(e.mode) == 10 && (e.mode[3] == 's' || e.mode[3] == 'S' || e.mode[6] == 's' || e.mode[6] == 'S') {
			t.Errorf("%s has a setuid or setgid bit (%s)", p, e.mode)
		}
	}
}

var serverBins = []string{"port49d", "port49-broker", "port49-inventory", "port49"}

func TestServerPackageContents(t *testing.T) {
	deb := dist(t, "port49-server_*_amd64.deb")
	files := debFiles(t, deb)
	for _, b := range serverBins {
		want(t, files, "/usr/bin/"+b, "-rwxr-xr-x")
	}
	for _, p := range []string{"/usr/lib/systemd/system/port49d.service", "/usr/lib/systemd/system/port49-broker.service",
		"/usr/lib/sysusers.d/port49.conf", "/usr/lib/tmpfiles.d/port49.conf"} {
		if _, ok := files[p]; !ok {
			t.Errorf("%s is not in the package", p)
		}
	}
	noSpecialBits(t, files)
	if got := strings.TrimSpace(run(t, "dpkg-deb", "-f", deb, "Conflicts")); !strings.Contains(got, "port49") || strings.Contains(got, "port49-server") {
		t.Errorf("Conflicts is %q, want port49", got)
	}
	// static: no program interpreter in any of the four
	dir := t.TempDir()
	run(t, "dpkg-deb", "-x", deb, dir)
	for _, b := range serverBins {
		if out := run(t, "readelf", "-l", filepath.Join(dir, "usr", "bin", b)); strings.Contains(out, "INTERP") {
			t.Errorf("%s has a program interpreter: it is not static", b)
		}
	}
}

func TestClientPackageContents(t *testing.T) {
	deb := dist(t, "port49_*_amd64.deb")
	files := debFiles(t, deb)
	want(t, files, "/usr/bin/port49", "-rwxr-xr-x")
	want(t, files, "/etc/port49/config.yaml", "-rw-r--r--")
	for _, p := range []string{"/usr/share/ansible/collections/ansible_collections/port49/client/galaxy.yml",
		"/usr/lib/python3/dist-packages/port49/__init__.py"} {
		if _, ok := files[p]; !ok {
			t.Errorf("%s is not in the package", p)
		}
	}
	for p := range files {
		if strings.Contains(p, "/ansible_collections/port49/client/tests/") {
			t.Errorf("%s: the collection's tests are in the package", p)
		}
	}
	noSpecialBits(t, files)
	dir := t.TempDir()
	run(t, "dpkg-deb", "-e", deb, dir)
	conf, err := os.ReadFile(filepath.Join(dir, "conffiles"))
	if err != nil || !regexp.MustCompile(`(?m)^/etc/port49/config\.yaml$`).Match(conf) {
		t.Errorf("/etc/port49/config.yaml is not in conffiles (%v)", err)
	}
	if got := strings.TrimSpace(run(t, "dpkg-deb", "-f", deb, "Conflicts")); got != "port49-server" {
		t.Errorf("Conflicts is %q, want port49-server", got)
	}
}

// The client package installs on a bare Debian, its library imports under the system python3, and
// ansible-core finds the collection on its default path. Needs Docker and the network.
func TestTheClientPackageImportsAndFindsTheCollection(t *testing.T) {
	deb := dist(t, "port49_*_amd64.deb")
	abs, err := filepath.Abs(deb)
	if err != nil {
		t.Fatal(err)
	}
	script := fmt.Sprintf(`set -e
apt-get update -qq
apt-get install -y -qq python3 python3-venv >/dev/null
apt-get install -y -qq /pkg/%s >/dev/null
python3 -c 'import port49'
python3 -m venv /v && /v/bin/pip install -q ansible-core==%s
/v/bin/ansible-doc -t lookup port49.client.token >/dev/null
`, filepath.Base(abs), ansibleCore)
	run(t, "docker", "run", "--rm", "-v", filepath.Dir(abs)+":/pkg:ro", "debian:trixie-slim", "sh", "-c", script)
}

func names(files map[string]entry, skip func(string) bool) []string {
	var out []string
	for p, e := range files {
		if strings.HasPrefix(e.mode, "-") && !skip(p) {
			out = append(out, p+" "+e.mode+" "+e.owner)
		}
	}
	sort.Strings(out)
	return out
}

// The rpm holds the same files and modes as the deb, except the Python library, which the rpm
// leaves to pip (an rpm has no version-independent site-packages).
func TestTheRPMsMatch(t *testing.T) {
	none := func(string) bool { return false }
	for _, c := range []struct {
		deb, rpm string
		skip     func(string) bool
	}{
		{"port49-server_*_amd64.deb", "port49-server_*_amd64.rpm", none},
		{"port49_*_amd64.deb", "port49_*_amd64.rpm", func(p string) bool { return strings.HasPrefix(p, "/usr/lib/python3/") }},
	} {
		d := names(debFiles(t, dist(t, c.deb)), c.skip)
		r := names(rpmFiles(t, dist(t, c.rpm)), none)
		if strings.Join(d, "\n") != strings.Join(r, "\n") {
			t.Errorf("%s and %s differ:\ndeb: %v\nrpm: %v", c.deb, c.rpm, d, r)
		}
	}
}

func TestTheDarwinClientArchivesExist(t *testing.T) {
	for _, arch := range []string{"arm64", "amd64"} {
		dist(t, "port49_*_darwin_"+arch+".tar.gz")
	}
}
