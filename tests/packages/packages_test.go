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
	for _, m := range specialBitProblems(files) {
		t.Error(m)
	}
}

// specialBitProblems lists the entries with a setuid or setgid bit, and the ones whose mode is malformed
// (a short mode string must fail with a message, not panic on an index).
func specialBitProblems(files map[string]entry) []string {
	var out []string
	for p, e := range files {
		if len(e.mode) != 10 {
			out = append(out, fmt.Sprintf("%s has a malformed mode %q", p, e.mode))
			continue
		}
		if e.mode[3] == 's' || e.mode[3] == 'S' || e.mode[6] == 's' || e.mode[6] == 'S' {
			out = append(out, fmt.Sprintf("%s has a setuid or setgid bit (%s)", p, e.mode))
		}
	}
	return out
}

// extractDir is `dpkg-deb -x` into a temp dir whose cleanup first gives the owner rwx on everything, so
// a package with a directory lacking the execute bit cannot leave the temp dir behind in /tmp. The
// cleanup is registered before the extraction. A directory the owner cannot traverse fails the test.
func extractDir(t *testing.T, deb string) string {
	t.Helper()
	dir := t.TempDir()
	t.Cleanup(func() {
		filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
			if d != nil && d.IsDir() {
				os.Chmod(p, 0o700)
			}
			return nil
		})
		filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
			if d != nil && d.Type() != os.ModeSymlink {
				if fi, e := d.Info(); e == nil {
					os.Chmod(p, fi.Mode().Perm()|0o700)
				}
			}
			return nil
		})
	})
	run(t, "dpkg-deb", "-x", deb, dir)
	filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if d != nil && d.IsDir() {
			if fi, e := d.Info(); e == nil && fi.Mode().Perm()&0o500 != 0o500 {
				t.Errorf("extracted directory %s is %v: the owner cannot traverse it", p, fi.Mode().Perm())
			}
		}
		return nil
	})
	return dir
}

// rootOwnedNotWritable: every entry is root/root and none is writable by its group or others. The modes
// come from .goreleaser.yaml, not from the builder's umask (a checkout under umask 002 has 0664 files).
func rootOwnedNotWritable(t *testing.T, files map[string]entry) {
	t.Helper()
	for _, m := range modeProblems(files) {
		t.Error(m)
	}
}

func modeProblems(files map[string]entry) []string {
	var out []string
	for p, e := range files {
		if len(e.mode) != 10 {
			out = append(out, fmt.Sprintf("%s has a malformed mode %q", p, e.mode))
			continue
		}
		if e.mode[0] != 'l' && (e.mode[5] == 'w' || e.mode[8] == 'w') {
			out = append(out, fmt.Sprintf("%s is writable by its group or others (%s)", p, e.mode))
		}
		if e.mode[0] == 'd' && e.mode != "drwxr-xr-x" {
			out = append(out, fmt.Sprintf("directory %s is %s, want drwxr-xr-x", p, e.mode))
		}
		if e.owner != "root/root" {
			out = append(out, fmt.Sprintf("%s is owned by %s, want root/root", p, e.owner))
		}
	}
	return out
}

func TestModeChecksReportAMalformedEntryInsteadOfPanicking(t *testing.T) {
	bad := map[string]entry{"/x": {"-rw", "root/root"}, "/y": {"", "root/root"}, "/ok": {"-rw-r--r--", "root/root"}, "/w": {"-rw-rw-r--", "root/root"}}
	if got := modeProblems(bad); len(got) != 3 {
		t.Errorf("modeProblems = %v, want the two malformed entries and the group-writable one", got)
	}
	if got := specialBitProblems(bad); len(got) != 2 {
		t.Errorf("specialBitProblems = %v, want the two malformed entries", got)
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
		want(t, files, p, "-rw-r--r--")
	}
	for _, p := range []string{"/usr/share/doc/port49-server/README.systemd.md", "/usr/share/doc/port49-server/examples/config/port49d.yaml",
		"/usr/share/doc/port49-server/examples/systemd/port49-enrollments-export.service", "/usr/share/doc/port49-server/examples/stores/README.md"} {
		if _, ok := files[p]; !ok {
			t.Errorf("%s is not in the package", p)
		}
	}
	noSpecialBits(t, files)
	rootOwnedNotWritable(t, files)
	// Every file of the three example trees is in the package: a new subdirectory must not be missed by
	// the globs in .goreleaser.yaml.
	for src, dst := range map[string]string{"deploy/systemd/config": "examples/config", "deploy/systemd/examples": "examples/systemd", "deploy/examples/stores": "examples/stores"} {
		err := filepath.WalkDir(filepath.Join("..", "..", filepath.FromSlash(src)), func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			rel, _ := filepath.Rel(filepath.Join("..", "..", filepath.FromSlash(src)), p)
			if _, ok := files["/usr/share/doc/port49-server/"+dst+"/"+filepath.ToSlash(rel)]; !ok {
				t.Errorf("%s/%s is not in the package", src, rel)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	// the maintainer scripts are ours: the postinst makes users and directories and starts
	// nothing, the prerm stops the units on removal only
	ctl := t.TempDir()
	run(t, "dpkg-deb", "-e", deb, ctl)
	post, _ := os.ReadFile(filepath.Join(ctl, "postinst"))
	for _, want := range []string{"systemd-sysusers port49.conf", "systemd-tmpfiles --create port49.conf", "systemctl daemon-reload"} {
		if !strings.Contains(string(post), want) {
			t.Errorf("postinst lacks %q", want)
		}
	}
	if regexp.MustCompile(`systemctl (enable|start|restart)`).Match(post) {
		t.Error("postinst enables or starts a unit")
	}
	pre, _ := os.ReadFile(filepath.Join(ctl, "prerm"))
	if !strings.Contains(string(pre), "systemctl disable --now port49d.service port49-broker.service") || !strings.Contains(string(pre), "remove | 0") {
		t.Error("prerm does not stop and disable the units on removal only")
	}
	if got := strings.TrimSpace(run(t, "dpkg-deb", "-f", deb, "Conflicts")); !strings.Contains(got, "port49") || strings.Contains(got, "port49-server") {
		t.Errorf("Conflicts is %q, want port49", got)
	}
	// static: no program interpreter in any of the four
	dir := extractDir(t, deb)
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
	rootOwnedNotWritable(t, files)
	// Nothing falls out: every file of the collection (but its tests) and of the Python library is in the
	// package, so a new subdirectory or a non-.py file the globs in .goreleaser.yaml miss fails here.
	inPackage := func(src, dst string, skipTests bool) {
		root := filepath.Join("..", "..", filepath.FromSlash(src))
		err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(root, p)
			if d.IsDir() {
				if d.Name() == "__pycache__" || skipTests && rel == "tests" {
					return filepath.SkipDir
				}
				return nil
			}
			if _, ok := files[dst+"/"+filepath.ToSlash(rel)]; !ok {
				t.Errorf("%s/%s is not in the package", src, rel)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	inPackage("clients/ansible/ansible_collections/port49/client", "/usr/share/ansible/collections/ansible_collections/port49/client", true)
	inPackage("clients/python/src/port49", "/usr/lib/python3/dist-packages/port49", false)
	dir := t.TempDir()
	run(t, "dpkg-deb", "-e", deb, dir)
	conf, err := os.ReadFile(filepath.Join(dir, "conffiles"))
	if err != nil || !regexp.MustCompile(`(?m)^/etc/port49/config\.yaml$`).Match(conf) {
		t.Errorf("/etc/port49/config.yaml is not in conffiles (%v)", err)
	}
	if got := strings.TrimSpace(run(t, "dpkg-deb", "-f", deb, "Recommends")); !strings.Contains(got, "python3") {
		t.Errorf("Recommends is %q, want python3", got)
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

// The rpms follow the same mode rules as the debs (directories 0755, files 0644, binaries 0755, root/root,
// nothing group- or other-writable), own the doc directories so removing the package leaves none, and
// carry the same scripts and maintainer.
func TestTheRPMsAreRootOwnedAndTheScriptsAreOurs(t *testing.T) {
	srv := dist(t, "port49-server_*_amd64.rpm")
	files := rpmFiles(t, srv)
	noSpecialBits(t, files)
	rootOwnedNotWritable(t, files)
	for p, e := range files {
		switch {
		case e.mode[0] == 'd':
		case strings.HasPrefix(p, "/usr/bin/"):
			want(t, files, p, "-rwxr-xr-x")
		default:
			want(t, files, p, "-rw-r--r--")
		}
	}
	for _, d := range []string{"/usr/share/doc/port49-server", "/usr/share/doc/port49-server/examples", "/usr/share/doc/port49-server/examples/stores/multi-region"} {
		want(t, files, d, "drwxr-xr-x")
	}
	cli := rpmFiles(t, dist(t, "port49_*_amd64.rpm"))
	rootOwnedNotWritable(t, cli)
	scripts := run(t, "rpm", "-qp", "--scripts", srv)
	for _, w := range []string{"systemd-sysusers port49.conf", "systemd-tmpfiles --create port49.conf", "systemctl daemon-reload",
		"systemctl disable --now port49d.service port49-broker.service", "remove | 0"} {
		if !strings.Contains(scripts, w) {
			t.Errorf("the rpm scripts lack %q", w)
		}
	}
	if regexp.MustCompile(`systemctl (enable|start|restart)`).MatchString(scripts) {
		t.Error("an rpm script enables or starts a unit")
	}
	for _, p := range []string{srv, dist(t, "port49_*_amd64.rpm")} {
		if got := strings.TrimSpace(run(t, "rpm", "-qp", "--qf", "%{PACKAGER}", p)); got != "port49 maintainers <port49@blanketfish.com>" {
			t.Errorf("%s packager is %q", filepath.Base(p), got)
		}
	}
}

// The rpm marks /etc/port49/config.yaml as a config file that an upgrade does not replace.
func TestTheRPMKeepsTheConffile(t *testing.T) {
	out := run(t, "rpm", "-qp", "--qf", `[%{FILEFLAGS:fflags} %{FILENAMES}\n]`, dist(t, "port49_*_amd64.rpm"))
	for _, ln := range strings.Split(out, "\n") {
		if f := strings.Fields(ln); len(f) == 2 && f[1] == "/etc/port49/config.yaml" {
			if !strings.Contains(f[0], "c") || !strings.Contains(f[0], "n") {
				t.Errorf("/etc/port49/config.yaml has file flags %q, want config and noreplace", f[0])
			}
			return
		}
	}
	t.Error("/etc/port49/config.yaml is not in the rpm")
}

func TestTheDarwinClientArchivesExist(t *testing.T) {
	for _, arch := range []string{"arm64", "amd64"} {
		dist(t, "port49_*_darwin_"+arch+".tar.gz")
	}
}
