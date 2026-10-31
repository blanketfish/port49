//go:build image

// Package image checks the built container image's layout (plan 12b, Task 5).
// Run it with `make image-check`, which builds port49:dev first.
package image

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const (
	uid      = 65532
	capXattr = "SCHILY.xattr.security.capability"
)

var binaries = []string{"port49d", "port49-broker", "port49", "port49-inventory"}

// state directories are the user's alone: broker.state_dir and the spool
// refuse anything a group or another user can write.
var stateDirs = []string{"var/lib/port49-broker", "var/spool/port49d", "run/port49"}

// layoutProblems reads an exported image filesystem and returns every path
// whose owner or mode is wrong, each naming the path and its mode.
//
// An OpenShift-style rebuild that runs chmod g=u over the tree gives every
// directory group write and fails here; the fence refuses the same tree at
// start, for the same reason.
func layoutProblems(r io.Reader) ([]string, error) {
	var problems []string
	seen := map[string]bool{}
	tr := tar.NewReader(r)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		name := strings.Trim(h.Name, "/")
		mode := h.FileInfo().Mode()
		seen[name] = true
		bad := func(why string) {
			problems = append(problems, fmt.Sprintf("/%s: %s (mode %s, uid %d gid %d)", name, why, mode, h.Uid, h.Gid))
		}
		if h.Typeflag == tar.TypeDir {
			if h.Uid != 0 && h.Uid != uid {
				bad("a directory owned by neither root nor the port49 user")
			}
			sticky := h.Mode&0o1000 != 0
			if h.Mode&0o022 != 0 && !(sticky && h.Uid == 0) {
				bad("a directory writable by group or other")
			}
		}
		// A file no group or other user can write, and no setuid or setgid bit anywhere: a
		// symlink's mode is always 0777 in a tar and means nothing, so it is skipped.
		if h.Typeflag != tar.TypeDir && h.Typeflag != tar.TypeSymlink && h.Typeflag != tar.TypeLink {
			if h.Mode&0o022 != 0 {
				bad("a file writable by group or other")
			}
			if h.Mode&0o6000 != 0 {
				bad("a setuid or setgid file")
			}
		}
		for _, d := range stateDirs {
			if name == d && (h.Uid != uid || h.Gid != uid || h.Mode&0o7777 != 0o700) {
				bad("a state directory must be 65532:65532 and 0700")
			}
		}
		for _, b := range binaries {
			if name != "usr/local/bin/"+b {
				continue
			}
			if h.Mode&0o7777 != 0o755 || h.Uid != 0 {
				bad("a binary must be 0755, owned by root, with no setuid or setgid bit")
			}
			if _, ok := h.PAXRecords[capXattr]; ok {
				bad("a binary carries a file capability")
			}
		}
	}
	for _, d := range stateDirs {
		if !seen[d] {
			problems = append(problems, "/"+d+": missing")
		}
	}
	for _, b := range binaries {
		if !seen["usr/local/bin/"+b] {
			problems = append(problems, "/usr/local/bin/"+b+": missing")
		}
	}
	return problems, nil
}

func TestTheImageLayout(t *testing.T) {
	out, err := exec.Command("docker", "create", "port49:dev").Output()
	if err != nil {
		t.Fatalf("docker create port49:dev: %v (run make image first)", err)
	}
	id := strings.TrimSpace(string(out))
	t.Cleanup(func() { _ = exec.Command("docker", "rm", id).Run() })
	cmd := exec.Command("docker", "export", id)
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	problems, err := layoutProblems(pipe)
	_, _ = io.Copy(io.Discard, pipe)
	if werr := cmd.Wait(); werr != nil && err == nil {
		err = werr
	}
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range problems {
		t.Error(p)
	}
}

type ent struct {
	name string
	typ  byte
	mode int64
	uid  int
	gid  int
	pax  map[string]string
}

func export(t *testing.T, ents []ent) *bytes.Reader {
	t.Helper()
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for _, e := range ents {
		h := &tar.Header{Name: e.name, Typeflag: e.typ, Mode: e.mode, Uid: e.uid, Gid: e.gid, PAXRecords: e.pax, Format: tar.FormatPAX}
		if e.typ == tar.TypeReg {
			h.Size = 0
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return bytes.NewReader(b.Bytes())
}

func good() []ent {
	e := []ent{
		{name: "tmp/", typ: tar.TypeDir, mode: 0o1777},
		{name: "usr/", typ: tar.TypeDir, mode: 0o755},
	}
	for _, d := range stateDirs {
		e = append(e, ent{name: d + "/", typ: tar.TypeDir, mode: 0o700, uid: uid, gid: uid})
	}
	for _, b := range binaries {
		e = append(e, ent{name: "usr/local/bin/" + b, typ: tar.TypeReg, mode: 0o755})
	}
	e = append(e,
		ent{name: "etc/ssl/certs/ca.pem", typ: tar.TypeReg, mode: 0o644},
		ent{name: "etc/ssl/cert.pem", typ: tar.TypeSymlink, mode: 0o777})
	return e
}

func TestTheLayoutCheckRefusesWhatItShould(t *testing.T) {
	if p, err := layoutProblems(export(t, good())); err != nil || len(p) != 0 {
		t.Fatalf("a good tree: %v %v", p, err)
	}
	for _, c := range []struct {
		name string
		edit func(e []ent) []ent
		want string
	}{
		{"group write on a directory (chmod g=u)", func(e []ent) []ent { e[1].mode = 0o775; return e }, "/usr: a directory writable"},
		{"world write on a directory", func(e []ent) []ent { e[1].mode = 0o757; return e }, "/usr: a directory writable"},
		{"a sticky directory owned by another user", func(e []ent) []ent { e[0].uid = 1000; return e }, "/tmp:"},
		{"a sticky world-writable directory owned by the user", func(e []ent) []ent { e[0].uid = uid; return e }, "/tmp: a directory writable"},
		{"a directory owned by another user", func(e []ent) []ent { e[1].uid = 1000; return e }, "/usr: a directory owned"},
		{"a state directory at 0755", func(e []ent) []ent { e[2].mode = 0o755; return e }, "/var/lib/port49-broker: a state directory"},
		{"a state directory owned by root", func(e []ent) []ent { e[3].uid = 0; return e }, "/var/spool/port49d: a state directory"},
		{"a state directory with the wrong group", func(e []ent) []ent { e[4].gid = 0; return e }, "/run/port49: a state directory"},
		{"a missing state directory", func(e []ent) []ent { return append(e[:2], e[3:]...) }, "/var/lib/port49-broker: missing"},
		{"a group-writable binary", func(e []ent) []ent { e[5].mode = 0o775; return e }, "/usr/local/bin/port49d: a binary"},
		{"a setuid binary", func(e []ent) []ent { e[6].mode = 0o4755; return e }, "/usr/local/bin/port49-broker: a binary"},
		{"a setgid binary", func(e []ent) []ent { e[7].mode = 0o2755; return e }, "/usr/local/bin/port49: a binary"},
		{"a binary owned by the user", func(e []ent) []ent { e[8].uid = uid; return e }, "/usr/local/bin/port49-inventory: a binary"},
		{"a binary with a file capability", func(e []ent) []ent {
			e[5].pax = map[string]string{capXattr: "x"}
			return e
		}, "/usr/local/bin/port49d: a binary carries a file capability"},
		{"a missing binary", func(e []ent) []ent { return append(e[:8], e[9:]...) }, "/usr/local/bin/port49-inventory: missing"},
		{"a group-writable file", func(e []ent) []ent { e[9].mode = 0o664; return e }, "/etc/ssl/certs/ca.pem: a file writable"},
		{"a world-writable file", func(e []ent) []ent { e[9].mode = 0o666; return e }, "/etc/ssl/certs/ca.pem: a file writable"},
		{"a setuid file", func(e []ent) []ent { e[9].mode = 0o4755; return e }, "/etc/ssl/certs/ca.pem: a setuid or setgid file"},
		{"a setgid file", func(e []ent) []ent { e[9].mode = 0o2755; return e }, "/etc/ssl/certs/ca.pem: a setuid or setgid file"},
	} {
		t.Run(c.name, func(t *testing.T) {
			p, err := layoutProblems(export(t, c.edit(good())))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(strings.Join(p, "\n"), c.want) {
				t.Errorf("want a problem containing %q, got %v", c.want, p)
			}
		})
	}
}

// The build context never carries a file that looks like a secret: the repository's own
// .dockerignore is applied to a throwaway context holding one of each, and the files a
// `COPY . .` would take are listed from the build's own output.
func TestTheBuildContextLeavesSecretLookingFilesOut(t *testing.T) {
	ignore, err := os.ReadFile("../../.dockerignore")
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.TempDir()
	if err := os.WriteFile(filepath.Join(ctx, ".dockerignore"), ignore, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ctx, "Dockerfile"), []byte("FROM scratch\nCOPY . /ctx/\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Each file holds the word "fake" and nothing else.
	planted := []string{"local.env", "deploy/compose/local/port49d.env", "etcd/root-key.pem", "broker.key", "a/b/server.key",
		"svc-port49.keytab", "deploy/secrets/encryption.key", "x/secrets.json", "tests/lab/oidc/keycloak/realm.json",
		"tests/lab/logs/windows/anything.txt"}
	kept := []string{"main.go", "deploy/compose/setup.sh", "internal/secretref/ref.go", "tests/lab/oidc/compose.yaml"}
	for _, f := range append(append([]string{}, planted...), kept...) {
		p := filepath.Join(ctx, f)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("fake\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	out := t.TempDir()
	if o, err := exec.Command("docker", "build", "--output", "type=local,dest="+out, ctx).CombinedOutput(); err != nil {
		t.Fatalf("docker build of the throwaway context: %v\n%s", err, o)
	}
	for _, f := range planted {
		if _, err := os.Stat(filepath.Join(out, "ctx", f)); err == nil {
			t.Errorf("%s is in the build context: .dockerignore does not exclude it", f)
		}
	}
	for _, f := range kept {
		if _, err := os.Stat(filepath.Join(out, "ctx", f)); err != nil {
			t.Errorf("%s is missing from the build context: .dockerignore excludes too much", f)
		}
	}
}
