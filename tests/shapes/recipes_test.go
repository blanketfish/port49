package shapes

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/blanketfish/port49/internal/secretref"
)

// The key files are made by `port49d key sealing` and `port49d key device`, whose guarantees are
// tested in internal/port49d (keycmd_test.go). What stays here is what the shapes' docs and units
// still carry: the export unit's shell line, and that no README writes a secret under /tmp.

// No README or example writes a secret under /tmp or a fixed name another user could plant.
func TestNoRecipeWritesASecretToTmp(t *testing.T) {
	_ = filepath.WalkDir(filepath.Join("..", "..", "deploy"), func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".md") {
			return nil
		}
		b, _ := os.ReadFile(p)
		for i, ln := range strings.Split(string(b), "\n") {
			if strings.Contains(ln, "/tmp/") && regexp.MustCompile(`(key|secret|pass)`).MatchString(strings.ToLower(ln)) {
				t.Errorf("%s:%d writes near a secret under /tmp: %s", p, i+1, strings.TrimSpace(ln))
			}
		}
		return nil
	})
}

// What the old recipes' output was: 32 raw bytes whose last is a newline read back as 31.
func TestARawKeyEndingInANewlineIsShort(t *testing.T) {
	tr := newTree(t)
	tr.write("/etc/port49/keys/raw", strings.Repeat("k", 31)+"\n", 0o440)
	_, s, err := secretref.New().ResolveText("key", "file:"+filepath.Join(tr.dir, "/etc/port49/keys/raw"))
	if err != nil || len(s.Bytes()) != 31 {
		t.Errorf("a 32-byte file ending in a newline reads as %d bytes (err %v), want 31", len(s.Bytes()), err)
	}
}

// The export unit's shell line, run for real with its paths moved and port49-broker replaced
// by a script that prints $FAKE_EXPORT: a shorter export is exactly its own bytes, a failed one
// leaves yesterday's file and no temporary file, and the file is 0600.
func TestTheExportNeverLeavesStaleBytes(t *testing.T) {
	exec1 := readUnit(t, "deploy/systemd/examples/port49-enrollments-export.service")["Service"]["ExecStart"]
	if len(exec1) != 1 || !strings.HasPrefix(exec1[0], "/bin/sh -c '") || !strings.HasSuffix(exec1[0], "'") {
		t.Fatalf("the export unit's ExecStart is not a sh -c line: %q", exec1)
	}
	script := strings.TrimSuffix(strings.TrimPrefix(exec1[0], "/bin/sh -c '"), "'")
	script = strings.NewReplacer("$$", "$", "%%", "%").Replace(script)
	dir := t.TempDir()
	out := filepath.Join(dir, "out")
	if err := os.Mkdir(out, 0o700); err != nil {
		t.Fatal(err)
	}
	fake := filepath.Join(dir, "port49-broker")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\n# export-enrollments --out FILE: a new file (noclobber is O_EXCL), removed if the export fails\n"+
		"[ \"$1\" = export-enrollments ] && [ \"$2\" = --out ] || exit 2\nset -C; umask 077\n"+
		"cat \"$FAKE_EXPORT\" > \"$3\" || { rm -f \"$3\"; exit 1; }\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	script = strings.NewReplacer("/var/backups/port49-broker", out, "/usr/bin/port49-broker", fake).Replace(script)
	run := func(src string) error {
		cmd := exec.Command("sh", "-c", script)
		cmd.Env = append(os.Environ(), "FAKE_EXPORT="+src)
		return cmd.Run()
	}
	long, short := filepath.Join(dir, "long"), filepath.Join(dir, "short")
	if err := os.WriteFile(long, []byte(strings.Repeat("L", 4096)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(short, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	files := func() []string {
		m, _ := filepath.Glob(filepath.Join(out, "*"))
		return m
	}
	if err := run(long); err != nil {
		t.Fatal(err)
	}
	if err := run(short); err != nil {
		t.Fatal(err)
	}
	f := files()
	if len(f) != 1 || !strings.HasSuffix(f[0], ".json") {
		t.Fatalf("the export left %v, want one dated .json", f)
	}
	if b, _ := os.ReadFile(f[0]); string(b) != "short" {
		t.Errorf("a shorter export left %d bytes, want exactly its 5", len(b))
	}
	if fi, _ := os.Stat(f[0]); fi.Mode().Perm() != 0o600 {
		t.Errorf("the export is mode %v, want 0600", fi.Mode().Perm())
	}
	// A temporary file a killed run left must not block today's export: --out never replaces a file.
	day := strings.TrimSpace(func() string { b, _ := exec.Command("date", "+%F").Output(); return string(b) }())
	if err := os.WriteFile(filepath.Join(out, "enrollments-"+day+".json.tmp"), []byte("left by a killed run"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run(long); err != nil {
		t.Fatalf("a stale temporary file blocked the export: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(out, "enrollments-"+day+".json")); len(b) != 4096 {
		t.Errorf("the export after a stale temporary file left %d bytes, want 4096", len(b))
	}
	if err := run(short); err != nil {
		t.Fatal(err)
	}
	if err := run(filepath.Join(dir, "missing")); err == nil {
		t.Error("a failed export exits 0")
	}
	if f := files(); len(f) != 1 {
		t.Errorf("a failed export left %v: no temporary file may stay", f)
	} else if b, _ := os.ReadFile(f[0]); string(b) != "short" {
		t.Error("a failed export changed the last good file")
	}
}
