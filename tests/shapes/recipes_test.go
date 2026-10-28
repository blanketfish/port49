package shapes

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/rhwendt/port49/internal/secretref"
)

// The key recipes in README.md are run as they are written. A key file loses one trailing
// newline when it is read (decision 53 ruling 1), so a recipe whose output can end in one
// makes a 31-byte key one time in 256, and a raw device key cannot be typed into a device.
const (
	sealRecipe   = "openssl rand -base64 24 > /tmp/encryption.key"
	deviceRecipe = "openssl rand -hex 16 > /tmp/k"
)

// runRecipe runs cmd with /tmp moved under dir and returns the file it wrote.
func runRecipe(t *testing.T, cmd, dir, name string) []byte {
	t.Helper()
	cmd = strings.ReplaceAll(cmd, "/tmp/", dir+"/")
	if out, err := exec.Command("sh", "-c", cmd).CombinedOutput(); err != nil {
		t.Fatalf("%s: %v: %s", cmd, err, out)
	}
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestTheKeyRecipesNeverMakeAKeyThatFails(t *testing.T) {
	readme := read(t, "deploy/systemd/README.md")
	for _, r := range []string{sealRecipe, deviceRecipe} {
		if !strings.Contains(readme, r) {
			t.Errorf("README.md does not hold the recipe %q", r)
		}
	}
	if strings.Contains(readme, "/dev/urandom") {
		t.Error("README.md makes a key from raw bytes: one in 256 ends in a newline that file: drops")
	}
	for i := 0; i < 40; i++ {
		dir := t.TempDir()
		tr := newTree(t)
		seal := runRecipe(t, sealRecipe, dir, "encryption.key")
		tr.write("/etc/port49/secrets/encryption.key", string(seal), 0o400)
		d, _ := tr.load("deploy/systemd/config")
		if _, err := d.EncryptionKeys(); err != nil {
			t.Fatalf("a sealing key from the recipe does not load: %v", err)
		}
		dev := runRecipe(t, deviceRecipe, dir, "k")
		tr.write("/etc/port49/keys/core-v2", string(dev), 0o440)
		_, s, err := secretref.New().ResolveText("key", "file:"+filepath.Join(tr.dir, "/etc/port49/keys/core-v2"))
		if err != nil {
			t.Fatalf("a device key from the recipe does not resolve: %v", err)
		}
		if got := s.Bytes(); len(got) != 32 || !regexp.MustCompile(`^[0-9a-f]{32}$`).Match(got) {
			t.Fatalf("a device key from the recipe is %d bytes and not 32 hex characters: it cannot be typed into a device", len(got))
		}
	}
}

// What the recipe replaced: 32 raw bytes whose last is a newline read back as 31, which the
// 32-byte check then refuses (the load error says so: see the shipped README).
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
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nexec cat \"$FAKE_EXPORT\"\n"), 0o755); err != nil {
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
	if err := run(filepath.Join(dir, "missing")); err == nil {
		t.Error("a failed export exits 0")
	}
	if f := files(); len(f) != 1 {
		t.Errorf("a failed export left %v: no temporary file may stay", f)
	} else if b, _ := os.ReadFile(f[0]); string(b) != "short" {
		t.Error("a failed export changed the last good file")
	}
}
