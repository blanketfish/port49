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
	sealRecipe   = `until head -c 32 /dev/urandom > /tmp/encryption.key; [ "$(tail -c1 /tmp/encryption.key | od -An -tx1 | tr -d ' ')" != 0a ]; do :; done`
	deviceRecipe = "openssl rand -hex 16 > /tmp/k"
)

// runRecipe runs cmd with /tmp moved under dir and returns the file it wrote.
func runRecipe(t *testing.T, cmd, dir, name string) []byte {
	t.Helper()
	cmd = strings.NewReplacer("/tmp/encryption.key", dir+"/encryption.key", "/tmp/k", dir+"/k").Replace(cmd)
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
	if strings.Contains(readme, "head -c 32 /dev/urandom > /tmp/k") {
		t.Error("README.md makes a device key from raw bytes: it cannot be typed into a device")
	}
	for i := 0; i < 40; i++ {
		dir := t.TempDir()
		tr := newTree(t)
		seal := runRecipe(t, sealRecipe, dir, "encryption.key")
		if len(seal) != 32 || seal[31] == '\n' {
			t.Fatalf("a sealing key from the recipe is %d bytes and ends in a newline: %v", len(seal), len(seal) == 32 && seal[31] == '\n')
		}
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

// The loop does regenerate: the generator is replaced by one that makes a key ending in a
// newline twice, then a good one, and the recipe's result is the good one.
func TestTheSealingRecipeRegeneratesAKeyEndingInANewline(t *testing.T) {
	dir := t.TempDir()
	gen := filepath.Join(dir, "gen")
	script := "#!/bin/sh\nn=$(cat " + dir + "/n 2>/dev/null || echo 0); echo $((n+1)) > " + dir + "/n\n" +
		"if [ \"$n\" -lt 2 ]; then printf 'kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk\\n'; else printf 'gggggggggggggggggggggggggggggggg'; fi\n"
	if err := os.WriteFile(gen, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	r := strings.Replace(sealRecipe, "head -c 32 /dev/urandom", gen, 1)
	if got := string(runRecipe(t, r, dir, "encryption.key")); got != strings.Repeat("g", 32) {
		t.Errorf("the recipe kept a key of %d bytes, want the third try's 32", len(got))
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
