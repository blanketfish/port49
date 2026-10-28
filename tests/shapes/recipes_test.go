package shapes

import (
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/secretref"
)

// The key recipes in README.md are run as they are written, with only the destination
// directory moved under a scratch tree, and chown (which needs root) replaced by a stub that
// records its arguments. A key file loses one trailing newline when it is read (decision 53
// ruling 1), so a raw key ending in one loads a byte short; a recipe that takes its status from
// a test alone, or writes a name in /tmp, can install or leak a key another user chose.

// readmeBlock is the README's fenced sh block that holds marker.
func readmeBlock(t *testing.T, marker string) string {
	t.Helper()
	parts := strings.Split(read(t, "deploy/systemd/README.md"), "```sh\n")
	for _, p := range parts[1:] {
		if body, _, ok := strings.Cut(p, "```"); ok && strings.Contains(body, marker) {
			return body
		}
	}
	t.Fatalf("README.md has no sh block holding %q", marker)
	return ""
}

// recipeEnv is a scratch root with the two key directories, a PATH of stubs, and what the
// stubs did. head draws from $HEAD: unset it is the real head, "newline2" ends the first two
// draws in a newline, "newline" every draw, "short" draws 31 bytes, "fail" fails.
type recipeEnv struct {
	t           *testing.T
	root, stubs string
}

func newRecipeEnv(t *testing.T) *recipeEnv {
	t.Helper()
	e := &recipeEnv{t: t, root: t.TempDir(), stubs: t.TempDir()}
	for _, d := range []string{"secrets", "keys"} {
		if err := os.Mkdir(filepath.Join(e.root, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	e.stub("chown", "echo \"chown $*\" >> "+e.log()+"\n")
	e.stub("mktemp", "echo \"mktemp $*\" >> "+e.log()+"\nexec /usr/bin/mktemp \"$@\"\n")
	e.stub("head", `n=$(cat '`+e.stubs+`/n' 2>/dev/null || echo 0); echo $((n+1)) > '`+e.stubs+`/n'
case "$HEAD" in
newline2) if [ "$n" -lt 2 ]; then printf 'kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk\n'; else exec /usr/bin/head "$@"; fi ;;
newline) printf 'kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk\n' ;;
short) printf 'kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk' ;;
fail) exit 1 ;;
*) exec /usr/bin/head "$@" ;;
esac
`)
	return e
}

func (e *recipeEnv) log() string { return filepath.Join(e.stubs, "calls") }

func (e *recipeEnv) stub(name, body string) {
	if err := os.WriteFile(filepath.Join(e.stubs, name), []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		e.t.Fatal(err)
	}
}

// run runs the README block in a fresh subshell and says what it exited and printed.
func (e *recipeEnv) run(block string, env ...string) (string, error) {
	block = strings.NewReplacer("/etc/port49/secrets", filepath.Join(e.root, "secrets"),
		"/etc/port49/keys", filepath.Join(e.root, "keys")).Replace(block)
	cmd := exec.Command("sh", "-c", block)
	// TMPDIR points at an empty scratch directory: a recipe that made its file there would
	// leave it behind, and the test says so.
	cmd.Env = append([]string{"PATH=" + e.stubs + ":/usr/bin:/bin", "TMPDIR=" + e.stubs + "/tmp"}, env...)
	_ = os.Mkdir(e.stubs+"/tmp", 0o700)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// leftovers is every file in dir but the named ones.
func leftovers(t *testing.T, dir string, keep ...string) []string {
	t.Helper()
	ents, _ := os.ReadDir(dir)
	var out []string
next:
	for _, e := range ents {
		for _, k := range keep {
			if e.Name() == k {
				continue next
			}
		}
		out = append(out, e.Name())
	}
	return out
}

const sealMarker, deviceMarker = `ln "$u" "$b"`, "openssl rand -hex 16"

// withID sets the recipe's KEY_ID line, and withDevice its DEVICE_KEY line.
func withID(block, id string) string {
	return strings.Replace(block, "KEY_ID=   #", "KEY_ID="+id+"   #", 1)
}

func withDevice(block, name string) string {
	return strings.Replace(block, "DEVICE_KEY=core-v2 ", "DEVICE_KEY="+name+" ", 1)
}

func TestTheKeyRecipesNeverMakeAKeyThatFails(t *testing.T) {
	seal, dev := readmeBlock(t, sealMarker), readmeBlock(t, deviceMarker)
	for i := 0; i < 40; i++ {
		e := newRecipeEnv(t)
		if out, err := e.run(seal); err != nil {
			t.Fatalf("the sealing recipe failed: %v: %s", err, out)
		}
		tr := newTree(t)
		for _, n := range []string{"encryption.key", "broker-encryption.key"} {
			b, err := os.ReadFile(filepath.Join(e.root, "secrets", n))
			if err != nil || len(b) != 32 || b[31] == '\n' {
				t.Fatalf("%s: %d bytes (%v), want 32 that do not end in a newline", n, len(b), err)
			}
			if fi, _ := os.Stat(filepath.Join(e.root, "secrets", n)); fi.Mode().Perm() != 0o400 {
				t.Fatalf("%s is mode %v, want 0400", n, fi.Mode().Perm())
			}
		}
		b, _ := os.ReadFile(filepath.Join(e.root, "secrets", "encryption.key"))
		tr.write("/etc/port49/secrets/encryption.key", string(b), 0o400)
		d, _ := tr.load("deploy/systemd/config")
		if _, err := d.EncryptionKeys(); err != nil {
			t.Fatalf("a sealing key from the recipe does not load: %v", err)
		}
		calls, _ := os.ReadFile(e.log())
		// each temporary file is made new, by mktemp, in the destination directory (a relative
		// template, after the cd), never under a name chosen in advance
		if got := strings.Count(string(calls), "mktemp ./.key.XXXXXX"); got != 2 {
			t.Fatalf("the sealing recipe ran mktemp ./.key.XXXXXX %d times, want 2: %s", got, calls)
		}
		for _, want := range []string{"chown port49d:port49d", "chown port49-broker:port49-broker"} {
			if !strings.Contains(string(calls), want) {
				t.Fatalf("the recipe did not run %q: %s", want, calls)
			}
		}
		if l := leftovers(t, filepath.Join(e.root, "secrets"), "encryption.key", "broker-encryption.key"); len(l) != 0 {
			t.Fatalf("the recipe left %v", l)
		}
		if l := leftovers(t, e.stubs+"/tmp"); len(l) != 0 {
			t.Fatalf("the recipe wrote under TMPDIR: %v", l)
		}
		if out, err := e.run(dev); err != nil {
			t.Fatalf("the device recipe failed: %v: %s", err, out)
		}
		tr.write("/etc/port49/keys/core-v2", mustRead(t, filepath.Join(e.root, "keys", "core-v2")), 0o440)
		_, s, err := secretref.New().ResolveText("key", "file:"+filepath.Join(tr.dir, "/etc/port49/keys/core-v2"))
		if err != nil {
			t.Fatalf("a device key from the recipe does not resolve: %v", err)
		}
		if got := s.Bytes(); len(got) != 32 || !regexp.MustCompile(`^[0-9a-f]{32}$`).Match(got) {
			t.Fatalf("a device key from the recipe is %d bytes and not 32 hex characters: it cannot be typed into a device", len(got))
		}
		if l := leftovers(t, filepath.Join(e.root, "keys"), "core-v2"); len(l) != 0 {
			t.Fatalf("the device recipe left %v", l)
		}
		if calls, _ := os.ReadFile(e.log()); strings.Count(string(calls), "mktemp ./.key.XXXXXX") != 3 {
			t.Fatalf("the device recipe did not make its temporary file with mktemp ./.key.XXXXXX: %s", calls)
		}
	}
}

func mustRead(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// A draw that ends in a newline is drawn again; a short one, a failed one, and ten bad ones in a row fail the
// recipe with a line, install nothing and leave no temporary file.
func TestTheSealingRecipeRefusesWhatItCannotMakeWell(t *testing.T) {
	seal := readmeBlock(t, sealMarker)
	e := newRecipeEnv(t)
	if out, err := e.run(seal, "HEAD=newline2"); err != nil {
		t.Fatalf("a key whose first two draws end in a newline: %v: %s", err, out)
	}
	if b := mustRead(t, filepath.Join(e.root, "secrets", "encryption.key")); len(b) != 32 || b[31] == '\n' {
		t.Errorf("the recipe kept a draw of %d bytes ending %q", len(b), b[len(b)-1:])
	}
	for mode, says := range map[string]string{"newline": "no usable 32-byte key in 10 draws", "short": "no usable 32-byte key in 10 draws", "fail": "no usable 32-byte key in 10 draws"} {
		e := newRecipeEnv(t)
		out, err := e.run(seal, "HEAD="+mode)
		if err == nil || !strings.Contains(out, says) {
			t.Errorf("HEAD=%s: exit %v, output %q, want a failure saying %q", mode, err, out, says)
		}
		if l := leftovers(t, filepath.Join(e.root, "secrets")); len(l) != 0 {
			t.Errorf("HEAD=%s: left %v", mode, l)
		}
	}
	// a step after the draw that fails stops the install
	e = newRecipeEnv(t)
	e.stub("chown", "exit 1\n")
	if out, err := e.run(seal); err == nil || !strings.Contains(out, "the sealing key was not made") {
		t.Errorf("a failed chown: exit %v, output %q", err, out)
	}
	if l := leftovers(t, filepath.Join(e.root, "secrets")); len(l) != 0 {
		t.Errorf("a failed chown left %v", l)
	}
}

// A key that is already there is never replaced: a file or a link at either final name is
// refused with the line, its bytes (or its link's target) are unchanged, nothing else is made and
// no temporary file stays. The rotation recipe, pasted with the old id, would otherwise destroy
// the current key and everything it sealed.
func TestTheKeyRecipesNeverOverwrite(t *testing.T) {
	seal, dev := readmeBlock(t, sealMarker), readmeBlock(t, deviceMarker)
	for _, c := range []struct{ block, dir, planted string }{
		{seal, "secrets", "encryption.key"},
		{seal, "secrets", "broker-encryption.key"},
		{dev, "keys", "core-v2"},
	} {
		for _, how := range []string{"file", "link", "dangling"} {
			link := how != "file"
			e := newRecipeEnv(t)
			victim := filepath.Join(e.stubs, "victim")
			if err := os.WriteFile(victim, []byte("EXISTING-NOT-A-REAL-KEY"), 0o400); err != nil {
				t.Fatal(err)
			}
			at := filepath.Join(e.root, c.dir, c.planted)
			if how == "dangling" {
				if err := os.Symlink(filepath.Join(e.stubs, "nowhere"), at); err != nil {
					t.Fatal(err)
				}
			} else if link {
				if err := os.Symlink(victim, at); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(at, []byte("EXISTING-NOT-A-REAL-KEY"), 0o400); err != nil {
				t.Fatal(err)
			}
			out, err := e.run(c.block)
			if err == nil || !strings.Contains(out, c.planted+" exists; pick a new key id") {
				t.Errorf("%s (%s): exit %v, output %q, want a refusal naming it", c.planted, how, err, out)
			}
			if how != "dangling" {
				if got := mustRead(t, at); got != "EXISTING-NOT-A-REAL-KEY" {
					t.Errorf("%s (%s): its bytes changed to %d bytes", c.planted, how, len(got))
				}
			} else if _, err := os.Lstat(filepath.Join(e.stubs, "nowhere")); err == nil {
				t.Errorf("%s (dangling): the recipe wrote through the link", c.planted)
			}
			// the check comes first: no temporary file is made, no key drawn, for a name taken
			if calls, _ := os.ReadFile(e.log()); strings.Contains(string(calls), "mktemp") {
				t.Errorf("%s (%s): the recipe made temporary files for a name already taken", c.planted, how)
			}
			if l := leftovers(t, filepath.Join(e.root, c.dir), c.planted); len(l) != 0 {
				t.Errorf("%s (%s): left %v", c.planted, how, l)
			}
		}
	}
}

// A final name that appears after the first check (another run, a planted file) is still not
// replaced: the link fails, and when the second of the two fails the first is taken back, so a
// failure never leaves half a key in place.
func TestTheSealingRecipeLeavesNoHalfAKey(t *testing.T) {
	seal := readmeBlock(t, sealMarker)
	for _, planted := range []string{"encryption.key", "broker-encryption.key"} {
		e := newRecipeEnv(t)
		// chown runs in the destination directory, after the checks and before the links
		e.stub("chown", "[ -e "+planted+" ] || echo EXISTING-NOT-A-REAL-KEY > "+planted+"\n")
		out, err := e.run(seal)
		if err == nil || !strings.Contains(out, planted+" exists; pick a new key id") {
			t.Errorf("%s appearing late: exit %v, output %q", planted, err, out)
		}
		if got := mustRead(t, filepath.Join(e.root, "secrets", planted)); got != "EXISTING-NOT-A-REAL-KEY\n" {
			t.Errorf("%s was replaced: %d bytes", planted, len(got))
		}
		if l := leftovers(t, filepath.Join(e.root, "secrets"), planted); len(l) != 0 {
			t.Errorf("%s appearing late: left %v", planted, l)
		}
	}
}

// The device recipe's name appearing after the check is not replaced either.
func TestTheDeviceRecipeLeavesALateKeyAlone(t *testing.T) {
	e := newRecipeEnv(t)
	e.stub("chown", "[ -e core-v2 ] || echo EXISTING-NOT-A-REAL-KEY > core-v2\n")
	out, err := e.run(readmeBlock(t, deviceMarker))
	if err == nil || !strings.Contains(out, "core-v2 exists; pick a new key id") {
		t.Errorf("core-v2 appearing late: exit %v, output %q", err, out)
	}
	if got := mustRead(t, filepath.Join(e.root, "keys", "core-v2")); got != "EXISTING-NOT-A-REAL-KEY\n" {
		t.Errorf("core-v2 was replaced: %d bytes", len(got))
	}
	if l := leftovers(t, filepath.Join(e.root, "keys"), "core-v2"); len(l) != 0 {
		t.Errorf("left %v", l)
	}
}

// A rotation makes the e2 pair beside an e1 pair it leaves untouched; a pasted rerun with the
// old id is refused.
func TestARotationLeavesTheOldKeyAlone(t *testing.T) {
	const e2 = "-e2"
	seal := readmeBlock(t, sealMarker)
	e := newRecipeEnv(t)
	if out, err := e.run(seal); err != nil {
		t.Fatalf("the first key: %v: %s", err, out)
	}
	old := mustRead(t, filepath.Join(e.root, "secrets", "encryption.key"))
	oldB := mustRead(t, filepath.Join(e.root, "secrets", "broker-encryption.key"))
	if out, err := e.run(withID(seal, "e2")); err != nil {
		t.Fatalf("the rotation: %v: %s", err, out)
	}
	for n, was := range map[string]string{"encryption.key": old, "broker-encryption.key": oldB} {
		if got := mustRead(t, filepath.Join(e.root, "secrets", n)); got != was {
			t.Errorf("the rotation changed %s", n)
		}
	}
	rotated := []string{"encryption" + e2 + ".key", "broker-encryption" + e2 + ".key"}
	for _, n := range rotated {
		if b := mustRead(t, filepath.Join(e.root, "secrets", n)); len(b) != 32 || b[31] == '\n' {
			t.Errorf("%s is %d bytes", n, len(b))
		}
	}
	if mustRead(t, filepath.Join(e.root, "secrets", rotated[0])) == old {
		t.Error("the e2 key is the e1 key")
	}
	if out, err := e.run(seal); err == nil || !strings.Contains(out, "exists; pick a new key id") {
		t.Errorf("a rerun with the old id: exit %v, output %q", err, out)
	}
	if l := leftovers(t, filepath.Join(e.root, "secrets"), "encryption.key", "broker-encryption.key",
		rotated[0], rotated[1]); len(l) != 0 {
		t.Errorf("left %v", l)
	}
	// the device recipe's other name sits beside the first
	d := newRecipeEnv(t)
	dev := readmeBlock(t, deviceMarker)
	for _, n := range []string{"core-v2", "core-v3"} {
		if out, err := d.run(withDevice(dev, n)); err != nil {
			t.Fatalf("%s: %v: %s", n, err, out)
		}
	}
}

// An interrupted run leaves no temporary file, including one whose second mktemp failed.
func TestTheRecipesCleanUpWhenInterrupted(t *testing.T) {
	e := newRecipeEnv(t)
	e.stub("mktemp", "n=$(cat '"+e.stubs+"/m' 2>/dev/null || echo 0); echo $((n+1)) > '"+e.stubs+"/m'\n"+
		"[ \"$n\" -ge 1 ] && exit 1\nexec /usr/bin/mktemp \"$@\"\n")
	if _, err := e.run(readmeBlock(t, sealMarker)); err == nil {
		t.Error("a failed second mktemp does not fail the recipe")
	}
	if l := leftovers(t, filepath.Join(e.root, "secrets")); len(l) != 0 {
		t.Errorf("a failed second mktemp left %v", l)
	}
}

func TestTheDeviceRecipeFailsWithoutInstalling(t *testing.T) {
	dev := readmeBlock(t, deviceMarker)
	e := newRecipeEnv(t)
	e.stub("openssl", "exit 1\n")
	out, err := e.run(dev)
	if err == nil || !strings.Contains(out, "the device key was not made") {
		t.Errorf("a failed openssl: exit %v, output %q", err, out)
	}
	if l := leftovers(t, filepath.Join(e.root, "keys")); len(l) != 0 {
		t.Errorf("a failed openssl left %v", l)
	}
	e = newRecipeEnv(t)
	e.stub("chown", "exit 1\n")
	if _, err := e.run(dev); err == nil {
		t.Error("a failed chown does not fail the device recipe")
	}
	if l := leftovers(t, filepath.Join(e.root, "keys")); len(l) != 0 {
		t.Errorf("a failed chown left %v", l)
	}
}

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

const copyMarker = "for pair in"

// copyEnv has the two files in a scratch $HOME and an install stub that records its calls and
// copies without the owner (which needs root); INSTALL=fail makes it fail.
func copyEnv(t *testing.T) *recipeEnv {
	t.Helper()
	e := newRecipeEnv(t)
	home := filepath.Join(e.stubs, "home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"encryption.key", "broker-encryption.key"} {
		if err := os.WriteFile(filepath.Join(home, f), []byte("FAKE-KEY-FOR-TEST-ONLY"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	e.stub("install", "echo \"install $*\" >> "+e.log()+"\n"+
		`[ "$INSTALL" = fail ] && exit 1`+"\n"+`for a; do last2=$last; last=$a; done; exec /usr/bin/cp "$last2" "$last"`+"\n")
	return e
}

// The copy-to-other-hosts snippet refuses an existing name, says which failure it is, and
// exits non-zero on any of them.
func TestTheCopySnippetRefusesAndSaysWhy(t *testing.T) {
	block := readmeBlock(t, copyMarker)
	e := copyEnv(t)
	out, err := e.run(block, "HOME="+filepath.Join(e.stubs, "home"))
	if err != nil {
		t.Fatalf("the plain copy failed: %v\n%s", err, out)
	}
	for _, f := range []string{"encryption.key", "broker-encryption.key"} {
		if _, err := os.Stat(filepath.Join(e.root, "secrets", f)); err != nil {
			t.Errorf("%s was not installed", f)
		}
	}
	for _, how := range []string{"file", "link", "dangling"} {
		e := copyEnv(t)
		at := filepath.Join(e.root, "secrets", "broker-encryption.key")
		var err error
		switch how {
		case "file":
			err = os.WriteFile(at, []byte("EXISTING-NOT-A-REAL-KEY"), 0o400)
		case "link":
			err = os.Symlink(filepath.Join(e.stubs, "home", "encryption.key"), at)
		default:
			err = os.Symlink(filepath.Join(e.stubs, "nowhere"), at)
		}
		if err != nil {
			t.Fatal(err)
		}
		out, err := e.run(block, "HOME="+filepath.Join(e.stubs, "home"))
		if err == nil || !strings.Contains(out, "broker-encryption.key exists") {
			t.Errorf("%s planted: err %v, output %q, want a refusal saying exists", how, err, out)
		}
		if strings.Contains(out, "install of") {
			t.Errorf("%s planted: said install failed for an existing name: %q", how, out)
		}
		if b, _ := os.ReadFile(at); how == "file" && string(b) != "EXISTING-NOT-A-REAL-KEY" {
			t.Errorf("an existing key was replaced")
		}
	}
	e = copyEnv(t)
	out, err = e.run(block, "HOME="+filepath.Join(e.stubs, "home"), "INSTALL=fail")
	if err == nil || !strings.Contains(out, "install of encryption.key failed") || strings.Contains(out, "exists") {
		t.Errorf("a failing install: err %v, output %q, want install failed and never exists", err, out)
	}
}

// An interrupt, a terminate or a hangup leaves no temporary file and fails the recipe, under
// dash as well as on a normal exit.
func TestTheRecipesCleanUpOnASignal(t *testing.T) {
	// Under nohup the test process ignores SIGHUP and every child would inherit that, and a shell
	// cannot trap a signal that was ignored on entry. Catching it here gives the children the
	// default again.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	for _, c := range []struct{ marker, dir, stub string }{
		{sealMarker, "secrets", "head"},
		{deviceMarker, "keys", "openssl"},
	} {
		for _, sig := range []syscall.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP} {
			e := newRecipeEnv(t)
			ready := filepath.Join(e.stubs, "ready")
			e.stub(c.stub, ": > '"+ready+"'\nexec sleep 30\n")
			block := strings.NewReplacer("/etc/port49/secrets", filepath.Join(e.root, "secrets"),
				"/etc/port49/keys", filepath.Join(e.root, "keys")).Replace(readmeBlock(t, c.marker))
			cmd := exec.Command("sh", "-c", block)
			cmd.Env = []string{"PATH=" + e.stubs + ":/usr/bin:/bin", "TMPDIR=" + e.stubs + "/tmp"}
			cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 200; i++ {
				if _, err := os.Stat(ready); err == nil {
					break
				}
				time.Sleep(25 * time.Millisecond)
			}
			if _, err := os.Stat(ready); err != nil {
				_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
				t.Fatalf("%s %v: the recipe never reached %s", c.marker, sig, c.stub)
			}
			_ = syscall.Kill(-cmd.Process.Pid, sig)
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			select {
			case err := <-done:
				if err == nil {
					t.Errorf("%s %v: the recipe exited 0 after the signal", c.marker, sig)
				}
			case <-time.After(10 * time.Second):
				_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
				t.Fatalf("%s %v: the recipe did not stop", c.marker, sig)
			}
			// the outer shell dies at once; the recipe's own subshell cleans up a moment later
			var l []string
			for i := 0; i < 80; i++ {
				if l = leftovers(t, filepath.Join(e.root, c.dir)); len(l) == 0 {
					break
				}
				time.Sleep(25 * time.Millisecond)
			}
			if len(l) != 0 {
				t.Errorf("%s %v left %v", c.marker, sig, l)
			}
		}
	}
}
