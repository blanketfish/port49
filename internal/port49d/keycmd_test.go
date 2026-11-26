package port49d

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/blanketfish/port49/internal/secretref"
)

// None of these tests prints a key: every check on key bytes is a boolean, and every fake key is
// drawn at run time.

// countRand serves chunks as one byte stream and counts what was read, so a test can say a
// refused command drew nothing.
type countRand struct {
	r io.Reader
	n int
}

func (c *countRand) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

func randKey(t *testing.T, last byte, endsInLast bool) []byte {
	t.Helper()
	for {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			t.Fatal(err)
		}
		if endsInLast {
			b[31] = last
			return b
		}
		if b[31] != last {
			return b
		}
	}
}

func goodKey(t *testing.T) []byte { return randKey(t, 0x0a, false) }
func badKey(t *testing.T) []byte  { return randKey(t, 0x0a, true) }

type kt struct {
	t           *testing.T
	dir         string
	rnd         *countRand
	env         keyEnv
	user, group string
	uid         int
}

// newKT is a destination directory under the test's own tree, owners that are the current user
// (so no chown to another user is needed) and a random source that serves chunks, then ends.
func newKT(t *testing.T, chunks ...[]byte) *kt {
	t.Helper()
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	g, err := user.LookupGroupId(u.Gid)
	if err != nil {
		t.Fatal(err)
	}
	readers := make([]io.Reader, len(chunks))
	for i, c := range chunks {
		readers[i] = bytes.NewReader(c)
	}
	rnd := &countRand{r: io.MultiReader(readers...)}
	gids, _ := os.Getgroups()
	k := &kt{t: t, rnd: rnd, user: u.Username, group: g.Name, uid: os.Geteuid(),
		env: keyEnv{rand: rnd, euid: os.Geteuid(), groups: append([]int{os.Getegid()}, gids...),
			link: os.Link, chown: func(f *os.File, uid, gid int) error { return f.Chown(uid, gid) },
			stop: func() bool { return false }}}
	k.dir = filepath.Join(t.TempDir(), "d")
	if err := os.Mkdir(k.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return k
}

// run is the command with the current user as every owner, and what it printed.
func (k *kt) run(args ...string) (stdout, stderr string, code int) {
	k.t.Helper()
	var out, errb bytes.Buffer
	code = keyCmdWith(args, &out, &errb, k.env)
	return out.String(), errb.String(), code
}

func (k *kt) seal(extra ...string) (string, string, int) {
	k.t.Helper()
	return k.run(append([]string{"sealing", "--dir", k.dir, "--daemon-user", k.user, "--broker-user", k.user}, extra...)...)
}

func (k *kt) device(name string, extra ...string) (string, string, int) {
	k.t.Helper()
	return k.run(append([]string{"device", name, "--dir", k.dir, "--device-owner", k.user, "--device-group", k.group}, extra...)...)
}

func (k *kt) path(n string) string { return filepath.Join(k.dir, n) }

func (k *kt) read(n string) []byte {
	k.t.Helper()
	b, err := os.ReadFile(k.path(n))
	if err != nil {
		k.t.Fatalf("%s: %v", n, err)
	}
	return b
}

func (k *kt) names() []string {
	k.t.Helper()
	ents, err := os.ReadDir(k.dir)
	if err != nil {
		k.t.Fatal(err)
	}
	var out []string
	for _, e := range ents {
		out = append(out, e.Name())
	}
	sort.Strings(out)
	return out
}

func (k *kt) wantNames(why string, want ...string) {
	k.t.Helper()
	sort.Strings(want)
	if got := k.names(); strings.Join(got, ",") != strings.Join(want, ",") {
		k.t.Errorf("%s: the directory holds %v, want %v", why, got, want)
	}
}

func (k *kt) wantMode(n string, mode os.FileMode) {
	k.t.Helper()
	fi, err := os.Lstat(k.path(n))
	if err != nil {
		k.t.Fatal(err)
	}
	if fi.Mode() != mode {
		k.t.Errorf("%s is mode %v, want %v", n, fi.Mode(), mode)
	}
	if uid, _, ok := ownerOf(fi); ok && uid != k.uid {
		k.t.Errorf("%s is not owned by the owner asked for", n)
	}
}

// pairNames is the two file names of the sealing pair made with --id id.
func pairNames(id string) []string {
	return []string{"encryption-" + id + ".key", "broker-encryption-" + id + ".key"}
}

// leaks reports whether out holds the key, raw, in hex or in base64.
func leaks(out string, key []byte) bool {
	return strings.Contains(out, string(key)) || strings.Contains(out, hex.EncodeToString(key)) ||
		strings.Contains(out, base64.StdEncoding.EncodeToString(key)) ||
		strings.Contains(out, base64.RawStdEncoding.EncodeToString(key))
}

func TestKeySealingWritesAnEqualPrivatePair(t *testing.T) {
	key := goodKey(t)
	k := newKT(t, key)
	out, errs, code := k.seal()
	if code != 0 || errs != "" {
		t.Fatalf("exit %d, stderr %q", code, errs)
	}
	k.wantNames("a pair and nothing else", "encryption.key", "broker-encryption.key")
	for _, n := range []string{"encryption.key", "broker-encryption.key"} {
		if !bytes.Equal(k.read(n), key) {
			t.Errorf("%s is not the drawn key", n)
		}
		k.wantMode(n, 0o400)
	}
	if leaks(out+errs, key) {
		t.Error("the key is in the output")
	}
	for _, want := range []string{k.path("encryption.key"), k.path("broker-encryption.key"), "0400", k.user,
		"port49d key sealing --import"} {
		if !strings.Contains(out, want) {
			t.Errorf("the output does not say %q: %s", want, out)
		}
	}
	// the key loads: a key file loses one trailing newline when read, and this one ends in none
	_, s, err := secretref.New().ResolveText("key", "file:"+k.path("encryption.key"))
	if err != nil || len(s.Bytes()) != 32 {
		t.Errorf("the key reads back as %d bytes (err %v), want 32", len(s.Bytes()), err)
	}
}

func TestKeySealingDrawsFromCryptoRandByDefault(t *testing.T) {
	k := newKT(t)
	k.env = keyEnv{} // every field from the host
	seen := map[string]bool{}
	for i := 0; i < 3; i++ {
		d := filepath.Join(t.TempDir(), "d")
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
		if _, errs, code := k.run("sealing", "--dir", d, "--daemon-user", k.user, "--broker-user", k.user); code != 0 {
			t.Fatalf("exit %d: %s", code, errs)
		}
		b, _ := os.ReadFile(filepath.Join(d, "encryption.key"))
		c, _ := os.ReadFile(filepath.Join(d, "broker-encryption.key"))
		if len(b) != 32 || b[31] == '\n' || !bytes.Equal(b, c) {
			t.Fatalf("a default draw is %d bytes (last byte a newline: %v, pair equal: %v)", len(b), len(b) == 32 && b[31] == '\n', bytes.Equal(b, c))
		}
		seen[string(b)] = true
	}
	if len(seen) != 3 {
		t.Error("three draws made fewer than three different keys")
	}
}

func TestKeySealingNamesTheKeyByID(t *testing.T) {
	k := newKT(t, goodKey(t))
	if _, errs, code := k.seal("--id", "e2"); code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	k.wantNames("the e2 pair", pairNames("e2")...)
}

func TestKeySealingBrokerDirHoldsTheBrokersFile(t *testing.T) {
	key := goodKey(t)
	k := newKT(t, key)
	other := filepath.Join(t.TempDir(), "b")
	if err := os.Mkdir(other, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, errs, code := k.seal("--broker-dir", other); code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	k.wantNames("the daemon's file", "encryption.key")
	b, err := os.ReadFile(filepath.Join(other, "broker-encryption.key"))
	if err != nil || !bytes.Equal(b, key) {
		t.Errorf("the broker's file in --broker-dir: err %v, equal %v", err, bytes.Equal(b, key))
	}
}

func TestKeySealingDrawsAgainWhenTheLastByteIsANewline(t *testing.T) {
	good := goodKey(t)
	k := newKT(t, badKey(t), badKey(t), good)
	if _, errs, code := k.seal(); code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if !bytes.Equal(k.read("encryption.key"), good) {
		t.Error("the file does not hold the first draw that was usable")
	}
}

func TestKeySealingGivesUpAfterTenBadDrawsAndLeavesNothing(t *testing.T) {
	var chunks [][]byte
	for i := 0; i < 11; i++ { // an eleventh is there and must stay unread
		chunks = append(chunks, badKey(t))
	}
	k := newKT(t, chunks...)
	_, errs, code := k.seal()
	if code != 1 || !strings.Contains(errs, "no usable 32-byte key in 10 draws") || strings.Count(errs, "\n") != 1 {
		t.Errorf("exit %d, stderr %q, want 1 and one line saying no usable key in 10 draws", code, errs)
	}
	if k.rnd.n != 320 {
		t.Errorf("%d bytes drawn, want ten draws of 32", k.rnd.n)
	}
	k.wantNames("a failed draw")
}

func TestKeySealingRefusesAnExistingNameAndChangesNothing(t *testing.T) {
	for _, planted := range []string{"encryption.key", "broker-encryption.key"} {
		for _, how := range []string{"file", "symlink", "dangling"} {
			k := newKT(t, goodKey(t))
			victim := filepath.Join(t.TempDir(), "victim")
			if err := os.WriteFile(victim, []byte("EXISTING-NOT-A-REAL-KEY"), 0o400); err != nil {
				t.Fatal(err)
			}
			var err error
			switch how {
			case "file":
				err = os.WriteFile(k.path(planted), []byte("EXISTING-NOT-A-REAL-KEY"), 0o400)
			case "symlink":
				err = os.Symlink(victim, k.path(planted))
			default:
				err = os.Symlink(filepath.Join(filepath.Dir(victim), "nowhere"), k.path(planted))
			}
			if err != nil {
				t.Fatal(err)
			}
			_, errs, code := k.seal()
			if code != 1 || !strings.Contains(errs, planted+" exists; pick a new key id") {
				t.Errorf("%s (%s): exit %d, stderr %q", planted, how, code, errs)
			}
			k.wantNames(planted+" ("+how+")", planted)
			if how != "dangling" {
				if b, _ := os.ReadFile(k.path(planted)); string(b) != "EXISTING-NOT-A-REAL-KEY" {
					t.Errorf("%s (%s) was changed", planted, how)
				}
			} else if _, err := os.Lstat(filepath.Join(filepath.Dir(victim), "nowhere")); err == nil {
				t.Errorf("%s (dangling): written through", planted)
			}
			if k.rnd.n != 0 {
				t.Errorf("%s (%s): a key was drawn for a name that was taken", planted, how)
			}
		}
	}
}

func TestKeySealingRemovesTheFirstFileWhenTheSecondCannotBeLinked(t *testing.T) {
	k := newKT(t, goodKey(t))
	real := k.env.link
	calls := 0
	k.env.link = func(oldname, newname string) error {
		calls++
		if calls == 2 { // another run puts the broker's name there between the check and the link
			if err := os.WriteFile(k.path("broker-encryption.key"), []byte("EXISTING-NOT-A-REAL-KEY"), 0o400); err != nil {
				t.Fatal(err)
			}
		}
		return real(oldname, newname)
	}
	_, errs, code := k.seal()
	if code != 1 || !strings.Contains(errs, "broker-encryption.key exists; pick a new key id") {
		t.Errorf("exit %d, stderr %q", code, errs)
	}
	k.wantNames("half a pair", "broker-encryption.key")
	if b := k.read("broker-encryption.key"); string(b) != "EXISTING-NOT-A-REAL-KEY" {
		t.Error("the name that appeared late was replaced")
	}
}

func TestKeySealingLeavesALateFirstNameAlone(t *testing.T) {
	k := newKT(t, goodKey(t))
	real := k.env.link
	k.env.link = func(oldname, newname string) error {
		if err := os.WriteFile(k.path("encryption.key"), []byte("EXISTING-NOT-A-REAL-KEY"), 0o400); err != nil {
			t.Fatal(err)
		}
		return real(oldname, newname)
	}
	_, errs, code := k.seal()
	if code != 1 || !strings.Contains(errs, "encryption.key exists; pick a new key id") {
		t.Errorf("exit %d, stderr %q", code, errs)
	}
	k.wantNames("a late first name", "encryption.key")
}

func TestKeySealingLeavesNothingWhenAStepFails(t *testing.T) {
	for _, step := range []string{"chown", "link"} {
		k := newKT(t, goodKey(t))
		switch step {
		case "chown":
			k.env.chown = func(*os.File, int, int) error { return errors.New("operation not permitted") }
		default:
			k.env.link = func(string, string) error { return errors.New("cross-device link") }
		}
		_, errs, code := k.seal()
		if code != 1 || errs == "" || strings.Count(errs, "\n") != 1 {
			t.Errorf("%s fails: exit %d, stderr %q, want 1 and one line", step, code, errs)
		}
		k.wantNames("a failed " + step)
	}
}

func TestKeySealingRemovesWhatItMadeWhenInterrupted(t *testing.T) {
	for after := 0; after <= 2; after++ { // before the first link, between the two, after both
		k := newKT(t, goodKey(t))
		real, links := k.env.link, 0
		k.env.link = func(o, n string) error { links++; return real(o, n) }
		k.env.stop = func() bool { return links >= after }
		_, errs, code := k.seal()
		if code != 1 || errs == "" {
			t.Errorf("interrupted after %d links: exit %d, stderr %q", after, code, errs)
		}
		k.wantNames("an interrupt after " + string(rune('0'+after)) + " links")
	}
}

func TestKeySealingImportInstallsThePairFromACopy(t *testing.T) {
	key := goodKey(t)
	k := newKT(t)
	src := filepath.Join(t.TempDir(), "copy")
	if err := os.WriteFile(src, key, 0o600); err != nil {
		t.Fatal(err)
	}
	out, errs, code := k.seal("--import", src, "--id", "e2")
	if code != 0 || errs != "" {
		t.Fatalf("exit %d, stderr %q", code, errs)
	}
	k.wantNames("an import", pairNames("e2")...)
	for _, n := range pairNames("e2") {
		if !bytes.Equal(k.read(n), key) {
			t.Errorf("%s is not the imported key", n)
		}
		k.wantMode(n, 0o400)
	}
	if k.rnd.n != 0 {
		t.Error("an import drew random bytes")
	}
	if leaks(out+errs, key) {
		t.Error("the key is in the output")
	}
	if _, err := os.Stat(src); err != nil {
		t.Error("the import removed its source: the operator deletes the copy")
	}
}

func TestKeySealingImportRefusesAKeyThatWouldNotLoad(t *testing.T) {
	long := append(goodKey(t), 'x')
	for name, content := range map[string][]byte{
		"empty":         {},
		"31 bytes":      goodKey(t)[:31],
		"33 bytes":      long,
		"newline-ended": badKey(t),
	} {
		k := newKT(t)
		src := filepath.Join(t.TempDir(), "copy")
		if err := os.WriteFile(src, content, 0o600); err != nil {
			t.Fatal(err)
		}
		out, errs, code := k.seal("--import", src)
		if code != 1 || strings.Count(errs, "\n") != 1 {
			t.Errorf("%s: exit %d, stderr %q, want 1 and one line", name, code, errs)
		}
		if leaks(out+errs, content) && len(content) > 0 {
			t.Errorf("%s: the key is in the output", name)
		}
		k.wantNames(name)
	}
	k := newKT(t)
	for name, src := range map[string]string{"a directory": t.TempDir(), "a missing file": filepath.Join(t.TempDir(), "none")} {
		if _, _, code := k.seal("--import", src); code != 1 {
			t.Errorf("%s: exit %d, want 1", name, code)
		}
		k.wantNames(name)
	}
}

func TestKeySealingImportRefusesBeforeWritingEitherWhenOneExists(t *testing.T) {
	for _, planted := range []string{"encryption.key", "broker-encryption.key"} {
		k := newKT(t)
		src := filepath.Join(t.TempDir(), "copy")
		if err := os.WriteFile(src, goodKey(t), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(k.path(planted), []byte("EXISTING-NOT-A-REAL-KEY"), 0o400); err != nil {
			t.Fatal(err)
		}
		_, errs, code := k.seal("--import", src)
		if code != 1 || !strings.Contains(errs, planted+" exists; pick a new key id") {
			t.Errorf("%s: exit %d, stderr %q", planted, code, errs)
		}
		k.wantNames(planted+" exists", planted)
	}
}

func TestKeyDeviceWritesAHexKeyTheCLICanTake(t *testing.T) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	k := newKT(t, raw)
	out, errs, code := k.device("core-v2")
	if code != 0 || errs != "" {
		t.Fatalf("exit %d, stderr %q", code, errs)
	}
	k.wantNames("one device key", "core-v2")
	b := k.read("core-v2")
	if len(b) != 33 || !regexp.MustCompile(`^[0-9a-f]{32}\n$`).Match(b) {
		t.Errorf("the file is %d bytes and not 32 lowercase hex characters and a newline", len(b))
	}
	if string(b) != hex.EncodeToString(raw)+"\n" {
		t.Error("the file is not the hex of the 16 bytes drawn")
	}
	k.wantMode("core-v2", 0o440)
	if fi, _ := os.Stat(k.path("core-v2")); fi != nil {
		if _, gid, ok := ownerOf(fi); ok && gid != lookupGid(t, k.group) {
			t.Error("the file's group is not the one asked for")
		}
	}
	if leaks(out+errs, b[:32]) || leaks(out+errs, raw) {
		t.Error("the key is in the output")
	}
	if !strings.Contains(out, k.path("core-v2")) || !strings.Contains(out, "0440") {
		t.Errorf("the output does not say where the key is and its mode: %s", out)
	}
	_, s, err := secretref.New().ResolveText("key", "file:"+k.path("core-v2"))
	if err != nil || len(s.Bytes()) != 32 {
		t.Errorf("the key reads back as %d bytes (err %v), want 32", len(s.Bytes()), err)
	}
}

func TestKeyDeviceRefusesAnExistingNameAndLeavesNothing(t *testing.T) {
	for _, how := range []string{"file", "symlink", "dangling"} {
		k := newKT(t, make([]byte, 16))
		target := filepath.Join(t.TempDir(), "victim")
		var err error
		switch how {
		case "file":
			err = os.WriteFile(k.path("core-v2"), []byte("EXISTING-NOT-A-REAL-KEY"), 0o440)
		case "symlink":
			if err = os.WriteFile(target, []byte("EXISTING-NOT-A-REAL-KEY"), 0o440); err == nil {
				err = os.Symlink(target, k.path("core-v2"))
			}
		default:
			err = os.Symlink(target, k.path("core-v2"))
		}
		if err != nil {
			t.Fatal(err)
		}
		_, errs, code := k.device("core-v2")
		if code != 1 || !strings.Contains(errs, "core-v2 exists; pick a new key id") {
			t.Errorf("%s: exit %d, stderr %q", how, code, errs)
		}
		k.wantNames(how, "core-v2")
		if k.rnd.n != 0 {
			t.Errorf("%s: a key was drawn for a name that was taken", how)
		}
		if how == "dangling" {
			if _, err := os.Lstat(target); err == nil {
				t.Error("written through a dangling link")
			}
		}
	}
	k := newKT(t, make([]byte, 16))
	k.env.chown = func(*os.File, int, int) error { return errors.New("operation not permitted") }
	if _, _, code := k.device("core-v2"); code != 1 {
		t.Errorf("a failed chown: exit %d", code)
	}
	k.wantNames("a failed chown")
}

func TestKeyRefusesANameThatIsNotOne(t *testing.T) {
	bad := []string{"../x", "a/b", ".hidden", "", "a b", "é", "a\nb", "x;y", strings.Repeat("a", 129)}
	for _, n := range bad {
		k := newKT(t, goodKey(t), goodKey(t))
		if _, errs, code := k.device(n); code != 2 || errs == "" {
			t.Errorf("device %q: exit %d, stderr %q, want 2", n, code, errs)
		}
		if _, errs, code := k.seal("--id", n); code != 2 || errs == "" {
			t.Errorf("sealing --id %q: exit %d, stderr %q, want 2", n, code, errs)
		}
		k.wantNames("a bad name " + n)
		if k.rnd.n != 0 {
			t.Errorf("%q: a key was drawn", n)
		}
	}
	for _, n := range []string{"core-v2", "Core_v2.3", "e2", "0", "a.b-c_d", strings.Repeat("a", 128)} {
		k := newKT(t, goodKey(t), goodKey(t))
		if _, errs, code := k.device(n); code != 0 {
			t.Errorf("device %q: exit %d: %s", n, code, errs)
		}
	}
}

func TestKeyNeedsRootForAnotherOwnerAndSaysWhichLine(t *testing.T) {
	cases := []struct {
		name string
		args func(k *kt) []string
		want string
	}{
		{"sealing, another daemon user", func(k *kt) []string {
			return []string{"sealing", "--dir", k.dir, "--daemon-user", "root", "--broker-user", k.user}
		}, "sudo port49d key sealing"},
		{"device, root owner by default", func(k *kt) []string {
			// the host has no group port49d; the owner is what is under test
			return []string{"device", "core-v2", "--dir", k.dir, "--device-group", k.group}
		}, "sudo port49d key device core-v2"},
	}
	for _, c := range cases {
		k := newKT(t, goodKey(t), make([]byte, 16))
		// not the owner of anything, not root, in no group of the files'
		k.env.euid, k.env.groups = k.uid+1, []int{k.uid + 1}
		_, errs, code := k.run(c.args(k)...)
		if code != 1 || !strings.Contains(errs, c.want) || strings.Count(errs, "\n") != 1 {
			t.Errorf("%s: exit %d, stderr %q, want 1 and one line naming %q", c.name, code, errs, c.want)
		}
		k.wantNames(c.name)
		if k.rnd.n != 0 {
			t.Errorf("%s: a key was drawn before the refusal", c.name)
		}
	}
	// a group the caller is not in is as foreign as another user
	k := newKT(t, make([]byte, 16))
	if k.uid == 0 {
		return // root may chown to any group
	}
	k.env.euid, k.env.groups = k.uid, []int{lookupGid(t, k.group) + 1}
	if _, errs, code := k.device("core-v2"); code != 1 || !strings.Contains(errs, "sudo port49d key device") {
		t.Errorf("a foreign group: exit %d, stderr %q", code, errs)
	}
	k.wantNames("a foreign group")
}

func TestKeyRefusesAnUnknownUserNamingTheFlag(t *testing.T) {
	k := newKT(t, goodKey(t))
	_, errs, code := k.run("sealing", "--dir", k.dir, "--daemon-user", "no-such-user-p49", "--broker-user", k.user)
	if code != 1 || !strings.Contains(errs, "--daemon-user") || !strings.Contains(errs, "no-such-user-p49") {
		t.Errorf("exit %d, stderr %q", code, errs)
	}
	k.wantNames("an unknown user")
}

func TestKeyTakesAUidAndAGidByNumber(t *testing.T) {
	k := newKT(t, goodKey(t))
	n := strconv.Itoa(k.uid)
	if _, errs, code := k.run("sealing", "--dir", k.dir, "--daemon-user", n, "--broker-user", n); code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	k.wantMode("encryption.key", 0o400)
}

func lookupGid(t *testing.T, name string) int {
	t.Helper()
	g, err := user.LookupGroup(name)
	if err != nil {
		t.Fatal(err)
	}
	n, err := strconv.Atoi(g.Gid)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestKeyRefusesADirectoryThatIsNotThere(t *testing.T) {
	k := newKT(t, goodKey(t))
	_, errs, code := k.run("sealing", "--dir", filepath.Join(k.dir, "none"), "--daemon-user", k.user, "--broker-user", k.user)
	if code != 1 || errs == "" {
		t.Errorf("exit %d, stderr %q", code, errs)
	}
	if k.rnd.n != 0 {
		t.Error("a key was drawn")
	}
}

func TestKeyUsage(t *testing.T) {
	k := newKT(t)
	for _, args := range [][]string{
		{}, {"nope"}, {"sealing", "extra"}, {"device"}, {"device", "a", "b"}, {"sealing", "--no-such-flag"},
		{"device", "core-v2", "--import", "x"}, {"sealing", "--import"}, {"sealing", "--help"},
	} {
		_, errs, code := k.run(args...)
		if code != 2 || !strings.Contains(errs, "usage: port49d key") {
			t.Errorf("%v: exit %d, stderr %q, want 2 and the usage line", args, code, errs)
		}
	}
}

func TestKeyIsADaemonSubcommand(t *testing.T) {
	found := false
	for _, n := range DaemonSubcommands() {
		found = found || n == "key"
	}
	if !found {
		t.Error("port49d key is not dispatched")
	}
}
