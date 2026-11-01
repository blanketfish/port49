package port49d

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/blanketfish/port49/internal/keyring"
	"github.com/blanketfish/port49/internal/keyset"
	"github.com/blanketfish/port49/internal/policy"
	"github.com/blanketfish/port49/internal/secretref"
	"github.com/blanketfish/port49/internal/secretref/secretreftest"
)

// keyedPolicy is the smallest valid policy with the keys: block keys.
func keyedPolicy(t *testing.T, keys string) *policy.Policy {
	t.Helper()
	p, err := policy.Parse([]byte(strings.Replace(minimalPolicy, runKeys, "", 1)+keys), policy.Env{})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// The policy's keys are read at build, once per reference: a second build of
// the same policy reads nothing, and one that adds a version reads only it
// (decision 53 ruling 2).
func TestLiveKeysReadEachReferenceOnce(t *testing.T) {
	dir := safeDir(t)
	k3, k4 := filepath.Join(dir, "k3"), filepath.Join(dir, "k4")
	if err := os.WriteFile(k3, []byte("three\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(k4, []byte("four\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	k := newLiveKeys(secretref.New(), secretref.Allowance{EnvPrefix: "T_LK_", FileDir: dir})
	pol := keyedPolicy(t, "keys:\n  k:\n    current: {version: 3, secret_ref: file:"+k3+"}\n")
	kb, err := k.build(pol)
	if err != nil {
		t.Fatal(err)
	}
	k.put(kb)
	if string(k.Set("k").Versions[0].Secret.Bytes()) != "three" {
		t.Fatal("version 3's secret is not the file's") // never print a secret
	}
	os.Remove(k3) // held: a rebuild of the version in force does not read it again
	pol2 := keyedPolicy(t, "keys:\n  k:\n    current: {version: 4, secret_ref: file:"+k4+"}\n"+
		"    accept: [{version: 3, secret_ref: file:"+k3+", retire_after: 2099-01-01}]\n")
	kb, err = k.build(pol2)
	if err != nil {
		t.Fatalf("a held version was read again: %v", err)
	}
	k.put(kb)
	if vs := k.Set("k").Versions; len(vs) != 2 || string(vs[0].Secret.Bytes()) != "four" ||
		string(vs[1].Secret.Bytes()) != "three" {
		t.Fatalf("%d versions, or a secret not its file's", len(vs))
	}
}

// A version's secret never changes: a policy naming another reference for a
// version in force is refused, with both references named (Review Focus 4).
func TestAReloadThatRekeysAVersionIsRefused(t *testing.T) {
	t.Setenv("T_LK_A", "a")
	t.Setenv("T_LK_B", "b")
	k := newLiveKeys(secretref.New(), secretref.Allowance{EnvPrefix: "T_LK_", FileDir: safeDir(t)})
	kb, err := k.build(keyedPolicy(t, "keys:\n  k:\n    current: {version: 1, secret_ref: env:T_LK_A}\n"))
	if err != nil {
		t.Fatal(err)
	}
	k.put(kb)
	_, err = k.build(keyedPolicy(t, "keys:\n  k:\n    current: {version: 1, secret_ref: env:T_LK_B}\n"))
	if err == nil || !strings.Contains(err.Error(), "env:T_LK_A") || !strings.Contains(err.Error(), "env:T_LK_B") ||
		!strings.Contains(err.Error(), "add a new version") {
		t.Fatalf("%v", err)
	}
}

// A version dropped by one reload and added back by a later one with another
// reference is a re-key too (re-review 7, M4): an open connection on it with
// no packet between the two would decrypt with the new secret. The process
// remembers each version's reference, not only those in force.
func TestAVersionRemovedAndAddedBackWithAnotherReferenceIsRefused(t *testing.T) {
	t.Setenv("T_LK_A", "a")
	t.Setenv("T_LK_B", "b")
	t.Setenv("T_LK_C", "c")
	k := newLiveKeys(secretref.New(), secretref.Allowance{EnvPrefix: "T_LK_", FileDir: safeDir(t)})
	for _, body := range []string{
		"keys:\n  k:\n    current: {version: 2, secret_ref: env:T_LK_C}\n    accept: [{version: 1, secret_ref: env:T_LK_A, retire_after: 2099-01-01}]\n",
		"keys:\n  k:\n    current: {version: 2, secret_ref: env:T_LK_C}\n", // version 1 removed
	} {
		kb, err := k.build(keyedPolicy(t, body))
		if err != nil {
			t.Fatal(err)
		}
		k.put(kb)
	}
	_, err := k.build(keyedPolicy(t, "keys:\n  k:\n    current: {version: 2, secret_ref: env:T_LK_C}\n"+
		"    accept: [{version: 1, secret_ref: env:T_LK_B, retire_after: 2099-01-01}]\n"))
	// The old reference is no longer in the file an operator greps, so the
	// refusal says port49d remembers it, not that the policy in force names it.
	if err == nil || !strings.Contains(err.Error(), "port49d has held env:T_LK_A for k version 1 since it started") ||
		!strings.Contains(err.Error(), "env:T_LK_B") || !strings.Contains(err.Error(), "add a new version") ||
		strings.Contains(err.Error(), "policy in force") {
		t.Fatalf("a removed version came back re-keyed: %v", err)
	}
	// The same reference comes back as it was: nothing was re-keyed.
	if _, err := k.build(keyedPolicy(t, "keys:\n  k:\n    current: {version: 2, secret_ref: env:T_LK_C}\n"+
		"    accept: [{version: 1, secret_ref: env:T_LK_A, retire_after: 2099-01-01}]\n")); err != nil {
		t.Fatalf("the same reference back was refused: %v", err)
	}
}

// A policy names only what port49d.yaml allows (Review Focus 2; decision 53
// ruling 12): the encryption key's variable, the bind password's, and a file
// outside file_dir are each refused before anything is read, naming the
// reference and the allowance, never a value.
func TestAPolicyKeyOutsideTheAllowanceIsRefused(t *testing.T) {
	t.Setenv("PORT49_ENC_V2", "hunter2hunter2hunter2hunter2hunt")
	t.Setenv("PORT49_BIND_PASSWORD", "hunter2-bind")
	tls := filepath.Join(t.TempDir(), "tls-key.pem")
	if err := os.WriteFile(tls, []byte("hunter2-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	k := newLiveKeys(secretref.New(), secretref.Allowance{})
	for _, ref := range []string{"env:PORT49_ENC_V2", "env:PORT49_BIND_PASSWORD", "file:" + tls} {
		_, err := k.build(keyedPolicy(t, "keys:\n  k:\n    current: {version: 1, secret_ref: "+ref+"}\n"))
		if err != nil && strings.Contains(err.Error(), "hunter2") {
			t.Errorf("%s: the refusal carries the secret", ref)
			continue
		}
		var unread *keyUnreadError
		// A file's path is printed, which a pasted secret cannot be; an env: name
		// is not, which one can (Task 9 re-review I1).
		named := ref
		if strings.HasPrefix(ref, "env:") {
			named = "an env: reference"
			if err != nil && strings.Contains(err.Error(), strings.TrimPrefix(ref, "env:")) {
				t.Errorf("%s: the refusal names the variable", ref)
			}
		}
		if err == nil || errors.As(err, &unread) || !strings.Contains(err.Error(), named) ||
			!strings.Contains(err.Error(), "outside key_secret_refs") {
			t.Errorf("%s: %v", ref, err)
		}
	}
}

// A reference inside file_dir that links out of it is refused by the read
// liveKeys makes (re-review N2): Allows checks the text alone, and the text
// is inside. The refusal names both paths and reads nothing.
func TestAPolicyKeyLinkingOutOfTheDirectoryIsRefused(t *testing.T) {
	dir := safeDir(t)
	tls := filepath.Join(safeDir(t), "tls-key.pem")
	if err := os.WriteFile(tls, []byte("hunter2-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out")
	if err := os.Symlink(tls, out); err != nil {
		t.Fatal(err)
	}
	k := newLiveKeys(secretref.New(), secretref.Allowance{EnvPrefix: "PORT49_KEY_", FileDir: dir})
	_, err := k.build(keyedPolicy(t, "keys:\n  k:\n    current: {version: 1, secret_ref: file:"+out+"}\n"))
	if err != nil && strings.Contains(err.Error(), "hunter2") {
		t.Fatal("the refusal carries the target's content")
	}
	if err == nil || !strings.Contains(err.Error(), out) || !strings.Contains(err.Error(), tls) {
		t.Fatalf("%v", err)
	}
}

// What liveKeys and keyBuild hold prints no secret under any verb, nor as
// JSON or YAML, reached by value, pointer or inside a container (Task 4
// carry-forward).
func TestLiveKeysPrintNoSecret(t *testing.T) {
	const secret = "fake-device-key-0123456789abcdef"
	t.Setenv("T_LK_S", secret)
	k := newLiveKeys(secretref.New(), secretref.Allowance{EnvPrefix: "T_LK_", FileDir: safeDir(t)})
	kb, err := k.build(keyedPolicy(t, "keys:\n  k:\n    current: {version: 1, secret_ref: env:T_LK_S}\n"))
	if err != nil {
		t.Fatal(err)
	}
	k.put(kb)
	forms := secretreftest.Forms([]byte(secret))
	holders := map[string]any{"liveKeys": k, "keyBuild": kb, "keyBuild pointer": &kb, "sets": k.All(),
		"set": k.Set("k"), "versions": k.Set("k").Versions, "held": k.held,
		"slice": []keyBuild{kb}, "map": map[string]keyring.Set{"k": k.Set("k")}}
	for name, h := range holders {
		for _, verb := range secretreftest.Verbs {
			if l := secretreftest.Leak([]byte(fmt.Sprintf(verb, h)), forms); l != "" {
				t.Errorf("%s %s prints the secret (%s)", name, verb, l)
			}
		}
	}
}

// put lets go of the secret of a version no later build names (re-review 6,
// M3): a removed version's key does not stay in memory.
func TestPutDropsTheSecretsNoVersionNames(t *testing.T) {
	t.Setenv("T_LK_A", "fake-a")
	t.Setenv("T_LK_B", "fake-b")
	k := newLiveKeys(secretref.New(), secretref.Allowance{EnvPrefix: "T_LK_", FileDir: safeDir(t)})
	both, err := k.build(keyedPolicy(t, "keys:\n  k:\n    current: {version: 2, secret_ref: env:T_LK_B}\n"+
		"    accept: [{version: 1, secret_ref: env:T_LK_A}]\n"))
	if err != nil {
		t.Fatal(err)
	}
	k.put(both)
	if len(k.held) != 2 {
		t.Fatalf("held %d secrets, want 2", len(k.held))
	}
	one, err := k.build(keyedPolicy(t, "keys:\n  k:\n    current: {version: 2, secret_ref: env:T_LK_B}\n"))
	if err != nil {
		t.Fatal(err)
	}
	k.put(one)
	if _, kept := k.held["env:T_LK_A"]; kept || len(k.held) != 1 {
		t.Fatalf("a removed version's secret is still held (%d held)", len(k.held))
	}
}

// keyChanges says a version retired and one removed, and that connections on
// it reset: it is what tells the operator why they did (re-review 6, M3).
func TestKeyChangesSaysRetiredAndRemoved(t *testing.T) {
	t.Setenv("T_LK_A", "fake-a")
	t.Setenv("T_LK_B", "fake-b")
	t.Setenv("T_LK_C", "fake-c")
	set := func(keys string) map[string]keyset.Set { return keyedPolicy(t, keys).KeySets() }
	three := set("keys:\n  k:\n    current: {version: 3, secret_ref: env:T_LK_C}\n" +
		"    accept: [{version: 2, secret_ref: env:T_LK_B}, {version: 1, secret_ref: env:T_LK_A}]\n")
	retired := set("keys:\n  k:\n    current: {version: 3, secret_ref: env:T_LK_C}\n" +
		"    accept: [{version: 2, secret_ref: env:T_LK_B}]\n" +
		"    retired: [{version: 1, secret_ref: env:T_LK_A}]\n")
	removed := set("keys:\n  k:\n    current: {version: 3, secret_ref: env:T_LK_C}\n" +
		"    accept: [{version: 2, secret_ref: env:T_LK_B}]\n")
	if got := keyChanges(three, retired); !strings.Contains(got, "k: version 1 retired (connections on it reset") {
		t.Errorf("retired: %q", got)
	}
	if got := keyChanges(retired, removed); !strings.Contains(got, "k: version 1 removed (connections on it reset") {
		t.Errorf("removed: %q", got)
	}
	if got := keyChanges(three, three); got != "" {
		t.Errorf("no change: %q", got)
	}
}

// A swap of keys while connections read them is race-free: Set, All and the
// secret bytes are read as 500 builds alternate (re-review 6, M2). Run under
// -race.
func TestLiveKeysSwapWhileRead(t *testing.T) {
	t.Setenv("T_LK_A", "fake-a")
	t.Setenv("T_LK_B", "fake-b")
	k := newLiveKeys(secretref.New(), secretref.Allowance{EnvPrefix: "T_LK_", FileDir: safeDir(t)})
	a := keyedPolicy(t, "keys:\n  k:\n    current: {version: 1, secret_ref: env:T_LK_A}\n")
	b := keyedPolicy(t, "keys:\n  k:\n    current: {version: 2, secret_ref: env:T_LK_B}\n"+
		"    accept: [{version: 1, secret_ref: env:T_LK_A}]\n")
	first, err := k.build(a)
	if err != nil {
		t.Fatal(err)
	}
	k.put(first)
	stop := make(chan struct{})
	var readers sync.WaitGroup
	for range 4 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				for _, v := range k.Set("k").Versions {
					_ = v.Secret.Bytes()
				}
				for _, s := range k.All() {
					_ = len(s.Versions)
				}
			}
		}()
	}
	for i := range 500 {
		pol := a
		if i%2 == 0 {
			pol = b
		}
		kb, err := k.build(pol)
		if err != nil {
			t.Fatal(err)
		}
		k.put(kb)
	}
	close(stop)
	readers.Wait()
}

// A secret pasted where an env: name goes parses as one, and is outside the
// allowance: the refusal names the key and version and never the variable
// (plan 6a Task 15; Task 9 re-review I1).
func TestAPastedSecretAsAPolicyEnvNameIsNeverPrinted(t *testing.T) {
	k := newLiveKeys(secretref.New(), secretref.Allowance{EnvPrefix: "T_LK_", FileDir: safeDir(t)})
	_, err := k.build(keyedPolicy(t, "keys:\n  k:\n    current: {version: 1, secret_ref: env:FAKEtoken0123456789abcdef0123456789abcdef}\n"))
	if err == nil || strings.Contains(err.Error(), "FAKEtoken") || !strings.Contains(err.Error(), "keys.k version 1 secret_ref") {
		t.Fatalf("the refusal is missing, or names the pasted variable, or not the key and version")
	}
}

// putFileKeys builds and puts in force a policy whose keys.k version 1 is the
// file at path, and returns the keys.
func putFileKeys(t *testing.T, dir, path string) *liveKeys {
	t.Helper()
	k := newLiveKeys(secretref.New(), secretref.Allowance{EnvPrefix: "PORT49_KEY_", FileDir: dir})
	kb, err := k.build(keyedPolicy(t, "keys:\n  k:\n    current: {version: 1, secret_ref: file:"+path+"}\n"))
	if err != nil {
		t.Fatal(err)
	}
	k.put(kb)
	return k
}

// A held file rewritten in place is found, and the secret in force is still
// the one read (decision 54 ruling 11; spec §12).
func TestAKeyFileRewrittenInPlaceIsFoundAndNotRead(t *testing.T) {
	const orig, rewritten = "not-a-real-key-v1", "not-a-real-key-v1-rewritten"
	dir := safeDir(t)
	path := filepath.Join(dir, "k_v1")
	if err := os.WriteFile(path, []byte(orig), 0o600); err != nil {
		t.Fatal(err)
	}
	k := putFileKeys(t, dir, path)
	if err := os.WriteFile(path, []byte(rewritten), 0o600); err != nil {
		t.Fatal(err)
	}
	got := k.rewritten()
	if len(got) != 1 || got[0].Ref != "k" || got[0].Version != 1 || got[0].Path != path ||
		got[0].State != keyFileChanged || got[0].Err != nil {
		t.Fatalf("findings = %+v, want one keyFileChanged for k version 1", got)
	}
	held := k.Set("k").Versions[0].Secret.Bytes()
	if string(held) != orig {
		t.Fatalf("the secret in force is not the one read: held %d bytes, rewritten file %d", len(held), len(rewritten))
	}
	k.mu.Lock()
	heldText := k.held["file:"+path].Bytes()
	k.mu.Unlock()
	if string(heldText) != orig {
		t.Fatalf("k.held no longer holds the bytes read: %d bytes, rewritten file %d", len(heldText), len(rewritten))
	}
}

func TestAKeyFileRemovedIsFoundUnreadable(t *testing.T) {
	const orig = "not-a-real-key-v1"
	dir := safeDir(t)
	path := filepath.Join(dir, "k_v1")
	if err := os.WriteFile(path, []byte(orig), 0o600); err != nil {
		t.Fatal(err)
	}
	k := putFileKeys(t, dir, path)
	os.Remove(path)
	got := k.rewritten()
	if len(got) != 1 || got[0].State != keyFileUnreadable || got[0].Err == nil {
		t.Fatalf("findings = %+v, want one keyFileUnreadable with an error", got)
	}
	if strings.Contains(got[0].Err.Error(), orig) {
		t.Fatal("the error carries the secret")
	}
}

func TestAnEnvKeyIsNeverReread(t *testing.T) {
	t.Setenv("PORT49_KEY_T", "not-a-real-key-env")
	k := newLiveKeys(secretref.New(), secretref.Allowance{EnvPrefix: "PORT49_KEY_", FileDir: safeDir(t)})
	kb, err := k.build(keyedPolicy(t, "keys:\n  k:\n    current: {version: 1, secret_ref: env:PORT49_KEY_T}\n"))
	if err != nil {
		t.Fatal(err)
	}
	k.put(kb)
	t.Setenv("PORT49_KEY_T", "not-a-real-key-env-changed")
	if got := k.rewritten(); len(got) != 0 {
		t.Fatalf("an env: reference was found changed: %+v", got)
	}
}

func TestAnUnchangedKeyFileIsNotAFinding(t *testing.T) {
	dir := safeDir(t)
	path := filepath.Join(dir, "k_v1")
	if err := os.WriteFile(path, []byte("not-a-real-key-v1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	k := putFileKeys(t, dir, path)
	if got := k.rewritten(); len(got) != 0 {
		t.Fatalf("findings = %+v, want none", got)
	}
	var nilKeys *liveKeys
	if got := nilKeys.rewritten(); got != nil {
		t.Fatal("a nil liveKeys has findings")
	}
}

// The re-read keeps the bound the first read had: a link in the key directory
// that now leads outside key_secret_refs.file_dir is not followed.
func TestAKeyFileLinkedOutsideTheKeyDirIsUnreadable(t *testing.T) {
	dir := safeDir(t)
	path := filepath.Join(dir, "k_v1")
	if err := os.WriteFile(path, []byte("not-a-real-key-v1"), 0o600); err != nil {
		t.Fatal(err)
	}
	k := putFileKeys(t, dir, path)
	outside := filepath.Join(safeDir(t), "elsewhere")
	if err := os.WriteFile(outside, []byte("not-a-real-key-other"), 0o600); err != nil {
		t.Fatal(err)
	}
	os.Remove(path)
	if err := os.Symlink(outside, path); err != nil {
		t.Fatal(err)
	}
	got := k.rewritten()
	if len(got) != 1 || got[0].State != keyFileUnreadable || got[0].Err == nil ||
		!strings.Contains(got[0].Err.Error(), "outside") {
		t.Fatalf("findings = %+v, want one keyFileUnreadable naming the bound", got)
	}
}

// ...and keeps the bound's width as well: a link that leads out of the
// reference's own directory but stays inside key_secret_refs.file_dir, as a
// Secret volume's `..data` links do, is followed.
func TestAKeyFileLinkedWithinTheKeyDirIsRead(t *testing.T) {
	dir := safeDir(t)
	real := filepath.Join(dir, "real")
	if err := os.WriteFile(real, []byte("not-a-real-key-v1"), 0o600); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(sub, "k_v1")
	if err := os.Symlink(real, path); err != nil {
		t.Fatal(err)
	}
	k := putFileKeys(t, dir, path)
	if got := k.rewritten(); len(got) != 0 {
		t.Fatalf("findings = %+v, want none: the link stays inside file_dir", got)
	}
}
