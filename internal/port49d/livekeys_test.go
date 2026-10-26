package port49d

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rhwendt/port49/internal/keyring"
	"github.com/rhwendt/port49/internal/policy"
	"github.com/rhwendt/port49/internal/secretref"
	"github.com/rhwendt/port49/internal/secretref/secretreftest"
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
		!strings.Contains(err.Error(), "add a version") {
		t.Fatalf("%v", err)
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
		if err == nil || errors.As(err, &unread) || !strings.Contains(err.Error(), ref) ||
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
