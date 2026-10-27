package port49d

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/rhwendt/port49/internal/secretref"
)

// A reload refused because a key's file is not there yet is tried again
// every keyRetryInterval, said once, and put in force when the file appears,
// with no SIGHUP (Review Focus 4; decision 53 ruling 2).
func TestAReloadWaitingOnASecretLoadsOnceTheFileAppears(t *testing.T) {
	t.Setenv("PORT49_KEY_RUN", "run-test-secret")
	dir := safeDir(t)
	rig := newReloadRig(t, minimalPolicy)
	rig.r.keys = newLiveKeys(secretref.New(), secretref.Allowance{EnvPrefix: "PORT49_KEY_", FileDir: dir})
	kb, err := rig.r.keys.build(rig.b.Policy.Load())
	if err != nil {
		t.Fatal(err)
	}
	rig.r.keys.put(kb)
	v2 := filepath.Join(dir, "v2")
	rig.write(t, strings.Replace(minimalPolicy, runKeys, "keys:\n  k:\n    current: {version: 2, secret_ref: file:"+
		v2+"}\n    accept: [{version: 1, secret_ref: env:PORT49_KEY_RUN, retire_after: 2099-01-01}]\n"+labKeyRun, 1))
	rig.pollTwice()
	if !strings.Contains(rig.out.String(), "tried again every 30s") {
		t.Fatalf("the refusal does not say it is retried:\n%s", rig.out.String())
	}
	rig.now = rig.now.Add(keyRetryInterval)
	rig.with(func() { rig.r.poll(context.Background()) })
	if n := strings.Count(rig.out.String(), "policy reload ("); n != 1 {
		t.Fatalf("a retry inside keyRetrySayEvery was said again (%d refusals):\n%s", n, rig.out.String())
	}
	if err := os.WriteFile(v2, []byte("two\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rig.now = rig.now.Add(keyRetryInterval)
	rig.with(func() { rig.r.poll(context.Background()) })
	if vs := rig.r.keys.Set("k").Versions; len(vs) != 2 || vs[0].Number != 2 {
		t.Fatalf("the policy did not load once its file appeared: %d versions\n%s", len(vs), rig.out.String())
	}
	if testutil.ToFloat64(rig.m.PolicyFileRefused) != 0 {
		t.Fatal("port49_policy_file_refused still 1")
	}
}

// A refusal that is the policy's own fault (outside the allowance) is not
// retried: only an edit fixes it.
func TestAPolicyFaultIsNotRetried(t *testing.T) {
	t.Setenv("PORT49_KEY_RUN", "run-test-secret")
	t.Setenv("PORT49_ENC_V2", "22222222222222222222222222222222")
	rig := newReloadRig(t, minimalPolicy)
	rig.r.keys = newLiveKeys(secretref.New(), secretref.Allowance{}.WithDefaults())
	kb, err := rig.r.keys.build(rig.b.Policy.Load())
	if err != nil {
		t.Fatal(err)
	}
	rig.r.keys.put(kb)
	rig.write(t, strings.Replace(minimalPolicy, runKeys, "keys:\n  k:\n    current: {version: 1, secret_ref: env:PORT49_ENC_V2}\n"+labKeyRun, 1))
	rig.pollTwice()
	if !strings.Contains(rig.out.String(), "outside key_secret_refs") {
		t.Fatalf("the refusal does not say why:\n%s", rig.out.String())
	}
	for range 2 {
		rig.now = rig.now.Add(keyRetryInterval)
		rig.with(func() { rig.r.poll(context.Background()) })
	}
	if n := strings.Count(rig.out.String(), "policy reload ("); n != 1 || rig.r.keyWait.v != "" ||
		strings.Contains(rig.out.String(), "tried again") {
		t.Fatalf("a policy fault was retried (%d refusals, wait %q):\n%s", n, rig.r.keyWait.v, rig.out.String())
	}
}

// A refused reload is tried again only when its time comes: a file that
// appears sooner waits for the next try (re-review 6, M3).
func TestARetryWaitsForItsNextTime(t *testing.T) {
	t.Setenv("PORT49_KEY_RUN", "run-test-secret")
	dir := safeDir(t)
	rig := newReloadRig(t, minimalPolicy)
	rig.r.keys = newLiveKeys(secretref.New(), secretref.Allowance{EnvPrefix: "PORT49_KEY_", FileDir: dir})
	kb, err := rig.r.keys.build(rig.b.Policy.Load())
	if err != nil {
		t.Fatal(err)
	}
	rig.r.keys.put(kb)
	v2 := filepath.Join(dir, "v2")
	rig.write(t, strings.Replace(minimalPolicy, runKeys, "keys:\n  k:\n    current: {version: 2, secret_ref: file:"+
		v2+"}\n    accept: [{version: 1, secret_ref: env:PORT49_KEY_RUN, retire_after: 2099-01-01}]\n"+labKeyRun, 1))
	rig.pollTwice()
	if err := os.WriteFile(v2, []byte("two\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rig.now = rig.now.Add(keyRetryInterval / 3)
	rig.with(func() { rig.r.poll(context.Background()) })
	if vs := rig.r.keys.Set("k").Versions; len(vs) != 1 {
		t.Fatalf("a retry ran before its time: %d versions\n%s", len(vs), rig.out.String())
	}
	rig.now = rig.now.Add(keyRetryInterval)
	rig.with(func() { rig.r.poll(context.Background()) })
	if vs := rig.r.keys.Set("k").Versions; len(vs) != 2 {
		t.Fatalf("the retry at its time did not load the policy: %d versions\n%s", len(vs), rig.out.String())
	}
}

// A wait for a policy version that is no longer the one refused is dropped,
// and SIGHUP says a refusal at once with its count (re-review 6, M3).
func TestAKeyWaitIsDroppedWhenTheRefusalMovesOnAndSIGHUPSaysItAtOnce(t *testing.T) {
	rig := newReloadRig(t, minimalPolicy)
	r := rig.r
	r.now = rig.clock
	unread := &keyUnreadError{errors.New("keys.k version 2 secret_ref file:/run/port49/keys/v2: not there")}
	if say, note := r.waitForKeys("v1", "", unread); !say || !strings.Contains(note, "tried again every 30s") {
		t.Fatalf("the first refusal: say %v note %q", say, note)
	}
	rig.now = rig.now.Add(keyRetryInterval)
	if say, _ := r.waitForKeys("v1", "", unread); say {
		t.Fatal("a second refusal inside keyRetrySayEvery was said")
	}
	rig.now = rig.now.Add(keyRetryInterval)
	say, note := r.waitForKeys("v1", "SIGHUP", unread)
	if !say || !strings.Contains(note, "still waiting: 2 tries") {
		t.Fatalf("SIGHUP: say %v note %q", say, note)
	}
	// The file still holds the version waited for, so only the refusal moving
	// on can end the wait.
	_, v, err := policyVersion(r.cfg.Policy.File)
	if err != nil {
		t.Fatal(err)
	}
	r.keyWait = keyWait{v: v, next: rig.now.Add(-time.Second)}
	r.refused = "another"
	r.retryKeys(context.Background(), "")
	if r.keyWait.v != "" {
		t.Fatalf("a wait for %q outlived the refusal it was for", r.keyWait.v)
	}
}

// A port49d start whose policy names a device-key file it cannot read ends
// the run with an error naming the key and version, never the file's bytes,
// and nothing listens: the reload's 30 s retry is for a running process, and a
// start that waited would sit silent behind a supervisor's "running"
// (decision 53 ruling 2).
func TestAStartWhoseDeviceKeyFileIsUnreadableExits(t *testing.T) {
	const fake = "FAKE-KEY-BYTES-0123456789abcdef"
	for name, prepare := range map[string]func(t *testing.T, path string){
		"mode 0000": func(t *testing.T, path string) {
			if err := os.WriteFile(path, []byte(fake), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0); err != nil {
				t.Fatal(err)
			}
		},
		"a missing file": func(t *testing.T, path string) {},
	} {
		t.Run(name, func(t *testing.T) {
			if os.Geteuid() == 0 && name == "mode 0000" {
				t.Skip("root reads a mode 0000 file")
			}
			b := brokerConfig(t, minimalPolicy).Broker
			keyDir := safeDir(t)
			path := filepath.Join(keyDir, "k1")
			prepare(t, path)
			writePolicyFile(t, b.PolicyFile, strings.Replace(minimalPolicy, runKeys,
				"keys:\n  k:\n    current: {version: 1, secret_ref: file:"+path+"}\n"+labKeyRun, 1))
			cfg := writeRunConfigWith(t, b, `
devices:
  - {name: leaf1, platform: arista_eos, addresses: [127.0.0.1]}
key_groups:
  - {match: {cidr: 127.0.0.0/8}, key_ref: k}
`, "key_secret_refs: {file_dir: "+keyDir+"}\n")
			out, err := runExpectingRefusal(t, cfg)
			if err == nil || !strings.Contains(err.Error(), "keys.k version 1 secret_ref") {
				t.Fatalf("the start did not end naming the key and version: %v", err)
			}
			if strings.Contains(err.Error(), fake) || strings.Contains(out, fake) {
				t.Fatal("the file's bytes were printed")
			}
			if strings.Contains(out, "listening on") {
				t.Fatalf("something listens after a refused start:\n%s", out)
			}
		})
	}
}
