package port49d

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
