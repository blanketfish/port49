package policy

import (
	"path/filepath"
	"runtime"
	"testing"
)

// The lab's policy is loaded by a daemon only inside `make lab`. Loading it here
// means a typo in it fails `make test`, not a VM boot ten minutes in.
func TestTheLabPolicyLoads(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(file), "..", "..", "..", "tests", "lab", "slice", "policy.yaml")
	p, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	r, ok := p.Resolve("user:alice@slice.port49.test", "arista_eos")
	if !ok || r.Username != "slice01" || len(r.Blob.Deny) != 1 || r.Blob.Deny[0] != "show hostname" {
		t.Fatalf("%+v %v", r, ok)
	}
}
