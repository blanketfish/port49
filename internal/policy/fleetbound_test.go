package policy

import (
	"testing"
	"time"
)

// The settle bounds of plan 12c Task 6b: port49d pays Parse at every start
// and inventory reload, and twice at a policy edit, and the reload's settle
// bound is 30 s.

func TestParseAtFleetSizeIsWithinTheSettleBound(t *testing.T) {
	if testing.Short() || raceBuild {
		t.Skip("a time bound; the race detector's slowdown alone breaks it")
	}
	t.Setenv("PORT49_KEY_LOAD", "not-a-real-key-0123456789")
	start := time.Now()
	if _, err := Parse([]byte(benchPolicyText("**")), Env{Now: noon, Devices: benchFleet(benchDevices)}); err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took > 12*time.Second {
		t.Fatalf("Parse took %s at 500 subjects x 10 000 devices, want under 12s", took)
	}
}

func TestClassAgesAtFleetSize(t *testing.T) {
	if testing.Short() || raceBuild {
		t.Skip("a time bound; the race detector's slowdown alone breaks it")
	}
	p := benchParse(t, benchPolicyText("**"), benchFleet(benchDevices))
	start := time.Now()
	if _, err := p.ClassAges("arista_eos", 15*time.Minute, noon); err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took > 10*time.Second {
		t.Fatalf("ClassAges took %s at 500 subjects x 10 000 devices, want under 10s", took)
	}
}
