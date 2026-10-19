package port49d

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestTheGenericPlatformGaugeCountsTheBundleInForce(t *testing.T) {
	rig := newReloadRig(t, minimalPolicy)
	watchQuarantine(rig.b.Policy, rig.m, rig.clock)
	if v := testutil.ToFloat64(rig.m.DevicesGenericPlatform); v != 0 {
		t.Fatalf("before the swap: %v", v)
	}
	rig.writeInventory(t, genericInventory)
	rig.pollTwice()
	if v := testutil.ToFloat64(rig.m.DevicesGenericPlatform); v != 2 {
		t.Fatalf("after the swap: %v", v)
	}
}
