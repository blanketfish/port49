package port49d

import (
	"testing"
	"time"
)

// A token another replica minted under the replaced policy before it
// reloaded is judged by the runner's settle pass (Ruling 8). The settle's
// delay is exact, not merely past a floor (pre-flight M4).
func TestTheSettlePassJudgesALateReplicasTokens(t *testing.T) {
	for interval, want := range map[time.Duration]time.Duration{
		time.Second: 30 * time.Second, 5 * time.Second: 30 * time.Second,
		20 * time.Second: 45 * time.Second, time.Minute: 125 * time.Second,
	} {
		if got := settleAfter(interval); got != want {
			t.Fatalf("settleAfter(%v) = %v, want %v", interval, got, want)
		}
	}
	rig := newReloadRig(t, minimalPolicy)   // reload_test.go's fixture: a reloader on a memory broker
	swapTo(t, rig, showOnly)                // the edit that withdraws alice's grant
	tok := mintUnder(t, rig, minimalPolicy) // another replica, still on the old policy
	runFirstPass(t, rig)
	runSettlePass(t, rig)
	if tokenStillRedeemable(t, rig, tok) {
		t.Fatal("the settle pass kept a token minted under the replaced policy after the first pass")
	}
}
