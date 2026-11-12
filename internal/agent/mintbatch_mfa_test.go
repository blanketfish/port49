package agent

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/broker/api"
)

// mintProving is a caller that can prove: it mints, and when the broker asks
// for a per-login proof it names the challenge it was given and mints again.
func mintProving(r *rig, device string) (api.MintItem, error) {
	item, err := r.a.Mint(context.Background(), device, false, 0, "")
	var need *MFARequiredError
	if errors.As(err, &need) {
		return r.a.Mint(context.Background(), device, false, 0, need.Requirement.Challenge)
	}
	return item, err
}

// Ten devices that each need the per-login proof, queued into one batch: the
// broker's one challenge for the request covers one device, so the agent hands
// it to one caller and sends the others alone, each to be given its own. No
// caller fails for another's use of the challenge.
func TestABatchOfPerLoginProofsGivesEachCallerItsOwnChallenge(t *testing.T) {
	r := newRig(t)
	devs := devices(10)
	r.fb.mu.Lock()
	r.fb.delay = 200 * time.Millisecond
	r.fb.mfaDevices = map[string]bool{}
	for _, d := range devs {
		r.fb.mfaDevices[d] = true
	}
	r.fb.mu.Unlock()
	first, _ := queueBehindOne(t, r, "plain", nil)
	out := make(chan mintResult, len(devs))
	for _, d := range devs {
		go func() {
			item, err := mintProving(r, d)
			out <- mintResult{d, item, err}
		}()
	}
	for range devs {
		res := <-out
		if res.err != nil {
			t.Errorf("%s: %v", res.device, res.err)
		} else if res.item.Verdict != "permit" || res.item.Address != "addr-"+res.device {
			t.Errorf("%s was answered with %q for %q", res.device, res.item.Verdict, res.item.Address)
		}
	}
	for res := range first {
		if res.err != nil {
			t.Errorf("%s: %v", res.device, res.err)
		}
	}
	r.fb.mu.Lock()
	defer r.fb.mu.Unlock()
	if r.fb.wrongProof != 0 {
		t.Errorf("%d proofs named a challenge another device had spent", r.fb.wrongProof)
	}
}
