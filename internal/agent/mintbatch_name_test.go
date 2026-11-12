package agent

import (
	"strings"
	"testing"
	"time"
)

// One device name the broker would refuse fails its own caller, locally, and
// nothing else: the broker 400s a whole request that names it.
func TestABadDeviceNameFailsAloneNotTheBatch(t *testing.T) {
	r := newRig(t)
	r.fb.mu.Lock()
	r.fb.delay = 200 * time.Millisecond
	r.fb.mu.Unlock()
	devs := devices(20)
	devs[7] = "leaf 07"
	first, rest := queueBehindOne(t, r, devs[0], devs[1:])
	var all []mintResult
	for res := range first {
		all = append(all, res)
	}
	for res := range rest {
		all = append(all, res)
	}
	for _, res := range all {
		if res.device == "leaf 07" {
			if res.err == nil || !strings.Contains(res.err.Error(), "printable ASCII") {
				t.Errorf("the bad name said %v", res.err)
			}
			continue
		}
		if res.err != nil {
			t.Errorf("%s failed for another device's name: %v", res.device, res.err)
		}
	}
	r.fb.mu.Lock()
	defer r.fb.mu.Unlock()
	for _, b := range r.fb.batches {
		for _, d := range b {
			if d == "leaf 07" {
				t.Error("the bad name was sent to the broker")
			}
		}
	}
}
