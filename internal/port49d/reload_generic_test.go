package port49d

import (
	"testing"

	"github.com/blanketfish/port49/internal/decision"
)

// A swap that puts a bundle in force writes one generic_platform record per
// generic device, once: the same bytes again, or a SIGHUP with no edit, swap
// nothing and write nothing (spec §5.7, §8).
func TestASwapWritesGenericPlatformRecordsOncePerBundle(t *testing.T) {
	rig := newReloadRig(t, minimalPolicy)
	var buf syncBuffer
	rig.b.Log = decision.NewJSONLines(&buf)
	rig.r.log = rig.b.Log
	rig.r.generic = newGenericRecorder(rig.b.Log, "port49d")
	rig.writeInventory(t, genericInventory)
	rig.pollTwice()
	if n := len(genericRecords(t, buf.String())); n != 2 {
		t.Fatalf("%d records after the swap: %s", n, buf.String())
	}
	rig.writeInventory(t, genericInventory)
	rig.pollTwice()
	rig.pollTwice()
	if n := len(genericRecords(t, buf.String())); n != 2 {
		t.Fatalf("%d records after the same bytes again: %s", n, buf.String())
	}
}

// port49-broker's reloader has no recorder: a split deployment writes one record
// per port49d, not one per process.
func TestAReloaderWithNoGenericRecorderWritesNone(t *testing.T) {
	rig := newReloadRig(t, minimalPolicy)
	var buf syncBuffer
	rig.b.Log = decision.NewJSONLines(&buf)
	rig.r.log = rig.b.Log
	rig.writeInventory(t, genericInventory)
	rig.pollTwice()
	if n := len(genericRecords(t, buf.String())); n != 0 {
		t.Fatalf("%d records: %s", n, buf.String())
	}
}
