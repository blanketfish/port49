package port49d

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/blanketfish/port49/internal/decision"
)

// genericInventory is leaf1 on a platform with an adapter and srl1, srl2 on one
// without; the policy's key group admits all three.
const genericInventory = `devices:
  - {name: leaf1, platform: arista_eos, addresses: [10.0.0.1], key_ref: lab_key}
  - {name: srl2, platform: nokia_srlinux, addresses: [10.0.0.3], key_ref: lab_key}
  - {name: srl1, platform: nokia_srlinux, addresses: [10.0.0.2], key_ref: lab_key}
`

// genericRig is a reload rig whose inventory holds genericInventory, loaded.
func genericRig(t *testing.T) (*reloadRig, *syncBuffer) {
	t.Helper()
	rig := newReloadRig(t, minimalPolicy)
	var buf syncBuffer
	rig.b.Log = decision.NewJSONLines(&buf)
	rig.r.log = rig.b.Log
	rig.writeInventory(t, genericInventory)
	rig.pollTwice()
	return rig, &buf
}

// genericRecords are the generic_platform records in a log, decoded.
func genericRecords(t *testing.T, log string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(log), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("%q: %v", line, err)
		}
		if rec["event"] == decision.EventGenericPlatform {
			out = append(out, rec)
		}
	}
	return out
}

func TestGenericRecorderWritesOneRecordPerDevicePerBundle(t *testing.T) {
	rig, _ := genericRig(t)
	pol := rig.b.Policy.Load()
	var buf, errs syncBuffer
	rec := newGenericRecorder(decision.NewJSONLines(&buf), "port49d")
	rig.out = &errs
	var n int
	rig.with(func() { n = rec.record(pol, rig.now) })
	if n != 2 {
		t.Fatalf("record returned %d, want 2", n)
	}
	recs := genericRecords(t, buf.String())
	if len(recs) != 2 {
		t.Fatalf("%d records: %s", len(recs), buf.String())
	}
	for i, name := range []string{"srl1", "srl2"} {
		r := recs[i]
		dev, _ := r["device"].(map[string]any)
		pl, _ := r["policy"].(map[string]any)
		if r["reason"] != string(decision.PlatformUnknown) || dev["name"] != name || dev["platform"] != "nokia_srlinux" ||
			pl["bundle"] != pol.Bundle {
			t.Errorf("record %d: %v", i, r)
		}
		if _, ok := r["verdict"]; ok {
			t.Errorf("record %d carries a verdict: %v", i, r)
		}
	}
	if strings.Contains(buf.String(), "leaf1") {
		t.Errorf("a device with an adapter was recorded: %s", buf.String())
	}
	line := errs.String()
	if !strings.Contains(line, "nokia_srlinux") || !strings.Contains(line, "2 device(s)") ||
		!strings.Contains(line, "platform_unknown") || strings.Contains(line, "srl1") ||
		strings.Count(line, "\n") != 1 {
		t.Errorf("the line: %q", line)
	}
}

func TestGenericRecorderDoesNotRepeatWithinABundle(t *testing.T) {
	rig, _ := genericRig(t)
	pol := rig.b.Policy.Load()
	var buf, errs syncBuffer
	rec := newGenericRecorder(decision.NewJSONLines(&buf), "port49d")
	rig.out = &errs
	rig.with(func() { rec.record(pol, rig.now) })
	logged, said := buf.String(), errs.String()
	var n int
	rig.with(func() { n = rec.record(pol, rig.now) })
	if n != 0 || buf.String() != logged || errs.String() != said {
		t.Fatalf("a second record of one bundle wrote %d: %q, %q", n, buf.String(), errs.String())
	}
}

func TestGenericRecorderRecordsAgainUnderANewBundle(t *testing.T) {
	rig, _ := genericRig(t)
	first := rig.b.Policy.Load()
	var buf syncBuffer
	rec := newGenericRecorder(decision.NewJSONLines(&buf), "port49d")
	rec.record(first, rig.now)
	rig.writeInventory(t, strings.Replace(genericInventory,
		"{name: srl2, platform: nokia_srlinux,", "{name: srl2, platform: arista_eos,", 1))
	rig.pollTwice()
	second := rig.b.Policy.Load()
	if second.Bundle == first.Bundle {
		t.Fatal("the edit did not change the bundle")
	}
	logged := buf.String()
	if n := rec.record(second, rig.now); n != 1 {
		t.Fatalf("record returned %d, want 1 (srl1 under the new bundle)", n)
	}
	recs := genericRecords(t, strings.TrimPrefix(buf.String(), logged))
	if len(recs) != 1 || recs[0]["device"].(map[string]any)["name"] != "srl1" {
		t.Fatalf("records: %s", buf.String())
	}
	if _, held := rec.recorded["srl2"]; held {
		t.Fatalf("a device no longer generic is still held: %v", rec.recorded)
	}
}
