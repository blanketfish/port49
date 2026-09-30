package keystatus

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/decision"
)

var t0 = time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)

func validated(at time.Time, device string, version int) decision.Record {
	return decision.Record{TS: at, Event: decision.EventAuthorizeCommand,
		Device: &decision.Device{Name: device, Platform: "arista_eos", KeyRef: "prod_key", KeyVersion: version}}
}

func unvalidated(at time.Time, source, diag string, version int) decision.Record {
	return decision.Record{TS: at, Event: decision.EventUnvalidated,
		Unvalidated: &decision.Unvalidated{Source: source, Diagnosis: diag, KeyRef: "prod_key", Version: version}}
}

// Spec §10, "Phase-out has to be observable": devices per version, the ones
// still on an old version named, and every unvalidated source bucketed.
func TestInferNamesTheDevicesARotationStallsOn(t *testing.T) {
	recs := []decision.Record{
		validated(t0.Add(-time.Hour), "leaf-19", 3), validated(t0.Add(-12*time.Minute), "leaf-19", 2),
		validated(t0.Add(-5*time.Minute), "leaf-01", 3),
		unvalidated(t0.Add(-30*time.Second), "10.20.4.9", "matches_retired", 1),
		unvalidated(t0.Add(-40*time.Second), "10.20.4.9", "matches_retired", 1),
		unvalidated(t0.Add(-2*time.Second), "203.0.113.7", "not_tacacs", 0),
		{TS: t0, Event: decision.EventUnvalidated, Unvalidated: &decision.Unvalidated{Source: "10.20.0.8",
			Diagnosis: "device_quarantined"}},
	}
	devices := []Device{
		{Name: "leaf-01", KeyRef: "prod_key", Addresses: []netip.Addr{netip.MustParseAddr("10.20.0.7")}},
		{Name: "leaf-19", KeyRef: "prod_key", Addresses: []netip.Addr{netip.MustParseAddr("10.20.4.9")}},
		{Name: "spine-02", KeyRef: "prod_key", Addresses: []netip.Addr{netip.MustParseAddr("10.20.7.3")}},
	}
	keys := []Key{{Ref: "prod_key", Versions: []Version{{Number: 3, State: "current"},
		{Number: 2, State: "accept", RetireAt: time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)},
		{Number: 1, State: "retired"}}}}
	rep := Infer(recs, devices, keys, Options{Now: t0})
	if len(rep.Rows) != 3 || rep.Rows[0].Version != 3 || strings.Join(rep.Rows[0].Devices, ",") != "leaf-01" ||
		strings.Join(rep.Rows[1].Devices, ",") != "leaf-19" || len(rep.Rows[2].Devices) != 0 {
		t.Fatalf("rows: %+v", rep.Rows)
	}
	if len(rep.Unseen) != 1 || rep.Unseen[0].Name != "spine-02" {
		t.Fatalf("unseen: %+v", rep.Unseen)
	}
	if len(rep.Sources) != 2 || rep.Sources[0].Source != "203.0.113.7" || rep.Sources[1].Device != "leaf-19" ||
		rep.Sources[1].Attempts != 2 {
		t.Fatalf("sources (a quarantine is not a key matter): %+v", rep.Sources)
	}
	var out bytes.Buffer
	rep.Write(&out, t0)
	for _, want := range []string{"⚠ rotation not finished: leaf-19 (retire_after 2026-10-01)", "12m ago",
		"never seen in the log: spine-02", "matches retired v1", "not TACACS+ (header invalid)"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in\n%s", want, out.String())
		}
	}
	if rep := Infer(recs, devices, keys, Options{Now: t0, From: t0.Add(-10 * time.Minute)}); len(rep.Rows[1].Devices) != 0 {
		t.Fatalf("--since kept an older record: %+v", rep.Rows[1])
	}
}
