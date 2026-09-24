package broker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/policy"
)

// refusingSink refuses blob records while down and passes everything else.
type refusingSink struct {
	next decision.Sink
	down bool
}

func (r *refusingSink) Emit(rec decision.Record) { _ = r.Write(rec) }

func (r *refusingSink) Write(rec decision.Record) error {
	if r.down && rec.Event == decision.EventBlob {
		return errors.New("sink: disk full")
	}
	return r.next.Write(rec)
}

// A blob record the sink refused is emitted again by the next mint that
// writes the hash: replay reads the log alone (spec §5.7), and a mint naming a
// blob the log never carried cannot be replayed (roadmap, plan 4).
func TestARefusedBlobRecordIsEmittedAgain(t *testing.T) {
	f := newFixture(t, 8)
	sink := &refusingSink{next: f.b.Log.(decision.Sink), down: true}
	f.b.Log = sink
	decodeMint(t, f.post(context.Background(), f.state(f.alice), `{"devices":["leaf1"]}`, ""))
	if n := len(f.blobRecords(t)); n != 0 {
		t.Fatalf("the refused blob reached the log %d times", n)
	}
	sink.down = false
	decodeMint(t, f.post(context.Background(), f.state(f.alice), `{"devices":["leaf1"]}`, ""))
	decodeMint(t, f.post(context.Background(), f.state(f.alice), `{"devices":["leaf1"]}`, ""))
	if n := len(f.blobRecords(t)); n != 1 {
		t.Fatalf("after the sink recovered the blob is emitted once, got %d", n)
	}
}

// The mint record names the policy it was decided against (spec §5.7).
func TestAMintRecordNamesItsBundle(t *testing.T) {
	f := newFixture(t, 8)
	decodeMint(t, f.post(context.Background(), f.state(f.alice), `{"devices":["leaf1"]}`, ""))
	mints := eventsOf(f.records(t), "mint")
	pol, _ := mints[len(mints)-1]["policy"].(map[string]any)
	if pol["bundle"] != f.b.Policy.Bundle || !strings.HasPrefix(f.b.Policy.Bundle, "sha256:") {
		t.Fatalf("mint record policy: %v", pol)
	}
}

// A device a joint check failed on is quarantined at load, and a mint for it
// is refused device_quarantined, by name, while every other device mints
// (spec §10; §13 decision 20). leaf1 is arista_eos, which renders no operator.
func TestAQuarantinedDeviceIsRefusedAtMint(t *testing.T) {
	f := newFixture(t, 8)
	path := filepath.Join(t.TempDir(), "policy.yaml")
	body := `
scopes: [{name: all_devices, match: {}}]
roles: [{name: r, privilege: operator, permit: ["**"]}]
subjects: [{name: s, identity: "user:alice@example.com", username: alice, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [r]}, {subject: c, scope: nx, roles: [r]}]
`
	body = strings.Replace(body, "scopes: [{name: all_devices, match: {}}]",
		"scopes: [{name: all_devices, match: {}}, {name: nx, match: {platform: cisco_nxos}}]", 1)
	body = strings.Replace(body, "subjects: [", `subjects: [{name: c, identity: "user:carol@example.com", username: carol, token_ttl: 60s}, `, 1)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	pol, err := policy.Load(path, policy.Env{Devices: []admission.Device{f.b.Devices["leaf1"], f.b.Devices["nx1"]}})
	if err != nil {
		t.Fatal(err)
	}
	f.b.Policy = pol
	resp := decodeMint(t, f.post(context.Background(), f.state(f.alice), `{"devices":["leaf1","nx1"]}`, ""))
	byDevice := map[string]string{}
	for _, it := range resp.Results {
		byDevice[it.Device] = it.Verdict + " " + it.Reason
	}
	if byDevice["leaf1"] != "deny device_quarantined" || !strings.HasPrefix(byDevice["nx1"], "permit") {
		t.Fatalf("%+v", resp.Results)
	}
	// A principal with no grant on the quarantined device hears
	// no_grants_matched, in the reply and the record: the mint API must not
	// tell a caller which devices exist (design §17).
	carol := f.client(t, "carol@example.com", f.now.Add(24*time.Hour))
	f.log.Reset()
	resp = decodeMint(t, f.post(context.Background(), f.state(carol), `{"devices":["leaf1"]}`, ""))
	if it := resp.Results[0]; it.Verdict != "deny" || it.Reason != "no_grants_matched" {
		t.Fatalf("carol: %+v", it)
	}
	for _, r := range f.records(t) {
		if r["reason"] == "device_quarantined" {
			t.Fatalf("carol's mint logged the quarantine: %v", r)
		}
	}
}

// An attribute the principal's own values would push past 255 bytes is the
// broker's refusal, by name, rather than a session the device cannot be sent.
// The template itself fits (252 bytes); `{principal}` filled in does not.
func TestASessionReplyThatWillNotFitIsRefusedAtMint(t *testing.T) {
	f := newFixture(t, 8)
	path := filepath.Join(t.TempDir(), "policy.yaml")
	body := `
scopes: [{name: all_devices, match: {}}]
roles: [{name: r, privilege: admin, permit: ["**"], attributes: {all: ["note*` + strings.Repeat("x", 235) + ` {principal}"]}}]
subjects: [{name: s, identity: "user:alice@example.com", username: alice, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [r]}]
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	pol, err := policy.Load(path, policy.Env{Devices: []admission.Device{f.b.Devices["leaf1"]}})
	if err != nil {
		t.Fatal(err)
	}
	f.b.Policy = pol
	resp := decodeMint(t, f.post(context.Background(), f.state(f.alice), `{"devices":["leaf1"]}`, ""))
	if it := resp.Results[0]; it.Error != "attribute_too_long" || it.Login != "" {
		t.Fatalf("%+v", it)
	}
	f.assertItemErrorOnly(t, "attribute_too_long")
}

// A substitution value a device could read as another attribute — here an
// inventory name carrying `=` — is refused at mint, by name, as the data's
// fault rather than the broker's (engine.ErrSubstitution).
func TestASessionReplyThatWouldCarryASeparatorIsRefusedAtMint(t *testing.T) {
	f := newFixture(t, 8)
	odd := admission.Device{Name: "sw=1", Platform: "arista_eos", Addresses: f.b.Devices["leaf1"].Addresses}
	f.b.Devices[odd.Name] = odd
	path := filepath.Join(t.TempDir(), "policy.yaml")
	body := `
scopes: [{name: all_devices, match: {}}]
roles: [{name: r, privilege: admin, permit: ["**"], attributes: {all: ["note*{device}"]}}]
subjects: [{name: s, identity: "user:alice@example.com", username: alice, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [r]}]
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	pol, err := policy.Load(path, policy.Env{Devices: []admission.Device{odd}})
	if err != nil {
		t.Fatal(err)
	}
	f.b.Policy = pol
	resp := decodeMint(t, f.post(context.Background(), f.state(f.alice), `{"devices":["sw=1"]}`, ""))
	if it := resp.Results[0]; it.Error != "attribute_unsafe" || it.Login != "" {
		t.Fatalf("%+v", it)
	}
	f.assertItemErrorOnly(t, "attribute_unsafe")
}

// assertItemErrorOnly checks an item error is counted by its code and is not
// a decision: no mint record says it (metrics.BrokerItemErrors).
func (f *fixture) assertItemErrorOnly(t *testing.T, code string) {
	t.Helper()
	if n := testutil.ToFloat64(f.b.Metrics.BrokerItemErrors.WithLabelValues(code)); n != 1 {
		t.Errorf("broker_item_errors_total{error=%q} = %v", code, n)
	}
	if mints := eventsOf(f.records(t), "mint"); len(mints) != 0 {
		t.Errorf("an item error wrote a decision record: %v", mints)
	}
}
