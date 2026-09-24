package broker

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/policy"
	"github.com/rhwendt/port49/internal/store"
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
	if pol["bundle"] != f.b.Policy.Load().Bundle || !strings.HasPrefix(f.b.Policy.Load().Bundle, "sha256:") {
		t.Fatalf("mint record policy: %v", pol)
	}
}

// A device a joint check failed on is quarantined at load, and a mint for it
// is refused device_quarantined, by name, while every other device mints
// (spec §10; §13 decision 20). nx1 is cisco_nxos, which defines no @loopback.
func TestAQuarantinedDeviceIsRefusedAtMint(t *testing.T) {
	f := newFixture(t, 8)
	path := filepath.Join(t.TempDir(), "policy.yaml")
	body := `
scopes: [{name: all_devices, match: {}}, {name: eos, match: {platform: arista_eos}, on_missing: exclude}]
roles: [{name: r, permit: ["**"], deny: [interface @loopback]}]
subjects:
  - {name: c, identity: "user:carol@example.com", username: carol, token_ttl: 60s}
  - {name: s, identity: "user:alice@example.com", username: alice, token_ttl: 60s}
grants: [{subject: s, scope: all_devices, roles: [r]}, {subject: c, scope: eos, roles: [r]}]
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	pol, err := policy.Load(path, policy.Env{Devices: []admission.Device{f.b.Devices["leaf1"], f.b.Devices["nx1"]}})
	if err != nil {
		t.Fatal(err)
	}
	f.b.Policy.Swap(pol)
	resp := decodeMint(t, f.post(context.Background(), f.state(f.alice), `{"devices":["leaf1","nx1"]}`, ""))
	byDevice := map[string]string{}
	for _, it := range resp.Results {
		byDevice[it.Device] = it.Verdict + " " + it.Reason
	}
	if byDevice["nx1"] != "deny device_quarantined" || !strings.HasPrefix(byDevice["leaf1"], "permit") {
		t.Fatalf("%+v", resp.Results)
	}
	// A principal with no grant on the quarantined device hears
	// no_grants_matched, in the reply and the record: the mint API must not
	// tell a caller which devices exist (design §17).
	carol := f.client(t, "carol@example.com", f.now.Add(24*time.Hour))
	f.log.Reset()
	resp = decodeMint(t, f.post(context.Background(), f.state(carol), `{"devices":["nx1"]}`, ""))
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
roles: [{name: r, privilege: admin, permit: ["**"], attributes: {all: ["home-directory*` + strings.Repeat("x", 225) + ` {principal}"]}}]
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
	f.b.Policy.Swap(pol)
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
roles: [{name: r, privilege: admin, permit: ["**"], attributes: {all: ["home-directory*{device}"]}}]
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
	f.b.Policy.Swap(pol)
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

// The next mint answers from a swapped policy, and names its bundle: a
// broker keeps nothing of the policy it was built with (plan 4b). Removing
// netops's one grant leaves alice no_grants_matched on the very next request.
func TestTheNextMintAnswersFromASwappedPolicy(t *testing.T) {
	f := newFixture(t, 8)
	if it := decodeMint(t, f.post(context.Background(), f.state(f.alice), `{"devices":["leaf1"]}`, "")).Results[0]; it.Verdict != "permit" {
		t.Fatalf("before the swap: %+v", it)
	}
	body := strings.Replace(testPolicy, "  - {subject: netops, scope: all_devices, roles: [network_admin, no_reload], max_privilege: admin}\n",
		"  - {subject: idle, scope: all_devices, roles: [network_admin]}\n", 1)
	pol, err := policy.Parse([]byte(body), policy.Env{Devices: []admission.Device{f.b.Devices["leaf1"]}})
	if err != nil {
		t.Fatal(err)
	}
	f.b.Policy.Swap(pol)
	f.log.Reset()
	if it := decodeMint(t, f.post(context.Background(), f.state(f.alice), `{"devices":["leaf1"]}`, "")).Results[0]; it.Verdict != "deny" || it.Reason != "no_grants_matched" {
		t.Fatalf("after the swap: %+v", it)
	}
	carol := f.client(t, "carol@example.com", f.now.Add(24*time.Hour))
	decodeMint(t, f.post(context.Background(), f.state(carol), `{"devices":["leaf1"]}`, ""))
	mints := eventsOf(f.records(t), "mint")
	if pol0, _ := mints[len(mints)-1]["policy"].(map[string]any); pol0["bundle"] != pol.Bundle {
		t.Fatalf("the mint after the swap names the new bundle: %v", mints[len(mints)-1])
	}
}

// stalledWriter is a response writer whose Write blocks until released: a
// client that stopped reading, or a peer that vanished mid-response.
type stalledWriter struct {
	header  http.Header
	writing chan struct{}
	release chan struct{}
}

func (w *stalledWriter) Header() http.Header { return w.header }
func (w *stalledWriter) WriteHeader(int)     {}
func (w *stalledWriter) Write(p []byte) (int, error) {
	close(w.writing)
	<-w.release
	return len(p), nil
}

// A mint holds the policy until its last token is written, not until its
// response is: a response the client never reads must not hold a reload, or
// every mint queued behind the reload, and every refresh after it (pre-flight
// S1).
func TestASwapDoesNotWaitForAResponseWrite(t *testing.T) {
	f := newFixture(t, 8)
	w := &stalledWriter{header: http.Header{}, writing: make(chan struct{}), release: make(chan struct{})}
	defer close(w.release)
	r := httptest.NewRequest("POST", "/v1/tokens", strings.NewReader(`{"devices":["leaf1"]}`))
	r.TLS = f.state(f.alice)
	go f.b.Handler().ServeHTTP(w, r)
	<-w.writing
	swapped := make(chan struct{})
	go func() { f.b.Policy.Swap(f.b.Policy.Load()); close(swapped) }()
	select {
	case <-swapped:
	case <-time.After(2 * time.Second):
		t.Fatal("a swap waited for a response write")
	}
}

// stallingStore is a store whose PutBlob does not answer until its context
// ends: a store that has stopped responding without refusing.
type stallingStore struct {
	store.Store
	entered chan struct{}
}

func (s *stallingStore) PutBlob(ctx context.Context, _ string, _ []byte, _ time.Duration) error {
	close(s.entered)
	<-ctx.Done()
	return ctx.Err()
}

// A mint holding the policy while a swap waits must still finish: a pending
// swap blocks every new Hold, so a mint that took a second one would never
// return, and one waiting on a store that never answers would hold the swap,
// and every mint queued behind it, for good. The store calls under the hold
// are bounded by holdTimeout, so the mint is refused store_unavailable and the
// swap goes through.
func TestAMintHoldingThePolicyFinishesUnderAPendingSwap(t *testing.T) {
	defer func(d time.Duration) { holdTimeout = d }(holdTimeout)
	holdTimeout = 100 * time.Millisecond
	f := newFixture(t, 8)
	st := &stallingStore{Store: f.st, entered: make(chan struct{})}
	f.b.Store = st
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/v1/tokens", strings.NewReader(`{"devices":["leaf1"]}`))
	r.TLS = f.state(f.alice)
	minted := make(chan struct{})
	go func() { f.b.Handler().ServeHTTP(w, r); close(minted) }()
	<-st.entered
	swapped := make(chan struct{})
	go func() { f.b.Policy.Swap(f.b.Policy.Load()); close(swapped) }()
	for _, c := range []chan struct{}{minted, swapped} {
		select {
		case <-c:
		case <-time.After(2 * time.Second):
			t.Fatal("a mint holding the policy under a pending swap never finished")
		}
	}
	if it := decodeMint(t, w).Results[0]; it.Verdict != "deny" || it.Reason != "store_unavailable" {
		t.Fatalf("%+v", it)
	}
}
