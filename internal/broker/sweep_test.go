package broker

import (
	"context"
	"errors"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/policy"
	"github.com/rhwendt/port49/internal/store"
)

// sweepPolicy grants alice on site dc1 alone.
const sweepPolicy = `
scopes:
  - {name: all_devices, match: {}}
  - {name: dc, match: {site: [dc1]}}
  - {name: lab, match: {site: [lab]}}
roles:
  - {name: network_admin, privilege: admin, permit: ["**"]}
subjects:
  - {name: netops, identity: ["user:alice@example.com"], username: alice, enable: token, token_ttl: 60s}
grants:
  - {subject: netops, scope: dc, roles: [network_admin], max_privilege: admin}
`

// newSweepFixture is the fixture (batch_max 4) with five dc1 devices and one
// lab device beside leaf1, nx1 and bare, which carry no site.
func newSweepFixture(t *testing.T) *fixture {
	t.Helper()
	dev := func(name, site, addr string) admission.Device {
		return admission.Device{Name: name, Platform: "arista_eos", Addresses: []netip.Addr{netip.MustParseAddr(addr)},
			Attributes: map[string]string{"site": site}}
	}
	return newFixtureWith(t, 8, sweepPolicy, dev("dc-a", "dc1", "10.1.0.1"), dev("dc-b", "dc1", "10.1.0.2"),
		dev("dc-c", "dc1", "10.1.0.3"), dev("dc-d", "dc1", "10.1.0.4"), dev("dc-e", "dc1", "10.1.0.5"),
		dev("lab-1", "lab", "10.9.0.1"))
}

// A sweep pages the granted devices its scope selects by name, batch_max at
// a time, each answered as a named device is, and every record names the
// sweep (decision 42 rulings 1 and 4).
func TestASweepPagesTheGrantedDevicesByName(t *testing.T) {
	f := newSweepFixture(t)
	ctx := context.Background()
	first := decodeMint(t, f.post(ctx, f.state(f.alice), `{"scope":"dc"}`, ""))
	var names []string
	for _, it := range first.Results {
		if it.Verdict != "permit" || it.Login == "" || it.Address == "" {
			t.Fatalf("each item is a named device's permit: %+v", it)
		}
		names = append(names, it.Device)
	}
	if strings.Join(names, ",") != "dc-a,dc-b,dc-c,dc-d" || first.Next != "dc-d" || first.Subject != "netops" {
		t.Fatalf("page 1: %v next %q subject %q", names, first.Next, first.Subject)
	}
	last := decodeMint(t, f.post(ctx, f.state(f.alice), `{"scope":"dc","after":"dc-d"}`, ""))
	if len(last.Results) != 1 || last.Results[0].Device != "dc-e" || last.Next != "" {
		t.Fatalf("page 2: %+v next %q", last.Results, last.Next)
	}
	// all_devices from a caller granted dc1 is dc1: never lab-1, leaf1, nx1 or bare.
	all := decodeMint(t, f.post(ctx, f.state(f.alice), `{"scope":"all_devices"}`, ""))
	for _, it := range all.Results {
		if !strings.HasPrefix(it.Device, "dc-") {
			t.Fatalf("a sweep listed %s, which alice holds no grant on", it.Device)
		}
	}
	// Page 1 (4 permits), page 2 (1) and all_devices (4): nine records.
	mints := eventsOf(f.records(t), "mint")
	if len(mints) != 9 {
		t.Fatalf("%d mint records, want 9: %v", len(mints), mints)
	}
	for _, r := range mints {
		sw, _ := r["sweep"].(map[string]any)
		if sw["scope"] == nil {
			t.Fatalf("a sweep's record without its sweep: %v", r)
		}
	}
}

// An undeclared scope and a declared one selecting no granted device are
// one answer, byte for byte, and one record each with no device (decision 42
// ruling 2).
func TestASweepIsNoEnumerationOracle(t *testing.T) {
	f := newSweepFixture(t)
	ctx := context.Background()
	undeclared := f.post(ctx, f.state(f.alice), `{"scope":"nope"}`, "")
	ungranted := f.post(ctx, f.state(f.alice), `{"scope":"lab"}`, "")
	pastTheEnd := f.post(ctx, f.state(f.alice), `{"scope":"dc","after":"dc-e"}`, "")
	if undeclared.Code != 200 || undeclared.Body.String() != ungranted.Body.String() ||
		undeclared.Body.String() != pastTheEnd.Body.String() {
		t.Fatalf("three answers:\n%s\n%s\n%s", answer(undeclared), answer(ungranted), answer(pastTheEnd))
	}
	for name, w := range map[string]*httptest.ResponseRecorder{"ungranted": ungranted, "past the end": pastTheEnd} {
		if w.Code != undeclared.Code || !reflect.DeepEqual(w.Header(), undeclared.Header()) {
			t.Errorf("%s: status %d headers %v, undeclared: %d %v", name, w.Code, w.Header(), undeclared.Code, undeclared.Header())
		}
	}
	if resp := decodeMint(t, undeclared); resp.Results == nil || len(resp.Results) != 0 || resp.Next != "" {
		t.Fatalf("an empty page is results: [] and no next: %s", undeclared.Body.String())
	}
	mints := eventsOf(f.records(t), "mint")
	if len(mints) != 3 {
		t.Fatalf("one record per empty page: %v", mints)
	}
	for _, r := range mints {
		if r["verdict"] != "deny" || r["reason"] != "no_grants_matched" || r["device"] != nil || r["sweep"] == nil {
			t.Fatalf("an empty page's record: %v", r)
		}
		// The bundle that answered "nothing granted", the same whichever case made it so.
		if pol, _ := r["policy"].(map[string]any); pol["bundle"] != f.b.Policy.Load().Bundle || pol["bundle"] == "" {
			t.Fatalf("an empty page's record names its bundle: %v", r)
		}
	}
}

// The empty page passes the mint gate first, as every other mint does: while
// it is closed the answer is 503 store_unavailable, not an empty 200.
func TestAnEmptySweepPageAsksTheMintGateFirst(t *testing.T) {
	f := newSweepFixture(t)
	f.b.MintGate = func(*policy.Policy) error { return errors.New("not yet judged") }
	for _, body := range []string{`{"scope":"nope"}`, `{"scope":"lab"}`, `{"scope":"dc","after":"dc-e"}`} {
		w := f.post(context.Background(), f.state(f.alice), body, "")
		if w.Code != 503 || !strings.Contains(w.Body.String(), "store_unavailable") {
			t.Errorf("%s: %s", body, answer(w))
		}
	}
	for _, r := range eventsOf(f.records(t), "mint") {
		if r["reason"] != "store_unavailable" || r["sweep"] == nil {
			t.Errorf("a gated empty page's record: %v", r)
		}
	}
}

// A name the inventory admits at 255 bytes can end a page and be the next
// after: the sweep continues past it (decision 42 ruling 1). A device named
// that long is still refused in a devices list, which keeps its 253.
func TestASweepContinuesPastA255ByteName(t *testing.T) {
	long := "dc-d" + strings.Repeat("x", 251)
	dev := func(name, addr string) admission.Device {
		return admission.Device{Name: name, Platform: "arista_eos", Addresses: []netip.Addr{netip.MustParseAddr(addr)},
			Attributes: map[string]string{"site": "dc1"}}
	}
	f := newFixtureWith(t, 8, sweepPolicy, dev("dc-a", "10.1.0.1"), dev("dc-b", "10.1.0.2"), dev("dc-c", "10.1.0.3"),
		dev(long, "10.1.0.4"), dev("dc-e", "10.1.0.5"))
	ctx := context.Background()
	first := decodeMint(t, f.post(ctx, f.state(f.alice), `{"scope":"dc"}`, ""))
	if len(long) != 255 || len(first.Results) != 4 || first.Next != long {
		t.Fatalf("page 1: %d results, next %q", len(first.Results), first.Next)
	}
	last := decodeMint(t, f.post(ctx, f.state(f.alice), `{"scope":"dc","after":"`+first.Next+`"}`, ""))
	if len(last.Results) != 1 || last.Results[0].Device != "dc-e" || last.Next != "" {
		t.Fatalf("page 2: %+v next %q", last.Results, last.Next)
	}
	if w := f.post(ctx, f.state(f.alice), `{"devices":["`+long+`"]}`, ""); w.Code != 400 {
		t.Fatalf("a devices list keeps its 253: %s", answer(w))
	}
}

// The revocation re-read after a sweep's mints writes no sweep block (ruling
// 4): its record is about the principal, not the page.
func TestTheRevocationRereadsRecordCarriesNoSweep(t *testing.T) {
	f := newSweepFixture(t)
	if err := f.st.PutRevocation(context.Background(), store.Revocation{Kind: store.RevocationPrincipal,
		Key: "user:alice@example.com", At: f.now, Origin: "test"}); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/v1/tokens", nil)
	r.TLS = f.state(f.alice)
	w := httptest.NewRecorder()
	_, cred, err := Identity(r.TLS, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if !f.b.revokedSince(w, r, caller{principal: "user:alice@example.com", cred: cred}, nil) || w.Code != 401 {
		t.Fatalf("revokedSince: %d %s", w.Code, w.Body)
	}
	recs := f.records(t)
	if len(recs) == 0 {
		t.Fatal("the re-read wrote no record")
	}
	for _, rec := range recs {
		if rec["sweep"] != nil {
			t.Fatalf("a revocation re-read's record names a sweep: %v", rec)
		}
	}
}

// A malformed sweep is refused whole, and writes no record.
func TestMalformedSweepsAreRefusedWhole(t *testing.T) {
	f := newSweepFixture(t)
	for name, body := range map[string]string{
		"devices and a scope":       `{"scope":"dc","devices":["dc-a"]}`,
		"empty devices and a scope": `{"scope":"dc","devices":[]}`,
		"a 256-byte after":          `{"scope":"dc","after":"` + strings.Repeat("a", 256) + `"}`,
		"after with no scope":       `{"after":"dc-a"}`,
		"after with devices":        `{"devices":["dc-a"],"after":"dc-a"}`,
		"scope, devices, trailing":  `{"scope":"dc","devices":["dc-a"]} x`,
		"a scope with a space":      `{"scope":"d c"}`,
		"a control character":       `{"scope":"dc","after":"dc\u0007"}`,
		"a 254-byte scope":          `{"scope":"` + strings.Repeat("s", 254) + `"}`,
	} {
		if w := f.post(context.Background(), f.state(f.alice), body, ""); w.Code != 400 {
			t.Errorf("%s: %s", name, answer(w))
		}
	}
	if recs := f.records(t); len(recs) != 0 {
		t.Fatalf("a malformed sweep writes no record: %v", recs)
	}
}

// A page retried under its key is replayed: the same tokens, and no device
// minted twice (decision 42 ruling 3).
func TestASweepPageRetriedUnderItsKeyIsReplayed(t *testing.T) {
	f := newSweepFixture(t)
	ctx := context.Background()
	a := decodeMint(t, f.post(ctx, f.state(f.alice), `{"scope":"dc"}`, "page-1"))
	b := decodeMint(t, f.post(ctx, f.state(f.alice), `{"scope":"dc"}`, "page-1"))
	if len(a.Results) != 4 || len(b.Results) != 4 {
		t.Fatalf("results: %d and %d", len(a.Results), len(b.Results))
	}
	for i := range a.Results {
		if a.Results[i].Login != b.Results[i].Login {
			t.Fatalf("%s was minted again on the retry", a.Results[i].Device)
		}
	}
	c, err := f.st.Candidates(ctx, store.TokenKey{NAS: "dc-a", Username: "alice"})
	if err != nil || len(c) != 1 {
		t.Fatalf("dc-a holds %d unspent tokens (%v), want 1", len(c), err)
	}
}

// A refusal of a whole sweep page names the sweep too, here the mint gate's
// (decision 42 ruling 4).
func TestASweepPageRefusedWholeNamesTheSweep(t *testing.T) {
	f := newSweepFixture(t)
	f.b.MintGate = func(*policy.Policy) error { return errors.New("not yet judged") }
	w := f.post(context.Background(), f.state(f.alice), `{"scope":"dc","after":"dc-a"}`, "")
	mints := eventsOf(f.records(t), "mint")
	if w.Code != 503 || len(mints) != 1 {
		t.Fatalf("%s\nrecords %v", answer(w), mints)
	}
	if sw, _ := mints[0]["sweep"].(map[string]any); sw["scope"] != "dc" || sw["after"] != "dc-a" {
		t.Fatalf("the refusal's record: %v", mints[0])
	}
}
