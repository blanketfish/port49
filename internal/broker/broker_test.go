package broker

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/engine"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/token"
)

// A batch is answered per item: a granted device gets a pair, an unknown one
// is refused exactly as an ungranted one would be, and each item has its own
// record (design §17).
func TestAMintAnswersEachDeviceOnItsOwn(t *testing.T) {
	f := newFixture(t, 8)
	resp := decodeMint(t, f.post(context.Background(), f.state(f.alice), `{"devices":["leaf1","ghost"],"enable":true}`, ""))
	if resp.Principal != "user:alice@example.com" || resp.Subject != "netops" || len(resp.Results) != 2 {
		t.Fatalf("response: %+v", resp)
	}
	ok, ghost := resp.Results[0], resp.Results[1]
	if ok.Verdict != "permit" || len(ok.Login) != token.Len || len(ok.Enable) != token.Len || ok.Username != "alice" ||
		ok.Address != "172.100.100.11" || ok.Platform != "arista_eos" || ok.ExpiresAt == "" {
		t.Fatalf("permitted item: %+v", ok)
	}
	if ghost.Verdict != "deny" || ghost.Reason != "no_grants_matched" || ghost.Login != "" || ghost.Address != "" {
		t.Fatalf("an unknown device must look exactly like an ungranted one: %+v", ghost)
	}
	recs := f.records(t)
	mints := eventsOf(recs, "mint")
	if len(mints) != 2 || mints[0]["verdict"] != "permit" || mints[1]["reason"] != "no_grants_matched" {
		t.Fatalf("one mint record per item: %v", mints)
	}
	if p, _ := mints[0]["policy"].(map[string]any); p["subject"] != "netops" {
		t.Fatalf("the permit names its subject: %v", mints[0])
	}
	if strings.Contains(f.log.String(), ok.Login) || strings.Contains(f.log.String(), ok.Enable) {
		t.Fatal("a token reached the log")
	}
	c, _ := f.st.Candidates(context.Background(), store.TokenKey{NAS: "leaf1", Username: "alice"})
	if len(c) != 2 || c[0].AuthTime.IsZero() || c[0].Credential.Method != "cert" || c[0].BlobHash == "" {
		t.Fatalf("the tokens carry the handshake's auth_time, the certificate, and the blob: %+v", c)
	}
	if c[0].Principal != "user:alice@example.com" {
		t.Fatalf("the tokens are the verified certificate's: %q", c[0].Principal)
	}
}

func TestAPrincipalWithoutAGrantIsDeniedPerItem(t *testing.T) {
	f := newFixture(t, 8)
	for _, email := range []string{"carol@example.com", "mallory@example.com"} {
		resp := decodeMint(t, f.post(context.Background(), f.state(f.client(t, email, f.now.Add(time.Hour))), `{"devices":["leaf1"]}`, ""))
		if it := resp.Results[0]; it.Verdict != "deny" || it.Reason != "no_grants_matched" {
			t.Fatalf("%s: %+v", email, it)
		}
	}
}

// The blob is written once, named by its content, readable by the daemon, and
// emitted into the log the first time it is written (spec §5.1.1). The log's
// copy is enough to replay from: its body hashes to its name and decodes.
func TestTheBlobIsWrittenAndEmittedOncePerHash(t *testing.T) {
	f := newFixture(t, 8)
	for i := 0; i < 2; i++ {
		decodeMint(t, f.post(context.Background(), f.state(f.alice), `{"devices":["leaf1","nx1"]}`, ""))
	}
	recs := f.records(t)
	blobs := f.blobRecords(t)
	if len(blobs) != 2 || blobs[0].Hash == blobs[1].Hash {
		t.Fatalf("two platforms, two blobs, each emitted once across two batches: %+v", blobs)
	}
	logged := map[string]bool{}
	for _, bl := range blobs {
		if engine.HashOf(bl.Body) != bl.Hash {
			t.Fatalf("the logged body does not hash to its name %q", bl.Hash)
		}
		if _, err := engine.Decode(bl.Hash, bl.Body); err != nil {
			t.Fatalf("the logged blob cannot be replayed: %v", err)
		}
		logged[bl.Hash] = true
	}
	for _, m := range eventsOf(recs, "mint") {
		mint, _ := m["mint"].(map[string]any)
		hash, _ := mint["blob"].(string)
		if !logged[hash] {
			t.Fatalf("mint names blob %q the log never carried", hash)
		}
		body, err := f.st.GetBlob(context.Background(), hash)
		if err != nil {
			t.Fatalf("mint names blob %q the store does not hold: %v", hash, err)
		}
		b, err := engine.Decode(hash, body)
		if err != nil {
			t.Fatal(err)
		}
		dev, _ := m["device"].(map[string]any)
		if dev["name"] == "leaf1" && !slices.Equal(b.Attributes, []string{"priv-lvl=15", "roles=network-admin"}) {
			t.Fatalf("leaf1's blob: %+v", b)
		}
	}
}

// Inventory may name a device with no platform (admission.LoadFile does not
// require one), and no blob can be compiled for it. That item is refused by
// name as the broker's fault, the rest of the batch is answered, and a caller
// with no grant still cannot tell the device exists.
func TestADeviceWithNoPlatformIsRefusedOnItsOwn(t *testing.T) {
	f := newFixture(t, 8)
	resp := decodeMint(t, f.post(context.Background(), f.state(f.alice), `{"devices":["bare","leaf1"]}`, ""))
	bare, leaf := resp.Results[0], resp.Results[1]
	if bare.Error != "device_unconfigured" || !strings.Contains(bare.Detail, "platform") || bare.Verdict != "" ||
		bare.Login != "" || bare.Address != "" {
		t.Fatalf("the unconfigured item: %+v", bare)
	}
	if leaf.Verdict != "permit" || leaf.Login == "" {
		t.Fatalf("the rest of the batch: %+v", leaf)
	}
	for _, m := range eventsOf(f.records(t), "mint") {
		if dev, _ := m["device"].(map[string]any); dev["name"] == "bare" {
			t.Fatalf("a broker fault is not a decision: %v", m)
		}
	}
	if c, _ := f.st.Candidates(context.Background(), store.TokenKey{NAS: "bare", Username: "alice"}); len(c) != 0 {
		t.Fatal("nothing may be minted for a device with no blob")
	}

	carol := f.client(t, "carol@example.com", f.now.Add(time.Hour))
	resp = decodeMint(t, f.post(context.Background(), f.state(carol), `{"devices":["bare"]}`, ""))
	if it := resp.Results[0]; it.Verdict != "deny" || it.Reason != "no_grants_matched" || it.Error != "" {
		t.Fatalf("an ungranted caller sees an ungranted device: %+v", it)
	}
}

// No trusted certificate, or one that has expired under the held connection,
// is trust_domain_unresolved: 401, one record, nothing minted.
func TestAnUntrustedCallerIsRefused(t *testing.T) {
	f := newFixture(t, 8)
	short := f.client(t, "alice@example.com", f.now.Add(time.Minute))
	for _, tt := range []struct {
		name  string
		state func() *tls.ConnectionState
	}{
		{"no certificate", func() *tls.ConnectionState { return nil }},
		{"expired since", func() *tls.ConnectionState { f.now = f.now.Add(2 * time.Minute); return f.state(short) }},
	} {
		w := f.post(context.Background(), tt.state(), `{"devices":["leaf1"]}`, "")
		var e api.Error
		_ = json.Unmarshal(w.Body.Bytes(), &e)
		if w.Code != 401 || e.Error != "trust_domain_unresolved" {
			t.Fatalf("%s: %s", tt.name, answer(w))
		}
	}
	mints := eventsOf(f.records(t), "mint")
	if len(mints) != 2 {
		t.Fatalf("one refusal record per request, two requests: %v", mints)
	}
	for _, m := range mints {
		if m["reason"] != "trust_domain_unresolved" {
			t.Fatalf("only refusals: %v", m)
		}
	}
	// No certificate: nothing to name. An expired one the anchor verified:
	// whose it was, so a helpdesk reading the log at 3am can tell.
	if _, ok := mints[0]["principal"]; ok || mints[0]["auth"].(map[string]any)["fingerprint"] != nil {
		t.Fatalf("a refusal with no certificate names no one: %v", mints[0])
	}
	auth, _ := mints[1]["auth"].(map[string]any)
	if mints[1]["principal"] != "user:alice@example.com" || auth["method"] != "cert" ||
		auth["fingerprint"] != "sha256:"+fingerprint(short) {
		t.Fatalf("an expired certificate's refusal names it: %v", mints[1])
	}
	if c, _ := f.st.Candidates(context.Background(), store.TokenKey{NAS: "leaf1", Username: "alice"}); len(c) != 0 {
		t.Fatal("nothing may be minted for an untrusted caller")
	}
}

// fingerprint is the leaf's sha256, hex, as Identity spells it.
func fingerprint(c tls.Certificate) string {
	sum := sha256.Sum256(c.Leaf.Raw)
	return hex.EncodeToString(sum[:])
}

// A held connection past max_session_age mints nothing: the caller must
// authenticate again (spec §13, decision 17), and the connection is closed so
// the next request is a new handshake.
func TestAConnectionPastTheCeilingIsRefused(t *testing.T) {
	f := newFixture(t, 8)
	ctx := withHeldConn(context.Background(), f.now)
	decodeMint(t, f.post(ctx, f.state(f.alice), `{"devices":["leaf1"]}`, ""))
	f.now = f.now.Add(12*time.Hour + time.Second)
	w := f.post(ctx, f.state(f.alice), `{"devices":["leaf1"]}`, "")
	var e api.Error
	_ = json.Unmarshal(w.Body.Bytes(), &e)
	if w.Code != 401 || e.Error != "session_expired" || w.Header().Get("Connection") != "close" {
		t.Fatalf("%s %v", answer(w), w.Header())
	}
	last := f.records(t)[len(f.records(t))-1]
	if last["event"] != "mint" || last["reason"] != "session_expired" || last["principal"] != "user:alice@example.com" {
		t.Fatalf("record: %v", last)
	}
}

// A device's ceiling is its roles', on the token and on the item; a device
// whose ceiling has passed since the connection authenticated is refused
// per item, session_expired, and another device on the same connection is
// not (spec §5.6; decision 33).
func TestTheMintCarriesEachDevicesCeiling(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, shortLeaf1Policy)
	ctx := context.Background()
	auth := f.now
	check := func(r api.MintResponse, leaf1Denied bool) {
		t.Helper()
		got := map[string]api.MintItem{}
		for _, it := range r.Results {
			got[it.Device] = it
		}
		if l := got["leaf1"]; leaf1Denied {
			if l.Verdict != "deny" || l.Reason != "session_expired" || !strings.Contains(l.Detail, "port49 refresh") {
				t.Fatalf("a device past its ceiling: %+v", l)
			}
		} else if l.Verdict != "permit" || l.SessionExpiresAt != auth.Add(time.Hour).UTC().Format(time.RFC3339) {
			t.Fatalf("leaf1's session_expires_at: %+v", l)
		}
		if n := got["nx1"]; n.Verdict != "permit" ||
			n.SessionExpiresAt != auth.Add(12*time.Hour).UTC().Format(time.RFC3339) {
			t.Fatalf("nx1 keeps the default ceiling: %+v", n)
		}
	}
	check(decodeMint(t, f.post(ctx, f.state(f.alice), `{"devices":["leaf1","nx1"]}`, "")), false)
	for nas, want := range map[string]time.Duration{"leaf1": time.Hour, "nx1": 12 * time.Hour} {
		toks, _ := f.st.Candidates(ctx, store.TokenKey{NAS: nas, Username: "alice"})
		if len(toks) != 1 || toks[0].MaxSessionAge != want {
			t.Fatalf("%s's token max_session_age: %+v", nas, toks)
		}
	}
	// An hour on, on a connection that authenticated at auth: leaf1 is
	// refused per item, nx1 is not.
	f.advance(time.Hour)
	check(decodeMint(t, f.postAt(ctx, f.state(f.alice), `{"devices":["leaf1","nx1"]}`, "", auth)), true)
}

// shortLeaf1Policy gives leaf1, through an eos scope, a 1h ceiling and alice
// a 15m token_ttl; nx1 keeps port49d's 12h default.
var shortLeaf1Policy = strings.NewReplacer(
	"  - {name: all_devices, match: {}}\n",
	"  - {name: all_devices, match: {}}\n  - {name: eos, match: {platform: arista_eos}, on_missing: exclude}\n",
	"  - {name: no_reload, deny: [\"reload **\"]}\n",
	"  - {name: no_reload, deny: [\"reload **\"]}\n  - {name: short_session, max_session_age: 1h}\n",
	"max_privilege: admin}\n",
	"max_privilege: admin}\n  - {subject: netops, scope: eos, roles: [short_session]}\n",
	"enable: token, token_ttl: 60s}",
	"enable: token, token_ttl: 15m}",
).Replace(testPolicy)

// A replay answers with the token it minted, so with that token's ceiling,
// not the new connection's; and a token whose ceiling has passed is never
// replayed: the mint is made again under the connection asking, whose
// ceiling the broker has just checked.
func TestAReplayKeepsItsTokensCeiling(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, shortLeaf1Policy)
	ctx := context.Background()
	auth := f.now
	body := `{"devices":["leaf1"]}`
	f.advance(55 * time.Minute)
	first := decodeMint(t, f.postAt(ctx, f.state(f.alice), body, "k1", auth)).Results[0]
	if first.Verdict != "permit" || first.SessionExpiresAt != auth.Add(time.Hour).UTC().Format(time.RFC3339) {
		t.Fatalf("the first mint: %+v", first)
	}
	// Minted 5m before a 1h ceiling with a 15m token_ttl, the token expires
	// at the ceiling (final review I-1).
	if first.ExpiresAt != first.SessionExpiresAt {
		t.Fatalf("the token outlives its ceiling: expires_at %s, session_expires_at %s",
			first.ExpiresAt, first.SessionExpiresAt)
	}
	// A fresh connection before the ceiling: the same token, its own ceiling.
	f.advance(3 * time.Minute)
	again := decodeMint(t, f.postAt(ctx, f.state(f.alice), body, "k1", f.now)).Results[0]
	if again.Login != first.Login || again.SessionExpiresAt != first.SessionExpiresAt {
		t.Fatalf("a replay reports the ceiling of the token it returns: %+v, first %+v", again, first)
	}
	// Past it: minted again, under the new connection.
	f.advance(3 * time.Minute)
	now := f.now
	fresh := decodeMint(t, f.postAt(ctx, f.state(f.alice), body, "k1", now)).Results[0]
	if fresh.Verdict != "permit" || fresh.Login == first.Login ||
		fresh.SessionExpiresAt != now.Add(time.Hour).UTC().Format(time.RFC3339) {
		t.Fatalf("a token past its ceiling is not replayed: %+v, first %+v", fresh, first)
	}
}

// A retry with the same key and body replays the same tokens; the same key
// with another body is a conflict and mints nothing (design §17). The key is
// the principal's own: another caller sending it gets nothing of alice's.
func TestIdempotency(t *testing.T) {
	f := newFixture(t, 8)
	body := `{"devices":["leaf1"]}`
	a := decodeMint(t, f.post(context.Background(), f.state(f.alice), body, "k1"))
	b := decodeMint(t, f.post(context.Background(), f.state(f.alice), body, "k1"))
	if a.Results[0].Login != b.Results[0].Login {
		t.Fatal("a retry must replay, not mint again: the two logins differ")
	}
	if c, _ := f.st.Candidates(context.Background(), store.TokenKey{NAS: "leaf1", Username: "alice"}); len(c) != 1 {
		t.Fatalf("one token minted, %d in the store", len(c))
	}
	if w := f.post(context.Background(), f.state(f.alice), `{"devices":["leaf1"],"enable":true}`, "k1"); w.Code != 409 {
		t.Fatalf("same key, different body: %s", answer(w))
	}
	mallory := f.client(t, "mallory@example.com", f.now.Add(time.Hour))
	m := decodeMint(t, f.post(context.Background(), f.state(mallory), body, "k1"))
	if it := m.Results[0]; it.Login != "" || it.Reason != "no_grants_matched" {
		t.Fatalf("another principal replayed alice's key: %+v", it)
	}
}

// gatedLog holds the first blob record at the sink until released, standing
// in for a slow write.
type gatedLog struct {
	next              decision.Emitter
	once              sync.Once
	inBlob, releaseIt chan struct{}
}

func (g *gatedLog) Emit(r decision.Record) {
	if r.Event == decision.EventBlob {
		g.once.Do(func() { close(g.inBlob); <-g.releaseIt })
	}
	g.next.Emit(r)
}

// Within one sink, a mint record naming a hash follows that hash's blob
// record, even when a second request for the same blob arrives while the
// first is still writing it.
func TestAMintRecordFollowsItsBlob(t *testing.T) {
	f := newFixture(t, 8)
	g := &gatedLog{next: f.b.Log, inBlob: make(chan struct{}), releaseIt: make(chan struct{})}
	f.b.Log = g
	f.b.Minter = token.NewMinter(f.st, g, rand.Reader, token.TagKey([]byte("k")), func() time.Time { return f.now }, 8)
	var wg sync.WaitGroup
	post := func() {
		defer wg.Done()
		f.post(context.Background(), f.state(f.alice), `{"devices":["leaf1"]}`, "")
	}
	wg.Add(1)
	go post()
	<-g.inBlob
	wg.Add(1)
	go post()
	// The second request would reach Mint and write its record here if
	// nothing held it back; give it the time to.
	time.Sleep(100 * time.Millisecond)
	close(g.releaseIt)
	wg.Wait()
	var sawBlob bool
	for _, r := range f.records(t) {
		switch r["event"] {
		case "blob":
			sawBlob = true
		case "mint":
			if !sawBlob {
				t.Fatalf("a mint record preceded its blob: %s", f.log.String())
			}
		}
	}
	if !sawBlob {
		t.Fatal("no blob record")
	}
}

// A conflict on any device refuses the batch before its first mint: a 409
// after an earlier device minted would leave a stored token, a permit record
// and a candidate-cap slot for a pair nobody received.
func TestAConflictLaterInTheBatchMintsNothing(t *testing.T) {
	f := newFixture(t, 8)
	decodeMint(t, f.post(context.Background(), f.state(f.alice), `{"devices":["leaf1"]}`, "k1"))
	before := len(eventsOf(f.records(t), "mint"))
	if w := f.post(context.Background(), f.state(f.alice), `{"devices":["nx1","leaf1"]}`, "k1"); w.Code != 409 {
		t.Fatalf("%s", answer(w))
	}
	if c, _ := f.st.Candidates(context.Background(), store.TokenKey{NAS: "nx1", Username: "alice"}); len(c) != 0 {
		t.Fatalf("nx1 minted %d tokens into a refused batch", len(c))
	}
	if after := len(eventsOf(f.records(t), "mint")); after != before {
		t.Fatalf("a refused batch wrote %d mint records", after-before)
	}
}

// A fault item is counted by its API error code alone, so a dashboard shows
// an inventory fault without a device in a label.
func TestAFaultItemIsCounted(t *testing.T) {
	f := newFixture(t, 8)
	decodeMint(t, f.post(context.Background(), f.state(f.alice), `{"devices":["bare","leaf1"]}`, ""))
	if got := testutil.ToFloat64(f.b.Metrics.BrokerItemErrors.WithLabelValues("device_unconfigured")); got != 1 {
		t.Fatalf("port49_broker_item_errors_total{error=device_unconfigured} = %v", got)
	}
}

func TestTheCandidateCapIsReportedPerItem(t *testing.T) {
	f := newFixture(t, 1)
	decodeMint(t, f.post(context.Background(), f.state(f.alice), `{"devices":["leaf1"]}`, ""))
	resp := decodeMint(t, f.post(context.Background(), f.state(f.alice), `{"devices":["leaf1"]}`, ""))
	if it := resp.Results[0]; it.Verdict != "deny" || it.Reason != "candidate_cap_reached" {
		t.Fatalf("%+v", it)
	}
	last := f.records(t)[len(f.records(t))-1]
	if last["reason"] != "candidate_cap_reached" {
		t.Fatalf("record: %v", last)
	}
}

// A malformed batch is refused whole, before any record: a device name that
// is no inventory name — too long, or not printable ASCII — would otherwise be
// written verbatim into the no_grants_matched record, and the log never
// carries an unvalidated body (pre-flight F11). So is an oversized
// Idempotency-Key, which the store would keep.
func TestMalformedBatchesAreRefusedWhole(t *testing.T) {
	f := newFixture(t, 8)
	for name, body := range map[string]string{
		"no devices":          `{"devices":[]}`,
		"over the cap":        `{"devices":["a","b","c","d","e"]}`,
		"unknown field":       `{"devices":["leaf1"],"reusable":true}`,
		"a principal":         `{"devices":["leaf1"],"principal":"user:bob@example.com"}`,
		"not json":            `devices=leaf1`,
		"an empty name":       `{"devices":[""]}`,
		"a 254-byte name":     `{"devices":["` + strings.Repeat("a", 254) + `"]}`,
		"a control character": `{"devices":["leaf1\u0007"]}`,
		"a space":             `{"devices":["leaf 1"]}`,
	} {
		if w := f.post(context.Background(), f.state(f.alice), body, ""); w.Code != 400 {
			t.Errorf("%s: %s", name, answer(w))
		}
	}
	if w := f.post(context.Background(), f.state(f.alice), `{"devices":["leaf1"]}`, strings.Repeat("k", 129)); w.Code != 400 {
		t.Errorf("a 129-byte Idempotency-Key: %s", answer(w))
	}
	if recs := f.records(t); len(recs) != 0 {
		t.Fatalf("a malformed batch writes no record: %v", recs)
	}
}

// /v1/config is unauthenticated by necessity and carries no fleet data.
func TestConfigIsDiscoveryOnly(t *testing.T) {
	f := newFixture(t, 8)
	w := httptest.NewRecorder()
	f.b.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/v1/config", nil))
	var c api.Config
	if err := json.Unmarshal(w.Body.Bytes(), &c); err != nil || w.Code != 200 ||
		len(c.Methods) != 1 || c.Methods[0] != "x509" || c.MaxSessionAgeSeconds != 43200 || c.BatchMax != 4 {
		t.Fatalf("%s", answer(w))
	}
	if strings.Contains(w.Body.String(), "leaf1") {
		t.Fatal("discovery must not name a device")
	}
}

// gatedStore holds every PutToken until gate is closed, so two requests can
// be made to overlap at the mint.
type gatedStore struct {
	store.Store
	entered chan struct{}
	gate    chan struct{}
}

func (g *gatedStore) PutToken(ctx context.Context, k store.TokenKey, t store.Token) (int, error) {
	select {
	case g.entered <- struct{}{}:
	default:
	}
	<-g.gate
	return g.Store.PutToken(ctx, k, t)
}

// gate puts the fixture's minter over a gatedStore and returns it.
func (f *fixture) gate() *gatedStore {
	g := &gatedStore{Store: f.st, entered: make(chan struct{}, 1), gate: make(chan struct{})}
	f.b.Minter = token.NewMinter(g, decision.NewJSONLines(f.log), rand.Reader, token.TagKey([]byte("k")), f.b.Now, 8)
	return g
}

// Design §17: two requests under one key cannot both mint. Under the same
// body the second is told the first is in progress, and a retry after it
// completes is its replay; under another body it is a conflict. Exactly one
// mint is made either way.
func TestTwoRequestsUnderOneKeyMintOnce(t *testing.T) {
	for _, tc := range []struct{ second, wantErr string }{
		{`{"devices":["leaf1"]}`, "idempotency_in_progress"},
		{`{"devices":["leaf1"],"enable":true}`, "idempotency_conflict"},
	} {
		t.Run(tc.wantErr, func(t *testing.T) {
			f := newFixture(t, 8)
			g := f.gate()
			first := make(chan *httptest.ResponseRecorder, 1)
			go func() { first <- f.post(context.Background(), f.state(f.alice), `{"devices":["leaf1"]}`, "01J") }()
			<-g.entered
			w := f.post(context.Background(), f.state(f.alice), tc.second, "01J")
			if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), tc.wantErr) {
				t.Fatalf("the overlapping request: %s", answer(w))
			}
			if tc.wantErr == "idempotency_in_progress" && w.Header().Get("Retry-After") != "1" {
				t.Fatalf("Retry-After: %q", w.Header().Get("Retry-After"))
			}
			close(g.gate)
			a := decodeMint(t, <-first)
			toks, _ := f.st.Candidates(context.Background(), store.TokenKey{NAS: "leaf1", Username: "alice"})
			if len(toks) != 1 { // the first request asks no enable token
				t.Fatalf("%d tokens stand for leaf1; one mint makes one login token", len(toks))
			}
			if tc.wantErr == "idempotency_in_progress" {
				b := decodeMint(t, f.post(context.Background(), f.state(f.alice), tc.second, "01J"))
				if b.Results[0].Login != a.Results[0].Login {
					t.Fatal("the retry after completion must be the first request's replay")
				}
			}
		})
	}
	// A replay abandoned because its tokens were superseded is taken over
	// before it mints, so of two retries one mints and the other is told it
	// is in progress (pre-flight M5).
	t.Run("abandoned_replay", func(t *testing.T) {
		f := newFixture(t, 8)
		body := `{"devices":["leaf1"]}`
		decodeMint(t, f.post(context.Background(), f.state(f.alice), body, "01S"))
		f.b.mu.Lock()
		f.b.superseded = map[store.TokenKey]time.Time{{NAS: "leaf1", Username: "alice"}: f.now.Add(time.Second)}
		f.b.mu.Unlock()
		g := f.gate()
		first := make(chan *httptest.ResponseRecorder, 1)
		go func() { first <- f.post(context.Background(), f.state(f.alice), body, "01S") }()
		<-g.entered
		w := f.post(context.Background(), f.state(f.alice), body, "01S")
		if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "idempotency_in_progress") {
			t.Fatalf("the second abandoned replay: %s", answer(w))
		}
		close(g.gate)
		if r := decodeMint(t, <-first); r.Results[0].Verdict != "permit" {
			t.Fatalf("the first abandoned replay: %+v", r)
		}
		if toks, _ := f.st.Candidates(context.Background(), store.TokenKey{NAS: "leaf1", Username: "alice"}); len(toks) != 2 {
			t.Fatalf("%d tokens: the first mint and one re-mint, not two", len(toks))
		}
	})
}

// steppedStore holds every PutBlob and PutToken, announcing each on entered,
// until a step is sent on gate: a test can move the clock between the
// moments of one device's mint.
type steppedStore struct {
	store.Store
	entered chan string
	gate    chan struct{}
}

func (s *steppedStore) PutBlob(ctx context.Context, hash string, body []byte, ttl time.Duration) error {
	s.entered <- "put_blob"
	<-s.gate
	return s.Store.PutBlob(ctx, hash, body, ttl)
}

func (s *steppedStore) PutToken(ctx context.Context, k store.TokenKey, t store.Token) (int, error) {
	s.entered <- "put_token"
	<-s.gate
	return s.Store.PutToken(ctx, k, t)
}

// A batch can outlast the reservation it took at the start: a hundred
// devices at up to ten seconds of store calls each. Each device's hold is
// renewed just before it is minted, so a retry arriving after the first
// minute, while that device is being minted, is told it is in progress
// rather than reserving the lapsed record and minting the device again
// (design §17).
func TestAHoldIsRenewedBeforeEachMintSoARetryMintsNothing(t *testing.T) {
	f := newFixture(t, 8)
	s := &steppedStore{Store: f.st, entered: make(chan string), gate: make(chan struct{})}
	f.b.Store = s
	f.b.Minter = token.NewMinter(s, decision.NewJSONLines(f.log), rand.Reader, token.TagKey([]byte("k")), f.b.Now, 8)
	body := `{"devices":["leaf1"]}`
	first := make(chan *httptest.ResponseRecorder, 1)
	go func() { first <- f.post(context.Background(), f.state(f.alice), body, "01T") }()
	if op := <-s.entered; op != "put_blob" {
		t.Fatalf("the first request's first store write: %s", op)
	}
	f.advance(50 * time.Second) // the batch's earlier devices took this long
	s.gate <- struct{}{}
	if op := <-s.entered; op != "put_token" {
		t.Fatalf("the first request's next store write: %s", op)
	}
	f.advance(20 * time.Second) // leaf1's mint runs past the minute the batch reserved it for
	second := make(chan *httptest.ResponseRecorder, 1)
	go func() { second <- f.post(context.Background(), f.state(f.alice), body, "01T") }()
	select {
	case w := <-second:
		if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "idempotency_in_progress") {
			t.Fatalf("the retry: %s", answer(w))
		}
	case op := <-s.entered:
		t.Fatalf("the retry reached %s while the first request was minting leaf1", op)
	}
	s.gate <- struct{}{}
	if r := decodeMint(t, <-first); r.Results[0].Verdict != "permit" {
		t.Fatalf("the first request: %+v", r)
	}
	if toks, _ := f.st.Candidates(context.Background(), store.TokenKey{NAS: "leaf1", Username: "alice"}); len(toks) != 1 {
		t.Fatalf("%d tokens stand for leaf1; it was minted once", len(toks))
	}
}

// A device refused by policy gives its reservation back: the same key and
// body, retried after the grant is added, mints rather than being answered
// in progress for a minute.
func TestARefusedDeviceReleasesItsReservation(t *testing.T) {
	f := newFixture(t, 8)
	carol := f.client(t, "carol@example.com", f.now.Add(time.Hour))
	if r := decodeMint(t, f.post(context.Background(), f.state(carol), `{"devices":["leaf1"]}`, "01K")); r.Results[0].Verdict != "deny" {
		t.Fatalf("carol has no grant: %+v", r)
	}
	if _, ok, err := f.st.ReserveIdempotency(context.Background(), "user:carol@example.com", "01K\x00leaf1",
		store.Idempotency{BodyHash: "x", Holder: "probe", Pending: true, ExpiresAt: f.now.Add(time.Minute)}); err != nil || !ok {
		t.Fatalf("the denied device's reservation is still held: %v %v", ok, err)
	}
}

// A batch that names a device twice is refused before anything is reserved.
func TestABatchNamingADeviceTwiceIsRefused(t *testing.T) {
	f := newFixture(t, 8)
	w := f.post(context.Background(), f.state(f.alice), `{"devices":["leaf1","leaf1"]}`, "01L")
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "twice") {
		t.Fatalf("%s", answer(w))
	}
}

// stallSink is a log whose Write blocks until release is closed, and says
// when the first Write has begun.
type stallSink struct {
	began   chan struct{}
	once    sync.Once
	release chan struct{}
	mu      sync.Mutex
	got     []decision.Record
}

func newStallSink() *stallSink {
	return &stallSink{began: make(chan struct{}), release: make(chan struct{})}
}
func (s *stallSink) Emit(r decision.Record) { _ = s.Write(r) }
func (s *stallSink) Write(r decision.Record) error {
	s.once.Do(func() { close(s.began) })
	<-s.release
	s.mu.Lock()
	s.got = append(s.got, r)
	s.mu.Unlock()
	return nil
}

// A log sink that stalls during a mint never holds a reload: the mint
// writes its records only once it has let go of the policy, so Swap
// returns while the sink is still stalled, and once it drains the mint's
// records land, in order (plan 7e Ruling 10; 4b Task 4).
func TestAStalledLogNeverHoldsAReload(t *testing.T) {
	sink := newStallSink()
	f := newFixture(t, 8)
	b := f.b
	b.Log = sink
	b.Minter = token.NewMinter(f.st, sink, rand.Reader, token.TagKey([]byte("k")), b.Now, 8)
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- f.post(context.Background(), f.state(f.alice), `{"devices":["leaf1"]}`, "") }()
	select {
	case <-sink.began:
	case <-time.After(5 * time.Second):
		t.Fatal("the mint never wrote a record")
	}
	swapped := make(chan struct{})
	go func() { b.Policy.Swap(b.Policy.Load()); close(swapped) }()
	select {
	case <-swapped:
	case <-time.After(time.Second):
		t.Fatal("a stalled log held the reload: the mint still held the policy while it wrote")
	}
	close(sink.release)
	if rr := <-done; rr.Code != http.StatusOK {
		t.Fatalf("the mint: %d %s", rr.Code, rr.Body)
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.got) < 2 || sink.got[0].Event != decision.EventBlob || sink.got[1].Event != decision.EventMint {
		t.Fatalf("records %+v", sink.got)
	}
}

// Two requests minting the same blob at once: each request's run of lines
// carries a blob record before its mint record, unless the hash was marked
// emitted, which happens only once a blob record has landed.
//
// A regression guard, not a failing-first test (pre-flight M4): today
// putBlob writes the blob record under b.mu before any mint record, so it
// passes before this task. It pins that buffering keeps the order.
func TestEveryMintRecordFollowsItsBlobRecord(t *testing.T) {
	buf := &lockedBuffer{}
	f := newFixture(t, 8)
	b := f.b
	b.Log = decision.NewJSONLines(buf)
	b.Minter = token.NewMinter(f.st, b.Log, rand.Reader, token.TagKey([]byte("k")), b.Now, 8)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			f.post(context.Background(), f.state(f.alice), `{"devices":["leaf1"]}`, "")
		}()
	}
	wg.Wait()
	seen := map[string]bool{}
	mints := 0
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var r map[string]any
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatal(err)
		}
		switch r["event"] {
		case decision.EventBlob:
			seen[r["blob"].(map[string]any)["hash"].(string)] = true
		case decision.EventMint:
			mints++
			h, _ := r["mint"].(map[string]any)["blob"].(string) // decision.Mint.BlobHash
			if h == "" || !seen[h] {
				t.Fatalf("a mint record names blob %q before any blob record for it:\n%s", h, buf.String())
			}
		}
	}
	if mints != 8 {
		t.Fatalf("%d mint records, want 8:\n%s", mints, buf.String())
	}
}

// blobsSeen forgets every hash once it holds blobsSeenMax, so a policy
// rewritten on a schedule cannot grow it without bound (4b m10): the next
// mint of a forgotten hash writes its blob record again, which replay reads
// as a duplicate.
func TestBlobsSeenIsBounded(t *testing.T) {
	b := newFixture(t, 8).b
	for i := 0; i < blobsSeenMax; i++ {
		b.markBlob(fmt.Sprintf("h%d", i))
	}
	if b.blobSeen("h0") != true {
		t.Fatal("a hash marked was not seen")
	}
	b.markBlob("one-more")
	if b.blobSeen("h0") || !b.blobSeen("one-more") || len(b.blobsSeen) != 1 {
		t.Fatalf("at the bound blobsSeen kept %d hashes", len(b.blobsSeen))
	}
}
