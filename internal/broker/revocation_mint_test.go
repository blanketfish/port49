package broker

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/token"
)

func (f *fixture) revoke(t *testing.T, kind, key string) {
	t.Helper()
	if err := f.st.PutRevocation(context.Background(), store.Revocation{Kind: kind, Key: key, At: f.b.Now(),
		Origin: "test"}); err != nil {
		t.Fatal(err)
	}
}

// revokeAndSweep is a revocation of a principal as it runs against a store:
// the mark, then a pass over the token index deleting every key it names.
// It finds only what was indexed when it read.
func (f *fixture) revokeAndSweep(t *testing.T, principal string) {
	t.Helper()
	f.revoke(t, store.RevocationPrincipal, principal)
	keys, err := f.st.TokensByPrincipal(context.Background(), principal)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range keys {
		if err := f.st.DeleteTokens(context.Background(), k); err != nil {
			t.Fatal(err)
		}
	}
}

func (f *fixture) live(t *testing.T, device string) int {
	t.Helper()
	toks, err := f.st.Candidates(context.Background(), store.TokenKey{NAS: device, Username: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	return len(toks)
}

// answer is a response for a failure message: its status, and its body
// unless that is a 200's, which carries tokens test output never prints.
func answer(w *httptest.ResponseRecorder) string {
	if w.Code == http.StatusOK {
		return "200 (body withheld: it carries tokens)"
	}
	return fmt.Sprintf("%d %s", w.Code, w.Body.String())
}

// pausedStore holds the first call to one store method — PutToken on one
// device, or ReserveIdempotency — until gate is closed; later calls pass, announcing it on
// entered: a test can land a revocation at exactly that point of a mint.
type pausedStore struct {
	store.Store
	method  string
	nas     string // PutToken: the device it pauses on
	paused  atomic.Bool
	entered chan struct{}
	gate    chan struct{}
}

func (p *pausedStore) pause(method, nas string) {
	if method == p.method && (p.nas == "" || nas == p.nas) {
		if p.paused.CompareAndSwap(false, true) {
			close(p.entered)
			<-p.gate
		}
	}
}

func (p *pausedStore) PutToken(ctx context.Context, k store.TokenKey, t store.Token) (int, error) {
	p.pause("PutToken", k.NAS)
	return p.Store.PutToken(ctx, k, t)
}

func (p *pausedStore) ReserveIdempotency(ctx context.Context, principal, key string,
	rec store.Idempotency) (store.Idempotency, bool, error) {
	p.pause("ReserveIdempotency", "")
	return p.Store.ReserveIdempotency(ctx, principal, key, rec)
}

// pauseAt puts the fixture's minter over a pausedStore, over the broker's
// store, and returns it.
func (f *fixture) pauseAt(method, nas string) *pausedStore {
	p := &pausedStore{Store: f.b.Store, method: method, nas: nas, entered: make(chan struct{}), gate: make(chan struct{})}
	f.b.Minter = token.NewMinter(p, decision.NewJSONLines(f.log), rand.Reader, token.TagKey([]byte("k")), f.b.Now, 8)
	return p
}

// A principal's mark refuses every mint by it: 401 credential_revoked, the
// connection closed, one record naming whose credential it was, and
// nothing minted (spec §5.1.4).
func TestARevokedPrincipalMintsNothing(t *testing.T) {
	f := newFixture(t, 8)
	f.revoke(t, store.RevocationPrincipal, "user:alice@example.com")
	w := f.post(context.Background(), f.state(f.alice), `{"devices":["leaf1"]}`, "")
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), `"credential_revoked"`) ||
		w.Header().Get("Connection") != "close" {
		t.Fatalf("%s %v", answer(w), w.Header())
	}
	if !strings.Contains(w.Body.String(), "this principal was revoked at") {
		t.Fatalf("the refusal must say what was revoked: %s", answer(w))
	}
	if n := f.live(t, "leaf1"); n != 0 {
		t.Fatalf("%d tokens minted for a revoked principal", n)
	}
	recs := eventsOf(f.records(t), "mint")
	if len(recs) != 1 || recs[0]["verdict"] != "deny" || recs[0]["reason"] != "credential_revoked" ||
		recs[0]["principal"] != "user:alice@example.com" ||
		recs[0]["auth"].(map[string]any)["fingerprint"] != "sha256:"+fingerprint(f.alice) { // M1
		t.Fatalf("records: %v", recs)
	}
}

// A certificate's mark refuses that certificate and no other: the same
// principal with a new certificate mints.
func TestARevokedCertificateMintsNothingAndAnotherDoes(t *testing.T) {
	f := newFixture(t, 8)
	f.revoke(t, store.RevocationCert, store.CertKey(f.alice.Leaf.Issuer.String(), f.alice.Leaf.SerialNumber.Text(16)))
	w := f.post(context.Background(), f.state(f.alice), `{"devices":["leaf1"]}`, "")
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "this certificate was revoked at") {
		t.Fatalf("the revoked certificate: %s", answer(w))
	}
	renewed := f.client(t, "alice@example.com", f.now.Add(time.Hour))
	if r := decodeMint(t, f.post(context.Background(), f.state(renewed), `{"devices":["leaf1"]}`, "")); r.Results[0].Verdict != "permit" {
		t.Fatalf("a new certificate for the same principal: %s", r.Results[0].Verdict)
	}
}

// revocationFailingStore cannot read the marks once it has answered ok
// reads, for bad reads, or for good when bad is 0.
type revocationFailingStore struct {
	store.Store
	ok, bad int32
	reads   atomic.Int32
}

func (s *revocationFailingStore) GetRevocation(ctx context.Context, kind, key string) (store.Revocation, error) {
	if n := s.reads.Add(1); n > s.ok && (s.bad == 0 || n <= s.ok+s.bad) {
		return store.Revocation{}, errors.New("store: connection refused")
	}
	return s.Store.GetRevocation(ctx, kind, key)
}

// Marks that cannot be read refuse the mint store_unavailable: a store that
// cannot say whether a credential is revoked mints for no one.
func TestUnreadableMarksMintNothing(t *testing.T) {
	f := newFixture(t, 8)
	f.b.Store = &revocationFailingStore{Store: f.st}
	w := f.post(context.Background(), f.state(f.alice), `{"devices":["leaf1"]}`, "")
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "store_unavailable") {
		t.Fatalf("%s", answer(w))
	}
	if n := f.live(t, "leaf1"); n != 0 {
		t.Fatal("minted with the marks unreadable")
	}
}

// Marks that cannot be read after the tokens are written return nothing:
// the caller is told store_unavailable and handed no token. The tokens stay
// for a revocation's index pass to find (pre-flight M7).
func TestUnreadableMarksAfterTheWritesReturnNothing(t *testing.T) {
	f := newFixture(t, 8)
	// The check before reads two marks, the principal's and the certificate's.
	f.b.Store = &revocationFailingStore{Store: f.st, ok: 2}
	w := f.post(context.Background(), f.state(f.alice), `{"devices":["leaf1"]}`, "")
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "store_unavailable") ||
		strings.Contains(w.Body.String(), `"login"`) {
		t.Fatalf("%s", answer(w))
	}
	keys, err := f.st.TokensByPrincipal(context.Background(), "user:alice@example.com")
	if err != nil || len(keys) != 1 {
		t.Fatalf("the tokens left behind must be indexed for a revocation: %v %v", keys, err)
	}
}

// A request the check after its writes could not clear supersedes what it
// wrote: its retry mints afresh rather than replaying tokens that may
// predate a mark another certificate's retry would otherwise be handed.
func TestUnreadableMarksAfterTheWritesSupersedeThem(t *testing.T) {
	f := newFixture(t, 8)
	f.b.Store = &revocationFailingStore{Store: f.st, ok: 2, bad: 1}
	if w := f.post(context.Background(), f.state(f.alice), `{"devices":["leaf1"]}`, "01U"); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("%s", answer(w))
	}
	f.advance(time.Second)
	decodeMint(t, f.post(context.Background(), f.state(f.alice), `{"devices":["leaf1"]}`, "01U"))
	if n := f.live(t, "leaf1"); n != 2 {
		t.Fatalf("%d live: the retry must mint afresh, not replay the unconfirmed mint", n)
	}
}

// The race decision 32 ruling 6 closes, deterministically: the mint indexes
// its token, a revocation lands and sweeps the index — which names a key
// that holds no token yet — and only then is the token written. The mint
// reads the marks again after its last write, deletes what it wrote, and
// answers credential_revoked, so no token minted under a revoked credential
// survives whichever of the two read the other's write first (spec §5.1.4).
// A replay of that request after a lift mints afresh.
func TestARevocationDuringAMintDeletesWhatItWrote(t *testing.T) {
	f := newFixture(t, 8)
	p := f.pauseAt("PutToken", "")
	answered := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		answered <- f.post(context.Background(), f.state(f.alice), `{"devices":["leaf1"]}`, "01R")
	}()
	<-p.entered
	keys, err := f.st.TokensByPrincipal(context.Background(), "user:alice@example.com")
	if err != nil || len(keys) != 1 || f.live(t, "leaf1") != 0 {
		t.Fatalf("paused between the index write and the token write: index %v %v, %d live", keys, err, f.live(t, "leaf1"))
	}
	f.revokeAndSweep(t, "user:alice@example.com")
	close(p.gate)
	w := <-answered
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "credential_revoked") ||
		strings.Contains(w.Body.String(), `"login"`) || w.Header().Get("Connection") != "close" {
		t.Fatalf("the mint a revocation overtook: %s %v", answer(w), w.Header())
	}
	if n := f.live(t, "leaf1"); n != 0 {
		t.Fatalf("%d token(s) survived the revocation", n)
	}
	// The permit the minter recorded at its write is followed by a deny
	// naming the same device, so the two join (spec §5.7).
	recs := eventsOf(f.records(t), "mint")
	if len(recs) != 2 || recs[0]["verdict"] != "permit" {
		t.Fatalf("records: %v", recs)
	}
	assertRevokedOn(t, f, recs[1], "leaf1")
	if _, ok := recs[1]["index_error"]; ok {
		t.Fatalf("a delete that succeeded is no index_error: %v", recs[1])
	}
	if err := f.st.DeleteRevocation(context.Background(), store.RevocationPrincipal, "user:alice@example.com"); err != nil {
		t.Fatal(err)
	}
	f.advance(time.Second)
	r := decodeMint(t, f.post(context.Background(), f.state(f.alice), `{"devices":["leaf1"]}`, "01R"))
	if n := f.live(t, "leaf1"); r.Results[0].Verdict != "permit" || n != 1 {
		t.Fatalf("after the lift the same key must mint afresh, not replay a deleted token: %s, %d live", r.Results[0].Verdict, n)
	}
}

// A mark that lands between two devices of one batch refuses the whole
// batch: the device minted before it is deleted with the one after.
func TestARevocationMidBatchDeletesEveryDevice(t *testing.T) {
	f := newFixture(t, 8)
	p := f.pauseAt("PutToken", "nx1")
	answered := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		answered <- f.post(context.Background(), f.state(f.alice), `{"devices":["leaf1","nx1"]}`, "01B")
	}()
	<-p.entered
	if f.live(t, "leaf1") != 1 {
		t.Fatal("leaf1 must be minted before nx1's pause")
	}
	f.revokeAndSweep(t, "user:alice@example.com")
	close(p.gate)
	if w := <-answered; w.Code != http.StatusUnauthorized || strings.Contains(w.Body.String(), `"login"`) {
		t.Fatalf("%s", answer(w))
	}
	for _, d := range []string{"leaf1", "nx1"} {
		if n := f.live(t, d); n != 0 {
			t.Fatalf("%d token(s) survived on %s", n, d)
		}
	}
	recs := eventsOf(f.records(t), "mint")
	if len(recs) != 4 {
		t.Fatalf("two permits and a deny for each: %v", recs)
	}
	assertRevokedOn(t, f, recs[2], "leaf1")
	assertRevokedOn(t, f, recs[3], "nx1")
}

func assertRevokedOn(t *testing.T, f *fixture, rec map[string]any, device string) {
	t.Helper()
	dev, _ := rec["device"].(map[string]any)
	auth, _ := rec["auth"].(map[string]any)
	if rec["verdict"] != "deny" || rec["reason"] != "credential_revoked" || dev["name"] != device ||
		rec["principal"] != "user:alice@example.com" || auth["fingerprint"] != "sha256:"+fingerprint(f.alice) {
		t.Fatalf("want deny credential_revoked naming %s: %v", device, rec)
	}
}

// deleteFailingStore cannot delete tokens.
type deleteFailingStore struct{ store.Store }

func (deleteFailingStore) DeleteTokens(context.Context, store.TokenKey) error {
	return errors.New("store: connection refused")
}

// Tokens a refused mint could not delete are said so on the device's deny,
// where an operator reading the decision log finds them, not only in the
// process log.
func TestAnUndeletedTokenIsNamedOnItsDeny(t *testing.T) {
	f := newFixture(t, 8)
	f.b.Store = deleteFailingStore{f.st}
	p := f.pauseAt("PutToken", "")
	answered := make(chan *httptest.ResponseRecorder, 1)
	go func() { answered <- f.post(context.Background(), f.state(f.alice), `{"devices":["leaf1"]}`, "") }()
	<-p.entered
	f.revoke(t, store.RevocationPrincipal, "user:alice@example.com")
	close(p.gate)
	if w := <-answered; w.Code != http.StatusUnauthorized {
		t.Fatalf("%s", answer(w))
	}
	recs := eventsOf(f.records(t), "mint")
	assertRevokedOn(t, f, recs[len(recs)-1], "leaf1")
	if ie, _ := recs[len(recs)-1]["index_error"].(string); !strings.HasPrefix(ie, "tokens not deleted: ") {
		t.Fatalf("index_error: %q", ie)
	}
}

// cancelHonouringStore fails a call on a context that is done, as a remote
// store does; the memory store does not look.
type cancelHonouringStore struct{ store.Store }

func (s cancelHonouringStore) GetRevocation(ctx context.Context, kind, key string) (store.Revocation, error) {
	if err := ctx.Err(); err != nil {
		return store.Revocation{}, err
	}
	return s.Store.GetRevocation(ctx, kind, key)
}

func (s cancelHonouringStore) DeleteTokens(ctx context.Context, k store.TokenKey) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.Store.DeleteTokens(ctx, k)
}

func (s cancelHonouringStore) PutToken(ctx context.Context, k store.TokenKey, t store.Token) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return s.Store.PutToken(ctx, k, t)
}

// A caller that hangs up mid-batch leaves nothing behind either: the check
// after the writes, and the deletes it orders, run without the caller's
// cancel.
func TestARevocationAfterTheCallerHungUpDeletesWhatItWrote(t *testing.T) {
	f := newFixture(t, 8)
	f.b.Store = cancelHonouringStore{f.st}
	p := f.pauseAt("PutToken", "nx1")
	ctx, hangUp := context.WithCancel(context.Background())
	answered := make(chan *httptest.ResponseRecorder, 1)
	go func() { answered <- f.post(ctx, f.state(f.alice), `{"devices":["leaf1","nx1"]}`, "01H") }()
	<-p.entered
	hangUp()
	f.revokeAndSweep(t, "user:alice@example.com")
	close(p.gate)
	// On the caller's context the check would fail store_unavailable and
	// leave leaf1's token.
	if w := <-answered; w.Code != http.StatusUnauthorized {
		t.Fatalf("%s", answer(w))
	}
	for _, d := range []string{"leaf1", "nx1"} {
		if n := f.live(t, d); n != 0 {
			t.Fatalf("%d token(s) survived on %s after the caller hung up", n, d)
		}
	}
}

// A revoked caller replaying a completed mint is refused before the replay:
// the record's tokens are not handed back.
func TestARevokedReplayReturnsNothing(t *testing.T) {
	f := newFixture(t, 8)
	decodeMint(t, f.post(context.Background(), f.state(f.alice), `{"devices":["leaf1"]}`, "01P"))
	f.revoke(t, store.RevocationPrincipal, "user:alice@example.com")
	w := f.post(context.Background(), f.state(f.alice), `{"devices":["leaf1"]}`, "01P")
	if w.Code != http.StatusUnauthorized || strings.Contains(w.Body.String(), `"login"`) {
		t.Fatalf("%s", answer(w))
	}
}

// A mark that lands while a replay is being answered: the replay wrote no
// token, but the check after still refuses it, and deletes the tokens the
// replay would have handed back. It recorded no permit, so its one deny
// names no device: a device deny would follow the original mint's permit,
// whose tokens were returned, and port49 capability would uncount them
// (Task 7 review N1).
func TestARevocationDuringAReplayReturnsNothing(t *testing.T) {
	f := newFixture(t, 8)
	decodeMint(t, f.post(context.Background(), f.state(f.alice), `{"devices":["leaf1"]}`, "01Q"))
	p := f.pauseAt("ReserveIdempotency", "")
	answered := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		answered <- f.post(context.Background(), f.state(f.alice), `{"devices":["leaf1"]}`, "01Q")
	}()
	<-p.entered
	f.revoke(t, store.RevocationPrincipal, "user:alice@example.com")
	close(p.gate)
	if w := <-answered; w.Code != http.StatusUnauthorized || strings.Contains(w.Body.String(), `"login"`) {
		t.Fatalf("%s", answer(w))
	}
	if n := f.live(t, "leaf1"); n != 0 {
		t.Fatalf("%d token(s) the refused replay named survived", n)
	}
	var denies []map[string]any
	for _, r := range f.records(t) {
		if r["event"] == "mint" && r["verdict"] == "deny" && r["reason"] == "credential_revoked" {
			denies = append(denies, r)
		}
	}
	if len(denies) != 1 || denies[0]["device"] != nil || denies[0]["principal"] != "user:alice@example.com" {
		t.Fatalf("the refused replay's denies: %v", denies)
	}
}

// A batch cut short as in progress — a later device's hold taken by a retry
// — still reads the marks after its writes: a mark that landed meanwhile
// deletes the devices it did mint and refuses it credential_revoked.
func TestARevocationBeforeABatchIsCutShortDeletesWhatItWrote(t *testing.T) {
	f := newFixture(t, 8)
	body := `{"devices":["leaf1","nx1"]}`
	p := f.pauseAt("PutToken", "leaf1")
	answered := make(chan *httptest.ResponseRecorder, 1)
	go func() { answered <- f.post(context.Background(), f.state(f.alice), body, "01C") }()
	<-p.entered
	// The first request's holds lapse, and a retry takes and mints both.
	f.advance(token.ReservationTTL + time.Second)
	decodeMint(t, f.post(context.Background(), f.state(f.alice), body, "01C"))
	f.revokeAndSweep(t, "user:alice@example.com")
	close(p.gate)
	if w := <-answered; w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "credential_revoked") {
		t.Fatalf("%s", answer(w))
	}
	if n := f.live(t, "leaf1"); n != 0 {
		t.Fatalf("%d token(s) survived on leaf1", n)
	}
}
