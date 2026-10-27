package broker

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/oidc/oidctest"
	"github.com/rhwendt/port49/internal/store"
)

func (f *fixture) revokeAs(t *testing.T, email, body string) *httptest.ResponseRecorder {
	t.Helper()
	return f.call(context.Background(), f.state(f.client(t, email, f.now.Add(time.Hour))), "POST",
		"/v1/tokens/revoke", body)
}

func decodeRevoke(t *testing.T, w *httptest.ResponseRecorder) api.RevokeResponse {
	t.Helper()
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	var r api.RevokeResponse
	if err := json.Unmarshal(w.Body.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	return r
}

// A caller with no right cannot revoke another principal: 403
// api_right_missing, one record naming the target and, in origin, the
// caller, with no auth (one credential per record; decision 34), and the
// target untouched (design §17).
func TestRevokingAnotherNeedsTheRight(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, sharedPolicy)
	ctx := context.Background()
	f.mintFor(t, "alice@example.com", "leaf1")
	w := f.revokeAs(t, "carol@example.com", `{"principal":"user:alice@example.com"}`)
	if w.Code != 403 || !strings.Contains(w.Body.String(), `"error":"api_right_missing"`) ||
		!strings.Contains(w.Body.String(), "revoke_others") {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	recs := eventsOf(f.records(t), "revoke")
	if len(recs) != 1 || recs[0]["reason"] != "api_right_missing" || recs[0]["principal"] != alicePrincipal ||
		recs[0]["auth"] != nil || recs[0]["revocation"].(map[string]any)["origin"] != "api user:carol@example.com" {
		t.Fatalf("%v", recs)
	}
	if got := tokensOf(t, f, store.TokenKey{NAS: "leaf1", Username: "alice"}); got[alicePrincipal] != 1 {
		t.Fatalf("alice's token was taken: %v", got)
	}
	if _, err := f.st.GetRevocation(ctx, store.RevocationPrincipal, alicePrincipal); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("a refused revocation left a mark")
	}
}

// The target is spelled as the broker spells it before it is compared with
// the caller: another principal in capitals is still another, and the
// caller's own in capitals is still the caller's (Review Focus 1).
func TestARevocationIsComparedAsTheBrokerSpellsIt(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, sharedPolicy)
	if w := f.revokeAs(t, "carol@example.com", `{"principal":"USER:Alice@Example.COM"}`); w.Code != 403 {
		t.Fatalf("another principal in capitals: %d %s", w.Code, w.Body)
	}
	r := decodeRevoke(t, f.revokeAs(t, "alice@example.com", `{"principal":"USER:Alice@Example.COM"}`))
	if r.By != "self" || r.Standing {
		t.Fatalf("the caller's own in capitals: %+v", r)
	}
}

// The caller's own principal, named as another's would be, is a self
// revocation, and the answer's first line says so before anything else:
// the CLI asked about a standing mark, and none was made (final review
// M2). mine is not told.
func TestTheCallersOwnPrincipalByNameSaysNoMarkWasMade(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, sharedPolicy)
	f.b.AdminSocket = "/run/port49/port49d.sock"
	const first = "this is your own principal: no mark was made; to lock it, ask an operator to use port49d's " +
		"admin socket (/run/port49/port49d.sock)\n"
	r := decodeRevoke(t, f.revokeAs(t, "alice@example.com", `{"principal":"user:alice@example.com"}`))
	if r.By != "self" || r.Standing || !strings.HasPrefix(r.Text, first) ||
		!strings.Contains(r.Text, "nothing stands against user:alice@example.com") {
		t.Fatalf("%+v", r)
	}
	if _, err := f.st.GetRevocation(context.Background(), store.RevocationPrincipal, alicePrincipal); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a mark was made: %v", err)
	}
	if r := decodeRevoke(t, f.revokeAs(t, "alice@example.com", `{"mine":true}`)); strings.Contains(r.Text, "your own principal") {
		t.Fatalf("mine: %q", r.Text)
	}
	f.b.AdminSocket = ""
	r = decodeRevoke(t, f.revokeAs(t, "alice@example.com", `{"principal":"user:alice@example.com"}`))
	if !strings.HasPrefix(r.Text, "this is your own principal: no mark was made; to lock it, port49d needs an "+
		"admin_socket, or an operator removes your grants from broker.policy_file\n") {
		t.Fatalf("with no admin socket: %q", r.Text)
	}
}

// {"mine": true}, or the caller's own principal, is a self-revocation: no
// mark, and the caller mints at once after it.
func TestMineIsASelfRevocation(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, sharedPolicy)
	f.mintFor(t, "alice@example.com", "leaf1")
	r := decodeRevoke(t, f.revokeAs(t, "alice@example.com", `{"mine":true}`))
	if r.By != "self" || r.Standing || r.TokenKeys != 1 || r.Saved != nil ||
		!strings.Contains(r.Text, "nothing stands against user:alice@example.com") ||
		!strings.Contains(r.Text, "close their session on the device") {
		t.Fatalf("%+v", r)
	}
	f.mintFor(t, "alice@example.com", "leaf1")
	r = decodeRevoke(t, f.revokeAs(t, "alice@example.com", `{"mine":true,"device":"leaf1","username":"alice"}`))
	if r.By != "self" || r.Device != "leaf1" || r.Username != "alice" || r.TokenKeys != 1 {
		t.Fatalf("mine on one key: %+v", r)
	}
}

// Under revoke_others, another principal is a standing mark with the caller
// as its origin, the answer naming the target's subject and where the mark
// is lifted, and the target's next mint is refused; a key is ended whoever
// holds it. Without the right a key is refused 403 and recorded with the
// key, never narrowed to the caller's own there (Review Focus 6;
// pre-flight I2); the caller's own on one key is mine with the key, which
// reaches nothing of alice's.
func TestRevokeOthersMarksAPrincipalAndEndsAKey(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, sharedPolicy)
	f.b.skipAdminProof = true // legacy: this test is about what a revocation does, not its proof
	ctx := context.Background()
	f.mintFor(t, "alice@example.com", "leaf1")
	f.liveContext(t, "leaf1", "alice", alicePrincipal, "")
	if w := f.revokeAs(t, "carol@example.com", `{"device":"leaf1","username":"alice"}`); w.Code != 403 ||
		!strings.Contains(w.Body.String(), `"error":"api_right_missing"`) {
		t.Fatalf("a peer's key revocation: %d %s", w.Code, w.Body)
	}
	recs := eventsOf(f.records(t), "revoke")
	if len(recs) != 1 || recs[0]["reason"] != "api_right_missing" || recs[0]["principal"] != nil || recs[0]["auth"] != nil {
		t.Fatalf("the peer's refusal: %v", recs)
	}
	if rv := recs[0]["revocation"].(map[string]any); rv["by"] != "key" || rv["device"] != "leaf1" ||
		rv["username"] != "alice" || rv["origin"] != "api user:carol@example.com" {
		t.Fatalf("the peer's refusal: %v", rv)
	}
	own := decodeRevoke(t, f.revokeAs(t, "carol@example.com", `{"mine":true,"device":"leaf1","username":"alice"}`))
	if own.By != "self" || own.TokenKeys != 0 || own.Contexts != 0 {
		t.Fatalf("the peer's own on alice's key: %+v", own)
	}
	if got := tokensOf(t, f, store.TokenKey{NAS: "leaf1", Username: "alice"}); got[alicePrincipal] != 1 {
		t.Fatalf("the peer reached alice's token: %v", got)
	}
	key := decodeRevoke(t, f.revokeAs(t, "bob@example.com", `{"device":"leaf1","username":"alice"}`))
	if key.By != "key" || key.TokenKeys != 1 || key.Contexts != 1 || key.Standing || key.Principal != alicePrincipal ||
		key.Subject != "netops" {
		t.Fatalf("bob's key revocation: %+v", key)
	}
	mark := decodeRevoke(t, f.revokeAs(t, "bob@example.com", `{"principal":"user:alice@example.com"}`))
	if mark.By != "principal" || !mark.Standing || mark.Saved == nil || mark.Subject != "netops" ||
		!strings.Contains(mark.Text, "port49d has no admin_socket configured: lifting this needs port49d stopped") {
		t.Fatalf("bob's revocation of alice: %+v", mark)
	}
	rv, err := f.st.GetRevocation(ctx, store.RevocationPrincipal, alicePrincipal)
	if err != nil || rv.Origin != "api user:bob@example.com" {
		t.Fatalf("the mark: %+v %v", rv, err)
	}
	if w := f.post(ctx, f.state(f.alice), `{"devices":["leaf1"]}`, ""); w.Code != 401 ||
		!strings.Contains(w.Body.String(), "credential_revoked") {
		t.Fatalf("alice's mint after the mark: %s", answer(w))
	}
	f.b.AdminSocket = "/run/port49/port49d.sock"
	again := decodeRevoke(t, f.revokeAs(t, "bob@example.com", `{"principal":"`+alice2+`"}`))
	if !strings.HasSuffix(again.Text, "the lift is made on port49d's admin socket (/run/port49/port49d.sock), "+
		"by port49d's user or root") {
		t.Fatalf("a mark with an admin socket: %s", again.Text)
	}
}

// A body naming no form, two forms, a sid, a lift, or a malformed device is
// refused 400, and nothing is revoked or recorded.
func TestARevocationBodyIsOneForm(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, sharedPolicy)
	for body, want := range map[string]string{
		`{}`: "name", `{"principal":"user:alice@example.com","device":"leaf1","username":"alice"}`: "not both",
		`{"mine":true,"principal":"user:alice@example.com"}`: "not both",
		`{"sid":"9c2b"}`: "OIDC", `{"principal":"user:alice@example.com","lift":true}`: "not a revocation request",
		`{"device":"leaf 1","username":"alice"}`: "printable", `{"device":"leaf1"}`: "name",
		`{"principal":"alice@example.com"}`:                   "begins user:",
		`{"mine":true}{"principal":"user:alice@example.com"}`: "not a revocation request",
		`{"mine":true} garbage`:                               "not a revocation request",
	} {
		w := f.revokeAs(t, "bob@example.com", body)
		if w.Code != 400 || !strings.Contains(w.Body.String(), want) {
			t.Errorf("%s: %d %s", body, w.Code, w.Body)
		}
	}
	if n := len(eventsOf(f.records(t), "revoke")); n != 0 {
		t.Fatalf("%d revoke records for refused bodies", n)
	}
}

// A revocation the store cannot record is 503 with a fixed sentence; the
// store's error goes to the process log, not to the caller. The way out it
// names is one that exists: port49 revoke on the admin socket, or, with
// none configured, the policy file (review M2).
func TestAMarkThatCannotBeWrittenIs503(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, sharedPolicy)
	f.b.skipAdminProof = true // legacy: this test is about what a revocation does, not its proof
	f.b.Store = putRevocationFails{f.st}
	for socket, want := range map[string]string{
		"": "port49d has no admin_socket configured, so meanwhile have an operator remove the principal's " +
			"grants from broker.policy_file",
		"/run/port49/port49d.sock": "ask an operator to run `port49 revoke` on port49d's admin socket " +
			"(/run/port49/port49d.sock)",
	} {
		f.b.AdminSocket = socket
		w := f.revokeAs(t, "bob@example.com", `{"principal":"user:alice@example.com"}`)
		if w.Code != 503 || !strings.Contains(w.Body.String(), "store_unavailable") ||
			strings.Contains(w.Body.String(), "disk on fire") || w.Header().Get("Retry-After") == "" ||
			!strings.Contains(w.Body.String(), want) {
			t.Fatalf("admin socket %q: %d %s", socket, w.Code, w.Body)
		}
		if socket == "" && strings.Contains(w.Body.String(), "port49 revoke") {
			t.Fatalf("no admin socket, yet port49 revoke is offered: %s", w.Body)
		}
	}
}

type putRevocationFails struct{ store.Store }

func (putRevocationFails) PutRevocation(context.Context, store.Revocation) error {
	return errors.New("disk on fire")
}

// A revocation that waits out its bound behind another revocation or lift
// is 503 revocation_busy, nothing revoked, never "may not have been recorded"
// (pre-flight M18).
func TestABusyRevocationIs503(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, sharedPolicy)
	f.b.skipAdminProof = true // legacy: this test is about what a revocation does, not its proof
	defer func(d time.Duration) { revokeSlotWait = d }(revokeSlotWait)
	revokeSlotWait = 50 * time.Millisecond
	release, err := f.b.acquireRevoke(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	w := f.revokeAs(t, "bob@example.com", `{"principal":"user:alice@example.com"}`)
	if w.Code != 503 || !strings.Contains(w.Body.String(), `"error":"revocation_busy"`) ||
		w.Header().Get("Retry-After") == "" {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if _, err := f.st.GetRevocation(context.Background(), store.RevocationPrincipal, alicePrincipal); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("a busy revocation left a mark")
	}
}

// tokensByPrincipalHangs holds the first TokensByPrincipal for principal
// until release closes, saying so on entered: a self-revocation behind a
// store that stopped answering. Later calls pass, so a run the limiter
// failed to stop answers rather than hangs.
type tokensByPrincipalHangs struct {
	store.Store
	principal string
	hung      *atomic.Bool
	entered   chan struct{}
	release   chan struct{}
}

func (s tokensByPrincipalHangs) TokensByPrincipal(ctx context.Context, principal string) ([]store.TokenKey, error) {
	if principal == s.principal && s.hung.CompareAndSwap(false, true) {
		close(s.entered)
		<-s.release
	}
	return s.Store.TokensByPrincipal(ctx, principal)
}

// A self or key revocation takes no revocation slot and runs detached, so
// one caller may have one in flight, not one per request: a second, in
// either form, is 503 revocation_busy and revokes nothing, another caller
// is not held up, and the slot is free again once the first finishes
// (ruling M4).
func TestOneSelfOrKeyRevocationInFlightPerCaller(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, sharedPolicy)
	f.b.skipAdminProof = true // legacy: this test is about what a revocation does, not its proof
	f.mintFor(t, "alice@example.com", "leaf1")
	hang := tokensByPrincipalHangs{Store: f.st, principal: "user:bob@example.com", hung: &atomic.Bool{}, entered: make(chan struct{}),
		release: make(chan struct{})}
	f.b.Store = hang
	bob := f.state(f.client(t, "bob@example.com", f.now.Add(time.Hour)))
	first := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		first <- f.call(context.Background(), bob, "POST", "/v1/tokens/revoke", `{"mine":true}`)
	}()
	select {
	case <-hang.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("bob's first revocation never reached the store")
	}
	for _, body := range []string{`{"mine":true}`, `{"device":"leaf1","username":"alice"}`,
		`{"principal":"user:bob@example.com"}`} {
		w := f.revokeAs(t, "bob@example.com", body)
		if w.Code != 503 || !strings.Contains(w.Body.String(), `"error":"revocation_busy"`) ||
			w.Header().Get("Retry-After") == "" {
			t.Fatalf("bob's second, %s: %d %s", body, w.Code, w.Body)
		}
	}
	if got := tokensOf(t, f, store.TokenKey{NAS: "leaf1", Username: "alice"}); got[alicePrincipal] != 1 {
		t.Fatalf("a busy key revocation reached alice's token: %v", got)
	}
	if r := decodeRevoke(t, f.revokeAs(t, "alice@example.com", `{"mine":true}`)); r.TokenKeys != 1 {
		t.Fatalf("alice behind bob's: %+v", r)
	}
	close(hang.release)
	select {
	case w := <-first:
		decodeRevoke(t, w)
	case <-time.After(5 * time.Second):
		t.Fatal("bob's first revocation never finished")
	}
	if r := decodeRevoke(t, f.revokeAs(t, "bob@example.com", `{"mine":true}`)); r.By != "self" {
		t.Fatalf("bob's after the first finished: %+v", r)
	}
	if n := len(eventsOf(f.records(t), "revoke")); n != 3 {
		t.Fatalf("%d revoke records, want 3: the busy ones write none", n)
	}
}

// On port49-broker the notes name its admin socket and its process, not
// port49d's: on etcd port49d's socket refuses revocations (Task 15a review
// M-6).
func TestTheRevokeNotesNameTheBrokersProcess(t *testing.T) {
	for _, socket := range []string{"", "/run/port49/broker.sock"} {
		b := &Broker{Proc: "port49-broker", AdminSocket: socket}
		for _, note := range []string{b.unrecordedNote(), b.ownNote(), b.liftNote()} {
			if strings.Contains(note, "port49d") || !strings.Contains(note, "port49-broker") ||
				(socket != "" && !strings.Contains(note, "port49-broker's admin socket ("+socket+")")) {
				t.Fatalf("admin socket %q: %s", socket, note)
			}
		}
	}
}

// The fallback a refused revocation names is the process's own: port49d's
// is to stop port49d, port49-broker's to stop every port49d, since the
// broker serves no device and stopping it cuts nothing. The busy error and
// the unrecorded one both carry it, and the unrecorded one names the
// process whose listener denies what the mark names (Task 18).
func TestARevocationsFallbackNamesTheProcess(t *testing.T) {
	for _, c := range []struct{ proc, stop, wrong string }{
		{"", "or stop port49d", "stop every port49d"},
		{"port49-broker", "or stop every port49d (port49-broker serves no device)", "this port49d"},
	} {
		f := newFixtureWithPolicy(t, 8, sharedPolicy)
		f.b.Proc = c.proc
		release, err := f.b.acquireRevoke(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		wait, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		_, err = f.b.Revoke(wait, RevokeRequest{Principal: alicePrincipal})
		cancel()
		release()
		if !errors.Is(err, ErrRevocationBusy) || !strings.HasSuffix(err.Error(), c.stop) ||
			strings.Contains(err.Error(), c.wrong) {
			t.Errorf("proc %q busy: %v", c.proc, err)
		}
		f.b.Store = putRevocationFails{f.st}
		_, err = f.b.Revoke(context.Background(), RevokeRequest{Principal: alicePrincipal})
		if err == nil || !strings.HasSuffix(err.Error(), c.stop) || strings.Contains(err.Error(), c.wrong) ||
			!strings.Contains(err.Error(), "this "+f.b.proc()+" denies what it names, until a lift on this "+f.b.proc()) {
			t.Errorf("proc %q unrecorded: %v", c.proc, err)
		}
	}
}

// A request that asks for a lift over the API is told where a lift is made:
// on the serving process's own admin socket (Task 18).
func TestALiftOverTheAPISaysWhichSocketLiftsPerProcess(t *testing.T) {
	for _, c := range []struct{ proc, want string }{
		{"", "a lift is port49d's admin socket's"},
		{"port49-broker", "a lift is port49-broker's admin socket's"},
	} {
		f := newFixtureWithPolicy(t, 8, sharedPolicy)
		f.b.Proc = c.proc
		w := f.revokeAs(t, "bob@example.com", `{"principal":"user:alice@example.com","lift":true}`)
		if w.Code != 400 || !strings.Contains(w.Body.String(), c.want) {
			t.Errorf("proc %q: %d %s", c.proc, w.Code, w.Body)
		}
	}
}

// A policy where carol, on call, holds revoke_others.
const onCallPolicy = `
scopes:
  - {name: all_devices, match: {}}
roles:
  - {name: network_admin, privilege: admin, permit: ["**"]}
subjects:
  - {name: netops, identity: ["user:alice@example.com"], username: alice, enable: token, token_ttl: 60s}
  - {name: oncall, identity: ["user:carol@example.com"], username: carol, token_ttl: 60s, api: [revoke_others]}
grants:
  - {subject: netops, scope: all_devices, roles: [network_admin], max_privilege: admin}
  - {subject: oncall, scope: all_devices, roles: [network_admin], max_privilege: admin}
`

func (f *fixture) carolToken(t *testing.T, iss *oidctest.Issuer) string {
	t.Helper()
	return iss.IDToken(t, "k1", testClientID, "sub-carol", f.b.Now(), map[string]any{"preferred_username": "carol@example.com"})
}

func TestRevokeBySidNeedsTheRightAndEndsTheSession(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, onCallPolicy)
	f.b.skipAdminProof = true // legacy: this test is about what a revocation does, not its proof
	iss := f.withOIDC(t)
	ctx := context.Background()
	now := f.b.Now()
	if w := f.bearer(ctx, "POST", "/v1/tokens", mintLeaf1, f.idToken(t, iss, nil)); w.Code != 200 {
		t.Fatalf("alice's mint: %d %s", w.Code, w.Body)
	}
	f.liveContextAt(t, "nx1", "alice", alicePrincipal, "", now, now.Add(12*time.Hour))
	if err := f.st.IndexContext(ctx, alicePrincipal, store.SidKey(iss.URL, "s-sub-alice"), "",
		store.ContextRef{NAS: "nx1", Username: "alice"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	body := `{"sid":"s-sub-alice"}`
	// alice herself holds no right: 403, recorded, nothing ended.
	if w := f.bearer(ctx, "POST", "/v1/tokens/revoke", body, f.idToken(t, iss, nil)); w.Code != 403 ||
		!strings.Contains(w.Body.String(), "api_right_missing") {
		t.Fatalf("without the right: %d %s", w.Code, w.Body)
	}
	w := f.bearer(ctx, "POST", "/v1/tokens/revoke", body, f.carolToken(t, iss))
	var resp api.RevokeResponse
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &resp) != nil {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if resp.By != "sid" || resp.Principal != alicePrincipal || resp.Standing || resp.Contexts != 1 || resp.TokenKeys != 1 ||
		!strings.Contains(resp.Text, "s-sub-alice") {
		t.Fatalf("response %+v", resp)
	}
	revs := eventsOf(f.records(t), decision.EventRevoke)
	if rv := revs[len(revs)-1]["revocation"].(map[string]any); rv["origin"] != "api user:carol@example.com" {
		t.Fatalf("origin %v", rv["origin"])
	}
}

// The call Task 12's operator line (logoutByHand) tells an operator to make:
// the sid with its issuer, both named.
func TestRevokeBySidTakesTheShapeTheOperatorLineNames(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, onCallPolicy)
	f.b.skipAdminProof = true // legacy: this test is about what a revocation does, not its proof
	iss := f.withOIDC(t)
	body := `{"sid": "s-sub-alice", "issuer": "` + iss.URL + `"}`
	if w := f.bearer(context.Background(), "POST", "/v1/tokens/revoke", body, f.carolToken(t, iss)); w.Code != 200 {
		t.Fatalf("the operator line's call: %d %s", w.Code, w.Body)
	}
}

// Pre-flight M-15: a revocation by sid takes the asker's one revocation
// slot, so a retry while one runs is 503 revocation_busy and ends nothing.
func TestRevokeBySidHoldsTheAskersSlot(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, onCallPolicy)
	f.b.skipAdminProof = true // legacy: this test is about what a revocation does, not its proof
	iss := f.withOIDC(t)
	release, ok := f.b.holdOwnRevoke("user:carol@example.com")
	if !ok {
		t.Fatal("the slot was taken")
	}
	w := f.bearer(context.Background(), "POST", "/v1/tokens/revoke", `{"sid":"s-sub-alice"}`, f.carolToken(t, iss))
	release()
	if w.Code != 503 || !strings.Contains(w.Body.String(), "revocation_busy") {
		t.Fatalf("a sid revocation while carol's slot is held: %d %s", w.Code, w.Body)
	}
}

func TestRevokeBySidRefusesWhatItCannotName(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, onCallPolicy)
	f.b.skipAdminProof = true // legacy: this test is about what a revocation does, not its proof
	iss := f.withOIDC(t)
	carol := f.carolToken(t, iss)
	for _, c := range []struct{ body, says string }{
		{`{"sid":"s","principal":"user:alice@example.com"}`, "name a sid alone"},
		{`{"sid":"s","mine":true}`, "name a sid alone"},
		{`{"sid":"s","device":"leaf1","username":"alice"}`, "name a sid alone"},
		{`{"sid":"s","issuer":"https://not-configured.example"}`, "no human OIDC verifier's"},
		{`{"issuer":"` + iss.URL + `"}`, "name the sid"},
		// Without its guard this is a standing ban on alice, the issuer dropped.
		{`{"issuer":"` + iss.URL + `","principal":"user:alice@example.com"}`, "name the sid"},
		{`{"sid":"has space"}`, "printable ASCII"},
		{`{"sid":"` + strings.Repeat("a", 256) + `"}`, "printable ASCII"},
	} {
		w := f.bearer(context.Background(), "POST", "/v1/tokens/revoke", c.body, carol)
		if w.Code != 400 || !strings.Contains(w.Body.String(), c.says) {
			t.Errorf("%s: %d %s", c.body, w.Code, w.Body)
		}
	}
	if n := len(eventsOf(f.records(t), decision.EventRevoke)); n != 0 {
		t.Errorf("a refused request wrote %d revoke record(s)", n)
	}
	// 255 is the longest sid taken.
	if w := f.bearer(context.Background(), "POST", "/v1/tokens/revoke",
		`{"sid":"`+strings.Repeat("a", 255)+`"}`, carol); w.Code != 200 {
		t.Errorf("a 255-character sid: %d %s", w.Code, w.Body)
	}
}

// I1: a logout whose record the store cannot write ended nothing, and says
// so: 503, never a 200 "ended".
func TestRevokeBySidWithTheStoreDownIsNotAnAnswerOfSuccess(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, onCallPolicy)
	f.b.skipAdminProof = true // legacy: this test is about what a revocation does, not its proof
	iss := f.withOIDC(t)
	f.b.Store = hookStore{Store: f.st, before: map[string]func() error{
		"PutLogout": func() error { return store.ErrUnavailable }}}
	w := f.bearer(context.Background(), "POST", "/v1/tokens/revoke", `{"sid":"s-sub-alice"}`, f.carolToken(t, iss))
	if w.Code != 503 || w.Header().Get("Retry-After") != "10" || !strings.Contains(w.Body.String(), "store_unavailable") ||
		!strings.Contains(w.Body.String(), "nothing was revoked") {
		t.Fatalf("%d %v %s", w.Code, w.Header(), w.Body)
	}
	if n := len(eventsOf(f.records(t), decision.EventRevoke)); n != 0 {
		t.Fatalf("a logout that did not apply wrote %d revoke record(s)", n)
	}
}

// M2: with two human verifiers a bare sid names no provider; guessing the
// first would end the wrong one's session.
func TestRevokeBySidNeedsItsIssuerWithTwoProviders(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, onCallPolicy)
	f.b.skipAdminProof = true // legacy: this test is about what a revocation does, not its proof
	iss := f.withOIDC(t)
	f.addIssuer(t, oidctest.NewIssuer(t), "example.com", false)
	w := f.bearer(context.Background(), "POST", "/v1/tokens/revoke", `{"sid":"s-sub-alice"}`, f.carolToken(t, iss))
	if w.Code != 400 || !strings.Contains(w.Body.String(), "name the sid's issuer") {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	body := `{"sid":"s-sub-alice","issuer":"` + iss.URL + `"}`
	if w := f.bearer(context.Background(), "POST", "/v1/tokens/revoke", body, f.carolToken(t, iss)); w.Code != 200 {
		t.Fatalf("with its issuer: %d %s", w.Code, w.Body)
	}
}

// M4: a sid whose owner record names two principals ends both, and the
// answer names both.
func TestRevokeBySidAnswerNamesEveryOwnerPrincipal(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, onCallPolicy)
	f.b.skipAdminProof = true // legacy: this test is about what a revocation does, not its proof
	iss := f.withOIDC(t)
	ctx := context.Background()
	const alice2 = "user:alice2@example.com"
	for _, p := range []string{alicePrincipal, alice2} {
		if err := f.st.PutOIDCOwner(ctx, store.SidKey(iss.URL, "s-sub-alice"), p, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	w := f.bearer(ctx, "POST", "/v1/tokens/revoke", `{"sid":"s-sub-alice"}`, f.carolToken(t, iss))
	var resp api.RevokeResponse
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &resp) != nil {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if !strings.Contains(resp.Text, alicePrincipal) || !strings.Contains(resp.Text, alice2) {
		t.Fatalf("the text names one owner only: %s", resp.Text)
	}
}

// With no human OIDC verifier there is no sid to end: a clear 400, never a
// 503 that reads like a store fault.
func TestRevokeBySidWithNoVerifierIsARefusalNotAStoreFault(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, onCallPolicy)
	w := f.revokeAs(t, "carol@example.com", `{"sid":"s-sub-alice"}`)
	if w.Code != 400 || strings.Contains(w.Body.String(), "store_unavailable") {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}
