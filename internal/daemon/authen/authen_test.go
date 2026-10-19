package authen

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/rhwendt/port49/internal/daemon/limits"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/session"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/crypt"
	"github.com/rhwendt/port49/internal/store/memory"
	"github.com/rhwendt/port49/internal/tacacs/wire"
	"github.com/rhwendt/port49/internal/token"
)

// labTagKey is the fixture's tag key. No token literal is written down: every
// secret in these tests is the device's own tag followed by filler, so a change
// to the tag derivation fails the tests rather than passing on a stale string.
var labTagKey = token.TagKey([]byte("labkey"))

// labTags is the window the fixture's handler accepts. One key: a second one is
// what TestRotatedEncryptionKeyKeepsItsTags is for.
var labTags = token.NewTagWindow(labTagKey)

type fixture struct {
	h    *Handler
	st   *memory.Store
	log  *bytes.Buffer
	now  time.Time
	peer Peer
	// m is the handler's own metrics, kept so a test can read a counter the
	// handler is expected to move.
	m *metrics.Metrics
}

func setup(t *testing.T) *fixture {
	t.Helper()
	return setupStore(t, func(st *memory.Store) store.Store { return st })
}

// tag is the device tag every token in this fixture carries: the peer is
// leaf-01, so a credential tagged for anything else is a device_mismatch.
func (f *fixture) tag() string { return token.Tag(labTagKey, "leaf-01") }

// setupStore is setup with a decorator hook: it builds and seeds the memory
// store exactly as setup does, then hands wrap(st) to New, so a test can drive
// a store fault without duplicating the fixture. f.st stays the memory store,
// so the tests keep reading records out of it directly.
func setupStore(t *testing.T, wrap func(*memory.Store) store.Store) *fixture {
	t.Helper()
	f := &fixture{log: &bytes.Buffer{}, now: time.Unix(1_757_041_495, 0), peer: Peer{NAS: "leaf-01", NASAddr: "10.20.0.7", Platform: "arista_eos"}}
	f.st = memory.New(func() time.Time { return f.now })
	ids := 0
	l := limits.New(limits.Config{AuthFailureDelayBase: time.Millisecond, AuthFailureDelayMax: 2 * time.Millisecond, AuthFailureWindow: time.Minute}, func() time.Time { return f.now })
	f.m = metrics.New(prometheus.NewRegistry())
	f.h = New(wrap(f.st), decision.NewJSONLines(f.log), l, f.m,
		func() time.Time { return f.now }, func() string { ids++; return "ctx" + string(rune('0'+ids)) },
		15*time.Minute, 2*time.Hour, time.Hour, time.Hour, labTags)
	if _, err := f.st.PutToken(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"},
		// Enable and MaxPrivilege are the shape a real mint produces (spec
		// §5.1.1): the login context they land on is escalatable, so a test
		// about the enable path reaches the enable path.
		store.Token{ID: "t1", Secret: []byte(f.tag() + "tok1tok1tok1tok1tok1tok1"), Kind: store.KindLogin,
			Username: "alice", Principal: "user:alice@example.com", Enable: "token", MaxPrivilege: 15,
			ExpiresAt: f.now.Add(15 * time.Minute)}); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fixture) records(t *testing.T) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(f.log.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatal(err)
		}
		out = append(out, m)
	}
	return out
}

func TestPAPRedeemsAndCreatesContext(t *testing.T) {
	f := setup(t)
	s := f.h.NewSession(f.peer)
	reply, done := s.Start(context.Background(), wire.AuthenStart{Action: wire.AuthenActionLogin, PrivLvl: 1,
		AuthenType: wire.AuthenTypePAP, Service: wire.AuthenServiceLogin,
		User: []byte("Alice"), Port: []byte("vty0"), RemAddr: []byte("198.51.100.4"), Data: []byte(f.tag() + "tok1tok1tok1tok1tok1tok1")})
	if !done || reply.Status != wire.AuthenStatusPass {
		t.Fatalf("reply %+v done %v", reply, done)
	}
	c, err := f.st.GetContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"})
	if err != nil || c.Username != "alice" || c.RemAddr != "198.51.100.4" || c.CtxID != "ctx1" {
		t.Fatalf("context %+v err %v", c, err)
	}
	if cands, _ := f.st.Candidates(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"}); len(cands) != 0 {
		t.Fatal("token not consumed")
	}
	r := f.records(t)
	if len(r) != 1 || r[0]["event"] != "redeem" || r[0]["verdict"] != "permit" || r[0]["reason"] != "token_redeemed" {
		t.Fatalf("%v", r)
	}
	if r[0]["session"].(map[string]any)["username"] != "alice" {
		t.Fatalf("session.username: %v", r[0]["session"])
	}
	if strings.Contains(f.log.String(), f.tag()+"tok1tok1tok1tok1tok1tok1") {
		t.Fatal("token leaked into the log")
	}
}

func TestRetransmissionReplaysReceipt(t *testing.T) {
	f := setup(t)
	start := wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP, Service: wire.AuthenServiceLogin,
		User: []byte("alice"), Port: []byte("vty0"), Data: []byte(f.tag() + "tok1tok1tok1tok1tok1tok1")}
	f.h.NewSession(f.peer).Start(context.Background(), start)
	reply, _ := f.h.NewSession(f.peer).Start(context.Background(), start)
	if reply.Status != wire.AuthenStatusPass {
		t.Fatalf("retry must PASS from the receipt: %+v", reply)
	}
	r := f.records(t)
	if r[1]["reason"] != "receipt_replayed" || r[1]["session"].(map[string]any)["ctx_id"] != "ctx1" {
		t.Fatalf("%v", r[1])
	}
	// Same device and username, different credential: the receipt must not
	// stand in for the check. Since the hash is in the receipt key (spec §13,
	// decision 15) this no longer collides with alice's receipt at all — it
	// misses, looks for a token of its own, and finds none. Before the re-key
	// the reason here was credential_mismatch; the deny is the same, and so is
	// the property being guarded.
	start.Data = []byte("something-else")
	reply, _ = f.h.NewSession(f.peer).Start(context.Background(), start)
	if reply.Status != wire.AuthenStatusFail || f.records(t)[2]["reason"] != "token_not_found" {
		t.Fatalf("%+v %v", reply, f.records(t)[2])
	}
}

func TestUnknownTokenFails(t *testing.T) {
	f := setup(t)
	reply, done := f.h.NewSession(f.peer).Start(context.Background(), wire.AuthenStart{Action: wire.AuthenActionLogin,
		AuthenType: wire.AuthenTypePAP, Service: wire.AuthenServiceLogin, User: []byte("alice"), Port: []byte("vty1"), Data: []byte("wrong")})
	if !done || reply.Status != wire.AuthenStatusFail || f.records(t)[0]["reason"] != "token_not_found" {
		t.Fatalf("%+v %v", reply, f.records(t))
	}
}

func TestASCIIMultiRound(t *testing.T) {
	f := setup(t)
	s := f.h.NewSession(f.peer)
	r1, done := s.Start(context.Background(), wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypeASCII,
		Service: wire.AuthenServiceLogin, Port: []byte("vty0")})
	if done || r1.Status != wire.AuthenStatusGetUser {
		t.Fatalf("%+v", r1)
	}
	r2, done := s.Continue(context.Background(), wire.AuthenContinue{UserMsg: []byte("alice")})
	if done || r2.Status != wire.AuthenStatusGetPass || r2.Flags&wire.AuthenReplyFlagNoEcho == 0 {
		t.Fatalf("%+v", r2)
	}
	r3, done := s.Continue(context.Background(), wire.AuthenContinue{UserMsg: []byte(f.tag() + "tok1tok1tok1tok1tok1tok1")})
	if !done || r3.Status != wire.AuthenStatusPass {
		t.Fatalf("%+v", r3)
	}
	if strings.Contains(f.log.String(), f.tag()+"tok1tok1tok1tok1tok1tok1") {
		t.Fatal("password leaked into the log")
	}
}

func TestASCIIAbort(t *testing.T) {
	f := setup(t)
	s := f.h.NewSession(f.peer)
	s.Start(context.Background(), wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypeASCII, Service: wire.AuthenServiceLogin})
	_, done := s.Continue(context.Background(), wire.AuthenContinue{Flags: wire.AuthenContinueFlagAbort})
	if !done || len(f.records(t)) != 0 {
		t.Fatal("abort must end the session without a record")
	}
}

func TestCHAP(t *testing.T) {
	f := setup(t)
	challenge := []byte("0123456789abcdef")
	sum := md5.Sum(append(append([]byte{0x2a}, []byte(f.tag()+"tok1tok1tok1tok1tok1tok1")...), challenge...))
	data := append(append([]byte{0x2a}, challenge...), sum[:]...)
	reply, done := f.h.NewSession(f.peer).Start(context.Background(), wire.AuthenStart{Action: wire.AuthenActionLogin,
		AuthenType: wire.AuthenTypeCHAP, Service: wire.AuthenServiceLogin, User: []byte("alice"), Port: []byte("vty0"), Data: data})
	if !done || reply.Status != wire.AuthenStatusPass {
		t.Fatalf("%+v", reply)
	}
	// A re-prompt with a fresh challenge does not match the receipt and fails (design §8).
	sum2 := md5.Sum(append(append([]byte{0x2b}, []byte(f.tag()+"tok1tok1tok1tok1tok1tok1")...), []byte("fedcba9876543210")...))
	data2 := append(append([]byte{0x2b}, []byte("fedcba9876543210")...), sum2[:]...)
	reply, _ = f.h.NewSession(f.peer).Start(context.Background(), wire.AuthenStart{Action: wire.AuthenActionLogin,
		AuthenType: wire.AuthenTypeCHAP, Service: wire.AuthenServiceLogin, User: []byte("alice"), Port: []byte("vty0"), Data: data2})
	if reply.Status != wire.AuthenStatusFail {
		t.Fatalf("fresh challenge must not replay: %+v", reply)
	}

	for _, leak := range []struct {
		name string
		want []byte
	}{
		{"challenge raw", challenge},
		{"challenge hex", []byte(hex.EncodeToString(challenge))},
		{"response raw", sum[:]},
		{"response hex", []byte(hex.EncodeToString(sum[:]))},
	} {
		if strings.Contains(f.log.String(), string(leak.want)) {
			t.Fatalf("%s leaked into the log", leak.name)
		}
	}
}

// TestLoginTokenLaterInSetIsFound guards against the fix for Important 1: the
// candidate search must not stop at the first token whose kind doesn't match.
func TestLoginTokenLaterInSetIsFound(t *testing.T) {
	f := setup(t)
	if _, err := f.st.PutToken(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "bob"},
		store.Token{ID: "bob_enable", Secret: []byte("bob_enable_tok"), Kind: store.KindEnable, Principal: "user:bob@example.com", ExpiresAt: f.now.Add(15 * time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.PutToken(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "bob"},
		store.Token{ID: "bob_login", Secret: []byte("bob_login_tok"), Kind: store.KindLogin, Principal: "user:bob@example.com", ExpiresAt: f.now.Add(15 * time.Minute)}); err != nil {
		t.Fatal(err)
	}

	reply, done := f.h.NewSession(f.peer).Start(context.Background(), wire.AuthenStart{Action: wire.AuthenActionLogin,
		AuthenType: wire.AuthenTypePAP, Service: wire.AuthenServiceLogin, User: []byte("bob"), Port: []byte("vty0"), Data: []byte("bob_login_tok")})
	if !done || reply.Status != wire.AuthenStatusPass {
		t.Fatalf("%+v", reply)
	}
}

func TestEnableStartWithLoginTokenIsKindMismatch(t *testing.T) {
	f := setup(t)
	// The enable gate is open — alice is logged in, with an `enable: token`
	// context under her ceiling — so what this test asks about is the kind of
	// the credential and nothing else.
	f.seedLogin(t, "token", 15)
	// alice has only a login token (from setup). Presenting it at enable is a
	// kind mismatch, not a missing token.
	reply, done := f.h.NewSession(f.peer).Start(context.Background(), wire.AuthenStart{Action: wire.AuthenActionLogin,
		AuthenType: wire.AuthenTypePAP, Service: wire.AuthenServiceEnable, User: []byte("alice"), Port: []byte("vty0"), Data: []byte(f.tag() + "tok1tok1tok1tok1tok1tok1")})
	if !done || reply.Status != wire.AuthenStatusFail || f.records(t)[0]["reason"] != "token_kind_mismatch" {
		t.Fatalf("%+v %v", reply, f.records(t))
	}

	// An enable START with a credential that matches nothing at all is a plain miss.
	reply, done = f.h.NewSession(f.peer).Start(context.Background(), wire.AuthenStart{Action: wire.AuthenActionLogin,
		AuthenType: wire.AuthenTypePAP, Service: wire.AuthenServiceEnable, User: []byte("alice"), Port: []byte("vty1"), Data: []byte("unknown")})
	if !done || reply.Status != wire.AuthenStatusFail || f.records(t)[1]["reason"] != "token_not_found" {
		t.Fatalf("%+v %v", reply, f.records(t))
	}
}

func TestUnsupportedAuthenTypeIsErrorWithRecord(t *testing.T) {
	f := setup(t)
	reply, done := f.h.NewSession(f.peer).Start(context.Background(), wire.AuthenStart{Action: wire.AuthenActionLogin,
		AuthenType: wire.AuthenTypeMSCHAP, Service: wire.AuthenServiceLogin, User: []byte("alice"), Port: []byte("vty0")})
	if !done || reply.Status != wire.AuthenStatusError {
		t.Fatalf("%+v", reply)
	}
	r := f.records(t)
	if len(r) != 1 || r[0]["event"] != "redeem" || r[0]["verdict"] != "deny" || r[0]["reason"] != "service_unsupported" {
		t.Fatalf("%v", r)
	}
}

// erroringCandidatesStore wraps a real store.Store but fails Candidates, to
// exercise the ERROR/store_unavailable path without a real backend failure.
type erroringCandidatesStore struct {
	store.Store
	err error
}

func (e *erroringCandidatesStore) Candidates(context.Context, store.TokenKey) ([]store.Token, error) {
	return nil, e.err
}

func TestStoreErrorIsErrorWithRecord(t *testing.T) {
	log := &bytes.Buffer{}
	now := time.Unix(1_757_041_495, 0)
	mem := memory.New(func() time.Time { return now })
	st := &erroringCandidatesStore{Store: mem, err: errors.New("store: connection refused")}
	l := limits.New(limits.Config{AuthFailureDelayBase: time.Millisecond, AuthFailureDelayMax: 2 * time.Millisecond, AuthFailureWindow: time.Minute}, func() time.Time { return now })
	ids := 0
	h := New(st, decision.NewJSONLines(log), l, metrics.New(prometheus.NewRegistry()),
		func() time.Time { return now }, func() string { ids++; return "ctx" + string(rune('0'+ids)) },
		15*time.Minute, 2*time.Hour, time.Hour, time.Hour, labTags)

	tok := token.Tag(labTagKey, "leaf-01") + "tok1tok1tok1tok1tok1tok1"
	reply, done := h.NewSession(Peer{NAS: "leaf-01", NASAddr: "10.20.0.7", Platform: "arista_eos"}).Start(context.Background(),
		wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP, Service: wire.AuthenServiceLogin,
			User: []byte("alice"), Port: []byte("vty0"), Data: []byte(tok)})
	if !done || reply.Status != wire.AuthenStatusError {
		t.Fatalf("%+v", reply)
	}

	lines := strings.Split(strings.TrimSpace(log.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("records: %v", lines)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &m); err != nil {
		t.Fatal(err)
	}
	if m["event"] != "redeem" || m["verdict"] != "deny" || m["reason"] != "store_unavailable" {
		t.Fatalf("%v", m)
	}
	if strings.Contains(log.String(), tok) {
		t.Fatal("token leaked into the log")
	}
}

func TestShortCHAPDataFailsWithDelayAndRecord(t *testing.T) {
	f := setup(t)
	reply, done := f.h.NewSession(f.peer).Start(context.Background(), wire.AuthenStart{Action: wire.AuthenActionLogin,
		AuthenType: wire.AuthenTypeCHAP, Service: wire.AuthenServiceLogin, User: []byte("alice"), Port: []byte("vty0"), Data: []byte{0x2a}})
	if !done || reply.Status != wire.AuthenStatusFail {
		t.Fatalf("%+v", reply)
	}
	r := f.records(t)
	if len(r) != 1 || r[0]["reason"] != "token_not_found" {
		t.Fatalf("%v", r)
	}
	auth, ok := r[0]["auth"].(map[string]any)
	if !ok || auth["credential_sha256"] == "" {
		t.Fatalf("missing credential hash: %v", r[0])
	}
}

func TestSessionIsTerminalAfterFinish(t *testing.T) {
	f := setup(t)
	s := f.h.NewSession(f.peer)
	reply, done := s.Start(context.Background(), wire.AuthenStart{Action: wire.AuthenActionLogin,
		AuthenType: wire.AuthenTypePAP, Service: wire.AuthenServiceLogin, User: []byte("alice"), Port: []byte("vty0"), Data: []byte(f.tag() + "tok1tok1tok1tok1tok1tok1")})
	if !done || reply.Status != wire.AuthenStatusPass {
		t.Fatalf("%+v", reply)
	}
	// A second Start on the same finished session must not resume the exchange.
	reply, done = s.Start(context.Background(), wire.AuthenStart{Action: wire.AuthenActionLogin,
		AuthenType: wire.AuthenTypePAP, Service: wire.AuthenServiceLogin, User: []byte("alice"), Port: []byte("vty0"), Data: []byte(f.tag() + "tok1tok1tok1tok1tok1tok1")})
	if !done || reply.Status != wire.AuthenStatusError {
		t.Fatalf("%+v", reply)
	}
	r := f.records(t)
	if r[1]["reason"] != "service_unsupported" {
		t.Fatalf("%v", r[1])
	}
}

// noStore panics on every call, so a test built on it fails loudly if the
// code under test ever reaches the store.
type noStore struct{}

func (noStore) PutToken(context.Context, store.TokenKey, store.Token) (int, error) {
	panic("store called")
}
func (noStore) Candidates(context.Context, store.TokenKey) ([]store.Token, error) {
	panic("store called")
}
func (noStore) RedeemAndReceipt(context.Context, store.TokenKey, string, store.ReceiptWrite) error {
	panic("store called")
}
func (noStore) DeleteTokens(context.Context, store.TokenKey) error {
	panic("store called")
}
func (noStore) DeleteToken(context.Context, store.TokenKey, string) error {
	panic("store called")
}
func (noStore) PurgeTokens(context.Context) (int, error) {
	panic("store called")
}
func (noStore) GetReceipt(context.Context, store.ReceiptKey) (store.Receipt, error) {
	panic("store called")
}
func (noStore) ExtendReceipt(context.Context, store.ReceiptKey, time.Time) error {
	panic("store called")
}
func (noStore) FailReceipt(context.Context, store.ReceiptKey) error {
	panic("store called")
}
func (noStore) DeleteReceiptsByPrincipal(context.Context, string) (int, error) {
	panic("store called")
}
func (noStore) PutContext(context.Context, store.ContextKey, store.Context, time.Duration) error {
	panic("store called")
}
func (noStore) SwapContext(context.Context, store.ContextKey, uint64, store.Context, time.Duration) error {
	panic("store called")
}
func (noStore) SwapLogin(context.Context, store.ContextKey, uint64, store.Context, time.Duration, store.LoginWrite) error {
	panic("store called")
}
func (noStore) GetContext(context.Context, store.ContextKey) (store.Context, error) {
	panic("store called")
}
func (noStore) TouchContext(context.Context, store.ContextKey, time.Duration) error {
	panic("store called")
}
func (noStore) SetPrivilege(context.Context, store.ContextKey, uint8) error {
	panic("store called")
}
func (noStore) DeleteContext(context.Context, store.ContextKey) error {
	panic("store called")
}
func (noStore) DeleteContextIf(context.Context, store.ContextKey, uint64) error {
	panic("store called")
}
func (noStore) PutBlob(context.Context, string, []byte, time.Duration) error {
	panic("store called")
}
func (noStore) GetBlob(context.Context, string) ([]byte, error) {
	panic("store called")
}
func (noStore) BumpBlob(context.Context, string, time.Duration) error {
	panic("store called")
}
func (noStore) IndexContext(context.Context, string, string, string, store.ContextRef, time.Duration) error {
	panic("store called")
}
func (noStore) UnindexContext(context.Context, string, string, string, store.ContextRef) error {
	panic("store called")
}
func (noStore) UnindexRef(context.Context, store.ContextRef) error {
	panic("store called")
}
func (noStore) ContextsByPrincipal(context.Context, string) ([]store.ContextRef, error) {
	panic("store called")
}
func (noStore) ContextsBySid(context.Context, string) ([]store.ContextRef, error) {
	panic("store called")
}
func (noStore) ContextsByCert(context.Context, string) ([]store.ContextRef, error) {
	panic("store called")
}
func (noStore) ReindexSid(context.Context, string, string, store.ContextRef, time.Duration) error {
	panic("store called")
}
func (noStore) ActivePrincipals(context.Context) ([]string, error) {
	panic("store called")
}
func (noStore) IndexToken(context.Context, string, string, store.TokenKey, time.Duration) error {
	panic("store called")
}
func (noStore) TokensByPrincipal(context.Context, string) ([]store.TokenKey, error) {
	panic("store called")
}
func (noStore) TokensByCert(context.Context, string) ([]store.TokenKey, error) {
	panic("store called")
}
func (noStore) ReserveIdempotency(context.Context, string, string, store.Idempotency) (store.Idempotency, bool, error) {
	panic("store called")
}
func (noStore) CompleteIdempotency(context.Context, string, string, string, store.Idempotency) error {
	panic("store called")
}
func (noStore) ReleaseIdempotency(context.Context, string, string, string) error {
	panic("store called")
}
func (noStore) PutRevocation(context.Context, store.Revocation) error {
	panic("store called")
}
func (noStore) GetRevocation(context.Context, string, string) (store.Revocation, error) {
	panic("store called")
}
func (noStore) DeleteRevocation(context.Context, string, string) error {
	panic("store called")
}
func (noStore) ListRevocations(context.Context) ([]store.Revocation, error) {
	panic("store called")
}

func (noStore) AnnotateContext(context.Context, store.ContextKey, string, string) error {
	panic("store called")
}

func (noStore) RefreshContext(context.Context, store.ContextKey, store.ContextRefresh, time.Duration) error {
	panic("store called")
}

func (noStore) SetRevokedAt(context.Context, store.ContextKey, time.Time) error {
	panic("store called")
}

func (noStore) RewriteContext(context.Context, store.ContextKey, uint64, store.Context, time.Duration, bool) error {
	panic("RewriteContext called")
}

func (noStore) SetContextPolicy(context.Context, store.ContextKey, uint64, store.ContextPolicy) error {
	panic("store called")
}

func (noStore) StampRefreshed(context.Context, store.ContextKey, uint64, time.Time) error {
	panic("store called")
}

func (noStore) SupersedeTokens(context.Context, store.TokenKey, time.Time) error {
	panic("store called")
}

func (noStore) SupersedeAll(context.Context, time.Time) error {
	panic("store called")
}

func (noStore) SupersededAt(context.Context, store.TokenKey) (time.Time, error) {
	panic("store called")
}

func (noStore) PutMembership(context.Context, store.Membership, time.Duration) error {
	panic("store called")
}

func (noStore) PutPin(context.Context, store.Membership, store.PinExpect) error {
	panic("store called")
}

func (noStore) RefuseMapKeys(context.Context, []string, time.Time, time.Duration) error {
	panic("store called")
}

func (noStore) GetMembership(context.Context, string) (store.Membership, error) {
	panic("store called")
}

func (noStore) MembershipByKey(context.Context, string) (store.Membership, error) {
	panic("store called")
}

func (noStore) MembershipPrincipals(context.Context) ([]string, error) {
	panic("store called")
}

func (noStore) DeleteMembership(context.Context, string) (store.Membership, error) {
	panic("store called")
}

func (noStore) PutOnce(context.Context, string, []byte, time.Duration) (bool, error) {
	panic("store called")
}

func (noStore) TakeOnce(context.Context, string) ([]byte, error) { panic("store called") }

func (noStore) PutOIDCOwner(context.Context, string, string, time.Duration) error {
	panic("store called")
}

func (noStore) OIDCOwner(context.Context, string) (store.OIDCOwner, error) { panic("store called") }

func (noStore) PutLogout(context.Context, store.Logout, time.Duration) error { panic("store called") }

func (noStore) GetLogout(context.Context, string) (store.Logout, error) { panic("store called") }

func (noStore) PutMFAProof(context.Context, store.MFAProof, time.Duration) error {
	panic("store called")
}

func (noStore) GetMFAProof(context.Context, string) (store.MFAProof, error) { panic("store called") }

func (noStore) NoteSignInAttempt(context.Context, string, time.Duration) (int, time.Time, error) {
	panic("store called")
}

func (noStore) UndoSignInAttempt(context.Context, string) error { panic("store called") }

func (noStore) ClearSignInAttempts(context.Context, string) (int, error) { panic("store called") }

var _ store.Store = noStore{}

func TestEmptyCanonicalUsernameFailsWithoutStoreLookup(t *testing.T) {
	log := &bytes.Buffer{}
	now := time.Unix(1_757_041_495, 0)
	l := limits.New(limits.Config{AuthFailureDelayBase: time.Millisecond, AuthFailureDelayMax: 2 * time.Millisecond, AuthFailureWindow: time.Minute}, func() time.Time { return now })
	ids := 0
	h := New(noStore{}, decision.NewJSONLines(log), l, metrics.New(prometheus.NewRegistry()),
		func() time.Time { return now }, func() string { ids++; return "ctx" + string(rune('0'+ids)) },
		15*time.Minute, 2*time.Hour, time.Hour, time.Hour, labTags)

	// "@corp.example.com" canonicalizes to "" (spec §2): everything before the
	// first "@" is stripped, leaving nothing.
	reply, done := h.NewSession(Peer{NAS: "leaf-01", NASAddr: "10.20.0.7", Platform: "arista_eos"}).Start(context.Background(),
		wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP, Service: wire.AuthenServiceLogin,
			User: []byte("@corp.example.com"), Port: []byte("vty0"), Data: []byte("whatever")})
	if !done || reply.Status != wire.AuthenStatusFail {
		t.Fatalf("%+v", reply)
	}
	r := []map[string]any{}
	for _, line := range strings.Split(strings.TrimSpace(log.String()), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatal(err)
		}
		r = append(r, m)
	}
	if len(r) != 1 || r[0]["reason"] != "token_not_found" {
		t.Fatalf("%v", r)
	}
}

func TestFailDelayIsCancellable(t *testing.T) {
	f := setup(t)
	// A long failure delay, then a cancelled context: the FAIL reply must
	// return promptly rather than waiting out the full delay.
	f.h.limits = limits.New(limits.Config{AuthFailureDelayBase: time.Hour, AuthFailureDelayMax: time.Hour, AuthFailureWindow: time.Minute}, func() time.Time { return f.now })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	reply, done := f.h.NewSession(f.peer).Start(ctx, wire.AuthenStart{Action: wire.AuthenActionLogin,
		AuthenType: wire.AuthenTypePAP, Service: wire.AuthenServiceLogin, User: []byte("alice"), Port: []byte("vty1"), Data: []byte("wrong")})
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("fail did not honor context cancellation: took %s", elapsed)
	}
	if !done || reply.Status != wire.AuthenStatusFail {
		t.Fatalf("%+v", reply)
	}
}

// A client that re-presents the same credential slides the window; one that
// stops for longer than the idle TTL does not. Both bounds are driven.
func TestReceiptSlidesThenExpiresOnIdle(t *testing.T) {
	f := setup(t)
	start := wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte("alice"), Port: []byte("vty0"), Data: []byte(f.tag() + "tok1tok1tok1tok1tok1tok1")}
	if reply, _ := f.h.NewSession(f.peer).Start(context.Background(), start); reply.Status != wire.AuthenStatusPass {
		t.Fatalf("first redemption: %+v", reply)
	}
	// Four re-presentations 10 minutes apart: 40 minutes on a 15-minute idle
	// TTL, which a fixed window could never carry.
	for i := 0; i < 4; i++ {
		f.now = f.now.Add(10 * time.Minute)
		reply, _ := f.h.NewSession(f.peer).Start(context.Background(), start)
		if reply.Status != wire.AuthenStatusPass {
			t.Fatalf("slide %d: %+v", i, reply)
		}
		r := f.records(t)
		if last := r[len(r)-1]; last["reason"] != "receipt_replayed" {
			t.Fatalf("slide %d: %v", i, last)
		}
	}
	f.now = f.now.Add(16 * time.Minute) // past the sliding bound
	reply, _ := f.h.NewSession(f.peer).Start(context.Background(), start)
	r := f.records(t)
	if reply.Status != wire.AuthenStatusFail || r[len(r)-1]["reason"] != "token_spent" {
		t.Fatalf("idle bound: %+v %v", reply, r[len(r)-1])
	}
}

func TestReceiptStopsAtTheAbsoluteCap(t *testing.T) {
	f := setup(t)
	start := wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte("alice"), Port: []byte("vty0"), Data: []byte(f.tag() + "tok1tok1tok1tok1tok1tok1")}
	f.h.NewSession(f.peer).Start(context.Background(), start)
	// Present every 10 minutes for two hours: the idle bound never lapses, so
	// only the cap can stop it. The iteration is asserted rather than just the
	// final reason, so the test pins *when* the cap bites (t = 2h exactly, at
	// i == 11) and not merely that it eventually does.
	for i := 0; i < 13; i++ {
		f.now = f.now.Add(10 * time.Minute)
		// The session is live and authorizing, which is what extends its
		// context (author.Handle's TouchContext). Without it this fixture's
		// one-hour context TTL would reclaim the context at 60 minutes, and
		// a replay onto a reclaimed context is token_spent (spec §5.6) —
		// which is not the cap this test pins.
		if err := f.st.TouchContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"}, time.Hour); err != nil {
			t.Fatalf("at i=%d: %v", i, err)
		}
		reply, _ := f.h.NewSession(f.peer).Start(context.Background(), start)
		r := f.records(t)
		gotStatus, gotReason := reply.Status, r[len(r)-1]["reason"]
		wantStatus, wantReason := uint8(wire.AuthenStatusPass), any("receipt_replayed")
		if elapsed := time.Duration(i+1) * 10 * time.Minute; elapsed >= 2*time.Hour {
			wantStatus, wantReason = wire.AuthenStatusFail, "token_spent"
		}
		if gotStatus != wantStatus || gotReason != wantReason {
			t.Fatalf("at t=%s (i=%d): got %d/%v, want %d/%v",
				time.Duration(i+1)*10*time.Minute, i, gotStatus, gotReason, wantStatus, wantReason)
		}
	}
	// And the token is not resurrected by the cap: it stays spent.
	if c, _ := f.st.Candidates(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"}); len(c) != 0 {
		t.Fatalf("token set: %+v", c)
	}
}

// The wire outcome is FAIL, exactly as a wrong password is; only the log tells
// the two apart (spec §5.7).
func TestTokenSpentIsIndistinguishableOnTheWire(t *testing.T) {
	f := setup(t)
	start := wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte("alice"), Port: []byte("vty0"), Data: []byte(f.tag() + "tok1tok1tok1tok1tok1tok1")}
	f.h.NewSession(f.peer).Start(context.Background(), start)
	// Past the cap (2h) and inside retention (RetainUntil is 2h15m), so the
	// receipt is still FOUND and the path under test is token_spent. At 3h the
	// receipt has been swept and the seeded token has expired, and the test
	// would pass on token_not_found — a different reason, which §5.7 draws the
	// distinction between and which this test exists to cover.
	f.now = f.now.Add(2*time.Hour + time.Minute)
	spent, _ := f.h.NewSession(f.peer).Start(context.Background(), start)
	r := f.records(t)
	if r[len(r)-1]["reason"] != "token_spent" {
		t.Fatalf("this test must drive token_spent, not %v", r[len(r)-1]["reason"])
	}
	wrong, _ := f.h.NewSession(f.peer).Start(context.Background(), wire.AuthenStart{Action: wire.AuthenActionLogin,
		AuthenType: wire.AuthenTypePAP, Service: wire.AuthenServiceLogin, User: []byte("alice"), Port: []byte("vty0"), Data: []byte("hunter2")})
	if spent.Status != wrong.Status || spent.Status != wire.AuthenStatusFail {
		t.Fatalf("spent %+v wrong %+v", spent, wrong)
	}
}

// A revoked principal's receipts are deleted (Task 13), and the credential that
// earned them must not still be answered PASS from one.
func TestRevokedPrincipalsReceiptNoLongerReplays(t *testing.T) {
	f := setup(t)
	start := wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte("alice"), Port: []byte("vty0"), Data: []byte(f.tag() + "tok1tok1tok1tok1tok1tok1")}
	if reply, _ := f.h.NewSession(f.peer).Start(context.Background(), start); reply.Status != wire.AuthenStatusPass {
		t.Fatalf("%+v", reply)
	}
	if n, err := f.st.DeleteReceiptsByPrincipal(context.Background(), "user:alice@example.com"); err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	reply, _ := f.h.NewSession(f.peer).Start(context.Background(), start)
	r := f.records(t)
	// token_not_found, not token_spent: revocation deleted the receipt, and the
	// token behind it was consumed by the redemption above, so the presentation
	// falls all the way through to an empty candidate set. Pinned so a change
	// that makes revocation answer something else is noticed here.
	if reply.Status != wire.AuthenStatusFail || r[len(r)-1]["reason"] != "token_not_found" {
		t.Fatalf("a revoked credential must not replay: %+v %v", reply, r[len(r)-1])
	}
}

// gonePastTheReadStore answers GetReceipt normally and then loses the receipt
// before the extend, which is what a revocation landing in that window looks
// like from inside redeem.
type gonePastTheReadStore struct{ *memory.Store }

func (gonePastTheReadStore) ExtendReceipt(context.Context, store.ReceiptKey, time.Time) error {
	return store.ErrNotFound
}

// The same revocation, landing in the window between the receipt read and the
// extend. ErrNotFound from ExtendReceipt cannot mean "swept": RetainUntil is
// later than both bounds and both bounds have just been checked, so the only
// deleter left is revocation. Answering PASS here hands out a decision the
// identity layer has already withdrawn.
func TestExtendMissingTheReceiptDeniesRatherThanReplays(t *testing.T) {
	f := setupStore(t, func(st *memory.Store) store.Store { return gonePastTheReadStore{st} })
	start := wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte("alice"), Port: []byte("vty0"), Data: []byte(f.tag() + "tok1tok1tok1tok1tok1tok1")}
	f.h.NewSession(f.peer).Start(context.Background(), start)
	reply, _ := f.h.NewSession(f.peer).Start(context.Background(), start)
	r := f.records(t)
	if reply.Status != wire.AuthenStatusFail || r[len(r)-1]["reason"] != "token_spent" {
		t.Fatalf("%+v %v", reply, r[len(r)-1])
	}
}

// extendCountingStore records every ExtendReceipt, so a test can assert that a
// presentation the handler refused did not also slide the window on its way to
// the refusal.
type extendCountingStore struct {
	*memory.Store
	extends int
}

func (e *extendCountingStore) ExtendReceipt(ctx context.Context, rk store.ReceiptKey, idleExpiresAt time.Time) error {
	e.extends++
	return e.Store.ExtendReceipt(ctx, rk, idleExpiresAt)
}

// A receipt answers only presentations of the kind that earned it. Without the
// kind in the receipt key, an enable START presenting the LOGIN token's secret
// finds alice's login receipt, is answered PASS `receipt_replayed` carrying the
// login ctx_id, and slides the window on every retry: privilege out of a
// credential the cold path refuses, with no `escalate` record and no
// `token_kind_mismatch` to alert on. The kind check at `Candidates` is not a
// gate if a live receipt can be presented instead of passing through it.
func TestLoginReceiptDoesNotAnswerAnEnableStart(t *testing.T) {
	var counter *extendCountingStore
	f := setupStore(t, func(st *memory.Store) store.Store {
		counter = &extendCountingStore{Store: st}
		return counter
	})
	login := wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte("alice"), Port: []byte("vty0"), Data: []byte(f.tag() + "tok1tok1tok1tok1tok1tok1")}
	if reply, _ := f.h.NewSession(f.peer).Start(context.Background(), login); reply.Status != wire.AuthenStatusPass {
		t.Fatalf("first redemption: %+v", reply)
	}

	// The same credential, the same device, the same user, inside the window —
	// but presented at enable, which is a different question.
	enable := login
	enable.Service = wire.AuthenServiceEnable
	reply, _ := f.h.NewSession(f.peer).Start(context.Background(), enable)
	r := f.records(t)
	// The login token was spent by the redemption above, so the enable START
	// falls through to an empty candidate set: token_not_found, which is the
	// cold answer. What matters is that it is a FAIL reached through the
	// candidate search and never PASS out of the login receipt.
	if reply.Status != wire.AuthenStatusFail || r[len(r)-1]["reason"] != "token_not_found" {
		t.Fatalf("an enable START must not be answered from the login receipt: %+v %v", reply, r[len(r)-1])
	}
	if counter.extends != 0 {
		t.Fatalf("a refused enable START slid the login receipt: %d extends", counter.extends)
	}

	// And the login receipt itself is untouched: the login credential still
	// replays as it did, on its own key.
	f.now = f.now.Add(time.Minute)
	if reply, _ := f.h.NewSession(f.peer).Start(context.Background(), login); reply.Status != wire.AuthenStatusPass {
		t.Fatalf("the login receipt must survive the enable attempt: %+v", reply)
	}
}

func TestDeviceMismatchByTag(t *testing.T) {
	f := setup(t)
	wrong := token.Tag(labTagKey, "leaf-99") + "tok1tok1tok1tok1tok1tok1"
	reply, done := f.h.NewSession(f.peer).Start(context.Background(), wire.AuthenStart{Action: wire.AuthenActionLogin,
		AuthenType: wire.AuthenTypePAP, Service: wire.AuthenServiceLogin, User: []byte("alice"),
		Port: []byte("vty0"), Data: []byte(wrong)})
	if !done || reply.Status != wire.AuthenStatusFail || f.records(t)[0]["reason"] != "device_mismatch" {
		t.Fatalf("%+v %v", reply, f.records(t))
	}
}

// The tag is compared before any store access at all (design §8), so a token
// cut for another device never reaches the receipt lookup or the candidate
// search: noStore panics if it does.
func TestDeviceMismatchTouchesNoStore(t *testing.T) {
	log := &bytes.Buffer{}
	now := time.Unix(1_757_041_495, 0)
	l := limits.New(limits.Config{AuthFailureDelayBase: time.Millisecond, AuthFailureDelayMax: 2 * time.Millisecond, AuthFailureWindow: time.Minute}, func() time.Time { return now })
	h := New(noStore{}, decision.NewJSONLines(log), l, metrics.New(prometheus.NewRegistry()),
		func() time.Time { return now }, func() string { return "ctx1" },
		15*time.Minute, 2*time.Hour, time.Hour, time.Hour, labTags)
	reply, done := h.NewSession(Peer{NAS: "leaf-01", NASAddr: "10.20.0.7", Platform: "arista_eos"}).Start(context.Background(),
		wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP, Service: wire.AuthenServiceLogin,
			User: []byte("alice"), Port: []byte("vty0"), Data: []byte(token.Tag(labTagKey, "leaf-99") + "tok1tok1tok1tok1tok1tok1")})
	if !done || reply.Status != wire.AuthenStatusFail {
		t.Fatalf("%+v", reply)
	}
	if !strings.Contains(log.String(), `"reason":"device_mismatch"`) {
		t.Fatalf("%s", log.String())
	}
}

func TestMistypedPasswordIsNotFoundNotMismatch(t *testing.T) {
	f := setup(t)
	f.h.NewSession(f.peer).Start(context.Background(), wire.AuthenStart{Action: wire.AuthenActionLogin,
		AuthenType: wire.AuthenTypePAP, Service: wire.AuthenServiceLogin, User: []byte("alice"),
		Port: []byte("vty0"), Data: []byte("hunter2")})
	if f.records(t)[0]["reason"] != "token_not_found" {
		t.Fatalf("%v", f.records(t)[0])
	}
}

// Under CHAP the daemon never sees the token, so the tag is invisible and a
// wrong-device credential is token_not_found (design §8).
//
// The exclusion is by method, not by shape, and this test holds that gate: the
// second half hands the CHAP path a blob that IS token-shaped and tagged for
// another device. A digest is ppp_id ‖ challenge ‖ response and has no reason
// to be Len bytes of base62 — but nothing stops it, and without the method gate
// the tag check would fire on one and report a wrong device for a credential
// the daemon never actually saw. Deleting `method != methodCHAP` must fail here.
func TestCHAPNeverReportsDeviceMismatch(t *testing.T) {
	f := setup(t)
	wrong := token.Tag(labTagKey, "leaf-99") + "tok1tok1tok1tok1tok1tok1"
	m := md5.New()
	m.Write([]byte{7})
	m.Write([]byte(wrong))
	m.Write([]byte("challenge"))
	data := append([]byte{7}, append([]byte("challenge"), m.Sum(nil)...)...)
	f.h.NewSession(f.peer).Start(context.Background(), wire.AuthenStart{Action: wire.AuthenActionLogin,
		AuthenType: wire.AuthenTypeCHAP, Service: wire.AuthenServiceLogin, User: []byte("alice"),
		Port: []byte("vty0"), Data: data})
	if f.records(t)[0]["reason"] != "token_not_found" {
		t.Fatalf("%v", f.records(t)[0])
	}

	// Long enough to pass verifyCHAP's length check (1 + challenge + 16) and
	// token-shaped all the same, which is the coincidence the method gate
	// exists for. It matches no token — the last 16 bytes are not a valid
	// digest for anything — so the outcome must be the cold token_not_found.
	shaped := []byte(token.Tag(labTagKey, "leaf-99") + "tok1tok1tok1tok1tok1tok1")
	if _, ok := token.Parse(shaped); !ok {
		t.Fatal("the fixture must be token-shaped or this test proves nothing")
	}
	f.h.NewSession(f.peer).Start(context.Background(), wire.AuthenStart{Action: wire.AuthenActionLogin,
		AuthenType: wire.AuthenTypeCHAP, Service: wire.AuthenServiceLogin, User: []byte("alice"),
		Port: []byte("vty0"), Data: shaped})
	if r := f.records(t)[1]; r["reason"] != "token_not_found" {
		t.Fatalf("CHAP must never report a device: %v", r)
	}
}

func TestContextCarriesSessionFieldsAndIsIndexed(t *testing.T) {
	f := setup(t)
	secret := f.tag() + "fullfullfullfullfull0123"
	if _, err := f.st.PutToken(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"},
		store.Token{ID: "full", Secret: []byte(secret), Kind: store.KindLogin, Username: "alice",
			Principal: "user:alice@example.com", BlobHash: "sha256:b", MaxSessionAge: 8 * time.Hour,
			AuthTime: f.now, Enable: "token", MaxPrivilege: 15,
			Credential: store.Credential{Method: "oidc", Sid: "s1", Sub: "a7f3", Issuer: "ca", Serial: "01"},
			ExpiresAt:  f.now.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	f.h.NewSession(f.peer).Start(context.Background(), wire.AuthenStart{Action: wire.AuthenActionLogin,
		AuthenType: wire.AuthenTypePAP, Service: wire.AuthenServiceLogin, User: []byte("alice"),
		Port: []byte("ssh"), RemAddr: []byte("198.51.100.4"), Data: []byte(secret)})
	c, err := f.st.GetContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"})
	if err != nil || c.Principal != "user:alice@example.com" || c.BlobHash != "sha256:b" || c.Enable != "token" ||
		c.MaxPrivilege != 15 || !c.SessionExpires.Equal(f.now.Add(8*time.Hour)) || !c.RefreshedAt.Equal(f.now) ||
		c.Credential.Sid != "s1" || c.Port != "ssh" || c.RemAddr != "198.51.100.4" {
		t.Fatalf("%+v %v", c, err)
	}
	// CreatedAt and LastTouchedAt are both stamped at the write. LastTouchedAt
	// is what Task 10 reads to decide whether an extension is due, so a zero
	// here would cost a store write per command.
	if !c.CreatedAt.Equal(f.now) || !c.LastTouchedAt.Equal(f.now) {
		t.Fatalf("created_at %v last_touched_at %v", c.CreatedAt, c.LastTouchedAt)
	}
	// The record carries the principal, which is the join from a redeem to
	// everything the session does later.
	if p := f.records(t)[0]["principal"]; p != "user:alice@example.com" {
		t.Fatalf("principal on the record: %v", p)
	}
	ref := store.ContextRef{NAS: "leaf-01", Username: "alice"}
	if refs, _ := f.st.ContextsByPrincipal(context.Background(), "user:alice@example.com"); len(refs) != 1 || refs[0] != ref {
		t.Fatalf("principal index: %v", refs)
	}
	if refs, _ := f.st.ContextsBySid(context.Background(), "s1"); len(refs) != 1 {
		t.Fatalf("sid index: %v", refs)
	}
	if refs, _ := f.st.ContextsByCert(context.Background(), store.CertKey("ca", "01")); len(refs) != 1 {
		t.Fatalf("cert index: %v", refs)
	}
}

// max_session_age: never must be expressible (spec §5.6): a zero
// MaxSessionAge leaves SessionExpires zero, and Task 10 reads that as no
// ceiling rather than as "expired at the epoch".
func TestNoMaxSessionAgeLeavesNoCeiling(t *testing.T) {
	f := setup(t)
	f.h.NewSession(f.peer).Start(context.Background(), wire.AuthenStart{Action: wire.AuthenActionLogin,
		AuthenType: wire.AuthenTypePAP, Service: wire.AuthenServiceLogin, User: []byte("alice"),
		Port: []byte("vty0"), Data: []byte(f.tag() + "tok1tok1tok1tok1tok1tok1")})
	c, _ := f.st.GetContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"})
	if !c.SessionExpires.IsZero() {
		t.Fatalf("a token with no ceiling must not create one: %+v", c)
	}
}

// The converse, and the direction that matters: a token that DOES carry a
// ceiling must produce a bounded session. The dangerous failure is silent —
// a dropped ceiling leaves SessionExpires zero, which Task 10 reads as
// `max_session_age: never`, so an 8h token becomes an unbounded one that looks
// exactly like a legitimate one. A ceiling with no AuthTime to anchor it is
// therefore still computed: it lands in the distant past, and the login is
// refused session_expired at redeem, with no context written — loud, rather
// than permitting forever quietly.
func TestACeilingIsNeverSilentlyDropped(t *testing.T) {
	for _, tc := range []struct {
		name     string
		authTime time.Time
		want     time.Time
	}{
		{"anchored", time.Unix(1_757_041_495, 0), time.Unix(1_757_041_495, 0).Add(8 * time.Hour)},
		{"no anchor", time.Time{}, time.Time{}.Add(8 * time.Hour)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := setup(t)
			secret := f.tag() + "ceilceilceilceilceil0123"
			if _, err := f.st.PutToken(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"},
				store.Token{ID: "ceiling", Secret: []byte(secret), Kind: store.KindLogin, Username: "alice",
					Principal: "user:alice@example.com", MaxSessionAge: 8 * time.Hour, AuthTime: tc.authTime,
					ExpiresAt: f.now.Add(time.Minute)}); err != nil {
				t.Fatal(err)
			}
			f.h.NewSession(f.peer).Start(context.Background(), wire.AuthenStart{Action: wire.AuthenActionLogin,
				AuthenType: wire.AuthenTypePAP, Service: wire.AuthenServiceLogin, User: []byte("alice"),
				Port: []byte("vty0"), Data: []byte(secret)})
			c, err := f.st.GetContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"})
			if tc.authTime.IsZero() {
				if r := f.records(t)[0]; !errors.Is(err, store.ErrNotFound) || r["reason"] != "session_expired" {
					t.Fatalf("a ceiling with no anchor opened a session: %v %v", err, r)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if c.SessionExpires.IsZero() {
				t.Fatalf("a ceiling became `never`: %+v", c)
			}
			if !c.SessionExpires.Equal(tc.want) {
				t.Fatalf("session_expires %v, want %v", c.SessionExpires, tc.want)
			}
		})
	}
}

// capturingStore keeps the Context the handler handed to SwapContext, before
// any store stamped anything on it.
type capturingStore struct {
	*memory.Store
	got store.Context
}

func (c *capturingStore) SwapContext(ctx context.Context, k store.ContextKey, rev uint64, v store.Context, ttl time.Duration) error {
	c.got = v
	return c.Store.SwapContext(ctx, k, rev, v, ttl)
}

func (c *capturingStore) SwapLogin(ctx context.Context, k store.ContextKey, rev uint64, v store.Context, ttl time.Duration,
	w store.LoginWrite) error {
	c.got = v
	return c.Store.SwapLogin(ctx, k, rev, v, ttl, w)
}

// memory.SwapContext stamps LastTouchedAt itself, so reading the context back
// cannot tell whether the handler set it. Task 10 reads that field to decide
// whether an extension is due, and a backend that does not stamp it would
// leave a zero there and cost a store write per command — so the handler's own
// stamp is asserted where the store cannot supply it.
func TestTheHandlerStampsTheContextClocksItself(t *testing.T) {
	var cs *capturingStore
	f := setupStore(t, func(st *memory.Store) store.Store { cs = &capturingStore{Store: st}; return cs })
	f.h.NewSession(f.peer).Start(context.Background(), wire.AuthenStart{Action: wire.AuthenActionLogin,
		AuthenType: wire.AuthenTypePAP, Service: wire.AuthenServiceLogin, User: []byte("alice"),
		Port: []byte("vty0"), Data: []byte(f.tag() + "tok1tok1tok1tok1tok1tok1")})
	if !cs.got.CreatedAt.Equal(f.now) || !cs.got.LastTouchedAt.Equal(f.now) || !cs.got.RefreshedAt.Equal(f.now) {
		t.Fatalf("%+v", cs.got)
	}
}

// indexFailsStore answers everything normally but never indexes a context,
// which is what a store that is up but refusing the index write looks like
// from inside redeem.
type indexFailsStore struct{ *memory.Store }

func (indexFailsStore) IndexContext(context.Context, string, string, string, store.ContextRef, time.Duration) error {
	return errors.New("index unavailable")
}

// A login is indexed by its own write (SwapLogin), never by a separate
// IndexContext call: with IndexContext failing, the login still PASSes,
// its context is found under its principal, and the record carries no
// index_error (plan 7d; decision 35; PR #7's third follow-up).
func TestALoginIsIndexedByItsOwnWrite(t *testing.T) {
	f := setupStore(t, func(st *memory.Store) store.Store { return indexFailsStore{st} })
	reply, _ := f.h.NewSession(f.peer).Start(context.Background(), wire.AuthenStart{Action: wire.AuthenActionLogin,
		AuthenType: wire.AuthenTypePAP, Service: wire.AuthenServiceLogin, User: []byte("alice"),
		Port: []byte("vty0"), Data: []byte(f.tag() + "tok1tok1tok1tok1tok1tok1")})
	if reply.Status != wire.AuthenStatusPass {
		t.Fatalf("status %d, want PASS", reply.Status)
	}
	if rec := f.records(t)[0]; rec["index_error"] != nil {
		t.Fatalf("record: %v", rec)
	}
	if refs, _ := f.st.ContextsByPrincipal(context.Background(), "user:alice@example.com"); len(refs) != 1 {
		t.Fatalf("the login's own write indexed %d refs, want 1", len(refs))
	}
}

// swapLoginFails answers everything normally but never writes a login:
// a store that is up for reads and refuses the one step that writes the
// context with its index.
type swapLoginFails struct{ *memory.Store }

func (swapLoginFails) SwapLogin(context.Context, store.ContextKey, uint64, store.Context, time.Duration,
	store.LoginWrite) error {
	return errors.New("store unavailable")
}

// A login whose context and index cannot be written together is refused
// ERROR store_unavailable, never admitted with a context no revocation
// can reach (plan 7d; decision 35). Before plan 7d it was a PASS with
// index_error.
func TestALoginThatCannotBeIndexedIsRefused(t *testing.T) {
	f := setupStore(t, func(st *memory.Store) store.Store { return swapLoginFails{st} })
	reply, _ := f.h.NewSession(f.peer).Start(context.Background(), wire.AuthenStart{Action: wire.AuthenActionLogin,
		AuthenType: wire.AuthenTypePAP, Service: wire.AuthenServiceLogin, User: []byte("alice"),
		Port: []byte("vty0"), Data: []byte(f.tag() + "tok1tok1tok1tok1tok1tok1")})
	if reply.Status != wire.AuthenStatusError {
		t.Fatalf("status %d, want ERROR", reply.Status)
	}
	rec := f.records(t)[0]
	if rec["reason"] != "store_unavailable" || rec["index_error"] != nil {
		t.Fatalf("record: %v", rec)
	}
	if refs, _ := f.st.ContextsByPrincipal(context.Background(), "user:alice@example.com"); len(refs) != 0 {
		t.Fatalf("an unindexed login left refs: %v", refs)
	}
	if _, err := f.st.GetContext(context.Background(), store.ContextKey{NAS: f.peer.NAS, Username: "alice"}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("an unindexed login left a context: %v", err)
	}
}

// A login by a principal a standing mark names is refused
// credential_revoked, and the context it wrote is revoked at the mark:
// the redemption that raced a revocation (spec §5.1.4; decision 35).
func TestALoginUnderAStandingMarkIsRefused(t *testing.T) {
	f := setupStore(t, func(st *memory.Store) store.Store { return st })
	at := f.now.Add(-time.Second)
	if err := f.st.PutRevocation(context.Background(), store.Revocation{Kind: store.RevocationPrincipal,
		Key: "user:alice@example.com", At: at, Origin: "test"}); err != nil {
		t.Fatal(err)
	}
	f.h.NewSession(f.peer).Start(context.Background(), wire.AuthenStart{Action: wire.AuthenActionLogin,
		AuthenType: wire.AuthenTypePAP, Service: wire.AuthenServiceLogin, User: []byte("alice"),
		Port: []byte("vty0"), Data: []byte(f.tag() + "tok1tok1tok1tok1tok1tok1")})
	rec := f.records(t)[0]
	if rec["reason"] != "credential_revoked" {
		t.Fatalf("record: %v", rec)
	}
	c, err := f.st.GetContext(context.Background(), store.ContextKey{NAS: f.peer.NAS, Username: "alice"})
	if err != nil || !c.RevokedAt.Equal(at) {
		t.Fatalf("context %+v %v", c, err)
	}
}

// getRevocationFailsOnce errs on the first mark read and answers every
// later one: the store blinks during a login's join and is back for the
// retransmission.
type getRevocationFailsOnce struct {
	*memory.Store
	mu     sync.Mutex
	failed bool
}

func (g *getRevocationFailsOnce) GetRevocation(ctx context.Context, kind, key string) (store.Revocation, error) {
	g.mu.Lock()
	first := !g.failed
	g.failed = true
	g.mu.Unlock()
	if first {
		return store.Revocation{}, errors.New("store unavailable")
	}
	return g.Store.GetRevocation(ctx, kind, key)
}

// certBToken puts window B's login token, for certificate ca|0b, under
// alice: the credential a join that fails never writes into window A's
// context or its index.
func (f *fixture) certBToken(t *testing.T) wire.AuthenStart {
	t.Helper()
	secret := f.tag() + "certBcertBcertBcertBcert"
	if _, err := f.st.PutToken(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"},
		store.Token{ID: "b", Secret: []byte(secret), Kind: store.KindLogin, Username: "alice",
			Principal:  "user:alice@example.com",
			Credential: store.Credential{Method: "cert", Issuer: "ca", Serial: "0b"}, Enable: "token",
			MaxPrivilege: 15, MintedAt: f.now.Add(-time.Minute), ExpiresAt: f.now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	return papStart("alice", "ssh", "198.51.100.4", secret)
}

// markCertB stands a mark for window B's certificate in the store, which
// the join reads, and in marks, the daemon's copy, when marks is not nil.
func (f *fixture) markCertB(t *testing.T, marks *store.Marks) {
	t.Helper()
	mark := store.Revocation{Kind: store.RevocationCert, Key: store.CertKey("ca", "0b"), At: f.now.Add(-time.Second),
		Origin: "test"}
	if err := f.st.PutRevocation(context.Background(), mark); err != nil {
		t.Fatal(err)
	}
	marks.Set(mark, true)
}

// A join that ERRORs leaves no PASS for a retransmission to replay (Task 3
// review I2; spec §5.6). The receipt is written PASS before the join,
// naming window A's context, and the join that failed never wrote window
// B's certificate into it or its index. A retransmission finds the
// receipt, but the certificate index does not reach the context, so the
// login did not commit: token_spent, and the token is not redeemed again.
func TestAJoinThatErrorsLeavesNoPassToReplay(t *testing.T) {
	g := &getRevocationFailsOnce{}
	f := setupStore(t, func(st *memory.Store) store.Store { g.Store = st; return g })
	f.joinFixture(t, nil)
	start := f.certBToken(t)
	f.markCertB(t, nil)
	if reply, _ := f.h.NewSession(f.peer).Start(context.Background(), start); reply.Status != wire.AuthenStatusError {
		t.Fatalf("the join whose mark read failed: %+v %v", reply, f.records(t))
	}
	// The principal is the join an incident responder needs to find whose
	// login ERRORed after its token was spent (Task 4 review M1).
	if rec := f.records(t)[0]; rec["reason"] != "store_unavailable" || rec["principal"] != "user:alice@example.com" {
		t.Fatalf("the failed join's record: %v", rec)
	}
	reply, _ := f.h.NewSession(f.peer).Start(context.Background(), start)
	if rec := f.records(t)[1]; reply.Status != wire.AuthenStatusFail || rec["reason"] != "token_spent" {
		t.Fatalf("a retransmission after a join that ERRORed: %+v %v", reply, rec)
	}
	if c, _ := f.st.GetContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"}); c.Credential.Serial == "0b" {
		t.Fatalf("the failed join wrote window B's credential: %+v", c)
	}
}

// The same retransmission, with the certificate's mark in the daemon's
// marks: refused credential_revoked, from the presented credential's own
// mark, though window A's context names another certificate and is not
// revoked (Task 4 review I3; plan 7d). Before the replay checked the
// presented credential, a FailReceipt the store lost left this PASS.
func TestAJoinErrorUnderAMarkOnThePresentedCertificateIsRefused(t *testing.T) {
	g := &getRevocationFailsOnce{}
	f := setupStore(t, func(st *memory.Store) store.Store { g.Store = st; return g })
	marks := store.NewMarks()
	f.h.WithMarks(marks)
	f.joinFixture(t, nil)
	start := f.certBToken(t)
	f.markCertB(t, marks)
	if reply, _ := f.h.NewSession(f.peer).Start(context.Background(), start); reply.Status != wire.AuthenStatusError {
		t.Fatalf("the join whose mark read failed: %+v %v", reply, f.records(t))
	}
	reply, _ := f.h.NewSession(f.peer).Start(context.Background(), start)
	rec := f.records(t)[1]
	if reply.Status != wire.AuthenStatusFail || rec["reason"] != "credential_revoked" {
		t.Fatalf("a retransmission of a marked certificate after a join that ERRORed: %+v %v", reply, rec)
	}
	if s, _ := rec["session"].(map[string]any); s["revoked_at"] == nil {
		t.Fatalf("the refusal does not say when the mark stood: %v", rec)
	}
}

// An earlier login with the presented credential already reaches the
// context through the index: a second `port49 token` window from one
// certificate, or any login of a credential with neither a sid nor a
// certificate, which is indexed by its principal. The index cannot tell a
// join that ERRORed from one that committed; the context's witness can, so
// the retransmission is token_spent either way (spec §5.6; Task 4b review
// I1). Before the witness, the last two were PASS.
func TestAJoinThatErrorsReplaysNoPassThroughAnEarlierLoginsIndex(t *testing.T) {
	ref := store.ContextRef{NAS: "leaf-01", Username: "alice"}
	for _, c := range []struct {
		name  string
		index [3]string // principal, sid, cert key an earlier login indexed
		cert  bool      // window B's certificate, else the seed's token-only login
	}{
		{"the certificate, no earlier window", [3]string{}, true},
		{"the certificate, an earlier window", [3]string{"", "", store.CertKey("ca", "0b")}, true},
		{"no sid and no certificate", [3]string{"user:alice@example.com", "", ""}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			g := &getRevocationFailsOnce{}
			f := setupStore(t, func(st *memory.Store) store.Store { g.Store = st; return g })
			start := f.joinFixture(t, nil)
			if c.cert {
				start = f.certBToken(t)
			}
			if c.index != ([3]string{}) {
				if err := f.st.IndexContext(context.Background(), c.index[0], c.index[1], c.index[2], ref,
					time.Hour); err != nil {
					t.Fatal(err)
				}
			}
			if reply, _ := f.h.NewSession(f.peer).Start(context.Background(), start); reply.Status != wire.AuthenStatusError {
				t.Fatalf("the join whose mark read failed: %+v %v", reply, f.records(t))
			}
			reply, _ := f.h.NewSession(f.peer).Start(context.Background(), start)
			if rec := f.records(t)[1]; reply.Status != wire.AuthenStatusFail || rec["reason"] != "token_spent" {
				t.Fatalf("a retransmission after a join that ERRORed: %+v %v", reply, rec)
			}
		})
	}
}

// failReceiptLost answers FailReceipt without writing it: the Failed flag
// a store write cleared, or one that never landed.
type failReceiptLost struct{ *memory.Store }

func (failReceiptLost) FailReceipt(context.Context, store.ReceiptKey) error { return nil }

// A login refused after its join, on a context the join wrote revoked, is
// never witnessed. Once a token minted later lifts that revocation on the
// same ctx_id (decision 15), its retransmission is token_spent, not the
// PASS its receipt was written with, though a store write cleared the
// receipt's plaintext Failed (Task 4b review I2).
func TestALoginRefusedAfterItsJoinReplaysNoPassOnceTheRevocationIsLifted(t *testing.T) {
	f := setupStore(t, func(st *memory.Store) store.Store { return failReceiptLost{st} })
	f.joinFixture(t, nil)
	start := f.certBToken(t)
	f.markCertB(t, nil)
	if reply, _ := f.h.NewSession(f.peer).Start(context.Background(), start); reply.Status != wire.AuthenStatusFail ||
		f.records(t)[0]["reason"] != "credential_revoked" {
		t.Fatalf("a login under a mark its token predates: %+v %v", reply, f.records(t))
	}
	if err := f.st.DeleteRevocation(context.Background(), store.RevocationCert, store.CertKey("ca", "0b")); err != nil {
		t.Fatal(err)
	}
	later := f.tag() + "certCcertCcertCcertCcert"
	if _, err := f.st.PutToken(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"},
		store.Token{ID: "c", Secret: []byte(later), Kind: store.KindLogin, Username: "alice",
			Principal:  "user:alice@example.com",
			Credential: store.Credential{Method: "cert", Issuer: "ca", Serial: "0c"}, Enable: "token",
			MaxPrivilege: 15, MintedAt: f.now, ExpiresAt: f.now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if reply, _ := f.h.NewSession(f.peer).Start(context.Background(), papStart("alice", "ssh", "198.51.100.4",
		later)); reply.Status != wire.AuthenStatusPass {
		t.Fatalf("a login minted after the revocation: %+v %v", reply, f.records(t))
	}
	if c, _ := f.st.GetContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"}); c.CtxID != "ctxL" ||
		!c.RevokedAt.IsZero() {
		t.Fatalf("the test needs the revocation lifted on the same ctx_id: %+v", c)
	}
	reply, _ := f.h.NewSession(f.peer).Start(context.Background(), start)
	recs := f.records(t)
	if rec := recs[len(recs)-1]; reply.Status != wire.AuthenStatusFail || rec["reason"] != "token_spent" {
		t.Fatalf("the refused login's retransmission after the lift: %+v %v", reply, rec)
	}
}

// A committed login replays PASS only while the index reaches its context
// under its credential, so that a revocation of the credential can still
// reach what the replay admits. Window B's certificate, indexed now only to
// another device's context, is token_spent here (Task 4b review I3,
// mutation A).
func TestAReplayTheIndexNoLongerReachesIsRefused(t *testing.T) {
	f := setup(t)
	f.joinFixture(t, nil)
	start := f.certBToken(t)
	if reply, _ := f.h.NewSession(f.peer).Start(context.Background(), start); reply.Status != wire.AuthenStatusPass {
		t.Fatalf("the login: %+v %v", reply, f.records(t))
	}
	cert := store.CertKey("ca", "0b")
	if err := f.st.IndexContext(context.Background(), "", "", cert, store.ContextRef{NAS: "leaf-02", Username: "alice"},
		time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := f.st.UnindexContext(context.Background(), "", "", cert,
		store.ContextRef{NAS: "leaf-01", Username: "alice"}); err != nil {
		t.Fatal(err)
	}
	reply, _ := f.h.NewSession(f.peer).Start(context.Background(), start)
	if rec := f.records(t)[1]; reply.Status != wire.AuthenStatusFail || rec["reason"] != "token_spent" {
		t.Fatalf("a replay the certificate index no longer reaches: %+v %v", reply, rec)
	}
}

// midJoinRetransmit runs during() inside the join's first mark read, then
// fails that read: a retransmission that arrives while a join is still in
// flight on a degraded store, and the join that then ERRORs.
type midJoinRetransmit struct {
	*memory.Store
	mu     sync.Mutex
	during func()
	done   bool
}

func (m *midJoinRetransmit) GetRevocation(ctx context.Context, kind, key string) (store.Revocation, error) {
	m.mu.Lock()
	first := !m.done && m.during != nil
	m.done = m.done || first
	m.mu.Unlock()
	if first {
		m.during()
		return store.Revocation{}, errors.New("store unavailable")
	}
	return m.Store.GetRevocation(ctx, kind, key)
}

// A retransmission that reads the receipt while the join is still in
// flight finds it PASS, naming window A's context, live and unrevoked: the
// join has not written cert B into it. The write has not committed, so it
// is token_spent (spec §5.6), or credential_revoked when the daemon's marks
// name the presented certificate (Task 4 review I2, I3). It was a PASS: a
// session for a marked certificate, authorized under window A's context.
func TestARetransmissionDuringAFailingJoinIsRefused(t *testing.T) {
	for _, c := range []struct {
		name   string
		marked bool
		reason string
	}{
		{"the certificate unmarked", false, "token_spent"},
		{"the certificate marked", true, "credential_revoked"},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := &midJoinRetransmit{}
			f := setupStore(t, func(st *memory.Store) store.Store { m.Store = st; return m })
			var marks *store.Marks
			if c.marked {
				marks = store.NewMarks()
				f.h.WithMarks(marks)
			}
			f.joinFixture(t, nil)
			start := f.certBToken(t)
			f.markCertB(t, marks)
			var mid wire.AuthenReply
			m.during = func() { mid, _ = f.h.NewSession(f.peer).Start(context.Background(), start) }
			if reply, _ := f.h.NewSession(f.peer).Start(context.Background(), start); reply.Status != wire.AuthenStatusError {
				t.Fatalf("the join whose mark read failed: %+v %v", reply, f.records(t))
			}
			if rec := f.records(t)[0]; mid.Status != wire.AuthenStatusFail || rec["reason"] != c.reason {
				t.Fatalf("a retransmission while the join was in flight: %+v %v", mid, rec)
			}
		})
	}
}

// redeemRace runs during() at the first RedeemAndReceipt, before that call
// redeems: another presentation of the same credential redeems the token
// first, and this one loses and replays the winner's receipt. With
// failJoin, the winner's join's first mark read errs.
type redeemRace struct {
	*memory.Store
	mu       sync.Mutex
	during   func()
	failJoin bool
	redeems  int
	reads    int
}

func (r *redeemRace) RedeemAndReceipt(ctx context.Context, k store.TokenKey, id string, w store.ReceiptWrite) error {
	r.mu.Lock()
	r.redeems++
	first := r.redeems == 1
	r.mu.Unlock()
	if first {
		r.during()
	}
	return r.Store.RedeemAndReceipt(ctx, k, id, w)
}

func (r *redeemRace) GetRevocation(ctx context.Context, kind, key string) (store.Revocation, error) {
	r.mu.Lock()
	r.reads++
	fail := r.failJoin && r.reads == 1
	r.mu.Unlock()
	if fail {
		return store.Revocation{}, errors.New("store unavailable")
	}
	return r.Store.GetRevocation(ctx, kind, key)
}

// The loser of a redemption race replays the winner's receipt on the
// checks a retransmission's replay makes (spec §5.6; plan 7d): PASS once
// the winner's join committed, and token_spent when it did not, since the
// index does not reach the context under the credential.
func TestALoserOfARedemptionReplaysOnlyACommittedLogin(t *testing.T) {
	for _, c := range []struct {
		name     string
		failJoin bool
		winner   uint8
		status   uint8
		reason   string
	}{
		{"the winner's join committed", false, wire.AuthenStatusPass, wire.AuthenStatusPass, "receipt_replayed"},
		{"the winner's join ERRORed", true, wire.AuthenStatusError, wire.AuthenStatusFail, "token_spent"},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := &redeemRace{failJoin: c.failJoin}
			f := setupStore(t, func(st *memory.Store) store.Store { r.Store = st; return r })
			f.joinFixture(t, nil)
			start := f.certBToken(t)
			var won wire.AuthenReply
			r.during = func() { won, _ = f.h.NewSession(f.peer).Start(context.Background(), start) }
			lost, _ := f.h.NewSession(f.peer).Start(context.Background(), start)
			if won.Status != c.winner {
				t.Fatalf("the winner: %+v %v", won, f.records(t))
			}
			if rec := f.records(t)[1]; lost.Status != c.status || rec["reason"] != c.reason {
				t.Fatalf("the loser: %+v %v", lost, rec)
			}
		})
	}
}

// A join that committed, whose reply the device lost, replays PASS on the
// retransmission: the certificate index reaches the context, and no mark
// names the credential or the context (spec §5.6). Window A's own
// retransmission after window B joined replays too: the index still holds
// its certificate. Window A's is refused credential_revoked once a mark
// names its own certificate, though the context now names window B's, and
// once a mark names window B's, though its own is clear (plan 7d).
func TestACommittedJoinWhoseReplyWasLostReplaysPass(t *testing.T) {
	f := setup(t)
	marks := store.NewMarks()
	f.h.WithMarks(marks)
	certA := f.tag() + "certAcertAcertAcertAcert"
	if _, err := f.st.PutToken(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"},
		store.Token{ID: "a", Secret: []byte(certA), Kind: store.KindLogin, Username: "alice",
			Principal:  "user:alice@example.com",
			Credential: store.Credential{Method: "cert", Issuer: "ca", Serial: "0a"}, Enable: "token",
			MaxPrivilege: 15, MintedAt: f.now.Add(-time.Minute), ExpiresAt: f.now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	windowA := papStart("alice", "ssh", "198.51.100.4", certA)
	windowB := f.certBToken(t)
	for _, start := range []wire.AuthenStart{windowA, windowB} {
		if reply, _ := f.h.NewSession(f.peer).Start(context.Background(), start); reply.Status != wire.AuthenStatusPass {
			t.Fatalf("a login: %+v %v", reply, f.records(t))
		}
	}
	for name, start := range map[string]wire.AuthenStart{"window B": windowB, "window A": windowA} {
		reply, _ := f.h.NewSession(f.peer).Start(context.Background(), start)
		recs := f.records(t)
		if rec := recs[len(recs)-1]; reply.Status != wire.AuthenStatusPass || rec["reason"] != "receipt_replayed" {
			t.Fatalf("%s's retransmission of a committed login: %+v %v", name, reply, rec)
		}
	}
	marks.Set(store.Revocation{Kind: store.RevocationCert, Key: store.CertKey("ca", "0a"), At: f.now}, true)
	reply, _ := f.h.NewSession(f.peer).Start(context.Background(), windowA)
	recs := f.records(t)
	if rec := recs[len(recs)-1]; reply.Status != wire.AuthenStatusFail || rec["reason"] != "credential_revoked" {
		t.Fatalf("window A's retransmission under a mark on its own certificate: %+v %v", reply, rec)
	}
	if reply, _ := f.h.NewSession(f.peer).Start(context.Background(), windowB); reply.Status != wire.AuthenStatusPass {
		t.Fatalf("window B's retransmission under a mark on another certificate: %+v %v", reply, f.records(t))
	}
	// A mark on the certificate the context names now refuses window A's
	// retransmission too, though its own certificate is clear.
	marks.Set(store.Revocation{Kind: store.RevocationCert, Key: store.CertKey("ca", "0a")}, false)
	marks.Set(store.Revocation{Kind: store.RevocationCert, Key: store.CertKey("ca", "0b"), At: f.now}, true)
	reply, _ = f.h.NewSession(f.peer).Start(context.Background(), windowA)
	recs = f.records(t)
	if rec := recs[len(recs)-1]; reply.Status != wire.AuthenStatusFail || rec["reason"] != "credential_revoked" {
		t.Fatalf("window A's retransmission under a mark on the context's certificate: %+v %v", reply, rec)
	}
}

// seedLogin writes the login context an enable START escalates. Every field an
// escalation must preserve is non-zero, so a rebuild in `escalate` that drops
// one is visible: a lost Credential costs revocation its reach by sid and
// certificate, a lost SessionExpires removes the absolute ceiling, a lost
// RefreshedAt defeats the staleness clock (spec §5.1.4).
func (f *fixture) seedLogin(t *testing.T, enable string, maxPriv uint8) {
	t.Helper()
	f.seedLoginWith(t, enable, maxPriv, nil)
}

// seedLoginWith is seedLogin with one adjustment applied before the write, for
// the gate states seedLogin never produces: a revoked context, an expired one.
func (f *fixture) seedLoginWith(t *testing.T, enable string, maxPriv uint8, adjust func(*store.Context)) {
	t.Helper()
	c := store.Context{CtxID: "ctxL", Username: "alice", Principal: "user:alice@example.com",
		Port: "ssh", RemAddr: "198.51.100.4", PrivLvl: 1, MaxPrivilege: maxPriv, Enable: enable,
		BlobHash: "sha256:b", CreatedAt: f.now,
		Credential:     store.Credential{Method: "oidc", Sid: "sid-1", Issuer: "ca", Serial: "01"},
		AuthTime:       f.now,
		SessionExpires: f.now.Add(8 * time.Hour),
		RefreshedAt:    f.now}
	if adjust != nil {
		adjust(&c)
	}
	f.st.PutContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"}, c, time.Hour)
}

func (f *fixture) enableStart(user string) wire.AuthenStart {
	return wire.AuthenStart{Action: wire.AuthenActionLogin, PrivLvl: 15, AuthenType: wire.AuthenTypeASCII,
		Service: wire.AuthenServiceEnable, User: []byte(user), Port: []byte("vty4"), RemAddr: []byte("198.51.100.4")}
}

// The measured shape: the enable START carries the operator's own username
// (tests/lab/results/L3-arista_eos.md, L3-cisco_iosxe.md), so it resolves
// through the ordinary (nas, username) context.
func TestEnableUpdatesPrivilegeInPlaceAndKeepsCtxID(t *testing.T) {
	f := setup(t)
	f.seedLogin(t, "token", 15)
	secret := f.tag() + "enabenabenabenabenab0123"
	f.st.PutToken(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"},
		store.Token{ID: "en", Secret: []byte(secret), Kind: store.KindEnable, Username: "alice",
			Principal: "user:alice@example.com", ExpiresAt: f.now.Add(time.Minute)})
	sess := f.h.NewSession(f.peer)
	if reply, done := sess.Start(context.Background(), f.enableStart("alice")); done || reply.Status != wire.AuthenStatusGetPass {
		t.Fatalf("enable START must prompt: %+v %v", reply, done)
	}
	reply, done := sess.Continue(context.Background(), wire.AuthenContinue{UserMsg: []byte(secret)})
	if !done || reply.Status != wire.AuthenStatusPass {
		t.Fatalf("%+v", reply)
	}
	c, _ := f.st.GetContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"})
	if c.CtxID != "ctxL" || c.PrivLvl != 15 || c.Principal != "user:alice@example.com" || c.BlobHash != "sha256:b" {
		t.Fatalf("escalation must update privilege in place and keep ctx_id: %+v", c)
	}
	// An escalation changes the privilege and nothing else. Each of these has
	// teeth downstream (spec §5.1.4): Credential is revocation's reach by sid
	// and certificate, SessionExpires the absolute ceiling, RefreshedAt the
	// staleness clock.
	if !c.AuthTime.Equal(f.now) || !c.SessionExpires.Equal(f.now.Add(8*time.Hour)) ||
		!c.RefreshedAt.Equal(f.now) || c.Credential.Sid != "sid-1" || c.Credential.Serial != "01" {
		t.Fatalf("an escalation changes the privilege and nothing else: %+v", c)
	}
	last := f.records(t)[len(f.records(t))-1]
	if last["event"] != "escalate" || last["reason"] != "escalation_granted" || last["principal"] != "user:alice@example.com" {
		t.Fatalf("%v", last)
	}
	// The escalation's OWN record must name the context it raised: that id is
	// the join from the login through the escalation to every later command.
	if last["session"].(map[string]any)["ctx_id"] != "ctxL" {
		t.Fatalf("the escalation's own record must name the context it raised: %v", last)
	}
	if last["session"].(map[string]any)["replaced_ctx_id"] != nil {
		t.Fatal("an escalation replaces nothing")
	}
	// The retransmission is what the receipt is for, and it must replay the
	// ctx_id the escalation kept — not a fresh one minted beside it that no
	// context, no authorize_* record and no accounting record ever held.
	sess2 := f.h.NewSession(f.peer)
	sess2.Start(context.Background(), f.enableStart("alice"))
	reply, _ = sess2.Continue(context.Background(), wire.AuthenContinue{UserMsg: []byte(secret)})
	last = f.records(t)[len(f.records(t))-1]
	if reply.Status != wire.AuthenStatusPass || last["reason"] != "receipt_replayed" ||
		last["session"].(map[string]any)["ctx_id"] != "ctxL" {
		t.Fatalf("the replayed enable must carry the context's own ctx_id: %+v %v", reply, last)
	}
}

func TestEnableWithoutContextIsContextMissing(t *testing.T) {
	f := setup(t)
	sess := f.h.NewSession(f.peer)
	sess.Start(context.Background(), f.enableStart("nobody"))
	reply, _ := sess.Continue(context.Background(), wire.AuthenContinue{UserMsg: []byte("anything")})
	if reply.Status != wire.AuthenStatusFail || f.records(t)[0]["reason"] != "context_missing" {
		t.Fatalf("%+v %v", reply, f.records(t))
	}
}

// The ceiling refuses an escalation above it, and a token minted without one
// has nothing to refuse against. Zero is "no ceiling", not "level 0 only", and
// it has to be the same reading the authorizer's clamp takes
// (store.Context.PrivilegeCeiling, TestTheGrantedLevelIsClampedToMaxPrivilege):
// a policy engine that mints without the field would otherwise get a fleet
// where session authorization grants 15 freely and every enable is refused
// naming a ceiling nobody configured.
//
// `auto` throughout, because the ceiling gate runs before the mechanism does:
// this table is about the bound, not about how the escalation is proved.
func TestEnableCeilingRefusesOnlyWhatWasMinted(t *testing.T) {
	for _, tt := range []struct {
		name    string
		maxPriv uint8
		status  uint8
		reason  string
		priv    uint8
	}{
		{"above the ceiling is refused", 7, wire.AuthenStatusFail, "ceiling_exceeded", 1},
		{"at the ceiling escalates", 15, wire.AuthenStatusPass, "escalation_granted", 15},
		{"no ceiling minted escalates", 0, wire.AuthenStatusPass, "escalation_granted", 15},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := setup(t)
			f.seedLogin(t, "auto", tt.maxPriv)
			sess := f.h.NewSession(f.peer)
			sess.Start(context.Background(), f.enableStart("alice"))
			reply, _ := sess.Continue(context.Background(), wire.AuthenContinue{UserMsg: []byte("anything")})
			if reply.Status != tt.status || f.records(t)[0]["reason"] != tt.reason {
				t.Fatalf("%+v %v", reply, f.records(t))
			}
			c, _ := f.st.GetContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"})
			if c.PrivLvl != tt.priv {
				t.Fatalf("recorded level %d, want %d", c.PrivLvl, tt.priv)
			}
		})
	}
}

func TestEnableNoneIsRefused(t *testing.T) {
	f := setup(t)
	f.seedLogin(t, "none", 15)
	sess := f.h.NewSession(f.peer)
	sess.Start(context.Background(), f.enableStart("alice"))
	reply, _ := sess.Continue(context.Background(), wire.AuthenContinue{UserMsg: []byte("anything")})
	if reply.Status != wire.AuthenStatusFail || f.records(t)[0]["reason"] != "enable_refused" {
		t.Fatalf("%+v %v", reply, f.records(t))
	}
}

func TestEnableFromAnotherAddressIsRefused(t *testing.T) {
	f := setup(t)
	f.seedLogin(t, "token", 15)
	start := f.enableStart("alice")
	start.RemAddr = []byte("203.0.113.9")
	sess := f.h.NewSession(f.peer)
	sess.Start(context.Background(), start)
	reply, _ := sess.Continue(context.Background(), wire.AuthenContinue{UserMsg: []byte("anything")})
	if reply.Status != wire.AuthenStatusFail || f.records(t)[0]["reason"] != "rem_addr_mismatch" {
		t.Fatalf("%+v %v", reply, f.records(t))
	}
}

func TestEnableAutoNeedsNoToken(t *testing.T) {
	f := setup(t)
	f.seedLogin(t, "auto", 15)
	// An enable token alice could have spent, so "needs no token" is a claim
	// about behaviour rather than about an empty store.
	f.st.PutToken(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"},
		store.Token{ID: "en", Secret: []byte(f.tag() + "enabenabenabenabenab0123"), Kind: store.KindEnable,
			Username: "alice", Principal: "user:alice@example.com", ExpiresAt: f.now.Add(time.Minute)})
	sess := f.h.NewSession(f.peer)
	sess.Start(context.Background(), f.enableStart("alice"))
	reply, _ := sess.Continue(context.Background(), wire.AuthenContinue{UserMsg: []byte("anything at all")})
	if reply.Status != wire.AuthenStatusPass || f.records(t)[0]["reason"] != "escalation_granted" {
		t.Fatalf("%+v %v", reply, f.records(t))
	}
	c, _ := f.st.GetContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"})
	if c.CtxID != "ctxL" || c.PrivLvl != 15 {
		t.Fatalf("%+v", c)
	}
	// The token is still there: `auto` decided on the context alone.
	cands, err := f.st.Candidates(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, tok := range cands {
		found = found || tok.ID == "en"
	}
	if !found {
		t.Fatalf("`auto` consulted and spent the enable token: %+v", cands)
	}
}

// A revoked context does not escalate. `auto` consults no token, so nothing
// else on that path would ever look, and on a session-only platform (spec §13,
// decision 21; tests/lab/results/L18-*.md) the enable exchange is the last
// decision port49 makes about the shell — Task 10's per-command check never
// runs there.
func TestEnableOnRevokedContextIsRefused(t *testing.T) {
	for _, enable := range []string{"auto", "token"} {
		t.Run(enable, func(t *testing.T) {
			f := setup(t)
			f.seedLoginWith(t, enable, 15, func(c *store.Context) { c.RevokedAt = f.now.Add(-time.Minute) })
			sess := f.h.NewSession(f.peer)
			sess.Start(context.Background(), f.enableStart("alice"))
			reply, _ := sess.Continue(context.Background(), wire.AuthenContinue{UserMsg: []byte("anything")})
			if reply.Status != wire.AuthenStatusFail || f.records(t)[0]["reason"] != "credential_revoked" {
				t.Fatalf("%+v %v", reply, f.records(t))
			}
			c, _ := f.st.GetContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"})
			if c.PrivLvl != 1 {
				t.Fatalf("a revoked context must not be raised: %+v", c)
			}
		})
	}
}

// A standing mark refuses an enable whatever the context's record says
// (plan 7d; Ruling 17): a record put back from before the revocation, or
// one a revocation never reached, is as revoked as one it marked.
func TestAnEnableUnderAStandingMarkIsRefused(t *testing.T) {
	for _, enable := range []string{"auto", "token"} {
		t.Run(enable, func(t *testing.T) {
			f := setup(t)
			marks := store.NewMarks()
			f.h.WithMarks(marks)
			f.seedLogin(t, enable, 15)
			marks.Set(store.Revocation{Kind: store.RevocationPrincipal, Key: "user:alice@example.com",
				At: f.now.Add(-time.Minute)}, true)
			sess := f.h.NewSession(f.peer)
			sess.Start(context.Background(), f.enableStart("alice"))
			reply, _ := sess.Continue(context.Background(), wire.AuthenContinue{UserMsg: []byte("anything")})
			if reply.Status != wire.AuthenStatusFail || f.records(t)[0]["reason"] != "credential_revoked" {
				t.Fatalf("%+v %v", reply, f.records(t))
			}
			if c, _ := f.st.GetContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"}); c.PrivLvl != 1 {
				t.Fatalf("a context under a standing mark was raised: %+v", c)
			}
		})
	}
}

// A replayed escalation is refused credential_revoked when a standing mark
// names the certificate its enable token was minted under, though the
// context names another certificate and its principal is clear (Task 4b
// review I3, mutation C). Enable is the escalation path.
func TestAnEnableReplayUnderAMarkOnThePresentedCertificateIsRefused(t *testing.T) {
	f := setup(t)
	marks := store.NewMarks()
	f.h.WithMarks(marks)
	f.seedLogin(t, "token", 15)
	secret := f.tag() + "enabenabenabenabenab0123"
	if _, err := f.st.PutToken(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"},
		store.Token{ID: "en", Secret: []byte(secret), Kind: store.KindEnable, Username: "alice",
			Principal:  "user:alice@example.com",
			Credential: store.Credential{Method: "cert", Issuer: "ca", Serial: "0b"},
			ExpiresAt:  f.now.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	enable := func() wire.AuthenReply {
		sess := f.h.NewSession(f.peer)
		sess.Start(context.Background(), f.enableStart("alice"))
		reply, _ := sess.Continue(context.Background(), wire.AuthenContinue{UserMsg: []byte(secret)})
		return reply
	}
	if reply := enable(); reply.Status != wire.AuthenStatusPass {
		t.Fatalf("the escalation: %+v %v", reply, f.records(t))
	}
	marks.Set(store.Revocation{Kind: store.RevocationCert, Key: store.CertKey("ca", "0b"), At: f.now}, true)
	reply := enable()
	recs := f.records(t)
	if rec := recs[len(recs)-1]; reply.Status != wire.AuthenStatusFail || rec["reason"] != "credential_revoked" {
		t.Fatalf("a replayed escalation under a mark on its certificate: %+v %v", reply, rec)
	}
}

// A retransmitted login onto a context a standing mark names is refused
// credential_revoked, not replayed, though the context's record is not
// revoked (plan 7d; Ruling 17).
func TestAReplayUnderAStandingMarkIsRefused(t *testing.T) {
	f := setup(t)
	marks := store.NewMarks()
	f.h.WithMarks(marks)
	start := wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP, Service: wire.AuthenServiceLogin,
		User: []byte("alice"), Port: []byte("vty0"), Data: []byte(f.tag() + "tok1tok1tok1tok1tok1tok1")}
	if reply, _ := f.h.NewSession(f.peer).Start(context.Background(), start); reply.Status != wire.AuthenStatusPass {
		t.Fatalf("the login: %+v %v", reply, f.records(t))
	}
	marks.Set(store.Revocation{Kind: store.RevocationPrincipal, Key: "user:alice@example.com", At: f.now}, true)
	reply, _ := f.h.NewSession(f.peer).Start(context.Background(), start)
	if rec := f.records(t)[1]; reply.Status != wire.AuthenStatusFail || rec["reason"] != "credential_revoked" {
		t.Fatalf("a replay under a standing mark: %+v %v", reply, rec)
	}
	if c, _ := f.st.GetContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"}); !c.RevokedAt.IsZero() {
		t.Fatalf("the test needs an unrevoked record: %+v", c)
	}
}

// Past max_session_age the enable prompt is the last chance to refuse on a
// session-only platform. A zero SessionExpires is `max_session_age: never` and
// must stay expressible (spec §5.6), so it is not read as expired at the epoch.
func TestEnableOnExpiredContextIsRefused(t *testing.T) {
	f := setup(t)
	f.seedLoginWith(t, "auto", 15, func(c *store.Context) { c.SessionExpires = f.now.Add(-time.Second) })
	sess := f.h.NewSession(f.peer)
	sess.Start(context.Background(), f.enableStart("alice"))
	reply, _ := sess.Continue(context.Background(), wire.AuthenContinue{UserMsg: []byte("anything")})
	if reply.Status != wire.AuthenStatusFail || f.records(t)[0]["reason"] != "session_expired" {
		t.Fatalf("%+v %v", reply, f.records(t))
	}

	// `max_session_age: never` still escalates.
	f2 := setup(t)
	f2.seedLoginWith(t, "auto", 15, func(c *store.Context) { c.SessionExpires = time.Time{} })
	sess2 := f2.h.NewSession(f2.peer)
	sess2.Start(context.Background(), f2.enableStart("alice"))
	reply, _ = sess2.Continue(context.Background(), wire.AuthenContinue{UserMsg: []byte("anything")})
	if reply.Status != wire.AuthenStatusPass || f2.records(t)[0]["reason"] != "escalation_granted" {
		t.Fatalf("a zero SessionExpires is `never`, not expired at the epoch: %+v %v", reply, f2.records(t))
	}
}

// setPrivilegeFailsOnce fails the first SetPrivilege and is healthy afterwards,
// to drive an escalation whose privilege never landed. seedLogin writes through
// f.st directly, so the first failure this sees is the escalation's own —
// SetPrivilege is where the escalation lands the level, and the only call this
// fixture makes to it.
type setPrivilegeFailsOnce struct {
	store.Store
	failed bool
}

func (p *setPrivilegeFailsOnce) SetPrivilege(ctx context.Context, k store.ContextKey, level uint8) error {
	if !p.failed {
		p.failed = true
		return errors.New("store: set_privilege failed")
	}
	return p.Store.SetPrivilege(ctx, k, level)
}

// A replayed enable must replay the escalation's EFFECT, not just its verdict.
// Here the first escalation's SetPrivilege fails after the token is already
// spent: at 3am the operator sees an error, types `enable` again, gets a prompt
// that accepts and a `#` — and the device now believes they are level 15. If
// the retry only replayed the receipt, every command they typed would be denied
// at their login privilege.
func TestReplayedEnableReAppliesThePrivilege(t *testing.T) {
	var fake *setPrivilegeFailsOnce
	f := setupStore(t, func(st *memory.Store) store.Store {
		fake = &setPrivilegeFailsOnce{Store: st}
		return fake
	})
	f.seedLogin(t, "token", 15)
	secret := f.tag() + "enabenabenabenabenab0123"
	f.st.PutToken(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"},
		store.Token{ID: "en", Secret: []byte(secret), Kind: store.KindEnable, Username: "alice",
			Principal: "user:alice@example.com", ExpiresAt: f.now.Add(time.Minute)})

	sess := f.h.NewSession(f.peer)
	sess.Start(context.Background(), f.enableStart("alice"))
	reply, _ := sess.Continue(context.Background(), wire.AuthenContinue{UserMsg: []byte(secret)})
	if reply.Status != wire.AuthenStatusError || f.records(t)[0]["reason"] != "store_unavailable" {
		t.Fatalf("a failed SetPrivilege must be ERROR, not a PASS the context cannot back up: %+v %v", reply, f.records(t))
	}
	c, _ := f.st.GetContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"})
	if c.PrivLvl != 1 {
		t.Fatalf("the privilege must not have landed: %+v", c)
	}

	sess2 := f.h.NewSession(f.peer)
	sess2.Start(context.Background(), f.enableStart("alice"))
	reply, _ = sess2.Continue(context.Background(), wire.AuthenContinue{UserMsg: []byte(secret)})
	last := f.records(t)[len(f.records(t))-1]
	if reply.Status != wire.AuthenStatusPass || last["reason"] != "receipt_replayed" {
		t.Fatalf("%+v %v", reply, last)
	}
	c, _ = f.st.GetContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"})
	if c.CtxID != "ctxL" || c.PrivLvl != 15 {
		t.Fatalf("the retry must leave the live context at the enable privilege: %+v", c)
	}
}

// revokeDuringRedeem stamps the context revoked inside RedeemAndReceipt, which
// is exactly where a concurrent RevokeByPrincipal lands: after the enable's gate
// read the context at the top of the request, and before the write that ends the
// escalation.
type revokeDuringRedeem struct {
	store.Store
	at time.Time
}

func (r revokeDuringRedeem) RedeemAndReceipt(ctx context.Context, k store.TokenKey, tokenID string, w store.ReceiptWrite) error {
	if err := r.Store.RedeemAndReceipt(ctx, k, tokenID, w); err != nil {
		return err
	}
	return r.Store.SetRevokedAt(ctx, store.ContextKey{NAS: k.NAS, Username: k.Username}, r.at)
}

// A revocation that lands mid-enable must survive the escalation. The 3am
// sequence this pins: the operator revokes alice, `mark` stamps revoked_at and
// deletes her receipts, and alice's in-flight enable finishes. If the escalation
// wrote back the context it read a moment earlier, revoked_at would go back to
// zero — and nothing would ever set it again, because the receipts that would
// have re-marked it are gone. The revocation reported one context touched and
// every command for the rest of the idle TTL is permitted.
//
// The escalation itself still PASSes: its gates ran against a context that was
// not yet revoked, and that decision was correct when it was made. What must not
// happen is the erasure, so the assertion is on the record, not the reply.
func TestEnableDoesNotUnrevokeAContextRevokedMidExchange(t *testing.T) {
	revokedAt := time.Unix(1_757_041_500, 0)
	f := setupStore(t, func(st *memory.Store) store.Store { return revokeDuringRedeem{st, revokedAt} })
	f.seedLogin(t, "token", 15)
	secret := f.tag() + "enabenabenabenabenab0123"
	f.st.PutToken(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"},
		store.Token{ID: "en", Secret: []byte(secret), Kind: store.KindEnable, Username: "alice",
			Principal: "user:alice@example.com", ExpiresAt: f.now.Add(time.Minute)})

	sess := f.h.NewSession(f.peer)
	sess.Start(context.Background(), f.enableStart("alice"))
	reply, _ := sess.Continue(context.Background(), wire.AuthenContinue{UserMsg: []byte(secret)})
	if reply.Status != wire.AuthenStatusPass {
		t.Fatalf("the escalation's gates ran before the revocation landed: %+v %v", reply, f.records(t))
	}

	c, err := f.st.GetContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if !c.RevokedAt.Equal(revokedAt) {
		t.Fatalf("the escalation erased the revocation: revoked_at = %v, want %v (%+v)", c.RevokedAt, revokedAt, c)
	}

	// And the authorization that follows it denies. This is the enable path's
	// own copy of the check author.Handle makes first (authen.go, spec §7): both
	// read the same field, so a revoked_at that survived here is a revoked_at
	// every later decision sees.
	sess2 := f.h.NewSession(f.peer)
	sess2.Start(context.Background(), f.enableStart("alice"))
	reply, _ = sess2.Continue(context.Background(), wire.AuthenContinue{UserMsg: []byte(secret)})
	last := f.records(t)[len(f.records(t))-1]
	if reply.Status != wire.AuthenStatusFail || last["reason"] != "credential_revoked" {
		t.Fatalf("the next decision must be credential_revoked: %+v %v", reply, last)
	}
}

// raceLoserStore makes every RedeemAndReceipt look like the losing half of a
// concurrent escalation: the work lands (the token is spent, the receipt is
// written), and the caller is told ErrNotFound — exactly what the loser of a
// real race sees when the winner got there first.
type raceLoserStore struct {
	store.Store
}

func (r raceLoserStore) RedeemAndReceipt(ctx context.Context, k store.TokenKey, tokenID string, w store.ReceiptWrite) error {
	if err := r.Store.RedeemAndReceipt(ctx, k, tokenID, w); err != nil {
		return err
	}
	return store.ErrNotFound
}

// The race loser adopts the winner's receipt, and it has the same obligation as
// the retransmission: replay the effect, not just the verdict. Two shells
// enabling at once must not leave one of them PASSed at login privilege.
func TestRaceLosingEnableStillRaisesTheContext(t *testing.T) {
	f := setupStore(t, func(st *memory.Store) store.Store { return raceLoserStore{st} })
	f.seedLogin(t, "token", 15)
	secret := f.tag() + "enabenabenabenabenab0123"
	f.st.PutToken(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"},
		store.Token{ID: "en", Secret: []byte(secret), Kind: store.KindEnable, Username: "alice",
			Principal: "user:alice@example.com", ExpiresAt: f.now.Add(time.Minute)})
	sess := f.h.NewSession(f.peer)
	sess.Start(context.Background(), f.enableStart("alice"))
	reply, _ := sess.Continue(context.Background(), wire.AuthenContinue{UserMsg: []byte(secret)})
	last := f.records(t)[len(f.records(t))-1]
	if reply.Status != wire.AuthenStatusPass || last["reason"] != "receipt_replayed" ||
		last["session"].(map[string]any)["ctx_id"] != "ctxL" {
		t.Fatalf("%+v %v", reply, last)
	}
	c, _ := f.st.GetContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"})
	if c.CtxID != "ctxL" || c.PrivLvl != 15 {
		t.Fatalf("the race loser must leave the context at the enable privilege: %+v", c)
	}
}

// A login token presented at the enable prompt is token_kind_mismatch, so the
// redeem and escalate records can never disagree with the wire (spec §7).
func TestLoginTokenAtEnableIsKindMismatch(t *testing.T) {
	f := setup(t)
	f.seedLogin(t, "token", 15)
	sess := f.h.NewSession(f.peer)
	sess.Start(context.Background(), f.enableStart("alice"))
	reply, _ := sess.Continue(context.Background(), wire.AuthenContinue{UserMsg: []byte(f.tag() + "tok1tok1tok1tok1tok1tok1")})
	if reply.Status != wire.AuthenStatusFail || f.records(t)[0]["reason"] != "token_kind_mismatch" {
		t.Fatalf("%+v %v", reply, f.records(t))
	}
}

// A rotation must not deny the fleet. The tag key is derived from an encryption
// key, and the store keeps a two-key read window, so a token sealed under the
// key that is now `previous` still opens — and its tag must still be accepted,
// or the instant an operator rotates, every outstanding token answers
// device_mismatch ("this token was minted for another device") to every
// operator on every device at once, with nothing in the log naming the
// rotation.
//
// The rotation is performed the way a real one is: the token is written through
// a store sealed under v1, and then read through the same store sealed under v2
// with v1 as previous. What changes between the two halves is only which tag
// keys the handler accepts.
func TestRotatedEncryptionKeyKeepsItsTagUntilItLeavesTheWindow(t *testing.T) {
	var v1, v2 crypt.Key
	v1.ID, v2.ID = "v1", "v2"
	copy(v1.Bytes[:], "rotation-test-key-one-32-bytes!!")
	copy(v2.Bytes[:], "rotation-test-key-two-32-bytes!!")
	tagV1, tagV2 := token.TagKey(v1.Bytes[:]), token.TagKey(v2.Bytes[:])
	secret := token.Tag(tagV1, "leaf-01") + "tok1tok1tok1tok1tok1tok1"

	// One store, two views of it: v1 current at mint, v2 current with v1
	// previous afterwards. Sealed under v1, readable under both.
	now := time.Unix(1_757_041_495, 0)
	st := memory.New(func() time.Time { return now })
	atMint := crypt.Wrap(st, crypt.Keys{Current: v1}, nil)
	afterRotation := crypt.Wrap(st, crypt.Keys{Current: v2, Previous: &v1}, nil)

	redeem := func(t *testing.T, s store.Store, tags token.TagWindow) (wire.AuthenReply, map[string]any) {
		t.Helper()
		if _, err := atMint.PutToken(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"},
			store.Token{ID: "rot", Secret: []byte(secret), Kind: store.KindLogin, Username: "alice",
				Principal: "user:alice@example.com", ExpiresAt: now.Add(15 * time.Minute)}); err != nil {
			t.Fatal(err)
		}
		log := &bytes.Buffer{}
		l := limits.New(limits.Config{AuthFailureDelayBase: time.Millisecond,
			AuthFailureDelayMax: 2 * time.Millisecond, AuthFailureWindow: time.Minute}, func() time.Time { return now })
		h := New(s, decision.NewJSONLines(log), l, metrics.New(prometheus.NewRegistry()),
			func() time.Time { return now }, func() string { return "ctx1" },
			15*time.Minute, 2*time.Hour, time.Hour, time.Hour, tags)
		sess := h.NewSession(Peer{NAS: "leaf-01", NASAddr: "10.20.0.7", Platform: "arista_eos"})
		reply, _ := sess.Start(context.Background(), wire.AuthenStart{Action: wire.AuthenActionLogin, PrivLvl: 1,
			AuthenType: wire.AuthenTypePAP, Service: wire.AuthenServiceLogin,
			User: []byte("alice"), Port: []byte("vty0"), RemAddr: []byte("198.51.100.4"), Data: []byte(secret)})
		var rec map[string]any
		if err := json.Unmarshal([]byte(strings.TrimSpace(log.String())), &rec); err != nil {
			t.Fatal(err)
		}
		return reply, rec
	}

	// v1 is still in the window: the token authenticates.
	reply, rec := redeem(t, afterRotation, token.NewTagWindow(tagV2, tagV1))
	if reply.Status != wire.AuthenStatusPass || rec["reason"] != "token_redeemed" {
		t.Fatalf("a token minted before the rotation must still authenticate while its key is in the "+
			"window: %v", rec)
	}

	// v1 has been dropped from the config: now, and only now, the tag is a
	// device_mismatch. The record it was sealed under is unreadable too, so
	// there is nothing left to redeem either way.
	reply, rec = redeem(t, crypt.Wrap(st, crypt.Keys{Current: v2}, nil), token.NewTagWindow(tagV2))
	if reply.Status != wire.AuthenStatusFail || rec["reason"] != "device_mismatch" {
		t.Fatalf("once the minting key has left the window its tags must be refused: %v", rec)
	}
}

// joinFixture seeds window A's live context and hands back window B's login
// START. Window A is enabled to 15 and accounting has bound one session to it,
// which is exactly the state a replace used to erase.
func (f *fixture) joinFixture(t *testing.T, adjust func(*store.Context)) wire.AuthenStart {
	t.Helper()
	f.seedLoginWith(t, "token", 15, func(c *store.Context) {
		c.PrivLvl = 15
		c.SessionDiscriminators = []string{store.HashDiscriminator("42")}
		if adjust != nil {
			adjust(c)
		}
	})
	return wire.AuthenStart{Action: wire.AuthenActionLogin, PrivLvl: 1, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte("alice"), Port: []byte("ssh"),
		RemAddr: []byte("198.51.100.4"), Data: []byte(f.tag() + "tok1tok1tok1tok1tok1tok1")}
}

// Window B's login joins window A's context: the ctx_id, A's privilege and A's
// bound session all survive, and the record names the kept context and
// displaces nothing (spec §5.6).
func TestASecondLoginJoinsAndKeepsTheFirstWindowsState(t *testing.T) {
	f := setup(t)
	start := f.joinFixture(t, nil)
	if reply, _ := f.h.NewSession(f.peer).Start(context.Background(), start); reply.Status != wire.AuthenStatusPass {
		t.Fatalf("%+v %v", reply, f.records(t))
	}
	c, _ := f.st.GetContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"})
	if c.CtxID != "ctxL" || c.PrivLvl != 15 || len(c.SessionDiscriminators) != 1 {
		t.Fatalf("the join must keep window A's ctx_id, privilege and bound session: %+v", c)
	}
	s := f.records(t)[0]["session"].(map[string]any)
	if s["ctx_id"] != "ctxL" || s["replaced_ctx_id"] != nil {
		t.Fatalf("%v", s)
	}
}

// The receipt carries the ctx_id the login will be written under, and for a
// join that is the live context's: a retransmission of window B's login
// replays naming ctxL, not an id minted for a context that was never written.
func TestAJoinedLoginsReceiptNamesTheKeptContext(t *testing.T) {
	f := setup(t)
	start := f.joinFixture(t, nil)
	f.h.NewSession(f.peer).Start(context.Background(), start)
	reply, _ := f.h.NewSession(f.peer).Start(context.Background(), start)
	last := f.records(t)[len(f.records(t))-1]
	if reply.Status != wire.AuthenStatusPass || last["reason"] != "receipt_replayed" ||
		last["session"].(map[string]any)["ctx_id"] != "ctxL" {
		t.Fatalf("%+v %v", reply, last)
	}
}

// Test 3 of the decisions. A token minted before a revocation is what the
// revocation was meant to stop, and redeeming it on a device where the revoked
// context is still live must not lift the mark. A token minted after it is the
// broker having verified the credential again, and admits (spec §13,
// decision 15).
//
// A token minted before the revocation is refused at the login, FAIL
// `credential_revoked` — the answer the enable gate gives for the same state
// (ruling F-I2). A PASS there would put a permit for a principal security has
// just revoked into the log, with every authorization after it denied and
// nothing on the permit saying why. The token is spent, so it cannot be
// retried, and the record carries the revoked_at that refused it. A
// retransmission replays the refusal, never a PASS.
func TestARevocationSurvivesATokenMintedBeforeIt(t *testing.T) {
	revokedAt := time.Unix(1_757_041_495, 0).Add(-time.Minute)
	for _, tt := range []struct {
		name     string
		mintedAt time.Time
		revoked  bool
	}{
		{"minted before the revocation", revokedAt.Add(-time.Minute), true},
		{"minted after the revocation", revokedAt.Add(time.Second), false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := setup(t)
			start := f.joinFixture(t, func(c *store.Context) { c.RevokedAt = revokedAt })
			secret := f.tag() + "mintmintmintmintmint0123"
			tk := store.TokenKey{NAS: "leaf-01", Username: "alice"}
			if _, err := f.st.PutToken(context.Background(), tk,
				store.Token{ID: "m", Secret: []byte(secret), Kind: store.KindLogin, Username: "alice",
					Principal: "user:alice@example.com", Enable: "token", MaxPrivilege: 15,
					MintedAt: tt.mintedAt, ExpiresAt: f.now.Add(time.Minute)}); err != nil {
				t.Fatal(err)
			}
			start.Data = []byte(secret)
			reply, _ := f.h.NewSession(f.peer).Start(context.Background(), start)
			rec := f.records(t)[0]
			s := rec["session"].(map[string]any)
			for _, c := range func() []store.Token { c, _ := f.st.Candidates(context.Background(), tk); return c }() {
				if c.ID == "m" {
					t.Fatal("the token must be spent either way")
				}
			}
			c, _ := f.st.GetContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"})
			if got := !c.RevokedAt.IsZero(); got != tt.revoked || c.CtxID != "ctxL" {
				t.Fatalf("revoked %v, want %v: %+v", got, tt.revoked, c)
			}
			retry, _ := f.h.NewSession(f.peer).Start(context.Background(), start)
			if !tt.revoked {
				if reply.Status != wire.AuthenStatusPass || rec["reason"] != "token_redeemed" || s["revoked_at"] != nil {
					t.Fatalf("a token minted after the revocation lifts it: %+v %v", reply, rec)
				}
				if retry.Status != wire.AuthenStatusPass {
					t.Fatalf("its retransmission replays the PASS: %+v", retry)
				}
				return
			}
			if reply.Status != wire.AuthenStatusFail || rec["verdict"] != "deny" || rec["reason"] != "credential_revoked" ||
				rec["principal"] != "user:alice@example.com" || s["ctx_id"] != "ctxL" {
				t.Fatalf("a token minted before the revocation must be refused credential_revoked: %+v %v", reply, rec)
			}
			if got, err := time.Parse(time.RFC3339Nano, s["revoked_at"].(string)); err != nil || !got.Equal(revokedAt) {
				t.Fatalf("the record must carry the revoked_at that refused it: %v %v", s["revoked_at"], err)
			}
			if c.PrivLvl != 15 || len(c.SessionDiscriminators) != 1 {
				t.Fatalf("a refused login must not write the context: %+v", c)
			}
			last := f.records(t)[len(f.records(t))-1]
			if retry.Status != wire.AuthenStatusFail || last["reason"] != "credential_revoked" {
				t.Fatalf("a retransmission is refused as the login was, credential_revoked, not "+
					"receipt_replayed (PR #7's second follow-up): %+v %v", retry, last)
			}
		})
	}
}

// A join whose token carries a lower ceiling lowers the level window A holds,
// and window A's next command is denied privilege_exceeded. The redeem record
// is the only line that can say why, so it carries the level before and after
// (review M4); a join that clamps nothing carries neither.
func TestAJoinThatClampsTheHeldLevelSaysSo(t *testing.T) {
	for _, tt := range []struct {
		name    string
		ceiling uint8
		clamped bool
	}{
		{"a lower ceiling", 7, true},
		{"the same ceiling", 15, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := setup(t)
			start := f.joinFixture(t, nil)
			secret := f.tag() + "clmpclmpclmpclmpclmpclmp"
			if _, err := f.st.PutToken(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"},
				store.Token{ID: "c", Secret: []byte(secret), Kind: store.KindLogin, Username: "alice",
					Principal: "user:alice@example.com", Enable: "token", MaxPrivilege: tt.ceiling,
					ExpiresAt: f.now.Add(time.Minute)}); err != nil {
				t.Fatal(err)
			}
			start.Data = []byte(secret)
			if reply, _ := f.h.NewSession(f.peer).Start(context.Background(), start); reply.Status != wire.AuthenStatusPass {
				t.Fatalf("%+v %v", reply, f.records(t))
			}
			s := f.records(t)[0]["session"].(map[string]any)
			pc, ok := s["privilege_clamped"].(map[string]any)
			if ok != tt.clamped {
				t.Fatalf("privilege_clamped present %v, want %v: %v", ok, tt.clamped, s)
			}
			if tt.clamped && (pc["from"] != float64(15) || pc["to"] != float64(7)) {
				t.Fatalf("privilege_clamped = %v, want from 15 to 7", pc)
			}
		})
	}
}

// Test 5 of the decisions. The same device-facing username under another
// principal is not this operator's second window: it replaces, starts at its
// own login level with nothing bound, and the record names what it displaced.
func TestAnotherPrincipalUnderTheSameUsernameReplaces(t *testing.T) {
	f := setup(t)
	start := f.joinFixture(t, nil)
	secret := f.tag() + "othrothrothrothrothrothr"
	if _, err := f.st.PutToken(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"},
		store.Token{ID: "o", Secret: []byte(secret), Kind: store.KindLogin, Username: "alice",
			Principal: "user:alice@corp.example", ExpiresAt: f.now.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	start.Data = []byte(secret)
	if reply, _ := f.h.NewSession(f.peer).Start(context.Background(), start); reply.Status != wire.AuthenStatusPass {
		t.Fatalf("%+v", reply)
	}
	c, _ := f.st.GetContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"})
	if c.CtxID != "ctx1" || c.Principal != "user:alice@corp.example" || c.PrivLvl != 1 || len(c.SessionDiscriminators) != 0 {
		t.Fatalf("another principal must get a fresh context: %+v", c)
	}
	s := f.records(t)[0]["session"].(map[string]any)
	if s["ctx_id"] != "ctx1" || s["replaced_ctx_id"] != "ctxL" {
		t.Fatalf("the replace must name what it displaced: %v", s)
	}
}

// contextReadFails answers GetContext the way a store that is down does: an
// error that is neither ErrNotFound nor a record the sealing layer could not
// open.
type contextReadFails struct{ *memory.Store }

func (contextReadFails) GetContext(context.Context, store.ContextKey) (store.Context, error) {
	return store.Context{}, errors.New("store: connection refused")
}

// A store port49 cannot reach cannot tell it whether there is a context to
// join, and writing one blind could erase a revocation. The login is ERROR —
// and it is ERROR before the token is spent, so the operator's token still
// works once the store is back, and the device's retry is not a replay of a
// PASS nothing backs.
func TestAContextReadErrorFailsTheLoginBeforeTheTokenIsSpent(t *testing.T) {
	f := setupStore(t, func(st *memory.Store) store.Store { return contextReadFails{st} })
	reply, _ := f.h.NewSession(f.peer).Start(context.Background(), papStart("alice", "ssh", "198.51.100.4", f.tag()+"tok1tok1tok1tok1tok1tok1"))
	if reply.Status != wire.AuthenStatusError || f.records(t)[0]["reason"] != "store_unavailable" {
		t.Fatalf("%+v %v", reply, f.records(t))
	}
	if cands, _ := f.st.Candidates(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"}); len(cands) != 1 {
		t.Fatalf("the token must not be spent on a login that cannot be written: %d left", len(cands))
	}
}

// Ruling R1, end to end through the real sealing layer. A key rotation past
// the two-key window leaves a live context no daemon can open. Refusing the
// login would lock the operator out until the idle TTL reclaims a record the
// authorizer cannot use anyway; instead the login replaces it, the replace
// keeps the plaintext revocation (the token was minted before it), the
// record says what happened — replaced_unreadable, and no replaced_ctx_id,
// because that id is sealed — and the login is refused credential_revoked,
// because the context it wrote is revoked (spec §5.6).
func TestAContextUnderARetiredKeyIsReplacedCarryingItsRevocation(t *testing.T) {
	var v0, v2 crypt.Key
	v0.ID, v2.ID = "v0", "v2"
	copy(v0.Bytes[:], "retired-context-key-v0-32-bytes!")
	copy(v2.Bytes[:], "current-context-key-v2-32-bytes!")
	var sealed store.Store
	f := setupStore(t, func(st *memory.Store) store.Store {
		sealed = crypt.Wrap(st, crypt.Keys{Current: v2}, nil)
		return sealed
	})
	key := store.ContextKey{NAS: "leaf-01", Username: "alice"}
	revokedAt := f.now.Add(-time.Minute)
	if err := crypt.Wrap(f.st, crypt.Keys{Current: v0}, nil).PutContext(context.Background(), key,
		store.Context{CtxID: "ctxL", Principal: "user:alice@example.com", Username: "alice", PrivLvl: 15,
			RevokedAt: revokedAt}, time.Hour); err != nil {
		t.Fatal(err)
	}
	// setupStore's t1 sits in the inner store in plaintext, which the sealing
	// layer drops as unreadable; this login's token is sealed under v2.
	secret := f.tag() + "rotdrotdrotdrotdrotdrotd"
	if _, err := sealed.PutToken(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"},
		store.Token{ID: "r", Secret: []byte(secret), Kind: store.KindLogin, Username: "alice",
			Principal: "user:alice@example.com", MintedAt: revokedAt.Add(-time.Minute),
			ExpiresAt: f.now.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	reply, _ := f.h.NewSession(f.peer).Start(context.Background(), papStart("alice", "ssh", "198.51.100.4", secret))
	rec := f.records(t)[0]
	s := rec["session"].(map[string]any)
	// Replaced rather than refused before the token was read — and then
	// refused, because what the replace wrote carries a revocation this token
	// predates (the uniform check after the join; spec §5.6).
	if reply.Status != wire.AuthenStatusFail || rec["reason"] != "credential_revoked" || s["ctx_id"] != "ctx1" ||
		s["replaced_ctx_id"] != nil || s["replaced_unreadable"] != true {
		t.Fatalf("a context under a retired key is replaced, and a replace carrying a revocation is refused: %+v %v", reply, rec)
	}
	c, err := sealed.GetContext(context.Background(), key)
	if err != nil || c.CtxID != "ctx1" || c.PrivLvl != 1 || !c.RevokedAt.Equal(revokedAt) {
		t.Fatalf("the replace must be readable under the current key and keep the revocation: %+v %v", c, err)
	}
	if left, _ := sealed.Candidates(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"}); len(left) != 0 {
		t.Fatalf("the token is spent by the login that replaced the record: %d left", len(left))
	}
}

// Ruling F-I1. An unreadable replace cannot name what it displaced — the
// record's principal and credential are sealed — so it clears the ref whole,
// as another principal's replace does. Otherwise the displaced login's sid
// stays indexed and every extension of the replacing context re-stamps it, and
// a back-channel logout of that sid hours later revokes whoever logged in
// since.
func TestAnUnreadableReplaceUnindexesWhatItDisplaced(t *testing.T) {
	var v0, v2 crypt.Key
	v0.ID, v2.ID = "v0", "v2"
	copy(v0.Bytes[:], "retired-context-key-v0-32-bytes!")
	copy(v2.Bytes[:], "current-context-key-v2-32-bytes!")
	var sealed store.Store
	f := setupStore(t, func(st *memory.Store) store.Store {
		sealed = crypt.Wrap(st, crypt.Keys{Current: v2}, nil)
		return sealed
	})
	key := store.ContextKey{NAS: "leaf-01", Username: "alice"}
	ref := store.ContextRef{NAS: "leaf-01", Username: "alice"}
	if err := crypt.Wrap(f.st, crypt.Keys{Current: v0}, nil).PutContext(context.Background(), key,
		store.Context{CtxID: "ctxL", Principal: "user:bob@example.com", Username: "alice"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := f.st.IndexContext(context.Background(), "user:bob@example.com", "sid-bob", store.CertKey("ca", "0b"), ref, time.Hour); err != nil {
		t.Fatal(err)
	}
	secret := f.tag() + "rotdrotdrotdrotdrotdrotd"
	if _, err := sealed.PutToken(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"},
		store.Token{ID: "r", Secret: []byte(secret), Kind: store.KindLogin, Username: "alice",
			Principal: "user:alice@example.com", Credential: store.Credential{Method: "oidc", Sid: "sid-alice"},
			ExpiresAt: f.now.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	reply, _ := f.h.NewSession(f.peer).Start(context.Background(), papStart("alice", "ssh", "198.51.100.4", secret))
	if s := f.records(t)[0]["session"].(map[string]any); reply.Status != wire.AuthenStatusPass || s["replaced_unreadable"] != true {
		t.Fatalf("%+v %v", reply, f.records(t))
	}
	for i := 0; i < 8; i++ {
		f.now = f.now.Add(30 * time.Minute)
		if err := f.st.TouchContext(context.Background(), key, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	if refs, _ := f.st.ContextsBySid(context.Background(), "sid-bob"); len(refs) != 0 {
		t.Fatalf("4h after an unreadable replace the displaced sid still reaches the context: %v", refs)
	}
	if refs, _ := f.st.ContextsByCert(context.Background(), store.CertKey("ca", "0b")); len(refs) != 0 {
		t.Fatalf("the displaced certificate still reaches the context: %v", refs)
	}
	if refs, _ := f.st.ContextsByPrincipal(context.Background(), "user:bob@example.com"); len(refs) != 0 {
		t.Fatalf("the displaced principal still reaches the context: %v", refs)
	}
	if refs, _ := f.st.ContextsBySid(context.Background(), "sid-alice"); len(refs) != 1 {
		t.Fatalf("the new login must be indexed under its own sid: %v", refs)
	}
	if refs, _ := f.st.ContextsByPrincipal(context.Background(), "user:alice@example.com"); len(refs) != 1 {
		t.Fatalf("the new login must be indexed under its own principal: %v", refs)
	}
	if n := testutil.ToFloat64(f.m.StoreOps.WithLabelValues("join_context", "ok")); n != 1 {
		t.Fatalf("store_operations_total{op=join_context,outcome=ok} = %v, want 1", n)
	}
}

// Ruling P3. A replace displaces another principal's login, and the reverse
// index keeps every sid and certificate a context was indexed under (the
// memory store's indexKeys) — so unless the replace unindexes the displaced
// credential, a back-channel logout of the OLD principal's sid keeps reaching
// the NEW principal's context for as long as it is extended, and revocation
// marks it without asking whose it is (session.RevokeBySid).
func TestAReplaceUnindexesTheCredentialItDisplaced(t *testing.T) {
	f := setup(t)
	start := f.joinFixture(t, nil)
	ref := store.ContextRef{NAS: "leaf-01", Username: "alice"}
	// ctxL's own login indexed it, as redeem does.
	if err := f.st.IndexContext(context.Background(), "user:alice@example.com", "sid-1", store.CertKey("ca", "01"), ref, time.Hour); err != nil {
		t.Fatal(err)
	}
	secret := f.tag() + "othrothrothrothrothrothr"
	if _, err := f.st.PutToken(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"},
		store.Token{ID: "o", Secret: []byte(secret), Kind: store.KindLogin, Username: "alice",
			Principal: "user:alice@corp.example", Credential: store.Credential{Method: "oidc", Sid: "sid-corp"},
			ExpiresAt: f.now.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	start.Data = []byte(secret)
	if reply, _ := f.h.NewSession(f.peer).Start(context.Background(), start); reply.Status != wire.AuthenStatusPass {
		t.Fatalf("%+v", reply)
	}
	// Extensions are what would carry a stale entry forward past index_ttl.
	key := store.ContextKey{NAS: "leaf-01", Username: "alice"}
	for i := 0; i < 3; i++ {
		f.now = f.now.Add(30 * time.Minute)
		if err := f.st.TouchContext(context.Background(), key, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	if refs, _ := f.st.ContextsBySid(context.Background(), "sid-1"); len(refs) != 0 {
		t.Fatalf("the displaced principal's sid still reaches the replacing context: %v", refs)
	}
	if refs, _ := f.st.ContextsByCert(context.Background(), store.CertKey("ca", "01")); len(refs) != 0 {
		t.Fatalf("the displaced principal's certificate still reaches the replacing context: %v", refs)
	}
	if refs, _ := f.st.ContextsBySid(context.Background(), "sid-corp"); len(refs) != 1 {
		t.Fatalf("the new login must still be indexed under its own sid: %v", refs)
	}
	// Another principal's replace clears the ref whole (ruling P10).
	if refs, _ := f.st.ContextsByPrincipal(context.Background(), "user:alice@example.com"); len(refs) != 0 {
		t.Fatalf("the displaced principal still reaches the replacing context: %v", refs)
	}
	if refs, _ := f.st.ContextsByPrincipal(context.Background(), "user:alice@corp.example"); len(refs) != 1 {
		t.Fatalf("the new login must be indexed under its own principal: %v", refs)
	}
	if n := testutil.ToFloat64(f.m.StoreOps.WithLabelValues("join_context", "ok")); n != 1 {
		t.Fatalf("store_operations_total{op=join_context,outcome=ok} = %v, want 1", n)
	}
}

// certReachStore checks, after the one write the login makes (SwapLogin),
// that revocation by one certificate still finds ref. It is how a test sees
// the moment after the write, which is where an unindex-then-index would
// drop a key both logins share.
type certReachStore struct {
	*memory.Store
	certKey string
	ref     store.ContextRef
	missed  []string
}

func (c *certReachStore) check(ctx context.Context, after string) {
	if refs, _ := c.Store.ContextsByCert(ctx, c.certKey); len(refs) != 1 || refs[0] != c.ref {
		c.missed = append(c.missed, after)
	}
}

func (c *certReachStore) SwapLogin(ctx context.Context, k store.ContextKey, rev uint64, v store.Context,
	ttl time.Duration, w store.LoginWrite) error {
	err := c.Store.SwapLogin(ctx, k, rev, v, ttl, w)
	c.check(ctx, "swap_login")
	return err
}

// Ruling P9. A replace that shares keys with what it displaced — here the
// same principal logging in with the same certificate after its context
// passed its session ceiling — must not unindex the shared keys. Unindexing
// them and indexing them again would leave a moment in which a CRL naming
// that certificate finds nothing, and the context written in that moment
// would never be marked. Revocation by the certificate reaches the new
// context at every point of the login, and after it.
func TestAReplaceKeepsTheKeysItShares(t *testing.T) {
	var cs *certReachStore
	ref := store.ContextRef{NAS: "leaf-01", Username: "alice"}
	certKey := store.CertKey("ca", "01")
	f := setupStore(t, func(st *memory.Store) store.Store {
		cs = &certReachStore{Store: st, certKey: certKey, ref: ref}
		return cs
	})
	cert := store.Credential{Method: "cert", Issuer: "ca", Serial: "01"}
	f.seedLoginWith(t, "token", 15, func(c *store.Context) {
		c.Credential = cert
		c.SessionExpires = f.now.Add(time.Minute)
	})
	if err := f.st.IndexContext(context.Background(), "user:alice@example.com", "", certKey, ref, time.Hour); err != nil {
		t.Fatal(err)
	}
	secret := f.tag() + "certcertcertcertcertcert"
	if _, err := f.st.PutToken(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"},
		store.Token{ID: "c", Secret: []byte(secret), Kind: store.KindLogin, Username: "alice",
			Principal: "user:alice@example.com", Credential: cert, ExpiresAt: f.now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(2 * time.Minute)
	if reply, _ := f.h.NewSession(f.peer).Start(context.Background(), papStart("alice", "ssh", "198.51.100.4", secret)); reply.Status != wire.AuthenStatusPass {
		t.Fatalf("%+v", reply)
	}
	if s := f.records(t)[0]["session"].(map[string]any); s["ctx_id"] != "ctx1" || s["replaced_ctx_id"] != "ctxL" {
		t.Fatalf("a login past the ceiling must replace: %v", s)
	}
	if len(cs.missed) != 0 {
		t.Fatalf("revocation by the shared certificate missed the context after %v", cs.missed)
	}
	key := store.ContextKey{NAS: "leaf-01", Username: "alice"}
	for i := 0; i < 3; i++ {
		f.now = f.now.Add(30 * time.Minute)
		if err := f.st.TouchContext(context.Background(), key, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	if refs, _ := f.st.ContextsByPrincipal(context.Background(), "user:alice@example.com"); len(refs) != 1 {
		t.Fatalf("the shared principal must still reach the replacing context: %v", refs)
	}
	refs, err := session.New(f.st, func() time.Time { return f.now }, time.Hour, time.Hour).RevokeByCert(context.Background(), "ca", "01")
	if err != nil || len(refs) != 1 {
		t.Fatalf("revocation by the shared certificate: %v %v", refs, err)
	}
	if c, _ := f.st.GetContext(context.Background(), key); c.CtxID != "ctx1" || c.RevokedAt.IsZero() {
		t.Fatalf("the replacing context must be revoked: %+v", c)
	}
}

// Ruling P4, for a login. The receipt froze the ctx_id the login was written
// under, and a retransmission replays PASS only while that is still the live
// context. A second login by the same principal JOINS it and keeps the id, so
// the replay still lands. Another principal's replace, or a reclaim, leaves a
// receipt naming a context that no longer exists: answering PASS from it would
// admit a session whose authorizations then answer from someone else's
// context, or from none. It is `token_spent`, and the window does not slide.
func TestARetransmittedLoginReplaysOnlyOntoTheContextItWasWrittenFor(t *testing.T) {
	putAndLogin := func(t *testing.T, f *fixture, id, principal, secret string) {
		t.Helper()
		if _, err := f.st.PutToken(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"},
			store.Token{ID: id, Secret: []byte(secret), Kind: store.KindLogin, Username: "alice",
				Principal: principal, ExpiresAt: f.now.Add(time.Minute)}); err != nil {
			t.Fatal(err)
		}
		if reply, _ := f.h.NewSession(f.peer).Start(context.Background(), papStart("alice", "ssh", "198.51.100.4", secret)); reply.Status != wire.AuthenStatusPass {
			t.Fatalf("login %s: %+v", id, reply)
		}
	}
	for _, tt := range []struct {
		name    string
		between func(t *testing.T, f *fixture)
		replays bool
	}{
		{"the same principal's second login joined it", func(t *testing.T, f *fixture) {
			putAndLogin(t, f, "t2", "user:alice@example.com", f.tag()+"tok2tok2tok2tok2tok2tok2")
		}, true},
		{"another principal's login replaced it", func(t *testing.T, f *fixture) {
			putAndLogin(t, f, "o", "user:alice@corp.example", f.tag()+"othrothrothrothrothrothr")
		}, false},
		{"the idle TTL reclaimed it", func(t *testing.T, f *fixture) {
			if err := f.st.DeleteContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"}); err != nil {
				t.Fatal(err)
			}
		}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var counter *extendCountingStore
			f := setupStore(t, func(st *memory.Store) store.Store {
				counter = &extendCountingStore{Store: st}
				return counter
			})
			first := papStart("alice", "ssh", "198.51.100.4", f.tag()+"tok1tok1tok1tok1tok1tok1")
			if reply, _ := f.h.NewSession(f.peer).Start(context.Background(), first); reply.Status != wire.AuthenStatusPass {
				t.Fatalf("first login: %+v", reply)
			}
			tt.between(t, f)
			reply, _ := f.h.NewSession(f.peer).Start(context.Background(), first)
			r := f.records(t)
			last := r[len(r)-1]
			if tt.replays {
				if reply.Status != wire.AuthenStatusPass || last["reason"] != "receipt_replayed" ||
					last["session"].(map[string]any)["ctx_id"] != "ctx1" || counter.extends != 1 {
					t.Fatalf("a receipt for the joined context must replay: %+v %v, %d extends", reply, last, counter.extends)
				}
				return
			}
			if reply.Status != wire.AuthenStatusFail || last["reason"] != "token_spent" || counter.extends != 0 {
				t.Fatalf("a receipt for a context that no longer exists must not replay, or slide: %+v %v, %d extends",
					reply, last, counter.extends)
			}
		})
	}
}

// Ruling P4, for an enable; it replaces TestReplayedEnableNamesTheLiveContext.
// The receipt froze the ctx_id the escalation raised, and a retransmitted
// enable replays that escalation only onto that context. The same principal's
// second login joins it and keeps the id, so the replay still lands. A replace
// writes a new ctx_id — the same principal past its session ceiling, or
// another principal under the same username — and raising the replacing
// context would carry an escalation across a ceiling that ended, or hand one
// principal's enable to another's session. It is `token_spent`.
func TestAReplayedEnableActsOnlyOnTheContextItWasWrittenFor(t *testing.T) {
	for _, tt := range []struct {
		name      string
		ceiling   time.Duration // the seeded context's SessionExpires, from now
		advance   time.Duration // between the escalation and the relogin
		principal string        // the relogin's
		ctxID     string        // where the relogin lands
		replays   bool
	}{
		{"the same principal's second login joined it", 8 * time.Hour, 0, "user:alice@example.com", "ctxL", true},
		{"the same principal's login past the ceiling replaced it", time.Minute, 2 * time.Minute, "user:alice@example.com", "ctx1", false},
		{"another principal's login replaced it", 8 * time.Hour, 0, "user:alice@corp.example", "ctx1", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := setup(t)
			f.seedLoginWith(t, "token", 15, func(c *store.Context) { c.SessionExpires = f.now.Add(tt.ceiling) })
			enable := f.tag() + "enabenabenabenabenab0123"
			relogin := f.tag() + "relgrelgrelgrelgrelgrelg"
			for id, tok := range map[string]store.Token{
				"en": {Secret: []byte(enable), Kind: store.KindEnable, Principal: "user:alice@example.com"},
				"re": {Secret: []byte(relogin), Kind: store.KindLogin, Principal: tt.principal, Enable: "token", MaxPrivilege: 15},
			} {
				tok.ID, tok.Username, tok.ExpiresAt = id, "alice", f.now.Add(time.Hour)
				if _, err := f.st.PutToken(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"}, tok); err != nil {
					t.Fatal(err)
				}
			}
			sess := f.h.NewSession(f.peer)
			sess.Start(context.Background(), f.enableStart("alice"))
			if reply, _ := sess.Continue(context.Background(), wire.AuthenContinue{UserMsg: []byte(enable)}); reply.Status != wire.AuthenStatusPass {
				t.Fatalf("first escalation: %+v", reply)
			}
			f.now = f.now.Add(tt.advance)
			if reply, _ := f.h.NewSession(f.peer).Start(context.Background(), papStart("alice", "ssh", "198.51.100.4", relogin)); reply.Status != wire.AuthenStatusPass {
				t.Fatalf("relogin: %+v", reply)
			}
			key := store.ContextKey{NAS: "leaf-01", Username: "alice"}
			if c, _ := f.st.GetContext(context.Background(), key); c.CtxID != tt.ctxID {
				t.Fatalf("the relogin landed on %q, want %q", c.CtxID, tt.ctxID)
			}

			// The device retransmits the enable, inside the receipt window.
			sess2 := f.h.NewSession(f.peer)
			sess2.Start(context.Background(), f.enableStart("alice"))
			reply, _ := sess2.Continue(context.Background(), wire.AuthenContinue{UserMsg: []byte(enable)})
			last := f.records(t)[len(f.records(t))-1]
			c, _ := f.st.GetContext(context.Background(), key)
			if tt.replays {
				if reply.Status != wire.AuthenStatusPass || last["reason"] != "receipt_replayed" ||
					last["session"].(map[string]any)["ctx_id"] != "ctxL" || c.PrivLvl != 15 {
					t.Fatalf("the replay must act on the joined context: %+v %v %+v", reply, last, c)
				}
				return
			}
			if reply.Status != wire.AuthenStatusFail || last["event"] != "escalate" || last["reason"] != "token_spent" || c.PrivLvl != 1 {
				t.Fatalf("a replayed enable must not raise a context it was not written for: %+v %v %+v", reply, last, c)
			}
		})
	}
}

// Ruling P8, through the login that writes the index. An OIDC login carries
// no certificate and a certificate login no sid; neither leaves an entry under
// the blank it does not have, so no lookup by a blank can find either.
func TestALoginIndexesNoBlankSidOrCertificate(t *testing.T) {
	for _, tt := range []struct {
		name string
		cred store.Credential
	}{
		{"oidc", store.Credential{Method: "oidc", Sid: "sid-1", Sub: "a7f3"}},
		{"certificate", store.Credential{Method: "cert", Issuer: "ca", Serial: "01"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := setup(t)
			secret := f.tag() + "credcredcredcredcredcred"
			if _, err := f.st.PutToken(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"},
				store.Token{ID: "c", Secret: []byte(secret), Kind: store.KindLogin, Username: "alice",
					Principal: "user:alice@example.com", Credential: tt.cred, ExpiresAt: f.now.Add(time.Minute)}); err != nil {
				t.Fatal(err)
			}
			if reply, _ := f.h.NewSession(f.peer).Start(context.Background(), papStart("alice", "ssh", "198.51.100.4", secret)); reply.Status != wire.AuthenStatusPass {
				t.Fatalf("%+v", reply)
			}
			if refs, _ := f.st.ContextsBySid(context.Background(), ""); len(refs) != 0 {
				t.Fatalf("the empty sid is indexed: %v", refs)
			}
			for _, certKey := range []string{"|", "ca|", "|01"} {
				if refs, _ := f.st.ContextsByCert(context.Background(), certKey); len(refs) != 0 {
					t.Fatalf("cert key %q is indexed: %v", certKey, refs)
				}
			}
			if refs, _ := f.st.ContextsByPrincipal(context.Background(), "user:alice@example.com"); len(refs) != 1 {
				t.Fatalf("the principal must still be indexed: %v", refs)
			}
		})
	}
}

// midRedemption runs during after the token is spent and before the login's
// JoinContext: the gap between the pre-read that predicted the ctx_id and the
// join that decides it.
type midRedemption struct {
	*memory.Store
	during func()
}

func (m midRedemption) RedeemAndReceipt(ctx context.Context, k store.TokenKey, tokenID string, w store.ReceiptWrite) error {
	err := m.Store.RedeemAndReceipt(ctx, k, tokenID, w)
	m.during()
	return err
}

// The pre-read predicted a join, and by the time JoinContext read the context
// again it was no longer joinable — its ceiling passed, or another principal's
// login replaced it. The login replaces it, and the context it writes must
// carry an id of its own: written under the predicted id, one ctx_id would
// name two contexts (spec §5.6: assigned once, never changes), the record
// would say a context replaced itself, and an enable receipt written for the
// displaced context would still match and carry its escalation across. The
// receipt names the prediction, which no context holds, so the login's
// retransmission is `token_spent` and the device prompts again.
func TestAJoinThatBecomesAReplaceMidLoginWritesAFreshCtxID(t *testing.T) {
	for _, tt := range []struct {
		name     string
		during   func(f *fixture)
		replaced string
	}{
		{"the ceiling passed", func(f *fixture) { f.now = f.now.Add(2 * time.Minute) }, "ctxL"},
		{"another principal replaced it", func(f *fixture) {
			f.st.PutContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"},
				store.Context{CtxID: "ctxB", Principal: "user:alice@corp.example", Username: "alice"}, time.Hour)
		}, "ctxB"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var f *fixture
			f = setupStore(t, func(st *memory.Store) store.Store {
				return midRedemption{Store: st, during: func() { tt.during(f) }}
			})
			f.seedLoginWith(t, "token", 15, func(c *store.Context) { c.SessionExpires = f.now.Add(time.Minute) })
			start := papStart("alice", "ssh", "198.51.100.4", f.tag()+"tok1tok1tok1tok1tok1tok1")
			reply, _ := f.h.NewSession(f.peer).Start(context.Background(), start)
			s := f.records(t)[0]["session"].(map[string]any)
			if reply.Status != wire.AuthenStatusPass || s["ctx_id"] == "ctxL" || s["ctx_id"] == s["replaced_ctx_id"] ||
				s["replaced_ctx_id"] != tt.replaced {
				t.Fatalf("a replace must write a ctx_id of its own: %+v %v", reply, s)
			}
			c, _ := f.st.GetContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"})
			if c.CtxID != s["ctx_id"] || c.PrivLvl != 1 {
				t.Fatalf("the live context must be the fresh one the record names: %+v", c)
			}
			reply, _ = f.h.NewSession(f.peer).Start(context.Background(), start)
			r := f.records(t)
			if last := r[len(r)-1]; reply.Status != wire.AuthenStatusFail || last["reason"] != "token_spent" {
				t.Fatalf("a receipt naming the mispredicted id must not replay: %+v %v", reply, last)
			}
		})
	}
}

// Ruling P10. A context two logins joined is indexed under both logins' sids,
// and a replace can read only the last one off the record it displaced. When
// another principal replaces it, every key the ref was indexed under goes,
// or a back-channel logout of the displaced principal's EARLIER session would
// keep marking the new principal's context for as long as it is extended.
func TestAnotherPrincipalsReplaceUnindexesEveryJoinedLogin(t *testing.T) {
	f := setup(t)
	for _, tok := range []store.Token{
		{ID: "s1", Principal: "user:alice@example.com", Credential: store.Credential{Method: "oidc", Sid: "sid-1"}},
		{ID: "s2", Principal: "user:alice@example.com", Credential: store.Credential{Method: "oidc", Sid: "sid-2"}},
		{ID: "o", Principal: "user:alice@corp.example", Credential: store.Credential{Method: "oidc", Sid: "sid-corp"}},
	} {
		tok.Secret, tok.Kind, tok.Username, tok.ExpiresAt = []byte(f.tag()+tok.ID+strings.Repeat("x", 24-len(tok.ID))),
			store.KindLogin, "alice", f.now.Add(time.Hour)
		if _, err := f.st.PutToken(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"}, tok); err != nil {
			t.Fatal(err)
		}
		if reply, _ := f.h.NewSession(f.peer).Start(context.Background(),
			papStart("alice", "ssh", "198.51.100.4", string(tok.Secret))); reply.Status != wire.AuthenStatusPass {
			t.Fatalf("login %s: %+v", tok.ID, reply)
		}
	}
	if s := f.records(t)[2]["session"].(map[string]any); s["replaced_ctx_id"] != "ctx1" {
		t.Fatalf("the third login must replace the joined context: %v", s)
	}
	key := store.ContextKey{NAS: "leaf-01", Username: "alice"}
	for i := 0; i < 3; i++ {
		f.now = f.now.Add(30 * time.Minute)
		if err := f.st.TouchContext(context.Background(), key, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	for _, sid := range []string{"sid-1", "sid-2"} {
		if refs, _ := f.st.ContextsBySid(context.Background(), sid); len(refs) != 0 {
			t.Fatalf("the displaced principal's %s still reaches the replacing context: %v", sid, refs)
		}
	}
	if refs, _ := f.st.ContextsByPrincipal(context.Background(), "user:alice@example.com"); len(refs) != 0 {
		t.Fatalf("the displaced principal still reaches the replacing context: %v", refs)
	}
	if refs, _ := f.st.ContextsBySid(context.Background(), "sid-corp"); len(refs) != 1 {
		t.Fatalf("the new login must be indexed under its own sid: %v", refs)
	}
	refs, err := session.New(f.st, func() time.Time { return f.now }, time.Hour, time.Hour).RevokeBySid(context.Background(), "sid-1")
	if err != nil || len(refs) != 0 {
		t.Fatalf("a logout of the displaced principal's first session must mark nothing: %v %v", refs, err)
	}
	if c, _ := f.st.GetContext(context.Background(), key); !c.RevokedAt.IsZero() {
		t.Fatalf("the replacing context was revoked by another principal's logout: %+v", c)
	}
	if refs, _ := f.st.ContextsByPrincipal(context.Background(), "user:alice@corp.example"); len(refs) != 1 {
		t.Fatalf("the new login must be indexed under its own principal: %v", refs)
	}
	if n := testutil.ToFloat64(f.m.StoreOps.WithLabelValues("join_context", "ok")); n != 3 {
		t.Fatalf("store_operations_total{op=join_context,outcome=ok} = %v, want 3", n)
	}
}

// PR #7's first follow-up. A login can write a context that is revoked in
// ways its pre-read cannot see: the same principal's context past its ceiling
// is replaced carrying a revocation the token predates, and a revocation that
// lands between the pre-read and the join is merged by it. (The third, a
// record under a retired key, is TestAContextUnderARetiredKeyIsReplacedCarryingItsRevocation.)
// Each must answer FAIL credential_revoked with the token spent and the
// revocation on the record — the enable gate's answer for the same state — and
// the retransmission must be refused the same way, never replayed as the PASS
// the receipt was written with.
func TestALoginWhoseContextEndsUpRevokedIsRefused(t *testing.T) {
	revokedAt := time.Unix(1_757_041_495, 0).Add(-time.Minute)
	key := store.ContextKey{NAS: "leaf-01", Username: "alice"}
	for _, tt := range []struct {
		name            string
		setup           func(t *testing.T) (*fixture, wire.AuthenStart)
		ctxID, replaced string
	}{
		{"the same principal past its ceiling", func(t *testing.T) (*fixture, wire.AuthenStart) {
			f := setup(t)
			f.seedLoginWith(t, "token", 15, func(c *store.Context) {
				c.RevokedAt = revokedAt
				c.SessionExpires = f.now.Add(time.Minute)
			})
			f.now = f.now.Add(2 * time.Minute)
			return f, papStart("alice", "ssh", "198.51.100.4", f.tag()+"tok1tok1tok1tok1tok1tok1")
		}, "ctx1", "ctxL"},
		{"a revocation landing mid-join", func(t *testing.T) (*fixture, wire.AuthenStart) {
			f := setupStore(t, func(st *memory.Store) store.Store {
				return midRedemption{Store: st, during: func() { _ = st.SetRevokedAt(context.Background(), key, revokedAt) }}
			})
			return f, f.joinFixture(t, nil)
		}, "ctxL", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f, start := tt.setup(t)
			reply, _ := f.h.NewSession(f.peer).Start(context.Background(), start)
			rec := f.records(t)[0]
			s := rec["session"].(map[string]any)
			if reply.Status != wire.AuthenStatusFail || rec["verdict"] != "deny" || rec["reason"] != "credential_revoked" ||
				rec["principal"] != "user:alice@example.com" || s["ctx_id"] != tt.ctxID {
				t.Fatalf("a login whose context ends up revoked must be refused credential_revoked: %+v %v", reply, rec)
			}
			if tt.replaced != "" && s["replaced_ctx_id"] != tt.replaced {
				t.Fatalf("the replace must still name what it displaced: %v", s)
			}
			ra, _ := s["revoked_at"].(string)
			if got, err := time.Parse(time.RFC3339Nano, ra); err != nil || !got.Equal(revokedAt) {
				t.Fatalf("the record must carry the revocation that refused it: %q %v", ra, err)
			}
			if left, _ := f.st.Candidates(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"}); len(left) != 0 {
				t.Fatalf("the token must be spent: %d left", len(left))
			}
			retry, _ := f.h.NewSession(f.peer).Start(context.Background(), start)
			r := f.records(t)
			if last := r[len(r)-1]; retry.Status != wire.AuthenStatusFail || last["reason"] != "credential_revoked" {
				t.Fatalf("the retransmission must be refused as revoked, not replayed: %+v %v", retry, last)
			}
		})
	}
}

// The control for the replace case: a token minted after the revocation is
// the broker having verified the credential again, and the replace it writes
// is not revoked (spec §13, decision 15). The uniform check must not refuse it.
func TestAReplacePastTheCeilingWithATokenMintedAfterTheRevocationAdmits(t *testing.T) {
	revokedAt := time.Unix(1_757_041_495, 0).Add(-time.Minute)
	f := setup(t)
	f.seedLoginWith(t, "token", 15, func(c *store.Context) {
		c.RevokedAt = revokedAt
		c.SessionExpires = f.now.Add(time.Minute)
	})
	secret := f.tag() + "aftraftraftraftraftraftr"
	if _, err := f.st.PutToken(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"},
		store.Token{ID: "a", Secret: []byte(secret), Kind: store.KindLogin, Username: "alice",
			Principal: "user:alice@example.com", MintedAt: revokedAt.Add(time.Second),
			ExpiresAt: f.now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(2 * time.Minute)
	reply, _ := f.h.NewSession(f.peer).Start(context.Background(), papStart("alice", "ssh", "198.51.100.4", secret))
	if rec := f.records(t)[0]; reply.Status != wire.AuthenStatusPass || rec["reason"] != "token_redeemed" {
		t.Fatalf("a token minted after the revocation must be admitted: %+v %v", reply, rec)
	}
	if c, _ := f.st.GetContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"}); !c.RevokedAt.IsZero() {
		t.Fatalf("the replace must not carry a revocation its token postdates: %+v", c)
	}
}

// A login refused credential_revoked after its join wrote its receipt as PASS
// before the join. The receipt branch refuses on the live context while it is
// revoked, but a token minted after the revocation lifts it on the same ctx_id
// (decision 15), and from then on the refused token's retransmission would
// replay the PASS: the second try spec §5.6 denies a token the revocation was
// meant to stop. The refusal marks its receipt FAIL, so the retransmission
// replays the refusal whatever the context says now.
func TestARefusedLoginStaysRefusedAfterTheRevocationIsLifted(t *testing.T) {
	revokedAt := time.Unix(1_757_041_495, 0).Add(-time.Minute)
	f := setup(t)
	f.seedLoginWith(t, "token", 15, func(c *store.Context) {
		c.RevokedAt = revokedAt
		c.SessionExpires = f.now.Add(time.Minute)
	})
	f.now = f.now.Add(2 * time.Minute)
	start := papStart("alice", "ssh", "198.51.100.4", f.tag()+"tok1tok1tok1tok1tok1tok1")
	if reply, _ := f.h.NewSession(f.peer).Start(context.Background(), start); reply.Status != wire.AuthenStatusFail {
		t.Fatalf("the replace past the ceiling must be refused: %+v", reply)
	}
	secret := f.tag() + "aftraftraftraftraftraftr"
	if _, err := f.st.PutToken(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"},
		store.Token{ID: "a", Secret: []byte(secret), Kind: store.KindLogin, Username: "alice",
			Principal: "user:alice@example.com", MintedAt: f.now, ExpiresAt: f.now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(time.Minute)
	if reply, _ := f.h.NewSession(f.peer).Start(context.Background(), papStart("alice", "ssh", "198.51.100.4", secret)); reply.Status != wire.AuthenStatusPass {
		t.Fatalf("a token minted after the revocation must be admitted, lifting it: %+v", reply)
	}
	if c, _ := f.st.GetContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"}); !c.RevokedAt.IsZero() {
		t.Fatalf("the join must have lifted the revocation for this test to mean anything: %+v", c)
	}
	f.now = f.now.Add(time.Minute)
	retry, _ := f.h.NewSession(f.peer).Start(context.Background(), start)
	r := f.records(t)
	if last := r[len(r)-1]; retry.Status != wire.AuthenStatusFail || last["verdict"] != "deny" || last["reason"] != "receipt_replayed" {
		t.Fatalf("a token refused credential_revoked must replay its refusal once the revocation is lifted: %+v %v", retry, last)
	}
}

// failedReceiptStore answers every receipt marked Failed, as FailReceipt
// leaves one: the login or escalation it was written for was refused after.
type failedReceiptStore struct{ *memory.Store }

func (s failedReceiptStore) GetReceipt(ctx context.Context, rk store.ReceiptKey) (store.Receipt, error) {
	r, err := s.Store.GetReceipt(ctx, rk)
	r.Failed = true
	return r, err
}

// A retransmitted enable whose receipt is marked failed replays the refusal;
// Failed overrides the PASS it was written with, on the retransmission path
// as on the race-loser path (T2 re-review nit).
func TestARetransmittedEnableOnAFailedReceiptIsRefused(t *testing.T) {
	f := setupStore(t, func(st *memory.Store) store.Store { return failedReceiptStore{st} })
	f.seedLogin(t, "token", 15)
	secret := f.tag() + "enabenabenabenabenab0123"
	f.st.PutToken(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"},
		store.Token{ID: "en", Secret: []byte(secret), Kind: store.KindEnable, Username: "alice",
			Principal: "user:alice@example.com", ExpiresAt: f.now.Add(time.Minute)})
	for i, want := range []uint8{wire.AuthenStatusPass, wire.AuthenStatusFail} {
		sess := f.h.NewSession(f.peer)
		sess.Start(context.Background(), f.enableStart("alice"))
		reply, _ := sess.Continue(context.Background(), wire.AuthenContinue{UserMsg: []byte(secret)})
		if reply.Status != want {
			t.Fatalf("presentation %d: status %d, want %d: %v", i+1, reply.Status, want, f.records(t))
		}
	}
	if last := f.records(t)[len(f.records(t))-1]; last["verdict"] != "deny" || last["reason"] != "receipt_replayed" {
		t.Fatalf("a failed receipt replays its refusal: %v", last)
	}
}

// receiptGoneStore answers FailReceipt with ErrNotFound: a revocation by
// principal deleted the receipt between the join and the refusal.
type receiptGoneStore struct{ *memory.Store }

func (receiptGoneStore) FailReceipt(context.Context, store.ReceiptKey) error {
	return store.ErrNotFound
}

// A receipt a revocation already deleted cannot replay a PASS, so the mark
// that did not land cost nothing: the refusal carries no index_error, which
// would send an incident responder after a loss that did not happen.
func TestAFailReceiptOnADeletedReceiptCostsNothing(t *testing.T) {
	revokedAt := time.Unix(1_757_041_495, 0).Add(-time.Minute)
	f := setupStore(t, func(st *memory.Store) store.Store { return receiptGoneStore{st} })
	f.seedLoginWith(t, "token", 15, func(c *store.Context) {
		c.RevokedAt = revokedAt
		c.SessionExpires = f.now.Add(time.Minute)
	})
	f.now = f.now.Add(2 * time.Minute)
	reply, _ := f.h.NewSession(f.peer).Start(context.Background(),
		papStart("alice", "ssh", "198.51.100.4", f.tag()+"tok1tok1tok1tok1tok1tok1"))
	rec := f.records(t)[0]
	if reply.Status != wire.AuthenStatusFail || rec["reason"] != "credential_revoked" {
		t.Fatalf("still refused credential_revoked: %+v %v", reply, rec)
	}
	if ie, ok := rec["index_error"]; ok {
		t.Fatalf("a receipt already deleted lost nothing; index_error %q", ie)
	}
}

// failReceiptErrorStore loses the FailReceipt write, which is what a store
// outage between the join and the refusal looks like.
type failReceiptErrorStore struct{ *memory.Store }

func (failReceiptErrorStore) FailReceipt(context.Context, store.ReceiptKey) error {
	return errors.New("store down")
}

// A FailReceipt that does not land does not turn the refusal into anything
// else: the answer is FAIL credential_revoked, the metric counts the error,
// and the record says what the lost write costs.
func TestALostFailReceiptStillRefusesAndSaysSo(t *testing.T) {
	revokedAt := time.Unix(1_757_041_495, 0).Add(-time.Minute)
	f := setupStore(t, func(st *memory.Store) store.Store { return failReceiptErrorStore{st} })
	f.seedLoginWith(t, "token", 15, func(c *store.Context) {
		c.RevokedAt = revokedAt
		c.SessionExpires = f.now.Add(time.Minute)
	})
	f.now = f.now.Add(2 * time.Minute)
	reply, _ := f.h.NewSession(f.peer).Start(context.Background(),
		papStart("alice", "ssh", "198.51.100.4", f.tag()+"tok1tok1tok1tok1tok1tok1"))
	rec := f.records(t)[0]
	ie, _ := rec["index_error"].(string)
	if reply.Status != wire.AuthenStatusFail || rec["reason"] != "credential_revoked" || !strings.Contains(ie, "receipt") {
		t.Fatalf("a lost FailReceipt must still refuse, and say what it cost: %+v %v", reply, rec)
	}
}

// A token whose session ceiling has passed opens nothing, even one still
// inside its own TTL: FAIL session_expired, with the record, and no context
// and no receipt written (plan 7b final review I-1). The token here is put
// with the full TTL the minter no longer gives, so this is the redeem check
// alone. Junos keeps a session whose authorization is refused and never asks
// again (decision 21), so on Junos this FAIL is the gate.
func TestARedeemPastTheSessionCeilingFails(t *testing.T) {
	f := setup(t)
	secret := f.tag() + "ceil1ceil1ceil1ceil1ceil"
	authTime := f.now.Add(-61 * time.Minute)
	if _, err := f.st.PutToken(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "bob"},
		store.Token{ID: "t9", Secret: []byte(secret), Kind: store.KindLogin, Username: "bob",
			Principal: "user:bob@example.com", Enable: "token", MaxPrivilege: 15,
			MaxSessionAge: time.Hour, AuthTime: authTime, MintedAt: f.now.Add(-2 * time.Minute),
			ExpiresAt: f.now.Add(13 * time.Minute)}); err != nil {
		t.Fatal(err)
	}
	start := wire.AuthenStart{Action: wire.AuthenActionLogin, PrivLvl: 1, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte("bob"), Port: []byte("vty0"), Data: []byte(secret)}
	for i := 0; i < 2; i++ {
		// The second is a retransmission: no receipt was written, so it is
		// refused the same way rather than replayed.
		reply, done := f.h.NewSession(f.peer).Start(context.Background(), start)
		if !done || reply.Status != wire.AuthenStatusFail {
			t.Fatalf("presentation %d past the ceiling: status %d done %v", i, reply.Status, done)
		}
		r := f.records(t)[i]
		sess := r["session"].(map[string]any)
		if r["event"] != "redeem" || r["verdict"] != "deny" || r["reason"] != "session_expired" ||
			r["principal"] != "user:bob@example.com" ||
			sess["session_expires"] != decision.FormatTime(authTime.Add(time.Hour)) {
			t.Fatalf("record %d: %v", i, r)
		}
	}
	if _, err := f.st.GetContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "bob"}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a context was written past the ceiling: %v", err)
	}
	if c, _ := f.st.Candidates(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "bob"}); len(c) != 1 {
		t.Fatalf("the refused token was spent: %d left", len(c))
	}
	if strings.Contains(f.log.String(), secret) {
		t.Fatal("token leaked into the log")
	}
	// A minute before the ceiling the same token opens a session.
	f.now = authTime.Add(59 * time.Minute)
	if reply, _ := f.h.NewSession(f.peer).Start(context.Background(), start); reply.Status != wire.AuthenStatusPass {
		t.Fatalf("inside the ceiling: status %d", reply.Status)
	}
}

// The reviewer's case end to end, through the real minter: with a 1h
// ceiling, a token minted at 59m does not redeem at 1h01m (plan 7b final
// review I-1).
func TestATokenMintedBeforeTheCeilingDoesNotRedeemAfterIt(t *testing.T) {
	f := setup(t)
	authTime := f.now
	f.now = authTime.Add(59 * time.Minute)
	m := token.NewMinter(f.st, decision.NewJSONLines(&bytes.Buffer{}), rand.Reader, labTagKey,
		func() time.Time { return f.now }, 8)
	res, err := m.Mint(context.Background(), token.Request{Device: "leaf-01", Platform: "juniper_vsrx",
		Subject: token.Subject{Principal: "user:bob@example.com", Username: "bob", TokenTTL: 15 * time.Minute,
			Enable: "token", MaxPrivilege: 15, MaxSessionAge: time.Hour, AuthTime: authTime}})
	if err != nil {
		t.Fatal(err)
	}
	f.now = authTime.Add(61 * time.Minute)
	reply, _ := f.h.NewSession(f.peer).Start(context.Background(), wire.AuthenStart{Action: wire.AuthenActionLogin,
		PrivLvl: 1, AuthenType: wire.AuthenTypePAP, Service: wire.AuthenServiceLogin, User: []byte("bob"),
		Port: []byte("vty0"), Data: []byte(res.Login)})
	if reply.Status != wire.AuthenStatusFail {
		t.Fatalf("a token minted at 59m redeemed at 1h01m: status %d", reply.Status)
	}
	if _, err := f.st.GetContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "bob"}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a context was written past the ceiling: %v", err)
	}
}

// A token minted from a membership verified earlier (a grace mint, plan
// 7g Ruling 11) gives its context that instant as refreshed_at, so the
// staleness ceiling counts from the directory's last answer, not the
// redemption. A token with none (no directory) is the redemption's now.
func TestALoginTakesTheTokensVerifiedAt(t *testing.T) {
	for _, c := range []struct {
		name     string
		verified time.Duration // before f.now; 0 is none
		want     time.Duration
	}{{"a grace mint", 3 * time.Hour, 3 * time.Hour}, {"no directory", 0, 0}} {
		t.Run(c.name, func(t *testing.T) {
			f := setup(t)
			secret := f.tag() + "veriveriveriveriveri0123"
			tok := store.Token{ID: "v", Secret: []byte(secret), Kind: store.KindLogin, Username: "alice",
				Principal: "user:alice@example.com", BlobHash: "sha256:b", AuthTime: f.now, Enable: "token",
				MaxPrivilege: 15, ExpiresAt: f.now.Add(time.Minute)}
			if c.verified > 0 {
				tok.VerifiedAt = f.now.Add(-c.verified)
			}
			if _, err := f.st.PutToken(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"}, tok); err != nil {
				t.Fatal(err)
			}
			f.h.NewSession(f.peer).Start(context.Background(), wire.AuthenStart{Action: wire.AuthenActionLogin,
				AuthenType: wire.AuthenTypePAP, Service: wire.AuthenServiceLogin, User: []byte("alice"),
				Port: []byte("ssh"), RemAddr: []byte("198.51.100.4"), Data: []byte(secret)})
			got, err := f.st.GetContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"})
			if err != nil || !got.RefreshedAt.Equal(f.now.Add(-c.want)) {
				t.Fatalf("refreshed_at %v, want %v (%v)", got.RefreshedAt, f.now.Add(-c.want), err)
			}
		})
	}
}

// A VerifiedAt after the redemption (a broker clock ahead of port49d's)
// is never written: the context is not given a staleness clock in the
// future.
func TestAVerifiedAtAheadOfTheDaemonIsNow(t *testing.T) {
	f := setup(t)
	secret := f.tag() + "aheadaheadaheadahead0123"
	if _, err := f.st.PutToken(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"},
		store.Token{ID: "a", Secret: []byte(secret), Kind: store.KindLogin, Username: "alice",
			Principal: "user:alice@example.com", BlobHash: "sha256:b", AuthTime: f.now, VerifiedAt: f.now.Add(time.Hour),
			ExpiresAt: f.now.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	f.h.NewSession(f.peer).Start(context.Background(), wire.AuthenStart{Action: wire.AuthenActionLogin,
		AuthenType: wire.AuthenTypePAP, Service: wire.AuthenServiceLogin, User: []byte("alice"),
		Port: []byte("ssh"), RemAddr: []byte("198.51.100.4"), Data: []byte(secret)})
	if got, _ := f.st.GetContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"}); !got.RefreshedAt.Equal(f.now) {
		t.Fatalf("refreshed_at %v, want now", got.RefreshedAt)
	}
}

func TestATLSPeersDeviceBlock(t *testing.T) {
	d := Peer{NAS: "tls-1", NASAddr: "10.0.0.9", Platform: "arista_eos", Transport: "tls", CertSHA256: "ab"}.Device()
	if d.Transport != "tls" || d.CertSHA256 != "ab" || d.KeyRef != "" {
		t.Fatalf("%+v", d)
	}
}
