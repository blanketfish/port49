package authen

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/rhwendt/port49/internal/daemon/limits"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/memory"
	"github.com/rhwendt/port49/internal/tacacs/wire"
	"github.com/rhwendt/port49/internal/token"
)

// labTagKey is the fixture's tag key. No token literal is written down: every
// secret in these tests is the device's own tag followed by filler, so a change
// to the tag derivation fails the tests rather than passing on a stale string.
var labTagKey = token.TagKey([]byte("labkey"))

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
		15*time.Minute, 2*time.Hour, time.Hour, time.Hour, labTagKey)
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
		15*time.Minute, 2*time.Hour, time.Hour, time.Hour, labTagKey)

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
func (noStore) GetReceipt(context.Context, store.ReceiptKey) (store.Receipt, error) {
	panic("store called")
}
func (noStore) ExtendReceipt(context.Context, store.ReceiptKey, time.Time) error {
	panic("store called")
}
func (noStore) DeleteReceiptsByPrincipal(context.Context, string) (int, error) {
	panic("store called")
}
func (noStore) PutContext(context.Context, store.ContextKey, store.Context, time.Duration) error {
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
func (noStore) PutIdempotency(context.Context, string, string, store.Idempotency) error {
	panic("store called")
}
func (noStore) GetIdempotency(context.Context, string, string) (store.Idempotency, error) {
	panic("store called")
}

func (noStore) AnnotateContext(context.Context, store.ContextKey, string, string) error {
	panic("store called")
}

var _ store.Store = noStore{}

func TestEmptyCanonicalUsernameFailsWithoutStoreLookup(t *testing.T) {
	log := &bytes.Buffer{}
	now := time.Unix(1_757_041_495, 0)
	l := limits.New(limits.Config{AuthFailureDelayBase: time.Millisecond, AuthFailureDelayMax: 2 * time.Millisecond, AuthFailureWindow: time.Minute}, func() time.Time { return now })
	ids := 0
	h := New(noStore{}, decision.NewJSONLines(log), l, metrics.New(prometheus.NewRegistry()),
		func() time.Time { return now }, func() string { ids++; return "ctx" + string(rune('0'+ids)) },
		15*time.Minute, 2*time.Hour, time.Hour, time.Hour, labTagKey)

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
		15*time.Minute, 2*time.Hour, time.Hour, time.Hour, labTagKey)
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
// therefore still computed: it lands in the distant past and denies, which is
// wrong but loud, rather than permitting forever quietly.
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

// capturingStore keeps the Context the handler handed to PutContext, before
// any store stamped anything on it.
type capturingStore struct {
	*memory.Store
	got store.Context
}

func (c *capturingStore) PutContext(ctx context.Context, k store.ContextKey, v store.Context, ttl time.Duration) error {
	c.got = v
	return c.Store.PutContext(ctx, k, v, ttl)
}

// memory.PutContext stamps LastTouchedAt itself, so reading the context back
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

// An index write that fails does not fail the login — the operator is
// authenticated and the context exists — but what is lost is reach: a later
// revocation by sid, principal or certificate will not find this context. A
// metric with outcome="error" says that happened somewhere on the fleet; only
// the record says WHICH session is now unrevocable, and §5.6 already requires
// revocation to report the contexts it could not reach.
func TestAnUnindexedContextSaysSoOnTheRecord(t *testing.T) {
	f := setupStore(t, func(st *memory.Store) store.Store { return indexFailsStore{st} })
	f.h.NewSession(f.peer).Start(context.Background(), wire.AuthenStart{Action: wire.AuthenActionLogin,
		AuthenType: wire.AuthenTypePAP, Service: wire.AuthenServiceLogin, User: []byte("alice"),
		Port: []byte("vty0"), Data: []byte(f.tag() + "tok1tok1tok1tok1tok1tok1")})
	rec := f.records(t)[0]
	if rec["reason"] != "token_redeemed" {
		t.Fatalf("an index failure must not fail the login: %v", rec)
	}
	if rec["index_error"] == nil {
		t.Fatalf("the record must name the lost reach: %v", rec)
	}
	// The principal is the join: the metric says an index failed somewhere on
	// the fleet, and only this field says whose session it was.
	if rec["principal"] != "user:alice@example.com" {
		t.Fatalf("the record must name the principal that lost its reach: %v", rec)
	}
	if n := testutil.ToFloat64(f.m.StoreOps.WithLabelValues("index_context", "error")); n != 1 {
		t.Fatalf("store_operations_total{op=index_context,outcome=error} = %v, want 1", n)
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

func TestEnableAboveCeilingIsRefused(t *testing.T) {
	f := setup(t)
	f.seedLogin(t, "token", 7)
	sess := f.h.NewSession(f.peer)
	sess.Start(context.Background(), f.enableStart("alice"))
	reply, _ := sess.Continue(context.Background(), wire.AuthenContinue{UserMsg: []byte("anything")})
	if reply.Status != wire.AuthenStatusFail || f.records(t)[0]["reason"] != "ceiling_exceeded" {
		t.Fatalf("%+v %v", reply, f.records(t))
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

// putContextFailsOnce fails the first PutContext and is healthy afterwards, to
// drive an escalation whose privilege never landed. seedLogin writes through
// f.st directly, so the first failure this sees is the escalation's own.
type putContextFailsOnce struct {
	store.Store
	failed bool
}

func (p *putContextFailsOnce) PutContext(ctx context.Context, k store.ContextKey, c store.Context, ttl time.Duration) error {
	if !p.failed {
		p.failed = true
		return errors.New("store: put_context failed")
	}
	return p.Store.PutContext(ctx, k, c, ttl)
}

// A replayed enable must replay the escalation's EFFECT, not just its verdict.
// Here the first escalation's PutContext fails after the token is already
// spent: at 3am the operator sees an error, types `enable` again, gets a prompt
// that accepts and a `#` — and the device now believes they are level 15. If
// the retry only replayed the receipt, every command they typed would be denied
// at their login privilege.
func TestReplayedEnableReAppliesThePrivilege(t *testing.T) {
	var fake *putContextFailsOnce
	f := setupStore(t, func(st *memory.Store) store.Store {
		fake = &putContextFailsOnce{Store: st}
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
		t.Fatalf("a failed PutContext must be ERROR, not a PASS the context cannot back up: %+v %v", reply, f.records(t))
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

// And when the context was replaced between the escalation and the
// retransmission, the replay must name the context that exists now. The receipt
// froze ctxL; alice's second shell replaced it with ctx1 (spec §15, L1: the key
// cannot tell two of her shells apart). Logging the frozen id would put a
// ctx_id in the decision log that no context, no authorize_* record and no
// accounting record ever held — the thing brief item 8 exists to prevent,
// arriving through the replay door.
func TestReplayedEnableNamesTheLiveContext(t *testing.T) {
	f := setup(t)
	f.seedLogin(t, "token", 15)
	secret := f.tag() + "enabenabenabenabenab0123"
	f.st.PutToken(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"},
		store.Token{ID: "en", Secret: []byte(secret), Kind: store.KindEnable, Username: "alice",
			Principal: "user:alice@example.com", ExpiresAt: f.now.Add(time.Minute)})
	sess := f.h.NewSession(f.peer)
	sess.Start(context.Background(), f.enableStart("alice"))
	if reply, _ := sess.Continue(context.Background(), wire.AuthenContinue{UserMsg: []byte(secret)}); reply.Status != wire.AuthenStatusPass {
		t.Fatalf("first escalation: %+v", reply)
	}

	// A second login on the same (nas, username): ctxL is replaced by ctx1, at
	// login privilege.
	if reply, _ := f.h.NewSession(f.peer).Start(context.Background(), wire.AuthenStart{Action: wire.AuthenActionLogin,
		AuthenType: wire.AuthenTypePAP, Service: wire.AuthenServiceLogin, User: []byte("alice"),
		Port: []byte("ssh"), RemAddr: []byte("198.51.100.4"),
		Data: []byte(f.tag() + "tok1tok1tok1tok1tok1tok1")}); reply.Status != wire.AuthenStatusPass {
		t.Fatalf("relogin: %+v", reply)
	}
	if c, _ := f.st.GetContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"}); c.CtxID != "ctx1" {
		t.Fatalf("the relogin must have replaced the context: %+v", c)
	}

	// The device retransmits the enable, inside the receipt window.
	sess2 := f.h.NewSession(f.peer)
	sess2.Start(context.Background(), f.enableStart("alice"))
	reply, _ := sess2.Continue(context.Background(), wire.AuthenContinue{UserMsg: []byte(secret)})
	last := f.records(t)[len(f.records(t))-1]
	if reply.Status != wire.AuthenStatusPass || last["reason"] != "receipt_replayed" ||
		last["session"].(map[string]any)["ctx_id"] != "ctx1" {
		t.Fatalf("the replay must name the live context, not the frozen one: %+v %v", reply, last)
	}
	c, _ := f.st.GetContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"})
	if c.CtxID != "ctx1" || c.PrivLvl != 15 {
		t.Fatalf("the replay must raise the context that exists now: %+v", c)
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
