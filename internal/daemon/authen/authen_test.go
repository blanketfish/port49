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

	"github.com/rhwendt/port49/internal/daemon/limits"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/memory"
	"github.com/rhwendt/port49/internal/tacacs/wire"
)

type fixture struct {
	h    *Handler
	st   *memory.Store
	log  *bytes.Buffer
	now  time.Time
	peer Peer
}

func setup(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{log: &bytes.Buffer{}, now: time.Unix(1_757_041_495, 0), peer: Peer{NAS: "leaf-01", NASAddr: "10.20.0.7", Platform: "arista_eos"}}
	f.st = memory.New(func() time.Time { return f.now })
	ids := 0
	l := limits.New(limits.Config{AuthFailureDelayBase: time.Millisecond, AuthFailureDelayMax: 2 * time.Millisecond, AuthFailureWindow: time.Minute}, func() time.Time { return f.now })
	f.h = New(f.st, decision.NewJSONLines(f.log), l, metrics.New(prometheus.NewRegistry()),
		func() time.Time { return f.now }, func() string { ids++; return "ctx" + string(rune('0'+ids)) },
		30*time.Second, time.Hour)
	if _, err := f.st.PutToken(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"},
		store.Token{Secret: []byte("p49_tok1"), Kind: store.KindLogin, ExpiresAt: f.now.Add(15 * time.Minute)}); err != nil {
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
		User: []byte("Alice"), Port: []byte("vty0"), RemAddr: []byte("198.51.100.4"), Data: []byte("p49_tok1")})
	if !done || reply.Status != wire.AuthenStatusPass {
		t.Fatalf("reply %+v done %v", reply, done)
	}
	c, err := f.st.GetContext(context.Background(), store.ContextKey{NAS: "leaf-01", Port: "vty0"})
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
	if strings.Contains(f.log.String(), "p49_tok1") {
		t.Fatal("token leaked into the log")
	}
}

func TestRetransmissionReplaysReceipt(t *testing.T) {
	f := setup(t)
	start := wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP, Service: wire.AuthenServiceLogin,
		User: []byte("alice"), Port: []byte("vty0"), Data: []byte("p49_tok1")}
	f.h.NewSession(f.peer).Start(context.Background(), start)
	reply, _ := f.h.NewSession(f.peer).Start(context.Background(), start)
	if reply.Status != wire.AuthenStatusPass {
		t.Fatalf("retry must PASS from the receipt: %+v", reply)
	}
	r := f.records(t)
	if r[1]["reason"] != "receipt_replayed" || r[1]["session"].(map[string]any)["ctx_id"] != "ctx1" {
		t.Fatalf("%v", r[1])
	}
	// Same line and username, different credential: the receipt must not stand in for the check.
	start.Data = []byte("something-else")
	reply, _ = f.h.NewSession(f.peer).Start(context.Background(), start)
	if reply.Status != wire.AuthenStatusFail || f.records(t)[2]["reason"] != "credential_mismatch" {
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
	r3, done := s.Continue(context.Background(), wire.AuthenContinue{UserMsg: []byte("p49_tok1")})
	if !done || r3.Status != wire.AuthenStatusPass {
		t.Fatalf("%+v", r3)
	}
	if strings.Contains(f.log.String(), "p49_tok1") {
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
	sum := md5.Sum(append(append([]byte{0x2a}, []byte("p49_tok1")...), challenge...))
	data := append(append([]byte{0x2a}, challenge...), sum[:]...)
	reply, done := f.h.NewSession(f.peer).Start(context.Background(), wire.AuthenStart{Action: wire.AuthenActionLogin,
		AuthenType: wire.AuthenTypeCHAP, Service: wire.AuthenServiceLogin, User: []byte("alice"), Port: []byte("vty0"), Data: data})
	if !done || reply.Status != wire.AuthenStatusPass {
		t.Fatalf("%+v", reply)
	}
	// A re-prompt with a fresh challenge does not match the receipt and fails (design §8).
	sum2 := md5.Sum(append(append([]byte{0x2b}, []byte("p49_tok1")...), []byte("fedcba9876543210")...))
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
		store.Token{Secret: []byte("bob_enable_tok"), Kind: store.KindEnable, ExpiresAt: f.now.Add(15 * time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.PutToken(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "bob"},
		store.Token{Secret: []byte("bob_login_tok"), Kind: store.KindLogin, ExpiresAt: f.now.Add(15 * time.Minute)}); err != nil {
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
	// alice has only a login token (from setup). Presenting it at enable is a
	// kind mismatch, not a missing token.
	reply, done := f.h.NewSession(f.peer).Start(context.Background(), wire.AuthenStart{Action: wire.AuthenActionLogin,
		AuthenType: wire.AuthenTypePAP, Service: wire.AuthenServiceEnable, User: []byte("alice"), Port: []byte("vty0"), Data: []byte("p49_tok1")})
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
		30*time.Second, time.Hour)

	reply, done := h.NewSession(Peer{NAS: "leaf-01", NASAddr: "10.20.0.7", Platform: "arista_eos"}).Start(context.Background(),
		wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP, Service: wire.AuthenServiceLogin,
			User: []byte("alice"), Port: []byte("vty0"), Data: []byte("p49_tok1")})
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
	if strings.Contains(log.String(), "p49_tok1") {
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
		AuthenType: wire.AuthenTypePAP, Service: wire.AuthenServiceLogin, User: []byte("alice"), Port: []byte("vty0"), Data: []byte("p49_tok1")})
	if !done || reply.Status != wire.AuthenStatusPass {
		t.Fatalf("%+v", reply)
	}
	// A second Start on the same finished session must not resume the exchange.
	reply, done = s.Start(context.Background(), wire.AuthenStart{Action: wire.AuthenActionLogin,
		AuthenType: wire.AuthenTypePAP, Service: wire.AuthenServiceLogin, User: []byte("alice"), Port: []byte("vty0"), Data: []byte("p49_tok1")})
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
func (noStore) RedeemAndReceipt(context.Context, store.TokenKey, []byte, store.ReceiptKey, store.Receipt) error {
	panic("store called")
}
func (noStore) GetReceipt(context.Context, store.ReceiptKey) (store.Receipt, error) {
	panic("store called")
}
func (noStore) PutContext(context.Context, store.ContextKey, store.Context, time.Duration) error {
	panic("store called")
}
func (noStore) GetContext(context.Context, store.ContextKey) (store.Context, error) {
	panic("store called")
}
func (noStore) DeleteContext(context.Context, store.ContextKey) error {
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
		30*time.Second, time.Hour)

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
