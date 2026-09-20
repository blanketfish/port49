package authen

import (
	"bytes"
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/rhwendt/port49/internal/daemon/limits"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/tacacs/wire"
)

// The ruled key (spec §13, decision 15): login context on (nas, username),
// receipt on (nas, username, credential_sha256), and port and rem_addr
// recorded attributes that are part of no key.

func papStart(user, port, remAddr, cred string) wire.AuthenStart {
	return wire.AuthenStart{Action: wire.AuthenActionLogin, PrivLvl: 1,
		AuthenType: wire.AuthenTypePAP, Service: wire.AuthenServiceLogin,
		User: []byte(user), Port: []byte(port), RemAddr: []byte(remAddr), Data: []byte(cred)}
}

// TestContextIsKeyedOnUsernameNotPort is the vEOS ssh→vty4 case at the point
// where the context is written: the key must not mention the port at all.
func TestContextIsKeyedOnUsernameNotPort(t *testing.T) {
	f := setup(t)
	reply, _ := f.h.NewSession(f.peer).Start(context.Background(), papStart("alice", "ssh", "172.100.100.1", "p49_tok1"))
	if reply.Status != wire.AuthenStatusPass {
		t.Fatalf("%+v", reply)
	}
	c, err := f.st.GetContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"})
	if err != nil {
		t.Fatalf("context not found under (nas, username): %v", err)
	}
	if c.Port != "ssh" {
		t.Fatalf("port must be recorded on the context as the device sent it, got %q", c.Port)
	}
	if c.RemAddr != "172.100.100.1" {
		t.Fatalf("rem_addr must be recorded on the context, got %q", c.RemAddr)
	}
}

// TestTwoUsersOnOneDeviceDoNotShareASlot is requirement (a) at redemption:
// under the old (nas, port) key both concurrent vEOS sessions reported the
// same port and destroyed each other's context.
func TestTwoUsersOnOneDeviceDoNotShareASlot(t *testing.T) {
	f := setup(t)
	if _, err := f.st.PutToken(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "bob"},
		store.Token{Secret: []byte("p49_tok2"), Kind: store.KindLogin, ExpiresAt: f.now.Add(15 * time.Minute)}); err != nil {
		t.Fatal(err)
	}
	// Both sessions report the same port, as vEOS and the N9Kv do.
	if reply, _ := f.h.NewSession(f.peer).Start(context.Background(), papStart("alice", "vty4", "172.100.100.1", "p49_tok1")); reply.Status != wire.AuthenStatusPass {
		t.Fatalf("alice: %+v", reply)
	}
	if reply, _ := f.h.NewSession(f.peer).Start(context.Background(), papStart("bob", "vty4", "172.100.100.1", "p49_tok2")); reply.Status != wire.AuthenStatusPass {
		t.Fatalf("bob: %+v", reply)
	}
	a, err := f.st.GetContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"})
	if err != nil || a.CtxID != "ctx1" {
		t.Fatalf("alice's context was disturbed by bob's login: %+v %v", a, err)
	}
	b, err := f.st.GetContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "bob"})
	if err != nil || b.CtxID != "ctx2" {
		t.Fatalf("bob's context: %+v %v", b, err)
	}
}

// TestSecondLoginReplacesContextAndLogsIt is requirement (c) and the accepted
// cost of the key: one user's concurrent sessions on one device share a
// context, so the overwrite has to be visible in the log (spec §5.6).
func TestSecondLoginReplacesContextAndLogsIt(t *testing.T) {
	f := setup(t)
	if _, err := f.st.PutToken(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"},
		store.Token{Secret: []byte("p49_tok2"), Kind: store.KindLogin, ExpiresAt: f.now.Add(15 * time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if reply, _ := f.h.NewSession(f.peer).Start(context.Background(), papStart("alice", "ssh", "172.100.100.1", "p49_tok1")); reply.Status != wire.AuthenStatusPass {
		t.Fatalf("first login: %+v", reply)
	}
	if reply, _ := f.h.NewSession(f.peer).Start(context.Background(), papStart("alice", "ssh", "172.100.100.1", "p49_tok2")); reply.Status != wire.AuthenStatusPass {
		t.Fatalf("second login: %+v", reply)
	}
	r := f.records(t)
	if len(r) != 2 {
		t.Fatalf("records: %v", r)
	}
	first := r[0]["session"].(map[string]any)
	if first["replaced_ctx_id"] != nil {
		t.Fatalf("first login replaced nothing: %v", first)
	}
	second := r[1]["session"].(map[string]any)
	if second["ctx_id"] != "ctx2" || second["replaced_ctx_id"] != "ctx1" {
		t.Fatalf("the overwrite must name the context it displaced: %v", second)
	}
	// The live context is the second login's, and it is still usable: the
	// first shell's later authorizations find it and are permitted.
	c, err := f.st.GetContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"})
	if err != nil || c.CtxID != "ctx2" || c.Username != "alice" {
		t.Fatalf("%+v %v", c, err)
	}
}

// TestReceiptIsScopedToNASUsernameAndCredential is requirement (d).
func TestReceiptIsScopedToNASUsernameAndCredential(t *testing.T) {
	f := setup(t)
	// bob holds a token of his own, so a miss here is a receipt miss and not
	// merely an empty candidate set.
	if _, err := f.st.PutToken(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "bob"},
		store.Token{Secret: []byte("p49_bob"), Kind: store.KindLogin, ExpiresAt: f.now.Add(15 * time.Minute)}); err != nil {
		t.Fatal(err)
	}
	start := papStart("alice", "ssh", "172.100.100.1", "p49_tok1")
	if reply, _ := f.h.NewSession(f.peer).Start(context.Background(), start); reply.Status != wire.AuthenStatusPass {
		t.Fatalf("%+v", reply)
	}

	// Same triple, and the port has moved on: the spent token still replays.
	replay := papStart("alice", "vty4", "172.100.100.1", "p49_tok1")
	reply, _ := f.h.NewSession(f.peer).Start(context.Background(), replay)
	if reply.Status != wire.AuthenStatusPass || f.records(t)[1]["reason"] != "receipt_replayed" {
		t.Fatalf("%+v %v", reply, f.records(t)[1])
	}

	// A different username presenting alice's spent token: no receipt of his,
	// and no token of his matches, so it is a plain miss.
	reply, _ = f.h.NewSession(f.peer).Start(context.Background(), papStart("bob", "ssh", "172.100.100.1", "p49_tok1"))
	if reply.Status != wire.AuthenStatusFail || f.records(t)[2]["reason"] != "token_not_found" {
		t.Fatalf("%+v %v", reply, f.records(t)[2])
	}

	// The same username on a different device: receipts do not cross a NAS.
	other := Peer{NAS: "leaf-02", NASAddr: "10.20.0.8", Platform: "arista_eos"}
	reply, _ = f.h.NewSession(other).Start(context.Background(), start)
	if reply.Status != wire.AuthenStatusFail || f.records(t)[3]["reason"] != "token_not_found" {
		t.Fatalf("%+v %v", reply, f.records(t)[3])
	}
}

// TestSecondLoginWithAFreshTokenIsNotCredentialMismatch is the bug the hash in
// the key fixes: alice's second login inside receipt_ttl presented a fresh
// valid token, found her first receipt, and was answered FAIL.
func TestSecondLoginWithAFreshTokenIsNotCredentialMismatch(t *testing.T) {
	f := setup(t)
	if _, err := f.st.PutToken(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"},
		store.Token{Secret: []byte("p49_tok2"), Kind: store.KindLogin, ExpiresAt: f.now.Add(15 * time.Minute)}); err != nil {
		t.Fatal(err)
	}
	f.h.NewSession(f.peer).Start(context.Background(), papStart("alice", "ssh", "172.100.100.1", "p49_tok1"))
	reply, _ := f.h.NewSession(f.peer).Start(context.Background(), papStart("alice", "ssh", "172.100.100.1", "p49_tok2"))
	if reply.Status != wire.AuthenStatusPass || f.records(t)[1]["reason"] != "token_redeemed" {
		t.Fatalf("a fresh token must redeem, not collide with the earlier receipt: %+v %v", reply, f.records(t)[1])
	}
}

// wrongReceiptStore answers GetReceipt with a receipt carrying a credential
// hash other than the one the key asked for. No correct store does this; the
// constant-time compare after the lookup is what catches one that does, and
// credential_mismatch is what it reports (spec §5.7).
type wrongReceiptStore struct {
	store.Store
}

func (wrongReceiptStore) GetReceipt(context.Context, store.ReceiptKey) (store.Receipt, error) {
	return store.Receipt{CredentialSHA256: sha256.Sum256([]byte("a different credential")),
		Status: wire.AuthenStatusPass, CtxID: "ctxX", ExpiresAt: time.Unix(1_757_041_495, 0).Add(time.Hour)}, nil
}

func TestReceiptCarryingAnotherCredentialIsRefused(t *testing.T) {
	log := &bytes.Buffer{}
	now := time.Unix(1_757_041_495, 0)
	l := limits.New(limits.Config{AuthFailureDelayBase: time.Millisecond, AuthFailureDelayMax: 2 * time.Millisecond, AuthFailureWindow: time.Minute}, func() time.Time { return now })
	h := New(wrongReceiptStore{}, decision.NewJSONLines(log), l, metrics.New(prometheus.NewRegistry()),
		func() time.Time { return now }, func() string { return "ctx1" }, 30*time.Second, time.Hour)

	reply, done := h.NewSession(Peer{NAS: "leaf-01", NASAddr: "10.20.0.7", Platform: "arista_eos"}).
		Start(context.Background(), papStart("alice", "ssh", "172.100.100.1", "p49_tok1"))
	if !done || reply.Status != wire.AuthenStatusFail {
		t.Fatalf("%+v", reply)
	}
	if !bytes.Contains(log.Bytes(), []byte(`"reason":"credential_mismatch"`)) {
		t.Fatalf("%s", log.String())
	}
}

// TestCanonicalIsTheWholeKeyDiscriminator pins Canonical, which under the ruled
// key is the only thing that separates one principal's context and receipts
// from another's on a device. Two names in the same row of this table are the
// same operator as far as every store lookup in this package is concerned, so
// a change to Canonical is a change to the key and has to break this test
// rather than pass quietly. It lives here rather than beside the function for
// that reason; username_test.go covers the four rules in isolation.
func TestCanonicalIsTheWholeKeyDiscriminator(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		// Case. The device chooses this, not the operator: a login typed
		// as ALICE and one typed as alice reach one context.
		{"lower_cases", "ALICE", "alice"},
		{"mixed_case_unchanged_otherwise", "AlIcE", "alice"},

		// Surrounding whitespace, including the tabs and newlines a pasted
		// username carries and U+00A0, which unicode.IsSpace also trims.
		{"trims_spaces", "  alice  ", "alice"},
		{"trims_tab_and_newline", "\talice\n", "alice"},
		{"trims_no_break_space", "alice ", "alice"},
		{"keeps_interior_space", "al ice", "al ice"},

		// Empty, and the inputs that become empty. authen refuses an empty
		// canonical username before it touches the store, so these are the
		// names no token and no context can ever be keyed under.
		{"empty_stays_empty", "", ""},
		{"only_space_becomes_empty", "   ", ""},
		{"bare_domain_suffix_becomes_empty", "@corp.example", ""},
		{"bare_domain_prefix_becomes_empty", `CORP\`, ""},

		// $enab{level}$ names. IOS-XE sends one of these on an enable START.
		// Canonical leaves the shape alone, so it is a principal like any
		// other and no token is minted under it -- but it lower-cases, so a
		// device that sends $ENAB15$ and one that sends $enab15$ are one name.
		{"enable_name_survives_intact", "$enab15$", "$enab15$"},
		{"enable_name_lower_cased", "$ENAB15$", "$enab15$"},
		{"enable_name_other_level", "$enab1$", "$enab1$"},
		{"enable_name_loses_at_suffix", "$enab15$@corp.example", "$enab15$"},
		{"enable_name_loses_domain_prefix", `CORP\$enab15$`, "$enab15$"},

		// Non-ASCII. ToLower is Unicode-aware, so a directory that admits
		// non-ASCII names has its own collisions: I-with-dot folds onto a
		// plain i on this implementation, which merges three spellings.
		{"latin1_folds", "ÄLICE", "älice"},
		{"latin1_already_folded", "älice", "älice"},
		{"greek_folds", "ΑΛΊΚΗ", "αλίκη"},
		{"dotted_capital_i_folds_to_plain_i", "İD", "id"},
		{"plain_capital_i_folds_to_plain_i", "ID", "id"},

		// Prefix and suffix stripping, where both are present and where the
		// separators repeat. Last backslash wins, first @ wins.
		{"strips_both_affixes", `CORP\Alice@corp.example`, "alice"},
		{"last_backslash_wins", `a\b\c`, "c"},
		{"first_at_wins", "alice@corp@b.example", "alice"},
		{"trailing_at_strips_nothing_else", "alice@", "alice"},
		{"slash_is_not_a_separator", "alice/ssh", "alice/ssh"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Canonical(c.in); got != c.want {
				t.Errorf("Canonical(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

// TestRedeemRecordCarriesPortAndRemAddr is requirement (e) on the redeem side:
// the fields leave the key but stay in the record.
func TestRedeemRecordCarriesPortAndRemAddr(t *testing.T) {
	f := setup(t)
	f.h.NewSession(f.peer).Start(context.Background(), papStart("alice", "ssh", "172.100.100.1", "p49_tok1"))
	s := f.records(t)[0]["session"].(map[string]any)
	if s["port"] != "ssh" || s["rem_addr"] != "172.100.100.1" {
		t.Fatalf("%v", s)
	}
}
