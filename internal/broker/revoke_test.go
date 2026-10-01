package broker

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/policy"
	"github.com/rhwendt/port49/internal/session"
	"github.com/rhwendt/port49/internal/store"
)

// fakeConns stands in for the Listener: the held connections are (principal,
// certKey) pairs, CloseHeld drops those match names, and marked is what
// Revoked was told.
type fakeConns struct {
	held   [][2]string
	marked map[[2]string]bool
}

func (c *fakeConns) Revoked(kind, key string, on bool) {
	if c.marked == nil {
		c.marked = map[[2]string]bool{}
	}
	c.marked[[2]string{kind, key}] = on
}

func (c *fakeConns) CloseHeld(match func(principal, certKey string) bool) int {
	var kept [][2]string
	n := 0
	for _, h := range c.held {
		if match(h[0], h[1]) {
			n++
		} else {
			kept = append(kept, h)
		}
	}
	c.held = kept
	return n
}

// A revocation by principal reaches everything (spec §5.1.4): the mark,
// the held connection, every live context, every unspent token, the
// record naming the context it cannot reach, and the next mint.
func TestRevokingAPrincipalReachesEverything(t *testing.T) {
	f := newFixture(t, 8)
	ctx := context.Background()
	conns := &fakeConns{held: [][2]string{{alice, certKey(f.alice)}, {"user:carol@example.com", "x"}}}
	saved := 0
	f.b.Conns = conns
	f.b.Persist = func(context.Context) error { saved++; return nil }
	decodeMint(t, f.post(ctx, f.state(f.alice), `{"devices":["leaf1","nx1"]}`, ""))
	f.liveContext(t, "leaf1", "alice", alice, certKey(f.alice))
	f.liveContext(t, "bare", "alice", alice, certKey(f.alice))

	rep, err := f.b.Revoke(ctx, RevokeRequest{Principal: alice, Origin: "admin_socket uid 0"})
	if err != nil || rep.Err != nil || rep.SaveErr != nil {
		t.Fatalf("%+v %v", rep, err)
	}
	if rep.Mark.Kind != store.RevocationPrincipal || !rep.Mark.At.Equal(f.now) || len(rep.Contexts) != 2 ||
		rep.TokenKeys != 2 || rep.Connections != 1 || !rep.Saved || saved != 1 {
		t.Fatalf("report: %+v (saved %d)", rep, saved)
	}
	if len(rep.Unreached) != 1 || rep.Unreached[0].NAS != "bare" {
		t.Fatalf("a device the inventory gives no platform is not reached: %+v", rep.Unreached)
	}
	if c, err := f.st.GetContext(ctx, store.ContextKey{NAS: "leaf1", Username: "alice"}); err != nil || !c.RevokedAt.Equal(f.now) {
		t.Fatalf("leaf1's context: %+v %v", c, err)
	}
	for _, dev := range []string{"leaf1", "nx1"} {
		if toks, _ := f.st.Candidates(ctx, store.TokenKey{NAS: dev, Username: "alice"}); len(toks) != 0 {
			t.Fatalf("%d unspent token(s) on %s survived", len(toks), dev)
		}
	}
	if len(conns.held) != 1 || conns.held[0][0] != "user:carol@example.com" {
		t.Fatalf("held connections left: %v", conns.held)
	}
	if !conns.marked[[2]string{store.RevocationPrincipal, alice}] {
		t.Fatal("the listener was not told of the mark")
	}
	recs := eventsOf(f.records(t), "revoke")
	if len(recs) != 1 || recs[0]["verdict"] != "deny" || recs[0]["reason"] != "credential_revoked" ||
		recs[0]["principal"] != alice {
		t.Fatalf("revoke records: %v", recs)
	}
	body := recs[0]["revocation"].(map[string]any)
	if body["by"] != "principal" || body["contexts"] != float64(2) || body["token_keys"] != float64(2) ||
		body["connections"] != float64(1) || body["saved"] != true || body["origin"] != "admin_socket uid 0" {
		t.Fatalf("revocation body: %v", body)
	}
	if un := body["unreached"].([]any); len(un) != 1 || un[0].(map[string]any)["device"] != "bare" {
		t.Fatalf("unreached: %v", body["unreached"])
	}
	if w := f.post(ctx, f.state(f.alice), `{"devices":["leaf1"]}`, ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("a mint after the revocation: %d", w.Code)
	}
	if got := testutil.ToFloat64(f.b.Metrics.Revocations.WithLabelValues("principal", "applied")); got != 1 {
		t.Fatalf("port49_revocations_total{by=principal,outcome=applied} = %v", got)
	}
	text := rep.Text()
	for _, want := range []string{"revoked user:alice@example.com", "2 live context(s) marked", "bare (alice)",
		"port49 revoke --lift --principal user:alice@example.com"} {
		if !strings.Contains(text, want) {
			t.Fatalf("the text lacks %q:\n%s", want, text)
		}
	}
}

// A revocation by certificate reaches what that certificate minted and
// logged into, and leaves the same principal's other certificate alone. A
// serial typed in another case or with 0x is the same certificate, and a
// repeat keeps the first mark's time.
func TestRevokingACertificateReachesThatCertificateAlone(t *testing.T) {
	f := newFixture(t, 8)
	ctx := context.Background()
	renewed := f.client(t, "alice@example.com", f.now.Add(2*time.Hour))
	conns := &fakeConns{held: [][2]string{{alice, certKey(f.alice)}, {alice, certKey(renewed)}}}
	f.b.Conns = conns
	decodeMint(t, f.post(ctx, f.state(f.alice), `{"devices":["leaf1"]}`, ""))
	decodeMint(t, f.post(ctx, f.state(renewed), `{"devices":["nx1"]}`, ""))
	f.liveContext(t, "leaf1", "alice", alice, certKey(f.alice))
	f.liveContext(t, "nx1", "alice", alice, certKey(renewed))

	req := RevokeRequest{Issuer: f.alice.Leaf.Issuer.String(), Serial: f.alice.Leaf.SerialNumber.Text(16), Origin: "t"}
	rep, err := f.b.Revoke(ctx, req)
	if err != nil || len(rep.Contexts) != 1 || rep.Contexts[0].NAS != "leaf1" || rep.TokenKeys != 1 ||
		rep.Connections != 1 {
		t.Fatalf("%+v %v", rep, err)
	}
	if len(conns.held) != 1 || conns.held[0][1] != certKey(renewed) {
		t.Fatalf("the other certificate's held connection was closed: %v", conns.held)
	}
	if !conns.marked[[2]string{store.RevocationCert, certKey(f.alice)}] {
		t.Fatalf("the listener was not told of the certificate's mark: %v", conns.marked)
	}
	if c, _ := f.st.GetContext(ctx, store.ContextKey{NAS: "nx1", Username: "alice"}); !c.RevokedAt.IsZero() {
		t.Fatal("the other certificate's context was marked")
	}
	if toks, _ := f.st.Candidates(ctx, store.TokenKey{NAS: "nx1", Username: "alice"}); len(toks) != 1 {
		t.Fatal("the other certificate's token was deleted")
	}
	if toks, _ := f.st.Candidates(ctx, store.TokenKey{NAS: "leaf1", Username: "alice"}); len(toks) != 0 {
		t.Fatal("the revoked certificate's token survived")
	}
	if w := f.post(ctx, f.state(f.alice), `{"devices":["leaf1"]}`, ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("the revoked certificate minted: %d", w.Code)
	}
	if r := decodeMint(t, f.post(ctx, f.state(renewed), `{"devices":["leaf1"]}`, "")); r.Results[0].Verdict != "permit" {
		t.Fatalf("the other certificate: %+v", r)
	}
	rec := eventsOf(f.records(t), "revoke")[0]
	body := rec["revocation"].(map[string]any)
	if _, named := rec["principal"]; named || body["serial"] != req.Serial || body["issuer"] != req.Issuer ||
		body["by"] != "cert" {
		t.Fatalf("a certificate's record names no principal, and the issuer and serial: %v", rec)
	}
	if got := testutil.ToFloat64(f.b.Metrics.Revocations.WithLabelValues("cert", "applied")); got != 1 {
		t.Fatalf("port49_revocations_total{by=cert,outcome=applied} = %v", got)
	}
	f.advance(time.Minute)
	again := req
	again.Serial = "0X" + strings.ToUpper(req.Serial)
	rep2, err := f.b.Revoke(ctx, again)
	if err != nil || rep2.Mark.Key != rep.Mark.Key || !rep2.Mark.At.Equal(rep.Mark.At) {
		t.Fatalf("the same certificate in another spelling: %+v %v", rep2.Mark, err)
	}
	if !strings.Contains(rep.Text(), "--cert-serial "+req.Serial) ||
		!strings.Contains(rep.Text(), "other certificates lost theirs on those devices too") {
		t.Fatalf("the lift command names the serial as compared, and the text the key-wide delete:\n%s", rep.Text())
	}
}

// A revocation reaches the receipts of the principal behind what it marks,
// by principal and by certificate: a receipt left behind would answer a
// retransmission of the revoked login PASS receipt_replayed (spec §13,
// decision 15).
func TestRevokingDeletesTheReceipts(t *testing.T) {
	for _, by := range []string{store.RevocationPrincipal, store.RevocationCert} {
		t.Run(by, func(t *testing.T) {
			f := newFixture(t, 8)
			ctx := context.Background()
			decodeMint(t, f.post(ctx, f.state(f.alice), `{"devices":["leaf1"]}`, ""))
			k := store.TokenKey{NAS: "leaf1", Username: "alice"}
			toks, err := f.st.Candidates(ctx, k)
			if err != nil || len(toks) != 1 {
				t.Fatalf("%d tokens: %v", len(toks), err)
			}
			rk := store.ReceiptKey{NAS: "leaf1", Username: "alice", Kind: store.KindLogin, CredentialSHA256: [32]byte{1}}
			if err := f.st.RedeemAndReceipt(ctx, k, toks[0].ID, store.ReceiptWrite{Key: rk, Principal: alice,
				IndexTTL: time.Hour, Receipt: store.Receipt{FirstRedeemedAt: f.now,
					IdleExpiresAt: f.now.Add(15 * time.Minute), RetainUntil: f.now.Add(3 * time.Hour)}}); err != nil {
				t.Fatal(err)
			}
			f.liveContext(t, "leaf1", "alice", alice, certKey(f.alice))
			req := RevokeRequest{Principal: alice}
			if by == store.RevocationCert {
				req = RevokeRequest{Issuer: f.alice.Leaf.Issuer.String(), Serial: f.alice.Leaf.SerialNumber.Text(16)}
			}
			// The index still names leaf1, whose token was redeemed: it
			// empties nothing and is not counted (M7).
			if rep, err := f.b.Revoke(ctx, req); err != nil || rep.Err != nil || len(rep.Contexts) != 1 ||
				rep.TokenKeys != 0 {
				t.Fatalf("%+v %v", rep, err)
			}
			if _, err := f.st.GetReceipt(ctx, rk); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("the receipt survived the revocation: %v", err)
			}
		})
	}
}

// A context is reached where its platform asks port49 about each command,
// and named unreached where it never does (spec §13 decision 21) or where
// the inventory gives the device no platform: every built-in platform, one
// context each.
func TestARevocationNamesTheContextsEachPlatformCannotReach(t *testing.T) {
	f := newFixture(t, 8)
	ctx := context.Background()
	devs := []admission.Device{f.devices["leaf1"], f.devices["nx1"], f.devices["bare"],
		{Name: "rtr1", Platform: "cisco_iosxe", Addresses: []netip.Addr{netip.MustParseAddr("172.100.100.51")}},
		{Name: "srx1", Platform: "juniper_junos", Addresses: []netip.Addr{netip.MustParseAddr("172.100.100.61")}}}
	pol, err := policy.Parse([]byte(testPolicy), policy.Env{Devices: devs, Now: f.b.Now()})
	if err != nil {
		t.Fatal(err)
	}
	f.b.Policy.Swap(pol)
	for _, d := range devs {
		f.liveContext(t, d.Name, "alice", alice, certKey(f.alice))
	}
	rep, err := f.b.Revoke(ctx, RevokeRequest{Principal: alice})
	if err != nil || rep.Err != nil || len(rep.Contexts) != len(devs) {
		t.Fatalf("%+v %v", rep, err)
	}
	var unreached []string
	for _, ref := range rep.Unreached {
		unreached = append(unreached, ref.NAS)
	}
	sort.Strings(unreached)
	if strings.Join(unreached, ",") != "bare,srx1" {
		t.Fatalf("unreached %v, want the device with no platform and the Junos one", unreached)
	}
	for _, d := range devs {
		if c, err := f.st.GetContext(ctx, store.ContextKey{NAS: d.Name, Username: "alice"}); err != nil ||
			c.RevokedAt.IsZero() {
			t.Fatalf("%s's context is not marked, reached or not: %+v %v", d.Name, c, err)
		}
	}
	if text := rep.Text(); !strings.Contains(text, "bare (alice)") || !strings.Contains(text, "srx1 (alice)") ||
		strings.Contains(text, "leaf1 (alice)") {
		t.Fatalf("the text names exactly the unreached contexts:\n%s", text)
	}
}

type markFailingStore struct{ store.Store }

func (markFailingStore) PutRevocation(context.Context, store.Revocation) error {
	return errors.New("store: connection refused")
}

// A mark that cannot be written revokes nothing, and says so: nothing below
// it may run without the mark that keeps a mint from undoing it.
func TestAMarkThatCannotBeWrittenRevokesNothing(t *testing.T) {
	f := newFixture(t, 8)
	conns := &fakeConns{held: [][2]string{{alice, certKey(f.alice)}}}
	f.b.Conns = conns
	f.b.Store = markFailingStore{f.st}
	f.liveContext(t, "leaf1", "alice", alice, certKey(f.alice))
	if _, err := f.b.Revoke(context.Background(), RevokeRequest{Principal: alice}); err == nil ||
		!strings.Contains(err.Error(), "nothing was revoked") {
		t.Fatalf("%v", err)
	}
	if c, _ := f.st.GetContext(context.Background(), store.ContextKey{NAS: "leaf1", Username: "alice"}); !c.RevokedAt.IsZero() {
		t.Fatal("a context was marked without the mark")
	}
	if len(conns.held) != 1 || len(conns.marked) != 0 {
		t.Fatalf("the listener was reached without the mark: %v %v", conns.held, conns.marked)
	}
	if len(eventsOf(f.records(t), "revoke")) != 0 {
		t.Fatal("a revocation that did not happen was recorded")
	}
}

type indexFailingStore struct{ store.Store }

func (indexFailingStore) TokensByPrincipal(context.Context, string) ([]store.TokenKey, error) {
	return nil, errors.New("store: i/o timeout")
}

// A step that fails after the mark leaves the mark in force, and the
// report, the record, the metric and the text say what was missed. The
// steps after it still run.
func TestAPartialRevocationSaysWhatItMissed(t *testing.T) {
	f := newFixture(t, 8)
	f.b.Store = indexFailingStore{f.st}
	f.liveContext(t, "leaf1", "alice", alice, certKey(f.alice))
	rep, err := f.b.Revoke(context.Background(), RevokeRequest{Principal: alice})
	if err != nil || rep.Err == nil || !rep.Partial() {
		t.Fatalf("%+v %v", rep, err)
	}
	if _, err := f.st.GetRevocation(context.Background(), store.RevocationPrincipal, alice); err != nil {
		t.Fatalf("the mark is not in force: %v", err)
	}
	if len(rep.Contexts) != 1 {
		t.Fatalf("a failed token pass stopped the context pass: %+v", rep)
	}
	if body := eventsOf(f.records(t), "revoke")[0]["revocation"].(map[string]any); !strings.Contains(body["error"].(string), "i/o timeout") {
		t.Fatalf("record: %v", body)
	}
	if got := testutil.ToFloat64(f.b.Metrics.Revocations.WithLabelValues("principal", "partial")); got != 1 {
		t.Fatalf("partial: %v", got)
	}
	if !strings.Contains(rep.Text(), "incomplete:") || !strings.Contains(rep.Text(), "run the same command again") ||
		!strings.Contains(rep.Text(), "unspent tokens may still log in") {
		t.Fatal(rep.Text())
	}
}

// A revocation the file could not keep is in force and says a restart
// forgets it.
func TestAnUnsavedRevocationSaysARestartForgetsIt(t *testing.T) {
	f := newFixture(t, 8)
	f.b.Persist = func(context.Context) error { return errors.New("no space left on device") }
	rep, err := f.b.Revoke(context.Background(), RevokeRequest{Principal: alice})
	if err != nil || rep.Saved || rep.SaveErr == nil || !rep.Partial() || !strings.Contains(rep.Text(), "NOT saved") {
		t.Fatalf("%+v %v\n%s", rep, err, rep.Text())
	}
	if body := eventsOf(f.records(t), "revoke")[0]["revocation"].(map[string]any); body["saved"] != false {
		t.Fatalf("record: %v", body)
	}
}

// Lifting removes the mark, in the store and the listener, is recorded
// permit revocation_lifted, and the principal mints again; it restores no
// token and un-marks no context, so a fresh login is needed (spec §5.7,
// revocation_lifted); lifting what is not in force is ErrNotRevoked.
func TestLiftingARevocation(t *testing.T) {
	f := newFixture(t, 8)
	ctx := context.Background()
	conns := &fakeConns{}
	saved := 0
	f.b.Conns = conns
	f.b.Persist = func(context.Context) error { saved++; return nil }
	decodeMint(t, f.post(ctx, f.state(f.alice), `{"devices":["nx1"]}`, ""))
	f.liveContext(t, "leaf1", "alice", alice, certKey(f.alice))
	if _, err := f.b.Revoke(ctx, RevokeRequest{Principal: alice}); err != nil {
		t.Fatal(err)
	}
	f.advance(time.Minute)
	rep, err := f.b.Lift(ctx, RevokeRequest{Principal: "user:ALICE@example.com", Origin: "admin_socket uid 0"})
	if err != nil || !strings.Contains(rep.LiftedText(), "unless another revocation stands") || !rep.Saved || saved != 2 {
		t.Fatalf("%+v %v (saved %d)", rep, err, saved)
	}
	if on, told := conns.marked[[2]string{store.RevocationPrincipal, alice}]; !told || on {
		t.Fatalf("the listener still holds the mark: %v", conns.marked)
	}
	if _, err := f.st.GetRevocation(ctx, store.RevocationPrincipal, alice); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the mark is still in the store: %v", err)
	}
	recs := eventsOf(f.records(t), "revoke")
	if len(recs) != 2 || recs[1]["verdict"] != "permit" || recs[1]["reason"] != "revocation_lifted" ||
		recs[1]["principal"] != alice || recs[1]["revocation"].(map[string]any)["origin"] != "admin_socket uid 0" {
		t.Fatalf("%v", recs)
	}
	if got := testutil.ToFloat64(f.b.Metrics.Revocations.WithLabelValues("principal", "lifted")); got != 1 {
		t.Fatalf("lifted: %v", got)
	}
	if c, _ := f.st.GetContext(ctx, store.ContextKey{NAS: "leaf1", Username: "alice"}); c.RevokedAt.IsZero() {
		t.Fatal("the lift un-marked a context")
	}
	if toks, _ := f.st.Candidates(ctx, store.TokenKey{NAS: "nx1", Username: "alice"}); len(toks) != 0 {
		t.Fatal("the lift restored a token")
	}
	if r := decodeMint(t, f.post(ctx, f.state(f.alice), `{"devices":["leaf1"]}`, "")); r.Results[0].Verdict != "permit" {
		t.Fatalf("after the lift: %+v", r)
	}
	if _, err := f.b.Lift(ctx, RevokeRequest{Principal: alice}); !errors.Is(err, ErrNotRevoked) {
		t.Fatalf("lifting twice: %v", err)
	}
}

// A certificate's mark is lifted under any spelling of its serial.
func TestLiftingACertificateInAnotherSpelling(t *testing.T) {
	f := newFixture(t, 8)
	ctx := context.Background()
	issuer, serial := f.alice.Leaf.Issuer.String(), f.alice.Leaf.SerialNumber.Text(16)
	if _, err := f.b.Revoke(ctx, RevokeRequest{Issuer: issuer, Serial: serial}); err != nil {
		t.Fatal(err)
	}
	rep, err := f.b.Lift(ctx, RevokeRequest{Issuer: issuer, Serial: "0x" + strings.ToUpper(serial)})
	if err != nil || rep.Mark.Key != certKey(f.alice) {
		t.Fatalf("%+v %v", rep, err)
	}
	if r := decodeMint(t, f.post(ctx, f.state(f.alice), `{"devices":["leaf1"]}`, "")); r.Results[0].Verdict != "permit" {
		t.Fatalf("after the lift: %+v", r)
	}
}

// A revocation names a principal or a certificate, exactly one, in a form
// a mark can hold.
func TestABadRevocationIsRefused(t *testing.T) {
	f := newFixture(t, 8)
	for _, req := range []RevokeRequest{
		{},
		{Principal: alice, Issuer: "CN=x", Serial: "1"},
		{Issuer: "CN=x"},
		{Serial: "1"},
		{Principal: "user:alice\n@example.com"},
		{Issuer: "CN=x", Serial: "not-hex"},
		{Issuer: "CN=x\x00", Serial: "1"},
		{Issuer: "CN=x\u0085", Serial: "1"}, // C1 (M2)
		{Issuer: "CN=\u202ex", Serial: "1"}, // a bidi override
		{Issuer: "CN=x\u200b", Serial: "1"}, // a format character
		{Issuer: "CN=x", Serial: "0x"},
		{Issuer: "CN=x", Serial: "--1"},
		{Principal: "alice@example.com"}, // no prefix (pre-flight I2)
		{Principal: "admin:alice"},
		{Principal: "user:"},
	} {
		if _, err := f.b.Revoke(context.Background(), req); !errors.Is(err, ErrBadRevocation) {
			t.Errorf("revoke %+v: %v", req, err)
		}
		if _, err := f.b.Lift(context.Background(), req); !errors.Is(err, ErrBadRevocation) {
			t.Errorf("lift %+v: %v", req, err)
		}
	}
	if recs := eventsOf(f.records(t), "revoke"); len(recs) != 0 {
		t.Fatalf("a refused request was recorded: %v", recs)
	}
	f.b.Sessions = nil
	if _, err := f.b.Revoke(context.Background(), RevokeRequest{Principal: alice}); err == nil {
		t.Fatal("a broker with no Sessions revoked rather than refusing (M12)")
	}
	if _, err := f.st.GetRevocation(context.Background(), store.RevocationPrincipal, alice); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("an unwired broker wrote the mark: %v", err)
	}
}

// A principal is compared as Identity spells it: an address in capitals
// marks the lower-case key, and a principal no subject names is still
// marked, behind a warning that the spelling may be wrong (pre-flight I2).
func TestAPrincipalIsSpelledAsTheBrokerSpellsIt(t *testing.T) {
	f := newFixture(t, 8)
	ctx := context.Background()
	rep, err := f.b.Revoke(ctx, RevokeRequest{Principal: "USER:Alice@Example.COM"})
	if err != nil || rep.Request.Principal != alice || rep.Mark.Key != alice {
		t.Fatalf("%+v %v", rep, err)
	}
	if _, err := f.st.GetRevocation(ctx, store.RevocationPrincipal, alice); err != nil {
		t.Fatalf("the mark is not under the lower-case key: %v", err)
	}
	if w := f.post(ctx, f.state(f.alice), `{"devices":["leaf1"]}`, ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("a mint under the capitalised mark: %d", w.Code)
	}
	if !strings.HasPrefix(rep.Text(), "nothing was found under user:alice@example.com") {
		t.Fatalf("a named principal with nothing reached is warned of:\n%s", rep.Text())
	}
	rep, err = f.b.Revoke(ctx, RevokeRequest{Principal: "user:alce@example.com"})
	if err != nil || !rep.Unnamed {
		t.Fatalf("%+v %v", rep, err)
	}
	if !strings.HasPrefix(rep.Text(), "no subject in the policy in force names user:alce@example.com") {
		t.Fatalf("no warning first:\n%s", rep.Text())
	}
	if _, err := f.st.GetRevocation(ctx, store.RevocationPrincipal, "user:alce@example.com"); err != nil {
		t.Fatal("the mark must still be written (deny more)")
	}
}

// A serial is taken as openssl prints it, with colons, and a negative one
// as Text(16) gives it (pre-flight M16, M17).
func TestASerialIsTakenInTheSpellingsOperatorsHave(t *testing.T) {
	for in, want := range map[string]string{"3F:9A:01": "3f9a01", "0x003f9a01": "3f9a01", "-1F": "-1f",
		"0": "0", "00": "0", "-0": "0", "-0x1f": "-1f"} {
		got, _, _, err := RevokeRequest{Issuer: "CN=x", Serial: in}.normal()
		if err != nil || got.Serial != want {
			t.Errorf("%q: %q %v, want %q", in, got.Serial, err, want)
		}
	}
}

// tokenGatedStore holds DeleteTokens until gate closes, so a redemption can
// land between the token pass and the context pass.
type tokenGatedStore struct {
	store.Store
	entered chan struct{}
	gate    chan struct{}
}

func (g *tokenGatedStore) DeleteTokens(ctx context.Context, k store.TokenKey) error {
	select {
	case g.entered <- struct{}{}:
	default:
	}
	<-g.gate
	return g.Store.DeleteTokens(ctx, k)
}

// A token redeemed while the revocation deletes tokens, on a device with no
// live context, writes a fresh context; the context pass, which runs after
// the token pass for exactly this, marks it (pre-flight I1; the session
// package comment's hole).
func TestAContextARedemptionWritesMidRevocationIsMarked(t *testing.T) {
	f := newFixture(t, 8)
	ctx := context.Background()
	decodeMint(t, f.post(ctx, f.state(f.alice), `{"devices":["leaf1"]}`, ""))
	g := &tokenGatedStore{Store: f.st, entered: make(chan struct{}, 1), gate: make(chan struct{})}
	f.b.Store = g
	done := make(chan RevokeReport, 1)
	go func() {
		rep, _ := f.b.Revoke(ctx, RevokeRequest{Principal: alice})
		done <- rep
	}()
	<-g.entered
	// The daemon's redemption, as authen writes it: join (a fresh context,
	// none being live) and index.
	k := store.ContextKey{NAS: "nx1", Username: "alice"}
	login := store.Context{CtxID: "ctx_mid", Principal: alice, Username: "alice", PrivLvl: 1,
		AuthTime: f.now, RefreshedAt: f.now}
	if _, err := store.JoinContext(ctx, f.st, k, login, f.now.Add(-time.Minute), f.now, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := f.st.IndexContext(ctx, alice, "", certKey(f.alice), store.ContextRef{NAS: "nx1", Username: "alice"},
		time.Hour); err != nil {
		t.Fatal(err)
	}
	close(g.gate)
	rep := <-done
	if c, err := f.st.GetContext(ctx, k); err != nil || c.RevokedAt.IsZero() {
		t.Fatalf("the context written mid-revocation is live and unrevoked: %+v %v", c, err)
	}
	if len(rep.Contexts) != 1 || rep.Contexts[0].NAS != "nx1" {
		t.Fatalf("the report must count the second pass's context: %+v", rep.Contexts)
	}
}

// contextRacedStore runs late once, after the first ContextsByPrincipal
// read returns: a redemption that took its token before the token pass and
// writes its context after the first context read.
type contextRacedStore struct {
	store.Store
	once sync.Once
	late func()
}

func (s *contextRacedStore) ContextsByPrincipal(ctx context.Context, principal string) ([]store.ContextRef, error) {
	refs, err := s.Store.ContextsByPrincipal(ctx, principal)
	s.once.Do(s.late)
	return refs, err
}

// A context a redemption in flight writes after the first context read is
// marked by the second (pre-flight I1), and counted once with the first's.
func TestTheSecondContextPassMarksALateContext(t *testing.T) {
	f := newFixture(t, 8)
	ctx := context.Background()
	f.liveContext(t, "leaf1", "alice", alice, certKey(f.alice))
	k := store.ContextKey{NAS: "nx1", Username: "alice"}
	raced := &contextRacedStore{Store: f.st, late: func() {
		login := store.Context{CtxID: "ctx_late", Principal: alice, Username: "alice", PrivLvl: 1,
			AuthTime: f.now, RefreshedAt: f.now}
		if _, err := store.JoinContext(ctx, f.st, k, login, f.now.Add(-time.Minute), f.now, time.Hour); err != nil {
			t.Error(err)
		}
		if err := f.st.IndexContext(ctx, alice, "", certKey(f.alice), store.ContextRef{NAS: "nx1", Username: "alice"},
			time.Hour); err != nil {
			t.Error(err)
		}
	}}
	f.b.Sessions = session.New(raced, f.b.Now, time.Hour, time.Hour)
	rep, err := f.b.Revoke(ctx, RevokeRequest{Principal: alice})
	if err != nil || rep.Err != nil {
		t.Fatalf("%+v %v", rep, err)
	}
	if c, err := f.st.GetContext(ctx, k); err != nil || c.RevokedAt.IsZero() {
		t.Fatalf("the late context is live and unrevoked: %+v %v", c, err)
	}
	var got []string
	for _, ref := range rep.Contexts {
		got = append(got, ref.NAS)
	}
	sort.Strings(got)
	if strings.Join(got, ",") != "leaf1,nx1" {
		t.Fatalf("each context once, the late one included: %v", got)
	}
}

// Broker.Revoke landing at each point of a mint leaves no token: before the
// mint writes anything, between its index write and its token write, and
// between two devices of its batch. The mint's read of the marks after its
// last write refuses it, and the revocation's index pass deletes what the
// mint had already written (spec §5.1.4; decision 32).
func TestARevocationAtEachPointOfAMintLeavesNoToken(t *testing.T) {
	for _, at := range [][2]string{{"ReserveIdempotency", ""}, {"PutToken", "leaf1"}, {"PutToken", "nx1"}} {
		t.Run(at[0]+"_"+at[1], func(t *testing.T) {
			f := newFixture(t, 8)
			p := f.pauseAt(at[0], at[1])
			answered := make(chan int, 1)
			go func() {
				answered <- f.post(context.Background(), f.state(f.alice), `{"devices":["leaf1","nx1"]}`, "01P").Code
			}()
			<-p.entered
			if rep, err := f.b.Revoke(context.Background(), RevokeRequest{Principal: alice}); err != nil || rep.Err != nil {
				t.Fatalf("%+v %v", rep, err)
			}
			close(p.gate)
			if code := <-answered; code != http.StatusUnauthorized {
				t.Fatalf("the mint a revocation overtook answered %d", code)
			}
			for _, d := range []string{"leaf1", "nx1"} {
				if n := f.live(t, d); n != 0 {
					t.Fatalf("%d token(s) survived on %s", n, d)
				}
			}
		})
	}
}

// A mint racing a revocation leaves no token under the revoked principal,
// whichever reads the other's write: the revocation's index pass finds what
// the mint indexed before it, and the mint's read after its last write finds
// the mark (spec §5.1.4; decision 32). Run under -race, many times over, the
// revocation started at a spread of offsets so some rounds find the mint
// finished and some find it under way.
func TestAMintRacingARevocationLeavesNoToken(t *testing.T) {
	for i := 0; i < 50; i++ {
		f := newFixture(t, 8)
		ctx := context.Background()
		var wg sync.WaitGroup
		start := make(chan struct{})
		var code int
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			r := f.post(ctx, f.state(f.alice), `{"devices":["leaf1","nx1"]}`, "")
			code = r.Code
		}()
		go func() {
			defer wg.Done()
			<-start
			time.Sleep(time.Duration(i%10) * 100 * time.Microsecond)
			if rep, err := f.b.Revoke(ctx, RevokeRequest{Principal: alice}); err != nil || rep.Err != nil {
				t.Errorf("%+v %v", rep, err)
			}
		}()
		close(start)
		wg.Wait()
		if code != http.StatusOK && code != http.StatusUnauthorized {
			t.Fatalf("round %d: the mint answered %d", i, code)
		}
		for _, dev := range []string{"leaf1", "nx1"} {
			if toks, _ := f.st.Candidates(ctx, store.TokenKey{NAS: dev, Username: "alice"}); len(toks) != 0 {
				t.Fatalf("round %d: %d token(s) on %s survived a revocation that raced their mint (mint %d)",
					i, len(toks), dev, code)
			}
		}
	}
}

// A revocation marks each (device, username) whose tokens it deleted
// superseded, so a retry of a mint from before it, under the same
// Idempotency-Key and after a lift, is minted afresh rather than answered
// with a token that no longer exists (Task 7 review M4).
func TestARevocationSupersedesTheKeysItEmptied(t *testing.T) {
	f := newFixture(t, 8)
	ctx := context.Background()
	first := decodeMint(t, f.post(ctx, f.state(f.alice), `{"devices":["leaf1"]}`, "k1"))
	f.advance(time.Second)
	if _, err := f.b.Revoke(ctx, RevokeRequest{Principal: alice}); err != nil {
		t.Fatal(err)
	}
	f.advance(time.Second)
	if _, err := f.b.Lift(ctx, RevokeRequest{Principal: alice}); err != nil {
		t.Fatal(err)
	}
	again := decodeMint(t, f.post(ctx, f.state(f.alice), `{"devices":["leaf1"]}`, "k1"))
	if again.Results[0].Login == first.Results[0].Login {
		t.Fatal("a retry after the revocation replayed a token the revocation deleted")
	}
	if toks, _ := f.st.Candidates(ctx, store.TokenKey{NAS: "leaf1", Username: "alice"}); len(toks) != 1 {
		t.Fatalf("%d tokens on leaf1, want the fresh one", len(toks))
	}
}

// The list names each mark as the flags that lift it would: a principal,
// or a certificate's issuer and serial.
func TestRevocationsTextNamesEachMark(t *testing.T) {
	at := time.Date(2026, 10, 1, 3, 0, 0, 0, time.UTC)
	text := RevocationsText([]store.Revocation{
		{Kind: store.RevocationCert, Key: store.CertKey("CN=Corp CA,O=Example", "3f9a01"), At: at, Origin: "admin_socket uid 0"},
		{Kind: store.RevocationPrincipal, Key: alice, At: at, Origin: "admin_socket uid 0"}})
	want := `certificate issuer="CN=Corp CA,O=Example" serial=3f9a01 since 2026-10-01T03:00:00Z (admin_socket uid 0)` +
		"\nprincipal user:alice@example.com since 2026-10-01T03:00:00Z (admin_socket uid 0)"
	if text != want {
		t.Fatalf("got\n%s\nwant\n%s", text, want)
	}
	if RevocationsText(nil) != "no revocation is in force" {
		t.Fatal(RevocationsText(nil))
	}
}

// A serial typed in decimal digits alone is read as hex, and the text says
// so: openssl prints a small serial in decimal (M1).
func TestADecimalLookingSerialIsFlagged(t *testing.T) {
	f := newFixture(t, 8)
	rep, err := f.b.Revoke(context.Background(), RevokeRequest{Issuer: "CN=x", Serial: "4096"})
	if err != nil || !strings.Contains(rep.Text(), "the serial 4096 was read as hexadecimal") ||
		!strings.Contains(rep.Text(), "--cert FILE") {
		t.Fatalf("%v\n%s", err, rep.Text())
	}
	rep, err = f.b.Revoke(context.Background(), RevokeRequest{Issuer: "CN=x", Serial: "0x4097"})
	if err != nil || strings.Contains(rep.Text(), "read as hexadecimal") {
		t.Fatalf("a serial written as hex is not flagged: %v\n%s", err, rep.Text())
	}
}

// liftRacedStore holds Revoke after its mark is written, until gate
// closes, so a Lift of the same key can try to land in between.
type liftRacedStore struct {
	store.Store
	once    sync.Once
	entered chan struct{}
	gate    chan struct{}
}

func (s *liftRacedStore) PutRevocation(ctx context.Context, r store.Revocation) error {
	err := s.Store.PutRevocation(ctx, r)
	s.once.Do(func() {
		close(s.entered)
		<-s.gate
	})
	return err
}

// A Lift that arrives while a Revoke of the same key runs waits for it, so
// the listener's copy of the marks ends as the store's does: lifted in
// both. Unserialised, the lift would clear the listener and the revocation
// set it again, refusing handshakes `--list` says nothing refuses (M5).
func TestARevokeAndALiftOfOneKeyDoNotInterleave(t *testing.T) {
	f := newFixture(t, 8)
	ctx := context.Background()
	conns := &fakeConns{}
	f.b.Conns = conns
	raced := &liftRacedStore{Store: f.st, entered: make(chan struct{}), gate: make(chan struct{})}
	f.b.Store = raced
	revoked := make(chan error, 1)
	go func() {
		_, err := f.b.Revoke(ctx, RevokeRequest{Principal: alice})
		revoked <- err
	}()
	<-raced.entered
	lifted := make(chan error, 1)
	go func() {
		_, err := f.b.Lift(ctx, RevokeRequest{Principal: alice})
		lifted <- err
	}()
	select {
	case err := <-lifted:
		t.Fatalf("the lift ran inside the revocation: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(raced.gate)
	if err := <-revoked; err != nil {
		t.Fatal(err)
	}
	if err := <-lifted; err != nil {
		t.Fatal(err)
	}
	_, err := f.st.GetRevocation(ctx, store.RevocationPrincipal, alice)
	if on := conns.marked[[2]string{store.RevocationPrincipal, alice}]; on || !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the listener holds the mark %v, the store %v: they must agree", on, err)
	}
}

// A Revoke or Lift waiting behind one held by a hung store call gives up
// when its ctx ends, saying nothing was done and, for a revocation, how to
// cut access another way (I1).
func TestARevokeOrLiftBehindAHungOneGivesUpAtItsDeadline(t *testing.T) {
	for _, lift := range []bool{false, true} {
		f := newFixture(t, 8)
		raced := &liftRacedStore{Store: f.st, entered: make(chan struct{}), gate: make(chan struct{})}
		f.b.Store = raced
		first := make(chan error, 1)
		go func() {
			_, err := f.b.Revoke(context.Background(), RevokeRequest{Principal: alice})
			first <- err
		}()
		<-raced.entered
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		var err error
		want := []string{"another revocation or lift is still running", "nothing was revoked", "cut access another way"}
		if lift {
			_, err = f.b.Lift(ctx, RevokeRequest{Principal: alice})
			want = []string{"another revocation or lift is still running", "nothing was lifted"}
		} else {
			_, err = f.b.Revoke(ctx, RevokeRequest{Principal: "user:carol@example.com"})
		}
		cancel()
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("lift %v: %v", lift, err)
		}
		for _, w := range want {
			if !strings.Contains(err.Error(), w) {
				t.Fatalf("lift %v: the error lacks %q: %v", lift, w, err)
			}
		}
		close(raced.gate)
		if err := <-first; err != nil {
			t.Fatal(err)
		}
		if !lift {
			if _, err := f.st.GetRevocation(context.Background(), store.RevocationPrincipal, "user:carol@example.com"); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("the revocation that gave up wrote its mark: %v", err)
			}
		} else if _, err := f.st.GetRevocation(context.Background(), store.RevocationPrincipal, alice); err != nil {
			t.Fatalf("the lift that gave up lifted: %v", err)
		}
	}
}

// A caller whose ctx ends after the mark is written, as when the operator's
// SSH session drops, does not leave the revocation half-done: the held
// connection is closed, the tokens deleted, the contexts marked and the
// file saved, each on a ctx the caller's end does not reach. A lift whose
// caller goes the same way is lifted and saved too.
func TestARevocationWhoseCallerGoesFinishes(t *testing.T) {
	f := newFixture(t, 8)
	conns := &fakeConns{held: [][2]string{{alice, certKey(f.alice)}}}
	f.b.Conns = conns
	var persisted []error
	f.b.Persist = func(ctx context.Context) error { persisted = append(persisted, ctx.Err()); return ctx.Err() }
	decodeMint(t, f.post(context.Background(), f.state(f.alice), `{"devices":["leaf1","nx1"]}`, ""))
	f.liveContext(t, "leaf1", "alice", alice, certKey(f.alice))
	raced := &liftRacedStore{Store: f.st, entered: make(chan struct{}), gate: make(chan struct{})}
	f.b.Store = raced

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan RevokeReport, 1)
	go func() {
		rep, err := f.b.Revoke(ctx, RevokeRequest{Principal: alice})
		if err != nil {
			t.Error(err)
		}
		done <- rep
	}()
	<-raced.entered // the mark is written
	cancel()
	close(raced.gate)
	rep := <-done
	if rep.Err != nil || rep.SaveErr != nil || !rep.Saved || rep.Partial() || rep.TokenKeys != 2 ||
		len(rep.Contexts) != 1 || rep.Connections != 1 {
		t.Fatalf("%+v", rep)
	}
	if len(persisted) != 1 || persisted[0] != nil {
		t.Fatalf("Persist ran on an ended ctx: %v", persisted)
	}
	bg := context.Background()
	for _, dev := range []string{"leaf1", "nx1"} {
		if toks, _ := f.st.Candidates(bg, store.TokenKey{NAS: dev, Username: "alice"}); len(toks) != 0 {
			t.Fatalf("%d unspent token(s) on %s survived", len(toks), dev)
		}
	}
	if c, err := f.st.GetContext(bg, store.ContextKey{NAS: "leaf1", Username: "alice"}); err != nil || c.RevokedAt.IsZero() {
		t.Fatalf("leaf1's context: %+v %v", c, err)
	}

	lifting := &liftGatedStore{Store: f.st, entered: make(chan struct{}), gate: make(chan struct{})}
	f.b.Store = lifting
	ctx, cancel = context.WithCancel(context.Background())
	lifted := make(chan error, 1)
	go func() {
		rep, err := f.b.Lift(ctx, RevokeRequest{Principal: alice})
		if err == nil && (!rep.Saved || rep.SaveErr != nil) {
			err = fmt.Errorf("unsaved: %+v", rep)
		}
		lifted <- err
	}()
	<-lifting.entered // the lift holds the semaphore
	cancel()
	close(lifting.gate)
	if err := <-lifted; err != nil {
		t.Fatal(err)
	}
	if len(persisted) != 2 || persisted[1] != nil {
		t.Fatalf("Persist ran on an ended ctx: %v", persisted)
	}
	if _, err := f.st.GetRevocation(bg, store.RevocationPrincipal, alice); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the lift did not land: %v", err)
	}
	if conns.marked[[2]string{store.RevocationPrincipal, alice}] {
		t.Fatal("the listener still holds the lifted mark")
	}
}

// liftGatedStore holds a Lift at its first read of the mark, after it took
// the semaphore, until gate closes.
type liftGatedStore struct {
	store.Store
	once    sync.Once
	entered chan struct{}
	gate    chan struct{}
}

func (s *liftGatedStore) GetRevocation(ctx context.Context, kind, key string) (store.Revocation, error) {
	s.once.Do(func() {
		close(s.entered)
		<-s.gate
	})
	return s.Store.GetRevocation(ctx, kind, key)
}

// A caller already gone when the semaphore is free gets the same answer
// every time: the slot is taken and the revocation runs whole. Only a wait
// is cut short by its ctx's end.
func TestACallerAlreadyGoneWithTheSlotFreeIsRevokedEveryTime(t *testing.T) {
	f := newFixture(t, 8)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for i := 0; i < 50; i++ {
		if _, err := f.b.Revoke(ctx, RevokeRequest{Principal: alice}); err != nil {
			t.Fatalf("revoke %d: %v", i, err)
		}
		if _, err := f.b.Lift(ctx, RevokeRequest{Principal: alice}); err != nil {
			t.Fatalf("lift %d: %v", i, err)
		}
	}
}
