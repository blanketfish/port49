package session

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/memory"
)

// ref is the context key the indexes hold: (nas, username), not (nas, port).
// The port is not the same value at the authentication that writes the context
// and the authorization that reads it (store.ContextKey; spec §15, L1).
var ref = store.ContextRef{NAS: "leaf-01", Username: "alice"}

func key(r store.ContextRef) store.ContextKey {
	return store.ContextKey{NAS: r.NAS, Username: r.Username}
}

func seed(t *testing.T, s *memory.Store, now time.Time) {
	t.Helper()
	ctx := context.Background()
	c := store.Context{CtxID: "c1", Principal: "user:alice@example.com", Username: "alice", PrivLvl: 15, BlobHash: "sha256:old",
		AuthTime: now.Add(-time.Hour), SessionExpires: now.Add(7 * time.Hour), RefreshedAt: now.Add(-time.Hour),
		Credential: store.Credential{Method: "oidc", Sid: "s1", Sub: "a7f3", Issuer: "ca", Serial: "01"}}
	if err := s.PutContext(ctx, key(ref), c, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := s.IndexContext(ctx, c.Principal, c.Credential.Sid, store.CertKey("ca", "01"), ref, time.Hour); err != nil {
		t.Fatal(err)
	}
}

func TestRefreshMovesAuthTimeKeepsWindowReindexesSid(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	s := memory.New(func() time.Time { return now })
	seed(t, s, now)
	m := New(s, func() time.Time { return now }, time.Hour, time.Hour)
	n, err := m.Refresh(context.Background(), "user:alice@example.com", now, now.Add(-10*time.Minute), "sha256:new", "s1", "s2")
	if err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	// The seed's window is 8h (auth_time now-1h, ceiling now+7h), so a refresh
	// at now writes now+8h: the ceiling moves with the authentication, and the
	// window it describes does not grow.
	c, _ := s.GetContext(context.Background(), key(ref))
	if !c.AuthTime.Equal(now) || !c.SessionExpires.Equal(now.Add(8*time.Hour)) || c.BlobHash != "sha256:new" || !c.RefreshedAt.Equal(now) {
		t.Fatalf("%+v", c)
	}
	if refs, _ := s.ContextsBySid(context.Background(), "s2"); len(refs) != 1 {
		t.Fatal("new sid not indexed")
	}
	if refs, _ := s.ContextsBySid(context.Background(), "s1"); len(refs) != 0 {
		t.Fatal("old sid still indexed")
	}
}

func TestRefreshWithoutCeilingLeavesNoCeiling(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	s := memory.New(func() time.Time { return now })
	ctx := context.Background()
	bob := store.ContextRef{NAS: "leaf-01", Username: "bob"}
	if err := s.PutContext(ctx, key(bob),
		store.Context{CtxID: "c", Principal: "user:bob@example.com", Username: "bob"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := s.IndexContext(ctx, "user:bob@example.com", "", "", bob, time.Hour); err != nil {
		t.Fatal(err)
	}
	m := New(s, func() time.Time { return now }, time.Hour, time.Hour)
	if _, err := m.Refresh(ctx, "user:bob@example.com", now, now.Add(-10*time.Minute), "", "", ""); err != nil {
		t.Fatal(err)
	}
	c, _ := s.GetContext(ctx, key(bob))
	if !c.SessionExpires.IsZero() {
		t.Fatalf("a context with no ceiling must not gain one: %+v", c)
	}
}

func TestRevokeBySidMarksNotDeletes(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	s := memory.New(func() time.Time { return now })
	seed(t, s, now)
	m := New(s, func() time.Time { return now }, time.Hour, time.Hour)
	refs, err := m.RevokeBySid(context.Background(), "s1")
	if err != nil || len(refs) != 1 || refs[0] != ref {
		t.Fatalf("%v %v", refs, err)
	}
	c, err := s.GetContext(context.Background(), key(ref))
	if err != nil || c.RevokedAt.IsZero() {
		t.Fatalf("revocation must mark, not delete: %+v %v", c, err)
	}
}

func TestRevokeByPrincipalAndByCert(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	s := memory.New(func() time.Time { return now })
	m := New(s, func() time.Time { return now }, time.Hour, time.Hour)
	seed(t, s, now)
	if refs, _ := m.RevokeByPrincipal(context.Background(), "user:alice@example.com"); len(refs) != 1 {
		t.Fatalf("principal: %v", refs)
	}
	seed(t, s, now)
	if refs, _ := m.RevokeByCert(context.Background(), "ca", "01"); len(refs) != 1 {
		t.Fatalf("cert: %v", refs)
	}
	if refs, _ := m.RevokeBySid(context.Background(), "nope"); len(refs) != 0 {
		t.Fatalf("unknown sid: %v", refs)
	}
}

// The scheduled refresh is a group re-resolution (spec §5.1.3), not a
// credential re-verification, and it runs on every principal with a live
// context every few minutes. A refresh that lifted the mark would un-revoke
// every revoked principal within one interval — on the very path §5.1.3 names
// as how a policy-driven revocation reaches live sessions. Spec §5.6 row 6,
// the idle TTL, is the only thing that ends a revocation.
func TestRefreshDoesNotClearRevocation(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	s := memory.New(func() time.Time { return now })
	seed(t, s, now)
	m := New(s, func() time.Time { return now }, time.Hour, time.Hour)
	if _, err := m.RevokeByPrincipal(context.Background(), "user:alice@example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Refresh(context.Background(), "user:alice@example.com", now, now.Add(-10*time.Minute), "sha256:new", "s1", "s1"); err != nil {
		t.Fatal(err)
	}
	c, _ := s.GetContext(context.Background(), key(ref))
	if c.RevokedAt.IsZero() {
		t.Fatal("a scheduled refresh must not lift a revocation: spec §5.6 row 6 is what reclaims it")
	}
	// The rest of the refresh still lands: the mark is not a veto on
	// re-resolving the policy blob, only on lifting the denial.
	if c.BlobHash != "sha256:new" || !c.AuthTime.Equal(now) {
		t.Fatalf("the refresh did not land: %+v", c)
	}
}

func TestRevocationDeletesTheReceiptsToo(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	s := memory.New(func() time.Time { return now })
	ctx := context.Background()
	seed(t, s, now)
	k := store.TokenKey{NAS: "leaf-01", Username: "alice"}
	if _, err := s.PutToken(ctx, k, store.Token{ID: "t", Secret: []byte("x"), ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	var h [32]byte
	h[0] = 1
	rk := store.ReceiptKey{NAS: "leaf-01", Username: "alice", CredentialSHA256: h}
	if err := s.RedeemAndReceipt(ctx, k, "t", store.ReceiptWrite{Key: rk, Principal: "user:alice@example.com", IndexTTL: time.Hour,
		Receipt: store.Receipt{FirstRedeemedAt: now, IdleExpiresAt: now.Add(15 * time.Minute), RetainUntil: now.Add(3 * time.Hour)}}); err != nil {
		t.Fatal(err)
	}

	m := New(s, func() time.Time { return now }, time.Hour, time.Hour)
	if _, err := m.RevokeByPrincipal(ctx, "user:alice@example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetReceipt(ctx, rk); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("a revoked principal's receipt must not keep answering receipt_replayed for up to receipt_max_age")
	}
	c, err := s.GetContext(ctx, store.ContextKey{NAS: "leaf-01", Username: "alice"})
	if err != nil || c.RevokedAt.IsZero() {
		t.Fatalf("revocation must mark the context, not delete it: %+v %v", c, err)
	}
}

// Revocation by sid or by certificate does not know the principal, so it reads
// it off each context before marking. This is that path reaching the receipts:
// the same hole as TestRevocationDeletesTheReceiptsToo, entered through the
// index an operator actually has at 3am when a CRL names a serial.
func TestRevokeByCertDeletesTheReceiptsItFindsThroughTheContext(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	s := memory.New(func() time.Time { return now })
	ctx := context.Background()
	seed(t, s, now)
	k := store.TokenKey{NAS: "leaf-01", Username: "alice"}
	if _, err := s.PutToken(ctx, k, store.Token{ID: "t", Secret: []byte("x"), ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	var h [32]byte
	h[0] = 2
	rk := store.ReceiptKey{NAS: "leaf-01", Username: "alice", CredentialSHA256: h}
	if err := s.RedeemAndReceipt(ctx, k, "t", store.ReceiptWrite{Key: rk, Principal: "user:alice@example.com", IndexTTL: time.Hour,
		Receipt: store.Receipt{FirstRedeemedAt: now, IdleExpiresAt: now.Add(15 * time.Minute), RetainUntil: now.Add(3 * time.Hour)}}); err != nil {
		t.Fatal(err)
	}

	m := New(s, func() time.Time { return now }, time.Hour, time.Hour)
	if _, err := m.RevokeByCert(ctx, "ca", "01"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetReceipt(ctx, rk); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("a revoked certificate's receipt must not keep answering receipt_replayed")
	}
}

// A principal whose context has already aged out can still have a live
// receipt: the receipt is retained past the token (store.Receipt) and the
// context has its own idle TTL. Revoking that principal must still reach the
// receipt, or the operator is told nothing was touched while a spent token
// keeps replaying.
func TestRevokeByPrincipalDeletesReceiptsWithNoLiveContext(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	s := memory.New(func() time.Time { return now })
	ctx := context.Background()
	k := store.TokenKey{NAS: "leaf-01", Username: "alice"}
	if _, err := s.PutToken(ctx, k, store.Token{ID: "t", Secret: []byte("x"), ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	var h [32]byte
	h[0] = 3
	rk := store.ReceiptKey{NAS: "leaf-01", Username: "alice", CredentialSHA256: h}
	if err := s.RedeemAndReceipt(ctx, k, "t", store.ReceiptWrite{Key: rk, Principal: "user:alice@example.com", IndexTTL: time.Hour,
		Receipt: store.Receipt{FirstRedeemedAt: now, IdleExpiresAt: now.Add(15 * time.Minute), RetainUntil: now.Add(3 * time.Hour)}}); err != nil {
		t.Fatal(err)
	}

	m := New(s, func() time.Time { return now }, time.Hour, time.Hour)
	refs, err := m.RevokeByPrincipal(ctx, "user:alice@example.com")
	if err != nil || len(refs) != 0 {
		t.Fatalf("refs=%v err=%v", refs, err)
	}
	if _, err := s.GetReceipt(ctx, rk); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("revoking a principal with no live context must still delete its receipts")
	}
}

// Revocation must not extend the context it marks. Spec §5.6 row 6 reclaims a
// revoked context on the idle TTL it was already on; a mark that re-put the
// record would restart that clock and keep the denial alive longer than the
// session it denies.
func TestRevocationDoesNotExtendTheContext(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	s := memory.New(func() time.Time { return now })
	ctx := context.Background()
	seed(t, s, now)
	m := New(s, func() time.Time { return now }, 24*time.Hour, time.Hour)
	if _, err := m.RevokeBySid(ctx, "s1"); err != nil {
		t.Fatal(err)
	}
	// The seed's context expires an hour after now; the manager's idle TTL is
	// a day. Past the seeded expiry the record must be gone.
	now = now.Add(time.Hour + time.Second)
	if _, err := s.GetContext(ctx, key(ref)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the mark restarted the idle TTL: %v", err)
	}
}

// The 3am case behind design §12's rule that an index entry carries the
// context's TTL: a shift-long session kept alive by activity, then revoked.
// If the index entries aged out underneath it, RevokeByPrincipal would return
// no refs on a context that is still live and still authorizing, and the
// operator would read "0 touched" as "already gone".
func TestRevokeFindsAContextKeptAliveByActivity(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	s := memory.New(func() time.Time { return now })
	ctx := context.Background()
	seed(t, s, now) // context and indexes both written with a one-hour TTL

	// Eight hours of a working shift, a command every half hour.
	for i := 0; i < 16; i++ {
		now = now.Add(30 * time.Minute)
		if err := s.TouchContext(ctx, key(ref), time.Hour); err != nil {
			t.Fatalf("touch %d: %v", i, err)
		}
	}

	m := New(s, func() time.Time { return now }, time.Hour, time.Hour)
	refs, err := m.RevokeByPrincipal(ctx, "user:alice@example.com")
	if err != nil || len(refs) != 1 {
		t.Fatalf("revocation by principal missed a live context: refs=%v err=%v", refs, err)
	}
	if refs, err := m.RevokeByCert(ctx, "ca", "01"); err != nil || len(refs) != 1 {
		t.Fatalf("revocation by certificate missed a live context: refs=%v err=%v", refs, err)
	}
	if refs, err := m.RevokeBySid(ctx, "s1"); err != nil || len(refs) != 1 {
		t.Fatalf("revocation by sid missed a live context: refs=%v err=%v", refs, err)
	}
	c, err := s.GetContext(ctx, key(ref))
	if err != nil || c.RevokedAt.IsZero() {
		t.Fatalf("the context was live but unmarked: %+v %v", c, err)
	}
}

// hookStore fires after every GetContext, which is exactly where a write that
// races a broker operation lands: after the operation has taken its copy and
// before it writes one back. A manager that re-put that copy would carry the
// hook's write away. It also counts the reads, because the strongest version
// of the property is not reading at all.
type hookStore struct {
	*memory.Store
	gets int
	hook func()
}

func (h *hookStore) GetContext(ctx context.Context, k store.ContextKey) (store.Context, error) {
	c, err := h.Store.GetContext(ctx, k)
	h.gets++
	if h.hook != nil {
		h.hook()
	}
	return c, err
}

// The recurring bug this plan keeps finding, run against revocation by sid —
// the one broker operation that does have to read a context, for the principal
// whose receipts it must delete. The annotation lands inside that window and
// must survive it (store.Store's comment on TouchContext).
func TestRevocationKeepsAWriteThatRacesIt(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	s := memory.New(func() time.Time { return now })
	ctx := context.Background()
	seed(t, s, now)
	hash := store.HashDiscriminator("31050")
	h := &hookStore{Store: s}
	h.hook = func() {
		h.hook = nil // once: the annotation races the read, it does not follow it
		if err := s.AnnotateContext(ctx, key(ref), hash, store.AccountingStateOpen); err != nil {
			t.Error(err)
		}
	}
	m := New(h, func() time.Time { return now }, time.Hour, time.Hour)
	if _, err := m.RevokeBySid(ctx, "s1"); err != nil {
		t.Fatal(err)
	}
	c, _ := s.GetContext(ctx, key(ref))
	if c.RevokedAt.IsZero() {
		t.Fatalf("the revocation did not land: %+v", c)
	}
	if len(c.SessionDiscriminators) != 1 || c.AccountingState != store.AccountingStateOpen || c.PrivLvl != 15 {
		t.Fatalf("the revocation discarded an annotation that landed after it read: %+v", c)
	}
}

// Refresh, and revocation by principal, take no copy at all: they have nothing
// to lose to a racing write because they never read one. The count is the
// assertion. For revocation by principal it is also the property crypt's
// package comment is about — the commonest revocation opens no sealed record,
// so it works on a day when the encryption key does not.
func TestRefreshAndRevokeByPrincipalTakeNoCopyToLose(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	s := memory.New(func() time.Time { return now })
	ctx := context.Background()
	seed(t, s, now)
	h := &hookStore{Store: s}
	m := New(h, func() time.Time { return now }, time.Hour, time.Hour)

	if _, err := m.Refresh(ctx, "user:alice@example.com", now, now.Add(-10*time.Minute), "sha256:new", "s1", "s2"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.RevokeByPrincipal(ctx, "user:alice@example.com"); err != nil {
		t.Fatal(err)
	}
	if h.gets != 0 {
		t.Fatalf("the manager read %d contexts; both must write through the narrow setters alone", h.gets)
	}
	c, _ := s.GetContext(ctx, key(ref))
	if c.PrivLvl != 15 || c.CtxID != "c1" || c.Credential.Sub != "a7f3" {
		t.Fatalf("a field that is not the broker's was written: %+v", c)
	}
}

// indexesEverything answers every sid and certificate lookup with every ref it
// was given, the way an index that once stored the empty keys would answer a
// lookup by them. It is what lets a test see that the refusal below is the
// Manager's own and not an accident of what the store happens to hold.
type indexesEverything struct {
	*memory.Store
	refs []store.ContextRef
}

func (e indexesEverything) ContextsBySid(context.Context, string) ([]store.ContextRef, error) {
	return e.refs, nil
}

func (e indexesEverything) ContextsByCert(context.Context, string) ([]store.ContextRef, error) {
	return e.refs, nil
}

// Ruling P8. Every certificate login has sid "", and every OIDC login has a
// certificate with no issuer and no serial. A revocation by either blank is a
// broker bug, and honouring it would mark every such operator's context on the
// fleet and delete their receipts. It is an error, and it marks nothing.
func TestARevocationByABlankSidOrCertificateMarksNothing(t *testing.T) {
	for _, tt := range []struct {
		name   string
		revoke func(m *Manager) ([]store.ContextRef, error)
	}{
		{"empty sid", func(m *Manager) ([]store.ContextRef, error) { return m.RevokeBySid(context.Background(), "") }},
		{"empty issuer and serial", func(m *Manager) ([]store.ContextRef, error) {
			return m.RevokeByCert(context.Background(), "", "")
		}},
		{"empty issuer", func(m *Manager) ([]store.ContextRef, error) { return m.RevokeByCert(context.Background(), "", "01") }},
		{"empty serial", func(m *Manager) ([]store.ContextRef, error) { return m.RevokeByCert(context.Background(), "ca", "") }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			now := time.Unix(1_000_000, 0)
			s := memory.New(func() time.Time { return now })
			seed(t, s, now)
			rk := store.ReceiptKey{NAS: "leaf-01", Username: "alice", Kind: store.KindLogin}
			if _, err := s.PutToken(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"},
				store.Token{ID: "t", Kind: store.KindLogin, ExpiresAt: now.Add(time.Hour)}); err != nil {
				t.Fatal(err)
			}
			if err := s.RedeemAndReceipt(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"}, "t",
				store.ReceiptWrite{Key: rk, Receipt: store.Receipt{CtxID: "c1", RetainUntil: now.Add(time.Hour)},
					Principal: "user:alice@example.com", IndexTTL: time.Hour}); err != nil {
				t.Fatal(err)
			}
			m := New(indexesEverything{Store: s, refs: []store.ContextRef{ref}}, func() time.Time { return now }, time.Hour, time.Hour)
			refs, err := tt.revoke(m)
			if !errors.Is(err, ErrBlankRevocation) || len(refs) != 0 {
				t.Fatalf("a blank revocation must be refused: %v %v", refs, err)
			}
			if c, _ := s.GetContext(context.Background(), key(ref)); !c.RevokedAt.IsZero() {
				t.Fatalf("a blank revocation marked a context: %+v", c)
			}
			if _, err := s.GetReceipt(context.Background(), rk); err != nil {
				t.Fatalf("a blank revocation deleted a receipt: %v", err)
			}
		})
	}
}

// A context past its grace window is never resumed by Refresh: it is
// skipped and not counted, and its ceiling stays where it was. A Refresh
// with no cutoff refreshes nothing (plan 7b final review M-3).
func TestRefreshNeverResumesAContextPastItsGraceWindow(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	s := memory.New(func() time.Time { return now })
	ctx := context.Background()
	expired := now.Add(-11 * time.Minute)
	if err := s.PutContext(ctx, key(ref), store.Context{CtxID: "c1", Principal: "user:alice@example.com",
		Username: "alice", AuthTime: expired.Add(-8 * time.Hour), SessionExpires: expired}, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := s.IndexContext(ctx, "user:alice@example.com", "", "", ref, time.Hour); err != nil {
		t.Fatal(err)
	}
	m := New(s, func() time.Time { return now }, time.Hour, time.Hour)
	if n, err := m.Refresh(ctx, "user:alice@example.com", now, time.Time{}, "", "", ""); !errors.Is(err, ErrNoGraceCutoff) || n != 0 {
		t.Fatalf("no cutoff: n=%d err=%v", n, err)
	}
	n, err := m.Refresh(ctx, "user:alice@example.com", now, now.Add(-10*time.Minute), "", "", "")
	if err != nil || n != 0 {
		t.Fatalf("past grace: n=%d err=%v", n, err)
	}
	if c, _ := s.GetContext(ctx, key(ref)); !c.SessionExpires.Equal(expired) || !c.AuthTime.Equal(expired.Add(-8*time.Hour)) {
		t.Fatalf("a context past its grace window was resumed: session_expires %v", c.SessionExpires)
	}
	// Inside the window it is carried forward, as before.
	n, err = m.Refresh(ctx, "user:alice@example.com", now, now.Add(-20*time.Minute), "", "", "")
	if c, _ := s.GetContext(ctx, key(ref)); err != nil || n != 1 || !c.SessionExpires.Equal(now.Add(8*time.Hour)) {
		t.Fatalf("inside grace: n=%d err=%v session_expires %v", n, err, c.SessionExpires)
	}
}

// outageAfterUnreadable is a store whose every context will not open, and
// whose mark of the one at down finds the store unavailable.
type outageAfterUnreadable struct {
	*memory.Store
	down store.ContextKey
}

func (o outageAfterUnreadable) GetContext(context.Context, store.ContextKey) (store.Context, error) {
	return store.Context{}, &store.UnreadableContextError{Err: errors.New("test: will not open")}
}

func (o outageAfterUnreadable) SetRevokedAt(ctx context.Context, k store.ContextKey, at time.Time) error {
	if k == o.down {
		return store.ErrUnavailable
	}
	return o.Store.SetRevokedAt(ctx, k, at)
}

// An outage is returned over a context that will not open, whichever came
// first: a caller retries on the outage, and must not take the pass for
// one that reached every context (plan 7d; pre-flight re-check 2 M-B9).
func TestAMarkReturnsAnOutageOverAnUnreadableContext(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	s := memory.New(func() time.Time { return now })
	ctx := context.Background()
	seed(t, s, now)
	other := store.ContextRef{NAS: "leaf-02", Username: "alice"}
	if err := s.PutContext(ctx, key(other), store.Context{CtxID: "c2", Principal: "user:alice@example.com",
		Username: "alice", PrivLvl: 1, BlobHash: "sha256:old", AuthTime: now}, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := s.IndexContext(ctx, "user:alice@example.com", "", store.CertKey("ca", "01"), other, time.Hour); err != nil {
		t.Fatal(err)
	}
	m := New(outageAfterUnreadable{Store: s, down: key(other)}, func() time.Time { return now }, time.Hour, time.Hour)
	refs, err := m.RevokeByCert(ctx, "ca", "01")
	if !errors.Is(err, store.ErrUnavailable) || len(refs) != 1 {
		t.Fatalf("RevokeByCert = %v, %v; want the one context marked and the outage", refs, err)
	}
}
