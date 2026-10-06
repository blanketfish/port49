package directory

import (
	"context"
	"crypto/x509"
	"errors"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/memory"
)

type world struct {
	clk *fakeClock
	srv *fakeServers
	dir *fakeDir
	st  store.Store
	say *lines
	r   *Resolver
}

const dc01 = "ldaps://dc-01"

// newWorld is one directory server holding alice (in netops-oncall,
// directly) and a resolver over a memory store, mapping by san_email.
func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{clk: newClock(), srv: newFakeServers(dc01), say: &lines{}}
	w.dir = w.srv.dirs[dc01]
	cfg := adCfg()
	cfg.Servers = []Server{{URI: dc01, Priority: 100}}
	cfg.Nested, cfg.Grace, cfg.QueryTimeout = "direct", 4*time.Hour, time.Second
	cfg.FailureThreshold, cfg.ProbeInterval, cfg.HealthInterval, cfg.HealthTimeout = 3, time.Minute, 30*time.Second, time.Second
	cfg.Mapping = Mapping{Kind: MapSANEmail, Attribute: "mail", AllowWeak: true, Issuers: pin}
	cfg.Bind.Mechanism = "simple"
	m := metrics.New(prometheus.NewRegistry())
	w.st = memory.New(w.clk.Now)
	w.r = &Resolver{Cfg: cfg, Pool: NewPool(cfg, w.srv.dial, noCheck, w.clk.Now, m, w.say.say), Store: w.st,
		Now: w.clk.Now, M: m, Say: w.say.say}
	a := entry(alice, map[string][]string{"userPrincipalName": {"alice@corp.example.com"},
		"sAMAccountName": {"alice"}, "mail": {"alice@corp.example.com"}})
	w.dir.on("(&(objectClass=person)(mail=alice@corp.example.com))", a)
	w.dir.on("(&(objectClass=person)(userPrincipalName=alice@corp.example.com))", a)
	w.dir.on("(userPrincipalName=alice@corp.example.com)", a) // principalUnique
	w.dir.on("(sAMAccountName=alice)", a)                     // usernameUnique
	w.dir.on(memberFilter(alice), grp(gOnCall, "netops-oncall"))
	w.dir.on(uniqueFilter("netops-oncall"), grp(gOnCall, "netops-oncall"))
	return w
}

// down takes dc-01 away: every connection to it closed, every dial refused.
func (w *world) down() {
	w.srv.setDown(dc01, true)
	w.srv.closeAll(dc01)
}

func aliceCert(t *testing.T) *x509.Certificate { return leaf(t, nil) }

const alicePrincipal = "user:alice@corp.example.com"

// A fresh mapping is written to the store, by principal and by key.
func TestMapVerifiesAndStores(t *testing.T) {
	w := newWorld(t)
	a, err := w.r.Map(context.Background(), aliceCert(t))
	if err != nil || a.Source != Fresh || a.Principal != alicePrincipal || a.Username != "alice" ||
		!slices.Equal(a.GroupNames, []string{"netops-oncall"}) || !a.VerifiedAt.Equal(w.clk.Now()) {
		t.Fatalf("%+v %v", a, err)
	}
	l, _ := w.r.Cfg.Mapping.Lookup(aliceCert(t), w.r.Cfg.UserFilter)
	if m, err := w.st.MembershipByKey(context.Background(), l.Key); err != nil || m.Principal != a.Principal {
		t.Fatalf("by key: %+v %v", m, err)
	}
}

// With no server answering, a bind and a mint read the store within
// grace, and refuse past it (Ruling 10); a restart loses nothing, as the
// store is the cache (Review Focus 4).
func TestGraceReadsTheStoreAfterARestart(t *testing.T) {
	w := newWorld(t)
	if _, err := w.r.Map(context.Background(), aliceCert(t)); err != nil {
		t.Fatal(err)
	}
	w.down()
	restarted := &Resolver{Cfg: w.r.Cfg, Pool: NewPool(w.r.Cfg, w.srv.dial, noCheck, w.clk.Now, w.r.M, w.say.say),
		Store: w.st, Now: w.clk.Now, M: w.r.M, Say: w.say.say}
	w.clk.Add(3 * time.Hour)
	a, err := restarted.Map(context.Background(), aliceCert(t))
	if err != nil || a.Source != Grace || a.Principal != alicePrincipal {
		t.Fatalf("within grace: %+v %v", a, err)
	}
	if c, err := restarted.Current(context.Background(), a.Principal); err != nil || c.Source != Grace {
		t.Fatalf("a mint within grace: %+v %v", c, err)
	}
	w.clk.Add(time.Hour + time.Minute)
	_, err = restarted.Current(context.Background(), a.Principal)
	if !errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), "past directory.grace") {
		t.Fatalf("past grace: %v", err)
	}
}

// A principal the directory refused before an outage is refused through
// it (pre-flight C-1): the refusal is stored, by principal and by key, and
// grace never overrules it. Without it, a user deleted at T and refused at
// T+5m would mint from grace when the DCs drop at T+10m.
func TestARefusedPrincipalIsNotServedFromGrace(t *testing.T) {
	w := newWorld(t)
	if _, err := w.r.Map(context.Background(), aliceCert(t)); err != nil {
		t.Fatal(err)
	}
	w.clk.Add(5 * time.Minute)
	w.dir.on("(&(objectClass=person)(userPrincipalName=alice@corp.example.com))") // deleted
	if _, err := w.r.Verify(context.Background(), alicePrincipal); !errors.Is(err, ErrUnmapped) {
		t.Fatalf("verify after the deletion: %v", err)
	}
	w.clk.Add(5 * time.Minute)
	w.down()
	if a, err := w.r.Map(context.Background(), aliceCert(t)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("a bind in the outage: %+v %v, want ErrUnavailable", a, err)
	}
	if a, err := w.r.Current(context.Background(), alicePrincipal); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("a mint in the outage: %+v %v, want ErrUnavailable", a, err)
	}
	if m, _ := w.st.GetMembership(context.Background(), alicePrincipal); !m.Refused {
		t.Fatalf("the refusal was not stored: %+v", m)
	}
}

// A bind refused by the key the certificate searched with (no entry maps)
// is stored by that key, so grace refuses the certificate too.
func TestAnUnmappedCertificateIsRefusedByKey(t *testing.T) {
	w := newWorld(t)
	if _, err := w.r.Map(context.Background(), aliceCert(t)); err != nil {
		t.Fatal(err)
	}
	w.clk.Add(time.Minute)
	w.dir.on("(&(objectClass=person)(mail=alice@corp.example.com))") // mail removed
	if _, err := w.r.Map(context.Background(), aliceCert(t)); !errors.Is(err, ErrUnmapped) {
		t.Fatalf("%v", err)
	}
	w.down()
	if _, err := w.r.Map(context.Background(), aliceCert(t)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("a bind in the outage: %v, want ErrUnavailable", err)
	}
}

// A principal claimed by another entry than the one it was verified on is
// identity_unmapped, at a bind and on a re-verification (pre-flight C-2):
// alice's UPN moves off her entry and mallory sets hers to it, and
// mallory's own certificate never becomes user:alice@. The refusal keeps
// alice's pin, so a second try fails the same way.
func TestAPrincipalOnAnotherEntryIsUnmapped(t *testing.T) {
	w := newWorld(t)
	if _, err := w.r.Map(context.Background(), aliceCert(t)); err != nil {
		t.Fatal(err)
	}
	w.clk.Add(time.Minute)
	mallory := entry("CN=Mallory,OU=Staff,DC=corp", map[string][]string{"userPrincipalName": {"alice@corp.example.com"},
		"sAMAccountName": {"mallory"}, "mail": {"mallory@corp.example.com"}})
	w.dir.on("(&(objectClass=person)(mail=mallory@corp.example.com))", mallory)
	w.dir.on("(&(objectClass=person)(userPrincipalName=alice@corp.example.com))", mallory)
	w.dir.on("(userPrincipalName=alice@corp.example.com)", mallory) // alice's own entry no longer holds it
	w.dir.on("(sAMAccountName=mallory)", mallory)
	mcert := leaf(t, func(c *x509.Certificate) { c.EmailAddresses = []string{"mallory@corp.example.com"} })
	for i := 0; i < 2; i++ {
		a, err := w.r.Map(context.Background(), mcert)
		if !errors.Is(err, ErrUnmapped) || !strings.Contains(err.Error(), "CN=Mallory") {
			t.Fatalf("mallory's bind %d: %+v %v", i, a, err)
		}
		if _, err := w.r.Verify(context.Background(), alicePrincipal); !errors.Is(err, ErrUnmapped) {
			t.Fatalf("re-verifying alice %d: %v", i, err)
		}
	}
	if m, _ := w.st.GetMembership(context.Background(), alicePrincipal); m.EntryID != "dn:"+strings.ToLower(alice) {
		t.Fatalf("the refusal dropped alice's pin: %+v", m)
	}
}

// An entry deleted and re-created (a rehire, a restore) keeps its DN and
// values and gets a new objectGUID: it is refused while the old pin's
// record lives, each refusal renewing it, and the line says once an hour
// how to end it. Once the record is forgotten (DeleteMembership, what
// `port49 directory forget` calls) the next bind pins the new entry
// (Ruling 3's escape).
func TestARecreatedEntryIsRefusedUntilForgotten(t *testing.T) {
	w := newWorld(t)
	seed := func(guid string) {
		a := entry(alice, map[string][]string{"objectGUID": {guid}, "userPrincipalName": {"alice@corp.example.com"},
			"sAMAccountName": {"alice"}, "mail": {"alice@corp.example.com"}})
		for _, f := range []string{"(&(objectClass=person)(mail=alice@corp.example.com))",
			"(&(objectClass=person)(userPrincipalName=alice@corp.example.com))",
			"(userPrincipalName=alice@corp.example.com)", "(sAMAccountName=alice)"} {
			w.dir.on(f, a)
		}
	}
	seed("\x0a\x1b")
	if _, err := w.r.Map(context.Background(), aliceCert(t)); err != nil {
		t.Fatal(err)
	}
	seed("\x9f\x8e")
	way := "port49 directory forget " + alicePrincipal
	for i := 0; i < 2; i++ {
		w.clk.Add(time.Minute)
		if _, err := w.r.Map(context.Background(), aliceCert(t)); !errors.Is(err, ErrUnmapped) ||
			!strings.Contains(err.Error(), "guid:0a1b") || !strings.Contains(err.Error(), way) {
			t.Fatalf("the re-created entry's bind %d: %v", i, err)
		}
		if _, err := w.r.Verify(context.Background(), alicePrincipal); !errors.Is(err, ErrUnmapped) {
			t.Fatalf("re-verifying alice %d: %v", i, err)
		}
	}
	if n := w.say.count(way); n != 1 {
		t.Fatalf("the line naming the way out was said %d times, want once in the hour", n)
	}
	old, err := w.st.DeleteMembership(context.Background(), alicePrincipal)
	if err != nil || old.EntryID != "guid:0a1b" || !old.Refused {
		t.Fatalf("forget: %+v %v, want the refusal pinned to the old entry", old, err)
	}
	w.clk.Add(time.Minute)
	if a, err := w.r.Map(context.Background(), aliceCert(t)); err != nil || a.Source != Fresh ||
		a.Principal != alicePrincipal {
		t.Fatalf("after forget: %+v %v", a, err)
	}
	if m, err := w.st.GetMembership(context.Background(), alicePrincipal); err != nil || m.EntryID != "guid:9f8e" {
		t.Fatalf("after forget, the pin: %+v %v, want the new entry's", m, err)
	}
}

// Two entries holding one principal value are both refused (pre-flight
// C-2), at a bind as on a re-verification.
func TestAPrincipalTwoEntriesHoldIsRefusedAtBind(t *testing.T) {
	w := newWorld(t)
	mallory := entry("CN=Mallory,OU=Staff,DC=corp", map[string][]string{"userPrincipalName": {"alice@corp.example.com"},
		"sAMAccountName": {"mallory"}})
	a := entry(alice, map[string][]string{"userPrincipalName": {"alice@corp.example.com"}, "sAMAccountName": {"alice"}})
	w.dir.on("(userPrincipalName=alice@corp.example.com)", a, mallory)
	if _, err := w.r.Map(context.Background(), aliceCert(t)); !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("%v", err)
	}
	if m, _ := w.st.GetMembership(context.Background(), alicePrincipal); !m.Refused {
		t.Fatalf("the principal's refusal was not stored: %+v", m)
	}
	w.down()
	if _, err := w.r.Map(context.Background(), aliceCert(t)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("a bind in the outage: %v, want ErrUnavailable", err)
	}
}

// A rotated bind password is the server not answering (pre-flight I-2):
// a request in it is served from grace.
func TestABindRefusalFailsOverAndReachesGrace(t *testing.T) {
	w := newWorld(t)
	if _, err := w.r.Map(context.Background(), aliceCert(t)); err != nil {
		t.Fatal(err)
	}
	w.srv.setRefuse(dc01, ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("invalid credentials")))
	w.srv.closeAll(dc01) // the held connection drops; the next dial is refused
	for i := 0; i < 2; i++ {
		if a, err := w.r.Current(context.Background(), alicePrincipal); err != nil || a.Source != Grace {
			t.Fatalf("request %d: %+v %v, want grace", i, a, err)
		}
	}
	if !w.say.has("refused the bind (simple)") {
		t.Fatalf("%v", w.say.l)
	}
}

// A server slower than query_timeout, asked under a caller deadline
// shorter still, reaches grace: the directory call is bounded by
// query_timeout alone and the grace read has its own budget (pre-flight
// I-8), so a slow DC is never blamed on the store.
func TestASlowServerReachesGrace(t *testing.T) {
	w := newWorld(t)
	if _, err := w.r.Map(context.Background(), aliceCert(t)); err != nil {
		t.Fatal(err)
	}
	w.dir.mu.Lock()
	w.dir.delay = 3 * time.Second
	w.dir.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if a, err := w.r.Current(ctx, alicePrincipal); err != nil || a.Source != Grace {
		t.Fatalf("%+v %v, want grace", a, err)
	}
}

// Verify never answers from grace: the scheduled refresh stamps only what
// a server said (Ruling 12).
func TestVerifyNeverServesGrace(t *testing.T) {
	w := newWorld(t)
	if _, err := w.r.Map(context.Background(), aliceCert(t)); err != nil {
		t.Fatal(err)
	}
	w.down()
	if _, err := w.r.Verify(context.Background(), alicePrincipal); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("%v", err)
	}
}

// A principal whose entry is gone or renamed is ErrUnmapped on Verify,
// so the scheduled pass revokes (Ruling 12).
func TestVerifyAGoneEntryIsUnmapped(t *testing.T) {
	w := newWorld(t)
	if _, err := w.r.Verify(context.Background(), "user:bob@corp.example.com"); !errors.Is(err, ErrUnmapped) {
		t.Fatalf("%v", err)
	}
}

// A machine principal is never searched for, and never a refusal: the
// directory holds no entry for it (pre-flight I-10).
func TestAMachinePrincipalIsNeverSearched(t *testing.T) {
	w := newWorld(t)
	for _, p := range []string{"app:deploy", "spiffe://corp/ns/x", "system:serviceaccount:ns:sa"} {
		_, err := w.r.Verify(context.Background(), p)
		if err == nil || errors.Is(err, ErrUnmapped) || !errors.Is(err, ErrNotUser) {
			t.Fatalf("%s: %v, want ErrNotUser", p, err)
		}
	}
	if len(w.dir.calls) != 0 {
		t.Fatalf("%d searches for machine principals", len(w.dir.calls))
	}
}

// A derived username a policy subject declares collides (Ruling 3), on a
// fresh answer and on a grace one (pre-flight M-11): a declaration made
// in a policy reload during an outage still refuses the stored membership.
func TestADeclaredUsernameCollides(t *testing.T) {
	declared := func() map[string]string { return map[string]string{"alice": "svc_alice"} }
	w := newWorld(t)
	w.r.Declared = declared
	if _, err := w.r.Map(context.Background(), aliceCert(t)); !errors.Is(err, ErrUsernameTaken) ||
		!strings.Contains(err.Error(), "svc_alice") {
		t.Fatalf("fresh: %v", err)
	}
	w = newWorld(t)
	if _, err := w.r.Map(context.Background(), aliceCert(t)); err != nil {
		t.Fatal(err)
	}
	w.down()
	w.r.Declared = declared
	if _, err := w.r.Current(context.Background(), alicePrincipal); !errors.Is(err, ErrUsernameTaken) {
		t.Fatalf("grace: %v", err)
	}
}

// An earlier verification never overwrites a later one, so a replica's
// slow answer cannot undo a removal (Ruling 10).
func TestAStaleVerificationDoesNotWin(t *testing.T) {
	w := newWorld(t)
	if _, err := w.r.Verify(context.Background(), alicePrincipal); err != nil {
		t.Fatal(err)
	}
	w.clk.Add(-time.Minute)
	w.dir.on(memberFilter(alice)) // no groups any more, but verified "earlier"
	a, err := w.r.Verify(context.Background(), alicePrincipal)
	if err != nil || len(a.GroupDNs) != 0 {
		t.Fatalf("the second answer: %+v %v, want no groups (pre-flight M-10)", a, err)
	}
	m, _ := w.st.GetMembership(context.Background(), alicePrincipal)
	if len(m.GroupDNs) != 1 {
		t.Fatalf("an earlier answer replaced the later one: %+v", m)
	}
}

// The mapping search and both uniqueness searches run on one connection
// (one Do), and the answer names the server by host:port, never its URI.
func TestAVerificationIsOneConnectionAndNamesTheServerByLabel(t *testing.T) {
	w := newWorld(t)
	a, err := w.r.Map(context.Background(), aliceCert(t))
	if err != nil || a.Server != "dc-01:636" {
		t.Fatalf("%+v %v, want server dc-01:636", a, err)
	}
	if v := testutil.ToFloat64(w.r.M.DirectoryQueries.WithLabelValues("dc-01:636", "ok")); v != 1 {
		t.Fatalf("%v pool queries for one bind, want 1 (one Do)", v)
	}
	if len(w.dir.calls) < 4 {
		t.Fatalf("%d searches: the mapping and both uniqueness searches did not all run", len(w.dir.calls))
	}
}

// A walk that meets a group again says "revisits (loops or diamonds)", not
// "loop", once.
func TestARevisitIsSaidAsARevisit(t *testing.T) {
	w := newWorld(t)
	w.r.Cfg.Nested = "recursive"
	w.dir.on(memberFilter(alice), grp(gLoopA, "g-loop-a"))
	w.dir.on(memberFilter(gLoopA), grp(gLoopB, "g-loop-b"))
	w.dir.on(memberFilter(gLoopB), grp(gLoopA, "g-loop-a"))
	w.dir.on(uniqueFilter("g-loop-a"), grp(gLoopA, "g-loop-a"))
	w.dir.on(uniqueFilter("g-loop-b"), grp(gLoopB, "g-loop-b"))
	for i := 0; i < 2; i++ {
		if _, err := w.r.Map(context.Background(), aliceCert(t)); err != nil {
			t.Fatal(err)
		}
	}
	if n := w.say.count("revisits (loops or diamonds)"); n != 1 {
		t.Fatalf("said %d times: %v", n, w.say.l)
	}
	if w.say.count("loop ") != 0 {
		t.Fatalf("a line calls a revisit a loop: %v", w.say.l)
	}
}

// A walk cut at max_depth counts once per resolution and keeps the groups
// it reached.
func TestACutWalkIsCounted(t *testing.T) {
	w := newWorld(t)
	w.r.Cfg.Nested, w.r.Cfg.MaxDepth = "recursive", 1
	w.dir.on(memberFilter(alice), grp(gLeaf, "g-leaf"))
	w.dir.on(memberFilter(gLeaf), grp(gMid, "g-mid"))
	w.dir.on(uniqueFilter("g-leaf"), grp(gLeaf, "g-leaf"))
	a, err := w.r.Map(context.Background(), aliceCert(t))
	if err != nil || !slices.Equal(a.GroupDNs, []string{gLeaf}) {
		t.Fatalf("%+v %v", a, err)
	}
	if v := testutil.ToFloat64(w.r.M.DirectoryWalksTruncated); v != 1 {
		t.Fatalf("port49_directory_walks_truncated_total = %v, want 1", v)
	}
}

// An outage with nothing stored for the certificate is directory_unavailable,
// never a guess: grace treats the store's not-found as no grace.
func TestGraceWithNothingStoredFailsClosed(t *testing.T) {
	w := newWorld(t)
	w.down()
	if _, err := w.r.Map(context.Background(), aliceCert(t)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("%v", err)
	}
	if _, err := w.r.Current(context.Background(), alicePrincipal); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("%v", err)
	}
}

// A forgotten principal (DeleteMembership) has no grace through the key
// either: the tombstone answers ErrNotFound and the resolver does not retry
// around it.
func TestAForgottenPrincipalHasNoGrace(t *testing.T) {
	w := newWorld(t)
	if _, err := w.r.Map(context.Background(), aliceCert(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := w.st.DeleteMembership(context.Background(), alicePrincipal); err != nil {
		t.Fatal(err)
	}
	w.down()
	if _, err := w.r.Map(context.Background(), aliceCert(t)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("a bind: %v", err)
	}
	if _, err := w.r.Current(context.Background(), alicePrincipal); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("a mint: %v", err)
	}
}

// Each outcome is counted: a refusal is unmapped and never grace, an
// outage is grace or unavailable.
func TestLookupOutcomesAreCounted(t *testing.T) {
	w := newWorld(t)
	if _, err := w.r.Map(context.Background(), aliceCert(t)); err != nil {
		t.Fatal(err)
	}
	w.down()
	if _, err := w.r.Current(context.Background(), alicePrincipal); err != nil {
		t.Fatal(err)
	}
	w.dir.on("(&(objectClass=person)(userPrincipalName=alice@corp.example.com))")
	w.srv.setDown(dc01, false)
	w.clk.Add(time.Minute)
	if _, err := w.r.Verify(context.Background(), alicePrincipal); !errors.Is(err, ErrUnmapped) {
		t.Fatal(err)
	}
	w.down()
	if _, err := w.r.Current(context.Background(), alicePrincipal); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	for outcome, want := range map[string]float64{"fresh": 1, "grace": 1, "unmapped": 1, "unavailable": 1} {
		if v := testutil.ToFloat64(w.r.M.DirectoryLookups.WithLabelValues(outcome)); v != want {
			t.Errorf("%s = %v, want %v", outcome, v, want)
		}
	}
}

// getFails makes the store's membership reads fail, as a timeout, an etcd
// hiccup or a record that will not open does.
type getFails struct {
	store.Store
	fail atomic.Bool
}

func (g *getFails) GetMembership(ctx context.Context, p string) (store.Membership, error) {
	if g.fail.Load() {
		return store.Membership{}, errors.New("store: read failed")
	}
	return g.Store.GetMembership(ctx, p)
}

// A refusal written while the store cannot be read keeps the principal
// held: its pin is one no entry matches, so mallory, who then sets her UPN
// to alice's, never becomes alice, and `port49 directory forget` frees it.
func TestARefusalWithAnUnreadablePinStillHoldsThePrincipal(t *testing.T) {
	w := newWorld(t)
	g := &getFails{Store: w.st}
	w.r.Store = g
	if _, err := w.r.Map(context.Background(), aliceCert(t)); err != nil {
		t.Fatal(err)
	}
	w.clk.Add(time.Minute)
	w.dir.on("(&(objectClass=person)(userPrincipalName=alice@corp.example.com))") // deleted
	g.fail.Store(true)
	if _, err := w.r.Verify(context.Background(), alicePrincipal); !errors.Is(err, ErrUnmapped) {
		t.Fatalf("%v", err)
	}
	g.fail.Store(false)
	if m, _ := w.st.GetMembership(context.Background(), alicePrincipal); !m.Refused || m.EntryID == "" {
		t.Fatalf("the refusal: %+v, want refused with a pin", m)
	}
	if !w.say.has("port49 directory forget "+alicePrincipal) || !w.say.has("could not be read") {
		t.Fatalf("%v", w.say.l)
	}
	w.clk.Add(time.Minute)
	mallory := entry("CN=Mallory,OU=Staff,DC=corp", map[string][]string{"userPrincipalName": {"alice@corp.example.com"},
		"sAMAccountName": {"mallory"}, "mail": {"mallory@corp.example.com"}})
	w.dir.on("(&(objectClass=person)(mail=mallory@corp.example.com))", mallory)
	w.dir.on("(userPrincipalName=alice@corp.example.com)", mallory)
	w.dir.on("(sAMAccountName=mallory)", mallory)
	mcert := leaf(t, func(c *x509.Certificate) { c.EmailAddresses = []string{"mallory@corp.example.com"} })
	if a, err := w.r.Map(context.Background(), mcert); !errors.Is(err, ErrUnmapped) {
		t.Fatalf("mallory bound as %+v %v", a.Principal, err)
	}
	if _, err := w.r.Current(context.Background(), alicePrincipal); !errors.Is(err, ErrUnmapped) {
		t.Fatalf("alice is held refused: %v", err)
	}
	if _, err := w.st.DeleteMembership(context.Background(), alicePrincipal); err != nil {
		t.Fatal(err)
	}
	if a, err := w.r.Map(context.Background(), mcert); err != nil || a.Principal != alicePrincipal {
		t.Fatalf("after forget: %+v %v", a, err)
	}
}

// State from a server that faulted never reaches the refusal a later
// server's answer causes: dc-01 maps alice and faults in the principal's
// uniqueness search, dc-02 finds the certificate ambiguous; only the
// certificate's key is refused, never user:alice@.
func TestAFailedOverQueryRefusesOnTheLaterAnswerAlone(t *testing.T) {
	const dc02 = "ldaps://dc-02"
	w := newWorld(t)
	w.srv.dirs[dc02] = newFakeDir()
	w.r.Cfg.Servers = []Server{{URI: dc01, Priority: 100}, {URI: dc02, Priority: 50}}
	w.r.Pool = NewPool(w.r.Cfg, w.srv.dial, noCheck, w.clk.Now, w.r.M, w.say.say)
	w.dir.err["(userPrincipalName=alice@corp.example.com)"] = ldap.NewError(ldap.ErrorNetwork, errors.New("reset"))
	a := entry(alice, map[string][]string{"userPrincipalName": {"alice@corp.example.com"}, "mail": {"alice@corp.example.com"}})
	b := entry("CN=Alice2,OU=Staff,DC=corp", map[string][]string{"mail": {"alice@corp.example.com"}})
	w.srv.dirs[dc02].on("(&(objectClass=person)(mail=alice@corp.example.com))", a, b)
	if _, err := w.r.Map(context.Background(), aliceCert(t)); !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("%v", err)
	}
	if m, err := w.st.GetMembership(context.Background(), alicePrincipal); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("dc-01's partial answer wrote a refusal for alice: %+v %v", m, err)
	}
}

// A name two groups share moves port49_directory_group_names_ambiguous, and
// it stays up through resolutions that see no shared name (an alert on it
// must not flap); an hour after the last sighting it is 0 again.
func TestASharedGroupNameMovesTheAmbiguousGauge(t *testing.T) {
	w := newWorld(t)
	evil := "CN=netops-oncall,OU=Users-Can-Create,DC=corp"
	w.dir.on(uniqueFilter("netops-oncall"), grp(gOnCall, "netops-oncall"), grp(evil, "netops-oncall"))
	gauge := func() float64 { return testutil.ToFloat64(w.r.M.DirectoryGroupNamesAmbiguous) }
	if gauge() != 0 {
		t.Fatalf("before: %v", gauge())
	}
	if _, err := w.r.Map(context.Background(), aliceCert(t)); err != nil {
		t.Fatal(err)
	}
	if gauge() != 1 {
		t.Fatalf("after a walk with a shared name: %v, want 1", gauge())
	}
	w.dir.on(uniqueFilter("netops-oncall"), grp(gOnCall, "netops-oncall")) // fixed in the directory
	w.clk.Add(30 * time.Minute)
	if _, err := w.r.Verify(context.Background(), alicePrincipal); err != nil {
		t.Fatal(err)
	}
	if gauge() != 1 {
		t.Fatalf("a clean resolution reset it: %v, want 1", gauge())
	}
	w.clk.Add(31 * time.Minute)
	if gauge() != 0 {
		t.Fatalf("an hour after the last sighting: %v, want 0", gauge())
	}
}
