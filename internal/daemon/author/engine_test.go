package author

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/engine"
	"github.com/rhwendt/port49/internal/platform"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/memory"
	"github.com/rhwendt/port49/internal/tacacs/wire"
)

// eosBlob is a compiled blob for arista_eos in the shape the broker writes.
func eosBlob() engine.Blob {
	return engine.Blob{Bundle: "sha256:policy", Platform: "arista_eos",
		Normalize: engine.Normalize{PipeToken: "|", StripCR: true}, Privilege: "admin",
		Attributes: []string{"priv-lvl=15", "home-directory*/home/{username}"},
		Rules: []engine.Rule{
			{Verdict: engine.Permit, Rule: "**", Role: "network_admin"},
			{Verdict: engine.Deny, Rule: "show hostname", Role: "slice_denies"},
			{Verdict: engine.Deny, Rule: "interface @management", Role: "safety"},
		},
		Pipe:    []string{"include **"},
		Classes: map[string][]string{"management": {`^Management[0-9]+$`}}}
}

// flakyBlobStore answers GetBlob from the memory store until down is set.
type flakyBlobStore struct {
	*memory.Store
	down bool
}

func (f *flakyBlobStore) GetBlob(ctx context.Context, hash string) ([]byte, error) {
	if f.down {
		return nil, errors.New("store: connection refused")
	}
	return f.Store.GetBlob(ctx, hash)
}

type engineFixture struct {
	st   *flakyBlobStore
	m    *metrics.Metrics
	h    *Handler
	log  *bytes.Buffer
	hash string
}

// newEngineFixture puts the blob in the store and a context naming it, as a
// broker-minted login leaves them, and serves them through the real handler.
func newEngineFixture(t *testing.T, b engine.Blob) *engineFixture {
	t.Helper()
	f := &engineFixture{st: &flakyBlobStore{Store: memory.New(time.Now)}, m: metrics.New(prometheus.NewRegistry()),
		log: &bytes.Buffer{}}
	body, hash, err := engine.Encode(b)
	if err != nil {
		t.Fatal(err)
	}
	f.hash = hash
	if err := f.st.PutBlob(context.Background(), hash, body, time.Hour); err != nil {
		t.Fatal(err)
	}
	f.st.PutContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"},
		store.Context{CtxID: "ctx1", Username: "alice", Principal: "user:alice@example.com", PrivLvl: 15,
			BlobHash: hash}, time.Hour)
	f.h = New(f.st, &Engine{Store: f.st, Metrics: f.m}, decision.NewJSONLines(f.log), f.m, time.Now,
		platform.Defaults(), time.Hour, time.Minute, time.Hour)
	return f
}

func (f *engineFixture) authorize(t *testing.T, args ...string) (wire.AuthorResponse, map[string]any) {
	t.Helper()
	resp := f.h.Handle(context.Background(), peer, req("alice", "vty0", append([]string{"service=shell"}, args...)...))
	return resp, lastRecord(t, f.log)
}

// A session is answered with the blob's attributes, substituted from the
// context and the device, and its record names the policy (spec §5.2, §5.7).
func TestTheEngineAnswersASessionFromTheBlob(t *testing.T) {
	f := newEngineFixture(t, eosBlob())
	resp, rec := f.authorize(t, "cmd=")
	if resp.Status != wire.AuthorStatusPassAdd || len(resp.Args) != 2 || string(resp.Args[1]) != "home-directory*/home/alice" {
		t.Fatalf("session reply: %+v", resp)
	}
	pol, _ := rec["policy"].(map[string]any)
	reply, _ := rec["reply"].(map[string]any)
	attrs, _ := reply["attributes"].([]any)
	if rec["reason"] != "context_matched" || pol["blob"] != f.hash || pol["bundle"] != "sha256:policy" ||
		len(attrs) != 2 || attrs[1] != "home-directory*/home/alice" {
		t.Fatalf("session record: %v", rec)
	}
}

// A command is decided by dominance, and the record carries what matched: a
// replay reads it back (spec §5.3, §5.7).
func TestTheEngineDecidesACommandAndSaysWhy(t *testing.T) {
	f := newEngineFixture(t, eosBlob())
	if resp, rec := f.authorize(t, "cmd=show", "cmd-arg=version", "cmd-arg=<cr>"); resp.Status != wire.AuthorStatusPassAdd ||
		rec["reason"] != "permit_dominates" {
		t.Fatalf("show version: %+v %v", resp, rec)
	}
	resp, rec := f.authorize(t, "cmd=interface", "cmd-arg=management1", "cmd-arg=<cr>")
	if resp.Status != wire.AuthorStatusFail || string(resp.ServerMsg) != "port49: denied by safety (interface @management) - see 'port49 explain'" {
		t.Fatalf("a class deny, in any case: %+v", resp)
	}
	pol, _ := rec["policy"].(map[string]any)
	deny, _ := pol["matched_deny"].(map[string]any)
	permits, _ := pol["matched_permits"].([]any)
	if rec["reason"] != "no_permit_dominates_deny" || deny["role"] != "safety" || len(permits) != 1 {
		t.Fatalf("record: %v", rec)
	}
	if resp, rec := f.authorize(t, "cmd=show", "cmd-arg=run", "cmd-arg=|", "cmd-arg=redirect", "cmd-arg=x"); resp.Status != wire.AuthorStatusFail ||
		rec["reason"] != "pipe_stage_denied" {
		t.Fatalf("a pipeline stage off the allowlist: %+v %v", resp, rec)
	}
}

// The blob is cached by hash: a replica answers from its copy when a blob read
// fails (spec §5.1.1), and the cache and the store read are both counted. It
// does not carry a whole-store outage: Handle reads the context from the same
// store first, and that read fails before the cache is asked.
func TestACachedBlobOutlivesABlobReadFailure(t *testing.T) {
	f := newEngineFixture(t, eosBlob())
	f.authorize(t, "cmd=show", "cmd-arg=version")
	f.st.down = true
	if resp, _ := f.authorize(t, "cmd=show", "cmd-arg=clock"); resp.Status != wire.AuthorStatusPassAdd {
		t.Fatalf("a cached blob answers through a blob read failure: %+v", resp)
	}
	if hit, miss := testutil.ToFloat64(f.m.BlobCache.WithLabelValues("hit")), testutil.ToFloat64(f.m.BlobCache.WithLabelValues("miss")); hit != 1 || miss != 1 {
		t.Fatalf("cache hit %v miss %v", hit, miss)
	}
	if n := testutil.ToFloat64(f.m.StoreOps.WithLabelValues("get_blob", "ok")); n != 1 {
		t.Fatalf("get_blob ok: %v", n)
	}
}

// A store that does not answer is store_unavailable, FAIL like every
// authorization denial (plan 4, owner's ruling; an ERROR falls through on
// some images, tests/lab/results/L4-error-*.md); a blob the store does not
// hold, or holds wrong, is
// blob_unavailable, also FAIL. The log tells them apart (spec §5.7; roadmap,
// carried from plan 3).
func TestAStoreErrorIsStoreUnavailableAndAMissingBlobIsNot(t *testing.T) {
	f := newEngineFixture(t, eosBlob())
	f.st.down = true
	resp, rec := f.authorize(t, "cmd=show", "cmd-arg=version")
	if resp.Status != wire.AuthorStatusFail || rec["reason"] != "store_unavailable" || string(resp.ServerMsg) != storeUnavailableMsg {
		t.Fatalf("store down: %+v %v", resp, rec)
	}
	f.st.down = false
	// A body stored under its own hash that this build refuses — an older
	// format left in the store at an upgrade — gets past the hash check and
	// is refused by the decode.
	refused := []byte(`{"version":2}`)
	f.st.PutBlob(context.Background(), engine.HashOf(refused), refused, time.Hour)
	for name, hash := range map[string]string{
		"missing":      engine.HashOf([]byte("nothing was stored under this")),
		"corrupt":      "sha256:wrong",
		"hash-correct": engine.HashOf(refused),
	} {
		f.st.PutBlob(context.Background(), "sha256:wrong", []byte(`{"version":2}`), time.Hour)
		f.st.PutContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"},
			store.Context{CtxID: "ctx1", Username: "alice", PrivLvl: 15, BlobHash: hash}, time.Hour)
		resp, rec := f.authorize(t, "cmd=show", "cmd-arg=version")
		if resp.Status != wire.AuthorStatusFail || rec["reason"] != "blob_unavailable" || string(resp.ServerMsg) != blobUnavailableMsg {
			t.Fatalf("%s: %+v %v", name, resp, rec)
		}
	}
}

// The cache stays within its bound: past blobCacheMax distinct blobs, one
// entry is dropped for each one added, and every blob still answers.
func TestTheBlobCacheIsBounded(t *testing.T) {
	st := memory.New(time.Now)
	e := &Engine{Store: st, Metrics: metrics.New(prometheus.NewRegistry())}
	for i := range blobCacheMax + 3 {
		b := eosBlob()
		b.Bundle = fmt.Sprintf("sha256:policy-%d", i)
		body, hash, err := engine.Encode(b)
		if err != nil {
			t.Fatal(err)
		}
		st.PutBlob(context.Background(), hash, body, time.Hour)
		if _, reason := e.program(context.Background(), hash); reason != "" {
			t.Fatalf("blob %d: %s", i, reason)
		}
		if len(e.cache) > blobCacheMax {
			t.Fatalf("cache holds %d, bound %d", len(e.cache), blobCacheMax)
		}
	}
	if len(e.cache) != blobCacheMax {
		t.Fatalf("cache holds %d, want the bound %d", len(e.cache), blobCacheMax)
	}
}

// A blob whose reply would tell the device a priv-lvl above the context's
// ceiling is refused, never sent and clamped: the device would run at the
// higher level while port49 held the session lower (spec §7). The load's
// joint check quarantines such a composition, so meeting it here means the
// context no longer fits the blob.
func TestASessionReplyAboveTheCeilingIsRefused(t *testing.T) {
	f := newEngineFixture(t, eosBlob())
	e := &Engine{Store: f.st, Metrics: f.m}
	c := store.Context{Username: "alice", Principal: "user:alice@example.com", PrivLvl: 1, MaxPrivilege: 1, BlobHash: f.hash}
	d := e.Session(context.Background(), Request{Context: c, Device: peer})
	if d.Permit || d.Reason != decision.BlobUnavailable || len(d.Attributes) != 0 || d.ServerMsg != blobUnavailableMsg ||
		d.Policy == nil || d.Policy.Blob != f.hash {
		t.Fatalf("%+v", d)
	}
	// At the ceiling, or with none, it is answered.
	for _, ceiling := range []uint8{15, 0} {
		c.MaxPrivilege = ceiling
		if d := e.Session(context.Background(), Request{Context: c, Device: peer}); !d.Permit {
			t.Fatalf("ceiling %d: %+v", ceiling, d)
		}
	}
}

// A blob whose reply carries a priv-lvl that is not a level is refused, never
// sent: IOS-XE refused the session for priv-lvl=99 (L18-cisco_iosxe.md,
// variant 7). The load's joint check quarantines such a composition, so a
// blob carrying one was minted before that check or under another adapter.
func TestASessionReplyWithAPrivLvlThatIsNotALevelIsRefused(t *testing.T) {
	for _, a := range []string{"priv-lvl=99", "priv-lvl=16", "priv-lvl=abc", "priv-lvl=", "priv-lvl*-1"} {
		b := eosBlob()
		b.Attributes = []string{a, "home-directory*/home/{username}"}
		f := newEngineFixture(t, b)
		c := store.Context{Username: "alice", Principal: "user:alice@example.com", BlobHash: f.hash}
		d := (&Engine{Store: f.st, Metrics: f.m}).Session(context.Background(), Request{Context: c, Device: peer})
		if d.Permit || d.Reason != decision.BlobUnavailable || len(d.Attributes) != 0 || d.ServerMsg != blobUnavailableMsg {
			t.Errorf("%s: %+v", a, d)
		}
	}
}

// A blob whose reply carries an idletime or timeout that is not a plain
// decimal is refused, never sent, as the load's joint check quarantines it
// (resolve.go, engine.NotANumber): a device sent a value it cannot use may
// refuse the session, and on IOS-XE a run of refusals locks out SSH
// (final review M2).
func TestASessionReplyWithANumberThatIsNotOneIsRefused(t *testing.T) {
	for _, a := range []string{"idletime*abc", "timeout*-1", "idletime*030", "timeout*99999"} {
		b := eosBlob()
		b.Attributes = []string{"priv-lvl=1", a}
		f := newEngineFixture(t, b)
		c := store.Context{Username: "alice", Principal: "user:alice@example.com", BlobHash: f.hash}
		d := (&Engine{Store: f.st, Metrics: f.m}).Session(context.Background(), Request{Context: c, Device: peer})
		if d.Permit || d.Reason != decision.BlobUnavailable || len(d.Attributes) != 0 || d.ServerMsg != blobUnavailableMsg {
			t.Errorf("%s: %+v", a, d)
		}
	}
}

// A blob that says which attributes its platform takes is never answered with
// another: the device would refuse the session, and on IOS-XE a run of
// refusals stops it answering SSH (L18-cisco_iosxe.md). The load's joint check
// quarantines such a composition, so a blob carrying one was minted before
// that check or under another adapter.
func TestASessionReplyTheBlobsPlatformDoesNotTakeIsRefused(t *testing.T) {
	b := eosBlob()
	b.AcceptedAttributes = []string{"priv-lvl"}
	f := newEngineFixture(t, b)
	c := store.Context{Username: "alice", Principal: "user:alice@example.com", BlobHash: f.hash}
	e := &Engine{Store: f.st, Metrics: f.m}
	d := e.Session(context.Background(), Request{Context: c, Device: peer})
	if d.Permit || d.Reason != decision.BlobUnavailable || len(d.Attributes) != 0 || d.ServerMsg != blobUnavailableMsg {
		t.Fatalf("%+v", d)
	}
	b.AcceptedAttributes = []string{"home-directory", "priv-lvl"}
	f = newEngineFixture(t, b)
	c.BlobHash = f.hash
	if d := (&Engine{Store: f.st, Metrics: f.m}).Session(context.Background(), Request{Context: c, Device: peer}); !d.Permit {
		t.Fatalf("every name accepted: %+v", d)
	}
}

// A blob compiled for another platform than the device's is never answered
// from: its attributes and its dialect are another vendor's (roadmap, plan 4,
// carried from plan 3).
func TestABlobForAnotherPlatformIsRefused(t *testing.T) {
	b := eosBlob()
	b.Platform = "cisco_nxos"
	f := newEngineFixture(t, b)
	for _, args := range [][]string{{"cmd="}, {"cmd=show", "cmd-arg=version"}} {
		resp, rec := f.authorize(t, args...)
		if resp.Status != wire.AuthorStatusFail || rec["reason"] != "blob_platform_mismatch" ||
			!strings.HasPrefix(string(resp.ServerMsg), "port49: ") {
			t.Fatalf("%q: %+v %v", args, resp, rec)
		}
	}
}

// A context with no blob is the fallback's, and with no fallback it is denied:
// port49 never falls back to permitting everything.
func TestAContextWithNoBlobIsTheFallbacksOrDenied(t *testing.T) {
	e := &Engine{Store: memory.New(time.Now), Metrics: metrics.New(prometheus.NewRegistry())}
	r := Request{Context: store.Context{Username: "alice"}, Device: peer, Vector: []string{"show", "version"}}
	if d := e.Command(context.Background(), r); d.Permit || d.Reason != decision.NoRuleMatched {
		t.Fatalf("no fallback: %+v", d)
	}
	if d := e.Session(context.Background(), r); d.Permit || d.Reason != decision.NoRuleMatched || len(d.Attributes) != 0 {
		t.Fatalf("no fallback, session: %+v", d)
	}
	e.Fallback = &Lab{SessionAttributes: []string{"priv-lvl=15"}}
	if d := e.Session(context.Background(), r); !d.Permit || !reflect.DeepEqual(d.Attributes, []string{"priv-lvl=15"}) {
		t.Fatalf("the lab's seeded contexts keep the lab's answers: %+v", d)
	}
}

// A substitution that no longer fits on the wire sends nothing partial.
func TestAnOverlongSubstitutionIsNotSent(t *testing.T) {
	f := newEngineFixture(t, eosBlob())
	long := strings.Repeat("a", 250)
	d := (&Engine{Store: f.st, Metrics: f.m}).Session(context.Background(),
		Request{Context: store.Context{Username: long, BlobHash: f.hash}, Device: peer})
	if d.Permit || d.Reason != decision.BlobUnavailable || len(d.Attributes) != 0 {
		t.Fatalf("%+v", d)
	}
}

// A substitution value that would change an attribute's structure is refused
// like an overlong one: nothing partial is sent, and the reason is the same.
func TestAnUnsafeSubstitutionIsNotSent(t *testing.T) {
	f := newEngineFixture(t, eosBlob())
	d := (&Engine{Store: f.st, Metrics: f.m}).Session(context.Background(),
		Request{Context: store.Context{Username: "alice*priv-lvl=15", BlobHash: f.hash}, Device: peer})
	if d.Permit || d.Reason != decision.BlobUnavailable || len(d.Attributes) != 0 {
		t.Fatalf("%+v", d)
	}
}

// The record's vector is the one the engine decided, not the handler's own
// parse: the two differ on a pipeline and on a blob that keeps `<cr>`, and a
// replay reads the record (Task 6 review, M3).
func TestTheRecordCarriesTheVectorTheEngineDecided(t *testing.T) {
	b := eosBlob()
	b.Normalize.StripCR = false
	f := newEngineFixture(t, b)
	for _, tt := range []struct {
		args []string
		want []any
	}{
		{[]string{"cmd=show", "cmd-arg=version", "cmd-arg=<cr>"}, []any{"show", "version", "<cr>"}},
		{[]string{"cmd=show", "cmd-arg=run", "cmd-arg=|", "cmd-arg=include", "cmd-arg=x"}, []any{"show", "run"}},
	} {
		_, rec := f.authorize(t, tt.args...)
		r, _ := rec["request"].(map[string]any)
		if !reflect.DeepEqual(r["vector"], tt.want) {
			t.Errorf("%q: request.vector %v, want %v", tt.args, r["vector"], tt.want)
		}
	}
}

// Decision.Error is lab-only: an ERROR on authorization runs every command
// under IOS-XE's if-authenticated and hands the N9Kv to local RBAC
// (tests/lab/results/L4-error-*.md), so Engine never sets it, on any path —
// a permit, a deny, a store outage, a blob it cannot use, a context it does
// not fit, or no blob and no Fallback.
func TestTheEngineNeverAnswersError(t *testing.T) {
	f := newEngineFixture(t, eosBlob())
	e := &Engine{Store: f.st, Metrics: f.m}
	ok := store.Context{Username: "alice", Principal: "user:alice@example.com", BlobHash: f.hash}
	other := eosBlob()
	other.Platform = "cisco_nxos"
	body, otherHash, err := engine.Encode(other)
	if err != nil {
		t.Fatal(err)
	}
	f.st.PutBlob(context.Background(), otherHash, body, time.Hour)
	contexts := map[string]store.Context{
		"blob":             ok,
		"missing blob":     {Username: "alice", BlobHash: engine.HashOf([]byte("absent"))},
		"another platform": {Username: "alice", BlobHash: otherHash},
		"unsafe username":  {Username: "alice*priv-lvl=15", BlobHash: f.hash},
		"above ceiling":    {Username: "alice", MaxPrivilege: 1, BlobHash: f.hash},
		"no blob":          {Username: "alice"},
	}
	for _, down := range []bool{false, true} {
		f.st.down = down
		e.cache = nil
		for name, c := range contexts {
			for _, raw := range [][]string{nil, {"service=shell", "cmd=show", "cmd-arg=version"},
				{"service=shell", "cmd=show", "cmd-arg=hostname"}} {
				r := Request{Context: c, Device: peer, Raw: raw}
				for _, d := range []Decision{e.Session(context.Background(), r), e.Command(context.Background(), r)} {
					if d.Error {
						t.Errorf("%s (store down %v, %q): Error set: %+v", name, down, raw, d)
					}
				}
			}
		}
	}
}

// The engine's vector drops the pipeline and the raw pairs keep it, so a
// pattern anchored at the end — one a `platforms:` block may add — matches
// the vector and not the raw pairs, while a built-in one matches both. Each
// pattern is judged on its own: the form it missed loses every argument,
// whatever another pattern did there (spec §5.8; task 11 review C1).
func TestASecretOneFormMissesIsRedactedInBoth(t *testing.T) {
	f := newEngineFixture(t, eosBlob())
	f.h.WithRedactor(func(name string) []platform.Redaction {
		return append(platform.Redactions(name),
			platform.Redaction{Match: []string{"tunnel", "psk", "*", "key", "*"}, After: "psk"})
	})
	_, rec := f.authorize(t, "cmd=tunnel", "cmd-arg=psk", "cmd-arg=S3cret", "cmd-arg=key", "cmd-arg=K1",
		"cmd-arg=|", "cmd-arg=no-more", "cmd-arg=<cr>")
	if strings.Contains(f.log.String(), "S3cret") || strings.Contains(f.log.String(), "K1") {
		t.Fatalf("a secret reached the log: %s", f.log.String())
	}
	if r := rec["request"].(map[string]any); r["redacted"] != true {
		t.Fatalf("%v", r)
	}
}

// A blob whose reply is a projection's fail-closed reply opens the session
// with that reply, recorded as projection_fail_closed: the subject told less
// than port49 would permit is in the log by name (spec §13 decision 26).
func TestAFailClosedReplyIsRecordedByName(t *testing.T) {
	// A Junos blob as the broker writes a fail-closed composition: the reply
	// is `deny-commands` `.*` alone, and the rules are what port49 decides
	// (Task 10 review, parked M1).
	b := engine.Blob{Bundle: "sha256:policy", Platform: "juniper_junos",
		Normalize: engine.Normalize{PipeToken: "|", StripCR: true, SessionOnly: true}, Privilege: "readonly",
		Attributes: []string{"deny-commands=^.*$"}, FailClosed: "refused_shape",
		Rules: []engine.Rule{
			{Verdict: engine.Permit, Rule: "show **", Role: "read_only"},
			{Verdict: engine.Deny, Rule: "show interfaces terse", Role: "read_only"},
		}}
	f := newEngineFixture(t, b)
	c := store.Context{Username: "alice", Principal: "user:alice@example.com", BlobHash: f.hash}
	d := (&Engine{Store: f.st, Metrics: f.m}).Session(context.Background(), Request{Context: c, Device: junosPeer})
	if !d.Permit || d.Reason != decision.ProjectionFailClosed || !reflect.DeepEqual(d.Attributes, b.Attributes) {
		t.Fatalf("%+v", d)
	}
	// Through the handler, as Junos asks, the record and the metric name it
	// (M2).
	resp := f.h.Handle(context.Background(), junosPeer, req("alice", "", "service=junos-exec"))
	rec := lastRecord(t, f.log)
	if resp.Status != wire.AuthorStatusPassAdd || rec["reason"] != string(decision.ProjectionFailClosed) {
		t.Fatalf("%+v %v", resp, rec)
	}
	if got := testutil.ToFloat64(f.m.Decisions.WithLabelValues("authorize_session", "permit",
		string(decision.ProjectionFailClosed))); got != 1 {
		t.Fatalf("port49_decisions_total{reason=%q} = %v", decision.ProjectionFailClosed, got)
	}
}
