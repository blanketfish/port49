package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/rhwendt/port49/internal/broker"
	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/engine"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/memory"
)

// reloadRig is a broker built from its files as port49d builds it, with a
// reloader over it on a clock the test moves, and stderr captured.
type reloadRig struct {
	cfg config.Config
	b   *broker.Broker
	m   *metrics.Metrics
	st  *memory.Store
	r   *reloader
	out *syncBuffer
	now time.Time
}

func newReloadRig(t *testing.T, policyBody string) *reloadRig {
	t.Helper()
	rig := &reloadRig{out: &syncBuffer{}, now: time.Now().Truncate(time.Second)}
	defer func(w io.Writer) { stderr = w }(stderr)
	stderr = io.Discard
	rig.cfg = brokerConfig(t, policyBody)
	rig.cfg.Broker.PolicyWatchInterval = time.Second
	rig.cfg.InventoryFile = filepath.Join(t.TempDir(), "inventory.yaml")
	if err := os.WriteFile(rig.cfg.InventoryFile, []byte("devices: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rig.st = memory.New(rig.clock)
	rig.m = metrics.New(prometheus.NewRegistry())
	_, b, err := buildBroker(rig.cfg, rig.st, seedMinter(), decision.NewJSONLines(io.Discard), rig.m)
	if err != nil {
		t.Fatal(err)
	}
	rig.b = b
	b.Now = rig.clock
	rig.r = newReloader(rig.cfg, b, rig.m, rig.clock)
	return rig
}

func (rig *reloadRig) clock() time.Time { return rig.now }

// write replaces the policy file's content.
func (rig *reloadRig) write(t *testing.T, body string) {
	t.Helper()
	if err := os.WriteFile(rig.cfg.Broker.PolicyFile, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// with runs fn with port49d's stderr captured in rig.out.
func (rig *reloadRig) with(fn func()) {
	defer func(w io.Writer) { stderr = w }(stderr)
	stderr = rig.out
	fn()
}

// A context alice holds on leaf1, as a redemption writes it, naming a blob the
// policy in force would not compile.
func (rig *reloadRig) aliceLoggedIn(t *testing.T) store.ContextKey {
	t.Helper()
	ctx := context.Background()
	k := store.ContextKey{NAS: "leaf1", Username: "alice"}
	if err := rig.st.PutContext(ctx, k, store.Context{CtxID: "c1", Principal: "user:alice@example.com",
		Username: "alice", PrivLvl: 15, BlobHash: "sha256:before"}, 12*time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := rig.st.IndexContext(ctx, "user:alice@example.com", "", "", store.ContextRef{NAS: "leaf1", Username: "alice"},
		12*time.Hour); err != nil {
		t.Fatal(err)
	}
	return k
}

const showOnly = `
scopes: [{name: all_devices, match: {}}]
roles: [{name: r, privilege: readonly, permit: [show **]}]
subjects: [{name: s, identity: ["user:alice@example.com"], username: alice, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [r]}]
`

// An edit is loaded once two reads in a row agree on it, so a file an editor
// is still writing is never loaded half-way; then it is in force, said, and
// counted.
func TestAPolicyEditIsLoadedOnceTwoReadsAgree(t *testing.T) {
	rig := newReloadRig(t, minimalPolicy)
	before := rig.b.Policy.Load().Bundle
	rig.write(t, showOnly)
	rig.with(func() { rig.r.poll(context.Background()) })
	if rig.b.Policy.Load().Bundle != before {
		t.Fatal("one read of a new file must not load it")
	}
	rig.with(func() { rig.r.poll(context.Background()) })
	if got := rig.b.Policy.Load().Bundle; got != engine.HashOf([]byte(showOnly)) {
		t.Fatalf("the second agreeing read loads it: bundle %s", got)
	}
	if n := testutil.ToFloat64(rig.m.PolicyReloads.WithLabelValues("applied")); n != 1 {
		t.Fatalf("port49_policy_reloads_total{outcome=applied} = %v", n)
	}
	if want := "port49d: policy reloaded (file changed): " + engine.HashOf([]byte(showOnly)) + " replaces " + before; !strings.Contains(rig.out.String(), want) {
		t.Fatalf("stderr %q, want %q", rig.out.String(), want)
	}
}

// A typo never takes the fleet down: a file that does not load is refused, the
// policy in force keeps serving, the refusal is said once with the reason and
// the bundle still serving, and port49_policy_file_refused holds at 1 until
// the file is put back.
func TestAPolicyThatDoesNotLoadIsRefusedAndTheOldOneServes(t *testing.T) {
	rig := newReloadRig(t, minimalPolicy)
	before := rig.b.Policy.Load().Bundle
	rig.write(t, strings.Replace(minimalPolicy, "privilege: admin", "privilege: root", 1))
	for i := 0; i < 5; i++ {
		rig.with(func() { rig.r.poll(context.Background()) })
	}
	if rig.b.Policy.Load().Bundle != before {
		t.Fatal("a refused file must leave the policy in force")
	}
	if n := testutil.ToFloat64(rig.m.PolicyReloads.WithLabelValues("refused")); n != 1 {
		t.Fatalf("a refusal is counted once per content, got %v", n)
	}
	if testutil.ToFloat64(rig.m.PolicyFileRefused) != 1 {
		t.Fatal("port49_policy_file_refused must be 1 while the file on disk is refused")
	}
	out := rig.out.String()
	if strings.Count(out, "refused") != 1 || !strings.Contains(out, "still serving "+before) ||
		!strings.Contains(out, `"root" is not a privilege level`) || !strings.Contains(out, rig.cfg.Broker.PolicyFile) {
		t.Fatalf("stderr: %q", out)
	}
	rig.write(t, minimalPolicy)
	rig.with(func() { rig.r.poll(context.Background()) })
	if testutil.ToFloat64(rig.m.PolicyFileRefused) != 0 || !strings.Contains(rig.out.String(), "is the policy in force again") {
		t.Fatalf("a file put back clears the alarm: %q", rig.out.String())
	}
}

// SIGHUP loads at once, with no second read, and says when nothing changed.
func TestSIGHUPLoadsAtOnce(t *testing.T) {
	rig := newReloadRig(t, minimalPolicy)
	rig.with(func() { rig.r.reload(context.Background(), "SIGHUP") })
	if n := testutil.ToFloat64(rig.m.PolicyReloads.WithLabelValues("unchanged")); n != 1 ||
		!strings.Contains(rig.out.String(), "port49d: policy reload (SIGHUP): broker.policy_file unchanged") {
		t.Fatalf("unchanged %v, stderr %q", n, rig.out.String())
	}
	rig.write(t, showOnly)
	rig.with(func() { rig.r.reload(context.Background(), "SIGHUP") })
	if rig.b.Policy.Load().Bundle != engine.HashOf([]byte(showOnly)) {
		t.Fatal("SIGHUP puts the file in force at once")
	}
}

// A reload is carried into every live context at once, and again
// settleAfterReload later for a login that was in flight across the swap
// (plan 4b). The line after it says what the refresh did.
func TestAReloadRefreshesLiveContextsAndSchedulesTheSettlePass(t *testing.T) {
	rig := newReloadRig(t, minimalPolicy)
	k := rig.aliceLoggedIn(t)
	rig.write(t, showOnly)
	rig.with(func() { rig.r.reload(context.Background(), "SIGHUP") })
	c, err := rig.st.GetContext(context.Background(), k)
	if err != nil || c.BlobHash == "sha256:before" || c.CtxID != "c1" || !c.RevokedAt.IsZero() || c.MaxPrivilege != 0 {
		t.Fatalf("alice's context takes the new policy in place: %+v %v", c, err)
	}
	if !rig.r.due.Equal(rig.now.Add(settleAfterReload)) {
		t.Fatalf("the settle pass is due at %v, got %v", rig.now.Add(settleAfterReload), rig.r.due)
	}
	if !strings.Contains(rig.out.String(), "port49d: policy refresh: 1 live context(s) updated, 0 revoked") {
		t.Fatalf("stderr: %q", rig.out.String())
	}
	if testutil.ToFloat64(rig.m.PolicyRefreshPending) != 0 {
		t.Fatal("a pass that completed leaves nothing pending")
	}
}

// failingStore stops a refresh at its first index read.
type failingStore struct{ store.Store }

func (failingStore) ActivePrincipals(context.Context) ([]string, error) {
	return nil, errors.New("store: connection refused")
}

// The store down during a reload: the new policy is in force for every mint
// at once, the refresh says how far it got and when it tries again, and the
// retry finishes the job once the store is back.
func TestARefreshTheStoreStopsIsRetried(t *testing.T) {
	rig := newReloadRig(t, minimalPolicy)
	k := rig.aliceLoggedIn(t)
	rig.b.Store = failingStore{rig.st}
	rig.write(t, showOnly)
	rig.with(func() { rig.r.reload(context.Background(), "SIGHUP") })
	if rig.b.Policy.Load().Bundle != engine.HashOf([]byte(showOnly)) {
		t.Fatal("the policy is in force whether or not the refresh finished")
	}
	if !strings.Contains(rig.out.String(), "port49d: policy refresh stopped") ||
		!strings.Contains(rig.out.String(), "trying again in 30s") || !rig.r.due.Equal(rig.now.Add(refreshRetry)) {
		t.Fatalf("due %v, stderr %q", rig.r.due, rig.out.String())
	}
	if testutil.ToFloat64(rig.m.PolicyRefreshPending) != 1 {
		t.Fatal("port49_policy_refresh_pending must be 1 while a context may hold the old policy")
	}
	// The policy it replaced was in force until the swap; the retry judges
	// its tokens over that span and no further (broker.Prior).
	if len(rig.r.priors) != 2 || !rig.r.priors[0].Until.Equal(rig.now) || !rig.r.priors[1].Until.IsZero() {
		t.Fatalf("priors: %+v", rig.r.priors)
	}
	rig.b.Store = rig.st
	rig.now = rig.now.Add(refreshRetry)
	rig.with(func() { rig.r.refresh(context.Background()) })
	if c, _ := rig.st.GetContext(context.Background(), k); c.BlobHash == "sha256:before" {
		t.Fatalf("the retry refreshes the context: %+v", c)
	}
	if testutil.ToFloat64(rig.m.PolicyRefreshPending) != 0 ||
		!strings.Contains(rig.out.String(), "port49d: policy refresh finished: 1 live context(s) updated") {
		t.Fatalf("the pass that completes after a stop says so and clears the gauge: %q", rig.out.String())
	}
}

// A scheduled pass the store stops, with no swap before it — a grant's expiry
// — raises port49_policy_refresh_pending too: a live context may still hold
// the expired grant.
func TestAScheduledRefreshTheStoreStopsIsPending(t *testing.T) {
	rig := newReloadRig(t, minimalPolicy)
	rig.aliceLoggedIn(t)
	rig.b.Store = failingStore{rig.st}
	rig.with(func() { rig.r.refresh(context.Background()) })
	if testutil.ToFloat64(rig.m.PolicyRefreshPending) != 1 || !rig.r.due.Equal(rig.now.Add(refreshRetry)) {
		t.Fatalf("due %v, stderr %q", rig.r.due, rig.out.String())
	}
}

// The watch loads the bytes its two reads agreed on, not a third read: an
// editor that begins writing again between them must not have its half-written
// file loaded (pre-flight S2). Here the file on disk is already torn by the
// time the agreed version is loaded.
func TestTheWatchLoadsTheBytesItsReadsAgreedOn(t *testing.T) {
	rig := newReloadRig(t, minimalPolicy)
	rig.write(t, showOnly[:len(showOnly)/2])
	rig.with(func() {
		rig.r.load(context.Background(), "file changed", []byte(showOnly), engine.HashOf([]byte(showOnly)), nil)
	})
	if got := rig.b.Policy.Load().Bundle; got != engine.HashOf([]byte(showOnly)) {
		t.Fatalf("bundle %s: the agreed bytes are what is loaded", got)
	}
}

// Whoever can write the policy decides every operator's access, so a file
// someone else could have written is refused at a reload as at start: the
// policy in force keeps serving, the refusal is said once and counted, and
// putting the mode right is a change the watch sees (spec §5.1.3).
func TestAPolicyFileOthersCouldWriteIsRefusedAtAReload(t *testing.T) {
	rig := newReloadRig(t, minimalPolicy)
	before := rig.b.Policy.Load().Bundle
	rig.write(t, showOnly)
	if err := os.Chmod(rig.cfg.Broker.PolicyFile, 0o622); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		rig.with(func() { rig.r.poll(context.Background()) })
	}
	if rig.b.Policy.Load().Bundle != before || testutil.ToFloat64(rig.m.PolicyFileRefused) != 1 ||
		testutil.ToFloat64(rig.m.PolicyReloads.WithLabelValues("refused")) != 1 {
		t.Fatalf("an unsafe file is refused once and the policy in force serves: %q", rig.out.String())
	}
	if strings.Count(rig.out.String(), "writable by others") != 1 {
		t.Fatalf("stderr: %q", rig.out.String())
	}
	if err := os.Chmod(rig.cfg.Broker.PolicyFile, 0o600); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		rig.with(func() { rig.r.poll(context.Background()) })
	}
	if rig.b.Policy.Load().Bundle != engine.HashOf([]byte(showOnly)) || testutil.ToFloat64(rig.m.PolicyFileRefused) != 0 {
		t.Fatalf("the file with its mode put right loads: %q", rig.out.String())
	}
}

// A refusal is one line, as every port49d line is: a YAML error's own lines
// are joined into it.
func TestARefusalIsOneLine(t *testing.T) {
	rig := newReloadRig(t, minimalPolicy)
	rig.write(t, strings.Replace(minimalPolicy, "token_ttl: 60s", "token_ttl: nope", 1))
	rig.with(func() { rig.r.reload(context.Background(), "SIGHUP") })
	out := strings.TrimSuffix(rig.out.String(), "\n")
	if strings.Contains(out, "\n") || !strings.Contains(out, "refused;") || !strings.Contains(out, "cannot unmarshal") {
		t.Fatalf("stderr: %q", rig.out.String())
	}
}

// A grant's expiry is a scheduled refresh (policy.NextChange).
func TestTheRefreshIsScheduledAtTheNextGrantExpiry(t *testing.T) {
	lapse := time.Now().Add(48 * time.Hour).Truncate(time.Second)
	rig := newReloadRig(t, strings.Replace(minimalPolicy, "roles: [r]}", "roles: [r], expires: "+
		lapse.UTC().Format(time.RFC3339)+"}", 1))
	if !rig.r.due.Equal(lapse) {
		t.Fatalf("due %v, want the expiry %v", rig.r.due, lapse)
	}
}

// The inventory is read once, at start, until plan 6: a reload after an
// inventory edit says so, once, rather than leaving an operator to believe
// SIGHUP applied it.
func TestAnInventoryEditIsSaidNotApplied(t *testing.T) {
	rig := newReloadRig(t, minimalPolicy)
	if err := os.WriteFile(rig.cfg.InventoryFile, []byte("devices: [{name: leaf2, platform: arista_eos}]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rig.with(func() { rig.r.reload(context.Background(), "SIGHUP") })
	rig.with(func() { rig.r.reload(context.Background(), "SIGHUP") })
	if n := strings.Count(rig.out.String(), "has changed since start and is not reloaded"); n != 1 {
		t.Fatalf("said %d times: %q", n, rig.out.String())
	}
}

// run takes SIGHUP from its channel and returns when its context ends.
func TestTheReloaderRunsOnSIGHUPUntilCancelled(t *testing.T) {
	rig := newReloadRig(t, minimalPolicy)
	defer func(w io.Writer) { stderr = w }(stderr)
	stderr = rig.out
	ctx, cancel := context.WithCancel(context.Background())
	hup := make(chan os.Signal, 1)
	done := make(chan struct{})
	go func() { rig.r.run(ctx, hup); close(done) }()
	hup <- syscall.SIGHUP
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(rig.out.String(), "(SIGHUP)") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("run did not return when its context ended")
	}
	if !strings.Contains(rig.out.String(), "port49d: policy reload (SIGHUP)") {
		t.Fatalf("stderr: %q", rig.out.String())
	}
}
