package port49d

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
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
	"github.com/rhwendt/port49/internal/platform"
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
	rig.cfg.Policy.WatchInterval = time.Second
	rig.cfg.MaxRemovedPercent = 10 // config.Load's default
	// safeDir: the inventory is read behind the policy file's fence.
	rig.cfg.InventoryFile = filepath.Join(safeDir(t), "inventory.yaml")
	if err := os.WriteFile(rig.cfg.InventoryFile, []byte("devices: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rig.st = memory.New(rig.clock)
	rig.m = metrics.New(prometheus.NewRegistry())
	_, b, err := buildBroker(rig.cfg, "inventory_file "+rig.cfg.InventoryFile, rig.st, seedMinter(), decision.NewJSONLines(io.Discard), rig.m)
	if err != nil {
		t.Fatal(err)
	}
	rig.b = b
	b.Now = rig.clock
	rig.r = newReloader(rig.cfg, b.Policy, b.Log, b.Refresh, rig.m, rig.clock)
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
	before := rig.b.Policy.Load().Source
	rig.write(t, showOnly)
	rig.with(func() { rig.r.poll(context.Background()) })
	if rig.b.Policy.Load().Source != before {
		t.Fatal("one read of a new file must not load it")
	}
	rig.with(func() { rig.r.poll(context.Background()) })
	if got := rig.b.Policy.Load().Source; got != engine.HashOf([]byte(showOnly)) {
		t.Fatalf("the second agreeing read loads it: bundle %s", got)
	}
	if n := testutil.ToFloat64(rig.m.PolicyReloads.WithLabelValues("applied")); n != 1 {
		t.Fatalf("port49_policy_reloads_total{outcome=applied} = %v", n)
	}
	if want := "port49d: policy reloaded (file changed): " + engine.HashOf([]byte(showOnly)) + " replaces " + before +
		" (bundle " + rig.b.Policy.Load().Bundle + ")"; !strings.Contains(rig.out.String(), want) {
		t.Fatalf("stderr %q, want %q", rig.out.String(), want)
	}
}

// A typo never takes the fleet down: a file that does not load is refused, the
// policy in force keeps serving, the refusal is said once with the reason and
// the bundle still serving, and port49_policy_file_refused holds at 1 until
// the file is put back.
func TestAPolicyThatDoesNotLoadIsRefusedAndTheOldOneServes(t *testing.T) {
	rig := newReloadRig(t, minimalPolicy)
	before := rig.b.Policy.Load().Source
	rig.write(t, strings.Replace(minimalPolicy, "privilege: admin", "privilege: root", 1))
	for i := 0; i < 5; i++ {
		rig.with(func() { rig.r.poll(context.Background()) })
	}
	if rig.b.Policy.Load().Source != before {
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
	if rig.b.Policy.Load().Source != engine.HashOf([]byte(showOnly)) {
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
	// A login in flight across the swap may still write the superseded
	// answer, so the reload is pending until the settle pass completes.
	if testutil.ToFloat64(rig.m.PolicyRefreshPending) != 1 {
		t.Fatal("port49_policy_refresh_pending must hold at 1 until the settle pass completes")
	}
	rig.now = rig.now.Add(settleAfterReload)
	rig.with(func() { rig.r.refresh(context.Background()) })
	if testutil.ToFloat64(rig.m.PolicyRefreshPending) != 0 || !rig.r.due.IsZero() {
		t.Fatalf("the settle pass clears the gauge, and nothing is due: due %v", rig.r.due)
	}
}

// A grant's expiry is settled as a reload is: a redemption in flight across
// the expiry pass may write the expired grant after the pass visited its
// context, so the pass runs again settleAfterReload later, and the expiry is
// pending until it completes.
func TestAnExpiryPassIsSettled(t *testing.T) {
	lapse := time.Now().Add(time.Hour).Truncate(time.Second)
	rig := newReloadRig(t, strings.Replace(minimalPolicy, "roles: [r]}", "roles: [r], expires: "+
		lapse.UTC().Format(time.RFC3339)+"}", 1))
	rig.now = lapse
	rig.with(func() { rig.r.refresh(context.Background()) })
	if !rig.r.due.Equal(lapse.Add(settleAfterReload)) || testutil.ToFloat64(rig.m.PolicyRefreshPending) != 1 {
		t.Fatalf("the expiry pass is settled 30s later and pending until then: due %v", rig.r.due)
	}
	rig.now = lapse.Add(settleAfterReload)
	rig.with(func() { rig.r.refresh(context.Background()) })
	if !rig.r.due.IsZero() || testutil.ToFloat64(rig.m.PolicyRefreshPending) != 0 {
		t.Fatalf("the settle pass clears it: due %v", rig.r.due)
	}
}

// gaugeStore reads port49_policy_refresh_pending as the pass reaches the
// contexts.
type gaugeStore struct {
	store.Store
	m    *metrics.Metrics
	seen *float64
}

func (g gaugeStore) ActivePrincipals(ctx context.Context) ([]string, error) {
	*g.seen = testutil.ToFloat64(g.m.PolicyRefreshPending)
	return g.Store.ActivePrincipals(ctx)
}

// From a grant's expiry a live context may still hold the expired grant, so
// port49_policy_refresh_pending is 1 from that instant, while the expiry pass
// runs, not only once it has finished (final review m4).
func TestAnExpiryIsPendingWhileItsPassRuns(t *testing.T) {
	lapse := time.Now().Add(time.Hour).Truncate(time.Second)
	rig := newReloadRig(t, strings.Replace(minimalPolicy, "roles: [r]}", "roles: [r], expires: "+
		lapse.UTC().Format(time.RFC3339)+"}", 1))
	seen := -1.0
	rig.b.Store = gaugeStore{Store: rig.st, m: rig.m, seen: &seen}
	rig.now = lapse
	rig.with(func() { rig.r.refresh(context.Background()) })
	if seen != 1 {
		t.Fatalf("port49_policy_refresh_pending during the expiry pass = %v", seen)
	}
}

// The next expiry is scheduled from the instant the pass judged at
// (RefreshReport.At), not from port49d's clock after it: an expiry between the
// two is one no context was judged after, so it is due at once.
func TestAnExpiryAfterThePassJudgedIsDueAtOnce(t *testing.T) {
	lapse := time.Now().Add(time.Hour).Truncate(time.Second)
	rig := newReloadRig(t, strings.Replace(minimalPolicy, "roles: [r]}", "roles: [r], expires: "+
		lapse.UTC().Format(time.RFC3339)+"}", 1))
	judged := lapse.Add(-time.Minute)
	rig.b.Now = func() time.Time { return judged }
	rig.now = lapse.Add(time.Minute)
	rig.with(func() { rig.r.refresh(context.Background()) })
	if !rig.r.due.Equal(lapse) {
		t.Fatalf("the expiry the pass judged before is due at once: due %v, want %v", rig.r.due, lapse)
	}
	if len(rig.r.priors) != 1 || !rig.r.priors[0].At.Equal(judged) {
		t.Fatalf("the next span starts where the pass judged: %+v", rig.r.priors)
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
	if rig.b.Policy.Load().Source != engine.HashOf([]byte(showOnly)) {
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
	if got := rig.b.Policy.Load().Source; got != engine.HashOf([]byte(showOnly)) {
		t.Fatalf("bundle %s: the agreed bytes are what is loaded", got)
	}
}

// Whoever can write the policy decides every operator's access, so a file
// someone else could have written is refused at a reload as at start: the
// policy in force keeps serving, the refusal is said once and counted, and
// putting the mode right is a change the watch sees (spec §5.1.3).
func TestAPolicyFileOthersCouldWriteIsRefusedAtAReload(t *testing.T) {
	rig := newReloadRig(t, minimalPolicy)
	before := rig.b.Policy.Load().Source
	rig.write(t, showOnly)
	if err := os.Chmod(rig.cfg.Broker.PolicyFile, 0o622); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		rig.with(func() { rig.r.poll(context.Background()) })
	}
	if rig.b.Policy.Load().Source != before || testutil.ToFloat64(rig.m.PolicyFileRefused) != 1 ||
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
	if rig.b.Policy.Load().Source != engine.HashOf([]byte(showOnly)) || testutil.ToFloat64(rig.m.PolicyFileRefused) != 0 {
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

// conflictingStore loses every compare-and-set a refresh makes, as a context
// a login writes to on every attempt would.
type conflictingStore struct{ store.Store }

func (conflictingStore) SetContextPolicy(context.Context, store.ContextKey, uint64, store.ContextPolicy) error {
	return store.ErrConflict
}

// A pass that visited every context but found one still changing did not
// stop, and the store is not down: the line says which, so it is not read at
// 3am as an outage.
func TestABusyContextIsSaidAsBusyNotAsAStop(t *testing.T) {
	rig := newReloadRig(t, minimalPolicy)
	rig.aliceLoggedIn(t)
	rig.b.Store = conflictingStore{rig.st}
	rig.write(t, showOnly)
	rig.with(func() { rig.r.reload(context.Background(), "SIGHUP") })
	out := rig.out.String()
	if strings.Contains(out, "stopped") || !strings.Contains(out, "1 context(s) still changing after every attempt") ||
		!strings.Contains(out, "trying them again in 30s") || !rig.r.due.Equal(rig.now.Add(refreshRetry)) ||
		testutil.ToFloat64(rig.m.PolicyRefreshPending) != 1 {
		t.Fatalf("due %v, stderr %q", rig.r.due, out)
	}
}

// A pass cut short because port49d is shutting down says nothing: "trying
// again in 30s" from a process that is exiting is a line to chase for nothing.
func TestAPassCancelledAtShutdownSaysNothing(t *testing.T) {
	rig := newReloadRig(t, minimalPolicy)
	rig.b.Store = failingStore{rig.st}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rig.with(func() { rig.r.refresh(ctx) })
	if rig.out.String() != "" {
		t.Fatalf("stderr: %q", rig.out.String())
	}
}

// A file that changes at every read — two tools fighting over it, or a
// templater stamping the time — never has two reads agree, so it never
// loads. That is said, once, and held in port49_policy_file_refused, rather
// than left for an operator to believe the edit is live.
func TestAFileThatNeverStopsChangingIsSaid(t *testing.T) {
	rig := newReloadRig(t, minimalPolicy)
	for i := 0; i < 2*stillChangingAfter; i++ {
		rig.write(t, fmt.Sprintf("# written %d\n%s", i, showOnly))
		rig.with(func() { rig.r.poll(context.Background()) })
	}
	if n := strings.Count(rig.out.String(), "has changed at each of the last"); n != 1 ||
		testutil.ToFloat64(rig.m.PolicyFileRefused) != 1 {
		t.Fatalf("said %d times: %q", n, rig.out.String())
	}
	for i := 0; i < 2; i++ {
		rig.with(func() { rig.r.poll(context.Background()) })
	}
	if rig.b.Policy.Load().Source == engine.HashOf([]byte(minimalPolicy)) || testutil.ToFloat64(rig.m.PolicyFileRefused) != 0 {
		t.Fatalf("a file that settles loads and clears the alarm: %q", rig.out.String())
	}
}

// A read that differs once and then finds the policy in force again — a
// file missing for a moment during a ConfigMap swap — is a blip, not a file
// that never settles: blips days apart must not add up to a false alarm.
func TestBlipsBetweenReadsOfThePolicyInForceRaiseNoAlarm(t *testing.T) {
	rig := newReloadRig(t, minimalPolicy)
	for i := 0; i < stillChangingAfter+1; i++ {
		rig.write(t, fmt.Sprintf("# blip %d\n%s", i, minimalPolicy))
		rig.with(func() { rig.r.poll(context.Background()) })
		rig.write(t, minimalPolicy)
		rig.with(func() { rig.r.poll(context.Background()) })
	}
	if strings.Contains(rig.out.String(), "has changed at each of the last") ||
		testutil.ToFloat64(rig.m.PolicyFileRefused) != 0 {
		t.Fatalf("blips raised the alarm: %q", rig.out.String())
	}
}

// A policy file deleted — or missing for a moment under a careless symlink
// swap — is refused like one that does not load: the policy in force keeps
// serving, and the refusal is said once.
func TestADeletedPolicyFileIsRefusedAndTheOldOneServes(t *testing.T) {
	rig := newReloadRig(t, minimalPolicy)
	before := rig.b.Policy.Load().Source
	if err := os.Remove(rig.cfg.Broker.PolicyFile); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		rig.with(func() { rig.r.poll(context.Background()) })
	}
	if rig.b.Policy.Load().Source != before || testutil.ToFloat64(rig.m.PolicyFileRefused) != 1 ||
		strings.Count(rig.out.String(), "refused") != 1 || !strings.Contains(rig.out.String(), "no such file") {
		t.Fatalf("stderr: %q", rig.out.String())
	}
	rig.with(func() { rig.r.reload(context.Background(), "SIGHUP") })
	if rig.b.Policy.Load().Source != before || testutil.ToFloat64(rig.m.PolicyReloads.WithLabelValues("refused")) != 2 {
		t.Fatalf("a SIGHUP with the file gone is refused too: %q", rig.out.String())
	}
}

// A file made unsafe with its content unchanged is refused all the same: it
// is the mode that says who could write the next edit.
func TestAPolicyFileMadeUnsafeInPlaceIsRefused(t *testing.T) {
	rig := newReloadRig(t, minimalPolicy)
	if err := os.Chmod(rig.cfg.Broker.PolicyFile, 0o622); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		rig.with(func() { rig.r.poll(context.Background()) })
	}
	if testutil.ToFloat64(rig.m.PolicyFileRefused) != 1 || strings.Count(rig.out.String(), "writable by others") != 1 {
		t.Fatalf("stderr: %q", rig.out.String())
	}
	if err := os.Chmod(rig.cfg.Broker.PolicyFile, 0o600); err != nil {
		t.Fatal(err)
	}
	rig.with(func() { rig.r.poll(context.Background()) })
	if testutil.ToFloat64(rig.m.PolicyFileRefused) != 0 || !strings.Contains(rig.out.String(), "is the policy in force again") {
		t.Fatalf("stderr: %q", rig.out.String())
	}
}

// With no broker: block SIGHUP still does not end port49d — its default
// action would take device AAA down — and says it has nothing to reload.
func TestRunWithNoBrokerSaysSIGHUPDoesNothing(t *testing.T) {
	var out syncBuffer
	defer func(w io.Writer) { stderr = w }(stderr)
	stderr = &out
	cfgPath := writeRunConfig(t, brokerConfig(t, minimalPolicy).Broker)
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, raw[:strings.Index(string(raw), "\nbroker:")+1], 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfgPath) }()
	defer func() {
		cancel()
		<-done
	}()
	waitFor(t, &out, "port49d: listening on ")
	// The metrics address said is the one bound, as for the other listeners:
	// `:0` says nothing about which port to scrape.
	m := regexp.MustCompile(`metrics on (127\.0\.0\.1:\d+)`).FindStringSubmatch(out.String())
	if m == nil || strings.HasSuffix(m[1], ":0") {
		t.Fatalf("stderr: %q", out.String())
	}
	resp, err := http.Get("http://" + m[1] + "/healthz")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("the metrics address said is not the one serving: %v %v", resp, err)
	}
	resp.Body.Close()
	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	waitFor(t, &out, "port49d: SIGHUP: no `broker:` block in the config, so there is no policy to reload")
}

// An operator withdrawing a compromised grant reads the summary line and
// stops. On a platform that never asks about a command (Junos, spec §13
// decision 21) the live shell keeps its access until logout, so the line says
// how many contexts that is; with none, it says nothing extra.
func TestTheSummarySaysWhatASessionOnlyPlatformKeeps(t *testing.T) {
	got := summary(broker.RefreshReport{Revoked: 3, Unreached: 1})
	if !strings.Contains(got, "3 revoked") ||
		!strings.Contains(got, "1 of them on platforms that do not authorize commands keep their live session "+
			"until logout (spec §13 decision 21)") {
		t.Fatalf("summary: %q", got)
	}
	if got := summary(broker.RefreshReport{Revoked: 3}); strings.Contains(got, "until logout") {
		t.Fatalf("summary: %q", got)
	}
}

// Task 12 m3, end to end: with a named pipe swapped in at port49d.yaml's path
// after start, SIGHUP still reloads the policy, and shutdown still returns,
// so the spool drains rather than waiting on the reloader for good.
func TestRunDrainsAfterSIGHUPWithANamedPipeAsItsConfig(t *testing.T) {
	var out syncBuffer
	defer func(w io.Writer) { stderr = w }(stderr)
	stderr = &out
	cfgPath := writeRunConfig(t, brokerConfig(t, minimalPolicy).Broker)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfgPath) }()
	stopped := false
	defer func() {
		if !stopped {
			cancel()
			<-done
		}
	}()
	waitFor(t, &out, "port49d: listening on ")
	if err := os.Remove(cfgPath); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(cfgPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	waitFor(t, &out, "inventory.max_removed_percent not re-read from "+cfgPath)
	waitFor(t, &out, "port49d: policy reload (SIGHUP)")
	cancel() // what SIGTERM does to run's context
	select {
	case <-done:
		stopped = true
	case <-time.After(10 * time.Second):
		t.Fatalf("shutdown did not return: %s", out.String())
	}
}

// Task 10: a device admission refuses is the operator's 3am signal in three
// places, all said at start: its own stderr line with why, the listening
// line's admitted count, which leaves it out, and the gauge.
func TestRunSaysARefusedDeviceAtStart(t *testing.T) {
	var out syncBuffer
	defer func(w io.Writer) { stderr = w }(stderr)
	stderr = &out
	cfgPath := writeRunConfig(t, brokerConfig(t, minimalPolicy).Broker)
	if err := os.WriteFile(filepath.Join(filepath.Dir(cfgPath), "inventory.yaml"), []byte(`
devices:
  - {name: leaf1, platform: arista_eos, addresses: [127.0.0.1]}
  - {name: leaf2, platform: arista_eos, addresses: [10.9.9.9]}
key_groups:
  - {match: {cidr: 127.0.0.0/8}, key_ref: k}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfgPath) }()
	defer func() {
		cancel()
		<-done
	}()
	waitFor(t, &out, "port49d: listening on ")
	if !strings.Contains(out.String(), "port49d: admission: device leaf2 (arista_eos) is refused: ") {
		t.Fatalf("the refused device was not named at start: %s", out.String())
	}
	if !regexp.MustCompile(`port49d: listening on \S+, metrics on \S+, 1 devices admitted\n`).MatchString(out.String()) {
		t.Fatalf("the listening line does not count one admitted device: %s", out.String())
	}
	m := regexp.MustCompile(`metrics on (127\.0\.0\.1:\d+)`).FindStringSubmatch(out.String())
	if m == nil {
		t.Fatalf("stderr: %q", out.String())
	}
	resp, err := http.Get("http://" + m[1] + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`(?m)^port49_devices_admission_refused 1$`).Match(body) {
		t.Fatalf("port49_devices_admission_refused is not 1:\n%s", body)
	}
}

// A policy edit that would quarantine more than inventory.max_removed_percent
// of the devices in service is refused: the policy in force keeps serving,
// the alarm is up, and the line names the cause and the remedy, and says
// the refused file is still on disk and a restart would load it unguarded
// (decision 34; pre-flight I4). With the bound off it applies, and the
// device is quarantined live.
func TestAReloadThatQuarantinesTheFleetIsRefused(t *testing.T) {
	rig := newReloadRig(t, minimalPolicy)
	before := rig.b.Policy.Load().Source
	rig.write(t, unmappedLevel+strings.Replace(minimalPolicy, "privilege: admin", "privilege: unmapped", 1))
	rig.with(func() { rig.r.reload(context.Background(), "SIGHUP") })
	if rig.b.Policy.Load().Source != before {
		t.Fatal("a reload quarantining the whole fleet was applied")
	}
	if testutil.ToFloat64(rig.m.PolicyFileRefused) != 1 {
		t.Fatal("port49_policy_file_refused")
	}
	if out := rig.out.String(); !strings.Contains(out, "it quarantines 1: leaf1") ||
		!strings.Contains(out, "raise inventory.max_removed_percent") ||
		!strings.Contains(out, "is NOT what is serving: a restart of port49d would load it with no such bound") {
		t.Fatalf("stderr: %s", out)
	}
	rig.r.cfg.MaxRemovedPercent = 100
	rig.with(func() { rig.r.reload(context.Background(), "SIGHUP") })
	if _, q := rig.b.Policy.Load().Quarantined("leaf1", rig.now); !q {
		t.Fatal("with the bound off the reload applies and quarantines leaf1")
	}
}

// A refused reload's line is redacted with the redactions of both the
// policy in force and the refused one before it reaches stderr, a log, and
// only then are its quoted values cut, so a cut never leaves a secret's
// head (spec §5.8; pre-flight I3): a quarantine's cause quotes policy text.
// The value is a Junos community, `community <c> {`: the pattern needs the
// brace past the cut, so a value cut first no longer matches and its
// secret's head would print (task 10 review M3).
func TestARefusedReloadsLineIsRedacted(t *testing.T) {
	pol := newReloadRig(t, minimalPolicy).b.Policy.Load()
	err := errors.New(`it quarantines 1: leaf1 (role r: "community ` + strings.Repeat("Hunter2", 9) + ` {")`)
	if cutFirst := platform.RedactQuoted(pol.Redactions(), oneLine(quotesCut{err})); !strings.Contains(cutFirst, "Hunter2") {
		t.Fatalf("the fixture does not tell the order apart: %s", cutFirst)
	}
	if line := refusalLine(err, false, pol, nil); strings.Contains(line, "Hunter2") || !strings.Contains(line, "leaf1") {
		t.Fatalf("%s", line)
	}
}

// What a start on a persistent store left unjudged is owed a pass: at
// once for a context still changing, at the next retry for one under an
// unheld key, with port49_policy_refresh_pending 1 until a pass completes
// (plan 7d; Rulings T12-a, T12-d).
func TestAStartThatLeftAContextOwesAPass(t *testing.T) {
	for _, c := range []struct {
		name string
		now  bool
		in   time.Duration
	}{{"still changing", true, 0}, {"under an unheld key", false, refreshRetry}} {
		t.Run(c.name, func(t *testing.T) {
			rig := newReloadRig(t, showOnly)
			rig.r.startLeft(c.now)
			if !rig.r.due.Equal(rig.now.Add(c.in)) || testutil.ToFloat64(rig.m.PolicyRefreshPending) != 1 {
				t.Fatalf("due %v (want %v from now), pending %v", rig.r.due.Sub(rig.now), c.in,
					testutil.ToFloat64(rig.m.PolicyRefreshPending))
			}
			rig.with(func() { rig.r.refresh(context.Background()) })
			if testutil.ToFloat64(rig.m.PolicyRefreshPending) != 0 || !strings.Contains(rig.out.String(),
				"policy refresh finished") {
				t.Fatalf("the owed pass: pending %v, said %q", testutil.ToFloat64(rig.m.PolicyRefreshPending),
					rig.out.String())
			}
		})
	}
}
