package port49d

import (
	"context"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/blanketfish/port49/internal/admission"
	"github.com/blanketfish/port49/internal/broker"
	"github.com/blanketfish/port49/internal/decision"
	"github.com/blanketfish/port49/internal/policy"
	"github.com/blanketfish/port49/internal/store/memory"
)

// failClosedPolicy is a policy on platform set 1.1.0 where subject s is
// admin and subject t holds role long, whose body is role; expiry, when set,
// ends t's grant ("" or ", expires: <time>").
func failClosedPolicy(role, expiry string) string {
	return `
platform_set: 1.1.0
scopes: [{name: all_devices, match: {}}]
roles:
  - {name: r, privilege: admin, permit: ["**"]}
  - {name: long, ` + role + `}
subjects:
  - {name: s, identity: ["user:alice@example.com"], username: alice, token_ttl: 60s}
  - {name: t, identity: ["user:carol@example.com"], username: carol, token_ttl: 60s}
grants:
  - {subject: s, scope: all_devices, roles: [r]}
  - {subject: t, scope: all_devices, roles: [long]` + expiry + `}
key_groups: [{match: {cidr: 10.0.0.0/8}, key_ref: lab_key}]
` + runKeys
}

// junosFleet is n juniper_junos devices.
func junosFleet(n int) string {
	var b strings.Builder
	b.WriteString("devices:\n")
	for i := 1; i <= n; i++ {
		fmt.Fprintf(&b, "  - {name: srx%02d, platform: juniper_junos, addresses: [10.0.%d.%d]}\n", i, i/250, i%250+1)
	}
	return b.String()
}

// A refused argument deny and an overflowing allow: each is a composition
// the fail-closed reply answers (spec §12).
const (
	cleanRole       = `privilege: readonly, permit: ["show **"]`
	overflowingRole = `privilege: readonly, permit: ["show interfaces **", "show route **", "show chassis **", ` +
		`"show bgp **", "show ospf **", "show isis **", "show lldp **", "show arp **", "show version **", ` +
		`"show mpls **", "show ldp **", "show rsvp **", "show system **", "show security **", "show log **", ` +
		`"show ethernet-switching **", "show evpn **", "show bfd **", "show vrrp **", "show pfe **", ` +
		`"show services **", "show firewall **", "show policy-options **", "show class-of-service **", ` +
		`"show multicast **", "show pim **", "show igmp **", "show vlans **", "show ntp **", "show snmp **"]`
	refusedRole = `privilege: readonly, permit: ["show **"], deny: ["show configuration system"]`
)

const countLine = "composition(s) answered fail-closed now (port49 policy test names them)"

// failClosedRig is a broker on clean policy with n Junos devices.
func failClosedRig(t *testing.T, n int) *reloadRig {
	t.Helper()
	rig := newReloadRig(t, failClosedPolicy(cleanRole, ""))
	rig.r.cfg.MaxRemovedPercent = 100 // the fleet replaces the one device the rig starts with
	rig.writeInventory(t, junosFleet(n))
	rig.pollTwice()
	return rig
}

func failClosedGauge(rig *reloadRig) float64 { return testutil.ToFloat64(rig.m.PolicyFailClosed) }

// A reload to a composition the fail-closed reply answers says so right
// after the reload line, names the finding as policy test does, and sets the
// gauge; reloading back says 0 once and clears it (spec §12).
func TestAReloadToAFailClosedCompositionIsSaidAndGauged(t *testing.T) {
	rig := failClosedRig(t, 2)
	if strings.Contains(rig.out.String(), countLine) || failClosedGauge(rig) != 0 {
		t.Fatalf("said with nothing fail-closed:\n%s", rig.out.String())
	}
	swapTo(t, rig, failClosedPolicy(overflowingRole, ""))
	out := rig.out.String()
	reloaded, said := strings.Index(out, "policy reloaded"), strings.Index(out, "port49d: policy: 1 "+countLine)
	if reloaded < 0 || said < reloaded || !strings.Contains(out, `policy: projection_overflow: subject "t" on juniper_junos `) ||
		!strings.Contains(out, "on 2 devices: srx01, srx02") || failClosedGauge(rig) != 1 {
		t.Fatalf("gauge %v:\n%s", failClosedGauge(rig), out)
	}
	swapTo(t, rig, failClosedPolicy(cleanRole, ""))
	if n := strings.Count(rig.out.String(), "policy: 0 "+countLine); n != 1 || failClosedGauge(rig) != 0 {
		t.Fatalf("the fix was said %d times, gauge %v:\n%s", n, failClosedGauge(rig), rig.out.String())
	}
	before := rig.out.String()
	swapTo(t, rig, failClosedPolicy(cleanRole, "")+"# comment\n")
	if strings.Count(rig.out.String(), countLine) != strings.Count(before, countLine) {
		t.Fatalf("a clean policy said it again:\n%s", rig.out.String())
	}
}

// The report of a generation is worked out after that generation's refresh
// pass, as the unverifiable-requirement line is: the pass carries the swap
// into live sessions, and the walk over every subject and device must not
// delay it. The pass here waits a while for a report begun too early.
func TestTheFailClosedLineIsSaidAfterTheRefreshPass(t *testing.T) {
	rig := failClosedRig(t, 2)
	var passing, early atomic.Bool
	began := make(chan struct{}, 16)
	compute := rig.r.failClosed.compute
	rig.r.failClosed.compute = func(pol *policy.Policy, now time.Time) []policy.FailClosed {
		early.Store(early.Load() || passing.Load())
		began <- struct{}{}
		return compute(pol, now)
	}
	pass := rig.r.pass
	rig.r.pass = func(ctx context.Context, priors []broker.Prior) (broker.RefreshReport, error) {
		passing.Store(true)
		defer passing.Store(false)
		fmt.Fprintln(stderr, "MARK pass")
		rep, err := pass(ctx, priors)
		select {
		case <-began:
		case <-time.After(200 * time.Millisecond):
		}
		return rep, err
	}
	swapTo(t, rig, failClosedPolicy(refusedRole, ""))
	out := rig.out.String()
	if pi, li := strings.Index(out, "MARK pass"), strings.Index(out, countLine); early.Load() || pi < 0 || li < pi {
		t.Fatalf("the report was worked out before its generation's pass finished (%v):\n%s", early.Load(), out)
	}
}

// A grant's expiry that ends a fail-closed composition moves the gauge to 0
// at the expiry pass, and says so; the finding before it carries its moment.
func TestAnExpiryPassClearsTheFailClosedGauge(t *testing.T) {
	for _, brokerInProcess := range []bool{true, false} {
		t.Run(fmt.Sprintf("broker=%v", brokerInProcess), func(t *testing.T) {
			rig := failClosedRig(t, 2)
			lapse := rig.now.Add(time.Hour)
			swapTo(t, rig, failClosedPolicy(overflowingRole, ", expires: "+lapse.UTC().Format(time.RFC3339)))
			if failClosedGauge(rig) != 1 || !strings.Contains(rig.out.String(), "until ") {
				t.Fatalf("gauge %v:\n%s", failClosedGauge(rig), rig.out.String())
			}
			if !brokerInProcess {
				rig.r.pass = nil
				rig.with(func() { rig.r.refresh(context.Background()) })
			}
			rig.now = lapse
			seen := len(rig.out.String())
			rig.with(func() { rig.r.refresh(context.Background()) })
			if n := strings.Count(rig.out.String()[seen:], "policy: 0 "+countLine); n != 1 || failClosedGauge(rig) != 0 {
				t.Fatalf("the expiry pass: gauge %v, said %d times:\n%s", failClosedGauge(rig), n, rig.out.String()[seen:])
			}
		})
	}
}

// A refusal as secret_rule prints no value a rule hides.
func TestAFailClosedLinePrintsNoHiddenLiteral(t *testing.T) {
	rig := failClosedRig(t, 2)
	swapTo(t, rig, failClosedPolicy(`privilege: readonly, permit: ["show **"], `+
		`deny: ["show system radius-server 10.0.0.1 secret HUNTER2"]`, ""))
	out := rig.out.String()
	if !strings.Contains(out, "projection_refused") || !strings.Contains(out, "secret_rule") ||
		strings.Contains(out, "HUNTER2") || failClosedGauge(rig) != 1 {
		t.Fatalf("gauge %v:\n%s", failClosedGauge(rig), out)
	}
}

// A finding on fifty devices says the count and three names.
func TestAFailClosedFindingNamesThreeDevices(t *testing.T) {
	rig := failClosedRig(t, 50)
	swapTo(t, rig, failClosedPolicy(refusedRole, ""))
	out := rig.out.String()
	if !strings.Contains(out, "on 50 devices: srx01, srx02, srx03 and 47 more") || strings.Contains(out, "srx04") {
		t.Fatalf("%s", out)
	}
}

// A start says it as a reload does, from the policy and inventory it loaded.
func TestAStartSaysWhichCompositionsAreFailClosed(t *testing.T) {
	rig := failClosedRig(t, 2)
	// A start reads the inventory config.Load read.
	inv, err := admission.LoadFile(rig.cfg.InventoryFile)
	if err != nil {
		t.Fatal(err)
	}
	rig.cfg.Inventory = inv
	for _, c := range []struct {
		role string
		want float64
	}{{cleanRole, 0}, {refusedRole, 1}} {
		rig.write(t, failClosedPolicy(c.role, ""))
		var start syncBuffer
		func() {
			defer func(w io.Writer) { stderr = w }(stderr)
			stderr = &start
			if _, _, err := buildBroker(rig.cfg, "inventory_file "+rig.cfg.InventoryFile, memory.New(time.Now), seedMinter(),
				decision.NewJSONLines(io.Discard), rig.m); err != nil {
				t.Fatalf("the start refused: %v", err)
			}
		}()
		if got := strings.Count(start.String(), "policy: 1 "+countLine); (got == 1) != (c.want == 1) || failClosedGauge(rig) != c.want {
			t.Fatalf("%q: gauge %v, said %d times:\n%s", c.role, failClosedGauge(rig), got, start.String())
		}
	}
}

// holdCompute makes rig's fail-closed report wait at entered until release is
// closed, each call telling entered first.
func holdCompute(rig *reloadRig) (entered chan struct{}, release chan struct{}) {
	entered, release = make(chan struct{}, 16), make(chan struct{})
	compute := rig.r.failClosed.compute
	rig.r.failClosed.compute = func(pol *policy.Policy, now time.Time) []policy.FailClosed {
		entered <- struct{}{}
		<-release
		return compute(pol, now)
	}
	return entered, release
}

// The report is worked out off the reload goroutine: a reload returns while
// it is still being worked out, and the line and gauge follow when it is.
func TestTheFailClosedReportRunsOffTheReloadGoroutine(t *testing.T) {
	rig := failClosedRig(t, 2)
	entered, release := holdCompute(rig)
	rig.write(t, failClosedPolicy(refusedRole, ""))
	reloaded := make(chan struct{})
	func() {
		defer func(w io.Writer) { stderr = w }(stderr)
		stderr = rig.out
		go func() {
			defer close(reloaded)
			rig.r.poll(context.Background())
			rig.r.poll(context.Background())
		}()
		select {
		case <-reloaded:
		case <-time.After(10 * time.Second):
			close(release)
			t.Fatal("the reload waited on the fail-closed report")
		}
	}()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the report was never worked out")
	}
	if strings.Contains(rig.out.String(), countLine) || failClosedGauge(rig) != 0 {
		t.Fatalf("said before it was worked out:\n%s", rig.out.String())
	}
	close(release)
	rig.r.failClosed.wait()
	if !strings.Contains(rig.out.String(), "policy: 1 "+countLine) || failClosedGauge(rig) != 1 {
		t.Fatalf("gauge %v:\n%s", failClosedGauge(rig), rig.out.String())
	}
}

// Asked again while a report is worked out, the reporter works out only the
// latest generation: one still pending is dropped, and one finished after a
// newer was asked for is never said, so an older result never overwrites a
// newer one.
func TestTheLatestFailClosedReportWins(t *testing.T) {
	rig := failClosedRig(t, 2)
	pol := rig.r.live.Load()
	at := func(n int) time.Time { return time.Unix(int64(n), 0) }
	finding := func(n int) []policy.FailClosed {
		return []policy.FailClosed{{Kind: policy.FindingProjectionRefused, Message: fmt.Sprintf("generation %d", n),
			Devices: []string{"srx01"}}}
	}
	entered, release := make(chan int, 8), make(chan struct{})
	var asked []int
	var mu sync.Mutex
	rig.r.failClosed.compute = func(_ *policy.Policy, now time.Time) []policy.FailClosed {
		n := int(now.Unix())
		mu.Lock()
		asked = append(asked, n)
		mu.Unlock()
		entered <- n
		if n == 1 {
			<-release
		}
		return finding(n)
	}
	var out syncBuffer
	rig.r.failClosed.ask(&out, "port49d", pol, at(1))
	<-entered
	rig.r.failClosed.ask(&out, "port49d", pol, at(2))
	rig.r.failClosed.ask(&out, "port49d", pol, at(3))
	close(release)
	rig.r.failClosed.wait()
	mu.Lock()
	defer mu.Unlock()
	if !slices.Equal(asked, []int{1, 3}) || strings.Contains(out.String(), "generation 1") ||
		strings.Contains(out.String(), "generation 2") || !strings.Contains(out.String(), "generation 3") ||
		failClosedGauge(rig) != 1 {
		t.Fatalf("worked out %v, gauge %v:\n%s", asked, failClosedGauge(rig), out.String())
	}
}

// A reloader that stops stops its reporter: what is in flight finishes, and
// nothing is worked out after, so shutdown leaves no worker behind.
func TestAStoppedReloaderLeavesNoFailClosedWorker(t *testing.T) {
	rig := failClosedRig(t, 2)
	entered, release := holdCompute(rig)
	var out syncBuffer
	rig.r.failClosed.ask(&out, "port49d", rig.r.live.Load(), rig.now)
	<-entered
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	stopped := make(chan struct{})
	go func() { defer close(stopped); rig.r.run(ctx, nil) }()
	select {
	case <-stopped:
		t.Fatal("run returned with the report still being worked out")
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	<-stopped
	rig.r.failClosed.ask(&out, "port49d", rig.r.live.Load(), rig.now)
	select {
	case <-entered:
		t.Fatal("a stopped reporter worked a report out")
	case <-time.After(100 * time.Millisecond):
	}
	if rig.r.failClosed.busy() {
		t.Fatal("a worker is still running")
	}
}

// A finding an expiry brings on is said with the moment it holds from, and
// is not counted now: here t's grant at admin lapses, and the level left,
// which no bit maps, has the fail-closed reply from then on.
func TestAFailClosedFindingFromALaterMomentIsSaidAndNotCounted(t *testing.T) {
	rig := failClosedRig(t, 2)
	lapse := rig.now.Add(time.Hour).UTC()
	swapTo(t, rig, `
platform_set: 1.1.0
privilege_levels: [{name: readonly}, {name: operator}, {name: unmapped}, {name: admin}]
scopes: [{name: all_devices, match: {}}]
roles:
  - {name: r, privilege: admin, permit: ["**"]}
  - {name: low, privilege: unmapped, permit: ["show version"]}
subjects:
  - {name: s, identity: ["user:alice@example.com"], username: alice, token_ttl: 60s}
  - {name: t, identity: ["user:carol@example.com"], username: carol, token_ttl: 60s}
grants:
  - {subject: s, scope: all_devices, roles: [r]}
  - {subject: t, scope: all_devices, roles: [low]}
  - {subject: t, scope: all_devices, roles: [r], expires: `+lapse.Format(time.RFC3339)+`}
key_groups: [{match: {cidr: 10.0.0.0/8}, key_ref: lab_key}]
`+runKeys)
	out := rig.out.String()
	from := `policy: projection_refused: subject "t" on juniper_junos, from ` + decision.FormatTime(lapse) +
		`, when grant all_devices [r] expires`
	if !strings.Contains(out, from) || strings.Contains(out, countLine) || failClosedGauge(rig) != 0 {
		t.Fatalf("gauge %v:\n%s", failClosedGauge(rig), out)
	}
}

// lapsePolicy is a policy where t holds low, at a level no bit maps, and r at
// admin until e1: from e1 t's composition is fail-closed. u holds r until e2.
func lapsePolicy(e1, e2 time.Time) string {
	return `
platform_set: 1.1.0
privilege_levels: [{name: readonly}, {name: operator}, {name: unmapped}, {name: admin}]
scopes: [{name: all_devices, match: {}}]
roles:
  - {name: r, privilege: admin, permit: ["**"]}
  - {name: low, privilege: unmapped, permit: ["show version"]}
subjects:
  - {name: s, identity: ["user:alice@example.com"], username: alice, token_ttl: 60s}
  - {name: t, identity: ["user:carol@example.com"], username: carol, token_ttl: 60s}
  - {name: u, identity: ["user:dave@example.com"], username: dave, token_ttl: 60s}
grants:
  - {subject: s, scope: all_devices, roles: [r]}
  - {subject: t, scope: all_devices, roles: [low]}
  - {subject: t, scope: all_devices, roles: [r], expires: ` + e1.UTC().Format(time.RFC3339) + `}
  - {subject: u, scope: all_devices, roles: [r], expires: ` + e2.UTC().Format(time.RFC3339) + `}
key_groups: [{match: {cidr: 10.0.0.0/8}, key_ref: lab_key}]
` + runKeys
}

// The report reads only the policy, the inventory and the clock, so a grant
// expiry moves the gauge at its instant even when the store is down and the
// pass after it cannot complete: at 3am the store being down is when the
// alarm must be right. The next expiry is said at its instant too, before the
// pass's retry.
func TestAnExpiryWithTheStoreDownStillMovesTheGauge(t *testing.T) {
	rig := failClosedRig(t, 2)
	e1 := rig.now.Add(time.Hour)
	e2 := e1.Add(refreshRetry / 3)
	swapTo(t, rig, lapsePolicy(e1, e2))
	if failClosedGauge(rig) != 0 {
		t.Fatalf("gauge %v before the expiry:\n%s", failClosedGauge(rig), rig.out.String())
	}
	rig.b.Store = failingStore{rig.st}
	rig.now = e1
	seen := len(rig.out.String())
	rig.with(func() { rig.r.refresh(context.Background()) })
	out := rig.out.String()[seen:]
	if !strings.Contains(out, "policy refresh stopped") || !strings.Contains(out, "policy: 1 "+countLine) ||
		failClosedGauge(rig) != 1 {
		t.Fatalf("the expiry with the store down: gauge %v:\n%s", failClosedGauge(rig), out)
	}
	if !rig.r.due.Equal(e2) {
		t.Fatalf("due %v, not the next expiry %v", rig.r.due, e2)
	}
	// At e2 the timer says the report again and runs no pass: the stopped
	// pass's retry stays at e1 + refreshRetry.
	rig.now = e2
	seen = len(rig.out.String())
	rig.with(func() { rig.r.fired(context.Background()) })
	out = rig.out.String()[seen:]
	if strings.Contains(out, "policy refresh") || !strings.Contains(out, "policy: 1 "+countLine) ||
		!rig.r.due.Equal(e1.Add(refreshRetry)) {
		t.Fatalf("at the next expiry: due %v:\n%s", rig.r.due, out)
	}
}

// With no broker there is no pass, and the expiry timer is armed again for
// the next expiry, not left at the one just said, which would fire at once
// for ever on the reload goroutine. Said once, it is not said again.
func TestANoBrokerExpiryRearmsAtTheNextExpiry(t *testing.T) {
	rig := failClosedRig(t, 2)
	e1 := rig.now.Add(time.Hour)
	e2 := e1.Add(time.Hour)
	swapTo(t, rig, lapsePolicy(e1, e2))
	rig.r.pass = nil
	rig.now = e1
	rig.with(func() { rig.r.refresh(context.Background()) })
	if !rig.r.due.Equal(e2) || failClosedGauge(rig) != 1 {
		t.Fatalf("due %v (want %v), gauge %v", rig.r.due, e2, failClosedGauge(rig))
	}
	seen := len(rig.out.String())
	rig.with(func() { rig.r.refresh(context.Background()) })
	if out := rig.out.String()[seen:]; strings.Contains(out, countLine) {
		t.Fatalf("said again at the same instant:\n%s", out)
	}
}
