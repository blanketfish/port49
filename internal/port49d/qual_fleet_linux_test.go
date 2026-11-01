//go:build linux

package port49d

// TestQualFleet plays one profile as 500 concurrent mock devices from distinct
// loopback sources (127.0.1.N needs Linux, where all of 127/8 is local)
// against a real port49d (plan 11b, fleet mode). It asserts outcomes, no
// latency number: plan 12 sets the targets.

import (
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/devicemock"
)

const (
	qualReloaded  = "port49d: policy reloaded (file changed)"
	qualRefreshed = "port49d: policy refresh" // also "refresh stopped", which the test rules out
)

func TestQualFleet(t *testing.T) {
	if os.Getenv("PORT49_QUAL_FLEET") != "1" {
		t.Skip("make qual-fleet")
	}
	const n = 500
	// The fleet plays a vetted profile, so it exercises the broker, listener and
	// policy path a real device's mock does, store fault included.
	p, err := devicemock.Load("../../tests/qual/profiles/arista_eos/cEOS-lab-4.36.3M.yaml", qualRoot)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("profile %s %s", p.Platform, p.Firmware)
	run := qualDaemon(t, p, qualOpts{scale: 0.1, handshakeTimeout: time.Second, devices: n})

	// round mints every device's token on the test goroutine (mint's helpers call
	// t.Fatal, which is invalid from a worker; workers only index the slice) and
	// plays the fleet once. A mint during a store fault would wait on the gate, so
	// before, which sets a fault, runs once the tokens are minted. mid runs on its
	// own goroutine, calls no t helper, and is handed the count of plays started.
	// onStart runs synchronously as play i starts, on the play's goroutine.
	round := func(name string, concurrency int, pace time.Duration, before func() error, mid func(started *atomic.Int32) error, onStart func(i int)) devicemock.FleetResult {
		logins := make([]devicemock.Login, n)
		for i := range n {
			logins[i] = run.login(i)
		}
		if before != nil {
			if err := before(); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
		}
		var started atomic.Int32
		midErr := make(chan error, 1)
		if mid != nil {
			go func() { midErr <- mid(&started) }()
		}
		fleet := devicemock.Fleet{Profile: p, N: n, Concurrency: concurrency, Scenario: "token_login"}
		res := fleet.Run(t.Context(), func(i int) devicemock.Target {
			started.Add(1)
			if onStart != nil {
				onStart(i)
			}
			time.Sleep(pace)
			return run.target(p, i)
		},
			func(i int) devicemock.Login { return logins[i] })
		if mid != nil {
			if err := <-midErr; err != nil {
				t.Fatalf("%s: %v", name, err)
			}
		}
		t.Logf("%s: %d plays, outcomes %v, errors %d %v, p50 %s, p99 %s", name, res.Plays, res.Outcomes, res.Errors, res.ErrorKinds, res.P50, res.P99)
		if res.Errors != 0 {
			t.Fatalf("%s: a play ended in an error: %v", name, res.ErrorKinds)
		}
		if run.logged("projection_fail_closed") {
			t.Fatalf("%s: the policy failed closed", name)
		}
		return res
	}
	// waitStarted blocks until the fleet has started k plays.
	waitStarted := func(started *atomic.Int32, k int32) {
		for started.Load() < k {
			time.Sleep(time.Millisecond)
		}
	}

	if res := round("concurrent logins", 100, 0, nil, nil, nil); res.Outcomes["login_ok"] != n {
		t.Fatalf("every device logs in: %v", res.Outcomes)
	}

	// settle waits for the reload of a touched policy (its line is new since
	// reloadsBefore) and then for the settle pass (port49_policy_refresh_pending
	// reads 0), before the next round mints: a token minted while either runs can
	// be lost.
	settle := func(reloadsBefore int) {
		for end := time.Now().Add(10 * time.Second); strings.Count(run.stderr.String(), qualReloaded) <= reloadsBefore; time.Sleep(10 * time.Millisecond) {
			if time.Now().After(end) {
				t.Fatal("the touched policy was never reloaded")
			}
		}
		for end := time.Now().Add(120 * time.Second); ; time.Sleep(100 * time.Millisecond) {
			ok, err := run.refreshSettled()
			if err != nil {
				t.Fatal(err)
			}
			if ok {
				return
			}
			if time.Now().After(end) {
				t.Fatal("the settle pass never finished")
			}
		}
	}
	// reloadRounds touches the policy a play in, with plays paced so the broker's
	// 1 s watch fires while they run, and accepts a round only if the reload line
	// was absent when it began and present when it ended; a round the reload
	// missed is tried again. check judges each round's outcomes.
	reloadRounds := func(name string, touch func() error, check func(devicemock.FleetResult)) {
		for try := 1; try <= 5; try++ {
			before := strings.Count(run.stderr.String(), qualReloaded)
			res := round(name, 10, 40*time.Millisecond, nil, func(started *atomic.Int32) error {
				waitStarted(started, 1)
				return touch()
			}, nil)
			check(res)
			landed := strings.Count(run.stderr.String(), qualReloaded) > before
			settle(before)
			if landed {
				return
			}
		}
		t.Fatalf("%s: the policy reload never landed while plays ran", name)
	}

	// Reload under load, an edit to the fleet's own role list. The refresh deletes
	// the unspent tokens whose answer the edit changed (spec §5.1.3, "Policy
	// reload"); every device here is in that list, so a play whose token the reload
	// superseded is refused and its device mints again. No other play is lost.
	reloadRounds("reload under load", run.touchPolicy, func(res devicemock.FleetResult) {
		if res.Outcomes["login_ok"]+res.Outcomes["login_refused"] != n {
			t.Fatalf("a reload under load: each play logs in or is refused: %v", res.Outcomes)
		}
	})
	if deny, notFound := strings.Count(run.log.String(), `"event":"redeem","verdict":"deny"`), strings.Count(run.log.String(), `"reason":"token_not_found"`); deny != notFound {
		t.Fatalf("a refused play was refused for token_not_found only: %d denies, %d token_not_found", deny, notFound)
	}
	if res := round("after the reload", 100, 0, nil, nil, nil); res.Outcomes["login_ok"] != n {
		t.Fatalf("tokens minted after the reload all log in: %v", res.Outcomes)
	}
	// The converse, which is what the spec promises: an edit to a role list no
	// device of the run is in changes no answer, so a reload loses no login.
	notFound := strings.Count(run.log.String(), `"reason":"token_not_found"`)
	reloadRounds("reload outside the fleet", run.touchPolicyOutsideFleet, func(res devicemock.FleetResult) {
		if res.Outcomes["login_ok"] != n {
			t.Fatalf("an edit outside the fleet loses no login: %v", res.Outcomes)
		}
	})
	if got := strings.Count(run.log.String(), `"reason":"token_not_found"`); got != notFound {
		t.Fatalf("an edit outside the fleet superseded %d tokens", got-notFound)
	}
	if run.said("port49d: policy refresh stopped") {
		t.Fatal("the reload's refresh stopped part way")
	}

	// The store fails while plays are in flight: each play either logged in
	// before the fault or ends as the profile's reaction says; none hangs.
	faultErr := make(chan error, 1)
	res := round("store fails mid-run", 20, 10*time.Millisecond, nil, nil, func(i int) {
		if i == n/3 { // exact: the file is written before this play dials
			faultErr <- run.fault("store_unavailable")
		}
	})
	if err := <-faultErr; err != nil {
		t.Fatal(err)
	}
	late := res.Outcomes["falls_to_local"] + res.Outcomes["login_refused"]
	if res.Outcomes["login_ok"] == 0 || late == 0 || res.Outcomes["login_ok"]+late != n || res.P99 > 10*time.Second {
		t.Fatalf("a mid-run fault splits the plays into logged in and not, none hung: %+v", res)
	}
	if err := run.fault(""); err != nil {
		t.Fatal(err)
	}

	// The fault in force before the first play: every play falls to local.
	// (Tokens are minted after the fault is cleared, then it is set again.)
	res = round("store down under load", 100, 0, func() error { return run.fault("store_unavailable") }, nil, nil)
	if res.Outcomes["falls_to_local"] != n || res.P99 > 10*time.Second {
		t.Fatalf("with the store down every play falls to local, none hangs: %+v", res)
	}
	if err := run.fault(""); err != nil {
		t.Fatal(err)
	}
	if res := round("store back", 100, 0, nil, nil, nil); res.Outcomes["login_ok"] != n {
		t.Fatalf("clearing the fault returns every play to login_ok: %v", res.Outcomes)
	}
}
