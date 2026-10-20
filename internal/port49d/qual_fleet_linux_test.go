//go:build linux

package port49d

// TestQualFleet plays one profile as 500 concurrent mock devices from distinct
// loopback sources (127.0.1.N needs Linux, where all of 127/8 is local)
// against a real port49d (plan 11b, fleet mode). It asserts outcomes, no
// latency number: plan 12 sets the targets.

import (
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/devicemock"
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
	// Task 14 adds the first wave of profiles; until then a fleet-only fixture
	// stands in, which exercises the same broker, listener and policy path.
	var p *devicemock.Profile
	if paths, _ := filepath.Glob("../../tests/qual/profiles/arista_eos/*.yaml"); len(paths) > 0 {
		var err error
		if p, err = devicemock.Load(paths[0], qualRoot); err != nil {
			t.Fatal(err)
		}
	} else {
		p = qualFixture(t, "fixture_fleet.yaml")
	}
	t.Logf("profile %s %s", p.Platform, p.Firmware)
	run := qualDaemon(t, p, qualOpts{scale: 0.1, handshakeTimeout: time.Second, devices: n})

	// round mints every device's token on the test goroutine (mint's helpers call
	// t.Fatal, which is invalid from a worker; workers only index the slice) and
	// plays the fleet once. A mint during a store fault would wait on the gate, so
	// before, which sets a fault, runs once the tokens are minted. mid runs on its
	// own goroutine, calls no t helper, and is handed the count of plays started.
	round := func(name string, concurrency int, pace time.Duration, before func() error, mid func(started *atomic.Int32) error) devicemock.FleetResult {
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
		res := fleet.Run(t.Context(), func(i int) devicemock.Target { started.Add(1); time.Sleep(pace); return run.target(p, i) },
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

	if res := round("concurrent logins", 100, 0, nil, nil); res.Outcomes["login_ok"] != n {
		t.Fatalf("every device logs in: %v", res.Outcomes)
	}

	// Reload under load: touch the policy a few plays in, play slowly enough
	// (one at a time, paced: the broker's 1 s watch must fire while plays run), and
	// accept the round only if the reload line was absent when the round began
	// and present when it ended. A round the reload missed is tried again.
	reloaded := false
	for try := 1; try <= 5 && !reloaded; try++ {
		before, refreshed := strings.Count(run.stderr.String(), qualReloaded), strings.Count(run.stderr.String(), qualRefreshed)
		res := round("reload under load", 1, 4*time.Millisecond, nil, func(started *atomic.Int32) error {
			waitStarted(started, 1)
			return run.touchPolicy()
		})
		// The refresh deletes the unspent tokens of every (device, username) (spec
		// §5.1.4), so a play whose token the reload superseded is refused and its
		// device mints again; no other play is lost.
		if res.Outcomes["login_ok"]+res.Outcomes["login_refused"] != n {
			t.Fatalf("a reload under load: each play logs in or is refused: %v", res.Outcomes)
		}
		reloaded = strings.Count(run.stderr.String(), qualReloaded) > before
		// Let the reload and its refresh of the live contexts finish before the
		// next round mints: a token minted while they run can be lost.
		for end := time.Now().Add(10 * time.Second); strings.Count(run.stderr.String(), qualRefreshed) <= refreshed; time.Sleep(10 * time.Millisecond) {
			if time.Now().After(end) {
				t.Fatal("the touched policy was never reloaded and refreshed")
			}
		}
	}
	if !reloaded {
		t.Fatal("the policy reload never landed while plays ran")
	}
	if deny, notFound := strings.Count(run.log.String(), `"event":"redeem","verdict":"deny"`), strings.Count(run.log.String(), `"reason":"token_not_found"`); deny != notFound {
		t.Fatalf("a refused play was refused for token_not_found only: %d denies, %d token_not_found", deny, notFound)
	}
	if res := round("after the reload", 100, 0, nil, nil); res.Outcomes["login_ok"] != n {
		t.Fatalf("tokens minted after the reload all log in: %v", res.Outcomes)
	}
	if run.said("port49d: policy refresh stopped") {
		t.Fatal("the reload's refresh stopped part way")
	}

	// The store fails while plays are in flight: each play either logged in
	// before the fault or ends as the profile's reaction says; none hangs.
	res := round("store fails mid-run", 20, 10*time.Millisecond, nil, func(started *atomic.Int32) error {
		waitStarted(started, n/3)
		return run.fault("store_unavailable")
	})
	late := res.Outcomes["falls_to_local"] + res.Outcomes["login_refused"]
	if res.Outcomes["login_ok"] == 0 || late == 0 || res.Outcomes["login_ok"]+late != n || res.P99 > 10*time.Second {
		t.Fatalf("a mid-run fault splits the plays into logged in and not, none hung: %+v", res)
	}
	if err := run.fault(""); err != nil {
		t.Fatal(err)
	}

	// The fault in force before the first play: every play falls to local.
	// (Tokens are minted after the fault is cleared, then it is set again.)
	res = round("store down under load", 100, 0, func() error { return run.fault("store_unavailable") }, nil)
	if res.Outcomes["falls_to_local"] != n || res.P99 > 10*time.Second {
		t.Fatalf("with the store down every play falls to local, none hangs: %+v", res)
	}
	if err := run.fault(""); err != nil {
		t.Fatal(err)
	}
	if res := round("store back", 100, 0, nil, nil); res.Outcomes["login_ok"] != n {
		t.Fatalf("clearing the fault returns every play to login_ok: %v", res.Outcomes)
	}
}
