//go:build linux

package port49d

// TestQualFleet plays one profile as 500 concurrent mock devices from distinct
// loopback sources (127.0.1.N needs Linux, where all of 127/8 is local)
// against a real port49d (plan 11b, fleet mode). It asserts outcomes, no
// latency number: plan 12 sets the targets.

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/devicemock"
)

func TestQualFleet(t *testing.T) {
	if os.Getenv("PORT49_QUAL_FLEET") != "1" {
		t.Skip("make qual-fleet")
	}
	const n = 500
	// Task 14 adds the first wave of profiles; until then the plain fixture
	// stands in, which exercises the same broker, listener and policy path.
	var p *devicemock.Profile
	if paths, _ := filepath.Glob("../../tests/qual/profiles/arista_eos/*.yaml"); len(paths) > 0 {
		var err error
		if p, err = devicemock.Load(paths[0], qualRoot); err != nil {
			t.Fatal(err)
		}
	} else {
		p = qualFixture(t, "fixture_plain.yaml")
	}
	run := qualDaemon(t, p, qualOpts{scale: 0.1, handshakeTimeout: time.Second, devices: n})
	fleet := devicemock.Fleet{Profile: p, N: n, Concurrency: 100, Scenario: "token_login"}
	// before runs on the test goroutine once every token is minted (a mint
	// during a store fault would wait on the gate); mid runs 'after' into the plays.
	phase := func(name string, before func() error, after time.Duration, mid func() error) devicemock.FleetResult {
		// Mint every device's token here, on the test goroutine: mint's helpers
		// call t.Fatal, which is invalid from a worker. Workers only index
		// this slice.
		logins := make([]devicemock.Login, n)
		for i := range n {
			logins[i] = run.login(i)
		}
		if before != nil {
			if err := before(); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
		}
		midErr := make(chan error, 1)
		if mid != nil {
			go func() { time.Sleep(after); midErr <- mid() }() // mid never calls a t helper
		}
		res := fleet.Run(t.Context(), func(i int) devicemock.Target { return run.target(p, i) },
			func(i int) devicemock.Login { return logins[i] })
		if mid != nil {
			if err := <-midErr; err != nil {
				t.Fatalf("%s: %v", name, err)
			}
		}
		t.Logf("%s: %d plays, outcomes %v, errors %d, p50 %s, p99 %s", name, res.Plays, res.Outcomes, res.Errors, res.P50, res.P99)
		return res
	}
	if res := phase("concurrent logins", nil, 0, nil); res.Outcomes["login_ok"] != n {
		t.Fatalf("every device logs in: %v", res.Outcomes)
	}
	if res := phase("reload under load", nil, 50*time.Millisecond, run.touchPolicy); res.Outcomes["login_ok"] != n {
		t.Fatalf("a reload under load loses no login: %v", res.Outcomes)
	}
	// The 1 s watch and the push may land after the phase's plays end: wait for it.
	qualWaitFor(t, run.stderr, "port49d: policy refresh", 10*time.Second)
	res := phase("store down under load", func() error { return run.fault("store_unavailable") }, 0, nil)
	// The fault is in force before the first play: a fault landing mid-play is
	// a profile with no reaction for it, an error, not an outcome (the fixture
	// has none for author_fail at authorize_session).
	if res.Outcomes["falls_to_local"] != n || res.Errors != 0 || res.P99 > 10*time.Second {
		t.Fatalf("with the store down every play falls to local, none hangs: %+v", res)
	}
	if err := run.fault(""); err != nil {
		t.Fatal(err)
	}
	if res := phase("store back", nil, 0, nil); res.Outcomes["login_ok"] != n {
		t.Fatalf("clearing the fault returns every play to login_ok: %v", res.Outcomes)
	}
}
