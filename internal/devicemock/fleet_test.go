package devicemock

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/tacacs/wire"
)

func TestLoopbackSource(t *testing.T) {
	for i, want := range map[int]string{0: "127.0.1.1", 253: "127.0.1.254", 254: "127.0.2.1", 507: "127.0.2.254"} {
		if got := LoopbackSource(i); got != want {
			t.Errorf("LoopbackSource(%d) = %s, want %s", i, got, want)
		}
	}
}

func TestFleetPlaysEveryDeviceWithinItsConcurrency(t *testing.T) {
	f := newFake(t, []byte("fresh-key"))
	f.authen = []uint8{wire.AuthenStatusPass}
	f.authenRepeat = true // 50 plays, one status
	f.authorArgs = [][]byte{[]byte("local-user-name=p49-ro")}
	p, _ := Load("testdata/profiles/fixture_plain.yaml", root)
	res := Fleet{Profile: p, N: 50, Concurrency: 10, Scenario: "token_login"}.Run(t.Context(),
		func(int) Target { return Target{Addr: f.ln.Addr().String(), Transport: "tcp", Key: f.key, Scale: 1} },
		func(int) Login { return Login{User: "q", Credential: freshCredential(t)} })
	if res.Plays != 50 || res.Outcomes["login_ok"] != 50 || res.Errors != 0 || res.P99 < res.P50 {
		t.Fatalf("%+v", res)
	}
}

func TestFleetPercentilesAreNearestRank(t *testing.T) {
	d := make([]time.Duration, 100)
	for i := range d {
		d[i] = time.Duration(i+1) * time.Millisecond
	}
	if p50, p99 := percentile(d, 50), percentile(d, 99); p50 != 50*time.Millisecond || p99 != 99*time.Millisecond {
		t.Fatalf("n=100: p50 %s p99 %s, want 50ms 99ms", p50, p99)
	}
	if got := percentile(d[:2], 50); got != time.Millisecond {
		t.Fatalf("n=2 p50 = %s, want the lower of the two", got)
	}
	if got := percentile(nil, 99); got != 0 {
		t.Fatalf("no plays: %s", got)
	}
}

func TestFleetCountsAnErrorByClassAndKeepsItOutOfTheLatencies(t *testing.T) {
	f := newFake(t, []byte("fresh-key"))
	f.authen = []uint8{wire.AuthenStatusPass}
	f.authenRepeat = true
	f.authorArgs = [][]byte{[]byte("local-user-name=p49-ro")}
	p, _ := Load("testdata/profiles/fixture_plain.yaml", root)
	p.Reactions = slices.DeleteFunc(p.Reactions, func(r Reaction) bool { return r.On == "author_pass_add" })
	res := Fleet{Profile: p, N: 5, Scenario: "token_login"}.Run(t.Context(),
		func(int) Target { return Target{Addr: f.ln.Addr().String(), Transport: "tcp", Key: f.key, Scale: 1} },
		func(int) Login { return Login{User: "q", Credential: freshCredential(t)} })
	if res.Errors != 5 || res.ErrorKinds["no_reaction"] != 5 || res.P50 != 0 || res.P99 != 0 {
		t.Fatalf("%+v", res)
	}
}

func TestFleetStopsStartingPlaysOnceItsContextEnds(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	p, _ := Load("testdata/profiles/fixture_plain.yaml", root)
	res := Fleet{Profile: p, N: 50, Concurrency: 2, Scenario: "token_login"}.Run(ctx,
		func(int) Target { return Target{Addr: "127.0.0.1:1", Transport: "tcp", Scale: 1} },
		func(int) Login { return Login{User: "q"} })
	if res.Plays != 0 {
		t.Fatalf("%d plays started on a cancelled context", res.Plays)
	}
}

func TestRateModeIsOpenLoop(t *testing.T) {
	f := newFake(t, []byte("fresh-key"))
	f.authen = []uint8{wire.AuthenStatusPass}
	f.authenRepeat = true
	f.authorArgs = [][]byte{[]byte("local-user-name=p49-ro")}
	f.delay = 2 * time.Second // every play stalls; a closed loop would start only a few
	p, _ := Load("testdata/profiles/fixture_plain.yaml", root)
	done := make(chan FleetResult, 1)
	t0 := time.Now()
	go func() {
		done <- Fleet{Profile: p, N: 10, Rate: 100, Duration: time.Second, Scenario: "token_login"}.Run(t.Context(),
			func(int) Target { return Target{Addr: f.ln.Addr().String(), Transport: "tcp", Key: f.key, Scale: 1} },
			func(int) Login { return Login{User: "q", Credential: freshCredential(t)} })
	}()
	time.Sleep(1100*time.Millisecond - time.Since(t0))
	if n := f.conns.Load(); n < 98 || n > 102 {
		t.Fatalf("%d plays started within 1.1s, want 100 +/- 2", n)
	}
	res := <-done
	if res.Late != 0 {
		t.Fatalf("Late = %d, want 0", res.Late)
	}
}

func TestStepLatenciesAreReported(t *testing.T) {
	f := newFake(t, []byte("fresh-key"))
	f.authen = []uint8{wire.AuthenStatusPass}
	f.authenRepeat = true
	f.authorArgs = [][]byte{[]byte("local-user-name=p49-ro")}
	f.delay = time.Millisecond
	p, _ := Load("testdata/profiles/fixture_plain.yaml", root)
	res := Fleet{Profile: p, N: 20, Concurrency: 4, Scenario: "token_login"}.Run(t.Context(),
		func(int) Target { return Target{Addr: f.ln.Addr().String(), Transport: "tcp", Key: f.key, Scale: 1} },
		func(int) Login { return Login{User: "q", Credential: freshCredential(t)} })
	p99, p50 := res.StepP99["authorize_session"], res.StepP50["authorize_session"]
	if p99 < time.Millisecond || p99 >= 50*time.Millisecond || p50 < time.Millisecond || p50 > p99 {
		t.Fatalf("authorize_session p50 %s p99 %s, want 1ms <= p50 <= p99 < 50ms; %+v", p50, p99, res)
	}
}
