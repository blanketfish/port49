package devicemock

import (
	"testing"

	"github.com/rhwendt/port49/internal/tacacs/wire"
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
