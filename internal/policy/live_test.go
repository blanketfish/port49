package policy

import (
	"reflect"
	"sync"
	"testing"
	"time"
)

// A mint holds the policy it resolved against until its token is written; a
// swap waits for it, and every hold after the swap sees the new policy. The
// quarantine question takes no lock and answers from whichever is in force.
func TestLiveSwapWaitsForAHoldAndThenAnswersFromTheNewPolicy(t *testing.T) {
	old := mustParse(t, good)
	next := mustParse(t, good+"\n# an edit\n")
	l := NewLive(old)
	held, release := l.Hold()
	if held != old {
		t.Fatal("Hold returns the policy in force")
	}
	swapped := make(chan *Policy)
	go func() { swapped <- l.Swap(next) }()
	select {
	case <-swapped:
		t.Fatal("Swap returned while a mint still held the old policy")
	case <-time.After(50 * time.Millisecond):
	}
	release()
	if got := <-swapped; got != old {
		t.Fatalf("Swap returns what it replaced: %p, want %p", got, old)
	}
	if p, release := l.Hold(); p != next {
		t.Fatal("a hold after the swap sees the new policy")
	} else {
		release()
	}
	if l.Load() != next {
		t.Fatal("Load sees the new policy")
	}
	if _, ok := l.Quarantined("leaf-01", noon); ok {
		t.Fatal("the quarantine question is asked of the policy in force")
	}
}

// Reads race a stream of swaps without a data race (go test -race).
func TestLiveIsSafeForConcurrentUse(t *testing.T) {
	a, b := mustParse(t, good), mustParse(t, good+"\n# b\n")
	l := NewLive(a)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				p, release := l.Hold()
				_ = p.Bundle
				release()
				l.Quarantined("leaf-01", noon)
			}
		}()
	}
	for j := 0; j < 200; j++ {
		if j%2 == 0 {
			l.Swap(b)
		} else {
			l.Swap(a)
		}
	}
	wg.Wait()
}

// good's one expiring grant is alice's, on 2026-12-01 (Decided 22 of plan 4:
// a date-only expiry is the start of that day, UTC).
func TestNextChangeIsTheNextGrantExpiry(t *testing.T) {
	p := mustParse(t, good)
	lapse := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	if at, ok := p.NextChange(noon); !ok || !at.Equal(lapse) {
		t.Fatalf("NextChange(noon) = %v %v, want %v", at, ok, lapse)
	}
	if _, ok := p.NextChange(lapse); ok {
		t.Fatal("no grant expires after the last expiry")
	}
}

func TestPrincipalsAndUsernameOf(t *testing.T) {
	p := mustParse(t, good)
	want := []string{"spiffe://port49/host/oxidized-01", "system:serviceaccount:netops:oxidized", "user:alice@example.com"}
	if got := p.Principals(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Principals() = %v, want %v (a group subject lists none)", got, want)
	}
	if u, ok := p.UsernameOf("system:serviceaccount:netops:oxidized"); !ok || u != "svc-config-backup" {
		t.Fatalf("UsernameOf = %q %v", u, ok)
	}
	if _, ok := p.UsernameOf("user:mallory@example.com"); ok {
		t.Fatal("a principal no subject lists has no username")
	}
}

// A nil policy is refused where it is handed over, not at the next packet
// that reads it, far from its cause (final review m8).
func TestLiveRefusesANilPolicy(t *testing.T) {
	for name, fn := range map[string]func(){
		"NewLive": func() { NewLive(nil) },
		"Swap":    func() { NewLive(&Policy{}).Swap(nil) },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s(nil) must panic", name)
				}
			}()
			fn()
		}()
	}
}
