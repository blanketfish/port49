package port49d

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/store"
	etcdstore "github.com/rhwendt/port49/internal/store/etcd"
)

// judgedAt is a judgedReader holding one record, or none.
type judgedAt struct {
	rec etcdstore.JudgedRecord
	ok  bool
}

func (j judgedAt) Judged(context.Context) (etcdstore.JudgedRecord, bool, error) {
	return j.rec, j.ok, nil
}

// A start whose policy file the reload guard would refuse against the
// policy last judged is refused; one it cannot judge says why and goes on
// (Ruling 17; pre-flight I6). The refused file is quarantiningLeaf1, which
// takes the whole fleet out of service: a file admitting no device is
// refused by the start itself (loadPolicy), before the guard.
func TestAStartRefusesAFileTheGuardRefusesAgainstTheJudgedBundle(t *testing.T) {
	cfg := brokerConfig(t, minimalPolicy) // its inventory: leaf1
	cfg.MaxRemovedPercent = 20
	inv := cfg.Inventory
	good, err := parseBundle(cfg, []byte(minimalPolicy), inv)
	if err != nil {
		t.Fatal(err)
	}
	none, err := parseBundle(cfg, []byte(quarantiningLeaf1), inv)
	if err != nil {
		t.Fatal(err)
	}
	ctx, now := context.Background(), time.Now()
	recorded := judgedAt{rec: etcdstore.JudgedRecord{Bundle: good.Bundle, Policy: good.Raw()}, ok: true}
	if refused, said := guardAtStart(ctx, cfg, recorded, none, now); refused == nil || said != "" {
		t.Fatalf("a file quarantining leaf1, against a judged one serving it: %v %q", refused, said)
	}
	if refused, said := guardAtStart(ctx, cfg, recorded, good, now); refused != nil || said != "" {
		t.Fatalf("the judged bundle itself: %v %q", refused, said)
	}
	for name, j := range map[string]judgedAt{
		"no record":      {},
		"no policy":      {rec: etcdstore.JudgedRecord{Bundle: "b-other"}, ok: true},
		"does not parse": {rec: etcdstore.JudgedRecord{Bundle: "b-other", Policy: []byte("scopes: [")}, ok: true},
	} {
		if refused, said := guardAtStart(ctx, cfg, j, none, now); refused != nil || said == "" {
			t.Fatalf("%s: the guard cannot judge, so the start goes on and says why: %v %q", name, refused, said)
		}
	}
	// A record that could not be read is not one that is absent: the start
	// waits for it, failing closed (Task 15a's security lens).
	refused, said := guardAtStart(ctx, cfg, judgedFails{}, none, now)
	var sr *startRefusal
	if refused == nil || said != "" || errors.As(refused, &sr) || !errors.Is(refused, store.ErrUnavailable) {
		t.Fatalf("a judged record that could not be read: %v %q", refused, said)
	}
	if refused, _ := guardAtStart(ctx, cfg, recorded, none, now); !errors.As(refused, &sr) || sr.bundle != good.Bundle {
		t.Fatalf("a refusal names the bundle it was judged against: %v", refused)
	}
}

// judgedFails is a judgedReader whose store does not answer.
type judgedFails struct{}

func (judgedFails) Judged(context.Context) (etcdstore.JudgedRecord, bool, error) {
	return etcdstore.JudgedRecord{}, false, fmt.Errorf("%w: test", store.ErrUnavailable)
}
