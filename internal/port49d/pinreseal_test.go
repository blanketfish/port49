package port49d

import (
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/broker"
	"github.com/blanketfish/port49/internal/store"
	"github.com/blanketfish/port49/internal/store/memory"
	"github.com/blanketfish/port49/internal/store/placement"
)

// The router brokerd builds over the directory (brokerd.go) is the store the
// scheduled pass finds its pin re-seal on: if either signature drifts, the
// broker's type assertion fails silently and no pin is ever re-sealed.
func TestThePinReSealIsOnTheRouterBrokerdBuilds(t *testing.T) {
	st := placement.Wrap(placement.Config{Session: memory.New(time.Now), Directory: memory.New(time.Now),
		Members: &lazyMembers{}, Marks: store.NewMarks()})
	if _, ok := st.(broker.PinResealer); !ok {
		t.Fatalf("%T has no ResealPins as broker.PinResealer wants it", st)
	}
}
