package port49d

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/platform"
	"github.com/rhwendt/port49/internal/policy"
)

// genericRecorder writes a generic_platform record for each admitted device
// whose platform has no adapter, once per device per bundle: at start and at
// each swap that puts a bundle in force (spec §5.7, §8). Only port49d has one;
// port49-broker's reloader leaves it nil, so a split deployment writes one
// record per port49d. A restart builds a new recorder and records again.
type genericRecorder struct {
	log  decision.Emitter
	proc string

	mu sync.Mutex
	// recorded maps a device to the bundle it was last recorded under.
	recorded map[string]string
}

func newGenericRecorder(log decision.Emitter, proc string) *genericRecorder {
	return &genericRecorder{log: log, proc: proc, recorded: map[string]string{}}
}

// record writes the records pol owes, says one line per platform with its
// count and no device list, forgets devices that are no longer generic, and
// returns how many records it wrote.
func (g *genericRecorder) record(pol *policy.Policy, now time.Time) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	now = now.UTC()
	current := map[string]bool{}
	owed := map[string]int{} // platform -> devices newly recorded
	n := 0
	for _, d := range pol.GenericDevices() {
		current[d.Name] = true
		if g.recorded[d.Name] == pol.Bundle {
			continue
		}
		g.recorded[d.Name] = pol.Bundle
		g.log.Emit(decision.Record{TS: now, Event: decision.EventGenericPlatform, Reason: decision.PlatformUnknown,
			Device: &decision.Device{Name: d.Name, Platform: d.Platform},
			Policy: &decision.Policy{Bundle: pol.Bundle}})
		owed[d.Platform]++
		n++
	}
	for name := range g.recorded {
		if !current[name] {
			delete(g.recorded, name)
		}
	}
	redact := pol.Redactions()
	platforms := make([]string, 0, len(owed))
	for p := range owed {
		platforms = append(platforms, p)
	}
	sort.Strings(platforms)
	for _, p := range platforms {
		line := fmt.Sprintf("%s: policy: platform %s has no adapter: %d device(s) served by the generic adapter "+
			"(priv-lvl only, supports [session]), each written as a platform_unknown record (spec §8)", g.proc, p, owed[p])
		fmt.Fprintln(stderr, platform.RedactQuoted(redact, line))
	}
	return n
}
