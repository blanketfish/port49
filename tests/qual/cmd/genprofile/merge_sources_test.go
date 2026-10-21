package main

import (
	"testing"

	"github.com/rhwendt/port49/internal/devicemock"
)

// A committed entry whose sources are a superset of the regenerated one's, all else equal, is a hand refinement, no conflict.
func TestRegenerationTreatsAdditionalSourcesAsNoConflict(t *testing.T) {
	more := append(qualSource(), devicemock.Source{Note: "tests/lab/results/L73-x.md", Register: "L73"})
	old := &devicemock.Profile{Reactions: []devicemock.Reaction{{Step: "login", On: "authen_error", Then: "a", Outcome: "o", Sources: more}}}
	gen := &devicemock.Profile{Reactions: []devicemock.Reaction{{Step: "login", On: "authen_error", Then: "a", Outcome: "o", Sources: qualSource()}}}
	if err := mergeHand(gen, &devicemock.Golden{}, old, nil, nil, nil); err != nil || len(gen.Reactions[0].Sources) != 2 {
		t.Fatalf("%v %+v", err, gen.Reactions)
	}
	// A changed outcome is still a conflict, sources or not.
	old.Reactions[0].Outcome = "other"
	gen = &devicemock.Profile{Reactions: []devicemock.Reaction{{Step: "login", On: "authen_error", Then: "a", Outcome: "o", Sources: qualSource()}}}
	if err := mergeHand(gen, &devicemock.Golden{}, old, nil, nil, nil); err == nil {
		t.Fatal("an outcome change passed on extra sources")
	}
}
