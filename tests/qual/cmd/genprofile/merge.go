package main

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/rhwendt/port49/internal/devicemock"
)

// goldenReactions names, per golden scenario, the reactions that explain a
// hand-edited golden outcome: tls_unknown_ca's outcome is the device's measured
// reaction to the refusal (falls_to_local), not the refusal port49 logs.
var goldenReactions = map[string][]string{
	"tls_unknown_ca": {"alert_unknown_ca", "conn_reset"},
}

// mergeHand carries what the committed profile and golden hold by hand into the
// regenerated ones (decision 52 ruling 1: reactions, acceptance, device facts,
// engine gaps and the golden's reviewed outcomes are reviewed by hand).
//
//   - an entry only the committed profile has (keyed by reaction step/on, or id)
//     is carried forward, in the committed order;
//   - an entry both have, equal, is kept;
//   - an entry both have, different, is a conflict: it is refused, naming its key,
//     unless take names the key (the regenerated value wins) or keep names it (the
//     committed one wins, a hand refinement the generator cannot know);
//   - a golden scenario that differs is carried when a carried reaction explains
//     it (goldenReactions), and a conflict otherwise.
//
// Merged lists keep the committed order, then the regenerated-only entries.
func mergeHand(gen *devicemock.Profile, genG *devicemock.Golden, old *devicemock.Profile, oldG *devicemock.Golden, take, keep map[string]bool) error {
	var conflicts []string
	merge := func(key string, same bool, differs bool) (useOld bool) {
		switch {
		case !same:
			return true // only in the committed profile: carried
		case !differs:
			return true
		case keep[key]:
			return true
		case take[key]:
			return false
		default:
			conflicts = append(conflicts, key)
			return true
		}
	}

	var reactions []devicemock.Reaction
	seen := map[string]bool{}
	for _, o := range old.Reactions {
		key := "reaction:" + o.Step + "/" + o.On
		seen[key] = true
		use := o
		if g, ok := findReaction(gen.Reactions, o); ok {
			if !merge(key, true, !sameEntry(o, g)) {
				use = g
			}
		}
		reactions = append(reactions, use)
	}
	for _, g := range gen.Reactions {
		if !seen["reaction:"+g.Step+"/"+g.On] {
			reactions = append(reactions, g)
		}
	}
	gen.Reactions = reactions

	var acceptance []devicemock.AcceptanceRule
	seen = map[string]bool{}
	for _, o := range old.Acceptance {
		seen[o.ID] = true
		use := o
		for _, g := range gen.Acceptance {
			if g.ID == o.ID && !merge("acceptance:"+o.ID, true, !sameEntry(o, g)) {
				use = g
			}
		}
		acceptance = append(acceptance, use)
	}
	for _, g := range gen.Acceptance {
		if !seen[g.ID] {
			acceptance = append(acceptance, g)
		}
	}
	gen.Acceptance = acceptance

	var facts []devicemock.DeviceFact
	seen = map[string]bool{}
	for _, o := range old.DeviceFacts {
		seen[o.ID] = true
		use := o
		for _, g := range gen.DeviceFacts {
			if g.ID == o.ID && !merge("device_fact:"+o.ID, true, !sameEntry(o, g)) {
				use = g
			}
		}
		facts = append(facts, use)
	}
	for _, g := range gen.DeviceFacts {
		if !seen[g.ID] {
			facts = append(facts, g)
		}
	}
	gen.DeviceFacts = facts

	var gaps []devicemock.EngineGap
	seen = map[string]bool{}
	for _, o := range old.EngineGaps {
		seen[o.ID] = true
		use := o
		for _, g := range gen.EngineGaps {
			if g.ID == o.ID && !merge("engine_gap:"+o.ID, true, !sameEntry(o, g)) {
				use = g
			}
		}
		gaps = append(gaps, use)
	}
	for _, g := range gen.EngineGaps {
		if !seen[g.ID] {
			gaps = append(gaps, g)
		}
	}
	gen.EngineGaps = gaps

	if oldG != nil {
		for sc, o := range oldG.Scenarios {
			g, ok := genG.Scenarios[sc]
			if !ok || sameEntry(o, g) {
				continue
			}
			key := "golden:" + sc
			switch {
			case take[key]:
			case keep[key]:
				genG.Scenarios[sc] = o
			case explainedByReaction(sc, o.Outcome, gen.Reactions):
				genG.Scenarios[sc] = o
			default:
				conflicts = append(conflicts, key)
			}
		}
	}

	if len(conflicts) > 0 {
		sort.Strings(conflicts)
		return fmt.Errorf("the regenerated value differs from the committed one for %s: edit the committed entry, or pass -keep=<key,...> to keep the committed one or -take=<key,...> to let the regenerated value win",
			strings.Join(conflicts, ", "))
	}
	return nil
}

func findReaction(rs []devicemock.Reaction, like devicemock.Reaction) (devicemock.Reaction, bool) {
	for _, r := range rs {
		if r.Step == like.Step && r.On == like.On {
			return r, true
		}
	}
	return devicemock.Reaction{}, false
}

func explainedByReaction(sc, outcome string, rs []devicemock.Reaction) bool {
	for _, on := range goldenReactions[sc] {
		for _, r := range rs {
			if r.On == on && r.Outcome == outcome {
				return true
			}
		}
	}
	return false
}

// sameEntry compares two entries as the YAML they are written as: a list read
// back empty and the generator's nil list are the same entry.
func sameEntry(a, b any) bool {
	x, _ := yaml.Marshal(a)
	y, _ := yaml.Marshal(b)
	return bytes.Equal(x, y)
}
