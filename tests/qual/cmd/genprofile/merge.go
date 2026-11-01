package main

import (
	"bytes"
	"fmt"
	"slices"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/blanketfish/port49/internal/devicemock"
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
	var stale []string
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
			if !merge(key, true, !sameUpToSources(o, g)) {
				use = g
			}
		} else if citesQUAL(o.Sources) && !keep[key] {
			stale = append(stale, key)
			continue
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
		found := false
		for _, g := range gen.Acceptance {
			if g.ID == o.ID {
				found = true
				if !merge("acceptance:"+o.ID, true, !sameUpToSources(o, g)) {
					use = g
				}
			}
		}
		if !found && citesQUAL(o.Sources) && !keep["acceptance:"+o.ID] {
			stale = append(stale, "acceptance:"+o.ID)
			continue
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
		found := false
		for _, g := range gen.DeviceFacts {
			if g.ID == o.ID {
				found = true
				if !merge("device_fact:"+o.ID, true, !sameUpToSources(o, g)) {
					use = g
				}
			}
		}
		if !found && strings.HasPrefix(o.ID, "tls_") && !keep["device_fact:"+o.ID] {
			stale = append(stale, "device_fact:"+o.ID)
			continue
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
		found := false
		for _, g := range gen.EngineGaps {
			if g.ID == o.ID {
				found = true
				if !merge("engine_gap:"+o.ID, true, !sameUpToSources(o, g)) {
					use = g
				}
			}
		}
		if !found && generatedGaps[o.ID] && !keep["engine_gap:"+o.ID] {
			stale = append(stale, "engine_gap:"+o.ID)
			continue
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
				// Only the outcome is a hand edit: the steps are the run's, and a
				// changed step list is a conflict the outcome must not hide.
				if !sameEntry(o.Steps, g.Steps) {
					conflicts = append(conflicts, key)
					break
				}
				g.Outcome = o.Outcome
				genG.Scenarios[sc] = g
			default:
				conflicts = append(conflicts, key)
			}
		}
	}

	if len(stale) > 0 {
		sort.Strings(stale)
		return fmt.Errorf("the committed profile has %s, which the generator wrote and this run no longer yields: it was measured differently, "+
			"so review it and delete the entry, or pass -keep=<key,...> to keep it", strings.Join(stale, ", ")+" (no longer generated)")
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

// generatedGaps are the engine gaps genprofile writes itself; any other gap is a hand entry.
var generatedGaps = map[string]bool{"command_authorization_not_sent": true, "minor_version_inferred_over_tls": true}

// citesQUAL is whether a reaction or acceptance rule cites a QUAL note: the
// pre-filled ones cite the run's own, a hand-written one cites a register row.
func citesQUAL(srcs []devicemock.Source) bool {
	for _, s := range srcs {
		if s.Register == "QUAL" {
			return true
		}
	}
	return false
}

// sourcesOf points at an entry's sources, for the four entry kinds.
func sourcesOf(e any) *[]devicemock.Source {
	switch v := e.(type) {
	case *devicemock.Reaction:
		return &v.Sources
	case *devicemock.AcceptanceRule:
		return &v.Sources
	case *devicemock.DeviceFact:
		return &v.Sources
	case *devicemock.EngineGap:
		return &v.Sources
	}
	return nil
}

// sameUpToSources is whether the committed entry o is the regenerated g, or g
// with more sources: a hand refinement that cites a further register row. The
// values (outcome, text, names) must still be equal.
func sameUpToSources[T any](o, g T) bool {
	if sameEntry(o, g) {
		return true
	}
	os, gs := sourcesOf(&o), sourcesOf(&g)
	if os == nil || gs == nil || len(*os) <= len(*gs) {
		return false
	}
	for _, want := range *gs {
		if !slices.Contains(*os, want) {
			return false
		}
	}
	trimmed := o
	*sourcesOf(&trimmed) = *gs
	return sameEntry(trimmed, g)
}
