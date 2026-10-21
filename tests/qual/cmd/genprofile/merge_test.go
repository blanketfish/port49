package main

import (
	"strings"
	"testing"

	"github.com/rhwendt/port49/internal/devicemock"
)

func handReaction(on string) devicemock.Reaction {
	return devicemock.Reaction{Step: "login", On: on, Then: "failover_local", Outcome: "falls_to_local", Status: "measured",
		Sources: []devicemock.Source{{Note: "tests/lab/results/L73-x.md", Register: "L73"}}}
}

// A regeneration keeps what the committed profile carries by hand: reactions,
// acceptance rules, device facts and engine gaps the generator does not write.
func TestRegenerationCarriesHandWrittenEntriesForward(t *testing.T) {
	old := &devicemock.Profile{
		Reactions:   []devicemock.Reaction{handReaction("alert_unknown_ca")},
		Acceptance:  []devicemock.AcceptanceRule{{ID: "role_names", Kind: "role_names"}},
		DeviceFacts: []devicemock.DeviceFact{{ID: "f1", What: "x"}},
		EngineGaps:  []devicemock.EngineGap{{ID: "operator_x", What: "y"}},
	}
	gen := &devicemock.Profile{Acceptance: []devicemock.AcceptanceRule{{ID: "priv_lvl_range", Kind: "priv_lvl_range"}}}
	if err := mergeHand(gen, &devicemock.Golden{}, old, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if len(gen.Reactions) != 1 || len(gen.DeviceFacts) != 1 || len(gen.EngineGaps) != 1 || len(gen.Acceptance) != 2 {
		t.Fatalf("hand entries lost: %+v", gen)
	}
	// Idempotent: carrying the carried profile changes nothing.
	again := &devicemock.Profile{Acceptance: gen.Acceptance[1:]}
	if err := mergeHand(again, &devicemock.Golden{}, gen, nil, nil, nil); err != nil || len(again.Acceptance) != 2 {
		t.Fatalf("%v %+v", err, again.Acceptance)
	}
}

// A regenerated value that differs from the committed entry of the same key is
// refused, naming the key; -take names the keys the regenerated value wins.
func TestRegenerationRefusesAConflictWithAHandEntryUnlessTaken(t *testing.T) {
	old := &devicemock.Profile{DeviceFacts: []devicemock.DeviceFact{{ID: "f1", What: "hand text"}}}
	gen := &devicemock.Profile{DeviceFacts: []devicemock.DeviceFact{{ID: "f1", What: "generated text"}}}
	err := mergeHand(gen, &devicemock.Golden{}, old, nil, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "device_fact:f1") {
		t.Fatalf("want a refusal naming device_fact:f1: %v", err)
	}
	gen = &devicemock.Profile{DeviceFacts: []devicemock.DeviceFact{{ID: "f1", What: "generated text"}}}
	if err := mergeHand(gen, &devicemock.Golden{}, old, nil, map[string]bool{"device_fact:f1": true}, nil); err != nil || gen.DeviceFacts[0].What != "generated text" {
		t.Fatalf("take: %v %+v", err, gen.DeviceFacts)
	}
}

// The golden's tls_unknown_ca outcome is the device's measured reaction, edited
// by hand: it is carried when a carried reaction explains it, and refused otherwise.
func TestRegenerationCarriesAGoldenOutcomeAReactionExplains(t *testing.T) {
	oldG := &devicemock.Golden{Scenarios: map[string]devicemock.GoldenScenario{"tls_unknown_ca": {Outcome: "falls_to_local"}}}
	genG := func() *devicemock.Golden {
		return &devicemock.Golden{Scenarios: map[string]devicemock.GoldenScenario{"tls_unknown_ca": {Outcome: "handshake_refused"}}}
	}
	old := &devicemock.Profile{Reactions: []devicemock.Reaction{handReaction("alert_unknown_ca")}}
	g := genG()
	if err := mergeHand(&devicemock.Profile{}, g, old, oldG, nil, nil); err != nil || g.Scenarios["tls_unknown_ca"].Outcome != "falls_to_local" {
		t.Fatalf("%v %+v", err, g.Scenarios)
	}
	err := mergeHand(&devicemock.Profile{}, genG(), &devicemock.Profile{}, oldG, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "golden:tls_unknown_ca") {
		t.Fatalf("an unexplained golden edit must be refused: %v", err)
	}
}

// A committed profile is read back with empty lists where the generator has
// nil ones: that is no conflict.
func TestRegenerationTreatsAnEmptyListAndNilAsEqual(t *testing.T) {
	old := &devicemock.Profile{Acceptance: []devicemock.AcceptanceRule{{ID: "priv_lvl_range", Kind: "priv_lvl_range", Names: []string{}}}}
	gen := &devicemock.Profile{Acceptance: []devicemock.AcceptanceRule{{ID: "priv_lvl_range", Kind: "priv_lvl_range"}}}
	if err := mergeHand(gen, &devicemock.Golden{}, old, nil, nil, nil); err != nil {
		t.Fatalf("nil against an empty list is a conflict: %v", err)
	}
}

// -keep names the keys where the committed entry wins over a differing regenerated one.
func TestRegenerationKeepsTheCommittedEntryWhenKept(t *testing.T) {
	old := &devicemock.Profile{DeviceFacts: []devicemock.DeviceFact{{ID: "f1", What: "hand text"}}}
	gen := &devicemock.Profile{DeviceFacts: []devicemock.DeviceFact{{ID: "f1", What: "generated text"}}}
	if err := mergeHand(gen, &devicemock.Golden{}, old, nil, nil, map[string]bool{"device_fact:f1": true}); err != nil || gen.DeviceFacts[0].What != "hand text" {
		t.Fatalf("keep: %v %+v", err, gen.DeviceFacts)
	}
}

func qualSource() []devicemock.Source {
	return []devicemock.Source{{Note: "tests/lab/results/QUAL-x.md", Register: "QUAL"}}
}

// The reviewer's L80 flip: the committed profile says the denied command runs,
// the new run says it was refused. The old fact is generator-written, so it is
// not carried: the merge refuses it as no longer generated, unless -keep names it.
func TestRegenerationRefusesAGeneratedEntryTheRunNoLongerYields(t *testing.T) {
	old := &devicemock.Profile{DeviceFacts: []devicemock.DeviceFact{{ID: devicemock.FactTLSPerRequestDeniedRuns, What: "runs", Sources: qualSource()}}}
	gen := &devicemock.Profile{DeviceFacts: []devicemock.DeviceFact{{ID: devicemock.FactTLSPerRequestDeniedRefused, What: "refused", Sources: qualSource()}}}
	err := mergeHand(gen, &devicemock.Golden{}, old, nil, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "device_fact:"+devicemock.FactTLSPerRequestDeniedRuns) || !strings.Contains(err.Error(), "no longer generated") {
		t.Fatalf("want a refusal naming the stale fact: %v", err)
	}
	if len(gen.DeviceFacts) != 1 {
		t.Fatalf("both facts on the page: %+v", gen.DeviceFacts)
	}
	for _, kind := range []struct {
		name string
		old  *devicemock.Profile
	}{
		{"engine_gap:command_authorization_not_sent", &devicemock.Profile{EngineGaps: []devicemock.EngineGap{{ID: "command_authorization_not_sent"}}}},
		{"engine_gap:minor_version_inferred_over_tls", &devicemock.Profile{EngineGaps: []devicemock.EngineGap{{ID: "minor_version_inferred_over_tls"}}}},
		{"reaction:login/authen_error", &devicemock.Profile{Reactions: []devicemock.Reaction{{Step: "login", On: "authen_error", Sources: qualSource()}}}},
		{"acceptance:priv_lvl_range", &devicemock.Profile{Acceptance: []devicemock.AcceptanceRule{{ID: "priv_lvl_range", Sources: qualSource()}}}},
	} {
		err := mergeHand(&devicemock.Profile{}, &devicemock.Golden{}, kind.old, nil, nil, nil)
		if err == nil || !strings.Contains(err.Error(), kind.name) {
			t.Errorf("%s: a stale generated entry was carried: %v", kind.name, err)
		}
	}
	gen = &devicemock.Profile{}
	if err := mergeHand(gen, &devicemock.Golden{}, old, nil, nil, map[string]bool{"device_fact:" + devicemock.FactTLSPerRequestDeniedRuns: true}); err != nil || len(gen.DeviceFacts) != 1 {
		t.Fatalf("keep: %v %+v", err, gen.DeviceFacts)
	}
}

// Only the outcome a hand reaction explains is carried; a changed step list is a conflict.
func TestRegenerationCarriesTheGoldenOutcomeNeverItsSteps(t *testing.T) {
	steps := func(ev string) []devicemock.GoldenStep { return []devicemock.GoldenStep{{Step: "login", Event: ev}} }
	oldG := &devicemock.Golden{Scenarios: map[string]devicemock.GoldenScenario{"tls_unknown_ca": {Outcome: "falls_to_local", Steps: steps("tls_refused")}}}
	old := &devicemock.Profile{Reactions: []devicemock.Reaction{handReaction("alert_unknown_ca")}}
	same := &devicemock.Golden{Scenarios: map[string]devicemock.GoldenScenario{"tls_unknown_ca": {Outcome: "handshake_refused", Steps: steps("tls_refused")}}}
	if err := mergeHand(&devicemock.Profile{}, same, old, oldG, nil, nil); err != nil || same.Scenarios["tls_unknown_ca"].Outcome != "falls_to_local" {
		t.Fatalf("%v %+v", err, same.Scenarios)
	}
	moved := &devicemock.Golden{Scenarios: map[string]devicemock.GoldenScenario{"tls_unknown_ca": {Outcome: "handshake_refused", Steps: steps("conn_reset")}}}
	err := mergeHand(&devicemock.Profile{}, moved, old, oldG, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "golden:tls_unknown_ca") {
		t.Fatalf("changed steps hidden behind a hand outcome: %v", err)
	}
	if moved.Scenarios["tls_unknown_ca"].Steps[0].Event != "conn_reset" {
		t.Fatalf("the old steps replaced the regenerated: %+v", moved.Scenarios)
	}
}
