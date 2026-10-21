package devicemock

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
)

type GoldenStep struct {
	Step  string   `json:"step"`
	Event string   `json:"event"`
	Args  []string `json:"args,omitempty"`
}

type GoldenScenario struct {
	Outcome string       `json:"outcome"`
	Steps   []GoldenStep `json:"steps"`
}

type Golden struct {
	PendingLab bool                      `json:"pending_lab"`
	Scenarios  map[string]GoldenScenario `json:"scenarios"`
}

func LoadGolden(path string) (Golden, error) {
	var g Golden
	raw, err := os.ReadFile(path)
	if err != nil {
		return g, err
	}
	return g, json.Unmarshal(raw, &g)
}

func WriteGolden(path string, g Golden) error {
	b, err := json.MarshalIndent(g, "", "  ") // map keys marshal sorted
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

// GoldenFrom keeps what port49 answered: each step's event and reply
// arguments and the outcome. A Transcript holds no credential, so neither
// does a golden.
func GoldenFrom(tr Transcript) GoldenScenario {
	g := GoldenScenario{Outcome: tr.Outcome}
	for _, s := range tr.Steps {
		g.Steps = append(g.Steps, GoldenStep{Step: s.Step, Event: s.Event, Args: s.Args})
	}
	return g
}

// Judge is a play's verdict against its golden: each measured gate is a
// failure line naming its rule; each unmeasured rule a warning; a reply that
// moved from the golden a failure naming the scenario.
func Judge(tr Transcript, want GoldenScenario) (fails, warns []string) {
	for _, v := range tr.Gate {
		fails = append(fails, fmt.Sprintf("%s: acceptance rule %s (%s): %s", tr.Scenario, v.Rule, v.Effect, v.Detail))
	}
	for _, v := range tr.Warn {
		warns = append(warns, fmt.Sprintf("%s: unmeasured acceptance rule %s: %s", tr.Scenario, v.Rule, v.Detail))
	}
	got := GoldenFrom(tr)
	if got.Outcome != want.Outcome || !slices.EqualFunc(got.Steps, want.Steps, func(a, b GoldenStep) bool {
		return a.Step == b.Step && a.Event == b.Event && slices.Equal(a.Args, b.Args)
	}) {
		fails = append(fails, fmt.Sprintf("%s: port49's replies moved from the golden (run make qual-update if on purpose)", tr.Scenario))
	}
	return fails, warns
}
