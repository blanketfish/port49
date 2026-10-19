package devicemock

import "fmt"

// React is the profile's next action for an event at a step: the step's own
// entry first, then "*". An event with no entry is an error: the vetter adds
// it from the lab notes, and the engine never guesses (decision 52 ruling 1).
func (p *Profile) React(step, on string) (Reaction, error) {
	for _, want := range []string{step, "*"} {
		for _, r := range p.Reactions {
			if r.Step == want && r.On == on {
				return r, nil
			}
		}
	}
	return Reaction{}, fmt.Errorf("%s %s: no reaction for %s at %s; add it from the lab notes", p.Platform, p.Firmware, on, step)
}
