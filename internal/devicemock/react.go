package devicemock

import (
	"fmt"
	"slices"
)

// React is the profile's next action for an event at a step: the step's own
// entry first, then "*". An event with no entry is an error: the vetter adds
// it from the lab notes, and the engine never guesses (decision 52 ruling 1).
func (p *Profile) React(step, on string) (Reaction, error) {
	if !slices.ContainsFunc(p.Stimulus.Steps, func(s Step) bool { return s.Name == step }) {
		return Reaction{}, fmt.Errorf("%s %s: %s is not a step of this profile", p.Platform, p.Firmware, step)
	}
	for _, want := range []string{step, "*"} {
		for _, r := range p.Reactions {
			if r.Step == want && r.On == on {
				return r, nil
			}
		}
	}
	return Reaction{}, fmt.Errorf("%s %s: no reaction for %s at %s; add it from the lab notes", p.Platform, p.Firmware, on, step)
}

// refusalEvents are the ways a device sees port49 refuse it. Whether the alert
// or the reset arrives first is a race, so a refusal is one class: Validate
// requires a step's reactions on these events to agree.
var refusalEvents = []string{"alert_unknown_ca", "alert_bad_certificate", "alert_certificate_expired",
	"alert_handshake_failure", "conn_reset", "conn_closed"}

// RefusalReaction is the step's reaction to a refusal seen as event ev: the
// entry for ev, else the entry for any other refusal event, which Validate
// guarantees agrees with it.
func (p *Profile) RefusalReaction(step, ev string) (Reaction, bool) {
	if r, err := p.React(step, ev); err == nil {
		return r, true
	}
	for _, e := range refusalEvents {
		if r, err := p.React(step, e); err == nil {
			return r, true
		}
	}
	return Reaction{}, false
}

// refusalDisagreement names a step whose refusal reactions differ.
func (p *Profile) refusalDisagreement() error {
	for _, s := range p.Stimulus.Steps {
		var first Reaction
		have := false
		for _, e := range refusalEvents {
			r, err := p.React(s.Name, e)
			if err != nil {
				continue
			}
			if !have {
				first, have = r, true
			} else if r.Then != first.Then || r.Outcome != first.Outcome {
				return fmt.Errorf("step %s: refusal reactions disagree (%s: %s/%q, %s: %s/%q); a refusal is one class because the alert and the reset race",
					s.Name, first.On, first.Then, first.Outcome, r.On, r.Then, r.Outcome)
			}
		}
	}
	return nil
}
