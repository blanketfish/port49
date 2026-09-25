package projection

import (
	"slices"
	"strings"

	"github.com/rhwendt/port49/internal/engine"
)

// model is the device's decision under a reply, as spec §8 measured it: a
// command runs where a matching allow beats every deny, or where the bits
// reach it and no deny matches (L11). The bits are a union: a command runs
// where any held bit's reach holds it, the baseline always held, unless a
// measured carve-out of a bit not held takes it out (carve_outs). Nothing
// else subtracts: a bit not held never removes a command another bit reaches.
// Each part is an engine program over the same rules the reply's regexes were
// written from, so the check below reads the reply exactly as the translation
// promises the device reads it. The bits' reach and carve-outs are applied by
// the device's command parser, which reads a command whatever its spacing,
// case or abbreviation, so both are matched as port49 matches a deny: the
// widest reading, which for the reach errs toward the device running more.
type model struct {
	port, allow, deny, reach, carve *engine.Program
	// held is every bit the session holds, `all` expanded and the baseline
	// in: what configuration mode, which no probe reaches, is read from.
	held []string
}

func (g generator) model(res Result) (*model, error) {
	prog := func(rules []engine.Rule) (*engine.Program, error) {
		return engine.Compile(engine.Blob{Version: engine.Version, Bundle: "projection", Platform: g.in.Platform,
			Normalize: g.in.Normalize, Rules: rules, Classes: g.in.Classes, Pipe: []string{}})
	}
	parsed := func(rules []string, role string) []engine.Rule {
		out := make([]engine.Rule, len(rules))
		for i, r := range rules {
			out[i] = engine.Rule{Verdict: engine.Deny, Rule: r, Role: role}
		}
		return out
	}
	var m model
	var err error
	if m.port, err = prog(g.in.Rules); err != nil {
		return nil, err
	}
	allows := make([]engine.Rule, len(res.Allows))
	for i, a := range res.Allows {
		allows[i] = engine.Rule{Verdict: engine.Permit, Rule: a.Rule, Role: a.Role}
	}
	if m.allow, err = prog(allows); err != nil {
		return nil, err
	}
	denies := slices.Clone(res.Denies)
	if res.Shape != ShapeCapability {
		denies = []engine.Rule{{Verdict: engine.Deny, Rule: "**", Role: "projection"}}
	}
	if m.deny, err = prog(denies); err != nil {
		return nil, err
	}
	held := g.held(res.Bits)
	m.held = held
	if m.reach, err = prog(parsed(g.reach(held), "reach")); err != nil {
		return nil, err
	}
	if m.carve, err = prog(parsed(g.carves(held), "carve")); err != nil {
		return nil, err
	}
	return &m, nil
}

func raw(vector []string) []string {
	out := []string{"cmd=" + vector[0]}
	for _, a := range vector[1:] {
		out = append(out, "cmd-arg="+a)
	}
	return out
}

// device is whether the device runs vector under the reply.
func (m *model) device(vector []string) bool {
	r := raw(vector)
	if len(m.allow.Command(r).Permits) > 0 {
		return true
	}
	if len(m.deny.Command(r).Denies) > 0 {
		return false
	}
	return len(m.reach.Command(r).Denies) > 0 && len(m.carve.Command(r).Denies) == 0
}

// probes is one vector per way the rules can be told apart (engine.Probes),
// less those with a word the device's parser never sees: empty, or with a
// space at either end. The parser splits a line on whitespace, so such a
// vector is its trimmed form, which is probed in its own right.
func (m *model) probes() [][]string { return probes(m.programs()...) }

func (m *model) programs() []*engine.Program {
	return []*engine.Program{m.port, m.allow, m.deny, m.reach, m.carve}
}

func probes(programs ...*engine.Program) [][]string {
	return slices.DeleteFunc(engine.Probes(programs...), func(v []string) bool {
		return slices.ContainsFunc(v, func(w string) bool { return w == "" || strings.TrimSpace(w) != w })
	})
}

// Widens reports whether the device can do more under to than under from:
// to holds a bit from does not, or runs a command from does not, among one
// vector per way either reply's rules can be told apart. It is how the diff
// judges a projected reply (spec §12; plan 5b pre-flight I14): a reply that
// only narrows is no raise, whatever its regexes say, and one that widens
// is. A side with no projection runs nothing and holds no bit; a reply with
// no model, which Project never returns, cannot be read, and widens. The
// vector is nil where a bit decided it.
func Widens(from, to *Result) ([]string, bool) {
	if to == nil {
		return nil, false
	}
	if to.model == nil {
		return nil, true
	}
	var was *model
	if from != nil {
		was = from.model
	}
	for _, b := range to.model.held {
		if was == nil || !slices.Contains(was.held, b) {
			return nil, true
		}
	}
	progs := to.model.programs()
	if was != nil {
		progs = append(progs, was.programs()...)
	}
	for _, v := range probes(progs...) {
		if len(v) > 0 && to.model.device(v) && (was == nil || !was.device(v)) {
			return v, true
		}
	}
	return nil, false
}

// ProbeSources maps each argument Narrower's commands may carry to the rule
// words it was made from (engine.ProbeSources), so a report prints one made
// from a value redaction hides as redacted.
func (r Result) ProbeSources() map[string][]string {
	if r.model == nil {
		return nil
	}
	m := r.model
	return engine.ProbeSources(m.port, m.allow, m.deny, m.reach, m.carve)
}

// unsound is a command the device would run and port49 would deny, among one
// vector per way the rules can be told apart (engine.Probes).
func (m *model) unsound() ([]string, bool) {
	for _, v := range m.probes() {
		if len(v) == 0 {
			continue
		}
		if m.device(v) && !m.port.Command(raw(v)).Permit {
			return v, true
		}
	}
	return nil, false
}

// Narrower lists up to max commands port49 permits and the device, under the
// reply, does not, or may not: an allow runs one its bits do not reach,
// which is unmeasured (Result.Unreached). It is what CI reports as the
// reply's shortfall (spec §8).
func (r Result) Narrower(max int) [][]string {
	if r.model == nil {
		return nil
	}
	var out [][]string
	for _, v := range r.model.probes() {
		if len(v) == 0 || slices.Contains(v, engine.OtherArgument) {
			continue
		}
		if r.model.port.Command(raw(v)).Permit && (!r.model.device(v) || r.model.allowOnly(v)) {
			out = append(out, v)
			if len(out) == max {
				break
			}
		}
	}
	return out
}

// Device reports whether the device runs vector under the reply: what
// explain and a policy test say beside port49's own answer on a projected
// platform (spec §8, "Verification").
func (r Result) Device(vector []string) bool {
	return r.model != nil && len(vector) > 0 && r.model.device(vector)
}

// allowOnly reports whether only an allow runs vector: no held bit reaches it,
// or a carve-out takes it out. The model runs it, the reading that errs toward
// the device running more; whether the device does is unmeasured.
func (m *model) allowOnly(vector []string) bool {
	r := raw(vector)
	return len(m.allow.Command(r).Permits) > 0 &&
		(len(m.reach.Command(r).Denies) == 0 || len(m.carve.Command(r).Denies) > 0)
}
