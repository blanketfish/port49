package engine

import (
	"regexp"
	"slices"
	"strings"

	"github.com/rhwendt/port49/internal/decision"
)

// Program is a blob with its terms parsed and its patterns compiled, ready to
// decide. It is immutable, so the daemon caches one per hash and shares it
// across every authorization that names that blob (spec §5.1.1).
type Program struct {
	Blob  Blob
	rules []compiled
	pipe  []compiled
}

type compiled struct {
	verdict, rule, role string
	terms               []cterm
}

type cterm struct {
	kind Kind
	word string
	res  []*regexp.Regexp // a regex term's one pattern, or a class's patterns
}

// Compile readies b for evaluation. It fails only where Decode would have, so a
// blob that decoded compiles.
func Compile(b Blob) (*Program, error) {
	if err := b.check(); err != nil {
		return nil, err
	}
	p := &Program{Blob: b}
	for _, r := range b.Rules {
		c, err := compileRule(r.Verdict, r.Rule, r.Role, b.Classes)
		if err != nil {
			return nil, err
		}
		p.rules = append(p.rules, c)
	}
	for _, r := range b.Pipe {
		c, err := compileRule(Permit, r, "", b.Classes)
		if err != nil {
			return nil, err
		}
		p.pipe = append(p.pipe, c)
	}
	return p, nil
}

func compileRule(verdict, rule, role string, classes map[string][]string) (compiled, error) {
	terms, err := ParseRule(rule)
	if err != nil {
		return compiled{}, err
	}
	c := compiled{verdict: verdict, rule: CanonicalRule(rule), role: role}
	for _, t := range terms {
		ct := cterm{kind: t.Kind, word: t.Text}
		var patterns []string
		switch t.Kind {
		case Regex:
			patterns = []string{t.Text}
		case Class:
			patterns = classes[t.Text]
		}
		for _, pat := range patterns {
			re, err := compileTerm(pat)
			if err != nil {
				return compiled{}, err
			}
			ct.res = append(ct.res, re)
		}
		c.terms = append(c.terms, ct)
	}
	return c, nil
}

// match reports whether the rule matches the whole vector and, when it does,
// the specificity tuple: one slot per argument of the command, each holding the
// rank of the term that covered it, with a trailing `**` scoring 0 for every
// argument it absorbs (spec §5.4). There is no implicit prefix match.
//
// abbrev is the fail-closed reading of a platform that may send what the
// operator typed (spec §3 rule 4): a word also matches any non-empty prefix of
// itself, so `rel` matches `reload`. It is only ever asked for denies —
// widening a permit that way would fail open — and it can only make a deny
// match more, so on such a platform an abbreviation is denied or matched as
// written, never slipped past a deny.
func (c compiled) match(vector []string, abbrev bool) ([]int, bool) {
	spec := make([]int, 0, len(vector))
	for i, t := range c.terms {
		if t.kind == Rest {
			for range vector[i:] {
				spec = append(spec, 0)
			}
			return spec, true
		}
		if i >= len(vector) {
			return nil, false
		}
		// Whitespace around an argument is compared both ways, as received
		// and trimmed, so it can only make a rule match more: `reload ` is
		// still denied by `deny reload **`, and no position moves.
		arg, trimmed := vector[i], strings.TrimSpace(vector[i])
		switch t.kind {
		case Any:
		case Word:
			if !strings.EqualFold(t.word, arg) && !strings.EqualFold(t.word, trimmed) &&
				!(abbrev && abbreviates(trimmed, t.word)) {
				return nil, false
			}
		case Class, Regex:
			hit := false
			for _, re := range t.res {
				if re.MatchString(arg) || re.MatchString(trimmed) {
					hit = true
					break
				}
			}
			if !hit {
				return nil, false
			}
		}
		spec = append(spec, t.kind.Rank())
	}
	if len(c.terms) != len(vector) {
		return nil, false
	}
	return spec, true
}

// abbreviates reports whether arg is a proper, non-empty prefix of word,
// ignoring case.
func abbreviates(arg, word string) bool {
	return arg != "" && len(arg) < len(word) && strings.HasPrefix(strings.ToLower(word), strings.ToLower(arg))
}

// Dominates reports whether a permit scoring x dominates a deny scoring y:
// at least as specific at every position and strictly more at one (spec §5.4).
// It is a partial order, and that is the point: two rules that disagree about
// which position matters are incomparable, and the deny stands.
func Dominates(x, y []int) bool {
	if len(x) != len(y) {
		return false
	}
	strict := false
	for i := range x {
		if x[i] < y[i] {
			return false
		}
		if x[i] > y[i] {
			strict = true
		}
	}
	return strict
}

// Match is one rule that matched a command.
type Match struct {
	Rule        string
	Role        string
	Specificity []int
}

// Outcome is one command decision and everything a record, a replay and an
// explanation need to say why.
type Outcome struct {
	Permit bool
	Reason decision.Reason
	// Vector is the normalized command without its pipeline; Pipeline is the
	// stages after it, split at the platform's pipe token (spec §3).
	Vector   []string
	Pipeline [][]string
	// Decided is the rule the verdict rests on: the permit that dominated, or
	// the deny no permit dominated. Nil for no_rule_matched.
	Decided *Match
	// Deny is the record's matched_deny; Permits its matched_permits, the
	// deciding permit first and the rest most specific first. Denies is every
	// deny that matched, most specific first: on a permit, every one of them
	// is a deny the deciding permit overrode, which is what the shadowed-deny
	// report's acknowledgment reads (spec §12).
	Deny    *Match
	Permits []Match
	Denies  []Match
	// Stage is the 1-based pipeline stage a pipe_stage_denied refused.
	Stage int
}

// Normalize turns an authorization request's AV pairs into the command
// vector and its pipeline stages (spec §3): `cmd` then every `cmd-arg`, in
// order, the trailing `<cr>` dropped where the platform sends one, split at
// every argument equal to the pipe token. Arguments are never split or
// re-joined and their case and whitespace are never changed. It is exported
// so a record's `raw` can be normalized by the same code that decided it.
func (n Normalize) Normalize(raw []string) (vector []string, pipeline [][]string) {
	var cmd string
	var args []string
	for _, a := range raw {
		i := strings.IndexAny(a, "=*")
		if i < 0 {
			continue
		}
		switch a[:i] {
		case "cmd":
			cmd = a[i+1:]
		case "cmd-arg":
			args = append(args, a[i+1:])
		}
	}
	if n.StripCR && len(args) > 0 && args[len(args)-1] == "<cr>" {
		args = args[:len(args)-1]
	}
	var words []string
	if cmd != "" {
		words = append([]string{cmd}, args...)
	}
	segments := [][]string{{}}
	for _, w := range words {
		if w == n.PipeToken {
			segments = append(segments, []string{})
			continue
		}
		segments[len(segments)-1] = append(segments[len(segments)-1], w)
	}
	return segments[0], segments[1:]
}

// Command decides one command authorization (spec §5.3, from "collect every
// matching rule"): every matching permit and deny is collected; with no permit
// the answer is no_rule_matched; a permit must dominate every matching deny or
// the deny stands; then every pipeline stage must match the pipe allowlist.
// Evaluation is order-independent: which rule is named is decided by the
// tuples, then by role name, then by rule text, never by position in a file.
func (p *Program) Command(raw []string) Outcome {
	vector, pipeline := p.Blob.Normalize.Normalize(raw)
	out := Outcome{Vector: vector, Pipeline: pipeline}
	if len(vector) == 0 || strings.TrimSpace(vector[0]) == "" {
		// No command is not a command authorization (spec §5.2 owns it), and
		// `**` must not permit it: replay and explain call Command on a
		// record's raw directly, whatever the record was.
		out.Reason = decision.NoRuleMatched
		return out
	}
	var permits, denies []Match
	for _, r := range p.rules {
		abbrev := r.verdict == Deny && !p.Blob.Normalize.ExpandsAbbreviations
		if spec, ok := r.match(vector, abbrev); ok {
			m := Match{Rule: r.rule, Role: r.role, Specificity: spec}
			if r.verdict == Permit {
				permits = append(permits, m)
			} else {
				denies = append(denies, m)
			}
		}
	}
	sortMatches(permits)
	sortMatches(denies)
	out.Permits, out.Denies = permits, denies
	if len(permits) == 0 {
		out.Reason = decision.NoRuleMatched
		if len(denies) > 0 {
			out.Deny = &denies[0]
		}
		return out
	}
	best := -1
	for i, pm := range permits {
		if dominatesAll(pm, denies) {
			best = i
			break
		}
	}
	if best < 0 {
		// Name the most specific deny the most specific permit fails to
		// dominate: there is always one, or that permit would have won.
		for i := range denies {
			if !Dominates(permits[0].Specificity, denies[i].Specificity) {
				out.Deny = &denies[i]
				break
			}
		}
		out.Decided = out.Deny
		out.Reason = decision.NoPermitDominatesDeny
		return out
	}
	// The deciding permit goes first; the rest keep their order.
	out.Permits = append([]Match{permits[best]}, slices.Delete(slices.Clone(permits), best, best+1)...)
	out.Decided = &out.Permits[0]
	if len(denies) > 0 {
		out.Deny = &denies[0]
	}
	for i, stage := range pipeline {
		if !p.pipePermits(stage) {
			out.Stage = i + 1
			out.Reason = decision.PipeStageDenied
			return out
		}
	}
	out.Permit, out.Reason = true, decision.PermitDominates
	return out
}

func dominatesAll(pm Match, denies []Match) bool {
	for _, d := range denies {
		if !Dominates(pm.Specificity, d.Specificity) {
			return false
		}
	}
	return true
}

// pipePermits reports whether one stage matches the allowlist. Stages are
// allow-listed, never deny-listed: a blocklist fails open on the next vendor
// extension (spec §4). A stage is matched as written, with no abbreviation,
// which fails closed.
func (p *Program) pipePermits(stage []string) bool {
	for _, r := range p.pipe {
		if _, ok := r.match(stage, false); ok {
			return true
		}
	}
	return false
}

// sortMatches orders matches most specific first — lexicographically greatest
// tuple — then by role name, then by rule text. It is presentation only: it
// decides which rule a record names, never the verdict (spec §5.4, "Ties and
// explain"), and it depends on nothing a file's layout can change.
func sortMatches(ms []Match) {
	slices.SortFunc(ms, func(a, b Match) int {
		if c := slices.Compare(b.Specificity, a.Specificity); c != 0 {
			return c
		}
		if c := strings.Compare(a.Role, b.Role); c != 0 {
			return c
		}
		return strings.Compare(a.Rule, b.Rule)
	})
}

// Policy renders the outcome as a decision record's policy block.
func (o Outcome) Policy(bundle, blob string) *decision.Policy {
	pol := &decision.Policy{Bundle: bundle, Blob: blob, Stage: o.Stage}
	if o.Deny != nil {
		r := o.Deny.record()
		pol.MatchedDeny = &r
	}
	for _, m := range o.Permits {
		pol.MatchedPermits = append(pol.MatchedPermits, m.record())
	}
	return pol
}

func (m Match) record() decision.PolicyRule {
	return decision.PolicyRule{Rule: strings.Fields(m.Rule), Specificity: append([]int(nil), m.Specificity...), Role: m.Role}
}

// ServerMsg is what the device shows the person who typed the command (spec
// §5.3): the rule and role that decided it, which they have just exercised,
// and the instrument, and nothing from the request itself — a server_msg is
// never built from device-supplied bytes. It is printable ASCII, because it
// lands on a console.
func (o Outcome) ServerMsg() string {
	switch o.Reason {
	case decision.NoPermitDominatesDeny:
		return printable("port49: denied by " + o.Deny.Role + " (" + o.Deny.Rule + ") - see 'port49 explain'")
	case decision.PipeStageDenied:
		return "port49: an output modifier in this command is not permitted - see 'port49 explain'"
	case decision.NoRuleMatched:
		return "port49: no rule permits this command - see 'port49 explain'"
	}
	return ""
}

// printable replaces every byte outside printable ASCII, so a rule written
// with a non-ASCII regex cannot put a control sequence on a console.
func printable(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c < 0x20 || c > 0x7e {
			b[i] = '?'
		}
	}
	return string(b)
}
