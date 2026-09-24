package policy

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/engine"
)

// Diff is the effective-permission diff between two versions of a policy
// loaded against the same inventory (spec §5.4, §12), at now and at every
// later instant a grant in either version expires: every command whose
// verdict moved, for every subject, on the devices that hold the same blobs
// before and after, pipeline stages included; every level and ceiling that
// moved; every device that gained or lost a subject's access outright; every
// rule carrying a regex or class term that changed, or that a changed deny
// meets, which the diff cannot enumerate; every device the new version
// quarantines for a cause the old did not, and every one it releases; every
// subject whose mint the new version's broker refuses where the old did not;
// and every composition that would not resolve.
type Diff struct {
	Changes     []Change
	Access      []AccessChange
	Levels      []LevelChange
	Regex       []RegexChange
	Quarantined []Quarantine
	Released    []Release
	// Refused are compositions whose mint the new version's broker would
	// refuse and the old one's would not (MintCheck): the subject is locked
	// out there, which fails the gate as a new quarantine does.
	Refused []MintRefusal
	// Unresolved are compositions the diff could not compare. The gate
	// cannot vouch for them, so each fails it.
	Unresolved []string
}

// Change is one command whose verdict moved.
type Change struct {
	Subject string
	Devices []string
	// At is the first instant the change holds: the diff's now, or a later
	// grant expiry.
	At time.Time
	// Command is Vector as a person reads it: an argument no rule names is
	// `<any other argument>`, and one carrying whitespace is quoted. Vector
	// is the command exactly as probed: an argument may carry whitespace,
	// which a deny reads trimmed and a permit does not (spec §3).
	Command  string
	Vector   []string
	Old, New engine.Outcome
	// PipeEntry is the new version's allowlist entry that permits the
	// pipeline stage the old version refused (pipe_stage_denied).
	PipeEntry string
	// OldRefused is the mint item error the old version's broker answered
	// for this subject and device, which refused everything there.
	OldRefused string
	// Gated is spec §12's privilege-expansion gate: a command the old
	// version refused with a deny, at a pipeline stage, or by quarantining
	// the device, that the new version permits. Acknowledged is a policy
	// test in the new version that exercises that permit.
	Gated, Acknowledged bool
}

// AccessChange is a subject gaining or losing every grant on some devices.
// It is one line, not one per command.
type AccessChange struct {
	Subject string
	Devices []string
	At      time.Time
	Gained  bool
}

// LevelChange is a privilege change (spec §6): the level the roles compose
// to, or the ceiling the grants do.
type LevelChange struct {
	Subject                                    string
	Devices                                    []string
	At                                         time.Time
	OldLevel, NewLevel, OldCeiling, NewCeiling string
	// Raise is spec §12's gate on privilege: the level rose, or the ceiling
	// rose or went. Acknowledged is a passing session test in the new
	// version, on one of Devices, asserting each new value that rose.
	Raise, Acknowledged bool
}

// RegexChange is a rule carrying a regex or class term whose commands are not
// enumerated, because a regex position is not (spec §12, "Effective-
// permission diff in CI"). With Deny empty, Rule is one version has and the
// other does not, and Added says the new one has it. With Deny set, Rule is a
// permit that meets Deny, a deny the change added (Added) or removed.
type RegexChange struct {
	Subject string
	Devices []string
	At      time.Time
	Rule    engine.Rule
	Deny    engine.Rule
	Added   bool
}

// MintRefusal is one subject the new version's broker would refuse to mint
// for on some devices, with the mint item error and why.
type MintRefusal struct {
	Subject      string
	Devices      []string
	At           time.Time
	Code, Detail string
}

// Release is a device the old version quarantines and the new does not.
// Everything the new version permits there is a change from refused.
type Release struct {
	Device, Platform string
	At               time.Time
}

// UnacknowledgedLevels counts the level and ceiling raises no session test
// asserts.
func (d Diff) UnacknowledgedLevels() int {
	n := 0
	for _, l := range d.Levels {
		if l.Raise && !l.Acknowledged {
			n++
		}
	}
	return n
}

// Unacknowledged counts the gated changes no test exercises.
func (d Diff) Unacknowledged() int {
	n := 0
	for _, c := range d.Changes {
		if c.Gated && !c.Acknowledged {
			n++
		}
	}
	return n
}

// side is one version's view of one subject on one device at one instant.
type side struct {
	prog *engine.Program
	res  Resolution
	// hash names the blob with a fixed bundle in place of its own, which
	// differs between any two files, so equal hashes mean the version
	// changed nothing here.
	hash        string
	quarantined bool
	// refused is the mint item error the broker would answer (MintCheck),
	// with why: nothing is minted, so nothing is permitted.
	refused, refusedDetail string
	err                    error
}

func (p *Policy) side(subject string, d admission.Device, at time.Time) side {
	if _, ok := p.Quarantined(d.Name, at); ok {
		return side{quarantined: true}
	}
	sub, ok := p.subs[subject]
	if !ok {
		return side{}
	}
	res, err := p.resolve(sub, d, at)
	if errors.Is(err, ErrNoGrants) {
		return side{}
	}
	if err != nil {
		return side{err: err}
	}
	if code, detail := mintCheck(res, sub.Identity, d.Name); code != "" {
		return side{refused: code, refusedDetail: detail}
	}
	unbundled := res.Blob
	unbundled.Bundle = "diff"
	_, hash, err := engine.Encode(unbundled)
	if err != nil {
		return side{err: err}
	}
	prog, err := engine.Compile(res.Blob)
	if err != nil {
		return side{err: err}
	}
	return side{prog: prog, res: res, hash: hash}
}

// decide is the side's answer to one command vector, each argument sent as
// it is: no grant is a deny, no_grants_matched, as the mint would answer.
func (s side) decide(vector []string) engine.Outcome {
	if s.prog == nil {
		return engine.Outcome{Reason: decision.NoGrantsMatched}
	}
	raw := []string{"service=shell", "cmd=" + vector[0]}
	for _, a := range vector[1:] {
		raw = append(raw, "cmd-arg="+a)
	}
	return s.prog.Command(raw)
}

// Compare computes the diff from before to after at now and at every later
// instant a grant in either version expires, when a composition, and so a
// quarantine, can change: a grant that lapsed in the old version and is
// re-armed in the new is seen at now, and a removed `expires:` at the
// instant it would have lapsed. The two must have been loaded against the
// same inventory; after's is the one walked. A change is reported once, at
// the first instant it holds.
func Compare(before, after *Policy, now time.Time) Diff {
	instants := before.expiryInstants(now)
	for _, at := range after.expiryInstants(now) {
		if !slices.ContainsFunc(instants, at.Equal) {
			instants = append(instants, at)
		}
	}
	slices.SortFunc(instants, func(a, b time.Time) int { return a.Compare(b) })
	c := comparison{before: before, after: after, acks: after.expansionAcks(before, instants), seen: map[string]bool{}}
	for k := range after.sessionAcks(instants) {
		c.acks[k] = true
	}
	for _, at := range instants {
		c.at(at)
	}
	return c.d
}

// comparison is one Compare in progress.
type comparison struct {
	before, after *Policy
	acks          map[string]bool
	// seen holds what has been reported, so an instant repeats nothing an
	// earlier one found.
	seen map[string]bool
	d    Diff
}

func (c *comparison) once(parts ...string) bool {
	k := shadowKey(parts...)
	if c.seen[k] {
		return false
	}
	c.seen[k] = true
	return true
}

func (c *comparison) at(at time.Time) {
	// Quarantines and releases are listed by device name, as Quarantines
	// lists them.
	byName := slices.Clone(c.after.Devices())
	slices.SortFunc(byName, func(a, b admission.Device) int { return strings.Compare(a.Name, b.Name) })
	for _, dev := range byName {
		was, is := currentEntries(c.before, dev.Name, at), currentEntries(c.after, dev.Name, at)
		var fresh []QuarantineEntry
		for _, e := range is {
			if !slices.ContainsFunc(was, func(w QuarantineEntry) bool { return w.Cause == e.Cause }) &&
				c.once("quarantine", dev.Name, e.Cause) {
				fresh = append(fresh, e)
			}
		}
		if len(fresh) > 0 {
			c.d.Quarantined = append(c.d.Quarantined, Quarantine{Device: dev.Name, Platform: dev.Platform, Entries: fresh})
		}
		if len(was) > 0 && len(is) == 0 && c.once("release", dev.Name) {
			c.d.Released = append(c.d.Released, Release{Device: dev.Name, Platform: dev.Platform, At: at})
		}
	}
	names := map[string]bool{}
	for n := range c.before.subs {
		names[n] = true
	}
	for n := range c.after.subs {
		names[n] = true
	}
	subjects := make([]string, 0, len(names))
	for n := range names {
		subjects = append(subjects, n)
	}
	sort.Strings(subjects)
	type group struct {
		was, is side
		devices []string
	}
	for _, subject := range subjects {
		var order []string
		groups := map[string]*group{}
		refusals := map[string][]string{}
		for _, dev := range c.after.Devices() {
			was, is := c.before.side(subject, dev, at), c.after.side(subject, dev, at)
			if is.refused != "" && is.refused != was.refused {
				refusals[is.refused+"\x00"+is.refusedDetail] = append(refusals[is.refused+"\x00"+is.refusedDetail], dev.Name)
			}
			if is.quarantined || is.refused != "" || (was.quarantined && is.prog == nil && is.err == nil) {
				continue
			}
			if err := errors.Join(was.err, is.err); err != nil {
				msg := fmt.Sprintf("%s on %s: %v", subject, dev.Name, err)
				if c.once("unresolved", msg) {
					c.d.Unresolved = append(c.d.Unresolved, msg)
				}
				continue
			}
			if !was.quarantined && was.refused == "" && was.prog == nil && is.prog == nil {
				continue
			}
			if was.refused != "" && is.prog == nil {
				continue
			}
			// The ceiling is the grants', not the blob's, so it is part of
			// what makes two devices alike.
			key := strconv.FormatBool(was.quarantined) + "|" + was.refused + "|" + was.hash + "|" + was.res.Ceiling + "|" + is.hash +
				"|" + is.res.Ceiling
			if _, ok := groups[key]; !ok {
				groups[key] = &group{was: was, is: is}
				order = append(order, key)
			}
			groups[key].devices = append(groups[key].devices, dev.Name)
		}
		for _, key := range order {
			g := groups[key]
			c.group(subject, g.devices, g.was, g.is, at)
		}
		for _, key := range sortedKeys(refusals) {
			code, detail, _ := strings.Cut(key, "\x00")
			devices := refusals[key]
			if c.once("refused", subject, strings.Join(devices, ","), key) {
				c.d.Refused = append(c.d.Refused, MintRefusal{Subject: subject, Devices: devices, At: at, Code: code,
					Detail: detail})
			}
		}
	}
}

// currentEntries are the device's quarantine entries in force at at.
func currentEntries(p *Policy, device string, at time.Time) []QuarantineEntry {
	q, ok := p.quarantine[device]
	if !ok {
		return nil
	}
	var out []QuarantineEntry
	for _, e := range q.Entries {
		if e.Current(at) {
			out = append(out, e)
		}
	}
	return out
}

// group compares one subject on devices that hold the same blobs.
func (c *comparison) group(subject string, devices []string, was, is side, at time.Time) {
	on := strings.Join(devices, ",")
	if was.quarantined || was.refused != "" {
		// The old version refused everything here, by quarantine or at the
		// mint, so everything the new one permits is a change from refused
		// (spec §10, §12).
		from := engine.Outcome{Reason: decision.DeviceQuarantined}
		if was.refused != "" {
			from = engine.Outcome{}
		}
		for _, v := range engine.Probes(is.prog) {
			if to := is.decide(v); to.Permit {
				c.change(subject, devices, at, v, from, to, is, was.refused)
			}
		}
		return
	}
	if was.prog == nil || is.prog == nil {
		if c.once("access", subject, on, strconv.FormatBool(was.prog == nil)) {
			c.d.Access = append(c.d.Access, AccessChange{Subject: subject, Devices: devices, At: at,
				Gained: was.prog == nil})
		}
		return
	}
	wr, ir := was.res, is.res
	if (wr.Level != ir.Level || wr.Ceiling != ir.Ceiling) &&
		c.once("level", subject, on, wr.Level, ir.Level, wr.Ceiling, ir.Ceiling) {
		c.d.Levels = append(c.d.Levels, c.levelChange(LevelChange{Subject: subject, Devices: devices, At: at,
			OldLevel: wr.Level, NewLevel: ir.Level, OldCeiling: wr.Ceiling, NewCeiling: ir.Ceiling}))
	}
	if was.hash == is.hash {
		return
	}
	for _, r := range regexChanges(wr.Blob.Rules, ir.Blob.Rules) {
		if c.once("regex", subject, on, r.Rule.Verdict, r.Rule.Role, r.Rule.Rule, r.Deny.Role, r.Deny.Rule,
			strconv.FormatBool(r.Added)) {
			r.Subject, r.Devices, r.At = subject, devices, at
			c.d.Regex = append(c.d.Regex, r)
		}
	}
	for _, e := range engine.Exposures(was.prog, is.prog) {
		if c.once("exposure", subject, on, e.Permit.Role, e.Permit.Rule, e.Deny.Role, e.Deny.Rule,
			strconv.FormatBool(e.Added)) {
			c.d.Regex = append(c.d.Regex, RegexChange{Subject: subject, Devices: devices, At: at, Rule: e.Permit,
				Deny: e.Deny, Added: e.Added})
		}
	}
	var base []string
	for _, v := range engine.Probes(was.prog, is.prog) {
		from, to := was.decide(v), is.decide(v)
		if from.Permit != to.Permit {
			c.change(subject, devices, at, v, from, to, is, "")
		} else if from.Permit && base == nil {
			base = v
		}
	}
	// A pipeline stage is decided by the allowlist once the command is
	// permitted, so one command both versions permit carries every stage
	// the two allowlists tell apart (spec §4, "Pipeline stages").
	token := is.prog.Blob.Normalize.PipeToken
	if base == nil || token == "" || slices.Equal(was.prog.Blob.Pipe, is.prog.Blob.Pipe) {
		return
	}
	for _, stage := range engine.PipeProbes(was.prog, is.prog) {
		v := slices.Concat(base, []string{token}, stage)
		if from, to := was.decide(v), is.decide(v); from.Permit != to.Permit {
			c.change(subject, devices, at, v, from, to, is, "")
		}
	}
}

// change records one command whose verdict moved, and whether it is gated.
func (c *comparison) change(subject string, devices []string, at time.Time, v []string, from, to engine.Outcome,
	is side, oldRefused string) {
	ch := Change{Subject: subject, Devices: devices, At: at, Command: display(v), Vector: v, Old: from, New: to,
		OldRefused: oldRefused}
	if to.Permit && !from.Permit {
		switch {
		case from.Reason == decision.DeviceQuarantined || oldRefused != "":
			ch.Gated = true
			ch.Acknowledged = c.acks[releaseKey(subject, to.Decided.Role, to.Decided.Rule)]
		case from.Reason == decision.PipeStageDenied && from.Stage > 0 && from.Stage <= len(to.Pipeline):
			ch.Gated = true
			ch.PipeEntry = is.prog.PipeEntry(to.Pipeline[from.Stage-1])
			ch.Acknowledged = c.acks[pipeKey(subject, ch.PipeEntry)]
		case from.Deny != nil:
			ch.Gated = true
			ch.Acknowledged = c.acks[shadowKey(subject, from.Deny.Role, from.Deny.Rule, to.Decided.Role,
				to.Decided.Rule)]
		}
	}
	var oldRule, newRule string
	if from.Deny != nil {
		oldRule = from.Deny.Rule
	}
	if to.Decided != nil {
		newRule = to.Decided.Rule
	}
	if c.once(append([]string{"change", subject, strings.Join(devices, ","), oldRefused, string(from.Reason),
		string(to.Reason), oldRule, newRule}, v...)...) {
		c.d.Changes = append(c.d.Changes, ch)
	}
}

// levelChange marks a raise and whether a session test asserts it (spec
// §12). Higher is later in the new version's privilege_levels; a level it no
// longer declares is below every level it does, so moving off one is a
// raise, and a ceiling removed is a raise from any.
func (c *comparison) levelChange(l LevelChange) LevelChange {
	idx := c.after.levelIndex
	levelUp := l.NewLevel != "" && idx(l.NewLevel) > idx(l.OldLevel)
	ceilingUp := l.OldCeiling != "" && (l.NewCeiling == "" || idx(l.NewCeiling) > idx(l.OldCeiling))
	l.Raise = levelUp || ceilingUp
	if !l.Raise {
		return l
	}
	newCeiling := l.NewCeiling
	if newCeiling == "" {
		newCeiling = NoCeiling
	}
	l.Acknowledged = slices.ContainsFunc(l.Devices, func(device string) bool {
		return (!levelUp || c.acks[levelKey(l.Subject, device, "level", l.NewLevel)]) &&
			(!ceilingUp || c.acks[levelKey(l.Subject, device, "max_privilege", newCeiling)])
	})
	return l
}

func levelKey(subject, device, field, value string) string {
	return shadowKey(subject, "session", device, field, value)
}

// sessionAcks is what each passing test in p asserting a level or ceiling
// acknowledges, at each of instants: that value, for its subject on its
// device (spec §12).
func (p *Policy) sessionAcks(instants []time.Time) map[string]bool {
	acks := map[string]bool{}
	for _, at := range instants {
		for _, r := range p.RunTests(at) {
			if !r.Pass {
				continue
			}
			subject := r.Test.Subject
			if subject == "" {
				subject = p.byID[r.Test.Principal]
			}
			if r.Test.Level != "" {
				acks[levelKey(subject, r.Test.Device, "level", r.Test.Level)] = true
			}
			if r.Test.MaxPrivilege != "" {
				acks[levelKey(subject, r.Test.Device, "max_privilege", r.Test.MaxPrivilege)] = true
			}
		}
	}
	return acks
}

// display is a probe vector as a person reads it.
func display(v []string) string {
	out := make([]string, len(v))
	for i, a := range v {
		switch {
		case a == engine.OtherArgument:
			out[i] = "<any other argument>"
		case a == "" || strings.TrimSpace(a) != a || strings.ContainsAny(a, " \t"):
			out[i] = strconv.Quote(a)
		default:
			out[i] = a
		}
	}
	return strings.Join(out, " ")
}

func releaseKey(subject, role, rule string) string {
	return shadowKey(subject, string(decision.DeviceQuarantined), role, rule)
}

func pipeKey(subject, entry string) string {
	return shadowKey(subject, string(decision.PipeStageDenied), entry)
}

// regexChanges lists the rules carrying a regex or class term that one side
// has and the other does not.
func regexChanges(was, is []engine.Rule) []RegexChange {
	var out []RegexChange
	for _, v := range []struct {
		have, other []engine.Rule
		added       bool
	}{{is, was, true}, {was, is, false}} {
		for _, r := range v.have {
			if !constrained(r.Rule) || slices.Contains(v.other, r) {
				continue
			}
			out = append(out, RegexChange{Rule: r, Added: v.added})
		}
	}
	return out
}

func constrained(rule string) bool {
	terms, _ := engine.ParseRule(rule)
	for _, t := range terms {
		if t.Kind == engine.Regex || t.Kind == engine.Class {
			return true
		}
	}
	return false
}

// expansionAcks is what each passing permit test in p acknowledges, at each
// of instants, where before refused the same command: with a deny, every
// (subject, deny, permit) for a permit in p that wins over every deny it
// meets, as the shadowed-deny report reads a test; at a pipeline stage, the
// allowlist entry that now permits it; on a device before quarantined, or
// where before's broker refused the mint, every such permit. The test is the author saying the expansion is meant (spec
// §12).
func (p *Policy) expansionAcks(before *Policy, instants []time.Time) map[string]bool {
	acks := map[string]bool{}
	for _, t := range p.passedPermits(instants) {
		dev, ok := p.device(t.result.Test.Device)
		if !ok {
			continue
		}
		o := t.result.Outcome
		var winners []engine.Match
		for _, pm := range o.Permits {
			if !slices.ContainsFunc(o.Denies, func(d engine.Match) bool {
				return !engine.Dominates(pm.Specificity, d.Specificity)
			}) {
				winners = append(winners, pm)
			}
		}
		res, was, err := before.Decide(t.subject, "", dev, t.result.Test.Command, t.at)
		refused := ""
		if err == nil {
			refused, _ = mintCheck(res, before.principalsOf(t.subject, ""), dev.Name)
		}
		switch {
		case errors.Is(err, ErrDeviceQuarantined) || refused != "":
			for _, pm := range winners {
				acks[releaseKey(t.subject, pm.Role, pm.Rule)] = true
			}
		case err != nil && !errors.Is(err, ErrNoGrants):
		case was.Reason == decision.PipeStageDenied && was.Stage > 0 && was.Stage <= len(o.Pipeline):
			res, err := p.ResolveSubject(t.subject, dev, t.at)
			if err != nil {
				continue
			}
			if prog, err := engine.Compile(res.Blob); err == nil {
				acks[pipeKey(t.subject, prog.PipeEntry(o.Pipeline[was.Stage-1]))] = true
			}
		case !was.Permit && was.Deny != nil:
			for _, pm := range winners {
				acks[shadowKey(t.subject, was.Deny.Role, was.Deny.Rule, pm.Role, pm.Rule)] = true
			}
		}
	}
	return acks
}
