package policy

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/engine"
	"github.com/rhwendt/port49/internal/platform"
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
	// Principals are principals that resolve to another subject, or none,
	// and Subjects subjects whose username or group changed: who holds an
	// access, which no subject's own diff shows (spec §12).
	Principals []PrincipalChange
	Subjects   []SubjectChange
	// StaleAcknowledgments are the new version's acknowledge: entries no
	// widening in the diff is the one they name. They acknowledge nothing and
	// are reported, acknowledge_stale (spec §12).
	StaleAcknowledgments []Acknowledgment
	// Adapters are the keys of a platform's adapter that differ between the
	// versions, on every platform either version has an adapter for or the
	// inventory has devices of: a platform_set moved, or a `platforms:` block
	// edited (spec §8, §12).
	Adapters []AdapterChange
}

// AdapterChange is one key of one platform's adapter that the two versions
// say differently. A key that changes what port49 decides — a rendering, a
// class, how a command is normalized — or what this gate reads — which
// attributes bear privilege, which the device takes, how its roles rank — is
// Gated: a diff cannot vouch for its own reading when the change is to the
// reading, so it is acknowledged only in writing, by an acknowledge: entry
// naming the platform, the key and New's Sha256 (review M8, 2026-09-24;
// task 9 review C1). Old and New are the key's value as JSON, `null` where
// the adapter leaves it unset.
type AdapterChange struct {
	Platform, Field string
	Old, New        string
	// OldShown and NewShown are Old and New as port49 may print them, a
	// block's text redacted (platform.RedactAdapter): what the diff prints
	// lands in CI logs (spec §5.8; final review I3).
	OldShown, NewShown  string
	Sha256              string // hex sha256 of New: what an acknowledge: entry names
	Gated, Acknowledged bool
	AcknowledgedBy      string
}

// reportedAdapterKeys are the only adapter keys an edit to is reported and
// not gated: each changes what explain says, and nothing port49 decides or
// this gate reads. Every other key is gated, one a later plan adds included,
// until it is listed here, so the list fails closed (task 1 review I3).
// device_config is not on it: it is the configuration check-config holds a
// device to, and a block that ends a line in `none` instead of `local` has the
// device authorize every command itself whenever port49 is unreachable
// (task 7 review H6).
var reportedAdapterKeys = []string{"port_pattern", "verified", "unreachable", "unreachable_note", "fallback", "fallback_note"}

// adapterKeyGated reports whether an edit to an adapter key is gated.
func adapterKeyGated(key string) bool { return !slices.Contains(reportedAdapterKeys, key) }

// UnacknowledgedAdapters counts the gated adapter edits no acknowledge: entry
// names.
func (d Diff) UnacknowledgedAdapters() int {
	n := 0
	for _, a := range d.Adapters {
		if a.Gated && !a.Acknowledged {
			n++
		}
	}
	return n
}

// PrincipalChange is a principal that resolves to another subject in the new
// version, or to none. Gated where it now resolves to a subject it did not:
// Acknowledged is a passing session test in the new version naming it.
type PrincipalChange struct {
	Principal, OldSubject, NewSubject string
	// APIGained are broker API rights the new subject has and the old did
	// not: the acknowledging test must assert them with api: (spec §12).
	APIGained           []string
	Gated, Acknowledged bool
}

// SubjectChange is a subject whose username, group or broker API rights
// changed (spec §12). A username change is gated, and acknowledged by a
// passing session test naming one of the subject's principals; API rights
// gained are gated, and acknowledged by a passing test asserting the whole
// list with api:, naming the subject or one of its principals; a group change
// and rights lost are reported, since a group subject mints for no one until
// plan 7 and a right lost widens nothing.
type SubjectChange struct {
	Subject, OldUsername, NewUsername, OldGroup, NewGroup string
	OldAPI, NewAPI, APIGained                             []string
	Gated, Acknowledged                                   bool
}

// UnacknowledgedPrincipals counts the gated principal and username changes
// no session test asserts.
func (d Diff) UnacknowledgedPrincipals() int {
	n := 0
	for _, p := range d.Principals {
		if p.Gated && !p.Acknowledged {
			n++
		}
	}
	for _, s := range d.Subjects {
		if s.Gated && !s.Acknowledged {
			n++
		}
	}
	return n
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

// LevelChange is a privilege change (spec §6, §12): the level the roles
// compose to, the ceiling the grants do, the device privilege the session
// lands at, or the subject's enable.
type LevelChange struct {
	Subject                                    string
	Devices                                    []string
	At                                         time.Time
	OldLevel, NewLevel, OldCeiling, NewCeiling string
	// OldPrivLvl and NewPrivLvl are the device privilege, a number or `none`
	// (Policy.devicePrivLvl); OldEnable and NewEnable the mechanism.
	OldPrivLvl, NewPrivLvl, OldEnable, NewEnable string
	// OldReply and NewReply are the session reply, placeholders empty.
	OldReply, NewReply []string
	// Raised names each dimension that rose, as a session test asserts it:
	// priv_lvl, max_privilege, level, enable, reply. Raise is spec §12's gate on
	// privilege, any of them. Acknowledged is a passing session test in the
	// new version, at At, on one of Devices, asserting the new value of each.
	Raised              []string
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
	// Gated is a widening, which fails spec §12's gate: a constrained permit
	// added, a constrained deny removed, or a constrained permit meeting a
	// deny the change removed. Acknowledged is a passing policy test in the
	// new version that exercises it, or an acknowledge: entry naming the
	// removed deny, whose reason is AcknowledgedBy (regexAcked).
	Gated, Acknowledged bool
	AcknowledgedBy      string
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

// UnacknowledgedRegex counts the regex-constrained widenings no test
// exercises.
func (d Diff) UnacknowledgedRegex() int {
	n := 0
	for _, r := range d.Regex {
		if r.Gated && !r.Acknowledged {
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
	priv                   privilege
}

// privilege is what one side gives the device and what port49 enforces there
// (spec §12): the level and its ceiling by name, the ceiling's number, the
// device privilege the session lands at, and the subject's enable.
type privilege struct {
	level, ceiling string
	hasMax         bool
	max            uint8
	// device is the device privilege as a session test asserts it: a number
	// or NoCeiling's `none`.
	device, enable string
	// reply is the session reply joined by replySep, and platform whose
	// adapter says which of its attributes bear privilege.
	reply, platform string
}

// replySep joins a reply's attributes, which cannot carry a newline
// (engine.CheckAttribute).
const replySep = "\n"

func (v privilege) key() string {
	return strings.Join([]string{v.level, v.ceiling, strconv.FormatBool(v.hasMax), strconv.Itoa(int(v.max)), v.device,
		v.enable, v.reply}, "/")
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
	priv := privilege{level: res.Level, ceiling: res.Ceiling, hasMax: res.HasCeiling, max: res.MaxPrivilege,
		device: NoCeiling, enable: res.Enable, reply: strings.Join(sessionReply(res), replySep), platform: d.Platform}
	if n, ok := p.devicePrivLvl(res, d.Platform); ok {
		priv.device = strconv.Itoa(int(n))
	}
	return side{prog: prog, res: res, hash: hash, priv: priv}
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
	c := comparison{before: before, after: after, acks: after.expansionAcks(before, instants), seen: map[string]bool{},
		usedAcks: map[Acknowledgment]bool{}, secrets: append(before.HiddenValues(), after.HiddenValues()...)}
	for k := range after.sessionAcks(instants) {
		c.acks[k] = true
	}
	for k := range after.regexAcks(before, instants) {
		c.acks[k] = true
	}
	for _, at := range instants {
		c.at(at)
	}
	c.principals(now)
	c.adapters()
	for _, a := range after.acked {
		if !c.usedAcks[a] {
			c.d.StaleAcknowledgments = append(c.d.StaleAcknowledgments, a)
		}
	}
	return c.d
}

// principals compares who holds each subject's access (spec §12): every
// principal either version lists, by the subject it resolves to, and every
// subject in both by its username and group. A principal session test is the
// acknowledgment, at now: it names the person and asserts what they get.
func (c *comparison) principals(now time.Time) {
	tested, apiTested := map[string]bool{}, map[string]bool{}
	for _, r := range c.after.RunTests(now) {
		if !r.Pass || !r.Test.Session() {
			continue
		}
		who := "subject:" + r.Test.Subject
		if r.Test.Principal != "" {
			who = "principal:" + r.Test.Principal
			// A test asserting API rights alone needs no mint, so it says
			// nothing about the access a principal holds.
			if !r.Test.onlyAPI() {
				tested[r.Test.Principal] = true
			}
		}
		if r.Test.AssertsAPI {
			apiTested[who] = true
		}
	}
	rights := func(p *Policy, subject string) []string {
		if s, ok := p.subs[subject]; ok {
			return s.API
		}
		return nil
	}
	ids := map[string]bool{}
	for id := range c.before.byID {
		ids[id] = true
	}
	for id := range c.after.byID {
		ids[id] = true
	}
	for _, id := range sortedKeys(ids) {
		was, is := c.before.byID[id], c.after.byID[id]
		if was == is {
			continue
		}
		ch := PrincipalChange{Principal: id, OldSubject: was, NewSubject: is, Gated: is != "",
			APIGained: gained(rights(c.before, was), rights(c.after, is))}
		ch.Acknowledged = ch.Gated && tested[id] && (len(ch.APIGained) == 0 || apiTested["principal:"+id])
		c.d.Principals = append(c.d.Principals, ch)
	}
	for _, name := range sortedKeys(c.after.subs) {
		is := c.after.subs[name]
		was, ok := c.before.subs[name]
		if !ok {
			// A new subject's principals are gated above; a new group
			// subject's rights have no principal to carry them.
			was = &Subject{Username: is.Username, Group: is.Group}
		}
		apiGained := gained(was.API, is.API)
		if was.Username == is.Username && was.Group == is.Group && slices.Equal(sortedRights(was.API), sortedRights(is.API)) {
			continue
		}
		ch := SubjectChange{Subject: name, OldUsername: was.Username, NewUsername: is.Username, OldGroup: was.Group,
			NewGroup: is.Group, OldAPI: sortedRights(was.API), NewAPI: sortedRights(is.API), APIGained: apiGained,
			Gated: was.Username != is.Username || len(apiGained) > 0}
		names := slices.Clone(is.Identity)
		usernameOK := was.Username == is.Username || slices.ContainsFunc(names, func(id string) bool { return tested[id] })
		apiOK := len(apiGained) == 0 || apiTested["subject:"+name] ||
			slices.ContainsFunc(names, func(id string) bool { return apiTested["principal:"+id] })
		ch.Acknowledged = ch.Gated && usernameOK && apiOK
		c.d.Subjects = append(c.d.Subjects, ch)
	}
}

// gained is what to has that from does not, sorted.
func gained(from, to []string) []string {
	var out []string
	for _, r := range to {
		if !slices.Contains(from, r) {
			out = append(out, r)
		}
	}
	slices.Sort(out)
	return out
}

func sortedRights(list []string) []string {
	out := slices.Clone(list)
	slices.Sort(out)
	return out
}

// comparison is one Compare in progress.
type comparison struct {
	before, after *Policy
	acks          map[string]bool
	// seen holds what has been reported, so an instant repeats nothing an
	// earlier one found.
	seen map[string]bool
	// usedAcks are the acknowledge: entries that acknowledged a widening.
	usedAcks map[Acknowledgment]bool
	// secrets are the values either version's redactions hide in its
	// rules, and src the rule words each probe argument of the group being
	// compared was made from: a changed command prints through probeShown.
	secrets []string
	src     map[string][]string
	d       Diff
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
			// The ceiling, the device privilege and enable are the grants'
			// and the subject's, not only the blob's, so they are part of
			// what makes two devices alike.
			key := strconv.FormatBool(was.quarantined) + "|" + was.refused + "|" + was.hash + "|" + was.priv.key() + "|" +
				is.hash + "|" + is.priv.key()
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
	c.src = engine.ProbeSources(was.prog, is.prog)
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
	if was.priv != is.priv && c.once("level", subject, on, was.priv.key(), is.priv.key()) {
		c.d.Levels = append(c.d.Levels, c.levelChange(LevelChange{Subject: subject, Devices: devices, At: at,
			OldLevel: wr.Level, NewLevel: ir.Level, OldCeiling: wr.Ceiling, NewCeiling: ir.Ceiling,
			OldPrivLvl: was.priv.device, NewPrivLvl: is.priv.device, OldEnable: was.priv.enable,
			NewEnable: is.priv.enable, OldReply: splitReply(was.priv.reply), NewReply: splitReply(is.priv.reply)},
			was.priv, is.priv))
	}
	if was.hash == is.hash {
		return
	}
	for _, r := range regexChanges(wr.Blob.Rules, ir.Blob.Rules) {
		if c.once("regex", subject, on, r.Rule.Verdict, r.Rule.Role, r.Rule.Rule, r.Deny.Role, r.Deny.Rule,
			strconv.FormatBool(r.Added)) {
			r.Subject, r.Devices, r.At = subject, devices, at
			c.d.Regex = append(c.d.Regex, c.regexAcked(r))
		}
	}
	for _, e := range engine.Exposures(was.prog, is.prog) {
		if c.once("exposure", subject, on, e.Permit.Role, e.Permit.Rule, e.Deny.Role, e.Deny.Rule,
			strconv.FormatBool(e.Added)) {
			c.d.Regex = append(c.d.Regex, c.regexAcked(RegexChange{Subject: subject, Devices: devices, At: at,
				Rule: e.Permit, Deny: e.Deny, Added: e.Added}))
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
	ch := Change{Subject: subject, Devices: devices, At: at, Command: display(probeShown(v, c.src, c.secrets)), Vector: v, Old: from, New: to,
		OldRefused: oldRefused}
	if to.Permit && !from.Permit {
		switch {
		case from.Reason == decision.DeviceQuarantined || oldRefused != "":
			ch.Gated = true
			ch.Acknowledged = c.acks[instantKey(at, releaseKey(subject, to.Decided.Role, to.Decided.Rule))]
		case from.Reason == decision.PipeStageDenied && from.Stage > 0 && from.Stage <= len(to.Pipeline):
			ch.Gated = true
			ch.PipeEntry = is.prog.PipeEntry(to.Pipeline[from.Stage-1])
			ch.Acknowledged = c.acks[instantKey(at, pipeKey(subject, ch.PipeEntry))]
		case from.Deny != nil:
			ch.Gated = true
			ch.Acknowledged = c.acks[instantKey(at, shadowKey(subject, from.Deny.Role, from.Deny.Rule, to.Decided.Role,
				to.Decided.Rule))]
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

// regexAcked marks a regex-constrained widening and whether it is
// acknowledged in the new version, on a device of its group at its instant
// (spec §12): an added permit, by a permit test it decides; a removed or
// rewritten deny, by a permit test on a command it refused before and the
// new version permits; a permit meeting such a deny, by a permit test that
// permit decides on a command that deny refused before. A removed deny, and
// every permit meeting it, is also acknowledged by an acknowledge: entry
// naming it. A test expecting deny acknowledges nothing: it cannot tell a
// narrower rewrite from a wider one. A narrowing is reported and not gated.
func (c *comparison) regexAcked(r RegexChange) RegexChange {
	tested := func(parts ...string) bool {
		return slices.ContainsFunc(r.Devices, func(device string) bool {
			return c.acks[instantKey(r.At, append([]string{r.Subject, device, "regex"}, parts...)...)]
		})
	}
	var deny engine.Rule
	switch {
	case r.Deny.Rule != "":
		r.Gated, deny = !r.Added, r.Deny
		r.Acknowledged = tested("pair", r.Deny.Role, r.Deny.Rule, r.Rule.Role, r.Rule.Rule)
	case r.Rule.Verdict == engine.Permit:
		r.Gated = r.Added
		r.Acknowledged = tested("permit", r.Rule.Role, r.Rule.Rule)
	default:
		r.Gated, deny = !r.Added, r.Rule
		r.Acknowledged = tested("flip", r.Rule.Role, r.Rule.Rule)
	}
	// An entry naming a rule the new version still has removed nothing: it
	// is stale, and acknowledges nothing.
	if a, ok := c.after.acknowledgment(deny.Role, deny.Rule); ok && deny.Rule != "" && r.Gated &&
		!c.after.hasDeny(deny.Rule) {
		c.usedAcks[a] = true
		if !r.Acknowledged {
			r.Acknowledged, r.AcknowledgedBy = true, a.Reason
		}
	}
	if !r.Gated {
		r.Acknowledged, r.AcknowledgedBy = false, ""
	}
	return r
}

// regexAcks is what each passing permit test in p acknowledges of a
// regex-constrained change, at each of instants, on its device: the permit
// that decides it; where before refused its command with a deny, that deny's
// flip, and the pair of that deny and the permit (spec §12). A test expecting
// deny acknowledges nothing here.
func (p *Policy) regexAcks(before *Policy, instants []time.Time) map[string]bool {
	acks := map[string]bool{}
	for _, at := range instants {
		for _, r := range p.RunTests(at) {
			if !r.Pass || !r.Permit || r.Test.Session() || r.MintError != "" || r.Outcome.Decided == nil {
				continue
			}
			subject := r.Test.Subject
			if subject == "" {
				subject = p.byID[r.Test.Principal]
			}
			dev, ok := p.device(r.Test.Device)
			if !ok || subject == "" {
				continue
			}
			win := r.Outcome.Decided
			acks[instantKey(at, subject, dev.Name, "regex", "permit", win.Role, win.Rule)] = true
			if _, was, err := before.Decide(subject, "", dev, r.Test.Command, at); err == nil && !was.Permit &&
				was.Deny != nil {
				acks[instantKey(at, subject, dev.Name, "regex", "flip", was.Deny.Role, was.Deny.Rule)] = true
				acks[instantKey(at, subject, dev.Name, "regex", "pair", was.Deny.Role, was.Deny.Rule, win.Role,
					win.Rule)] = true
			}
		}
	}
	return acks
}

// levelChange marks a raise and whether a session test asserts it (spec
// §12). The gate compares what the device gets and what port49 enforces, not
// level names:
//
//   - priv_lvl: the device privilege rose, or became unknown;
//   - max_privilege: the ceiling went away, or rose by its number or by its
//     place in either version's privilege_levels;
//   - level: the level rose under either version's order; a level a version
//     does not declare is below every level it does;
//   - enable: the mechanism went from none to token, or to auto, which asks
//     for nothing more than a login;
//   - reply: the session reply gained, changed or lost an attribute that
//     bears privilege on the platform, priv-lvl aside.
func (c *comparison) levelChange(l LevelChange, was, is privilege) LevelChange {
	rose := func(from, to string) bool {
		return from != to && to != "" && (c.before.levelIndex(to) > c.before.levelIndex(from) ||
			c.after.levelIndex(to) > c.after.levelIndex(from))
	}
	if was.device != is.device {
		from, errFrom := strconv.Atoi(was.device)
		to, errTo := strconv.Atoi(is.device)
		if errTo != nil || (errFrom == nil && to > from) || (errFrom != nil && errTo == nil) {
			l.Raised = append(l.Raised, "priv_lvl")
		}
	}
	if was.ceiling != "" && (is.ceiling == "" || (was.hasMax && is.hasMax && is.max > was.max) ||
		rose(was.ceiling, is.ceiling)) {
		l.Raised = append(l.Raised, "max_privilege")
	}
	if rose(was.level, is.level) {
		l.Raised = append(l.Raised, "level")
	}
	if enableRank[is.enable] > enableRank[was.enable] {
		l.Raised = append(l.Raised, "enable")
	}
	before, after := c.before.dialect(was.platform), c.after.dialect(is.platform)
	oldRendered, _, _ := c.before.render(before, was.level)
	newRendered, _, _ := c.after.render(after, is.level)
	if replyRose(l.OldReply, l.NewReply, oldRendered, newRendered, before, after) {
		l.Raised = append(l.Raised, "reply")
	}
	l.Raise = len(l.Raised) > 0
	if !l.Raise {
		return l
	}
	l.Acknowledged = slices.ContainsFunc(l.Devices, func(device string) bool {
		for _, field := range l.Raised {
			if !c.acks[levelKey(l.At, l.Subject, device, field, l.NewValue(field))] {
				return false
			}
		}
		return true
	})
	return l
}

// replyRose reports whether the session reply gained, changed or lost an
// attribute, other than priv-lvl, which priv_lvl judges, that bears privilege
// under either version's adapter or any shipped set, other than by provably
// going down (attributeRose; spec §12).
func replyRose(old, new, oldRendered, newRendered []string, before, after platform.Dialect) bool {
	was, is := attributesByName(old), attributesByName(new)
	names := sortedKeys(was)
	for _, n := range sortedKeys(is) {
		if !slices.Contains(names, n) {
			names = append(names, n)
		}
	}
	for _, name := range names {
		if attributeRose(name, was[name], is[name], oldRendered, newRendered, before, after) {
			return true
		}
	}
	return false
}

// attributeRose is whether a privilege-bearing attribute went up in the
// diff: priv-lvl aside, which each caller judges as a number, and only for an
// attribute that bears privilege under either adapter or any shipped set
// (bearsPrivilege), by the one judgment the ceiling check shares (rose).
func attributeRose(name string, from, to, fromRendered, toRendered []string, before, after platform.Dialect) bool {
	return !strings.EqualFold(name, "priv-lvl") && bearsPrivilege(name, before, after) &&
		rose(from, to, fromRendered, toRendered, before, after)
}

// rose is the one judgment of whether an attribute's values went up: from
// its values in one reply to its values in another, each read beside what the
// level it came from renders. The diff gate asks it of a reply's old and new
// values (attributeRose), and the joint check asks it of the ceiling's
// rendering and the reply sent under the ceiling (exceeds), so the two cannot
// disagree about what raises a session (final review I1). Which attributes
// each asks about differs: the diff gates every change it cannot read, and the
// ceiling bounds only what can carry privilege (raisesCeiling).
//
// A change rises unless it provably goes down: one value a level renders
// replaced by one value the other level renders, which role_order ranks
// strictly below under both adapters. A subject moved from admin to readonly
// on EOS is lowered because network-operator ranks below network-admin (L16),
// not because readonly is below admin, which a custom level's parent can make
// untrue of what it renders. Anything else changes what the device lets the
// session do in a direction nobody can read: a role's or grant's attribute
// either way (on a session-only platform losing deny-commands widens access),
// and a role no adapter ranks, which ranks above every role.
func rose(from, to, fromRendered, toRendered []string, before, after platform.Dialect) bool {
	if slices.Equal(from, to) {
		return false
	}
	return len(from) != 1 || len(to) != 1 || !slices.Contains(fromRendered, from[0]) ||
		!slices.Contains(toRendered, to[0]) || !before.Lowers(from[0], to[0]) || !after.Lowers(from[0], to[0])
}

// attributesByName is a reply's attributes keyed by name.
func attributesByName(reply []string) map[string][]string {
	out := map[string][]string{}
	for _, a := range reply {
		out[engine.AttributeName(a)] = append(out[engine.AttributeName(a)], a)
	}
	return out
}

// enableRank orders the mechanisms by what they ask of an escalation: none
// refuses it, token asks for a second credential, auto for nothing more.
var enableRank = map[string]int{"none": 0, "": 0, "token": 1, "auto": 2}

// NewValue is the new version's value of a raised dimension, as a session
// test asserts it.
func (l LevelChange) NewValue(field string) string {
	switch field {
	case "priv_lvl":
		return l.NewPrivLvl
	case "max_privilege":
		if l.NewCeiling == "" {
			return NoCeiling
		}
		return l.NewCeiling
	case "level":
		return l.NewLevel
	case "reply":
		return strings.Join(l.NewReply, replySep)
	}
	return l.NewEnable
}

func splitReply(joined string) []string {
	if joined == "" {
		return []string{}
	}
	return strings.Split(joined, replySep)
}

func levelKey(at time.Time, subject, device, field, value string) string {
	return instantKey(at, subject, "session", device, field, value)
}

// instantKey is an acknowledgment key that holds at one instant: a test
// acknowledges what it asserts only where it passes (spec §12).
func instantKey(at time.Time, parts ...string) string {
	return shadowKey(append([]string{at.UTC().Format(time.RFC3339Nano)}, parts...)...)
}

// sessionAcks is what each passing test in p asserting a session value
// acknowledges, at each of instants: the value it resolved, for its subject
// on its device, at that instant (spec §12).
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
			for field, asserted := range map[string]bool{"level": r.Test.Level != "",
				"max_privilege": r.Test.MaxPrivilege != "", "priv_lvl": r.Test.PrivLvl != "", "enable": r.Test.Enable != "",
				"reply": r.Test.AssertsReply} {
				if !asserted {
					continue
				}
				value := map[string]string{"level": r.Level, "max_privilege": r.Ceiling, "priv_lvl": r.PrivLvl,
					"enable": r.Enable, "reply": strings.Join(r.Reply, replySep)}[field]
				acks[levelKey(at, subject, r.Test.Device, field, value)] = true
			}
		}
	}
	return acks
}

// probeShown is a probe vector with every argument made from a value
// redaction hides printed Redacted: the value, a piece of it a probe split
// or cut short, or a witness of a class or regex term whose text is hidden,
// none of which a writer recognizes as the secret (src is
// engine.ProbeSources; spec §5.8). An argument with no source recorded is
// one nothing says is safe, and prints Redacted too; OtherArgument is no
// rule's text. The vector probed is left as it was.
func probeShown(v []string, src map[string][]string, secrets []string) []string {
	out := slices.Clone(v)
	for i, a := range out {
		if a == engine.OtherArgument {
			continue
		}
		if len(src[a]) == 0 || hidden(secrets, strings.TrimSpace(a)) || slices.ContainsFunc(src[a],
			func(w string) bool { return hidden(secrets, w) }) {
			out[i] = platform.Redacted
		}
	}
	return out
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
// where before's broker refused the mint, every such permit. Each holds only
// at the instant the test passed. The test is the author saying the
// expansion is meant (spec §12).
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
				acks[instantKey(t.at, releaseKey(t.subject, pm.Role, pm.Rule))] = true
			}
		case err != nil && !errors.Is(err, ErrNoGrants):
		case was.Reason == decision.PipeStageDenied && was.Stage > 0 && was.Stage <= len(o.Pipeline):
			res, err := p.ResolveSubject(t.subject, dev, t.at)
			if err != nil {
				continue
			}
			if prog, err := engine.Compile(res.Blob); err == nil {
				acks[instantKey(t.at, pipeKey(t.subject, prog.PipeEntry(o.Pipeline[was.Stage-1])))] = true
			}
		case !was.Permit && was.Deny != nil:
			for _, pm := range winners {
				acks[instantKey(t.at, shadowKey(t.subject, was.Deny.Role, was.Deny.Rule, pm.Role, pm.Rule))] = true
			}
		}
	}
	return acks
}

// bearsPrivilege reports whether the gate reads an attribute as bearing
// privilege: under the stricter of the two versions' adapters, and always
// where any platform set port49 ships lists it as bearing privilege. Which
// attributes bear privilege is itself read from the adapters, so an edit that
// lists an attribute inert cannot hide a change to that attribute in the same
// diff, and no adapter, however it was loaded, unlists a shipped one (review
// M8, 2026-09-24).
func bearsPrivilege(name string, before, after platform.Dialect) bool {
	return before.BearsPrivilege(name) || after.BearsPrivilege(name) ||
		platform.ContainsName(platform.PrivilegeAttributeNames(), name)
}

// adapters compares each platform's adapter, key by key, for every platform
// the inventory has devices of and every platform either version has an
// adapter for. A block for a platform no device has yet is compared too: the
// inventory is not diffed, so the day a device of it arrives is no review
// (pre-flight B2). Each side is the platform's effective adapter
// (adapterSpec), the generic one where the version has none.
func (c *comparison) adapters() {
	platforms := map[string]bool{}
	for _, p := range []*Policy{c.before, c.after} {
		for _, d := range p.Devices() {
			platforms[d.Platform] = true
		}
		for name := range p.adapters {
			platforms[name] = true
		}
	}
	// The generic adapter is what every device of a platform with no adapter
	// receives, the first device of one the inventory does not yet have
	// included, so a moved pin that changes it is gated like any adapter
	// (owner's ruling 2026-09-24, task 13).
	platforms[genericPlatform] = true
	keys := platform.SpecKeys()
	// A secret either version's text holds is hidden on both sides: an edit
	// that removes a block's pattern still prints the old text.
	patterns := slices.Concat(c.before.Redactions(), c.after.Redactions())
	secret := c.before.SecretClasses()
	for class := range c.after.SecretClasses() {
		secret[class] = true
	}
	shown := func(p *Policy, name string) reflect.Value {
		return reflect.ValueOf(p.shownSpec(name, patterns, secret))
	}
	for _, name := range sortedKeys(platforms) {
		was := reflect.ValueOf(c.before.adapterSpec(name))
		is := reflect.ValueOf(c.after.adapterSpec(name))
		wasShown, isShown := shown(c.before, name), shown(c.after, name)
		for i, key := range keys {
			if reflect.DeepEqual(was.Field(i).Interface(), is.Field(i).Interface()) {
				continue
			}
			a := AdapterChange{Platform: name, Field: key, Old: canonical(was.Field(i).Interface()),
				New: canonical(is.Field(i).Interface()), OldShown: canonical(wasShown.Field(i).Interface()),
				NewShown: canonical(isShown.Field(i).Interface()), Gated: adapterKeyGated(key)}
			a.Sha256 = fmt.Sprintf("%x", sha256.Sum256([]byte(a.New)))
			for _, ack := range c.after.acked {
				// The digest binds the entry to this edit: one left in the file
				// from an earlier edit to the key names another value, and
				// acknowledges nothing (task 9 review C1).
				if a.Gated && ack.Platform == name && ack.Field == key && ack.Sha256 == a.Sha256 {
					a.Acknowledged, a.AcknowledgedBy = true, ack.Reason
					c.usedAcks[ack] = true
				}
			}
			c.d.Adapters = append(c.d.Adapters, a)
		}
	}
}

// adapterSpec is the platform's effective adapter in this version as the diff
// compares it. Where the version has no adapter for the name, supports is
// unset (save on the generic adapter itself, compared whole): the generic
// adapter's `session` is assumed, not measured, and an
// unmeasured platform is not treated as session-only (normalizeFor). So a
// block equal to the generic adapter still shows as an edit to supports, the
// key that makes the platform session-only and turns off abbreviation
// matching on its denies (task 9 review I2).
func (p *Policy) adapterSpec(name string) platform.Spec {
	s := platform.SpecOf(p.dialect(name))
	if _, known := p.platforms()[name]; !known && name != genericPlatform {
		s.Supports = nil
	}
	return s
}

// shownSpec is adapterSpec with a block's text as port49 may print it
// (platform.RedactAdapter).
func (p *Policy) shownSpec(name string, patterns []platform.Redaction, secret map[string]bool) platform.Spec {
	s := platform.SpecOf(platform.RedactAdapter(patterns, secret, p.dialect(name)))
	if _, known := p.platforms()[name]; !known && name != genericPlatform {
		s.Supports = nil
	}
	return s
}

// canonical is an adapter value as JSON, the text an acknowledgment's digest
// is taken over. Every Spec field marshals; were one not to, the change is
// still shown, and gated like any other.
func canonical(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "unrenderable: " + err.Error()
	}
	return string(b)
}
