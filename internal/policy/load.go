// Package policy is the policy engine's authoring half (spec §2–§6, §11): it
// loads the policy file, resolves a principal on a device into the grants,
// roles and ceilings that apply (spec §5.1), and compiles the result into the
// blob internal/engine decides with. The broker mints from it; `port49
// explain`, `port49 policy test`, `port49 access review` and `port49 grants
// remove` read it offline. The daemon never does: it has the blob.
package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"regexp/syntax"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"gopkg.in/yaml.v3"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/engine"
	"github.com/rhwendt/port49/internal/platform"
	"github.com/rhwendt/port49/internal/token"
)

// Env is what a policy is loaded against. The joint checks of spec §6 and §10
// — a class a platform does not define, a level it cannot render, `enable:
// auto` where the enable exchange carries no principal — are questions about
// the platforms actually present, so they run over the inventory.
type Env struct {
	// Devices is the inventory: the file inventory the daemon admits from,
	// until plan 6's bundle.
	Devices []admission.Device
	// Dialects replaces platforms of the pinned set when non-nil: tests use
	// it to stand a platform up with other behaviour.
	Dialects map[string]platform.Dialect
	// Sets and Generics replace the built-in platform sets and their generic
	// adapters, by version, when Sets is non-nil: tests use them to stand up
	// a second set, since this build ships one. A set Generics leaves out
	// has the unpinned set's generic adapter.
	Sets     map[string]map[string]platform.Dialect
	Generics map[string]platform.Dialect
	// Now is the present the joint checks start from: a grant already expired
	// by then is not checked. Zero is the clock at load; tests fix it.
	Now time.Time
}

// Policy is a loaded, validated policy file.
type Policy struct {
	// Bundle names this policy on every blob and record: the sha256 of the
	// file's bytes, until plan 6 publishes versioned bundles (spec §5.7).
	Bundle string

	// set is the platform set the policy pins (spec §8), and adapters its
	// platforms: the built-in set, the file's `platforms:` blocks over it,
	// Env.Dialects over those. overrides are the blocks as written, for the
	// drift report.
	set       string
	adapters  map[string]platform.Dialect
	overrides map[string]filePlatform

	levels  []string          // the declared ordering, lowest first
	parents map[string]string // level → parent, for rendering
	scopes  map[string]*Scope
	roles   map[string]*Role
	subs    map[string]*Subject
	byID    map[string]string // identity → subject
	grants  []*Grant
	tests   []Test
	acked   []Acknowledgment
	env     Env
	// quarantine is every device a joint check failed on, by name (Task 10).
	quarantine map[string]*Quarantine
}

// Scope selects devices by their inventory attributes (spec §5.5).
type Scope struct {
	Name        string
	Match       map[string]matchValue
	OnMissing   string // "include" | "exclude"
	SecurityLog bool
	Attached    map[string][]string // "humans" | "machines" → roles
	res         map[string]*regexp.Regexp
	// onMissingDeclared is whether the file wrote on_missing rather than
	// taking the default, which a deny-bearing scope must (spec §5.5).
	onMissingDeclared bool
}

// Role is a named set of rules, an optional level, and attributes (spec §6).
type Role struct {
	Name       string
	Privilege  string
	Reason     string
	Permit     []string
	Deny       []string
	Pipe       []string // nil: the shipped default
	Attributes map[string][]string
}

// Subject addresses a set of principals (spec §2).
type Subject struct {
	Name     string
	Group    string
	Identity []string
	Domain   string // "humans" | "machines", the key attached_roles uses
	Username string
	Enable   string
	TokenTTL time.Duration
	API      []string
}

// Grant is one flat row: subject × scope × roles (spec §13, decision 2).
type Grant struct {
	Subject      string
	Scope        string
	Roles        []string
	MaxPrivilege string
	Expires      time.Time // zero: never
	Attributes   map[string][]string
}

// Test is one `tests:` entry (spec §11, §12). With no Command it is a session
// test, which asserts Level, MaxPrivilege or both.
type Test struct {
	Subject, Principal, Device, Command, Expect, Reason string
	// Level is the level the roles compose to on the device, and
	// MaxPrivilege the ceiling the grants compose to there, `none` for no
	// ceiling; PrivLvl is the device privilege the session lands at, a
	// number or `none` (Policy.devicePrivLvl), and Enable the subject's
	// mechanism. Empty asserts nothing.
	Level, MaxPrivilege, PrivLvl, Enable string
	// Reply is the exact session reply, in order, with the placeholders
	// empty, where AssertsReply.
	Reply        []string
	AssertsReply bool
	// API is the subject's broker API rights, sorted, where AssertsAPI. A
	// test asserting them alone passes on any device: they do not depend on
	// one (spec §12).
	API        []string
	AssertsAPI bool
}

// Acknowledgment is one `acknowledge:` entry (spec §12): a removed or
// rewritten deny, named by its role and exact rule text, or an edited key of a
// platform's adapter, named by the platform, the key and the sha256 of the
// key's new value, that the author acknowledges in writing, with why. The
// digest binds the entry to the one edit it was written for: left in the
// file, it acknowledges no later edit to the same key (spec §12).
type Acknowledgment struct {
	Role, Rule, Platform, Field, Sha256, Reason string
}

// NoCeiling is how a test asserts that the grants compose to no ceiling.
const NoCeiling = "none"

// DefaultPipe is the output-modifier allowlist every role inherits unless it
// declares its own (spec §4).
var DefaultPipe = []string{"include **", "exclude **", "begin **", "section **", "json", "count", "no-more"}

// reservedLevels ship built in and cannot be renamed or removed (spec §6).
var reservedLevels = []string{"readonly", "operator", "admin"}

var apiRights = []string{"revoke_others", "explain_others", "sync", "keys_show", "replay"}

// Design §8: device tokens live 30–900s.
const (
	minTokenTTL = 30 * time.Second
	maxTokenTTL = 900 * time.Second
)

// Load reads and validates the policy file at path against env. Every error
// names the file and what to change.
func Load(path string, env Env) (*Policy, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	p, err := Parse(raw, env)
	if err != nil {
		return nil, fmt.Errorf("policy: %s: %w", path, err)
	}
	return p, nil
}

// Parse validates a policy file's bytes against env.
func Parse(raw []byte, env Env) (*Policy, error) {
	if err := refusedKeys(raw); err != nil {
		return nil, err
	}
	var f file
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil && err != io.EOF {
		// A type error quotes the value it could not decode, and the value
		// may be a rule or a secret in it: the line and the types say where
		// (spec §5.8).
		msg := yamlValue.ReplaceAllString(err.Error(), "cannot unmarshal a $1 value")
		msg = yamlField.ReplaceAllString(msg, "an unknown field in type $1")
		msg = yamlKey.ReplaceAllString(msg, "a mapping key already defined at line $1")
		if strings.Contains(msg, "time.Duration") {
			return nil, fmt.Errorf("%s; durations need a unit, e.g. 60s", msg)
		}
		return nil, errors.New(msg)
	}
	// A second document would be ignored by a single Decode, and an ignored
	// `---` followed by a `scopes:` block is a policy that reads as scoped and
	// is not.
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return nil, errors.New("the policy file must be one YAML document; remove the `---` separator and " +
			"everything after it, or merge it into the first document")
	}
	p := &Policy{Bundle: engine.HashOf(raw), env: env}
	for _, step := range []func(file) error{p.buildPlatforms, p.buildLevels, p.checkBlockOrder, p.buildRoles, p.buildScopes, p.buildSubjects,
		p.buildGrants, p.checkMinters, p.buildTests, p.buildAcknowledgments} {
		if err := step(f); err != nil {
			return nil, err
		}
	}
	// An empty policy fails closed, but a truncated file or the wrong one would
	// go unnoticed until the first refused mint.
	if len(p.subs) == 0 {
		return nil, errors.New("declares no subjects, so nobody can mint; is this the right file?")
	}
	p.checkDevices()
	return p, nil
}

// yamlValue is the value a YAML type error quotes; yamlField and yamlKey
// the key an unknown-field or duplicate-key error does. Each names its line.
var (
	yamlValue = regexp.MustCompile("cannot unmarshal (!!\\w+) `[^`]*`")
	yamlField = regexp.MustCompile(`field .* not found in type (\S+)`)
	yamlKey   = regexp.MustCompile(`mapping key ".*" already defined at line (\d+)`)
)

// refusedKeys names the plan that reads a key this build does not, before the
// strict decode can say only that the field is unknown. Spec §11's example
// carries two of them.
func refusedKeys(raw []byte) error {
	var loose struct {
		KeyGroups any              `yaml:"key_groups"`
		Roles     []map[string]any `yaml:"roles"`
	}
	if err := yaml.Unmarshal(raw, &loose); err != nil {
		return nil // the strict decode reports it, with a line number
	}
	switch {
	case loose.KeyGroups != nil:
		return errors.New("key_groups: key groups live in the inventory file (inventory_file) until plan 6 " +
			"moves them to the policy repository; move the block there")
	}
	for i, r := range loose.Roles {
		if _, ok := r["max_session_age"]; ok {
			role := fmt.Sprintf("roles[%d]", i)
			if name, ok := r["name"].(string); ok && name != "" {
				role = fmt.Sprintf("role %q", name)
			}
			return fmt.Errorf("%s: max_session_age per role is plan 7's; session.max_session_age_default "+
				"in port49d.yaml applies to every role until then", role)
		}
	}
	return nil
}

// buildPlatforms resolves the platform set the policy pins, or UnpinnedSet
// where it pins none (spec §8): a binary upgrade never changes what a policy
// renders, and a set this binary does not ship is refused by name. Each
// `platforms:` block then merges over the set per top-level key, or starts
// from another platform (`based_on:`) or from nothing (`replace: true`), and
// is validated exactly as a built-in is.
func (p *Policy) buildPlatforms(f file) error {
	p.set = f.PlatformSet
	if p.set == "" {
		p.set = platform.UnpinnedSet
	}
	set, ok := p.builtinSet(p.set)
	if !ok {
		return fmt.Errorf("platform_set: %s is not a set this binary ships; it ships %s. Pin one of those, or run "+
			"a binary that ships %s (spec §8)", p.set, strings.Join(platform.Sets(), ", "), p.set)
	}
	builtin, _ := p.builtinSet(p.set)
	generic, _ := p.builtinGeneric(p.set)
	p.overrides = f.Platforms
	for _, name := range sortedKeys(f.Platforms) {
		b := f.Platforms[name]
		at := "platforms." + name
		_, shipped := builtin[name]
		var base platform.Dialect
		switch {
		case !platformNameShape.MatchString(name):
			return fmt.Errorf("%s: a platform name is lower case, digits and _, starting with a letter, as an "+
				"inventory's platform: field writes it", at)
		case name == "all" || name == "default":
			// `all` keys an attribute to every platform (§6) and `default` is
			// the redaction list of every platform with none (§5.8): a platform
			// of either name would be read as the other.
			return fmt.Errorf("%s: %s is reserved: attributes.all names every platform and the built-in redaction "+
				"table's default list every unlisted one; name the platform as the inventory does", at, name)
		case name == genericPlatform:
			// An acknowledge: entry names the generic adapter as platform
			// generic (§12), so a block of that name would be read as it.
			return fmt.Errorf("%s: generic is reserved: it names the generic adapter a platform with no adapter "+
				"gets, which a set ships and a block does not change; name the platform as the inventory does", at)
		case b.Verified != nil:
			return fmt.Errorf("%s: verified is port49's own claim about its lab (spec §8); an adapter written "+
				"here is unverified until it is contributed and measured, so remove the key", at)
		case b.FallbackNote != nil:
			return fmt.Errorf("%s: fallback_note is port49's own record of a block's fallback text over the set's "+
				"(spec §12); write the text under fallback", at)
		case b.Replace && b.BasedOn != "":
			return fmt.Errorf("%s: replace starts from nothing and based_on from another platform; use one", at)
		case b.BasedOn != "" && shipped:
			return fmt.Errorf("%s: based_on declares a variant under a new name, and %s is a platform this set "+
				"ships; set the keys to change on it directly, or name the variant", at, name)
		case b.BasedOn != "":
			d, ok := builtin[b.BasedOn]
			if !ok {
				return fmt.Errorf("%s: based_on %q is not a platform in set %s; it ships %s", at, b.BasedOn, p.set,
					strings.Join(sortedKeys(builtin), ", "))
			}
			base = d
		case b.Replace || !shipped:
			// A new platform, or one discarded whole, starts from what an
			// unmodeled device gets (spec §8, "Unknown platforms").
			base = generic
		default:
			base = builtin[name]
		}
		d := b.Spec.Over(base)
		// The lab verified the set's adapter, not this one: `platform show`
		// and `export` print the claim only where nothing changed it (spec §8).
		d.Verified = ""
		shippedAs := name
		if b.BasedOn != "" {
			shippedAs = b.BasedOn
		}
		// What the set measured the device refuses, and gives a session on
		// its own, the reports keep whatever the block says (spec §12); text
		// the block gives a level the set measured nothing for is the
		// operator's note, never read as a measurement.
		ref, measured := builtin[shippedAs]
		if measured {
			d = platform.KeepMeasured(d, ref)
		}
		if b.Spec.Fallback != nil {
			for _, level := range sortedKeys(*b.Spec.Fallback) {
				if ref.Fallback[level] == "" {
					if d.FallbackNote == nil {
						d.FallbackNote = map[string]string{}
					}
					d.FallbackNote[level] = d.Fallback[level]
					delete(d.Fallback, level)
				}
			}
			if len(d.Fallback) == 0 {
				d.Fallback = nil
			}
		}
		if err := platform.Validate(name, d); err != nil {
			return err
		}
		// What the set measured about the device is the lab's (spec §8): a
		// block tightens it and never loosens it, `replace: true` and
		// `based_on:` included, since the device behind the name is the same
		// device. A new platform has no measurement to keep, save that no
		// set's privilege attribute is inert anywhere.
		if err := inertBearsNoPrivilege(at, d); err != nil {
			return err
		}
		if measured {
			if err := keepsSetClaims(at, shippedAs, d, ref, p.set); err != nil {
				return err
			}
		}
		set[name] = d
	}
	for name, d := range p.env.Dialects {
		set[name] = d
	}
	p.adapters = set
	return nil
}

// inertBearsNoPrivilege refuses an inert attribute that any adapter port49
// ships lists as bearing privilege (task 7 review C1). Listed inert, a later
// change to it passes the diff ungated and takes a placeholder, so one
// acknowledged edit would blind the gate to it for good.
func inertBearsNoPrivilege(at string, d platform.Dialect) error {
	for _, n := range d.InertAttributes {
		if slices.Contains(platform.PrivilegeAttributeNames(), n) {
			return fmt.Errorf("%s.inert_attributes: %s bears privilege in a platform set port49 ships, so no block "+
				"may list it inert (spec §8)", at, n)
		}
	}
	return nil
}

// keepsSetClaims refuses a merged adapter that loosens what the set's
// adapter it stands for measured about the device (spec §8; task 7 review
// C1, I1): the attributes that bear privilege are a floor, the attributes the
// device takes and the capabilities it authorizes a ceiling; a normalization
// that makes a deny match more is kept, and a claim that makes a rule look
// enforced where the lab found it is not is refused; and the set's
// role_order keeps its order. A block may tighten each.
func keepsSetClaims(at, shippedAs string, d, ref platform.Dialect, version string) error {
	if err := keepsRoleOrder(at, d, ref, version); err != nil {
		return err
	}
	for _, n := range ref.PrivilegeAttributes {
		if !slices.Contains(d.PrivilegeAttributes, n) {
			return fmt.Errorf("%s.privilege_attributes: %s is missing, and platform set %s lists it as bearing "+
				"privilege on %s; a block may add to the list, not remove from it (spec §8)", at, n, version, shippedAs)
		}
	}
	if ref.AcceptedAttributes != nil {
		if d.AcceptedAttributes == nil {
			return fmt.Errorf("%s.accepted_attributes: platform set %s lists what %s takes (%s), and the device "+
				"refuses a session for any other; restate the list, or narrow it (spec §8)", at, version, shippedAs,
				strings.Join(ref.AcceptedAttributes, ", "))
		}
		for _, n := range d.AcceptedAttributes {
			if !slices.Contains(ref.AcceptedAttributes, n) {
				return fmt.Errorf("%s.accepted_attributes: %s is not in platform set %s's list for %s (%s); a block "+
					"may narrow it, not widen it (spec §8)", at, n, version, shippedAs,
					strings.Join(ref.AcceptedAttributes, ", "))
			}
		}
	}
	// A name the set does not hold inert bears privilege on the device, by
	// measurement or because nobody measured it (spec §6, §8; final review M5).
	for _, n := range d.InertAttributes {
		if !slices.Contains(ref.InertAttributes, n) {
			return fmt.Errorf("%s.inert_attributes: %s is not listed inert by platform set %s on %s, so it bears "+
				"privilege there; a block may drop a name from the list, not add one (spec §8)", at, n, version,
				shippedAs)
		}
	}
	for _, c := range d.Supports {
		if !slices.Contains(ref.Supports, c) {
			return fmt.Errorf("%s.supports: %s is not a capability platform set %s measured on %s; a rule would read "+
				"as enforced where the device never asks (spec §8, §9)", at, c, version, shippedAs)
		}
	}
	// The token cuts a command into its stages before any rule reads it, so a
	// different one splits a deny's vector apart: the set measured what the
	// device sends, and there is no tighter value.
	if d.PipeToken != ref.PipeToken {
		return fmt.Errorf("%s.pipe_token: platform set %s measured %q on %s, and another token would split a "+
			"command where the device does not, walking it past a deny; a block may not change it (spec §8)", at,
			version, ref.PipeToken, shippedAs)
	}
	for _, f := range []struct {
		key           string
		set, is, weak bool
	}{
		// true claims a pipe rule or an abbreviation reaches port49 as typed
		{"pipe_authorized", ref.PipeAuthorized, d.PipeAuthorized, true},
		{"expands_abbreviations", ref.ExpandsAbbreviations, d.ExpandsAbbreviations, true},
		// false stops a deny matching the split name or the <cr>-ended vector
		{"splits_interface_names", ref.SplitsInterfaceNames, d.SplitsInterfaceNames, false},
		{"strip_cr", ref.StripCR, d.StripCR, false},
	} {
		if f.is != f.set && f.is == f.weak {
			return fmt.Errorf("%s.%s: platform set %s measured %v on %s, and %v would let a command past a deny "+
				"or a rule the device does not enforce; a block may not loosen it (spec §8)", at, f.key, version,
				f.set, shippedAs, f.is)
		}
	}
	return nil
}

// keepsRoleOrder refuses a merged adapter that ranks two values of a role
// attribute the other way round from the set's adapter it stands for: the
// diff gate reads a move down role_order as a lowering (spec §12), so a
// reversed order would pass a raise as one.
func keepsRoleOrder(at string, d, set platform.Dialect, version string) error {
	for _, attr := range sortedKeys(set.RoleOrder) {
		ranked := set.RoleOrder[attr]
		for i, lower := range ranked {
			for _, higher := range ranked[i+1:] {
				rl, okl := d.RoleRank(attr, lower)
				rh, okh := d.RoleRank(attr, higher)
				if okl && okh && rl > rh {
					return fmt.Errorf("%s.role_order.%s: %s is ranked above %s, and platform set %s ranks it below "+
						"(its lab note); a block may rank a value the set does not, not reorder the set's (spec §8)",
						at, attr, lower, higher, version)
				}
			}
		}
	}
	return nil
}

// mapKeys is a block map's keys, sorted; none where the block leaves it out.
func mapKeys[V any](m *map[string]V) []string {
	if m == nil {
		return nil
	}
	return sortedKeys(*m)
}

// genericPlatform is the name the diff and an acknowledge: entry give the
// generic adapter (spec §12).
const genericPlatform = "generic"

// builtinSet is a built-in platform set by version, copied: the environment's
// where it gives sets, the binary's otherwise.
func (p *Policy) builtinSet(version string) (map[string]platform.Dialect, bool) {
	if p.env.Sets == nil {
		return platform.Set(version)
	}
	set, ok := p.env.Sets[version]
	if !ok {
		return nil, false
	}
	out := make(map[string]platform.Dialect, len(set))
	for name, d := range set {
		out[name] = d
	}
	return out, true
}

// builtinGeneric is a set's generic adapter by version: the environment's
// where it gives sets, and there the unpinned set's where it gives no generic
// for the version, so a test's second set changes the generic adapter only
// where it says so; the binary's otherwise.
func (p *Policy) builtinGeneric(version string) (platform.Dialect, bool) {
	if p.env.Sets == nil {
		return platform.Generic(version)
	}
	if d, ok := p.env.Generics[version]; ok {
		return d, true
	}
	if _, ok := p.env.Sets[version]; !ok {
		return platform.Dialect{}, false
	}
	return platform.Generic(platform.UnpinnedSet)
}

// platformNameShape is how an inventory writes a platform.
var platformNameShape = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// PlatformSet is the platform set the policy renders with.
func (p *Policy) PlatformSet() string { return p.set }

// PlatformNames is every platform the policy renders, sorted: its set's, its
// `platforms:` blocks', and each inventory platform neither adapts, which the
// daemon renders with the set's generic adapter (dialect).
func (p *Policy) PlatformNames() []string {
	names := map[string]bool{}
	for name := range p.adapters {
		names[name] = true
	}
	for _, d := range p.env.Devices {
		if d.Platform != "" {
			names[d.Platform] = true
		}
	}
	return sortedKeys(names)
}

// PlatformSource says where a platform's adapter comes from, as `port49
// platform list` prints it: `built-in`, `overridden` (a block over a built-in,
// or one that replaced it), `variant` (based_on), `local` (a platform the set
// does not ship), or `generic` (an inventory platform nothing adapts, rendered
// with the set's generic adapter).
func (p *Policy) PlatformSource(name string) string {
	b, written := p.overrides[name]
	builtin, _ := p.builtinSet(p.set)
	_, shipped := builtin[name]
	_, adapted := p.adapters[name]
	switch {
	case !adapted:
		return "generic"
	case !written:
		return "built-in"
	case b.BasedOn != "":
		return "variant"
	case shipped:
		return "overridden"
	}
	return "local"
}

func (p *Policy) buildLevels(f file) error {
	p.parents = map[string]string{}
	if len(f.PrivilegeLevels) == 0 {
		p.levels = append([]string(nil), reservedLevels...)
		return nil
	}
	seen := map[string]bool{}
	for i, l := range f.PrivilegeLevels {
		switch {
		case l.Name == "":
			return fmt.Errorf("privilege_levels[%d]: name is required", i)
		case seen[l.Name]:
			return fmt.Errorf("privilege level %q is declared twice", l.Name)
		case l.Parent != "" && slices.Contains(reservedLevels, l.Name):
			return fmt.Errorf("privilege level %q is reserved and has no parent: it is what a parent chain ends at", l.Name)
		}
		seen[l.Name] = true
		p.levels = append(p.levels, l.Name)
		if l.Parent != "" {
			p.parents[l.Name] = l.Parent
		}
	}
	for _, r := range reservedLevels {
		if !seen[r] {
			return fmt.Errorf("privilege_levels must list %s: readonly, operator and admin are reserved and cannot "+
				"be removed, so every shipped platform keeps working (spec §6); put them where they belong in the order", r)
		}
	}
	// The reserved levels keep their relative order, or "higher" would mean
	// one thing in the shipped adapters and another in this file (spec §6).
	for i := 1; i < len(reservedLevels); i++ {
		if slices.Index(p.levels, reservedLevels[i-1]) > slices.Index(p.levels, reservedLevels[i]) {
			return fmt.Errorf("privilege_levels: the reserved levels keep their order: readonly, then operator, then " +
				"admin; custom levels may go anywhere their parent allows (spec §6)")
		}
	}
	for name, parent := range p.parents {
		if !seen[parent] {
			return fmt.Errorf("privilege level %q: parent %q is not declared", name, parent)
		}
	}
	for name := range p.parents {
		cur, hops := name, 0
		for p.parents[cur] != "" {
			cur = p.parents[cur]
			if hops++; hops > len(p.levels) {
				return fmt.Errorf("privilege level %q: its parent chain is a cycle", name)
			}
		}
	}
	// A child ordered below its parent renders higher than levels the
	// max-join ranks above it, so the join stops being monotone in what it
	// renders (spec §6).
	for name, parent := range p.parents {
		if slices.Index(p.levels, name) < slices.Index(p.levels, parent) {
			return fmt.Errorf("privilege level %q must be listed after its parent %q in privilege_levels (spec §6)",
				name, parent)
		}
	}
	return nil
}

// checkBlockOrder refuses a `platforms:` block whose merged adapter does not
// render monotone in the policy's level order (platform.Monotone), which is
// known only once the levels are built. The pinned set's own adapters are
// monotone as shipped; a block is the operator's word, and the diff gate's
// lowering exemption rests on it.
func (p *Policy) checkBlockOrder(file) error {
	for _, name := range sortedKeys(p.overrides) {
		// An entry for a level nobody declared renders nothing: a typo that
		// reads as a change and runs as none (task 7 review I2).
		b := p.overrides[name].Spec
		for _, entries := range []struct {
			key    string
			levels []string
		}{{"privilege", mapKeys(b.Privilege)}, {"ceiling_levels", mapKeys(b.CeilingLevels)},
			{"unreachable", mapKeys(b.Unreachable)}, {"fallback", mapKeys(b.Fallback)}} {
			for _, l := range entries.levels {
				if !slices.Contains(p.levels, l) {
					return fmt.Errorf("platforms.%s.%s.%s: level %s is not declared; the levels are %s", name,
						entries.key, l, l, strings.Join(p.levels, ", "))
				}
			}
		}
		if err := platform.Monotone(name, p.adapters[name], p.levels); err != nil {
			return err
		}
	}
	return nil
}

func (p *Policy) checkLevel(name string) error {
	if name == "" || slices.Contains(p.levels, name) {
		return nil
	}
	return fmt.Errorf("%q is not a privilege level; the levels are %s", name, strings.Join(p.levels, ", "))
}

func (p *Policy) buildRoles(f file) error {
	p.roles = map[string]*Role{}
	for i, r := range f.Roles {
		if r.Name == "" {
			return fmt.Errorf("roles[%d]: name is required", i)
		}
		if _, dup := p.roles[r.Name]; dup {
			return fmt.Errorf("role %q is declared twice", r.Name)
		}
		if err := p.checkLevel(r.Privilege); err != nil {
			return fmt.Errorf("role %q: privilege: %w", r.Name, err)
		}
		role := &Role{Name: r.Name, Privilege: r.Privilege, Reason: r.Reason, Attributes: r.Attributes}
		// A rule is named by its list and position, never quoted: a refusal
		// goes to logs, and the refused file's own redaction patterns never
		// loaded (spec §5.8).
		for _, list := range []struct {
			name string
			in   []string
			out  *[]string
			deny bool
		}{{"permit", r.Permit, &role.Permit, false}, {"deny", r.Deny, &role.Deny, true}} {
			for i, rule := range list.in {
				if err := checkRule(rule, list.deny); err != nil {
					return fmt.Errorf("role %q: %s #%d: %w", r.Name, list.name, i+1, err)
				}
				if err := p.checkClasses(rule); err != nil {
					return fmt.Errorf("role %q: %s #%d: %w", r.Name, list.name, i+1, err)
				}
				if list.deny {
					if err := p.checkDenyClasses(rule); err != nil {
						return fmt.Errorf("role %q: %s #%d: %w", r.Name, list.name, i+1, err)
					}
				}
				*list.out = append(*list.out, engine.CanonicalRule(rule))
			}
		}
		if r.Pipe != nil {
			role.Pipe = []string{}
			for i, rule := range r.Pipe.Permit {
				if err := checkRule(rule, false); err != nil {
					return fmt.Errorf("role %q: pipe #%d: %w", r.Name, i+1, err)
				}
				if err := p.checkClasses(rule); err != nil {
					return fmt.Errorf("role %q: pipe #%d: %w", r.Name, i+1, err)
				}
				role.Pipe = append(role.Pipe, engine.CanonicalRule(rule))
			}
		}
		if err := p.checkAttributes(r.Attributes); err != nil {
			return fmt.Errorf("role %q: %w", r.Name, err)
		}
		p.roles[r.Name] = role
	}
	return nil
}

// checkRule parses a rule and refuses a regex that buys specificity by how it
// is written rather than by what it constrains (spec §4; §14, "Rank lint"):
// one equivalent to `*` ranks 2 where `*` ranks 1, and one equivalent to a
// literal ranks 2 where the word ranks 3. In a deny it also refuses a regex
// that turns case-insensitivity off anywhere in it (spec §3 rule 3, §4): a
// differently-cased command would walk past it. A permit may opt out, since
// that only narrows what it permits.
func checkRule(rule string, deny bool) error {
	terms, err := engine.ParseRule(rule)
	if err != nil {
		return err
	}
	for i, t := range terms {
		if t.Kind != engine.Regex {
			continue
		}
		if deny && caseSensitive(t.Text) {
			return fmt.Errorf("term %d turns case-insensitivity off; port49 matches case-insensitively, and a "+
				"case-sensitive deny could be walked past by changing case (spec §4)", i+1)
		}
		if simpler, ok := rankLint(t.Text); ok {
			if simpler != anyTerm {
				// The word itself is the term's text: not quoted.
				return fmt.Errorf("term %d is a regex that is one word; write the word instead (spec §4)", i+1)
			}
			return fmt.Errorf("term %d is a regex that is %s; write that instead (spec §4)", i+1, simpler)
		}
	}
	return nil
}

// checkAttributes validates an attribute block: keyed by `all` or by a
// platform port49 ships or the inventory names, each attribute structurally
// valid (engine.CheckAttribute).
func (p *Policy) checkAttributes(attrs map[string][]string) error {
	for key, list := range attrs {
		if _, adapted := p.adapters[key]; key != "all" && !adapted && !p.inInventory(key) {
			return fmt.Errorf("attributes: %q is neither `all` nor a platform port49 ships or the inventory names", key)
		}
		for i, a := range list {
			at := fmt.Sprintf("attributes.%s[%d]", key, i)
			if err := engine.CheckAttribute(a); err != nil {
				return fmt.Errorf("%s: %w", at, err)
			}
			if err := p.checkPlaceholder(at, key, a); err != nil {
				return err
			}
		}
	}
	return nil
}

// checkPlaceholder allows a placeholder only in an attribute listed inert on
// its platform key, or under `all` on every platform port49 ships and the
// inventory names (spec §6). Anywhere else the device would get whatever the
// mint fills in, which no review tool sees: a level, or a principal's text in
// a session-only device's own allow-list.
func (p *Policy) checkPlaceholder(at, key, a string) error {
	if !slices.ContainsFunc(engine.Placeholders, func(v string) bool { return strings.Contains(a, v) }) {
		return nil
	}
	name := a[:strings.IndexAny(a, "=*")]
	if slices.Contains(engine.NumericAttributes, name) {
		return fmt.Errorf("%s: %s is a number and takes no placeholder: a mint fills in an identity, which is "+
			"never a value the device takes, and on IOS-XE a refused session locks out SSH (spec §6)", at, name)
	}
	if slices.Contains(platform.PrivilegeAttributeNames(), name) || slices.ContainsFunc(sortedKeys(p.adapters),
		func(n string) bool { return slices.Contains(p.adapters[n].PrivilegeAttributes, name) }) {
		return fmt.Errorf("%s: %s carries privilege and takes no placeholder: the device would get "+
			"whatever the mint fills in, which no review tool can see (spec §6)", at, name)
	}
	platforms := []string{key}
	if key == "all" {
		platforms = sortedKeys(p.platforms())
		for _, d := range p.env.Devices {
			if !slices.Contains(platforms, d.Platform) {
				platforms = append(platforms, d.Platform)
			}
		}
	}
	for _, name2 := range platforms {
		if p.dialect(name2).BearsPrivilege(name) {
			return fmt.Errorf("%s: %s is not listed inert on %s, so it takes no placeholder: only an "+
				"attribute an adapter holds to carry no privilege may (spec §6)", at, name, platformName(name2))
		}
	}
	return nil
}

func (p *Policy) inInventory(platformName string) bool {
	for _, d := range p.env.Devices {
		if d.Platform == platformName {
			return true
		}
	}
	return false
}

func (p *Policy) buildScopes(f file) error {
	p.scopes = map[string]*Scope{}
	for i, s := range f.Scopes {
		if s.Name == "" {
			return fmt.Errorf("scopes[%d]: name is required", i)
		}
		if _, dup := p.scopes[s.Name]; dup {
			return fmt.Errorf("scope %q is declared twice", s.Name)
		}
		sc := &Scope{Name: s.Name, Match: s.Match, OnMissing: s.OnMissing, SecurityLog: s.SecurityLog,
			Attached: map[string][]string{"humans": s.AttachedRoles.Humans, "machines": s.AttachedRoles.Machines},
			res:      map[string]*regexp.Regexp{}, onMissingDeclared: s.OnMissing != ""}
		// Keys and comparisons in a fixed order, so a scope with several
		// faults is refused for the same one on every load.
		for _, key := range sortedKeys(s.Match) {
			v := s.Match[key]
			if key == "" {
				return fmt.Errorf("scope %q: a match key is empty", s.Name)
			}
			if v.Equal == nil && v.Cmp == nil {
				return fmt.Errorf("scope %q: match.%s: a match value is a string, a list or a comparison", s.Name, key)
			}
			for _, op := range sortedKeys(v.Cmp) {
				bound := v.Cmp[op]
				if op == "re" {
					re, err := regexp.Compile(bound)
					if err != nil {
						return fmt.Errorf("scope %q: match.%s.re does not compile: %s", s.Name, key,
							platform.RegexpProblem(err))
					}
					sc.res[key] = re
				} else if bound == "" {
					return fmt.Errorf("scope %q: match.%s.%s needs a version to compare against", s.Name, key, op)
				}
			}
		}
		deny := false
		for _, domain := range []string{"humans", "machines"} {
			for _, r := range sc.Attached[domain] {
				role, ok := p.roles[r]
				if !ok {
					return fmt.Errorf("scope %q: attached_roles.%s: role %q is not declared", s.Name, domain, r)
				}
				deny = deny || len(role.Deny) > 0
			}
		}
		switch s.OnMissing {
		case "include", "exclude":
		case "":
			// A deny-bearing scope that silently excludes a device with no
			// version data lifts a mitigation on a broken sync (spec §5.5), so
			// the direction has to be written down, not defaulted. A scope with
			// no match key selects every device and has nothing to miss.
			// buildGrants checks the other way a scope carries a deny.
			if deny && len(s.Match) > 0 {
				return fmt.Errorf("scope %q attaches a deny: declare on_missing (include assumes a device with no "+
					"data for the match is affected, which is the safe direction for a mitigation; spec §5.5)", s.Name)
			}
			sc.OnMissing = "exclude"
		default:
			return fmt.Errorf("scope %q: on_missing is include or exclude", s.Name)
		}
		p.scopes[s.Name] = sc
	}
	return nil
}

var serviceAccount = regexp.MustCompile(`^system:serviceaccount:[^:\s]+:[^:\s]+$`)

// identityDomain classifies an identity string by its form (spec §2), which is
// how CI tells a human from a machine without a verifier to ask. A string in
// no recognized form is itself a load error.
func identityDomain(id string) (string, error) {
	if strings.IndexFunc(id, func(r rune) bool { return r < 0x21 || r > 0x7e }) >= 0 {
		return "", fmt.Errorf("identity %q must be printable ASCII with no spaces", id)
	}
	switch {
	case strings.HasPrefix(id, "user:") && len(id) > len("user:"):
		email := strings.TrimPrefix(id, "user:")
		if !strings.Contains(email, "@") {
			return "", fmt.Errorf("identity %q: the one human verifier is an x509 certificate, whose principal is "+
				"`user:<email>` (spec §2)", id)
		}
		if lower := strings.ToLower(email); lower != email {
			return "", fmt.Errorf("identity %q must be lower-case, because certificate identities are compared "+
				"lower-case: write \"user:%s\"", id, lower)
		}
		return "humans", nil
	case strings.HasPrefix(id, "spiffe://") && len(id) > len("spiffe://"),
		serviceAccount.MatchString(id),
		strings.HasPrefix(id, "app:") && len(id) > len("app:"):
		return "machines", nil
	}
	return "", fmt.Errorf("identity %q is in no recognized form: user:<email>, spiffe://…, "+
		"system:serviceaccount:<namespace>:<name>, or app:<client_id> (spec §2)", id)
}

func (p *Policy) buildSubjects(f file) error {
	p.subs, p.byID = map[string]*Subject{}, map[string]string{}
	users := map[string]string{}
	for i, s := range f.Subjects {
		if s.Name == "" {
			return fmt.Errorf("subjects[%d]: name is required", i)
		}
		if _, dup := p.subs[s.Name]; dup {
			return fmt.Errorf("subject %q is declared twice", s.Name)
		}
		sub := &Subject{Name: s.Name, Group: s.Group, Identity: s.Identity, Username: s.Username,
			Enable: s.Enable, TokenTTL: s.TokenTTL, API: s.API}
		switch {
		case s.Group != "" && len(s.Identity) > 0:
			return fmt.Errorf("subject %q: a subject is a group or a list of identities, not both (spec §2)", s.Name)
		case s.Group == "" && len(s.Identity) == 0:
			return fmt.Errorf("subject %q: give it a group or an identity list (spec §2)", s.Name)
		case s.Group != "":
			// A group is resolved through the directory, whose members are
			// people, and each member's username comes from the same query
			// (spec §2). Declaring one would give every member the same name.
			sub.Domain = "humans"
			if s.Username != "" {
				return fmt.Errorf("subject %q: a group's usernames come from the directory, one per member; "+
					"remove username", s.Name)
			}
		}
		for _, id := range s.Identity {
			domain, err := identityDomain(id)
			if err != nil {
				return fmt.Errorf("subject %q: %w", s.Name, err)
			}
			if sub.Domain != "" && sub.Domain != domain {
				return fmt.Errorf("subject %q lists a human and a machine identity; trust domains must stay "+
					"distinguishable, so give each its own subject (spec §2)", s.Name)
			}
			sub.Domain = domain
			if other, dup := p.byID[id]; dup {
				if other == s.Name {
					return fmt.Errorf("identity %q is listed twice in subject %q; list it once", id, s.Name)
				}
				return fmt.Errorf("identity %q is listed by both subject %q and subject %q; a principal must "+
					"resolve to one subject", id, other, s.Name)
			}
			p.byID[id] = s.Name
		}
		// Whether a username is required depends on whether a grant names the
		// subject, which checkMinters settles once the grants are read.
		if len(s.Identity) > 0 && s.Username != "" {
			if !token.CanonicalUsername(s.Username) {
				return fmt.Errorf("subject %q: username %q must be printable ASCII and already canonical — lower "+
					"case, no DOMAIN\\ prefix, no @suffix — because the daemon looks tokens up by the canonical form "+
					"of what the device sends (spec §2)", s.Name, s.Username)
			}
			if other, dup := users[s.Username]; dup {
				return fmt.Errorf("subjects %q and %q both claim username %q; usernames must be unique across "+
					"subjects, or two principals share one (nas, username) context (spec §2)", other, s.Name, s.Username)
			}
			users[s.Username] = s.Name
		}
		switch s.Enable {
		case "":
			sub.Enable = "none"
		case "none", "token", "auto":
		default:
			return fmt.Errorf("subject %q: enable must be none, auto or token (spec §7)", s.Name)
		}
		if s.TokenTTL != 0 && (s.TokenTTL < minTokenTTL || s.TokenTTL > maxTokenTTL) {
			return fmt.Errorf("subject %q: token_ttl must be between %s and %s (design §8); got %s",
				s.Name, minTokenTTL, maxTokenTTL, s.TokenTTL)
		}
		for i, r := range s.API {
			if !slices.Contains(apiRights, r) {
				return fmt.Errorf("subject %q: api[%d] is not a right; the rights are %s", s.Name, i,
					strings.Join(apiRights, ", "))
			}
		}
		p.subs[s.Name] = sub
	}
	return nil
}

// parseExpires reads a grant's `expires`: a date is the start of that day,
// UTC — the grant has stopped matching by the time the day begins — and a
// full RFC 3339 time is exact.
func parseExpires(s string) (time.Time, error) {
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t, nil
	}
	return time.Parse(time.RFC3339, s)
}

func (p *Policy) buildGrants(f file) error {
	seen := map[string]int{} // subject, scope and sorted roles → first row
	for i, g := range f.Grants {
		// Grants have no name, and an index alone means counting rows by hand
		// in a file of hundreds; the row names what it grants.
		row := fmt.Sprintf("grants[%d] (subject %s, scope %s)", i, g.Subject, g.Scope)
		if _, ok := p.subs[g.Subject]; !ok {
			return fmt.Errorf("%s: subject %q is not declared", row, g.Subject)
		}
		if _, ok := p.scopes[g.Scope]; !ok {
			if g.Scope == "all_devices" {
				return fmt.Errorf("%s: scope all_devices is not declared; it is an ordinary scope since "+
					"plan 4 (spec §5.5) — add `scopes: [{name: all_devices, match: {}}]`", row)
			}
			return fmt.Errorf("%s: scope %q is not declared", row, g.Scope)
		}
		if len(g.Roles) == 0 {
			return fmt.Errorf("%s: a grant needs at least one role", row)
		}
		for j, r := range g.Roles {
			if _, ok := p.roles[r]; !ok {
				return fmt.Errorf("%s: role %q is not declared", row, r)
			}
			if slices.Contains(g.Roles[:j], r) {
				return fmt.Errorf("%s: role %q is listed twice; list it once", row, r)
			}
		}
		if err := p.checkLevel(g.MaxPrivilege); err != nil {
			return fmt.Errorf("%s: max_privilege: %w", row, err)
		}
		if g.MaxPrivilege != "" && !p.numberedAnywhere(g.MaxPrivilege) {
			return fmt.Errorf("%s: max_privilege %s has no priv-lvl number on any platform, so no token "+
				"could carry it; use a level a platform numbers (spec §5.3, §6)", row, g.MaxPrivilege)
		}
		// A deny reaches a scope through a grant as surely as through
		// attached_roles, and a broken sync that drops the device from the
		// scope lifts it the same way (spec §5.5).
		if sc := p.scopes[g.Scope]; len(sc.Match) > 0 && !sc.onMissingDeclared {
			for _, r := range g.Roles {
				if len(p.roles[r].Deny) > 0 {
					return fmt.Errorf("%s: role %q carries a deny onto scope %q: declare on_missing on the "+
						"scope (include assumes a device with no data for the match is affected, the safe direction "+
						"for a mitigation; exclude says the grant must be earned by data; spec §5.5)", row, r, g.Scope)
				}
			}
		}
		// Roles are kept sorted, so nothing a grant reports — the mint
		// record, explain, access review — depends on how the file lists them.
		roles := slices.Clone(g.Roles)
		slices.Sort(roles)
		// Two grants that differ only in ceiling, expiry or attributes would
		// leave file order to decide which one an attribute comes from, and
		// reordering grants must not change a decision (spec §5.4).
		key := g.Subject + "\x00" + g.Scope + "\x00" + strings.Join(roles, "\x00")
		if first, dup := seen[key]; dup {
			return fmt.Errorf("%s repeats grants[%d]: the same subject, scope and roles; merge the two rows "+
				"into one", row, first)
		}
		seen[key] = i
		grant := &Grant{Subject: g.Subject, Scope: g.Scope, Roles: roles, MaxPrivilege: g.MaxPrivilege,
			Attributes: g.Attributes}
		if g.Expires != "" {
			t, err := parseExpires(g.Expires)
			if err != nil {
				return fmt.Errorf("%s: expires is a date (2026-12-01) or an RFC 3339 time", row)
			}
			grant.Expires = t
		}
		if err := p.checkAttributes(g.Attributes); err != nil {
			return fmt.Errorf("%s: %w", row, err)
		}
		p.grants = append(p.grants, grant)
	}
	return nil
}

// checkMinters requires what minting needs of every subject a grant names: a
// username for an identity-list subject, which has no directory to derive one
// from, and a token_ttl. A subject no grant names mints nothing — spec §2's
// API-only subjects — and needs neither.
func (p *Policy) checkMinters(file) error {
	for _, g := range p.grants {
		s := p.subs[g.Subject]
		if len(s.Identity) > 0 && s.Username == "" {
			// A machine has no directory entry, so it declares its username
			// (spec §2). A literal human identity declares one too until plan 7
			// derives it through the certificate-to-directory mapping.
			return fmt.Errorf("subject %q: username is required: a grant names it, and an identity-list subject "+
				"has no directory to derive one from (spec §2; §14, \"Username resolution\")", s.Name)
		}
		if s.TokenTTL == 0 {
			return fmt.Errorf("subject %q: token_ttl is required: a grant names it, so it mints device tokens, "+
				"which live %s to %s (design §8)", s.Name, minTokenTTL, maxTokenTTL)
		}
	}
	return nil
}

func (p *Policy) buildTests(f file) error {
	for i, t := range f.Tests {
		who := "subject " + t.Subject
		if t.Subject == "" {
			who = "principal " + t.Principal
		}
		// The command is operator text and is never quoted: a test exercising
		// a secret-bearing command is the test the shadow gate asks for
		// beside such a deny (spec §5.8). The index finds it.
		row := fmt.Sprintf("tests[%d] (%s, device %s)", i, who, t.Device)
		switch {
		case (t.Subject == "") == (t.Principal == ""):
			return fmt.Errorf("%s: name a subject or a principal, one of the two", row)
		case t.Subject != "" && p.subs[t.Subject] == nil:
			return fmt.Errorf("%s: subject %q is not declared", row, t.Subject)
		case t.Device == "":
			return fmt.Errorf("%s: device is required", row)
		case strings.TrimSpace(t.Command) == "" && t.Level == "" && t.MaxPrivilege == "" && t.PrivLvl == "" &&
			t.Enable == "" && t.Reply == nil && t.API == nil:
			return fmt.Errorf("%s: command is required, or a session test's level, max_privilege, priv_lvl, enable, "+
				"reply or api", row)
		case strings.TrimSpace(t.Command) == "" && (t.Expect != "" || t.Reason != ""):
			return fmt.Errorf("%s: a session test takes no expect or reason: it passes where the subject is "+
				"minted a token with the level and ceiling it names", row)
		case strings.TrimSpace(t.Command) != "" && t.Expect != "permit" && t.Expect != "deny":
			return fmt.Errorf("%s: expect is permit or deny", row)
		case t.Reason != "" && !decision.Known(decision.Reason(t.Reason)):
			return fmt.Errorf("%s: the reason is not in spec §5.7's vocabulary", row)
		}
		// A principal no verifier could produce resolves to no subject, and
		// an `expect: deny` test on it passes without testing anything.
		if t.Principal != "" {
			if _, err := identityDomain(t.Principal); err != nil {
				return fmt.Errorf("%s: principal: %w", row, err)
			}
		}
		if _, ok := p.device(t.Device); !ok {
			return fmt.Errorf("%s: device %q is not in the inventory", row, t.Device)
		}
		if err := p.checkLevel(t.Level); err != nil {
			return fmt.Errorf("%s: level: %w", row, err)
		}
		if t.MaxPrivilege != NoCeiling {
			if err := p.checkLevel(t.MaxPrivilege); err != nil {
				return fmt.Errorf("%s: max_privilege: %w", row, err)
			}
		}
		if n, err := strconv.Atoi(t.PrivLvl); t.PrivLvl != "" && t.PrivLvl != NoCeiling && (err != nil || n < 0 || n > 15) {
			return fmt.Errorf("%s: priv_lvl is a number from 0 to 15, or none", row)
		}
		if t.Enable != "" && t.Enable != "none" && t.Enable != "auto" && t.Enable != "token" {
			return fmt.Errorf("%s: enable is none, auto or token", row)
		}
		test := Test{Subject: t.Subject, Principal: t.Principal, Device: t.Device, Command: t.Command,
			Expect: t.Expect, Reason: t.Reason, Level: t.Level, MaxPrivilege: t.MaxPrivilege, PrivLvl: t.PrivLvl,
			Enable: t.Enable, AssertsReply: t.Reply != nil}
		if t.Reply != nil {
			test.Reply = append([]string{}, (*t.Reply)...)
		}
		if t.API != nil {
			for j, r := range *t.API {
				if !slices.Contains(apiRights, r) {
					return fmt.Errorf("%s: api[%d] is not a right; the rights are %s", row, j, strings.Join(apiRights, ", "))
				}
			}
			test.API, test.AssertsAPI = slices.Clone(*t.API), true
			slices.Sort(test.API)
		}
		p.tests = append(p.tests, test)
	}
	return nil
}

func (p *Policy) buildAcknowledgments(f file) error {
	for i, a := range f.Acknowledge {
		byRule, byAdapter := a.Role != "" || a.Rule != "", a.Platform != "" || a.Field != "" || a.Sha256 != ""
		switch {
		case byRule == byAdapter:
			return fmt.Errorf("acknowledge[%d]: name a deny by role and rule, or an adapter edit by platform and "+
				"field, one of the two (spec §12)", i)
		case byRule && (a.Role == "" || a.Rule == ""):
			return fmt.Errorf("acknowledge[%d]: role and rule are required: the entry names the exact deny it "+
				"acknowledges (spec §12)", i)
		case byAdapter && (a.Platform == "" || !slices.Contains(platform.SpecKeys(), a.Field)):
			return fmt.Errorf("acknowledge[%d]: platform and field are required, and field is one of an adapter's "+
				"keys: %s (spec §8, §12)", i, strings.Join(platform.SpecKeys(), ", "))
		case byAdapter && !sha256Hex.MatchString(a.Sha256):
			return fmt.Errorf("acknowledge[%d]: sha256 is required: the digest `port49 policy diff` prints for the "+
				"key's new value, 64 lower-case hex digits, so the entry acknowledges that edit and no later one "+
				"(spec §12)", i)
		case strings.TrimSpace(a.Reason) == "":
			return fmt.Errorf("acknowledge[%d]: reason is required: review reads it beside the change it "+
				"acknowledges (spec §12)", i)
		}
		p.acked = append(p.acked, Acknowledgment(a))
	}
	return nil
}

// sha256Hex is the shape of an adapter acknowledgment's digest.
var sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)

// hasDeny reports whether any role in the policy denies rule as written:
// an acknowledge: entry naming it removed nothing (spec §12).
func (p *Policy) hasDeny(rule string) bool {
	for _, r := range p.roles {
		if slices.Contains(r.Deny, rule) {
			return true
		}
	}
	return false
}

// Acknowledgments returns the file's acknowledge: entries.
func (p *Policy) Acknowledgments() []Acknowledgment { return p.acked }

// acknowledgment is the entry naming a deny, if any.
func (p *Policy) acknowledgment(role, rule string) (Acknowledgment, bool) {
	for _, a := range p.acked {
		if a.Role == role && a.Rule == rule {
			return a, true
		}
	}
	return Acknowledgment{}, false
}

func (p *Policy) device(name string) (admission.Device, bool) {
	for _, d := range p.env.Devices {
		if d.Name == name {
			return d, true
		}
	}
	return admission.Device{}, false
}

// platforms is every dialect this policy can meet: its pinned set, the
// environment's own table over it. The map is the policy's own; callers read
// it and never write it.
func (p *Policy) platforms() map[string]platform.Dialect { return p.adapters }

// checkClasses refuses a rule naming a class no platform defines. That is
// the policy's own error, a typo, rather than a device's: no inventory could
// make it compile. A class some platforms define and others do not is a joint
// check, and quarantines the devices on the others (Task 10; spec §10).
func (p *Policy) checkClasses(rule string) error {
	terms, err := engine.ParseRule(rule)
	if err != nil {
		return err
	}
	for i, t := range terms {
		if t.Kind != engine.Class {
			continue
		}
		defined := false
		for _, d := range p.platforms() {
			if _, ok := d.EntityClasses[t.Text]; ok {
				defined = true
			}
		}
		if !defined {
			return fmt.Errorf("term %d names a class which no platform defines; a class is a platform's (spec §4, §8)",
				i+1)
		}
	}
	return nil
}

// checkDenyClasses refuses a deny naming a class whose pattern turns
// case-insensitivity off on any platform: a class pattern is compiled
// case-insensitively (engine.compileTerm), and one that opts out lets a
// differently-cased interface name walk past the deny (spec §3 rule 3, §4).
// A deny's own regex term is checkRule's; a class's patterns are an
// adapter's, the operator's since plan 5, so they are checked here where the
// adapters are known. A permit may opt out, since that only narrows it.
func (p *Policy) checkDenyClasses(rule string) error {
	terms, err := engine.ParseRule(rule)
	if err != nil {
		return err
	}
	for i, t := range terms {
		if t.Kind != engine.Class {
			continue
		}
		for _, name := range sortedKeys(p.adapters) {
			for _, pattern := range p.adapters[name].EntityClasses[t.Text] {
				if caseSensitive(pattern) {
					return fmt.Errorf("term %d names a class whose pattern on %s turns case-insensitivity off; "+
						"port49 matches case-insensitively, and a differently-cased name would walk past the deny "+
						"(spec §4); remove the (?-i) from that class under platforms.%s.entity_classes", i+1, name,
						name)
				}
			}
		}
	}
	return nil
}

// normalizeFor is the part of a platform's dialect a blob carries (spec
// §5.1.2). A platform port49 has a dialect for that declares no command
// authorization is session-only (Junos: L18, decision 21), and no command
// rule is widened for it; the generic adapter's `session` alone is assumed,
// not measured, so an unknown platform is not.
func (p *Policy) normalizeFor(name string) engine.Normalize {
	d := p.dialect(name)
	_, known := p.platforms()[name]
	return engine.Normalize{PipeToken: d.PipeToken, PipeAuthorized: d.PipeAuthorized,
		StripCR: d.StripCR, ExpandsAbbreviations: d.ExpandsAbbreviations, SplitsInterfaceNames: d.SplitsInterfaceNames,
		SessionOnly: known && !d.Authorizes("commands")}
}

// numberedAnywhere reports whether some platform gives level a priv-lvl
// number above 0, following the parent chain: a ceiling none can number is the
// policy's own error, like a class none defines.
func (p *Policy) numberedAnywhere(level string) bool {
	for _, d := range p.platforms() {
		// The token reads priv-lvl 0 as no ceiling (resolve), so 0 numbers nothing.
		if n, ok := p.privLvl(d, level); ok && n > 0 {
			return true
		}
	}
	return false
}

// privLvl is the priv-lvl number a platform gives a level, following the
// level's parent chain to the first level the platform numbers (spec §6,
// `parent:`).
func (p *Policy) privLvl(dialect platform.Dialect, level string) (uint8, bool) {
	for l := level; l != ""; l = p.parents[l] {
		if n, ok := dialect.PrivLvl(l); ok {
			return n, true
		}
	}
	return 0, false
}

// dialect is the platform's dialect in this policy's set, or that set's
// generic adapter for a platform it has none for (spec §8, "Unknown
// platforms").
func (p *Policy) dialect(name string) platform.Dialect {
	if d, ok := p.adapters[name]; ok {
		return d
	}
	d, _ := p.builtinGeneric(p.set)
	return d
}

// ConfigDialect is the adapter `port49 devices check-config` holds a device of
// the platform to: the policy's, over the set's adapter the platform stands
// for — its own, or the one its block is based_on — as the floor
// (platform.ConfigFloor). A block's device_config is what `platform show`
// prints, and a block that rewrote a set line to end in `none` would
// otherwise have the check require the unsafe line; the set's lines and
// checks apply whatever the block says. A platform no set ships has no floor.
// A set that cannot be read is an error, never an adapter without its floor.
func (p *Policy) ConfigDialect(platformName string) (platform.Dialect, error) {
	d := p.dialect(platformName)
	shippedAs := platformName
	if b, ok := p.overrides[platformName]; ok && b.BasedOn != "" {
		shippedAs = b.BasedOn
	}
	builtin, ok := p.builtinSet(p.set)
	if !ok {
		return platform.Dialect{}, fmt.Errorf("platform set %s cannot be read, so the lines and checks it holds a "+
			"device to are unknown", p.set)
	}
	if ref, ok := builtin[shippedAs]; ok {
		return platform.ConfigFloor(d, ref), nil
	}
	return d, nil
}

// SubjectOf names the subject a principal resolves to, by its identity lists.
// A group subject is matched through the directory, which is plan 7's.
func (p *Policy) SubjectOf(principal string) (string, bool) {
	name, ok := p.byID[principal]
	return name, ok
}

// Subject returns a declared subject.
func (p *Policy) Subject(name string) (*Subject, bool) {
	s, ok := p.subs[name]
	return s, ok
}

// Grants returns the grant rows naming subject, in file order.
func (p *Policy) Grants(subject string) []*Grant {
	var out []*Grant
	for _, g := range p.grants {
		if g.Subject == subject {
			out = append(out, g)
		}
	}
	return out
}

// Devices is the inventory the policy was loaded against.
func (p *Policy) Devices() []admission.Device { return p.env.Devices }

// Tests returns the file's tests.
func (p *Policy) Tests() []Test { return p.tests }

// sortedKeys is a map's keys in order, for walking a map where the order can
// show: which of several faults is reported.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// caseSensitive reports whether a regex term, compiled the way the matcher
// compiles it, has any literal or character class that does not fold case
// and holds a rune that has another case: what a `(?-i)` or any flag group
// clearing `i` leaves behind, however it is spelled. A rune with no other
// case has nothing to fold, which is what `[.]` or `[_]` is rewritten to.
func caseSensitive(body string) bool {
	re, err := syntax.Parse("(?i)"+body, syntax.Perl)
	if err != nil {
		return false // ParseRule has already refused it
	}
	var walk func(*syntax.Regexp) bool
	walk = func(re *syntax.Regexp) bool {
		if re.Flags&syntax.FoldCase == 0 {
			switch re.Op {
			case syntax.OpLiteral:
				if slices.ContainsFunc(re.Rune, cased) {
					return true
				}
			case syntax.OpCharClass:
				for i := 0; i+1 < len(re.Rune); i += 2 {
					for r := re.Rune[i]; r <= re.Rune[i+1]; r++ {
						if cased(r) {
							return true
						}
					}
				}
			}
		}
		return slices.ContainsFunc(re.Sub, walk)
	}
	return walk(re)
}

// cased reports whether r has another case to fold to.
func cased(r rune) bool { return unicode.SimpleFold(r) != r }
