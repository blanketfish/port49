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
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/rhwendt/port49/internal/admission"
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
	// Dialects replaces the built-in platform table when non-nil. Tests use it;
	// plan 5's layered adapters will too.
	Dialects map[string]platform.Dialect
	// EnableUsernames is config's resolved table (config.Config); a platform
	// with no entry is `principal`.
	EnableUsernames map[string]string
}

// Policy is a loaded, validated policy file.
type Policy struct {
	// Bundle names this policy on every blob and record: the sha256 of the
	// file's bytes, until plan 6 publishes versioned bundles (spec §5.7).
	Bundle string

	levels  []string          // the declared ordering, lowest first
	parents map[string]string // level → parent, for rendering
	scopes  map[string]*Scope
	roles   map[string]*Role
	subs    map[string]*Subject
	byID    map[string]string // identity → subject
	grants  []*Grant
	tests   []Test
	env     Env
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

// Test is one `tests:` entry (spec §11, §12).
type Test struct {
	Subject, Principal, Device, Command, Expect, Reason string
}

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
		if strings.Contains(err.Error(), "time.Duration") {
			return nil, fmt.Errorf("%w; durations need a unit, e.g. 60s", err)
		}
		return nil, err
	}
	// A second document would be ignored by a single Decode, and an ignored
	// `---` followed by a `scopes:` block is a policy that reads as scoped and
	// is not.
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return nil, errors.New("the policy file must be one YAML document; remove the `---` separator and " +
			"everything after it, or merge it into the first document")
	}
	p := &Policy{Bundle: engine.HashOf(raw), env: env}
	for _, step := range []func(file) error{p.buildLevels, p.buildRoles, p.buildScopes, p.buildSubjects,
		p.buildGrants, p.buildTests} {
		if err := step(f); err != nil {
			return nil, err
		}
	}
	// An empty policy fails closed, but a truncated file or the wrong one would
	// go unnoticed until the first refused mint.
	if len(p.subs) == 0 {
		return nil, errors.New("declares no subjects, so nobody can mint; is this the right file?")
	}
	return p, nil
}

// refusedKeys names the plan that reads a key this build does not, before the
// strict decode can say only that the field is unknown. Spec §11's example
// carries two of them.
func refusedKeys(raw []byte) error {
	var loose struct {
		PlatformSet any              `yaml:"platform_set"`
		KeyGroups   any              `yaml:"key_groups"`
		Platforms   any              `yaml:"platforms"`
		Roles       []map[string]any `yaml:"roles"`
	}
	if err := yaml.Unmarshal(raw, &loose); err != nil {
		return nil // the strict decode reports it, with a line number
	}
	switch {
	case loose.PlatformSet != nil:
		return errors.New("platform_set: pinning the platform set is plan 5's; remove the key until it lands")
	case loose.KeyGroups != nil:
		return errors.New("key_groups: key groups live in the inventory file (inventory_file) until plan 6 " +
			"moves them to the policy repository; move the block there")
	case loose.Platforms != nil:
		return errors.New("platforms: user platform definitions are plan 5's; the built-in adapters apply")
	}
	for _, r := range loose.Roles {
		if _, ok := r["max_session_age"]; ok {
			return fmt.Errorf("role %v: max_session_age per role is plan 7's; session.max_session_age_default "+
				"in port49d.yaml applies to every role until then", r["name"])
		}
	}
	return nil
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
		for _, list := range []struct {
			in  []string
			out *[]string
		}{{r.Permit, &role.Permit}, {r.Deny, &role.Deny}} {
			for _, rule := range list.in {
				if err := checkRule(rule); err != nil {
					return fmt.Errorf("role %q: %w", r.Name, err)
				}
				if err := p.checkClasses(rule); err != nil {
					return fmt.Errorf("role %q: %w", r.Name, err)
				}
				*list.out = append(*list.out, engine.CanonicalRule(rule))
			}
		}
		if r.Pipe != nil {
			role.Pipe = []string{}
			for _, rule := range r.Pipe.Permit {
				if err := checkRule(rule); err != nil {
					return fmt.Errorf("role %q: pipe: %w", r.Name, err)
				}
				if err := p.checkClasses(rule); err != nil {
					return fmt.Errorf("role %q: pipe: %w", r.Name, err)
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
// literal ranks 2 where the word ranks 3.
func checkRule(rule string) error {
	terms, err := engine.ParseRule(rule)
	if err != nil {
		return err
	}
	for _, t := range terms {
		if t.Kind != engine.Regex {
			continue
		}
		if simpler, ok := rankLint(t.Text); ok {
			return fmt.Errorf("rule %q: /%s/ is %s; write that instead (spec §4)", rule, t.Text, simpler)
		}
	}
	return nil
}

// checkAttributes validates an attribute block: keyed by `all` or by a
// platform port49 ships or the inventory names, each attribute structurally
// valid (engine.CheckAttribute).
func (p *Policy) checkAttributes(attrs map[string][]string) error {
	for key, list := range attrs {
		if key != "all" && !platform.Known(key) && !p.inInventory(key) {
			return fmt.Errorf("attributes: %q is neither `all` nor a platform port49 ships or the inventory names", key)
		}
		for _, a := range list {
			if err := engine.CheckAttribute(a); err != nil {
				return fmt.Errorf("attributes.%s: %w", key, err)
			}
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
		for key, v := range s.Match {
			if key == "" {
				return fmt.Errorf("scope %q: a match key is empty", s.Name)
			}
			for op, bound := range v.Cmp {
				if op == "re" {
					re, err := regexp.Compile(bound)
					if err != nil {
						return fmt.Errorf("scope %q: match.%s.re: %w", s.Name, key, err)
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
			return fmt.Errorf("scope %q: on_missing is include or exclude, not %q", s.Name, s.OnMissing)
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
		if len(s.Identity) > 0 {
			// A machine has no directory entry, so it declares its username
			// (spec §2). A literal human identity declares one too until plan 7
			// derives it through the certificate-to-directory mapping.
			if s.Username == "" {
				return fmt.Errorf("subject %q: username is required: an identity-list subject has no directory to "+
					"derive one from (spec §2; §14, \"Username resolution\")", s.Name)
			}
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
			return fmt.Errorf("subject %q: enable %q: it must be none, auto or token (spec §7)", s.Name, s.Enable)
		}
		if s.TokenTTL < minTokenTTL || s.TokenTTL > maxTokenTTL {
			return fmt.Errorf("subject %q: token_ttl must be between %s and %s (design §8); got %s",
				s.Name, minTokenTTL, maxTokenTTL, s.TokenTTL)
		}
		for _, r := range s.API {
			if !slices.Contains(apiRights, r) {
				return fmt.Errorf("subject %q: api: %q is not a right; the rights are %s", s.Name, r,
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
	for i, g := range f.Grants {
		if _, ok := p.subs[g.Subject]; !ok {
			return fmt.Errorf("grants[%d]: subject %q is not declared", i, g.Subject)
		}
		if _, ok := p.scopes[g.Scope]; !ok {
			if g.Scope == "all_devices" {
				return fmt.Errorf("grants[%d]: scope all_devices is not declared; it is an ordinary scope since "+
					"plan 4 (spec §5.5) — add `scopes: [{name: all_devices, match: {}}]`", i)
			}
			return fmt.Errorf("grants[%d]: scope %q is not declared", i, g.Scope)
		}
		if len(g.Roles) == 0 {
			return fmt.Errorf("grants[%d]: a grant needs at least one role", i)
		}
		for _, r := range g.Roles {
			if _, ok := p.roles[r]; !ok {
				return fmt.Errorf("grants[%d]: role %q is not declared", i, r)
			}
		}
		if err := p.checkLevel(g.MaxPrivilege); err != nil {
			return fmt.Errorf("grants[%d]: max_privilege: %w", i, err)
		}
		if g.MaxPrivilege != "" && !p.numberedAnywhere(g.MaxPrivilege) {
			return fmt.Errorf("grants[%d]: max_privilege %s has no priv-lvl number on any platform, so no token "+
				"could carry it; use a level a platform numbers (spec §5.3, §6)", i, g.MaxPrivilege)
		}
		// A deny reaches a scope through a grant as surely as through
		// attached_roles, and a broken sync that drops the device from the
		// scope lifts it the same way (spec §5.5).
		if sc := p.scopes[g.Scope]; len(sc.Match) > 0 && !sc.onMissingDeclared {
			for _, r := range g.Roles {
				if len(p.roles[r].Deny) > 0 {
					return fmt.Errorf("grants[%d]: role %q carries a deny onto scope %q: declare on_missing on the "+
						"scope (include assumes a device with no data for the match is affected, the safe direction "+
						"for a mitigation; exclude says the grant must be earned by data; spec §5.5)", i, r, g.Scope)
				}
			}
		}
		// Roles are kept sorted, so nothing a grant reports — the mint
		// record, explain, access review — depends on how the file lists them.
		roles := slices.Clone(g.Roles)
		slices.Sort(roles)
		grant := &Grant{Subject: g.Subject, Scope: g.Scope, Roles: roles, MaxPrivilege: g.MaxPrivilege,
			Attributes: g.Attributes}
		if g.Expires != "" {
			t, err := parseExpires(g.Expires)
			if err != nil {
				return fmt.Errorf("grants[%d]: expires %q: a date (2026-12-01) or an RFC 3339 time", i, g.Expires)
			}
			grant.Expires = t
		}
		if err := p.checkAttributes(g.Attributes); err != nil {
			return fmt.Errorf("grants[%d]: %w", i, err)
		}
		p.grants = append(p.grants, grant)
	}
	return nil
}

func (p *Policy) buildTests(f file) error {
	for i, t := range f.Tests {
		switch {
		case (t.Subject == "") == (t.Principal == ""):
			return fmt.Errorf("tests[%d]: name a subject or a principal, one of the two", i)
		case t.Subject != "" && p.subs[t.Subject] == nil:
			return fmt.Errorf("tests[%d]: subject %q is not declared", i, t.Subject)
		case t.Device == "":
			return fmt.Errorf("tests[%d]: device is required", i)
		case strings.TrimSpace(t.Command) == "":
			return fmt.Errorf("tests[%d]: command is required", i)
		case t.Expect != "permit" && t.Expect != "deny":
			return fmt.Errorf("tests[%d]: expect is permit or deny, not %q", i, t.Expect)
		}
		if _, ok := p.device(t.Device); !ok {
			return fmt.Errorf("tests[%d]: device %q is not in the inventory", i, t.Device)
		}
		p.tests = append(p.tests, Test(t))
	}
	return nil
}

func (p *Policy) device(name string) (admission.Device, bool) {
	for _, d := range p.env.Devices {
		if d.Name == name {
			return d, true
		}
	}
	return admission.Device{}, false
}

// platforms is every dialect this policy can meet: the built-in table with
// the environment's own table over it.
func (p *Policy) platforms() map[string]platform.Dialect {
	out := platform.Dialects()
	for name, d := range p.env.Dialects {
		out[name] = d
	}
	return out
}

// checkClasses refuses a rule naming a class no platform defines. That is
// the policy's own error, a typo, rather than a device's: no inventory could
// make it compile. A class some platforms define and others do not is a joint
// check, and quarantines the devices on the others (Task 10; spec §10).
func (p *Policy) checkClasses(rule string) error {
	terms, err := engine.ParseRule(rule)
	if err != nil {
		return err
	}
	for _, t := range terms {
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
			return fmt.Errorf("rule %q names @%s, which no platform defines; a class is a platform's (spec §4, §8)",
				rule, t.Text)
		}
	}
	return nil
}

// numberedAnywhere reports whether some platform gives level a priv-lvl
// number, following the parent chain: a ceiling none can number is the
// policy's own error, like a class none defines.
func (p *Policy) numberedAnywhere(level string) bool {
	for _, d := range p.platforms() {
		if _, ok := p.privLvl(d, level); ok {
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

// dialect is the platform's dialect under this policy's environment.
func (p *Policy) dialect(name string) platform.Dialect {
	if p.env.Dialects != nil {
		if d, ok := p.env.Dialects[name]; ok {
			return d
		}
	}
	d, _ := platform.DialectFor(name)
	return d
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
