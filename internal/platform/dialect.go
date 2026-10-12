package platform

import (
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/rhwendt/port49/internal/engine"
)

// Dialect is what the policy engine compiles into a blob about one platform
// (spec §5.1.2): how a command vector from this device is normalized, which of
// its entity names belong to which class, how an abstract privilege level is
// rendered, and what the device authorizes at all. The daemon never reads it:
// the broker compiles it into the blob, so a daemon and a broker cannot
// disagree about a rule.
//
// The built-in dialects are files, platforms/<set>/<platform>.yaml (spec §8,
// "Knowing what is shipped"), parsed by LoadSets into this type.
type Dialect struct {
	// PipeToken is the argument that separates a command from its output
	// modifiers (spec §3 rule 2). Only a whole argument equal to it splits.
	PipeToken string
	// PipeAuthorized says whether an output modifier ever reaches port49 on
	// this platform. Where it does not, the device applies the modifier after
	// port49 authorized the bare command, so a pipe rule protects nothing and
	// `port49 explain` must say so (spec §4, "Platform caveat").
	PipeAuthorized bool
	// StripCR drops a trailing `<cr>` argument (spec §3 rule 1).
	StripCR bool
	// ExpandsAbbreviations says the device sends the resolved command words
	// rather than what the operator typed. Where it is false, a deny's words
	// also match any abbreviation of them, so `rel` cannot slip past
	// `deny reload **` (spec §3 rule 4; engine.Normalize).
	ExpandsAbbreviations bool
	// SplitsInterfaceNames says the device sends an interface name and its
	// index as two arguments, `GigabitEthernet` and `1` for a typed `Gi1`.
	// Where it is true, a deny's term naming an interface with its index also
	// matches the two, so `deny interface GigabitEthernet1 **` still binds
	// (spec §3 rule 5; engine.Normalize).
	SplitsInterfaceNames bool
	// ShowsServerMsg says the device displays the server_msg of an
	// authorization reply to the operator. Where it does not, nothing spec §5.6
	// says through server_msg — the session-ceiling warning, context_stale,
	// credential_revoked — reaches anyone, and `port49 explain` must say so
	// (spec §15, L2).
	ShowsServerMsg bool
	// Supports is the capability declaration of spec §9: which of `session`,
	// `commands` and `config_commands` the platform authorizes. The engine
	// evaluates every rule whatever it says; explain reads it to say which
	// rules the device will never ask about.
	Supports []string
	// EntityClasses maps a class name to the RE2 patterns of this platform's
	// names in it (spec §4, §8). A rule naming a class the platform does not
	// define is a policy load error.
	EntityClasses map[string][]string
	// Levels maps an abstract privilege level to the session attributes that
	// render it (spec §6). nil means the platform renders no level at all —
	// plan 3's shape for every platform but arista_eos (plan 3, Decided 6 and
	// Question 2) — and is not a load error; an entry missing from a non-nil
	// map is, unless the level's parent chain reaches one.
	Levels map[string][]string
	// CeilingLevels is the priv-lvl number each level stands for where the
	// platform's rendering sends no priv-lvl — NX-OS is sent a role and no
	// level (L16) — and the token's ceiling still needs one. nil on a platform
	// with no Levels is plan 3's table, ceilingLevels.
	CeilingLevels map[string]uint8
	// PrivilegeAttributes are the attribute names measured to carry privilege
	// on this platform (spec §6): none takes a placeholder, and the policy
	// diff gates a change to one (spec §12).
	PrivilegeAttributes []string
	// InertAttributes are names held to carry none: the only attributes a
	// placeholder may go in (spec §6), and the only ones whose change the
	// diff does not gate. An attribute in neither list bears privilege: the
	// gate and the load fail closed on what nobody listed.
	InertAttributes []string
	// AcceptedAttributes, where it is not nil, is every attribute name this
	// platform's session reply may carry: the device refuses the whole session
	// for any other (IOS-XE, L18), so a composition whose reply carries one
	// fails the joint check and quarantines the device. nil takes any name.
	// Where it is set, a priv-lvl the reply carries must also be one of the
	// levels this adapter renders: what the device lets another level run is
	// unmeasured.
	AcceptedAttributes []string
	// RoleOrder ranks the values of an attribute that names a role, lowest
	// first, where the lab measured one fencing less than another (spec §8):
	// the diff gate lets a change to such an attribute through only where
	// its value provably went down (spec §12), and a level renders no role
	// above the one a higher level renders. A value it does not list is
	// unranked, and ranks above every value, failing closed.
	RoleOrder map[string][]string
	// DeviceConfig is the device configuration this adapter's renderings
	// depend on, one line each: `port49 platform show` prints it, and a device
	// without it does not get what the level promises (IOS-XE's level 7 is
	// level 1 until it is given commands, ceiling-cisco_iosxe.md).
	DeviceConfig []string
	// EnableUsername is what the platform's enable START carries in `user`:
	// EnablePrincipal, the operator's own username, on every platform
	// measured. It lives in the adapter, where the offline tools read it as
	// port49d does, so the `enable: auto` joint check answers the same in CI
	// (spec §5.6, §7).
	EnableUsername string
	// Redact are the redaction patterns an operator's `platforms:` block adds
	// to the platform's built-in ones (Redactions). A block adds; it never
	// removes a built-in pattern (spec §5.8).
	Redact []Redaction
	// Verified is how the adapter's spellings were confirmed (spec §8):
	// "containerlab" where a tests/lab/results/ note shows every attribute it
	// sends applied by a lab image, "community" for a contributed adapter
	// nobody here has run, and empty where neither is true. Only a built-in
	// adapter may say it.
	Verified string
	// Unreachable maps a level to the rules the device refuses at that level
	// in its own parser, never asking port49 (tests/lab/results/ceiling-*.md):
	// a permit every command of which is here is dead there (spec §12).
	// Only measured commands are listed; a level with none lists nothing.
	Unreachable map[string][]string
	// UnreachableNote maps a level to a `platforms:` block's unreachable
	// rules that the set did not measure: the operator's word, kept apart
	// from the measurement as FallbackNote is, so the dead-rule report names
	// it operator-listed and cites no lab note for it, and `platform export
	// --all` does not write it into a set (spec §8, §12; task 14 review M7).
	// Its Spec key, unreachable_note, is set only by SpecOf; a block may not
	// write it.
	UnreachableNote map[string][]string
	// Fallback maps a level to what the device gives a session at it on its
	// own when port49 cannot answer and the command method list falls back to
	// local, where that is more than a confined role: a subject port49
	// confines at that level has more access in an outage than the policy
	// grants (spec §6, §12, "Fallback exposure"). It is only what the lab
	// measured, or what a block wrote for a level no set measured anything
	// for: a block's text for a level the set did measure is FallbackNote.
	Fallback map[string]string
	// FallbackNote maps a level to a `platforms:` block's fallback text where
	// the set measured its own: the operator's word, kept apart from the
	// measurement so the report prints it as a note no text in it can close
	// or forge (spec §12). Its Spec key, fallback_note, is set only by
	// SpecOf; a block may not write it.
	FallbackNote map[string]string
	// LocalAccounts are RE2 patterns, one capture group each, that find a
	// device-local account's name in the device's configuration: `port49
	// devices check-config` warns where one is a username port49 serves
	// there, which the spec forbids (§5.6, "Local account names MUST NOT
	// collide").
	LocalAccounts []string
	// ConfigChecks are configuration lines the spec says a device must not
	// carry (§5.6, §6), each with what it costs: the same check names them.
	ConfigChecks []ConfigCheck
	// CommandProjection names how a session-only platform's rules are
	// rendered into its session reply (spec §8, "Projection for session-only
	// platforms"): ProjectionJunosRegex, or empty for none. Where it is set,
	// the adapter's `privilege` is each level's ceiling in permission bits
	// (CeilingBits), not attributes, and Levels is nil.
	CommandProjection string
	// Bits maps each permission bit the platform's classes carry to its reach
	// in rule form: every command the bit lets a session run, as rules, an
	// upper bound measured in the lab (spec §15, L12). A session's reach is
	// the union of its bits' (Junos permissions are a union), save what
	// CarveOuts removes. A reach that says less than the bit does would let
	// the device run what port49 denies, so a block may add to a bit's reach,
	// a gated edit, and never take from it (spec §8). The bit named
	// BaselineBit is what a class with no bits runs: every session holds it.
	Bits map[string][]string
	// CarveOuts maps a bit to the commands that only it makes available,
	// whatever other bit's reach holds them: `view-configuration`'s `show
	// configuration **`, which `view` alone does not show (L12). Only a
	// measured carve-out is listed; a block may drop one and never add one,
	// since a carve-out says the held bits reach less (spec §8).
	CarveOuts map[string][]string
	// BitDelivery is how the chosen bits reach the device (spec §8):
	// BitDeliveryUserPermissions, `user-permissions=<bits>` per session over a
	// bitless template, or BitDeliveryLocalUserName, `local-user-name=` one
	// template per level whose class carries the level's bits.
	BitDelivery string
	// LocalUserNames maps a level to the device's template user for it under
	// BitDeliveryLocalUserName; `port49 platform export --classes` renders
	// each with its class.
	LocalUserNames map[string]string
	// CeilingBits maps a level to the permission bits that are its ceiling on
	// a projected platform: the `privilege` key of such an adapter.
	CeilingBits map[string][]string
	// RPCEntryDenies are the denies a reply adds where a deny is the only
	// guard beneath a sent bit or the baseline: a wire deny binds no native
	// RPC (L12-netconf), and these close the CLI's ways into one, per user
	// (tests/lab/results/L26c-junoscript-juniper_*.md; decision 44). Set 1.2.0's
	// juniper_junos carries `junoscript **` and `op **`; empty, the projection
	// fails such a composition closed (set 1.1.0, option C). A block keeps the
	// whole list or drops it with `[]`, and never adds one: a partial list is
	// refused at load, since it leaves an entry open (spec §8).
	RPCEntryDenies []string
}

// The command projections port49 renders (spec §8).
const ProjectionJunosRegex = "junos_regex"

// The ways bits reach a projected device (spec §8, "bit_delivery").
const (
	BitDeliveryUserPermissions = "user_permissions"
	BitDeliveryLocalUserName   = "local_user_name"
)

// BaselineBit names, in Bits, what a class with no bits runs: held by every
// session on the platform, and never in a level's ceiling (spec §8).
const BaselineBit = "baseline"

// RPCEntryRole is the role of a deny the projection adds from RPCEntryDenies:
// none of the grant's, as BaselineBit's is none (decision 44).
const RPCEntryRole = "rpc_entry"

// projectionOwned is every attribute a projection's platform reads as a
// login class's template, bits or command or configuration regex, numbered
// variants included (`allow-commands2`, `user-permissions1`), in any case:
// what a role or grant may not set there (spec §8, "Generator constraints").
var projectionOwned = regexp.MustCompile(
	`(?i)^((allow|deny)-(commands|configuration)(-regexps)?|user-permissions|local-user-name)[0-9]*$`)

// ProjectionOwns reports whether an attribute name is one a projected
// platform reads as a class's template, bits or regexes, or one its adapter
// lists as bearing privilege: no role or grant sets it there.
func (d Dialect) ProjectionOwns(name string) bool {
	return d.Projected() && (projectionOwned.MatchString(name) || ContainsName(d.PrivilegeAttributes, name))
}

// RemoteClass is the login class the reference configuration gives the
// device's `remote` template user: no bits, so a session whose reply names no
// template, or names one the device does not have, runs nothing a bit
// reaches (spec §8; tests/lab/results/L18-juniper_*.md: an unknown template
// degrades to `remote`).
const RemoteClass = "p49-remote"

// projectionAttributes are the reply attributes a projection renders and
// owns on its platform: every name Junos documents for a login class's
// template, bits and command and configuration regexes (spec §8). No role or
// grant may set one on a projected platform, or it would stand beside, or
// over, what the generator proved (Policy.checkAttributes).
var projectionAttributes = map[string][]string{
	ProjectionJunosRegex: {"local-user-name", "user-permissions", "allow-commands", "deny-commands",
		"allow-configuration", "deny-configuration", "allow-commands-regexps", "deny-commands-regexps",
		"allow-configuration-regexps", "deny-configuration-regexps"},
}

// ProjectionAttributes is the attribute names projection owns, copied; none
// for no projection.
func ProjectionAttributes(projection string) []string {
	return slices.Clone(projectionAttributes[projection])
}

// Projected reports whether the platform's rules are rendered into its
// session reply.
func (d Dialect) Projected() bool { return d.CommandProjection != "" }

// LevelBits returns the permission bits that are exactly this level's
// ceiling on a projected platform, without following a parent chain (the
// policy's to follow), and whether the adapter names the level.
func (d Dialect) LevelBits(level string) ([]string, bool) {
	bits, ok := d.CeilingBits[level]
	return slices.Clone(bits), ok
}

// ExpandBits is bits with every bit `all` implies: on Junos the `all`
// permission is every permission (spec §8), so a set holding it holds every
// bit the adapter declares. The result is sorted and has no duplicates.
func (d Dialect) ExpandBits(bits []string) []string {
	if slices.Contains(bits, "all") {
		// The baseline is held by every session and never delivered.
		bits = slices.DeleteFunc(sortedKeys(d.Bits), func(b string) bool { return b == BaselineBit })
	}
	out := slices.Clone(bits)
	slices.Sort(out)
	return slices.Compact(out)
}

// ConfigCheck is one line a device's configuration must not carry: an RE2
// pattern over each line, and what the line costs, as the check says it.
type ConfigCheck struct {
	Match string `yaml:"match" json:"match"`
	Says  string `yaml:"says" json:"says"`
}

// builtin is the default set's adapters, platforms/<DefaultSet>/*.yaml, where
// every value is cited to the lab note that measured it or marked unmeasured
// and chosen in the direction that fails closed.
func builtin() map[string]Dialect { return sets[DefaultSet] }

// inert is the generic adapter's InertAttributes, and every shipped adapter's
// but cisco_iosxe's, which is empty: the C8000V refused a session for
// home-directory (tests/lab/results/L22-cisco_iosxe.md).
var inert = []string{"home-directory"}

// generics is each set's generic adapter, by version: the dialect of a
// platform the set ships no adapter for (spec §8, "Unknown platforms"). The
// device still logs in, nothing is rendered for it, no modifier is claimed to
// reach port49, and the device is assumed to send abbreviations as typed.
// Each of the set's files is laid over it, so it is frozen with its set: a
// device on a platform missing from a pinned set renders the same on every
// later binary. A new set that changes it adds its own entry; one that does
// not repeats the last, and LoadSets refuses a set with none.
//
// Its PrivilegeAttributes lists priv-lvl, what an unknown TACACS+ device most
// likely reads.
var generics = map[string]Dialect{
	"1.0.0": {PipeToken: "|", StripCR: true, Supports: []string{"session"},
		PrivilegeAttributes: []string{"priv-lvl"}, InertAttributes: inert, EnableUsername: EnablePrincipal},
	// 1.1.0 changes no generic value: the Junos projection is juniper_junos's.
	"1.1.0": {PipeToken: "|", StripCR: true, Supports: []string{"session"},
		PrivilegeAttributes: []string{"priv-lvl"}, InertAttributes: inert, EnableUsername: EnablePrincipal},
	// 1.2.0 changes no generic value: the entry deny is juniper_junos's.
	"1.2.0": {PipeToken: "|", StripCR: true, Supports: []string{"session"},
		PrivilegeAttributes: []string{"priv-lvl"}, InertAttributes: inert, EnableUsername: EnablePrincipal},
}

// Generic returns set version's generic adapter, copied, and whether the
// binary has one for that version.
func Generic(version string) (Dialect, bool) {
	d, ok := generics[version]
	return d.clone(), ok
}

// ceilingLevels is the priv-lvl number a level stands for on a platform that
// renders no level, where the number is still needed: the token's
// max_privilege is compared against the priv_lvl a device puts on a request
// (spec §5.3, §7). It is plan 3's table, for a platform with no CeilingLevels
// of its own; `operator` is absent because nothing measured says what it is
// on IOS-XE and Junos.
var ceilingLevels = map[string]uint8{"readonly": 1, "admin": 15}

// DialectFor returns name's dialect in the default set and whether port49
// ships one. An unknown platform gets the default set's generic dialect. The
// maps are copies: a caller cannot edit the table through them.
func DialectFor(name string) (Dialect, bool) {
	d, ok := builtin()[name]
	if !ok {
		d = generics[DefaultSet]
	}
	return d.clone(), ok
}

// Dialects is the whole built-in table, copied.
func Dialects() map[string]Dialect {
	out := make(map[string]Dialect, len(builtin()))
	for name, d := range builtin() {
		out[name] = d.clone()
	}
	return out
}

func (d Dialect) clone() Dialect {
	d.Supports = append([]string(nil), d.Supports...)
	d.PrivilegeAttributes = slices.Clone(d.PrivilegeAttributes)
	d.InertAttributes = slices.Clone(d.InertAttributes)
	d.AcceptedAttributes = slices.Clone(d.AcceptedAttributes)
	d.DeviceConfig = slices.Clone(d.DeviceConfig)
	d.Redact = slices.Clone(d.Redact)
	if d.RoleOrder != nil {
		order := make(map[string][]string, len(d.RoleOrder))
		for k, v := range d.RoleOrder {
			order[k] = slices.Clone(v)
		}
		d.RoleOrder = order
	}
	if d.EntityClasses != nil {
		classes := make(map[string][]string, len(d.EntityClasses))
		for k, v := range d.EntityClasses {
			classes[k] = append([]string(nil), v...)
		}
		d.EntityClasses = classes
	}
	if d.Levels != nil {
		levels := make(map[string][]string, len(d.Levels))
		for k, v := range d.Levels {
			levels[k] = append([]string(nil), v...)
		}
		d.Levels = levels
	}
	if d.CeilingLevels != nil {
		d.CeilingLevels = maps.Clone(d.CeilingLevels)
	}
	if d.Unreachable != nil {
		unreachable := make(map[string][]string, len(d.Unreachable))
		for k, v := range d.Unreachable {
			unreachable[k] = slices.Clone(v)
		}
		d.Unreachable = unreachable
	}
	if d.UnreachableNote != nil {
		note := make(map[string][]string, len(d.UnreachableNote))
		for k, v := range d.UnreachableNote {
			note[k] = slices.Clone(v)
		}
		d.UnreachableNote = note
	}
	if d.Fallback != nil {
		d.Fallback = maps.Clone(d.Fallback)
	}
	if d.FallbackNote != nil {
		d.FallbackNote = maps.Clone(d.FallbackNote)
	}
	d.LocalAccounts = slices.Clone(d.LocalAccounts)
	d.ConfigChecks = slices.Clone(d.ConfigChecks)
	d.Bits = cloneLists(d.Bits)
	d.CarveOuts = cloneLists(d.CarveOuts)
	d.CeilingBits = cloneLists(d.CeilingBits)
	d.RPCEntryDenies = slices.Clone(d.RPCEntryDenies)
	if d.LocalUserNames != nil {
		d.LocalUserNames = maps.Clone(d.LocalUserNames)
	}
	return d
}

// cloneLists is a map of lists copied deep; nil stays nil.
func cloneLists(m map[string][]string) map[string][]string {
	if m == nil {
		return nil
	}
	out := make(map[string][]string, len(m))
	for k, v := range m {
		out[k] = slices.Clone(v)
	}
	return out
}

// BearsPrivilege reports whether an attribute name may carry privilege on
// this platform: every name but one measured inert (InertAttributes).
func (d Dialect) BearsPrivilege(name string) bool { return !slices.Contains(d.InertAttributes, name) }

// ContainsName reports whether list holds name in any case: a comparison
// that makes more of an attribute bear privilege reads it this way, since
// what a device makes of a name's case is unmeasured (re-review 2, RR2-M1).
// A comparison that exempts one, inert or accepted, stays exact.
func ContainsName(list []string, name string) bool {
	return slices.ContainsFunc(list, func(n string) bool { return strings.EqualFold(n, name) })
}

// PrivilegeAttributeNames is the PrivilegeAttributes of every platform in
// every built-in set, sorted: the names no attribute value may put a
// placeholder in, whatever platform key it is written under (spec §6).
func PrivilegeAttributeNames() []string {
	var out []string
	for _, d := range generics {
		for _, n := range d.PrivilegeAttributes {
			if !slices.Contains(out, n) {
				out = append(out, n)
			}
		}
	}
	for _, set := range sets {
		for _, d := range set {
			for _, n := range d.PrivilegeAttributes {
				if !slices.Contains(out, n) {
					out = append(out, n)
				}
			}
		}
	}
	slices.Sort(out)
	return out
}

// RoleRank is value's place in the role_order of attribute name, lowest
// first. ok is false for a value it does not rank, which ranks above every
// value it does.
func (d Dialect) RoleRank(name, value string) (rank int, ok bool) {
	rank = slices.Index(d.RoleOrder[name], value)
	if rank < 0 {
		return 0, false
	}
	return rank, true
}

// Authorizes reports whether the platform declares capability c.
func (d Dialect) Authorizes(c string) bool {
	for _, s := range d.Supports {
		if s == c {
			return true
		}
	}
	return false
}

// Render returns the attributes this platform renders for exactly this level,
// without following a parent chain (the policy's to follow). ok is false for a
// level the platform does not map; a platform with no Levels maps every level
// to nothing.
func (d Dialect) Render(level string) (attrs []string, ok bool) {
	if d.Levels == nil {
		return nil, true
	}
	attrs, ok = d.Levels[level]
	return append([]string(nil), attrs...), ok
}

// PrivLvl is the priv-lvl number this platform gives exactly this level: the
// value of a `priv-lvl` attribute in its rendering; where the rendering sends
// none, its CeilingLevels (NX-OS renders a role and no level, L16); and where
// the platform renders nothing at all and declares no table, plan 3's. ok is
// false where none says.
func (d Dialect) PrivLvl(level string) (uint8, bool) {
	for _, a := range d.Levels[level] {
		i := strings.IndexAny(a, "=*")
		if i < 0 || a[:i] != "priv-lvl" {
			continue
		}
		// A rendered priv-lvl that is not a level is no number at all, never
		// CeilingLevels' instead: the device is sent the value, not the table
		// (Validate refuses it; this is the belt to that).
		return engine.PrivLvlValue(a[i+1:])
	}
	table := d.CeilingLevels
	if table == nil {
		if d.Levels != nil {
			return 0, false
		}
		table = ceilingLevels
	}
	n, ok := table[level]
	return n, ok
}
