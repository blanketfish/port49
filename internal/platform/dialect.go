package platform

import (
	"maps"
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
	// DeviceConfig is the device configuration this adapter's renderings
	// depend on, one line each: `port49 platform show` prints it, and a device
	// without it does not get what the level promises (IOS-XE's level 7 is
	// level 1 until it is given commands, ceiling-cisco_iosxe.md).
	DeviceConfig []string
}

// builtin is the default set's adapters, platforms/<DefaultSet>/*.yaml, where
// every value is cited to the lab note that measured it or marked unmeasured
// and chosen in the direction that fails closed.
func builtin() map[string]Dialect { return sets[DefaultSet] }

// inert is the generic adapter's InertAttributes, as every shipped adapter's.
var inert = []string{"home-directory"}

// generic is the dialect of a platform port49 ships no adapter for (spec §8,
// "Unknown platforms"): the device still logs in, nothing is rendered for it,
// no modifier is claimed to reach port49, and the device is assumed to send
// abbreviations as typed.
var generic = Dialect{PipeToken: "|", StripCR: true, Supports: []string{"session"},
	PrivilegeAttributes: []string{"priv-lvl"}, InertAttributes: inert}

// ceilingLevels is the priv-lvl number a level stands for on a platform that
// renders no level, where the number is still needed: the token's
// max_privilege is compared against the priv_lvl a device puts on a request
// (spec §5.3, §7). It is plan 3's table, for a platform with no CeilingLevels
// of its own; `operator` is absent because nothing measured says what it is
// on IOS-XE and Junos.
var ceilingLevels = map[string]uint8{"readonly": 1, "admin": 15}

// DialectFor returns name's dialect and whether port49 ships one. An unknown
// platform gets the generic dialect. The maps are copies: a caller cannot edit
// the table through them.
func DialectFor(name string) (Dialect, bool) {
	d, ok := builtin()[name]
	if !ok {
		d = generic
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
	return d
}

// BearsPrivilege reports whether an attribute name may carry privilege on
// this platform: every name but one measured inert (InertAttributes).
func (d Dialect) BearsPrivilege(name string) bool { return !slices.Contains(d.InertAttributes, name) }

// PrivilegeAttributeNames is the PrivilegeAttributes of every platform in
// every built-in set, sorted: the names no attribute value may put a
// placeholder in, whatever platform key it is written under (spec §6).
func PrivilegeAttributeNames() []string {
	out := slices.Clone(generic.PrivilegeAttributes)
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
