package platform

import (
	"maps"
	"strconv"
	"strings"
)

// Dialect is what the policy engine compiles into a blob about one platform
// (spec §5.1.2): how a command vector from this device is normalized, which of
// its entity names belong to which class, how an abstract privilege level is
// rendered, and what the device authorizes at all. The daemon never reads it:
// the broker compiles it into the blob, so a daemon and a broker cannot
// disagree about a rule.
//
// BORROWED AHEAD from plan 5, which builds the adapters in full — user
// overrides and layering, the pinned platform set, `redact`, projection — and
// replaces this table. Every value here is either measured and cited, or
// marked unmeasured and chosen in the direction that fails closed.
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
	// CeilingLevels is the priv-lvl number each level stands for on a
	// platform that renders none (Levels nil), where the token's ceiling still
	// needs one. nil is plan 3's table, ceilingLevels.
	CeilingLevels map[string]uint8
}

// dialects are the built-in platforms. Each value is cited or marked
// unmeasured:
//
//   - PipeAuthorized is false on every platform with a command path, and that
//     is measured: typing `show clock | include AAAA…` sent port49 `show clock`
//     alone on vEOS 4.31.2F, NX-OS 10.4(2)F and IOS-XE 17.13.01a
//     (tests/lab/results/L2-arista_eos.md, L2-cisco_nxos.md,
//     L2-cisco_iosxe.md). Whether any other modifier reaches port49 anywhere
//     is unmeasured. Junos never authorizes a command.
//   - ShowsServerMsg: a 61-character server_msg on a denied command was
//     displayed in full on vEOS 4.31.2F and IOS-XE 17.13.01a and not at all on
//     NX-OS 10.4(2)F, which printed its own error (tests/lab/results/
//     L2-arista_eos.md, L2-cisco_iosxe.md, L2-cisco_nxos.md). Junos makes no
//     command request to carry one and is unmeasured, so false.
//   - StripCR: every command authorization measured ends `cmd-arg=<cr>`
//     (L10-arista_eos.md, L10-cisco_nxos.md, L10-cisco_iosxe.md).
//   - ExpandsAbbreviations is true on EOS, NX-OS and IOS-XE, set from L21:
//     typed `sh ver`, `sho run` and `sh clock` arrived as the full keywords on
//     the authorization request and the accounting record on vEOS 4.31.2F,
//     NX-OS 10.4(2)F and IOS-XE 17.13.01a, and `sh clock` was denied by a
//     `show clock` deny on all three (tests/lab/results/L21-arista_eos.md,
//     L21-cisco_nxos.md, L21-cisco_iosxe.md). That was interactive SSH; eAPI,
//     NX-API and NETCONF are unmeasured. Junos sends no command to expand and
//     is unmeasured, so false, the direction that fails closed.
//   - SplitsInterfaceNames is true on IOS-XE alone: a typed `int Gi1` arrived
//     as `cmd-arg=GigabitEthernet cmd-arg=1` on IOS-XE 17.13.01a, while vEOS
//     and the N9Kv sent one argument, `Ethernet1` and `Ethernet1/1`
//     (tests/lab/results/L21-cisco_iosxe.md, L21-arista_eos.md,
//     L21-cisco_nxos.md). Other interface types and subinterfaces are
//     unmeasured; an index is read as digits and `/ . :`.
//   - Supports: EOS, NX-OS and IOS-XE send per-command authorization (L1, L10);
//     Junos sends none, in 26 sessions on two images (L18; decision 21).
//     Config-command authorization is unmeasured, so no platform claims it.
//   - EntityClasses: interface NAMES, not device behaviour. `management` is the
//     interface the lab reaches each image on (fxp0 and mgmt0 in
//     tests/lab/configs/vjunos-startup.conf and nxos-startup.cfg; Management1
//     is spec §8's EOS example, and `em0` spec §8's Junos one, which no lab
//     image uses); `loopback` and `physical` are spec §8's EOS example. IOS-XE defines none: its lab management interface is
//     GigabitEthernet1, which is a physical port by name.
//   - Levels: arista_eos renders `priv-lvl` for readonly and admin, applied by
//     vEOS on every lab run since 2026-09-20 (L16-arista_eos.md). `operator`
//     renders as admin does, on the owner's ruling of 2026-09-24 (spec §6,
//     decision 23): at level 15 vEOS ran `clear counters`, `clear ip bgp *`
//     and `configure` for a `network-operator` session, and at level 1 refused
//     even `clear counters` (ceiling-arista_eos.md), so no level fences an
//     operator there and port49's command rules are the fence. Every other
//     platform renders nothing, as in plan 3; plan 5 fills them.
//   - CeilingLevels: cisco_nxos numbers `operator` 15, admin's number, on the
//     same ruling: every N9Kv role ran all three commands and
//     `network-operator` changed configuration (ceiling-cisco_nxos.md).
//     IOS-XE, whose level 7 can carry the operator rung (ceiling-cisco_iosxe.md),
//     keeps plan 3's table until plan 5 renders it.
var dialects = map[string]Dialect{
	"arista_eos": {
		PipeToken: "|", PipeAuthorized: false, StripCR: true, ExpandsAbbreviations: true, ShowsServerMsg: true,
		Supports: []string{"session", "commands"},
		EntityClasses: map[string][]string{
			"management": {`^Management[0-9]+$`},
			"loopback":   {`^Loopback[0-9]+$`},
			"physical":   {`^Ethernet[0-9/.]+$`, `^Port-Channel[0-9]+$`},
		},
		Levels: map[string][]string{"readonly": {"priv-lvl=1"}, "operator": {"priv-lvl=15"}, "admin": {"priv-lvl=15"}},
	},
	"cisco_nxos": {
		PipeToken: "|", PipeAuthorized: false, StripCR: true, ExpandsAbbreviations: true, ShowsServerMsg: false,
		Supports:      []string{"session", "commands"},
		EntityClasses: map[string][]string{"management": {`^mgmt[0-9]+$`}},
		CeilingLevels: map[string]uint8{"readonly": 1, "operator": 15, "admin": 15},
	},
	"cisco_iosxe": {
		PipeToken: "|", PipeAuthorized: false, StripCR: true, ExpandsAbbreviations: true, ShowsServerMsg: true,
		SplitsInterfaceNames: true,
		Supports:             []string{"session", "commands"},
	},
	"juniper_junos": {
		PipeToken: "|", PipeAuthorized: false, StripCR: true, ExpandsAbbreviations: false,
		Supports:      []string{"session"},
		EntityClasses: map[string][]string{"management": {`^(fxp0|em0)$`}},
	},
}

// generic is the dialect of a platform port49 ships no adapter for (spec §8,
// "Unknown platforms"): the device still logs in, nothing is rendered for it,
// no modifier is claimed to reach port49, and the device is assumed to send
// abbreviations as typed.
var generic = Dialect{PipeToken: "|", StripCR: true, Supports: []string{"session"}}

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
	d, ok := dialects[name]
	if !ok {
		d = generic
	}
	return d.clone(), ok
}

// Dialects is the whole built-in table, copied.
func Dialects() map[string]Dialect {
	out := make(map[string]Dialect, len(dialects))
	for name, d := range dialects {
		out[name] = d.clone()
	}
	return out
}

func (d Dialect) clone() Dialect {
	d.Supports = append([]string(nil), d.Supports...)
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
// value of a `priv-lvl` attribute in its rendering, or, where the platform
// renders none, its CeilingLevels or plan 3's table. ok is false where none
// says.
func (d Dialect) PrivLvl(level string) (uint8, bool) {
	if d.Levels == nil {
		table := d.CeilingLevels
		if table == nil {
			table = ceilingLevels
		}
		n, ok := table[level]
		return n, ok
	}
	for _, a := range d.Levels[level] {
		i := strings.IndexAny(a, "=*")
		if i < 0 || a[:i] != "priv-lvl" {
			continue
		}
		if n, err := strconv.ParseUint(a[i+1:], 10, 8); err == nil && n <= 15 {
			return uint8(n), true
		}
	}
	return 0, false
}
