package platform

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"regexp/syntax"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/rhwendt/port49/internal/engine"
)

// Spec is one platform block as a file writes it (spec §8): a built-in adapter
// under platforms/<set>/. A nil field is one the block does not set, and Over
// lays the set fields over a base, so a block that sets one key inherits every
// other. A nil field is also one `port49 platform export` leaves out.
type Spec struct {
	Supports             *[]string            `yaml:"supports,omitempty"`
	Privilege            *map[string][]string `yaml:"privilege,omitempty"`
	CeilingLevels        *map[string]uint8    `yaml:"ceiling_levels,omitempty"`
	EntityClasses        *map[string][]string `yaml:"entity_classes,omitempty"`
	ExpandsAbbreviations *bool                `yaml:"expands_abbreviations,omitempty"`
	SplitsInterfaceNames *bool                `yaml:"splits_interface_names,omitempty"`
	PipeToken            *string              `yaml:"pipe_token,omitempty"`
	PipeAuthorized       *bool                `yaml:"pipe_authorized,omitempty"`
	StripCR              *bool                `yaml:"strip_cr,omitempty"`
	ShowsServerMsg       *bool                `yaml:"shows_server_msg,omitempty"`
	PrivilegeAttributes  *[]string            `yaml:"privilege_attributes,omitempty"`
	InertAttributes      *[]string            `yaml:"inert_attributes,omitempty"`
	AcceptedAttributes   *[]string            `yaml:"accepted_attributes,omitempty"`
	RoleOrder            *map[string][]string `yaml:"role_order,omitempty"`
	DeviceConfig         *[]string            `yaml:"device_config,omitempty"`
	EnableUsername       *string              `yaml:"enable_username,omitempty"`
	Redact               *[]Redaction         `yaml:"redact,omitempty"`
	Verified             *string              `yaml:"verified,omitempty"`
	Unreachable          *map[string][]string `yaml:"unreachable,omitempty"`
	UnreachableNote      *map[string][]string `yaml:"unreachable_note,omitempty"`
	Fallback             *map[string]string   `yaml:"fallback,omitempty"`
	FallbackNote         *map[string]string   `yaml:"fallback_note,omitempty"`
	LocalAccounts        *[]string            `yaml:"local_accounts,omitempty"`
	ConfigChecks         *[]ConfigCheck       `yaml:"config_checks,omitempty"`
	CommandProjection    *string              `yaml:"command_projection,omitempty"`
	Bits                 *map[string][]string `yaml:"bits,omitempty"`
	CarveOuts            *map[string][]string `yaml:"carve_outs,omitempty"`
	BitDelivery          *string              `yaml:"bit_delivery,omitempty"`
	LocalUserNames       *map[string]string   `yaml:"local_user_names,omitempty"`
}

// ParseSpecs reads an adapter file: one YAML document whose one key is
// `platforms`, a map of platform name to Spec. A key the schema does not know
// is refused, never ignored: an ignored key is an adapter that reads one way
// and renders another.
func ParseSpecs(raw []byte) (map[string]Spec, error) {
	var f struct {
		Platforms map[string]Spec `yaml:"platforms"`
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil && err != io.EOF {
		return nil, err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return nil, errors.New("an adapter file is one YAML document; remove the `---` separator and what follows it")
	}
	if len(f.Platforms) == 0 {
		return nil, errors.New("an adapter file defines its platforms under a `platforms:` key, and this one defines none")
	}
	return f.Platforms, nil
}

// Over lays s over base, per top-level key (spec §8): a list or a value s
// sets replaces base's whole, and a map s sets — privilege, ceiling_levels,
// entity_classes, role_order — merges into base's per entry, so a block that adds one
// class keeps the rest. Every field s leaves nil is base's. The result shares
// nothing with either. Discarding an entry takes `replace: true`, which
// starts from nothing.
func (s Spec) Over(base Dialect) Dialect {
	d := base.clone()
	if s.Supports != nil {
		d.Supports = slices.Clone(*s.Supports)
	}
	if s.CommandProjection != nil {
		d.CommandProjection = *s.CommandProjection
	}
	// On a projected platform `privilege` is each level's ceiling in bits
	// (spec §8), read by the projection and never sent as attributes.
	if s.Privilege != nil && d.Projected() {
		d.CeilingBits = mergeLists(d.CeilingBits, *s.Privilege)
	} else if s.Privilege != nil {
		d.Levels = mergeLists(d.Levels, *s.Privilege)
	}
	if s.Bits != nil {
		d.Bits = mergeLists(d.Bits, *s.Bits)
	}
	if s.CarveOuts != nil {
		d.CarveOuts = mergeLists(d.CarveOuts, *s.CarveOuts)
	}
	if s.BitDelivery != nil {
		d.BitDelivery = *s.BitDelivery
	}
	if s.LocalUserNames != nil {
		if d.LocalUserNames == nil {
			d.LocalUserNames = map[string]string{}
		}
		for k, v := range *s.LocalUserNames {
			d.LocalUserNames[k] = v
		}
	}
	if s.CeilingLevels != nil {
		if d.CeilingLevels == nil {
			d.CeilingLevels = map[string]uint8{}
		}
		for k, v := range *s.CeilingLevels {
			d.CeilingLevels[k] = v
		}
	}
	if s.EntityClasses != nil {
		d.EntityClasses = mergeLists(d.EntityClasses, *s.EntityClasses)
	}
	if s.ExpandsAbbreviations != nil {
		d.ExpandsAbbreviations = *s.ExpandsAbbreviations
	}
	if s.SplitsInterfaceNames != nil {
		d.SplitsInterfaceNames = *s.SplitsInterfaceNames
	}
	if s.PipeToken != nil {
		d.PipeToken = *s.PipeToken
	}
	if s.PipeAuthorized != nil {
		d.PipeAuthorized = *s.PipeAuthorized
	}
	if s.StripCR != nil {
		d.StripCR = *s.StripCR
	}
	if s.ShowsServerMsg != nil {
		d.ShowsServerMsg = *s.ShowsServerMsg
	}
	if s.PrivilegeAttributes != nil {
		d.PrivilegeAttributes = slices.Clone(*s.PrivilegeAttributes)
	}
	if s.InertAttributes != nil {
		d.InertAttributes = slices.Clone(*s.InertAttributes)
	}
	if s.AcceptedAttributes != nil {
		d.AcceptedAttributes = slices.Clone(*s.AcceptedAttributes)
	}
	if s.DeviceConfig != nil {
		d.DeviceConfig = slices.Clone(*s.DeviceConfig)
	}
	if s.EnableUsername != nil {
		d.EnableUsername = *s.EnableUsername
	}
	if s.RoleOrder != nil {
		d.RoleOrder = mergeLists(d.RoleOrder, *s.RoleOrder)
	}
	if s.Redact != nil {
		// Appended, never replaced: a block cannot take a redaction away.
		d.Redact = append(d.Redact, *s.Redact...)
	}
	if s.Verified != nil {
		d.Verified = *s.Verified
	}
	if s.Unreachable != nil {
		d.Unreachable = unionLists(d.Unreachable, *s.Unreachable)
	}
	if s.UnreachableNote != nil {
		d.UnreachableNote = unionLists(d.UnreachableNote, *s.UnreachableNote)
	}
	if s.Fallback != nil {
		if d.Fallback == nil {
			d.Fallback = map[string]string{}
		}
		// Over a measured text, a block's own is the operator's note, never
		// the measurement (spec §12); restating the text changes nothing.
		for k, v := range *s.Fallback {
			switch set := d.Fallback[k]; {
			case set == "":
				d.Fallback[k] = v
			case v == set || strings.TrimSpace(v) == "":
			default:
				if d.FallbackNote == nil {
					d.FallbackNote = map[string]string{}
				}
				d.FallbackNote[k] = v
			}
		}
	}
	if s.FallbackNote != nil {
		if d.FallbackNote == nil {
			d.FallbackNote = map[string]string{}
		}
		for k, v := range *s.FallbackNote {
			d.FallbackNote[k] = v
		}
	}
	if s.LocalAccounts != nil {
		d.LocalAccounts = slices.Clone(*s.LocalAccounts)
	}
	if s.ConfigChecks != nil {
		d.ConfigChecks = slices.Clone(*s.ConfigChecks)
	}
	return d
}

// mergeLists sets every entry of over in base, a map Over already owns, and
// returns it; a nil base becomes a new map.
func mergeLists(base, over map[string][]string) map[string][]string {
	if base == nil {
		base = make(map[string][]string, len(over))
	}
	for k, v := range over {
		base[k] = slices.Clone(v)
	}
	return base
}

// unionLists adds every entry of over to base's list for its key, a map Over
// already owns, keeping base's: what the lab measured the device refuses, a
// block adds to and never takes away (spec §8, §12). A nil base becomes a new
// map.
func unionLists(base, over map[string][]string) map[string][]string {
	if base == nil {
		base = make(map[string][]string, len(over))
	}
	for k, v := range over {
		for _, e := range v {
			if !slices.Contains(base[k], e) {
				base[k] = append(base[k], e)
			}
		}
	}
	return base
}

// KeepMeasured is d with ref's unreachable rules and fallback texts laid back
// under it: what the set measured about the device a block cannot discard,
// `replace: true` included, since the device behind the name is the same
// device (spec §8, §12). Text d had in a measured text's place becomes its
// note.
func KeepMeasured(d, ref Dialect) Dialect {
	d = d.clone()
	d.Unreachable = unionLists(d.Unreachable, ref.Unreachable)
	if len(d.Unreachable) == 0 {
		d.Unreachable = nil
	}
	for _, level := range sortedKeys(ref.Fallback) {
		if d.Fallback == nil {
			d.Fallback = map[string]string{}
		}
		if was := d.Fallback[level]; was != ref.Fallback[level] {
			if strings.TrimSpace(was) != "" && d.FallbackNote[level] == "" {
				if d.FallbackNote == nil {
					d.FallbackNote = map[string]string{}
				}
				d.FallbackNote[level] = was
			}
			d.Fallback[level] = ref.Fallback[level]
		}
	}
	return d
}

// verifications are what `verified` may say (spec §8, "Knowing what is
// shipped"): unset, confirmed against a lab image on every change
// (`containerlab`, with a tests/lab/results/ note), or contributed and run by
// nobody here (`community`).
var verifications = []string{"", "containerlab", "community"}

// capabilities is spec §9's vocabulary for `supports`.
var capabilities = []string{"session", "commands", "config_commands"}

// className is the shape of an entity class name, as a rule writes it after
// `@` (engine.ParseRule).
var className = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// Validate is the structural validation spec §8 requires of every adapter,
// built-in or not: port49 cannot check what an attribute means, so it checks
// everything else. Each error names the field.
//
// An error names a value by its key and index and never quotes it: an adapter
// is policy text, and a refusal goes to logs where the refused file's
// redaction patterns never loaded (spec §5.8). Names — of a level, a class,
// an attribute that passed its own check — are named.
func Validate(name string, d Dialect) error {
	field := func(f string) string { return "platforms." + name + "." + f }
	if len(d.Supports) == 0 {
		return fmt.Errorf("%s is required: which of %s the platform authorizes (spec §9)", field("supports"),
			strings.Join(capabilities, ", "))
	}
	for i, c := range d.Supports {
		if !slices.Contains(capabilities, c) {
			return fmt.Errorf("%s[%d] is not a capability; the capabilities are %s", field("supports"), i,
				strings.Join(capabilities, ", "))
		}
	}
	if !slices.Contains(d.Supports, "session") {
		return fmt.Errorf("%s must include session: every platform port49 serves authorizes its sessions",
			field("supports"))
	}
	for _, level := range sortedKeys(d.Levels) {
		seen := map[string]bool{}
		for i, a := range d.Levels[level] {
			at := fmt.Sprintf("%s[%d]", field("privilege."+level), i)
			if err := engine.CheckAttribute(a); err != nil {
				return fmt.Errorf("%s: %w", at, err)
			}
			// A level's rendering is the level: a placeholder in it would let a
			// principal's name decide what the device is told (spec §6).
			if slices.ContainsFunc(engine.Placeholders, func(p string) bool { return strings.Contains(a, p) }) {
				return fmt.Errorf("%s: a level's rendering takes no placeholder (spec §6)", at)
			}
			n := engine.AttributeName(a)
			if engine.NotALevel(a) {
				// A value the device cannot use refuses the session: IOS-XE
				// did for priv-lvl=99 (L18-cisco_iosxe.md, variant 7).
				return fmt.Errorf("%s: not a privilege level; they run 0 to 15", at)
			}
			if seen[n] {
				// A device keeps the first of two and drops the second, silently
				// (spec §8, "Generator constraints").
				return fmt.Errorf("%s: %s is sent twice; send it once", field("privilege."+level), n)
			}
			seen[n] = true
		}
	}
	for _, level := range sortedKeys(d.CeilingLevels) {
		if n := d.CeilingLevels[level]; n > 15 {
			return fmt.Errorf("%s: %d is not a privilege level; they run 0 to 15", field("ceiling_levels."+level), n)
		}
	}
	for k, class := range sortedKeys(d.EntityClasses) {
		if !className.MatchString(class) {
			// Not a name, so not named: its place in name order finds it.
			return fmt.Errorf("%s: class %d in name order is not a class name: lower case, digits and _, "+
				"starting with a letter", field("entity_classes"), k+1)
		}
		if len(d.EntityClasses[class]) == 0 {
			return fmt.Errorf("%s is empty, which matches nothing; remove the class instead", field("entity_classes."+class))
		}
		for i, p := range d.EntityClasses[class] {
			if strings.Contains(p, Redacted) {
				return pastedBack(fmt.Sprintf("%s[%d]", field("entity_classes."+class), i))
			}
			if _, err := regexp.Compile(p); err != nil {
				return fmt.Errorf("%s[%d] does not compile: %s", field("entity_classes."+class), i, RegexpProblem(err))
			}
		}
	}
	if d.PipeToken == "" || strings.ContainsAny(d.PipeToken, " \t") {
		return fmt.Errorf("%s is not one argument with no whitespace, e.g. \"|\"", field("pipe_token"))
	}
	for _, list := range []struct {
		name  string
		names []string
	}{{"privilege_attributes", d.PrivilegeAttributes}, {"inert_attributes", d.InertAttributes},
		{"accepted_attributes", d.AcceptedAttributes}} {
		for i, n := range list.names {
			if n == "" || strings.ContainsAny(n, "=* \t") {
				return fmt.Errorf("%s[%d] is not an attribute name", field(list.name), i)
			}
		}
	}
	if err := oneSpelling(field, d); err != nil {
		return err
	}
	for _, n := range d.InertAttributes {
		if slices.Contains(d.PrivilegeAttributes, n) {
			return fmt.Errorf("%s: %s is also in privilege_attributes; an attribute carries privilege or it does not",
				field("inert_attributes"), n)
		}
		// What a level renders is the level (spec §6): listed inert, every
		// later change to it would pass the diff ungated.
		rendered := strings.EqualFold(n, "priv-lvl")
		for _, level := range sortedKeys(d.Levels) {
			rendered = rendered || slices.ContainsFunc(d.Levels[level], func(a string) bool {
				return strings.EqualFold(engine.AttributeName(a), n)
			})
		}
		if rendered {
			return fmt.Errorf("%s: %s: a level renders it, so it carries privilege", field("inert_attributes"), n)
		}
	}
	if d.AcceptedAttributes != nil && len(d.AcceptedAttributes) == 0 {
		// Read as nothing accepted, it refuses every session; read as no list,
		// it lifts the device's restriction. Neither is safe to guess.
		return fmt.Errorf("%s is empty: list every attribute name the device takes, or remove the key to take any",
			field("accepted_attributes"))
	}
	if d.AcceptedAttributes != nil {
		// The adapter's own rendering has to be something the device takes,
		// or every session at that level is refused.
		for _, level := range sortedKeys(d.Levels) {
			for _, a := range d.Levels[level] {
				if n := engine.AttributeName(a); !slices.Contains(d.AcceptedAttributes, n) {
					return fmt.Errorf("%s: %s is not in accepted_attributes, so the device would refuse every session "+
						"at %s", field("privilege."+level), n, level)
				}
			}
		}
	}
	for k, attr := range sortedKeys(d.RoleOrder) {
		switch {
		case attr == "" || strings.ContainsAny(attr, "=* \t"):
			return fmt.Errorf("%s: key %d in name order is not an attribute name", field("role_order"), k+1)
		case attr == "priv-lvl":
			return fmt.Errorf("%s: priv-lvl ranks by its number; remove it", field("role_order.priv-lvl"))
		case len(d.RoleOrder[attr]) == 0:
			return fmt.Errorf("%s is empty, which ranks nothing; remove it", field("role_order."+attr))
		}
		for i, v := range d.RoleOrder[attr] {
			if v == "" || strings.ContainsFunc(v, func(r rune) bool { return r < 0x20 || r > 0x7e }) {
				return fmt.Errorf("%s[%d]: a value is printable ASCII and not empty", field("role_order."+attr), i)
			}
			if j := slices.Index(d.RoleOrder[attr], v); j != i {
				return fmt.Errorf("%s[%d] is ranked twice, as [%d]; rank it once", field("role_order."+attr), i, j)
			}
		}
	}
	for i, r := range d.Redact {
		if err := r.check(); err != nil {
			return fmt.Errorf("%s[%d]: %w", field("redact"), i, err)
		}
	}
	for _, level := range sortedKeys(d.Unreachable) {
		for i, rule := range d.Unreachable[level] {
			if strings.Contains(rule, Redacted) {
				// No position: a block's list merges into the set's, so its
				// place in the union is not its place in the block.
				return pastedBack(field("unreachable." + level))
			}
			if _, err := engine.ParseRule(rule); err != nil {
				return fmt.Errorf("%s[%d]: %w", field("unreachable."+level), i, err)
			}
		}
	}
	for _, level := range sortedKeys(d.UnreachableNote) {
		for i, rule := range d.UnreachableNote[level] {
			if strings.Contains(rule, Redacted) {
				return pastedBack(field("unreachable." + level))
			}
			if _, err := engine.ParseRule(rule); err != nil {
				return fmt.Errorf("%s[%d]: %w", field("unreachable."+level), i, err)
			}
		}
	}
	for _, level := range sortedKeys(d.Fallback) {
		if strings.Contains(d.Fallback[level], Redacted) {
			return pastedBack(field("fallback." + level))
		}
		if strings.TrimSpace(d.Fallback[level]) == "" {
			return fmt.Errorf("%s is empty: say what the device gives a session at %s on its own", field("fallback."+level),
				level)
		}
	}
	for _, level := range sortedKeys(d.FallbackNote) {
		// A block's own text for the level, kept as its note.
		if strings.Contains(d.FallbackNote[level], Redacted) {
			return pastedBack(field("fallback." + level))
		}
		if strings.TrimSpace(d.FallbackNote[level]) == "" {
			return fmt.Errorf("%s is empty: say what the device gives a session at %s on its own", field("fallback."+level),
				level)
		}
	}
	for i, p := range d.LocalAccounts {
		re, err := regexp.Compile(p)
		if err != nil || re.NumSubexp() != 1 {
			return fmt.Errorf("%s[%d] is an RE2 pattern with one capture group, the account's name",
				field("local_accounts"), i)
		}
	}
	for i, c := range d.ConfigChecks {
		if strings.Contains(c.Match, Redacted) {
			return pastedBack(fmt.Sprintf("%s[%d].match", field("config_checks"), i))
		}
		if _, err := regexp.Compile(c.Match); err != nil || c.Match == "" || strings.TrimSpace(c.Says) == "" {
			return fmt.Errorf("%s[%d]: match is an RE2 pattern over a configuration line, and says what the line costs",
				field("config_checks"), i)
		}
	}
	if err := validateProjection(field, d); err != nil {
		return err
	}
	if !slices.Contains(verifications, d.Verified) {
		return fmt.Errorf("%s is not containerlab, community, or unset", field("verified"))
	}
	switch d.EnableUsername {
	case EnablePrincipal:
	case EnableEnab:
		// The $enab{level}$ enable path is unbuilt on purpose: it would need a
		// (nas, rem_addr) index that must refuse rather than guess, and no
		// device in the lab has sent that username form (spec §7, L3).
		return fmt.Errorf("%s: %q is refused: no platform in the lab has been measured sending that username "+
			"form, and port49 does not ship an unexercised enable path for it. Every platform with an enable "+
			"exchange sends the operator's own username (tests/lab/results/L3-arista_eos.md, L3-cisco_iosxe.md). "+
			"To enable it, add a tests/lab/results/ note showing a device sending it and lift this refusal with "+
			"the code that reads it", field("enable_username"), EnableEnab)
	default:
		return fmt.Errorf("%s must be %q", field("enable_username"), EnablePrincipal)
	}
	for i, line := range d.DeviceConfig {
		if strings.Contains(line, Redacted) {
			return pastedBack(fmt.Sprintf("%s[%d]", field("device_config"), i))
		}
		if strings.TrimSpace(line) == "" || strings.ContainsFunc(line, func(r rune) bool { return r < 0x20 || r > 0x7e }) {
			return fmt.Errorf("%s[%d]: one printable ASCII configuration line", field("device_config"), i)
		}
	}
	return nil
}

// oneSpelling refuses an adapter that spells one attribute name in two
// cases across its privilege_attributes, inert_attributes,
// accepted_attributes, its renderings and priv-lvl: an exact comparison reads
// the two as two names, and one of them can then escape a list the other is
// in (re-review 2, RR2-M1). It names both spellings; a name is the file's
// identifier, never a secret.
func oneSpelling(field func(string) string, d Dialect) error {
	seen := map[string]string{"priv-lvl": "priv-lvl"}
	for _, level := range sortedKeys(d.Levels) {
		for _, a := range d.Levels[level] {
			n := engine.AttributeName(a)
			if first, ok := seen[strings.ToLower(n)]; ok && first != n {
				return fmt.Errorf("%s: %s and %s are one attribute name in two cases; spell it one way",
					field("privilege."+level), n, first)
			}
			seen[strings.ToLower(n)] = n
		}
	}
	for _, list := range []struct {
		key   string
		names []string
	}{{"privilege_attributes", d.PrivilegeAttributes}, {"inert_attributes", d.InertAttributes},
		{"accepted_attributes", d.AcceptedAttributes}} {
		for _, n := range list.names {
			if first, ok := seen[strings.ToLower(n)]; ok && first != n {
				return fmt.Errorf("%s: %s and %s are one attribute name in two cases; spell it one way",
					field(list.key), n, first)
			}
			seen[strings.ToLower(n)] = n
		}
	}
	return nil
}

// pastedBack is the refusal of a value holding the marker `platform export`
// writes in a secret's place (spec §5.8): an export pasted back would hold a
// device to a line nobody wrote, or run a check that matches nothing.
func pastedBack(at string) error {
	return fmt.Errorf("%s holds %s, the marker platform export writes in place of a value redaction hides: "+
		"re-enter the value from your policy", at, Redacted)
}

// RegexpProblem is what a pattern RE2 refuses has wrong, without the
// pattern: a syntax error's code, e.g. "missing closing )". Its text quotes
// the pattern, which may be a value redaction hides (spec §5.8).
func RegexpProblem(err error) string {
	var serr *syntax.Error
	if errors.As(err, &serr) {
		return string(serr.Code)
	}
	return "RE2 refuses it"
}

// Monotone refuses an adapter whose renderings do not rise with order, the
// policy's levels lowest first: a lower level's priv-lvl above a higher one's,
// an attribute a lower level renders that a higher one does not, or a value
// that ranks above the higher level's in its role_order, an unranked value
// ranking above every other. The diff gate lets a move to a lower level
// through only where every value provably went down (spec §12); this keeps
// the adapter's own ladder from being the thing that goes up. A level the
// adapter neither renders nor numbers is skipped: its parent chain renders it.
// Values are compared without their separator, so `roles=x` below `roles*x`
// passes; the diff gates a separator change on its own (Lowers).
func Monotone(name string, d Dialect, order []string) error {
	var levels []string
	for _, l := range order {
		_, rendered := d.Levels[l]
		_, numbered := d.CeilingLevels[l]
		if rendered || numbered {
			levels = append(levels, l)
		}
	}
	for i, lower := range levels {
		n, numbered := d.PrivLvl(lower)
		at := "platforms." + name + ".ceiling_levels." + lower
		if slices.ContainsFunc(d.Levels[lower], func(a string) bool { return engine.AttributeName(a) == "priv-lvl" }) {
			at = "platforms." + name + ".privilege." + lower
		}
		for _, higher := range levels[i+1:] {
			if m, ok := d.PrivLvl(higher); numbered && (!ok || n > m) {
				return fmt.Errorf("%s: priv-lvl %d is above %s's %s; a level renders no more than the levels above it",
					at, n, higher, privLvlText(m, ok))
			}
			for _, a := range d.Levels[lower] {
				attr := engine.AttributeName(a)
				if attr == "priv-lvl" {
					continue
				}
				j := slices.IndexFunc(d.Levels[higher], func(b string) bool { return engine.AttributeName(b) == attr })
				if j < 0 {
					return fmt.Errorf("platforms.%s.privilege.%s: %s is rendered at %s and not at %s, above it; a "+
						"level renders no more than the levels above it", name, lower, attr, lower, higher)
				}
				b := d.Levels[higher][j]
				if v, w := attributeValue(a), attributeValue(b); v != w && !d.rankedBelow(attr, v, w) {
					return fmt.Errorf("platforms.%s.privilege.%s: %s ranks above %s's %s in role_order.%s, or is not "+
						"ranked there; a level renders no more than the levels above it", name, lower, a, higher, b, attr)
				}
			}
		}
	}
	return nil
}

// rankedBelow reports whether role_order puts v below w: v ranked, and w
// ranked above it or not ranked, which is above everything.
func (d Dialect) rankedBelow(attr, v, w string) bool {
	rv, okv := d.RoleRank(attr, v)
	rw, okw := d.RoleRank(attr, w)
	return okv && (!okw || rv < rw)
}

// Lowers reports whether a reply's attribute from, replaced by to, provably
// fences the session more: the same name, the same separator, and both values
// ranked in its role_order with to's strictly below. Anything else is a
// change whose direction nobody measured (spec §12).
func (d Dialect) Lowers(from, to string) bool {
	i, j := strings.IndexAny(from, "=*"), strings.IndexAny(to, "=*")
	if i < 0 || j < 0 || from[:i+1] != to[:j+1] {
		return false
	}
	rf, okf := d.RoleRank(from[:i], from[i+1:])
	rt, okt := d.RoleRank(to[:j], to[j+1:])
	return okf && okt && rt < rf
}

// attributeValue is what follows an attribute's separator.
func attributeValue(a string) string {
	if i := strings.IndexAny(a, "=*"); i >= 0 {
		return a[i+1:]
	}
	return ""
}

func privLvlText(n uint8, ok bool) string {
	if !ok {
		return "none"
	}
	return fmt.Sprint(n)
}

// SpecOf is d as a block that sets every field d has: nil where d leaves a
// map or a list nil, so that SpecOf(d).Over(Dialect{}) is d again. `port49
// platform export` writes it, and the policy diff compares two adapters
// through it, key by key.
func SpecOf(d Dialect) Spec {
	s := Spec{ExpandsAbbreviations: ptr(d.ExpandsAbbreviations), SplitsInterfaceNames: ptr(d.SplitsInterfaceNames),
		PipeToken: ptr(d.PipeToken), PipeAuthorized: ptr(d.PipeAuthorized), StripCR: ptr(d.StripCR),
		ShowsServerMsg: ptr(d.ShowsServerMsg), EnableUsername: ptr(d.EnableUsername)}
	d = d.clone()
	if d.Supports != nil {
		s.Supports = &d.Supports
	}
	if d.Levels != nil {
		s.Privilege = &d.Levels
	}
	if d.Projected() {
		s.CommandProjection = &d.CommandProjection
		s.Privilege = nil
		if d.CeilingBits != nil {
			s.Privilege = &d.CeilingBits
		}
	}
	if d.Bits != nil {
		s.Bits = &d.Bits
	}
	if d.CarveOuts != nil {
		s.CarveOuts = &d.CarveOuts
	}
	if d.BitDelivery != "" {
		s.BitDelivery = &d.BitDelivery
	}
	if d.LocalUserNames != nil {
		s.LocalUserNames = &d.LocalUserNames
	}
	if d.CeilingLevels != nil {
		s.CeilingLevels = &d.CeilingLevels
	}
	if d.EntityClasses != nil {
		s.EntityClasses = &d.EntityClasses
	}
	if d.PrivilegeAttributes != nil {
		s.PrivilegeAttributes = &d.PrivilegeAttributes
	}
	if d.InertAttributes != nil {
		s.InertAttributes = &d.InertAttributes
	}
	if d.AcceptedAttributes != nil {
		s.AcceptedAttributes = &d.AcceptedAttributes
	}
	if d.RoleOrder != nil {
		s.RoleOrder = &d.RoleOrder
	}
	if d.DeviceConfig != nil {
		s.DeviceConfig = &d.DeviceConfig
	}
	if d.Redact != nil {
		s.Redact = &d.Redact
	}
	if d.Verified != "" {
		s.Verified = &d.Verified
	}
	if d.Unreachable != nil {
		s.Unreachable = &d.Unreachable
	}
	if d.UnreachableNote != nil {
		s.UnreachableNote = &d.UnreachableNote
	}
	if d.Fallback != nil {
		s.Fallback = &d.Fallback
	}
	if d.FallbackNote != nil {
		s.FallbackNote = &d.FallbackNote
	}
	if d.LocalAccounts != nil {
		s.LocalAccounts = &d.LocalAccounts
	}
	if d.ConfigChecks != nil {
		s.ConfigChecks = &d.ConfigChecks
	}
	return s
}

func ptr[T any](v T) *T { return &v }

// SpecKeys are the keys an adapter block may set, in the order Spec
// declares them: what an acknowledge: entry may name as a field.
func SpecKeys() []string {
	t := reflect.TypeOf(Spec{})
	out := make([]string, t.NumField())
	for i := range out {
		out[i] = strings.Split(t.Field(i).Tag.Get("yaml"), ",")[0]
	}
	return out
}

// bitName is the shape of a permission bit's name, as Junos spells them
// (`view-configuration`).
var bitName = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

// templateName is the shape of a template user this build renders: what
// Junos takes as a login name, lower case so no two differ only by case.
var templateName = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,63}$`)

// p49Template is port49's template namespace: a template the device already
// has for another reason, `root` or `remote`, would put the session in that
// account's class whatever bits the projection proved (spec §8,
// local_user_names). No subject may take a p49- name either
// (ReservedUsername).
var p49Template = regexp.MustCompile(`^` + templatePrefix + `[a-z0-9][a-z0-9._-]*$`)

const templatePrefix = "p49-"

// remoteUser is the device's own fallback template: the user a session with
// no template, or one the device lacks, lands under (RemoteClass).
const remoteUser = "remote"

// ReservedUsername reports whether u names one of a device's own accounts,
// in any case: `remote`, any p49- name, or any platform's system user. A
// session under one lands in that account's class whatever the reply says,
// so no subject takes one: policy load refuses a declared one and the mint
// one a directory derives (spec §8; §13 decision 26).
func ReservedUsername(u string) bool {
	return strings.EqualFold(u, remoteUser) || strings.HasPrefix(strings.ToLower(u), templatePrefix) ||
		ContainsName(systemUserNames(), u)
}

// systemUserNames is every platform's system users as one list: no template
// user takes one, whatever platform it is declared on.
func systemUserNames() []string {
	var out []string
	for _, users := range systemUsers {
		out = append(out, users...)
	}
	return out
}

// validateProjection is Validate for the projection keys (spec §8): a
// projection this build renders, a session-only platform, `privilege` as
// ceiling bits the adapter declares, each bit's reach in rule form, a
// delivery, and a template per level where the delivery needs one. Where
// there is no projection, none of the keys is set: a key nothing reads reads
// as enforced.
func validateProjection(field func(string) string, d Dialect) error {
	if !d.Projected() {
		for _, k := range []struct {
			key string
			set bool
		}{{"bits", d.Bits != nil}, {"carve_outs", d.CarveOuts != nil}, {"bit_delivery", d.BitDelivery != ""},
			{"local_user_names", d.LocalUserNames != nil}} {
			if k.set {
				return fmt.Errorf("%s is read only with command_projection; set that, or remove the key", field(k.key))
			}
		}
		return nil
	}
	if d.CommandProjection != ProjectionJunosRegex {
		return fmt.Errorf("%s is not a projection this build renders; the one it renders is %s",
			field("command_projection"), ProjectionJunosRegex)
	}
	if !slices.Equal(d.Supports, []string{"session"}) {
		return fmt.Errorf("%s: a projected platform authorizes its sessions and nothing else, so supports is "+
			"[session]; a platform that asks port49 about commands is answered per command (spec §8)", field("supports"))
	}
	if d.Levels != nil {
		// Unreachable through a file: Over routes `privilege` to CeilingBits
		// on a projected platform. A Dialect built by hand could carry both.
		return fmt.Errorf("%s names permission bits on a projected platform, never attributes", field("privilege"))
	}
	if d.AcceptedAttributes != nil {
		return fmt.Errorf("%s: a projected platform's reply is the projection's own names; remove the key",
			field("accepted_attributes"))
	}
	for _, n := range ProjectionAttributes(d.CommandProjection) {
		if !slices.Contains(d.PrivilegeAttributes, n) {
			return fmt.Errorf("%s: %s is missing: the projection sends it, and it carries privilege (spec §8)",
				field("privilege_attributes"), n)
		}
	}
	if len(d.Bits) == 0 {
		return fmt.Errorf("%s is required with command_projection: each permission bit's reach in rule form "+
			"(spec §8)", field("bits"))
	}
	for k, bit := range sortedKeys(d.Bits) {
		if !bitName.MatchString(bit) {
			return fmt.Errorf("%s: bit %d in name order is not a permission bit's name", field("bits"), k+1)
		}
		if len(d.Bits[bit]) == 0 {
			return fmt.Errorf("%s is empty: a bit that reaches nothing is not declared", field("bits."+bit))
		}
		for i, rule := range d.Bits[bit] {
			terms, err := engine.ParseRule(rule)
			if err != nil {
				return fmt.Errorf("%s[%d]: %w", field("bits."+bit), i, err)
			}
			// A bit's reach is the device's: a class is a policy's names and a
			// regex no containment can read (engine.Contains).
			for j, t := range terms {
				if t.Kind == engine.Class || t.Kind == engine.Regex {
					return fmt.Errorf("%s[%d]: term %d: a bit's reach is words, `*` and `**`", field("bits."+bit), i, j+1)
				}
			}
		}
	}
	for _, bit := range sortedKeys(d.CarveOuts) {
		if bit == BaselineBit {
			return fmt.Errorf("%s.%s: a carve-out belongs to a bit a level may hold, never to %s, which every "+
				"session holds", field("carve_outs"), bit, BaselineBit)
		}
		if _, ok := d.Bits[bit]; !ok {
			return fmt.Errorf("%s.%s: %s is not a bit under bits, so it has no reach to carve out of",
				field("carve_outs"), bit, bit)
		}
		for i, rule := range d.CarveOuts[bit] {
			// Only commands the bit itself reaches can be the bit's alone.
			held := slices.ContainsFunc(d.Bits[bit], func(r string) bool {
				ok, err := engine.Contains(r, rule, nil)
				return err == nil && ok
			})
			if !held {
				return fmt.Errorf("%s[%d]: the bit's own reach does not hold it", field("carve_outs."+bit), i)
			}
		}
	}
	switch d.BitDelivery {
	case BitDeliveryUserPermissions, BitDeliveryLocalUserName:
	default:
		return fmt.Errorf("%s is %s or %s (spec §8)", field("bit_delivery"), BitDeliveryUserPermissions,
			BitDeliveryLocalUserName)
	}
	// With no ceiling bits a level would be projected against nothing the
	// adapter says; every projected level names its bits.
	if len(d.CeilingBits) == 0 {
		return fmt.Errorf("%s is required with command_projection: each level's ceiling in permission bits (spec §8)",
			field("privilege"))
	}
	for _, level := range sortedKeys(d.CeilingBits) {
		seen := map[string]bool{}
		for i, bit := range d.CeilingBits[level] {
			if _, ok := d.Bits[bit]; !ok {
				return fmt.Errorf("%s[%d]: %s is not a bit under bits", field("privilege."+level), i, bit)
			}
			if bit == BaselineBit {
				return fmt.Errorf("%s[%d]: %s is held by every session, so no level names it", field("privilege."+level),
					i, bit)
			}
			if seen[bit] {
				return fmt.Errorf("%s: %s is listed twice", field("privilege."+level), bit)
			}
			seen[bit] = true
		}
	}
	if d.BitDelivery != BitDeliveryLocalUserName {
		if d.LocalUserNames != nil {
			return fmt.Errorf("%s is read only under bit_delivery: %s", field("local_user_names"), BitDeliveryLocalUserName)
		}
		return nil
	}
	byName := map[string]string{}
	for _, level := range sortedKeys(d.CeilingBits) {
		name, ok := d.LocalUserNames[level]
		if !ok {
			return fmt.Errorf("%s: level %s has no template user; bit_delivery: %s sends one per level", field(
				"local_user_names"), level, BitDeliveryLocalUserName)
		}
		if !templateName.MatchString(name) {
			return fmt.Errorf("%s is not a login name: lower case letters, digits, `.`, `-` and `_`, starting with "+
				"a letter, at most 64", field("local_user_names."+level))
		}
		if name == remoteUser {
			return fmt.Errorf("%s: %s is the device's own fallback template, the bitless one a session lands under "+
				"when its template is missing; a level's template is p49-<name> (spec §8)",
				field("local_user_names."+level), name)
		}
		if !p49Template.MatchString(name) || ContainsName(systemUserNames(), name) {
			return fmt.Errorf("%s: %s is not a p49- template: a level's template is p49-<name>, since one the "+
				"device already has, root or a local account, puts the session in its own class whatever bits the "+
				"projection proved (spec §8)", field("local_user_names."+level), name)
		}
		// One template is one class: two levels sharing it get the same bits.
		if other, ok := byName[name]; ok && !slices.Equal(d.ExpandBits(d.CeilingBits[other]),
			d.ExpandBits(d.CeilingBits[level])) {
			return fmt.Errorf("%s: levels %s and %s share template %s and have different bits; one template is one "+
				"class", field("local_user_names"), other, level, name)
		}
		byName[name] = level
	}
	for _, level := range sortedKeys(d.LocalUserNames) {
		if _, ok := d.CeilingBits[level]; !ok {
			return fmt.Errorf("%s: level %s has no bits under privilege", field("local_user_names"), level)
		}
	}
	return nil
}

// MonotoneBits refuses a projected adapter whose ceiling bits do not rise
// with order, the policy's levels lowest first: every bit a lower level's
// ceiling holds, `all` read as every bit, a higher level's holds too. It is
// Monotone for a platform whose levels are bits (spec §8).
func MonotoneBits(name string, d Dialect, order []string) error {
	var levels []string
	for _, l := range order {
		if _, ok := d.CeilingBits[l]; ok {
			levels = append(levels, l)
		}
	}
	for i, lower := range levels {
		low := d.ExpandBits(d.CeilingBits[lower])
		for _, higher := range levels[i+1:] {
			high := d.ExpandBits(d.CeilingBits[higher])
			for _, bit := range low {
				if !slices.Contains(high, bit) {
					return fmt.Errorf("platforms.%s.privilege.%s: %s is not in %s's bits, above it; a level's ceiling "+
						"holds no bit the levels above it lack", name, lower, bit, higher)
				}
			}
		}
	}
	return nil
}
