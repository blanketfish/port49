package platform

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/rhwendt/port49/internal/engine"
)

// Spec is one platform block as a file writes it (spec §8): a built-in adapter
// under platforms/<set>/. A nil field is one the block does not set, and Over
// lays the set fields over a base, so a block that sets one key inherits every
// other.
type Spec struct {
	Supports             *[]string            `yaml:"supports"`
	Privilege            *map[string][]string `yaml:"privilege"`
	CeilingLevels        *map[string]uint8    `yaml:"ceiling_levels"`
	EntityClasses        *map[string][]string `yaml:"entity_classes"`
	ExpandsAbbreviations *bool                `yaml:"expands_abbreviations"`
	SplitsInterfaceNames *bool                `yaml:"splits_interface_names"`
	PipeToken            *string              `yaml:"pipe_token"`
	PipeAuthorized       *bool                `yaml:"pipe_authorized"`
	StripCR              *bool                `yaml:"strip_cr"`
	ShowsServerMsg       *bool                `yaml:"shows_server_msg"`
	PrivilegeAttributes  *[]string            `yaml:"privilege_attributes"`
	InertAttributes      *[]string            `yaml:"inert_attributes"`
	AcceptedAttributes   *[]string            `yaml:"accepted_attributes"`
	RoleOrder            *map[string][]string `yaml:"role_order"`
	DeviceConfig         *[]string            `yaml:"device_config"`
	EnableUsername       *string              `yaml:"enable_username"`
	Redact               *[]Redaction         `yaml:"redact"`
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
	if s.Privilege != nil {
		d.Levels = mergeLists(d.Levels, *s.Privilege)
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

// capabilities is spec §9's vocabulary for `supports`.
var capabilities = []string{"session", "commands", "config_commands"}

// className is the shape of an entity class name, as a rule writes it after
// `@` (engine.ParseRule).
var className = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// Validate is the structural validation spec §8 requires of every adapter,
// built-in or not: port49 cannot check what an attribute means, so it checks
// everything else. Each error names the field.
func Validate(name string, d Dialect) error {
	field := func(f string) string { return "platforms." + name + "." + f }
	if len(d.Supports) == 0 {
		return fmt.Errorf("%s is required: which of %s the platform authorizes (spec §9)", field("supports"),
			strings.Join(capabilities, ", "))
	}
	for _, c := range d.Supports {
		if !slices.Contains(capabilities, c) {
			return fmt.Errorf("%s: %q is not a capability; the capabilities are %s", field("supports"), c,
				strings.Join(capabilities, ", "))
		}
	}
	if !slices.Contains(d.Supports, "session") {
		return fmt.Errorf("%s must include session: every platform port49 serves authorizes its sessions",
			field("supports"))
	}
	for _, level := range sortedKeys(d.Levels) {
		seen := map[string]bool{}
		for _, a := range d.Levels[level] {
			if err := engine.CheckAttribute(a); err != nil {
				return fmt.Errorf("%s: %w", field("privilege."+level), err)
			}
			// A level's rendering is the level: a placeholder in it would let a
			// principal's name decide what the device is told (spec §6).
			if slices.ContainsFunc(engine.Placeholders, func(p string) bool { return strings.Contains(a, p) }) {
				return fmt.Errorf("%s: %s: a level's rendering takes no placeholder (spec §6)", field("privilege."+level), a)
			}
			n := engine.AttributeName(a)
			if engine.NotALevel(a) {
				// A value the device cannot use refuses the session: IOS-XE
				// did for priv-lvl=99 (L18-cisco_iosxe.md, variant 7).
				return fmt.Errorf("%s: %s: not a privilege level; they run 0 to 15", field("privilege."+level), a)
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
	for _, class := range sortedKeys(d.EntityClasses) {
		if !className.MatchString(class) {
			return fmt.Errorf("%s: %q is not a class name: lower case, digits and _, starting with a letter",
				field("entity_classes"), class)
		}
		if len(d.EntityClasses[class]) == 0 {
			return fmt.Errorf("%s is empty, which matches nothing; remove the class instead", field("entity_classes."+class))
		}
		for _, p := range d.EntityClasses[class] {
			if _, err := regexp.Compile(p); err != nil {
				return fmt.Errorf("%s: %q does not compile under RE2: %w", field("entity_classes."+class), p, err)
			}
		}
	}
	if d.PipeToken == "" || strings.ContainsAny(d.PipeToken, " \t") {
		return fmt.Errorf("%s is %q: one argument with no whitespace, e.g. \"|\"", field("pipe_token"), d.PipeToken)
	}
	for _, list := range []struct {
		name  string
		names []string
	}{{"privilege_attributes", d.PrivilegeAttributes}, {"inert_attributes", d.InertAttributes},
		{"accepted_attributes", d.AcceptedAttributes}} {
		for _, n := range list.names {
			if n == "" || strings.ContainsAny(n, "=* \t") {
				return fmt.Errorf("%s: %q is not an attribute name", field(list.name), n)
			}
		}
	}
	for _, n := range d.InertAttributes {
		if slices.Contains(d.PrivilegeAttributes, n) {
			return fmt.Errorf("%s: %s is also in privilege_attributes; an attribute carries privilege or it does not",
				field("inert_attributes"), n)
		}
		// What a level renders is the level (spec §6): listed inert, every
		// later change to it would pass the diff ungated.
		rendered := n == "priv-lvl"
		for _, level := range sortedKeys(d.Levels) {
			rendered = rendered || slices.ContainsFunc(d.Levels[level], func(a string) bool {
				return engine.AttributeName(a) == n
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
	for _, attr := range sortedKeys(d.RoleOrder) {
		switch {
		case attr == "" || strings.ContainsAny(attr, "=* \t"):
			return fmt.Errorf("%s: %q is not an attribute name", field("role_order"), attr)
		case attr == "priv-lvl":
			return fmt.Errorf("%s: priv-lvl ranks by its number; remove it", field("role_order.priv-lvl"))
		case len(d.RoleOrder[attr]) == 0:
			return fmt.Errorf("%s is empty, which ranks nothing; remove it", field("role_order."+attr))
		}
		for i, v := range d.RoleOrder[attr] {
			if v == "" || strings.ContainsFunc(v, func(r rune) bool { return r < 0x20 || r > 0x7e }) {
				return fmt.Errorf("%s[%d]: a value is printable ASCII and not empty", field("role_order."+attr), i)
			}
			if slices.Index(d.RoleOrder[attr], v) != i {
				return fmt.Errorf("%s: %q is ranked twice; rank it once", field("role_order."+attr), v)
			}
		}
	}
	for i, r := range d.Redact {
		if err := r.check(); err != nil {
			return fmt.Errorf("%s[%d]: %w", field("redact"), i, err)
		}
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
		return fmt.Errorf("%s is %q; it must be %q", field("enable_username"), d.EnableUsername, EnablePrincipal)
	}
	for i, line := range d.DeviceConfig {
		if strings.TrimSpace(line) == "" || strings.ContainsFunc(line, func(r rune) bool { return r < 0x20 || r > 0x7e }) {
			return fmt.Errorf("%s[%d]: one printable ASCII configuration line", field("device_config"), i)
		}
	}
	return nil
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
