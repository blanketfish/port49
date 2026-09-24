package platform

import (
	"bytes"
	"errors"
	"fmt"
	"io"
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
	DeviceConfig         *[]string            `yaml:"device_config"`
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
// entity_classes — merges into base's per entry, so a block that adds one
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
	for i, line := range d.DeviceConfig {
		if strings.TrimSpace(line) == "" || strings.ContainsFunc(line, func(r rune) bool { return r < 0x20 || r > 0x7e }) {
			return fmt.Errorf("%s[%d]: one printable ASCII configuration line", field("device_config"), i)
		}
	}
	return nil
}

// Monotone refuses an adapter whose renderings do not rise with order, the
// policy's levels lowest first: a lower level's priv-lvl above a higher one's,
// or an attribute a lower level renders that a higher one does not. The diff
// gate lets a move to a lower level through as a lowering (spec §12), which
// holds only while a lower level renders no more than a higher one. port49
// cannot rank two values of one attribute, a role's name, so it checks the
// numbers and the names. A level the adapter neither renders nor numbers is
// skipped: its parent chain renders it.
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
				if !slices.ContainsFunc(d.Levels[higher], func(b string) bool { return engine.AttributeName(b) == attr }) {
					return fmt.Errorf("platforms.%s.privilege.%s: %s is rendered at %s and not at %s, above it; a "+
						"level renders no more than the levels above it", name, lower, attr, lower, higher)
				}
			}
		}
	}
	return nil
}

func privLvlText(n uint8, ok bool) string {
	if !ok {
		return "none"
	}
	return fmt.Sprint(n)
}
