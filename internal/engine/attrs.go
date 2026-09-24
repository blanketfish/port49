package engine

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// MaxAttribute is the longest AV pair RFC 8907 can carry: its argument length
// field is one byte (spec §6, "Validation without semantics").
const MaxAttribute = 255

// Placeholders is the whole substitution vocabulary of spec §6. A general
// template language would be a footgun; this is four names and nothing more.
var Placeholders = []string{"{username}", "{principal}", "{device}", "{privilege}"}

var placeholder = regexp.MustCompile(`\{[^{}]*\}`)

// AttributeName is the attribute's name: everything before its separator,
// which is the first `=` (mandatory) or `*` (optional).
func AttributeName(a string) string {
	if i := strings.IndexAny(a, "=*"); i >= 0 {
		return a[:i]
	}
	return a
}

// Mandatory reports whether the attribute is sent mandatory (`=`), which a
// device that cannot parse it answers by refusing the whole session.
func Mandatory(a string) bool {
	i := strings.IndexAny(a, "=*")
	return i >= 0 && a[i] == '='
}

// CheckAttribute is the structural validation spec §6 requires, since port49
// cannot check what an attribute means: a non-empty name before the first `=`
// or `*`, no whitespace in the name, at most MaxAttribute bytes as written,
// no placeholder in the name, and none outside the vocabulary.
//
// An error quotes nothing of the attribute but a valid name: it is policy
// text, and a refusal goes to logs where the refused file's redaction
// patterns never loaded (spec §5.8).
func CheckAttribute(a string) error {
	i := strings.IndexAny(a, "=*")
	switch {
	case i < 0:
		return errors.New("an attribute has no `=` (mandatory) or `*` (optional) separator")
	case i == 0:
		return errors.New("an attribute has an empty name")
	case strings.ContainsAny(a[:i], " \t"):
		return errors.New("an attribute's name contains whitespace")
	case len(a) > MaxAttribute:
		return fmt.Errorf("attribute %q is %d bytes; RFC 8907 carries at most %d", AttributeName(a), len(a), MaxAttribute)
	case placeholder.MatchString(a[:i]):
		// A substitution in the name would let a username rewrite which
		// attribute is sent, and whether it is mandatory.
		return errors.New("an attribute's name carries a placeholder; a placeholder may appear only in the value " +
			"(spec §6)")
	}
	for _, p := range placeholder.FindAllString(a, -1) {
		known := false
		for _, v := range Placeholders {
			known = known || p == v
		}
		if !known {
			return fmt.Errorf("attribute %s: a placeholder in the value is not a substitution; the vocabulary is %s",
				AttributeName(a), strings.Join(Placeholders, " "))
		}
	}
	return nil
}

// Values are what a session authorization fills the placeholders with, from
// the login context and the device (spec §5.2). The blob is shared across
// principals, so this happens in the daemon at each session authorization and
// never at mint.
type Values struct {
	Username, Principal, Device string
}

// ErrAttributeTooLong is a substituted attribute longer than RFC 8907 can
// carry. The broker checks the same values at mint and refuses there, so the
// daemon meeting it means the context no longer holds what was minted.
var ErrAttributeTooLong = errors.New("engine: a substituted attribute is longer than 255 bytes")

// ErrSubstitution is a substitution value that carries a separator (`=` or
// `*`), a control character or invalid UTF-8: something a device could read as
// the start of another attribute. It is refused, never escaped.
var ErrSubstitution = errors.New("engine: a substitution value carries a separator or control character")

// SessionAttributes renders the session reply for one login: the blob's
// attributes with every placeholder filled, `{privilege}` from the blob's own
// level. It returns a fresh slice.
func (b Blob) SessionAttributes(v Values) ([]string, error) {
	values := map[string]string{"{username}": v.Username, "{principal}": v.Principal,
		"{device}": v.Device, "{privilege}": b.Privilege}
	r := strings.NewReplacer("{username}", v.Username, "{principal}", v.Principal,
		"{device}", v.Device, "{privilege}", b.Privilege)
	out := make([]string, 0, len(b.Attributes))
	for _, a := range b.Attributes {
		for _, p := range placeholder.FindAllString(a, -1) {
			if !safeValue(values[p]) {
				return nil, fmt.Errorf("%w: %s in %s", ErrSubstitution, p, AttributeName(a))
			}
		}
		s := r.Replace(a)
		if len(s) > MaxAttribute {
			return nil, fmt.Errorf("%w: %s", ErrAttributeTooLong, AttributeName(a))
		}
		out = append(out, s)
	}
	return out, nil
}

// safeValue reports whether a substitution value can go inside an attribute's
// value without changing its structure.
func safeValue(s string) bool {
	if !utf8.ValidString(s) || strings.ContainsAny(s, "=*") {
		return false
	}
	return !strings.ContainsFunc(s, unicode.IsControl)
}

// GrantedPrivLvl finds the level a session reply's attributes grant, if they
// grant one, and the index of the attribute that does. The attribute is
// `priv-lvl`, in either the mandatory (`=`) or optional (`*`) form, since a
// device reads both. A value that is not a privilege level is no grant. The
// last occurrence wins, which is what a device reading the arguments in order
// ends up applying. The daemon records the level from it, and the joint check
// compares it with the ceiling, so both read a reply the same way.
func GrantedPrivLvl(attrs []string) (level uint8, at int, ok bool) {
	at = -1
	for i, a := range attrs {
		j := strings.IndexAny(a, "=*")
		if j < 0 || a[:j] != "priv-lvl" {
			continue
		}
		n, valid := PrivLvlValue(a[j+1:])
		if !valid {
			continue
		}
		level, at, ok = n, i, true
	}
	return level, at, ok
}

// PrivLvlValue reads a priv-lvl attribute's value as a level: decimal as
// written plainly, 0 to 15, no sign and no leading zero. ok is false for
// anything else, which no device is measured to take:
// IOS-XE refused the session for priv-lvl=99 rather than clamp or ignore it
// (tests/lab/results/L18-cisco_iosxe.md, variant 7).
func PrivLvlValue(v string) (level uint8, ok bool) {
	n, err := strconv.ParseUint(v, 10, 8)
	if err != nil || n > 15 || strconv.FormatUint(n, 10) != v {
		return 0, false
	}
	return uint8(n), true
}

// NumericAttributes are the session attributes whose value is a number: L22
// measured `idletime*30` and `timeout*480` leaving a session unchanged
// (tests/lab/results/L22-*.md, "Inert candidates"), and no other value. A
// placeholder never goes in one, since a mint fills in an identity, and a
// value that is not a plain decimal is never sent (spec §6).
var NumericAttributes = []string{"idletime", "timeout"}

// NotANumber reports whether a is one of NumericAttributes, in either form,
// whose value is not decimal as written plainly, 0 to 65535, no sign and no
// leading zero.
func NotANumber(a string) bool {
	i := strings.IndexAny(a, "=*")
	if i < 0 || !slices.Contains(NumericAttributes, a[:i]) {
		return false
	}
	n, err := strconv.ParseUint(a[i+1:], 10, 16)
	return err != nil || strconv.FormatUint(n, 10) != a[i+1:]
}

// NotALevel reports whether a is a priv-lvl attribute, in either form, whose
// value PrivLvlValue refuses.
func NotALevel(a string) bool {
	i := strings.IndexAny(a, "=*")
	if i < 0 || a[:i] != "priv-lvl" {
		return false
	}
	_, ok := PrivLvlValue(a[i+1:])
	return !ok
}
