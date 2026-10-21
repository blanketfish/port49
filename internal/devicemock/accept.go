package devicemock

import (
	"bytes"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

type Violation struct {
	Rule, Step, Effect string
	Detail             string // lengths and attribute names only, never a value
	Measured           bool
}

// Check applies a profile's acceptance rules to one reply's arguments. A
// measured rule's violation gates; an unmeasured one is a warning that never
// fails the suite (decision 52 ruling 4).
func Check(rules []AcceptanceRule, step string, args [][]byte) (gate, warn []Violation) {
	for _, r := range rules {
		if r.Applies != "any" && r.Applies != step {
			continue
		}
		d := violates(r, args)
		if d == "" {
			continue
		}
		v := Violation{Rule: r.ID, Step: step, Effect: r.Effect, Detail: d, Measured: r.Status == "measured"}
		if v.Measured {
			gate = append(gate, v)
		} else {
			warn = append(warn, v)
		}
	}
	return gate, warn
}

// attrName is the name before the separator. An argument with no separator is
// malformed and may hold anything, so it is never named.
func attrName(a []byte) string {
	if i := bytes.IndexAny(a, "=*"); i >= 0 {
		return string(a[:i])
	}
	return "<unnamed>"
}

func attrValue(a []byte) string {
	if i := bytes.IndexAny(a, "=*"); i >= 0 {
		return string(a[i+1:])
	}
	return ""
}

// roleNames splits a roles value as the device reads it: names separated by
// spaces, the whole list optionally in double quotes, which NX-OS documents
// for more than one role.
func roleNames(v string) []string {
	return strings.Fields(strings.Trim(strings.TrimSpace(v), `"`))
}

func violates(r AcceptanceRule, args [][]byte) string {
	switch r.Kind {
	case "max_attribute_bytes":
		for _, a := range args {
			if len(a) > r.Max {
				return fmt.Sprintf("%s is %d bytes, over %d", attrName(a), len(a), r.Max)
			}
		}
	case "max_reply_bytes":
		// The total counts each argument's whole name=value bytes, not the
		// 1-byte length prefix the wire adds per argument.
		total := 0
		for _, a := range args {
			total += len(a)
		}
		if total > r.Max {
			return fmt.Sprintf("the reply's %d attributes total %d bytes, over %d", len(args), total, r.Max)
		}
	case "priv_lvl_range":
		for _, a := range args {
			if attrName(a) == "priv-lvl" {
				n, err := strconv.Atoi(attrValue(a))
				if err != nil || n < r.Min || n > r.Max {
					return fmt.Sprintf("priv-lvl outside %d..%d", r.Min, r.Max)
				}
			}
		}
	case "attribute_refused":
		for _, a := range args {
			if slices.Contains(r.Names, attrName(a)) {
				return fmt.Sprintf("%s is an attribute this device refuses", attrName(a))
			}
		}
	case "role_names":
		for _, a := range args {
			if n := attrName(a); n == "shell:roles" || n == "roles" {
				for _, role := range roleNames(attrValue(a)) {
					if !slices.Contains(r.Names, role) {
						return fmt.Sprintf("%s names a role this device does not honour", n)
					}
				}
			}
		}
	}
	return ""
}
