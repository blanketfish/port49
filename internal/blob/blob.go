// Package blob is the compiled decision a token names (spec §5.1.1, §5.1.2),
// in the vertical slice's simplest form. BORROWED AHEAD from plan 4, which
// replaces the format, the rule grammar and the matcher: this one carries a
// platform, a privilege level, the session reply's attributes, and permit and
// deny rules in a strict subset of spec §4. It is content-addressed — the name
// is the hash of the bytes — so a blob is immutable and a sweep across one
// platform writes it once.
package blob

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Blob is one compiled decision for one platform.
type Blob struct {
	// Platform is the device platform the blob was compiled for. The
	// attributes are rendered for it, so two platforms never share a blob.
	Platform string `json:"platform"`
	// Privilege is the level the granted roles compose to, as the priv-lvl
	// number the device is told (spec §6). Zero: no role carried one.
	Privilege uint8 `json:"privilege"`
	// Attributes are the session authorization reply's AV pairs, exactly as
	// they go on the wire.
	Attributes []string `json:"attributes"`
	// Permit and Deny are command rules in the slice's subset of spec §4
	// (CheckRule), sorted, each normalized to single spaces.
	Permit []string `json:"permit"`
	Deny   []string `json:"deny"`
}

// ErrHashMismatch is a stored body that does not hash to the name it was
// stored under. It is a store fault, never a decision.
var ErrHashMismatch = errors.New("blob: body does not match its hash")

// HashOf names a body: "sha256:" and the hex digest of exactly these bytes.
func HashOf(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Encode renders b and names it. encoding/json writes struct fields in
// declaration order, so one Blob value always encodes to the same bytes; the
// caller (policy.Resolve) is what makes one decision one value, by sorting.
func Encode(b Blob) ([]byte, string, error) {
	body, err := json.Marshal(b)
	if err != nil {
		return nil, "", err
	}
	return body, HashOf(body), nil
}

// Decode parses a stored blob. A body that does not hash to its name is
// refused, and so is a field this daemon does not know: half-reading a
// decision a newer broker compiled is how a daemon and a broker come to
// disagree about a rule (spec §5.1.2).
func Decode(hash string, body []byte) (Blob, error) {
	if HashOf(body) != hash {
		return Blob{}, ErrHashMismatch
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var b Blob
	if err := dec.Decode(&b); err != nil {
		return Blob{}, fmt.Errorf("blob: %s: %w", hash, err)
	}
	return b, nil
}

// CheckRule refuses a rule outside the slice's subset of spec §4: words, `*`
// for one argument, and `**` for zero or more in the last position. An entity
// class or a regex is refused by name — read as a word it would silently never
// match, which is the failure §4 makes a load error.
func CheckRule(rule string) error {
	terms := strings.Fields(rule)
	if len(terms) == 0 {
		return errors.New("blob: an empty rule matches nothing; remove it")
	}
	for i, t := range terms {
		switch {
		case t == "**" && i != len(terms)-1:
			return fmt.Errorf("blob: rule %q: `**` is trailing-only (spec §4)", rule)
		case strings.HasPrefix(t, "@"), len(t) > 1 && strings.HasPrefix(t, "/") && strings.HasSuffix(t, "/"):
			return fmt.Errorf("blob: rule %q: %q is an entity class or a regex, which the policy engine "+
				"compiles (plan 4); the vertical slice matches words, `*` and a trailing `**`", rule, t)
		case t != "*" && t != "**" && strings.Contains(t, "*"):
			return fmt.Errorf("blob: rule %q: %q puts a wildcard inside a word; a wildcard is a whole term (spec §4)", rule, t)
		}
	}
	return nil
}

// Matches reports whether rule matches the whole command vector: there is no
// implicit prefix match (spec §4). Words compare case-insensitively.
func Matches(rule string, vector []string) bool {
	terms := strings.Fields(rule)
	for i, t := range terms {
		if t == "**" {
			return true // trailing-only, by CheckRule
		}
		if i >= len(vector) {
			return false
		}
		if t != "*" && !strings.EqualFold(t, vector[i]) {
			return false
		}
	}
	return len(vector) == len(terms)
}

// Verdict is the slice's command decision.
type Verdict int

const (
	NoRuleMatched Verdict = iota
	Permitted
	Denied
)

// Command decides one command vector, deny-overrides: a matching deny refuses
// whatever permit also matches, and otherwise a matching permit allows. That
// is stricter than spec §5.4's specificity dominance, which plan 4 replaces it
// with: it can only refuse a command dominance would permit, never permit one
// dominance would refuse.
func (b Blob) Command(vector []string) Verdict {
	for _, r := range b.Deny {
		if Matches(r, vector) {
			return Denied
		}
	}
	for _, r := range b.Permit {
		if Matches(r, vector) {
			return Permitted
		}
	}
	return NoRuleMatched
}
