// Package engine is the policy engine's executor: the compiled blob a token
// names (spec §5.1.1, §5.1.2) and the one evaluator that decides against it.
// The daemon runs it on every authorization, `port49 policy replay` runs it on a
// logged record, and `port49 explain` runs it on a hypothetical one — the same
// code, so a replay that disagrees with the log is a finding and never a
// difference between two implementations (spec §5.7, "Replay").
//
// A blob is fully compiled: it carries the platform's normalization
// parameters and the patterns behind every entity class its rules name, so
// the daemon never reads a platform definition (spec §13, decision 9). It is
// content-addressed — its name is the hash of its bytes — and immutable.
package engine

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
)

// Version is the blob format this package writes and the only one it reads.
// Plan 3's slice blob has none, and is refused by name.
const Version = 2

// Blob is one compiled decision: the rules a principal's composed roles
// resolve to on one platform, and the session reply that goes with them.
type Blob struct {
	Version int `json:"version"`
	// Bundle names the policy the blob was compiled from (spec §5.7): until
	// plan 6 publishes versioned bundles, the sha256 of the policy file. It is
	// part of the content, so deduplication is per policy version and
	// platform (spec §5.1.2, "Cost").
	Bundle string `json:"bundle"`
	// Platform is the device platform the blob was compiled for. The daemon
	// refuses to answer from a blob compiled for another platform than the
	// device's (blob_platform_mismatch).
	Platform  string    `json:"platform"`
	Normalize Normalize `json:"normalize"`
	// Privilege is the abstract level the roles compose to (spec §6), or ""
	// when no role carries one. It is what `{privilege}` renders.
	Privilege string `json:"privilege"`
	// Attributes are the session authorization reply, platform then role then
	// grant layer already applied, in wire order. They may carry the four
	// substitutions of spec §6, which the daemon fills per session.
	Attributes []string `json:"attributes"`
	// Rules are every permit and deny of the composed roles. Pipe is the
	// output-modifier allowlist (spec §4, "Pipeline stages").
	Rules []Rule   `json:"rules"`
	Pipe  []string `json:"pipe"`
	// Classes are the patterns behind every `@class` the rules name, as this
	// platform defines them.
	Classes map[string][]string `json:"classes"`
}

// Normalize is the platform's dialect as the evaluator needs it (spec §3).
type Normalize struct {
	PipeToken            string `json:"pipe_token"`
	PipeAuthorized       bool   `json:"pipe_authorized"`
	StripCR              bool   `json:"strip_cr"`
	ExpandsAbbreviations bool   `json:"expands_abbreviations"`
}

// Rule is one command rule and the role that carries it. The role is on the
// rule so a decision names exactly one (spec §5.3).
type Rule struct {
	Verdict string `json:"verdict"` // "permit" | "deny"
	Rule    string `json:"rule"`
	Role    string `json:"role"`
}

// The two rule verdicts.
const (
	Permit = "permit"
	Deny   = "deny"
)

// ErrHashMismatch is a body that does not hash to the name it was stored or
// logged under: a store fault, or a log that was altered. Never a decision.
var ErrHashMismatch = errors.New("engine: blob body does not match its hash")

// HashOf names a body: "sha256:" and the hex digest of exactly these bytes.
func HashOf(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Encode puts b in canonical form, refuses it if Decode would, and names it.
// Canonical form is what makes one decision one hash: rules respaced, sorted
// and deduplicated, the pipe list the same, class patterns sorted and
// deduplicated, classes no rule names dropped, and nil slices empty. Sorting is
// safe because evaluation is order-independent (spec §5.4). Attributes keep
// their order, which is the wire's.
func Encode(b Blob) ([]byte, string, error) {
	c := Blob{Version: Version, Bundle: b.Bundle, Platform: b.Platform, Normalize: b.Normalize,
		Privilege: b.Privilege, Attributes: append([]string{}, b.Attributes...),
		Rules: []Rule{}, Pipe: []string{}, Classes: map[string][]string{}}
	for _, r := range b.Rules {
		c.Rules = append(c.Rules, Rule{Verdict: r.Verdict, Rule: CanonicalRule(r.Rule), Role: r.Role})
	}
	slices.SortFunc(c.Rules, func(x, y Rule) int {
		return strings.Compare(x.Verdict+"\x00"+x.Rule+"\x00"+x.Role, y.Verdict+"\x00"+y.Rule+"\x00"+y.Role)
	})
	c.Rules = slices.Compact(c.Rules)
	for _, p := range b.Pipe {
		c.Pipe = append(c.Pipe, CanonicalRule(p))
	}
	slices.Sort(c.Pipe)
	c.Pipe = slices.Compact(c.Pipe)
	for name := range referencedClasses(c) {
		patterns := append([]string(nil), b.Classes[name]...)
		slices.Sort(patterns)
		c.Classes[name] = slices.Compact(patterns)
	}
	if err := c.check(); err != nil {
		return nil, "", err
	}
	body, err := json.Marshal(c)
	if err != nil {
		return nil, "", err
	}
	return body, HashOf(body), nil
}

// Decode parses a blob and refuses anything it cannot decide with, because a
// half-understood decision is how a daemon and a broker come to disagree about
// a rule (spec §5.1.2): a body that does not hash to its name, a field this
// build does not know, another format version, bytes after the value, and a
// blob whose rules would not run. Every refusal is an error, which the daemon
// answers blob_unavailable — never a permit.
func Decode(hash string, body []byte) (Blob, error) {
	if HashOf(body) != hash {
		return Blob{}, ErrHashMismatch
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var b Blob
	if err := dec.Decode(&b); err != nil {
		return Blob{}, fmt.Errorf("engine: blob %s: %w (a blob with no \"version\" is plan 3's, which this "+
			"daemon does not read)", hash, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return Blob{}, fmt.Errorf("engine: blob %s: bytes after the blob", hash)
	}
	if err := b.check(); err != nil {
		return Blob{}, fmt.Errorf("%w (blob %s)", err, hash)
	}
	return b, nil
}

// check refuses a blob this package cannot decide with. It is the one
// definition of "valid" that Encode and Decode share.
func (b Blob) check() error {
	if b.Version != Version {
		return fmt.Errorf("engine: blob format version %d; this build reads %d", b.Version, Version)
	}
	if b.Platform == "" {
		return errors.New("engine: blob names no platform")
	}
	if b.Normalize.PipeToken == "" {
		return errors.New("engine: blob has no pipe token")
	}
	for _, r := range b.Rules {
		if r.Verdict != Permit && r.Verdict != Deny {
			return fmt.Errorf("engine: rule %q: verdict %q is neither permit nor deny", r.Rule, r.Verdict)
		}
		if r.Role == "" {
			return fmt.Errorf("engine: rule %q names no role", r.Rule)
		}
		if _, err := ParseRule(r.Rule); err != nil {
			return fmt.Errorf("engine: %w", err)
		}
	}
	for _, p := range b.Pipe {
		if _, err := ParseRule(p); err != nil {
			return fmt.Errorf("engine: pipe %w", err)
		}
	}
	for name := range referencedClasses(b) {
		patterns := b.Classes[name]
		if len(patterns) == 0 {
			return fmt.Errorf("engine: a rule names @%s and the blob carries no pattern for it", name)
		}
		for _, p := range patterns {
			if _, err := compileTerm(p); err != nil {
				return fmt.Errorf("engine: @%s pattern %q: %w", name, p, err)
			}
		}
	}
	for _, a := range b.Attributes {
		if err := CheckAttribute(a); err != nil {
			return fmt.Errorf("engine: %w", err)
		}
	}
	return nil
}

// referencedClasses is the set of class names b's rules and pipe list use.
// Rules that do not parse contribute nothing; check refuses them itself.
func referencedClasses(b Blob) map[string]bool {
	out := map[string]bool{}
	add := func(rule string) {
		terms, err := ParseRule(rule)
		if err != nil {
			return
		}
		for _, t := range terms {
			if t.Kind == Class {
				out[t.Text] = true
			}
		}
	}
	for _, r := range b.Rules {
		add(r.Rule)
	}
	for _, p := range b.Pipe {
		add(p)
	}
	return out
}
