package projection

import (
	"fmt"
	"slices"
	"strings"

	"github.com/rhwendt/port49/internal/engine"
)

// Junos matches a deny-commands or allow-commands regex against a command's
// keywords only, never its arguments: `^show interfaces fxp0( .*)?$` did not
// refuse `show interfaces fxp0 terse` on either image, while a deny of
// keywords refused them typed, abbreviated or piped
// (tests/lab/results/L12-juniper_*.md, L9-juniper_*.md; spec §13 decision
// 27). port49 has no Junos grammar, so a rule reaches the wire only where the
// set's keyword tree proves each of its words a keyword (platform.Keywords).
// What is proven is the one shape the device matches as port49 does: words,
// optionally ending in `**`. A `*`, an entity class or a regex stands for an
// argument, and so does a word the tree does not list at its place.

// keywordShape is rule's words before any `**`, whether `**` ends it, and
// the first term that is not a word, as its text, or "" where every term
// before `**` is one.
func keywordShape(rule string) (words []string, rest bool, other string) {
	terms, err := engine.ParseRule(rule)
	if err != nil {
		return nil, false, rule
	}
	for _, t := range terms {
		switch t.Kind {
		case engine.Word:
			words = append(words, t.Text)
		case engine.Rest:
			return words, true, ""
		case engine.Any:
			return words, false, "*"
		case engine.Class:
			return words, false, "@" + t.Text
		default:
			return words, false, "/" + t.Text + "/"
		}
	}
	return words, false, ""
}

// argument is the first term of rule the keyword tree does not prove a
// keyword, as the rule writes it, and the words before it, which are: ok
// where every word is proven and none stands for an argument.
func (g generator) argument(rule string) (term string, prefix []string, ok bool) {
	words, _, other := keywordShape(rule)
	for i, w := range words {
		if !g.in.Keywords.Keyword(words[:i], w) {
			return w, words[:i], false
		}
	}
	if other != "" {
		return other, words, false
	}
	return "", words, true
}

// denyProvable reports whether the device refuses every command a deny of
// rule matches: each word is a keyword, so the command's keywords begin with
// them, and a trailing `**` is the regex's own `( .*)?`. The device may
// refuse more — `show interfaces` exactly also refuses `show interfaces
// fxp0` — which is narrower, and fails closed.
func (g generator) denyProvable(rule string) bool {
	_, _, ok := g.argument(rule)
	return ok
}

// unsendableAllow is why an allow of rule cannot go out, or "": on the
// device an allow runs every command whose keywords its regex matches, so
// it is sent only where those are the commands port49 permits under it. A
// word that is not a keyword never matches, and an argument that may be typed
// among the rule's words would be run too: `show interfaces terse` would also
// run `show interfaces fxp0 terse`. Both are left off the wire, which is
// narrower, and reported.
func (g generator) unsendableAllow(rule string) string {
	term, prefix, ok := g.argument(rule)
	if !ok {
		return g.argumentWhy(term, prefix) + ", so an allow of it never matches on the device"
	}
	// An argument typed before any of the rule's words, or after its last
	// where no `**` permits one there, is one port49 does not permit.
	words, rest, _ := keywordShape(rule)
	places := len(words)
	if !rest {
		places++
	}
	for i := 0; i < places; i++ {
		if g.in.Keywords.TakesArgument(words[:i]) {
			at := strings.Join(words[:i], " ")
			return fmt.Sprintf("an argument may be typed after %s, so an allow of it would also run %s with an "+
				"argument there, which port49 does not permit", g.quote(at), g.quote(strings.TrimSpace(at+" <argument> "+
				strings.Join(words[i:], " "))))
		}
	}
	return ""
}

// argumentWhy says which term is not a proven keyword, each value a
// redaction hides redacted (quote, shown).
func (g generator) argumentWhy(term string, prefix []string) string {
	if strings.HasPrefix(term, "@") || strings.HasPrefix(term, "/") || term == "*" {
		return fmt.Sprintf("%s stands for an argument", g.shown(term))
	}
	at := strings.Join(prefix, " ")
	if at == "" {
		return fmt.Sprintf("%s is not a keyword the lab measured at the start of a command", g.quote(term))
	}
	return fmt.Sprintf("%s is not a keyword the lab measured after %s", g.quote(term), g.quote(at))
}

// configurationVerbs are the configuration-mode commands that change the
// configuration. deny-commands never reaches a statement typed there: under a
// deny naming `set system host-name`, the statement ran on both images
// (tests/lab/results/L12-configuration-juniper_*.md). A reply that can enter
// configuration mode carries no deny at all (configuration), so a deny
// starting with one of these is enforced only as an operational command, where
// the keyword tree proves it or it fails closed.
var configurationVerbs = []string{"activate", "annotate", "commit", "copy", "deactivate", "delete", "edit",
	"insert", "load", "protect", "rename", "replace", "rollback", "save", "set", "top", "unprotect", "up",
	"wildcard"}

// denyRefusal is the refusal of a deny that meets a permit and is not proven
// keyword-only: configuration_deny where its first word is a configuration
// verb, argument_deny otherwise.
func (g generator) denyRefusal(d engine.Rule) error {
	words, _, _ := keywordShape(d.Rule)
	if len(words) == 0 || !slices.Contains(configurationVerbs, strings.ToLower(words[0])) {
		return g.argumentDeny(d)
	}
	term, prefix, _ := g.argument(d.Rule)
	return refuse(FailConfigurationDeny, "on %s, `deny %s` (role %q) names a configuration statement, and Junos "+
		"never applies deny-commands in configuration mode: on both images a statement ran there under a "+
		"deny-commands naming it (tests/lab/results/L12-configuration-juniper_*.md), and deny-configuration is not "+
		"measured; as an operational command it is not proven either (%s). port49 cannot enforce it: drop the rule",
		g.in.Platform, g.shown(d.Rule), d.Role, g.argumentWhy(term, prefix))
}

// argumentDeny is decision 27's refusal of a deny port49 needs enforced and
// the device cannot: the subject gets the fail-closed reply, and `policy
// test` and `policy diff` name the word and the whole command to deny instead.
func (g generator) argumentDeny(d engine.Rule) error {
	term, prefix, _ := g.argument(d.Rule)
	instead := "drop the rule"
	if len(prefix) > 0 {
		instead = fmt.Sprintf("deny the whole command (`%s`) or drop the rule", g.shown(strings.Join(prefix, " ")))
	}
	return refuse(FailArgumentDeny, "on %s, Junos can't deny by argument: `%s` in `deny %s` (role %q): %s, and "+
		"Junos matches a deny against a command's keywords only (tests/lab/results/L12-juniper_*.md); %s",
		g.in.Platform, g.shown(term), g.shown(d.Rule), d.Role, g.argumentWhy(term, prefix), instead)
}
