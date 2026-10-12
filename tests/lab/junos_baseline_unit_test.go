//go:build lab

package lab

import (
	"strings"
	"testing"
)

// These run without a device: L58's entry cell and its `save` verdict.

func TestL58EntryCell(t *testing.T) {
	for _, c := range []struct{ out, want string }{
		{"<?xml version=\"1.0\"?>\n<junoscript xmlns=\"http://xml.juniper.net/xnm/1.1/xnm\">", "greeting"},
		{"<hello xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"></hello>", "greeting"},
		{"xml-mode\n^\nunknown command.\nuser@srx1> ", "refused"},
		{"user@srx1> ", "not observed"},
	} {
		if got := l58EntryCell(c.out); got != c.want {
			t.Errorf("%q: %s, want %s", c.out, got, c.want)
		}
	}
}

// G5 reads the shipped readonly's `save` refusals with the caret under `save`,
// as G3 does: a "refused" cell whose caret sits elsewhere is the image's own
// refusal, not the deny's.
func TestL58Nested(t *testing.T) {
	const prompt = "alice01@srx1> "
	a, b := junosL58Saves[0], junosL58Saves[1]
	atSave := "save dhcp-security-snoop\n" + strings.Repeat(" ", len(prompt)) + "^\nunknown command.\n"
	pastSave := "save dhcp-security-snoop /var/tmp/x\n" + strings.Repeat(" ", len(prompt)+len("save dhcp-security-snoop ")) +
		"^\nsyntax error, expecting <command>.\n"
	entries := func(cell string) map[string]string {
		m := map[string]string{}
		for _, e := range junosL58Entries {
			m[e] = cell
		}
		return m
	}
	with := func(m map[string]string, kv ...string) map[string]string {
		for i := 0; i < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return m
	}
	for _, c := range []struct {
		name                string
		deny, shipped, outs map[string]string
		want                bool
	}{
		{"caret under save", with(entries("refused"), a, "refused", b, "refused"),
			with(entries("refused"), a, "refused", b, "refused"), map[string]string{a: atSave, b: atSave}, true},
		{"refusal past save is the image's own", with(entries("refused"), a, "refused"),
			with(entries("refused"), a, "refused"), map[string]string{a: pastSave}, false},
		{"no output to read the caret in", with(entries("refused"), a, "refused"),
			with(entries("refused"), a, "refused"), map[string]string{}, false},
		{"shipped did not refuse where the deny did", with(entries("refused"), a, "refused"),
			with(entries("refused"), a, "ran"), map[string]string{a: atSave}, false},
		{"the deny refused no save: none to check", entries("refused"), entries("refused"), nil, true},
		{"shipped entry greeted", with(entries("refused"), a, "refused"),
			with(entries("refused"), a, "refused", junosL58Entries[0], "greeting"), map[string]string{a: atSave}, false},
	} {
		if got := l58Nested(c.deny, c.shipped, c.outs, len(prompt)); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

// `save` is proven by any candidate the control ran and the deny refused;
// a control that refused every candidate leaves it unproven, never absent.
func TestL58Save(t *testing.T) {
	a, b := junosL58Saves[0], junosL58Saves[1]
	if v, by := l58Save(map[string]string{a: "refused", b: "ran"}, map[string]string{a: "refused", b: "refused"},
		nil, 0); v != "proven" || by != b {
		t.Errorf("the second candidate: %s %q", v, by)
	}
	if v, _ := l58Save(map[string]string{a: "refused", b: "refused"}, map[string]string{a: "refused", b: "refused"},
		map[string]string{a: "unknown command", b: "unknown command"}, 0); v != "unproven" {
		t.Errorf("the control ran none: %s", v)
	}
	if v, _ := l58Save(map[string]string{a: "ran", b: "ran"}, map[string]string{a: "ran", b: "not observed"},
		nil, 0); v != "unproven" {
		t.Errorf("the deny refused none: %s", v)
	}
	// vSRX, measured 2026-10-11: the control's CLI took `save` and refused
	// after it; the deny refused at `save`.
	const prompt = "alice01@srx1> "
	platform := "\nerror: command is not valid on the vsrx\n"
	past := "save dhcp-security-snoop /var/tmp/x\n" + strings.Repeat(" ", len(prompt)+len("save dhcp-security-snoop ")) +
		"^\nsyntax error, expecting <command>.\n"
	at := "save dhcp-security-snoop\n" + strings.Repeat(" ", len(prompt)) + "^\nunknown command.\n"
	for _, c := range []struct {
		name, out, deny, want string
	}{
		{"platform refusal", platform, "refused", "proven"},
		{"caret past save", past, "refused", "proven"},
		{"caret at save", at, "refused", "unproven"},
		{"deny not refused", platform, "not observed", "unproven"},
	} {
		v, _ := l58Save(map[string]string{a: "refused", b: "not observed"}, map[string]string{a: c.deny, b: c.deny},
			map[string]string{a: c.out, b: c.out}, len(prompt))
		if v != c.want {
			t.Errorf("%s: %s, want %s", c.name, v, c.want)
		}
	}
}
