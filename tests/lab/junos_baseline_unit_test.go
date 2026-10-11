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
