package policy

import (
	"strings"
	"testing"
)

// A refused policy's error goes to port49d's stderr at start and on every
// reload, and to CI through policy test, diff and explain, and the refused
// file's own redaction patterns never loaded. So a load error quotes nothing
// the file says: it names where — the role, the list, the test row, the
// class, the index, the line — and what is wrong, never the value
// (spec §5.8; task 11 review C3, C4, M3, M4, fail closed).
func TestARefusalQuotesNothingFromTheFile(t *testing.T) {
	const base = scopeOK + roleOK + subjOK + grantOK
	block := func(body string) string { return "platforms:\n  arista_eos:\n    " + body + "\n" + base }
	for _, tt := range []struct{ name, yaml, want string }{
		// C3: an entity class pattern RE2 refuses.
		{"a class pattern that does not compile", block("entity_classes: {bad_comm: ['^Hunter2(']}"),
			"platforms.arista_eos.entity_classes.bad_comm[0] does not compile: missing closing )"},
		// C4: a test row's command.
		{"a test row's command", base + "tests:\n  - {subject: s, device: leaf-01, command: \"snmp-server community " +
			"Hunter2 ro\", expect: maybe}\n", "tests[0] (subject s, device leaf-01): expect is permit or deny"},
		{"a test row's reason", base + "tests:\n  - {subject: s, device: leaf-01, command: show, expect: deny, " +
			"reason: Hunter2}\n",
			"tests[0] (subject s, device leaf-01): the reason is not in spec §5.7's vocabulary"},
		{"a test row's priv_lvl", base + "tests:\n  - {subject: s, device: leaf-01, priv_lvl: Hunter2}\n",
			"tests[0] (subject s, device leaf-01): priv_lvl is a number from 0 to 15, or none"},
		{"a test row's enable", base + "tests:\n  - {subject: s, device: leaf-01, enable: Hunter2}\n",
			"tests[0] (subject s, device leaf-01): enable is none, auto or token"},
		{"a test row's api", base + "tests:\n  - {subject: s, device: leaf-01, command: show, expect: permit, " +
			"api: [Hunter2]}\n", "tests[0] (subject s, device leaf-01): api[0] is not a right"},
		// M3: YAML keys.
		{"an unknown field", "roles:\n  - {name: r, \"snmp-server community Hunter2\": x}\n" + subjOK,
			"line 2: an unknown field"},
		{"a duplicate key", "roles:\n  - {name: r, Hunter2: x, Hunter2: y}\n" + subjOK, "line 2: a mapping key"},
		// M4: an operator redaction pattern.
		{"a redaction after of two words", block("redact: [{match: ['**'], after: 'psk Hunter2'}]"),
			"platforms.arista_eos.redact[0]: after is one word"},
		{"a redaction match word with a slash", block("redact: [{match: [crypto, 'Hunter2/x'], after: psk}]"),
			"platforms.arista_eos.redact[0]: match word #2: a pattern is words"},
		// The sweep: every other value a load error used to echo.
		{"a subject's enable", roleOK + "subjects:\n  - {name: s, identity: [\"user:a@example.com\"], username: a, " +
			"enable: Hunter2, token_ttl: 60s}\n", `subject "s": enable must be none, auto or token`},
		{"a subject's api right", roleOK + "subjects:\n  - {name: s, identity: [\"user:a@example.com\"], username: a, " +
			"token_ttl: 60s, api: [Hunter2]}\n", `subject "s": api[0] is not a right`},
		{"a scope's on_missing", "scopes:\n  - {name: x, match: {site: dc1}, on_missing: Hunter2}\n" + subjOK,
			`scope "x": on_missing is include or exclude`},
		{"a scope regex", "scopes:\n  - {name: x, match: {site: {re: \"(Hunter2\"}}}\n" + subjOK,
			`scope "x": match.site.re does not compile: missing closing )`},
		{"a scope comparison", "scopes:\n  - {name: x, match: {site: {Hunter2: \"1\"}}}\n" + subjOK,
			"not a comparison"},
		{"a grant's expires", scopeOK + roleOK + subjOK + "grants:\n  - {subject: s, scope: all_devices, roles: [r], " +
			"expires: Hunter2}\n", "expires is a date (2026-12-01) or an RFC 3339 time"},
		{"an attribute with no separator", "roles:\n  - {name: r, attributes: {all: [Hunter2]}}\n" + subjOK,
			"attributes.all[0]: an attribute has no `=` (mandatory) or `*` (optional) separator"},
		{"a placeholder in a privilege attribute", "roles:\n  - {name: r, attributes: {all: [\"priv-lvl={username}" +
			"Hunter2\"]}}\n" + subjOK, "attributes.all[0]: priv-lvl carries privilege and takes no placeholder"},
		{"a capability", block("supports: [session, Hunter2]"), "platforms.arista_eos.supports[1] is not a capability"},
		{"a level's rendering", block("privilege: {admin: ['priv-lvl=Hunter2']}"),
			"platforms.arista_eos.privilege.admin[0]: not a privilege level"},
		{"an accepted attribute name", block("accepted_attributes: ['Hunter2=x']"),
			"platforms.arista_eos.accepted_attributes[0] is not an attribute name"},
		{"a pipe token", block("pipe_token: 'Hunter2 x'"),
			"platforms.arista_eos.pipe_token is not one argument with no whitespace"},
		{"a role_order value ranked twice", block("role_order: {roles: [Hunter2, Hunter2]}"),
			"platforms.arista_eos.role_order.roles[1] is ranked twice"},
	} {
		_, err := Parse([]byte(tt.yaml), env())
		if err == nil || !strings.Contains(err.Error(), tt.want) || strings.Contains(strings.ToLower(err.Error()), "hunt") {
			t.Errorf("%s: %v", tt.name, err)
		}
	}
}
