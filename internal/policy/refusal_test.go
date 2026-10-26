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
		// Task 11 re-review m5, m6: a tagged scalar and an alias quote the
		// value too.
		{"a tagged scalar", "roles:\n  - {name: r, deny: [!!int \"snmp-server community Hunter2\"]}\n" + subjOK,
			"cannot decode a !!str value as a !!int; look for an explicit !!tag"},
		{"an unknown anchor", "roles:\n  - {name: r, deny: [*Hunter2]}\n" + subjOK, "an unknown anchor"},
		// M4: an operator redaction pattern.
		{"a redaction after of two words", block("redact: [{match: ['**'], after: 'psk Hunter2'}]"),
			"platforms.arista_eos.redact[0]: after is one word"},
		{"a redaction match word with a slash", block("redact: [{match: [crypto, 'Hunter2/x'], after: psk}]"),
			"platforms.arista_eos.redact[0]: match word #2: a pattern is words"},
		// The sweep: every other value a load error used to echo.
		// A secret pasted into the keys: block: a custom tag, and a value
		// holding a backtick, which cut the quoted text short.
		{"a custom tag in keys", roleOK + subjOK + "keys:\n  k:\n    current: !Hunter2 x\n",
			"cannot decode a value with a custom tag"},
		{"a backtick in keys", roleOK + subjOK + "keys:\n  k:\n    current: Hunt`er2-pasted-here\n",
			"cannot unmarshal a !!str value"},
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

// leakShapes are the ways a key pasted where a keys: block names a reference
// reaches yaml.v3's error text: a quoted value, a backtick in it, a newline
// in it, a block literal, a custom tag, a secondary-handle tag and a verbatim
// one (re-review 8, I1). {KEY} is the pasted secret.
var leakShapes = []string{
	"{KEY}",
	"\"`{KEY}\"",
	"\"`\\n{KEY}\"",
	"\"a\\n{KEY}\"",
	"|\n      {KEY}",
	"|\n      x\n      {KEY}",
	"!{KEY} x",
	"!!{KEY} x",
	"!!{KEY}-x y",
	"!<{KEY}> x",
}

// A policy decode error carries a line and a fixed category, never a byte of
// a value, tag or key the file holds, in any shape yaml.v3 quotes it in.
func TestADecodeErrorCarriesNoPastedKey(t *testing.T) {
	// A key of nine bytes or less is echoed whole by yaml.v3, so both lengths.
	for _, key := range []string{"Wd7ZkP2mRq9TxL4vNc8B", "Wd7ZkP2mR"} {
		testDecodeErrorCarriesNoKey(t, key)
	}
}

func testDecodeErrorCarriesNoKey(t *testing.T, key string) {
	t.Helper()
	for _, shape := range leakShapes {
		body := roleOK + subjOK + "keys:\n  k:\n    current: " + strings.ReplaceAll(shape, "{KEY}", key) + "\n"
		_, err := Parse([]byte(body), env())
		if err == nil {
			t.Errorf("%q parsed", shape)
			continue
		}
		for i := 0; i+4 <= len(key); i++ {
			if strings.Contains(err.Error(), key[i:i+4]) {
				t.Errorf("%q: the error carries the key (window %d)", shape, i) // never the text: it holds the key
				break
			}
		}
	}
}

// The policy editors read the file as nodes, and a node decode quotes an
// alias's name when it is unknown: a key pasted as `*KEY` or `<<: *KEY`
// must not come back in the error `grants remove` and `platform upgrade`
// print (re-review 8, round 2 I1).
func TestAPolicyEditorsErrorCarriesNoAliasName(t *testing.T) {
	const pasted = "Wd7ZkP2mRq9TxL4vNc8B"
	for _, shape := range []string{"keys:\n  k:\n    current: *{KEY}\n", "keys:\n  k:\n    <<: *{KEY}\n"} {
		raw := []byte(roleOK + subjOK + strings.ReplaceAll(shape, "{KEY}", pasted))
		_, _, errRemove := RemoveSubject(raw, "s")
		_, errSet := SetPlatformSet(raw, "1.0.0")
		for name, err := range map[string]error{"RemoveSubject": errRemove, "SetPlatformSet": errSet} {
			if err == nil {
				t.Errorf("%s accepted %q", name, shape)
				continue
			}
			for i := 0; i+4 <= len(pasted); i++ {
				if strings.Contains(err.Error(), pasted[i:i+4]) {
					t.Errorf("%s on %q: the error carries the key", name, shape) // not the error: it holds the key
					break
				}
			}
		}
	}
}
