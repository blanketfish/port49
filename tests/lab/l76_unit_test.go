package lab

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/rhwendt/port49/tests/lab/labcreds"
)

// Every L76 cell is in the register row, word for word, in order, once.
func TestL76CellsAreTheRegistersCells(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "design", "2026-08-23-policy-engine-spec.md"))
	if err != nil {
		t.Fatal(err)
	}
	var row string
	for _, ln := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(ln, "| **L76** |") {
			row = ln
		}
	}
	if row == "" {
		t.Fatal("spec §15 has no L76 row")
	}
	want := []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"}
	if len(l76Cells) != len(want) {
		t.Fatalf("%d cells, want %d", len(l76Cells), len(want))
	}
	last := -1
	for i, c := range l76Cells {
		if c.id != want[i] {
			t.Errorf("cell %d is %q, want %q", i, c.id, want[i])
		}
		at := strings.Index(row, "("+c.id+") "+c.claim)
		if at < 0 {
			t.Errorf("cell %s's claim is not in the row:\n%s", c.id, c.claim)
		}
		if at <= last {
			t.Errorf("cell %s is out of order in the row", c.id)
		}
		if n := strings.Count(row, "("+c.id+") "+c.claim); n != 1 {
			t.Errorf("cell %s's claim is in the row %d times, want once", c.id, n)
		}
		last = at
	}
	if !strings.HasPrefix(l76Claim(), "Nokia SR Linux") || !strings.Contains(l76Claim(), "(j) "+l76Cells[9].claim) {
		t.Errorf("l76Claim does not carry the cells: %q", l76Claim())
	}
}

// The topology, inventory, seeds and startup config agree with the constants.
func TestL76FilesAgree(t *testing.T) {
	read := func(p string) string {
		t.Helper()
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	topo := read(l76Topo)
	for _, s := range []string{"name: port49-srlinux", "    " + l76Node + ":", "kind: nokia_srlinux",
		"image: " + l76Image, "startup-config: ../" + l76Config, "mgmt-ipv4: " + l76Addr,
		"network: port49-lab", "ipv4-subnet: 172.100.100.0/24"} {
		if !strings.Contains(topo, s) {
			t.Errorf("%s lacks %q", l76Topo, s)
		}
	}
	inv := read("inventory-lab.yaml")
	if !strings.Contains(inv, "{name: "+l76Node+", platform: "+l76PlatformName+", addresses: ["+l76Addr+"]}") {
		t.Errorf("inventory-lab.yaml has no %s line", l76Node)
	}
	cfg := read("port49d-lab.yaml")
	for n := 1; n <= 16; n++ {
		s := "{nas: " + l76Node + ", username: alice" + l76TwoDigits(n) + "}"
		if strings.Count(cfg, s) != 1 {
			t.Errorf("port49d-lab.yaml holds %q %d times, want once", s, strings.Count(cfg, s))
		}
	}
	cli := read(l76Config)
	for i, b := range []byte(cli) {
		if b > 0x7e || (b < 0x20 && b != '\n' && b != '\t') {
			t.Fatalf("%s byte %d is %#02x: startup configs are pure ASCII", l76Config, i, b)
		}
	}
	for _, s := range []string{
		"secret-key " + labcreds.Key, "password " + labcreds.BreakglassPassword,
		"user " + labcreds.BreakglassUser + " {", "server-group local {", "type local",
		"server-group port49 {", "type tacacs", "priv-lvl-authorization true",
		"server 172.100.100.1 {", "network-instance mgmt", "port 49",
		"event command {", "record start-stop",
		"role p49-read {", "priv-lvl 1\n", "role p49-admin {", "priv-lvl 15",
		"action read", "action write",
	} {
		if !strings.Contains(cli, s) {
			t.Errorf("%s lacks %q", l76Config, s)
		}
	}
	if got := l76LeafList(cli, "authentication-method"); strings.Join(got, " ") != "port49 local" {
		t.Errorf("authentication-method is %v, want [port49 local]", got)
	}
	if got := l76LeafList(cli, "accounting-method"); strings.Join(got, " ") != "port49" {
		t.Errorf("accounting-method is %v, want [port49]", got)
	}

	// Each statement sits in the block that owns it: the priv-lvl to role
	// mapping is what cell (h) measures, so a swap must not pass.
	path := func(names ...string) []string {
		t.Helper()
		lines := strings.Split(cli, "\n")
		for _, n := range names {
			var ok bool
			if lines, ok = l76Child(lines, n); !ok {
				t.Fatalf("%s has no block %q under %q", l76Config, n, names)
			}
		}
		return lines
	}
	for _, c := range []struct {
		where []string
		own   string
	}{
		{[]string{"system", "aaa", "authorization", "role p49-read", "tacacs"}, "priv-lvl 1"},
		{[]string{"system", "aaa", "authorization", "role p49-admin", "tacacs"}, "priv-lvl 15"},
		{[]string{"system", "configuration", "role p49-read", "rule /"}, "action read"},
		{[]string{"system", "configuration", "role p49-admin", "rule /"}, "action write"},
		{[]string{"system", "aaa", "server-group port49", "tacacs"}, "priv-lvl-authorization true"},
		{[]string{"system", "aaa", "server-group port49", "server 172.100.100.1", "tacacs"}, "port 49\nsecret-key " + labcreds.Key},
	} {
		if got := strings.Join(l76Own(path(c.where...)), "\n"); got != c.own {
			t.Errorf("%s holds %q, want %q", strings.Join(c.where, " > "), got, c.own)
		}
	}
	user := path("system", "aaa", "authentication", "user "+labcreds.BreakglassUser)
	if got := strings.Join(l76Own(user), "\n"); !strings.HasPrefix(got, "password "+labcreds.BreakglassPassword+"\nrole [") {
		t.Errorf("%s's own lines are not its password and its role list", labcreds.BreakglassUser)
	}
	if got := l76LeafList(strings.Join(user, "\n"), "role"); strings.Join(got, " ") != "p49-admin" {
		t.Errorf("%s's roles are %v, want [p49-admin]", labcreds.BreakglassUser, got)
	}
}

// l76Child returns the body of the first direct child block of lines whose
// header line is `name {`, by brace depth.
func l76Child(lines []string, name string) ([]string, bool) {
	depth, start := 0, -1
	for i, ln := range lines {
		ln = strings.TrimSpace(ln)
		if depth == 0 && start < 0 && ln == name+" {" {
			start = i + 1
		}
		if strings.HasSuffix(ln, "{") {
			depth++
		}
		if ln == "}" {
			depth--
			if start >= 0 && depth == 0 {
				return lines[start:i], true
			}
		}
	}
	return nil, false
}

// l76Own returns the depth-0 lines of a block body: its leaf statements,
// without the blocks nested in it and without bracket-list contents.
func l76Own(body []string) []string {
	var out []string
	depth := 0
	for _, ln := range body {
		ln = strings.TrimSpace(ln)
		switch {
		case ln == "":
		case strings.HasSuffix(ln, "{"):
			depth++
		case ln == "}":
			depth--
		case depth == 0:
			out = append(out, ln)
		}
	}
	return out
}

func l76TwoDigits(n int) string { return string([]byte{byte('0' + n/10), byte('0' + n%10)}) }

func TestL76MaskConfigKeepsShapeAndDropsValues(t *testing.T) {
	in := "server 172.100.100.1 {\n    tacacs {\n        secret-key $aes1$AWBu+Zz0aHVr1m8=$Jx0Ab\n" +
		"user breakglass {\n    password $y$j9T$abcdefghijkl$mnopqrstuvwx\n" +
		"user other {\n    password plaintext-here\n" +
		"leaf password {\n" +
		"authentication-method [\n    port49\n    local\n]\n" +
		"nokia-srl-authorization-role-netconf false\n"
	got := l76MaskConfig(in)
	for _, gone := range []string{"$aes1$", "AWBu", "$y$", "j9T", "plaintext-here"} {
		if strings.Contains(got, gone) {
			t.Errorf("%q survived:\n%s", gone, got)
		}
	}
	for _, kept := range []string{"secret-key <masked>", "password <masked>", "leaf password {",
		"server 172.100.100.1 {", "port49", "nokia-srl-authorization-role-netconf false"} {
		if !strings.Contains(got, kept) {
			t.Errorf("%q was lost:\n%s", kept, got)
		}
	}
	if l76MaskConfig(got) != got {
		t.Errorf("masking is not idempotent")
	}
}

// containerlab injects the runner's public keys into the admin users; neither
// the key nor its comment may reach committed evidence.
func TestL76MaskConfigDropsSSHPublicKeys(t *testing.T) {
	in := "admin-user {\n    ssh-key [\n        \"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOab3 someone@somehost\"\n" +
		"        \"ssh-rsa AAAAB3NzaC1yc2EAAAADAQAB other@example.com\"\n    ]\n}\n" +
		"linuxadmin-user {\n    ssh-key [ \"ecdsa-sha2-nistp256 AAAAE2VjZHNh x@y\" ]\n}\n"
	for name, got := range map[string]string{"config": l76MaskConfig(in), "log": l76FilterLog(in)} {
		for _, gone := range []string{"AAAA", "someone@somehost", "other@example.com", "x@y", "ssh-ed25519", "ssh-rsa", "ecdsa-sha2"} {
			if strings.Contains(got, gone) {
				t.Errorf("%s: %q survived:\n%s", name, gone, got)
			}
		}
		if strings.Count(got, "<ssh public key masked>") != 3 || !strings.Contains(got, "ssh-key [") {
			t.Errorf("%s: the statements were not kept:\n%s", name, got)
		}
		if leaks := l76Leaks(got, nil); len(leaks) != 0 {
			t.Errorf("%s: masked text still leaks %v", name, leaks)
		}
	}
	if leaks := l76Leaks(in, nil); len(leaks) == 0 || leaks[0] != "an SSH public key" {
		t.Errorf("unmasked keys: %v", leaks)
	}
}

func TestL76FilterLogFollowsTheShellRule(t *testing.T) {
	in := "Oct 17 alice01 authenticated via port49\n" +
		"tacacs+ reply: password incorrect\n" +
		"got token abc\n" +
		"shared secret mismatch\n" +
		"bearer eyJhbGciOi\n" +
		"hash $6$saltsalt$deadbeef\n" +
		"blob QUJDREVGR0hJSktMTU5PUFFSU1RVVldY end\n"
	got := l76FilterLog(in)
	for _, gone := range []string{"incorrect", "token", "secret", "eyJ", "$6$", "QUJDREVGR0hJSktMTU5PUFFSU1RVVldY"} {
		if strings.Contains(strings.ToLower(got), strings.ToLower(gone)) {
			t.Errorf("%q survived:\n%s", gone, got)
		}
	}
	for _, kept := range []string{"alice01 authenticated via port49", "blob <LONG> end", "hash <masked>"} {
		if !strings.Contains(got, kept) {
			t.Errorf("%q was lost:\n%s", kept, got)
		}
	}
}

func TestL76GrepKeepsMatchingLinesOnly(t *testing.T) {
	got := l76Grep("a alice01 x\nb TACACS y\nc other\n", []string{"alice01", "tacacs"})
	if got != "a alice01 x\nb TACACS y" {
		t.Errorf("got %q", got)
	}
}

func TestL76LeaksFindsEverySecretAndShape(t *testing.T) {
	secrets := []string{"labsecret", "breakglass-only", "0123456789abcdef0123456789abcdef"}
	if got := l76Leaks("clean text, secret-key <masked>", secrets); len(got) != 0 {
		t.Errorf("clean text leaks %v", got)
	}
	for text, want := range map[string]string{
		"key labsecret":                        "secret #0",
		"pw breakglass-only":                   "secret #1",
		"x 0123456789abcdef0123456789abcdef y": "secret #2",
		"secret-key $aes1$AAAA":                "a hash",
		"password $ar2$BBBB":                   "a hash",
		"Authorization: Bearer eyJhbGciOiJ":    "a JWT",
	} {
		got := l76Leaks(text, secrets)
		if len(got) != 1 || got[0] != want {
			t.Errorf("%q: %v, want [%s]", text, got, want)
		}
	}
	if got := l76Leaks("labsecret", []string{""}); len(got) != 0 {
		t.Errorf("an empty secret matched: %v", got)
	}
}

// Every hash scheme the gate names is caught on its own, outside a
// secret-key or password statement that would mask it anyway.
func TestL76LeaksFindsEachHashScheme(t *testing.T) {
	for _, text := range []string{"x $aes1$AAAA", "x $ar2$AAAA", "x $y$j9T$AAAA", "x $1$AAAA", "x $5$AAAA", "x $6$AAAA", "x $8$AAAA", "x $9$AAAA"} {
		if got := l76Leaks(text, nil); len(got) != 1 || got[0] != "a hash" {
			t.Errorf("%q: %v, want [a hash]", text, got)
		}
	}
	if got := l76Leaks("price $7 and $x$ ok", nil); len(got) != 0 {
		t.Errorf("a non-hash leaks %v", got)
	}
}

// OpenSSH certificate key types carry the same user@host comment.
func TestL76SSHKeyMaskCoversCertificateTypes(t *testing.T) {
	in := "ssh-key [\n \"ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5 cert@host\"\n" +
		" \"ecdsa-sha2-nistp256-cert-v01@openssh.com AAAAKGVjZHNh c2@host\"\n" +
		" \"ssh-rsa-cert-v01@openssh.com AAAAHHNzaC1yc2E c3@host\"\n" +
		" \"sk-ssh-ed25519-cert-v01@openssh.com AAAAIHNr c4@host\"\n" +
		" \"sk-ssh-ed25519@openssh.com AAAAGnNr c5@host\" ]\n"
	for name, got := range map[string]string{"config": l76MaskConfig(in), "log": l76FilterLog(in)} {
		for _, gone := range []string{"AAAA", "@host", "cert-v01", "openssh.com"} {
			if strings.Contains(got, gone) {
				t.Errorf("%s: %q survived:\n%s", name, gone, got)
			}
		}
		if n := strings.Count(got, "<ssh public key masked>"); n != 5 {
			t.Errorf("%s: %d keys masked, want 5:\n%s", name, n, got)
		}
	}
	if leaks := l76Leaks(in, nil); len(leaks) != 1 || leaks[0] != "an SSH public key" {
		t.Errorf("unmasked certificate keys: %v", leaks)
	}
}

// A device that wraps a value across lines must not hide it from the gate:
// each half is under the 24-character mask floor.
func TestL76LeaksFindsASecretSplitAcrossLines(t *testing.T) {
	secrets := []string{"labsecret", "9f3a7c1e5b2d4086a1c3e5f70b2d4f68"}
	for name, text := range map[string]string{
		"newline":     "bad key 9f3a7c1e5b2d4086\na1c3e5f70b2d4f68\n",
		"crlf indent": "bad key 9f3a7c1e5b2d4086\r\n        a1c3e5f70b2d4f68",
	} {
		if got := l76Leaks(text, secrets); len(got) != 1 || got[0] != "secret #1" {
			t.Errorf("%s: %v, want [secret #1]", name, got)
		}
		if strings.Contains(l76MaskLong(text), "<LONG>") {
			t.Errorf("%s: the halves are no longer below the mask floor", name)
		}
	}
	if got := l76Leaks("lab\n  secret", secrets); len(got) != 1 || got[0] != "secret #0" {
		t.Errorf("short secret split: %v", got)
	}
	if got := l76Leaks("9f3a7c1e5b2d4086\nunrelated\na1c3e5f70b2d4f68", secrets); len(got) != 0 {
		t.Errorf("unrelated lines leaked %v", got)
	}
	if got := l76Leaks("labsecret\nlab secret", secrets); len(got) != 1 {
		t.Errorf("a secret found twice is named %d times", len(got))
	}
}

func TestL76MaskConfigMasksJSONValuesWithoutMangling(t *testing.T) {
	in := `{"server":[{"name":"s1","secret-key":"plain-one","authentication-key":"p two","password": "x\"y","priv":"$aes1$AWBu+Zz0$Jx0Ab"}],"keep":"ok"}`
	got := l76MaskConfig(in)
	for _, gone := range []string{"plain-one", "p two", `x\"y`, "AWBu", "$aes1$"} {
		if strings.Contains(got, gone) {
			t.Errorf("%q survived:\n%s", gone, got)
		}
	}
	want := `{"server":[{"name":"s1","secret-key":"<masked>","authentication-key":"<masked>","password": "<masked>","priv":"<masked>"}],"keep":"ok"}`
	if got != want {
		t.Errorf("mangled:\n%s\nwant:\n%s", got, want)
	}
	if l76MaskConfig(got) != got {
		t.Errorf("not idempotent")
	}
	if g := l76FilterLog(`{"authentication-key":"abc def","n":1}`); g != `{"authentication-key":"<masked>","n":1}` {
		t.Errorf("log form: %s", g)
	}
	if g := l76MaskConfig("authentication-key secretvalue\n"); g != "authentication-key <masked>\n" {
		t.Errorf("text form: %q", g)
	}
	if g := l76MaskConfig(`{"hash":"$y$j9T$abc$def","n":1}`); g != `{"hash":"<masked>","n":1}` {
		t.Errorf("a quoted hash lost its closing: %s", g)
	}
}

func TestL76HashSchemesIncludeBcryptScryptArgon2(t *testing.T) {
	for _, h := range []string{"$2a$12$abcdefghijklmnopqrstuv", "$2b$12$abc", "$2y$10$abc", "$7$CU..../....abc",
		"$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA", "$argon2i$v=19$abc", "$argon2d$v=19$abc", "$scrypt$ln=16,r=8,p=1$c2FsdA$aGFzaA"} {
		if got := l76Leaks("x "+h, nil); len(got) != 1 || got[0] != "a hash" {
			t.Errorf("gate missed a scheme (%.8s): %v", h, got)
		}
		if got := l76FilterLog("x " + h + " y"); got != "x <masked> y" {
			t.Errorf("log kept a scheme (%.8s): %q", h, got)
		}
	}
	if got := l76Leaks("$2c$ $argon2x$ $3$", nil); len(got) != 0 {
		t.Errorf("non-hashes leak %v", got)
	}
}

// The keyword exemption is for YANG-style names, not for any lowercase run.
func TestL76MaskLongExemptsKeywordsNotLowercaseSecrets(t *testing.T) {
	for _, kept := range []string{"nokia-srl-authorization-role-netconf", "aaa_accounting_event_type"} {
		if got := l76MaskLong("x " + kept + " y"); got != "x "+kept+" y" {
			t.Errorf("keyword masked: %s", got)
		}
	}
	for name, in := range map[string]string{
		"lowercase run":  "x abcdefghijklmnopqrstuvwxyzabcdef y",
		"long segment":   "x ab-abcdefghijklmnopqrstuvwxyzab y",
		"very long path": "x " + strings.Repeat("abc-", 17) + "abc y",
	} {
		if got := l76MaskLong(in); !strings.Contains(got, "<LONG>") {
			t.Errorf("%s was exempted: %s", name, got)
		}
	}
}

func TestL76LeaksIgnoresCaseOfASecret(t *testing.T) {
	secrets := []string{"labsecret", "9f3a7c1e5b2d4086a1c3e5f70b2d4f68"}
	for text, want := range map[string]string{
		"KEY LABSECRET":                             "secret #0",
		"x 9F3A7C1E5B2D4086A1C3E5F70B2D4F68 y":      "secret #1",
		"x 9F3A7C1E5B2D4086\n   A1C3E5F70B2D4F68 y": "secret #1",
	} {
		if got := l76Leaks(text, secrets); len(got) != 1 || got[0] != want {
			t.Errorf("%q: %v, want [%s]", text, got, want)
		}
	}
}

// Only a line break joins the halves of a wrapped value: the published key's
// two words in prose, on one line, are not a leak.
func TestL76LeaksSqueezesLineBreaksNotSpaces(t *testing.T) {
	secrets := []string{"labsecret", "NokiaSrl1!"}
	for _, text := range []string{"a lab secret story", "Lab\tSecret", "LAB  SECRET", "Nokia Srl1!", "the lab\tsecret"} {
		if got := l76Leaks(text, secrets); len(got) != 0 {
			t.Errorf("%q: prose flagged %v", text, got)
		}
	}
	for text, want := range map[string]string{
		"lab\nsecret":      "secret #0",
		"LAB\r\n   SECRET": "secret #0",
		"Nokia\n\tSrl1!":   "secret #1",
		"x labsecret y":    "secret #0",
	} {
		if got := l76Leaks(text, secrets); len(got) != 1 || got[0] != want {
			t.Errorf("%q: %v, want [%s]", text, got, want)
		}
	}
}

func TestL76MaskConfigTextFormValueClasses(t *testing.T) {
	for in, want := range map[string]string{
		`{"d":"change password now","n":1}`:            `{"d":"change password <masked>","n":1}`,
		`{"d":"set secret-key abc"}`:                   `{"d":"set secret-key <masked>"}`,
		`password "two words" tail`:                    `password "<masked>" tail`,
		`password=plainvalue`:                          `password=<masked>`,
		`password: plainvalue`:                         `password: <masked>`,
		"password : plainvalue":                        "password : <masked>",
		`secret-key="a b"`:                             `secret-key="<masked>"`,
		"password:\nnext line":                         "password:\nnext line",
		"leaf password {":                              "leaf password {",
		"authentication-key=k1 authentication-key: k2": "authentication-key=<masked> authentication-key: <masked>",
	} {
		got := l76MaskConfig(in)
		if got != want {
			t.Errorf("%q:\n got %q\nwant %q", in, got, want)
		}
		if l76MaskConfig(got) != got {
			t.Errorf("%q: not idempotent", in)
		}
	}
	if !json.Valid([]byte(l76MaskConfig(`{"d":"change password now","e":"x secret-key y"}`))) {
		t.Errorf("JSON prose mangled")
	}
}

func TestL76FilterLogMasksAuthenticationKey(t *testing.T) {
	for in, want := range map[string]string{
		"authentication-key abc123\n":   "authentication-key <masked>\n",
		"authentication-key=abc123":     "authentication-key=<masked>",
		"authentication-key: abc123 ok": "authentication-key: <masked> ok",
		"authentication-key \"a b\"":    "authentication-key \"<masked>\"",
	} {
		if got := l76FilterLog(in); got != want {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
	}
}

// A quoted value ends on its own line: a string that closes right after the
// keyword must not swallow the statements below it.
func TestL76MaskConfigQuotedValueStaysOnItsLine(t *testing.T) {
	in := "desc \"close after password \"\nsecret-key abc\npassword def\nother \"x\"\n"
	want := "desc \"close after password <masked>\nsecret-key <masked>\npassword <masked>\nother \"x\"\n"
	if got := l76MaskConfig(in); got != want {
		t.Errorf("got %q\nwant %q", got, want)
	}
}

// A quote that never closes still hides its value, to the end of the line.
func TestL76MaskConfigMasksAnUnterminatedQuote(t *testing.T) {
	for in, want := range map[string]string{
		"password \"abc def\nnext line\n":    "password <masked>\nnext line\n",
		"secret-key=\"abc\\\" tail":          "secret-key=<masked>",
		"authentication-key: \"k 1 and more": "authentication-key: <masked>",
	} {
		got := l76MaskConfig(in)
		if got != want {
			t.Errorf("%q:\n got %q\nwant %q", in, got, want)
		}
		if l76MaskConfig(got) != got {
			t.Errorf("%q: not idempotent", in)
		}
	}
}

// The session table in the 26.7.2 report plugin's columns: ID, User name,
// Service name, Authentication method, Priv-lvl, TTY, Remote host, Network
// instance, Login time, Role. The first eight cells of rows 31 and 32 are
// SA#display-user-session-information's own; the network-instance and role
// cells (which the guide's older table lacks), the borders, the header and
// row 30 are rebuilt in that layout, with a login-time cell that wraps.
const l76SessionTable = `+----+----------+---------+--------------+-------+-----+------------+------+----------+-------+
| ID | User     | Service | Authenticati | Priv- | TTY | Remote     | Netw | Login    | Role  |
|    | name     | name    | on method    | lvl   |     | host       | ork  | time     |       |
+====+==========+=========+==============+=======+=====+============+======+==========+=======+
| 30 | admin    | sshd    | LOCAL-GROUP  |       | ssh | 172.18.0.1 | mgmt | 2023-11- |       |
|    |          |         |              |       |     |            |      | 13T10:5  |       |
| 31 | bob      | sshd    | TACACS-GROUP |  15   | ssh | 172.18.0.1 | mgmt | 2023-11- |       |
| 32 | user151* | sshd    | RADIUS-GROUP |       | ssh | 172.18.0.1 | mgmt | 2023-11- |       |
+----+----------+---------+--------------+-------+-----+------------+------+----------+-------+
`

func TestL76SessionsReadTheGuidesTable(t *testing.T) {
	got := l76Sessions(l76SessionTable)
	want := []l76Session{
		{ID: "30", User: "admin", Service: "sshd", Method: "LOCAL-GROUP", PrivLvl: "", TTY: "ssh"},
		{ID: "31", User: "bob", Service: "sshd", Method: "TACACS-GROUP", PrivLvl: "15", TTY: "ssh"},
		{ID: "32", User: "user151", Service: "sshd", Method: "RADIUS-GROUP", PrivLvl: "", TTY: "ssh", Current: true},
	}
	if len(got) != len(want) {
		t.Fatalf("%d rows: %+v", len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("row %d: %+v, want %+v", i, got[i], want[i])
		}
	}
	if l76Sessions("Error: unknown command\n") != nil {
		t.Error("an error message parsed as sessions")
	}
}

func TestL76LeafListReadsBothLayouts(t *testing.T) {
	for _, in := range []string{
		"authentication-method [ port49 local ]\n",
		"authentication-method [\n    port49\n    local\n]\n",
		"x {\n  authentication-method [\n port49\n local\n ]\n idle-timeout 600\n}\n",
	} {
		if got := l76LeafList(in, "authentication-method"); strings.Join(got, ",") != "port49,local" {
			t.Errorf("%q: %v", in, got)
		}
	}
	if l76LeafList("accounting-method [ port49 ]", "authentication-method") != nil {
		t.Error("read another leaf-list")
	}
	if l76LeafList("authentication-method [ port49", "authentication-method") != nil {
		t.Error("read an unterminated list")
	}
}

func TestL76RolesIn(t *testing.T) {
	in := "session 31 {\n    username alice01\n    role [\n        p49-read\n        p49-admin\n    ]\n}\n"
	if got := l76RolesIn(in, "alice01"); strings.Join(got, ",") != "p49-admin,p49-read" {
		t.Errorf("got %v", got)
	}
	if l76RolesIn("session 32 {\n    username carol\n    role [ network-admin ]\n}\n", "carol") != nil {
		t.Error("a role that is not the lab's was read")
	}
}

// The state read lists every session the device holds. Cell (d)'s
// break-glass session (p49-admin) can still be there when (h) logs in at
// priv-lvl 1; reading it would report a false privilege grant (pre-flight I2).
func TestL76RolesInReadsOnlyTheUsersSession(t *testing.T) {
	in := "system {\n    aaa {\n        authentication {\n" +
		"            session 30 {\n                username breakglass\n                role [\n                    p49-admin\n                ]\n            }\n" +
		"            session 31 {\n                username alice01\n                role [\n                    p49-read\n                ]\n            }\n" +
		"        }\n    }\n}\n"
	if got := l76RolesIn(in, "alice01"); strings.Join(got, ",") != "p49-read" {
		t.Errorf("alice01: %v, want [p49-read]", got)
	}
	if got := l76RolesIn(in, "breakglass"); strings.Join(got, ",") != "p49-admin" {
		t.Errorf("breakglass: %v, want [p49-admin]", got)
	}
	own := l76UserSessions(in, "alice01")
	if !strings.Contains(own, "session 31 {") || strings.Contains(own, "breakglass") || strings.Contains(own, "p49-admin") {
		t.Errorf("alice01's blocks hold another session:\n%s", own)
	}
	if l76RolesIn(in, "bob") != nil || l76UserSessions(in, "bob") != "" {
		t.Error("a user with no session read as one")
	}
	if got := l76RolesOf(in, "bob"); got != "(no session block for `bob` in the state read)" {
		t.Errorf("l76RolesOf bob: %q", got)
	}
	if got := l76RolesOf(in, "alice01"); got != "[p49-read]" {
		t.Errorf("l76RolesOf alice01: %q", got)
	}
	if l76RolesIn("session 41 {\n    username dave\n    role [ p49-read ]\n", "dave") != nil {
		t.Error("an unterminated block was read")
	}
	if l76RolesIn("session 42 {\n    username alice011\n    role [ p49-read ]\n}\n", "alice01") != nil {
		t.Error("another user whose name starts with the user's was read")
	}
}

// Every command, set line and sr_cli form the run sends has a cite, and the
// note prints each with its page (pre-flight I3: "cite the doc page in your
// notes").
func TestL76SourcesCiteEveryCommand(t *testing.T) {
	cited := map[string]bool{}
	for _, s := range l76Sources {
		if s.what == "" || !l76CiteKnown(s.cite) {
			t.Errorf("source %q has cite %q: each part must be SA#, CM#, CLAB#, YANG or HELP", s.what, s.cite)
		}
		cited[s.what] = true
	}
	var used []string
	used = append(used, l76Commands...)
	used = append(used, l76SetLines...)
	used = append(used, l76RootForms...)
	used = append(used, l76ReadRunning, l76ReadGroup)
	for _, c := range used {
		if !cited[c] {
			t.Errorf("%q has no row in l76Sources", c)
		}
	}
	sec := l76SourcesSection()
	for _, s := range l76Sources {
		if !strings.Contains(sec, "`"+s.what+"`") {
			t.Errorf("the Sources section lacks %q", s.what)
		}
	}
	for _, url := range []string{l76SAURL + "#configuring-tacacsx-authorization", l76CMURL + "#configuration-datastores",
		l76CLABURL + "#cli"} {
		if !strings.Contains(sec, url) {
			t.Errorf("the Sources section lacks %s", url)
		}
	}
	if l76CiteKnown("") || l76CiteKnown("the guide") || l76CiteKnown("SA#configuring-role; somewhere") {
		t.Error("an unknown cite was accepted")
	}
	// The live test sends set lines only through l76SetLines: a literal in
	// l76_test.go would bypass this test. Before Task 5 the file does not exist.
	src, err := os.ReadFile("l76_test.go")
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if strings.Contains(string(src), "\"set /") {
		t.Error("l76_test.go holds a set / literal; use an l76SetLines constant")
	}
}

// l76TypesFixture is copied from ghcr.io/nokia/srlinux:26.7.2-519,
// /opt/srlinux/models/srl_nokia/models/system/srl_nokia-aaa-types.yang
// lines 77-81 and 109-113.
const l76TypesFixture = `
  identity command {
    base aaa_accounting_event_type;
    description
      "Specifies interactive command events for AAA accounting";
  }
  identity commands {
    base aaa_authorization_event_type;
    description
      "Specifies interactive command events for authorization";
  }
`

// l76AAAFixture is copied from the same image's
// /opt/srlinux/models/srl_nokia/models/system/srl_nokia-aaa.yang lines
// 134-135, 254-257, 1096, 1123 and 1148 (no line of that file uses the
// first two groupings).
const l76AAAFixture = `
      must '(. = "local") = (../type = "srl-aaa-types:local")' {
        error-message "Server group name must be 'local' if and only if local server type is 'local'";
      description
        "Use TACACS+ priv-lvl based authorization

         If false, then authorization is skipped for TACACS+ users granting full admin access for those users.";
  grouping aaa-authorization-methods-config {
  grouping aaa-authorization-events-top {
      uses aaa-authorization-role-top;
`

func TestL76IdentityBase(t *testing.T) {
	if got := l76IdentityBase(l76TypesFixture, "command"); got != "aaa_accounting_event_type" {
		t.Errorf("command: %q", got)
	}
	if got := l76IdentityBase(l76TypesFixture, "commands"); got != "aaa_authorization_event_type" {
		t.Errorf("commands: %q", got)
	}
	if got := l76IdentityBase(l76TypesFixture, "config"); got != "" {
		t.Errorf("absent identity: %q", got)
	}
}

func TestL76SchemaFindingsNameEachOverrule(t *testing.T) {
	got := strings.Join(l76SchemaFindings(l76AAAFixture, l76TypesFixture), "\n")
	for _, want := range []string{"`event command`", "named `local`", "no TACACS+ authorization method", "full admin"} {
		if !strings.Contains(got, want) {
			t.Errorf("findings lack %q:\n%s", want, got)
		}
	}
	if f := l76SchemaFindings("", ""); len(f) != 0 {
		t.Errorf("empty models produced findings: %v", f)
	}
	used := l76AAAFixture + "    uses aaa-authorization-methods-config;\n"
	if strings.Contains(strings.Join(l76SchemaFindings(used, ""), "\n"), "no TACACS+ authorization method") {
		t.Error("a used grouping read as unused")
	}
}

func TestL76SchemaExcerptKeepsIdentifiers(t *testing.T) {
	got := l76SchemaExcerpt(l76TypesFixture, []string{"base aaa_"})
	if got != "base aaa_accounting_event_type;\nbase aaa_authorization_event_type;" {
		t.Errorf("got %q", got)
	}
}

func TestL76SchemaExcerptKeepsKeyLinesMasked(t *testing.T) {
	got := l76SchemaExcerpt(l76AAAFixture, []string{"Server group name", "authorization is skipped"})
	if strings.Count(got, "\n") != 1 || !strings.Contains(got, "must be 'local'") {
		t.Errorf("got %q", got)
	}
}

func TestL76RecordHelpers(t *testing.T) {
	recs := []map[string]any{
		{"event": "redeem", "verdict": "permit", "auth": map[string]any{"method": "pap"},
			"session": map[string]any{"username": "alice01"}},
		{"event": "authorize_session", "verdict": "permit", "session": map[string]any{"username": "alice01"},
			"request": map[string]any{"service": "shell", "raw": []any{"service=shell", "cmd="}},
			"reply":   map[string]any{"attributes": []any{"priv-lvl=15"}}},
		{"event": "account", "flags": "start", "session": map[string]any{"username": "alice01"},
			"record": map[string]any{"raw": []any{"task_id=1", "cmd=show version"}}},
		{"event": "unvalidated", "unvalidated": map[string]any{"diagnosis": "no_known_key_matches"}},
		{"event": "redeem", "verdict": "deny", "session": map[string]any{"username": "bob"}},
	}
	if n := len(l76Of(recs, "alice01")); n != 3 {
		t.Errorf("l76Of: %d", n)
	}
	if l76Count(recs, "redeem") != 2 || l76Count(recs, "account") != 1 {
		t.Error("l76Count")
	}
	if d := l76Diagnoses(recs); d["no_known_key_matches"] != 1 || len(d) != 1 {
		t.Errorf("l76Diagnoses: %v", d)
	}
	if s := l76Services(recs); s["shell"] != 1 || len(s) != 1 {
		t.Errorf("l76Services: %v", s)
	}
	if l76Str(recs[0], "auth", "method") != "pap" || l76Str(recs[0], "nope", "x") != "" {
		t.Error("l76Str")
	}
	if got := l76Strs(recs[1], "reply", "attributes"); len(got) != 1 || got[0] != "priv-lvl=15" {
		t.Errorf("l76Strs: %v", got)
	}
	r := l76Render(recs)
	for _, want := range []string{"redeem permit/ method=pap user=alice01",
		"authorize_session permit/ user=alice01 service=shell request=[service=shell cmd=] reply=[priv-lvl=15]",
		"account flags=start user=alice01 record=[task_id=1 cmd=show version]",
		"unvalidated diagnosis=no_known_key_matches"} {
		if !strings.Contains(r, want) {
			t.Errorf("render lacks %q:\n%s", want, r)
		}
	}
}

func TestL76WrongKeyConfigSwapsTheOneBlock(t *testing.T) {
	cfg := "keys:\n" + l76KeyAnchor + "other: 1\n"
	got, err := l76WrongKeyConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "PORT49_LAB_KEY") || !strings.Contains(got, "secret_env: "+l76WrongKeyEnv) ||
		!strings.Contains(got, "other: 1") {
		t.Errorf("got:\n%s", got)
	}
	if _, err := l76WrongKeyConfig("keys: {}\n"); err == nil {
		t.Error("no anchor: no error")
	}
	if _, err := l76WrongKeyConfig(cfg + l76KeyAnchor); err == nil {
		t.Error("two anchors: no error")
	}
}

func TestL76LabConfigHoldsTheKeyAnchorOnce(t *testing.T) {
	raw, err := os.ReadFile("port49d-lab.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l76WrongKeyConfig(string(raw)); err != nil {
		t.Fatal(err)
	}
}

func TestL76ObservationHasEveryCellInOrder(t *testing.T) {
	out := map[string]string{}
	for _, c := range l76Cells {
		out[c.id] = "seen " + c.id
	}
	got := l76Observation(out, "schema text", "EXTRA LINE")
	last := strings.Index(got, "schema text")
	if last < 0 {
		t.Fatal("no schema section")
	}
	for _, c := range l76Cells {
		at := strings.Index(got, "### ("+c.id+") ")
		if at <= last || !strings.Contains(got[at:], "seen "+c.id) {
			t.Errorf("cell %s missing or out of order", c.id)
		}
		last = at
	}
	src := strings.Index(got, "### Sources\n\n")
	if src <= last || !strings.Contains(got[src:], l76SourcesSection()) {
		t.Error("the Sources section is missing or not after the cells")
	}
}

// Only the exact tokens of the `role [ ... ]` leaf-list count: a role that
// merely contains a lab role's name, or sits outside the leaf-list, is not it.
func TestL76RolesInReadsWholeTokensOfTheRoleLeafList(t *testing.T) {
	for _, in := range []string{
		"session 1 {\n    username u\n    role [ p49-read-only ]\n}\n",
		"session 1 {\n    username u\n    role [ x-p49-admin ]\n}\n",
		"session 1 {\n    username u\n    description p49-admin\n    role [ network-admin ]\n}\n",
	} {
		if got := l76RolesIn(in, "u"); got != nil {
			t.Errorf("%q read as %v", in, got)
		}
	}
	two := "session 1 {\n    username u\n    role [ p49-read ]\n}\nsession 2 {\n    username u\n    role [\n p49-admin\n ]\n}\n"
	if got := l76RolesIn(two, "u"); strings.Join(got, ",") != "p49-admin,p49-read" {
		t.Errorf("two sessions of one user: %v", got)
	}
}

// A brace inside a quoted value is not block structure. Counting it would
// let alice01's block swallow carol's session and report p49-admin.
func TestL76UserSessionsSkipsBracesInQuotedValues(t *testing.T) {
	in := "session 31 {\n    username alice01\n    note \"a { b\"\n    role [ p49-read ]\n}\n" +
		"session 32 {\n    username carol\n    note \"c } d\"\n    role [ p49-admin ]\n}\n" +
		"session 33 {\n    username erin\n    note \"say \\\"{\\\" now\"\n    role [ p49-read ]\n}\n"
	own := l76UserSessions(in, "alice01")
	if strings.Contains(own, "carol") || strings.Contains(own, "p49-admin") || !strings.Contains(own, "session 31 {") {
		t.Errorf("alice01's blocks:\n%s", own)
	}
	if got := l76RolesIn(in, "alice01"); strings.Join(got, ",") != "p49-read" {
		t.Errorf("alice01: %v", got)
	}
	if got := l76RolesIn(in, "carol"); strings.Join(got, ",") != "p49-admin" {
		t.Errorf("carol: %v", got)
	}
	if got := l76RolesIn(in, "erin"); strings.Join(got, ",") != "p49-read" {
		t.Errorf("erin (an escaped quote and a brace): %v", got)
	}
}

// l76StartupRules maps each statement of configs/srlinux-startup.cli to the
// l76Sources row that cites it. The key is the statement under the AAA
// section that holds it ("authentication", "server-group port49", ...).
var l76StartupRules = []struct{ re, what string }{
	{`^authentication/authentication-method \[$`, "authentication-method [ port49 local ]"},
	{`^authentication/(user \S+ \{|password \S+|role \[)$`, "user breakglass { password ...; role [ p49-admin ] }"},
	{`^authorization/(role \S+ \{|priv-lvl \d+)$`, "authorization { role <n> { tacacs { priv-lvl <n> } } }"},
	{`^accounting/(accounting-method \[|event command \{|record start-stop)$`,
		"accounting { accounting-method [ port49 ]; event command { record start-stop } }"},
	{`^server-group local/(server-group local \{|type local)$`, "server-group local { type local }"},
	{`^server-group port49/(server-group port49 \{|type tacacs|priv-lvl-authorization true)$`,
		"server-group port49 { type tacacs; tacacs { priv-lvl-authorization true } }"},
	{`^server-group port49/(server \S+ \{|network-instance mgmt|port 49|secret-key \S+)$`,
		"server 172.100.100.1 { network-instance mgmt; tacacs { port 49; secret-key ... } }"},
	{`^configuration/(role \S+ \{|rule / \{|action (read|write))$`,
		"configuration { role <n> { rule / { action read|write } } }"},
}

// l76StartupStatements is the statements of a startup config: every line
// that is not a comment, a closer, a list member or a bare container head,
// as "<section>/<line>".
func l76StartupStatements(cli string) []string {
	var out, stack []string
	inList := false
	for _, raw := range strings.Split(cli, "\n") {
		ln := strings.TrimSpace(raw)
		switch {
		case ln == "" || strings.HasPrefix(ln, "#"):
			continue
		case ln == "}":
			stack = stack[:len(stack)-1]
			continue
		case ln == "]":
			inList = false
			continue
		case inList:
			continue
		}
		head := strings.HasSuffix(ln, "{")
		if head {
			stack = append(stack, strings.TrimSpace(strings.TrimSuffix(ln, "{")))
		}
		if strings.HasSuffix(ln, "[") {
			inList = true
		}
		if head && len(strings.Fields(ln)) == 2 {
			continue // a bare container: `aaa {`
		}
		section := ""
		switch {
		case len(stack) > 1 && stack[1] == "configuration":
			section = "configuration"
		case len(stack) > 2:
			section = stack[2]
		}
		out = append(out, section+"/"+ln)
	}
	return out
}

func TestL76StartupStatementsAreCited(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("configs", "srlinux-startup.cli"))
	if err != nil {
		t.Fatal(err)
	}
	cited := map[string]bool{}
	for _, s := range l76Sources {
		cited[s.what] = true
	}
	stmts := l76StartupStatements(string(raw))
	if len(stmts) < 20 {
		t.Fatalf("only %d statements read: %v", len(stmts), stmts)
	}
	for _, st := range stmts {
		ok := false
		for _, r := range l76StartupRules {
			if regexp.MustCompile(r.re).MatchString(st) {
				if !cited[r.what] {
					t.Errorf("%q maps to %q, which has no row in l76Sources", st, r.what)
				}
				ok = true
				break
			}
		}
		if !ok {
			t.Errorf("startup statement %q has no cite row", st)
		}
	}
	if extra := l76StartupStatements(string(raw) + "\nsystem {\n    aaa {\n        accounting {\n            idle-timeout 5\n        }\n    }\n}\n"); len(extra) != len(stmts)+1 {
		t.Errorf("a new statement was not counted: %d vs %d", len(extra), len(stmts))
	}
}

func TestL76LiveTestSendsNoInfoLiteral(t *testing.T) {
	src, err := os.ReadFile("l76_test.go")
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if strings.Contains(string(src), "\"info ") {
		t.Error("l76_test.go holds an info literal; use an l76Read constant")
	}
}

// The note ends with its Sources: whatever the live test adds after the cells
// (the retries line, the Evidence pointer) goes before them.
func TestL76ObservationEndsWithSources(t *testing.T) {
	out := map[string]string{}
	got := l76Observation(out, "schema text", "RETRIES AND EVIDENCE\n")
	tail := "\n### Sources\n\n" + l76SourcesSection() + "\n"
	if !strings.HasSuffix(got, tail) {
		t.Errorf("the note does not end with its Sources block; ends %q", got[max(0, len(got)-120):])
	}
	extra := strings.Index(got, "RETRIES AND EVIDENCE")
	if extra < 0 || extra > strings.Index(got, "### Sources") {
		t.Error("the extra text is missing or after the Sources")
	}
}

// An INVALID message that holds a secret is replaced by a fixed one that
// names the secret by index only.
func TestL76InvalidMessageIsGatedByLeaks(t *testing.T) {
	secrets := []string{"alpha-secret-one", "bravo-secret-two"}
	if got := l76SafeInvalid("login failed: no secret here", secrets); got != "login failed: no secret here" {
		t.Errorf("a clean message was changed: %q", got)
	}
	got := l76SafeInvalid("the device echoed bravo-secret-two back", secrets)
	if strings.Contains(got, "bravo") || !strings.Contains(got, "secret #1") {
		t.Errorf("a leaking message was printed or not named by index: %q", got)
	}
	if got := l76SafeInvalid("echo "+"ALPHA-SECRET-ONE", secrets); strings.Contains(strings.ToLower(got), "alpha") {
		t.Errorf("a folded-case leak was printed: %q", got)
	}
}

// invalid is the one place the live test fails a run: it must pass its
// message through l76SafeInvalid, or the gate above guards nothing.
func TestL76InvalidUsesTheLeakGate(t *testing.T) {
	src, err := os.ReadFile("l76_test.go")
	if err != nil {
		t.Fatal(err)
	}
	_, body, ok := strings.Cut(string(src), "func (e *l76Env) invalid(")
	if !ok {
		t.Fatal("no invalid method")
	}
	body, _, _ = strings.Cut(body, "\n}\n")
	if !strings.Contains(body, "l76InvalidText(") || !strings.Contains(body, "e.secrets()") {
		t.Error("invalid does not gate its message with l76InvalidText over e.secrets()")
	}
}

func TestL76InvalidTextKeepsItsOwnWording(t *testing.T) {
	seed := "seedtok-9f3a"
	secrets := []string{"labkey-xyz", seed}
	for _, m := range []string{
		"cell d: alice01 logged in with a wrong password",
		"cell d: the login with the wrong credential failed before authentication: ssh: handshake failed",
		"cell a: the control login as alice01 failed after 3s: ssh: unable to authenticate, attempted methods [none password], no supported methods remain",
		"evidence a-1.txt holds [secret #0]",
	} {
		if got := l76InvalidText(m, secrets); got != m {
			t.Errorf("the message was changed:\n got %q\nwant %q", got, m)
		}
	}
	if got := l76InvalidText("echo "+seed, secrets); strings.Contains(got, seed) || !strings.Contains(got, "secret #1") {
		t.Errorf("a seed was printed: %q", got)
	}
	long := "AbCdEf0123456789AbCdEf0123456789xyz"
	if got := l76InvalidText("device said "+long, secrets); strings.Contains(got, long) {
		t.Errorf("a token-shaped run was printed: %q", got)
	}
}

func TestL76ReturnsFromInvalidOnlyForADeferredRestoreAfterAFailure(t *testing.T) {
	for _, c := range []struct{ restoring, failed, want bool }{
		{false, false, false},
		{false, true, false}, // a stray t.Errorf must not turn INVALID into a return
		{true, false, false},
		{true, true, true},
	} {
		if got := l76ReturnsFromInvalid(c.restoring, c.failed); got != c.want {
			t.Errorf("restoring=%v failed=%v: got %v, want %v", c.restoring, c.failed, got, c.want)
		}
	}
}

// The live test's retries line and Evidence pointer sit under their own
// heading, so they do not read as part of cell (j).
func TestL76RunSectionHasItsOwnHeading(t *testing.T) {
	got := l76RunSection(nil, "L76-srlinux")
	if !strings.HasPrefix(got, "\n### Run\n\n") || !strings.HasSuffix(got, "\n") {
		t.Errorf("the run section does not start with its heading and end with a newline: %q", got)
	}
	if !strings.Contains(got, ": none") || !strings.Contains(got, "`tests/lab/evidence/L76-srlinux/`") {
		t.Errorf("no 'none' retries line or no evidence pointer: %q", got)
	}
	got = l76RunSection([]string{"first", "second"}, "L76-srlinux")
	if !strings.Contains(got, "\n- first\n- second\n") {
		t.Errorf("retries are not listed one per line: %q", got)
	}
	full := l76Observation(map[string]string{}, "schema", got)
	if strings.Index(full, "### Run") < strings.Index(full, "### ("+l76Cells[len(l76Cells)-1].id+")") {
		t.Error("the Run section is before the last cell")
	}
}

// invalid returns, instead of stopping, only while a deferred restore runs
// (restore sets and clears the flag), so every defer in a cell must go through
// restore. A bare `defer e.set(...)` would let a failed restore stop the
// unwinding. This scan is a tripwire beside the behavioral test below.
func TestL76EveryDeferInACellGoesThroughRestore(t *testing.T) {
	src, err := os.ReadFile("l76_test.go")
	if err != nil {
		t.Fatal(err)
	}
	defers := 0
	inCell := false
	for _, line := range strings.Split(string(src), "\n") {
		if strings.HasPrefix(line, "func ") {
			inCell = strings.HasPrefix(line, "func (e *l76Env) cell")
		}
		trim := strings.TrimSpace(line)
		if !inCell || !strings.HasPrefix(trim, "defer ") {
			continue
		}
		defers++
		if !strings.HasPrefix(trim, "defer e.restore(") {
			t.Errorf("a cell's defer does not go through e.restore: %s", trim)
		}
	}
	if defers < 4 {
		t.Errorf("found %d defers in cells, want at least 4 (h, i, j, e)", defers)
	}
}

// restore raises the flag for f and clears it when f returns, so a later
// INVALID (a leak gate, say) stops the run again.
func TestL76RestoreClearsTheFlagWhenItReturns(t *testing.T) {
	e := &l76Restoring{}
	var inside, insideReturns bool
	e.restore(func() {
		inside = e.restoring
		insideReturns = l76ReturnsFromInvalid(e.restoring, true)
	})
	if !inside || !insideReturns {
		t.Errorf("inside restore: restoring=%v, invalid would return=%v; want both true", inside, insideReturns)
	}
	if e.restoring {
		t.Error("restoring is still set after restore returned")
	}
	if l76ReturnsFromInvalid(e.restoring, true) {
		t.Error("after restore, an INVALID on a failing run would return instead of stopping")
	}
	func() {
		defer func() { _ = recover() }()
		e.restore(func() { panic("restore failed") })
	}()
	if e.restoring {
		t.Error("restoring is still set after f panicked")
	}
}

func TestL76MaskLongKeepsDecisionReasons(t *testing.T) {
	// A closed-vocabulary reason code is long but is not a secret: it must
	// survive, whatever its length. Any other long run is still masked.
	for _, r := range []string{"no_permit_dominates_deny", "trust_domain_unresolved", "per_login_mfa_unavailable"} {
		if got := l76MaskLong("reason=" + r); got != "reason="+r {
			t.Errorf("%s was masked: %q", r, got)
		}
	}
	unknown := "Zq9Xk2Lm7Wp4Rt8Vb3Nc6Hy1Jd5Fs0A"
	if got := l76MaskLong("reason=" + unknown); strings.Contains(got, unknown) {
		t.Errorf("an unknown long value survived: %q", got)
	}
}

func TestL76SummarizeNamesReasonAndRequest(t *testing.T) {
	recs := []map[string]any{{
		"event": "authorize_session", "verdict": "deny", "reason": "no_permit_dominates_deny",
		"session": map[string]any{"username": "alice01", "port": "ssh"},
		"request": map[string]any{"service": "shell", "raw": []any{"service=shell", "cmd=", "priv-lvl=15"}},
	}}
	got := l76InvalidText(l76Summarize(recs, nil), nil)
	for _, want := range []string{"reason=no_permit_dominates_deny", "service=shell", "attribute names: service, cmd, priv-lvl"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %q", want, got)
		}
	}
	// Attribute values are never printed.
	if strings.Contains(got, "priv-lvl=15") {
		t.Errorf("a value was printed: %q", got)
	}
	// A line that leaks is withheld, alone.
	recs = append(recs, map[string]any{"event": "authorize_command", "verdict": "deny", "reason": "no_rule_matched",
		"request": map[string]any{"service": "labsecret-svc", "raw": []any{"service=x"}}})
	got = l76Summarize(recs, []string{"labsecret-svc"})
	if strings.Contains(got, "labsecret-svc") || !strings.Contains(got, "withheld") || !strings.Contains(got, "reason=no_permit_dominates_deny") {
		t.Errorf("got %q", got)
	}
}

func TestL76DecisionDumpRedactsAndFilters(t *testing.T) {
	hash := strings.Repeat("ab", 32)
	recs := []map[string]any{
		{"event": "redeem", "verdict": "permit", "credential_sha256": hash},
		{"event": "authorize_session", "verdict": "deny", "reason": "no_permit_dominates_deny"},
	}
	got := l76DecisionDump(recs)
	if strings.Contains(got, hash) {
		t.Errorf("the credential hash survived: %q", got)
	}
	if !strings.Contains(got, `"reason":"no_permit_dominates_deny"`) {
		t.Errorf("the reason was lost: %q", got)
	}
}
