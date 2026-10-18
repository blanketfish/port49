package lab

import (
	"encoding/json"
	"os"
	"path/filepath"
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
