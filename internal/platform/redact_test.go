package platform

import (
	"fmt"
	"io/fs"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/rhwendt/port49/platforms"
)

// The built-in table loads, has a default list, and gives Junos its own on
// top of it: a platform's list adds to the default and never replaces it, so
// a word the default removes is removed everywhere.
func TestBuiltInRedactionsLoad(t *testing.T) {
	if _, err := LoadRedactions(platforms.Redact); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(Redactions("arista_eos"), Redactions("meinberg_lantime")) || len(Redactions("")) == 0 {
		t.Fatal("a platform with no list of its own takes the default")
	}
	junos, all := Redactions("juniper_junos"), Redactions("arista_eos")
	if len(junos) <= len(all) || !reflect.DeepEqual(junos[:len(all)], all) {
		t.Fatalf("junos has the default list and its own after it: %+v", junos)
	}
	list := Redactions("arista_eos")
	list[0].After = "changed"
	if Redactions("arista_eos")[0].After == "changed" {
		t.Fatal("Redactions must return a copy")
	}
}

// Spec §5.8's own case: `username bob secret Hunter2` is written with the
// secret removed, in the vector and the raw pairs alike, and the vector keeps
// its shape and length so the reconciliation join still lines up. The command
// word is never removed.
func TestASecretIsRemovedAndTheShapeKept(t *testing.T) {
	rules := Redactions("cisco_iosxe")
	for _, tt := range []struct{ in, want []string }{
		{[]string{"username", "bob", "secret", "Hunter2"}, []string{"username", "bob", "secret", Redacted}},
		{[]string{"username", "bob", "privilege", "15", "secret", "0", "Hunter2"},
			[]string{"username", "bob", "privilege", "15", "secret", Redacted, Redacted}},
		{[]string{"enable", "password", "x"}, []string{"enable", "password", Redacted}},
		{[]string{"tacacs-server", "host", "10.0.0.1", "key", "7", "0822455D0A16"},
			[]string{"tacacs-server", "host", "10.0.0.1", "key", Redacted, Redacted}},
		{[]string{"snmp-server", "community", "s3cret", "RO"}, []string{"snmp-server", "community", Redacted, Redacted}},
	} {
		got, redacted := Redact(rules, tt.in)
		if !redacted || !reflect.DeepEqual(got, tt.want) {
			t.Errorf("%q: %q %v, want %q", tt.in, got, redacted, tt.want)
		}
	}
	in := []string{"show", "running-config"}
	if got, redacted := Redact(rules, in); redacted || !reflect.DeepEqual(got, in) {
		t.Fatalf("a command with no secret is untouched: %q", got)
	}
	raw := []string{"task_id=43", "service=shell", "cmd=username", "cmd-arg=bob", "cmd-arg=secret", "cmd-arg=Hunter2",
		"cmd-arg=<cr>"}
	got, _, redacted := RedactRecord(rules, raw, nil)
	want := []string{"task_id=43", "service=shell", "cmd=username", "cmd-arg=bob", "cmd-arg=secret",
		"cmd-arg=" + Redacted, "cmd-arg=<cr>"}
	if !redacted || !reflect.DeepEqual(got, want) {
		t.Fatalf("raw: %q", got)
	}
	if strings.Contains(strings.Join(got, " "), "Hunter2") || raw[5] != "cmd-arg=Hunter2" {
		t.Fatal("the secret is gone from the copy, and the input is not edited")
	}
}

// One real line per secret each vendor's syntax carries, on each platform's
// built-in patterns: the secret is not in what is written. The NX-OS
// accounting `cmd` is the configuration path joined with ` ; ` and a result
// (tests/lab/results/L21-cisco_nxos.md), which is why the patterns lead with
// `**`.
func TestEachVendorsSecretsAreRedacted(t *testing.T) {
	for _, tt := range []struct {
		platform string
		raw      []string
	}{
		{"arista_eos", []string{"cmd=snmp-server", "cmd-arg=user", "cmd-arg=u", "cmd-arg=g", "cmd-arg=v3",
			"cmd-arg=auth", "cmd-arg=sha", "cmd-arg=SECRET1", "cmd-arg=priv", "cmd-arg=aes", "cmd-arg=SECRET2"}},
		{"arista_eos", []string{"cmd=ip", "cmd-arg=ospf", "cmd-arg=message-digest-key", "cmd-arg=1", "cmd-arg=md5",
			"cmd-arg=SECRET1"}},
		{"cisco_iosxe", []string{"cmd=neighbor", "cmd-arg=10.0.0.1", "cmd-arg=password", "cmd-arg=7",
			"cmd-arg=SECRET1"}},
		{"cisco_iosxe", []string{"cmd=crypto", "cmd-arg=isakmp", "cmd-arg=key", "cmd-arg=SECRET1", "cmd-arg=address",
			"cmd-arg=10.0.0.1"}},
		{"cisco_iosxe", []string{"cmd=pre-shared-key", "cmd-arg=local", "cmd-arg=SECRET1"}},
		{"cisco_iosxe", []string{"cmd=pre-shared-key", "cmd-arg=SECRET1"}},
		{"cisco_iosxe", []string{"cmd=key-string", "cmd-arg=SECRET1"}},
		{"cisco_iosxe", []string{"cmd=password", "cmd-arg=7", "cmd-arg=SECRET1"}},
		{"cisco_iosxe", []string{"cmd=ntp", "cmd-arg=authentication-key", "cmd-arg=1", "cmd-arg=md5",
			"cmd-arg=SECRET1"}},
		{"cisco_nxos", []string{"cmd=configure terminal ; username bob password SECRET1 role network-admin (SUCCESS)"}},
		{"cisco_nxos", []string{"cmd=configure terminal ; snmp-server user u network-admin auth sha SECRET1 priv " +
			"aes-128 SECRET2 (SUCCESS)"}},
		{"juniper_junos", []string{"cmd=set protocols ospf area 0 interface ge-0/0/0.0 authentication md5 1 key SECRET1"}},
		{"juniper_junos", []string{"cmd=set snmp v3 usm local-engine user u authentication-sha authentication-password " +
			"SECRET1"}},
		{"juniper_junos", []string{"cmd=set snmp v3 usm local-engine user u privacy-aes128 privacy-password SECRET1"}},
		{"juniper_junos", []string{"cmd=set system radius-server 10.0.0.1 secret SECRET1"}},
		{"juniper_junos", []string{"cmd=set security ike policy p pre-shared-key ascii-text SECRET1"}},
		{"juniper_junos", []string{"cmd=set system login user bob authentication plain-text-password-value SECRET1"}},
	} {
		got, _, redacted := RedactRecord(Redactions(tt.platform), tt.raw, nil)
		if joined := strings.Join(got, " "); !redacted || strings.Contains(joined, "SECRET") {
			t.Errorf("%s %q: %q", tt.platform, tt.raw, got)
		}
	}
}

// Junos sends a whole command line as one `cmd`, so each element is split
// into words; and a pattern's word matches its abbreviations on every
// platform, whatever expands_abbreviations says, because L21 measured
// expansion for interactive SSH only and a missed abbreviation leaks a secret
// the log cannot take back (task 10 review I1).
func TestJunosLinesAndAbbreviationsAreRedacted(t *testing.T) {
	got, _, redacted := RedactRecord(Redactions("juniper_junos"),
		[]string{"task_id=2", "cmd=set system root-authentication encrypted-password \"$6$abc\" <cr>"}, nil)
	if !redacted || got[1] != "cmd=set system root-authentication encrypted-password "+Redacted+" "+Redacted {
		t.Fatalf("%q", got)
	}
	for _, platform := range []string{"arista_eos", "cisco_nxos", "cisco_iosxe"} {
		for _, line := range []string{"usern x sec 0 SECRET1", "snmp comm SECRET1 ro", "snmp us u g v3 au sha SECRET1",
			"ena sec SECRET1", "tacacs-server k 7 SECRET1", "snmp host 10.0.0.1 vers 2c SECRET1"} {
			if got, redacted := Redact(Redactions(platform), strings.Fields(line)); !redacted ||
				strings.Contains(strings.Join(got, " "), "SECRET") {
				t.Errorf("%s %q: %q", platform, line, got)
			}
		}
	}
}

// A command whose own word is the one the secret follows, as a submode's is,
// keeps that word and loses what follows it: the join needs the command word.
func TestTheCommandWordSurvives(t *testing.T) {
	for _, tt := range []struct{ in, want []string }{
		{[]string{"key-string", "X"}, []string{"key-string", Redacted}},
		{[]string{"pre-shared-key", "local", "X"}, []string{"pre-shared-key", Redacted, Redacted}},
		{[]string{"password", "7", "X"}, []string{"password", Redacted, Redacted}},
		{[]string{"area-password", "X"}, []string{"area-password", Redacted}},
	} {
		if got, _ := Redact(Redactions("cisco_iosxe"), tt.in); !reflect.DeepEqual(got, tt.want) {
			t.Errorf("%q: %q, want %q", tt.in, got, tt.want)
		}
	}
}

// A pattern's match is anchored at both ends, `from` counts positions and a
// negative one counts from the end, and nothing removes the command word.
func TestMatchAndFrom(t *testing.T) {
	from := func(n int) *int { return &n }
	rules := []Redaction{{Match: []string{"crypto", "key", "*", "**"}, From: from(3)},
		{Match: []string{"**", "psk"}, From: from(-1)}}
	for _, tt := range []struct{ in, want []string }{
		{[]string{"crypto", "key", "a", "b", "c"}, []string{"crypto", "key", "a", Redacted, Redacted}},
		{[]string{"crypto", "keys", "a", "b"}, []string{"crypto", "keys", "a", "b"}},
		{[]string{"x", "psk"}, []string{"x", Redacted}},
		{[]string{"psk"}, []string{"psk"}},
	} {
		if got, _ := Redact(rules, tt.in); !reflect.DeepEqual(got, tt.want) {
			t.Errorf("%q: %q, want %q", tt.in, got, tt.want)
		}
	}
}

// A pattern that could not do what it says is refused where it is written.
func TestARedactionIsValidated(t *testing.T) {
	zero, one := 0, 1
	for want, r := range map[string]Redaction{
		"match is required":      {After: "x"},
		"no regex or class":      {Match: []string{"/secret/"}, After: "x"},
		"more than two **":       {Match: []string{"**", "a", "**", "b", "**"}, After: "x"},
		"one of the two":         {Match: []string{"**"}, After: "x", From: &one},
		"from: 0 is the command": {Match: []string{"**"}, From: &zero},
		"after is one word":      {Match: []string{"**"}, After: "a b"},
		"matches every command":  {Match: []string{"*", "**"}, From: &one},
	} {
		if err := r.check(); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v", want, err)
		}
	}
	d, _ := DialectFor("arista_eos")
	d.Redact = []Redaction{{Match: []string{"**"}}}
	if err := Validate("arista_eos", d); err == nil || !strings.Contains(err.Error(), "platforms.arista_eos.redact[0]") {
		t.Fatalf("%v", err)
	}
}

// A block's redact adds to what the adapter has; it never replaces a list.
func TestABlockAddsRedactions(t *testing.T) {
	specs, err := ParseSpecs([]byte("platforms:\n  x:\n    redact: [{match: ['**'], after: psk}]\n"))
	if err != nil {
		t.Fatal(err)
	}
	base := Dialect{Redact: []Redaction{{Match: []string{"**"}, After: "secret"}}}
	d := specs["x"].Over(base)
	if len(d.Redact) != 2 || d.Redact[0].After != "secret" || d.Redact[1].After != "psk" || len(base.Redact) != 1 {
		t.Fatalf("%+v", d.Redact)
	}
}

// Every secret keyword the 5a platforms' syntax carries, one line per pattern
// and each sibling the default list already covers, on all three: the secret
// is not in what is written, in the vector or the raw pairs (task 10 review
// C1, C2). The NX-OS line is its ` ; `-joined path and result.
func TestTheSecretKeywordsAreRedactedOnEveryPlatform(t *testing.T) {
	lines := []string{
		// SNMPv1/v2c trap and inform hosts carry the community.
		"snmp-server host 10.0.0.1 version 2c SECRET1 udp-port 162",
		"snmp-server host 10.0.0.1 traps version 2c SECRET1",
		"snmp-server host 10.0.0.1 informs version 2c SECRET1",
		"snmp-server host 10.0.0.1 SECRET1",
		"snmp-server host 10.0.0.1 version 1 SECRET1",
		// HSRP and VRRP text authentication.
		"standby 1 authentication text SECRET1",
		"standby 1 authentication SECRET1",
		"standby authentication SECRET1",
		"vrrp 1 authentication text SECRET1",
		"configure terminal ; interface Ethernet1/1 ; hsrp 1 ; authentication text SECRET1 (SUCCESS)",
		// IS-IS.
		"area-password SECRET1",
		"domain-password SECRET1",
		"isis password SECRET1",
		// OSPFv3 IPsec: the SPI and the key after it.
		"ospfv3 authentication ipsec spi 256 sha1 SECRET1",
		"ipv6 ospf authentication ipsec spi 256 md5 SECRET1",
		// BGP.
		"bgp auth-password SECRET1",
		"neighbor 10.0.0.1 password-encrypt SECRET1",
		"neighbor 10.0.0.1 password 7 SECRET1",
		// PIM.
		"ip pim hello-authentication ah-md5 SECRET1",
		// NHRP.
		"ip nhrp authentication SECRET1",
		// EOS IPsec profiles, IOS-XE smart licensing, IOS manual IPsec keys,
		// and siblings (task 10 re-review C4).
		"shared-key 7 SECRET1",
		"license smart trust idtoken SECRET1 all",
		"license smart register idtoken SECRET1",
		"set session-key inbound esp 256 cipher SECRET1",
		"set session-key outbound ah 256 SECRET1",
		// Siblings the default list covers.
		"ntp authentication-key 1 md5 SECRET1",
		"radius-server key 7 SECRET1",
		"key 7 SECRET1",
		"crypto ca import tp pkcs12 flash:tp.p12 password SECRET1",
		"enrollment password SECRET1",
		"snmp-server community SECRET1 ro",
	}
	for _, platform := range []string{"arista_eos", "cisco_nxos", "cisco_iosxe"} {
		for _, line := range lines {
			words := strings.Fields(line)
			got, redacted := Redact(Redactions(platform), words)
			if joined := strings.Join(got, " "); !redacted || strings.Contains(joined, "SECRET") {
				t.Errorf("%s vector %q: %q", platform, line, got)
			}
			raw := []string{"cmd=" + words[0]}
			for _, w := range words[1:] {
				raw = append(raw, "cmd-arg="+w)
			}
			gotRaw, _, redacted := RedactRecord(Redactions(platform), append(raw, "cmd-arg=<cr>"), nil)
			if joined := strings.Join(gotRaw, " "); !redacted || strings.Contains(joined, "SECRET") {
				t.Errorf("%s raw %q: %q", platform, line, gotRaw)
			}
		}
	}
}

// A BGP community is routing policy, not a secret: it is removed only from
// the snmp-server command that makes one a password (task 10 review M1).
func TestARoutingCommunityIsKept(t *testing.T) {
	for _, line := range []string{"set community 65000:1 additive", "match community C1",
		"show ip bgp community 65000:1"} {
		in := strings.Fields(line)
		if got, redacted := Redact(Redactions("cisco_iosxe"), in); redacted {
			t.Errorf("%q: %q", line, got)
		}
	}
}

// A record's raw pairs and its vector are two spellings of one command. A
// pattern anchored at both ends can match one and not the other — the raw
// pairs lose their `<cr>`, the vector may keep it — so where either form loses
// a word and the other matched nothing, the other loses every argument: the
// secret is never left standing in the form the pattern missed.
func TestARecordIsRedactedInBothForms(t *testing.T) {
	rules := []Redaction{{Match: []string{"username", "*", "secret", "*"}, After: "secret"}}
	raw := []string{"cmd=username", "cmd-arg=bob", "cmd-arg=secret", "cmd-arg=Hunter2", "cmd-arg=<cr>"}
	vector := []string{"username", "bob", "secret", "Hunter2", "<cr>"}
	gotRaw, gotVector, redacted := RedactRecord(rules, raw, vector)
	if !redacted || strings.Contains(strings.Join(gotRaw, " ")+strings.Join(gotVector, " "), "Hunter2") ||
		gotVector[0] != "username" || len(gotVector) != len(vector) {
		t.Fatalf("raw %q vector %q", gotRaw, gotVector)
	}
	if r, v, redacted := RedactRecord(rules, raw[:2], vector[:2]); redacted || len(r) != 2 || len(v) != 2 {
		t.Fatalf("nothing matched, nothing changed: %q %q", r, v)
	}
}

// A password in a URL's userinfo is replaced whatever the patterns say, on
// every platform, and the scheme, user and host stay so the audit still shows
// where a configuration went (task 10 re-review C3). No `after:` pattern can
// hide part of a word, and `after: copy` would blank every copy.
func TestAURLPasswordIsRedacted(t *testing.T) {
	for _, tt := range []struct{ line, want string }{
		{"copy running-config scp://admin:SECRET1@10.0.0.9/r.cfg",
			"copy running-config scp://admin:" + Redacted + "@10.0.0.9/r.cfg"},
		{"copy ftp://admin:SECRET1@h/img.bin flash:", "copy ftp://admin:" + Redacted + "@h/img.bin flash:"},
		{"copy http://u:SECRET1@h:8080/x bootflash:", "copy http://u:" + Redacted + "@h:8080/x bootflash:"},
		{"copy running-config SFTP://u:SECRET1@h/x", "copy running-config SFTP://u:" + Redacted + "@h/x"},
		{"copy tftp://u:SECRET1@h/x startup-config", "copy tftp://u:" + Redacted + "@h/x startup-config"},
		{"copy https://u:SEC:RET1@h/x flash:", "copy https://u:" + Redacted + "@h/x flash:"},
		{"path scp://admin:SECRET1@h/arch", "path scp://admin:" + Redacted + "@h/arch"},
		{"configure terminal ; archive ; path scp://admin:SECRET1@h/arch (SUCCESS)",
			"configure terminal ; archive ; path scp://admin:" + Redacted + "@h/arch (SUCCESS)"},
	} {
		for _, platform := range []string{"arista_eos", "cisco_nxos", "cisco_iosxe"} {
			words := strings.Fields(tt.line)
			got, redacted := Redact(Redactions(platform), words)
			if joined := strings.Join(got, " "); !redacted || joined != tt.want {
				t.Errorf("%s vector %q: %q", platform, tt.line, joined)
			}
			raw := []string{"cmd=" + words[0]}
			for _, w := range words[1:] {
				raw = append(raw, "cmd-arg="+w)
			}
			gotRaw, _, redacted := RedactRecord(Redactions(platform), append(raw, "cmd-arg=<cr>"), nil)
			if joined := strings.Join(gotRaw, " "); !redacted || strings.Contains(joined, "SEC") ||
				!strings.Contains(joined, "://") || !strings.Contains(joined, ":"+Redacted+"@") {
				t.Errorf("%s raw %q: %q", platform, tt.line, gotRaw)
			}
		}
	}
	for _, line := range []string{"copy scp://admin@h/x flash:", "copy running-config flash:backup",
		"ping 10.0.0.1"} {
		if got, redacted := Redact(Redactions("cisco_iosxe"), strings.Fields(line)); redacted {
			t.Errorf("no password in %q: %q", line, got)
		}
	}
}

// Two patterns, one matching both forms and one matching only the vector:
// the raw pairs still lose what the second one hides. Whether a form lost a
// word is judged per pattern, never per record (task 11 review C1).
func TestEachPatternIsJudgedOnBothForms(t *testing.T) {
	rules := []Redaction{{Match: []string{"tunnel", "psk", "*", "key", "*"}, After: "psk"},
		{Match: []string{"**"}, After: "key"}}
	raw := []string{"cmd=tunnel", "cmd-arg=password", "cmd-arg=S3cret", "cmd-arg=key", "cmd-arg=K1", "cmd-arg=|",
		"cmd-arg=no-more"}
	vector := []string{"tunnel", "psk", "S3cret", "key", "K1"}
	r, v, redacted := RedactRecord(rules, raw, vector)
	if !redacted || strings.Contains(strings.Join(r, " ")+strings.Join(v, " "), "S3cret") ||
		strings.Contains(strings.Join(r, " ")+strings.Join(v, " "), "K1") || r[0] != "cmd=tunnel" || v[0] != "tunnel" ||
		len(r) != len(raw) || len(v) != len(vector) {
		t.Fatalf("raw %q vector %q", r, v)
	}
}

// A line that quotes policy text — an error, a report — has every quoted
// value redacted as a rule is, "…" and `…` alike, and nothing else changed
// (task 11 review C2, I1).
func TestAQuotedRuleIsRedactedInALine(t *testing.T) {
	all := AllRedactions()
	line := "role \"r\": rule \"snmp-server community Hunter2 /^rw$/\": `snmp-server community Hunter2 ro` and \"show **\""
	got := RedactQuoted(all, line)
	if strings.Contains(got, "Hunter2") || !strings.Contains(got, `"snmp-server community «redacted» «redacted»"`) ||
		!strings.Contains(got, "`snmp-server community «redacted» «redacted»`") || !strings.Contains(got, `"show **"`) ||
		!strings.HasPrefix(got, `role "r": rule `) {
		t.Fatalf("%s", got)
	}
	if RedactQuoted(all, `an "unclosed quote`) != `an "unclosed quote` {
		t.Fatal("an unclosed quote is left alone")
	}
	// Every platform's built-in list is in the union, not only the default.
	for name := range redactions {
		for _, r := range redactions[name] {
			if !slices.ContainsFunc(all, func(a Redaction) bool { return reflect.DeepEqual(a, r) }) {
				t.Fatalf("%s: %+v missing", name, r)
			}
		}
	}
}

// A secret glued to its keyword by `=` or `:`, or after a keyword that ends in
// a colon, is removed as the keyword's next word is, and so are the keywords
// the default list names for tokens and pre-shared secrets and Junos's
// hierarchical `community X {`: on every platform, since the default list
// guards the accounting log as well as check-config (task 15 review I4). The
// word keeps its keyword, and the command keeps its shape.
func TestAGluedOrNamedSecretIsRedacted(t *testing.T) {
	for _, line := range []string{
		"tacacs-server key=Hunter2", "tacacs-server host 10.1.1.1 key=Hunter2 timeout 5", "password:Hunter2",
		"username bob password: Hunter2", "username bob secret=0 Hunter2", "snmp-server community=Hunter2 ro",
		"community Hunter2 {", "wpa-psk ascii 0 Hunter2", "management api gnmi token Hunter2",
		"radius-server shared-secret Hunter2", "oauth client-secret Hunter2", "set client-secret=Hunter2",
	} {
		for _, name := range []string{"default", "arista_eos", "cisco_iosxe", "cisco_nxos", "juniper_junos"} {
			in := strings.Fields(line)
			got, redacted := Redact(Redactions(name), in)
			keyword := func(w string) string {
				return strings.FieldsFunc(w, func(r rune) bool { return r == '=' || r == ':' })[0]
			}
			if !redacted || strings.Contains(strings.Join(got, " "), "Hunter2") || len(got) != len(in) ||
				keyword(got[0]) != keyword(in[0]) {
				t.Errorf("%s: %q: %q", name, line, got)
			}
			if one, _ := Redact(Redactions(name), []string{line}); strings.Contains(one[0], "Hunter2") ||
				len(strings.Fields(one[0])) != len(in) {
				t.Errorf("%s: %q as one element: %q", name, line, one)
			}
		}
	}
	for in, want := range map[string]string{
		"tacacs-server key=Hunter2":      "tacacs-server key=«redacted»",
		"username bob password: Hunter2": "username bob password: «redacted»",
		"copy scp://u:Hunter2@h/x t":     "copy scp://u:«redacted»@h/x t",
		"set community 65000:1 additive": "set community 65000:1 additive",
	} {
		if got, _ := Redact(Redactions("cisco_iosxe"), []string{in}); got[0] != want {
			t.Errorf("%q: %q, want %q", in, got[0], want)
		}
	}
	raw := []string{"cmd=tacacs-server", "cmd-arg=key=Hunter2", "cmd-arg=<cr>"}
	gotRaw, gotVector, _ := RedactRecord(Redactions("arista_eos"), raw, []string{"tacacs-server", "key=Hunter2", "<cr>"})
	if strings.Contains(strings.Join(gotRaw, " ")+strings.Join(gotVector, " "), "Hunter2") {
		t.Fatalf("record: %q %q", gotRaw, gotVector)
	}
}

// Every argument matches a secret keyword's every abbreviation, and the
// command word — the first word, or the word after a leading `do` — only in
// a key's shape: three characters or more, one character, or two followed by
// an encryption type's digit. So an exec `sh` is not read as `shared-key`,
// while `sh 7 X` in an EOS IPsec profile and `k X` in a key chain still are
// (spec §5.8; task 15 re-review, Question 2).
func TestAShortCommandWordIsASecretKeywordOnlyInAKeysShape(t *testing.T) {
	for _, line := range []string{"tacacs-server k Hunter2", "radius-server k Hunter2",
		"crypto isakmp k Hunter2 address 0.0.0.0", "enable s 0 Hunter2", "enable p Hunter2", "enable pa Hunter2",
		"username bob pa Hunter2", "username bob se 0 Hunter2", "neighbor 10.0.0.1 pa Hunter2", "sh 7 Hunter2",
		"sh 0 Hunter2", "k Hunter2", "shared-key 7 Hunter2", "do sh 7 Hunter2", "key-string Hunter2",
		"license smart register idtoken Hunter2", "management api gnmi token Hunter2",
		// A token need not be the last word (task 15 re-review 2, R2).
		"token 0 Hunter2", "ip http token Hunter2 extra", "management api gnmi token Hunter2 vrf mgmt"} {
		for _, name := range []string{"default", "arista_eos", "cisco_iosxe", "cisco_nxos", "juniper_junos"} {
			if got, _ := Redact(Redactions(name), []string{line}); strings.Contains(got[0], "Hunter2") {
				t.Errorf("%s: %q: %q", name, line, got[0])
			}
		}
	}
	for _, line := range []string{"sh ip int br", "sh run", "do sh run", "sh ip bgp | i 65000", "sh ip bgp | i hostname",
		"do sh ip int br"} {
		for _, name := range []string{"default", "arista_eos", "cisco_iosxe", "cisco_nxos", "juniper_junos"} {
			if got, redacted := Redact(Redactions(name), []string{line}); redacted {
				t.Errorf("%s: %q: %q", name, line, got[0])
			}
		}
	}
}

// A keyword's leading `-` or `/` is not part of it, so a secret glued to an
// option is redacted (task 15 re-review N1).
func TestAnOptionsSecretIsRedacted(t *testing.T) {
	for in, want := range map[string]string{
		"bash curl --password=Hunter2 x": "bash curl --password=«redacted» «redacted»",
		"run /password:Hunter2":          "run /password:«redacted»",
		"bash tool -key=Hunter2":         "bash tool -key=«redacted»",
		"bash curl --password Hunter2":   "bash curl --password «redacted»",
	} {
		if got, _ := Redact(Redactions("arista_eos"), []string{in}); got[0] != want {
			t.Errorf("%q: %q, want %q", in, got[0], want)
		}
	}
}

// A quoted value is split as prose is, by whitespace and then by
// punctuation and a regex's operators, an escape one separator: the JSON a
// diff prints of a config check's match, `^snmp-server community X`, is
// redacted as platform show redacts it; text a set ships prints as written
// (final review I3).
func TestAQuotedRegexIsRedactedAsProse(t *testing.T) {
	all := AllRedactions()
	for _, line := range []string{
		`[{"match":"^snmp-server community Hunter2","says":"x"}]`,
		`["^snmp-server\\s+community\\s+Hunter2$"]`,
		"`(password|secret):Hunter2`",
	} {
		if got := RedactQuoted(all, line); strings.Contains(got, "Hunter2") {
			t.Errorf("%s -> %s", line, got)
		}
	}
	shippedLine := strconv.Quote(`^aaa authentication enable default .*\b(local|enable)\s*$`)
	if got := RedactQuoted(all, shippedLine); got != shippedLine {
		t.Errorf("a shipped match: %s", got)
	}
}

// An escaped backslash is one separator, taken before a single escape: in
// `password\\SEKRIT` the `\S` is not an escape, and reading it as one hid
// the S from the word after `password` (task 15 re-review 3, S1).
func TestAnEscapedBackslashIsOneSeparator(t *testing.T) {
	got := RedactProse(AllRedactions(), `^password\\SEKRIT$`)
	if strings.Contains(got, "S") || got != `^password\\`+Redacted+`$` {
		t.Fatalf("%s", got)
	}
	// A regex escape after the pair is still one separator.
	if got := RedactProse(AllRedactions(), `^username\\\s+x$`); got != `^username\\\s+x$` {
		t.Fatalf("%s", got)
	}
}

// A credential in a URL's query string — a presigned `X-Amz-Signature`, a
// `token` or an `access_token` — is replaced whatever the patterns say, as a
// userinfo password is, and the rest of the URL is kept; and a WLC's
// `security wpa psk set-key` key is redacted as `wpa-psk`'s is (task 10
// re-review, parked).
func TestAURLQueryCredentialIsRedacted(t *testing.T) {
	for in, want := range map[string]string{
		"copy https://b.s3.amazonaws.com/x.bin?X-Amz-Credential=AKIAHunter2&X-Amz-Signature=Hunter2&v=1 flash:": "copy https://b.s3.amazonaws.com/x.bin?X-Amz-Credential=«redacted»&X-Amz-Signature=«redacted»&v=1 flash:",
		"copy https://h/x?sig=Hunter2 flash:":                  "copy https://h/x?sig=«redacted» flash:",
		"copy http://h/x?access_token=Hunter2;token=Hunter2 t": "copy http://h/x?access_token=«redacted»;token=«redacted» t",
		"copy http://h/x?Password=Hunter2&key=Hunter2 t":       "copy http://h/x?Password=«redacted»&key=«redacted» t",
		"copy http://h/x?X-Amz-Security-Token=Hunter2 t":       "copy http://h/x?X-Amz-Security-Token=«redacted» t",
		"copy http://h/x?version=2 t":                          "copy http://h/x?version=2 t",
	} {
		if got, _ := Redact(nil, []string{in}); got[0] != want {
			t.Errorf("%q: %q, want %q", in, got[0], want)
		}
	}
	if got, _ := Redact(Redactions("default"), []string{"security wpa psk set-key ascii 0 Hunter2"}); strings.Contains(got[0], "Hunter2") {
		t.Errorf("%q", got)
	}
}

// The values a rule's redaction hides are what a writer redacts wherever a
// line prints them, as a word of its own, and nowhere else.
func TestHiddenValuesAreRedactedWhereverALinePrintsThem(t *testing.T) {
	rules := Redactions("cisco_iosxe")
	got := HiddenValues(rules, strings.Fields("show system radius-server 10.0.0.1 secret HUNTER2"))
	if !slices.Equal(got, []string{"HUNTER2"}) {
		t.Fatalf("%q", got)
	}
	if got := HiddenValues(rules, strings.Fields("show version")); got != nil {
		t.Fatalf("%q", got)
	}
	line := "`HUNTER2` never matches; write `HUNTER2x` or HunTer2, not xHUNTER2"
	if got, want := RedactValues([]string{"HUNTER2"}, line),
		"`«redacted»` never matches; write `HUNTER2x` or «redacted», not xHUNTER2"; got != want {
		t.Fatalf("%q", got)
	}
}

// A value with a `"` or `\` in it is past the writer's pass once %q quotes
// it, so the pass matches its quoted forms too, in any letter case, and
// QuoteShown redacts before it quotes, which is how a report quotes text
// derived from a rule (task 12b review I1).
func TestAQuotedValueIsStillRedacted(t *testing.T) {
	for _, v := range []string{`pa"ss9`, `a\b9`, `Mi"X\d9`} {
		leaks := func(got string) bool {
			low := strings.ToLower(got)
			return strings.Contains(low, strings.ToLower(v)) ||
				strings.Contains(low, strings.ToLower(strings.Trim(strconv.Quote(v), `"`)))
		}
		for _, line := range []string{
			fmt.Sprintf("allow %q is not sent: %q is not a keyword", "show "+v+" **", v),
			fmt.Sprintf("%q", strings.ToUpper(v)),
			strconv.QuoteToASCII(strings.ToLower(v)),
			"`" + v + "`",
		} {
			if got := RedactValues([]string{v}, line); leaks(got) || !strings.Contains(got, Redacted) {
				t.Errorf("%s: %s -> %s", v, line, got)
			}
		}
		if got := QuoteShown([]string{v}, "show "+strings.ToUpper(v)+" **"); got != `"show `+Redacted+` **"` {
			t.Errorf("%s: %s", v, got)
		}
	}
}

// A reply regex writes a word re-cased, a letter as `[hH]`, or escaped, which
// no writer's pass recognizes: one that carries a hidden value prints
// redacted whole, and any other as it is (task 12b review I1).
func TestARegexCarryingAHiddenValueIsRedactedWhole(t *testing.T) {
	for _, re := range []string{`^(show [hH][uU][nN][tT][eE][rR]2)$`, `^(show hunter2( .*)?)$`, `^(show x\.y|show HUNTER2)$`} {
		if got := RegexShown([]string{"HUNTER2"}, re); got != Redacted {
			t.Errorf("%s: %s", re, got)
		}
	}
	if got := RegexShown([]string{"x.y"}, `^(show x\.y)$`); got != Redacted {
		t.Errorf("escaped: %s", got)
	}
	if re := `^(show [hH]unter( .*)?)$`; RegexShown([]string{"HUNTER2"}, re) != re {
		t.Errorf("%s redacted", re)
	}
}

// A value is matched in any letter case by Unicode case folding, not ASCII
// only: `PÄ"ss9` hidden is `pä"ss9` typed, as written, %q-quoted or quoted
// in ASCII (task 12b review).
func TestAValueIsMatchedInAnyUnicodeCase(t *testing.T) {
	v := `PÄ"ss9`
	for _, line := range []string{
		`show pä"ss9 **`,
		fmt.Sprintf("allow %q", `show pä"SS9 **`),
		strconv.QuoteToASCII(`show pä"ss9`),
		`the word ΣΑΣ, and ſtop`,
	} {
		got := RedactValues([]string{v, "σας", "stop"}, line)
		if low := strings.ToLower(got); strings.Contains(low, "ss9") || strings.Contains(low, "σας") ||
			strings.Contains(got, "ſtop") || !strings.Contains(got, Redacted) {
			t.Errorf("%s -> %s", line, got)
		}
	}
	if got := QuoteShown([]string{v}, `show pä"SS9 **`); got != `"show `+Redacted+` **"` {
		t.Errorf("%s", got)
	}
}

// Rendered registers only text whose every hidden word is regex syntax or a
// proven deny keyword. A keyword glued to a literal, `community,X`, is not one
// prose word, so the literal is never proven and prints redacted (issue 17,
// review I2 and M3).
func TestRenderedRefusesAKeywordGluedToALiteral(t *testing.T) {
	rules := Redactions("juniper_junos")
	glued := `^( *snmp-server +community,fakesecret123( .*)? *(\|.*)?)$`
	if Rendered(rules, glued, []string{"snmp-server", "community,fakesecret123"}) ||
		Rendered(rules, glued, []string{"snmp-server", "community"}) {
		t.Fatal("a keyword glued to a literal was registered")
	}
	printed := RedactQuoted(rules, strconv.Quote(glued))
	if strings.Contains(printed, "fakesecret123") {
		t.Fatalf("the literal was printed: %s", printed)
	}
	// The same line with a clean keyword registers, and prints whole.
	clean := `^( *show +key( .*)? *(\|.*)?)$`
	if !Rendered(rules, clean, []string{"show", "key", "**"}) || RedactQuoted(rules, strconv.Quote(clean)) != strconv.Quote(clean) {
		t.Fatalf("a proven keyword's line was not printed as rendered: %s", RedactQuoted(rules, strconv.Quote(clean)))
	}
	// A word no rule proved is not exempt, even without a literal's look.
	unproven := `^( *show +key( foo)?)$`
	if Rendered(rules, unproven, []string{"show", "key"}) || !Rendered(rules, unproven, []string{"show", "key", "foo"}) {
		t.Fatal("a hidden word is exempt only when proven")
	}
}

// The safety of Rendered rests on a shipped deny keyword being exactly one
// prose word as the printer tokenizes it: a keyword with a separator in it
// would split into pieces the proof does not cover.
func TestEveryShippedKeywordIsOneProseWord(t *testing.T) {
	versions, err := fs.ReadDir(platforms.Keywords, "keywords")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, v := range versions {
		if !v.IsDir() {
			continue
		}
		k := KeywordsFor(v.Name(), "juniper_junos")
		if k == nil {
			continue
		}
		for path, node := range k.nodes {
			for _, w := range node.Words {
				n++
				if !oneProseWord(w) {
					t.Errorf("%s: keyword %q after %q is not one prose word", v.Name(), w, path)
				}
			}
		}
	}
	if n == 0 {
		t.Fatal("no shipped keyword was checked")
	}
}

// oneProseWord is whether word is a single word as the printer tokenizes.
func oneProseWord(word string) bool {
	sp := proseWord.FindAllStringIndex(word, -1)
	return len(sp) == 1 && sp[0][0] == 0 && sp[0][1] == len(word) && word[0] != '\\'
}

// Rendered's whitespace pass refuses text a URL's password hides, which the
// prose pass cannot see: the URL's pieces are no keyword (issue 17, review m3).
func TestRenderedRefusesATextTheWhitespacePassHides(t *testing.T) {
	rules := Redactions("default")
	text := "copy scp://u:fakesecret123@h/x t"
	if Rendered(rules, text, nil) {
		t.Fatal("a URL password was registered")
	}
	if got := RedactQuoted(rules, strconv.Quote(text)); strings.Contains(got, "fakesecret123") {
		t.Fatalf("the literal was printed: %s", got)
	}
}

// A credential keyword glued to a value with any separator hides the value on
// every path a line is printed by (issue 19): the whitespace pass, the quoted
// prose pass, a rule's words and a record's two forms.
func TestAGlueSeparatorNeverCarriesAValuePast(t *testing.T) {
	const lit = "fakesecret123"
	for _, sep := range []string{",", ":", "=", "+", "|", ";", "/"} {
		for _, name := range []string{"default", "arista_eos", "cisco_iosxe", "cisco_nxos", "juniper_junos"} {
			rules := Redactions(name)
			line := "request password" + sep + lit
			paths := map[string]string{}
			got, _ := Redact(rules, []string{line})
			paths["Redact"] = got[0]
			words, _ := RedactRule(rules, strings.Fields(line))
			paths["RedactRule"] = strings.Join(words, " ")
			paths["RedactProse"] = RedactProse(rules, line)
			paths["RedactQuoted"] = RedactQuoted(rules, strconv.Quote(line))
			paths["RedactQuoted regex"] = RedactQuoted(rules, strconv.Quote("^( *request +password"+sep+lit+"( .*)? *)$"))
			raw, vec, _ := RedactRecord(rules, []string{"cmd=request", "cmd-arg=password" + sep + lit, "cmd-arg=<cr>"},
				[]string{"request", "password" + sep + lit, "<cr>"})
			paths["RedactRecord"] = strings.Join(raw, " ") + " " + strings.Join(vec, " ")
			for path, out := range paths {
				if strings.Contains(out, lit) {
					t.Errorf("%s: sep %q: %s printed the literal: %s", name, sep, path, out)
				}
			}
		}
	}
}
