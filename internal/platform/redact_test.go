package platform

import (
	"reflect"
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
	got, redacted := RedactRaw(rules, raw)
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
		got, redacted := RedactRaw(Redactions(tt.platform), tt.raw)
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
	got, redacted := RedactRaw(Redactions("juniper_junos"),
		[]string{"task_id=2", "cmd=set system root-authentication encrypted-password \"$6$abc\" <cr>"})
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
		"match is required":         {After: "x"},
		"no regex or class":         {Match: []string{"/secret/"}, After: "x"},
		"more than two **":          {Match: []string{"**", "a", "**", "b", "**"}, After: "x"},
		"one of the two":            {Match: []string{"**"}, After: "x", From: &one},
		"from: 0 is the command":    {Match: []string{"**"}, From: &zero},
		"after \"a b\" is one word": {Match: []string{"**"}, After: "a b"},
		"matches every command":     {Match: []string{"*", "**"}, From: &one},
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
			gotRaw, redacted := RedactRaw(Redactions(platform), append(raw, "cmd-arg=<cr>"))
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
