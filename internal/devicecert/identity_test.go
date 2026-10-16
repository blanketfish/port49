package devicecert

import (
	"crypto/x509"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/rhwendt/port49/internal/admission"
)

func leafNaming(dns []string, ips ...string) *x509.Certificate {
	c := &x509.Certificate{DNSNames: dns}
	for _, s := range ips {
		c.IPAddresses = append(c.IPAddresses, net.ParseIP(s))
	}
	return c
}

func TestRuleMatch(t *testing.T) {
	dev := admission.Device{Name: "leaf-01", Addresses: []netip.Addr{netip.MustParseAddr("10.0.1.5"),
		netip.MustParseAddr("2001:db8::5")}}
	both := Rule{DNSName: true, IPAddress: true, DNSSuffixes: []string{"net.example.com"}}
	for name, c := range map[string]struct {
		rule Rule
		leaf *x509.Certificate
		ok   bool
	}{
		"exact name":                 {both, leafNaming([]string{"leaf-01"}), true},
		"name under a suffix":        {both, leafNaming([]string{"leaf-01.net.example.com"}), true},
		"case and trailing dot":      {both, leafNaming([]string{"LEAF-01.Net.Example.COM."}), true},
		"an unlisted suffix":         {both, leafNaming([]string{"leaf-01.other.example.com"}), false},
		"another device":             {both, leafNaming([]string{"leaf-02.net.example.com"}), false},
		"a wildcard never":           {both, leafNaming([]string{"*.net.example.com"}), false},
		"a name only as a prefix":    {both, leafNaming([]string{"leaf-01x"}), false},
		"one of its addresses":       {both, leafNaming(nil, "10.0.1.5"), true},
		"its v6 address":             {both, leafNaming(nil, "2001:db8::5"), true},
		"an address not its own":     {both, leafNaming(nil, "10.0.1.6"), false},
		"dns only ignores addresses": {Rule{DNSName: true}, leafNaming(nil, "10.0.1.5"), false},
		"ip only ignores names":      {Rule{IPAddress: true}, leafNaming([]string{"leaf-01"}), false},
		"a prefix before the name":   {both, leafNaming([]string{"evil-leaf-01.net.example.com"}), false},
		"a label after the suffix":   {both, leafNaming([]string{"leaf-01.net.example.com.evil"}), false},
		"a doubled trailing dot":     {both, leafNaming([]string{"leaf-01.net.example.com.."}), false},
	} {
		err := c.rule.Match(c.leaf, dev)
		if (err == nil) != c.ok {
			t.Errorf("%s: %v, want ok=%v", name, err, c.ok)
		}
	}
}

func TestRuleMatchNeverReadsTheCommonName(t *testing.T) {
	leaf := leafNaming(nil)
	leaf.Subject.CommonName = "leaf-01"
	if err := (Rule{DNSName: true, IPAddress: true}).Match(leaf, admission.Device{Name: "leaf-01"}); err == nil {
		t.Fatal("the common name named the device (RFC 9525: it is never read)")
	}
}

func TestAMismatchSaysWhatWasNamedAndWanted(t *testing.T) {
	dev := admission.Device{Name: "leaf-01", Addresses: []netip.Addr{netip.MustParseAddr("10.0.1.5")}}
	err := Rule{DNSName: true, IPAddress: true, DNSSuffixes: []string{"example.net"}}.Match(
		leafNaming([]string{"leaf-02.example.net"}, "10.9.9.9"), dev)
	if err == nil {
		t.Fatal("matched")
	}
	for _, want := range []string{"leaf-02.example.net", "10.9.9.9", "leaf-01 or leaf-01.example.net", "10.0.1.5"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%q lacks %q", err, want)
		}
	}
}

// strings.ToLower is Unicode folding: a Kelvin sign would stand for a k.
func TestRuleMatchFoldsASCIIOnly(t *testing.T) {
	r := Rule{DNSName: true}
	if err := r.Match(leafNaming([]string{"kr1"}), admission.Device{Name: "\u212ar1"}); err == nil {
		t.Fatal("a Kelvin-sign device name matched kr1")
	}
	if err := r.Match(leafNaming([]string{"\u212ar1"}), admission.Device{Name: "kr1"}); err == nil {
		t.Fatal("a non-ASCII SAN matched kr1")
	}
	if err := r.Match(leafNaming([]string{"KR1"}), admission.Device{Name: "kr1"}); err != nil {
		t.Fatalf("ASCII case folding lost: %v", err)
	}
}

func TestRuleUnidentifiable(t *testing.T) {
	tls := func(n, addr string) admission.Device {
		return admission.Device{Name: n, Transport: admission.TransportTLS, Addresses: []netip.Addr{netip.MustParseAddr(addr)}}
	}
	tcp := func(n, addr string) admission.Device {
		return admission.Device{Name: n, Transport: admission.TransportTCP, Addresses: []netip.Addr{netip.MustParseAddr(addr)}}
	}
	devs := []admission.Device{tls("leaf-01", "10.0.0.1"), tls("Leaf-01.Example.NET", "10.0.0.2"), tls("leaf-02", "10.0.0.3"),
		tls("léaf-09", "10.0.0.4"), tcp("tcp-a", "10.0.0.5"), tcp("tcp-a.example.net", "10.0.0.6"),
		tcp("tçp-b", "10.0.0.7"), tls("Dup", "10.0.0.8"), tls("dup", "10.0.0.9")}
	names := func(m map[string]string) []string {
		var out []string
		for n := range m {
			out = append(out, n)
		}
		slices.Sort(out)
		return out
	}
	for name, c := range map[string]struct {
		rule Rule
		want []string
	}{
		"dns with a suffix: the pair, and the non-ASCII name": {Rule{DNSName: true, DNSSuffixes: []string{"example.net"}},
			[]string{"Leaf-01.Example.NET", "leaf-01", "léaf-09"}},
		"dns without a suffix: only the non-ASCII name": {Rule{DNSName: true}, []string{"léaf-09"}},
		"both kinds: the address names the non-ASCII device": {Rule{DNSName: true, IPAddress: true, DNSSuffixes: []string{"example.net"}},
			[]string{"Leaf-01.Example.NET", "leaf-01"}},
		"ip_address only: nothing, names are not read": {Rule{IPAddress: true, DNSSuffixes: []string{"example.net"}}, nil},
		"an uppercase, dotted suffix still joins":      {Rule{DNSName: true, IPAddress: true, DNSSuffixes: []string{"Example.NET."}}, []string{"Leaf-01.Example.NET", "leaf-01"}},
	} {
		got := c.rule.Unidentifiable(devs)
		if !slices.Equal(names(got), c.want) {
			t.Errorf("%s: %v, want %v", name, names(got), c.want)
		}
		for n, why := range got {
			if why == "" || strings.Contains(why, "\n") {
				t.Errorf("%s: %s: reason %q is not one line", name, n, why)
			}
		}
		// The case-folding pair is admission's refusal already; never reported twice.
		if _, dup := got["Dup"]; dup {
			t.Errorf("%s: Dup is already refused by admission", name)
		}
	}
}
