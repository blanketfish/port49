package devicecert

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/blanketfish/port49/internal/admission"
	"github.com/blanketfish/port49/internal/printsafe"
)

// Rule is tls_listener.device_identity (decision 50 ruling 6): which
// subjectAltName kinds name a device, and the DNS suffixes its inventory
// name may carry. Suffixes are lower case with no leading or trailing dot
// (config refuses any other). The common name is never read (RFC 9525).
type Rule struct {
	DNSName     bool
	IPAddress   bool
	DNSSuffixes []string
}

// Match is nil when leaf names dev: a dNSName equal to its name, or its
// name under a suffix, case-insensitively and with a trailing dot dropped;
// or an iPAddress among its inventory addresses. A wildcard never names a
// device, and a non-ASCII name never matches (admission.FoldASCII). The error says what the certificate named and what was wanted.
func (r Rule) Match(leaf *x509.Certificate, dev admission.Device) error {
	if r.DNSName {
		for _, san := range leaf.DNSNames {
			if r.namesDevice(san, dev.Name) {
				return nil
			}
		}
	}
	if r.IPAddress {
		for _, ip := range leaf.IPAddresses {
			if a, ok := netip.AddrFromSlice(ip); ok && slices.Contains(dev.Addresses, a.Unmap()) {
				return nil
			}
		}
	}
	return errors.New(r.describe(leaf, dev))
}

func (r Rule) namesDevice(san, name string) bool {
	san, sanOK := admission.FoldASCII(strings.TrimSuffix(san, "."))
	name, nameOK := admission.FoldASCII(name)
	if !sanOK || !nameOK || san == "" || strings.Contains(san, "*") {
		return false
	}
	if san == name {
		return true
	}
	for _, s := range r.DNSSuffixes {
		if san == name+"."+s {
			return true
		}
	}
	return false
}

func (r Rule) describe(leaf *x509.Certificate, dev admission.Device) string {
	var has, want []string
	if r.DNSName {
		has = append(has, "dns_name "+bounded(leaf.DNSNames))
		names := []string{dev.Name}
		for _, s := range r.DNSSuffixes {
			names = append(names, dev.Name+"."+s)
		}
		want = append(want, "dns_name "+strings.Join(names, " or "))
	}
	if r.IPAddress {
		ips := make([]string, 0, len(leaf.IPAddresses))
		for _, ip := range leaf.IPAddresses {
			ips = append(ips, ip.String())
		}
		has = append(has, "ip_address "+bounded(ips))
		addrs := make([]string, 0, len(dev.Addresses))
		for _, a := range dev.Addresses {
			addrs = append(addrs, a.String())
		}
		want = append(want, "ip_address "+strings.Join(addrs, " or "))
	}
	return printsafe.Line(fmt.Sprintf("the certificate names %s; device %s is %s", strings.Join(has, " and "),
		dev.Name, strings.Join(want, ", or ")), 400)
}

// bounded lists at most eight entries, "[none]" for none.
func bounded(s []string) string {
	if len(s) == 0 {
		return "[none]"
	}
	if len(s) > 8 {
		return "[" + strings.Join(s[:8], " ") + fmt.Sprintf(" and %d more]", len(s)-8)
	}
	return "[" + strings.Join(s, " ") + "]"
}

// Unidentifiable are the tls devices this Rule cannot tell apart or cannot
// name, by name, each with a one-line reason (decision 50 ruling 6). The
// listener alone refuses them: a connection from one is declined
// identity_mismatch, and the policy means the same on every replica.
//   - Clash, when DNSName is in the Rule: two devices share a candidate
//     dNSName (the name, or the name plus "." plus a suffix, ASCII-folded), so
//     one certificate would name both. Both are flagged.
//   - A name with a non-ASCII byte, when IPAddress is not in the Rule: no
//     dNSName can carry it and no address identifies it. With ip_address the
//     address still names the device, so it is not flagged.
//
// A tcp device is not judged. A tls device already refused for the name clash
// admission.TLSNameClashes finds is not reported, but its names still count: its
// certificate exists and can name another device. A reason never holds a key,
// a pin or certificate bytes.
func (r Rule) Unidentifiable(devs []admission.Device) map[string]string {
	out := map[string]string{}
	refused := admission.TLSNameClashes(devs)
	byCandidate := map[string][]string{}
	for _, d := range devs {
		if d.EffectiveTransport() != admission.TransportTLS {
			continue
		}
		f, ascii := admission.FoldASCII(d.Name)
		if !ascii {
			if !r.IPAddress {
				out[d.Name] = "has a name with a non-ASCII byte, which no dNSName can carry, and match does not " +
					"include ip_address, so no certificate can name it"
			}
			continue
		}
		if !r.DNSName {
			continue
		}
		cands := map[string]bool{f: true}
		for _, s := range r.DNSSuffixes {
			if fs, ok := admission.FoldASCII(strings.Trim(s, ".")); ok && fs != "" {
				cands[f+"."+fs] = true
			}
		}
		for c := range cands {
			byCandidate[c] = append(byCandidate[c], d.Name)
		}
	}
	with := map[string]map[string]bool{}
	for _, names := range byCandidate {
		if len(names) < 2 {
			continue
		}
		for _, n := range names {
			if with[n] == nil {
				with[n] = map[string]bool{}
			}
			for _, m := range names {
				with[n][m] = true
			}
		}
	}
	for n, set := range with {
		if _, done := refused[n]; done {
			continue // admission refused it already; it only counted as a claimant
		}
		names := make([]string, 0, len(set))
		for m := range set {
			names = append(names, m)
		}
		slices.Sort(names)
		out[n] = fmt.Sprintf("is one of tls devices %q that one certificate dNSName could name (the name, or the "+
			"name plus a dns_suffixes suffix), so a certificate could not tell them apart", names)
	}
	return out
}
