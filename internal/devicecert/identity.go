package devicecert

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/printsafe"
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
