// Package normal is the form a principal, a certificate's issuer and a serial
// take in a revocation or an admin call: the one spelling the broker compares
// and an admin proof's target shows. The broker and the agent both use it, so
// the agent can derive from its own request the target a challenge must name
// (spec §5.1.6, "Presence, not intent"). An error's text is the reason alone;
// the caller adds its own prefix.
package normal

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/rhwendt/port49/internal/k8sid"
	"github.com/rhwendt/port49/internal/printsafe"
	"github.com/rhwendt/port49/internal/spiffe"
)

// Prefixes are the forms a verifier gives a principal (spec §2): user: for
// people, app: for an OIDC machine (plan 7h), spiffe:// for a workload
// certificate (plan 8), system:serviceaccount: for a cluster's service
// account (plan 10).
var Prefixes = []string{"user:", "app:", spiffe.Scheme, k8sid.Prefix}

// Principal is p as Identity spells it: user: and the lower-cased email, the
// mapping being case-insensitive by construction, or app: and the client id
// verbatim (a client id is case-sensitive). One that is not printable ASCII,
// has no known prefix, or nothing after it, is refused (pre-flight I2, M16).
// The HTTP endpoints compare a caller to a principal a request names only
// after this, so no spelling makes another principal read as the caller, or
// the caller as another (decision 34).
func Principal(p string) (string, error) {
	if strings.HasPrefix(strings.ToLower(p), spiffe.Scheme) {
		// Before the 1024-byte guard below: an ID may be spiffe.MaxLen bytes,
		// and the verifier authenticates one that long, so the operator must be
		// able to revoke it. Verbatim: the path is case-sensitive, and the
		// verifier gives the ID only in the form ParseWorkload accepts, which
		// bounds its length and characters (decision 40 ruling 4).
		if _, err := spiffe.ParseWorkload(p); err != nil {
			return "", fmt.Errorf("%s is not a workload's SPIFFE ID as the broker spells one (%v)",
				printsafe.Line(p, 200), err)
		}
		return p, nil
	}
	if strings.HasPrefix(strings.ToLower(p), k8sid.Prefix) {
		// Verbatim: a cluster names accounts in lower case alone, and the
		// verifier gives one only in the form k8sid.Parse accepts (decision 49
		// ruling 8). Before the 1024-byte guard, as a spiffe ID is.
		id, err := k8sid.Parse(p)
		if err != nil {
			return "", fmt.Errorf("%s is not a service account as its cluster names one (%v)",
				printsafe.Line(p, 200), err)
		}
		return id.String(), nil
	}
	if len(p) > 1024 || strings.IndexFunc(p, func(r rune) bool { return r < 0x21 || r > 0x7e }) >= 0 {
		return "", errors.New("a principal is printable ASCII")
	}
	for _, pre := range Prefixes {
		if strings.HasPrefix(strings.ToLower(p), pre) && len(p) > len(pre) {
			if pre == "app:" {
				return pre + p[len(pre):], nil // a client id is case-sensitive
			}
			return pre + strings.ToLower(p[len(pre):]), nil
		}
	}
	return "", fmt.Errorf("a principal begins %s, as the log names it (user:alice@example.com, app:port49-ci, "+
		"spiffe://corp.example.com/host/oxidized-01, system:serviceaccount:netops:oxidized)",
		strings.Join(Prefixes, " or "))
}

// User is Principal for a person: only a user: principal signs in with a
// directory password, so only one has a second factor to reset or a lockout
// to clear.
func User(principal string) (string, error) {
	if !strings.HasPrefix(strings.ToLower(principal), "user:") {
		return "", fmt.Errorf("%q is not a user: principal; only a person signs in with a directory password",
			printsafe.Line(principal, 200))
	}
	n, err := Principal(principal)
	if err != nil {
		return "", fmt.Errorf("%q is not a principal as the log spells one: user: and an email",
			printsafe.Line(principal, 300))
	}
	return n, nil
}

// Issuer refuses a certificate issuer that is not valid UTF-8 or has a
// control or format character (C0, C1, a bidi override), which the log would
// carry raw.
func Issuer(s string) error {
	if len(s) > 2048 || !utf8.ValidString(s) ||
		strings.IndexFunc(s, func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) }) >= 0 {
		return errors.New("the issuer has a control or format character or is not UTF-8")
	}
	return nil
}

// Serial is a certificate serial in lower-case hex as big.Int.Text(16) prints
// it, which is what Identity records: colons, a 0x and leading zeros are
// dropped, and a leading - (a negative serial, which Go 1.22 still accepts)
// is kept.
func Serial(serial string) (string, error) {
	s := strings.ReplaceAll(strings.ToLower(serial), ":", "")
	neg := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(strings.TrimPrefix(s, "-"), "0x")
	if s == "" || len(s) > 64 || strings.Trim(s, "0123456789abcdef") != "" {
		return "", errors.New("a serial is hexadecimal")
	}
	if s = strings.TrimLeft(s, "0"); s == "" {
		s, neg = "0", false
	}
	if neg {
		s = "-" + s
	}
	return s, nil
}
