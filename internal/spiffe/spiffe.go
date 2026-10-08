// Package spiffe reads a SPIFFE ID (the SPIFFE ID specification, §2): the
// form a workload certificate's one URI SAN names its workload in (plan 8;
// policy engine spec §13 decision 40). The policy's load, the broker's
// workload verifier and a revocation's principal each read an ID through
// Parse, so the three agree on what one is. Nothing is folded or trimmed:
// an ID outside the form is refused, since the path is case-sensitive and
// a folded string would make two IDs one.
package spiffe

import (
	"errors"
	"fmt"
	"strings"
)

// Scheme is how every ID begins, in lower case (SPIFFE ID §2).
const Scheme = "spiffe://"

// MaxLen is the longest ID, in bytes (SPIFFE ID §2.3).
const MaxLen = 2048

// ErrNotSPIFFE is a string that is not a SPIFFE ID.
var ErrNotSPIFFE = errors.New("not a SPIFFE ID")

// ID is a parsed SPIFFE ID. Path is "" for the trust domain's own ID, and
// otherwise begins with "/".
type ID struct {
	TrustDomain string
	Path        string
}

// String is the ID as Parse read it.
func (id ID) String() string { return Scheme + id.TrustDomain + id.Path }

// Parse reads s as a SPIFFE ID, or says why it is not one: the lower-case
// scheme, a trust domain of a-z 0-9 . - _ (§2.1), and path segments of
// A-Z a-z 0-9 . - _, none empty, "." or "..", with no trailing "/" (§2.2),
// at most MaxLen bytes. Those sets leave no room for a port, userinfo, a
// query, a fragment or a percent-encoding.
func Parse(s string) (ID, error) {
	if len(s) > MaxLen {
		return ID{}, fmt.Errorf("%w: it is longer than %d bytes", ErrNotSPIFFE, MaxLen)
	}
	rest, ok := strings.CutPrefix(s, Scheme)
	if !ok {
		return ID{}, fmt.Errorf("%w: it does not begin %s, in lower case", ErrNotSPIFFE, Scheme)
	}
	td, path := rest, ""
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		td, path = rest[:i], rest[i:]
	}
	if err := CheckTrustDomain(td); err != nil {
		return ID{}, err
	}
	if path != "" {
		for _, seg := range strings.Split(path[1:], "/") {
			switch {
			case seg == "":
				return ID{}, fmt.Errorf("%w: an empty path segment (a // or a trailing /)", ErrNotSPIFFE)
			case seg == "." || seg == "..":
				return ID{}, fmt.Errorf("%w: a path segment of . or ..", ErrNotSPIFFE)
			case strings.IndexFunc(seg, func(r rune) bool { return !segmentRune(r) }) >= 0:
				return ID{}, fmt.Errorf("%w: a path segment holds a character outside A-Z a-z 0-9 . - _", ErrNotSPIFFE)
			}
		}
	}
	return ID{TrustDomain: td, Path: path}, nil
}

// ParseWorkload is Parse for a workload's ID, which has a path: the trust
// domain's own ID names the domain, not a workload (decision 40 ruling 3).
func ParseWorkload(s string) (ID, error) {
	id, err := Parse(s)
	if err == nil && id.Path == "" {
		return ID{}, fmt.Errorf("%w: %s names the trust domain itself, not a workload; a workload's ID has a path "+
			"(spiffe://%s/<path>)", ErrNotSPIFFE, s, id.TrustDomain)
	}
	return id, err
}

// CheckTrustDomain checks a trust domain name alone (SPIFFE ID §2.1): one or
// more of a-z 0-9 . - _, as broker.identity.machines[].spiffe_trust_domains
// lists it.
func CheckTrustDomain(td string) error {
	switch {
	case td == "":
		return fmt.Errorf("%w: the trust domain is empty", ErrNotSPIFFE)
	case len(Scheme)+len(td) > MaxLen:
		return fmt.Errorf("%w: the trust domain is longer than an ID may be", ErrNotSPIFFE)
	case strings.IndexFunc(td, func(r rune) bool { return !trustDomainRune(r) }) >= 0:
		return fmt.Errorf("%w: the trust domain holds a character outside a-z 0-9 . - _ (upper case is refused, "+
			"not folded)", ErrNotSPIFFE)
	}
	return nil
}

func trustDomainRune(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '_'
}

func segmentRune(r rune) bool { return trustDomainRune(r) || r >= 'A' && r <= 'Z' }
