package directory

import (
	"encoding/hex"
	"fmt"
	"slices"
	"strings"

	"github.com/go-ldap/ldap/v3"

	"github.com/rhwendt/port49/internal/printsafe"
	"github.com/rhwendt/port49/internal/spiffe"
	"github.com/rhwendt/port49/internal/token"
)

// Identity is one directory entry as a principal (Ruling 3). EntryID is
// the entry's immutable id, the pin a principal keeps.
type Identity struct{ DN, EntryID, Principal, Username string }

// entryAttrs is what an entry search reads: the principal and username
// attributes, the mapping's, for KeysOf, both immutable ids, of which a
// directory holds one, and, under a workload mapping, its attribute, which
// notWorkload reads (decision 41 ruling 4).
func (c Config) entryAttrs() []string {
	attrs := []string{c.PrincipalAttribute, c.UsernameAttribute, "objectGUID", "entryUUID"}
	if c.Mapping.Attribute != "" { // a sign-in with no certificate mapping has none (I8)
		attrs = append(attrs, c.Mapping.Attribute)
	}
	if c.Workload != nil {
		attrs = append(attrs, c.Workload.Attribute)
	}
	return attrs
}

// notWorkload is ErrUnmapped when e, read as a person's, holds a SPIFFE ID in
// the workload attribute (decision 41 ruling 4: one entry, one domain). Such
// an entry is a workload's: as a person's too, it would give a user:
// principal and a workload one (nas, username) context, and whichever minted
// last would hold the other's grants. A value that is no SPIFFE ID (an
// attribute such as description, set on people for other reasons) is no
// refusal. The prefix test is byte for byte, as a workload's own match is: a
// value in another case can never map a workload, so it is no workload's.
func (c Config) notWorkload(e *ldap.Entry) error {
	if c.Workload == nil {
		return nil
	}
	for _, v := range e.GetAttributeValues(c.Workload.Attribute) {
		if strings.HasPrefix(v, spiffe.Scheme) {
			return fmt.Errorf("%w: entry %s: the entry is a workload's (%s): it holds a SPIFFE ID there, and one "+
				"entry is one trust domain, so it is never a person's principal (spec §13 decision 41 ruling 4)",
				ErrUnmapped, printsafe.Line(e.DN, 200), c.Workload.Attribute)
		}
	}
	return nil
}

// entryID is e's immutable id (Ruling 3): entryUUID lower-cased (RFC 4530,
// server-assigned: OpenLDAP, 389), else objectGUID's bytes in hex (AD, which
// has no entryUUID), else the DN canonicalized, which an OU move changes.
// entryUUID wins because some schemas let a user write objectGUID (review M-4).
func entryID(e *ldap.Entry) string {
	if u := e.GetAttributeValue("entryUUID"); u != "" {
		return "uuid:" + strings.ToLower(u)
	}
	if raw := e.GetRawAttributeValue("objectGUID"); len(raw) > 0 {
		return "guid:" + hex.EncodeToString(raw)
	}
	return "dn:" + canonicalValue(MapSubjectDN, e.DN)
}

// oneEntry is the one entry filter finds under base_dn, size limit 2:
// none is ErrUnmapped, two (or the server's size-limit error) ErrAmbiguous
// naming both, never the first (design §7).
func (c Config) oneEntry(s Searcher, filter string, attrs []string) (*ldap.Entry, error) {
	res, err := s.Search(ldap.NewSearchRequest(c.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2,
		int(c.QueryTimeout.Seconds()), false, filter, attrs, nil))
	if ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) || (err == nil && len(res.Entries) > 1) {
		var dns []string
		if res != nil {
			for _, e := range res.Entries {
				dns = append(dns, printsafe.Line(e.DN, 200))
			}
		}
		return nil, fmt.Errorf("%w: %d or more entries (%s)", ErrAmbiguous, max(len(dns), 2), strings.Join(dns, "; "))
	}
	if err != nil {
		return nil, err
	}
	if len(res.Entries) == 0 {
		return nil, fmt.Errorf("%w: no entry under %s", ErrUnmapped, c.BaseDN)
	}
	return res.Entries[0], nil
}

// identityOf derives the principal and username from e (Ruling 3).
func (c Config) identityOf(e *ldap.Entry) (Identity, error) {
	one := func(attr string) (string, error) {
		vs := e.GetAttributeValues(attr)
		if len(vs) != 1 {
			return "", fmt.Errorf("%w: entry %s has %d values of %s; exactly one", ErrUnmapped,
				printsafe.Line(e.DN, 200), len(vs), attr)
		}
		return vs[0], nil
	}
	p, err := one(c.PrincipalAttribute)
	if err != nil {
		return Identity{}, err
	}
	if !asciiName(p) {
		return Identity{}, fmt.Errorf("%w: entry %s's %s is not printable ASCII (%d bytes)", ErrUnmapped,
			printsafe.Line(e.DN, 200), c.PrincipalAttribute, len(p))
	}
	p = strings.ToLower(p)
	if !printable(p) || strings.ContainsAny(p, " \t") || !strings.Contains(p, "@") {
		return Identity{}, fmt.Errorf("%w: entry %s's %s is not a printable name with an @ (%d bytes)", ErrUnmapped,
			printsafe.Line(e.DN, 200), c.PrincipalAttribute, len(p))
	}
	u, err := c.usernameOf(e)
	if err != nil {
		return Identity{}, err
	}
	return Identity{DN: e.DN, EntryID: entryID(e), Principal: "user:" + p, Username: u}, nil
}

// usernameOf is e's username_attribute as a username (Ruling 3): one value,
// printable ASCII, lower-cased, canonical and not reserved.
func (c Config) usernameOf(e *ldap.Entry) (string, error) {
	vs := e.GetAttributeValues(c.UsernameAttribute)
	if len(vs) != 1 {
		return "", fmt.Errorf("%w: entry %s has %d values of %s; exactly one", ErrUnmapped,
			printsafe.Line(e.DN, 200), len(vs), c.UsernameAttribute)
	}
	u := vs[0]
	if !asciiName(u) {
		return "", fmt.Errorf("%w: entry %s's %s is not printable ASCII (%d bytes)", ErrUnmapped,
			printsafe.Line(e.DN, 200), c.UsernameAttribute, len(u))
	}
	u = strings.ToLower(u)
	switch {
	case !token.CanonicalUsername(u):
		return "", fmt.Errorf("%w: entry %s's %s is not a canonical username (printable ASCII, no "+
			"DOMAIN\\ prefix, no @suffix; %d bytes)", ErrUnmapped, printsafe.Line(e.DN, 200), c.UsernameAttribute, len(u))
	case token.ReservedUsername(u):
		return "", fmt.Errorf("%w: entry %s's %s %q is reserved: the device's own account (spec §2)",
			ErrUnmapped, printsafe.Line(e.DN, 200), c.UsernameAttribute, u)
	}
	return u, nil
}

// asciiName is whether s is bytes 0x21-0x7E only (spec §5.7), checked before
// any case folding: Go folds U+212A to k, a directory's matching rule need
// not (review I-2).
func asciiName(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// heldElsewhere is the DN of an entry under base_dn other than dn whose
// attr equals value, "" for none: one search, size limit 2, and no
// user_filter, so an entry outside it is found too, which only denies more
// (pre-flight M-5). DNs compare as DNs.
func (c Config) heldElsewhere(s Searcher, attr, value, dn string) (string, error) {
	res, err := s.Search(ldap.NewSearchRequest(c.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2,
		int(c.QueryTimeout.Seconds()), false, fmt.Sprintf("(%s=%s)", attr, ldap.EscapeFilter(value)), []string{"1.1"}, nil))
	if err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) {
		return "", err
	}
	mine, _ := ldap.ParseDN(dn)
	sawMine := false
	if res != nil {
		for _, e := range res.Entries {
			if other, perr := ldap.ParseDN(e.DN); perr != nil || mine == nil || !other.EqualFold(mine) {
				return e.DN, nil
			}
			sawMine = true
		}
	}
	if err != nil { // more than two entries, none of the two returned another: still another
		return "(further entries past the size limit)", nil
	}
	if !sawMine { // the server's matching rule disagrees with the value: not proof of uniqueness (review M-2)
		return "", fmt.Errorf("%w: the search for %s=%q did not return %s itself; its matching rule must be case-insensitive",
			ErrAmbiguous, attr, printsafe.Line(value, 200), printsafe.Line(dn, 200))
	}
	return "", nil
}

// usernameUnique is ErrUsernameTaken when another entry under base_dn
// holds id's username (Ruling 3): two people under one username would
// share one (nas, username) context.
func (c Config) usernameUnique(s Searcher, id Identity) error {
	other, err := c.heldElsewhere(s, c.UsernameAttribute, id.Username, id.DN)
	if err != nil || other == "" {
		return err
	}
	return fmt.Errorf("%w: username %q is held by %s and by %s", ErrUsernameTaken, id.Username,
		printsafe.Line(id.DN, 200), printsafe.Line(other, 200))
}

// workloadAttrs is what a workload entry search reads: the workload
// attribute, the username and both immutable ids (decision 41 ruling 2).
func (c Config) workloadAttrs() []string {
	return []string{c.Workload.Attribute, c.UsernameAttribute, "objectGUID", "entryUUID"}
}

// workloadIdentityOf is e as the workload it names (decision 41 rulings 2 and
// 4). With want, e's workload attribute must hold want as its one value, byte
// for byte: a SPIFFE ID's path is case-sensitive and a directory's matching
// rule need not be, so another case is no match. With no want (pre-warm), the
// value is read, and must be a SPIFFE ID in one of the verifier's trust
// domains. The username is usernameOf's.
func (c Config) workloadIdentityOf(e *ldap.Entry, want string) (Identity, error) {
	attr := c.Workload.Attribute
	vs := e.GetAttributeValues(attr)
	if len(vs) != 1 {
		return Identity{}, fmt.Errorf("%w: entry %s has %d values of %s; exactly one", ErrUnmapped,
			printsafe.Line(e.DN, 200), len(vs), attr)
	}
	p := vs[0]
	switch {
	case want != "" && p != want:
		return Identity{}, fmt.Errorf("%w: entry %s's %s is %s, which is not %s byte for byte: a SPIFFE ID's "+
			"path is case-sensitive, and the directory's matching rule found it anyway", ErrUnmapped,
			printsafe.Line(e.DN, 200), attr, printsafe.Line(p, 300), printsafe.Line(want, 300))
	case want == "":
		id, err := spiffe.ParseWorkload(p)
		if err != nil || !slices.Contains(c.Workload.TrustDomains, id.TrustDomain) {
			return Identity{}, fmt.Errorf("%w: entry %s's %s is not a SPIFFE ID in %s", ErrUnmapped,
				printsafe.Line(e.DN, 200), attr, strings.Join(c.Workload.TrustDomains, ", "))
		}
	}
	u, err := c.usernameOf(e)
	if err != nil {
		return Identity{}, err
	}
	return Identity{DN: e.DN, EntryID: entryID(e), Principal: p, Username: u}, nil
}

// workloadUnique is ErrAmbiguous when another entry under base_dn holds id's
// SPIFFE ID in the workload attribute, searched with no user_filter (decision
// 41 ruling 2, as principalUnique is decision 38 ruling 3's).
func (c Config) workloadUnique(s Searcher, id Identity) error {
	other, err := c.heldElsewhere(s, c.Workload.Attribute, id.Principal, id.DN)
	if err != nil || other == "" {
		return err
	}
	return fmt.Errorf("%w: %s %q is held by %s and by %s: two entries under one workload is an impersonation path",
		ErrAmbiguous, c.Workload.Attribute, printsafe.Line(id.Principal, 300), printsafe.Line(id.DN, 200),
		printsafe.Line(other, 200))
}

// principalUnique is ErrAmbiguous when another entry under base_dn holds
// id's principal_attribute value (pre-flight C-2). Without it, a user who
// can write their own mail sets it to a colleague's address and binds as
// the colleague's principal; with it, both are refused while the two
// collide, and neither becomes the other.
func (c Config) principalUnique(s Searcher, id Identity) error {
	value := strings.TrimPrefix(id.Principal, "user:")
	other, err := c.heldElsewhere(s, c.PrincipalAttribute, value, id.DN)
	if err != nil || other == "" {
		return err
	}
	return fmt.Errorf("%w: %s %q is held by %s and by %s: two people under one principal is an impersonation path",
		ErrAmbiguous, c.PrincipalAttribute, printsafe.Line(value, 200), printsafe.Line(id.DN, 200), printsafe.Line(other, 200))
}
