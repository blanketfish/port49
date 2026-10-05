package directory

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"

	"github.com/rhwendt/port49/internal/printsafe"
	"github.com/rhwendt/port49/internal/token"
)

// Identity is one directory entry as a principal (Ruling 3). EntryID is
// the entry's immutable id, the pin a principal keeps.
type Identity struct{ DN, EntryID, Principal, Username string }

// entryAttrs is what an entry search reads: the principal and username
// attributes, the mapping's, for KeysOf, and both immutable ids, of which
// a directory holds one.
func (c Config) entryAttrs() []string {
	return []string{c.PrincipalAttribute, c.UsernameAttribute, c.Mapping.Attribute, "objectGUID", "entryUUID"}
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
	u, err := one(c.UsernameAttribute)
	if err != nil {
		return Identity{}, err
	}
	if !asciiName(u) {
		return Identity{}, fmt.Errorf("%w: entry %s's %s is not printable ASCII (%d bytes)", ErrUnmapped,
			printsafe.Line(e.DN, 200), c.UsernameAttribute, len(u))
	}
	u = strings.ToLower(u)
	switch {
	case !token.CanonicalUsername(u):
		return Identity{}, fmt.Errorf("%w: entry %s's %s is not a canonical username (printable ASCII, no "+
			"DOMAIN\\ prefix, no @suffix; %d bytes)", ErrUnmapped, printsafe.Line(e.DN, 200), c.UsernameAttribute, len(u))
	case token.ReservedUsername(u):
		return Identity{}, fmt.Errorf("%w: entry %s's %s %q is reserved: the device's own account (spec §2)",
			ErrUnmapped, printsafe.Line(e.DN, 200), c.UsernameAttribute, u)
	}
	return Identity{DN: e.DN, EntryID: entryID(e), Principal: "user:" + p, Username: u}, nil
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
