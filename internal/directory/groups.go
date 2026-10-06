package directory

import (
	"fmt"
	"slices"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// inChainOID is LDAP_MATCHING_RULE_IN_CHAIN (design §10).
const inChainOID = "1.2.840.113556.1.4.1941"

// Groups is an entry's membership under the nested mode (Ruling 6). DNs
// and Names are only groups the walk reached and confirmed: a truncated
// walk never grants a group it did not reach, and never invents one.
type Groups struct {
	DNs, Names []string // sorted; Names are those verified unique
	Truncated  bool     // max_depth or the node bound ended the walk with groups unconfirmed
	Loops      int      // groups met again: a loop, or a diamond (two paths to one group); not only cycles
	Ambiguous  []string // names dropped because two groups share them
	Unfound    []string // names dropped because their uniqueness search found no group
}

const (
	// walkBatch is how many DNs one recursive step asks about in one search.
	walkBatch = 50
	// maxWalkNodes bounds the groups one walk collects, whatever max_depth
	// says: a wide tree is as much a bound as a deep one.
	maxWalkNodes = 2000
)

// groupsOf is userDN's groups under groups_base_dn: in_chain in one
// search, recursive by walking member upward, direct by its first step.
// Every DN is compared canonicalized (RFC 4514), never as a raw string.
func (c Config) groupsOf(s Searcher, userDN string) (Groups, error) {
	names := map[string]string{} // canonical DN → name
	dnOf := map[string]string{}  // canonical DN → DN as the directory spells it
	var g Groups
	search := func(filter string, sizeLimit int) (*ldap.SearchResult, error) {
		return s.SearchWithPaging(ldap.NewSearchRequest(c.GroupsBaseDN, ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases, sizeLimit, int(c.QueryTimeout.Seconds()), false, filter,
			[]string{c.GroupNameAttribute}, nil), 500)
	}
	switch c.Nested {
	case "in_chain":
		res, err := search(fmt.Sprintf("(&%s(%s:%s:=%s))", c.GroupFilter, c.MemberAttribute, inChainOID,
			ldap.EscapeFilter(userDN)), maxWalkNodes+1)
		over := ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded)
		if err != nil && !over {
			return Groups{}, err
		}
		if res != nil {
			for _, e := range res.Entries {
				k := canonicalDN(e.DN)
				if _, dup := dnOf[k]; dup {
					continue
				}
				if len(dnOf) >= maxWalkNodes {
					over = true
					break
				}
				dnOf[k], names[k] = e.DN, e.GetAttributeValue(c.GroupNameAttribute)
			}
		}
		g.Truncated = over
	default:
		depth := 1
		if c.Nested == "recursive" {
			depth = c.MaxDepth
		}
		visited := map[string]bool{canonicalDN(userDN): true}
		frontier := []string{userDN}
	walk:
		for level := 0; level < depth && len(frontier) > 0; level++ {
			var next []string
			for start := 0; start < len(frontier); start += walkBatch {
				res, err := search(memberOfAny(c, frontier[start:min(start+walkBatch, len(frontier))]), 0)
				if err != nil {
					return Groups{}, err
				}
				for _, e := range res.Entries {
					k := canonicalDN(e.DN)
					if visited[k] {
						g.Loops++
						continue
					}
					if len(dnOf) >= maxWalkNodes {
						g.Truncated = true
						break walk
					}
					visited[k] = true
					dnOf[k], names[k] = e.DN, e.GetAttributeValue(c.GroupNameAttribute)
					next = append(next, e.DN)
				}
			}
			frontier = next
		}
		// Groups the last level found may have parents the depth never
		// asked about: one more search, whose answer is not kept, says
		// whether the walk stopped short or simply ran out of groups.
		if c.Nested == "recursive" && !g.Truncated && len(frontier) > 0 {
		probe:
			for start := 0; start < len(frontier); start += walkBatch {
				res, err := search(memberOfAny(c, frontier[start:min(start+walkBatch, len(frontier))]), 0)
				if err != nil {
					return Groups{}, err
				}
				for _, e := range res.Entries {
					if !visited[canonicalDN(e.DN)] {
						g.Truncated = true
						break probe
					}
				}
			}
		}
	}
	var uniq []string
	for k, name := range names {
		g.DNs = append(g.DNs, dnOf[k])
		if name != "" {
			uniq = append(uniq, name)
		}
	}
	slices.Sort(g.DNs)
	var err error
	if g.Names, g.Ambiguous, g.Unfound, err = c.uniqueNames(s, uniq); err != nil {
		return Groups{}, err
	}
	return g, nil
}

// memberOfAny is the search for the groups holding any of dns, each value
// escaped.
func memberOfAny(c Config, dns []string) string {
	if len(dns) == 1 {
		return fmt.Sprintf("(&%s(%s=%s))", c.GroupFilter, c.MemberAttribute, ldap.EscapeFilter(dns[0]))
	}
	var b strings.Builder
	for _, d := range dns {
		fmt.Fprintf(&b, "(%s=%s)", c.MemberAttribute, ldap.EscapeFilter(d))
	}
	return fmt.Sprintf("(&%s(|%s))", c.GroupFilter, b.String())
}

// uniqueNames splits names into those exactly one group under
// groups_base_dn has, those two or more share (Ruling 7), and those whose
// search found no group at all (a group renamed between the two searches,
// or a group_name_attribute that does not match as written): the last two
// are dropped and reported, never silently (pre-flight M-9). Compared
// lower-cased; returned as the directory spells them, sorted.
func (c Config) uniqueNames(s Searcher, names []string) (unique, ambiguous, unfound []string, err error) {
	seen := map[string]bool{}
	for _, n := range names {
		k := strings.ToLower(n)
		if seen[k] {
			continue
		}
		seen[k] = true
		res, err := s.Search(ldap.NewSearchRequest(c.GroupsBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2,
			int(c.QueryTimeout.Seconds()), false, fmt.Sprintf("(&%s(%s=%s))", c.GroupFilter, c.GroupNameAttribute,
				ldap.EscapeFilter(n)), []string{"dn"}, nil))
		switch {
		case ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded), err == nil && len(res.Entries) > 1:
			ambiguous = append(ambiguous, n)
		case err != nil:
			return nil, nil, nil, err
		case len(res.Entries) == 1:
			unique = append(unique, n)
		default:
			unfound = append(unfound, n)
		}
	}
	slices.Sort(unique)
	slices.Sort(ambiguous)
	slices.Sort(unfound)
	return unique, ambiguous, unfound, nil
}

// membersOf is every user DN under groupDN, transitively under the nested
// mode, at most limit: what pre-warm enumerates (Ruling 20). capped means
// the limit was reached and no more is listed. cut means the walk ended at
// max_depth or the node bound with groups unexpanded, so the list may be
// short: a different thing, counted apart, which must not stop pre-warm of
// the next group. in_chain asks for limit+1 and stops there, so a huge
// group is never paged in whole (pre-flight M-8).
func (c Config) membersOf(s Searcher, groupDN string, limit int) (dns []string, capped, cut bool, err error) {
	if c.Nested == "in_chain" {
		res, err := s.SearchWithPaging(ldap.NewSearchRequest(c.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
			limit+1, int(c.QueryTimeout.Seconds()), false, fmt.Sprintf("(&%s(memberOf:%s:=%s))", c.UserFilter, inChainOID,
				ldap.EscapeFilter(groupDN)), []string{"dn"}, nil), 500)
		truncated := ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded)
		if err != nil && !truncated {
			return nil, false, false, err
		}
		var out []string
		if res != nil {
			for _, e := range res.Entries {
				out = append(out, e.DN)
			}
		}
		if len(out) > limit {
			out, truncated = out[:limit], true
		}
		return out, truncated, false, nil
	}
	depth := 1
	if c.Nested == "recursive" {
		depth = c.MaxDepth
	}
	// A member outside groups_base_dn is never a group the walk follows
	// (groupsOf searches only under it), so it is a user without a search;
	// inside, isGroup's answer is kept for the call (pre-flight M-8).
	groupsBase, _ := ldap.ParseDN(c.GroupsBaseDN)
	kind := map[string]bool{}
	classify := func(dn string) (bool, error) {
		if d, err := ldap.ParseDN(dn); err == nil && groupsBase != nil && !groupsBase.AncestorOfFold(d) {
			return false, nil
		}
		k := canonicalDN(dn)
		if g, ok := kind[k]; ok {
			return g, nil
		}
		g, err := c.isGroup(s, dn)
		if err == nil {
			kind[k] = g
		}
		return g, err
	}
	visited := map[string]bool{canonicalDN(groupDN): true}
	frontier, users, groups := []string{groupDN}, []string{}, 0
	for level := 0; level < depth && len(frontier) > 0; level++ {
		var next []string
		for _, g := range frontier {
			res, err := s.Search(ldap.NewSearchRequest(g, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1,
				int(c.QueryTimeout.Seconds()), false, "(objectClass=*)", []string{c.MemberAttribute}, nil))
			if err != nil {
				return nil, false, false, err
			}
			for _, e := range res.Entries {
				for _, m := range e.GetAttributeValues(c.MemberAttribute) {
					k := canonicalDN(m)
					if visited[k] {
						continue
					}
					visited[k] = true
					isGroup, err := classify(m)
					if err != nil {
						return nil, false, false, err
					}
					if isGroup {
						if groups++; groups > maxWalkNodes {
							return users, false, true, nil
						}
						next = append(next, m)
					} else if len(users) < limit {
						users = append(users, m)
					} else {
						return users, true, false, nil
					}
				}
			}
		}
		frontier = next
	}
	return users, false, len(frontier) > 0 && c.Nested == "recursive", nil
}

func (c Config) isGroup(s Searcher, dn string) (bool, error) {
	res, err := s.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1,
		int(c.QueryTimeout.Seconds()), false, c.GroupFilter, []string{"dn"}, nil))
	if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
		return false, nil
	}
	return err == nil && len(res.Entries) == 1, err
}
