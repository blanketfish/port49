package directory

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/rhwendt/port49/internal/printsafe"
)

// PrewarmReport is one pre-warm pass.
type PrewarmReport struct {
	Groups, Principals, Failed int
	Capped                     bool
}

// Prewarm verifies every member of groups, transitively under the nested
// mode, at most prewarm.max_principals, and writes each membership with
// its mapping keys, so an operator who never logged in can log in within
// grace in an outage (design §10; Ruling 20). groups are the policy's
// `group:` values: a DN, or a name resolved to its one group under
// groups_base_dn (a shared name is skipped and said, as it matches no one).
func (r *Resolver) Prewarm(ctx context.Context, groups []string) (PrewarmReport, error) {
	var rep PrewarmReport
	var dns []string
	_, err := r.Pool.Do(ctx, func(s Searcher) error {
		for _, g := range groups {
			if isDN(g) {
				dns = append(dns, g)
				continue
			}
			res, err := s.Search(ldap.NewSearchRequest(r.Cfg.GroupsBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
				2, int(r.Cfg.QueryTimeout.Seconds()), false, fmt.Sprintf("(&%s(%s=%s))", r.Cfg.GroupFilter,
					r.Cfg.GroupNameAttribute, ldap.EscapeFilter(g)), []string{"dn"}, nil))
			if err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) {
				return err
			}
			if res == nil || len(res.Entries) != 1 {
				continue // none, or shared: it matches no one (Ruling 7)
			}
			dns = append(dns, res.Entries[0].DN)
		}
		return nil
	})
	if err != nil {
		return rep, err
	}
	rep.Groups = len(dns)
	seen := map[string]bool{}
	var users []string
	for _, g := range dns {
		var members []string
		var capped, cut bool
		if _, err := r.Pool.Do(ctx, func(s Searcher) error {
			var err error
			members, capped, cut, err = r.Cfg.membersOf(s, g, r.Cfg.PrewarmMax-len(users))
			return err
		}); err != nil {
			return rep, err
		}
		for _, m := range members {
			if k := canonicalDN(m); !seen[k] {
				seen[k] = true
				users = append(users, m)
			}
		}
		if cut {
			// A walk that ended at max_depth or the node bound lists short;
			// that is no reason to skip the next group.
			r.M.DirectoryWalksTruncated.Inc()
			r.sayOnce("prewarmcut:"+canonicalDN(g), time.Hour, "directory: pre-warm's walk of %s ended at max_depth (%d) "+
				"or the node bound; members past it are not pre-warmed", printsafe.Line(g, 200), r.Cfg.MaxDepth)
		}
		if capped {
			rep.Capped = true
			r.sayOnce("prewarmcap", time.Hour, "directory: pre-warm reached prewarm.max_principals (%d); the rest "+
				"are not pre-warmed", r.Cfg.PrewarmMax)
			break
		}
	}
	for _, dn := range users {
		if ctx.Err() != nil {
			return rep, ctx.Err()
		}
		if _, err := r.verify(ctx, lookup{find: r.byDN(dn), say: dn}); err != nil {
			if errors.Is(err, ErrUnavailable) {
				return rep, err
			}
			rep.Failed++
			continue
		}
		rep.Principals++
	}
	r.M.DirectoryPrewarmPrincipals.Set(float64(rep.Principals))
	r.M.DirectoryPrewarmLastSuccess.Set(float64(r.Now().Unix()))
	return rep, nil
}

// isDN is Ruling 7's test, shared with the policy's group match: a value
// holding "=" that ldap.ParseDN accepts is a DN; anything else is a name
// (pre-flight M-9).
func isDN(g string) bool {
	if !strings.Contains(g, "=") {
		return false
	}
	_, err := ldap.ParseDN(g)
	return err == nil
}
