package directory

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/blanketfish/port49/internal/printsafe"
	"github.com/blanketfish/port49/internal/spiffe"
)

// PrewarmReport is one pre-warm pass.
type PrewarmReport struct {
	Groups, Principals, Failed int
	Capped                     bool
}

// prewarm is one pre-warm pass over groups under c (r.Cfg, or r.Cfg with the
// workload user_filter for machine groups, so in_chain enumerates workloads
// under it), verifying each member through at(dn). It sets no metric.
//
// It verifies every member of groups, transitively under the nested mode, at
// most prewarm.max_principals, and writes each membership with its mapping
// keys, so an operator who never logged in can log in within grace in an
// outage (design §10; Ruling 20). groups are the policy's `group:` values: a
// DN, or a name resolved to its one group under groups_base_dn (a shared name
// is skipped and said, as it matches no one).
//
// capKey and capFor tell the pass's cap line apart from another pass's: the
// sayOnce key suffix and the words that say whose cap it is (both empty for
// the people's).
func (r *Resolver) prewarm(ctx context.Context, c Config, groups []string, at func(dn string) lookup,
	capKey, capFor string) (PrewarmReport, error) {
	var rep PrewarmReport
	var dns []string
	_, err := r.Pool.Do(ctx, func(s Searcher) error {
		for _, g := range groups {
			if isDN(g) {
				dns = append(dns, g)
				continue
			}
			res, err := s.Search(ldap.NewSearchRequest(c.GroupsBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
				2, int(c.QueryTimeout.Seconds()), false, fmt.Sprintf("(&%s(%s=%s))", c.GroupFilter,
					c.GroupNameAttribute, ldap.EscapeFilter(g)), []string{"dn"}, nil))
			if err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) {
				return err
			}
			if err != nil || (res != nil && len(res.Entries) > 1) {
				r.noteAmbiguous(g) // the size-limit error, or two entries: shared
			}
			if res == nil || len(res.Entries) != 1 {
				// none, or shared: it matches no one (Ruling 7)
				r.sayOnce("prewarmname:"+g, time.Hour, "directory: pre-warm: group name %q matched no group, or two or "+
					"more, under %s; it is skipped (use its DN)", printsafe.Line(g, 200), c.GroupsBaseDN)
				continue
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
			members, capped, cut, err = c.membersOf(s, g, c.PrewarmMax)
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
		if len(users) > c.PrewarmMax { // distinct users only: each walk is bounded by the limit alone
			users, capped = users[:c.PrewarmMax], true
		}
		if cut {
			// A walk that ended at max_depth or the node bound lists short;
			// that is no reason to skip the next group.
			r.M.DirectoryWalksTruncated.Inc()
			r.sayOnce("prewarmcut:"+canonicalDN(g), time.Hour, "directory: pre-warm's walk of %s ended at max_depth (%d) "+
				"or the node bound; members past it are not pre-warmed", printsafe.Line(g, 200), c.MaxDepth)
		}
		if capped {
			rep.Capped = true
			r.sayOnce("prewarmcap"+capKey, time.Hour, "directory: pre-warm reached prewarm.max_principals (%d)%s; "+
				"the rest are not pre-warmed", c.PrewarmMax, capFor)
			break
		}
	}
	for _, dn := range users {
		if ctx.Err() != nil {
			return rep, ctx.Err()
		}
		if _, err := r.verify(ctx, at(dn)); err != nil {
			if errors.Is(err, ErrUnavailable) {
				return rep, err
			}
			rep.Failed++
			continue
		}
		rep.Principals++
	}
	return rep, nil
}

// Prewarm is PrewarmAll for people alone.
func (r *Resolver) Prewarm(ctx context.Context, groups []string) (PrewarmReport, error) {
	return r.PrewarmAll(ctx, groups, nil, nil)
}

// PrewarmAll verifies every member of groups as a person, and, under a
// workload mapping, every member of machineGroups and then every SPIFFE ID in
// workloads as a workload (decision 41 ruling 6), and writes each membership,
// so a principal that never asked can be served in an outage within grace
// (design §10; Ruling 20). People take at most prewarm.max_principals, and
// workloads, the two kinds together, as many again. machineGroups are the
// policy's machine_group: values and workloads its listed spiffe:// identities
// (pre-flight I-3: a workload granted by its own identity subject alone is in
// no group); without a mapping neither is read. A workload in both is
// verified twice, which costs one search pair and no grant.
func (r *Resolver) PrewarmAll(ctx context.Context, groups, machineGroups, workloads []string) (PrewarmReport, error) {
	rep, err := r.prewarm(ctx, r.Cfg, groups, func(dn string) lookup { return lookup{find: r.byDN(dn), say: dn} }, "", "")
	if err != nil {
		return rep, err
	}
	if w := r.Cfg.Workload; w != nil {
		var wrep PrewarmReport
		if len(machineGroups) > 0 {
			wc := r.Cfg
			wc.UserFilter = w.UserFilter
			wrep, err = r.prewarm(ctx, wc, machineGroups, func(dn string) lookup {
				return lookup{find: r.byWorkloadDN(dn), say: dn, workload: true}
			}, ":machine_groups", " for the workloads in machine groups")
		}
		if err == nil {
			err = r.prewarmWorkloads(ctx, slices.Sorted(slices.Values(workloads)), &wrep)
		}
		rep.Groups, rep.Principals, rep.Failed = rep.Groups+wrep.Groups, rep.Principals+wrep.Principals, rep.Failed+wrep.Failed
		rep.Capped = rep.Capped || wrep.Capped
		if err != nil {
			return rep, err
		}
	}
	r.M.DirectoryPrewarmPrincipals.Set(float64(rep.Principals))
	r.M.DirectoryPrewarmLastSuccess.Set(float64(r.Now().Unix()))
	return rep, nil
}

// prewarmWorkloads verifies each SPIFFE ID in ids, in the verifier's trust
// domains, as VerifyWorkload does, within what the machine groups left of
// prewarm.max_principals, adding to rep. An ID outside the trust domains is
// skipped unsearched: no workload certificate gives it (decision 40 ruling
// 16's start line names it). An outage stops the pass, as for people.
func (r *Resolver) prewarmWorkloads(ctx context.Context, ids []string, rep *PrewarmReport) error {
	left := r.Cfg.PrewarmMax - rep.Principals - rep.Failed
	for _, p := range ids {
		if id, err := spiffe.ParseWorkload(p); err != nil || !slices.Contains(r.Cfg.Workload.TrustDomains, id.TrustDomain) {
			continue
		}
		if left <= 0 {
			rep.Capped = true
			r.sayOnce("prewarmcap:workloads", time.Hour, "directory: pre-warm reached prewarm.max_principals (%d) "+
				"for workloads; the rest are not pre-warmed", r.Cfg.PrewarmMax)
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		left--
		if _, err := r.VerifyWorkload(ctx, p); err != nil {
			if errors.Is(err, ErrUnavailable) {
				return err
			}
			rep.Failed++
			continue
		}
		rep.Principals++
	}
	return nil
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
