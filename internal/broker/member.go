package broker

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/blanketfish/port49/internal/decision"
	"github.com/blanketfish/port49/internal/directory"
	"github.com/blanketfish/port49/internal/policy"
	"github.com/blanketfish/port49/internal/printsafe"
	"github.com/blanketfish/port49/internal/store"
)

// directoryRefusal is a resolver error as the API answers it (Ruling 4).
// A refusal's detail never carries the resolver's error text, which can
// quote a directory entry or a server.
func directoryRefusal(err error) *BindRefusal {
	switch {
	case errors.Is(err, directory.ErrUnavailable):
		return &BindRefusal{Status: http.StatusServiceUnavailable, Reason: decision.DirectoryUnavailable,
			Error: string(decision.DirectoryUnavailable), RetryAfter: 30,
			Detail: "no directory server answered and no membership verified within the grace window is held; " +
				"the agent retries"}
	case errors.Is(err, directory.ErrAmbiguous):
		return &BindRefusal{Status: http.StatusUnauthorized, Reason: decision.IdentityAmbiguous,
			Error: string(decision.IdentityAmbiguous), Detail: "this certificate maps to more than one directory entry; tell the operator"}
	case errors.Is(err, directory.ErrUsernameTaken):
		return &BindRefusal{Status: http.StatusUnauthorized, Reason: decision.UsernameCollision,
			Error: string(decision.UsernameCollision), Detail: "your directory username is held by another; tell the operator"}
	case errors.Is(err, directory.ErrUnmapped):
		return &BindRefusal{Status: http.StatusUnauthorized, Reason: decision.IdentityUnmapped,
			Error: string(decision.IdentityUnmapped), Detail: "this certificate maps to no usable directory entry; tell the operator"}
	case errors.Is(err, store.ErrUnavailable), errors.Is(err, context.DeadlineExceeded):
		return &BindRefusal{Status: http.StatusServiceUnavailable, Reason: decision.StoreUnavailable,
			Error: string(decision.StoreUnavailable), RetryAfter: 30, Detail: "the broker's store did not answer; the agent retries"}
	}
	return &BindRefusal{Status: http.StatusServiceUnavailable, Reason: decision.DirectoryUnavailable,
		Error: string(decision.DirectoryUnavailable), RetryAfter: 30, Detail: "the directory lookup failed; the agent retries"}
}

// BindMap is Listener.Map (Ruling 4): the connection's certificate mapped
// once, by the resolver, bounded by the caller's context. The line for a
// refusal is the resolver's; the record is RefusedAtBind's.
func (b *Broker) BindMap(ctx context.Context, cs tls.ConnectionState, _ store.Credential) (directory.Answer, *BindRefusal) {
	if len(cs.VerifiedChains) == 0 || len(cs.VerifiedChains[0]) == 0 {
		return directory.Answer{}, directoryRefusal(directory.ErrUnmapped)
	}
	machine, chainErr := b.machineChain(&cs)
	switch {
	case chainErr != nil:
		// A chain no verifier may take (both anchors) is no one's, so the
		// directory is not asked either (spec §5.7).
		return directory.Answer{}, &BindRefusal{Status: http.StatusUnauthorized, Reason: decision.TrustDomainUnresolved,
			Error: string(decision.TrustDomainUnresolved), Detail: printsafe.Line(chainErr.Error(), 300)}
	case machine:
		// Defence in depth behind Listener.Caller (pre-flight I-4): a workload
		// is never mapped through the directory (decision 40 ruling 5).
		return directory.Answer{}, &BindRefusal{Status: http.StatusUnauthorized, Reason: decision.IdentityUnmapped,
			Error: string(decision.IdentityUnmapped), Detail: "a workload certificate is never mapped through the " +
				"directory; the broker's listener is wired without Caller, so tell the operator"}
	}
	a, err := b.Directory.Map(ctx, cs.VerifiedChains[0][0])
	if err != nil {
		return directory.Answer{}, directoryRefusal(err)
	}
	if a.Principal == "" || !directory.IsUser(a.Principal) {
		return directory.Answer{}, directoryRefusal(directory.ErrUnmapped)
	}
	return a, nil
}

// member is the policy's view of a person's directory answer.
func member(a directory.Answer) policy.Member {
	return policy.Member{Principal: a.Principal, Domain: policy.DomainHumans, Directory: true, Username: a.Username,
		GroupDNs: a.GroupDNs, GroupNames: a.GroupNames}
}

// workloadMapped reports whether principal is a workload this broker resolves
// through the directory (decision 41 ruling 1): a SPIFFE ID, with the x509
// machine verifier's directory: configured.
func (b *Broker) workloadMapped(principal string) bool {
	return b.Directory != nil && b.Directory.Cfg.Workload != nil && directory.IsWorkload(principal)
}

// workloadMember is a workload's directory answer as pol judges it (decision
// 41 ruling 4). Its username is the one its identity subject declares, when
// that subject declares one; else its entry's, refused
// directory.ErrUsernameTaken when a subject declares that, the declared one
// standing (decision 38 ruling 3).
func workloadMember(pol *policy.Policy, a directory.Answer) (policy.Member, error) {
	m := policy.Member{Principal: a.Principal, Domain: policy.DomainMachines, Directory: true, Username: a.Username,
		GroupDNs: a.GroupDNs, GroupNames: a.GroupNames}
	if u := pol.DeclaredFor(a.Principal); u != "" {
		m.Username = u
		return m, nil
	}
	if who, ok := pol.DeclaredUsernames()[a.Username]; ok && a.Username != "" {
		return policy.Member{Principal: a.Principal, Domain: policy.DomainMachines, Directory: true},
			fmt.Errorf("%w: the directory derives username %q for %s, which subject %q declares",
				directory.ErrUsernameTaken, a.Username, printsafe.Line(a.Principal, 300), who)
	}
	return m, nil
}

// heldCollision judges m's username again under pol, the policy a mint or a
// session refresh holds: a reload can land between the membership read and
// the hold, and declare the username the directory gave (final review M-1).
// A workload under the mapping is settled again by workloadMember, so its own
// subject's declaration is no collision and another's is (decision 41 ruling
// 4); the member it returns is the one to judge. Anyone else is refused
// directory.ErrUsernameTaken when a subject now declares its username.
func heldCollision(pol *policy.Policy, m policy.Member, answer *directory.Answer) (policy.Member, error) {
	if m.Domain == policy.DomainMachines && answer != nil {
		return workloadMember(pol, *answer)
	}
	if m.Directory && pol.DeclaredUsernames()[m.Username] != "" {
		return m, directory.ErrUsernameTaken
	}
	return m, nil
}

// memberFor is the membership one request resolves with. A request on a
// held connection reads the pinned principal's membership again (fresh, or
// grace): group membership is resolved at mint time (design §7), not at
// bind. Without a directory, or for a machine principal the workload
// mapping does not cover, it is MemberOf(principal) and the answer is nil
// (pre-flight I-10; decision 41 ruling 1).
func (b *Broker) memberFor(ctx context.Context, principal string) (policy.Member, *directory.Answer, error) {
	switch {
	case b.Directory != nil && directory.IsUser(principal):
		a, err := b.Directory.Current(ctx, principal)
		if err != nil {
			return policy.Member{}, nil, err
		}
		return member(a), &a, nil
	case b.workloadMapped(principal):
		// A workload is never mapped at bind: its principal is its SPIFFE
		// ID, and its membership is read here, as a person's is (decision
		// 41 ruling 6).
		a, err := b.Directory.CurrentWorkload(ctx, principal)
		if err != nil {
			return policy.Member{}, nil, err
		}
		m, err := workloadMember(b.Policy.Load(), a)
		if err != nil {
			return policy.Member{}, nil, err
		}
		return m, &a, nil
	}
	return policy.MemberOf(principal), nil, nil
}

// memberBudget is memberFor's deadline: the directory's own query_timeout
// plus a store read's holdTimeout, so a DC slower than holdTimeout still
// reaches grace and is never answered store_unavailable (pre-flight I-8).
func (b *Broker) memberBudget() time.Duration {
	if b.Directory == nil {
		return holdTimeout
	}
	return b.Directory.Cfg.QueryTimeout + holdTimeout
}

// directoryAuth is auth.directory for a record (spec §5.7).
func directoryAuth(a *directory.Answer) *decision.Directory {
	if a == nil {
		return nil
	}
	return &decision.Directory{Source: string(a.Source), VerifiedAt: decision.FormatTime(a.VerifiedAt),
		Server: a.Server, Site: a.Site}
}

// storedMemberOf is principal's membership as the store holds it, for a
// revocation's answer: it never asks a server, since a revocation must not
// wait on the directory. With none stored, or none readable, it is
// identity subjects alone.
func (b *Broker) storedMemberOf(ctx context.Context, principal string) policy.Member {
	if b.workloadMapped(principal) {
		if m, err := b.storedWorkload(ctx, principal); err == nil {
			return m
		}
		return policy.MemberOf(principal)
	}
	if b.Directory == nil || !directory.IsUser(principal) {
		return policy.MemberOf(principal)
	}
	m, ok, err := b.Directory.Stored(ctx, principal)
	if err != nil || !ok || m.Refused {
		return policy.MemberOf(principal)
	}
	return member(directory.Answer{Membership: m})
}

// verifiedAt is the instant a membership was verified: the stored one under
// grace, never the clock; zero without a directory.
func verifiedAt(a *directory.Answer) time.Time {
	if a == nil {
		return time.Time{}
	}
	return a.VerifiedAt
}

// subjectNames splits a member's matched subjects into the one name a
// record and a response carry alone, or the several.
func subjectNames(pol *policy.Policy, m policy.Member) (one string, several []string) {
	names := pol.SubjectsOf(m)
	if len(names) == 1 {
		return names[0], nil
	}
	return "", names
}

// mappedOf is the answer the listener pinned to c at bind, nil without one.
func mappedOf(c net.Conn) *directory.Answer {
	if tc, ok := c.(*tls.Conn); ok {
		if t, ok := tc.NetConn().(*trackedConn); ok && t.mapped != nil {
			a := *t.mapped
			return &a
		}
	}
	return nil
}

// legacyPrincipal is the principal the certificate had before a directory:
// "user:" and its one email SAN, or "" (pre-flight I-16). A mark made by
// that principal still refuses the certificate once a directory maps it to
// another.
func legacyPrincipal(leaf *x509.Certificate) string {
	p, err := principalOf(leaf)
	if err != nil {
		return ""
	}
	return p
}
