package broker

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/directory"
	"github.com/rhwendt/port49/internal/policy"
	"github.com/rhwendt/port49/internal/store"
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
	a, err := b.Directory.Map(ctx, cs.VerifiedChains[0][0])
	if err != nil {
		return directory.Answer{}, directoryRefusal(err)
	}
	if a.Principal == "" || !directory.IsUser(a.Principal) {
		return directory.Answer{}, directoryRefusal(directory.ErrUnmapped)
	}
	return a, nil
}

// member is the policy's view of a directory answer.
func member(a directory.Answer) policy.Member {
	return policy.Member{Principal: a.Principal, Directory: true, Username: a.Username, GroupDNs: a.GroupDNs,
		GroupNames: a.GroupNames}
}

// memberFor is the membership one request resolves with. A request on a
// held connection reads the pinned principal's membership again (fresh, or
// grace): group membership is resolved at mint time (design §7), not at
// bind. Without a directory, or for a machine principal, it is
// MemberOf(principal) and the answer is nil (pre-flight I-10).
func (b *Broker) memberFor(ctx context.Context, principal string) (policy.Member, *directory.Answer, error) {
	if b.Directory == nil || !directory.IsUser(principal) {
		return policy.MemberOf(principal), nil, nil
	}
	a, err := b.Directory.Current(ctx, principal)
	if err != nil {
		return policy.Member{}, nil, err
	}
	return member(a), &a, nil
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
