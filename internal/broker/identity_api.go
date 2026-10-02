package broker

import (
	"net/http"
	"slices"
	"time"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/decision"
)

// identity is GET /v1/identity (design §17): what the policy in force
// resolves the caller to. It answers the caller alone: the principal is the
// connection's, the request names no one, and no right shows another's
// (spec §2; decision 34). It writes one identity record (spec §5.7).
func (b *Broker) identity(w http.ResponseWriter, r *http.Request) {
	principal, cred, ok := b.authenticate(w, r, decision.EventIdentity, "answered nothing")
	if !ok {
		return
	}
	now, at := b.Now(), b.authTime(r)
	out := api.Identity{Principal: principal, Method: cred.Method, Fingerprint: cred.Fingerprint,
		Groups: []string{}, Grants: []api.IdentityGrant{}, API: []string{}, AuthTime: at.UTC().Format(time.RFC3339)}
	if b.MaxSessionAge > 0 {
		out.ConnectionEndsAt = at.Add(b.MaxSessionAge).UTC().Format(time.RFC3339)
	}
	rec := decision.Record{TS: now, Event: decision.EventIdentity, Verdict: decision.VerdictDeny,
		Reason: decision.NoGrantsMatched, Principal: principal,
		Auth: &decision.Auth{Method: cred.Method, Fingerprint: cred.Fingerprint}}
	pol := b.Policy.Load()
	if name, ok := pol.SubjectOf(principal); ok {
		out.Subject = name
		if sub, ok := pol.Subject(name); ok {
			out.API = append(out.API, sub.API...)
			slices.Sort(out.API)
		}
		for _, g := range pol.Grants(name) {
			if !g.Expires.IsZero() && !now.Before(g.Expires) {
				continue // expired: it selects nothing now
			}
			ig := api.IdentityGrant{Scope: g.Scope, Roles: slices.Clone(g.Roles), MaxPrivilege: g.MaxPrivilege}
			if !g.Expires.IsZero() {
				ig.Expires = g.Expires.UTC().Format(time.RFC3339)
			}
			out.Grants = append(out.Grants, ig)
		}
		rec.Policy = &decision.Policy{Bundle: pol.Bundle, Subject: name}
		if len(out.Grants) > 0 {
			rec.Verdict, rec.Reason = decision.VerdictPermit, decision.GrantsMatched
		}
	}
	b.emit(rec)
	writeJSON(w, http.StatusOK, out)
}
