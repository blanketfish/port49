package store

import (
	"errors"
	"time"
)

// The narrow setters' rules, one definition for every backend and for
// the sealing layer, which applies them to a record it has opened (plan
// 7d; Ruling 17). Each changes c and nothing else; the store's own
// bookkeeping (the revisions, the expiry) is the caller's.

// ApplyPrivilege is SetPrivilege's rule: raise-only, then clamped to the
// ceiling (spec §5.3). moved reports a level that changed, which is a
// write to what the refresh decides (Context.PolicyRev).
func ApplyPrivilege(c *Context, level uint8) (moved bool) {
	held := c.PrivLvl
	if level > c.PrivLvl {
		c.PrivLvl = level
	}
	if ceiling, ok := c.PrivilegeCeiling(); ok && c.PrivLvl > ceiling {
		c.PrivLvl = ceiling
	}
	return c.PrivLvl != held
}

// ApplyRefresh is RefreshContext's rule, ExpectRev aside (the caller
// compares it with the revision it read): ErrPastGrace, writing nothing,
// for a ceiling before r.GraceCutoff; else the window, AuthTime,
// RefreshedAt, BlobHash and a rotated sid. moved reports a blob hash that
// changed.
// RevokedAt is not on the list: a refresh is a directory re-resolution,
// not a credential re-verification, and the only thing that ends a
// revocation is spec §5.6 row 6 reclaiming the record (store.Store).
// "Has a ceiling" is read as the authorizer reads it, a non-zero
// SessionExpires, so a context it denies session_expired is one no
// refresh resumes. A SessionAge replaces the window outright: a refresh
// is a fresh authentication event, so it may lengthen the ceiling
// (decision 33).
func ApplyRefresh(c *Context, r ContextRefresh) (moved bool, err error) {
	if !r.GraceCutoff.IsZero() && !c.SessionExpires.IsZero() && c.SessionExpires.Before(r.GraceCutoff) {
		return false, ErrPastGrace
	}
	switch {
	case r.SessionAge != nil && *r.SessionAge == 0:
		c.SessionExpires = time.Time{}
	case r.SessionAge != nil:
		c.SessionExpires = r.AuthTime.Add(*r.SessionAge)
	case c.HasCeiling():
		c.SessionExpires = r.AuthTime.Add(c.SessionExpires.Sub(c.AuthTime))
	}
	c.AuthTime, c.RefreshedAt = r.AuthTime, r.RefreshedAt
	moved = r.BlobHash != "" && r.BlobHash != c.BlobHash
	if r.BlobHash != "" {
		c.BlobHash = r.BlobHash
	}
	if r.Sid != "" {
		c.Credential.Sid = r.Sid
	}
	if r.MFAMethod != "" {
		c.Credential.MFAMethod, c.Credential.MFAAt, c.Credential.MFAAgentSHA256 = r.MFAMethod, r.MFAAt, r.MFAAgentSHA256
		// The login's fresh flag does not describe this proof; false is the
		// side that fails closed (Credential.MFAFresh).
		c.Credential.MFAFresh = false
	}
	return moved, nil
}

// ApplyRevokedAt is SetRevokedAt's rule: the later mark stands, or a
// token minted between the two would lift the revocation at a join.
func ApplyRevokedAt(c *Context, at time.Time) {
	if at.After(c.RevokedAt) {
		c.RevokedAt = at
	}
}

// CheckContextPolicy refuses a policy write that neither revokes nor
// names a blob: a live context pointing at no blob is a corrupt record.
func CheckContextPolicy(p ContextPolicy) error {
	if p.RevokedAt.IsZero() && p.BlobHash == "" {
		return errors.New("store: a policy write that does not revoke must name a blob hash")
	}
	return nil
}

// ApplyContextPolicy is SetContextPolicy's rule, the policy revision's
// compare aside (the caller's): a revocation keeps the later mark; any
// other write replaces the blob, ceiling and enable, lowers a held level
// above the new ceiling, and only ever moves the session ceiling earlier
// (decision 33). A context with a zero AuthTime has no instant to anchor a
// ceiling to, and is given one in the distant past, as a login gives a
// token with none (authen's loginContext): it denies, loudly, where
// dropping the ceiling would leave an unbounded session that looks exactly
// like a legitimate `never`.
func ApplyContextPolicy(c *Context, p ContextPolicy) {
	if !p.RevokedAt.IsZero() {
		ApplyRevokedAt(c, p.RevokedAt)
		return
	}
	c.BlobHash, c.MaxPrivilege, c.Enable = p.BlobHash, p.MaxPrivilege, p.Enable
	if ceiling, ok := c.PrivilegeCeiling(); ok && c.PrivLvl > ceiling {
		c.PrivLvl = ceiling
	}
	if p.MaxSessionAge > 0 {
		if ceiling := c.AuthTime.Add(p.MaxSessionAge); c.SessionExpires.IsZero() || ceiling.Before(c.SessionExpires) {
			c.SessionExpires = ceiling
		}
	}
	ApplyStamp(c, p.RefreshedAt)
}

// ApplyStamp raises RefreshedAt to at, never lowering it (plan 7g).
func ApplyStamp(c *Context, at time.Time) {
	if at.After(c.RefreshedAt) {
		c.RefreshedAt = at
	}
}
