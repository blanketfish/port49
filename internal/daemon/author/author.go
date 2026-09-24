// Package author runs session and command authorization (spec §5.2, §5.3)
// against login context, delegating the policy question to an Authorizer.
package author

import (
	"context"
	"crypto/subtle"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/rhwendt/port49/internal/daemon/authen"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/engine"
	"github.com/rhwendt/port49/internal/platform"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/tacacs/wire"
)

// Decision is what an Authorizer returns. Engine is the one the daemon runs;
// Lab is the lab's instrument for seeded contexts.
type Decision struct {
	Permit     bool
	Reason     decision.Reason
	ServerMsg  string
	Attributes []string // session only, e.g. "priv-lvl=15"
	// Policy is the record's policy block when the decision consulted a blob
	// (spec §5.7): bundle and blob always, and the rules that matched.
	Policy *decision.Policy
	// Vector is the command vector the authorizer decided, when it normalized
	// the request itself; Handle records it in place of its own parse, so the
	// record and the decision never disagree (spec §3, §5.7).
	Vector []string
	// Error answers a refusal ERROR rather than FAIL. It is lab-only: the
	// lab's fault switch (LabFault) is the only thing that may set it, and it
	// is ignored on a permit. A production Authorizer MUST leave it false —
	// a store outage is FAIL `store_unavailable` (plan 4's ruling), because an
	// ERROR here authorizes every command on an IOS-XE `if-authenticated`
	// list and hands the N9Kv to local RBAC (tests/lab/results/L4-error-*.md).
	// Plan 4 keeps it lab-only: Engine never sets it.
	Error bool
}

// Request is one authorization after the §5.3 checks have passed: the context
// they read, the device the request came from, and the request's AV pairs as
// received. Vector is nil for a session authorization.
type Request struct {
	Context store.Context
	Device  authen.Peer
	Raw     []string
	Vector  []string
}

type Authorizer interface {
	Session(ctx context.Context, r Request) Decision
	Command(ctx context.Context, r Request) Decision
}

type Handler struct {
	store   store.Store
	authz   Authorizer
	log     decision.Emitter
	metrics *metrics.Metrics
	now     func() time.Time

	// services is the resolved authorization-`service` table, platform name to
	// the values that platform's sessions may arrive with (spec §5.2, §8).
	// config.Load builds it from the built-in table plus any operator
	// override; a nil map is legal and means every platform takes the
	// fallback, which is `shell`.
	services map[string][]string

	// stalenessCeiling is how long a context may go without a policy refresh
	// before authorization denies on it (spec §5.1.4, §5.3). It is measured
	// from RefreshedAt; a context with no RefreshedAt is not subject to it.
	// Zero or negative disables the check, which is what a daemon with nothing
	// refreshing RefreshedAt must pass.
	stalenessCeiling time.Duration
	// graceWindow is how long past session_expires a context is retained so a
	// late `port49 login` can resume the session (spec §5.6). It is a
	// retention decision, not a denial one: this package denies at the ceiling
	// and deletes nothing, so nothing here reads it. Plan 7's idle sweep is
	// the reader.
	graceWindow time.Duration
	// contextIdleTTL is the idle lifetime a permitted request extends a
	// context to. It is an idle clock, not a session clock — session_expires
	// is the session clock — so activity slides it forward (spec §5.6).
	contextIdleTTL time.Duration
	// redact is the redaction every record passes through before it is
	// written (spec §5.8); nil is the built-in patterns.
	redact platform.Redactor
}

// WithRedactor sets the redaction applied to every record before it is
// written: port49d passes the policy in force's, so a `platforms:` block's
// patterns reach the log. Without it the built-in patterns apply.
func (h *Handler) WithRedactor(r platform.Redactor) *Handler {
	h.redact = r
	return h
}

// redactions is the patterns that apply to a platform's records.
func (h *Handler) redactions(platformName string) []platform.Redaction {
	if h.redact == nil {
		return platform.BuiltInRedactor(platformName)
	}
	return h.redact(platformName)
}

// New builds an authorization handler. stalenessCeiling, graceWindow and
// contextIdleTTL are the three §5.6 durations; see the Handler fields.
func New(s store.Store, a Authorizer, e decision.Emitter, m *metrics.Metrics, now func() time.Time,
	services map[string][]string, stalenessCeiling, graceWindow, contextIdleTTL time.Duration) *Handler {
	return &Handler{store: s, authz: a, log: e, metrics: m, now: now, services: services,
		stalenessCeiling: stalenessCeiling, graceWindow: graceWindow, contextIdleTTL: contextIdleTTL}
}

// authorizes reports whether a session on this platform may arrive with this
// `service`. A platform with no entry falls back to the built-in table's
// fallback, `shell` — what port49 required of every platform before the table
// existed, so an unmodeled device keeps reaching a prompt (spec §8, "Unknown
// platforms").
//
// The list is short — one or two entries — so this is a scan rather than a
// set. It is the only thing the `service` value is ever compared against: it
// selects no policy, no privilege and no rule (spec §5.2).
func (h *Handler) authorizes(platformName, service string) bool {
	list, ok := h.services[platformName]
	if !ok {
		list = platform.SessionServices(platformName)
	}
	for _, s := range list {
		if s == service {
			return true
		}
	}
	return false
}

// ParseArgs splits RFC 8907 AV pairs. A trailing cmd-arg of "<cr>" is dropped
// from cmdArgs but kept in raw (spec §5.8).
func ParseArgs(args [][]byte) (kv map[string]string, cmd string, cmdArgs []string, raw []string) {
	kv = make(map[string]string, len(args))
	for _, a := range args {
		s := string(a)
		raw = append(raw, s)
		i := strings.IndexAny(s, "=*")
		if i < 0 {
			continue
		}
		k, v := s[:i], s[i+1:]
		switch k {
		case "cmd":
			cmd = v
		case "cmd-arg":
			cmdArgs = append(cmdArgs, v)
		default:
			kv[k] = v
		}
	}
	if n := len(cmdArgs); n > 0 && cmdArgs[n-1] == "<cr>" {
		cmdArgs = cmdArgs[:n-1]
	}
	return kv, cmd, cmdArgs, raw
}

// Vector is the command vector authorization and accounting agree on: the
// command followed by its arguments, or nil for a session request (cmd == "").
func Vector(cmd string, cmdArgs []string) []string {
	if cmd == "" {
		return nil
	}
	return append([]string{cmd}, cmdArgs...)
}

func (h *Handler) Handle(ctx context.Context, peer authen.Peer, req wire.AuthorRequest) wire.AuthorResponse {
	kv, cmd, cmdArgs, raw := ParseArgs(req.Args)
	port := string(req.Port)
	vector := Vector(cmd, cmdArgs)
	rec := decision.Record{TS: h.now(), Event: decision.EventAuthorizeCommand,
		Device:  &decision.Device{NAS: peer.NASAddr, Name: peer.NAS, Platform: peer.Platform},
		Session: &decision.Session{Port: port, RemAddr: string(req.RemAddr), Privilege: req.PrivLvl},
		Request: &decision.Request{Service: kv["service"], Raw: raw, Vector: vector}}
	if cmd == "" {
		rec.Event = decision.EventAuthorizeSession
	}

	// The lookup is (nas, username): the request's own name, never its port.
	// The port on an authorization request is not the port the authentication
	// carried on any platform measured — vEOS says `ssh` then `vty4`, the N9Kv
	// sends it empty on every command — so keying on it denied sessions port49
	// had just authenticated (spec §13, decision 15; §15, L1).
	//
	// Because the username is the key, a request under a name port49 did not
	// authenticate finds no context and is `context_missing`. It cannot land
	// on someone else's context, so there is nothing here to invalidate — the
	// deletion this path used to perform is gone with the old key.
	user := authen.Canonical(string(req.User))
	rec.Session.Username = user
	c, err := h.store.GetContext(ctx, store.ContextKey{NAS: peer.NAS, Username: user})
	h.metrics.StoreOps.WithLabelValues("get_context", storeOutcome(err)).Inc()
	if errors.Is(err, store.ErrNotFound) {
		return h.deny(rec, decision.ContextMissing, "port49: this session was not authenticated by port49")
	}
	if err != nil {
		return h.deny(rec, decision.StoreUnavailable, storeUnavailableMsg)
	}
	// The key already selected on the username; this re-checks what came back,
	// for the same reason package authen re-checks the receipt hash after its
	// lookup. A correct store cannot fail it. A store that answers with a
	// record it was not asked for would otherwise get a permit evaluated
	// against another principal's context — their privilege, their blob — and
	// a record asserting this username belongs to that principal. `subtle`
	// because this is the same class of compare as the receipt's and one rule
	// is easier to audit than an exception.
	//
	// The record keeps the sender's username and drops the principal: it is
	// this request being denied, not the context's owner, and ctx_id already
	// says which context it collided with.
	if subtle.ConstantTimeCompare([]byte(c.Username), []byte(user)) != 1 {
		rec.Session.CtxID = c.CtxID
		return h.deny(rec, decision.UsernameMismatch, "port49: username does not match the authenticated session")
	}
	rec.Session.CtxID = c.CtxID
	rec.Principal = c.Principal

	// Spec §5.3, in order. Each denial says what to do next rather than what
	// went wrong inside: the person who typed the command is reading this.
	now := h.now()
	if !c.RevokedAt.IsZero() {
		return h.deny(rec, decision.CredentialRevoked, "port49: this session was revoked - log in again")
	}
	if !c.SessionExpires.IsZero() && now.After(c.SessionExpires) {
		// Denial at the ceiling is FAIL, not ERROR, and the context is
		// retained: the grace window is plan 7's sweep, not a check here.
		return h.deny(rec, decision.SessionExpired, "port49: session expired - run `port49 login` to resume")
	}
	// A non-positive ceiling is "no staleness check", the same shape as the
	// zero SessionExpires four lines above. It is what a daemon with nothing
	// refreshing `refreshed_at` must pass: a finite ceiling against a clock
	// that only ever moves at login denies a steadily working operator "the
	// broker is unreachable" at login + the ceiling, with no broker to reach.
	if h.stalenessCeiling > 0 && !c.RefreshedAt.IsZero() && now.Sub(c.RefreshedAt) > h.stalenessCeiling {
		return h.deny(rec, decision.ContextStale, "port49: policy has not been refreshed within the staleness ceiling - the broker is unreachable")
	}
	if req.PrivLvl > c.PrivLvl {
		return h.deny(rec, decision.PrivilegeExceeded, "port49: request is above the session's privilege level")
	}

	// Which `service` values this platform's sessions arrive with is a platform
	// fact and not the constant `shell`: L10 measured Junos sending
	// `junos-exec`, and Junos renames it per device with `set system
	// tacplus-options service-name`, so the list is configurable too
	// (spec §5.2, §8; §15, L10).
	if !h.authorizes(peer.Platform, kv["service"]) {
		// server_msg is never built from device-supplied bytes; the service
		// value the NAS sent is already recorded in request.service and
		// request.raw on this record.
		return h.deny(rec, decision.ServiceUnsupported, "port49: service not authorized by port49")
	}

	var d Decision
	ar := Request{Context: c, Device: peer, Raw: raw, Vector: vector}
	if cmd == "" {
		d = h.authz.Session(ctx, ar)
	} else {
		d = h.authz.Command(ctx, ar)
	}
	rec.Policy = d.Policy
	if d.Vector != nil {
		rec.Request.Vector = d.Vector
	}
	if !d.Permit {
		msg := h.serverMsg(peer.Platform, d)
		if d.Error {
			resp := h.deny(rec, d.Reason, msg)
			resp.Status = wire.AuthorStatusError
			return resp
		}
		return h.deny(rec, d.Reason, msg)
	}
	rec.Verdict, rec.Reason = decision.VerdictPermit, d.Reason
	// What the device is told goes on the record as sent, so a replay can
	// re-derive a session's attributes and compare (spec §5.7).
	if len(d.Attributes) > 0 {
		rec.Reply = &decision.Reply{Attributes: d.Attributes}
	}
	h.emit(rec)

	// `ctx.privilege` is the highest level port49 has GRANTED this user on this
	// device, so a permitted session authorization whose reply carries
	// `priv-lvl` raises it to that level and never lowers it: the context covers
	// every window of one operator, and a second window granted less must not
	// take the first window's enable away (spec §5.3, §7; SetPrivilege is
	// raise-only in the store).
	// Measured on vEOS: the session authorization arrives at priv_lvl 1, this
	// reply grants 15, and every command after it arrives at 15, so a context
	// still holding the login START's level would deny all of them
	// (tests/lab/results/L1-arista_eos.md, L3-arista_eos.md).
	//
	// Sessions only. A per-command reply is not a grant, and letting one move
	// the level would hand the session's privilege to whatever the last
	// command's attributes happened to say.
	//
	// SetPrivilege, never PutContext, and for the reason the extension below
	// gives: `c` was read at the top of this request.
	if cmd == "" {
		if level, _, ok := engine.GrantedPrivLvl(d.Attributes); ok {
			// Clamped to the ceiling the token was minted with, the same bound
			// the enable path refuses above (`ceiling_exceeded`, spec §7).
			// Engine refuses a blob whose reply exceeds the ceiling before it
			// gets here, and the policy's joint check quarantines one at load,
			// so only another Authorizer (the lab's) can reach it; the clamp
			// keeps the invariant next to the field it protects. A grant above
			// the ceiling records the ceiling rather than being dropped: the
			// device was told the higher level either way, and recording the
			// lower one is what makes the next command denied instead of
			// permitted.
			//
			// A zero MaxPrivilege is a token minted with no ceiling, not a
			// ceiling of zero — the same reading as a zero SessionExpires
			// above. Clamping to it would record level 0 and deny every command
			// of a session port49 had just granted level 15. The reading lives
			// in store.Context.PrivilegeCeiling, which the enable path's refusal
			// reads too, so the two cannot drift apart.
			if ceiling, ok := c.PrivilegeCeiling(); ok && level > ceiling {
				level = ceiling
			}
			err := h.store.SetPrivilege(ctx, store.ContextKey{NAS: peer.NAS, Username: user}, level)
			h.metrics.StoreOps.WithLabelValues("set_privilege", storeOutcome(err)).Inc()
		}
	}

	// Activity extends the idle TTL (spec §5.6): it is a backstop against
	// abandoned state, not a session clock, and session_expires is the clock.
	// Only a permit extends it — a denied loop must not keep a revoked context
	// alive.
	//
	// TouchContext, never PutContext: `c` was read at the top of this request,
	// and writing it back would discard a revocation, an accounting annotation
	// or an escalation that landed since. It is the difference between a
	// narrow race and a routine one.
	//
	// And only when the remaining life has fallen below half, which is what
	// LastTouchedAt is for: a steady operator costs one store write per half
	// TTL, not one per command.
	if now.Sub(c.LastTouchedAt) >= h.contextIdleTTL/2 {
		err := h.store.TouchContext(ctx, store.ContextKey{NAS: peer.NAS, Username: user}, h.contextIdleTTL)
		// Counted on both outcomes, as every other store call site in this
		// package is, or the "ok" label means nothing. ErrNotFound means the
		// context was reclaimed or revoked out from under this request; the
		// next one reads it for itself and is denied on its own terms, so
		// there is nothing to do here but count it.
		h.metrics.StoreOps.WithLabelValues("touch_context", storeOutcome(err)).Inc()
	}

	resp := wire.AuthorResponse{Status: wire.AuthorStatusPassAdd}
	for _, a := range d.Attributes {
		resp.Args = append(resp.Args, []byte(a))
	}
	return resp
}

func (h *Handler) deny(rec decision.Record, reason decision.Reason, msg string) wire.AuthorResponse {
	rec.Verdict, rec.Reason, rec.ServerMsg = decision.VerdictDeny, reason, msg
	h.emit(rec)
	return wire.AuthorResponse{Status: wire.AuthorStatusFail, ServerMsg: []byte(msg)}
}

// serverMsg is the decision's server_msg, rebuilt when the rule it names
// carries a secret: a rule written with a literal secret in it is echoed with
// the secret redacted, as the record echoes it (spec §5.8). The placeholder
// is ASCII, because a server_msg lands on a console.
func (h *Handler) serverMsg(platformName string, d Decision) string {
	if d.Reason != decision.NoPermitDominatesDeny || d.Policy == nil || d.Policy.MatchedDeny == nil {
		return d.ServerMsg
	}
	rule, ok := platform.RedactRule(h.redactions(platformName), d.Policy.MatchedDeny.Rule)
	if !ok {
		return d.ServerMsg
	}
	text := strings.ReplaceAll(strings.Join(rule, " "), platform.Redacted, "<redacted>")
	return engine.DenyMsg(d.Policy.MatchedDeny.Role, text)
}

func (h *Handler) emit(rec decision.Record) {
	// The decision was made on the command as sent; only the record loses
	// its secret. A typed `username bob secret Hunter2` is authorized like
	// any command and is never written (spec §5.7, §5.8). The rules the
	// record echoes lose theirs too, and a record either touched says it was
	// redacted: what it carries is no longer what was decided.
	if rec.Request != nil && rec.Device != nil {
		rules := h.redactions(rec.Device.Platform)
		req := *rec.Request
		if raw, vector, ok := platform.RedactRecord(rules, req.Raw, req.Vector); ok {
			req.Raw, req.Vector, req.Redacted = raw, vector, true
		}
		if pol, ok := redactPolicy(rules, rec.Policy); ok {
			rec.Policy, req.Redacted = pol, true
		}
		rec.Request = &req
	}
	h.log.Emit(rec)
	h.metrics.Decisions.WithLabelValues(rec.Event, rec.Verdict, string(rec.Reason)).Inc()
}

// redactPolicy is pol with every matched rule's text redacted, and whether
// any was. pol itself is the authorizer's and is not changed.
func redactPolicy(rules []platform.Redaction, pol *decision.Policy) (*decision.Policy, bool) {
	if pol == nil {
		return nil, false
	}
	out, redacted := *pol, false
	out.MatchedPermits = slices.Clone(pol.MatchedPermits)
	if pol.MatchedDeny != nil {
		if words, ok := platform.RedactRule(rules, pol.MatchedDeny.Rule); ok {
			deny := *pol.MatchedDeny
			deny.Rule, out.MatchedDeny, redacted = words, &deny, true
		}
	}
	for i, m := range out.MatchedPermits {
		if words, ok := platform.RedactRule(rules, m.Rule); ok {
			out.MatchedPermits[i].Rule, redacted = words, true
		}
	}
	return &out, redacted
}

// storeOutcome maps a store error to the StoreOps metric's outcome label.
func storeOutcome(err error) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, store.ErrNotFound):
		return "not_found"
	case errors.As(err, new(*store.UnreadableContextError)):
		// The record is there and the store answered; the sealing layer
		// could not open it. Counted apart from "error" so a key rotation
		// does not read as a store outage (spec §5.6).
		return "unreadable"
	default:
		return "error"
	}
}
