package broker

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/policy"
	"github.com/rhwendt/port49/internal/printsafe"
	"github.com/rhwendt/port49/internal/store"
)

// maxDeviceUsername bounds a device-facing username a request names: a
// generous bound on what any platform takes, and what a record may carry.
const maxDeviceUsername = 64

// revokeSlotWait bounds a principal revocation's wait for revokeSem
// (api.RevokeSlotWait, which the agent sizes its own wait from); swapped in
// tests.
var revokeSlotWait = api.RevokeSlotWait

// errIncomplete stands in, on the wire, for the store error that stopped a
// step: the caller is told to run it again, and the process log says what
// failed (Global Constraints).
var errIncomplete = errors.New("a step did not finish (port49d's log says which)")

// errNotSaved stands in, on the wire, for broker.revocations_file's write
// error.
var errNotSaved = errors.New("port49d's log says why")

// tokensRevoke is POST /v1/tokens/revoke (design §17; spec §5.1.4; decision
// 34). The caller acts on itself unless its subject declares revoke_others,
// and the request's form, never the caller's rights, decides what it means:
//
//   - mine, or a principal that is the caller's: RevokeOwn, everywhere or,
//     with a device and username, on that key alone, leaving no mark;
//   - another principal: revoke_others, then 7a's Revoke, a standing mark
//     whose origin is the caller; without the right, 403 api_right_missing;
//   - a (device, username) without mine: revoke_others, then RevokeKey,
//     whoever holds it; without the right, 403 api_right_missing, never the
//     caller's own there (pre-flight I2): a right a reload withdrew minutes
//     ago fails loudly, rather than reporting "0 contexts marked" to an
//     on-call who believes someone else's session is gone.
//
// A principal is compared with the caller only as the broker spells it
// (normalPrincipal), so no spelling crosses the line either way. The right
// is read once, from the policy in force, before Revoke waits for its slot,
// and not again after the wait, as a mint reads the policy once (pre-flight
// M18). A self or key revocation takes no slot; one caller may have one in
// flight (revokeOwnOrKey). A lift and a revocation by certificate are the
// admin socket's alone.
func (b *Broker) tokensRevoke(w http.ResponseWriter, r *http.Request) {
	c, ok := b.authenticate(w, r, decision.EventRevoke, "revoked nothing")
	if !ok {
		return
	}
	asker := c.principal
	var req api.RevokeRequest
	dec := json.NewDecoder(io.LimitReader(r.Body, 4<<10))
	dec.DisallowUnknownFields()
	err := dec.Decode(&req)
	if err == nil {
		// One object and nothing after it: a second one would otherwise be
		// dropped unread, narrowing the request silently.
		if _, terr := dec.Token(); terr != io.EOF {
			err = errors.New("trailing data")
		}
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "the body is not a revocation request: "+
			"name mine, a principal, or a device and a username (a lift is "+b.proc()+"'s admin socket's)")
		return
	}
	origin := "api " + asker
	byKey := req.Device != "" || req.Username != ""
	switch {
	case req.Sid != "" && (req.Mine || req.Principal != "" || byKey):
		writeError(w, http.StatusBadRequest, "bad_request", "name a sid alone, with its issuer when more than one "+
			"provider is configured")
		return
	case req.Issuer != "" && req.Sid == "":
		writeError(w, http.StatusBadRequest, "bad_request", "an issuer names a sid's provider; name the sid")
		return
	case req.Mine && req.Principal != "", byKey && req.Principal != "":
		writeError(w, http.StatusBadRequest, "bad_request", "name mine, a principal, or a device and a username, not both")
		return
	case req.Sid == "" && !req.Mine && !byKey && req.Principal == "", byKey && (req.Device == "" || req.Username == ""):
		writeError(w, http.StatusBadRequest, "bad_request", "name mine, a principal, or a device and a username "+
			"(both, for one key)")
		return
	case byKey && (!deviceName(req.Device) || !deviceUsername(req.Username)):
		writeError(w, http.StatusBadRequest, "bad_request", "a device is its inventory name and a username the "+
			"device-facing one, each printable ASCII with no spaces")
		return
	}
	pol := b.Policy.Load()
	// mayOthers asks the directory only when the request names another
	// principal or a key: a caller revoking themselves never waits on the
	// directory, and can always end their own sessions (pre-flight I-9).
	mayOthers := func() (bool, *BindRefusal) {
		ctx, cancel := context.WithTimeout(r.Context(), b.memberBudget())
		defer cancel()
		m, _, err := b.memberFor(ctx, asker)
		if err != nil {
			return false, directoryRefusal(err)
		}
		return pol.HasRightOf(m, policy.RightRevokeOthers), nil
	}
	refused := func(ref *BindRefusal, rec decision.Record) {
		rec.Verdict, rec.Reason = decision.VerdictDeny, ref.Reason
		b.emit(rec)
		b.answerRefusal(w, r, ref)
	}
	if req.Sid != "" {
		b.revokeSid(w, r, pol, asker, origin, req, mayOthers, refused)
		return
	}
	if byKey {
		k := store.TokenKey{NAS: req.Device, Username: req.Username}
		switch {
		case req.Mine:
			b.revokeOwnOrKey(w, pol, asker, origin, func() RevokeReport {
				return b.RevokeOwn(r.Context(), asker, &k, origin)
			})
		default:
			now := b.Now()
			rec := decision.Record{TS: now, Event: decision.EventRevoke,
				Revocation: &decision.Revocation{By: ByKey, Device: k.NAS, Username: k.Username,
					At: decision.FormatTime(now), Origin: origin}}
			ok, ref := mayOthers()
			switch {
			case ref != nil:
				rec.Principal = asker // the key names no one; whose request it was
				refused(ref, rec)
			case ok:
				b.revokeOwnOrKey(w, pol, asker, origin, func() RevokeReport {
					return b.RevokeKey(r.Context(), k, origin)
				})
			default:
				b.refuseRight(w, rec, policy.RightRevokeOthers, "ending a (device, username) whoever holds it")
			}
		}
		return
	}
	own := func() RevokeReport { return b.RevokeOwn(r.Context(), asker, nil, origin) }
	if req.Mine {
		b.revokeOwnOrKey(w, pol, asker, origin, own)
		return
	}
	target, err := normalPrincipal(req.Principal)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", strings.TrimPrefix(err.Error(), "broker: "))
		return
	}
	if target == asker {
		// The caller's own, named as another's would be: a self
		// revocation, no mark (decision 34). The answer says so first,
		// since the CLI asked about a standing mark (final review M2).
		b.revokeOwnOrKey(w, pol, asker, origin, func() RevokeReport {
			rep := own()
			rep.OwnNote = b.ownNote()
			return rep
		})
		return
	}
	now := b.Now()
	rec := decision.Record{TS: now, Event: decision.EventRevoke, Principal: target,
		Revocation: &decision.Revocation{By: ByPrincipal, At: decision.FormatTime(now), Origin: origin}}
	switch ok, ref := mayOthers(); {
	case ref != nil:
		refused(ref, rec)
		return
	case !ok:
		b.refuseRight(w, rec, policy.RightRevokeOthers, "revoking another principal")
		return
	}
	// The wait for the revocation slot is bounded; once Revoke holds it, it
	// runs to the end detached from this request (Revoke's comment).
	wait, cancel := context.WithTimeout(r.Context(), revokeSlotWait)
	defer cancel()
	rep, err := b.Revoke(wait, RevokeRequest{Principal: target, Origin: origin})
	switch {
	case errors.Is(err, ErrBadRevocation):
		writeError(w, http.StatusBadRequest, "bad_request", strings.TrimPrefix(err.Error(), "broker: "))
	case errors.Is(err, ErrRevocationBusy):
		writeBusy(w, "another revocation or lift is still running, so nothing was revoked; try again")
	case err != nil:
		// The mark was not written, so nothing was revoked beyond this
		// port49d's own copy (Revoke): Revoke's own error names the store's
		// fault and the fallback, for port49d's log.
		b.logf("broker: a revocation of %s asked by %s was not made: %v", target, asker, err)
		w.Header().Set("Retry-After", "10")
		writeError(w, http.StatusServiceUnavailable, string(decision.StoreUnavailable), "the revocation could not "+
			"be recorded, so nothing was revoked; "+b.unrecordedNote())
	default:
		rep.LiftNote = b.liftNote()
		b.answerRevocation(w, pol, rep, origin)
	}
}

// revokeSid is the sid form (Ruling 14): one OIDC session ended as a
// back-channel logout by sid ends it, under revoke_others, its origin the
// caller. It holds the asker's one revocation slot while it runs, as a self
// or key revocation does (holdOwnRevoke): RevokeSid runs detached, so a
// caller retrying against a slow store would otherwise stack one detached
// logout per retry (pre-flight M-15).
func (b *Broker) revokeSid(w http.ResponseWriter, r *http.Request, pol *policy.Policy, asker, origin string,
	req api.RevokeRequest, mayOthers func() (bool, *BindRefusal), refused func(*BindRefusal, decision.Record)) {
	var humans []string
	if b.Identity != nil {
		for _, v := range b.Identity.Humans() {
			humans = append(humans, v.Issuer)
		}
	}
	issuer := req.Issuer
	switch {
	case len(humans) == 0:
		writeError(w, http.StatusBadRequest, "bad_request", "this broker has no human OIDC verifier, so no sid")
		return
	case issuer == "" && len(humans) > 1:
		writeError(w, http.StatusBadRequest, "bad_request", "name the sid's issuer: more than one human OIDC "+
			"verifier is configured")
		return
	case issuer == "":
		issuer = humans[0]
	case !slices.Contains(humans, issuer):
		writeError(w, http.StatusBadRequest, "bad_request", "the issuer is no human OIDC verifier's")
		return
	}
	if len(req.Sid) > 255 || strings.IndexFunc(req.Sid, func(r rune) bool { return r < 0x21 || r > 0x7e }) >= 0 {
		writeError(w, http.StatusBadRequest, "bad_request", "a sid is 1 to 255 printable ASCII characters")
		return
	}
	now := b.Now()
	rec := decision.Record{TS: now, Event: decision.EventRevoke, Revocation: &decision.Revocation{By: ByLogoutSid,
		OIDCIssuer: issuer, Sid: req.Sid, At: decision.FormatTime(now), Origin: origin}}
	switch ok, ref := mayOthers(); {
	case ref != nil:
		rec.Principal = asker
		refused(ref, rec)
		return
	case !ok:
		b.refuseRight(w, rec, policy.RightRevokeOthers, "ending an OIDC session")
		return
	}
	release, held := b.holdOwnRevoke(asker)
	if !held {
		writeBusy(w, "another revocation of yours is still running, so this session was not ended; try again once "+
			"it finishes")
		return
	}
	defer release()
	rep, err := b.RevokeSid(r.Context(), issuer, req.Sid, origin)
	if err != nil {
		b.logf("broker: a revocation of sid %s at %s asked by %s was not made: %v", printsafe.Line(req.Sid, 80),
			issuer, asker, err)
		w.Header().Set("Retry-After", "10")
		writeError(w, http.StatusServiceUnavailable, string(decision.StoreUnavailable), "the session's end could not "+
			"be recorded, so nothing was revoked; try again")
		return
	}
	b.answerRevocation(w, pol, rep, origin)
}

// revokeOwnOrKey runs one self or key revocation for caller and answers it.
// Neither takes revokeSem, and each runs detached for up to RevokeTimeout
// whatever the request does, so a caller retrying against a slow store
// would stack one detached run per retry: one of caller's runs at a time,
// and another while it does is 503 revocation_busy and revokes nothing
// (ruling M4). The slot is let go when run returns, which is when its
// detached work has finished: run is synchronous.
func (b *Broker) revokeOwnOrKey(w http.ResponseWriter, pol *policy.Policy, asker, origin string,
	run func() RevokeReport) {
	rep, ran := func() (RevokeReport, bool) {
		release, ok := b.holdOwnRevoke(asker)
		if !ok {
			return RevokeReport{}, false
		}
		defer release()
		return run(), true
	}()
	if !ran {
		writeBusy(w, "another revocation of yours is still running, so nothing was revoked by this one; try "+
			"again once it finishes")
		return
	}
	b.answerRevocation(w, pol, rep, origin)
}

// holdOwnRevoke takes caller's one self-or-key revocation slot, or reports
// false when it is taken. The map holds only callers with a run in flight.
func (b *Broker) holdOwnRevoke(asker string) (func(), bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.ownRevoking[asker] {
		return nil, false
	}
	if b.ownRevoking == nil {
		b.ownRevoking = map[string]bool{}
	}
	b.ownRevoking[asker] = true
	return func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		delete(b.ownRevoking, asker)
	}, true
}

// writeBusy answers a revocation that did nothing because another was
// running: 503 revocation_busy, with Retry-After (design §17).
func writeBusy(w http.ResponseWriter, detail string) {
	w.Header().Set("Retry-After", "5")
	writeError(w, http.StatusServiceUnavailable, "revocation_busy", detail)
}

// unrecordedNote says what to do when a standing mark could not be
// written: `port49 revoke` on the serving process's admin socket, or,
// with none configured, the one cut there is, as its start line says
// (liftNote).
func (b *Broker) unrecordedNote() string {
	if b.AdminSocket == "" {
		return "try again; " + b.proc() + " has no admin_socket configured, so meanwhile have an operator remove " +
			"the principal's grants from broker.policy_file"
	}
	return "try again, or ask an operator to run `port49 revoke` on " + b.proc() + "'s admin socket (" +
		b.AdminSocket + ")"
}

// ownNote is the first line of a self revocation asked by the caller's own
// principal's name: no mark was made, and who can make one.
func (b *Broker) ownNote() string {
	if b.AdminSocket == "" {
		return "this is your own principal: no mark was made; to lock it, " + b.proc() + " needs an admin_socket, " +
			"or an operator removes your grants from broker.policy_file"
	}
	return "this is your own principal: no mark was made; to lock it, ask an operator to use " + b.proc() +
		"'s admin socket (" + b.AdminSocket + ")"
}

// liftNote says where a standing mark made over HTTP is lifted: the
// serving process's admin socket, or, with none configured, the only way
// there is (pre-flight I7). Revoking stays allowed without one: it is the
// safe direction.
func (b *Broker) liftNote() string {
	if b.AdminSocket == "" {
		return b.proc() + " has no admin_socket configured: lifting this needs " + b.proc() + " stopped, the " +
			"entry removed from broker.revocations_file, and a start"
	}
	return "the lift is made on " + b.proc() + "'s admin socket (" + b.AdminSocket + "), by " + b.proc() +
		"'s user or root"
}

// proc is Proc, "port49d" when empty.
func (b *Broker) proc() string {
	if b.Proc == "" {
		return "port49d"
	}
	return b.Proc
}

// answerRevocation writes rep, with a step's store error, and a standing
// mark's file error, replaced by fixed ones on the wire and said whole in
// port49d's log: neither is the caller's to read. It names the subject the
// revoked principal, or the key's owner, resolves to in pol (pre-flight
// M11), so a typo of a real colleague's address is seen at once.
func (b *Broker) answerRevocation(w http.ResponseWriter, pol *policy.Policy, rep RevokeReport, origin string) {
	if rep.Err != nil {
		b.logf("broker: a revocation (%s, by %s) did not finish: %v", rep.By, origin, rep.Err)
		rep.Err = errIncomplete
	}
	if rep.SaveErr != nil {
		b.logf("broker: a revocation (%s, by %s) was not saved to broker.revocations_file: %v", rep.By, origin,
			rep.SaveErr)
		rep.SaveErr = errNotSaved
	}
	out := rep.response()
	if rep.By != ByOwn && rep.Request.Principal != "" {
		ctx, cancel := context.WithTimeout(context.Background(), holdTimeout)
		out.Subject, out.Subjects = subjectNames(pol, b.storedMemberOf(ctx, rep.Request.Principal))
		cancel()
	}
	writeJSON(w, http.StatusOK, out)
}

// response is rep's wire form (api.RevokeResponse), Subject aside.
func (r RevokeReport) response() api.RevokeResponse {
	out := api.RevokeResponse{By: r.By, Principal: r.Request.Principal, Standing: r.By == ByPrincipal || r.By == ByCert,
		At: r.Mark.At.UTC().Format(time.RFC3339), Contexts: len(r.Contexts), TokenKeys: r.TokenKeys,
		Connections: r.Connections, Unreached: []api.SessionRef{}, Text: r.Text()}
	if r.Key != (store.TokenKey{}) {
		out.Device, out.Username = r.Key.NAS, r.Key.Username
	}
	for _, ref := range r.Unreached {
		out.Unreached = append(out.Unreached, api.SessionRef{Device: ref.NAS, Username: ref.Username})
	}
	if out.Standing {
		saved := r.Saved
		out.Saved = &saved
	}
	if r.Err != nil {
		out.Incomplete = r.Err.Error()
	}
	return out
}

// deviceUsername reports whether s can be a device-facing username: 1 to
// maxDeviceUsername bytes of printable ASCII, no spaces.
func deviceUsername(s string) bool {
	return s != "" && len(s) <= maxDeviceUsername &&
		strings.IndexFunc(s, func(r rune) bool { return r < 0x21 || r > 0x7e }) < 0
}
