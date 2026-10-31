package broker

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/k8sid"
	"github.com/rhwendt/port49/internal/normal"
	"github.com/rhwendt/port49/internal/printsafe"
	"github.com/rhwendt/port49/internal/spiffe"
	"github.com/rhwendt/port49/internal/store"
)

// ErrBadRevocation is a revocation that names neither a principal nor a
// certificate, or both, or one in a form no mark can hold.
var ErrBadRevocation = errors.New("broker: a revocation names a principal, or a certificate's issuer and serial; exactly one")

// ErrRevocationBusy is a revocation that could not take revokeSem before
// its ctx ended: another revocation or lift was running, and this one did
// nothing (decision 34). The HTTP endpoint answers it 503 revocation_busy.
var ErrRevocationBusy = errors.New("broker: another revocation or lift is still running")

// ErrNotRevoked is a lift of a revocation that is not in force.
var ErrNotRevoked = errors.New("broker: no such revocation is in force")

// What a revocation named (spec §5.7's revoke body, "by"). A principal's
// or a certificate's is a standing mark (Revoke, Lift); a principal ending
// its own sessions (RevokeOwn) and one (device, username) ended
// (RevokeKey) leave none (decision 34).
const (
	ByPrincipal = store.RevocationPrincipal
	ByCert      = store.RevocationCert
	ByOwn       = "self"
	ByKey       = "key"

	ByLogoutSid = store.OIDCSid // an OIDC session ended (plan 7h)
	ByLogoutSub = store.OIDCSub // every session of an OIDC subject ended
)

// RevokeRequest is one revocation or lift (spec §5.1.4): of a principal, or
// of one certificate by its issuer (RFC 2253, as Go prints it) and serial
// (hex). Origin says who asked, for the record.
type RevokeRequest struct {
	Principal      string
	Issuer, Serial string
	Origin         string
}

// RevokeReport is what a revocation reached. Err is the first step after
// the mark that did not finish: the mark stands, and the request can be run
// again. SaveErr is broker.revocations_file's write. Unnamed is set when no
// subject in the policy in force names the principal (pre-flight I2).
type RevokeReport struct {
	Request RevokeRequest
	// By is what the revocation named (ByPrincipal, ByCert, ByOwn, ByKey).
	By string
	// Key is the (device, username) a ByKey revocation, or a ByOwn one
	// limited to one key, named.
	Key store.TokenKey
	// LiftNote says where a standing mark made over HTTP is lifted: the
	// endpoint sets it (liftNote; decision 34), and Text prints
	// it after the mark's own text. Empty from `revoke --offline`, whose
	// caller is already there.
	LiftNote string
	// OwnNote is the first line of a self revocation the request named by
	// the caller's own principal, as it would another's: no mark was made,
	// and who can make one. The endpoint sets it (ownNote); empty otherwise.
	OwnNote string
	Mark    store.Revocation
	// OIDCIssuer and Sid or Sub name what a ByLogoutSid or ByLogoutSub
	// revocation ended (plan 7h).
	OIDCIssuer, Sid, Sub string
	// Principals is every owner principal a logout reached (Ruling 24);
	// Request.Principal is the first.
	Principals  []string
	Contexts    []store.ContextRef
	Unreached   []store.ContextRef
	TokenKeys   int
	Connections int
	// Saved is whether broker.revocations_file was written; Attempted is whether
	// there was a file to write (Broker.Persist set), so a broker that keeps none
	// reports no Saved at all.
	Saved, Attempted bool
	SaveErr          error
	Err              error
	Unnamed          bool
	// decimal is set when the serial was typed in decimal digits alone,
	// which is read as hex: openssl prints a small serial in decimal (M1).
	decimal bool
	// landedHere is set when this call's own write created a mark the store
	// flagged landed_after_lift; a flagged mark that already stood is not
	// this call's (task 2 re-review RR-M1).
	landedHere bool
	// workload is set when a certificate revocation's issuer is a workload's
	// (Workload.Issued): the workload renews under a new serial (decision 40
	// ruling 8).
	workload bool
}

// normal checks req and puts it in the form a mark holds (pre-flight I2,
// M16, M17): a principal as Identity spells it, user: and the lower-cased
// email (the mapping is case-insensitive by construction), or app: and the
// client id verbatim (a client id is case-sensitive), refusing one
// without that prefix or with nothing after it; an issuer of valid UTF-8
// with no control or format character (C0, C1, a bidi override), which the
// log would carry raw; a serial in lower-case hex as big.Int.Text(16)
// prints it, which is what Identity records: colons, a 0x and leading zeros
// are dropped, and a leading - (a negative serial, which Go 1.22 still
// accepts) is kept. It returns the mark's kind and key.
func (req RevokeRequest) normal() (RevokeRequest, string, string, error) {
	byCert := req.Issuer != "" || req.Serial != ""
	switch {
	case (req.Principal != "") == byCert:
		return req, "", "", ErrBadRevocation
	case req.Principal != "":
		p, err := normalPrincipal(req.Principal)
		if err != nil {
			return req, "", "", err
		}
		req.Principal = p
		return req, store.RevocationPrincipal, p, nil
	case req.Issuer == "" || req.Serial == "":
		return req, "", "", fmt.Errorf("%w: a certificate is named by its issuer and its serial, both", ErrBadRevocation)
	}
	if err := normal.Issuer(req.Issuer); err != nil {
		return req, "", "", fmt.Errorf("%w: %v", ErrBadRevocation, err)
	}
	serial, err := normal.Serial(req.Serial)
	if err != nil {
		return req, "", "", fmt.Errorf("%w: %v", ErrBadRevocation, err)
	}
	req.Serial = serial
	return req, store.RevocationCert, store.CertKey(req.Issuer, req.Serial), nil
}

// normalPrincipal is p as Identity spells it: user: and the lower-cased
// email, the mapping being case-insensitive by construction, or app: and the
// client id verbatim (a client id is case-sensitive). One that is
// not printable ASCII, has no known prefix, or nothing after it, is refused
// (pre-flight I2, M16). The HTTP endpoints compare a caller to a principal
// a request names only after this, so no spelling makes another principal
// read as the caller, or the caller as another (decision 34).
func normalPrincipal(p string) (string, error) {
	n, err := normal.Principal(p)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrBadRevocation, err)
	}
	return n, nil
}

// Revoke puts a mark in force and reaches everything it names (spec
// §5.1.4, §13 decision 32). The mark is written first: from then on every
// mint it names is refused, on every connection, and a mint that raced it
// reads it again after its last token write (tokens). A mark that cannot be
// written revokes nothing and is the error, naming the fallback. Then, in
// order (pre-flight I1): the listener is told of the mark and the held
// connections it names are closed, both in memory; the marks are written to
// broker.revocations_file (Persist); its unspent tokens are deleted, key by
// key, through the token index, and each key is superseded so no idempotent
// retry replays a deleted token; its live contexts are marked and its
// principals' receipts deleted (session.Manager); and the context index is
// read and marked again. Tokens go before contexts because a token redeemed
// on a device with no live context writes a fresh context (the session
// package comment); the second pass marks one a redemption in flight wrote.
// A failure after the mark is the report's Err, the mark standing, and the
// steps after it still run.
//
// Revoke and Lift hold revokeSem, so a revocation and a lift of one key
// cannot interleave and leave the listener's copy disagreeing with the
// store's (M5). One that cannot take it before ctx ends does nothing and
// says so. That wait is all ctx's end cancels: once it holds revokeSem a
// revocation runs to the end on a ctx detached from the caller and bounded
// by RevokeTimeout, so one the operator started is never left half-done
// because their SSH session dropped.
//
// A revocation by certificate that finds no live context deletes no
// receipt (session.Manager reads the principals off the contexts). That
// replays nothing: with no live context a retransmission is answered
// token_spent, not from its receipt (spec §5.6).
func (b *Broker) Revoke(ctx context.Context, req RevokeRequest) (RevokeReport, error) {
	decimal := req.Serial != "" && strings.Trim(req.Serial, "0123456789") == ""
	req, kind, key, err := req.normal()
	if err != nil {
		return RevokeReport{}, err
	}
	if b.Sessions == nil {
		// A wiring fault, said rather than panicked on: a request goroutine
		// shares the process with TACACS+ (M12).
		return RevokeReport{}, errors.New("broker: revocation is not wired (no session manager); nothing was revoked")
	}
	release, err := b.acquireRevoke(ctx)
	if err != nil {
		return RevokeReport{}, fmt.Errorf("%w, so nothing was revoked by this one (%w); "+b.fallback(),
			ErrRevocationBusy, err)
	}
	defer release()
	ctx, cancel := b.detach(ctx)
	defer cancel()
	now := b.Now()
	mark := store.Revocation{Kind: kind, Key: key, At: now, Origin: req.Origin}
	// In force for the daemon's authorizations before the store's write is
	// sent (plan 7d; Task 4b review M6): a write that commits and whose
	// reply is lost leaves the store's mark standing, and the daemon's
	// copy must not be the one that lacks it. Only a refusal that wrote
	// nothing takes it out again, and only when it did not stand already.
	// A new mark is unwritten (Pend) until the store is known to hold it,
	// so a marks feed's reload in between never lifts it (Ruling T9-b).
	held := b.Marks.Holds(kind, key)
	if !held {
		b.Marks.Pend(mark)
	}
	// The put carries this process's floor, what its marks feed has
	// delivered: a lift recorded above it is one this process had not seen,
	// and the store flags the mark landed_after_lift (decision 51).
	if err := b.Store.PutRevocation(store.WithMarkFloor(ctx, b.Marks.ConfirmedRevision()), mark); err != nil {
		if errors.Is(err, store.ErrIncompleteMark) || errors.Is(err, store.ErrRefused) {
			if held { // a refused write never lands: the mark held here stands (task 2 review M2)
				return RevokeReport{}, fmt.Errorf("broker: the revocation was refused; the revocation of %s this %s "+
					"already holds stands (%w); "+b.fallback(), printsafe.Line(key, 160), b.proc(), err)
			}
			b.Marks.Set(mark, false)
			return RevokeReport{}, fmt.Errorf("broker: the revocation was refused, so nothing was revoked (%w); "+
				b.fallback(), err)
		}
		// A copy already sent may land when the store answers again, held
		// or not, and over a lift made meanwhile (L79 k): its mark is said
		// as this process's own then (MarkChanged; post-11b, C2).
		b.Marks.NoteFailedWrite(mark)
		// Once the store holds it after all (another process's revocation,
		// or this write committed with its reply lost), the marks feed
		// brings it to this listener (Marks.Unrecorded; review I1); when
		// the feed's put came first, it is applied here.
		if !held && b.Marks.Unrecorded(mark) {
			told := mark
			if r, ok := b.Marks.Get(kind, key); ok { // the store's, its flag with it (task 2 review M5)
				told = r
			}
			b.MarkChanged(store.MarkChange{Revocation: told, Standing: true})
		}
		return RevokeReport{}, fmt.Errorf("broker: the revocation may not have been recorded: a copy already sent "+
			"can still land when the directory answers again, and then stands everywhere, even over a lift made "+
			"meanwhile. Until then this %s denies what it names, until a lift on this %s or its restart; after the "+
			"heal check `port49 revoke --list` (%w); "+b.fallback(), b.proc(), b.proc(), err)
	}
	rep := RevokeReport{Request: req, By: kind, Mark: mark, decimal: decimal}
	rep.workload = kind == store.RevocationCert && b.Workload != nil && b.Workload.Issued(req.Issuer)
	if got, err := b.readMark(ctx, kind, key); err == nil {
		rep.Mark = got // an earlier mark stands, with its own time
	}
	rep.landedHere = rep.Mark.LandedAfterLift && rep.Mark.At.Equal(mark.At)
	// A correction only: a lift the feed brought since the write is not
	// undone, and the listener is not marked for it (review M2).
	stands := b.Marks == nil || b.Marks.Put(rep.Mark)
	if kind == store.RevocationPrincipal {
		rep.Unnamed = len(b.Policy.Load().SubjectsOf(b.storedMemberOf(ctx, key))) == 0
	}
	note := func(err error) {
		if err != nil && rep.Err == nil {
			rep.Err = err
		}
	}
	if b.Conns != nil {
		if stands {
			b.Conns.Revoked(rep.Mark, true)
		}
		rep.Connections = b.Conns.CloseHeld(matchMark(rep.Mark))
	}
	rep.Attempted = b.Persist != nil
	rep.Saved, rep.SaveErr = b.persist(ctx)
	n, refs, rerr := b.ReachMark(ctx, rep.Mark)
	rep.TokenKeys, rep.Contexts = n, refs
	note(rerr)
	rep.Unreached = b.unreachedOf(rep.Contexts)
	outcome := "applied"
	if rep.Err != nil {
		outcome = "partial"
	}
	b.recordRevocation(now, rep, decision.VerdictDeny, decision.CredentialRevoked, outcome)
	return rep, nil
}

// ReachMark deletes the unspent tokens r names in this broker's session
// store and marks its live contexts revoked there, as Revoke does after its
// mark (spec §5.1.4): the token keys its index names, each deleted and
// superseded, then the contexts, in two passes, so one a redemption in
// flight wrote is marked too. It writes no mark and no record. In a split
// (plan 11a, R20) the runner applies a mark another region made with it,
// which that region's broker recorded. It returns how many token keys held
// a token or could not be read, the contexts it marked, and the first step
// that did not finish; the steps after it still run.
func (b *Broker) ReachMark(ctx context.Context, r store.Revocation) (tokenKeys int, contexts []store.ContextRef,
	err error) {
	if b.Sessions == nil {
		return 0, nil, errors.New("broker: revocation is not wired (no session manager); nothing was reached")
	}
	note := func(e error) {
		if e != nil && err == nil {
			err = e
		}
	}
	var keys []store.TokenKey
	var kerr error
	if r.Kind == store.RevocationPrincipal {
		keys, kerr = b.Store.TokensByPrincipal(ctx, r.Key)
	} else {
		keys, kerr = b.Store.TokensByCert(ctx, r.Key)
	}
	note(kerr)
	for _, k := range keys {
		// Read first only to count, as the refresh does: an index entry
		// outliving its tokens empties nothing. A read that fails counts.
		toks, cerr := b.Store.Candidates(ctx, k)
		if derr := b.Store.DeleteTokens(ctx, k); derr != nil {
			note(derr)
			continue
		}
		// The delete's own time, not the revocation's start: a mint that
		// stamped its record in between is superseded too (M3).
		b.supersede(ctx, k, b.Now())
		if cerr != nil || len(toks) > 0 {
			tokenKeys++
		}
	}
	var issuer, serial string
	if r.Kind == store.RevocationCert {
		i := strings.LastIndexByte(r.Key, '|')
		if i < 0 {
			// A mark from another region is not vetted here: say so rather
			// than reach nothing in silence.
			note(fmt.Errorf("broker: a %s mark whose key has no issuer|serial split reached no context", r.Kind))
			return tokenKeys, nil, err
		}
		issuer, serial = r.Key[:i], r.Key[i+1:]
	}
	seen := map[store.ContextRef]bool{}
	for pass := 0; pass < 2; pass++ {
		var refs []store.ContextRef
		var rerr error
		if r.Kind == store.RevocationPrincipal {
			refs, rerr = b.Sessions.RevokeByPrincipal(ctx, r.Key)
		} else {
			refs, rerr = b.Sessions.RevokeByCert(ctx, issuer, serial)
		}
		note(rerr)
		for _, ref := range refs {
			if !seen[ref] {
				seen[ref] = true
				contexts = append(contexts, ref)
			}
		}
	}
	return tokenKeys, contexts, err
}

// matchMark names the held connections r names: a principal's by its
// principal, a certificate's by its certificate key.
func matchMark(r store.Revocation) func(principal, certKey string) bool {
	return func(principal, certKey string) bool {
		if r.Kind == store.RevocationPrincipal {
			return principal == r.Key
		}
		return certKey == r.Key
	}
}

// markReader is a store whose GetRevocation answers from a copy (the
// placement router in a split) and that can also ask the directory itself.
type markReader interface {
	ReadRevocation(ctx context.Context, kind, key string) (store.Revocation, error)
}

// readMark is the mark kind|key, for a caller that must know whether one
// stands: the store's answer, and when that is a miss and the store keeps a
// copy, the directory's own, within its call timeout. A directory that does
// not answer is an error, never "absent": a lift fails closed rather than
// report "not revoked" about a mark the copy has not yet followed.
func (b *Broker) readMark(ctx context.Context, kind, key string) (store.Revocation, error) {
	r, err := b.Store.GetRevocation(ctx, kind, key)
	if !errors.Is(err, store.ErrNotFound) {
		return r, err
	}
	if mr, ok := b.Store.(markReader); ok {
		return mr.ReadRevocation(ctx, kind, key)
	}
	return r, err
}

// Lift removes a mark, from the store and the listener. It restores no
// token and un-marks no context: the contexts it marked stay revoked until
// a login whose token was minted after the lift joins them (spec §5.6).
// As with Revoke, ctx's end cancels only the wait for revokeSem.
func (b *Broker) Lift(ctx context.Context, req RevokeRequest) (RevokeReport, error) {
	req, kind, key, err := req.normal()
	if err != nil {
		return RevokeReport{}, err
	}
	release, err := b.acquireRevoke(ctx)
	if err != nil {
		return RevokeReport{}, fmt.Errorf("broker: another revocation or lift is still running, so nothing was "+
			"lifted (%w)", err)
	}
	defer release()
	ctx, cancel := b.detach(ctx)
	defer cancel()
	cur, err := b.readMark(ctx, kind, key)
	switch {
	case errors.Is(err, store.ErrNotFound):
		// The daemon's copy may hold a mark whose write failed (Revoke);
		// the store, which is the authority, holds none.
		b.Marks.Set(store.Revocation{Kind: kind, Key: key}, false)
		return RevokeReport{}, ErrNotRevoked
	case err != nil:
		return RevokeReport{}, fmt.Errorf("broker: reading the revocation: %w", err)
	}
	if err := b.Store.DeleteRevocation(ctx, kind, key, store.Lift{At: b.Now(), Origin: req.Origin}); err != nil {
		if errors.Is(err, store.ErrConflict) {
			// The store's "context changed" would send an operator to the
			// sessions; this names the mark and what to do.
			return RevokeReport{}, fmt.Errorf("broker: nothing was lifted: %s was revoked again while this lift "+
				"ran, and that revocation stands; lift again only if it should go too", markWhat(cur))
		}
		return RevokeReport{}, fmt.Errorf("broker: the revocation could not be lifted, and stands: %w", err)
	}
	b.Marks.Set(cur, false)
	if b.Conns != nil {
		b.Conns.Revoked(cur, false)
	}
	rep := RevokeReport{Request: req, By: cur.Kind, Mark: cur}
	rep.Attempted = b.Persist != nil
	rep.Saved, rep.SaveErr = b.persist(ctx)
	b.recordRevocation(b.Now(), rep, decision.VerdictPermit, decision.RevocationLifted, "lifted")
	return rep, nil
}

// unreachedOf is each of refs on a platform that never asks about a command,
// which keeps the live session whatever its context says (spec §13 decision
// 21), or on a device the inventory gives no platform, assumed to, as the
// refresh assumes.
func (b *Broker) unreachedOf(refs []store.ContextRef) []store.ContextRef {
	pol := b.Policy.Load()
	var out []store.ContextRef
	for _, ref := range refs {
		if dev, ok := pol.Device(ref.NAS); !ok || dev.Platform == "" || sessionOnly(pol, dev.Platform) {
			out = append(out, ref)
		}
	}
	return out
}

// fallback is how to cut access when a revocation cannot be made. On
// port49-broker, which serves no device, stopping it cuts nothing: the
// port49d that serve the devices are what stop.
func (b *Broker) fallback() string {
	const edit = "cut access another way: remove the principal's grants from broker.policy_file (live within " +
		"two watch intervals), or "
	if b.proc() == "port49-broker" {
		return edit + "stop every port49d (port49-broker serves no device)"
	}
	return edit + "stop port49d"
}

// acquireRevoke takes revokeSem, or gives up when ctx ends first. A free
// slot is taken whatever ctx says, so a caller already gone is answered the
// same way every time: only an actual wait is cut short by ctx's end.
func (b *Broker) acquireRevoke(ctx context.Context) (func(), error) {
	b.mu.Lock()
	if b.revokeSem == nil {
		b.revokeSem = make(chan struct{}, 1)
	}
	sem := b.revokeSem
	b.mu.Unlock()
	select {
	case sem <- struct{}{}:
		return func() { <-sem }, nil
	default:
	}
	select {
	case sem <- struct{}{}:
		return func() { <-sem }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// DefaultRevokeTimeout is RevokeTimeout's zero value. The daemons set
// RevokeTimeout to api.OpTimeout.
const DefaultRevokeTimeout = 60 * time.Second

// detach is the ctx a revocation or lift runs on once it holds revokeSem:
// ctx's values, none of its cancellation, and a deadline RevokeTimeout away.
func (b *Broker) detach(ctx context.Context) (context.Context, context.CancelFunc) {
	d := b.RevokeTimeout
	if d <= 0 {
		d = DefaultRevokeTimeout
	}
	return context.WithTimeout(context.WithoutCancel(ctx), d)
}

// persist writes the marks in force to broker.revocations_file.
func (b *Broker) persist(ctx context.Context) (bool, error) {
	if b.Persist == nil {
		return false, nil
	}
	if err := b.Persist(ctx); err != nil {
		return false, err
	}
	return true, nil
}

// recordRevocation writes the one revoke record a revocation or lift makes
// (spec §5.7), and counts it.
func (b *Broker) recordRevocation(now time.Time, rep RevokeReport, verdict string, reason decision.Reason, outcome string) {
	body := &decision.Revocation{By: rep.By, At: decision.FormatTime(rep.Mark.At), Origin: rep.Request.Origin,
		Contexts: len(rep.Contexts), TokenKeys: rep.TokenKeys, Connections: rep.Connections}
	rec := decision.Record{TS: now, Event: decision.EventRevoke, Verdict: verdict, Reason: reason, Revocation: body}
	switch rep.By {
	case ByCert:
		body.Issuer, body.Serial = rep.Request.Issuer, rep.Request.Serial
	default:
		rec.Principal = rep.Request.Principal // ByKey: the context's owner, when one was read
	}
	body.OIDCIssuer, body.Sid, body.Sub = rep.OIDCIssuer, rep.Sid, rep.Sub
	if len(rep.Principals) > 1 {
		body.Principals = rep.Principals
	}
	if rep.Key != (store.TokenKey{}) {
		body.Device, body.Username = rep.Key.NAS, rep.Key.Username
	}
	if (rep.By == ByPrincipal || rep.By == ByCert) && rep.Attempted {
		saved := rep.Saved // a standing mark's file; self and key write none, and a broker without one has none
		body.Saved = &saved
	}
	for _, ref := range rep.Unreached {
		body.Unreached = append(body.Unreached, decision.ContextRef{Device: ref.NAS, Username: ref.Username})
	}
	if rep.Err != nil {
		body.Error = printsafe.Line(rep.Err.Error(), 300)
	}
	b.emit(rec)
	b.Metrics.Revocations.WithLabelValues(rep.By, outcome).Inc()
}

// what names the revoked credential for a person. A serial is shown as
// the broker compares it: lower-case hex, no colons, no leading zeros
// (M23).
func (r RevokeReport) what() string {
	if r.Mark.Kind == store.RevocationPrincipal {
		return r.Request.Principal
	}
	return fmt.Sprintf("the certificate issuer=%q serial=%s (as the broker compares it)", r.Request.Issuer,
		r.Request.Serial)
}

// flags are the port49 revoke flags that name the same credential.
func (r RevokeReport) flags() string {
	if r.Mark.Kind == store.RevocationPrincipal {
		return "--principal " + r.Request.Principal
	}
	return fmt.Sprintf("--cert-issuer %q --cert-serial %s", r.Request.Issuer, r.Request.Serial)
}

// Partial reports whether the revocation or lift is in force but did not
// finish or was not saved: `port49 revoke` exits 3 on it (M10).
func (r RevokeReport) Partial() bool { return r.Err != nil || r.SaveErr != nil }

// Text is what port49 revoke prints for a revocation: for a standing mark,
// a warning first when the principal may be misspelled, what was revoked and
// what it reached; for a self or key revocation, what it ended and that
// nothing stands; then, for all, the contexts it could not reach and
// anything that did not finish.
func (r RevokeReport) Text() string {
	var b strings.Builder
	at := r.Mark.At.UTC().Format(time.RFC3339)
	switch r.By {
	case ByOwn:
		if r.OwnNote != "" {
			b.WriteString(r.OwnNote + "\n")
		}
		where := "everywhere"
		if r.Key != (store.TokenKey{}) {
			where = fmt.Sprintf("on %s (%s)", r.Key.NAS, r.Key.Username)
		}
		fmt.Fprintf(&b, "ended %s's sessions %s at %s: %d live context(s) marked, the unspent tokens under %d "+
			"(device, username) key(s) deleted; nothing stands against %s, so a new `port49 token` and login work "+
			"at once", r.Request.Principal, where, at, len(r.Contexts), r.TokenKeys, r.Request.Principal)
		// A login joins the context it shares and lifts its mark for every
		// session on that (device, username) (spec §5.6; decision 15), a
		// stranger's on a leaked token included (pre-flight I1).
		b.WriteString("\nyour next login on a device re-admits every session open there under your username: if " +
			"anyone else used your token, close their session on the device (or ask an operator to revoke your " +
			"principal) before you log in there again")
	case ByKey:
		if len(r.Contexts) == 0 && r.TokenKeys == 0 && r.Err == nil {
			fmt.Fprintf(&b, "nothing was found under %s (%s): check the device and username as the log names them",
				r.Key.NAS, r.Key.Username)
			break
		}
		owner := ""
		if r.Request.Principal != "" {
			owner = ", " + r.Request.Principal + "'s,"
		}
		fmt.Fprintf(&b, "ended the session on %s (%s)%s at %s: %d live context(s) marked, the unspent tokens "+
			"under %d key(s) deleted; no revocation stands, so its owner can mint and log in again (to stop that, "+
			"revoke the principal)", r.Key.NAS, r.Key.Username, owner, at, len(r.Contexts), r.TokenKeys)
		fmt.Fprintf(&b, "\nthe owner's next login on %s re-admits any session still open on it under %s; close it "+
			"on the device", r.Key.NAS, r.Key.Username)
	case ByLogoutSid, ByLogoutSub:
		what := "session sid " + r.Sid
		if r.By == ByLogoutSub {
			what = "every session of sub " + r.Sub
		}
		owner := ""
		if len(r.Principals) > 0 {
			owner = " (" + strings.Join(r.Principals, ", ") + ")"
		} else if r.Request.Principal != "" {
			owner = " (" + r.Request.Principal + ")"
		}
		fmt.Fprintf(&b, "ended %s at %s%s at %s: %d live context(s) marked, the unspent tokens under %d key(s) "+
			"deleted; its tokens are refused from now on; no revocation stands, so a new login works at once (to "+
			"stop that, revoke the principal)", what, r.OIDCIssuer, owner, at, len(r.Contexts), r.TokenKeys)
	default:
		b.WriteString(r.markText())
		if r.LiftNote != "" {
			b.WriteString("\n" + r.LiftNote)
		}
	}
	if len(r.Unreached) > 0 {
		var names []string
		for _, ref := range r.Unreached {
			names = append(names, fmt.Sprintf("%s (%s)", ref.NAS, ref.Username))
		}
		fmt.Fprintf(&b, "\nnot reached, on a platform that never asks port49 about a command (close these on the "+
			"device): %s", strings.Join(names, ", "))
	}
	if r.SaveErr != nil {
		fmt.Fprintf(&b, "\nNOT saved to broker.revocations_file (%v): this is in force now, and a restart of "+
			"port49d forgets it", r.SaveErr)
	}
	if r.Err != nil && (r.By == ByPrincipal || r.By == ByCert) {
		fmt.Fprintf(&b, "\nincomplete: %v; the mark is in force and refuses every new mint, but until a run "+
			"finishes, unspent tokens may still log in on a device (up to their TTL) and unmarked contexts keep "+
			"authorizing — run the same command again, which repeats every step", r.Err)
	} else if r.Err != nil {
		fmt.Fprintf(&b, "\nincomplete: %v; what it reached is ended, but may not be sealed into the store yet, "+
			"so after a restart of port49d a store write could bring it back, and the rest still works: run the "+
			"same command again, which repeats every step", r.Err)
	}
	return b.String()
}

// markText is what Text prints first for a standing mark: a warning first
// when the principal may be misspelled, then what was revoked and what it
// reached.
func (r RevokeReport) markText() string {
	var b strings.Builder
	nothing := len(r.Contexts) == 0 && r.TokenKeys == 0 && r.Connections == 0
	if r.Mark.Kind == store.RevocationPrincipal && (r.Unnamed || nothing) {
		lead := "nothing was found under " + r.Request.Principal
		if r.Unnamed {
			lead = "no subject in the policy in force names " + r.Request.Principal
		}
		spelled := "the broker spells a certificate's principal user:<lower-case email>"
		if strings.HasPrefix(r.Request.Principal, spiffe.Scheme) {
			spelled = "a workload's principal is its certificate's SPIFFE ID, verbatim"
		}
		if strings.HasPrefix(r.Request.Principal, k8sid.Prefix) {
			spelled = "a service account's principal is system:serviceaccount:<namespace>:<name>, verbatim, as its token's sub names it"
		}
		fmt.Fprintf(&b, "%s; %s, so check the spelling (the mark is written anyway)\n", lead, spelled)
	}
	mints := "by " + r.Request.Principal
	if r.Mark.Kind == store.RevocationCert {
		mints = "with this certificate"
	}
	fmt.Fprintf(&b, "revoked %s at %s: %d live context(s) marked, the unspent tokens under %d (device, username) "+
		"key(s) deleted, %d held broker connection(s) closed; every mint %s is refused until `port49 revoke --lift %s`",
		r.what(), r.Mark.At.UTC().Format(time.RFC3339), len(r.Contexts), r.TokenKeys, r.Connections, mints, r.flags())
	switch { // decision 51; task 2 review M5, re-review RR-M1
	case r.landedHere:
		fmt.Fprintf(&b, "\nthis revocation landed over a lift of %s this process's marks feed had not yet shown: it "+
			"stands everywhere, and whoever lifted it may not know; `port49 revoke --list` names the lift", r.what())
	case r.Mark.LandedAfterLift:
		fmt.Fprintf(&b, "\nan earlier revocation of %s, flagged landed_after_lift, stands; `port49 revoke --list` "+
			"names its lift", r.what())
	}
	if r.Mark.Kind == store.RevocationPrincipal && strings.HasPrefix(r.Request.Principal, k8sid.Prefix) {
		b.WriteString("\na token its cluster issued stays valid at port49 until its exp, or max_token_age after it was " +
			"issued, whatever the cluster does; this mark refuses it now, and stands for a service account " +
			"re-created under that name until `port49 revoke --lift`")
	}
	if r.Mark.Kind == store.RevocationCert && r.decimal {
		fmt.Fprintf(&b, "\nthe serial %s was read as hexadecimal; if you copied a decimal serial (openssl prints a "+
			"small one as 4096 (0x1000)), revoke it again with --cert FILE, then lift this one", r.Request.Serial)
	}
	if r.Mark.Kind == store.RevocationCert && r.workload {
		b.WriteString("\nthis certificate's issuer is the workload trust anchor (broker.identity.machines) or an intermediate under it: the " +
			"workload renews it under a new serial this mark does not name; revoke its principal too (port49 " +
			"revoke --principal spiffe://…), and revoke the certificate at your CA so it cannot be renewed")
	}
	if r.Mark.Kind == store.RevocationCert && r.TokenKeys > 0 {
		b.WriteString("\nunspent tokens are deleted by (device, username): the same principal's other certificates " +
			"lost theirs on those devices too; they can mint again")
	}
	if r.Mark.Kind == store.RevocationCert && nothing {
		b.WriteString("\nnothing was found under this certificate; if it is in use, its issuer is likely spelled " +
			"differently from the broker's (RFC 2253, as Go prints it: CN=Corp Issuing CA,O=Example): use --cert FILE")
	}
	return b.String()
}

// LiftedText is what `port49 revoke --lift` prints. An unsaved lift is the
// reverse of an unsaved revocation: a restart puts the revocation back (M9).
func (r RevokeReport) LiftedText() string {
	var b strings.Builder
	fmt.Fprintf(&b, "lifted the revocation of %s (in force since %s); mints are made for it again unless another "+
		"revocation stands (port49 revoke --list). Contexts it marked stay revoked until a login with a token minted from now joins them", r.what(),
		r.Mark.At.UTC().Format(time.RFC3339))
	if r.SaveErr != nil {
		fmt.Fprintf(&b, "\nNOT saved to broker.revocations_file (%v): the lift is in force now, and a restart of "+
			"port49d puts the revocation back", r.SaveErr)
	}
	return b.String()
}

// RevocationsText is what `port49 revoke --list` prints. A mark flagged
// LandedAfterLift names its lift, the time and revision liftOf reads from
// the lift's record: a put cannot copy them into the mark (decision 51).
func RevocationsText(rs []store.Revocation, liftOf func(kind, key string) (store.Lift, error)) string {
	if len(rs) == 0 {
		return "no revocation is in force"
	}
	var lines []string
	for _, r := range rs {
		line := fmt.Sprintf("%s since %s (%s)", markWhat(r), r.At.UTC().Format(time.RFC3339), r.Origin)
		if r.LandedAfterLift {
			l, err := liftOf(r.Kind, r.Key)
			switch {
			case err == nil:
				line += fmt.Sprintf("; landed after the lift at %s (revision %d)", l.At.UTC().Format(time.RFC3339),
					l.Revision)
			case errors.Is(err, store.ErrNotFound):
				line += "; landed after a lift; the lift's record has expired"
			default:
				line += fmt.Sprintf("; landed after a lift; the lift's record could not be read (%s)",
					printsafe.Line(err.Error(), 300))
			}
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

// markWhat names what r revokes, as an operator reads it.
func markWhat(r store.Revocation) string {
	if i := strings.LastIndex(r.Key, "|"); r.Kind == store.RevocationCert && i >= 0 {
		return fmt.Sprintf("certificate issuer=%q serial=%s", r.Key[:i], r.Key[i+1:])
	}
	return "principal " + r.Key
}
