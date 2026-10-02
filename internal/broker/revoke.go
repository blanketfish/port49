package broker

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/printsafe"
	"github.com/rhwendt/port49/internal/store"
)

// ErrBadRevocation is a revocation that names neither a principal nor a
// certificate, or both, or one in a form no mark can hold.
var ErrBadRevocation = errors.New("broker: a revocation names a principal, or a certificate's issuer and serial; exactly one")

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
	// endpoint sets it from Broker.AdminSocket (decision 34), and Text prints
	// it after the mark's own text. Empty from the admin socket, whose
	// caller is already there.
	LiftNote    string
	Mark        store.Revocation
	Contexts    []store.ContextRef
	Unreached   []store.ContextRef
	TokenKeys   int
	Connections int
	Saved       bool
	SaveErr     error
	Err         error
	Unnamed     bool
	// decimal is set when the serial was typed in decimal digits alone,
	// which is read as hex: openssl prints a small serial in decimal (M1).
	decimal bool
}

// principalPrefixes are the forms Identity and the policy give a principal
// (spec §2). Only user: is minted for today; the others are refused until
// their verifier exists, rather than marked under a key nothing spells.
var principalPrefixes = []string{"user:"}

// normal checks req and puts it in the form a mark holds (pre-flight I2,
// M16, M17): a principal as Identity spells it, user: and the lower-cased
// email (the mapping is case-insensitive by construction), refusing one
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
	if len(req.Issuer) > 2048 || !utf8.ValidString(req.Issuer) ||
		strings.IndexFunc(req.Issuer, func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) }) >= 0 {
		return req, "", "", fmt.Errorf("%w: the issuer has a control or format character or is not UTF-8", ErrBadRevocation)
	}
	s := strings.ReplaceAll(strings.ToLower(req.Serial), ":", "")
	neg := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(strings.TrimPrefix(s, "-"), "0x")
	if s == "" || len(s) > 64 || strings.Trim(s, "0123456789abcdef") != "" {
		return req, "", "", fmt.Errorf("%w: a serial is hexadecimal", ErrBadRevocation)
	}
	if s = strings.TrimLeft(s, "0"); s == "" {
		s, neg = "0", false
	}
	if neg {
		s = "-" + s
	}
	req.Serial = s
	return req, store.RevocationCert, store.CertKey(req.Issuer, req.Serial), nil
}

// normalPrincipal is p as Identity spells it: user: and the lower-cased
// email, the mapping being case-insensitive by construction. One that is
// not printable ASCII, has no known prefix, or nothing after it, is refused
// (pre-flight I2, M16). The HTTP endpoints compare a caller to a principal
// a request names only after this, so no spelling makes another principal
// read as the caller, or the caller as another (decision 34).
func normalPrincipal(p string) (string, error) {
	if len(p) > 1024 || strings.IndexFunc(p, func(r rune) bool { return r < 0x21 || r > 0x7e }) >= 0 {
		return "", fmt.Errorf("%w: a principal is printable ASCII", ErrBadRevocation)
	}
	for _, pre := range principalPrefixes {
		if strings.HasPrefix(strings.ToLower(p), pre) && len(p) > len(pre) {
			return pre + strings.ToLower(p[len(pre):]), nil
		}
	}
	return "", fmt.Errorf("%w: a principal begins %s, as the log names it (user:alice@example.com)",
		ErrBadRevocation, strings.Join(principalPrefixes, " or "))
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
		// A wiring fault, said rather than panicked on: the admin socket's
		// goroutine shares the process with TACACS+ (M12).
		return RevokeReport{}, errors.New("broker: revocation is not wired (no session manager); nothing was revoked")
	}
	release, err := b.acquireRevoke(ctx)
	if err != nil {
		return RevokeReport{}, fmt.Errorf("broker: another revocation or lift is still running, so nothing was "+
			"revoked by this one (%w); "+fallback, err)
	}
	defer release()
	ctx, cancel := b.detach(ctx)
	defer cancel()
	now := b.Now()
	mark := store.Revocation{Kind: kind, Key: key, At: now, Origin: req.Origin}
	if err := b.Store.PutRevocation(ctx, mark); err != nil {
		return RevokeReport{}, fmt.Errorf("broker: the revocation could not be recorded, so nothing was revoked (%w); "+
			fallback, err)
	}
	rep := RevokeReport{Request: req, By: kind, Mark: mark, decimal: decimal}
	if got, err := b.Store.GetRevocation(ctx, kind, key); err == nil {
		rep.Mark = got // an earlier mark stands, with its own time
	}
	if kind == store.RevocationPrincipal {
		_, named := b.Policy.Load().SubjectOf(key)
		rep.Unnamed = !named
	}
	note := func(err error) {
		if err != nil && rep.Err == nil {
			rep.Err = err
		}
	}
	if b.Conns != nil {
		b.Conns.Revoked(rep.Mark, true)
		rep.Connections = b.Conns.CloseHeld(func(principal, certKey string) bool {
			if kind == store.RevocationPrincipal {
				return principal == key
			}
			return certKey == key
		})
	}
	rep.Saved, rep.SaveErr = b.persist(ctx)
	var tokenKeys []store.TokenKey
	if kind == store.RevocationPrincipal {
		tokenKeys, err = b.Store.TokensByPrincipal(ctx, key)
	} else {
		tokenKeys, err = b.Store.TokensByCert(ctx, key)
	}
	note(err)
	for _, k := range tokenKeys {
		// Read first only to count, as the refresh does: an index entry
		// outliving its tokens empties nothing. A read that fails counts.
		toks, cerr := b.Store.Candidates(ctx, k)
		if err := b.Store.DeleteTokens(ctx, k); err != nil {
			note(err)
			continue
		}
		// The delete's own time, not the revocation's start: a mint that
		// stamped its record in between is superseded too (M3).
		b.supersede(k, b.Now())
		if cerr != nil || len(toks) > 0 {
			rep.TokenKeys++
		}
	}
	seen := map[store.ContextRef]bool{}
	for pass := 0; pass < 2; pass++ {
		var refs []store.ContextRef
		if kind == store.RevocationPrincipal {
			refs, err = b.Sessions.RevokeByPrincipal(ctx, key)
		} else {
			refs, err = b.Sessions.RevokeByCert(ctx, req.Issuer, req.Serial)
		}
		note(err)
		for _, ref := range refs {
			if !seen[ref] {
				seen[ref] = true
				rep.Contexts = append(rep.Contexts, ref)
			}
		}
	}
	rep.Unreached = b.unreachedOf(rep.Contexts)
	outcome := "applied"
	if rep.Err != nil {
		outcome = "partial"
	}
	b.recordRevocation(now, rep, decision.VerdictDeny, decision.CredentialRevoked, outcome)
	return rep, nil
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
	cur, err := b.Store.GetRevocation(ctx, kind, key)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return RevokeReport{}, ErrNotRevoked
	case err != nil:
		return RevokeReport{}, fmt.Errorf("broker: reading the revocation: %w", err)
	}
	if err := b.Store.DeleteRevocation(ctx, kind, key); err != nil {
		return RevokeReport{}, fmt.Errorf("broker: the revocation could not be lifted, and stands: %w", err)
	}
	if b.Conns != nil {
		b.Conns.Revoked(cur, false)
	}
	rep := RevokeReport{Request: req, By: cur.Kind, Mark: cur}
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

// fallback is how to cut access when a revocation cannot be made.
const fallback = "cut access another way: remove the principal's grants from broker.policy_file (live within " +
	"two watch intervals), or stop port49d"

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

// DefaultRevokeTimeout is RevokeTimeout's zero value. port49d sets
// RevokeTimeout to the admin socket's own bound (admin.OpTimeout).
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
	if rep.Key != (store.TokenKey{}) {
		body.Device, body.Username = rep.Key.NAS, rep.Key.Username
	}
	if rep.By == ByPrincipal || rep.By == ByCert {
		saved := rep.Saved // a standing mark's file; self and key write none
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
		fmt.Fprintf(&b, "\nincomplete: %v; what it reached is ended, and the rest still works: run the same "+
			"command again, which repeats every step", r.Err)
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
		fmt.Fprintf(&b, "%s; the broker spells a certificate's principal user:<lower-case email>, so check the "+
			"spelling (the mark is written anyway)\n", lead)
	}
	mints := "by " + r.Request.Principal
	if r.Mark.Kind == store.RevocationCert {
		mints = "with this certificate"
	}
	fmt.Fprintf(&b, "revoked %s at %s: %d live context(s) marked, the unspent tokens under %d (device, username) "+
		"key(s) deleted, %d held broker connection(s) closed; every mint %s is refused until `port49 revoke --lift %s`",
		r.what(), r.Mark.At.UTC().Format(time.RFC3339), len(r.Contexts), r.TokenKeys, r.Connections, mints, r.flags())
	if r.Mark.Kind == store.RevocationCert && r.decimal {
		fmt.Fprintf(&b, "\nthe serial %s was read as hexadecimal; if you copied a decimal serial (openssl prints a "+
			"small one as 4096 (0x1000)), revoke it again with --cert FILE, then lift this one", r.Request.Serial)
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

// RevocationsText is what `port49 revoke --list` prints.
func RevocationsText(rs []store.Revocation) string {
	if len(rs) == 0 {
		return "no revocation is in force"
	}
	var lines []string
	for _, r := range rs {
		what := "principal " + r.Key
		if i := strings.LastIndex(r.Key, "|"); r.Kind == store.RevocationCert && i >= 0 {
			what = fmt.Sprintf("certificate issuer=%q serial=%s", r.Key[:i], r.Key[i+1:])
		}
		lines = append(lines, fmt.Sprintf("%s since %s (%s)", what, r.At.UTC().Format(time.RFC3339), r.Origin))
	}
	return strings.Join(lines, "\n")
}
