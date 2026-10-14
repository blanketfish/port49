package broker

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/directory"
	"github.com/rhwendt/port49/internal/issuer"
	"github.com/rhwendt/port49/internal/oidc"
	"github.com/rhwendt/port49/internal/printsafe"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/totp"
)

// SignInDirectory is what a directory sign-in asks the directory;
// *directory.Resolver is one.
type SignInDirectory interface {
	SignInEntry(ctx context.Context, name, filter string) (directory.SignInEntry, error)
	CheckPassword(ctx context.Context, s directory.Server, dn, password string) error
}

const (
	// enrollFor is how long an enrollment's handle lives: the person's time
	// to add the secret to an authenticator and read its first code.
	enrollFor = 10 * time.Minute
	// maxSignInName is the longest name typed at a sign-in, in bytes.
	maxSignInName = 256
	// signInMethod is the auth.method of every directory sign-in record.
	signInMethod = "directory_password"
)

// The answers a directory sign-in gives, fixed text by reason: nothing the
// directory, a store or the person typed is ever put in one.
const (
	refusedText = "the name, password or code was not accepted; check them and run `port49 login` again"
	lostText    = "the broker's store of second factors is lost, so no one can sign in with a password until an " +
		"operator restores it; anyone already signed in keeps working until their certificate ends"
	directoryDownText = "the broker cannot reach its directory now, so no one can sign in with a password; anyone " +
		"already signed in keeps working until their certificate ends; try again shortly"
	storeDownText = "the broker could not reach its store, so it signed no one in; try again shortly"
	closedText    = "you have no second factor, and enrollment is closed for you: ask an operator to run " +
		"`port49 directory reset-second-factor` for your account"
	endedText = "this enrollment ended or was confirmed; run `port49 login` again"
)

// stateWords is a refusal of the account's state, said by its Data: the
// state and who fixes it, never the directory's own message.
func stateWords(p *directory.PasswordRefusal) string {
	switch p.Data {
	case "532", "password_expired":
		return "your password has expired: change it in your directory, then run `port49 login` again"
	case "773", "change_after_reset":
		return "your password must be changed: change it in your directory, then run `port49 login` again"
	case "533":
		return "your account is disabled: ask your directory administrator"
	case "775", "account_locked":
		return "your account is locked: ask your directory administrator, or wait for it to unlock"
	case "701":
		return "your account has expired: ask your directory administrator"
	case "530", "531":
		return "your account may not sign in at this time or from here: ask your directory administrator"
	}
	// A 53 and any state with no data code of its own.
	return "your directory refuses this account now: ask your directory administrator"
}

// signInAttempt is one request's state, and every answer it gives. Each
// refusal is one issue deny record, counted under SignIns, and an answer
// whose words are fixed by its reason.
type signInAttempt struct {
	b   *Broker
	w   http.ResponseWriter
	now time.Time
	src string
}

// rec emits a deny record of event for principal ("" when none is known).
func (s *signInAttempt) rec(event string, reason decision.Reason, principal string, si decision.SignIn) {
	si.Source = s.src
	s.b.emit(decision.Record{TS: s.now, Event: event, Verdict: decision.VerdictDeny, Reason: reason,
		Principal: principal, Auth: &decision.Auth{Method: signInMethod}, SignIn: &si})
}

// refuseWith is the one refusal: 401 sign_in_refused for a wrong name,
// password or code alike (ruling 7).
func (s *signInAttempt) refuseWith(principal string, si decision.SignIn, text string) {
	s.rec(decision.EventIssue, decision.SignInRefused, principal, si)
	s.b.Metrics.SignIns.WithLabelValues("refused").Inc()
	writeError(s.w, http.StatusUnauthorized, string(decision.SignInRefused), text)
}

// refuse is a refusal with no principal known.
func (s *signInAttempt) refuse(failed string) {
	s.refuseWith("", decision.SignIn{Failed: failed}, refusedText)
}

// refuseAs is a refusal of the person e names.
func (s *signInAttempt) refuseAs(principal, failed string) {
	s.refuseWith(principal, decision.SignIn{Failed: failed}, refusedText)
}

// storeLost is C1's answer (D7): the enrollment store is lost, and no
// password sign-in is taken.
func (s *signInAttempt) storeLost() {
	s.rec(decision.EventIssue, decision.EnrollmentStoreLost, "", decision.SignIn{})
	s.b.Metrics.SignIns.WithLabelValues("enrollment_store_lost").Inc()
	s.w.Header().Set("Retry-After", "300")
	writeError(s.w, http.StatusServiceUnavailable, string(decision.EnrollmentStoreLost), lostText)
}

// storeUnavailable is 503 store_unavailable: a store that did not answer, or
// a record that will not open. what and err go to the broker's line (never
// the answer); text is the answer's words, storeDownText when empty.
func (s *signInAttempt) storeUnavailable(principal, what string, err error, text string) {
	s.b.sayOnce("sign_in_store_"+what, sayEvery, "sign-in: the %s store did not answer: %s", what,
		printsafe.Line(fmt.Sprint(err), 300))
	s.rec(decision.EventIssue, decision.StoreUnavailable, principal, decision.SignIn{})
	s.b.Metrics.SignIns.WithLabelValues("store_unavailable").Inc()
	if text == "" {
		text = storeDownText
	}
	writeError(s.w, http.StatusServiceUnavailable, string(decision.StoreUnavailable), text)
}

// directoryUnavailable is 503 directory_unavailable: the directory did not
// answer. The 3am answer says that anyone signed in keeps working. The
// directory's own error is never said: it may hold the name typed.
func (s *signInAttempt) directoryUnavailable(principal string) {
	s.b.sayOnce("sign_in_directory_unavailable", sayEvery, "sign-in: the directory did not answer; password "+
		"sign-in is refused until it does")
	s.rec(decision.EventIssue, decision.DirectoryUnavailable, principal, decision.SignIn{})
	s.b.Metrics.SignIns.WithLabelValues("directory_unavailable").Inc()
	s.w.Header().Set("Retry-After", "30")
	writeError(s.w, http.StatusServiceUnavailable, string(decision.DirectoryUnavailable), directoryDownText)
}

// throttled is 429 sign_in_throttled, the words fixed by who is over their
// limit; neither names the principal (I3).
func (s *signInAttempt) throttled(failed, principal, text string, end time.Time) {
	s.rec(decision.EventIssue, decision.SignInThrottled, principal, decision.SignIn{Failed: failed})
	s.b.Metrics.SignIns.WithLabelValues("throttled").Inc()
	wait := int(math.Ceil(end.Sub(s.now).Seconds()))
	s.w.Header().Set("Retry-After", strconv.Itoa(max(wait, 1)))
	writeError(s.w, http.StatusTooManyRequests, string(decision.SignInThrottled), fmt.Sprintf(text, end.UTC().Format(time.RFC3339)))
}

// csrKey is the public key a sign-in's CSR proves, answering 400 when the
// CSR does not parse, is not signed by its key, or holds a key no certificate
// is issued for. Nothing is counted or recorded: it is no attempt.
func (s *signInAttempt) csrKey(raw string) (crypto.PublicKey, bool) {
	der, err := base64.RawURLEncoding.DecodeString(raw)
	var csr *x509.CertificateRequest
	if err == nil {
		csr, err = x509.ParseCertificateRequest(der)
	}
	if err == nil {
		err = csr.CheckSignature()
	}
	if err != nil {
		writeError(s.w, http.StatusBadRequest, "bad_request", "the CSR does not parse, or its signature is not its key's")
		return nil, false
	}
	if why := issuableKey(csr.PublicKey); why != "" {
		writeError(s.w, http.StatusBadRequest, "bad_request", why)
		return nil, false
	}
	return csr.PublicKey, true
}

// underLimit takes one attempt under key and reports whether it is within
// limit; over it, it has answered 429 with text (one %s: when the window
// ends). A store that does not answer fails closed, 503.
func (s *signInAttempt) underLimit(ctx context.Context, cfg *oidc.PasswordSignIn, key, failed, principal string,
	limit int, text string) bool {
	n, end, err := s.b.Store.NoteSignInAttempt(ctx, key, cfg.Window)
	if err != nil {
		s.storeUnavailable(principal, "attempts", err, "")
		return false
	}
	if n > limit {
		s.throttled(failed, principal, text, end)
		return false
	}
	return true
}

// underSourceLimit counts the attempt against the source and judges it; 0
// failures_per_source is off: nothing is counted.
func (s *signInAttempt) underSourceLimit(ctx context.Context, cfg *oidc.PasswordSignIn) bool {
	if cfg.FailuresPerSource <= 0 {
		return true
	}
	return s.underLimit(ctx, cfg, "source:"+s.src, "source_limit", "", cfg.FailuresPerSource,
		"too many failed sign-ins from this address; try again after %s")
}

// underPrincipalLimit counts the attempt against the principal and judges it
// (D4: counted before it is judged, so parallel attempts cannot pass it).
func (s *signInAttempt) underPrincipalLimit(ctx context.Context, cfg *oidc.PasswordSignIn, principal string) bool {
	return s.underLimit(ctx, cfg, "principal:"+principal, "principal_limit", principal, cfg.FailuresPerPrincipal,
		"too many failed sign-ins for this account; try again after %s, or an operator can clear it with "+
			"`port49 directory unlock` for your account")
}

// entry is the directory's entry for the name typed, answering when there is
// none. The directory's error is read for its class alone: Pool.Do wraps the
// server's diagnostic, which may echo the filter and so the name typed (R8).
func (s *signInAttempt) entry(ctx context.Context, name string, cfg *oidc.PasswordSignIn) (directory.SignInEntry, bool) {
	e, err := s.b.SignInDirectory.SignInEntry(ctx, name, cfg.Filter)
	switch {
	case errors.Is(err, directory.ErrUnavailable):
		s.directoryUnavailable("")
		return e, false
	case errors.Is(err, directory.ErrAmbiguous):
		// Two entries answer the name: the person is refused, and the operator
		// told by the record. No principal: none is certain.
		s.b.Metrics.SignIns.WithLabelValues("refused").Inc()
		s.rec(decision.EventIssue, decision.IdentityAmbiguous, "", decision.SignIn{Failed: "name"})
		writeError(s.w, http.StatusUnauthorized, string(decision.SignInRefused), refusedText)
		return e, false
	case err != nil:
		s.refuse("name")
		return e, false
	case !slicesContainsDomain(cfg, e.Principal):
		s.refuse("name") // a principal this verifier does not take is no one's here
		return e, false
	}
	return e, true
}

// slicesContainsDomain is whether principal is a user: principal in one of
// cfg's principal_domains.
func slicesContainsDomain(cfg *oidc.PasswordSignIn, principal string) bool {
	d := oidc.DomainOf(principal)
	if d == "" {
		return false
	}
	for _, want := range cfg.PrincipalDomains {
		if d == want {
			return true
		}
	}
	return false
}

// entryMoved is a second factor enrolled for another entry than the
// directory gives now: refused with the one sentence, the operator told once
// an hour (ruling 12; I12).
func (s *signInAttempt) entryMoved(e directory.SignInEntry, was string) {
	s.b.sayOnce("sign_in_entry_moved "+e.Principal, time.Hour, "sign-in: %s's second factor was enrolled for entry "+
		"%s, and the directory now gives %s: an operator runs `port49 directory reset-second-factor %s`",
		printsafe.Line(e.Principal, 300), printsafe.Line(was, 300), printsafe.Line(e.EntryID, 300),
		printsafe.Line(e.Principal, 300))
	s.refuseAs(e.Principal, "second_factor")
}

// refuseSkew is a code for a time outside the window, from a clock that is
// off: refused, and the person told by how much.
func (s *signInAttempt) refuseSkew(principal string, by time.Duration) {
	mins := int(math.Round(math.Abs(by.Minutes())))
	dir := "behind"
	if by > 0 {
		dir = "ahead of"
	}
	s.refuseWith(principal, decision.SignIn{Failed: "second_factor_skew", SkewSeconds: int(by / time.Second)},
		fmt.Sprintf("your authenticator's clock is about %d minutes off (%s the broker's): set it to the network "+
			"time and run `port49 login` again", mins, dir))
}

// signOf is the sign-in a certificate for principal on entryID is issued over.
func (s *signInAttempt) signOf(principal, entryID string) issuer.SignIn {
	return issuer.SignIn{Method: issuer.MethodDirectoryPassword, Principal: principal,
		Subject: issuer.EntrySubject(entryID), AMR: []string{"pwd", "otp"}, AuthTime: s.now, IssuedAt: s.now}
}

// issuable is whether a certificate can be made for principal on entryID,
// before anything is spent (C3): the person's claims it cannot carry are
// the person's (a recorded refusal), the CA's own faults the broker's
// (unrecorded), as issue answers them.
func (s *signInAttempt) issuable(principal, entryID string) bool {
	err := s.b.Issuer.CanIssue(s.signOf(principal, entryID), s.now, s.b.certificateLifetime())
	switch {
	case err == nil:
		return true
	case errors.Is(err, issuer.ErrNotCertifiable):
		s.rec(decision.EventIssue, decision.SignInRefused, principal, decision.SignIn{})
		s.b.Metrics.SignIns.WithLabelValues("refused").Inc()
		writeError(s.w, http.StatusUnauthorized, "sign_in_not_certifiable", "your account's principal cannot be "+
			"carried in a certificate; tell the operator")
	default:
		s.b.Metrics.CertificatesIssued.WithLabelValues("unavailable").Inc()
		s.b.sayOnce("issuance_unavailable", sayEvery, "issuance: a sign-in of %s was not issued a certificate: %s",
			printsafe.Line(principal, 300), printsafe.Line(err.Error(), 300))
		s.w.Header().Set("Retry-After", "60")
		writeError(s.w, http.StatusServiceUnavailable, "issuance_unavailable", "this broker cannot issue certificates "+
			"now: its issuing CA is not usable; tell its operator (the broker's log says why)")
	}
	return false
}

// password checks the person's password at the directory and answers a
// refusal: false when it did. A refusal naming the account's state says it;
// the data recorded is the allow-listed one the directory package kept.
func (s *signInAttempt) password(ctx context.Context, e directory.SignInEntry, password string) bool {
	err := s.b.SignInDirectory.CheckPassword(ctx, e.Server, e.DN, password)
	var refusal *directory.PasswordRefusal
	switch {
	case err == nil:
		return true
	case errors.Is(err, directory.ErrEmptyPassword):
		s.refuseAs(e.Principal, "password")
	case errors.As(err, &refusal) && refusal.State():
		s.refuseWith(e.Principal, decision.SignIn{Failed: "directory_state", DirectoryResult: refusal.Result,
			DirectoryData: refusal.Data}, stateWords(refusal))
	case errors.As(err, &refusal):
		s.refuseAs(e.Principal, "password")
	default:
		// The dial's or the bind's own failure, or anything the directory
		// package does not name a refusal: not a wrong password.
		s.directoryUnavailable(e.Principal)
	}
	return false
}

// succeeded clears the principal's count, and takes this attempt back from
// the source's (with that limit on). A store error here is the broker's
// line, never a refusal: the person is signed in.
func (s *signInAttempt) succeeded(ctx context.Context, cfg *oidc.PasswordSignIn, principal string) {
	if _, err := s.b.Store.ClearSignInAttempts(ctx, "principal:"+principal); err != nil {
		s.b.sayOnce("sign_in_clear", sayEvery, "sign-in: a principal's failed-attempt count could not be cleared: %s",
			printsafe.Line(err.Error(), 300))
	}
	if cfg.FailuresPerSource > 0 {
		if err := s.b.Store.UndoSignInAttempt(ctx, "source:"+s.src); err != nil {
			s.b.sayOnce("sign_in_undo", sayEvery, "sign-in: a source's attempt could not be taken back: %s",
				printsafe.Line(err.Error(), 300))
		}
	}
}

// issue signs the person's certificate and answers it, counting it issued.
func (s *signInAttempt) issue(pub crypto.PublicKey, principal, entryID string) {
	sign := s.signOf(principal, entryID)
	auth := &decision.Auth{Method: signInMethod, DirectoryPassword: directoryPasswordAuth(sign)}
	if s.b.issueTo(s.w, s.now, pub, sign, auth, &decision.SignIn{Source: s.src}) {
		s.b.Metrics.SignIns.WithLabelValues("issued").Inc()
	}
}

// normalName is the name typed as it is searched: surrounding space dropped.
// A name with a control or format character (a bidi override), invalid UTF-8,
// or none or too many bytes is no name.
func normalName(raw string) (string, bool) {
	name := strings.TrimSpace(raw)
	if name == "" || len(name) > maxSignInName || !utf8.ValidString(name) {
		return "", false
	}
	for _, r := range name {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp) {
			return "", false
		}
	}
	return name, true
}

// sourcePrefix is r's peer as the per-source limit counts it: an IPv4
// address /32, an IPv6 address /64.
func sourcePrefix(remoteAddr string) string {
	ap, err := netip.ParseAddrPort(remoteAddr)
	if err != nil {
		return "unknown"
	}
	a := ap.Addr().Unmap()
	if a.Is4() {
		return netip.PrefixFrom(a, 32).String()
	}
	return netip.PrefixFrom(a, 64).Masked().String()
}

// handleKey is the once-only key of an enrollment handle: its SHA-256, so
// the store never holds a handle.
func handleKey(handle string) string {
	sum := sha256.Sum256([]byte(handle))
	return "enroll_handle " + hex.EncodeToString(sum[:])
}

// readSignInBody reads r's body into v, refusing a body with another member
// and naming none of it.
func readSignInBody(w http.ResponseWriter, r *http.Request, v any, shape string) bool {
	dec := json.NewDecoder(io.LimitReader(r.Body, 16<<10))
	dec.DisallowUnknownFields()
	if dec.Decode(v) != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "the body is not a sign-in: "+shape)
		return false
	}
	return true
}

// signIn is POST /v1/sign-in (plan 9e; spec §13 decision 47): a person's
// directory name, password and TOTP code, exchanged for 9b's certificate,
// or, for a person with no second factor inside a window, an enrollment.
// The order is ruling D4's: the lost store, the source's limit, the entry,
// the principal's limit, the code (its step taken), the password. A lost
// enrollment store refuses before anything is counted or read (D7). Nothing
// in the body is ever echoed or logged.
func (b *Broker) signIn(w http.ResponseWriter, r *http.Request) {
	cfg := b.PasswordSignIn
	if cfg == nil || b.Issuer == nil || b.SignInDirectory == nil {
		writeError(w, http.StatusNotFound, "not_signing_in", "this broker takes no directory password "+
			"(broker.identity has no directory_password verifier)")
		return
	}
	s := &signInAttempt{b: b, w: w, now: b.Now(), src: sourcePrefix(r.RemoteAddr)}
	if b.enrollmentLost() != "" {
		s.storeLost()
		return
	}
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		writeError(w, http.StatusBadRequest, "bad_request", "a sign-in carries no client certificate")
		return
	}
	var req api.SignInRequest
	if !readSignInBody(w, r, &req, `{"name", "password", "code", "csr"}`) {
		return
	}
	pub, ok := s.csrKey(req.CSR) // 400 on a bad CSR, before anything is counted
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), holdTimeout)
	defer cancel()
	if !s.underSourceLimit(ctx, cfg) {
		return
	}
	name, ok := normalName(req.Name)
	if !ok {
		s.refuse("name")
		return
	}
	if strings.TrimSpace(req.Password) == "" { // never sent (Review Focus 1); no principal is known yet (M7)
		s.refuse("password")
		return
	}
	e, ok := s.entry(ctx, name, cfg)
	if !ok {
		return
	}
	if !s.underPrincipalLimit(ctx, cfg, e.Principal) {
		return
	}
	f, err := b.Enrollments.GetSecondFactor(ctx, e.Principal)
	switch {
	case errors.Is(err, store.ErrNotFound) || err == nil && f.State != store.SecondFactorActive:
		s.enrollOrRefuse(ctx, cfg, e, f, err == nil, req.Password, pub)
		return
	case errors.Is(err, store.ErrEnrollmentStoreLost):
		s.storeLost()
		return
	case err != nil:
		s.storeUnavailable(e.Principal, "second factor", err, "the broker could not read your second factor; "+
			"if this recurs, an operator runs `port49 directory reset-second-factor` for your account")
		return
	case f.EntryID != e.EntryID:
		// The one sentence to the caller (ruling 7); the broker's line, once an
		// hour, names the entries and reset-second-factor (ruling 12, I12).
		s.entryMoved(e, f.EntryID)
		return
	}
	if !s.issuable(e.Principal, e.EntryID) { // CanIssue with the principal, before the step is taken (C3)
		return
	}
	step, err := totp.Check(f.Secret, req.Code, s.now, f.LastStep)
	var skew *totp.Skewed
	switch {
	case errors.As(err, &skew):
		s.refuseSkew(e.Principal, skew.By)
		return
	case err != nil:
		s.refuseAs(e.Principal, "second_factor")
		return
	}
	// The step is taken before the password is tried (decision 47 ruling 5):
	// a code is one attempt at the password, whatever its answer, and two
	// sign-ins racing one code reach the directory once.
	f.LastStep = step
	switch err := b.Enrollments.SwapSecondFactor(ctx, f, f.Rev); {
	case errors.Is(err, store.ErrConflict):
		s.refuseAs(e.Principal, "second_factor")
		return
	case errors.Is(err, store.ErrEnrollmentStoreLost):
		s.storeLost()
		return
	case err != nil:
		s.storeUnavailable(e.Principal, "second factor", err, "") // 503 store_unavailable (I2)
		return
	}
	if !s.password(ctx, e, req.Password) {
		return
	}
	s.succeeded(ctx, cfg, e.Principal)
	s.issue(pub, e.Principal, e.EntryID)
}

// windowOpen is whether enrollment is open for the person e names, whose
// record is f when exists (C5): the rollout window, a new entry's, a reopened
// record's, or reset --all's. Only the last reads the store, and only when
// the others are closed; it has answered, and returns false, when the store
// is lost or does not answer.
func (s *signInAttempt) windowOpen(ctx context.Context, cfg *oidc.PasswordSignIn, e directory.SignInEntry,
	f store.SecondFactor, exists bool) (open, answered bool) {
	switch {
	case cfg.OpenUntil.After(s.now):
		return true, false
	case cfg.NewEntriesFor > 0 && !e.CreatedAt.IsZero() && s.now.Before(e.CreatedAt.Add(cfg.NewEntriesFor)):
		return true, false
	case exists && f.State == store.SecondFactorReopened && f.Until.After(s.now):
		return true, false
	}
	m, err := s.b.Enrollments.GetEnrollmentMark(ctx)
	switch {
	case errors.Is(err, store.ErrEnrollmentStoreLost), errors.Is(err, store.ErrNotFound):
		s.storeLost()
		return false, true
	case err != nil:
		s.storeUnavailable(e.Principal, "enrollment", err, "")
		return false, true
	}
	return m.ReopenAllUntil.After(s.now), false
}

// enrollOrRefuse is a person with no active second factor: inside a window,
// the right password starts an enrollment; outside every window, any
// password is 403, and nothing is bound (C5).
func (s *signInAttempt) enrollOrRefuse(ctx context.Context, cfg *oidc.PasswordSignIn, e directory.SignInEntry,
	f store.SecondFactor, exists bool, password string, pub crypto.PublicKey) {
	b := s.b
	open, answered := s.windowOpen(ctx, cfg, e, f, exists)
	switch {
	case answered:
		return
	case !open:
		// Counted as a failure: it was counted before it was judged.
		s.rec(decision.EventIssue, decision.EnrollmentClosed, e.Principal, decision.SignIn{Failed: "enrollment"})
		b.Metrics.SignIns.WithLabelValues("enrollment_closed").Inc()
		writeError(s.w, http.StatusForbidden, string(decision.EnrollmentClosed), closedText)
		return
	}
	// An enrolling person has only the password.
	if !s.password(ctx, e, password) || !s.issuable(e.Principal, e.EntryID) {
		return
	}
	account := strings.TrimPrefix(e.Principal, "user:")
	if strings.Contains(cfg.TOTPLabel, ":") || strings.Contains(account, ":") {
		// A ':' would move the label's end in the otpauth URI: no authenticator
		// would read it as this account's.
		b.sayOnce("sign_in_totp_label "+e.Principal, time.Hour, "sign-in: %s cannot be enrolled: a ':' is in the "+
			"totp_label or the account, and an authenticator reads one as the label's end", printsafe.Line(e.Principal, 300))
		s.rec(decision.EventIssue, decision.SignInRefused, e.Principal, decision.SignIn{Failed: "enrollment"})
		b.Metrics.SignIns.WithLabelValues("refused").Inc()
		writeError(s.w, http.StatusServiceUnavailable, "enrollment_unavailable", "the broker cannot enroll your "+
			"account's second factor; tell the operator (the broker's log says why)")
		return
	}
	secret, err := totp.NewSecret()
	if err != nil {
		s.storeUnavailable(e.Principal, "secret", err, "")
		return
	}
	until := s.now.Add(enrollFor) // once (M14): the record's end, the handle's and the answer's
	rec := store.SecondFactor{Principal: e.Principal, State: store.SecondFactorPending, EntryID: e.EntryID,
		Secret: secret, Until: until}
	rev := uint64(0)
	if exists {
		rev = f.Rev
	}
	switch err := b.Enrollments.SwapSecondFactor(ctx, rec, rev); {
	case errors.Is(err, store.ErrConflict):
		s.refuseAs(e.Principal, "enrollment")
		return
	case errors.Is(err, store.ErrEnrollmentStoreLost):
		s.storeLost()
		return
	case err != nil:
		s.storeUnavailable(e.Principal, "second factor", err, "")
		return
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		s.storeUnavailable(e.Principal, "handle", err, "")
		return
	}
	handle := base64.RawURLEncoding.EncodeToString(raw)
	if _, err := b.Store.PutOnce(ctx, handleKey(handle), []byte(e.Principal), until.Sub(s.now)); err != nil {
		s.storeUnavailable(e.Principal, "handle", err, "")
		return
	}
	b.Metrics.SignIns.WithLabelValues("enrollment_started").Inc()
	s.w.Header().Set("Cache-Control", "no-store") // the answer holds a secret (M8)
	writeJSON(s.w, http.StatusAccepted, api.EnrollResponse{Enroll: api.Enrollment{Handle: handle,
		URI: totp.URI(secret, cfg.TOTPLabel, account), ConfirmBy: decision.FormatTime(until)}})
}

// signInConfirm is POST /v1/sign-in/confirm: the first code of an
// enrollment, under the handle its sign-in answered. The handle is taken
// once; a refusal that is not the person's last word puts it back.
func (b *Broker) signInConfirm(w http.ResponseWriter, r *http.Request) {
	cfg := b.PasswordSignIn
	if cfg == nil || b.Issuer == nil || b.SignInDirectory == nil {
		writeError(w, http.StatusNotFound, "not_signing_in", "this broker takes no directory password "+
			"(broker.identity has no directory_password verifier)")
		return
	}
	s := &signInAttempt{b: b, w: w, now: b.Now(), src: sourcePrefix(r.RemoteAddr)}
	if b.enrollmentLost() != "" {
		s.storeLost()
		return
	}
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		writeError(w, http.StatusBadRequest, "bad_request", "a sign-in carries no client certificate")
		return
	}
	var req api.ConfirmRequest
	if !readSignInBody(w, r, &req, `{"handle", "code", "csr"}`) {
		return
	}
	pub, ok := s.csrKey(req.CSR)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), holdTimeout)
	defer cancel()
	if !s.underSourceLimit(ctx, cfg) {
		return
	}
	key := handleKey(req.Handle)
	held, err := b.Store.TakeOnce(ctx, key)
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.refuseWith("", decision.SignIn{Failed: "enrollment"}, endedText)
		return
	case err != nil:
		s.storeUnavailable("", "handle", err, "")
		return
	}
	principal := string(held)
	// putBack is the handle returned for what is left of its enrollment, after
	// a refusal that is not the person's last word (M10).
	var until time.Time
	putBack := func() {
		if ttl := until.Sub(s.now); ttl > 0 {
			if _, err := b.Store.PutOnce(ctx, key, held, ttl); err != nil {
				b.sayOnce("sign_in_handle", sayEvery, "sign-in: an enrollment's handle could not be put back: %s",
					printsafe.Line(err.Error(), 300))
			}
		}
	}
	f, err := b.Enrollments.GetSecondFactor(ctx, principal)
	switch {
	case errors.Is(err, store.ErrNotFound), err == nil && (f.State != store.SecondFactorPending || !f.Until.After(s.now)):
		s.refuseWith(principal, decision.SignIn{Failed: "enrollment"}, endedText)
		return
	case errors.Is(err, store.ErrEnrollmentStoreLost):
		s.storeLost()
		return
	case err != nil:
		s.storeUnavailable(principal, "second factor", err, "")
		return
	}
	until = f.Until
	if !s.underPrincipalLimit(ctx, cfg, principal) {
		putBack()
		return
	}
	if !s.issuable(principal, f.EntryID) {
		putBack()
		return
	}
	step, err := totp.Check(f.Secret, req.Code, s.now, 0)
	var skew *totp.Skewed
	switch {
	case errors.As(err, &skew):
		putBack()
		s.refuseSkew(principal, skew.By)
		return
	case err != nil:
		putBack()
		s.refuseAs(principal, "second_factor")
		return
	}
	entryID := f.EntryID
	f.State, f.LastStep, f.EnrolledAt, f.EnrolledFrom, f.Until = store.SecondFactorActive, step, s.now, s.src, time.Time{}
	switch err := b.Enrollments.SwapSecondFactor(ctx, f, f.Rev); {
	case errors.Is(err, store.ErrConflict):
		s.refuseAs(principal, "enrollment")
		return
	case errors.Is(err, store.ErrEnrollmentStoreLost):
		s.storeLost()
		return
	case err != nil:
		s.storeUnavailable(principal, "second factor", err, "")
		return
	}
	sign := s.signOf(principal, entryID)
	b.Metrics.SignIns.WithLabelValues("enrolled").Inc()
	b.emit(decision.Record{TS: s.now, Event: decision.EventEnroll, Verdict: decision.VerdictPermit,
		Reason: decision.SecondFactorEnrolled, Principal: principal,
		Auth:   &decision.Auth{Method: signInMethod, DirectoryPassword: directoryPasswordAuth(sign)},
		SignIn: &decision.SignIn{Source: s.src}})
	s.succeeded(ctx, cfg, principal)
	s.issue(pub, principal, entryID)
}

// enrollmentLost is why password sign-in is refused, "" when it is not: the
// lost state, and no enrollment store at all.
func (b *Broker) enrollmentLost() string {
	if why := b.EnrollmentStoreLost(); why != "" {
		return why
	}
	if b.Enrollments == nil {
		return "this broker has no enrollment store"
	}
	return ""
}

// EnrollmentStoreLost is why password sign-in is refused, "" when it is not.
func (b *Broker) EnrollmentStoreLost() string {
	b.enrollMu.Lock()
	defer b.enrollMu.Unlock()
	return b.enrollLost
}

// CheckEnrollmentStore is the start's and each scheduled pass's look at the
// enrollment store (D7): its mark present is well (gauge 1, lost cleared);
// no mark (ErrNotFound, a new install included) or a store that will not
// open (ErrEnrollmentStoreLost) is lost (gauge 0, one error line naming
// init-enrollments, import and reset-second-factor --all). It never
// creates the mark. A store that does not answer is not lost: the state and
// the gauge stay as they were, and the next pass looks again; its error is
// returned.
func (b *Broker) CheckEnrollmentStore(ctx context.Context) error {
	if b.Enrollments == nil {
		return errors.New("broker: no enrollment store is configured")
	}
	_, err := b.Enrollments.GetEnrollmentMark(ctx)
	var why string
	switch {
	case err == nil:
	case errors.Is(err, store.ErrNotFound):
		why = "it holds no creation mark"
	case errors.Is(err, store.ErrEnrollmentStoreLost):
		why = printsafe.Line(err.Error(), 300)
	default:
		return err
	}
	b.enrollMu.Lock()
	b.enrollLost = why
	say := why != "" && why != b.enrollLostSaid
	b.enrollLostSaid = why
	b.enrollMu.Unlock()
	if why == "" {
		b.Metrics.DirectoryEnrollmentStoreOK.WithLabelValues().Set(1)
		return nil
	}
	b.Metrics.DirectoryEnrollmentStoreOK.WithLabelValues().Set(0)
	if say {
		b.say("sign-in: the enrollment store is lost (%s): password sign-in is refused until an operator acts. On a "+
			"new install run `port49 directory init-enrollments` once; if this broker has enrolled people, restore "+
			"the store (`port49 directory import`, or the etcd snapshot) or run `port49 directory "+
			"reset-second-factor --all`", why)
	}
	return nil
}
