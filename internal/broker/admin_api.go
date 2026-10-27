package broker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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

// The admin endpoints (spec §2, §5.1.4, §5.1.6; plan 12b): each write is
// refused 403 api_right_missing without its right, then asks for a touch
// bound to its own request, then runs. In that order, so a caller without the
// right never presses the key, and a refused proof changes nothing. The
// answers carry the text the admin socket printed (api.AdminResult).

// importReadTimeout is api.ImportReadTimeout, a variable so a test can shorten it.
var importReadTimeout = api.ImportReadTimeout

// maxAdminBody bounds a small admin request's JSON body.
const maxAdminBody = 4 << 10

// readAdminBody reads r's body once, at most max bytes: an admin proof is
// made for these exact bytes. Over max it answers 413 without reading on, and
// issues no challenge.
func readAdminBody(w http.ResponseWriter, r *http.Request, max int64) ([]byte, bool) {
	if r.ContentLength > max {
		w.Header().Set("Connection", "close")
		writeError(w, http.StatusRequestEntityTooLarge, "payload_too_large", fmt.Sprintf("the body is over %d bytes",
			max))
		return nil, false
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, max))
	var tooBig *http.MaxBytesError
	switch {
	case errors.As(err, &tooBig):
		w.Header().Set("Connection", "close")
		writeError(w, http.StatusRequestEntityTooLarge, "payload_too_large", fmt.Sprintf("the body is over %d bytes",
			max))
		return nil, false
	case err != nil:
		writeError(w, http.StatusBadRequest, "bad_request", "the body did not arrive whole")
		return nil, false
	}
	return body, true
}

// decodeAdminBody decodes body as one JSON object into v, refusing an unknown
// field or anything after the object, which would otherwise be dropped unread.
func decodeAdminBody(body []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing data")
	}
	return nil
}

// adminRight reports whether the caller's subject declares one of rights,
// read once from the policy in force. When it does not it has answered: 403
// api_right_missing, recorded as rec (an event of the call's own), or the
// directory's refusal. rec names what the call was about; the caller is the
// record's origin.
func (b *Broker) adminRight(w http.ResponseWriter, r *http.Request, c caller, rec decision.Record, rights []string,
	what string) bool {
	pol := b.Policy.Load()
	ctx, cancel := context.WithTimeout(r.Context(), b.memberBudget())
	defer cancel()
	m, _, err := b.memberFor(ctx, c.principal)
	if err != nil {
		ref := directoryRefusal(err)
		rec.Verdict, rec.Reason = decision.VerdictDeny, ref.Reason
		b.emit(rec)
		b.answerRefusal(w, r, ref)
		return false
	}
	if slices.ContainsFunc(rights, func(right string) bool { return pol.HasRightOf(m, right) }) {
		return true
	}
	b.refuseRight(w, rec, strings.Join(rights, " or "), what)
	return false
}

// adminFailed answers an operation that ran after its proof and refused or
// failed: 409 admin_operation_failed with the operation's own text, for an
// operator, and the whole error in the process's log.
func (b *Broker) adminFailed(w http.ResponseWriter, op string, err error) {
	b.logf("broker: the admin operation %s did not run: %v", op, err)
	writeError(w, http.StatusConflict, "admin_operation_failed",
		printsafe.Line(strings.TrimPrefix(err.Error(), "broker: "), 600))
}

// adminUnavailable answers a call whose operation cannot run on this broker
// (no directory, no directory_password verifier): 409 admin_operation_failed,
// after the right and before any challenge, so a rightless caller learns
// nothing and no key press is spent on it. The text is the broker's own
// about itself, or names a principal the caller has validated.
func (b *Broker) adminUnavailable(w http.ResponseWriter, op string, err error) {
	b.adminFailed(w, op, err)
}

// certTargetOf is the target a challenge shows for a certificate: its issuer
// and serial, as the broker compares them.
func certTargetOf(req RevokeRequest) string { return req.Issuer + " serial " + req.Serial }

// revokeCertificate is the certificate form of POST /v1/tokens/revoke: a
// standing mark on one certificate, under revoke_others and a touch, its
// origin the caller (spec §5.1.4).
func (b *Broker) revokeCertificate(w http.ResponseWriter, r *http.Request, pol *policy.Policy, asker, origin string,
	req api.RevokeRequest, mayOthers func() (bool, *BindRefusal), refused func(*BindRefusal, decision.Record),
	gate func(op, target string) bool) {
	rr, _, _, err := RevokeRequest{Issuer: req.CertIssuer, Serial: req.CertSerial}.normal()
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", strings.TrimPrefix(err.Error(), "broker: "))
		return
	}
	rr.Origin = origin
	now := b.Now()
	rec := decision.Record{TS: now, Event: decision.EventRevoke, Revocation: &decision.Revocation{By: ByCert,
		Issuer: rr.Issuer, Serial: rr.Serial, At: decision.FormatTime(now), Origin: origin}}
	switch ok, ref := mayOthers(); {
	case ref != nil:
		refused(ref, rec)
		return
	case !ok:
		b.refuseRight(w, rec, policy.RightRevokeOthers, "revoking a certificate")
		return
	}
	if !gate("revoke_certificate", certTargetOf(rr)) {
		return
	}
	b.runRevoke(w, r, pol, rr, asker, origin)
}

// revocationsLift is POST /v1/revocations/lift: a principal, or a
// certificate by its issuer and serial, under lift_revocations and a touch.
// revoke_others does not lift: a lift is the one call that weakens (spec §2).
func (b *Broker) revocationsLift(w http.ResponseWriter, r *http.Request) {
	c, ok := b.authenticate(w, r, decision.EventRevoke, "lifted nothing")
	if !ok {
		return
	}
	body, ok := readAdminBody(w, r, maxAdminBody)
	if !ok {
		return
	}
	// The right is fixed by the route, so it is checked before the body is
	// judged: a caller without it learns nothing and leaves a record, whatever
	// it sent. The record names the target only when the body gives one.
	origin := "api " + c.principal
	now := b.Now()
	rec := decision.Record{TS: now, Event: decision.EventRevoke,
		Revocation: &decision.Revocation{By: ByPrincipal, At: decision.FormatTime(now), Origin: origin}}
	var (
		req    api.LiftRequest
		rr     RevokeRequest
		kind   string
		target string
	)
	bad := "the body is not a lift: name a principal, or a certificate's cert_issuer and cert_serial"
	if decodeAdminBody(body, &req) == nil {
		var err error
		rr, kind, _, err = RevokeRequest{Principal: req.Principal, Issuer: req.CertIssuer, Serial: req.CertSerial}.normal()
		if err != nil {
			bad = strings.TrimPrefix(err.Error(), "broker: ")
		} else {
			bad = ""
			target = rr.Principal
			if kind == store.RevocationCert {
				rec.Revocation.By, rec.Revocation.Issuer, rec.Revocation.Serial = ByCert, rr.Issuer, rr.Serial
				target = certTargetOf(rr)
			} else {
				rec.Principal = rr.Principal
			}
		}
	}
	if !b.adminRight(w, r, c, rec, []string{policy.RightLiftRevocations}, "lifting a revocation") {
		return
	}
	if bad != "" {
		writeError(w, http.StatusBadRequest, "bad_request", bad)
		return
	}
	if !b.adminGate(w, r, c, body, "lift", target) {
		return
	}
	rr.Origin = origin
	// The wait for the revocation slot is bounded; once Lift holds it, it
	// runs to the end detached from this request (Lift's comment).
	wait, cancel := context.WithTimeout(r.Context(), revokeSlotWait)
	defer cancel()
	rep, err := b.Lift(wait, rr)
	switch {
	case errors.Is(err, ErrBadRevocation):
		writeError(w, http.StatusBadRequest, "bad_request", strings.TrimPrefix(err.Error(), "broker: "))
	case errors.Is(err, ErrNotRevoked):
		writeError(w, http.StatusNotFound, "not_revoked", "no such revocation is in force (`port49 revoke --list`)")
	case errors.Is(err, ErrRevocationBusy):
		writeBusy(w, "another revocation or lift is still running, so nothing was lifted; try again")
	case err != nil:
		b.adminFailed(w, "lift", err)
	default:
		if b.OnLift != nil {
			b.OnLift(rep.Mark)
		}
		writeJSON(w, http.StatusOK, api.AdminResult{Text: rep.LiftedText(), Partial: rep.Partial()})
	}
}

// revocationsList is GET /v1/revocations: every mark in force, as `port49
// revoke --list` prints it. It reads, so it needs revoke_others or
// lift_revocations and no touch (spec §2).
func (b *Broker) revocationsList(w http.ResponseWriter, r *http.Request) {
	c, ok := b.authenticate(w, r, decision.EventRevoke, "listed nothing")
	if !ok {
		return
	}
	rec := decision.Record{TS: b.Now(), Event: decision.EventRevoke, Principal: c.principal}
	if !b.adminRight(w, r, c, rec, []string{policy.RightRevokeOthers, policy.RightLiftRevocations},
		"listing the revocations") {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), holdTimeout)
	defer cancel()
	rs, err := b.Store.ListRevocations(ctx)
	if err != nil {
		b.logf("broker: the revocations in force could not be read for %s: %v", c.principal, err)
		w.Header().Set("Retry-After", "10")
		writeError(w, http.StatusServiceUnavailable, string(decision.StoreUnavailable),
			"the revocations in force could not be read; try again")
		return
	}
	lifts := map[[2]string]*store.Lift{}
	liftErr := map[[2]string]error{}
	liftOf := func(kind, key string) (store.Lift, error) {
		k := [2]string{kind, key}
		if l, ok := lifts[k]; ok {
			return *l, nil
		}
		if err, ok := liftErr[k]; ok {
			return store.Lift{}, err
		}
		l, err := b.Store.GetLift(ctx, kind, key)
		if err != nil {
			liftErr[k] = err
			return store.Lift{}, err
		}
		lifts[k] = &l
		return l, nil
	}
	out := api.RevocationList{Marks: []api.Revocation{}, Text: RevocationsText(rs, liftOf)}
	for _, m := range rs {
		mark := api.Revocation{Since: m.At.UTC().Format(time.RFC3339), Origin: m.Origin, LandedAfterLift: m.LandedAfterLift}
		if i := strings.LastIndex(m.Key, "|"); m.Kind == store.RevocationCert && i >= 0 {
			mark.Kind, mark.CertIssuer, mark.CertSerial = "cert", m.Key[:i], m.Key[i+1:]
		} else {
			mark.Kind, mark.Principal = "principal", m.Key
		}
		if m.LandedAfterLift {
			if l, err := liftOf(m.Kind, m.Key); err == nil {
				mark.LiftAt, mark.LiftRevision = l.At.UTC().Format(time.RFC3339), l.Revision
			}
		}
		out.Marks = append(out.Marks, mark)
	}
	writeJSON(w, http.StatusOK, out)
}

// adminDirectory is what directoryHead found: the caller, the exact body bytes
// a proof is made for, and the origin the call's records carry.
type adminDirectory struct {
	c      caller
	body   []byte
	origin string
	// decodeFailed: the body is not the call's JSON object.
	decodeFailed bool
}

// directoryHead authenticates the caller under the call's event and reads a
// small JSON body, decoding it into v; it has answered when it returns false.
// A body that does not decode is not answered here: the right is checked
// first, so decodeFailed is left to the caller to answer after it.
func (b *Broker) directoryHead(w http.ResponseWriter, r *http.Request, event string, v any) (adminDirectory, bool) {
	c, ok := b.authenticate(w, r, event, "did nothing")
	if !ok {
		return adminDirectory{}, false
	}
	body, ok := readAdminBody(w, r, maxAdminBody)
	if !ok {
		return adminDirectory{}, false
	}
	return adminDirectory{c: c, body: body, origin: "api " + c.principal, decodeFailed: decodeAdminBody(body, v) != nil}, true
}

// directoryForget is POST /v1/directory/forget (forget_principals, a touch).
func (b *Broker) directoryForget(w http.ResponseWriter, r *http.Request) {
	var req api.PrincipalRequest
	d, ok := b.directoryHead(w, r, decision.EventDirectoryForget, &req)
	if !ok {
		return
	}
	var principal string
	bad := "the body names a principal"
	if !d.decodeFailed {
		var err error
		if principal, err = normalPrincipal(req.Principal); err != nil {
			bad = strings.TrimPrefix(err.Error(), "broker: ")
		} else {
			bad = ""
		}
	}
	rec := decision.Record{TS: b.Now(), Event: decision.EventDirectoryForget, Principal: principal,
		Forget: &decision.Forget{Origin: d.origin}}
	if !b.adminRight(w, r, d.c, rec, []string{policy.RightForgetPrincipals}, "forgetting a directory pin") {
		return
	}
	if bad != "" {
		writeError(w, http.StatusBadRequest, "bad_request", bad)
		return
	}
	if err := b.forgetUnavailable(principal); err != nil {
		b.adminUnavailable(w, "forget_principal", err)
		return
	}
	if !b.adminGate(w, r, d.c, d.body, "forget_principal", principal) {
		return
	}
	text, err := b.Forget(r.Context(), principal, d.origin)
	if err != nil {
		b.adminFailed(w, "forget_principal", err)
		return
	}
	writeJSON(w, http.StatusOK, api.AdminResult{Text: text})
}

// directoryResetSecondFactor is POST /v1/directory/reset-second-factor
// (reset_second_factor, a touch): one principal, or all.
func (b *Broker) directoryResetSecondFactor(w http.ResponseWriter, r *http.Request) {
	var req api.ResetSecondFactorRequest
	d, ok := b.directoryHead(w, r, decision.EventSecondFactorReset, &req)
	if !ok {
		return
	}
	op, target := "reset_second_factor", ""
	bad := "the body names a principal, or all"
	if !d.decodeFailed {
		switch {
		case req.All && req.Principal != "":
			bad = "name a principal or all, not both"
		case !req.All && req.Principal == "":
			bad = "name a principal, or all"
		case req.All:
			op, target, bad = "reset_second_factor_all", "all", ""
		default:
			if p, err := userPrincipal(req.Principal); err != nil {
				bad = strings.TrimPrefix(err.Error(), "broker: ")
			} else {
				target, bad = p, ""
			}
		}
	}
	rec := decision.Record{TS: b.Now(), Event: decision.EventSecondFactorReset,
		SecondFactorReset: &decision.SecondFactorReset{All: bad == "" && req.All, Origin: d.origin}}
	if bad == "" && !req.All {
		rec.Principal = target
	}
	if !b.adminRight(w, r, d.c, rec, []string{policy.RightResetSecondFactor}, "resetting a second factor") {
		return
	}
	if bad != "" {
		writeError(w, http.StatusBadRequest, "bad_request", bad)
		return
	}
	if err := b.signInOps(); err != nil {
		b.adminUnavailable(w, op, err)
		return
	}
	if !b.adminGate(w, r, d.c, d.body, op, target) {
		return
	}
	principal := target
	if req.All {
		principal = ""
	}
	text, err := b.ResetSecondFactor(r.Context(), principal, req.All, d.origin)
	if err != nil {
		b.adminFailed(w, op, err)
		return
	}
	writeJSON(w, http.StatusOK, api.AdminResult{Text: text})
}

// directoryUnlock is POST /v1/directory/unlock (unlock_sign_in, a touch).
func (b *Broker) directoryUnlock(w http.ResponseWriter, r *http.Request) {
	var req api.PrincipalRequest
	d, ok := b.directoryHead(w, r, decision.EventSignInUnlock, &req)
	if !ok {
		return
	}
	var principal string
	bad := "the body names a principal"
	if !d.decodeFailed {
		var err error
		if principal, err = userPrincipal(req.Principal); err != nil {
			bad = strings.TrimPrefix(err.Error(), "broker: ")
		} else {
			bad = ""
		}
	}
	rec := decision.Record{TS: b.Now(), Event: decision.EventSignInUnlock, Principal: principal,
		SignInUnlock: &decision.SignInUnlock{Origin: d.origin}}
	if !b.adminRight(w, r, d.c, rec, []string{policy.RightUnlockSignIn}, "clearing a sign-in lockout") {
		return
	}
	if bad != "" {
		writeError(w, http.StatusBadRequest, "bad_request", bad)
		return
	}
	if err := b.signInOps(); err != nil {
		b.adminUnavailable(w, "unlock_sign_in", err)
		return
	}
	if !b.adminGate(w, r, d.c, d.body, "unlock_sign_in", principal) {
		return
	}
	text, err := b.UnlockSignIn(r.Context(), principal, d.origin)
	if err != nil {
		b.adminFailed(w, "unlock_sign_in", err)
		return
	}
	writeJSON(w, http.StatusOK, api.AdminResult{Text: text})
}

// directoryImport is POST /v1/directory/import?replace=true|false
// (import_enrollments, a touch): the sealed export as the body, at most
// api.MaxImportBytes. It sets its own read deadline, since the server's,
// sized for a mint, would bound a 16 MiB body to about 4.5 Mbit/s (A-M7).
func (b *Broker) directoryImport(w http.ResponseWriter, r *http.Request) {
	c, ok := b.authenticate(w, r, decision.EventEnrollmentsImport, "imported nothing")
	if !ok {
		return
	}
	origin := "api " + c.principal
	rec := decision.Record{TS: b.Now(), Event: decision.EventEnrollmentsImport,
		EnrollmentsImport: &decision.EnrollmentsImport{Origin: origin}}
	if !b.adminRight(w, r, c, rec, []string{policy.RightImportEnrollments}, "importing the enrollment store") {
		return
	}
	replace, err := importReplace(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	if err := b.signInOps(); err != nil {
		b.adminUnavailable(w, "import_enrollments", err)
		return
	}
	// ErrNotSupported (a recorder in a test) is no reason to refuse.
	_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(importReadTimeout))
	body, ok := readAdminBody(w, r, api.MaxImportBytes)
	if !ok {
		return
	}
	// No deadline needs clearing here: net/http clears the connection's when
	// the body hits EOF (startBackgroundRead), so it never cancels r.Context
	// under the write below. TestAnImportWhoseBodyArrivesNearTheDeadlineStillWrites
	// pins that, should a later net/http change it.
	if len(bytes.TrimSpace(body)) == 0 {
		writeError(w, http.StatusBadRequest, "bad_request", "the body is the sealed export `port49-broker "+
			"export-enrollments` wrote: none arrived")
		return
	}
	sum := sha256.Sum256(body)
	mode := "merge"
	if replace {
		mode = "replace"
	}
	if !b.adminGate(w, r, c, body, "import_enrollments", mode+" "+hex.EncodeToString(sum[:])[:12]) {
		return
	}
	text, err := b.ImportEnrollments(r.Context(), body, replace, origin)
	if err != nil {
		b.adminFailed(w, "import_enrollments", err)
		return
	}
	writeJSON(w, http.StatusOK, api.AdminResult{Text: text})
}

// importReplace is the query's replace=true|false, false when absent. Any
// other parameter or value is refused: the query is part of the request a
// proof is made for, so it is never ignored.
func importReplace(r *http.Request) (bool, error) {
	q := r.URL.Query()
	for k := range q {
		if k != "replace" {
			return false, fmt.Errorf("the only parameter is replace=true or replace=false, not %q", printsafe.Line(k, 40))
		}
	}
	switch v := q["replace"]; {
	case len(v) == 0:
		return false, nil
	case len(v) == 1 && v[0] == "true":
		return true, nil
	case len(v) == 1 && v[0] == "false":
		return false, nil
	}
	return false, errors.New("replace is true or false")
}
