package broker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/policy"
	"github.com/rhwendt/port49/internal/store"
)

// maxExplainCommand bounds a command explain is asked: a line a person
// types, with room.
const maxExplainCommand = 1024

// explain is POST /v1/explain (design §17; decision 34): the broker's
// answer for one device, from the policy in force, as it would mint and the
// daemon decide (policy.Explain, the evaluator port49 explain runs). It is
// about the caller unless the request names another principal, which needs
// explain_others. A device the inventory does not name is answered exactly
// as one the principal has no grant on, and neither names a platform: the
// API tells no caller which devices exist. A principal under a mark is
// credential_revoked. One explain record, which names the bundle that
// answered and never holds the command.
func (b *Broker) explain(w http.ResponseWriter, r *http.Request) {
	caller, cred, ok := b.authenticate(w, r, decision.EventExplain, "explained nothing")
	if !ok {
		return
	}
	var req api.ExplainRequest
	// Past the bound the body is refused, not read in part: a trailing byte
	// beyond it would otherwise go unseen.
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	dec.DisallowUnknownFields()
	err := dec.Decode(&req)
	if err == nil {
		// One object and nothing after it, as tokensRevoke reads its body.
		if _, terr := dec.Token(); terr != io.EOF {
			err = errors.New("trailing data")
		}
	}
	if err != nil || !deviceName(req.Device) || !commandLine(req.Command) {
		writeError(w, http.StatusBadRequest, "bad_request", fmt.Sprintf("name a device (1 to %d printable ASCII "+
			"characters) and, if you like, a command of at most %d printable characters", maxDeviceName,
			maxExplainCommand))
		return
	}
	about := caller
	if req.Principal != "" {
		p, err := normalPrincipal(req.Principal)
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_request", "the principal is not one the broker spells: "+
				"user: and an email, or app: and a client id, as the log names it")
			return
		}
		about = p
	}
	now := b.Now()
	pol := b.Policy.Load()
	// No auth: principal is whom it was about, and the caller's credential
	// is in explain.asked_by_fingerprint, so a record's auth and principal
	// always describe one credential (decision 34; pre-flight I8).
	rec := decision.Record{TS: now, Event: decision.EventExplain, Principal: about,
		Device: &decision.Device{Name: req.Device}, Policy: &decision.Policy{Bundle: pol.Bundle},
		Explain: &decision.Explain{AskedBy: caller, AskedByFingerprint: cred.Fingerprint, Command: req.Command != ""}}
	if about != caller {
		// The caller's own membership: a refusal is the caller's, recorded
		// and answered as a mint's is (their certificate, their connection).
		ctx, cancel := context.WithTimeout(r.Context(), b.memberBudget())
		callerMember, _, err := b.memberFor(ctx, caller)
		cancel()
		if err != nil {
			ref := directoryRefusal(err)
			b.emit(decision.Record{TS: now, Event: decision.EventExplain, Verdict: decision.VerdictDeny,
				Reason: ref.Reason, Principal: caller,
				Auth: &decision.Auth{Method: cred.Method, Fingerprint: cred.Fingerprint}})
			b.answerRefusal(w, r, ref)
			return
		}
		if !pol.HasRightOf(callerMember, policy.RightExplainOthers) {
			b.refuseRight(w, rec, policy.RightExplainOthers, "explaining another principal")
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), holdTimeout)
	rv, revoked, err := b.revocation(ctx, about, store.Credential{})
	cancel()
	if err != nil {
		rec.Verdict, rec.Reason = decision.VerdictDeny, decision.StoreUnavailable
		b.emit(rec)
		writeError(w, http.StatusServiceUnavailable, string(decision.StoreUnavailable),
			"the broker could not read the revocations in force, so it explained nothing; try again")
		return
	}
	// A principal under a mark is answered from the mark alone: nothing
	// would be minted for it, so the policy is not asked, and a fault there
	// is not its answer.
	var e policy.Explanation
	if revoked {
		e = policy.Explanation{Subject: about, Device: req.Device, Command: req.Command, Revoked: rv.At}
	} else {
		ctx, cancel := context.WithTimeout(r.Context(), b.memberBudget())
		aboutMember, _, merr := b.memberFor(ctx, about)
		cancel()
		if merr != nil {
			// The directory's "no" about the principal asked about is the
			// answer, not a refusal of the caller: 200, the connection kept.
			ref := directoryRefusal(merr)
			if about == caller {
				// Their own membership: the caller's refusal, as a mint's.
				b.emit(decision.Record{TS: now, Event: decision.EventExplain, Verdict: decision.VerdictDeny,
					Reason: ref.Reason, Principal: caller,
					Auth: &decision.Auth{Method: cred.Method, Fingerprint: cred.Fingerprint}})
				b.answerRefusal(w, r, ref)
				return
			}
			rec.Verdict, rec.Reason = decision.VerdictDeny, ref.Reason
			b.emit(rec)
			writeJSON(w, http.StatusOK, api.ExplainResponse{Principal: about, Device: req.Device,
				Verdict: decision.VerdictDeny, Reason: string(ref.Reason),
				Text: fmt.Sprintf("%s would be refused %s: the directory's answer about %s, not about you", about,
					ref.Reason, about)})
			return
		}
		rec.Policy.Subject, rec.Policy.Subjects = subjectNames(pol, aboutMember)
		e, err = explanationOf(pol, aboutMember, req.Device, req.Command, now)
	}
	if err != nil {
		// The mint refuses the same fault with this item error, which is no
		// decision; the call is still recorded (decision 34).
		rec.Device.Platform = e.Platform
		rec.Explain.MintError = "broker_error"
		b.Log.Emit(rec)
		b.logf("broker: explaining %s on %q: %v", about, req.Device, err)
		writeError(w, http.StatusInternalServerError, "broker_error",
			"the broker could not explain this; tell the operator")
		return
	}
	verdict, reason, mintErr := e.Answer()
	rec.Verdict, rec.Reason = verdict, reason
	rec.Device.Platform = e.Platform
	rec.Explain.MintError = mintErr
	if reason == "" {
		b.Log.Emit(rec) // a mint error is no decision, and is not counted as one
	} else {
		b.emit(rec)
	}
	var text strings.Builder
	e.Redacted(pol.Redactions()).RenderWithoutAttributes(&text)
	out := api.ExplainResponse{Principal: about, Subject: e.Subject, Device: req.Device,
		Platform: e.Platform, Verdict: verdict, Reason: string(reason), MintError: mintErr, Text: text.String()}
	if revoked {
		out.Subject = "" // the mark is on the principal; no subject was resolved
	}
	writeJSON(w, http.StatusOK, out)
}

// explanationOf is explanationIn, swapped in tests for a policy fault no
// loaded policy can be made to have.
var explanationOf = explanationIn

// explanationIn is pol's answer for principal on device. A device the
// inventory does not name is no_grants_matched, built here because
// policy.Explain names a missing device (an offline tool's operator holds
// the inventory); a no-grant answer carries no platform.
func explanationIn(pol *policy.Policy, m policy.Member, device, line string, now time.Time) (policy.Explanation, error) {
	subject := m.Principal
	if names := pol.SubjectsOf(m); len(names) > 0 {
		subject = strings.Join(names, ", ")
	}
	if _, ok := pol.Device(device); !ok {
		return policy.Explanation{Subject: subject, Device: device, Command: line, NoGrants: true}, nil
	}
	e, err := pol.ExplainMember(m, device, line, now)
	if err != nil {
		return e, err
	}
	if e.NoGrants {
		e.Platform = ""
	}
	return e, nil
}

// commandLine reports whether s can be a command explain is asked: at most
// maxExplainCommand bytes of printable ASCII and spaces. Empty is the
// session.
func commandLine(s string) bool {
	return len(s) <= maxExplainCommand && strings.IndexFunc(s, func(r rune) bool { return r < 0x20 || r > 0x7e }) < 0
}
