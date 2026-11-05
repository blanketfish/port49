package broker

import (
	"context"
	"net/http"
	"time"
)

// oidcPartialRefreshText answers a refresh whose challenge is spent and whose
// extension did not finish: a retry with the same token is refused, so the
// text asks for a new challenge, not a retry.
const oidcPartialRefreshText = "the broker could not finish extending your live sessions; some may have been " +
	"extended; ask for a new challenge (run `port49 refresh` again) after Retry-After and it reports them all"

// markExtended marks every context rep extended, context by context, after a
// logout landed during the refresh (pre-flight I-2). The logout's passes may
// have run before the new sid was indexed, and a logout leaves no standing
// mark (Ruling 13), so what this refresh extended is marked here. A sid-less
// token indexed nothing, and the loop does not need the index.
func (b *Broker) markExtended(ctx context.Context, c caller, rep SessionRefreshReport) {
	at := b.Now()
	var failed error
	for _, s := range rep.Sessions {
		if s.Outcome != "extended" {
			continue
		}
		if _, err := b.revokeOwnContext(ctx, c.principal, s.Ref, at); err != nil && failed == nil {
			failed = err
		}
	}
	if failed != nil {
		b.say("logout: a session %s's refresh extended could not be marked after a logout landed during it "+
			"(%v); %s", c.principal, failed, b.logoutRecovery(c.principal))
	}
}

// logoutRecovery is what an operator does about a session a logout may have
// left extended. A logout is not a ban: the person may log in again once
// clock_skew has passed after the logout (spec §5.1.4; the refusal names the
// time), so the tail ends their contexts and lifts the mark that does it
// (spec §5.1.4: a mark stands until an operator lifts it). With no admin
// socket there is no revoke to run: the cut is the grants, as unrecordedNote
// says.
func (b *Broker) logoutRecovery(principal string) string {
	return "if the decision log has a revoke record with origin backchannel_logout for " + principal +
		" just before this line, " + b.endThenLift(principal, "its")
}

// endThenLift is how an operator ends principal's contexts once a logout
// record refuses the held ID token: revoke, then lift at once. its names the
// principal's contexts in the sentence ("its", or the principal's own).
func (b *Broker) endThenLift(principal, its string) string {
	return "end " + its + " contexts with `port49 revoke --principal " + principal + "`, then `port49 revoke --lift " +
		"--principal " + principal + "` so they may log in again; a lift can be lost across a " + b.proc() +
		" stop, so last check that `port49 revoke --list` shows no mark for " + principal
}

// failedRefresh answers a refresh whose extension failed part way. The
// contexts already extended are checked against the logouts again as a
// finished refresh's are (pre-flight I-2): the provider was answered 200 for
// its logout and will not send it again. text is the 503's: the bearer path
// asks for a new challenge, the certificate path for a retry.
func (b *Broker) failedRefresh(ctx context.Context, w http.ResponseWriter, now time.Time, c caller,
	rep SessionRefreshReport, text string) {
	extended := false
	for _, s := range rep.Sessions {
		extended = extended || s.Outcome == "extended"
	}
	if extended {
		l, out, err := b.loggedOut(ctx, *c.oidc)
		switch {
		case err != nil:
			b.say("logout: the logouts could not be read again after a refresh of %s failed part way (%v); a session "+
				"it extended may have outlived a logout that landed during it; %s", c.principal, err,
				b.logoutRecovery(c.principal))
		case out:
			b.markExtended(ctx, c, rep)
			b.Metrics.SessionRefreshes.WithLabelValues("refused").Inc()
			b.answerLoggedOut(w, l)
			return
		}
	}
	b.refreshStoreError(w, now, c.principal, c.cred, c.auth().OIDC, nil, refreshEvery, text)
}
