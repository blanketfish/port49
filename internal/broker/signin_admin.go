package broker

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"time"

	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/normal"
	"github.com/rhwendt/port49/internal/printsafe"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/crypt"
)

// The operator's side of the directory-password sign-in (plan 9e, decision
// 47 D7, D13): the scheduled re-seal, reset-second-factor (one person, or
// --all), unlock, init-enrollments, export and import. None of them writes
// or logs a secret: a record that is reopened with a pending secret is read
// as a record, never as corruption, and no operation here turns one into an
// active factor.

// signInOps is the common refusal of an operator op on a broker with no
// directory_password verifier or no enrollment store handle.
func (b *Broker) signInOps() error {
	switch {
	case b.PasswordSignIn == nil:
		return errors.New("broker: this broker has no directory_password verifier (broker.identity), so it holds no " +
			"second factors")
	case b.Enrollments == nil:
		return errors.New("broker: this broker has no enrollment store")
	}
	return nil
}

// userPrincipal is principal as the log spells a person's: user: and an
// email, lower-cased as Forget lowers it. Only a person signs in with a
// password.
func userPrincipal(principal string) (string, error) {
	n, err := normal.User(principal)
	if err != nil {
		return "", fmt.Errorf("broker: %w", err)
	}
	return n, nil
}

// lostRemedy is what an operator does about an enrollment store that is lost,
// the words every refusal of an operator op on one ends with.
const lostRemedy = "restore it (`port49 directory import`, or the etcd snapshot), or replace it with `port49 " +
	"directory reset-second-factor --all`; on a new install run `port49-broker init-enrollments`"

// ResealSecondFactors is the scheduled pass that seals every record and the
// mark that opened under the previous encryption key afresh under the current
// one, so encryption.previous can be retired (ruling 11). A record is
// swapped back unchanged at the revision it was read at: a reopened record
// that holds a pending secret keeps it, and an operator's write between the
// read and the swap (ErrConflict) is not an error, the next pass looks again.
// A record that will not open is said once per principal per hour, naming
// reset-second-factor, and is never deleted. It returns how many records
// and marks it sealed again; an error is a store that did not answer, or is
// lost.
func (b *Broker) ResealSecondFactors(ctx context.Context) (int, error) {
	if b.Enrollments == nil {
		return 0, errors.New("broker: no enrollment store is configured")
	}
	principals, err := b.Enrollments.SecondFactorPrincipals(ctx)
	if err != nil {
		return 0, err
	}
	var sealed, unopened int
	for _, p := range principals {
		f, err := b.Enrollments.GetSecondFactor(ctx, p)
		switch {
		case errors.Is(err, store.ErrNotFound):
			continue // deleted by an import since the listing
		case errors.Is(err, store.ErrEnrollmentStoreLost), errors.Is(err, store.ErrUnavailable), ctx.Err() != nil:
			return sealed, err
		case err != nil:
			unopened++
			b.sayOnce("sign_in_reseal "+p, time.Hour, "sign-in: %s's second factor does not open (%s): it is left as it "+
				"is; if the person cannot sign in, an operator runs `port49 directory reset-second-factor %s`",
				printsafe.Line(p, 300), printsafe.Line(err.Error(), 300), printsafe.Line(p, 300))
			continue
		case !f.Stale:
			continue
		}
		switch err := b.Enrollments.SwapSecondFactor(ctx, f, f.Rev); {
		case err == nil:
			sealed++
		case errors.Is(err, store.ErrConflict):
		default:
			return sealed, err
		}
	}
	if unopened > 0 {
		b.sayOnce("sign_in_reseal_unopened", time.Hour, "sign-in: the re-seal could not open %d second factors; "+
			"encryption.previous cannot be retired while they are sealed under it", unopened)
	}
	m, err := b.Enrollments.GetEnrollmentMark(ctx)
	switch {
	case err != nil && (errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrEnrollmentStoreLost)):
		return sealed, nil // lost: CheckEnrollmentStore says it
	case err != nil:
		return sealed, err
	case !m.Stale:
		return sealed, nil
	}
	// An operator's reset --all, an import or another replica's re-seal moved
	// the mark since it was read: theirs stands, and the next pass looks again.
	switch err := b.Enrollments.SwapEnrollmentMark(ctx, m, m.Rev); {
	case err == nil:
		sealed++
	case errors.Is(err, store.ErrConflict):
	default:
		return sealed, err
	}
	return sealed, nil
}

// ResetSecondFactor is `port49 directory reset-second-factor`: the person's
// record becomes reopened for reopen_for with no secret, so their next
// sign-in enrolls (the lost phone at 3am). A record that will not open is
// replaced too: the reset is the operator's way past it. It writes one
// second_factor_reset record naming origin and the enrollment it cleared,
// never its secret.
//
// With all (principal "") it is --all: it drops no active factor, puts the
// mark {CreatedAt: kept or now, ReopenAllUntil: now + reopen_for} (replacing a
// lost store, its unreadable file renamed aside and never deleted), clears the
// lost state, and records second_factor_reset {"all": true}.
func (b *Broker) ResetSecondFactor(ctx context.Context, principal string, all bool, origin string) (string, error) {
	if err := b.signInOps(); err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, holdTimeout)
	defer cancel()
	if all {
		if principal != "" {
			return "", errors.New("broker: reset-second-factor names a principal or --all, not both")
		}
		return b.resetAll(ctx, origin)
	}
	principal, err := userPrincipal(principal)
	if err != nil {
		return "", err
	}
	now := b.Now()
	until := now.Add(b.PasswordSignIn.ReopenFor)
	f, err := b.Enrollments.GetSecondFactor(ctx, principal)
	var was string
	rev := uint64(0)
	switch {
	case errors.Is(err, store.ErrNotFound):
		was = principal + " had no second factor"
	case errors.Is(err, store.ErrEnrollmentStoreLost):
		return "", fmt.Errorf("broker: the enrollment store is lost (%s): %s", lostWhy(err), lostRemedy)
	case err != nil && f.Rev != 0:
		// The record will not open (a retired key, a damaged record): its revision
		// came back with the error, so the reset replaces it.
		rev = f.Rev
		was = principal + "'s second factor did not open (" + printsafe.Line(err.Error(), 200) + ") and is replaced"
	case err != nil:
		b.logf("broker: resetting %s failed: %v", printsafe.Line(principal, 200), err)
		return "", fmt.Errorf("broker: resetting %s failed: the store did not answer, so nothing changed: run it again",
			printsafe.Line(principal, 200))
	default:
		rev = f.Rev
		switch f.State {
		case store.SecondFactorActive:
			was = fmt.Sprintf("reset %s's second factor (enrolled %s from %s)", principal,
				decision.FormatTime(f.EnrolledAt), printsafe.Line(f.EnrolledFrom, 80))
		default:
			was = fmt.Sprintf("reset %s's unconfirmed enrollment", principal)
		}
	}
	reopened := store.SecondFactor{Principal: principal, State: store.SecondFactorReopened, Until: until}
	switch err := b.Enrollments.SwapSecondFactor(ctx, reopened, rev); {
	case errors.Is(err, store.ErrConflict):
		return "", fmt.Errorf("broker: %s's record changed while it was being reset (a sign-in or another reset): "+
			"run it again", printsafe.Line(principal, 200))
	case errors.Is(err, store.ErrEnrollmentStoreLost):
		return "", fmt.Errorf("broker: the enrollment store is lost (%s): %s", lostWhy(err), lostRemedy)
	case err != nil:
		b.logf("broker: resetting %s failed: %v", printsafe.Line(principal, 200), err)
		return "", fmt.Errorf("broker: resetting %s failed: the store did not answer, so nothing changed: run it again",
			printsafe.Line(principal, 200))
	}
	rec := decision.SecondFactorReset{ReopenUntil: decision.FormatTime(until), Origin: origin}
	if rev != 0 && f.State == store.SecondFactorActive {
		rec.EnrolledAt, rec.EnrolledFrom = decision.FormatTime(f.EnrolledAt), f.EnrolledFrom
	}
	b.Log.Emit(decision.Record{TS: now, Event: decision.EventSecondFactorReset, Principal: principal,
		SecondFactorReset: &rec})
	b.say("sign-in: %s reset %s's second factor; they may enroll until %s", origin, printsafe.Line(principal, 200),
		decision.FormatTime(until))
	return fmt.Sprintf("%s; they may enroll until %s", was, decision.FormatTime(until)), nil
}

// resetAll is reset-second-factor --all (D7): every entry with no active
// second factor may enroll until reopen_for from now. It is also the way past
// an enrollment store that is lost, which it replaces.
func (b *Broker) resetAll(ctx context.Context, origin string) (string, error) {
	// A store that looks lost may be a file whose mode the operator has just
	// fixed: look at it afresh before deciding it is, or --all would replace
	// (and set aside) a good file.
	if r, ok := b.Enrollments.(interface{ Refresh() }); ok {
		r.Refresh()
	}
	now := b.Now()
	until := now.Add(b.PasswordSignIn.ReopenFor)
	mark := store.EnrollmentMark{CreatedAt: now, ReopenAllUntil: until}
	replaced := false
	switch m, err := b.Enrollments.GetEnrollmentMark(ctx); {
	case err == nil:
		mark.CreatedAt = m.CreatedAt
	case errors.Is(err, store.ErrNotFound):
		// Records with no mark: the mark is written beside them.
	case errors.Is(err, store.ErrEnrollmentStoreLost):
		replaced = true
	default:
		b.logf("broker: reset --all failed: %v", err)
		return "", errors.New("broker: reset --all failed: the store did not answer, so nothing changed: run it again")
	}
	if err := b.Enrollments.PutEnrollmentMark(ctx, mark); err != nil {
		b.logf("broker: reset --all failed: %v", err)
		return "", fmt.Errorf("broker: reset --all failed, so nothing changed: %s", printsafe.Line(err.Error(), 300))
	}
	_ = b.CheckEnrollmentStore(ctx) // clears the lost state and sets the gauge; a store that is down says so itself
	// --all means everyone enrolls again: a record that will not open (a lost
	// key, a damaged record) is no factor anyone can use, and answers
	// store_unavailable until it is replaced, so it is replaced here at the
	// revision its open error returned. A record that opens is never touched.
	unopened, sweepErr := b.reopenUnopenable(ctx, until)
	if sweepErr != nil {
		b.logf("broker: reset --all: %v", sweepErr)
	}
	b.Log.Emit(decision.Record{TS: now, Event: decision.EventSecondFactorReset,
		SecondFactorReset: &decision.SecondFactorReset{ReopenUntil: decision.FormatTime(until), All: true, Origin: origin}})
	b.say("sign-in: %s reopened enrollment for every entry with no active second factor, until %s; second factors "+
		"that did not open and were replaced: %d", origin, decision.FormatTime(until), unopened)
	text := fmt.Sprintf("every entry with no active second factor may enroll until %s", decision.FormatTime(until))
	switch {
	case replaced && b.EnrollmentFile == "":
		// etcd: only the mark key is written; every record stays where it is.
		text += "; the enrollment mark did not open and is replaced; second factors that still open keep working; " +
			"the etcd snapshot is the only copy of the old mark"
	case replaced:
		text += "; the enrollment store was lost and is replaced by an empty one, so everyone enrolls again"
		if kept := b.unreadableCopy(); kept != "" {
			text += "; the unreadable store was kept at " + kept
		} else {
			text += "; the unreadable store was kept beside it"
		}
	}
	if unopened > 0 {
		text += fmt.Sprintf("; second factors that did not open and are replaced: %d", unopened)
	}
	if sweepErr != nil {
		return "", fmt.Errorf("broker: reset --all opened the enrollment window until %s, but the store stopped answering "+
			"after %d unreadable second factors were replaced: run it again", decision.FormatTime(until), unopened)
	}
	return text, nil
}

// reopenUnopenable replaces each second factor that will not open with a
// reopened one until until, at the revision the open error returned, and
// returns how many. A record another write moved meanwhile is left (the
// write stands). A lost or unreachable store stops it with that error.
func (b *Broker) reopenUnopenable(ctx context.Context, until time.Time) (int, error) {
	principals, err := b.Enrollments.SecondFactorPrincipals(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, p := range principals {
		f, err := b.Enrollments.GetSecondFactor(ctx, p)
		switch {
		case err == nil, errors.Is(err, store.ErrNotFound):
			continue
		case errors.Is(err, store.ErrEnrollmentStoreLost), errors.Is(err, store.ErrUnavailable), ctx.Err() != nil:
			return n, err
		case f.Rev == 0:
			continue // no revision to replace it at
		}
		switch err := b.Enrollments.SwapSecondFactor(ctx,
			store.SecondFactor{Principal: p, State: store.SecondFactorReopened, Until: until}, f.Rev); {
		case err == nil:
			n++
		case errors.Is(err, store.ErrConflict):
		default:
			return n, err
		}
	}
	return n, nil
}

// unreadableCopy is the newest file a lost enrollments file was renamed to,
// "" when the broker keeps none on a file or none is there.
func (b *Broker) unreadableCopy() string {
	if b.EnrollmentFile == "" {
		return ""
	}
	kept, err := filepath.Glob(b.EnrollmentFile + ".unreadable-*")
	if err != nil || len(kept) == 0 {
		return ""
	}
	slices.Sort(kept)
	return kept[len(kept)-1]
}

// UnlockSignIn is `port49 directory unlock`: it clears the principal's failed
// sign-in count, so their next sign-in is judged afresh, and records
// sign_in_unlock with the count it held.
func (b *Broker) UnlockSignIn(ctx context.Context, principal, origin string) (string, error) {
	if err := b.signInOps(); err != nil {
		return "", err
	}
	principal, err := userPrincipal(principal)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, holdTimeout)
	defer cancel()
	prev, err := b.Enrollments.GetUnlock(ctx, principal)
	switch {
	case errors.Is(err, store.ErrNotFound):
	case errors.Is(err, store.ErrEnrollmentStoreLost):
		return "", fmt.Errorf("broker: the enrollment store is lost (%s): %s", lostWhy(err), lostRemedy)
	case err != nil:
		b.logf("broker: unlocking %s failed: %v", printsafe.Line(principal, 200), err)
		return "", fmt.Errorf("broker: unlocking %s failed: the directory store did not answer, so nothing "+
			"changed: run it again", printsafe.Line(principal, 200))
	}
	// The unlock is the directory's: every region counts under a new key
	// from here (R15).
	switch err := b.Enrollments.PutUnlock(ctx, principal, b.Now()); {
	case errors.Is(err, store.ErrEnrollmentStoreLost):
		return "", fmt.Errorf("broker: the enrollment store is lost (%s): %s", lostWhy(err), lostRemedy)
	case err != nil:
		b.logf("broker: unlocking %s failed: %v", printsafe.Line(principal, 200), err)
		return "", fmt.Errorf("broker: unlocking %s failed: the directory store did not answer, so nothing "+
			"changed: run it again", printsafe.Line(principal, 200))
	}
	// This region's count under the key the unlock replaced, for the record;
	// a failure here costs nothing, the unlock is in force, and the record
	// then carries no count rather than a zero.
	n, err := b.Store.ClearSignInAttempts(ctx, attemptKey(principal, prev))
	if err != nil {
		b.logf("broker: the unlock of %s is in force; this region's old count could not be read: %v",
			printsafe.Line(principal, 200), err)
		b.Log.Emit(decision.Record{TS: b.Now(), Event: decision.EventSignInUnlock, Principal: principal,
			SignInUnlock: &decision.SignInUnlock{Origin: origin}})
		b.say("sign-in: %s started every region's count again for %s; this region's old count could not be read",
			origin, printsafe.Line(principal, 200))
		return fmt.Sprintf("unlocked %s: every region's count starts again; this region's old count could not be "+
			"read, so how many it held is unknown", printsafe.Line(principal, 200)), nil
	}
	b.Log.Emit(decision.Record{TS: b.Now(), Event: decision.EventSignInUnlock, Principal: principal,
		SignInUnlock: &decision.SignInUnlock{Failures: &n, Origin: origin}})
	b.say("sign-in: %s cleared %d failed sign-ins for %s here, and started every region's count again", origin, n,
		printsafe.Line(principal, 200))
	return fmt.Sprintf("cleared %d failed sign-ins for %s here; every region's count starts again", n,
		printsafe.Line(principal, 200)), nil
}

// InitEnrollments is init-enrollments (D7), the only thing that creates an
// enrollment store: CreateEnrollmentMark{CreatedAt: now}. A store, a lost
// one, or a record with no mark already there refuses it (ErrConflict): it
// writes nothing, and the answer names import and reset-second-factor --all.
// It records second_factor_reset {"created": true}, then looks at the store.
func (b *Broker) InitEnrollments(ctx context.Context, origin string) (string, error) {
	if err := b.signInOps(); err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, holdTimeout)
	defer cancel()
	now := b.Now()
	switch err := b.Enrollments.CreateEnrollmentMark(ctx, store.EnrollmentMark{CreatedAt: now}); {
	case errors.Is(err, store.ErrConflict):
		return "", errors.New("broker: the enrollment store is already there: if it is this broker's own nothing is " +
			"needed; if it is lost or holds records with no mark, " + lostRemedy)
	case err != nil:
		b.logf("broker: init-enrollments failed: %v", err)
		return "", fmt.Errorf("broker: init-enrollments failed, so nothing was created: %s",
			printsafe.Line(err.Error(), 300))
	}
	b.Log.Emit(decision.Record{TS: now, Event: decision.EventSecondFactorReset,
		SecondFactorReset: &decision.SecondFactorReset{Created: true, Origin: origin}})
	b.say("sign-in: %s created the enrollment store", origin)
	if err := b.CheckEnrollmentStore(ctx); err != nil {
		return "created the enrollment store; the broker could not read it back yet (" +
			printsafe.Line(err.Error(), 200) + "), and the next scheduled pass looks again" + runningNote(), nil
	}
	return "created the enrollment store; password sign-in is on" + enrollWindowNote(b, now) + runningNote(), nil
}

// runningNote is what init-enrollments tells the operator about a broker already running: it is another
// process, and it finds the new store at its next recheck.
func runningNote() string {
	return "; a broker already running picks the store up within " + EnrollmentRecheckEvery.String() +
		", and until then its sign-ins answer enrollment_store_lost"
}

// enrollWindowNote says who can enroll in the new store at now: the rollout
// window of the verifier.
func enrollWindowNote(b *Broker, now time.Time) string {
	if b.PasswordSignIn != nil && b.PasswordSignIn.OpenUntil.After(now) {
		return "; enrollment is open until " + decision.FormatTime(b.PasswordSignIn.OpenUntil)
	}
	return "; enrollment is open to new directory entries only, so run `port49 directory reset-second-factor` for " +
		"anyone else"
}

// ExportEnrollments is `port49-broker export-enrollments`: every record and the mark,
// sealed whole under the broker's key (D13). It holds no secret or entry id
// in the clear.
func (b *Broker) ExportEnrollments(ctx context.Context) ([]byte, error) {
	if err := b.signInOps(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, holdTimeout)
	defer cancel()
	raw, err := b.Enrollments.Export(ctx)
	switch {
	case errors.Is(err, store.ErrEnrollmentStoreLost):
		return nil, fmt.Errorf("broker: the enrollment store is lost (%s), so there is nothing to export: %s",
			lostWhy(err), lostRemedy)
	case err != nil:
		b.logf("broker: exporting the enrollments failed: %v", err)
		return nil, fmt.Errorf("broker: the export failed: %s", printsafe.Line(err.Error(), 300))
	}
	return raw, nil
}

// ImportEnrollments is `port49 directory import`: it checks the export's seal
// and writes it as the store, refusing one that would undo a second factor
// enrolled or reset after the export was taken unless replace (D13). It
// records enrollments_import, then looks at the store, so a restore clears a
// lost one at once.
func (b *Broker) ImportEnrollments(ctx context.Context, sealed []byte, replace bool, origin string) (string, error) {
	if err := b.signInOps(); err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, holdTimeout)
	defer cancel()
	n, at, err := b.Enrollments.Import(ctx, sealed, replace)
	switch {
	case errors.Is(err, store.ErrConflict):
		return "", errors.New("broker: the store holds a second factor enrolled or reset after this export was " +
			"taken, and importing it would undo that: run it with --replace to replace the store anyway")
	case errors.Is(err, crypt.ErrUnknownKey):
		// The store's text quotes the key id the export names, which is the
		// export's own and not yet checked: never echoed.
		return "", errors.New("broker: the export is sealed under a key this broker does not hold: set " +
			"encryption.previous to the key it was exported under, then import it again")
	case err != nil:
		// The text is the store's own about the export, never its content.
		return "", fmt.Errorf("broker: the import failed, so nothing changed: %s", printsafe.Line(err.Error(), 300))
	}
	b.Log.Emit(decision.Record{TS: b.Now(), Event: decision.EventEnrollmentsImport,
		EnrollmentsImport: &decision.EnrollmentsImport{Records: n, ExportedAt: decision.FormatTime(at), Replaced: replace,
			Origin: origin}})
	b.say("sign-in: %s imported %d second factors exported at %s", origin, n, decision.FormatTime(at))
	_ = b.CheckEnrollmentStore(ctx)
	return fmt.Sprintf("imported %d second factors exported at %s", n, decision.FormatTime(at)), nil
}
