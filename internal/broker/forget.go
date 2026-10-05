package broker

import (
	"context"
	"errors"
	"fmt"

	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/directory"
	"github.com/rhwendt/port49/internal/printsafe"
	"github.com/rhwendt/port49/internal/store"
)

// Forget is `port49 directory forget` (Ruling 3's escape). An entry
// deleted and re-created, a rehire or a directory restore, has a new
// objectGUID or entryUUID, and is refused identity_unmapped while its
// principal's record lives: max(directory.grace, 24h) after the last
// verification or refusal, and every refusal renews it. Forget deletes the
// record, pin included, so the principal's next verification pins the
// entry the directory gives it then. It writes one directory_forget record
// naming origin and the entry the principal was pinned to. It never asks
// the directory and grants nothing; whether the new entry is the same
// person is the operator's to confirm before running it.
//
// The store leaves a tombstone holding the forget's time (DeleteMembership),
// so a verification begun before the forget can never write the old pin
// back: one forget ends it.
func (b *Broker) Forget(ctx context.Context, principal, origin string) (string, error) {
	if b.Directory == nil {
		return "", errors.New("broker: no broker.directory is configured, so no membership is held to forget")
	}
	if !directory.IsUser(principal) {
		return "", fmt.Errorf("broker: %q is not a user: principal; only a directory principal has a membership",
			printsafe.Line(principal, 200))
	}
	ctx, cancel := context.WithTimeout(ctx, holdTimeout)
	defer cancel()
	m, err := b.Store.DeleteMembership(ctx, principal)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return fmt.Sprintf("no membership is held for %s, so nothing pins it; its next verification pins the "+
			"entry the directory gives it then", printsafe.Line(principal, 200)), nil
	case err != nil:
		b.logf("broker: forgetting %s failed: %v", printsafe.Line(principal, 200), err)
		return "", fmt.Errorf("broker: forgetting %s failed, so the record may or may not be gone: run it again",
			printsafe.Line(principal, 200))
	}
	entry := m.EntryID
	if entry == "" {
		entry = "unknown (the record did not open)"
	}
	// Not a decision: it has no verdict, and is not counted as one.
	b.Log.Emit(decision.Record{TS: b.Now(), Event: decision.EventDirectoryForget, Principal: principal,
		Forget: &decision.Forget{EntryID: m.EntryID, DN: m.DN, VerifiedAt: decision.FormatTime(m.VerifiedAt),
			Refused: m.Refused, Origin: origin}})
	b.say("directory: %s forgot %s, pinned to entry %s (%s)", origin, printsafe.Line(principal, 200),
		printsafe.Line(entry, 120), printsafe.Line(m.DN, 200))
	return fmt.Sprintf("forgot %s: it was pinned to entry %s (%s), last verified %s; its next verification "+
		"pins the entry the directory gives it then", printsafe.Line(principal, 200), printsafe.Line(entry, 120),
		printsafe.Line(m.DN, 200), decision.FormatTime(m.VerifiedAt)), nil
}
