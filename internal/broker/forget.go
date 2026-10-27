package broker

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/directory"
	"github.com/rhwendt/port49/internal/printsafe"
	"github.com/rhwendt/port49/internal/spiffe"
	"github.com/rhwendt/port49/internal/store"
)

// Forget is `port49 directory forget` (Ruling 3's escape; decision 41
// ruling 3 for a workload). An entry
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
// forgetUnavailable is why a forget of normal (a principal as the broker
// spells it; "" before one is named) cannot hold anything to forget: no
// directory, or a workload with no mapping (pre-flight M-6). The API asks it
// before it asks for a touch, so no key press is spent on a call that cannot
// run. It echoes only normal, which the caller has validated.
func (b *Broker) forgetUnavailable(normal string) error {
	if b.Directory == nil {
		return errors.New("broker: no broker.directory is configured, so no membership is held to forget")
	}
	if normal != "" && directory.IsWorkload(normal) && b.Directory.Cfg.Workload == nil {
		// Nothing is held for a workload without the mapping, and nothing
		// would read it. A record left from when one was configured expires
		// with its lease.
		return fmt.Errorf("broker: no workload mapping is configured (broker.identity.machines[].directory), so "+
			"no membership is held for %s to forget", printsafe.Line(normal, 300))
	}
	return nil
}

func (b *Broker) Forget(ctx context.Context, principal, origin string) (string, error) {
	if err := b.forgetUnavailable(""); err != nil {
		return "", err
	}
	// The principal as the log spells it (the mark's own rule), so a
	// mixed-case name finds the record it names.
	// A person's principal, or a mapped workload's SPIFFE ID (decision 41
	// ruling 3), as the log spells it.
	lower := strings.ToLower(principal)
	if !strings.HasPrefix(lower, "user:") && !strings.HasPrefix(lower, spiffe.Scheme) {
		return "", fmt.Errorf("broker: %q is neither a user: principal nor a workload's spiffe:// ID; only a "+
			"directory principal has a membership", printsafe.Line(principal, 200))
	}
	normal, err := normalPrincipal(principal)
	if err != nil {
		return "", fmt.Errorf("broker: %q is not a principal as the log spells one: user: and an email, or a "+
			"workload's SPIFFE ID verbatim", printsafe.Line(principal, 300))
	}
	if err := b.forgetUnavailable(normal); err != nil {
		return "", err
	}
	principal = normal
	ctx, cancel := context.WithTimeout(ctx, holdTimeout)
	defer cancel()
	m, err := b.Store.DeleteMembership(ctx, principal)
	switch {
	case errors.Is(err, store.ErrNotFound):
		// Not nothing: the store leaves a tombstone for a pin it lost, so a copy another
		// region holds cannot put it back (plan 11a, I2).
		return fmt.Sprintf("no membership was held for %s; it is forgotten all the same, and no region will "+
			"restore an old pin for it; its next verification pins the entry the directory gives it then",
			printsafe.Line(principal, 200)), nil
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
