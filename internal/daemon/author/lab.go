package author

import (
	"context"
	"errors"
	"os"
	"strings"

	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/store"
)

// Lab is the lab's measurement instrument, not a policy: it returns fixed
// session attributes and denies commands by prefix, with a server_msg, which
// is exactly what lab register entries L2, L10, L16 and L18 vary one attribute
// at a time. It answers only contexts with no blob — the tokens `lab.seed_tokens`
// mints — and only where port49d.yaml carries a `lab:` block; Engine answers
// everything else (plan 4, Decided 12).
type Lab struct {
	SessionAttributes []string
	// CommandAttributes are returned on a PERMITTED per-command authorization,
	// the way SessionAttributes are on a session one.
	//
	// It is a second list rather than a reuse of the first because register
	// entry L18 varies one at a time: the same unrecognised attribute on a
	// session reply and on a per-command reply are different questions -- three
	// of the five platforms in this lab answer the session one by ending the
	// session, and what they do on the command path was unaskable until this
	// field existed, because Command returned a bare permit and there was no
	// reply to put an attribute in.
	//
	// Empty is the shipped shape and means a bare permit, which is what every
	// config in this repository but an L18 derivation carries.
	CommandAttributes []string
	// DenyPrefixes lists commands denied by prefix match on a token boundary:
	// the joined command line must equal the prefix, or begin with the prefix
	// followed by a space, so "show" denies "show version" but not "shower".
	DenyPrefixes []string
	// Fault is the lab's fault switch; see LabFault. The zero value is no
	// fault.
	Fault LabFault
}

func (l *Lab) Session(_ context.Context, _ Request) Decision {
	return Decision{Permit: true, Reason: decision.ContextMatched, Attributes: l.SessionAttributes}
}

func (l *Lab) Command(_ context.Context, r Request) Decision {
	switch {
	case l.Fault.Is(FaultCommandError):
		return Decision{Error: true, Reason: decision.StoreUnavailable, ServerMsg: "port49: authorization store unavailable"}
	case l.Fault.Is(FaultCommandFail):
		return Decision{Reason: decision.NoRuleMatched, ServerMsg: "port49: denied by lab fault command_fail"}
	}
	line := strings.Join(r.Vector, " ")
	for _, p := range l.DenyPrefixes {
		// A denial carries no attributes on purpose: its payload is the
		// server_msg, and a FAIL with arguments hung off it is protocol
		// behaviour invented in order to measure protocol behaviour.
		if line == p || strings.HasPrefix(line, p+" ") {
			return Decision{Permit: false, Reason: decision.NoPermitDominatesDeny,
				ServerMsg: "port49: denied by lab_deny (" + p + "); see 'port49 explain'"}
		}
	}
	return Decision{Permit: true, Reason: decision.PermitDominates, Attributes: l.CommandAttributes}
}

// LabFault is the lab's fault switch (spec §15, L4): a file whose trimmed
// contents name the fault in force. It is read on every request, so a
// measurement moves between faults without restarting the daemon -- a restart
// re-mints the seeded tokens, and the redactor can verify a capture only
// against the tokens of the run that made it.
//
// An empty Path, a missing file and an empty file are all "no fault", which is
// what every configuration but a lab derivation carries: `lab.fault_file` is
// absent from tests/lab/port49d-lab.yaml on purpose, so a file left behind by
// one run cannot inject a fault into the next.
type LabFault struct{ Path string }

const (
	// FaultStoreUnavailable makes FaultStore fail the reads each request
	// handler begins with, so every handler answers as it does when the store
	// is down: authentication ERROR store_unavailable, authorization FAIL
	// store_unavailable, accounting spooled unattributed.
	FaultStoreUnavailable = "store_unavailable"
	// FaultCommandError answers every per-command authorization ERROR. No
	// production path does: a store outage at command authorization is a FAIL
	// (Handler.Handle). It exists to measure what a device does with an ERROR
	// there, which is the fall-through question L4 (b) asks.
	FaultCommandError = "command_error"
	// FaultCommandFail answers every per-command authorization FAIL, the
	// counterpart of FaultCommandError without a daemon restart.
	FaultCommandFail = "command_fail"
)

// Is reports whether the named fault is in force.
func (f LabFault) Is(name string) bool {
	if f.Path == "" {
		return false
	}
	b, err := os.ReadFile(f.Path)
	return err == nil && strings.TrimSpace(string(b)) == name
}

var errLabStoreUnavailable = errors.New("lab fault: store_unavailable")

// FaultStore is a store that fails, under FaultStoreUnavailable, the reads
// that start authentication (GetReceipt, Candidates, and GetContext for an
// enable), authorization and accounting (GetContext). Everything else passes
// through, which is enough: no handler reaches a write without one of those
// reads succeeding first.
type FaultStore struct {
	store.Store
	Fault LabFault
}

func (s *FaultStore) GetReceipt(ctx context.Context, rk store.ReceiptKey) (store.Receipt, error) {
	if s.Fault.Is(FaultStoreUnavailable) {
		return store.Receipt{}, errLabStoreUnavailable
	}
	return s.Store.GetReceipt(ctx, rk)
}

func (s *FaultStore) Candidates(ctx context.Context, k store.TokenKey) ([]store.Token, error) {
	if s.Fault.Is(FaultStoreUnavailable) {
		return nil, errLabStoreUnavailable
	}
	return s.Store.Candidates(ctx, k)
}

func (s *FaultStore) GetContext(ctx context.Context, k store.ContextKey) (store.Context, error) {
	if s.Fault.Is(FaultStoreUnavailable) {
		return store.Context{}, errLabStoreUnavailable
	}
	return s.Store.GetContext(ctx, k)
}
