// Package acct records device accounting as `account` events (spec §5.8).
// Accounting never enforces, never deletes state, and is never written to the
// store: a request is recorded whether or not it can be attributed to a login
// context, and the reply is always SUCCESS unless the durable spool write
// itself fails.
package acct

import (
	"context"
	"crypto/subtle"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/blanketfish/port49/internal/daemon/authen"
	"github.com/blanketfish/port49/internal/daemon/author"
	"github.com/blanketfish/port49/internal/daemon/metrics"
	"github.com/blanketfish/port49/internal/decision"
	"github.com/blanketfish/port49/internal/platform"
	"github.com/blanketfish/port49/internal/store"
	"github.com/blanketfish/port49/internal/tacacs/wire"
	"github.com/blanketfish/port49/internal/token"
)

type Handler struct {
	store   store.Store
	spool   *Spool
	metrics *metrics.Metrics
	now     func() time.Time
	// systemUsers is the table main.go handed this handler at construction,
	// from platform.SystemUsers(). It is read-only from here on, which is why
	// there is no lock and no package global: a global would be a mutator of
	// production state in the production binary, and an unlocked map read by
	// parallel requests.
	systemUsers map[string][]string
	// redact is the redaction every record passes through before it reaches
	// the spool (spec §5.8); nil is the built-in patterns.
	redact platform.Redactor
}

// WithRedactor sets the redaction applied to every record before it reaches
// the spool: port49d passes the policy in force's. Without it the built-in
// patterns apply.
func (h *Handler) WithRedactor(r platform.Redactor) *Handler {
	h.redact = r
	return h
}

// New builds the accounting handler.
//
// It takes no idle TTL, deliberately. An annotation writes through
// store.AnnotateContext, which moves neither the expiry nor LastTouchedAt:
// accounting is not activity for the idle TTL, or a device sending only STOPs
// — records saying a session ended — could hold a context open forever. The
// half-TTL extension belongs to authorization (spec §5.8; §5.6, Task 10).
func New(s store.Store, sp *Spool, m *metrics.Metrics, now func() time.Time,
	systemUsers map[string][]string) *Handler {
	return &Handler{store: s, spool: sp, metrics: m, now: now, systemUsers: systemUsers}
}

func flagsName(f uint8) string {
	switch {
	case f&wire.AcctFlagWatchdog != 0:
		return "watchdog"
	case f&wire.AcctFlagStart != 0:
		return "start"
	case f&wire.AcctFlagStop != 0:
		return "stop"
	}
	return "unknown"
}

func (h *Handler) Handle(ctx context.Context, peer authen.Peer, req wire.AcctRequest) wire.AcctReply {
	if labAcctHold > 0 {
		defer holdReply(ctx)
	}
	_, cmd, cmdArgs, raw := author.ParseArgs(req.Args)
	port := string(req.Port)
	// The vector keeps ParseArgs' untrimmed command and arguments: it is the
	// normalized command §3 owns and §9 joins on, and trimming a typed
	// argument would change what reconciliation compares. Every AV pair this
	// handler reads for itself goes through avOf instead (spec §5.8, "Three
	// wire details that break the join").
	vector := author.Vector(cmd, cmdArgs)
	canonical := authen.Canonical(string(req.User))
	loggedName, redacted := token.LoggedUsername(string(req.User))

	// (nas, username), not (nas, port): the accounting port is a third value
	// again on most platforms — `0`, `1` or `non-tty` on Junos where the
	// authentication carried the empty string — so attributing on it resolved
	// almost nothing (spec §5.8; §13, decision 15). The port stays on the
	// record.
	key := store.ContextKey{NAS: peer.NAS, Username: canonical}
	c, cerr := h.store.GetContext(ctx, key)
	h.metrics.StoreOps.WithLabelValues("get_context", storeOutcome(cerr)).Inc()
	// A store error other than ErrNotFound is not a reason to refuse
	// accounting (spec §5.8: accounting never enforces): treat it the same
	// as no context and still spool the record as unattributed.
	//
	// The key already selects on the username; this re-checks what came back,
	// for the same reason package authen re-checks the receipt hash after its
	// lookup. A store answering with a record it was not asked for would
	// otherwise have this record name another principal, silently and in the
	// audit trail, which is the one thing accounting exists to get right.
	resolved := cerr == nil && subtle.ConstantTimeCompare([]byte(c.Username), []byte(canonical)) == 1

	// Which record is an exec record, and what separates two sessions of one
	// user, are both per platform (spec §5.8). A platform with no
	// discriminator leaves `seen` empty and takes the username-only branch.
	disc, hasDisc := platform.SessionDiscriminator(peer.Wire())
	seen := ""
	if hasDisc {
		seen = avOf(raw, disc)
	}
	exec := platform.IsExecRecord(peer.Wire(), avOf(raw, "cmd"))
	// START|WATCHDOG (0x0a) is a legal flag combination and the wire decoder
	// accepts it — Cisco IOS sends interim updates that way. It is an update
	// about a session already running, not a session beginning, so it must not
	// add a discriminator, must not say `open`, and must stay eligible for
	// `foreign`: the alert exists for records of a session port49 never saw
	// begin, and a device that sends every record with the START bit set would
	// otherwise switch it off entirely. flagsName already reports these as
	// `watchdog`, so treating them as a START here would also have the log line
	// and the annotation disagree about what the record was.
	start := req.Flags&wire.AcctFlagStart != 0 && req.Flags&wire.AcctFlagWatchdog == 0

	attribution := "unattributed"
	switch {
	case resolved && exec && !start && seen != "" && len(c.SessionDiscriminators) > 0 &&
		!contains(c.SessionDiscriminators, store.HashDiscriminator(seen)):
		// A record for a session whose START port49 never saw, on a device
		// where it did watch this user's other sessions begin: a local
		// fallback, a console login, or a device-local account sharing the
		// name (§5.6). A START is never foreign — it is port49 watching a
		// session begin, and it simply adds. An empty set is never foreign
		// either, or stop-only accounting would page on every record.
		attribution = "foreign"
	case resolved:
		attribution = "resolved"
	case h.isSystemUser(peer.Wire(), canonical):
		// The device acting on its own behalf, not a session port49 failed to
		// authenticate (§5.8). Never foreign; countable on its own.
		attribution = "system"
	}

	rec := decision.Record{TS: h.now(), Event: decision.EventAccount, Flags: flagsName(req.Flags),
		Attribution: attribution, TaskID: avOf(raw, "task_id"),
		Device:       peer.Device(),
		PacketFields: decision.AcctFields(req),
		Session:      &decision.Session{Username: loggedName, UsernameRedacted: redacted, Port: port, RemAddr: string(req.RemAddr), Privilege: req.PrivLvl},
		AcctRecord: &decision.AcctRecord{Raw: raw, Vector: vector, PrivLvl: req.PrivLvl,
			StartTime: num(avOf(raw, "start_time")), StopTime: num(avOf(raw, "stop_time")),
			ElapsedTime: num(avOf(raw, "elapsed_time"))}}
	// TaskID stays `task_id` even where the discriminator is not: it is the
	// field the log has always carried and reconciliation joins on, and on
	// Junos it is the only per-record counter there is. It is the value in the
	// clear; only the stored discriminator set is hashed.
	if attribution == "resolved" {
		rec.Principal = c.Principal
		rec.Session.CtxID = c.CtxID
	}
	// Before the spool, which is on disk: command accounting carries typed
	// text verbatim, and a secret must not reach the disk any more than the
	// sink (spec §5.8). The attribution above read the record as sent.
	redactAccount(h.redact, &rec)

	if err := h.spool.Offer(rec); err != nil {
		h.metrics.Requests.WithLabelValues("acct", "error").Inc()
		return wire.AcctReply{Status: wire.AcctStatusError, ServerMsg: []byte("port49: accounting spool unavailable")}
	}
	h.metrics.Requests.WithLabelValues("acct", "success").Inc()
	// Counted once the record is durable, not before: a refused record is
	// answered ERROR and the device sends it again.
	h.metrics.Attributions.WithLabelValues(attribution).Inc()

	// Annotate exec records only, never command records, and never delete
	// (spec §5.6 row 7, §5.8). The record is already durable at this point.
	// The annotation is advisory for authorization, but it is written before
	// the reply, deliberately: a START's discriminator must be in the store
	// when the device sends its next record, on this daemon or on any other
	// replica, or that STOP or WATCHDOG finds a non-empty set without its
	// session and is attributed `foreign`, the series spec §5.8 says to alert
	// on. A queued or dropped annotation would page for a legitimate session
	// exactly when the store is slow. A store error is still not a reason to
	// refuse the record (annotate counts it and goes on).
	//
	// Every write goes through AnnotateContext, which writes at most two
	// fields under the store's own lock. The accounting path never calls
	// PutContext: a re-put of the Context read at the top of this request
	// would put back a RevokedAt of zero over a revocation that landed in
	// between, which is the race store.Store's comment on TouchContext names
	// accounting's annotation for by hand.
	if exec && attribution == "resolved" {
		switch {
		case start:
			// A START always adds — it is port49 watching a session begin —
			// and says the context is open, which is what clears a `closing`
			// left by an earlier session's STOP (§5.8).
			h.annotate(ctx, key, hashOf(seen), store.AccountingStateOpen)
		case req.Flags&wire.AcctFlagStop != 0:
			// Reaching here means the discriminator was in the set or the set
			// was empty; a STOP outside a non-empty set was attributed
			// `foreign` above and annotates nothing. `closing` is reported and
			// nothing else: it does not stop refresh, does not authorize, does
			// not deny, and §5.6 row 6 reclaims the state. The discriminator
			// is deliberately NOT removed — that would cost a second write to
			// narrow a field no decision reads, and would turn a device's
			// duplicate STOP into a `foreign` alert.
			h.annotate(ctx, key, "", store.AccountingStateClosing)
		}
		// A WATCHDOG is neither: it is a keepalive, so it neither adds a
		// discriminator nor says a session closed. It can still be `foreign`
		// above, which is the point — a keepalive for a session port49 never
		// saw begin is the same signal as its STOP.
	}
	return wire.AcctReply{Status: wire.AcctStatusSuccess}
}

// annotate is the one store write on the accounting path.
//
// There is no second read and no re-put, so there is no read-modify-write to
// lose a revocation to. What remains is a narrow window: between this request's
// GetContext and this write the operator can log out and log back in, and this
// write then lands on the NEW context — adding the old session's discriminator
// to it, or stamping it `closing` for a session that is not this one.
//
// Two consequences, and only the first is benign:
//
//   - A stale entry in the set suppresses nothing real. A device does not reuse
//     a discriminator across a logout (measured: `session_pid` 14656 → 14695
//     one millisecond after a logout on the same port, spec §5.8), so the entry
//     matches no later record. It costs one of the eight slots.
//   - A `foreign` can be CAUSED, not only suppressed, and this is the case the
//     comment here used to deny. If the old session's STOP wins this race, the
//     new context is created with an empty set and then annotated `closing`
//     with nothing added — and if a non-START exec record of the new session
//     (its STOP, or a WATCHDOG) is then processed before its own START, it
//     finds a set that is still empty and takes the username branch, not
//     `foreign`. The set has to be non-empty for `foreign`, so causing one
//     needs the new session's START to have landed AND a third session's
//     record to arrive reordered. That is narrow rather than impossible.
//
// Closing it needs the annotation to name the ctx_id it was attributed to, so
// the store can refuse a write aimed at a context that has since been replaced.
// That is an AnnotateContext signature change and is recorded in this plan's
// report rather than taken here.
func (h *Handler) annotate(ctx context.Context, key store.ContextKey, discHash, state string) {
	err := h.store.AnnotateContext(ctx, key, discHash, state)
	h.metrics.StoreOps.WithLabelValues("annotate_context", storeOutcome(err)).Inc()
}

// hashOf renders a discriminator for the store, and maps "no discriminator" to
// "nothing to add" rather than to the hash of the empty string — a platform
// with no discriminator, or a record that did not carry one, must add no entry
// at all (spec §5.8).
func hashOf(seen string) string {
	if seen == "" {
		return ""
	}
	return store.HashDiscriminator(seen)
}

// contains reports whether hash is already in the set. A plain loop over at
// most MaxSessionDiscriminators entries; nothing an attacker influences
// reaches it, and the values compared are hashes rather than secrets.
func contains(set []string, hash string) bool {
	for _, h := range set {
		if h == hash {
			return true
		}
	}
	return false
}

// isSystemUser reports whether this platform's adapter declares user as one of
// its own machinery's accounting identities (spec §5.8). Every shipped
// platform's list is empty, so this returns false in the binary as it ships.
func (h *Handler) isSystemUser(platformName, user string) bool {
	for _, u := range h.systemUsers[platformName] {
		if u == user {
			return true
		}
	}
	return false
}

// avOf reads one accounting AV pair's value out of the raw argument list,
// TRIMMING both halves.
//
// The trimming is a measurement, not tidiness. vSRX 21.4R3.15 and
// vJunos-router 23.4R2-S2.1 send
//
//	session_pid = 31050
//
// with a space on each side of the `=`, where every other argument in the same
// record — task_id=1, service=shell, cmd=login — carries none
// (tests/lab/results/L17-juniper_vsrx.md, L17-juniper_vjunos-router.md,
// L6-juniper_vsrx.md). ParseArgs keeps both halves verbatim, so `kv` holds the
// key "session_pid " and the value " 31050" and a lookup for "session_pid"
// finds nothing. Since session_pid is the only AV pair that separates two
// concurrent Junos sessions, the untrimmed reader binds nothing there and does
// it silently, as the unset branch. The lab harness hit exactly this and
// carries the same fix (tests/lab/junos_opts_test.go, splitAcctAV).
//
// The authorization path is deliberately left alone: no device in this lab has
// sent a spaced argument on an authorization request, and trimming there would
// change what a rule matches (spec §5.8, "Three wire details that break the
// join").
func avOf(raw []string, key string) string {
	for _, a := range raw {
		i := strings.IndexAny(a, "=*")
		if i < 0 {
			continue
		}
		if strings.TrimSpace(a[:i]) == key {
			return strings.TrimSpace(a[i+1:])
		}
	}
	return ""
}

// holdReply holds an accounting reply for labAcctHold, or until ctx ends.
// Only a lab build holds anything (hold.go).
func holdReply(ctx context.Context) {
	t := time.NewTimer(labAcctHold)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}

// storeOutcome maps a store error to the StoreOps metric's outcome label.
func storeOutcome(err error) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, store.ErrNotFound):
		return "not_found"
	case errors.As(err, new(*store.UnreadableContextError)):
		// The record is there and the store answered; the sealing layer
		// could not open it. Counted apart from "error" so a key rotation
		// does not read as a store outage (spec §5.6).
		return "unreadable"
	default:
		return "error"
	}
}

func num(s string) int64 {
	n, _ := strconv.ParseInt(s, 10, 64)
	return n
}
