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

	"github.com/rhwendt/port49/internal/daemon/authen"
	"github.com/rhwendt/port49/internal/daemon/author"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/platform"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/tacacs/wire"
)

type Handler struct {
	store   store.Store
	spool   *Spool
	metrics *metrics.Metrics
	now     func() time.Time
	// contextIdleTTL is the TTL an annotation re-puts the context under. An
	// annotation is activity, so it extends the idle TTL exactly as the
	// authorizer's extension does (spec §5.6; Task 10).
	contextIdleTTL time.Duration
	// systemUsers is the table main.go handed this handler at construction,
	// from platform.SystemUsers(). It is read-only from here on, which is why
	// there is no lock and no package global: a global would be a mutator of
	// production state in the production binary, and an unlocked map read by
	// parallel requests.
	systemUsers map[string][]string
}

func New(s store.Store, sp *Spool, m *metrics.Metrics, now func() time.Time,
	contextIdleTTL time.Duration, systemUsers map[string][]string) *Handler {
	return &Handler{store: s, spool: sp, metrics: m, now: now,
		contextIdleTTL: contextIdleTTL, systemUsers: systemUsers}
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
	kv, cmd, cmdArgs, raw := author.ParseArgs(req.Args)
	port := string(req.Port)
	vector := author.Vector(cmd, cmdArgs)
	canonical := authen.Canonical(string(req.User))

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
	disc, hasDisc := platform.SessionDiscriminator(peer.Platform)
	seen := ""
	if hasDisc {
		seen = avOf(raw, disc)
	}
	exec := platform.IsExecRecord(peer.Platform, cmd)
	start := req.Flags&wire.AcctFlagStart != 0

	attribution := "unattributed"
	switch {
	case resolved && exec && start && c.SessionDiscriminator != "" && seen != "" && c.SessionDiscriminator != seen:
		// A second exec START on a context already bound to another session of
		// this user: port49 did not authenticate this one. Local fallback, a
		// console login, or a device-local account sharing the name (§5.6).
		// A START carrying the bound value is this session again — a
		// retransmission — and is deliberately not alertable.
		attribution = "foreign"
	case resolved:
		attribution = "resolved"
	case h.isSystemUser(peer.Platform, canonical):
		// The device acting on its own behalf, not a session port49 failed to
		// authenticate (§5.8). Never foreign; countable on its own.
		attribution = "system"
	}

	rec := decision.Record{TS: h.now(), Event: decision.EventAccount, Flags: flagsName(req.Flags),
		Attribution: attribution, TaskID: kv["task_id"],
		Device:  &decision.Device{NAS: peer.NASAddr, Name: peer.NAS, Platform: peer.Platform},
		Session: &decision.Session{Username: canonical, Port: port, RemAddr: string(req.RemAddr), Privilege: req.PrivLvl},
		AcctRecord: &decision.AcctRecord{Raw: raw, Vector: vector, PrivLvl: req.PrivLvl,
			StartTime: num(kv["start_time"]), StopTime: num(kv["stop_time"]), ElapsedTime: num(kv["elapsed_time"])}}
	// TaskID stays `task_id` even where the discriminator is not: it is the
	// field the log has always carried and reconciliation joins on, and on
	// Junos it is the only per-record counter there is.
	if attribution == "resolved" {
		rec.Principal = c.Principal
		rec.Session.CtxID = c.CtxID
	}

	if err := h.spool.Offer(rec); err != nil {
		h.metrics.Requests.WithLabelValues("acct", "error").Inc()
		return wire.AcctReply{Status: wire.AcctStatusError, ServerMsg: []byte("port49: accounting spool unavailable")}
	}
	h.metrics.Requests.WithLabelValues("acct", "success").Inc()

	// Annotate exec records only, never command records, and never delete
	// (spec §5.6 row 7, §5.8). The record is already durable at this point:
	// the annotation is advisory, so it must not stand between a device and
	// its reply.
	if exec && attribution == "resolved" {
		h.annotate(ctx, key, c.CtxID, canonical, seen, start, req.Flags&wire.AcctFlagStop != 0)
	}
	return wire.AcctReply{Status: wire.AcctStatusSuccess}
}

// annotate writes the exec record's conclusion onto the login context.
//
// It re-reads the context rather than writing back the copy the record was
// built from, and the reason is the one store.Store's comment on TouchContext
// names accounting's annotation for: a read-modify-write discards everything
// written between the read and the write, and one of those writers is
// revocation. Re-reading here does not close that window — the store offers no
// in-place setter for these two fields, because SessionDiscriminator is sealed
// and the sealing layer cannot write one field of a record it cannot read — but
// it narrows the window from "across the durable spool write" to a few
// instructions, and it costs one store read on exec records only, which are two
// per session rather than one per command. The residual race is recorded in
// this plan's report; closing it needs a sealed-field setter, which is a §12
// change.
//
// ctxID is what the record was attributed to. If the re-read finds a different
// context — the operator logged out and back in across the spool write — the
// annotation belongs to a session that is gone and is dropped rather than
// applied to a stranger's.
func (h *Handler) annotate(ctx context.Context, key store.ContextKey, ctxID, canonical, seen string, start, stop bool) {
	c, err := h.store.GetContext(ctx, key)
	h.metrics.StoreOps.WithLabelValues("get_context", storeOutcome(err)).Inc()
	if err != nil || subtle.ConstantTimeCompare([]byte(c.Username), []byte(canonical)) != 1 || c.CtxID != ctxID {
		return
	}
	switch {
	case start:
		if c.SessionDiscriminator == "" && seen != "" {
			c.SessionDiscriminator = seen
		}
		c.AccountingState = ""
	case stop:
		// closing is reported and nothing else: it does not stop refresh,
		// does not authorize, does not deny, and row 6 reclaims the state.
		if c.SessionDiscriminator != "" && c.SessionDiscriminator != seen {
			return
		}
		c.AccountingState = "closing"
	default:
		// A WATCHDOG is neither, and annotates nothing.
		return
	}
	// PutContext stamps LastTouchedAt from the store's own clock, so the
	// authorizer's half-TTL rule measures from this extension whoever made it
	// (store.Context; Task 10).
	err = h.store.PutContext(ctx, key, c, h.contextIdleTTL)
	h.metrics.StoreOps.WithLabelValues("put_context", storeOutcome(err)).Inc()
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

// storeOutcome maps a store error to the StoreOps metric's outcome label.
func storeOutcome(err error) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, store.ErrNotFound):
		return "not_found"
	default:
		return "error"
	}
}

func num(s string) int64 {
	n, _ := strconv.ParseInt(s, 10, 64)
	return n
}
