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
	"time"

	"github.com/rhwendt/port49/internal/daemon/authen"
	"github.com/rhwendt/port49/internal/daemon/author"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/tacacs/wire"
)

type Handler struct {
	store   store.Store
	spool   *Spool
	metrics *metrics.Metrics
	now     func() time.Time
}

func New(s store.Store, sp *Spool, m *metrics.Metrics, now func() time.Time) *Handler {
	return &Handler{store: s, spool: sp, metrics: m, now: now}
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

	rec := decision.Record{TS: h.now(), Event: decision.EventAccount, Flags: flagsName(req.Flags),
		Attribution: "unattributed", TaskID: kv["task_id"],
		Device:  &decision.Device{NAS: peer.NASAddr, Name: peer.NAS, Platform: peer.Platform},
		Session: &decision.Session{Username: canonical, Port: port, RemAddr: string(req.RemAddr), Privilege: req.PrivLvl},
		AcctRecord: &decision.AcctRecord{Raw: raw, Vector: vector, PrivLvl: req.PrivLvl,
			StartTime: num(kv["start_time"]), StopTime: num(kv["stop_time"]), ElapsedTime: num(kv["elapsed_time"])}}

	// (nas, username), not (nas, port): the accounting port is a third value
	// again on most platforms — `0`, `1` or `non-tty` on Junos where the
	// authentication carried the empty string — so attributing on it resolved
	// almost nothing (spec §5.8; §13, decision 15). The port stays on the
	// record.
	c, err := h.store.GetContext(ctx, store.ContextKey{NAS: peer.NAS, Username: canonical})
	h.metrics.StoreOps.WithLabelValues("get_context", storeOutcome(err)).Inc()
	// A store error other than ErrNotFound is not a reason to refuse
	// accounting (spec §5.8: accounting never enforces): treat it the same
	// as no context and still spool the record as unattributed.
	//
	// The key already selects on the username; this re-checks what came back,
	// for the same reason package authen re-checks the receipt hash after its
	// lookup. A store answering with a record it was not asked for would
	// otherwise have this record name another principal, silently and in the
	// audit trail, which is the one thing accounting exists to get right.
	if err == nil && subtle.ConstantTimeCompare([]byte(c.Username), []byte(canonical)) == 1 {
		rec.Attribution = "resolved"
		rec.Principal = c.Principal
		rec.Session.CtxID = c.CtxID
	}

	if err := h.spool.Offer(rec); err != nil {
		h.metrics.Requests.WithLabelValues("acct", "error").Inc()
		return wire.AcctReply{Status: wire.AcctStatusError, ServerMsg: []byte("port49: accounting spool unavailable")}
	}
	h.metrics.Requests.WithLabelValues("acct", "success").Inc()
	return wire.AcctReply{Status: wire.AcctStatusSuccess}
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
