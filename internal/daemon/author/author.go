// Package author runs session and command authorization (spec §5.2, §5.3)
// against login context, delegating the policy question to an Authorizer.
package author

import (
	"context"
	"crypto/subtle"
	"errors"
	"strings"
	"time"

	"github.com/rhwendt/port49/internal/daemon/authen"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/tacacs/wire"
)

// Decision is what an Authorizer returns; the policy engine (plan 4)
// implements Authorizer for real.
type Decision struct {
	Permit     bool
	Reason     decision.Reason
	ServerMsg  string
	Attributes []string // session only, e.g. "priv-lvl=15"
}

type Authorizer interface {
	Session(ctx context.Context, c store.Context, args []string) Decision
	Command(ctx context.Context, c store.Context, vector []string, args []string) Decision
}

type Handler struct {
	store   store.Store
	authz   Authorizer
	log     decision.Emitter
	metrics *metrics.Metrics
	now     func() time.Time
}

func New(s store.Store, a Authorizer, e decision.Emitter, m *metrics.Metrics, now func() time.Time) *Handler {
	return &Handler{store: s, authz: a, log: e, metrics: m, now: now}
}

// ParseArgs splits RFC 8907 AV pairs. A trailing cmd-arg of "<cr>" is dropped
// from cmdArgs but kept in raw (spec §5.8).
func ParseArgs(args [][]byte) (kv map[string]string, cmd string, cmdArgs []string, raw []string) {
	kv = make(map[string]string, len(args))
	for _, a := range args {
		s := string(a)
		raw = append(raw, s)
		i := strings.IndexAny(s, "=*")
		if i < 0 {
			continue
		}
		k, v := s[:i], s[i+1:]
		switch k {
		case "cmd":
			cmd = v
		case "cmd-arg":
			cmdArgs = append(cmdArgs, v)
		default:
			kv[k] = v
		}
	}
	if n := len(cmdArgs); n > 0 && cmdArgs[n-1] == "<cr>" {
		cmdArgs = cmdArgs[:n-1]
	}
	return kv, cmd, cmdArgs, raw
}

// Vector is the command vector authorization and accounting agree on: the
// command followed by its arguments, or nil for a session request (cmd == "").
func Vector(cmd string, cmdArgs []string) []string {
	if cmd == "" {
		return nil
	}
	return append([]string{cmd}, cmdArgs...)
}

func (h *Handler) Handle(ctx context.Context, peer authen.Peer, req wire.AuthorRequest) wire.AuthorResponse {
	kv, cmd, cmdArgs, raw := ParseArgs(req.Args)
	port := string(req.Port)
	vector := Vector(cmd, cmdArgs)
	rec := decision.Record{TS: h.now(), Event: decision.EventAuthorizeCommand,
		Device:  &decision.Device{NAS: peer.NASAddr, Name: peer.NAS, Platform: peer.Platform},
		Session: &decision.Session{Port: port, RemAddr: string(req.RemAddr), Privilege: req.PrivLvl},
		Request: &decision.Request{Raw: raw, Vector: vector}}
	if cmd == "" {
		rec.Event = decision.EventAuthorizeSession
	}

	// The lookup is (nas, username): the request's own name, never its port.
	// The port on an authorization request is not the port the authentication
	// carried on any platform measured — vEOS says `ssh` then `vty4`, the N9Kv
	// sends it empty on every command — so keying on it denied sessions port49
	// had just authenticated (spec §13, decision 15; §15, L1).
	//
	// Because the username is the key, a request under a name port49 did not
	// authenticate finds no context and is `context_missing`. It cannot land
	// on someone else's context, so there is nothing here to invalidate — the
	// deletion this path used to perform is gone with the old key.
	user := authen.Canonical(string(req.User))
	rec.Session.Username = user
	c, err := h.store.GetContext(ctx, store.ContextKey{NAS: peer.NAS, Username: user})
	h.metrics.StoreOps.WithLabelValues("get_context", storeOutcome(err)).Inc()
	if errors.Is(err, store.ErrNotFound) {
		return h.deny(rec, decision.ContextMissing, "port49: this session was not authenticated by port49")
	}
	if err != nil {
		return h.deny(rec, decision.StoreUnavailable, "port49: authorization store unavailable")
	}
	// The key already selected on the username; this re-checks what came back,
	// for the same reason package authen re-checks the receipt hash after its
	// lookup. A correct store cannot fail it. A store that answers with a
	// record it was not asked for would otherwise get a permit evaluated
	// against another principal's context — their privilege, their blob — and
	// a record asserting this username belongs to that principal. `subtle`
	// because this is the same class of compare as the receipt's and one rule
	// is easier to audit than an exception.
	//
	// The record keeps the sender's username and drops the principal: it is
	// this request being denied, not the context's owner, and ctx_id already
	// says which context it collided with.
	if subtle.ConstantTimeCompare([]byte(c.Username), []byte(user)) != 1 {
		rec.Session.CtxID = c.CtxID
		return h.deny(rec, decision.UsernameMismatch, "port49: username does not match the authenticated session")
	}
	rec.Session.CtxID = c.CtxID
	rec.Principal = c.Principal
	if kv["service"] != "shell" {
		// server_msg is never built from device-supplied bytes; the service
		// value the NAS sent is already recorded in request.raw on this record.
		return h.deny(rec, decision.ServiceUnsupported, "port49: service not authorized by port49")
	}

	var d Decision
	if cmd == "" {
		d = h.authz.Session(ctx, c, raw)
	} else {
		d = h.authz.Command(ctx, c, vector, raw)
	}
	if !d.Permit {
		return h.deny(rec, d.Reason, d.ServerMsg)
	}
	rec.Verdict, rec.Reason = decision.VerdictPermit, d.Reason
	h.emit(rec)
	resp := wire.AuthorResponse{Status: wire.AuthorStatusPassAdd}
	for _, a := range d.Attributes {
		resp.Args = append(resp.Args, []byte(a))
	}
	return resp
}

func (h *Handler) deny(rec decision.Record, reason decision.Reason, msg string) wire.AuthorResponse {
	rec.Verdict, rec.Reason, rec.ServerMsg = decision.VerdictDeny, reason, msg
	h.emit(rec)
	return wire.AuthorResponse{Status: wire.AuthorStatusFail, ServerMsg: []byte(msg)}
}

func (h *Handler) emit(rec decision.Record) {
	h.log.Emit(rec)
	h.metrics.Decisions.WithLabelValues(rec.Event, rec.Verdict, string(rec.Reason)).Inc()
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
