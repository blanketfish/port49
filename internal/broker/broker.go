// Package broker is the vertical slice's broker (design §19 step 3): POST
// /v1/tokens and GET /v1/config, over a held mutual-TLS connection, against
// one trust anchor and the policy engine (internal/policy, plan 4), minting
// through plan 2's token.Minter. It runs inside port49d because the only store
// is in-process (plan 3, Decided 1). Plan 7 builds the broker in full: OIDC,
// the directory, the rest of §17, and the api: rights model — until then a
// principal can only ever mint for itself, which is §17's default.
//
// The broker never writes a login context: the daemon creates it at
// redemption (spec §5.1.1). It writes tokens (through the minter), blobs, and
// the idempotency record.
package broker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/engine"
	"github.com/rhwendt/port49/internal/platform"
	"github.com/rhwendt/port49/internal/policy"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/token"
)

// maxBody bounds a mint request. A batch is capped at BatchMax device names,
// so a megabyte is generous and an unbounded read is a memory hazard (§17).
const maxBody = 1 << 20

// maxDeviceName is a DNS name's length, and maxIdempotencyKey is generous for
// the agent's 32 hex characters. Both bound what a caller can make the broker
// log or store (plan 3, pre-flight F11).
const (
	maxDeviceName     = 253
	maxIdempotencyKey = 128
)

// Broker is the slice's broker. Every field is required.
type Broker struct {
	// Policy is the policy in force. port49d swaps it when the file changes
	// (plan 4b), and a request resolves against the one version it held from
	// its first mint to its last, never half of each.
	Policy *policy.Live
	// Devices is the inventory by name: the admission snapshot the daemon
	// admits from (plan 3, Decided 15). A target is named, never addressed,
	// and a name inventory does not know is refused (design §17).
	Devices       map[string]admission.Device
	Minter        *token.Minter
	Store         store.Store
	Log           decision.Emitter
	Metrics       *metrics.Metrics
	Now           func() time.Time
	MaxSessionAge time.Duration
	BatchMax      int
	// Redact is the redaction the blob event's rule text passes through
	// before it is logged (spec §5.8): port49d passes the policy in force's.
	// It is the one optional field; nil is the built-in patterns.
	Redact platform.Redactor

	mu        sync.Mutex
	blobsSeen map[string]bool
	// quarantineRecorded is, by ctx_id, the bundle under which a refresh last
	// recorded the context left for a quarantine: one record per context per
	// policy, not one per pass (refreshContext).
	quarantineRecorded map[string]string
	// superseded is, by (device, username), when a refresh last deleted its
	// unspent tokens: an idempotent retry of a mint from before then is not
	// replayed with a token that no longer exists (token.Request). It holds
	// at most one entry per key the policy has ever minted for.
	superseded map[store.TokenKey]time.Time
}

// Handler routes the two endpoints the slice serves.
func (b *Broker) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/config", b.config)
	mux.HandleFunc("POST /v1/tokens", b.tokens)
	return mux
}

// heldConn is one connection's session state (design §7: on the certificate
// path the agent's session IS the connection). at is when the broker accepted
// the connection: stamped before the handshake that follows, so never later
// than the key's use, and it never moves. A first request's time would let a
// client handshake, idle, and start its session's clock later (plan 3,
// Decided 2; pre-flight F3).
type heldConn struct {
	at time.Time
}

type heldConnKey struct{}

// withHeldConn gives a connection its session state, authenticated at at.
// Server installs it as http.Server.ConnContext, so every request on one
// connection shares it.
func withHeldConn(ctx context.Context, at time.Time) context.Context {
	return context.WithValue(ctx, heldConnKey{}, &heldConn{at: at})
}

// authTime is when this request's connection authenticated. A request with
// no held-connection state — a handler driven without Server — authenticated
// now.
func (b *Broker) authTime(r *http.Request) time.Time {
	if h, ok := r.Context().Value(heldConnKey{}).(*heldConn); ok {
		return h.at
	}
	return b.Now()
}

func (b *Broker) config(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, api.Config{Methods: []string{"x509"},
		MaxSessionAgeSeconds: int(b.MaxSessionAge / time.Second), BatchMax: b.BatchMax})
}

// deviceName reports whether name can be an inventory name: 1 to
// maxDeviceName bytes of printable ASCII. Anything else is refused before it
// can reach a record (pre-flight F11).
func deviceName(name string) bool {
	return name != "" && len(name) <= maxDeviceName &&
		strings.IndexFunc(name, func(r rune) bool { return r < 0x21 || r > 0x7e }) < 0
}

func (b *Broker) tokens(w http.ResponseWriter, r *http.Request) {
	now := b.Now()
	authTime := b.authTime(r)
	// The principal comes from the verified connection and nowhere else: the
	// body has no field that names one, and DisallowUnknownFields refuses a
	// body that tries.
	principal, cred, err := Identity(r.TLS, now)
	if err != nil {
		// A chain the anchor verified is named on the refusal (principal when
		// it maps to one, the fingerprint always); no chain names no one.
		b.emit(decision.Record{TS: now, Event: decision.EventMint, Verdict: decision.VerdictDeny,
			Reason: decision.TrustDomainUnresolved, Principal: principal,
			Auth: &decision.Auth{Method: "cert", Fingerprint: cred.Fingerprint}})
		writeError(w, http.StatusUnauthorized, string(decision.TrustDomainUnresolved), err.Error())
		return
	}
	if b.MaxSessionAge > 0 && now.Sub(authTime) > b.MaxSessionAge {
		b.emit(decision.Record{TS: now, Event: decision.EventMint, Verdict: decision.VerdictDeny,
			Reason: decision.SessionExpired, Principal: principal, Auth: &decision.Auth{Method: cred.Method}})
		// Closing the connection is what makes the next request a handshake,
		// and the handshake is the fresh authentication decision 17 requires.
		w.Header().Set("Connection", "close")
		writeError(w, http.StatusUnauthorized, string(decision.SessionExpired), fmt.Sprintf(
			"this connection authenticated at %s, more than max_session_age (%s) ago; authenticate again",
			authTime.UTC().Format(time.RFC3339), b.MaxSessionAge))
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil || len(body) > maxBody {
		writeError(w, http.StatusBadRequest, "bad_request", "the request body could not be read or is over 1 MiB")
		return
	}
	var req api.MintRequest
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "the body is not a mint request: "+err.Error())
		return
	}
	if len(req.Devices) == 0 || len(req.Devices) > b.BatchMax {
		writeError(w, http.StatusBadRequest, "bad_request", fmt.Sprintf(
			"name between 1 and %d devices per request; page a larger sweep (design §17)", b.BatchMax))
		return
	}
	for _, name := range req.Devices {
		if !deviceName(name) {
			writeError(w, http.StatusBadRequest, "bad_request", fmt.Sprintf(
				"a device name is 1 to %d printable ASCII characters, as the inventory names it", maxDeviceName))
			return
		}
	}
	key := r.Header.Get("Idempotency-Key")
	if len(key) > maxIdempotencyKey {
		writeError(w, http.StatusBadRequest, "bad_request", fmt.Sprintf(
			"an Idempotency-Key is at most %d bytes", maxIdempotencyKey))
		return
	}
	sum := sha256.Sum256(body)
	bodyHash := hex.EncodeToString(sum[:])

	// A conflict on any device refuses the whole batch, so it is looked for
	// before the first mint: found on the second device, the first would
	// already hold a stored token, a permit record and a candidate-cap slot
	// for a pair the 409 never returns. A record exists only where this
	// principal has minted, so the check tells it nothing about inventory.
	for _, name := range req.Devices {
		if b.Minter.Conflict(r.Context(), principal, key, name, bodyHash) {
			writeConflict(w)
			return
		}
	}
	// Held from the first resolution to the last token write, so a reload's
	// swap waits for this request's mints and the refresh after it sees every
	// token the old policy minted (policy.Live). Released before the response
	// is written: a client that stops reading, or a peer that vanishes
	// mid-response, must not hold a reload — and, behind it, every mint and
	// every refresh — until TCP gives up. The deferred call is for a panic,
	// which net/http recovers: a hold it leaked would stop every reload.
	pol, hold := b.Policy.Hold()
	held := true
	release := func() {
		if held {
			held = false
			hold()
		}
	}
	defer release()
	// Nothing under the hold takes a second one: a pending Swap blocks every
	// new Hold, so a nested one would wait on the swap that waits on this.
	ctx, cancel := context.WithTimeout(r.Context(), holdTimeout)
	defer cancel()
	resp := api.MintResponse{Principal: principal}
	resp.Subject, _ = pol.SubjectOf(principal)
	for _, name := range req.Devices {
		item, err := b.mintOne(ctx, pol, principal, cred, authTime, name, req, key, bodyHash)
		if errors.Is(err, token.ErrIdempotencyConflict) {
			// Only a concurrent request on the same key, between the check
			// above and this mint, reaches here.
			release()
			writeConflict(w)
			return
		}
		resp.Results = append(resp.Results, item)
	}
	release()
	writeJSON(w, http.StatusOK, resp)
}

// mintOne answers one device. The only error it returns is an idempotency
// conflict, which is the whole request's; every other refusal is an item.
func (b *Broker) mintOne(ctx context.Context, pol *policy.Policy, principal string, cred store.Credential,
	authTime time.Time, name string, req api.MintRequest, key, bodyHash string) (api.MintItem, error) {
	deny := func(reason decision.Reason, platform string) api.MintItem {
		b.emit(decision.Record{TS: b.Now(), Event: decision.EventMint, Verdict: decision.VerdictDeny, Reason: reason,
			Principal: principal, Auth: &decision.Auth{Method: cred.Method},
			Device: &decision.Device{Name: name, Platform: platform}})
		return api.MintItem{Device: name, Verdict: decision.VerdictDeny, Reason: string(reason)}
	}
	dev, ok := b.Devices[name]
	if !ok {
		// The same answer as a device with no grant: the API must not tell a
		// caller which devices exist (design §17). The record names the
		// device and no platform, which is what tells an operator which.
		return deny(decision.NoGrantsMatched, ""), nil
	}
	res, err := pol.Resolve(principal, dev, b.Now())
	switch {
	case errors.Is(err, policy.ErrNoGrants):
		return deny(decision.NoGrantsMatched, dev.Platform), nil
	case dev.Platform == "":
		// Inventory may name a device with no platform (admission.LoadFile
		// does not require one), and no blob can be compiled for it. That is
		// the operator's inventory to fix, not a refusal of the caller, so it
		// is this item's error and no decision record. The policy quarantines
		// such a device at load, so it is named here, as the inventory fault
		// it is, before the quarantine. It is checked after the grants so
		// that a caller with no grant on it is answered no_grants_matched and
		// learns nothing about which devices exist.
		log.Printf("broker: inventory names device %q with no platform; refusing to mint for it until it has one", name)
		return b.fault(name, "device_unconfigured",
			"inventory gives this device no platform, so the broker cannot compile its policy; tell the operator"), nil
	case errors.Is(err, policy.ErrDeviceQuarantined):
		// A joint check fails on this device now: nothing correct can be
		// compiled for it, and the daemon closes its connections without a
		// reply, so no token is minted to present there (spec §10).
		return deny(decision.DeviceQuarantined, dev.Platform), nil
	case err != nil:
		// The policy's load-time checks compile every subject on every device
		// in inventory and quarantine the ones that fail, so this is a broker
		// defect, not a refusal.
		log.Printf("broker: resolving %s on %q: %v", principal, name, err)
		return b.fault(name, "broker_error", "the broker could not compile this device's policy; tell the operator"), nil
	}
	// The daemon fills the session reply's placeholders from the context, at
	// each session authorization (spec §5.2), with the values the broker holds
	// now. An attribute they would push past 255 bytes is refused here, where
	// the operator can be told, rather than there, where the device can only
	// be refused. A value carrying a separator is refused the same way
	// (attribute_unsafe): the fault is in the data it fills in, not the
	// broker, and the daemon would refuse the reply it builds
	// (blob_unavailable). policy.MintCheck is the one reading of these, so
	// explain, the policy tests and the diff answer as the broker does.
	switch code, detail := policy.MintCheck(res, principal, name); code {
	case "":
	case "attribute_too_long":
		log.Printf("broker: the session reply for %s on %q does not fit the wire: %s", principal, name, detail)
		return b.fault(name, code,
			"a session attribute for this device is longer than 255 bytes once filled in; tell the operator"), nil
	case "attribute_unsafe":
		log.Printf("broker: the session reply for %s on %q cannot carry a substitution: %s", principal, name, detail)
		return b.fault(name, code, "a session attribute for this device would carry =, *, a control "+
			"character or invalid UTF-8 once filled in; tell the operator"), nil
	default:
		// Policy load checks every rule and compiles every device's blob, so
		// this is a broker defect, not a refusal. The error names policy
		// content and is the operator's.
		log.Printf("broker: the policy for %s on %q compiled to a blob the daemon would refuse: %s", principal, name, detail)
		return b.fault(name, "broker_error", "the broker could not compile this device's policy; tell the operator"), nil
	}
	body, hash, err := engine.Encode(res.Blob)
	if err != nil {
		log.Printf("broker: the policy for %s on %q compiled to a blob the daemon would refuse: %v", principal, name, err)
		return b.fault(name, "broker_error", "the broker could not compile this device's policy; tell the operator"), nil
	}
	if err := b.putBlob(ctx, hash, body); err != nil {
		return deny(decision.StoreUnavailable, dev.Platform), nil
	}
	b.mu.Lock()
	supersededAt := b.superseded[store.TokenKey{NAS: name, Username: res.Username}]
	b.mu.Unlock()
	out, err := b.Minter.Mint(ctx, token.Request{
		Subject: token.Subject{Principal: principal, Username: res.Username, TokenTTL: res.TokenTTL,
			Enable: res.Enable, MaxPrivilege: res.MaxPrivilege, MaxSessionAge: b.MaxSessionAge,
			Credential: cred, AuthTime: authTime},
		Device: name, Platform: dev.Platform, BlobHash: hash, WithEnable: req.Enable,
		TTL:            time.Duration(req.TTLSeconds) * time.Second,
		IdempotencyKey: key, BodyHash: bodyHash, SupersededAt: supersededAt,
		Policy: &decision.Policy{Bundle: pol.Bundle, Subject: res.Subject, Grants: res.Grants}})
	var capped *token.ErrTooManyOutstanding
	switch {
	case errors.Is(err, token.ErrIdempotencyConflict):
		return api.MintItem{}, err
	case errors.As(err, &capped):
		return deny(decision.CandidateCapReached, dev.Platform), nil
	case err != nil:
		return deny(decision.StoreUnavailable, dev.Platform), nil
	}
	// The minter emitted the permit record; the counter is the broker's. An
	// idempotent replay is counted again: it is a permit answered.
	b.Metrics.Decisions.WithLabelValues(decision.EventMint, decision.VerdictPermit, string(decision.GrantsMatched)).Inc()
	item := api.MintItem{Device: name, Verdict: decision.VerdictPermit, Platform: dev.Platform,
		Username: out.Username, Login: out.Login, Enable: out.Enable, ExpiresAt: out.ExpiresAt.UTC().Format(time.RFC3339)}
	if len(dev.Addresses) > 0 {
		// A fact from the source of truth; the client must not trust it
		// further than an SSH host key (design §17).
		item.Address = dev.Addresses[0].String()
	}
	return item, nil
}

// fault is an item the broker could not decide: its own error, not a
// verdict, so it never carries a §5.7 reason and is counted apart from the
// decisions, by its code alone.
func (b *Broker) fault(name, code, detail string) api.MintItem {
	b.Metrics.BrokerItemErrors.WithLabelValues(code).Inc()
	return api.MintItem{Device: name, Error: code, Detail: detail}
}

// putBlob writes an encoded blob under its hash and emits it into the log the
// first time this process writes it (spec §5.1.1; §13, decision 19). Its store
// TTL is max_session_age: a context's session_expires is its auth_time plus
// that, and auth_time is never later than the mint, so no context this blob
// backs can outlive it. PutBlob keeps the later expiry, so a re-put never
// shortens it. A blob is emitted once per process, and the log's first copy
// serves every later re-put, including one after the store's copy expired
// (plan 3, Decided 8).
//
// The emit happens under b.mu, so a second request for the same hash cannot
// return from putBlob, and so cannot reach Mint, until the blob record is
// written: within one sink, every mint record naming a hash follows that
// hash's blob record. Emit is one buffered line write, so that is all the lock
// holds.
//
// A blob record the sink refuses is not marked emitted, so the next mint that
// writes the hash emits it again (roadmap, plan 4): replay reads the log alone,
// and a mint record naming a blob the log never carried cannot be replayed.
// The refusal is counted by port49_decision_log_write_failures_total. An
// Emitter that cannot report a refusal is trusted, as before.
func (b *Broker) putBlob(ctx context.Context, hash string, body []byte) error {
	if err := b.Store.PutBlob(ctx, hash, body, b.MaxSessionAge); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.blobsSeen == nil {
		b.blobsSeen = map[string]bool{}
	}
	if !b.blobsSeen[hash] {
		rec := decision.Record{TS: b.Now(), Event: decision.EventBlob, Blob: b.blobEvent(hash, body)}
		if sink, ok := b.Log.(decision.Sink); ok {
			b.blobsSeen[hash] = sink.Write(rec) == nil
		} else {
			b.Log.Emit(rec)
			b.blobsSeen[hash] = true
		}
	}
	return nil
}

// blobEvent is the blob event's body: the blob as stored, unless a rule's
// text carries a value the platform's redaction patterns hide — a policy
// literal is no safer in a log than a typed one (spec §5.8). Then the rules
// are logged redacted and the event says so. The body no longer hashes to
// its name, so replay reports every record naming it unverifiable rather
// than reading the change as tampering; the store and the policy file keep
// the blob verbatim, and the hash beside it still names which one it was.
func (b *Broker) blobEvent(hash string, body []byte) *decision.Blob {
	ev := &decision.Blob{Hash: hash, Body: body}
	var blob engine.Blob
	if err := json.Unmarshal(body, &blob); err != nil {
		// The minter encoded it a moment ago; a body that does not decode
		// has no rule text to redact that this could find, and is logged
		// as it is for replay to report.
		return ev
	}
	redact := b.Redact
	if redact == nil {
		redact = platform.BuiltInRedactor
	}
	patterns, redacted := redact(blob.Platform), false
	for i, r := range blob.Rules {
		if words, ok := platform.RedactRule(patterns, strings.Fields(r.Rule)); ok {
			blob.Rules[i].Rule, redacted = strings.Join(words, " "), true
		}
	}
	if !redacted {
		return ev
	}
	out, err := json.Marshal(blob)
	if err != nil {
		// Never the verbatim body in place of a redacted one.
		out = []byte("{}")
	}
	ev.Body, ev.Redacted = out, true
	return ev
}

// emit writes a refusal the broker decided itself, and counts it.
func (b *Broker) emit(r decision.Record) {
	b.Log.Emit(r)
	b.Metrics.Decisions.WithLabelValues(r.Event, r.Verdict, string(r.Reason)).Inc()
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeConflict(w http.ResponseWriter) {
	writeError(w, http.StatusConflict, "idempotency_conflict",
		"this Idempotency-Key was used with a different body; the first request's result stands (design §17)")
}

func writeError(w http.ResponseWriter, code int, errCode, detail string) {
	writeJSON(w, code, api.Error{Error: errCode, Detail: detail})
}

// holdTimeout bounds a mint request's store calls while it holds the policy,
// swapped in tests. A pending Swap blocks every new Hold, so a store that stops
// answering would otherwise hold a reload, and every mint queued behind it,
// until the store came back. Past it the rest of the batch is refused
// store_unavailable, as a store that refused would be. Ten seconds is long for
// a healthy store and short for an operator waiting on a reload.
var holdTimeout = 10 * time.Second
