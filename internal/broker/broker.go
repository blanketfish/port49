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

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/engine"
	"github.com/rhwendt/port49/internal/platform"
	"github.com/rhwendt/port49/internal/policy"
	"github.com/rhwendt/port49/internal/session"
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

// Broker is the slice's broker. Every field is required but Redact, Conns and
// Persist.
type Broker struct {
	// Policy is the policy in force. port49d swaps it when the file changes
	// (plan 4b), and a request resolves against the one version it held from
	// its first mint to its last, never half of each.
	Policy        *policy.Live
	Minter        *token.Minter
	Store         store.Store
	Log           decision.Emitter
	Metrics       *metrics.Metrics
	Now           func() time.Time
	MaxSessionAge time.Duration
	BatchMax      int
	// Redact is the redaction the blob event's rule text passes through
	// before it is logged (spec §5.8): port49d passes the policy in force's.
	// Nil is the built-in patterns.
	Redact platform.Redactor
	// Sessions marks a revoked principal's or certificate's live contexts
	// and deletes their receipts (Revoke). Required for Revoke.
	Sessions *session.Manager
	// Conns closes a revoked principal's or certificate's held connections:
	// the Listener this broker is served through. Nil closes none.
	Conns ConnCloser
	// Persist writes the marks in force to broker.revocations_file after
	// every change. Nil keeps them in the store alone.
	Persist func(context.Context) error

	// RevokeTimeout bounds a revocation's or lift's steps once it holds
	// revokeSem, which run detached from the caller (Revoke). Zero is
	// DefaultRevokeTimeout.
	RevokeTimeout time.Duration

	// revokeSem is a one-slot semaphore serialising Revoke and Lift (M5),
	// made lazily under mu. A channel, not a mutex, so a caller waiting
	// behind a hung store call or Persist gives up when its ctx ends.
	revokeSem chan struct{}

	mu        sync.Mutex
	blobsSeen map[string]bool
	// quarantineRecorded is, by ctx_id, the bundle under which a refresh last
	// recorded the context left for a quarantine: one record per context per
	// policy, not one per pass (refreshContext).
	quarantineRecorded map[string]string
	// superseded is, by (device, username), when a refresh or a revocation
	// last deleted its unspent tokens: an idempotent retry of a mint from
	// before then is not replayed with a token that no longer exists
	// (token.Request). It holds at most one entry per key the policy has
	// ever minted for.
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
	// A revocation stands against the principal, or this certificate, until
	// an operator lifts it (spec §5.1.4). It is read before anything else, so
	// a revoked caller is told nothing more, and again after the last token
	// write, below. Marks that cannot be read mint for no one.
	checkCtx, cancelCheck := context.WithTimeout(r.Context(), holdTimeout)
	rv, revoked, err := b.revocation(checkCtx, principal, cred)
	cancelCheck()
	switch {
	case err != nil:
		b.emit(decision.Record{TS: now, Event: decision.EventMint, Verdict: decision.VerdictDeny,
			Reason: decision.StoreUnavailable, Principal: principal, Auth: &decision.Auth{Method: cred.Method}})
		writeError(w, http.StatusServiceUnavailable, string(decision.StoreUnavailable),
			"the broker could not read the revocations in force, so it minted nothing; try again")
		return
	case revoked:
		b.refuseRevoked(w, now, principal, cred, rv)
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
	seen := make(map[string]bool, len(req.Devices))
	for _, name := range req.Devices {
		if !deviceName(name) {
			writeError(w, http.StatusBadRequest, "bad_request", fmt.Sprintf(
				"a device name is 1 to %d printable ASCII characters, as the inventory names it", maxDeviceName))
			return
		}
		if seen[name] {
			// One record per device under the key: a second mention would
			// find this request's own reservation and refuse the batch.
			writeError(w, http.StatusBadRequest, "bad_request", "a device is named twice in one request")
			return
		}
		seen[name] = true
	}
	key := r.Header.Get("Idempotency-Key")
	if len(key) > maxIdempotencyKey {
		writeError(w, http.StatusBadRequest, "bad_request", fmt.Sprintf(
			"an Idempotency-Key is at most %d bytes", maxIdempotencyKey))
		return
	}
	sum := sha256.Sum256(body)
	bodyHash := hex.EncodeToString(sum[:])

	// Every device's record is reserved before the first is minted (design
	// §17; plan 7a), atomically: two requests under one key cannot both pass,
	// and a conflict on any device refuses the whole batch before a token, a
	// permit record or a candidate-cap slot exists for a pair it never
	// returns. A record exists only where this principal has minted, so the
	// answer tells it nothing about inventory.
	reserveCtx, cancelReserve := context.WithTimeout(r.Context(), holdTimeout)
	res, err := b.Minter.Reserve(reserveCtx, principal, key, req.Devices, bodyHash)
	cancelReserve()
	switch {
	case errors.Is(err, token.ErrIdempotencyConflict):
		b.Metrics.BrokerIdempotency.WithLabelValues("conflict").Inc()
		writeConflict(w)
		return
	case errors.Is(err, token.ErrIdempotencyInProgress):
		b.writeInProgress(w)
		return
	case err != nil:
		b.Metrics.BrokerIdempotency.WithLabelValues("store_error").Inc()
		b.emit(decision.Record{TS: now, Event: decision.EventMint, Verdict: decision.VerdictDeny,
			Reason: decision.StoreUnavailable, Principal: principal, Auth: &decision.Auth{Method: cred.Method}})
		writeError(w, http.StatusServiceUnavailable, string(decision.StoreUnavailable),
			"the broker could not reserve the Idempotency-Key, so it minted nothing; retry under the same key")
		return
	}
	// Whatever this request does not complete is given back, so a retry is
	// not answered "in progress" by its own leftovers. Its own deadline: the
	// caller may have hung up.
	if res != nil {
		defer func() {
			ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), holdTimeout)
			defer cancel()
			b.Minter.Release(ctx, principal, res)
		}()
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
		item, err := b.mintOne(ctx, pol, principal, cred, authTime, name, req, res, bodyHash)
		if errors.Is(err, token.ErrIdempotencyInProgress) {
			// This device's hold was taken by another request under the
			// key, or lapsed before its turn: two retries that both
			// abandoned a replay, or a batch that outlasted its
			// reservation. Nothing is minted for it, and the devices
			// already minted are completed records a retry replays — unless
			// a revocation landed while they were written.
			release()
			if b.revokedSince(w, r, principal, cred, resp.Results) {
				return
			}
			b.writeInProgress(w)
			return
		}
		resp.Results = append(resp.Results, item)
	}
	release()
	if b.revokedSince(w, r, principal, cred, resp.Results) {
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// revokedSince reads the marks again after a request's last token write,
// and answers the request when one stands. A revocation that landed while
// this request minted may have read the token index before these tokens
// were indexed; reading the marks now closes that: whichever of the two
// read the other's write, no token survives (spec §5.1.4; decision 32). A
// mark deletes what the request wrote and refuses it credential_revoked.
//
// Marks that cannot be read refuse it store_unavailable and leave the
// tokens. A revocation's index pass finds them unless it read the index
// before this request wrote it, and then the read that just failed was the
// only guard. They are never returned, though, so they are reachable only
// by a replay of this request, and its keys are superseded: a replay here
// mints afresh, and anywhere is refused at its first read while a mark
// stands. Deleting them would take an earlier mint's tokens under the same
// key with them (pre-flight M7).
//
// It runs on its own deadline, without the caller's cancel: a caller that
// hung up must not leave its tokens behind.
func (b *Broker) revokedSince(w http.ResponseWriter, r *http.Request, principal string, cred store.Credential,
	items []api.MintItem) bool {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), holdTimeout)
	defer cancel()
	rv, revoked, err := b.revocation(ctx, principal, cred)
	switch {
	case err != nil:
		now := b.Now()
		for _, it := range items {
			if it.Verdict == decision.VerdictPermit {
				b.supersede(store.TokenKey{NAS: it.Device, Username: it.Username}, now)
			}
		}
		b.emit(decision.Record{TS: now, Event: decision.EventMint, Verdict: decision.VerdictDeny,
			Reason: decision.StoreUnavailable, Principal: principal, Auth: &decision.Auth{Method: cred.Method}})
		writeError(w, http.StatusServiceUnavailable, string(decision.StoreUnavailable), "the broker could not "+
			"confirm that no revocation landed during this mint, so it returns nothing; try again")
		return true
	case revoked:
		if b.unmint(ctx, principal, cred, items) == 0 {
			b.emit(revokedRecord(b.Now(), principal, cred))
		}
		answerRevoked(w, rv)
		return true
	}
	return false
}

// revocation is the mark refusing this caller, if any: one on the
// principal, then one on the certificate (spec §5.1.4). A certificate with
// no issuer or serial is never a mark's key.
func (b *Broker) revocation(ctx context.Context, principal string, cred store.Credential) (store.Revocation, bool, error) {
	keys := [][2]string{{store.RevocationPrincipal, principal}}
	if cred.Issuer != "" && cred.Serial != "" {
		keys = append(keys, [2]string{store.RevocationCert, store.CertKey(cred.Issuer, cred.Serial)})
	}
	for _, k := range keys {
		rv, err := b.Store.GetRevocation(ctx, k[0], k[1])
		switch {
		case err == nil:
			return rv, true, nil
		case !errors.Is(err, store.ErrNotFound):
			return store.Revocation{}, false, err
		}
	}
	return store.Revocation{}, false, nil
}

// refuseRevoked answers a caller a revocation stands against before it
// minted anything: one mint record naming whose credential it was (spec
// §5.7), and answerRevoked.
func (b *Broker) refuseRevoked(w http.ResponseWriter, now time.Time, principal string, cred store.Credential,
	rv store.Revocation) {
	b.emit(revokedRecord(now, principal, cred))
	answerRevoked(w, rv)
}

// revokedRecord is a mint refused credential_revoked: it names whose
// credential it was as trust_domain_unresolved does (spec §5.7).
func revokedRecord(now time.Time, principal string, cred store.Credential) decision.Record {
	return decision.Record{TS: now, Event: decision.EventMint, Verdict: decision.VerdictDeny,
		Reason: decision.CredentialRevoked, Principal: principal,
		Auth: &decision.Auth{Method: cred.Method, Fingerprint: cred.Fingerprint}}
}

// RefusedAtBind records a request the broker's listener refused
// credential_revoked, its connection's principal or certificate marked
// (Listener.Refused): the same one mint deny record a mint under the mark
// writes, counted in port49_decisions (spec §5.7).
func (b *Broker) RefusedAtBind(principal string, cred store.Credential) {
	b.emit(revokedRecord(b.Now(), principal, cred))
}

// answerRevoked is the 401 credential_revoked, with the connection closed
// so nothing more rides it.
func answerRevoked(w http.ResponseWriter, rv store.Revocation) {
	w.Header().Set("Connection", "close")
	writeJSON(w, http.StatusUnauthorized, revokedError(rv))
}

// revokedError is credential_revoked's body, the same from a mint and from
// the listener's answer to a marked connection (Listener.answerRevoked).
func revokedError(rv store.Revocation) api.Error {
	what := "this principal"
	if rv.Kind == store.RevocationCert {
		what = "this certificate"
	}
	return api.Error{Error: string(decision.CredentialRevoked), Detail: fmt.Sprintf(
		"%s was revoked at %s; nothing is minted for it until an operator lifts the revocation "+
			"(port49 revoke --lift)", what, rv.At.UTC().Format(time.RFC3339))}
}

// unmint deletes the unspent tokens under every key a refused request
// minted under, and marks each key superseded, so a replay of the request
// is minted afresh rather than handed a token that no longer exists. Each
// device's permit, already recorded, is followed by a deny
// credential_revoked naming it, with index_error when its tokens could not
// be deleted (spec §5.7). It returns how many it recorded.
func (b *Broker) unmint(ctx context.Context, principal string, cred store.Credential, items []api.MintItem) int {
	now := b.Now()
	n := 0
	for _, it := range items {
		if it.Verdict != decision.VerdictPermit {
			continue
		}
		k := store.TokenKey{NAS: it.Device, Username: it.Username}
		rec := revokedRecord(now, principal, cred)
		rec.Device = &decision.Device{Name: it.Device, Platform: it.Platform}
		if err := b.Store.DeleteTokens(ctx, k); err != nil {
			b.logf("broker: deleting the tokens a revoked mint wrote under %q on %q: %v; they expire at their TTL",
				it.Username, it.Device, err)
			rec.IndexError = fmt.Sprintf("tokens not deleted: %v; they expire at their TTL", err)
		}
		b.supersede(k, now)
		b.emit(rec)
		n++
	}
	return n
}

// supersede records that k's unspent tokens were deleted at at, keeping
// the later of two (token.Request.SupersededAt).
func (b *Broker) supersede(k store.TokenKey, at time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.superseded == nil {
		b.superseded = map[store.TokenKey]time.Time{}
	}
	if at.After(b.superseded[k]) {
		b.superseded[k] = at
	}
}

// mintOne answers one device. The only error it returns is
// ErrIdempotencyInProgress, which is the whole request's; every other refusal
// is an item.
func (b *Broker) mintOne(ctx context.Context, pol *policy.Policy, principal string, cred store.Credential,
	authTime time.Time, name string, req api.MintRequest, hold *token.Reservation, bodyHash string) (api.MintItem, error) {
	deny := func(reason decision.Reason, platform string) api.MintItem {
		b.emit(decision.Record{TS: b.Now(), Event: decision.EventMint, Verdict: decision.VerdictDeny, Reason: reason,
			Principal: principal, Auth: &decision.Auth{Method: cred.Method},
			Device: &decision.Device{Name: name, Platform: platform}})
		return api.MintItem{Device: name, Verdict: decision.VerdictDeny, Reason: string(reason)}
	}
	dev, ok := pol.Device(name)
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
	case errors.Is(err, policy.ErrDeviceRefused):
		// Admission refuses this device (spec §10): its packets are closed
		// after the header, so a token for it would only be a login that
		// falls to its local method. Asked after the grants, as a
		// quarantine is, so no caller learns which devices exist.
		return deny(decision.DeviceUnknown, dev.Platform), nil
	case err != nil:
		// The policy's load-time checks compile every subject on every device
		// in inventory and quarantine the ones that fail, so this is a broker
		// defect, not a refusal.
		b.logf("broker: resolving %s on %q: %v", principal, name, err)
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
		b.logf("broker: the policy for %s on %q compiled to a blob the daemon would refuse: %s", principal, name, detail)
		return b.fault(name, "broker_error", "the broker could not compile this device's policy; tell the operator"), nil
	}
	body, hash, err := engine.Encode(res.Blob)
	if err != nil {
		b.logf("broker: the policy for %s on %q compiled to a blob the daemon would refuse: %v", principal, name, err)
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
		TTL:         time.Duration(req.TTLSeconds) * time.Second,
		Reservation: hold, BodyHash: bodyHash, SupersededAt: supersededAt,
		Policy: &decision.Policy{Bundle: pol.Bundle, Subject: res.Subject, Grants: res.Grants}})
	var capped *token.ErrTooManyOutstanding
	switch {
	case errors.Is(err, token.ErrIdempotencyInProgress):
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
	// An entity class a rule names where a value is redacted holds those
	// values: `snmp-server community @bad **` lists bad communities.
	secretClasses := map[string]bool{}
	for i, r := range blob.Rules {
		orig := strings.Fields(r.Rule)
		if words, ok := platform.RedactRule(patterns, orig); ok {
			blob.Rules[i].Rule, redacted = strings.Join(words, " "), true
			for k, w := range words {
				if w == platform.Redacted && strings.HasPrefix(orig[k], "@") {
					secretClasses[orig[k][1:]] = true
				}
			}
		}
	}
	// A pipe permit is a rule over an output modifier, redacted as one.
	for i, p := range blob.Pipe {
		if words, ok := platform.RedactRule(patterns, strings.Fields(p)); ok {
			blob.Pipe[i], redacted = strings.Join(words, " "), true
		}
	}
	for name := range secretClasses {
		for i := range blob.Classes[name] {
			blob.Classes[name][i] = platform.Redacted
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

// logf is log.Printf for a line that may quote policy text — a resolve or
// compile error names the rule it failed on — with every quoted value
// redacted by every pattern the policy in force applies: the process log is
// a log like any other (spec §5.8).
func (b *Broker) logf(format string, args ...any) {
	redact := platform.AllRedactions()
	if b.Policy != nil {
		redact = b.Policy.Load().Redactions()
	}
	log.Print(platform.RedactQuoted(redact, fmt.Sprintf(format, args...)))
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

// writeInProgress answers a request whose key another request under the
// same body is still minting (design §17; plan 7a). It is the API's own
// code, as idempotency_conflict is, and no decision record carries it.
func (b *Broker) writeInProgress(w http.ResponseWriter) {
	b.Metrics.BrokerIdempotency.WithLabelValues("in_progress").Inc()
	w.Header().Set("Retry-After", "1")
	writeError(w, http.StatusConflict, "idempotency_in_progress", "a request under this Idempotency-Key "+
		"is still being minted; retry it under the same key, and it is answered from that request's result "+
		"(design §17)")
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
