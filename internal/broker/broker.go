// Package broker is the vertical slice's broker (design §19 step 3): POST
// /v1/tokens and GET /v1/config, over a held mutual-TLS connection, against
// one trust anchor and the file policy of internal/broker/policy, minting
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
	"github.com/rhwendt/port49/internal/blob"
	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/broker/policy"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
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
	Policy *policy.Policy
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

	mu        sync.Mutex
	blobsSeen map[string]bool
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
		b.emit(decision.Record{TS: now, Event: decision.EventMint, Verdict: decision.VerdictDeny,
			Reason: decision.TrustDomainUnresolved, Auth: &decision.Auth{Method: "cert"}})
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

	resp := api.MintResponse{Principal: principal}
	resp.Subject, _ = b.Policy.SubjectOf(principal)
	for _, name := range req.Devices {
		item, err := b.mintOne(r.Context(), principal, cred, authTime, name, req, key, bodyHash)
		if errors.Is(err, token.ErrIdempotencyConflict) {
			writeError(w, http.StatusConflict, "idempotency_conflict",
				"this Idempotency-Key was used with a different body; the first request's result stands (design §17)")
			return
		}
		resp.Results = append(resp.Results, item)
	}
	writeJSON(w, http.StatusOK, resp)
}

// mintOne answers one device. The only error it returns is an idempotency
// conflict, which is the whole request's; every other refusal is an item.
func (b *Broker) mintOne(ctx context.Context, principal string, cred store.Credential, authTime time.Time,
	name string, req api.MintRequest, key, bodyHash string) (api.MintItem, error) {
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
	res, ok := b.Policy.Resolve(principal, dev.Platform)
	if !ok {
		return deny(decision.NoGrantsMatched, dev.Platform), nil
	}
	// Inventory may name a device with no platform (admission.LoadFile does
	// not require one), and no blob can be compiled for it. That is the
	// operator's inventory to fix, not a refusal of the caller, so it is this
	// item's error and no decision record. It is checked after Resolve so
	// that a caller with no grant is answered no_grants_matched and learns
	// nothing about which devices exist.
	if dev.Platform == "" {
		log.Printf("broker: inventory names device %q with no platform; refusing to mint for it until it has one", name)
		return fault(name, "device_unconfigured",
			"inventory gives this device no platform, so the broker cannot compile its policy; tell the operator"), nil
	}
	body, hash, err := blob.Encode(res.Blob)
	if err != nil {
		// Policy load checks every rule, so this is a broker defect, not a
		// refusal. The error names policy content and is the operator's.
		log.Printf("broker: the policy for %s on %q compiled to a blob the daemon would refuse: %v", principal, name, err)
		return fault(name, "broker_error", "the broker could not compile this device's policy; tell the operator"), nil
	}
	if err := b.putBlob(ctx, hash, body); err != nil {
		return deny(decision.StoreUnavailable, dev.Platform), nil
	}
	out, err := b.Minter.Mint(ctx, token.Request{
		Subject: token.Subject{Principal: principal, Username: res.Username, TokenTTL: res.TokenTTL,
			Enable: res.Enable, MaxPrivilege: res.MaxPrivilege, MaxSessionAge: b.MaxSessionAge,
			Credential: cred, AuthTime: authTime},
		Device: name, Platform: dev.Platform, BlobHash: hash, WithEnable: req.Enable,
		TTL:            time.Duration(req.TTLSeconds) * time.Second,
		IdempotencyKey: key, BodyHash: bodyHash,
		Policy: &decision.Policy{Subject: res.Subject, Grants: res.Grants}})
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
// verdict, so it never carries a §5.7 reason.
func fault(name, code, detail string) api.MintItem {
	return api.MintItem{Device: name, Error: code, Detail: detail}
}

// putBlob writes an encoded blob under its hash and emits it into the log the
// first time this process writes it (spec §5.1.1; §13, decision 19). Its store
// TTL is max_session_age: a context's session_expires is its auth_time plus
// that, and auth_time is never later than the mint, so no context this blob
// backs can outlive it. PutBlob keeps the later expiry, so a re-put never
// shortens it. The emitted set dies with the process, and so does the
// in-process store, so once per process is once per store (plan 3, Decided 8).
func (b *Broker) putBlob(ctx context.Context, hash string, body []byte) error {
	if err := b.Store.PutBlob(ctx, hash, body, b.MaxSessionAge); err != nil {
		return err
	}
	b.mu.Lock()
	if b.blobsSeen == nil {
		b.blobsSeen = map[string]bool{}
	}
	first := !b.blobsSeen[hash]
	b.blobsSeen[hash] = true
	b.mu.Unlock()
	if first {
		b.Log.Emit(decision.Record{TS: b.Now(), Event: decision.EventBlob, Blob: &decision.Blob{Hash: hash, Body: body}})
	}
	return nil
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

func writeError(w http.ResponseWriter, code int, errCode, detail string) {
	writeJSON(w, code, api.Error{Error: errCode, Detail: detail})
}
