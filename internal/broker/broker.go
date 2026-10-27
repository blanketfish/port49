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
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/directory"
	"github.com/rhwendt/port49/internal/engine"
	"github.com/rhwendt/port49/internal/issuer"
	"github.com/rhwendt/port49/internal/oidc"
	"github.com/rhwendt/port49/internal/platform"
	"github.com/rhwendt/port49/internal/policy"
	"github.com/rhwendt/port49/internal/printsafe"
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

// maxInventoryName is the longest name the bundle admits for a device
// (bundle.NameOK). A sweep's after is a device name its last page returned
// as next, so it takes every name the inventory holds; a devices list and a
// scope keep maxDeviceName, which they have always had.
const maxInventoryName = 255

// blobsSeenMax bounds blobsSeen: a policy rewritten on a schedule mints a
// new hash per device per rewrite, and the set must not grow with them.
const blobsSeenMax = 4096

// Broker is the slice's broker. Every field is required but Redact, Sessions
// (which only Revoke needs, and refuses without), Conns, Persist,
// RevokeTimeout, CertStatus and OnUnavailable.
type Broker struct {
	// Policy is the policy in force. port49d swaps it when the file changes
	// (plan 4b), and a request resolves against the one version it held from
	// its first mint to its last, never half of each.
	Policy *policy.Live
	// Directory maps a certificate to a directory principal at the TLS bind
	// and reads its membership (plan 7g). Nil: no directory, and the
	// certificate's email SAN is the principal.
	Directory *directory.Resolver
	// Identity verifies OIDC bearer tokens (plan 7h): nil when no oidc
	// verifier is configured, and a bearer is then refused.
	Identity *oidc.Set
	// PasswordSignIn is broker.identity's directory_password verifier (plan
	// 9e; decision 47): nil when there is none. A certificate issued over a
	// directory sign-in is taken only while it names the principal's domain.
	PasswordSignIn *oidc.PasswordSignIn
	// SignInDirectory is what a directory sign-in asks the directory;
	// *directory.Resolver is one. Nil with PasswordSignIn set answers 404.
	SignInDirectory SignInDirectory
	// Enrollments is the enrollment store's handle (decision 47 D12); Store
	// keeps the attempt counts. Nil with PasswordSignIn set is a lost store.
	Enrollments store.Enrollments
	// EnrollmentFile is the enrollment store's file on the memory backend, ""
	// on etcd: reset-second-factor --all names the copy it keeps of a lost one.
	EnrollmentFile string
	// NoX509 is an OIDC-only broker (Ruling 1): no x509 verifier, so Server
	// requests no client certificate and /v1/config offers no x509.
	NoX509 bool
	// Issuer is the broker's issuing CA (plan 9b; spec §13 decision 43): nil
	// issues nothing and trusts no port49-issued certificate. Its CAs join
	// the handshake's pool, for people alone (Server, CertCallerOf).
	Issuer *issuer.CA
	// issueHeld is HoldIssuance: set at start, cleared once the CA passed the
	// record check.
	issueHeld atomic.Bool
	// CertificateLifetime is broker.identity.issuance.certificate_lifetime
	// (decision 43 ruling 9); zero is issuer.DefaultLifetime.
	CertificateLifetime time.Duration
	// CABundle is broker.tls_ca_bundle_file's CAs, PEM, which GET /v1/config
	// sends every client (decision 43 ruling 25); nil sends none.
	CABundle []byte
	// CABundleRefused is a tls_ca_bundle_file configured and refused at
	// start: GET /v1/config says so, and clients keep what they hold.
	CABundleRefused bool
	// Workload is the workload certificate verifier (plan 8; decision 40):
	// x509 under broker.identity.machines. Nil reads every certificate as a
	// person's, as before plan 8.
	Workload *Workload
	// PerLoginMFA is what this broker verifies for per_login_mfa (plan 9c;
	// decision 45): nil verifies hardware_key_touch never, and idp_mfa while
	// a human OIDC verifier is configured.
	PerLoginMFA   *MFAVerifiers
	Minter        *token.Minter
	Store         store.Store
	Log           decision.Emitter
	Metrics       *metrics.Metrics
	Now           func() time.Time
	MaxSessionAge time.Duration
	BatchMax      int
	// CeilingWarning is session.ceiling_warning, told to the agent by
	// /v1/config so `port49 token` warns too (plan 7b).
	CeilingWarning time.Duration
	// ContextIdleTTL is the idle lifetime a refreshed context is extended to,
	// and GraceWindow how long past its ceiling a refresh may still resume
	// one (spec §5.6): port49d's context_idle_ttl and session.grace_window.
	ContextIdleTTL time.Duration
	GraceWindow    time.Duration
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
	// Marks is the daemon's copy of the standing marks (store.Marks): a
	// revocation puts its mark in it once the store holds the mark, and a
	// lift takes it out once the store's is gone. Nil keeps none.
	Marks *store.Marks
	// Persist writes the marks in force to broker.revocations_file after
	// every change. Nil keeps them in the store alone.
	Persist func(context.Context) error
	// Say writes a line where port49d writes its own (its stderr), redacted
	// as logf redacts. Nil is the process log (logf). Only MarkChanged's
	// line goes through it (Ruling T9-c).
	Say func(format string, args ...any)

	// RevokeTimeout bounds a revocation's or lift's steps once it holds
	// revokeSem, which run detached from the caller (Revoke). Zero is
	// DefaultRevokeTimeout.
	RevokeTimeout time.Duration

	// AdminSocket is the serving process's admin_socket, where a revocation
	// is lifted; empty when none is configured. Only the HTTP revocation's
	// answer reads it, to say where its mark is lifted (decision 34).
	AdminSocket string
	// Proc names the process serving the API in those answers: "port49d"
	// when empty, "port49-broker" on the broker (Task 15a review M-6).
	Proc string

	// MintGate, when set, is asked of the policy a mint would run under,
	// with the policy held: an error refuses the whole batch
	// store_unavailable, minting nothing. port49-broker refuses until a
	// replica serving a bundle other than the one last judged has marked
	// meta/judged in doubt (Task 15a re-review 1, I-2), and from its start
	// until it has seen a takeover done for the bundle it serves (decision
	// 36, the mint gate at a start). Its error is never the caller's to
	// read: the gate's owner says why, once, as it waits.
	MintGate func(pol *policy.Policy) error

	// CertStatus answers a certificate chain's revocation status (spec
	// §5.1.4; decision 33): nil checks nothing, port49d's `disabled: true`.
	// OnUnavailable is "refuse" or "allow", for a status it cannot establish.
	CertStatus    StatusChecker
	OnUnavailable string

	// queueOnce makes revokeQueue, the certificates a CRL or a refusal
	// named, waiting for RunRevocationQueue (OnCRLEntry).
	queueOnce   sync.Once
	revokeQueue chan queuedRevoke

	// revokeSem is a one-slot semaphore serialising Revoke and Lift (M5),
	// made lazily under mu. A channel, not a mutex, so a caller waiting
	// behind a hung store call or Persist gives up when its ctx ends.
	revokeSem chan struct{}

	// ownRevoking is, by caller principal, a self or key revocation over
	// HTTP still running (holdOwnRevoke). Neither takes revokeSem, and both
	// run detached, so without it one caller's retries would pile up
	// detached runs against a slow store (ruling M4). Guarded by mu.
	ownRevoking map[string]bool
	// admin is the admin-level calls' challenges, in memory (adminproof.go).
	admin adminChallenges
	// skipAdminProof lets adminGate pass every call. It is unexported and set
	// by test fixtures alone, for tests of what a revocation does once its
	// proof is in hand: TestNothingButTestsSkipsTheAdminProof holds that.
	skipAdminProof bool

	mu sync.Mutex
	// blobsSeen is which blob hashes this process has written into its
	// decision log, bounded at blobsSeenMax and forgotten whole there: a
	// forgotten hash is emitted again, which costs one duplicate record
	// (plan 7e, Ruling 9). Per process, by design: each process's log stays
	// replayable alone.
	blobsSeen map[string]bool
	// quarantineRecorded is, by ctx_id, the bundle under which a refresh last
	// recorded the context left for a quarantine: one record per context per
	// policy, not one per pass (refreshContext).
	quarantineRecorded map[string]string
	// superseded is, by (device, username), when a refresh or a revocation
	// last deleted its unspent tokens: an idempotent retry of a mint from
	// before then is not replayed with a token that no longer exists
	// (token.Request). It is this process's copy of the store's (plan 7e,
	// Ruling 9), each entry kept SupersededFor from when it was recorded, as
	// the store keeps its own (supersede).
	superseded map[store.TokenKey]supersededMark
	// supersedePruned is when supersede last pruned superseded: at most once
	// per supersedePruneEvery, so a pass that supersedes n keys scans the
	// map once, not n times, under mu.
	supersedePruned time.Time
	// queued is, by (issuer, serial), each certificate in revokeQueue, and
	// pending each one a store error or a full queue left for RetryPending.
	queued  map[[2]string]bool
	pending map[[2]string]queuedRevoke
	// said is, by key, when sayOnce last said it.
	said map[string]time.Time

	// enrollLost is why the enrollment store is lost, "" when it is not;
	// enrollLostSaid is the why its error line last said. Guarded by
	// enrollMu, which EnrollmentStoreLost takes on every sign-in.
	enrollMu       sync.Mutex
	enrollLost     string
	enrollChecked  bool // a check has got an answer
	enrollLostSaid string

	// ready is what /readyz answers (SetReady).
	ready atomic.Pointer[string]
}

// Handler routes the endpoints the broker serves.
func (b *Broker) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/config", b.config)
	mux.HandleFunc("POST /v1/tokens", b.tokens)
	mux.HandleFunc("POST /v1/mfa", b.mfaProve)
	mux.HandleFunc("POST /v1/logout", b.logout)
	mux.HandleFunc("POST /v1/refresh/challenge", b.refreshChallenge)
	mux.HandleFunc("POST /v1/refresh", b.refresh)
	mux.HandleFunc("POST /v1/certificate", b.issue)
	mux.HandleFunc("POST /v1/sign-in", b.signIn)
	mux.HandleFunc("POST /v1/sign-in/confirm", b.signInConfirm)
	mux.HandleFunc("GET /v1/identity", b.identity)
	mux.HandleFunc("POST /v1/tokens/revoke", b.tokensRevoke)
	mux.HandleFunc("POST /v1/explain", b.explain)
	mux.HandleFunc("GET /healthz", b.healthz)
	mux.HandleFunc("GET /readyz", b.readyz)
	return announceCloseWithoutCertificate(mux)
}

// announceCloseWithoutCertificate says Connection: close on every answer to a
// request that came over TLS with no client certificate. The server closes
// such a connection the moment it goes idle (closeIdleWithoutCertificate);
// without the header a client that pools connections and never retries
// (Keycloak's back-channel logout, final review F1) writes its next request
// into the closed socket, reads EOF, and the request is lost with nothing
// said on either side. With it, net/http closes after the answer and the
// client sees the close and opens a new connection.
func announceCloseWithoutCertificate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil && len(r.TLS.PeerCertificates) == 0 && len(r.TLS.VerifiedChains) == 0 {
			w.Header().Set("Connection", "close")
		}
		next.ServeHTTP(w, r)
	})
}

// heldConn is one connection's session state (design §7: on the certificate
// path the agent's session IS the connection). at is when it authenticated:
// stamped at accept, before the handshake (plan 3, Decided 2), and moved
// only by a refresh that verified (spec §5.6; decision 33). nonce is the
// refresh challenge outstanding on it, single use; lastRefresh paces
// refreshes to one per refreshEvery.
type heldConn struct {
	mu          sync.Mutex
	at          time.Time
	answer      *directory.Answer // the directory's answer pinned at bind; nil without a directory
	nonce       []byte
	nonceExp    time.Time
	lastRefresh time.Time
	// proved is the proof a refresh challenge request took by naming its
	// challenge, kept beside the nonce and expiring with it; the refresh
	// that follows spends it (plan 9c, decision 45 ruling 16).
	proved *provedChallenge
}

func (h *heldConn) authAt() time.Time {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.at
}

type heldConnKey struct{}

// withHeldConn gives a connection its session state, authenticated at at.
// Server installs it as http.Server.ConnContext, so every request on one
// connection shares it. a is the answer the listener pinned at bind (nil
// without a directory): the connection's principal for its life (Ruling 4).
func withHeldConn(ctx context.Context, at time.Time, a *directory.Answer) context.Context {
	return context.WithValue(ctx, heldConnKey{}, &heldConn{at: at, answer: a})
}

// authTime is when this request's connection authenticated. A request with
// no held-connection state — a handler driven without Server — authenticated
// now.
func (b *Broker) authTime(r *http.Request) time.Time {
	if h := heldOf(r); h != nil {
		return h.authAt()
	}
	return b.Now()
}

// heldOf is r's connection's session state, nil for a request driven without
// Server.
func heldOf(r *http.Request) *heldConn {
	h, _ := r.Context().Value(heldConnKey{}).(*heldConn)
	return h
}

func (b *Broker) config(w http.ResponseWriter, _ *http.Request) {
	c := api.Config{MaxSessionAgeSeconds: int(b.MaxSessionAge / time.Second), BatchMax: b.BatchMax,
		CeilingWarningSeconds: int(b.CeilingWarning / time.Second)}
	if !b.NoX509 {
		c.Methods = append(c.Methods, "x509")
	}
	if b.Identity != nil {
		c.Methods = append(c.Methods, "oidc")
		for _, v := range b.Identity.Humans() {
			// scopes is never null: a public client asks for at least openid.
			scopes := slices.Clone(v.Scopes)
			if len(scopes) == 0 {
				scopes = []string{"openid"}
			}
			c.OIDC = append(c.OIDC, api.OIDCProvider{Issuer: v.Issuer, ClientID: v.ClientID, Scopes: scopes})
		}
	}
	if b.PasswordSignIn != nil {
		c.Methods = append(c.Methods, "directory_password")
		c.SignIn = &api.SignInConfig{SecondFactor: "totp"}
	}
	if b.Issuer != nil {
		available := b.Issuer.Unavailable == nil
		c.Issuance = &api.Issuance{CertificateLifetimeSeconds: int(b.certificateLifetime() / time.Second),
			Available: &available}
	}
	c.BrokerCABundle, c.BrokerCABundleRefused = string(b.CABundle), b.CABundleRefused
	c.PerLoginMFA = b.mfaConfig()
	writeJSON(w, http.StatusOK, c)
}

// deviceName reports whether name can be an inventory name: 1 to
// maxDeviceName bytes of printable ASCII. Anything else is refused before it
// can reach a record (pre-flight F11).
func deviceName(name string) bool { return printable(name, maxDeviceName) }

// printable reports whether s is 1 to max bytes of printable ASCII.
func printable(s string, max int) bool {
	return s != "" && len(s) <= max &&
		strings.IndexFunc(s, func(r rune) bool { return r < 0x21 || r > 0x7e }) < 0
}

func (b *Broker) tokens(w http.ResponseWriter, r *http.Request) {
	// The principal comes from the verified connection and nowhere else: the
	// body has no field that names one, and DisallowUnknownFields refuses a
	// body that tries. The marks authenticate read are read again after the
	// last token write, below.
	c, ok := b.authenticate(w, r, decision.EventMint, "minted nothing")
	if !ok {
		return
	}
	principal := c.principal
	now := b.Now()

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
	if req.Scope != "" || req.After != "" {
		// devices beside a scope is refused whatever it holds, [] included:
		// the key is what ruling 1 refuses, not its length.
		// encoding/json leaves the slice nil for an absent key or null, and
		// non-nil for [].
		if msg := sweepRequestError(req, req.Devices != nil); msg != "" {
			writeError(w, http.StatusBadRequest, "bad_request", msg)
			return
		}
	} else if len(req.Devices) == 0 || len(req.Devices) > b.BatchMax {
		writeError(w, http.StatusBadRequest, "bad_request", fmt.Sprintf(
			"name between 1 and %d devices per request, or a scope; page a larger sweep (design §17)", b.BatchMax))
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

	// Group membership is resolved here, once for the batch, as the pinned
	// principal's (Ruling 10): a refusal denies the whole request.
	dctx, dcancel := context.WithTimeout(r.Context(), b.memberBudget())
	m, answer, err := b.memberFor(dctx, principal)
	dcancel()
	if err != nil {
		ref := directoryRefusal(err)
		b.emit(decision.Record{TS: now, Event: decision.EventMint, Verdict: decision.VerdictDeny, Reason: ref.Reason,
			Principal: principal, Auth: c.auth(), Sweep: sweepOf(req)})
		b.answerRefusal(w, r, ref)
		return
	}

	// No token exists that a logout cannot find (Ruling 11).
	if c.oidc != nil {
		octx, ocancel := context.WithTimeout(r.Context(), holdTimeout)
		err := b.noteOwner(octx, *c.oidc)
		ocancel()
		if err != nil {
			b.emit(decision.Record{TS: now, Event: decision.EventMint, Verdict: decision.VerdictDeny,
				Reason: decision.StoreUnavailable, Principal: principal, Auth: c.auth(), Sweep: sweepOf(req)})
			writeError(w, http.StatusServiceUnavailable, string(decision.StoreUnavailable),
				"the broker could not record your session for a logout to find, so it minted nothing; try again")
			return
		}
	}

	// A sweep's page is resolved here, from the policy in force now, so the
	// reservation below holds each of its devices; each is minted under the
	// hold against the policy held, as a named device is (decision 42 ruling
	// 1). An empty page is one answer whatever made it so (ruling 2).
	var next string
	if req.Scope != "" {
		pol := b.Policy.Load()
		req.Devices, next = pol.SweepPage(m, req.Scope, req.After, b.BatchMax, now)
		if len(req.Devices) == 0 {
			if b.mintGateRefuses(w, pol, now, c, req) {
				return
			}
			ca := c.auth()
			b.emit(decision.Record{TS: now, Event: decision.EventMint, Verdict: decision.VerdictDeny,
				Reason: decision.NoGrantsMatched, Principal: principal,
				Auth: &decision.Auth{Method: c.cred.Method, Directory: directoryAuth(answer), OIDC: ca.OIDC,
					K8s: ca.K8s, DirectoryPassword: ca.DirectoryPassword},
				Policy: &decision.Policy{Bundle: pol.Bundle}, Sweep: sweepOf(req)})
			resp := api.MintResponse{Principal: principal, Results: []api.MintItem{}}
			resp.Subject, resp.Subjects = subjectNames(pol, m)
			writeJSON(w, http.StatusOK, resp)
			return
		}
	}

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
			Reason: decision.StoreUnavailable, Principal: principal, Auth: c.auth(), Sweep: sweepOf(req)})
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
	//
	// Every record written under the hold goes to buf, and is written to the
	// log once the hold is let go: a log sink that stalls must not hold a
	// reload either (plan 7e, Ruling 10).
	buf := newHeldLog()
	pol, hold := b.Policy.Hold()
	held := true
	release := func() {
		if held {
			held = false
			hold()
			buf.Flush(b.Log, b.blobLanded)
		}
	}
	defer release()
	// A reload can land between the membership read and the hold, and
	// declare the username the directory gave this member: the collision
	// is judged again under the policy the mint holds, as verify judged it
	// under the one it saw (final review M-1).
	// A workload's username is settled again here (decision 41 ruling 4):
	// its own subject's declaration is no collision, another's is.
	if m, err = heldCollision(pol, m, answer); err != nil {
		release()
		ref := directoryRefusal(directory.ErrUsernameTaken)
		b.emit(decision.Record{TS: now, Event: decision.EventMint, Verdict: decision.VerdictDeny, Reason: ref.Reason,
			Principal: principal, Auth: c.auth(), Sweep: sweepOf(req)})
		b.answerRefusal(w, r, ref)
		return
	}
	if b.mintGateRefuses(w, pol, now, c, req) {
		release()
		return
	}
	// Nothing under the hold takes a second one: a pending Swap blocks every
	// new Hold, so a nested one would wait on the swap that waits on this.
	ctx, cancel := context.WithTimeout(r.Context(), holdTimeout)
	defer cancel()
	// The challenge a retried mint names is taken only now that the request
	// holds its reservation and has passed the collision and the mint gate,
	// and under this caller's own binding: a request refused above, the
	// gate's 503 among them, spends no proof, and another caller's challenge
	// is not found (decision 45 ruling 14; re-review R1; final review broker
	// I2).
	mf := &mfaRequest{agentSHA256: callerAgentKey(c, r)}
	if req.PerLoginMFAChallenge != "" {
		mf.proved, mf.takeErr = b.takeProved(ctx, c, mf.agentSHA256, req.PerLoginMFAChallenge)
	}
	resp := api.MintResponse{Principal: principal}
	resp.Subject, resp.Subjects = subjectNames(pol, m)
	for _, name := range req.Devices {
		item, err := b.mintOne(ctx, buf, pol, m, answer, c, name, req, res, bodyHash, mf)
		if errors.Is(err, token.ErrIdempotencyInProgress) {
			// This device's hold was taken by another request under the
			// key, or lapsed before its turn: two retries that both
			// abandoned a replay, or a batch that outlasted its
			// reservation. Nothing is minted for it, and the devices
			// already minted are completed records a retry replays — unless
			// a revocation landed while they were written.
			release()
			if b.revokedSince(w, r, c, resp.Results) {
				return
			}
			b.writeInProgress(w)
			return
		}
		resp.Results = append(resp.Results, item)
	}
	release()
	if b.revokedSince(w, r, c, resp.Results) {
		return
	}
	resp.Next = next
	writeJSON(w, http.StatusOK, resp)
}

// mintGateRefuses asks MintGate of pol and, when it refuses, writes the
// answer and the record: 503 store_unavailable, minting nothing. The empty
// page of a sweep asks it too, so a broker the gate has not cleared answers
// no policy-derived page at all.
func (b *Broker) mintGateRefuses(w http.ResponseWriter, pol *policy.Policy, now time.Time, c caller, req api.MintRequest) bool {
	if b.MintGate == nil || b.MintGate(pol) == nil {
		return false
	}
	b.emit(decision.Record{TS: now, Event: decision.EventMint, Verdict: decision.VerdictDeny,
		Reason: decision.StoreUnavailable, Principal: c.principal, Auth: c.auth(), Sweep: sweepOf(req)})
	w.Header().Set("Retry-After", "5")
	writeError(w, http.StatusServiceUnavailable, string(decision.StoreUnavailable),
		"the broker has not yet recorded what it serves in the store, or seen it judged since it started, "+
			"so it minted nothing; retry shortly")
	return true
}

// sweepRequestError is why a request naming scope or after is malformed, or
// "" (decision 42 ruling 1): a scope in place of devices, after only beside
// a scope, each written as an inventory name is.
func sweepRequestError(req api.MintRequest, hasDevices bool) string {
	switch {
	case req.Scope == "":
		return "after continues a sweep: name its scope (design §17)"
	case hasDevices:
		return "name devices or a scope, not both (design §17)"
	case !deviceName(req.Scope):
		return fmt.Sprintf("a scope is 1 to %d printable ASCII characters", maxDeviceName)
	case req.After != "" && !printable(req.After, maxInventoryName):
		return fmt.Sprintf("a sweep's after is 1 to %d printable ASCII characters", maxInventoryName)
	}
	return ""
}

// sweepOf is the sweep block a mint record carries, nil for a mint by name
// (decision 42 ruling 4).
func sweepOf(req api.MintRequest) *decision.Sweep {
	if req.Scope == "" {
		return nil
	}
	return &decision.Sweep{Scope: req.Scope, After: req.After}
}

// authenticate is the first step of every authenticated endpoint but the
// refresh, which re-authenticates (spec §5.6): the caller is the
// connection's verified certificate (Identity) and nothing in the request;
// the connection is within max_session_age (decision 17); no revocation
// stands against the principal or the certificate, read before anything
// else so a revoked caller is told nothing more (spec §5.1.4); and the
// certificate's status does not refuse it (decision 33). A caller any of
// these refuses is answered here, recorded once under event with a mint's
// reasons and meanings (spec §5.7; decision 34), and ok is false. nothing
// completes the marks-unreadable answer: "so it minted nothing".
func (b *Broker) authenticate(w http.ResponseWriter, r *http.Request, event, nothing string) (caller, bool) {
	raw, hasBearer, berr := bearerOf(r)
	hasCert := r.TLS != nil && (len(r.TLS.PeerCertificates) > 0 || len(r.TLS.VerifiedChains) > 0)
	switch {
	case hasBearer && hasCert:
		writeError(w, http.StatusBadRequest, "bad_request", "one credential per request: a client certificate or "+
			"an Authorization header, not both")
		return caller{}, false
	case hasBearer && berr != nil:
		b.emit(decision.Record{TS: b.Now(), Event: event, Verdict: decision.VerdictDeny,
			Reason: decision.TrustDomainUnresolved, Auth: &decision.Auth{Method: "oidc"}})
		writeError(w, http.StatusUnauthorized, string(decision.TrustDomainUnresolved), berr.Error())
		return caller{}, false
	case hasBearer:
		c, ok := b.bearerCaller(w, r, event, nothing, raw)
		if ok && b.Issuer != nil && c.oidc.Domain == oidc.Humans {
			// One path for people (decision 43 ruling 13): this broker
			// exchanges a person's ID token for a certificate, and takes it
			// nowhere else.
			b.emit(decision.Record{TS: b.Now(), Event: event, Verdict: decision.VerdictDeny,
				Reason: decision.TrustDomainUnresolved, Principal: c.principal, Auth: c.auth()})
			writeError(w, http.StatusUnauthorized, string(decision.TrustDomainUnresolved), personBearerText)
			return caller{}, false
		}
		return c, ok
	case b.NoX509 && !(hasCert && (b.Workload != nil || b.Issuer != nil)):
		// An OIDC-only broker has no anchor and asks for no certificate: say
		// what it does take rather than blame a certificate.
		detail := "this broker accepts an OIDC ID token only (Authorization: Bearer); run `port49 login`"
		switch {
		case b.Issuer != nil:
			detail = "this broker takes the certificate it issues at `port49 login`, or a workload's where " +
				"broker.identity.machines names one; run `port49 login`"
		case b.Workload != nil:
			detail = "this broker accepts an OIDC ID token (Authorization: Bearer), or a workload certificate " +
				"where broker.identity.machines names one; run `port49 login`"
		}
		b.emit(decision.Record{TS: b.Now(), Event: event, Verdict: decision.VerdictDeny,
			Reason: decision.TrustDomainUnresolved, Auth: &decision.Auth{Method: "oidc"}})
		writeError(w, http.StatusUnauthorized, string(decision.TrustDomainUnresolved), detail)
		return caller{}, false
	}
	now := b.Now()
	authTime := b.authTime(r)
	cc, err := b.CertCallerOf(r.TLS, now)
	principal, legacy, cred := cc.Principal, cc.Legacy, cc.Cred
	if b.Directory != nil && cc.Domain == DomainHumans && cc.SignIn == nil {
		if h := heldOf(r); h != nil && h.answer != nil {
			principal = h.answer.Principal // already mapped: it names the refusal's caller
		}
	}
	// named is whose request a refusal records: the principal when known,
	// else the one the certificate's email SAN gave before a directory.
	named := cmp.Or(principal, legacy)
	if err != nil {
		// A chain the anchor verified is named on the refusal (principal when
		// it maps to one, the fingerprint always); no chain names no one. A
		// workload naming no principal is identity_unmapped (decision 40).
		reason := decision.TrustDomainUnresolved
		if errors.Is(err, ErrWorkloadUnmapped) {
			reason = decision.IdentityUnmapped
		}
		b.emit(decision.Record{TS: now, Event: event, Verdict: decision.VerdictDeny,
			Reason: reason, Principal: named,
			Auth: &decision.Auth{Method: "cert", Fingerprint: cred.Fingerprint}})
		writeError(w, http.StatusUnauthorized, string(reason), err.Error())
		return caller{}, false
	}
	// viaOIDC or viaDir is the sign-in a certificate this broker issued
	// carries: every record the certificate makes names it (decision 43
	// rulings 10, 11; decision 47).
	var viaOIDC *decision.OIDC
	var viaDir *decision.DirectoryPassword
	if cc.Issued != nil {
		viaOIDC = oidcAuth(*cc.Issued)
	}
	if cc.SignIn != nil && cc.SignIn.Method == issuer.MethodDirectoryPassword {
		viaDir = directoryPasswordAuth(*cc.SignIn)
	}
	if b.MaxSessionAge > 0 && now.Sub(authTime) > b.MaxSessionAge {
		b.emit(decision.Record{TS: now, Event: event, Verdict: decision.VerdictDeny,
			Reason: decision.SessionExpired, Principal: named,
			Auth: &decision.Auth{Method: cred.Method, OIDC: viaOIDC, DirectoryPassword: viaDir}})
		// Closing the connection is what makes the next request a handshake,
		// and the handshake is the fresh authentication decision 17 requires.
		w.Header().Set("Connection", "close")
		writeError(w, http.StatusUnauthorized, string(decision.SessionExpired), fmt.Sprintf(
			"this connection authenticated at %s, more than max_session_age (%s) ago; authenticate again",
			authTime.UTC().Format(time.RFC3339), b.MaxSessionAge))
		return caller{}, false
	}
	// marked reads the marks on principal (and also) and the certificate,
	// and answers the request when one stands or none can be read.
	marked := func(principal string, also ...string) bool {
		checkCtx, cancelCheck := context.WithTimeout(r.Context(), holdTimeout)
		rv, revoked, err := b.revocation(checkCtx, principal, cred, also...)
		cancelCheck()
		switch {
		case err != nil:
			b.emit(decision.Record{TS: now, Event: event, Verdict: decision.VerdictDeny,
				Reason: decision.StoreUnavailable, Principal: named,
				Auth: &decision.Auth{Method: cred.Method, OIDC: viaOIDC, DirectoryPassword: viaDir}})
			writeError(w, http.StatusServiceUnavailable, string(decision.StoreUnavailable),
				"the broker could not read the revocations in force, so it "+nothing+"; try again")
			return true
		case revoked:
			b.refuseRevokedAuth(w, event, now, named, cred, viaOIDC, viaDir, rv)
			return true
		}
		return false
	}
	// status answers the certificate's status refusal, if any (decision 33).
	status := func() bool {
		statusCtx, cancelStatus := context.WithTimeout(r.Context(), holdTimeout)
		ref := b.certRefusal(statusCtx, r.TLS, cred)
		cancelStatus()
		if ref == nil {
			return false
		}
		b.emit(decision.Record{TS: now, Event: event, Verdict: decision.VerdictDeny, Reason: ref.Reason,
			Principal: named, Auth: &decision.Auth{Method: cred.Method, Fingerprint: cred.Fingerprint,
				OIDC: viaOIDC, DirectoryPassword: viaDir}})
		b.answerRefusal(w, r, ref)
		return true
	}
	// Without a directory, for a workload, which never reaches one (decision 40 ruling 5), and for
	// a certificate this broker issued, whose principal its sign-in gave (decision 43 ruling 10):
	// the principal is the certificate's own.
	if b.Directory == nil || cc.Domain == DomainMachines || cc.SignIn != nil {
		if marked(principal) || status() {
			return caller{}, false
		}
		c := caller{principal: principal, cred: cred, authTime: authTime, oidc: cc.Issued, signIn: cc.SignIn}
		// A certificate this broker issued answers to its sign-in's
		// logouts (decision 43 ruling 16).
		if cc.Issued != nil && b.issuedLoggedOut(w, r, event, nothing, now, c) {
			return caller{}, false
		}
		// Only a certificate that is served is counted late.
		b.noteRenewal(cc, now)
		return c, true
	}
	// Under a directory the certificate's own marks (its key, and the
	// principal its email SAN gave before a directory: pre-flight I-16) and
	// its status are decided before the mapping, so a request with no held
	// connection never maps a revoked certificate (pre-flight I-4); the
	// mapped principal's mark after (Ruling 4).
	if marked("", legacy) || status() {
		return caller{}, false
	}
	if principal == "" {
		var ref *BindRefusal
		if principal, ref = b.pinnedPrincipal(r, cred); ref != nil {
			b.emit(decision.Record{TS: now, Event: event, Verdict: decision.VerdictDeny, Reason: ref.Reason,
				Principal: legacy, Auth: &decision.Auth{Method: cred.Method, Fingerprint: cred.Fingerprint}})
			b.answerRefusal(w, r, ref)
			return caller{}, false
		}
		named = principal
	}
	if marked(principal) {
		return caller{}, false
	}
	return caller{principal: principal, legacy: legacy, cred: cred, authTime: authTime}, true
}

// callerOf is the caller of a request that does not map: the principal and
// credential of the connection's verified certificate, legacy, the
// principal its email SAN gave before a directory ("" without one), issued,
// the OIDC sign-in a certificate this broker issued carries, and signIn, its
// sign-in of either method (each nil for any other; decision 43 ruling 10). Under a directory the principal is
// the one pinned to the held connection at bind (Ruling 4), never the
// email SAN's; a connection with no pin is refused (errNoPin). An issued
// certificate is never mapped.
func (b *Broker) callerOf(r *http.Request, now time.Time) (principal, legacy string, cred store.Credential,
	issued *oidc.Assertion, signIn *issuer.SignIn, err error) {
	cc, err := b.CertCallerOf(r.TLS, now)
	if err != nil || b.Directory == nil || cc.Domain == DomainMachines || cc.SignIn != nil {
		return cc.Principal, cc.Legacy, cc.Cred, cc.Issued, cc.SignIn, err
	}
	if h := heldOf(r); h != nil && h.answer != nil {
		return h.answer.Principal, cc.Legacy, cc.Cred, nil, nil, nil
	}
	b.logf("broker: a held connection has no directory principal pinned (the listener has no Map); refusing it")
	return "", cc.Legacy, cc.Cred, nil, nil, errNoPin
}

// errNoPin is a connection under a directory with no principal pinned to it:
// a wiring fault, answered as the directory not answering (503
// directory_unavailable), never as the certificate's fault.
var errNoPin = errors.New("broker: this connection has no directory principal pinned to it")

// legacyOf is the principal r's certificate had before a directory, "" when
// there is no directory or none: the mark a re-read after a write also reads.
func (b *Broker) legacyOf(r *http.Request) string {
	if b.Directory == nil || r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
		return ""
	}
	if machine, _ := b.machineChain(r.TLS); machine {
		return "" // a workload answers to no person's mark (decision 40 ruling 3)
	}
	return legacyPrincipal(r.TLS.VerifiedChains[0][0])
}

// pinnedPrincipal is the principal the listener mapped at bind and pinned to
// r's connection: it is never mapped again for the life of the connection
// (Ruling 4). A request with no held connection (a handler driven without
// Server) maps now, bounded as the listener's bind is, or returns the
// mapping's refusal. A held connection with no pin is a wiring fault (a
// directory without Listener.Map): it is refused directory_unavailable, never
// mapped per request.
func (b *Broker) pinnedPrincipal(r *http.Request, cred store.Credential) (string, *BindRefusal) {
	if h := heldOf(r); h != nil {
		if h.answer != nil {
			return h.answer.Principal, nil
		}
		b.logf("broker: a held connection has no directory principal pinned (the listener has no Map); refusing it")
		return "", directoryRefusal(directory.ErrUnavailable)
	}
	timeout := holdTimeout
	if q := b.Directory.Cfg.QueryTimeout; q > 0 {
		timeout = q + time.Second
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	a, ref := b.BindMap(ctx, *r.TLS, cred)
	if ref != nil {
		return "", ref
	}
	return a.Principal, nil
}

// revokedSince reads the marks again after a request's last token write,
// and answers the request when one stands (and, on the OIDC path, the
// logouts: Ruling 13). A revocation that landed while
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
func (b *Broker) revokedSince(w http.ResponseWriter, r *http.Request, c caller, items []api.MintItem) bool {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), holdTimeout)
	defer cancel()
	principal, cred := c.principal, c.cred
	rv, revoked, err := b.revocation(ctx, principal, cred, b.legacyOf(r))
	var l logoutRefusal
	var out bool
	if err == nil && !revoked && c.oidc != nil {
		l, out, err = b.loggedOut(ctx, *c.oidc)
	}
	switch {
	case err != nil:
		now := b.Now()
		for _, it := range items {
			if it.Verdict == decision.VerdictPermit {
				b.supersede(ctx, store.TokenKey{NAS: it.Device, Username: it.Username}, now)
			}
		}
		b.emit(decision.Record{TS: now, Event: decision.EventMint, Verdict: decision.VerdictDeny,
			Reason: decision.StoreUnavailable, Principal: principal, Auth: c.auth()})
		writeError(w, http.StatusServiceUnavailable, string(decision.StoreUnavailable), "the broker could not "+
			"confirm that no revocation landed during this mint, so it returns nothing; try again")
		return true
	case revoked:
		if b.unmint(ctx, principal, cred, c.auth(), items) == 0 {
			rec := revokedRecord(b.Now(), principal, cred)
			rec.Auth = c.auth()
			b.emit(rec)
		}
		answerRevoked(w, rv)
		return true
	case out:
		if b.unmint(ctx, principal, cred, c.auth(), items) == 0 {
			rec := revokedRecord(b.Now(), principal, cred)
			rec.Auth = c.auth()
			b.emit(rec)
		}
		b.answerLoggedOut(w, l)
		return true
	}
	return false
}

// revocation is the mark refusing this caller, if any: one on the
// principal, then one on each further principal (the legacy email-SAN
// principal of a certificate a directory maps: pre-flight I-16), then one
// on the certificate (spec §5.1.4). An empty principal is never read. A
// certificate with no issuer or serial is never a mark's key.
func (b *Broker) revocation(ctx context.Context, principal string, cred store.Credential, also ...string) (store.Revocation, bool, error) {
	var keys [][2]string
	for _, p := range append([]string{principal}, also...) {
		if p != "" {
			keys = append(keys, [2]string{store.RevocationPrincipal, p})
		}
	}
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

// refuseRevokedAuth answers a caller a revocation stands against before it
// was answered anything else: one record under event naming whose
// credential it was (spec §5.7), and answerRevoked. A refresh under a mark
// is recorded as a refresh (pre-flight M2), any other call under its
// endpoint's event (decision 34). The record names the caller's sign-in:
// OIDC's (via), a directory password's (viaDir), or neither.
func (b *Broker) refuseRevokedAuth(w http.ResponseWriter, event string, now time.Time, principal string,
	cred store.Credential, via *decision.OIDC, viaDir *decision.DirectoryPassword, rv store.Revocation) {
	rec := revokedRecord(now, principal, cred)
	rec.Event = event
	rec.Auth.OIDC, rec.Auth.DirectoryPassword = via, viaDir
	b.emit(rec)
	answerRevoked(w, rv)
}

// revokedRecord is a mint refused credential_revoked: it names whose
// credential it was as trust_domain_unresolved does (spec §5.7).
func revokedRecord(now time.Time, principal string, cred store.Credential) decision.Record {
	return decision.Record{TS: now, Event: decision.EventMint, Verdict: decision.VerdictDeny,
		Reason: decision.CredentialRevoked, Principal: principal,
		Auth: &decision.Auth{Method: cred.Method, Fingerprint: cred.Fingerprint}}
}

// MarkChanged is a mark made or lifted on a broker process, this one
// included, as the marks feed brings it (plan 7e, Ruling 5): the
// listener's copy follows, and a mark that stands closes this process's
// held connections it names, as Revoke closes its own. A lift a reload
// found (Reloaded) is said, never silent: it may be a mark an etcd restore
// lost (final review 7e-1 C-1). The daemon's marks (b.Marks) are the
// feed's own to keep (store.FollowMarks).
//
// A mark the store flagged landed_after_lift is said once, as it is told
// Standing (store.MarkChange), off the feed's goroutine, whether or not this process runs its
// region (decision 51; R-I5): in the form its time against the lift's
// calls for (landedLine). One this process's own write failed to record
// is said as its own (Marks.FailedWrite; post-11b, C2).
func (b *Broker) MarkChanged(c store.MarkChange) {
	if c.Reloaded && !c.Standing {
		b.say("broker: a reload of the marks found the revocation of %s lifted: lifted on a broker process "+
			"while the marks feed was down, or lost by an etcd restore; revoke it again unless it was lifted "+
			"on purpose", printsafe.Line(c.Key, 160))
	}
	if c.Standing {
		own := b.Marks.FailedWrite(c.Kind, c.Key, c.At)
		switch {
		case c.LandedAfterLift:
			// The lift's record is read off the feed's goroutine, so a slow
			// directory never stalls the marks every login and mint read
			// (task 2 review M1). Flagged marks are rare: each needs a lift
			// of its key within the hour.
			go func(r store.Revocation) {
				line := b.landedLine(r)
				if own {
					line += "; " + b.ownClause()
				}
				b.say("%s", line)
			}(c.Revocation)
		case own:
			b.say("broker: a revocation of %s %s, landed when the store answered again; it stands everywhere",
				printsafe.Line(c.Key, 160), b.ownClause())
		}
	}
	if b.Conns == nil {
		return
	}
	b.Conns.Revoked(c.Revocation, c.Standing)
	if !c.Standing {
		return
	}
	if n := b.Conns.CloseHeld(matchMark(c.Revocation)); n > 0 {
		b.say("broker: a revocation of %s made on a broker process closed %d held connection(s) here",
			printsafe.Line(c.Key, 160), n)
	}
}

// landedReadTimeout bounds the read of a lift's record for a flagged mark's
// line, read off the marks feed's goroutine (MarkChanged); one that does not
// answer in time is said in the unreadable form.
const landedReadTimeout = 5 * time.Second

// landedLine is the line for r, a mark flagged landed_after_lift (spec §13
// decision 51; re-review R-I2): r's time against the lift's, read from its
// record, says whether it was a copy sent before the lift and held back by
// a cut, or a revoke made after it by a writer that had not yet seen it.
// Clocks are NTP-close and a cut lasts seconds. No form tells anyone to
// lift again but a runner's put-back of a mark made before the lift
// (store.PutBackOrigin; task 2 review I1), which re-created a lifted mark,
// as sayPutBack says: a put-back made after it was a revoke the store had
// lost.
func (b *Broker) landedLine(r store.Revocation) string {
	ctx, cancel := context.WithTimeout(context.Background(), landedReadTimeout)
	defer cancel()
	l, err := b.Store.GetLift(ctx, r.Kind, r.Key)
	key := printsafe.Line(r.Key, 160)
	_, putBack := store.PutBackOf(r.Origin)
	switch {
	case err == nil && putBack && r.At.Before(l.At):
		return fmt.Sprintf("broker: a revocation of %s made at %s was put back after the lift at %s by a "+
			"port49-broker runner from its broker.state_dir/marks.json: its watch had not delivered the lift, which "+
			"it cannot tell from a mark an etcd restore lost; it stands everywhere; lift it again with port49 revoke "+
			"--lift if it was lifted on purpose", key, r.At.UTC().Format(time.RFC3339), l.At.UTC().Format(time.RFC3339))
	case err == nil && putBack:
		return fmt.Sprintf("broker: a revocation of %s made at %s after the lift at %s was put back by a "+
			"port49-broker runner from its broker.state_dir/marks.json: the store had lost it (an etcd restore); it "+
			"stands everywhere", key, r.At.UTC().Format(time.RFC3339), l.At.UTC().Format(time.RFC3339))
	case errors.Is(err, store.ErrNotFound):
		return fmt.Sprintf("broker: a revocation of %s landed after a lift; the lift's record has expired", key)
	case err != nil:
		return fmt.Sprintf("broker: a revocation of %s landed after a lift; the lift's record could not be read "+
			"(%s): `port49 revoke --list` names it", key, printsafe.Line(err.Error(), 300))
	case r.At.Before(l.At):
		return fmt.Sprintf("broker: a revocation of %s made at %s before the lift at %s landed after it: a copy "+
			"sent while its writer was cut off; it stands everywhere", key, r.At.UTC().Format(time.RFC3339),
			l.At.UTC().Format(time.RFC3339))
	}
	return fmt.Sprintf("broker: a revocation of %s made at %s (%s) after the lift at %s, by a writer whose marks "+
		"feed had not yet shown the lift; it stands everywhere; check with whoever revoked before lifting", key,
		r.At.UTC().Format(time.RFC3339), printsafe.Line(r.Origin, 160), l.At.UTC().Format(time.RFC3339))
}

// ownClause says a mark was this process's own write, reported failed.
func (b *Broker) ownClause() string {
	return "made on this " + b.proc() + ", reported unrecorded then"
}

// RefusedAtBind records a request the broker's listener refused as its
// connection bound (Listener.Refused): credential_revoked for a mark on its
// principal or certificate, or the reason its certificate's status gave.
// It is the one deny record a call refused after the bind writes, under
// the event of the path it asked for (bindEvent), counted in
// port49_decisions (spec §5.7; decision 34).
func (b *Broker) RefusedAtBind(path, principal string, cred store.Credential, reason decision.Reason) {
	rec := revokedRecord(b.Now(), principal, cred)
	rec.Event, rec.Reason = bindEvent(path), reason
	b.emit(rec)
}

// bindEvent is the event a request refused as its connection bound is
// recorded under: its endpoint's own, and mint for any other path, as
// before (decision 34). It matches the path alone, not the method, by
// design: the request reaches no handler, so its event is all it names.
func bindEvent(path string) string {
	switch path {
	case "/v1/identity":
		return decision.EventIdentity
	case "/v1/explain":
		return decision.EventExplain
	case "/v1/tokens/revoke":
		return decision.EventRevoke
	}
	return decision.EventMint
}

// answerRevoked is the 401 credential_revoked, with the connection closed
// so nothing more rides it.
func answerRevoked(w http.ResponseWriter, rv store.Revocation) {
	w.Header().Set("Connection", "close")
	writeJSON(w, http.StatusUnauthorized, revokedError(rv))
}

// revokedError is credential_revoked's body, the same from a mint and from
// the listener's answer to a marked connection (Listener.answerRevoked).
//
// A mark a CA's revocation wrote, its origin a source's ("crl <name>",
// "ocsp <responder>"; spec §5.1.4), says the CA revoked it and offers no
// lift: the user cannot lift it, and the CA has revoked the certificate.
// After a lift the next bind checks the CA again, which refuses it, or,
// with the list gone stale, answers certificate_status_unavailable (or
// admits it under on_unavailable: allow); a lift is no fix.
func revokedError(rv store.Revocation) api.Error {
	what := "this principal"
	if rv.Kind == store.RevocationCert {
		what = "this certificate"
		if strings.HasPrefix(rv.Origin, "crl ") || strings.HasPrefix(rv.Origin, "ocsp ") {
			return api.Error{Error: string(decision.CredentialRevoked), Detail: fmt.Sprintf(
				"%s was revoked at its CA (%s) and marked at %s; nothing is minted for it; "+
					"request a new certificate", what,
				printsafe.Line(rv.Origin, 160), rv.At.UTC().Format(time.RFC3339))}
		}
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
//
// A replayed item's tokens are deleted too, but it gets no deny: this
// request recorded no permit for it, and the permit a device deny would
// follow is the original mint's, whose tokens were returned then and so
// were issued (port49 capability; Task 7 review N1).
func (b *Broker) unmint(ctx context.Context, principal string, cred store.Credential, auth *decision.Auth,
	items []api.MintItem) int {
	now := b.Now()
	n := 0
	for _, it := range items {
		if it.Verdict != decision.VerdictPermit {
			continue
		}
		k := store.TokenKey{NAS: it.Device, Username: it.Username}
		err := b.Store.DeleteTokens(ctx, k)
		if err != nil {
			b.logf("broker: deleting the tokens a revoked mint wrote under %q on %q: %v; they expire at their TTL",
				it.Username, it.Device, err)
		}
		b.supersede(ctx, k, now)
		if it.Replayed {
			continue
		}
		rec := revokedRecord(now, principal, cred)
		rec.Auth = auth
		rec.Device = &decision.Device{Name: it.Device, Platform: it.Platform}
		if err != nil {
			rec.IndexError = fmt.Sprintf("tokens not deleted: %v; they expire at their TTL", err)
		}
		b.emit(rec)
		n++
	}
	return n
}

// supersede records that k's unspent tokens were deleted at at: in this
// process, so its own replays mint afresh whatever the store says, and in
// the store, so every broker process's do (plan 7e, Ruling 9). A store
// write that fails is said, and this process's copy still covers its own
// replays; another process may then answer one with a deleted token's
// record, which redeems token_not_found.
func (b *Broker) supersede(ctx context.Context, k store.TokenKey, at time.Time) {
	b.mu.Lock()
	if b.superseded == nil {
		b.superseded = map[store.TokenKey]supersededMark{}
	}
	now := b.Now()
	mark := b.superseded[k]
	if at.After(mark.at) {
		mark.at = at
	}
	mark.recorded = now
	b.superseded[k] = mark
	if now.Sub(b.supersedePruned) >= supersedePruneEvery {
		b.supersedePruned = now
		for key, m := range b.superseded {
			if now.Sub(m.recorded) > store.SupersededFor {
				delete(b.superseded, key)
			}
		}
	}
	b.mu.Unlock()
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), holdTimeout)
	defer cancel()
	if err := b.Store.SupersedeTokens(sctx, k, at); err != nil {
		b.logf("broker: recording that the tokens under %q on %q were superseded: %v; this process still "+
			"mints a replay of them afresh", k.Username, k.NAS, err)
	}
}

// supersededMark is one key's entry in Broker.superseded: at is the instant
// a replay of a mint from before is minted afresh, and recorded when this
// process last recorded it, what the entry's life runs from. A refresh's at
// is a deleted token's MintedAt, which may be older than SupersededFor.
type supersededMark struct{ at, recorded time.Time }

// supersedePruneEvery bounds how often supersede prunes its local copy: an
// entry lives at most this long past SupersededFor, which only ever mints
// a replay afresh.
const supersedePruneEvery = time.Minute

// supersededAt is the later of this process's instant for k and the
// store's (every process's, and a start's purge).
func (b *Broker) supersededAt(ctx context.Context, k store.TokenKey) (time.Time, error) {
	b.mu.Lock()
	local := b.superseded[k].at
	b.mu.Unlock()
	at, err := b.Store.SupersededAt(ctx, k)
	if err != nil {
		return time.Time{}, err
	}
	if local.After(at) {
		at = local
	}
	return at, nil
}

// mintOne answers one device. The only error it returns is
// ErrIdempotencyInProgress, which is the whole request's; every other refusal
// is an item. Every record it writes goes to buf, the request's buffer
// (tokens).
func (b *Broker) mintOne(ctx context.Context, buf *heldLog, pol *policy.Policy, m policy.Member,
	answer *directory.Answer, c caller, name string, req api.MintRequest, hold *token.Reservation,
	bodyHash string, mf *mfaRequest) (api.MintItem, error) {
	principal := m.Principal
	var res policy.Resolution
	// mfaRec is the per-login requirement's part of this item's records: set
	// once the requirement is judged, so a deny after it carries it too.
	var mfaRec *decision.PerLoginMFA
	ca := c.auth()
	deny := func(reason decision.Reason, platform string) api.MintItem {
		rec := decision.Record{TS: b.Now(), Event: decision.EventMint, Verdict: decision.VerdictDeny, Reason: reason,
			Principal: principal, Auth: &decision.Auth{Method: c.cred.Method, Directory: directoryAuth(answer),
				OIDC: ca.OIDC, K8s: ca.K8s, DirectoryPassword: ca.DirectoryPassword},
			Device: &decision.Device{Name: name, Platform: platform}, Sweep: sweepOf(req), PerLoginMFA: mfaRec}
		if len(res.Subjects) > 0 {
			rec.Policy = &decision.Policy{Bundle: pol.Bundle, Subjects: res.Subjects}
		}
		b.emitTo(buf, rec)
		return api.MintItem{Device: name, Verdict: decision.VerdictDeny, Reason: string(reason)}
	}
	dev, ok := pol.Device(name)
	if !ok {
		// The same answer as a device with no grant: the API must not tell a
		// caller which devices exist (design §17). The record names the
		// device and no platform, which is what tells an operator which.
		return deny(decision.NoGrantsMatched, ""), nil
	}
	res, err := pol.ResolveMember(m, dev, b.Now())
	switch {
	case errors.Is(err, policy.ErrNoGrants):
		return deny(decision.NoGrantsMatched, dev.Platform), nil
	case errors.Is(err, policy.ErrNoUsername):
		// The directory gave this principal no username: nothing falls back
		// to a declared name (spec §2, decision 38).
		b.logf("broker: %v", err)
		return deny(decision.IdentityUnmapped, dev.Platform), nil
	case errors.Is(err, policy.ErrCompositionRefused):
		// The principal's subjects compose here to a reply a joint check
		// refuses: this device alone, never a quarantine (Ruling 5).
		b.logf("broker: %v", err)
		return deny(decision.CompositionRefused, dev.Platform), nil
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
	// The device's ceiling is the least of its roles' (spec §5.6). One that
	// has passed since this connection authenticated would mint a token for a
	// context born expired: refused for this device alone, and `port49
	// refresh` resumes it (decision 33).
	age := res.SessionAge.Of(b.MaxSessionAge)
	if age > 0 && !b.Now().Before(c.authTime.Add(age)) {
		item := deny(decision.SessionExpired, dev.Platform)
		item.Detail = "this device's session ceiling has passed since you authenticated; run 'port49 refresh'"
		return item, nil
	}
	var supersededAt time.Time
	if hold != nil { // only a request under an Idempotency-Key can be replayed
		var err error
		if supersededAt, err = b.supersededAt(ctx, store.TokenKey{NAS: name, Username: res.Username}); err != nil {
			return deny(decision.StoreUnavailable, dev.Platform), nil
		}
	}
	// A replay is answered before the requirement is read: a retry whose
	// answer was lost returns the token it minted, though the proof that
	// covered it is spent (decision 45 ruling 14).
	cred := c.cred
	var perLogin *decision.PerLoginMFA
	// judge reads the requirement; denied is true when it refuses the item.
	judge := func() (item api.MintItem, denied bool) {
		v := b.judgeMFA(ctx, c, mf, name, res.PerLoginMFA, b.Now(), nil)
		mfaRec = v.rec
		if v.reason != "" {
			item = deny(v.reason, dev.Platform)
			item.Detail, item.PerLoginMFA = v.detail, v.item
			return item, true
		}
		perLogin = v.rec
		cred.MFAMethod, cred.MFAAt, cred.MFAAgentSHA256, cred.MFAFresh = v.method, v.at, v.agent, v.fresh
		return api.MintItem{}, false
	}
	// Replay-versus-fresh is decided here once. The mint is told, so one
	// that finds the replay gone refuses (ErrReplayLapsed) instead of
	// minting afresh under a requirement nothing judged.
	replays := res.PerLoginMFA.Required() &&
		b.Minter.Replays(token.Request{Device: name, Reservation: hold, SupersededAt: supersededAt})
	if res.PerLoginMFA.Required() && !replays {
		if item, denied := judge(); denied {
			return item, nil
		}
	}
	body, hash, err := engine.Encode(res.Blob)
	if err != nil {
		b.logf("broker: the policy for %s on %q compiled to a blob the daemon would refuse: %v", principal, name, err)
		return b.fault(name, "broker_error", "the broker could not compile this device's policy; tell the operator"), nil
	}
	if err := b.putBlob(ctx, buf, hash, body, blobTTL(age, b.MaxSessionAge)); err != nil {
		return deny(decision.StoreUnavailable, dev.Platform), nil
	}
	mint := func(replayOnly bool) (token.Result, error) {
		return b.Minter.Mint(ctx, token.Request{
			Subject: token.Subject{Principal: principal, Username: res.Username, TokenTTL: res.TokenTTL,
				Enable: res.Enable, MaxPrivilege: res.MaxPrivilege, MaxSessionAge: age,
				Credential: cred, AuthTime: c.authTime, VerifiedAt: verifiedAt(answer)},
			Device: name, Platform: dev.Platform, BlobHash: hash, WithEnable: req.Enable,
			TTL:         time.Duration(req.TTLSeconds) * time.Second,
			Reservation: hold, BodyHash: bodyHash, SupersededAt: supersededAt, ReplayOnly: replayOnly,
			Policy:    &decision.Policy{Bundle: pol.Bundle, Subject: res.Subject, Subjects: res.Subjects, Grants: res.Grants},
			Directory: directoryAuth(answer), OIDC: ca.OIDC, K8s: ca.K8s, DirectoryPassword: ca.DirectoryPassword,
			Log: buf, Sweep: sweepOf(req), PerLoginMFA: perLogin})
	}
	out, err := mint(replays)
	if errors.Is(err, token.ErrReplayLapsed) {
		// The replay the requirement was skipped for is gone: judge the
		// requirement now, and mint afresh only if it is covered.
		if item, denied := judge(); denied {
			return item, nil
		}
		out, err = mint(false)
	}
	var capped *token.ErrTooManyOutstanding
	switch {
	case errors.Is(err, token.ErrIdempotencyInProgress):
		return api.MintItem{}, err
	case errors.As(err, &capped):
		return deny(decision.CandidateCapReached, dev.Platform), nil
	case errors.Is(err, token.ErrSessionExpired):
		// The ceiling passed between the check above and the mint.
		item := deny(decision.SessionExpired, dev.Platform)
		item.Detail = "this device's session ceiling has passed since you authenticated; run 'port49 refresh'"
		return item, nil
	case errors.Is(err, token.ErrNoAuthTime):
		b.logf("broker: minting for %s on %q: %v", principal, name, err)
		return b.fault(name, "broker_error", "the broker could not mint for this device; tell the operator"), nil
	case err != nil:
		return deny(decision.StoreUnavailable, dev.Platform), nil
	}
	// The minter emitted the permit record; the counter is the broker's. An
	// idempotent replay is counted again: it is a permit answered.
	b.Metrics.Decisions.WithLabelValues(decision.EventMint, decision.VerdictPermit, string(decision.GrantsMatched)).Inc()
	item := api.MintItem{Device: name, Verdict: decision.VerdictPermit, Platform: dev.Platform,
		Username: out.Username, Login: out.Login, Enable: out.Enable, ExpiresAt: out.ExpiresAt.UTC().Format(time.RFC3339),
		Replayed: out.Replayed}
	// A replay answers with the ceiling of the tokens it returns, which
	// their connection's authentication set. A record written before the
	// minter kept it has none, and is answered with this connection's.
	switch {
	case !out.SessionExpiresAt.IsZero():
		item.SessionExpiresAt = out.SessionExpiresAt.UTC().Format(time.RFC3339)
	case age > 0:
		item.SessionExpiresAt = c.authTime.Add(age).UTC().Format(time.RFC3339)
	}
	if len(dev.Addresses) > 0 {
		// A fact from the source of truth; the client must not trust it
		// further than an SSH host key (design §17).
		item.Address = dev.Addresses[0].String()
	}
	return item, nil
}

// blobTTL is how long a minted blob is kept: as long as the longest context
// it can back at mint (decision 19). A `never` context keeps it alive by
// the daemon's bump on activity (plan 7b, Task 6).
func blobTTL(age, def time.Duration) time.Duration {
	return max(age, def)
}

// fault is an item the broker could not decide: its own error, not a
// verdict, so it never carries a §5.7 reason and is counted apart from the
// decisions, by its code alone.
func (b *Broker) fault(name, code, detail string) api.MintItem {
	b.Metrics.BrokerItemErrors.WithLabelValues(code).Inc()
	return api.MintItem{Device: name, Error: code, Detail: detail}
}

// putBlob writes an encoded blob under its hash, and buffers its blob
// record into out the first time this process writes it (spec §5.1.1;
// §13, decision 19). out is the request's buffer, written to the log once
// the request lets go of the policy (plan 7e, Ruling 10); a hash is marked
// emitted only when its record lands (blobLanded), so a request that finds
// a hash unmarked buffers a blob record of its own, and within one sink
// every mint record follows one for its hash.
//
// Its store TTL is ttl, at least the ceiling of any context it backs
// (blobTTL): a context's session_expires is its auth_time plus that, and
// auth_time is never later than the mint, so no context this blob backs can
// outlive it. PutBlob keeps the later expiry, so a re-put never shortens it.
// The log's first copy serves every later re-put, including one after the
// store's copy expired (plan 3, Decided 8).
//
// A blob record the sink refuses is counted by
// port49_decision_log_write_failures_total and is not marked emitted, so
// the next mint that writes the hash emits it again: replay reads the log
// alone, and a mint record naming a blob the log never carried cannot be
// replayed. An Emitter that cannot report a refusal is trusted.
func (b *Broker) putBlob(ctx context.Context, out *heldLog, hash string, body []byte, ttl time.Duration) error {
	if err := b.Store.PutBlob(ctx, hash, body, ttl); err != nil {
		return err
	}
	if !b.blobSeen(hash) && !out.blobs[hash] {
		out.Emit(decision.Record{TS: b.Now(), Event: decision.EventBlob, Blob: b.blobEvent(hash, body)})
		out.blobs[hash] = true
	}
	return nil
}

// heldLog is the records one request or pass writes while it holds the
// policy, with the blob hashes it already carries a record for: two
// devices, or two contexts, that compile to one blob buffer one blob record
// between them, not one each (Task 4 review I1). One goroutine uses it.
type heldLog struct {
	*decision.Buffer
	blobs map[string]bool
}

func newHeldLog() *heldLog {
	return &heldLog{Buffer: decision.NewBuffer(), blobs: map[string]bool{}}
}

// blobLanded is Buffer.Flush's landed for the request's buffer: a blob
// record the sink took marks its hash emitted. One the sink refused is not
// marked, so the next mint that writes the hash emits it again (roadmap,
// plan 4).
func (b *Broker) blobLanded(r decision.Record, err error) {
	if err == nil && r.Event == decision.EventBlob && r.Blob != nil {
		b.markBlob(r.Blob.Hash)
	}
}

// markBlob records that hash's blob record landed in the log, forgetting
// every hash first when blobsSeen is full.
func (b *Broker) markBlob(hash string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.blobsSeen == nil || len(b.blobsSeen) >= blobsSeenMax {
		b.blobsSeen = map[string]bool{}
	}
	b.blobsSeen[hash] = true
}

// blobSeen reports whether hash's blob record has landed in the log.
func (b *Broker) blobSeen(hash string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.blobsSeen[hash]
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

// say is logf to Say when it is set.
func (b *Broker) say(format string, args ...any) {
	if b.Say == nil {
		b.logf(format, args...)
		return
	}
	redact := platform.AllRedactions()
	if b.Policy != nil {
		redact = b.Policy.Load().Redactions()
	}
	b.Say("%s", platform.RedactQuoted(redact, fmt.Sprintf(format, args...)))
}

// emit writes a refusal the broker decided itself, and counts it.
func (b *Broker) emit(r decision.Record) {
	b.emitTo(b.Log, r)
}

// emitTo is emit into to: a request's buffer, under the policy hold. The
// decision is counted when it is buffered, not when it lands; the two differ
// only for a process that dies before the flush.
func (b *Broker) emitTo(to decision.Emitter, r decision.Record) {
	to.Emit(r)
	b.Metrics.Decisions.WithLabelValues(r.Event, r.Verdict, string(r.Reason)).Inc()
}

// refuseRight answers a call that would act on another principal, or on a
// (device, username) whoever holds it, without the api: right that
// unlocks it: 403 api_right_missing, and rec, the one deny record. rec
// names whom the call was about and, in origin or explain.asked_by, who
// asked; it carries no auth, so a record's auth and principal always
// describe one credential (spec §5.7; decision 34). what says what was
// asked, for the answer. Nothing is done.
func (b *Broker) refuseRight(w http.ResponseWriter, rec decision.Record, right, what string) {
	rec.Verdict, rec.Reason, rec.Auth = decision.VerdictDeny, decision.APIRightMissing, nil
	b.emit(rec)
	writeError(w, http.StatusForbidden, string(decision.APIRightMissing), fmt.Sprintf(
		"%s needs the api: %s right, which your subject does not declare (spec §2)", what, right))
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
