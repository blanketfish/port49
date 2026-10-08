package broker

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/certstatus"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/printsafe"
	"github.com/rhwendt/port49/internal/store"
)

// StatusChecker is certstatus.Checker as the broker sees it.
type StatusChecker interface {
	Check(ctx context.Context, chain []*x509.Certificate) certstatus.Result
}

// BindRefusal is why a certificate is refused, and how it is answered:
// 401 for a verdict (revoked), 503 with Retry-After for a status that
// cannot be established, which ends no session (pre-flight I7).
type BindRefusal struct {
	Status        int
	Reason        decision.Reason
	Error, Detail string
	RetryAfter    int
	// revoke is the revocation a revoked leaf queues once it is answered.
	revoke *queuedRevoke
	// queue queues revoke; BindStatus sets it for the listener to run once
	// bind has chosen this refusal (BindStatus).
	queue func()
}

// certRefusal is the chain's status as a refusal, or nil to go on (spec
// §5.1.4; decision 33). A revoked leaf is refused and revoked through
// Revoke, queued, so every path reaches it and the mark outlives a source
// that goes stale; a revoked intermediate or a hold refuses without a mark.
// The revocation is the refusal's to queue (queueRevoke), once its answer is
// written.
// Unknown is refused as unavailable unless OnUnavailable is "allow".
func (b *Broker) certRefusal(ctx context.Context, cs *tls.ConnectionState, cred store.Credential) *BindRefusal {
	if b.CertStatus == nil || cs == nil || len(cs.VerifiedChains) == 0 {
		return nil
	}
	res := b.CertStatus.Check(ctx, cs.VerifiedChains[0])
	switch res.Verdict {
	case certstatus.Revoked:
		what, how := "this certificate", "was revoked"
		switch {
		case res.Depth > 0:
			what = fmt.Sprintf("this certificate's issuer, %s,", res.Subject)
		case res.Hold:
			how = "is on hold" // lifted by the CA, so never marked (M13)
		}
		ref := &BindRefusal{Status: http.StatusUnauthorized, Reason: decision.CredentialRevoked,
			Error: string(decision.CredentialRevoked), Detail: fmt.Sprintf(
				"%s %s at its CA (%s %s, %s); nothing is minted for it", what, how, res.Source,
				printsafe.Line(res.Name, 120), res.RevokedAt.UTC().Format(time.RFC3339))}
		if res.Depth == 0 && !res.Hold {
			ref.revoke = &queuedRevoke{cred.Issuer, cred.Serial, res.Source + " " + res.Name}
		}
		return ref
	case certstatus.Unknown:
		if b.OnUnavailable == "allow" {
			// Limited by a fixed class, never by the detail's text, which an
			// OCSP responder's answer can vary at will.
			b.sayOnce("allow "+unknownClass(res.Detail), 10*time.Minute, "broker: admitting a certificate whose "+
				"revocation status cannot be established (%s); broker.certificate_status.on_unavailable is allow",
				printsafe.Line(res.Detail, 300))
			return nil
		}
		// An uncovered status holds until the operator or the CA changes
		// something, and port49 workload takes it as final: never "try again".
		next := "try again"
		if unknownClass(res.Detail) == "uncovered" {
			next = "it stays so until a CRL or OCSP source covers this certificate"
		}
		return &BindRefusal{Status: http.StatusServiceUnavailable, Reason: decision.TrustDomainUnresolved,
			Error: "certificate_status_unavailable", RetryAfter: 60,
			Detail: "the broker cannot establish this certificate's revocation status (" + res.Detail + "); " + next}
	}
	return nil
}

// unknownClass is which kind of source left a status unestablished, from
// the fixed start certstatus gives each Unknown's detail: "crl" (a list past
// its next update), "ocsp" (a responder), "uncovered" (no source covers the
// issuer), or "other".
func unknownClass(detail string) string {
	switch {
	case strings.HasPrefix(detail, "CRL "):
		return "crl"
	case strings.HasPrefix(detail, "OCSP"):
		return "ocsp"
	case strings.HasPrefix(detail, api.UncoveredStatus):
		return "uncovered"
	}
	return "other"
}

// BindStatus is Listener.Status: the check before a connection binds. Its
// revocation is not queued here but by the listener, through the refusal's
// queue, once bind has chosen the refusal's answer: queued here, the
// queue's mark could land before bind, which would answer the mark ("an
// operator lifts the revocation") where the CA revoked it, and count no
// revoked_refused. The connection is not held, so the revocation closes the
// certificate's other connections and never this one's answer.
func (b *Broker) BindStatus(cs tls.ConnectionState, principal string, cred store.Credential) *BindRefusal {
	ctx, cancel := context.WithTimeout(context.Background(), holdTimeout)
	defer cancel()
	ref := b.certRefusal(ctx, &cs, cred)
	if ref != nil {
		ref.queue = func() { b.queueRevoke(ref) }
	}
	return ref
}

// queueRevoke queues the revocation ref carries, if any.
func (b *Broker) queueRevoke(ref *BindRefusal) {
	if ref != nil && ref.revoke != nil {
		b.enqueueRevoke(ref.revoke.issuer, ref.revoke.serial, ref.revoke.origin, false)
	}
}

// answerRefusal answers a request on a held connection refused for its
// certificate's status (writeRefusal), and then queues the revocation the
// refusal carries. That revocation closes the certificate's held
// connections, this one among them, so the answer goes first, whole and
// flushed, after the request's body is drained: a close with the body
// unread would be a reset the answer is lost to, and the agent would read a
// hang-up where it should read credential_revoked.
func (b *Broker) answerRefusal(w http.ResponseWriter, r *http.Request, ref *BindRefusal) {
	if ref.revoke != nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, maxBody))
	}
	writeRefusal(w, ref)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	b.queueRevoke(ref)
}

// writeRefusal answers a status refusal: a verdict closes the connection;
// an unavailable status keeps it, says when to retry, and ends nothing. Its
// length is set, so a flush sends the answer whole rather than chunked.
func writeRefusal(w http.ResponseWriter, ref *BindRefusal) {
	if ref.RetryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(ref.RetryAfter))
	} else {
		w.Header().Set("Connection", "close")
	}
	body, _ := json.Marshal(api.Error{Error: ref.Error, Detail: ref.Detail})
	body = append(body, '\n')
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(ref.Status)
	_, _ = w.Write(body)
}

// revokeQueueLen bounds the CRL revocations waiting; queueWarn is the
// count past which a load is said (pre-flight I9).
const (
	revokeQueueLen = 4096
	queueWarn      = 100
)

type queuedRevoke struct{ issuer, serial, origin string }

func (q queuedRevoke) key() [2]string { return [2]string{q.issuer, q.serial} }

// OnCRLEntry queues a certificate a CRL newly names; RunRevocationQueue
// revokes it if it is still present. It never blocks the loader. A restart
// names every entry of each list again (certstatus.LoadPersisted): one
// already marked is passed over at its turn, so a replay revokes and
// records nothing twice.
//
// bulk is a whole list rather than news: a restart's replay, or a source's
// first list. Its load is not said, since nearly every entry touches nothing
// in use, and a line saying thousands are queued would read as a revocation
// storm (final review M-6). Each entry is still checked.
func (b *Broker) OnCRLEntry(issuer, serial, source string, bulk bool) {
	b.enqueueRevoke(issuer, serial, "crl "+source, bulk)
}

// enqueueRevoke queues q once: a certificate already waiting, refused at
// every bind meanwhile, is not queued again. quiet does not say the queue's
// load.
func (b *Broker) enqueueRevoke(issuer, serial, origin string, quiet bool) {
	q := queuedRevoke{issuer, serial, origin}
	b.queueOnce.Do(func() { b.revokeQueue = make(chan queuedRevoke, revokeQueueLen) })
	b.mu.Lock()
	if b.queued == nil {
		b.queued = map[[2]string]bool{}
	}
	if b.queued[q.key()] {
		b.mu.Unlock()
		return
	}
	b.queued[q.key()] = true
	b.mu.Unlock()
	select {
	case b.revokeQueue <- q:
		if n := len(b.revokeQueue); n >= queueWarn && !quiet {
			b.sayOnce("queue", 10*time.Minute, "broker: %d CRL entries are being checked against what is in use; "+
				"each certificate is refused at every use meanwhile", n)
		}
	default:
		b.mu.Lock()
		delete(b.queued, q.key())
		b.mu.Unlock()
		b.pend(q) // full: kept for the next retry
	}
}

// RunRevocationQueue revokes queued certificates one at a time, each only
// if it is still present: a held connection, a live context, an unspent
// token. A store error reading those puts it on the pending set rather than
// marking it (pre-flight I9). Each Revoke takes 7a's semaphore in turn, so
// an operator's port49 revoke is served between two queued ones.
func (b *Broker) RunRevocationQueue(ctx context.Context) {
	b.queueOnce.Do(func() { b.revokeQueue = make(chan queuedRevoke, revokeQueueLen) })
	for {
		select {
		case <-ctx.Done():
			return
		case q := <-b.revokeQueue:
			b.mu.Lock()
			delete(b.queued, q.key())
			b.mu.Unlock()
			b.revokeIfPresent(ctx, q)
		}
	}
}

// revokeIfPresent revokes q's certificate unless a mark already stands on
// it (a restart's replay, or a second source naming it) or nothing of it is
// present.
func (b *Broker) revokeIfPresent(ctx context.Context, q queuedRevoke) {
	key := store.CertKey(q.issuer, q.serial)
	rctx, cancel := context.WithTimeout(ctx, holdTimeout)
	_, err := b.Store.GetRevocation(rctx, store.RevocationCert, key)
	cancel()
	switch {
	case err == nil:
		return
	case !errors.Is(err, store.ErrNotFound):
		b.pend(q)
		return
	}
	present := b.Conns != nil && b.Conns.HoldsCert(key)
	if !present {
		rctx, cancel := context.WithTimeout(ctx, holdTimeout)
		refs, err := b.Store.ContextsByCert(rctx, key)
		toks, err2 := b.Store.TokensByCert(rctx, key)
		cancel()
		if err != nil || err2 != nil {
			b.pend(q)
			return
		}
		present = len(refs) > 0 || len(toks) > 0
	}
	if !present {
		return
	}
	b.logf("broker: %s names a certificate in use (issuer=%q, serial=%s); revoking it", q.origin, q.issuer, q.serial)
	if _, err := b.Revoke(ctx, RevokeRequest{Issuer: q.issuer, Serial: q.serial, Origin: q.origin}); err != nil {
		b.logf("broker: revoking a certificate its CA revoked (%s): %v; it is refused at every use anyway", q.origin, err)
		if !errors.Is(err, ErrBadRevocation) {
			b.pend(q) // a name no mark can hold is never retried
		}
	}
}

// pend keeps q for RetryPending.
func (b *Broker) pend(q queuedRevoke) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.pending == nil {
		b.pending = map[[2]string]queuedRevoke{}
	}
	if _, ok := b.pending[q.key()]; !ok {
		b.pending[q.key()] = q
	}
}

// RetryPending requeues every pending entry (port49d calls it on a
// refresh_interval ticker).
func (b *Broker) RetryPending() {
	b.mu.Lock()
	pending := b.pending
	b.pending = nil
	b.mu.Unlock()
	for _, q := range pending {
		b.enqueueRevoke(q.issuer, q.serial, q.origin, false)
	}
}

// sayOnce logs a line at most once per key per window. Keys past their
// window are dropped once there are many, so the map stays small.
func (b *Broker) sayOnce(key string, window time.Duration, format string, args ...any) {
	now := b.Now()
	b.mu.Lock()
	if last, ok := b.said[key]; ok && now.Sub(last) < window {
		b.mu.Unlock()
		return
	}
	if b.said == nil {
		b.said = map[string]time.Time{}
	}
	if len(b.said) >= 256 {
		for k, t := range b.said {
			if now.Sub(t) >= window {
				delete(b.said, k)
			}
		}
	}
	b.said[key] = now
	b.mu.Unlock()
	b.logf(format, args...)
}
