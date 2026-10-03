// Package etcd is store.Store on etcd v3 (plan 7d; spec §13, decision 35).
//
// Each record is one key under Config.Prefix + "v1/", its value JSON with
// snake_case keys (records.go), and every compare-and-set a transaction on
// the key's mod_revision (commit.go). Expiry is the record's own, read
// against Config.Now; leases only reclaim, at least LeaseGrace after it
// (leases.go). Every read is linearizable: a member cut off from its
// quorum answers nothing, never a stale record. A context's Rev is its
// key's mod_revision, and its PolicyRev comes from the same counter
// (records.go, ctxRec).
package etcd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.etcd.io/etcd/api/v3/v3rpc/rpctypes"
	clientv3 "go.etcd.io/etcd/client/v3"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/rhwendt/port49/internal/store"
)

// Config is one component's view of etcd.
type Config struct {
	Endpoints []string
	// TLS is the component's client certificate and the CA that signs
	// etcd's. Nil dials in the clear, which only tests do: port49d refuses
	// an endpoint that is not https.
	TLS *tls.Config
	// Prefix is the keyspace; "/port49/" when empty. Records live under
	// Prefix + "v1/".
	Prefix string
	// Now is the clock every expiry is read against; time.Now when nil.
	Now func() time.Time
	// LeaseGrace is how long past its expiry a record's lease outlives it;
	// 5m when zero.
	LeaseGrace time.Duration
	// DialTimeout bounds Open's connect; 5s when zero.
	DialTimeout time.Duration
	// Logf says what a read skipped, by key alone; log.Printf when nil.
	Logf func(format string, args ...any)
	// IndexUndecodable counts the index records a read skipped or took
	// unread because they do not decode
	// (metrics.IndexRecordsUndecodable); nil counts nothing.
	IndexUndecodable prometheus.Counter
}

// Store is store.Store on etcd.
type Store struct {
	k   keys
	now func() time.Time
	// tok and ctx are the token and context pools (design §12), two
	// clients and so two connections: mint pressure on one cannot take the
	// other's connection.
	tok, ctx             *clientv3.Client
	tokLeases, ctxLeases *leases
	owned                []*clientv3.Client // closed by Close
	seen                 seenCache          // GetContext's last read per key (contexts.go)
	seenRev              atomic.Uint64      // Seen: the highest revision a response carried
	logf                 func(format string, args ...any)
	idxUndecodable       prometheus.Counter // nil counts nothing
	// user is the etcd user this identity authenticates as, its client
	// certificate's CN, or "" when Open could not read one. CheckIdentity
	// reads its grants, and refuses "" unless the store is in the clear.
	user  string
	clear bool // dialed with no TLS: tests only, and etcd's auth cannot know it
}

var _ store.Store = (*Store)(nil)

// ErrRefused is etcd refusing this identity an operation: a role that
// does not grant it, or authentication that failed. It is store.ErrRefused,
// so the guard, which imports no backend, tells it from an outage: it trips
// no circuit (Task 9).
var ErrRefused = store.ErrRefused

// ErrTooLarge is a request etcd will not take for its size (its
// --max-request-bytes, 1.5 MiB by default, or gRPC's 2 MiB message
// limit). It is a fault in the request, not in the store: never
// store.ErrUnavailable, so it trips no circuit (pre-flight M19).
var ErrTooLarge = errors.New("etcd: request too large")

// Open builds the store's clients. It never waits for etcd: clientv3.New
// returns at once whether or not an endpoint answers, and an expired
// certificate or a wrong CA fails only the first call, as a deadline
// (pre-flight I9). A caller that must know etcd answers calls Ping; one
// that must know why it does not checks the certificates and the TLS
// handshake first (port49d does, Task 12). It fails only on a
// configuration clientv3 refuses outright.
func Open(c Config) (*Store, error) {
	c = c.withDefaults()
	tok, err := dial(c)
	if err != nil {
		return nil, err
	}
	ctxCli, err := dial(c)
	if err != nil {
		tok.Close()
		return nil, err
	}
	s := newStore(tok, ctxCli, c)
	s.owned = []*clientv3.Client{tok, ctxCli}
	s.user = userOf(c.TLS)
	return s, nil
}

func (c Config) withDefaults() Config {
	if c.Prefix == "" {
		c.Prefix = "/port49/"
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.LeaseGrace == 0 {
		c.LeaseGrace = 5 * time.Minute
	}
	if c.DialTimeout == 0 {
		c.DialTimeout = 5 * time.Second
	}
	if c.Logf == nil {
		c.Logf = log.Printf
	}
	return c
}

func dial(c Config) (*clientv3.Client, error) {
	if len(c.Endpoints) == 0 {
		return nil, errors.New("etcd: no endpoints")
	}
	cli, err := clientv3.New(clientv3.Config{Endpoints: c.Endpoints, TLS: c.TLS, DialTimeout: c.DialTimeout,
		// The client's own JSON lines would land in port49d's stderr, which
		// is the operator's; port49d says what matters itself.
		Logger:               zap.NewNop(),
		DialKeepAliveTime:    5 * time.Second,
		DialKeepAliveTimeout: 2 * time.Second,
		RejectOldCluster:     true,
	})
	if err != nil {
		// Not ErrUnavailable: New does not dial, so this is a configuration
		// it will not take (an endpoint it cannot parse, a TLS config it
		// refuses), and waiting would not change it.
		return nil, fmt.Errorf("etcd at %v: %w", c.Endpoints, err)
	}
	return cli, nil
}

// userOf is the CN of t's client certificate, the user etcd
// authenticates it as; "" when there is none or it does not parse.
func userOf(t *tls.Config) string {
	if t == nil || len(t.Certificates) == 0 || len(t.Certificates[0].Certificate) == 0 {
		return ""
	}
	c, err := x509.ParseCertificate(t.Certificates[0].Certificate[0])
	if err != nil {
		return ""
	}
	return c.Subject.CommonName
}

// newStore is a store on clients the caller owns: tests build many on one.
func newStore(tok, ctx *clientv3.Client, c Config) *Store {
	c = c.withDefaults()
	s := &Store{k: newKeys(c.Prefix), now: c.Now, tok: tok, ctx: ctx, logf: c.Logf, idxUndecodable: c.IndexUndecodable,
		clear: c.TLS == nil}
	s.tokLeases = newLeases(tok, c.Now, c.LeaseGrace)
	s.ctxLeases = s.tokLeases
	if ctx != tok {
		s.ctxLeases = newLeases(ctx, c.Now, c.LeaseGrace)
	}
	return s
}

// Close closes the clients Open dialed.
func (s *Store) Close() error {
	var first error
	for _, c := range s.owned {
		if err := c.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// Ping is one linearizable read on the context pool: nil when etcd's
// quorum answers.
func (s *Store) Ping(ctx context.Context) error {
	resp, err := s.ctx.Get(ctx, s.k.meta("ping"))
	if err != nil {
		return unavailable(err)
	}
	s.saw(resp.Header.Revision)
	return nil
}

// saw raises Seen to rev.
func (s *Store) saw(rev int64) {
	for {
		cur := s.seenRev.Load()
		if uint64(rev) <= cur || s.seenRev.CompareAndSwap(cur, uint64(rev)) {
			return
		}
	}
}

// Seen is the highest store revision any of this store's responses or
// watch events carried (store.RevStore).
func (s *Store) Seen() uint64 { return s.seenRev.Load() }

// unavailable classifies an etcd error for the layers above: a caller that
// gave up is its own error; a refusal of this identity is ErrRefused; a
// request too large is ErrTooLarge; any other — a deadline, no leader, no
// quorum, a dropped connection — is store.ErrUnavailable. The guard reads
// the caller's own context before this error (Task 9), so a deadline is
// told apart there, not here.
func unavailable(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, context.Canceled):
		return err
	case errors.Is(err, rpctypes.ErrPermissionDenied), errors.Is(err, rpctypes.ErrAuthFailed),
		errors.Is(err, rpctypes.ErrUserEmpty), errors.Is(err, rpctypes.ErrInvalidAuthToken):
		return fmt.Errorf("%w: %v", ErrRefused, err)
	case errors.Is(err, rpctypes.ErrRequestTooLarge), status.Code(err) == codes.ResourceExhausted:
		return fmt.Errorf("%w: %v", ErrTooLarge, err)
	}
	return fmt.Errorf("%w: %v", store.ErrUnavailable, err)
}
