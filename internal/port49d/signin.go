package port49d

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/rhwendt/port49/internal/broker"
	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/directory"
	"github.com/rhwendt/port49/internal/oidc"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/crypt"
	"github.com/rhwendt/port49/internal/store/enrollfile"
	etcdstore "github.com/rhwendt/port49/internal/store/etcd"
	"github.com/rhwendt/port49/internal/store/guard"
)

const (
	// enrollmentRetryEvery is how often an enrollment store that did not
	// open is tried again: by the next call after it, no oftener.
	enrollmentRetryEvery = 30 * time.Second
	// enrollmentStartWait bounds the check at start, so a dead etcd delays
	// the listener by no more than this.
	enrollmentStartWait = 15 * time.Second
	// totpLabelMax is the longest default authenticator label.
	totpLabelMax = 64
)

// wirePasswordSignIn is plan 9e's wiring on a broker buildBrokerAnchor made:
// the directory_password verifier, the directory it asks, and the enrollment
// store, opened by its shape and never created (init-enrollments is the one
// creator; a store or mark that is not there is enrollment_store_lost). It
// then checks the store once, before any listener opens, and says what it
// found. Nothing here stops port49d: a store that cannot be opened or reached
// refuses password sign-in alone, and every other path serves.
//
// shared is the *etcd.Store the broker runs on, for an enrollment_store that
// names no etcd of its own; a literal nil on the memory store (never a nil
// *etcd.Store, which is not a nil interface). It does nothing for a broker
// with no directory_password verifier.
func wirePasswordSignIn(ctx context.Context, cfg config.Config, b *broker.Broker, keys crypt.Keys,
	m *metrics.Metrics, shared store.Enrollments, out io.Writer) {
	if b == nil || cfg.Broker == nil || cfg.Broker.Identity == nil || cfg.Broker.Identity.PasswordSignIn == nil {
		return
	}
	proc := procOf(cfg)
	say := func(format string, args ...any) { fmt.Fprintf(out, proc+": "+format+"\n", args...) }
	p := *cfg.Broker.Identity.PasswordSignIn // the config's own is not edited
	if p.TOTPLabel == "" {
		p.TOTPLabel = defaultTOTPLabel(cfg.Broker.Listen)
	}
	b.PasswordSignIn = &p
	// A nil *Resolver in the interface would be a non-nil interface that
	// panics on its first call: sign-in answers 404 for a nil one instead.
	if b.Directory != nil {
		b.SignInDirectory = b.Directory
	}
	es := cfg.Broker.Directory.EnrollmentStore
	b.EnrollmentFile = es.File
	where := es.File
	var open func() (store.Enrollments, error)
	switch {
	case es.Backend != config.BackendEtcd:
		open = func() (store.Enrollments, error) {
			f, err := enrollfile.Open(es.File, keys, time.Now)
			if err != nil {
				return nil, fmt.Errorf("%w: %v", store.ErrEnrollmentStoreLost, err)
			}
			return crypt.WrapEnrollments(f, keys, m.CryptOpenFailures), nil
		}
	case es.Etcd == nil && shared != nil:
		where = "store.etcd " + strings.Join(cfg.Store.Etcd.Endpoints, ", ")
		gc := guardConfig(proc, "broker", cfg.Store.Etcd, m, out, func(error) {})
		gc.StopAfter, gc.Unhealthy = 0, nil
		open = func() (store.Enrollments, error) {
			return crypt.WrapEnrollments(guard.WrapEnrollments(shared, gc), keys, m.CryptOpenFailures), nil
		}
	case es.Etcd != nil:
		where = "etcd " + strings.Join(es.Etcd.Endpoints, ", ")
		open = func() (store.Enrollments, error) { return openEnrollmentEtcd(es.Etcd, keys, m, proc, out) }
	default:
		// The config cannot make this: an etcd backend names an etcd or
		// shares store.etcd, which has a broker only in port49-broker.
		where = "no store"
		open = func() (store.Enrollments, error) {
			return nil, fmt.Errorf("%w: no enrollment store is configured for this process", store.ErrEnrollmentStoreLost)
		}
	}
	late := &lateEnrollments{open: open, now: time.Now}
	go func() { <-ctx.Done(); late.close() }()
	b.Enrollments = late

	cctx, cancel := context.WithTimeout(ctx, enrollmentStartWait)
	defer cancel()
	if err := b.CheckEnrollmentStore(cctx); err != nil {
		say("sign-in: the enrollment store did not answer at start (%v): password sign-in answers "+
			"store_unavailable until a scheduled pass reaches it", printsafeErr(err))
	}
	say("broker: directory-password sign-in on (second factor totp; principal domains %s; enrollments in %s; %s; "+
		"limits %d per principal, %s, per %s)", strings.Join(p.PrincipalDomains, ", "), where, enrollWindow(p),
		p.FailuresPerPrincipal, perSource(p), durText(p.Window))
}

// enrollWindow is the start line's account of when a person may enroll.
func enrollWindow(p oidc.PasswordSignIn) string {
	s := "enrollment is open only after reset-second-factor"
	if !p.OpenUntil.IsZero() {
		s = "enrollment open until " + decision.FormatTime(p.OpenUntil)
	}
	if p.NewEntriesFor > 0 {
		return s + ", new entries for " + durText(p.NewEntriesFor)
	}
	return s + ", no new entries after it"
}

func perSource(p oidc.PasswordSignIn) string {
	if p.FailuresPerSource == 0 {
		return "no per-source limit"
	}
	return fmt.Sprintf("%d per source", p.FailuresPerSource)
}

// durText is d as 336h or 15m, without the zero units Duration.String adds.
func durText(d time.Duration) string {
	s := d.String()
	s = strings.TrimSuffix(s, "0s")
	s = strings.TrimSuffix(s, "0m")
	if s == "" {
		return d.String()
	}
	return s
}

// printsafeErr is err on one line, for a start line.
func printsafeErr(err error) string {
	return strings.Join(strings.Fields(err.Error()), " ")
}

// defaultTOTPLabel is "port49 (<host>)" for the host broker.listen binds, or
// this host's name when it binds every address. It never holds ':' (the
// otpauth label's separator, which signin refuses), so an IPv6 literal's are
// replaced; nor anything but printable ASCII.
func defaultTOTPLabel(listen string) string {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		host = listen
	}
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		host, _ = os.Hostname()
	}
	var sb strings.Builder
	for _, r := range host {
		switch {
		case r == ':':
			sb.WriteByte('-')
		case r > ' ' && r < 0x7f && r != '(' && r != ')':
			sb.WriteRune(r)
		}
	}
	h := sb.String()
	if h == "" {
		h = "broker"
	}
	if len(h) > totpLabelMax-len("port49 ()") {
		h = h[:totpLabelMax-len("port49 ()")]
	}
	return "port49 (" + h + ")"
}

// openEnrollmentEtcd opens an enrollment store's own etcd: its CA and
// identity read now, the dial never waited for (clientv3 does not), so an
// etcd that is down surfaces as store.ErrUnavailable on the first call.
func openEnrollmentEtcd(e *directory.EnrollmentEtcd, keys crypt.Keys, m *metrics.Metrics, proc string,
	out io.Writer) (store.Enrollments, error) {
	pool, _, err := caCerts(e.CAFile)
	if err != nil {
		return nil, fmt.Errorf("broker.directory.enrollment_store.etcd.ca_file %s: %w", e.CAFile, err)
	}
	tc, _, err := identity("enrollment_store", config.EtcdIdentity{CertFile: e.CertFile, KeyFile: e.KeyFile}, pool,
		time.Now())
	if err != nil {
		return nil, err
	}
	logf := func(format string, args ...any) { fmt.Fprintf(out, proc+": enrollment store: "+format+"\n", args...) }
	s, err := etcdstore.Open(etcdstore.Config{Endpoints: e.Endpoints, Prefix: e.Prefix, TLS: tc, Logf: logf,
		IndexUndecodable: m.IndexRecordsUndecodable})
	if err != nil {
		return nil, fmt.Errorf("broker.directory.enrollment_store.etcd: %w", err)
	}
	gc := guard.Config{Proc: proc, Component: "broker", CallTimeout: e.CallTimeout, BulkTimeout: 10 * e.CallTimeout,
		MaxInFlight: map[guard.Pool]int{guard.Token: 64, guard.Context: 64, guard.Bulk: 4}, Failures: 5,
		OpenFor: 5 * time.Second, Metrics: m.StoreGuard(),
		Say: func(l string) { fmt.Fprintln(out, l) }}
	return &closingEnrollments{Enrollments: crypt.WrapEnrollments(guard.WrapEnrollments(s, gc), keys,
		m.CryptOpenFailures), closer: s}, nil
}

// closingEnrollments closes the etcd it owns.
type closingEnrollments struct {
	store.Enrollments
	closer interface{ Close() error }
}

func (c *closingEnrollments) Close() error { return c.closer.Close() }

// lateEnrollments is a store.Enrollments that opens its backend on first use
// and, while that fails, tries again no oftener than enrollmentRetryEvery,
// answering meanwhile: store.ErrEnrollmentStoreLost when the backend says so,
// else store.ErrUnavailable. So a store that cannot be opened or reached at
// start never stops port49d, and sign-in finds it by itself when it can.
type lateEnrollments struct {
	open func() (store.Enrollments, error)
	now  func() time.Time

	mu     sync.Mutex
	inner  store.Enrollments
	tried  time.Time
	failed error
}

var _ store.Enrollments = (*lateEnrollments)(nil)

func (l *lateEnrollments) get() (store.Enrollments, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.inner != nil {
		return l.inner, nil
	}
	if !l.tried.IsZero() && l.now().Sub(l.tried) < enrollmentRetryEvery {
		return nil, l.failed
	}
	l.tried = l.now()
	in, err := l.open()
	if err != nil {
		if !errors.Is(err, store.ErrEnrollmentStoreLost) {
			err = fmt.Errorf("%w: the enrollment store did not open: %v", store.ErrUnavailable, err)
		}
		l.failed = err
		return nil, err
	}
	l.inner, l.failed = in, nil
	return in, nil
}

func (l *lateEnrollments) close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if c, ok := l.inner.(interface{ Close() error }); ok {
		_ = c.Close()
	}
}

func (l *lateEnrollments) GetSecondFactor(ctx context.Context, principal string) (store.SecondFactor, error) {
	in, err := l.get()
	if err != nil {
		return store.SecondFactor{}, err
	}
	return in.GetSecondFactor(ctx, principal)
}

func (l *lateEnrollments) SwapSecondFactor(ctx context.Context, f store.SecondFactor, rev uint64) error {
	in, err := l.get()
	if err != nil {
		return err
	}
	return in.SwapSecondFactor(ctx, f, rev)
}

func (l *lateEnrollments) SecondFactorPrincipals(ctx context.Context) ([]string, error) {
	in, err := l.get()
	if err != nil {
		return nil, err
	}
	return in.SecondFactorPrincipals(ctx)
}

func (l *lateEnrollments) GetEnrollmentMark(ctx context.Context) (store.EnrollmentMark, error) {
	in, err := l.get()
	if err != nil {
		return store.EnrollmentMark{}, err
	}
	return in.GetEnrollmentMark(ctx)
}

func (l *lateEnrollments) CreateEnrollmentMark(ctx context.Context, m store.EnrollmentMark) error {
	in, err := l.get()
	if err != nil {
		return err
	}
	return in.CreateEnrollmentMark(ctx, m)
}

func (l *lateEnrollments) PutEnrollmentMark(ctx context.Context, m store.EnrollmentMark) error {
	in, err := l.get()
	if err != nil {
		return err
	}
	return in.PutEnrollmentMark(ctx, m)
}

func (l *lateEnrollments) SwapEnrollmentMark(ctx context.Context, m store.EnrollmentMark, rev uint64) error {
	in, err := l.get()
	if err != nil {
		return err
	}
	return in.SwapEnrollmentMark(ctx, m, rev)
}

func (l *lateEnrollments) Export(ctx context.Context) ([]byte, error) {
	in, err := l.get()
	if err != nil {
		return nil, err
	}
	return in.Export(ctx)
}

func (l *lateEnrollments) Import(ctx context.Context, sealed []byte, replace bool) (int, time.Time, error) {
	in, err := l.get()
	if err != nil {
		return 0, time.Time{}, err
	}
	return in.Import(ctx, sealed, replace)
}
