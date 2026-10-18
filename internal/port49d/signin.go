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

	"github.com/prometheus/client_golang/prometheus"

	"github.com/rhwendt/port49/internal/broker"
	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/oidc"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/crypt"
	"github.com/rhwendt/port49/internal/store/enrollfile"
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
// dir is the directory store's handle, the broker's identity on it (the
// session store's own in a shared store); nil on the memory store. It does
// nothing for a broker with no directory_password verifier.
//
// The channel it returns closes once ctx is cancelled and the goroutines the
// wiring started have returned; a caller that closes the store joins it first.
func wirePasswordSignIn(ctx context.Context, cfg config.Config, b *broker.Broker, keys crypt.Keys,
	m *metrics.Metrics, dir *dirHandle, out io.Writer) <-chan struct{} {
	var sh func() store.Enrollments // nil: no shared store
	if dir != nil {
		sh = func() store.Enrollments {
			if s := dir.get(); s != nil {
				return s
			}
			return nil // a nil *Store is not a nil interface
		}
	}
	return wireSignIn(ctx, cfg, b, keys, m, sh, out)
}

// setPasswordSignIn gives b its own copy of the directory_password verifier
// (the config's is not edited), with the default TOTP label. It does nothing
// for a config with none, or a broker that has one.
func setPasswordSignIn(cfg config.Config, b *broker.Broker) {
	if b == nil || b.PasswordSignIn != nil || cfg.Broker == nil || cfg.Broker.Identity == nil ||
		cfg.Broker.Identity.PasswordSignIn == nil {
		return
	}
	p := *cfg.Broker.Identity.PasswordSignIn
	if p.TOTPLabel == "" {
		p.TOTPLabel = defaultTOTPLabel(cfg.Broker.Listen)
	}
	b.PasswordSignIn = &p
}

// wireSignIn is wirePasswordSignIn over the shared store's enrollment handle,
// read at each open so a directory that answers late is used when it does;
// a test can fake it. Its channel is wirePasswordSignIn's.
func wireSignIn(ctx context.Context, cfg config.Config, b *broker.Broker, keys crypt.Keys,
	m *metrics.Metrics, shared func() store.Enrollments, out io.Writer) <-chan struct{} {
	done := make(chan struct{})
	if b == nil || cfg.Broker == nil || cfg.Broker.Identity == nil || cfg.Broker.Identity.PasswordSignIn == nil {
		close(done)
		return done
	}
	var wg sync.WaitGroup
	proc := procOf(cfg)
	say := func(format string, args ...any) { fmt.Fprintf(out, proc+": "+format+"\n", args...) }
	setPasswordSignIn(cfg, b) // buildBrokerAnchor did; a broker built another way gets it here
	p := *b.PasswordSignIn
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
		open = func() (store.Enrollments, error) { return openEnrollmentFile(es.File, keys, m.CryptOpenFailures) }
	case es.Backend == config.BackendEtcd && shared != nil:
		where = "stores.directory etcd " + strings.Join(cfg.Stores.Directory.Etcd.Endpoints, ", ")
		gc := guardConfig(proc, "broker", "stores.directory", cfg.Stores.Directory.Etcd, m, out, func(error) {})
		if !cfg.Stores.Shared {
			gc.Store = "directory store" // its circuit line at 3am reads as the directory's, not the session store's
		}
		gc.StopAfter, gc.Unhealthy = 0, nil
		open = func() (store.Enrollments, error) {
			sh := shared()
			if sh == nil {
				return nil, errNoDirectory // lateEnrollments opens again at its next interval
			}
			return crypt.WrapEnrollments(guard.WrapEnrollments(sh, gc), keys, m.CryptOpenFailures), nil
		}
	default:
		// The config cannot make this: an etcd backend shares the directory
		// store, which has a broker only in port49-broker.
		where = "no store"
		open = func() (store.Enrollments, error) {
			return nil, fmt.Errorf("%w: no enrollment store is configured for this process", store.ErrEnrollmentStoreLost)
		}
	}
	late := &lateEnrollments{open: open, now: time.Now}
	wg.Add(1)
	go func() { defer wg.Done(); <-ctx.Done(); late.close() }()
	b.Enrollments = late

	cctx, cancel := context.WithTimeout(ctx, enrollmentStartWait)
	defer cancel()
	if err := b.CheckEnrollmentStore(cctx); err != nil {
		say("sign-in: the enrollment store did not answer at start (%v): password sign-in answers "+
			"store_unavailable until it does; this process looks again every %s", printsafeErr(err), enrollmentRecheckEvery)
	}
	wg.Add(1)
	go func() { defer wg.Done(); recheckEnrollmentStore(ctx, b, enrollmentRecheckEvery) }()
	say("broker: directory-password sign-in on (second factor totp; principal domains %s; enrollments in %s; %s; "+
		"limits %d per principal, %s, per %s)", strings.Join(p.PrincipalDomains, ", "), where, enrollWindow(p),
		p.FailuresPerPrincipal, perSource(p), durText(p.Window))
	go func() { wg.Wait(); close(done) }()
	return done
}

// enrollmentRecheckEvery is how often a process that finds its enrollment
// store lost looks again; a variable so a test can shorten it.
var enrollmentRecheckEvery = 30 * time.Second

// recheckEnrollmentStore leaves the lost state without a restart (D7): while
// the store is lost, or has not yet answered at all (the gauge is absent until
// it does), it looks at the mark every interval, in every process, so
// a replica that is not the runner follows an init-enrollments, an import or a
// reset run elsewhere. It never seals and never writes; the runner's pass
// keeps the re-seal. It stops with ctx.
func recheckEnrollmentStore(ctx context.Context, b *broker.Broker, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if b.EnrollmentStoreLost() == "" && b.EnrollmentStoreChecked() {
				continue
			}
			cctx, cancel := context.WithTimeout(ctx, enrollmentStartWait)
			_ = b.CheckEnrollmentStore(cctx) // an unreachable store stays as it was; the next tick looks again
			cancel()
		}
	}
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

// openEnrollmentFile opens the memory backend's sealed file, never creating
// it. A refusal of the file's directory or a link at its path is lost, as an
// unreadable file is.
func openEnrollmentFile(path string, keys crypt.Keys, openFailures *prometheus.CounterVec) (store.Enrollments, error) {
	f, err := enrollfile.Open(path, keys, time.Now)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", store.ErrEnrollmentStoreLost, err)
	}
	return &reopenable{Enrollments: crypt.WrapEnrollments(f, keys, openFailures), lost: f.Lost}, nil
}

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

// reopenable is a store that knows whether it opened: a file that could not be
// read is lost for as long as the handle lives, though the operator fixes its
// owner or mode a minute later, so lateEnrollments opens it again.
type reopenable struct {
	store.Enrollments
	lost func() string
}

func (r *reopenable) Lost() string { return r.lost() }

// Close closes what it wraps, when that has anything to close.
func (r *reopenable) Close() error {
	if c, ok := r.Enrollments.(interface{ Close() error }); ok {
		return c.Close()
	}
	return nil
}

func (l *lateEnrollments) get() (store.Enrollments, error) { return l.fetch(false) }

// Refresh opens a lost or unopened store again at once (the broker's
// reset --all calls it before it reads the mark).
func (l *lateEnrollments) Refresh() { _, _ = l.fetch(true) }

// getFresh is get for an op that replaces a lost store (a mark put, a mark
// created, an import): a handle that is lost, or not yet open, is opened
// again at once whatever the 30s say, so the operator who has just fixed the
// file's mode and runs `reset-second-factor --all` does not have the good file
// set aside (re-review I4-r).
func (l *lateEnrollments) getFresh() (store.Enrollments, error) { return l.fetch(true) }

// fetch is the handle. The open itself runs outside the lock (an etcd's probe
// takes seconds), so concurrent callers meanwhile get the last answer; the
// attempt is stamped first, so only one runs per interval unless forced.
func (l *lateEnrollments) fetch(force bool) (store.Enrollments, error) {
	l.mu.Lock()
	cur := l.inner
	if cur != nil {
		if r, ok := cur.(*reopenable); !ok || r.Lost() == "" {
			l.mu.Unlock()
			return cur, nil
		}
	}
	if !force && !l.tried.IsZero() && l.now().Sub(l.tried) < enrollmentRetryEvery {
		failed := l.failed
		l.mu.Unlock()
		if cur != nil {
			return cur, nil
		}
		return nil, failed
	}
	l.tried = l.now()
	l.mu.Unlock()

	in, err := l.open()

	l.mu.Lock()
	defer l.mu.Unlock()
	// A handle this call opened and does not keep is closed, whichever branch
	// drops it: an own etcd's is a live client.
	discard := func() {
		if err == nil {
			if c, ok := in.(interface{ Close() error }); ok {
				_ = c.Close()
			}
		}
	}
	if cur != nil {
		// Lost: keep the new handle only if it is well (a lost one answers the
		// same as the old) and nothing moved while it opened: l.inner must be
		// the handle this call started from and still lost. Otherwise another
		// caller swapped in, or wrote through, a newer one, and this read is
		// older than that write.
		stale := l.inner != cur
		if r, ok := l.inner.(*reopenable); !stale && (!ok || r.Lost() == "") {
			stale = true // a write through cur cleared it meanwhile
		}
		if err == nil && !stale {
			if nr, ok := in.(*reopenable); !ok || nr.Lost() == "" {
				l.inner = in
				return in, nil
			}
		}
		discard()
		return l.inner, nil
	}
	if l.inner != nil {
		discard()
		return l.inner, nil // another caller opened it meanwhile
	}
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

func (l *lateEnrollments) GetUnlock(ctx context.Context, principal string) (time.Time, error) {
	in, err := l.get()
	if err != nil {
		return time.Time{}, err
	}
	return in.GetUnlock(ctx, principal)
}

func (l *lateEnrollments) PutUnlock(ctx context.Context, principal string, at time.Time) error {
	in, err := l.getFresh()
	if err != nil {
		return err
	}
	return in.PutUnlock(ctx, principal, at)
}

func (l *lateEnrollments) GetEnrollmentMark(ctx context.Context) (store.EnrollmentMark, error) {
	in, err := l.get()
	if err != nil {
		return store.EnrollmentMark{}, err
	}
	return in.GetEnrollmentMark(ctx)
}

func (l *lateEnrollments) CreateEnrollmentMark(ctx context.Context, m store.EnrollmentMark) error {
	in, err := l.getFresh()
	if err != nil {
		return err
	}
	return in.CreateEnrollmentMark(ctx, m)
}

func (l *lateEnrollments) PutEnrollmentMark(ctx context.Context, m store.EnrollmentMark) error {
	in, err := l.getFresh()
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
	in, err := l.getFresh()
	if err != nil {
		return 0, time.Time{}, err
	}
	return in.Import(ctx, sealed, replace)
}
