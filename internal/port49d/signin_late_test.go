package port49d

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/directory"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/crypt"
	"github.com/rhwendt/port49/internal/store/enrollfile"
	"github.com/rhwendt/port49/internal/testpki"
)

type countingCloser struct{ closed int }

func (c *countingCloser) Close() error { c.closed++; return nil }

// lateEnrollments opens its backend on first use and tries again no oftener
// than every 30s while that fails: a failure is not retried before then, a
// success is cached and never reopened, a lost store passes through as lost
// and anything else is unavailable, and close closes what it owns.
func TestLateEnrollments(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	calls := 0
	fail := errors.New("dial tcp: connection refused")
	cl := &countingCloser{}
	l := &lateEnrollments{now: func() time.Time { return now }}
	l.open = func() (store.Enrollments, error) {
		calls++
		if fail != nil {
			return nil, fail
		}
		return &closingEnrollments{closer: cl}, nil
	}
	if _, err := l.get(); !errors.Is(err, store.ErrUnavailable) || errors.Is(err, store.ErrEnrollmentStoreLost) || calls != 1 {
		t.Fatalf("a first failure: %v after %d opens", err, calls)
	}
	now = now.Add(enrollmentRetryEvery - time.Second)
	if _, err := l.get(); !errors.Is(err, store.ErrUnavailable) || calls != 1 {
		t.Fatalf("before the retry: %v after %d opens", err, calls)
	}
	now = now.Add(2 * time.Second)
	if _, err := l.get(); !errors.Is(err, store.ErrUnavailable) || calls != 2 {
		t.Fatalf("at the retry: %v after %d opens", err, calls)
	}
	fail = nil
	now = now.Add(enrollmentRetryEvery)
	if in, err := l.get(); err != nil || in == nil || calls != 3 {
		t.Fatalf("the success: %v after %d opens", err, calls)
	}
	now = now.Add(time.Hour)
	if _, err := l.get(); err != nil || calls != 3 {
		t.Fatalf("a cached store was opened again: %v after %d opens", err, calls)
	}
	l.close()
	if cl.closed != 1 {
		t.Fatalf("close closed %d times", cl.closed)
	}

	lost := &lateEnrollments{now: func() time.Time { return now }, open: func() (store.Enrollments, error) {
		return nil, errors.Join(store.ErrEnrollmentStoreLost, errors.New("it cannot be read"))
	}}
	if _, err := lost.get(); !errors.Is(err, store.ErrEnrollmentStoreLost) || errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("a lost store: %v", err)
	}
}

// A file lost because it could not be read is opened again after 30s: the
// operator who fixes its mode does not then run --all, which would set the
// good file aside.
func TestALostEnrollmentFileIsOpenedAgainOnceFixed(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a mode 0000 file")
	}
	ctx := context.Background()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "enrollments.json")
	file, err := enrollfile.Open(path, signInTestKeys, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if err := crypt.WrapEnrollments(file, signInTestKeys, nil).CreateEnrollmentMark(ctx,
		store.EnrollmentMark{CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	l := &lateEnrollments{now: func() time.Time { return now },
		open: func() (store.Enrollments, error) { return openEnrollmentFile(path, signInTestKeys, nil) }}
	if _, err := l.GetEnrollmentMark(ctx); !errors.Is(err, store.ErrEnrollmentStoreLost) {
		t.Fatalf("an unreadable file: %v", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	now = now.Add(enrollmentRetryEvery - time.Second)
	if _, err := l.GetEnrollmentMark(ctx); !errors.Is(err, store.ErrEnrollmentStoreLost) {
		t.Fatalf("before the retry: %v", err)
	}
	now = now.Add(2 * time.Second)
	if _, err := l.GetEnrollmentMark(ctx); err != nil {
		t.Fatalf("after the retry the fixed file is still lost: %v", err)
	}
}

// An enrollment store's own etcd gets the main store's start checks and names
// its own config path: a CA outside its validity, an identity that does not
// load, a certificate the server refuses, and, once it handshakes, the
// certificate's expiry in port49_store_certificate_expiry_timestamp_seconds
// as broker_enrollments.
func TestAnOwnEnrollmentEtcdIsCheckedAsTheMainStoreIs(t *testing.T) {
	const at = "broker.directory.enrollment_store.etcd"
	now := time.Now()
	ca, err := testpki.NewCA("ca", now.Add(-48*time.Hour), now.Add(48*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	other, err := testpki.NewCA("other", now.Add(-48*time.Hour), now.Add(48*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	writeCA := func(name string, c *testpki.CA) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, c.PEM(), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	id := writeIdentity(t, ca, "port49-broker", now.Add(-time.Hour), now.Add(72*time.Hour), 0o600)
	etcd := func(caFile string, id config.EtcdIdentity, endpoint string) *directory.EnrollmentEtcd {
		return &directory.EnrollmentEtcd{Endpoints: []string{endpoint}, CAFile: caFile, CertFile: id.CertFile,
			KeyFile: id.KeyFile, Prefix: "/e/", CallTimeout: 100 * time.Millisecond}
	}
	open := func(e *directory.EnrollmentEtcd, m *metrics.Metrics) error {
		_, err := openEnrollmentEtcd(e, signInTestKeys, m, "port49-broker", &syncBuffer{})
		return err
	}
	m := metrics.New(prometheus.NewRegistry())

	expired, err := testpki.NewCA("old", now.Add(-72*time.Hour), now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := open(etcd(writeCA("expired.pem", expired), id, "https://127.0.0.1:1"), m); err == nil ||
		!strings.Contains(err.Error(), at+".ca_file") || !strings.Contains(err.Error(), "valid only from") {
		t.Fatalf("an expired CA: %v", err)
	}
	bad := config.EtcdIdentity{CertFile: filepath.Join(dir, "none.pem"), KeyFile: filepath.Join(dir, "none.key")}
	if err := open(etcd(writeCA("ca.pem", ca), bad, "https://127.0.0.1:1"), m); err == nil ||
		!strings.Contains(err.Error(), at+".identity") || strings.Contains(err.Error(), "store.etcd.enrollment_store") {
		t.Fatalf("an identity that does not load: %v", err)
	}

	// A server that wants client certificates from clientCA.
	serve := func(clientCA *testpki.CA) string {
		sc, err := ca.Issue(testpki.Leaf{CommonName: "etcd", IPs: testpki.Loopback(), NotBefore: now.Add(-time.Hour),
			NotAfter: now.Add(24 * time.Hour)})
		if err != nil {
			t.Fatal(err)
		}
		ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{sc},
			ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientCA.Pool(), MinVersion: tls.VersionTLS13})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go func() {
					c.SetDeadline(time.Now().Add(2 * time.Second))
					c.Read(make([]byte, 1))
					c.Close()
				}()
			}
		}()
		return "https://" + ln.Addr().String()
	}
	if err := open(etcd(writeCA("ca.pem", ca), id, serve(other)), m); err == nil ||
		!strings.Contains(err.Error(), "refused this certificate") && !strings.Contains(err.Error(), "handshake failed") {
		t.Fatalf("a certificate the server refuses: %v", err)
	}
	if n := testutil.CollectAndCount(m.StoreCertExpiry); n != 0 {
		t.Fatalf("the expiry is set (%d series) for a certificate that was refused", n)
	}
	// It handshakes; the server is no etcd, so the open still fails, after the
	// expiry is recorded.
	_ = open(etcd(writeCA("ca.pem", ca), id, serve(ca)), m)
	pair, err := os.ReadFile(id.CertFile)
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(pair)
	leaf, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if got := testutil.ToFloat64(m.StoreCertExpiry.WithLabelValues("broker_enrollments")); got != float64(leaf.NotAfter.Unix()) {
		t.Fatalf("the expiry reads %v, want %v", got, leaf.NotAfter.Unix())
	}
}
