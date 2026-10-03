package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/rhwendt/port49/internal/broker"
	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/crypt"
	etcdstore "github.com/rhwendt/port49/internal/store/etcd"
	"github.com/rhwendt/port49/internal/store/etcd/etcdtest"
	"github.com/rhwendt/port49/internal/testpki"
)

// writeIdentity issues a client certificate for cn, valid from nb to na,
// and writes it and its key, the key at mode.
func writeIdentity(t *testing.T, ca *testpki.CA, cn string, nb, na time.Time, mode os.FileMode) config.EtcdIdentity {
	t.Helper()
	dir := t.TempDir()
	c, err := ca.Issue(testpki.Leaf{CommonName: cn, Client: true, NotBefore: nb, NotAfter: na})
	if err != nil {
		t.Fatal(err)
	}
	cp, kp, err := testpki.PEMs(c)
	if err != nil {
		t.Fatal(err)
	}
	id := config.EtcdIdentity{CertFile: filepath.Join(dir, "c.pem"), KeyFile: filepath.Join(dir, "k.pem")}
	if err := os.WriteFile(id.CertFile, cp, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(id.KeyFile, kp, mode); err != nil {
		t.Fatal(err)
	}
	return id
}

// An expired store certificate is named for what it is, a key file others
// can read is refused at the read, and a certificate that does not parse
// is refused naming its key (pre-flight I9, I13; Task 11): none is ever
// "not answering".
func TestAStoreIdentityIsCheckedWhereItIsRead(t *testing.T) {
	now := time.Now()
	ca, err := testpki.NewCA("ca", now.Add(-48*time.Hour), now.Add(48*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	expired := writeIdentity(t, ca, "port49-daemon", now.Add(-48*time.Hour), now.Add(-time.Hour), 0o600)
	_, _, err = identity("daemon", expired, ca.Pool(), now)
	var fault *storeFault
	if !errors.As(err, &fault) || !strings.Contains(err.Error(), "expired at") || errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("an expired certificate: %v", err)
	}
	loose := writeIdentity(t, ca, "port49-daemon", now.Add(-time.Hour), now.Add(time.Hour), 0o644)
	if _, _, err := identity("daemon", loose, ca.Pool(), now); !errors.As(err, &fault) || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("a key others can read: %v", err)
	}
	garbled := writeIdentity(t, ca, "port49-daemon", now.Add(-time.Hour), now.Add(time.Hour), 0o600)
	if err := os.WriteFile(garbled.CertFile, []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"),
		0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := identity("daemon", garbled, ca.Pool(), now); !errors.As(err, &fault) ||
		!strings.Contains(err.Error(), garbled.KeyFile) || errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("a certificate that does not parse: %v", err)
	}
	root := writeIdentity(t, ca, etcdstore.RootUser, now.Add(-time.Hour), now.Add(time.Hour), 0o600)
	if _, _, err := identity("daemon", root, ca.Pool(), now); !errors.As(err, &fault) ||
		!strings.Contains(err.Error(), "etcd's administrator") {
		t.Fatalf("a certificate for etcd's root: %v", err)
	}
	good := writeIdentity(t, ca, "port49-daemon", now.Add(-time.Hour), now.Add(time.Hour), 0o600)
	if _, leaf, err := identity("daemon", good, ca.Pool(), now); err != nil || leaf.Subject.CommonName != "port49-daemon" {
		t.Fatalf("a good identity: %v", err)
	}
}

// A certificate etcd refuses, and a server this CA does not verify, are
// named by the probe; a port nothing answers on is an outage (pre-flight
// I9).
func TestProbeTLSTellsAFaultFromAnOutage(t *testing.T) {
	srv := etcdtest.Start(t, etcdtest.Options{TLS: true})
	ctx := context.Background()
	good := srv.TLS(t, "port49-daemon")
	if err := probeTLS(ctx, []string{srv.Endpoint}, good, time.Second); err != nil {
		t.Fatalf("a good identity: %v", err)
	}
	now := time.Now()
	other, err := testpki.NewCA("other", now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	stranger := writeIdentity(t, other, "port49-daemon", now.Add(-time.Hour), now.Add(time.Hour), 0o600)
	tc, _, err := identity("daemon", stranger, good.RootCAs, now)
	if err != nil {
		t.Fatal(err)
	}
	var fault *storeFault
	if err := probeTLS(ctx, []string{srv.Endpoint}, tc, time.Second); !errors.As(err, &fault) {
		t.Fatalf("a client certificate etcd does not trust: %v", err)
	}
	wrongCA := good.Clone()
	wrongCA.RootCAs = other.Pool()
	if err := probeTLS(ctx, []string{srv.Endpoint}, wrongCA, time.Second); !errors.As(err, &fault) {
		t.Fatalf("a server this CA does not verify: %v", err)
	}
	if err := probeTLS(ctx, []string{"https://127.0.0.1:1"}, good, time.Second); !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("nothing listening: %v", err)
	}
}

// The start's roles check refuses a daemon that reaches past its role in
// ErrNotSeparated's words, naming the fix; under store.etcd.roles:
// unenforced it skips the daemon's, and still refuses a broker that cannot
// do its own work (Ruling 10; Task 11).
func TestTheRolesCheckRunsTheBrokersUnderUnenforced(t *testing.T) {
	const prefix = "/port49/"
	srv := etcdtest.Start(t, etcdtest.Options{TLS: true})
	var grants []etcdtest.Grant
	for _, g := range etcdstore.Roles(prefix) {
		grants = append(grants, etcdtest.Grant{Role: g.Role, Key: g.Key, RangeEnd: g.RangeEnd, Write: g.Write})
	}
	// Each identity has the other's role: the daemon reaches past its own,
	// and the broker cannot write meta/.
	srv.EnableAuth(t, grants, map[string][]string{"port49-daemon": {etcdstore.RoleBroker},
		"port49-broker": {etcdstore.RoleDaemon}, "port49-broker2": {etcdstore.RoleBroker}})
	open := func(cn string) (*etcdstore.Store, *x509.Certificate) {
		tc := srv.TLS(t, cn)
		s, err := etcdstore.Open(etcdstore.Config{Endpoints: []string{srv.Endpoint}, TLS: tc, Prefix: prefix})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.Close() })
		leaf, err := x509.ParseCertificate(tc.Certificates[0].Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		return s, leaf
	}
	d, dl := open("port49-daemon")
	b, bl := open("port49-broker")
	b2, b2l := open("port49-broker2")
	ctx := context.Background()
	e := &config.EtcdConfig{CallTimeout: 2 * time.Second, Roles: config.RolesEnforced}

	err := checkRoles(ctx, d, b2, e, map[string]*x509.Certificate{"daemon": dl, "broker": b2l})
	if !errors.Is(err, etcdstore.ErrNotSeparated) || !strings.Contains(err.Error(), "a store identity reaches past its role") ||
		!strings.Contains(err.Error(), "store.etcd.roles: unenforced") || !strings.Contains(err.Error(), "store.etcd.daemon") {
		t.Fatalf("enforced, a daemon with the broker's role: %v", err)
	}
	e.Roles = config.RolesUnenforced
	if err := checkRoles(ctx, d, b2, e, map[string]*x509.Certificate{"daemon": dl, "broker": b2l}); err != nil {
		t.Fatalf("unenforced, the daemon's check is skipped: %v", err)
	}
	err = checkRoles(ctx, d, b, e, map[string]*x509.Certificate{"daemon": dl, "broker": bl})
	if !errors.Is(err, store.ErrRefused) || !strings.Contains(err.Error(), "store.etcd.broker") {
		t.Fatalf("unenforced, a broker that cannot write meta/: %v", err)
	}
}

// After a store gone, a start that fails for any other reason is said
// and tried again, never an exit; a cold start's error is returned
// (re-check R-I2).
func TestAStartAfterAStoreGoneRetriesEveryError(t *testing.T) {
	var out syncBuffer
	e := stderr
	t.Cleanup(func() { stderr = e })
	stderr = &out
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var calls []bool
	once := func(again bool) error {
		calls = append(calls, again)
		switch len(calls) {
		case 1:
			return &storeGone{why: "test: the store went"}
		case 2, 3:
			return errors.New("test: the policy file is half-written")
		}
		cancel()
		return nil
	}
	if err := runLoop(ctx, once, time.Millisecond); err != nil {
		t.Fatalf("runLoop = %v", err)
	}
	if len(calls) != 4 || calls[0] || !calls[1] || !calls[3] {
		t.Fatalf("runs %v; want a cold start, then three after the store gone", calls)
	}
	if strings.Count(out.String(), "starting again after a store gone: test: the policy file is half-written") != 2 {
		t.Fatalf("said %q", out.String())
	}
	cold := errors.New("test: a bad config")
	if err := runLoop(context.Background(), func(bool) error { return cold }, time.Millisecond); err != cold {
		t.Fatalf("a cold start's error: %v", err)
	}
}

// What the start's carry left decides what the start does (Rulings T12-a,
// T12-c, T12-d): an outage or an unvisited principal holds it, returned
// for the retry to wait on; a busy context opens it owing a pass at once,
// an unheld key opens it owing the next retry, and anything else is
// returned to end it (Task 12 review I-1; re-review m-5).
func TestTheStartsCarryDecidesHoldOrOpen(t *testing.T) {
	other := errors.New("test: something else")
	unvisited := fmt.Errorf("pass: %w", broker.ErrPrincipalUnvisited)
	outage := fmt.Errorf("pass: %w", store.ErrUnavailable)
	for _, c := range []struct {
		name  string
		err   error
		owed  refreshOwed
		again error
		waits error // what the start's retry waits on, for a hold
	}{
		{"nothing left", nil, refreshOwed{}, nil, nil},
		{"an unvisited principal holds", unvisited, refreshOwed{}, unvisited, broker.ErrPrincipalUnvisited},
		{"an outage holds", outage, refreshOwed{}, outage, store.ErrUnavailable},
		{"a busy context opens owing a pass now", fmt.Errorf("pass: %w", store.ErrConflict),
			refreshOwed{owed: true, now: true}, nil, nil},
		{"an unheld key opens owing the next retry", fmt.Errorf("pass: %w", broker.ErrLeftUnderUnheldKey),
			refreshOwed{owed: true}, nil, nil},
		{"anything else ends the start", other, refreshOwed{}, other, nil},
	} {
		owed, again := startLeftBy(c.err)
		if owed != c.owed || again != c.again {
			t.Errorf("%s: startLeftBy = %+v, %v; want %+v, %v", c.name, owed, again, c.owed, c.again)
		}
		if c.waits != nil && !errors.Is(again, c.waits) {
			t.Errorf("%s: the start's retry would not wait on %v", c.name, again)
		}
	}
}

// A start whose store was last written under a current key this
// configuration does not hold warns and sets the gauge; one that holds it
// as previous does not (Ruling 14). Either way it records its own.
func TestCheckSealKeysWarnsAboutAKeyNotHeld(t *testing.T) {
	srv := etcdtest.Start(t, etcdtest.Options{})
	s, err := etcdstore.Open(etcdstore.Config{Endpoints: []string{srv.Endpoint}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	if err := s.PutSealKeys(ctx, etcdstore.SealKeys{Current: "enc2"}); err != nil {
		t.Fatal(err)
	}
	m := metrics.New(prometheus.NewRegistry())
	var out bytes.Buffer
	rotated := crypt.Keys{Current: crypt.Key{ID: "enc3"}}
	if err := checkSealKeys(ctx, s, rotated, m, &out); err != nil {
		t.Fatal(err)
	}
	// None is revoked for it: the start leaves a context under an unheld
	// key unjudged, and every path denies it store_unavailable (spec, a
	// start on etcd, Keys; Ruling T12-a).
	if !strings.Contains(out.String(), `whose current key is "enc2", which this configuration does not hold`) ||
		!strings.Contains(out.String(), "are denied store_unavailable until a start holds that key again") ||
		testutil.ToFloat64(m.CryptStoreKeyUnknown) != 1 {
		t.Fatalf("said %q, gauge %v", out.String(), testutil.ToFloat64(m.CryptStoreKeyUnknown))
	}
	out.Reset()
	kept := crypt.Keys{Current: crypt.Key{ID: "enc4"}, Previous: &crypt.Key{ID: "enc3"}}
	if err := checkSealKeys(ctx, s, kept, m, &out); err != nil || out.Len() != 0 ||
		testutil.ToFloat64(m.CryptStoreKeyUnknown) != 0 {
		t.Fatalf("a window holding the store's key: said %q, %v", out.String(), err)
	}
}

// The unopenable line names the key and what to do, once per record kind
// and key id per ten minutes.
func TestUnopenableSayerSaysOncePerKeyPerTenMinutes(t *testing.T) {
	now := time.Unix(1000, 0)
	var out bytes.Buffer
	say := unopenableSayer(crypt.Keys{Current: crypt.Key{ID: "enc3"}}, &out, func() time.Time { return now })
	say("token", "enc2")
	say("token", "enc2")
	if strings.Count(out.String(), "\n") != 1 || !strings.Contains(out.String(),
		`a token is sealed under key id "enc2", which this port49d does not hold (current "enc3", no previous)`) {
		t.Fatalf("said %q", out.String())
	}
	say("context", "enc2")
	now = now.Add(11 * time.Minute)
	say("token", "enc2")
	if strings.Count(out.String(), "\n") != 3 {
		t.Fatalf("said %q", out.String())
	}
	say("token", "enc3")
	if !strings.Contains(out.String(), `failed authentication under key id "enc3"`) {
		t.Fatalf("a record under a held key that will not open: %q", out.String())
	}
}
