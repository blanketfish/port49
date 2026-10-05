package port49d

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	clientv3 "go.etcd.io/etcd/client/v3"

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
	// The daemon's identity alone (plan 7e): unenforced, its check is
	// skipped and there is no broker's to run; enforced, it is refused as
	// above.
	if err := checkRoles(ctx, d, nil, e, map[string]*x509.Certificate{"daemon": dl}); err != nil {
		t.Fatalf("unenforced, the daemon alone: %v", err)
	}
	e.Roles = config.RolesEnforced
	if err := checkRoles(ctx, d, nil, e, map[string]*x509.Certificate{"daemon": dl}); !errors.Is(err,
		etcdstore.ErrNotSeparated) || !strings.Contains(err.Error(), "store.etcd.daemon") {
		t.Fatalf("enforced, the daemon alone with the broker's role: %v", err)
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

// sealKeysStore is an etcd store on a server of its own, for the start's
// key check.
func sealKeysStore(t *testing.T) (*etcdtest.Server, *etcdstore.Store) {
	t.Helper()
	srv := etcdtest.Start(t, etcdtest.Options{})
	s, err := etcdstore.Open(etcdstore.Config{Endpoints: []string{srv.Endpoint}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return srv, s
}

// A start whose store was last written under a current key this
// configuration does not hold warns and sets the gauge; one that holds it
// as previous does not (Ruling 14). Either way it records its own.
func TestCheckSealKeysWarnsAboutAKeyNotHeld(t *testing.T) {
	_, s := sealKeysStore(t)
	ctx := context.Background()
	if err := s.PutSealKeys(ctx, etcdstore.SealKeys{Current: "enc2"}); err != nil {
		t.Fatal(err)
	}
	m := metrics.New(prometheus.NewRegistry())
	var out bytes.Buffer
	rotated := crypt.Keys{Current: crypt.Key{ID: "enc3"}}
	if err := checkSealKeys(ctx, s, rotated, m, &out, time.Second, newKeyAlarm(), true); err != nil {
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
	// Another process: a window holding the store's key.
	kept := crypt.Keys{Current: crypt.Key{ID: "enc4"}, Previous: &crypt.Key{ID: "enc3"}}
	if err := checkSealKeys(ctx, s, kept, m, &out, time.Second, newKeyAlarm(), true); err != nil || out.Len() != 0 ||
		testutil.ToFloat64(m.CryptStoreKeyUnknown) != 0 {
		t.Fatalf("a window holding the store's key: said %q, %v", out.String(), err)
	}
}

// port49d with no broker reads the last start's key ids and warns as a
// broker's start does, and writes nothing over them: its role cannot write
// meta/, and the runner records them (plan 7e).
func TestCheckSealKeysWithoutWriteLeavesTheRecord(t *testing.T) {
	_, s := sealKeysStore(t)
	ctx := context.Background()
	if err := s.PutSealKeys(ctx, etcdstore.SealKeys{Current: "enc2"}); err != nil {
		t.Fatal(err)
	}
	m := metrics.New(prometheus.NewRegistry())
	var out bytes.Buffer
	if err := checkSealKeys(ctx, s, crypt.Keys{Current: crypt.Key{ID: "enc3"}}, m, &out, time.Second, newKeyAlarm(),
		false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `whose current key is "enc2"`) || testutil.ToFloat64(m.CryptStoreKeyUnknown) != 1 {
		t.Fatalf("said %q, gauge %v", out.String(), testutil.ToFloat64(m.CryptStoreKeyUnknown))
	}
	if got, ok, err := s.SealKeys(ctx); !ok || err != nil || got.Current != "enc2" {
		t.Fatalf("written over: %+v %v %v", got, ok, err)
	}
}

// A run after a store gone keeps the alarm: the records under the lost key
// are as live as before, though the first run wrote its own window over
// the store's. The gauge, a new run's, stays 1 until port49d restarts, and
// the line is not said again (review m-1). Nor is it said again for the
// same window while a start retries through an outage (review m-4).
func TestCheckSealKeysKeepsTheAlarmAcrossARun(t *testing.T) {
	_, s := sealKeysStore(t)
	ctx := context.Background()
	if err := s.PutSealKeys(ctx, etcdstore.SealKeys{Current: "enc2"}); err != nil {
		t.Fatal(err)
	}
	alarm := newKeyAlarm()
	var out bytes.Buffer
	rotated := crypt.Keys{Current: crypt.Key{ID: "enc3"}}
	if err := checkSealKeys(ctx, s, rotated, metrics.New(prometheus.NewRegistry()), &out, time.Second,
		alarm, true); err != nil {
		t.Fatal(err)
	}
	// An outage after the read: the next try reads the same window.
	if err := s.PutSealKeys(ctx, etcdstore.SealKeys{Current: "enc2"}); err != nil {
		t.Fatal(err)
	}
	if err := checkSealKeys(ctx, s, rotated, metrics.New(prometheus.NewRegistry()), &out, time.Second,
		alarm, true); err != nil {
		t.Fatal(err)
	}
	if strings.Count(out.String(), "\n") != 1 {
		t.Fatalf("a retry said the same window again: %q", out.String())
	}
	again := metrics.New(prometheus.NewRegistry())
	if err := checkSealKeys(ctx, s, rotated, again, &out, time.Second, alarm, true); err != nil {
		t.Fatal(err)
	}
	if strings.Count(out.String(), "\n") != 1 || testutil.ToFloat64(again.CryptStoreKeyUnknown) != 1 {
		t.Fatalf("a run after a store gone: said %q, gauge %v", out.String(),
			testutil.ToFloat64(again.CryptStoreKeyUnknown))
	}
}

// A stored id is the store writer's, so the warning echoes it only within
// the key-id charset (review I-2; pre-flight M44).
func TestCheckSealKeysEchoesNoForeignID(t *testing.T) {
	for _, c := range []struct{ name, id string }{
		{"outside the charset", "a\nb;c"},
		{"a megabyte", strings.Repeat("k", 1<<20)},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, s := sealKeysStore(t)
			ctx := context.Background()
			if err := s.PutSealKeys(ctx, etcdstore.SealKeys{Current: c.id}); err != nil {
				t.Fatal(err)
			}
			m := metrics.New(prometheus.NewRegistry())
			var out bytes.Buffer
			if err := checkSealKeys(ctx, s, crypt.Keys{Current: crypt.Key{ID: "enc3"}}, m, &out, time.Second,
				newKeyAlarm(), true); err != nil {
				t.Fatal(err)
			}
			if out.Len() > 1024 || !strings.Contains(out.String(), `whose current key is "?"`) ||
				strings.Contains(out.String(), `a\nb`) || testutil.ToFloat64(m.CryptStoreKeyUnknown) != 1 {
				t.Fatalf("said %d bytes: %.300q", out.Len(), out.String())
			}
		})
	}
}

// A store that stops answering after the hold does not hang the start: each
// call of the check is bounded, and the bound's end is an outage, which
// openStores says and tries again (review I-1).
func TestCheckSealKeysIsBounded(t *testing.T) {
	srv := etcdtest.Start(t, etcdtest.Options{})
	proxy := etcdtest.NewProxy(t, strings.TrimPrefix(srv.Endpoint, "http://"))
	s, err := etcdstore.Open(etcdstore.Config{Endpoints: []string{"http://" + proxy.Addr()}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	proxy.Hang(true)
	defer proxy.Hang(false)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	start := time.Now()
	err = checkSealKeys(ctx, s, crypt.Keys{Current: crypt.Key{ID: "enc3"}}, metrics.New(prometheus.NewRegistry()),
		io.Discard, 200*time.Millisecond, newKeyAlarm(), true)
	if !errors.Is(err, store.ErrUnavailable) || time.Since(start) > 2*time.Second {
		t.Fatalf("a hung store: %v after %v", err, time.Since(start))
	}
}

// The unopenable line names the key and what to do, once per record kind
// and key id per ten minutes.
func TestUnopenableSayerSaysOncePerKeyPerTenMinutes(t *testing.T) {
	now := time.Unix(1000, 0)
	var out bytes.Buffer
	say := unopenableSayer("port49d", crypt.Keys{Current: crypt.Key{ID: "enc3"}}, &out, func() time.Time { return now })
	say("token", "enc2", nil)
	say("token", "enc2", nil)
	if strings.Count(out.String(), "\n") != 1 || !strings.Contains(out.String(),
		`a token is sealed under key id "enc2", which this port49d does not hold (current "enc3", no previous)`) {
		t.Fatalf("said %q", out.String())
	}
	say("context", "enc2", nil)
	now = now.Add(11 * time.Minute)
	say("token", "enc2", nil)
	if strings.Count(out.String(), "\n") != 3 {
		t.Fatalf("said %q", out.String())
	}
	say("token", "enc3", nil)
	if !strings.Contains(out.String(), `failed authentication under key id "enc3"`) {
		t.Fatalf("a record under a held key that will not open: %q", out.String())
	}
}

// A record too short to name a key is corrupt, not a key a rotation
// retired: it gets the altered wording, never the rotation advice (review
// m-3).
func TestUnopenableSayerCallsANamelessRecordCorrupt(t *testing.T) {
	var out bytes.Buffer
	say := unopenableSayer("port49d", crypt.Keys{Current: crypt.Key{ID: "enc3"}}, &out, time.Now)
	say("token", "", nil)
	if !strings.Contains(out.String(), "it was altered or is corrupt") ||
		strings.Contains(out.String(), "encryption.previous") {
		t.Fatalf("a nameless record: %q", out.String())
	}
	out.Reset()
	say("token", "enc2", nil)
	if !strings.Contains(out.String(), `set encryption.previous to "enc2"`) ||
		strings.Contains(out.String(), "altered") {
		t.Fatalf("a record under a retired key: %q", out.String())
	}
}

// An earlier form is the upgrade, said as the upgrade: never "altered or is
// corrupt", which at 3am reads as an attack across the fleet.
func TestTheSayerNamesAnEarlierFormAsTheUpgrade(t *testing.T) {
	var out bytes.Buffer
	keys := crypt.Keys{Current: crypt.Key{ID: "v2"}}
	say := unopenableSayer("port49d", keys, &out, time.Now)
	say("context", "v2", fmt.Errorf("crypt: opening context: %w", crypt.ErrEarlierForm))
	got := out.String()
	if !strings.Contains(got, "a context sealed by an earlier port49 (form 3) does not open: expected once "+
		"after the 7e upgrade; replaced at its user's next login") || strings.Contains(got, "altered") {
		t.Fatalf("%q", got)
	}
}

// An earlier-form line does not silence a put-back or a tamper line under
// the same key id, nor the reverse: a store writer can put a form-3 record
// back at any key every 10 minutes, and the line that names tampering must
// still be said (Task 7 review I-1).
func TestAnEarlierFormLineDoesNotSilenceAPutBackLine(t *testing.T) {
	var out bytes.Buffer
	keys := crypt.Keys{Current: crypt.Key{ID: "v2"}}
	say := unopenableSayer("port49d", keys, &out, time.Now)
	say("context", "v2", fmt.Errorf("crypt: opening context: %w", crypt.ErrEarlierForm))
	say("context", "v2", crypt.ErrNotLastWritten)
	say("context", "v2", nil)
	say("context", "v2", fmt.Errorf("crypt: opening context: %w", crypt.ErrEarlierForm))
	got := out.String()
	if strings.Count(got, "\n") != 3 || !strings.Contains(got, "earlier port49") || !strings.Contains(got, "put back") ||
		!strings.Contains(got, "altered") {
		t.Fatalf("%q", got)
	}
}

// Under a key this port49d does not hold, the line is the rotation advice
// whatever the open said: the earlier-form and put-back lines are only for
// a held key, whose record did open (Task 7 review M-6).
func TestTheSayerGivesTheRotationAdviceUnderAnUnheldKey(t *testing.T) {
	for _, why := range []error{fmt.Errorf("crypt: opening context: %w", crypt.ErrEarlierForm),
		crypt.ErrNotLastWritten} {
		var out bytes.Buffer
		say := unopenableSayer("port49d", crypt.Keys{Current: crypt.Key{ID: "v2"}}, &out, time.Now)
		say("context", "v1", why)
		got := out.String()
		if !strings.Contains(got, `set encryption.previous to "v1"`) || strings.Contains(got, "earlier port49") ||
			strings.Contains(got, "put back") {
			t.Fatalf("%v: %q", why, got)
		}
	}
}

// A record below the newest write is named as that, not as "the one this
// port49d last wrote", which is no longer the rule (plan 7e, Ruling 3).
func TestTheSayerNamesAPutBackAsBelowTheNewestWrite(t *testing.T) {
	var out bytes.Buffer
	keys := crypt.Keys{Current: crypt.Key{ID: "v2"}}
	say := unopenableSayer("port49d", keys, &out, time.Now)
	say("context", "v2", crypt.ErrNotLastWritten)
	got := out.String()
	if !strings.Contains(got, "is sealed below the newest write any port49 process made there") ||
		strings.Contains(got, "last wrote") {
		t.Fatalf("%q", got)
	}
}

// Every sealing layer openStores builds shares one sayer, so a key is
// said once, not once per layer or per read (pre-flight M44; review m-2).
// With no broker in the process the daemon's is the one layer, read
// twice. The broker's half is TestTheBrokersStoresShareOneSayer.
func TestOpenStoresSharesOneSayer(t *testing.T) {
	daemonCfg, _ := etcdSplit(t)
	cfg, err := config.Load(daemonCfg)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := cfg.EncryptionKeys()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var out syncBuffer
	sts, err := openStores(ctx, cfg, keys, metrics.New(prometheus.NewRegistry()), &out, newReadiness(), false,
		func(error) {}, crypt.NewLedger(), newKeyAlarm(), store.NewMarks())
	if err != nil {
		t.Fatal(err)
	}
	defer sts.close()
	// The feed follows as runOnce's does: a fenced read waits for it.
	fctx, stopFollow := context.WithCancel(ctx)
	followDone := make(chan struct{})
	go func() { defer close(followDone); sts.follow(fctx) }()
	defer func() { stopFollow(); <-followDone }()
	k := store.ContextKey{NAS: "leaf1", Username: "alice"}
	retired := crypt.Keys{Current: crypt.Key{ID: "retired", Bytes: [32]byte{7}}}
	// The daemon's role writes contexts: the test writes one under a key
	// this port49d does not hold, as an earlier port49d would have.
	if err := crypt.Wrap(sts.etcd, retired, nil).PutContext(ctx, k, store.Context{CtxID: "c", Principal: "user:alice",
		Username: "alice", AuthTime: time.Now(), RefreshedAt: time.Now()}, time.Hour); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := sts.daemon.GetContext(ctx, k); !errors.Is(err, crypt.ErrUnknownKey) {
			t.Fatalf("a context under a retired key: %v", err)
		}
	}
	if n := strings.Count(out.String(), `sealed under key id "retired"`); n != 1 {
		t.Fatalf("said %d times: %q", n, out.String())
	}
	if sts.broker != nil || sts.probe == nil {
		t.Fatalf("the split daemon's stores: broker %v, probe %v", sts.broker != nil, sts.probe != nil)
	}
}

// port49d with no broker on etcd takes no hold and writes nothing under
// meta/: its role cannot, and any number of port49d share a keyspace
// (plan 7e, Ruling 11). It reads the seal keys and warns, and
// port49_store_keyspace_held stays 0. The marks in the store are loaded
// into the process's marks before the start returns.
func TestTheSplitDaemonsStartTakesNoHoldAndWritesNoMeta(t *testing.T) {
	daemonCfg, _, srv := etcdSplitServer(t)
	root := srv.Client(t, "root")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := root.Put(ctx, "/port49/v1/meta/seal_keys", `{"current":"enc0","written_at":"2026-10-03T03:00:00Z"}`); err != nil {
		t.Fatal(err)
	}
	if _, err := root.Put(ctx, "/port49/v1/rv/principal/user:alice@example.com", `{"kind":"principal",`+
		`"key":"user:alice@example.com","at":"2026-10-03T03:00:00Z","origin":"test: a broker"}`); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(daemonCfg)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := cfg.EncryptionKeys()
	if err != nil {
		t.Fatal(err)
	}
	m := metrics.New(prometheus.NewRegistry())
	marks := store.NewMarks()
	var out syncBuffer
	sts, err := openStores(ctx, cfg, keys, m, &out, newReadiness(), false, func(error) {}, crypt.NewLedger(),
		newKeyAlarm(), marks)
	if err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	defer sts.close()
	resp, err := root.Get(ctx, "/port49/v1/meta/", clientv3.WithPrefix())
	if err != nil || len(resp.Kvs) != 1 || string(resp.Kvs[0].Key) != "/port49/v1/meta/seal_keys" ||
		!strings.Contains(string(resp.Kvs[0].Value), `"enc0"`) {
		t.Fatalf("meta/ after the split daemon's start: %v %v", resp, err)
	}
	if testutil.ToFloat64(m.StoreKeyspaceHeld) != 0 || testutil.ToFloat64(m.CryptStoreKeyUnknown) != 1 ||
		!strings.Contains(out.String(), `whose current key is "enc0"`) {
		t.Fatalf("held %v, key unknown %v:\n%s", testutil.ToFloat64(m.StoreKeyspaceHeld),
			testutil.ToFloat64(m.CryptStoreKeyUnknown), out.String())
	}
	if !marks.Holds(store.RevocationPrincipal, "user:alice@example.com") ||
		!strings.Contains(out.String(), "port49d: store: 1 revocation(s) in force from the store\n") {
		t.Fatalf("the marks: %v\n%s", marks.All(), out.String())
	}
}

// A daemon role without the read on lw/ (roles applied before plan 7e)
// ends the start as a store fault naming store-roles: waiting does not
// mend a refusal (pre-flight M17).
func TestARefusedLedgerRecordReadNamesStoreRoles(t *testing.T) {
	daemonCfg, _, srv := etcdSplitServer(t)
	lw := "/port49/v1/lw/"
	if _, err := srv.Client(t, "root").RoleRevokePermission(context.Background(), etcdstore.RoleDaemon, lw,
		clientv3.GetPrefixRangeEnd(lw)); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(daemonCfg)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := cfg.EncryptionKeys()
	if err != nil {
		t.Fatal(err)
	}
	var out syncBuffer
	_, err = openStores(context.Background(), cfg, keys, metrics.New(prometheus.NewRegistry()), &out, newReadiness(),
		false, func(error) {}, crypt.NewLedger(), newKeyAlarm(), store.NewMarks())
	var fault *storeFault
	if !errors.As(err, &fault) || !strings.Contains(err.Error(), "apply port49d store-roles (plan 7e)") {
		t.Fatalf("a refused read of the ledger record: %v", err)
	}
}

// A daemon role without the read on meta/witness or meta/purged (roles
// applied by 7e-1's output, or by hand) leaves the restore guard silently
// off on a fresh process, and refuses every redemption for good if the
// grant is lost after a witness was followed. The start probes both reads
// and ends as a store fault naming store-roles (final review 7e-2 M-7).
func TestARefusedWitnessReadNamesStoreRoles(t *testing.T) {
	for _, key := range []string{"witness", "purged"} {
		t.Run(key, func(t *testing.T) {
			daemonCfg, _, srv := etcdSplitServer(t)
			if _, err := srv.Client(t, "root").RoleRevokePermission(context.Background(), etcdstore.RoleDaemon,
				"/port49/v1/meta/"+key, ""); err != nil {
				t.Fatal(err)
			}
			cfg, err := config.Load(daemonCfg)
			if err != nil {
				t.Fatal(err)
			}
			keys, err := cfg.EncryptionKeys()
			if err != nil {
				t.Fatal(err)
			}
			var out syncBuffer
			_, err = openStores(context.Background(), cfg, keys, metrics.New(prometheus.NewRegistry()), &out,
				newReadiness(), false, func(error) {}, crypt.NewLedger(), newKeyAlarm(), store.NewMarks())
			var fault *storeFault
			if !errors.As(err, &fault) || !strings.Contains(err.Error(), "meta/witness and meta/purged") ||
				!strings.Contains(err.Error(), "port49d store-roles") {
				t.Fatalf("a refused read of meta/%s: %v", key, err)
			}
		})
	}
}

// openStores fences the daemon's layer under its guard (pre-flight C1;
// review 8a I-1): with the feed not running, a context written after the
// start's scan is not read, a context-pool timeout at call_timeout,
// though the store answers it, and counted in
// port49_store_fence_timeouts_total, which tells it from an etcd failure
// (final review 7e-1 M-4). The probe pings through the same guard and
// fence, so with the feed stopped its pings time out too (plan 7e, Ruling
// 11). The broker's half is TestTheBrokersStoreIsFencedUnderItsGuard.
func TestOpenStoresFencesEachLayerUnderItsGuard(t *testing.T) {
	daemonCfg, _ := etcdSplit(t)
	cfg, err := config.Load(daemonCfg)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := cfg.EncryptionKeys()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := metrics.New(prometheus.NewRegistry())
	sts, err := openStores(ctx, cfg, keys, m, io.Discard, newReadiness(), false, func(error) {}, crypt.NewLedger(),
		newKeyAlarm(), store.NewMarks())
	if err != nil {
		t.Fatal(err)
	}
	defer sts.close()
	// Another process's login: sealed past this one's base, so only the
	// fence keeps it from being read.
	other := crypt.NewLedger()
	other.SetBase(sts.etcd.Seen() + 1)
	k := store.ContextKey{NAS: "leaf1", Username: "alice"}
	if err := crypt.Wrap(sts.etcd, keys, nil, crypt.WithLedger(other)).PutContext(ctx, k, store.Context{CtxID: "c",
		Principal: "user:alice", Username: "alice", AuthTime: time.Now(), RefreshedAt: time.Now()},
		time.Hour); err != nil {
		t.Fatal(err)
	}
	if got, err := sts.daemon.GetContext(ctx, k); !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("the daemon read %q with the feed not running: %v", got.CtxID, err)
	}
	if n := testutil.ToFloat64(m.StoreCalls.WithLabelValues("daemon", "context", "timeout")); n != 1 {
		t.Fatalf("the daemon's guard counted %v context timeouts", n)
	}
	if n := testutil.ToFloat64(m.StoreFenceTimeouts); n != 1 {
		t.Fatalf("port49_store_fence_timeouts_total = %v, want 1", n)
	}
	// One probe round (hold_ttl/6 is under 2s here): fenced, and counted
	// by the daemon's guard.
	pctx, stopProbe := context.WithCancel(ctx)
	probeDone := make(chan struct{})
	go func() { defer close(probeDone); sts.probe(pctx) }()
	deadline := time.Now().Add(10 * time.Second)
	for testutil.ToFloat64(m.StoreFenceTimeouts) < 2 {
		if time.Now().After(deadline) {
			t.Fatal("the probe's ping was not fenced")
		}
		time.Sleep(50 * time.Millisecond)
	}
	stopProbe()
	<-probeDone
	if n := testutil.ToFloat64(m.StoreCalls.WithLabelValues("daemon", "context", "timeout")); n < 2 {
		t.Fatalf("the daemon's guard counted %v context timeouts with the probe's", n)
	}
}

// A run after a store gone shows the alarm a run before it raised for as
// long as it waits for the store, not from when the store answers: the
// wait is the outage, and an alert would resolve through it (re-review
// I-3).
func TestARaisedAlarmIsGaugedWhileTheStoreIsAway(t *testing.T) {
	daemonCfg, proxy := etcdSplit(t)
	cfg, err := config.Load(daemonCfg)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := cfg.EncryptionKeys()
	if err != nil {
		t.Fatal(err)
	}
	proxy.Hang(true)
	defer proxy.Hang(false)
	alarm := newKeyAlarm()
	alarm.warn(storedWindow{current: "enc2"}, func() {})
	m := metrics.New(prometheus.NewRegistry())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var out syncBuffer
	done := make(chan error, 1)
	go func() {
		_, err := openStores(ctx, cfg, keys, m, &out, newReadiness(), true, func(error) {}, crypt.NewLedger(), alarm,
			store.NewMarks())
		done <- err
	}()
	waitCountWithin(t, &out, "not answering", 1, 10*time.Second)
	if v := testutil.ToFloat64(m.CryptStoreKeyUnknown); v != 1 {
		t.Fatalf("port49_crypt_store_key_unknown = %v while the store is away", v)
	}
	cancel()
	<-done
}

// Both feeds' series read 0 from when a run on etcd begins waiting for
// the store, before either feed first runs: an alert on
// port49_store_feed_up == 0 for hold_ttl cannot fire on an absent series
// (final review 7e-1 M-3). The rescan counters are there at 0 too, so the
// first rescan is an increase.
func TestBothFeedsReadDownWhileTheStoreIsAway(t *testing.T) {
	daemonCfg, proxy := etcdSplit(t)
	cfg, err := config.Load(daemonCfg)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := cfg.EncryptionKeys()
	if err != nil {
		t.Fatal(err)
	}
	proxy.Hang(true)
	defer proxy.Hang(false)
	m := metrics.New(prometheus.NewRegistry())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var out syncBuffer
	done := make(chan error, 1)
	go func() {
		_, err := openStores(ctx, cfg, keys, m, &out, newReadiness(), false, func(error) {}, crypt.NewLedger(),
			newKeyAlarm(), store.NewMarks())
		done <- err
	}()
	waitCountWithin(t, &out, "not answering", 1, 10*time.Second)
	if up, rescans := testutil.CollectAndCount(m.StoreFeedUp), testutil.CollectAndCount(m.StoreFeedRescans); up != 2 ||
		rescans != 2 {
		t.Fatalf("while the store is away: %d port49_store_feed_up series and %d rescan series, want 2 each", up,
			rescans)
	}
	for _, feed := range []string{"contexts", "marks"} {
		if v := testutil.ToFloat64(m.StoreFeedUp.WithLabelValues(feed)); v != 0 {
			t.Fatalf("port49_store_feed_up{feed=%q} = %v while the store is away", feed, v)
		}
	}
	cancel()
	<-done
}

// A last window that does not decode never refuses the start: whoever can
// write the store would otherwise hold every start shut. It is said with
// none of its bytes, gauged, and written over with this window (spec, a
// start on etcd, Keys).
func TestCheckSealKeysGoesOnPastAnUndecodableRecord(t *testing.T) {
	srv, s := sealKeysStore(t)
	ctx := context.Background()
	if _, err := srv.Client(t, "root").Put(ctx, "/port49/v1/meta/seal_keys", "{\"current\":\"a\nb"); err != nil {
		t.Fatal(err)
	}
	m := metrics.New(prometheus.NewRegistry())
	var out bytes.Buffer
	keys := crypt.Keys{Current: crypt.Key{ID: "enc3"}}
	if err := checkSealKeys(ctx, s, keys, m, &out, time.Second, newKeyAlarm(), true); err != nil {
		t.Fatalf("an undecodable record refused the start: %v", err)
	}
	if !strings.Contains(out.String(), "the last start's key ids are unreadable") ||
		strings.Contains(out.String(), "a\nb") || strings.Count(out.String(), "\n") != 1 ||
		testutil.ToFloat64(m.CryptStoreKeyUnknown) != 1 {
		t.Fatalf("said %q, gauge %v", out.String(), testutil.ToFloat64(m.CryptStoreKeyUnknown))
	}
	if got, ok, err := s.SealKeys(ctx); !ok || err != nil || got.Current != "enc3" {
		t.Fatalf("not written over: %+v %v %v", got, ok, err)
	}
}

// meta/holder is the store's, so the line echoes it only in the shape
// port49-broker writes, or a 7d port49d wrote, quoted and cut to 200
// bytes, and "?" otherwise (final review 7d-2 m-1).
func TestLineHolderEchoesOnlyTheShapePort49dWrites(t *testing.T) {
	ok := "port49d on leaf-host.example.com (pid 4242, since 2026-10-03T01:02:03Z)"
	broker := "port49-broker on leaf-host.example.com (pid 4242, since 2026-10-03T01:02:03Z)"
	long := "port49d on " + strings.Repeat("h", 250) + " (pid 4242, since 2026-10-03T01:02:03Z)"
	for in, want := range map[string]string{
		ok:     fmt.Sprintf("%q", ok),
		broker: fmt.Sprintf("%q", broker),
		long:   fmt.Sprintf("%q", long[:200]),
		"port49-brokers on host (pid 1, since 2026-10-03T01:02:03Z)":                       "?",
		"port49d on host (pid 1, since 2026-10-03T01:02:03Z)\nport49d: forged line":        "?",
		"port49d on host (pid 1, since 2026-10-03T01:02:03Z)" + strings.Repeat("x", 1<<20): "?",
		strings.Repeat("x", 1<<20): "?",
		"":                         "?",
	} {
		if got := lineHolder(in); got != want {
			t.Errorf("lineHolder(%.80q) = %.300q, want %.300q", in, got, want)
		}
	}
}
