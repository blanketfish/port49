package port49d

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/rhwendt/port49/internal/broker"
	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/daemon/admin"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/directory"
	"github.com/rhwendt/port49/internal/oidc"
	"github.com/rhwendt/port49/internal/policy"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/crypt"
	"github.com/rhwendt/port49/internal/store/memory"
)

var signInTestKeys = crypt.Keys{Current: crypt.Key{ID: "k", Bytes: [32]byte{9}}}

// signInConfig is brokerConfig with a directory_password verifier, a
// directory and a state directory of its own, the enrollment store in the
// memory backend's file.
func signInConfig(t *testing.T, listen string) (config.Config, string) {
	t.Helper()
	cfg := brokerConfig(t, directoryPolicy)
	state := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg.Broker.StateDir = state
	cfg.Broker.Listen = listen
	cfg.Broker.Identity = &oidc.Config{
		Issuance: &oidc.Issuance{CertificateLifetime: 12 * time.Hour},
		PasswordSignIn: &oidc.PasswordSignIn{PrincipalDomains: []string{"example.com"},
			NewEntriesFor: oidc.DefaultNewEntriesFor, ReopenFor: oidc.DefaultReopenFor,
			FailuresPerPrincipal: oidc.DefaultFailuresPerPrincipal, FailuresPerSource: oidc.DefaultFailuresPerSource,
			Window: oidc.DefaultSignInWindow, OpenUntil: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)}}
	cfg.Broker.Directory = directoryCfg("gssapi")
	file := filepath.Join(state, stateEnrollmentsFile)
	cfg.Broker.Directory.EnrollmentStore = directory.EnrollmentStore{Backend: config.BackendMemory, File: file}
	return cfg, file
}

// builtSignInBroker is buildBroker over cfg, its directory a static one.
func builtSignInBroker(t *testing.T, cfg config.Config, m *metrics.Metrics) *broker.Broker {
	t.Helper()
	var sink syncBuffer
	e, o, h := stderr, stdout, openDirectoryHook
	t.Cleanup(func() { stderr, stdout, openDirectoryHook = e, o, h })
	stderr, stdout = &sink, io.Discard
	openDirectoryHook = func(_ config.Config, st store.Store, _ *policy.Live, _ *metrics.Metrics,
		_ func(string, ...any)) (*directory.Resolver, error) {
		return directory.ForTestsStaticResolver(st, map[string]directory.Answer{}, nil), nil
	}
	_, b, err := buildBroker(cfg, "inventory_file", memory.New(time.Now), seedMinter(), decision.NewJSONLines(io.Discard), m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// signInStatus posts a sign-in, with no certificate, to b and returns the
// status and the error code in the body.
func signInStatus(t *testing.T, b *broker.Broker) (int, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(api.SignInRequest{Name: "alice", Password: "not-a-real-password", Code: "123456",
		CSR: base64.RawURLEncoding.EncodeToString(der)})
	req := httptest.NewRequest(http.MethodPost, "/v1/sign-in", bytes.NewReader(body))
	w := httptest.NewRecorder()
	b.Handler().ServeHTTP(w, req)
	var e api.Error
	_ = json.Unmarshal(w.Body.Bytes(), &e)
	return w.Code, e.Error
}

// port49d and port49-broker wire the sign-in beside the issuer (plan 9e,
// Task 10): the verifier with the default label, the directory, and an
// enrollment store that is opened and never created. A new state directory
// has no enrollments.json after the start; sign-in answers 503
// enrollment_store_lost; the gauge reads 0; the line names init-enrollments;
// the start line names the verifier. An operator's init-enrollments then
// brings it up.
func TestPort49dWiresThePasswordSignIn(t *testing.T) {
	cfg, file := signInConfig(t, "127.0.0.1:0")
	m := metrics.New(prometheus.NewRegistry())
	b := builtSignInBroker(t, cfg, m)
	var out syncBuffer
	b.Say = func(format string, args ...any) {
		out.Write([]byte(strings.TrimSuffix(fmt.Sprintf(format, args...), "\n") + "\n"))
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wirePasswordSignIn(ctx, cfg, b, signInTestKeys, m, nil, &out)

	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatalf("the start created %s: %v", file, err)
	}
	if b.PasswordSignIn == nil || b.PasswordSignIn == cfg.Broker.Identity.PasswordSignIn {
		t.Fatal("the broker has no verifier of its own")
	}
	if got := b.PasswordSignIn.TOTPLabel; got != "port49 (127.0.0.1)" {
		t.Fatalf("the label is %q", got)
	}
	if cfg.Broker.Identity.PasswordSignIn.TOTPLabel != "" {
		t.Fatal("the config's verifier was edited")
	}
	if b.SignInDirectory == nil || b.Enrollments == nil || b.EnrollmentFile != file {
		t.Fatalf("directory %v, enrollments %v, file %q", b.SignInDirectory, b.Enrollments, b.EnrollmentFile)
	}
	if code, why := signInStatus(t, b); code != 503 || why != "enrollment_store_lost" {
		t.Fatalf("sign-in answered %d %q", code, why)
	}
	if v := testutil.ToFloat64(m.DirectoryEnrollmentStoreOK); v != 0 {
		t.Fatalf("the gauge reads %v", v)
	}
	got := out.String()
	for _, want := range []string{
		"port49d: broker: directory-password sign-in on (second factor totp; principal domains example.com; " +
			"enrollments in " + file + "; enrollment open until " + decision.FormatTime(time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)) +
			", new entries for 336h; " +
			"limits 5 per principal, 50 per source, per 15m)",
		"init-enrollments",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the output lacks %q:\n%s", want, got)
		}
	}

	// The operator's init, through the admin socket's adapter.
	srv := &admin.Server{}
	serveSignInOps(srv, b)
	if srv.EnrollmentsInit == nil || srv.SecondFactorReset == nil || srv.SignInUnlock == nil ||
		srv.EnrollmentsExport == nil || srv.EnrollmentsImport == nil {
		t.Fatal("the sign-in ops are not wired")
	}
	if text, err := srv.EnrollmentsInit(ctx, 1000); err != nil || text == "" {
		t.Fatalf("init: %q %v", text, err)
	}
	if v := testutil.ToFloat64(m.DirectoryEnrollmentStoreOK); v != 1 {
		t.Fatalf("after init the gauge reads %v", v)
	}
	if _, err := os.Stat(file); err != nil {
		t.Fatalf("init wrote no %s: %v", file, err)
	}
}

// A broker with no directory_password verifier gets none of it, and the
// admin socket leaves the sign-in ops to say where they run.
func TestNoPasswordSignInWiresNothing(t *testing.T) {
	cfg, _ := signInConfig(t, "127.0.0.1:0")
	cfg.Broker.Identity.PasswordSignIn = nil
	m := metrics.New(prometheus.NewRegistry())
	b := builtSignInBroker(t, cfg, m)
	var out syncBuffer
	wirePasswordSignIn(context.Background(), cfg, b, signInTestKeys, m, nil, &out)
	if b.PasswordSignIn != nil || b.Enrollments != nil || out.String() != "" {
		t.Fatalf("wired: %v %v %q", b.PasswordSignIn, b.Enrollments, out.String())
	}
	srv := &admin.Server{}
	serveSignInOps(srv, b)
	serveSignInOps(srv, nil)
	if srv.EnrollmentsInit != nil || srv.SecondFactorReset != nil {
		t.Fatal("the ops are wired with no verifier")
	}
}

// The default authenticator label never holds ':' (an IPv6 literal's), and
// is the host broker.listen names, else this host's.
func TestTheDefaultTOTPLabelNeverHoldsAColon(t *testing.T) {
	host, _ := os.Hostname()
	for listen, want := range map[string]string{
		"127.0.0.1:8443":         "port49 (127.0.0.1)",
		"broker.example.com:443": "port49 (broker.example.com)",
		"[2001:db8::1]:8443":     "port49 (2001-db8--1)",
		"[::1]:8443":             "port49 (--1)",
		"0.0.0.0:8443":           "port49 (" + host + ")",
		"[::]:8443":              "port49 (" + host + ")",
		":8443":                  "port49 (" + host + ")",
	} {
		got := defaultTOTPLabel(listen)
		if strings.Contains(got, ":") || len(got) > totpLabelMax {
			t.Errorf("%q: %q", listen, got)
		}
		if host != "" && got != want {
			t.Errorf("%q: got %q, want %q", listen, got, want)
		}
	}
}

// aliceDirectory answers alice's entry and accepts any password, so a
// sign-in reaches the enrollment store.
type aliceDirectory struct{}

func (aliceDirectory) SignInEntry(context.Context, string, string) (directory.SignInEntry, error) {
	return directory.SignInEntry{Identity: directory.Identity{DN: "cn=alice,dc=corp", EntryID: "uuid:alice",
		Principal: "user:alice@example.com", Username: "alice"}, Server: directory.Server{URI: "ldaps://dc1.corp.example:636"}}, nil
}

func (aliceDirectory) CheckPassword(context.Context, directory.Server, string, string) error {
	return nil
}

// downEnrollments is the global etcd's enrollment handle with etcd gone: it
// was opened (the dial is the start's, before this) and no call is answered.
type downEnrollments struct{ store.Enrollments }

func (downEnrollments) GetEnrollmentMark(context.Context) (store.EnrollmentMark, error) {
	return store.EnrollmentMark{}, store.ErrUnavailable
}

func (downEnrollments) GetSecondFactor(context.Context, string) (store.SecondFactor, error) {
	return store.SecondFactor{}, store.ErrUnavailable
}

// An etcd that does not answer at start, the global one or the enrollment
// store's own, never stops port49d: the check says so and returns, the gauge
// stays absent (the store is not known lost), and sign-in is store_unavailable
// until a pass reaches it.
func TestAnEnrollmentEtcdThatDoesNotAnswerNeverStopsTheStart(t *testing.T) {
	for name, tc := range map[string]struct {
		own    bool
		shared bool
	}{
		"the global etcd":                   {shared: true},
		"an own etcd with unreadable files": {own: true},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, _ := signInConfig(t, "127.0.0.1:0")
			es := &cfg.Broker.Directory.EnrollmentStore
			es.Backend, es.File = config.BackendEtcd, ""
			var raw store.Enrollments
			if tc.shared {
				cfg.Store.Etcd = &config.EtcdConfig{Endpoints: []string{"https://etcd-0:2379"}, CallTimeout: 300 * time.Millisecond,
					BulkTimeout: time.Second}
				cfg.Store.Etcd.Breaker.Failures = 5
				raw = downEnrollments{}
			}
			if tc.own {
				missing := filepath.Join(t.TempDir(), "missing")
				es.Etcd = &directory.EnrollmentEtcd{Endpoints: []string{"https://127.0.0.1:1"}, CAFile: missing,
					CertFile: missing, KeyFile: missing, Prefix: "/e/", CallTimeout: 300 * time.Millisecond}
			}
			m := metrics.New(prometheus.NewRegistry())
			b := builtSignInBroker(t, cfg, m)
			var out syncBuffer
			b.Say = func(format string, args ...any) { out.Write([]byte(fmt.Sprintf(format, args...) + "\n")) }
			start := time.Now()
			wireSignIn(context.Background(), cfg, b, signInTestKeys, m, raw, &out)
			if d := time.Since(start); d > 10*time.Second {
				t.Fatalf("the start waited %s", d)
			}
			if b.Enrollments == nil {
				t.Fatal("no enrollment handle")
			}
			if n := testutil.CollectAndCount(m.DirectoryEnrollmentStoreOK); n != 0 {
				t.Fatalf("the gauge is set (%d series) for a store that is only unreachable", n)
			}
			got := out.String()
			if !strings.Contains(got, "did not answer at start") || !strings.Contains(got, "store_unavailable") ||
				!strings.Contains(got, "directory-password sign-in on") {
				t.Fatalf("output:\n%s", got)
			}
			b.SignInDirectory = aliceDirectory{}
			if code, why := signInStatus(t, b); code != 503 || why != "store_unavailable" {
				t.Fatalf("sign-in answered %d %q", code, why)
			}
		})
	}
}
