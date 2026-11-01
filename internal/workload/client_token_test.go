package workload

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/broker/api"
	"github.com/blanketfish/port49/internal/testpki"
)

// tokenHarness is a TLS broker that asks for no client certificate, as an
// OIDC-only or k8s-only broker does, and a Config presenting a token file.
func tokenHarness(t *testing.T, f *fakeBroker, token string) (Config, string) {
	t.Helper()
	now := time.Now()
	ca, err := testpki.NewCA("broker", now.Add(-time.Hour), now.Add(48*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ca.Issue(testpki.Leaf{CommonName: "broker", IPs: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(f)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	p := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(p, []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}
	return Config{Broker: srv.URL, BrokerCA: ca.Pool(), TokenFile: p, Deadline: time.Minute}, p
}

func TestATokenFileIsPresentedAsABearer(t *testing.T) {
	f := &fakeBroker{batchMax: 10, answers: []func(http.ResponseWriter, api.MintRequest){permitAll}}
	cfg, _ := tokenHarness(t, f, "eyJ.a.b\n")
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Mint(context.Background(), MintOptions{Devices: devices(1)}); err != nil {
		t.Fatal(err)
	}
	if len(f.auths) != 1 || f.auths[0] != "Bearer eyJ.a.b" {
		t.Fatalf("%q: the file's trailing newline is trimmed, nothing else", f.auths)
	}
	if len(f.presents) != 0 {
		t.Fatal("a certificate was presented beside the token")
	}
}

// A retry presents the token the kubelet wrote since.
func TestTheTokenFileIsReadAtEveryAttempt(t *testing.T) {
	var p string
	rotate := func(w http.ResponseWriter, req api.MintRequest) {
		if err := os.WriteFile(p, []byte("second.a.b"), 0o600); err != nil {
			t.Error(err)
		}
		refuse(http.StatusServiceUnavailable, "identity_provider_unavailable", "1")(w, req)
	}
	f := &fakeBroker{batchMax: 10, answers: []func(http.ResponseWriter, api.MintRequest){rotate, permitAll}}
	cfg, file := tokenHarness(t, f, "first.a.b")
	p = file
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	c.sleep = func(context.Context, time.Duration) error { return nil }
	if _, err := c.Mint(context.Background(), MintOptions{Devices: devices(1)}); err != nil {
		t.Fatal(err)
	}
	if len(f.auths) != 2 || f.auths[0] != "Bearer first.a.b" || f.auths[1] != "Bearer second.a.b" {
		t.Fatalf("%q", f.auths)
	}
}

func TestATokenFileIsRefusedBesideACertificate(t *testing.T) {
	f := &fakeBroker{batchMax: 10, answers: []func(http.ResponseWriter, api.MintRequest){permitAll}}
	cfg, _ := tokenHarness(t, f, "a.b.c")
	cfg.CertFile, cfg.KeyFile = "/c.pem", "/k.pem"
	if _, err := New(cfg); err == nil || !strings.Contains(err.Error(), "a certificate or a token file, not both") {
		t.Fatalf("%v", err)
	}
}

func TestAnUnusableTokenFileIsRefusedAtTheStart(t *testing.T) {
	f := &fakeBroker{batchMax: 10, answers: []func(http.ResponseWriter, api.MintRequest){permitAll}}
	for name, body := range map[string]string{"empty": "", "spaced": "a.b c", "too long": strings.Repeat("a", MaxTokenFile+1)} {
		cfg, _ := tokenHarness(t, f, body)
		_, err := New(cfg)
		var te *TokenFileError
		if !errors.As(err, &te) || strings.Contains(err.Error(), "a.b c") {
			t.Errorf("%s: %v", name, err)
		}
	}
	cfg, p := tokenHarness(t, f, "a.b.c")
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	var te *TokenFileError
	if _, err := New(cfg); !errors.As(err, &te) {
		t.Fatalf("missing: %v", err)
	}
}

// The kubelet's projected volume reaches the token through symlinks.
func TestASymlinkedTokenFileIsRead(t *testing.T) {
	f := &fakeBroker{batchMax: 10, answers: []func(http.ResponseWriter, api.MintRequest){permitAll}}
	cfg, real := tokenHarness(t, f, "link.a.b\n")
	dir := t.TempDir()
	mid := filepath.Join(dir, "..data")
	if err := os.Symlink(real, mid); err != nil {
		t.Fatal(err)
	}
	cfg.TokenFile = filepath.Join(dir, "token")
	if err := os.Symlink(mid, cfg.TokenFile); err != nil {
		t.Fatal(err)
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Mint(context.Background(), MintOptions{Devices: devices(1)}); err != nil {
		t.Fatal(err)
	}
	if len(f.auths) != 1 || f.auths[0] != "Bearer link.a.b" {
		t.Fatalf("%q", f.auths)
	}
}

// A token file that is a directory, unreadable, or whitespace only is a
// TokenFileError, and no message carries the token.
func TestTokenFileFailuresNeverCarryTheToken(t *testing.T) {
	const secret = "SECRETFAKE.tok.en"
	f := &fakeBroker{batchMax: 10, answers: []func(http.ResponseWriter, api.MintRequest){permitAll}}
	cases := map[string]func(t *testing.T, cfg *Config, p string){
		"directory": func(t *testing.T, cfg *Config, _ string) { cfg.TokenFile = t.TempDir() },
		"whitespace only": func(t *testing.T, _ *Config, p string) {
			if err := os.WriteFile(p, []byte(" \n\t\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"inner space": func(t *testing.T, _ *Config, p string) {
			if err := os.WriteFile(p, []byte(secret+" more"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"non-ascii": func(t *testing.T, _ *Config, p string) {
			if err := os.WriteFile(p, []byte(secret+"é"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"unreadable": func(t *testing.T, _ *Config, p string) {
			if os.Geteuid() == 0 {
				t.Skip("root reads any file")
			}
			if err := os.WriteFile(p, []byte(secret), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(p, 0); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			cfg, p := tokenHarness(t, f, secret)
			setup(t, &cfg, p)
			_, err := New(cfg)
			var te *TokenFileError
			if !errors.As(err, &te) {
				t.Fatalf("%v", err)
			}
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("the message carries the token: %v", err)
			}
		})
	}
}

// The file going away under the run is final, and says nothing of the token.
func TestATokenFileThatGoesAwayMidRunIsFinal(t *testing.T) {
	var p string
	gone := func(w http.ResponseWriter, req api.MintRequest) {
		_ = os.Remove(p)
		refuse(http.StatusServiceUnavailable, "identity_provider_unavailable", "1")(w, req)
	}
	f := &fakeBroker{batchMax: 10, answers: []func(http.ResponseWriter, api.MintRequest){gone, permitAll}}
	cfg, file := tokenHarness(t, f, "first.a.b")
	p = file
	cfg.Deadline = 3 * time.Second
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	c.sleep = func(context.Context, time.Duration) error { return nil }
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = c.Mint(ctx, MintOptions{Devices: devices(1)})
	var te *TokenFileError
	if !errors.As(err, &te) || strings.Contains(err.Error(), "first.a.b") {
		t.Fatalf("%v", err)
	}
	if len(f.auths) != 1 {
		t.Fatalf("%d requests: a file that went away is final, not retried", len(f.auths))
	}
}
