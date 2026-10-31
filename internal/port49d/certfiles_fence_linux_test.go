//go:build linux

package port49d

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/rhwendt/port49/internal/broker"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/oidc"
	"github.com/rhwendt/port49/internal/oidc/oidctest"
	"github.com/rhwendt/port49/internal/policy"
)

// attestation_roots_file and an OIDC verifier's ca_file name the certificates the broker trusts, so a
// file anyone but the process's user or root can replace is a way to add a trusted root. Both are read
// through the policy-file fence (fence.Read) at the start, and the roots again at SIGHUP.
type unsafeFile struct {
	name string
	// make returns the path to give the broker; the file or its place is the unsafe part.
	make func(t *testing.T, pem []byte) string
}

func unsafeCertFiles() []unsafeFile {
	return []unsafeFile{
		{"in a world-writable directory", func(t *testing.T, pem []byte) string {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0o777); err != nil {
				t.Fatal(err)
			}
			p := filepath.Join(dir, "roots.pem")
			if err := os.WriteFile(p, pem, 0o644); err != nil {
				t.Fatal(err)
			}
			return p
		}},
		{"in a group-writable directory", func(t *testing.T, pem []byte) string {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0o775); err != nil {
				t.Fatal(err)
			}
			p := filepath.Join(dir, "roots.pem")
			if err := os.WriteFile(p, pem, 0o644); err != nil {
				t.Fatal(err)
			}
			return p
		}},
		{"a link to a file outside, in a world-writable directory", func(t *testing.T, pem []byte) string {
			out := t.TempDir()
			if err := os.Chmod(out, 0o777); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(out, "roots.pem"), pem, 0o644); err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			p := filepath.Join(dir, "roots.pem")
			if err := os.Symlink(filepath.Join(out, "roots.pem"), p); err != nil {
				t.Fatal(err)
			}
			return p
		}},
		{"a named pipe", func(t *testing.T, _ []byte) string {
			p := filepath.Join(t.TempDir(), "roots.pem")
			if err := syscall.Mkfifo(p, 0o600); err != nil {
				t.Fatal(err)
			}
			return p
		}},
		{"owned by another user", func(t *testing.T, pem []byte) string {
			if os.Getuid() != 0 {
				t.Skip("needs root to chown; the CI job that runs the root tests covers it")
			}
			p := filepath.Join(t.TempDir(), "roots.pem")
			if err := os.WriteFile(p, pem, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Chown(p, 12345, 12345); err != nil {
				t.Fatal(err)
			}
			return p
		}},
	}
}

// within fails the test if f hangs: a FIFO read with a plain open would.
func within(t *testing.T, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { f(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the read hung")
	}
}

func TestAttestationRootsFileIsReadThroughTheFence(t *testing.T) {
	pem, _ := rootsPEM(t, "attest-root")
	for _, u := range unsafeCertFiles() {
		t.Run(u.name, func(t *testing.T) {
			path := u.make(t, pem)
			var said []string
			say := func(f string, a ...any) { said = append(said, fmt.Sprintf(f, a...)) }
			within(t, func() {
				v := loadPerLoginMFA(&oidc.PerLoginMFA{AttestationRootsFile: path}, say)
				if v == nil || v.Anchors != nil {
					t.Errorf("the roots of an unsafe file are in force: %+v", v)
				}
			})
			if len(said) != 1 || !strings.Contains(said[0], "unavailable") {
				t.Errorf("said %q, want one line saying hardware_key_touch is unavailable", said)
			}
		})
	}
}

func TestAttestationRootsFileIsReadThroughTheFenceAtSIGHUP(t *testing.T) {
	pem, _ := rootsPEM(t, "attest-root")
	good := filepath.Join(stateDirT(t), "roots.pem")
	if err := os.WriteFile(good, pem, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, u := range unsafeCertFiles() {
		t.Run(u.name, func(t *testing.T) {
			path := u.make(t, pem)
			var said []string
			say := func(f string, a ...any) { said = append(said, fmt.Sprintf(f, a...)) }
			b := &broker.Broker{PerLoginMFA: loadPerLoginMFA(&oidc.PerLoginMFA{AttestationRootsFile: good}, say)}
			held := b.PerLoginMFA.Anchors
			if held == nil {
				t.Fatal("the good roots file was not read")
			}
			said = nil
			within(t, func() {
				reloadAttestationRoots(&oidc.PerLoginMFA{AttestationRootsFile: path}, b, func() *policy.Policy { return nil }, say)
			})
			if b.PerLoginMFA.Anchors != held {
				t.Error("an unsafe file replaced the roots in force")
			}
			if len(said) != 1 || !strings.Contains(said[0], "keeping the attestation roots already in force") {
				t.Errorf("said %q, want one line keeping the roots", said)
			}
		})
	}
}

func TestOIDCCAFileIsReadThroughTheFence(t *testing.T) {
	iss := oidctest.NewIssuer(t)
	for _, u := range unsafeCertFiles() {
		t.Run(u.name, func(t *testing.T) {
			path := u.make(t, iss.CertPEM())
			dir := stateDirT(t)
			cfg := brokerConfig(t, directoryPolicy)
			cfg.Broker.Identity = identityCfg(t, iss, dir)
			for i := range cfg.Broker.Identity.OIDC {
				cfg.Broker.Identity.OIDC[i].CAFile = path
			}
			within(t, func() {
				if _, err := openOIDC(cfg, dir, metrics.New(prometheus.NewRegistry()), func(string, ...any) {}); err == nil {
					t.Error("an unsafe ca_file was trusted")
				} else if !strings.Contains(err.Error(), "ca_file") {
					t.Errorf("the refusal does not name ca_file: %v", err)
				}
			})
		})
	}
}
