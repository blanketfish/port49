//go:build linux

package port49d

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/broker"
	"github.com/rhwendt/port49/internal/config"
)

// The files that name what port49d trusts - a client CA or a trust anchor, etcd's CA, a CRL issuer, a CA
// bundle sent to clients, the device listener's CA and intermediates - are read through the policy-file
// fence like attestation_roots_file is (decision 54 ruling 16): a file or a directory anyone else can
// write, a link out of its directory and a named pipe are each refused, with a good file in a safe
// directory as the control that the refusal is the fence's, not the PEM's.
func TestRootOfTrustFilesAreReadThroughTheFence(t *testing.T) {
	pem, _ := rootsPEM(t, "trust-root")
	readers := []struct {
		name string
		read func(path string) error
	}{
		{"client_ca_file / trust_anchor_file (broker.ReadAnchor)", func(p string) error { _, err := broker.ReadAnchor(p); return err }},
		{"etcd ca_file (caCerts)", func(p string) error { _, _, err := caCerts(p); return err }},
		{"crls issuer_file (readIssuerFile)", func(p string) error { _, err := readIssuerFile(p); return err }},
		{"tls_ca_bundle_file (readCABundle)", func(p string) error { _, err := readCABundle(p); return err }},
	}
	for _, r := range readers {
		t.Run(r.name, func(t *testing.T) {
			good := filepath.Join(stateDirT(t), "ca.pem")
			if err := os.WriteFile(good, pem, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := r.read(good); err != nil {
				t.Fatalf("the control, a good file in a safe directory, was refused: %v", err)
			}
			for _, u := range unsafeCertFiles() {
				t.Run(u.name, func(t *testing.T) {
					path := u.make(t, pem)
					within(t, func() {
						if err := r.read(path); err == nil {
							t.Error("an unsafe file was read")
						}
					})
				})
			}
		})
	}
}

// At a reload the listener keeps the files in force when its CA, or its intermediates, is one the fence
// refuses, and says so once; at the start it refuses to come up.
func TestTLSListenerCAFilesAreReadThroughTheFence(t *testing.T) {
	for _, field := range []string{"client_ca_file", "intermediates_file"} {
		for _, u := range unsafeCertFiles() {
			t.Run(field+" "+u.name, func(t *testing.T) {
				p := writeDevicePKI(t)
				pem, err := os.ReadFile(p.caFile)
				if err != nil {
					t.Fatal(err)
				}
				path := u.make(t, pem)
				set := func(c *config.TLSListenerConfig) {
					if field == "client_ca_file" {
						c.ClientCAFile = path
					} else {
						c.IntermediatesFile = path
					}
				}
				var sink lineSink
				within(t, func() {
					cfg := p.listenerCfg()
					set(&cfg)
					if l, err := newTLSListener(cfg, nil, nil, false, nil, time.Now, sink.say); err == nil || l != nil {
						t.Errorf("the start accepted an unsafe %s", field)
					}
				})
				l, err := newTLSListener(p.listenerCfg(), nil, nil, false, nil, time.Now, sink.say)
				if err != nil {
					t.Fatal(err)
				}
				first := l.Material()
				set(&l.cfg)
				within(t, func() { l.reload("SIGHUP") })
				if l.Material() != first || first == nil {
					t.Error("an unsafe file replaced the material in force")
				}
				if !strings.Contains(sink.all(), "not reloaded, the files in force stay") {
					t.Errorf("the refusal is not said: %s", sink.all())
				}
			})
		}
	}
}
