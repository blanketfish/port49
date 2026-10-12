package port49d

import (
	"io"
	"os"

	"github.com/rhwendt/port49/internal/broker"
	"github.com/rhwendt/port49/internal/oidc"
	"github.com/rhwendt/port49/internal/pivattest"
)

// maxAttestationRootsBytes bounds attestation_roots_file: a few PEM
// certificates, never a bundle of a system's.
const maxAttestationRootsBytes = 1 << 20

// loadPerLoginMFA is broker.identity.per_login_mfa resolved for the broker
// (plan 9c; decision 45), or nil when none is configured. A roots file that
// cannot be read, holds no PEM, or holds no self-signed root never refuses
// the start: hardware_key_touch is then unavailable, one line names the
// file, and a mint under a requirement that accepts it alone is answered
// per_login_mfa_unavailable rather than a broker that will not start.
func loadPerLoginMFA(cfg *oidc.PerLoginMFA, say func(string, ...any)) *broker.MFAVerifiers {
	if cfg == nil {
		return nil
	}
	v := &broker.MFAVerifiers{AMR: cfg.AMR, ACRValues: cfg.ACRValues}
	if cfg.AttestationRootsFile == "" {
		return v
	}
	raw, err := readLimited(cfg.AttestationRootsFile, maxAttestationRootsBytes)
	if err == nil {
		var a pivattest.Anchors
		if a, err = pivattest.ParseAnchors(raw); err == nil {
			v.Anchors = &a
			say("broker: per_login_mfa hardware_key_touch verifies attestations against %s", cfg.AttestationRootsFile)
			return v
		}
	}
	say("broker: per_login_mfa.hardware_key_touch.attestation_roots_file %s: %v; hardware_key_touch is "+
		"unavailable until it is fixed and the broker restarts", cfg.AttestationRootsFile, err)
	return v
}

func readLimited(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, limit))
}
