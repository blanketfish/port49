package port49d

import (
	"time"

	"github.com/blanketfish/port49/internal/broker"
	"github.com/blanketfish/port49/internal/fence"
	"github.com/blanketfish/port49/internal/oidc"
	"github.com/blanketfish/port49/internal/pivattest"
	"github.com/blanketfish/port49/internal/policy"
)

// maxAttestationRootsBytes bounds attestation_roots_file: a few PEM
// certificates, never a bundle of a system's.
const maxAttestationRootsBytes = 1 << 20

// maxCAFileBytes bounds an OIDC verifier's ca_file, a few certificates likewise.
const maxCAFileBytes = 1 << 20

// loadPerLoginMFA is broker.identity.per_login_mfa resolved for the broker
// (plan 9c; decision 45), or nil when none is configured. A roots file that
// cannot be read, holds no PEM, holds a block that is not a certificate or is
// not terminated or well formed, or holds no self-signed root never refuses
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
	raw, err := readLimited(cfg.AttestationRootsFile, maxAttestationRootsBytes, "attestation roots file")
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

// reloadAttestationRoots re-reads attestation_roots_file at a SIGHUP and puts the roots in
// force, as spec §5.1.6's "add the root or intermediate to attestation_roots_file, then
// reload" says. A file that cannot be read, holds no PEM or no self-signed root changes
// nothing: the roots in force stay, and one line says so, as a key file that cannot be
// read at a reload keeps the secret already held. With no roots file configured it does
// nothing. b is the broker serving; its other verifier settings are untouched.
func reloadAttestationRoots(cfg *oidc.PerLoginMFA, b *broker.Broker, pol func() *policy.Policy, say func(string, ...any)) {
	if cfg == nil || cfg.AttestationRootsFile == "" || b == nil {
		return
	}
	raw, err := readLimited(cfg.AttestationRootsFile, maxAttestationRootsBytes, "attestation roots file")
	var a pivattest.Anchors
	if err == nil {
		a, err = pivattest.ParseAnchors(raw)
	}
	if err != nil {
		say("broker: SIGHUP: per_login_mfa.hardware_key_touch.attestation_roots_file %s: %v; keeping the "+
			"attestation roots already in force", cfg.AttestationRootsFile, err)
		return
	}
	was := 0
	if old := b.AttestationRoots(); old != nil {
		was = old.NumRoots
	}
	b.SetAttestationRoots(&a)
	say("broker: SIGHUP: per_login_mfa hardware_key_touch verifies attestations against %s; re-read: %d roots (was %d)",
		cfg.AttestationRootsFile, a.NumRoots, was)
	// What the roots now in force change about the policy in force, as at a start.
	if p := pol(); p != nil {
		if line := b.MFAUnavailable(p, time.Now()); line != "" {
			say("broker: %s", line)
		}
		if line := b.AdminTouchLine(p); line != "" {
			say("%s", line)
		}
	}
}

// readLimited reads a certificate file through the policy-file fence (fence.Read): the file and its
// directory are ours or root's alone to write, a link is followed only through directories held to
// that rule, a named pipe is refused, and more than limit bytes is refused. A file anyone else can
// replace would add a trusted root.
func readLimited(path string, limit int64, what string) ([]byte, error) {
	return fence.Read(path, limit, what)
}
