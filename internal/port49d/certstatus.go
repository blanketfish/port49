package port49d

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"syscall"

	"github.com/rhwendt/port49/internal/certstatus"
	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/printsafe"
)

// issuerFileMax bounds an issuer_file's read: one certificate is a few
// kilobytes.
const issuerFileMax = 1 << 20

// certStatusConfig maps broker.certificate_status onto certstatus.Config
// (plan 7b Task 11). It reads each issuer_file, one PEM certificate, and
// refuses one that is neither the anchor nor signed by it, naming the source
// (pre-flight C1): a list is trusted for the issuer it names, so that issuer
// must be one the broker trusts already. The kept lists go in stateDir:
// port49-broker's broker.state_dir (plan 7e, Ruling 12), or for the
// in-process broker on memory the directory holding
// broker.revocations_file (pre-flight I8).
//
// It lives here rather than as a config method, as the plan has it, because
// certstatus imports inventory, which imports config.
func certStatusConfig(cs config.CertificateStatusConfig, anchors []*x509.Certificate, stateDir,
	trusted, who string) (certstatus.Config, error) {
	out := certstatus.Config{RefreshInterval: cs.RefreshInterval, StateDir: stateDir}
	for i, src := range cs.CRLs {
		key := fmt.Sprintf("crls[%d].issuer_file %s", i, src.IssuerFile)
		issuer, err := readIssuerFile(src.IssuerFile)
		if err != nil {
			return certstatus.Config{}, fmt.Errorf("%s: %w", key, err)
		}
		under := slices.ContainsFunc(anchors, func(a *x509.Certificate) bool {
			return bytes.Equal(issuer.Raw, a.Raw) || issuer.CheckSignatureFrom(a) == nil
		})
		if !under {
			return certstatus.Config{}, fmt.Errorf("%s: %s is neither a trust anchor's certificate nor signed by "+
				"one (%s); CRL %s would vouch for certificates %s does not trust", key,
				printsafe.Line(issuer.Subject.String(), 200), trusted, src.Name, who)
		}
		if !issuer.BasicConstraintsValid || !issuer.IsCA {
			return certstatus.Config{}, fmt.Errorf("%s: %s is not a CA certificate, so it signs no CRL", key,
				printsafe.Line(issuer.Subject.String(), 200))
		}
		out.CRLs = append(out.CRLs, certstatus.CRLSource{Name: src.Name, File: src.File, URL: src.URL, Issuer: issuer})
	}
	if o := cs.OCSP; o != nil {
		hash := crypto.SHA256
		if o.Hash == "sha1" {
			hash = crypto.SHA1
		}
		out.OCSP = &certstatus.OCSPConfig{Responder: o.Responder, UseAIA: o.UseAIA, Timeout: o.Timeout, Hash: hash}
	}
	return out, nil
}

// readIssuerFile reads one PEM certificate, and nothing else, from a regular
// file. It is opened non-blocking, so a named pipe in its place is refused
// rather than hanging the start. An error never repeats the file's bytes.
func readIssuerFile(path string) (*x509.Certificate, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	raw, err := io.ReadAll(io.LimitReader(f, issuerFileMax+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > issuerFileMax {
		return nil, fmt.Errorf("larger than %d KiB; it holds one certificate", issuerFileMax>>10)
	}
	var blocks []*pem.Block
	for rest := raw; ; {
		var blk *pem.Block
		if blk, rest = pem.Decode(rest); blk == nil {
			break
		}
		blocks = append(blocks, blk)
	}
	switch {
	case len(blocks) != 1:
		return nil, fmt.Errorf("holds %d PEM blocks; it must hold exactly one, the CA certificate that signs the "+
			"list", len(blocks))
	case blocks[0].Type != "CERTIFICATE":
		return nil, fmt.Errorf("holds a %s PEM block, not the CA certificate that signs the list",
			printsafe.Line(blocks[0].Type, 40))
	}
	cert, err := x509.ParseCertificate(blocks[0].Bytes)
	if err != nil {
		return nil, fmt.Errorf("does not parse as a certificate (%v)", err)
	}
	return cert, nil
}

// uncoveredAnchor reports whether no CRL covers anchor: none whose issuer is
// anchor or a CA it signed. OCSP is not read here: whether a responder
// answers for this anchor's certificates cannot be known at start
// (anchorCoverLine says so; pre-flight M-18).
func uncoveredAnchor(cfg certstatus.Config, anchor *x509.Certificate) bool {
	for _, src := range cfg.CRLs {
		if bytes.Equal(src.Issuer.Raw, anchor.Raw) || src.Issuer.CheckSignatureFrom(anchor) == nil {
			return false
		}
	}
	return true
}

// anchorCoverLine is what the start says of an anchor no CRL covers, "" when
// one does. With no OCSP either, every certificate under it has a status
// nothing can establish: under on_unavailable: refuse (the default) each is
// refused 503 and retried; under allow each is admitted with its status
// unchecked. With OCSP alone, the cover is unchecked for this anchor. The
// start never refuses itself over it (decision 40 ruling 7): a refused
// port49d start takes device AAA down for everyone. It names the safe path,
// never on_unavailable: allow.
func anchorCoverLine(a namedAnchor, cfg certstatus.Config, onUnavailable string) string {
	if !uncoveredAnchor(cfg, a.cert) {
		return ""
	}
	subj := printsafe.Line(a.cert.Subject.String(), 200)
	if cfg.OCSP != nil {
		outcome := "is refused (503; final at port49 workload)"
		if onUnavailable == "allow" {
			outcome = "is admitted unchecked (on_unavailable: allow)"
		}
		return fmt.Sprintf("broker: certificate status: certificates under %s (%s) are covered by OCSP alone, "+
			"unchecked for this anchor: one with no OCSP URL, or one its responder does not answer for, %s",
			subj, a.key, outcome)
	}
	outcome := "will be refused (503; final at port49 workload)"
	if onUnavailable == "allow" {
		outcome = "will be admitted with its revocation status unchecked (on_unavailable: allow)"
	}
	return fmt.Sprintf("broker: certificate status: every certificate under %s (%s) %s: no crls "+
		"entry is that anchor or a CA it signed, and no ocsp is set; turn the CA's CRL on and name it in crls, "+
		"or sync it to a file: source", subj, a.key, outcome)
}

// intermediateCoverLine is what the start says of a CRL signer nothing
// covers (uncoveredIssuers), for both daemons: what happens to its
// certificates follows on_unavailable, as anchorCoverLine's does.
func intermediateCoverLine(subject, onUnavailable string) string {
	outcome := "will be refused (503; final at port49 workload)"
	if onUnavailable == "allow" {
		outcome = "will be admitted with their revocation status unchecked (on_unavailable: allow)"
	}
	return fmt.Sprintf("broker: certificate status: certificates issued by %s %s: nothing covers %s itself; "+
		"name the root CA's CRL", subject, outcome, subject)
}

// uncoveredIssuers names each CRL signer other than the anchor whose own
// status nothing can establish: no source's issuer_file is the anchor and
// OCSP is off. Every certificate it issued is then Unknown, and refused
// under on_unavailable: refuse (re-check R3).
func uncoveredIssuers(cfg certstatus.Config, anchor *x509.Certificate) []string {
	if cfg.OCSP != nil {
		return nil
	}
	for _, src := range cfg.CRLs {
		if bytes.Equal(src.Issuer.Raw, anchor.Raw) {
			return nil
		}
	}
	var out []string
	seen := map[string]bool{}
	for _, src := range cfg.CRLs {
		if src.Issuer.CheckSignatureFrom(anchor) != nil {
			continue // another anchor's: never named under this one
		}
		if subject := src.Issuer.Subject.String(); !seen[subject] {
			seen[subject] = true
			out = append(out, printsafe.Line(subject, 200))
		}
	}
	return out
}
