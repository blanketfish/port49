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
// must be one the broker trusts already. The kept lists go in stateDir, the
// directory holding broker.revocations_file (pre-flight I8).
//
// It lives here rather than as a config method, as the plan has it, because
// certstatus imports inventory, which imports config.
func certStatusConfig(cs config.CertificateStatusConfig, anchor *x509.Certificate, stateDir string) (certstatus.Config, error) {
	out := certstatus.Config{RefreshInterval: cs.RefreshInterval, StateDir: stateDir}
	for i, src := range cs.CRLs {
		key := fmt.Sprintf("crls[%d].issuer_file %s", i, src.IssuerFile)
		issuer, err := readIssuerFile(src.IssuerFile)
		if err != nil {
			return certstatus.Config{}, fmt.Errorf("%s: %w", key, err)
		}
		if !bytes.Equal(issuer.Raw, anchor.Raw) {
			if err := issuer.CheckSignatureFrom(anchor); err != nil {
				return certstatus.Config{}, fmt.Errorf("%s: %s is neither broker.client_ca_file's certificate nor "+
					"signed by it (%v); CRL %s would vouch for certificates the broker does not trust", key,
					printsafe.Line(issuer.Subject.String(), 200), err, src.Name)
			}
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
		if subject := src.Issuer.Subject.String(); !seen[subject] {
			seen[subject] = true
			out = append(out, printsafe.Line(subject, 200))
		}
	}
	return out
}
