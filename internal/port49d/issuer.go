package port49d

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/blanketfish/port49/internal/config"
	"github.com/blanketfish/port49/internal/daemon/metrics"
	"github.com/blanketfish/port49/internal/issuer"
	"github.com/blanketfish/port49/internal/keyfile"
)

// issuerFiles reads the issuing CA's files in dir (spec §13 decision 43
// ruling 14): the certificates as the broker reads its own kept state
// (readOwnerOnly), the keys through keyfile's owner-only rule. A file that
// is not there is none.
func issuerFiles(dir string) issuer.Files {
	return issuer.Files{
		Cert: func(name string) ([]byte, error) { return readOwnerOnly(filepath.Join(dir, name)) },
		Key: func(name string) ([]byte, error) {
			path := filepath.Join(dir, name)
			if _, err := os.Lstat(path); errors.Is(err, fs.ErrNotExist) {
				return nil, nil
			}
			return keyfile.ReadOwn(path)
		},
	}
}

// openIssuer loads the issuing CA when broker.identity.issuance is set
// (decision 43 ruling 14), says what it holds, one line per fact, and sets
// the CA's end on its gauge (0 for none). It never refuses the start (R4):
// port49d answers device AAA in the same process.
func openIssuer(cfg config.Config, m *metrics.Metrics, say func(string, ...any)) *issuer.CA {
	return openIssuerFrom(cfg, m, say, loadIssuer(cfg, time.Now()))
}

// openIssuerFrom is openIssuer from a CA already read, the one the record
// check held.
func openIssuerFrom(cfg config.Config, m *metrics.Metrics, say func(string, ...any), l *loadedIssuer) *issuer.CA {
	dir := brokerStateDir(cfg)
	ca, lines := l.ca, l.lines
	for _, l := range lines {
		say("issuance: %s", l)
	}
	say("issuance: certificates of %s over an OIDC sign-in, from the issuing CA in %s",
		cfg.Broker.Identity.Issuance.CertificateLifetime, dir)
	if ca.Cert != nil && ca.Unavailable == nil {
		m.IssuingCANotAfter.Set(float64(ca.Cert.NotAfter.Unix()))
	}
	return ca
}

// fingerprintOf is the fingerprint of the one certificate in certPEM, for a
// line that names a CA just written.
func fingerprintOf(certPEM []byte) string {
	blk, _ := pem.Decode(certPEM)
	if blk == nil {
		return "?"
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return "?"
	}
	return issuer.Fingerprint(c)
}

// initIssuer is init-issuer (decision 43 ruling 14): the issuing CA made in
// dir, once, the key first. A CA already there and whole writes nothing, so
// a provisioning step may run it twice; half of one is refused.
func initIssuer(dir string, now time.Time) (created bool, line string, err error) {
	f := issuerFiles(dir)
	certPEM, errCert := f.Cert(issuer.CertFile)
	keyPEM, errKey := f.Key(issuer.KeyFile)
	switch {
	case errCert != nil || errKey != nil:
		return false, "", errors.Join(errCert, errKey)
	case certPEM != nil && keyPEM != nil:
		ca, _ := issuer.Load(f, now)
		if ca.Unavailable != nil {
			return false, "", fmt.Errorf("the issuing CA in %s is there and not usable (%v); init never replaces it: "+
				"fix the file, or if the CA has expired run rotate-issuer twice, restarting every broker after each",
				dir, ca.Unavailable)
		}
		return false, fmt.Sprintf("the issuing CA in %s is already there (%s); nothing written", dir,
			issuer.Fingerprint(ca.Cert)), nil
	case certPEM == nil && keyPEM != nil:
		return false, "", fmt.Errorf("%s is in %s without %s; if init-issuer was interrupted, remove %s and run it "+
			"again; otherwise restore %s", issuer.KeyFile, dir, issuer.CertFile, issuer.KeyFile, issuer.CertFile)
	case certPEM != nil:
		return false, "", fmt.Errorf("%s is in %s without the other, %s; restore it, or remove it on purpose",
			issuer.CertFile, dir, issuer.KeyFile)
	}
	if certPEM, keyPEM, err = issuer.New(now); err != nil {
		return false, "", err
	}
	if err := createOwnerOnly(filepath.Join(dir, issuer.KeyFile), keyPEM); err != nil {
		return false, "", err
	}
	if err := writeOwnerOnly(filepath.Join(dir, issuer.CertFile), certPEM); err != nil {
		return false, "", err
	}
	return true, fmt.Sprintf("created the issuing CA in %s: %s (%s) and %s, written by uid %d, which the broker must "+
		"run as; on every further broker on this store, copy both into its broker.state_dir; then restart each broker",
		dir, issuer.CertFile, fingerprintOf(certPEM), issuer.KeyFile, os.Geteuid()), nil
}

// rotateIssuer is rotate-issuer (decision 43 ruling 14; R5), run on one
// broker. With no staged CA it stages one: its certificate alone goes to the
// other brokers, which trust it from their next start, and its key stays
// here. With one it promotes it: the current certificate becomes the
// previous, its key is overwritten by the staged key, and the staged becomes
// current. A promotion is refused while an earlier rotation's previous CA is
// still here, since certificates it issued may still be valid, and on a
// broker that holds the staged certificate without its key. Each step is a
// whole-file write, so a promotion interrupted is finished by running it
// again; a staged file that is already the current CA, left by a promotion
// that finished or kept by another broker, is removed and nothing promoted.
func rotateIssuer(dir string, now time.Time) (string, error) {
	f := issuerFiles(dir)
	var cur, curKey, prev, nextCert, nextKey []byte
	for _, r := range []struct {
		dst  *[]byte
		name string
		read func(string) ([]byte, error)
	}{{&cur, issuer.CertFile, f.Cert}, {&curKey, issuer.KeyFile, f.Key}, {&prev, issuer.PreviousCertFile, f.Cert},
		{&nextCert, issuer.NextCertFile, f.Cert}, {&nextKey, issuer.NextKeyFile, f.Key}} {
		raw, err := r.read(r.name)
		if err != nil {
			return "", err
		}
		*r.dst = raw
	}
	join := func(name string) string { return filepath.Join(dir, name) }
	removeNext := func() error {
		for _, name := range []string{issuer.NextKeyFile, issuer.NextCertFile} {
			if err := os.Remove(join(name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return err
			}
		}
		return nil
	}
	switch {
	case cur == nil:
		return "", fmt.Errorf("there is no %s in %s to rotate from; run init-issuer first", issuer.CertFile, dir)
	case nextCert == nil && nextKey == nil:
		certPEM, keyPEM, err := issuer.New(now)
		if err != nil {
			return "", err
		}
		if err := writeOwnerOnly(join(issuer.NextKeyFile), keyPEM); err != nil {
			return "", err
		}
		if err := writeOwnerOnly(join(issuer.NextCertFile), certPEM); err != nil {
			return "", err
		}
		return fmt.Sprintf("staged the next issuing CA in %s (%s): copy %s alone to every other broker on this store "+
			"(its key, %s, stays here) and restart each, so each trusts it; then run rotate-issuer again here to issue "+
			"with it", dir, fingerprintOf(certPEM), issuer.NextCertFile, issuer.NextKeyFile), nil
	case nextCert != nil && bytes.Equal(cur, nextCert) && (nextKey == nil || bytes.Equal(curKey, nextKey)):
		if err := removeNext(); err != nil {
			return "", err
		}
		return fmt.Sprintf("the staged CA in %s is the current one already (%s), so nothing was promoted; removed "+
			"the staged files left from its promotion; if this broker promoted it, copy %s, %s and %s to every "+
			"other broker on this store, and restart each", dir, fingerprintOf(cur), issuer.CertFile, issuer.KeyFile,
			issuer.PreviousCertFile), nil
	case nextKey == nil:
		return "", fmt.Errorf("%s is in %s without %s: this broker trusts the staged CA but cannot promote it; run "+
			"rotate-issuer on the broker that staged it, which holds the key, then copy the files it names here",
			issuer.NextCertFile, dir, issuer.NextKeyFile)
	case nextCert == nil:
		return "", fmt.Errorf("%s is in %s without %s; restore it, or remove it on purpose", issuer.NextKeyFile, dir,
			issuer.NextCertFile)
	case prev != nil && !bytes.Equal(prev, cur) && !bytes.Equal(cur, nextCert):
		return "", fmt.Errorf("%s from an earlier rotation is still in %s, and a promotion would overwrite it while "+
			"certificates it issued may still be valid: remove it once certificate_lifetime has passed since that "+
			"promotion, restart each broker, and run rotate-issuer again", issuer.PreviousCertFile, dir)
	}
	// The staged pair is checked before anything is written: a promotion
	// overwrites the working key for good, so a staged certificate that does
	// not parse, is not a valid CA now, or does not belong to the staged key
	// (another broker's copied over this one's) is refused with every file as it was.
	if staged, _ := issuer.Load(issuer.Mem(map[string][]byte{issuer.CertFile: nextCert, issuer.KeyFile: nextKey}),
		now); staged.Unavailable != nil {
		return "", fmt.Errorf("the staged %s and %s in %s are not a usable pair (%v); nothing was changed: "+
			"restage with rotate-issuer on the broker that holds the key, after removing both staged files",
			issuer.NextCertFile, issuer.NextKeyFile, dir, staged.Unavailable)
	}
	if !bytes.Equal(cur, nextCert) {
		if err := writeOwnerOnly(join(issuer.PreviousCertFile), cur); err != nil {
			return "", err
		}
		if err := writeOwnerOnly(join(issuer.CertFile), nextCert); err != nil {
			return "", err
		}
	}
	if err := writeOwnerOnly(join(issuer.KeyFile), nextKey); err != nil {
		return "", err
	}
	if err := removeNext(); err != nil {
		return "", err
	}
	return fmt.Sprintf("promoted the staged CA in %s (%s): copy %s, %s and %s to every other broker on this store, "+
		"remove the %s staged there, and restart each; each then issues with it and still trusts the previous; after "+
		"certificate_lifetime, remove %s and restart again", dir, fingerprintOf(nextCert), issuer.CertFile,
		issuer.KeyFile, issuer.PreviousCertFile, issuer.NextCertFile, issuer.PreviousCertFile), nil
}

// issuerCmd runs `<proc> init-issuer|rotate-issuer [--config FILE]`
// (decision 43 ruling 14): it reads the config the process starts from and
// acts in its broker's state directory. It is run as the broker's user. It
// exits 0 having done it or found it done, 1 when it would not, and 2 on
// usage.
func issuerCmd(proc, op, defaultConfig string, load func(string) (config.Config, error), args []string,
	stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet(proc+" "+op, flag.ContinueOnError)
	flags.SetOutput(stderr)
	cfgPath := flags.String("config", defaultConfig, "path to "+filepath.Base(defaultConfig))
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintf(stderr, "usage: %s %s [--config FILE]\n", proc, op)
		return 2
	}
	cfg, err := load(*cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "%s %s: %v\n", proc, op, err)
		return 1
	}
	if cfg.Broker == nil || cfg.Broker.Identity == nil || cfg.Broker.Identity.Issuance == nil {
		fmt.Fprintf(stderr, "%s %s: %s configures no broker.identity.issuance; add `issuance: {}` under "+
			"broker.identity first\n", proc, op, *cfgPath)
		return 1
	}
	dir := brokerStateDir(cfg)
	var line string
	if op == "init-issuer" {
		_, line, err = initIssuer(dir, time.Now())
	} else {
		line, err = rotateIssuer(dir, time.Now())
	}
	if err != nil {
		fmt.Fprintf(stderr, "%s %s: %v\n", proc, op, err)
		return 1
	}
	fmt.Fprintf(stdout, "%s: %s\n", proc, line)
	return 0
}
