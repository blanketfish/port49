//go:build lab && unix

package lab

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"

	"github.com/blanketfish/port49/internal/directory"
)

// adcsBind is L44's EXTERNAL bind with the AD CS-issued broker certificate, as this process loads it
// (directory.LoadCredentials reads the pair through the fence): private copies, since w.dir is in the tree.
func (c *winCerts) adcsBind(t testing.TB) directory.Bind {
	cert, err := labPrivateSecret(t, c.brokerCertFile)
	if err != nil {
		panic(fmt.Sprintf("the AD CS bind certificate %s cannot be staged: %v", c.brokerCertFile, err))
	}
	key, err := labPrivateSecret(t, c.brokerKeyFile)
	if err != nil {
		panic(fmt.Sprintf("the AD CS bind key %s cannot be staged: %v", c.brokerKeyFile, err))
	}
	return directory.Bind{Mechanism: "external", TLSCertFile: cert, TLSKeyFile: key}
}

// The fence walks every directory above a trust, policy or secret file and refuses one that others can
// write (decision 53 ruling 11). A lab host's checkout lives under a group-writable ~/git, so nothing
// the daemons read may stay inside the repository: the harness hands them private copies, in a directory
// only this user can write, outside the tree.

// labPrivateRoot is that directory, made once: 0700, owned by this user, under the temp directory.
func labPrivateRoot() (string, error) {
	dir := filepath.Join(os.TempDir(), fmt.Sprintf("port49-lab-%d", os.Getuid()))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return "", err
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); !ok || int(st.Uid) != os.Getuid() || !fi.IsDir() {
		return "", fmt.Errorf("%s is not a directory this user owns: remove it", dir)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}

// labPrivateSub is name under labPrivateRoot.
func labPrivateSub(name string) (string, error) {
	r, err := labPrivateRoot()
	if err != nil {
		return "", err
	}
	return filepath.Join(r, name), nil
}

// labPrivateCopy copies src (read as the lab reads it) into the private directory and returns the copy's
// path. The copy's name carries a hash of src's path, so two files of one name stay apart.
func labPrivateCopy(src string) (string, error) {
	abs, err := filepath.Abs(src)
	if err != nil {
		return "", err
	}
	raw, err := os.ReadFile(abs)
	if err != nil {
		return "", err
	}
	r, err := labPrivateRoot()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(abs))
	dst := filepath.Join(r, hex.EncodeToString(sum[:4])+"-"+filepath.Base(abs))
	if err := os.WriteFile(dst, raw, 0o600); err != nil {
		return "", err
	}
	return dst, os.Chmod(dst, 0o600)
}

// labPrivateSecret is labPrivateCopy for key material (a private key, a keytab): the copy is removed when
// the test ends, so it does not outlive the run in the temp directory.
func labPrivateSecret(t testing.TB, src string) (string, error) {
	dst, err := labPrivateCopy(src)
	if err == nil {
		t.Cleanup(func() { os.Remove(dst) })
	}
	return dst, err
}

// stagedKeys are the config keys whose file a daemon reads through the fence, or as a secret.
var stagedKeys = regexp.MustCompile(`\b(tls_cert_file|tls_key_file|client_ca_file|ca_file|trust_anchor_file|` +
	`attestation_roots_file|tls_ca_bundle_file|issuer_file|cert_file|key_file|intermediates_file|keytab_file|` +
	`signing_key_file|webhook_tls_cert_file|webhook_tls_key_file):\s*([^\s,}\]#]+)`)

// underRoot reports whether p, relative to the repository root when it is not absolute, is inside it.
func underRoot(p string) (string, bool) {
	if !filepath.IsAbs(p) {
		p = filepath.Join(root, p)
	}
	rel, err := filepath.Rel(root, p)
	return p, err == nil && !strings.HasPrefix(rel, "..")
}

// stagePrivateFiles points every fenced file a config names inside the repository at a private copy.
func stagePrivateFiles(cfg string) (string, error) {
	var firstErr error
	out := stagedKeys.ReplaceAllStringFunc(cfg, func(m string) string {
		sub := stagedKeys.FindStringSubmatch(m)
		p, in := underRoot(sub[2])
		if !in {
			return m
		}
		dst, err := labPrivateCopy(p)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("%s: %s: %w", sub[1], sub[2], err)
			}
			return m
		}
		return sub[1] + ": " + dst
	})
	return out, firstErr
}

// privateCA is the directory CA as a daemon (or this process, dialling the directory) reads it: a private
// copy, since the fence refuses the repository's group-writable ancestors.
func (p *dirPKI) privateCA() string {
	if p.caFile == "" {
		return "" // no directory was brought up: nothing to stage
	}
	dst, err := labPrivateCopy(p.caFile)
	if err != nil {
		panic(fmt.Sprintf("the directory CA %s cannot be staged: %v", p.caFile, err))
	}
	return dst
}

// privateBroker is the broker's client certificate and key for the directory's EXTERNAL bind as this process
// loads them (directory.LoadCredentials reads the pair through the fence): private copies. It panics with the
// path, never the content.
func (p *dirPKI) privateBroker(t testing.TB) (cert, key string) {
	var err error
	if cert, err = labPrivateSecret(t, p.brokerCert); err != nil {
		panic(fmt.Sprintf("the directory bind certificate %s cannot be staged: %v", p.brokerCert, err))
	}
	if key, err = labPrivateSecret(t, p.brokerKey); err != nil {
		panic(fmt.Sprintf("the directory bind key %s cannot be staged: %v", p.brokerKey, err))
	}
	return cert, key
}
