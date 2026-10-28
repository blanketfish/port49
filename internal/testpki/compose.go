package testpki

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// WriteCompose writes deploy/compose's local/ directory into dir (plan 7f,
// Task 1): etcd's CA, a certificate for each of its three members (no
// extended key usage, so it serves a peer's and a client's side), a client
// certificate per etcd user (root, port49d, port49-broker), the broker's
// lab PKI under broker/ for email and for ComposeOperator and ComposeBob,
// the device key as keys/tacacs_v1, and each component's sealing key as
// secrets/port49d-encryption.key and secrets/broker-encryption.key (files,
// never an env file: nothing secret may show in a container's environment).
// Valid 24h, as WriteLab's. Nothing it writes protects anything real: a trial and the
// tests use it, never a deployment.
func WriteCompose(dir, email string, now time.Time) error {
	for _, d := range []string{dir, filepath.Join(dir, "etcd"), filepath.Join(dir, "keys"), filepath.Join(dir, "secrets")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
	}
	if err := WriteLabWith(filepath.Join(dir, "broker"), email, []string{ComposeOperator, ComposeBob}, now); err != nil {
		return err
	}
	from, until := now.Add(-time.Hour), now.Add(24*time.Hour)
	ca, err := NewCA("port49 compose etcd CA", from, until)
	if err != nil {
		return err
	}
	files := map[string][]byte{"etcd/ca.pem": ca.PEM()}
	issue := func(name string, l Leaf) error {
		l.NotBefore, l.NotAfter = from, until
		c, err := ca.Issue(l)
		if err != nil {
			return err
		}
		cert, key, err := PEMs(c)
		if err != nil {
			return err
		}
		files["etcd/"+name+".pem"], files["etcd/"+name+"-key.pem"] = cert, key
		return nil
	}
	for _, m := range []string{"etcd-1", "etcd-2", "etcd-3"} {
		if err := issue(m, Leaf{CommonName: m, DNSNames: []string{m, "localhost"}, IPs: Loopback(),
			NoExtKeyUsage: true}); err != nil {
			return err
		}
	}
	for _, u := range []string{"root", "port49d", "port49-broker"} {
		if err := issue(u, Leaf{CommonName: u, Client: true}); err != nil {
			return err
		}
	}
	tacacs, err := secret(32)
	if err != nil {
		return err
	}
	enc, err := secret(32) // encryption keys are 32 bytes (config.key32)
	if err != nil {
		return err
	}
	files["keys/tacacs_v1"] = []byte(tacacs)
	files["secrets/port49d-encryption.key"], files["secrets/broker-encryption.key"] = []byte(enc), []byte(enc)
	for name, body := range files {
		if err := writeFresh(filepath.Join(dir, name), body); err != nil {
			return fmt.Errorf("testpki: %s: %w", name, err)
		}
	}
	return nil
}

// The two people besides the trial's own client whom WriteCompose cuts a
// client certificate for: the admin operator (policy: api revoke_others) and
// bob, whom the admin cells revoke and mint for (LabClientFiles names them).
const (
	ComposeOperator = "operator@example.com"
	ComposeBob      = "bob@example.com"
)

// RandomSecret is n random characters from [A-Za-z0-9], n bytes long: a
// fresh key for a test to write as a file.
func RandomSecret(n int) (string, error) { return secret(n) }

// secret is n random characters from [A-Za-z0-9], n bytes long.
func secret(n int) (string, error) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	out := make([]byte, n)
	for i := range out {
		v, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			return "", err
		}
		out[i] = alphabet[v.Int64()]
	}
	return string(out), nil
}
