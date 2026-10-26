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
// lab PKI under broker/ for email, and the two env files. Valid 24h, as
// WriteLab's. Nothing it writes protects anything real: a trial and the
// tests use it, never a deployment.
func WriteCompose(dir, email string, now time.Time) error {
	for _, d := range []string{dir, filepath.Join(dir, "etcd")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
	}
	if err := WriteLab(filepath.Join(dir, "broker"), email, now); err != nil {
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
	tacacs, err := secret(24)
	if err != nil {
		return err
	}
	enc, err := secret(32) // encryption keys are 32 bytes (config.key32)
	if err != nil {
		return err
	}
	files["port49d.env"] = []byte(fmt.Sprintf("PORT49_KEY_TACACS=%s\nPORT49_ENC_KEY=%s\n", tacacs, enc))
	files["port49-broker.env"] = []byte(fmt.Sprintf("PORT49_ENC_KEY=%s\n", enc))
	for name, body := range files {
		if err := writeFresh(filepath.Join(dir, name), body); err != nil {
			return fmt.Errorf("testpki: %s: %w", name, err)
		}
	}
	return nil
}

// secret is n random characters from [A-Za-z0-9]: safe in an env file
// unquoted, and n bytes long.
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
