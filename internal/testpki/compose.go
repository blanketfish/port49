package testpki

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
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
	var ms []member
	for _, m := range []string{"etcd-1", "etcd-2", "etcd-3"} {
		ms = append(ms, member{m, []string{m, "localhost"}, Loopback()})
	}
	return writeStack(dir, email, now, ms, nil)
}

// member is one etcd member's certificate: its file name and the names it answers to.
type member struct {
	name string
	dns  []string
	ips  []net.IP
}

// WriteKind is WriteCompose's layout for a cluster (plan 12b, Task 11): the same files, but the
// member certificates are etcd-0 .. etcd-<members-1>, each answering to the DNS names its pod has
// behind the headless Service etcd in namespace: etcd-<i>.etcd.<namespace>.svc and
// etcd-<i>.etcd.<namespace>.svc.cluster.local.
func WriteKind(dir, namespace string, members int, email string, now time.Time) error {
	if members < 1 {
		return fmt.Errorf("testpki: %d etcd members", members)
	}
	if namespace == "" || strings.Contains(namespace, ".") {
		return fmt.Errorf("testpki: %q is not a namespace name", namespace)
	}
	var ms []member
	for i := 0; i < members; i++ {
		n := fmt.Sprintf("etcd-%d", i)
		host := n + ".etcd." + namespace + ".svc"
		ms = append(ms, member{n, []string{host, host + ".cluster.local"}, nil})
	}
	// The broker's Service is <release>-broker in this namespace: any release name answers.
	return writeStack(dir, email, now, ms, []string{"*." + namespace + ".svc", "*." + namespace + ".svc.cluster.local"})
}

func writeStack(dir, email string, now time.Time, members []member, brokerDNS []string) error {
	for _, d := range []string{dir, filepath.Join(dir, "etcd"), filepath.Join(dir, "keys"), filepath.Join(dir, "secrets")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
	}
	if err := writeLab(filepath.Join(dir, "broker"), email, []string{ComposeOperator, ComposeBob}, brokerDNS, nil, now); err != nil {
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
	for _, m := range members {
		if err := issue(m.name, Leaf{CommonName: m.name, DNSNames: m.dns, IPs: m.ips,
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
