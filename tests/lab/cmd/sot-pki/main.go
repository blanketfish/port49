// Command sot-pki writes the L32 and L33 lab PKI into -dir (plan 6c Tasks 14
// and 15): one CA (ca.pem); the TLS proxies' certificate (proxy.pem,
// proxy-key.pem: 127.0.0.1 and localhost, which the connector dials); and
// port49-inventory's webhook certificate (webhook.pem, webhook-key.pem:
// port49-inventory.lab, the name the stack's worker resolves to the host,
// and 127.0.0.1). Valid for a day; keys 0600. run.sh writes it into the
// run's private temporary directory and removes it on exit.
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/blanketfish/port49/internal/testpki"
)

func main() {
	dir := flag.String("dir", "", "the directory to write into")
	flag.Parse()
	if *dir == "" {
		fmt.Fprintln(os.Stderr, "sot-pki: -dir is required")
		os.Exit(2)
	}
	if err := write(*dir, time.Now()); err != nil {
		fmt.Fprintln(os.Stderr, "sot-pki:", err)
		os.Exit(1)
	}
}

func write(dir string, now time.Time) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	nb, na := now.Add(-time.Hour), now.Add(24*time.Hour)
	ca, err := testpki.NewCA("port49 lab sot CA", nb, na)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.pem"), ca.PEM(), 0o644); err != nil {
		return err
	}
	for _, l := range []struct {
		leaf      testpki.Leaf
		cert, key string
	}{
		{testpki.Leaf{CommonName: "l32 proxy", IPs: []net.IP{net.ParseIP("127.0.0.1")}, DNSNames: []string{"localhost"}},
			"proxy.pem", "proxy-key.pem"},
		{testpki.Leaf{CommonName: "port49-inventory webhook", IPs: []net.IP{net.ParseIP("127.0.0.1")},
			DNSNames: []string{"port49-inventory.lab"}}, "webhook.pem", "webhook-key.pem"},
	} {
		l.leaf.NotBefore, l.leaf.NotAfter = nb, na
		c, err := ca.Issue(l.leaf)
		if err != nil {
			return err
		}
		certPEM, keyPEM, err := testpki.PEMs(c)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, l.cert), certPEM, 0o644); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, l.key), keyPEM, 0o600); err != nil {
			return err
		}
	}
	return nil
}
