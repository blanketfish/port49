//go:build lab

package lab

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// labScanTimeout bounds a scan: the connect and the key exchange.
var labScanTimeout = 15 * time.Second

// errLabScanned ends the handshake once the key is read.
var errLabScanned = errors.New("hostkeys: the key is read; the connection goes no further")

// labFingerprint is k's SHA256 fingerprint, as ssh-keygen -lf prints it.
func labFingerprint(k ssh.PublicKey) string { return ssh.FingerprintSHA256(k) }

// labScan connects to addr (host:port), reads the host key the server presents
// in the key exchange, and closes the connection before authentication: no
// username is offered and no credential is sent. Every algorithm x/crypto/ssh
// knows is offered, the insecure ones included, except certificates and DSA.
// Moved from internal/hostkeys by plan 9d: the scan is L53's instrument now,
// not a product path.
func labScan(ctx context.Context, addr string) (ssh.PublicKey, error) {
	sup, weak := ssh.SupportedAlgorithms(), ssh.InsecureAlgorithms()
	hostKeys := slices.DeleteFunc(append(sup.HostKeys, weak.HostKeys...), func(a string) bool {
		return strings.Contains(a, "-cert-v01@") || a == ssh.InsecureKeyAlgoDSA
	})
	var got ssh.PublicKey
	cfg := &ssh.ClientConfig{
		User: "port49-scan",
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			got = key
			return errLabScanned
		},
		HostKeyAlgorithms: hostKeys,
		Config: ssh.Config{
			KeyExchanges: append(sup.KeyExchanges, weak.KeyExchanges...),
			Ciphers:      append(sup.Ciphers, weak.Ciphers...),
			MACs:         append(sup.MACs, weak.MACs...),
		},
		Timeout: labScanTimeout,
	}
	d := net.Dialer{Timeout: labScanTimeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(labScanTimeout))
	_, _, _, err = ssh.NewClientConn(conn, addr, cfg)
	if got != nil {
		return got, nil
	}
	return nil, fmt.Errorf("%s presented no host key: %w", addr, err)
}
