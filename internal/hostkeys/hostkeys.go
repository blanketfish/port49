// Package hostkeys pins the SSH host key each device presents (design §17;
// spec §13 decision 42, rulings 7–9). The pins live in an OpenSSH known_hosts
// file of port49's own, $XDG_CONFIG_HOME/port49/known_hosts, one line per
// key, whose host field is the device's inventory name. `port49 ssh` hands it
// to ssh with the device's name as HostKeyAlias, so a key is checked against
// the device it was pinned for, never against whatever address inventory
// gives today. The file is held to userconfig's rule: whoever can write it
// chooses which keys port49 accepts.
package hostkeys

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/rhwendt/port49/internal/userconfig"
)

// what names the file in a refusal.
const what = "pinned host keys file"

// maxFile bounds the file: a line a key, a fleet of them.
const maxFile = 4 << 20

// Path is the pinned host keys file's default path.
func Path() string { return filepath.Join(userconfig.Dir(), "known_hosts") }

var validName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$`)

// ValidName reports whether device can be a known_hosts host field and an
// ssh destination as written (decision 42 ruling 8): letters, digits, '.',
// '_' and '-', starting with a letter or a digit, 253 at most. known_hosts
// reads '*', '?', '!', ',' and '[' as patterns, and a leading '@' or '|' as
// a marker or a hash, so a name holding one could pin a key for other
// devices.
func ValidName(device string) bool { return validName.MatchString(device) }

// ErrPinned is a device that already has a pinned key.
var ErrPinned = errors.New("hostkeys: a key is already pinned for this device")

// Fingerprint is k's SHA-256 fingerprint as OpenSSH prints it: SHA256:base64.
func Fingerprint(k ssh.PublicKey) string { return ssh.FingerprintSHA256(k) }

// Lookup is every key pinned for device: lines with no marker whose host
// field is device and nothing else. A missing file pins nothing.
func Lookup(path, device string) ([]ssh.PublicKey, error) {
	raw, err := userconfig.ReadPrivate(path, maxFile, what)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var keys []ssh.PublicKey
	for rest := raw; len(rest) > 0; {
		marker, hosts, key, _, next, err := ssh.ParseKnownHosts(rest)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if marker == "" && slices.Equal(hosts, []string{device}) {
			keys = append(keys, key)
		}
		rest = next
	}
	return keys, nil
}

// Pin writes key as device's pinned key. A device with a pin already is
// ErrPinned unless replace is set, which removes every key pinned for it
// first. Every other line, another device's or one the operator wrote, is
// kept as it was.
func Pin(path, device string, key ssh.PublicKey, replace bool) error {
	if !ValidName(device) {
		return fmt.Errorf("hostkeys: %q is not a name port49 pins (decision 42 ruling 8)", device)
	}
	unlock, err := lock(path)
	if err != nil {
		return err
	}
	defer unlock()
	raw, err := userconfig.ReadPrivate(path, maxFile, what)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	var kept []string
	pinned := false
	for _, line := range strings.SplitAfter(string(raw), "\n") {
		if line == "" {
			continue
		}
		marker, hosts, _, _, _, perr := ssh.ParseKnownHosts([]byte(line))
		if perr == nil && marker == "" && slices.Equal(hosts, []string{device}) {
			pinned = true
			if replace {
				continue
			}
		}
		kept = append(kept, strings.TrimSuffix(line, "\n")+"\n")
	}
	if pinned && !replace {
		return ErrPinned
	}
	kept = append(kept, device+" "+string(bytes.TrimSpace(ssh.MarshalAuthorizedKey(key)))+"\n")
	return userconfig.WritePrivate(path, []byte(strings.Join(kept, "")), what)
}

// lock takes an exclusive flock on a lock file made 0600 beside the pins file
// at path, so two trust runs never lose a pin between one's read and the
// other's write. The directory is resolved and judged first, through
// userconfig (making it 0700 if it is missing), and the lock file is made
// only inside the directory that passed: a refused directory gets no lock
// file. The returned func lets the lock go.
func lock(path string) (func(), error) {
	dir := filepath.Dir(path)
	resolved, err := userconfig.PrivateDir(dir, what)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(resolved, filepath.Base(path)+".lock"),
		os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}

// scanTimeout bounds a scan: the connect and the key exchange.
var scanTimeout = 15 * time.Second

// errScanned ends the handshake once the key is read.
var errScanned = errors.New("hostkeys: the key is read; the connection goes no further")

// Scan connects to addr (host:port), reads the host key the server presents
// in the key exchange, and closes the connection before authentication: no
// username is offered and no credential is sent (decision 42 ruling 9; what
// a device does with that is §15 L53's). Every algorithm x/crypto/ssh knows is
// offered, the insecure ones included, since a scan only reads a public key
// the operator then verifies on the device's console. Two host-key
// algorithms are not: certificates, since port49 pins plain keys, and DSA,
// since OpenSSH 10 has none and `port49 ssh` could never accept a DSA pin. A
// DSA-only device is refused at the scan: no common host-key algorithm.
func Scan(ctx context.Context, addr string) (ssh.PublicKey, error) {
	sup, weak := ssh.SupportedAlgorithms(), ssh.InsecureAlgorithms()
	hostKeys := slices.DeleteFunc(append(sup.HostKeys, weak.HostKeys...), func(a string) bool {
		return strings.Contains(a, "-cert-v01@") || a == ssh.InsecureKeyAlgoDSA
	})
	var got ssh.PublicKey
	cfg := &ssh.ClientConfig{
		User: "port49-scan",
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			got = key
			return errScanned
		},
		HostKeyAlgorithms: hostKeys,
		Config: ssh.Config{
			KeyExchanges: append(sup.KeyExchanges, weak.KeyExchanges...),
			Ciphers:      append(sup.Ciphers, weak.Ciphers...),
			MACs:         append(sup.MACs, weak.MACs...),
		},
		Timeout: scanTimeout,
	}
	d := net.Dialer{Timeout: scanTimeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(scanTimeout))
	_, _, _, err = ssh.NewClientConn(conn, addr, cfg)
	if got != nil {
		return got, nil
	}
	return nil, fmt.Errorf("%s presented no host key: %w", addr, err)
}
