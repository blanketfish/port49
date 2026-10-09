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

// PinnedError is ErrPinned with the line that holds the pin: Name is the host
// field as written there, which differs from the device asked about when the
// two differ only in case. OpenSSH matches the host field without regard to
// case, so port49 does too: the two are one host.
type PinnedError struct {
	Name string
	Line int
}

func (e *PinnedError) Error() string {
	return fmt.Sprintf("%v (line %d, %q)", ErrPinned, e.Line, e.Name)
}

func (e *PinnedError) Is(target error) bool { return target == ErrPinned }

// Fingerprint is k's SHA-256 fingerprint as OpenSSH prints it: SHA256:base64.
func Fingerprint(k ssh.PublicKey) string { return ssh.FingerprintSHA256(k) }

// Entry is one pin: the host field as written, its line number (from 1), and
// its key.
type Entry struct {
	Name string
	Line int
	Key  ssh.PublicKey
}

// parsed is one line of the pins file: its text (newline kept), and, for a
// pin, the entry.
type parsed struct {
	text  string
	entry *Entry
}

// parse reads the pins file. port49 owns this file, and OpenSSH reads it
// differently from the way port49 does for anything but a plain
// "name key" line, so a line that is not a blank, a comment or exactly that is
// refused, naming the file and the line, and port49 neither guesses what
// OpenSSH would make of it nor rewrites around it.
func parse(path string, raw []byte) ([]parsed, error) {
	var lines []parsed
	for i, text := range strings.SplitAfter(string(raw), "\n") {
		if text == "" {
			continue
		}
		trimmed := strings.TrimSpace(text)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			lines = append(lines, parsed{text: text})
			continue
		}
		marker, hosts, key, _, _, err := ssh.ParseKnownHosts([]byte(text))
		var why string
		switch {
		case err != nil:
			why = "it does not parse (" + err.Error() + ")"
		case marker != "":
			why = "it carries the marker @" + marker
		case len(hosts) != 1:
			why = "it names several hosts"
		case !ValidName(hosts[0]):
			why = fmt.Sprintf("its host field %q is a pattern, a hash, a negation or a port form", hosts[0])
		}
		if why != "" {
			return nil, fmt.Errorf("%s: line %d: %s: port49 owns this file; OpenSSH would read this line, "+
				"so port49 will not guess. Remove it, or move it to ~/.ssh/known_hosts", path, i+1, why)
		}
		lines = append(lines, parsed{text: strings.TrimSuffix(text, "\n") + "\n",
			entry: &Entry{Name: hosts[0], Line: i + 1, Key: key}})
	}
	return lines, nil
}

// Entries is every pin whose host field is device, compared without regard to
// case as OpenSSH does. A missing file pins nothing; a line port49 does not
// fully understand refuses the file.
func Entries(path, device string) ([]Entry, error) {
	raw, err := userconfig.ReadPrivate(path, maxFile, what)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	lines, err := parse(path, raw)
	if err != nil {
		return nil, err
	}
	var found []Entry
	for _, l := range lines {
		if l.entry != nil && strings.EqualFold(l.entry.Name, device) {
			found = append(found, *l.entry)
		}
	}
	return found, nil
}

// Lookup is every key pinned for device (see Entries).
func Lookup(path, device string) ([]ssh.PublicKey, error) {
	found, err := Entries(path, device)
	var keys []ssh.PublicKey
	for _, e := range found {
		keys = append(keys, e.Key)
	}
	return keys, err
}

// Pin writes key as device's pinned key, under the name as given. A device
// with a pin already, one whose name differs only in case included, is a
// *PinnedError (ErrPinned) unless replace is set, which removes every key
// pinned for it first. Every other line, another device's or a comment the
// operator wrote, is kept as it was. A file holding a line port49 does not
// understand is refused and left alone.
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
	lines, err := parse(path, raw)
	if err != nil {
		return err
	}
	var kept []string
	for _, l := range lines {
		if l.entry != nil && strings.EqualFold(l.entry.Name, device) {
			if !replace {
				return &PinnedError{Name: l.entry.Name, Line: l.entry.Line}
			}
			continue
		}
		kept = append(kept, l.text)
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
