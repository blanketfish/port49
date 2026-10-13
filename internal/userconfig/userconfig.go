// Package userconfig is the operator's own files under ~/.port49 (spec §13
// decision 43 ruling 24, amending decision 42 ruling 6): config.yaml, over the
// system-wide /etc/port49/config.yaml the install ships, which gives `port49
// login` its broker, broker CA, certificate and key, or its identity provider
// (decision 43 ruling 19); the certificate the broker issued it
// (IssuedPaths); and the private-file reading and writing it shares with the
// pinned host keys (internal/hostkeys). Whoever can write these files chooses
// which broker the operator trusts and which device keys `port49 ssh`
// accepts, so a file, or a directory holding one, that anyone else can write
// is refused, never read. It is keyfile's rule for a private key, for writing
// rather than reading, and unlike internal/fence it holds on macOS too.
package userconfig

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"gopkg.in/yaml.v3"

	"github.com/rhwendt/port49/internal/hwkey"
)

// getuid is os.Getuid, swapped in tests: no second uid exists to own a file.
var getuid = os.Getuid

// Dir is ~/.port49, the operator's own port49 directory, as ~/.ssh is
// OpenSSH's (decision 43 ruling 24): config.yaml, and the certificates
// brokers issued (IssuedPaths). WritePrivate makes it 0700 when it is
// missing. It sits in the home directory, so its walk never meets a shared
// parent such as a group-writable ~/.config.
func Dir() string {
	if h, err := os.UserHomeDir(); err == nil {
		return filepath.Join(h, ".port49")
	}
	return ".port49"
}

// EnvConfig names a config file in place of ~/.port49/config.yaml; --config
// overrides it.
const EnvConfig = "PORT49_CONFIG"

// Path is the personal config file: $PORT49_CONFIG, else
// ~/.port49/config.yaml.
func Path() string {
	if p := os.Getenv(EnvConfig); p != "" {
		return p
	}
	return filepath.Join(Dir(), "config.yaml")
}

// SystemPath is the system-wide config file the install ships, under every
// user's own (LoadAll). Only the tests change it.
var SystemPath = "/etc/port49/config.yaml"

// SystemOwner is the uid that must own SystemPath: 0, root, as /etc is. Only
// the tests change it, standing their own uid in for root's, which no test
// can give a file.
var SystemOwner uint32

// LegacyDir is plan 9a's directory, $XDG_CONFIG_HOME/port49, else
// ~/.config/port49. The pinned host keys stay there until plan 9d takes
// them out of the user's flow; a config.yaml there is refused, naming the
// move (LoadAll).
func LegacyDir() string {
	if d := os.Getenv("XDG_CONFIG_HOME"); d != "" {
		return filepath.Join(d, "port49")
	}
	if h, err := os.UserHomeDir(); err == nil {
		return filepath.Join(h, ".config", "port49")
	}
	return filepath.Join(".config", "port49")
}

// LegacyPinsPath is plan 9a's pins file. Nothing reads it since plan 9d
// (decision 46 ruling 5); port49 ssh names it while it exists.
func LegacyPinsPath() string { return filepath.Join(LegacyDir(), "known_hosts") }

// IssuedPathsIn is where, under dir, `port49 login` keeps the certificate a
// broker issued it and its key (spec §13 decision 43 ruling 7):
// dir/issued/<host>_<port>.pem and .key, one pair per broker. A broker URL
// that is not https with a host, or whose host is not a plain name or
// address, is refused rather than made a file name.
func IssuedPathsIn(dir, broker string) (cert, key string, err error) {
	u, err := url.Parse(broker)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
		return "", "", fmt.Errorf("broker %q is not an https URL with a host", broker)
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	host := strings.ToLower(strings.ReplaceAll(u.Hostname(), ":", "-"))
	if strings.HasPrefix(host, ".") || strings.IndexFunc(host, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '-')
	}) >= 0 {
		return "", "", fmt.Errorf("broker %q: its host is not a plain name or address", broker)
	}
	base := filepath.Join(dir, "issued", host+"_"+port)
	return base + ".pem", base + ".key", nil
}

// IssuedTPMPathsIn is where, under dir, this machine keeps a TPM-held pair:
// tpmKey <host>_<port>.<machine>.tpmkey and tpmCert <host>_<port>.<machine>.pem
// beside IssuedPathsIn's pair, <machine> the first 8 hex digits of SHA-256 of
// /etc/machine-id (decision 45 ruling 7), so hosts sharing a home directory
// keep a pair each. The broker URL is judged as IssuedPathsIn judges it.
func IssuedTPMPathsIn(dir, broker string) (tpmCert, tpmKey string, err error) {
	cert, _, err := IssuedPathsIn(dir, broker)
	if err != nil {
		return "", "", err
	}
	machine, err := MachineID()
	if err != nil {
		return "", "", err
	}
	base := strings.TrimSuffix(cert, ".pem") + "." + machine
	return base + ".pem", base + ".tpmkey", nil
}

// IssuedTokenPathsIn is where, under dir, the certificate for a token-held
// issued key is kept (decision 45 ruling 7): <host>_<port>.<k>.pem, <k> the
// first 8 hex digits of SHA-256 of ref, the canonical issued_key reference.
// The name follows the key, so it needs no token to find, and a token host and
// a file host sharing a home never name the same certificate. The broker URL
// is judged as IssuedPathsIn judges it.
func IssuedTokenPathsIn(dir, broker, ref string) (cert string, err error) {
	cert, _, err = IssuedPathsIn(dir, broker)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(ref))
	return strings.TrimSuffix(cert, ".pem") + "." + hex.EncodeToString(sum[:])[:8] + ".pem", nil
}

// IssuedTokenPaths is IssuedTokenPathsIn ~/.port49 (Dir).
func IssuedTokenPaths(broker, ref string) (cert string, err error) {
	return IssuedTokenPathsIn(Dir(), broker, ref)
}

// IssuedTPMPaths is IssuedTPMPathsIn ~/.port49 (Dir).
func IssuedTPMPaths(broker string) (tpmCert, tpmKey string, err error) {
	return IssuedTPMPathsIn(Dir(), broker)
}

// machineIDFile is what MachineID names this machine from.
var machineIDFile = "/etc/machine-id"

// MachineID is this machine's 8-hex-digit name: the first 8 digits of the
// SHA-256 of /etc/machine-id as the file is, so `sha256sum /etc/machine-id`
// says it. A var so cmd/port49's tests set it.
var MachineID = func() (string, error) {
	raw, err := os.ReadFile(machineIDFile)
	if err != nil {
		return "", fmt.Errorf("this machine has no readable %s to name its TPM key by: %w", machineIDFile, err)
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return "", fmt.Errorf("%s is empty, so it cannot name this machine's TPM key", machineIDFile)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])[:8], nil
}

// CABundlePathIn is where, under dir, the agent keeps the CA bundle a broker
// sent it (spec §13 decision 43 ruling 25): dir/broker_ca/<host>_<port>.pem,
// one per broker, so no broker's bundle is trusted for another.
func CABundlePathIn(dir, broker string) (string, error) {
	cert, _, err := IssuedPathsIn(dir, broker)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "broker_ca", filepath.Base(cert)), nil
}

// CABundlePath is CABundlePathIn ~/.port49 (Dir).
func CABundlePath(broker string) (string, error) { return CABundlePathIn(Dir(), broker) }

// IssuedPaths is IssuedPathsIn ~/.port49 (Dir).
func IssuedPaths(broker string) (cert, key string, err error) { return IssuedPathsIn(Dir(), broker) }

// File is config.yaml. Every key is optional; `port49 login` takes each one
// its flags leave out. Paths are resolved by Load: relative to the file's
// directory, and ~/ the home directory.
type File struct {
	Broker   string `yaml:"broker"`
	BrokerCA string `yaml:"broker_ca"`
	Cert     string `yaml:"cert"`
	Key      string `yaml:"key"`
	// Method is how `port49 login` authenticates: x509, the default, or
	// oidc, a sign-in the broker issues a certificate for (decision 43
	// ruling 19).
	Method string `yaml:"method"`
	// OIDCIssuer names the provider to sign in at when the broker lists
	// several.
	OIDCIssuer string `yaml:"oidc_issuer"`
	// OIDCCA is the CA that issued the provider's TLS certificate; none is
	// the system's roots.
	OIDCCA string `yaml:"oidc_ca"`
	// OIDCRedirectPort is the loopback port a sign-in returns to; 0 picks a
	// free one.
	OIDCRedirectPort int `yaml:"oidc_redirect_port"`
	// BrokerCRL is whether the broker's certificate is checked against the
	// CRLs it names, before anything is sent to the broker: check, the
	// default, refuses a revoked one and says an unobtainable list; require
	// refuses that too; off checks nothing (plan 9c, ruling 9).
	BrokerCRL string `yaml:"broker_crl"`
	// TouchKey is the touch_key slot: a key reference on the same token as
	// Key, whose touch the agent may use (plan 9c, ruling 12).
	TouchKey string `yaml:"touch_key"`
	// IssuedKeyStore is where the key of a certificate the broker issues
	// lives: auto, file, tpm, secure_enclave or pkcs11. IssuedKey names the
	// reference for tpm and pkcs11.
	IssuedKeyStore string `yaml:"issued_key_store"`
	IssuedKey      string `yaml:"issued_key"`

	// BrokerCAPEM is the bytes of the file BrokerCA names, read once by Load
	// through the same ownership walk; nil under WithoutCA or with no CA named.
	BrokerCAPEM []byte `yaml:"-"`
	// OIDCCAPEM is OIDCCA's bytes, read as BrokerCAPEM is; nil under
	// WithoutOIDCCA or with none named.
	OIDCCAPEM []byte `yaml:"-"`
}

// Option changes what Load does.
type Option func(*loadOptions)

type loadOptions struct{ skipCA, skipOIDCCA bool }

// WithoutOIDCCA is WithoutCA for oidc_ca, which --oidc-ca overrides.
func WithoutOIDCCA() Option { return func(o *loadOptions) { o.skipOIDCCA = true } }

// WithoutCA is for a caller whose --broker-ca overrides the file's: a CA that
// is not going to be used is neither read nor checked, so a bad one does not
// block a login that never touches it.
func WithoutCA() Option { return func(o *loadOptions) { o.skipCA = true } }

// maxFile bounds config.yaml; maxCA bounds the broker CA.
const (
	maxFile = 64 << 10
	maxCA   = 1 << 20
)

// Load reads config.yaml at path. ok is false, with no error, when there is
// no file; a file that is there and cannot be used is an error, never a file
// ignored.
func Load(path string, opts ...Option) (File, bool, error) {
	f, ok, err := parse(path, "port49 config file", false)
	if err != nil || !ok {
		return File{}, false, err
	}
	if err := f.readCAs(options(opts), path, path); err != nil {
		return File{}, false, err
	}
	return f, true, nil
}

// LoadAll is Load over two files, key by key (decision 43 ruling 24): the
// system-wide file at SystemPath, then path's, every key of which that is
// set wins. path is the personal file, ~/.port49/config.yaml, or one that
// --config or $PORT49_CONFIG names (named), which must then be there. ok is
// false, with no error, when neither file is. The system file must be
// root's: it names the broker for every user on the host. Each file's
// relative paths are its own directory's, and each CA is read once, from
// the file whose key won.
func LoadAll(path string, named bool, opts ...Option) (File, bool, error) {
	sys, sysOK, err := parse(SystemPath, "system port49 config file", true)
	if err != nil {
		return File{}, false, err
	}
	f, ok, err := parse(path, "port49 config file", false)
	switch {
	case err != nil:
		return File{}, false, err
	case !ok && named:
		return File{}, false, fmt.Errorf("%s: no such file", path)
	case !ok:
		if err := noLegacy(path); err != nil {
			return File{}, false, err
		}
		if !sysOK {
			return File{}, false, nil
		}
	}
	brokerFrom, oidcFrom := path, path
	if f.BrokerCA == "" {
		brokerFrom = SystemPath
	}
	if f.OIDCCA == "" {
		oidcFrom = SystemPath
	}
	f = overlay(sys, f)
	if err := f.readCAs(options(opts), brokerFrom, oidcFrom); err != nil {
		return File{}, false, err
	}
	return f, true, nil
}

// overlay is base with every key over sets in its place.
func overlay(base, over File) File {
	base.Broker = cmp.Or(over.Broker, base.Broker)
	base.BrokerCA = cmp.Or(over.BrokerCA, base.BrokerCA)
	base.Cert = cmp.Or(over.Cert, base.Cert)
	base.Key = cmp.Or(over.Key, base.Key)
	base.Method = cmp.Or(over.Method, base.Method)
	base.OIDCIssuer = cmp.Or(over.OIDCIssuer, base.OIDCIssuer)
	base.OIDCCA = cmp.Or(over.OIDCCA, base.OIDCCA)
	base.OIDCRedirectPort = cmp.Or(over.OIDCRedirectPort, base.OIDCRedirectPort)
	base.BrokerCRL = cmp.Or(over.BrokerCRL, base.BrokerCRL)
	base.TouchKey = cmp.Or(over.TouchKey, base.TouchKey)
	base.IssuedKeyStore = cmp.Or(over.IssuedKeyStore, base.IssuedKeyStore)
	base.IssuedKey = cmp.Or(over.IssuedKey, base.IssuedKey)
	return base
}

// noLegacy refuses a config.yaml at plan 9a's place when path, the default,
// holds none, and names the move: unread, it would leave the operator logged
// in to whatever the system file names, or to nothing, with no word why.
func noLegacy(path string) error {
	old := filepath.Join(LegacyDir(), "config.yaml")
	if _, err := os.Lstat(old); err != nil {
		return nil
	}
	// The legacy file is never read (ruling 24), so the clause is fixed: a
	// certificate login moved under a system file that says method: oidc
	// would sign in instead, its cert and key unused.
	return fmt.Errorf("%s is where plan 9a kept port49's config file; port49 reads %s now: "+
		"mkdir -m 700 -p %s && mv %s %s (if it holds a certificate login, add `method: x509`)",
		old, path, filepath.Dir(path), old, path)
}

// options is what opts make of Load's defaults.
func options(opts []Option) loadOptions {
	var o loadOptions
	for _, opt := range opts {
		opt(&o)
	}
	return o
}

// parse reads and checks one config file, resolving its paths, and reads no
// CA. With rootOnly the file must be root's (SystemOwner).
func parse(path, what string, rootOnly bool) (f File, ok bool, err error) {
	raw, err := readPrivate(path, maxFile, what, rootOnly)
	if errors.Is(err, fs.ErrNotExist) {
		return File{}, false, nil
	}
	if err != nil {
		return File{}, false, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil && !errors.Is(err, io.EOF) {
		return File{}, false, fmt.Errorf("%s: %w", path, err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return File{}, false, fmt.Errorf("%s holds a second YAML document; port49 reads one", path)
	}
	base := filepath.Dir(path)
	switch f.Method {
	case "", "x509", "oidc":
	default:
		return File{}, false, fmt.Errorf("%s: method %q: port49 logs in by x509 or oidc", path, f.Method)
	}
	switch f.BrokerCRL {
	case "", "check", "require", "off":
	default:
		return File{}, false, fmt.Errorf("%s: broker_crl %q: it is check, require or off", path, f.BrokerCRL)
	}
	switch f.IssuedKeyStore {
	case "", "auto", "file", "tpm", "secure_enclave", "pkcs11":
	default:
		return File{}, false, fmt.Errorf("%s: issued_key_store %q: it is auto, file, tpm, secure_enclave or pkcs11",
			path, f.IssuedKeyStore)
	}
	for name, ref := range map[string]string{"touch_key": f.TouchKey, "issued_key": f.IssuedKey} {
		if ref != "" && !hwkey.IsRef(ref) {
			return File{}, false, fmt.Errorf("%s: %s %q is not a key reference: it starts with pkcs11:, tpm: or secure-enclave:",
				path, name, ref)
		}
	}
	if f.OIDCRedirectPort < 0 || f.OIDCRedirectPort > 65535 {
		return File{}, false, fmt.Errorf("%s: oidc_redirect_port %d is not a port", path, f.OIDCRedirectPort)
	}
	// A key reference is not a path: it is carried as written, never joined to
	// the file's directory.
	for _, p := range []*string{&f.BrokerCA, &f.Cert, &f.Key, &f.OIDCCA} {
		if hwkey.IsRef(*p) {
			continue
		}
		if *p, err = resolve(base, *p); err != nil {
			return File{}, false, fmt.Errorf("%s: %w", path, err)
		}
	}
	return f, true, nil
}

// readCAs reads the CAs f names; brokerFrom and oidcFrom are the files that
// named them, for a refusal.
func (f *File) readCAs(o loadOptions, brokerFrom, oidcFrom string) error {
	var err error
	// The CA a config file names pins the broker as the file does, so it is
	// held to the same line, ReadPrivate's: owned by you or root, nobody
	// else can write it or the directories above it. It is read here, once,
	// and its bytes carried, so nothing can be swapped in between a check and
	// a read.
	if f.BrokerCA != "" && !o.skipCA {
		if f.BrokerCAPEM, err = ReadPrivate(f.BrokerCA, maxCA, "broker CA"); err != nil {
			return fmt.Errorf("broker_ca in %s: %w", brokerFrom, err)
		}
	}
	// The provider's CA decides whose sign-in port49 trusts, as the broker
	// CA decides the broker: held to the same line, read once.
	if f.OIDCCA != "" && !o.skipOIDCCA {
		if f.OIDCCAPEM, err = ReadPrivate(f.OIDCCA, maxCA, "identity provider CA"); err != nil {
			return fmt.Errorf("oidc_ca in %s: %w", oidcFrom, err)
		}
	}
	return nil
}

// resolve is p as Load reads it: ~ and ~/ from the home directory, a relative
// path from base.
func resolve(base, p string) (string, error) {
	switch {
	case p == "":
		return "", nil
	case strings.HasPrefix(p, "~") && p != "~" && !strings.HasPrefix(p, "~/"):
		return "", fmt.Errorf("%q: port49 expands ~ and ~/ to your home directory, not ~user; write the path out", p)
	case p == "~" || strings.HasPrefix(p, "~/"):
		h, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(h, strings.TrimPrefix(p, "~")), nil
	case filepath.IsAbs(p):
		return p, nil
	}
	return filepath.Join(base, p), nil
}

// ReadPrivate reads path, at most max bytes, refusing it unless it is a
// regular file of its own (a symlink is refused, not followed) that this
// user or root owns and nobody else can write, and every directory above it
// is held to resolveOwned. A missing file is an error errors.Is(err,
// fs.ErrNotExist) reports. what names the file in a refusal.
//
// path is walked as the kernel resolves it, one component at a time from the
// path as written (resolveOwned), and the file is opened by the resolved path,
// so the file read is the one whose directories were judged.
func ReadPrivate(path string, max int64, what string) ([]byte, error) {
	return readPrivate(path, max, what, false)
}

// CheckOwned refuses path as a PKCS#11 module unless the file, every
// symbolic link on the way to it and every directory above each is held to
// the rules ReadPrivate applies: owned by this user or root, and not writable
// by group or others. A module is code the agent runs, so whoever could
// replace it could run theirs. The base name may be a chain of links (a
// libykcs11.so usually is): each link must be owned by root or the user, and
// the directory its target is in is walked again. The final component must
// be a regular file. Nothing is opened.
func CheckOwned(path string) error {
	const what = "PKCS#11 module"
	links := 0
	for {
		dir, base, err := splitPath(path)
		if err != nil {
			return fmt.Errorf("%s: %w; the %s must be a file", path, err, what)
		}
		resolved, err := resolveOwned(dir, false, what)
		if err != nil {
			return err
		}
		file := joinPath(resolved, base)
		fi, err := os.Lstat(file)
		if err != nil {
			return dirError(resolved, err, what)
		}
		if fi.Mode()&fs.ModeSymlink == 0 {
			if !fi.Mode().IsRegular() {
				return fmt.Errorf("%s is not a regular file; the %s must be one", file, what)
			}
			return ownedAlone(file, fi, what)
		}
		if err := ownedBy(file, fi, what); err != nil {
			return err
		}
		if links++; links > maxLinks {
			return fmt.Errorf("%s: too many symbolic links (over %d) on the way to the %s; a link loop is refused",
				path, maxLinks, what)
		}
		target, err := os.Readlink(file)
		if err != nil {
			return err
		}
		if !strings.HasPrefix(target, "/") {
			target = resolved + "/" + target
		}
		path = target
	}
}

// readPrivate is ReadPrivate; with rootOnly the file must be root's
// (SystemOwner), not this user's.
func readPrivate(path string, max int64, what string, rootOnly bool) ([]byte, error) {
	dir, base, err := splitPath(path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w; the %s must be a file", path, err, what)
	}
	resolved, err := resolveOwned(dir, false, what)
	if err != nil {
		// Nothing is read from a path refused, and nothing is there to read
		// when the kernel finds no file: that is no file, as it always was,
		// not a complaint about a directory that holds nothing.
		if _, serr := os.Lstat(path); errors.Is(serr, fs.ErrNotExist) {
			return nil, serr
		}
		return nil, err
	}
	file := joinPath(resolved, base)
	li, err := os.Lstat(file)
	if errors.Is(err, fs.ErrPermission) {
		return nil, dirError(resolved, err, what)
	}
	if err != nil {
		return nil, err
	}
	if li.Mode()&fs.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s is a symbolic link; the %s is read only as a file of its own", path, what)
	}
	if !li.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file; the %s must be one", path, what)
	}
	if err := ownedAlone(file, li, what); err != nil {
		return nil, err
	}
	if st, ok := li.Sys().(*syscall.Stat_t); rootOnly && (!ok || st.Uid != SystemOwner) {
		return nil, fmt.Errorf("%s is not owned by root; the %s names the broker for every user on this host, "+
			"so it is root's alone: chown root %s", path, what, path)
	}
	f, err := os.OpenFile(file, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, syscall.ELOOP) {
		return nil, fmt.Errorf("%s is a symbolic link; the %s is read only as a file of its own", path, what)
	}
	if errors.Is(err, fs.ErrPermission) {
		if st, ok := li.Sys().(*syscall.Stat_t); ok && int(st.Uid) != getuid() {
			// Not this user's to chmod: say the mode it needs and whose to set.
			return nil, fmt.Errorf("%s is %04o and owned by %s; the %s must be readable by you, so %s (%w)",
				file, li.Mode().Perm(), ownerName(st.Uid), what, fixFor(file, "0644 (and its directory 0755)"), err)
		}
		return nil, fmt.Errorf("cannot open %s: permission denied; the %s must be readable by you: chmod u+r %s (%w)",
			file, what, file, err)
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	// The file opened is the file judged, not one swapped in between.
	if !os.SameFile(li, fi) {
		return nil, fmt.Errorf("%s changed while port49 was checking it; run the command again", file)
	}
	raw, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > max {
		return nil, fmt.Errorf("%s is over %d bytes; a %s is never that large", path, max, what)
	}
	return raw, nil
}

// ownedAlone refuses what fi describes unless this user or root owns it and
// neither its group nor others can write it. A directory with the sticky bit
// set, as /tmp has, is the exception: there nobody can rename or replace an
// entry they do not own, which is all a directory above the file is checked
// for. Root owning a file is OpenSSH's StrictModes rule too: root can write
// anything, so trusting it trusts nobody new.
func ownedAlone(path string, fi fs.FileInfo, what string) error {
	if err := ownedBy(path, fi, what); err != nil {
		return err
	}
	if fi.Mode().Perm()&0o022 != 0 && fi.IsDir() && fi.Mode()&fs.ModeSticky == 0 {
		// A directory may be shared, as a group-writable ~/.config is, so
		// the refusal says what it needs, never a chmod that would change it
		// for everyone else.
		return fmt.Errorf("%s is writable by others (mode %v); whoever can write the %s chooses what port49 "+
			"trusts, so port49 needs it writable by its owner alone (mode 0755 or 0700)", path, fi.Mode().Perm(), what)
	}
	if fi.Mode().Perm()&0o022 != 0 && !fi.IsDir() {
		return fmt.Errorf("%s is writable by others (mode %v); whoever can write the %s chooses what port49 "+
			"trusts: chmod go-w %s", path, fi.Mode().Perm(), what, path)
	}
	return nil
}

// ownedBy refuses what fi describes unless this user or root owns it.
func ownedBy(path string, fi fs.FileInfo, what string) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || (int(st.Uid) != getuid() && st.Uid != 0) {
		var owner any = "an unknown user"
		if ok {
			owner = st.Uid
		}
		return fmt.Errorf("%s is owned by uid %v, not you (uid %d); whoever owns the %s chooses what port49 "+
			"trusts, so it is refused: move it aside and recreate it as yourself", path, owner, getuid(), what)
	}
	return nil
}

// maxLinks is how many symbolic links resolveOwned follows before it calls a
// path a loop; Linux's own limit is 40.
const maxLinks = 40

// splitPath is path's directory part, as written, and its last element. It
// does not Clean: Dir would fold `link/..` away lexically, and the kernel does
// not.
func splitPath(path string) (dir, base string, err error) {
	i := strings.LastIndexByte(path, '/')
	switch {
	case i < 0:
		dir, base = ".", path
	case i == 0:
		dir, base = "/", path[1:]
	default:
		dir, base = path[:i], path[i+1:]
	}
	if base == "" || base == "." || base == ".." {
		return "", "", errors.New("names a directory")
	}
	return dir, base, nil
}

// joinPath is dir, a resolved absolute path, and one name.
func joinPath(dir, name string) string {
	if dir == "/" {
		return "/" + name
	}
	return dir + "/" + name
}

// resolveOwned resolves dir as the kernel does, from "/" one component at a
// time, and judges every component on the way (OpenSSH's StrictModes walk,
// with the check in the loop). A directory must be owned by you or root and
// not writable by its group or others: one that someone else can write lets
// them rename the directory below it and put their own in its place. A
// symbolic link must be owned by you or root, and the directory holding it has
// passed already, so nobody else can repoint it; its target is spliced in
// front of the rest of the path and walked the same way, so a link met inside
// a target is judged like the first. `..` goes to the parent of the resolved
// prefix, which holds no links, never to the lexical one. The returned path
// holds no links.
//
// dir is taken as written, never cleaned; a relative one is joined to the
// working directory as a string. The directories above the home directory are
// not judged: root's, and the one a login got to the home through. With create
// set, a missing directory is made 0700 and judged like the rest, which only
// happens below a prefix that has passed, so a refused path creates nothing.
func resolveOwned(dir string, create bool, what string) (string, error) {
	if !strings.HasPrefix(dir, "/") {
		cwd, err := os.Getwd()
		if err != nil {
			return "", err
		}
		dir = cwd + "/" + dir
	}
	home, _ := os.UserHomeDir()
	if h, err := filepath.EvalSymlinks(home); err == nil && home != "" {
		home = h
	}
	holder := "directory holding the " + what
	prefix, links := "/", 0
	pending := strings.Split(dir, "/")
	for len(pending) > 0 {
		c := pending[0]
		pending = pending[1:]
		switch c {
		case "", ".":
			continue
		case "..":
			prefix = filepath.Dir(prefix)
			continue
		}
		next := joinPath(prefix, c)
		fi, err := os.Lstat(next)
		if create && errors.Is(err, fs.ErrNotExist) {
			if err = os.Mkdir(next, 0o700); err == nil || errors.Is(err, fs.ErrExist) {
				fi, err = os.Lstat(next)
			}
		}
		if err != nil {
			return "", dirError(prefix, err, what)
		}
		switch {
		case fi.Mode()&fs.ModeSymlink != 0:
			// A link's own mode is never the point; who owns it is.
			if err := ownedBy(next, fi, holder); err != nil {
				return "", err
			}
			if links++; links > maxLinks {
				return "", fmt.Errorf("%s: too many symbolic links (over %d) on the way to the %s; a link loop is refused",
					dir, maxLinks, what)
			}
			target, err := os.Readlink(next)
			if err != nil {
				return "", err
			}
			if strings.HasPrefix(target, "/") {
				prefix = "/"
			}
			pending = append(strings.Split(target, "/"), pending...)
		case !fi.IsDir():
			return "", fmt.Errorf("%s is not a directory; the directory for the %s must be one", next, what)
		default:
			if home != "" && home != next && strings.HasPrefix(home, next+"/") {
				prefix = next // above the home directory: not judged
				continue
			}
			if err := ownedAlone(next, fi, holder); err != nil {
				return "", err
			}
			prefix = next
		}
	}
	return prefix, nil
}

// fixFor is who sets the mode on a file this user does not own: whoever
// installed it for a path outside the user's home, the user, with sudo, for
// one inside it (a root-owned ~/.port49 is no installer's).
func fixFor(path, mode string) string {
	if h, err := os.UserHomeDir(); err == nil && h != "" && strings.HasPrefix(path, h+"/") {
		return "make it yours (sudo chown " + getenvUser() + " " + path + ") or " + mode
	}
	return "whoever installed it must make it " + mode
}

// getenvUser is $USER for the advice, else a placeholder.
func getenvUser() string {
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	return "YOU"
}

// ownerName is root for uid 0, else the uid.
func ownerName(uid uint32) string {
	if uid == 0 {
		return "root"
	}
	return fmt.Sprintf("uid %d", uid)
}

// dirError says which directory port49 could not look inside, and for a
// refused one what to run. d is the directory that was being searched, not
// the entry below it that failed.
func dirError(d string, err error, what string) error {
	if errors.Is(err, fs.ErrPermission) {
		if fi, serr := os.Lstat(d); serr == nil {
			if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != getuid() {
				return fmt.Errorf("%s is %04o and owned by %s; port49 must look inside it to check who can write the %s, "+
					"so %s (%w)", d, fi.Mode().Perm(), ownerName(st.Uid), what, fixFor(d, "0755"), err)
			}
		}
		return fmt.Errorf("%s: permission denied; port49 must look inside it to check who can write the %s: "+
			"chmod u+rx %s (%w)", d, what, d, err)
	}
	return err
}

// PrivateDir resolves dir as WritePrivate does (resolveOwned): a missing
// directory is made 0700 under a prefix that has passed, and the resolved path,
// holding no links, is returned. It is for a caller that keeps a file beside
// the one WritePrivate writes, such as a lock, and must not make it before the
// directory is judged.
func PrivateDir(dir, what string) (string, error) { return resolveOwned(dir, true, what) }

// WritePrivate replaces path with data at mode 0600, through a temporary
// file in its directory renamed over it, so a reader never sees half a file.
// Missing directories are made 0700. The directory is walked as ReadPrivate
// walks it (resolveOwned), top down, and a directory is made only under a
// prefix that has passed, so a path that would be refused creates nothing.
func WritePrivate(path string, data []byte, what string) error {
	return WritePrivateAll(PrivateFile{Path: path, Data: data, What: what})
}

// PrivateFile is one file for WritePrivateAll.
type PrivateFile struct {
	Path string
	Data []byte
	What string
}

// WritePrivateAll is WritePrivate for files that only make sense together,
// such as a key and its certificate: every file is written to a temporary
// beside its path first, and only when all of them are there are they renamed
// into place, in the order given. A failure before the first rename leaves
// every path as it was; the one that remains is a rename failing after an
// earlier one, which the last file of the order is the least likely to be.
func WritePrivateAll(files ...PrivateFile) error {
	type staged struct{ tmp, path, dir string }
	var all []staged
	defer func() {
		for _, s := range all {
			os.Remove(s.tmp) // after the rename there is nothing at tmp
		}
	}()
	for _, f := range files {
		dirPart, base, err := splitPath(f.Path)
		if err != nil {
			return fmt.Errorf("%s: %w; the %s must be a file", f.Path, err, f.What)
		}
		dir, err := resolveOwned(dirPart, true, f.What)
		if err != nil {
			return err
		}
		tmp, err := os.CreateTemp(dir, "."+base+".*")
		if err != nil {
			return err
		}
		all = append(all, staged{tmp.Name(), joinPath(dir, base), dir})
		if err := tmp.Chmod(0o600); err != nil {
			tmp.Close()
			return err
		}
		if _, err := tmp.Write(f.Data); err != nil {
			tmp.Close()
			return err
		}
		if err := tmp.Sync(); err != nil {
			tmp.Close()
			return err
		}
		if err := tmp.Close(); err != nil {
			return err
		}
	}
	for _, s := range all {
		if err := os.Rename(s.tmp, s.path); err != nil {
			return err
		}
		if d, err := os.Open(s.dir); err == nil {
			_ = d.Sync()
			d.Close()
		}
	}
	return nil
}
