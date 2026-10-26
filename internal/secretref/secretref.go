// Package secretref names and reads the secrets port49 holds (spec §13
// decision 53): `secret_ref: env:NAME` or `file:/path`. A reference is a
// name, so a file that carries one — the policy file, which CI and every
// operator read — carries no secret. A reference that does not parse is
// refused without being printed: it is most likely the secret, pasted where
// its name goes. A secret store reaches port49 as a file its own agent
// renders: port49 holds no secret-store client (ruling 5).
package secretref

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/rhwendt/port49/internal/fence"
)

const (
	SchemeEnv  = "env"
	SchemeFile = "file"
)

// Ref is a parsed secret_ref. Name is the variable for env:, the absolute
// path for file:.
type Ref struct{ Scheme, Name string }

// String is the reference as port49 prints it.
func (r Ref) String() string { return r.Scheme + ":" + r.Name }

var (
	envName   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	errShape  = errors.New("is not a secret reference: write env:NAME or file:/absolute/path")
	maxRefLen = 1024
)

// Parse reads s. Its error never quotes s.
func Parse(s string) (Ref, error) {
	scheme, rest, ok := strings.Cut(s, ":")
	if !ok || len(s) > maxRefLen || strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return Ref{}, errShape
	}
	switch scheme {
	case SchemeEnv:
		if envName.MatchString(rest) {
			return Ref{Scheme: SchemeEnv, Name: rest}, nil
		}
	case SchemeFile:
		if filepath.IsAbs(rest) && filepath.Clean(rest) == rest {
			return Ref{Scheme: SchemeFile, Name: rest}, nil
		}
	}
	return Ref{}, errShape
}

// Secret is a resolved secret. It prints as <redacted> under every fmt verb
// and in JSON; Bytes is the one way to the value, at the one place that uses
// it. The value sits behind a pointer, so a Secret reached through an
// unexported field prints as an address (sot.Secret's rule).
type Secret struct{ p *[]byte }

func newSecret(b []byte) Secret { return Secret{&b} }

// Bytes is the value; nil for none.
func (s Secret) Bytes() []byte {
	if s.p == nil {
		return nil
	}
	return *s.p
}

func (Secret) Format(f fmt.State, _ rune)   { io.WriteString(f, "<redacted>") }
func (Secret) String() string               { return "<redacted>" }
func (Secret) GoString() string             { return "<redacted>" }
func (Secret) MarshalJSON() ([]byte, error) { return []byte(`"<redacted>"`), nil }

// maxSecret bounds a file: read: a shared key or a token is far smaller.
const maxSecret = 1 << 20

// Resolver reads references: env: from the environment, file: through the
// write fence (fence.ReadSecret).
type Resolver struct {
	lookupEnv func(string) (string, bool)
	readFile  func(path, within string, max int64) ([]byte, error)
}

// New is the process's resolver.
func New() *Resolver {
	return &Resolver{lookupEnv: os.LookupEnv, readFile: fence.ReadSecret}
}

// Resolve reads ref. A file: reference, and every link on its way, must stay
// inside within, or inside its own directory when within is "". An error
// names the reference and why, never a value.
func (r *Resolver) Resolve(ref Ref, within string) (Secret, error) {
	var raw []byte
	switch ref.Scheme {
	case SchemeEnv:
		v, ok := r.lookupEnv(ref.Name)
		if !ok {
			return Secret{}, fmt.Errorf("%s: the variable is not set", ref)
		}
		raw = []byte(v)
	case SchemeFile:
		if within == "" {
			within = filepath.Dir(ref.Name)
		}
		b, err := r.readFile(ref.Name, within, maxSecret)
		if err != nil {
			return Secret{}, fmt.Errorf("%s: %w", ref, err)
		}
		raw = trimOneNewline(b)
	default:
		return Secret{}, errShape
	}
	if len(raw) == 0 {
		return Secret{}, fmt.Errorf("%s: the secret is empty", ref)
	}
	return newSecret(raw), nil
}

// ResolveText parses text and resolves it; every error begins with at, the
// key that holds it, and quotes text only once it has parsed.
func (r *Resolver) ResolveText(at, text string) (Ref, Secret, error) {
	ref, err := Parse(text)
	if err != nil {
		return Ref{}, Secret{}, fmt.Errorf("%s %w", at, err)
	}
	s, err := r.Resolve(ref, "")
	if err != nil {
		return Ref{}, Secret{}, fmt.Errorf("%s %w", at, err)
	}
	return ref, s, nil
}

// Allowance is where a policy's key references may point (decision 53
// ruling 12): port49d.yaml's key_secret_refs. A policy writer must not
// choose which of the host's secrets becomes a TACACS+ key.
type Allowance struct {
	EnvPrefix string `yaml:"env_prefix"`
	FileDir   string `yaml:"file_dir"`
}

// DefaultAllowance is the allowance a port49d.yaml that names none gets.
var DefaultAllowance = Allowance{EnvPrefix: "PORT49_KEY_", FileDir: "/run/port49/keys"}

// WithDefaults fills what a is missing from DefaultAllowance.
func (a Allowance) WithDefaults() Allowance {
	if a.EnvPrefix == "" {
		a.EnvPrefix = DefaultAllowance.EnvPrefix
	}
	if a.FileDir == "" {
		a.FileDir = DefaultAllowance.FileDir
	}
	return a
}

// Check refuses an allowance too wide to bound anything: a prefix shorter
// than 4 characters or not a variable name's start, a directory not absolute
// and clean.
func (a Allowance) Check() error {
	if len(a.EnvPrefix) < 4 || !envName.MatchString(a.EnvPrefix) {
		return fmt.Errorf("env_prefix %q must be at least 4 characters of an environment variable name", a.EnvPrefix)
	}
	if !filepath.IsAbs(a.FileDir) || filepath.Clean(a.FileDir) != a.FileDir || a.FileDir == "/" {
		return fmt.Errorf("file_dir %q must be an absolute, clean path below /", a.FileDir)
	}
	return nil
}

// Allows reports whether ref is inside a: an env: variable longer than the
// prefix and starting with it, or a file: path below the directory. A link
// inside the directory is held to it at the read (fence.ReadSecret).
func (a Allowance) Allows(ref Ref) bool {
	switch ref.Scheme {
	case SchemeEnv:
		return len(ref.Name) > len(a.EnvPrefix) && strings.HasPrefix(ref.Name, a.EnvPrefix)
	case SchemeFile:
		return strings.HasPrefix(ref.Name, a.FileDir+"/")
	}
	return false
}

// String is the allowance as a refusal names it.
func (a Allowance) String() string {
	return fmt.Sprintf("env: variables starting %s, file: under %s", a.EnvPrefix, a.FileDir)
}

// trimOneNewline drops one trailing LF or CRLF (decision 53 ruling 1).
func trimOneNewline(b []byte) []byte {
	if bytes.HasSuffix(b, []byte("\r\n")) {
		return b[:len(b)-2]
	}
	return bytes.TrimSuffix(b, []byte("\n"))
}
