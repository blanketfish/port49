// Package inventory is port49-inventory (spec §10, "The inventory service"):
// its configuration, its sources, the syncer that bounds and publishes the
// signed bundle document, its state directory and mirror, and its mutual-TLS
// API; and the client port49d and the port49 tool read that API with.
package inventory

import (
	"bytes"
	"fmt"
	"io"
	"regexp"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/yamlfault"
)

// SourceConfig is one entry of sync: (spec §10, "Connectors and sync
// cadence"). The file source is this plan's; netbox and nautobot are plan
// 6c's.
type SourceConfig struct {
	Name, Type, Path string
	// Interval is how often this source is synced (spec §10), default the
	// top-level interval.
	Interval          time.Duration
	MaxRemovedPercent int
}

// Config is port49-inventory.yaml. Every path is read at start; nothing in
// it is a secret — the TLS and signing keys are files read through keyfile.
type Config struct {
	// Listen is the API, mutual TLS on every path; MetricsListen serves
	// /metrics, /healthz and /readyz in plain HTTP, and no fleet data.
	Listen, MetricsListen                 string
	TLSCertFile, TLSKeyFile, ClientCAFile string
	// Readers may read; Syncers may read and POST /v1/sync (design §17).
	Readers, Syncers           []string
	SigningKeyFile, PolicyFile string
	// VerifyKeyFiles are further public keys the service accepts for its own
	// state_dir and mirror: the old signing key's, through a rotation, so the
	// sequence and the bound survive it (pre-flight M6). Its own signing key's
	// public half is always accepted.
	VerifyKeyFiles      []string
	StateDir, MirrorDir string
	// SyncTimeout bounds one sync: a source that hangs cannot hold the
	// syncer, the schedule or a shutdown (pre-flight minor 10).
	Interval, SyncTimeout time.Duration
	// MaxRemovedPercent is the bound a source without its own takes, and a
	// source no longer configured is held to.
	MaxRemovedPercent int
	Sync              []SourceConfig
}

type safetyYAML struct {
	MaxRemovedPercent *int `yaml:"max_removed_percent"`
}

type fileConfig struct {
	Listen         string        `yaml:"listen"`
	MetricsListen  string        `yaml:"metrics_listen"`
	TLSCertFile    string        `yaml:"tls_cert_file"`
	TLSKeyFile     string        `yaml:"tls_key_file"`
	ClientCAFile   string        `yaml:"client_ca_file"`
	Readers        []string      `yaml:"readers"`
	Syncers        []string      `yaml:"syncers"`
	SigningKeyFile string        `yaml:"signing_key_file"`
	VerifyKeyFiles []string      `yaml:"verify_key_files"`
	SyncTimeout    time.Duration `yaml:"sync_timeout"`
	PolicyFile     string        `yaml:"policy_file"`
	StateDir       string        `yaml:"state_dir"`
	MirrorDir      string        `yaml:"mirror_dir"`
	Interval       time.Duration `yaml:"interval"`
	Safety         safetyYAML    `yaml:"safety"`
	Sync           []struct {
		Name     string        `yaml:"name"`
		Type     string        `yaml:"type"`
		Path     string        `yaml:"path"`
		Interval time.Duration `yaml:"interval"`
		Safety   safetyYAML    `yaml:"safety"`
	} `yaml:"sync"`
}

// identityShape is a caller as CallerOf names one: `user:` and an email, or a
// URI with a scheme; printable, no space.
var identityShape = regexp.MustCompile(`^(user:[^@\s]+@[^@\s]+|[a-z][a-z0-9+.-]*://\S+)$`)

// Load reads port49-inventory.yaml as port49d reads its own: a regular file,
// bounded, strictly decoded, a decode error printed as its line and a
// category only.
func Load(path string) (Config, error) {
	raw, err := config.ReadRegular(path, config.MaxConfigSize)
	if err != nil {
		return Config{}, err
	}
	var f fileConfig
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil && err != io.EOF {
		return Config{}, fmt.Errorf("port49-inventory: %s: %w; check the key spelling against the "+
			"port49-inventory.yaml schema", path, yamlfault.Of(err))
	}
	c := Config{Listen: f.Listen, MetricsListen: f.MetricsListen, TLSCertFile: f.TLSCertFile, TLSKeyFile: f.TLSKeyFile,
		ClientCAFile: f.ClientCAFile, Readers: f.Readers, Syncers: f.Syncers, SigningKeyFile: f.SigningKeyFile,
		VerifyKeyFiles: f.VerifyKeyFiles, PolicyFile: f.PolicyFile, StateDir: f.StateDir, MirrorDir: f.MirrorDir,
		Interval: f.Interval, SyncTimeout: f.SyncTimeout}
	if c.SyncTimeout == 0 {
		c.SyncTimeout = 5 * time.Minute
	}
	if c.SyncTimeout < 10*time.Second || c.SyncTimeout > time.Hour {
		return Config{}, fmt.Errorf("port49-inventory: sync_timeout must be between 10s and 1h; got %s", c.SyncTimeout)
	}
	if c.MetricsListen == "" {
		c.MetricsListen = ":9050"
	}
	if c.Interval == 0 {
		c.Interval = 10 * time.Minute
	}
	for _, req := range []struct{ key, v string }{{"listen", c.Listen}, {"tls_cert_file", c.TLSCertFile},
		{"tls_key_file", c.TLSKeyFile}, {"client_ca_file", c.ClientCAFile}, {"signing_key_file", c.SigningKeyFile},
		{"policy_file", c.PolicyFile}, {"state_dir", c.StateDir}} {
		if req.v == "" {
			return Config{}, fmt.Errorf("port49-inventory: %s is required", req.key)
		}
	}
	if c.Interval < time.Minute || c.Interval > 24*time.Hour {
		return Config{}, fmt.Errorf("port49-inventory: interval must be between 1m and 24h; got %s", c.Interval)
	}
	if len(c.Readers)+len(c.Syncers) == 0 {
		return Config{}, fmt.Errorf("port49-inventory: readers or syncers must name someone; nobody could read the bundle")
	}
	for _, l := range []struct {
		key string
		ids []string
	}{{"readers", c.Readers}, {"syncers", c.Syncers}} {
		for i, id := range l.ids {
			if !identityShape.MatchString(id) {
				// The index, not the value: a list of names is where a
				// token gets pasted.
				return Config{}, fmt.Errorf("port49-inventory: %s[%d] is not an identity: `user:` and an email, "+
					"or a certificate's URI SAN such as spiffe://...", l.key, i)
			}
		}
	}
	if c.MaxRemovedPercent, err = bound("safety.max_removed_percent", f.Safety, 10); err != nil {
		return Config{}, err
	}
	if len(f.Sync) == 0 {
		return Config{}, fmt.Errorf("port49-inventory: sync must name at least one sync source")
	}
	seen := map[string]bool{}
	for i, s := range f.Sync {
		if !admission.KeyRefShape.MatchString(s.Name) || seen[s.Name] {
			return Config{}, fmt.Errorf("port49-inventory: sync[%d].name must be unique, lowercase letters, digits "+
				"and _, starting with a letter", i)
		}
		seen[s.Name] = true
		switch s.Type {
		case "file":
			if s.Path == "" {
				return Config{}, fmt.Errorf("port49-inventory: sync[%d] (%s): path is required for a file source", i, s.Name)
			}
		case "netbox", "nautobot":
			return Config{}, fmt.Errorf("port49-inventory: sync[%d] (%s): type %s is not built yet (plan 6c); "+
				"this build has the file source", i, s.Name, s.Type)
		default:
			return Config{}, fmt.Errorf("port49-inventory: sync[%d] (%s): type must be file", i, s.Name)
		}
		p, err := bound(fmt.Sprintf("sync[%d].safety.max_removed_percent", i), s.Safety, c.MaxRemovedPercent)
		if err != nil {
			return Config{}, err
		}
		iv := s.Interval
		if iv == 0 {
			iv = c.Interval
		}
		if iv < time.Minute || iv > 24*time.Hour {
			return Config{}, fmt.Errorf("port49-inventory: sync[%d].interval must be between 1m and 24h; got %s", i, iv)
		}
		c.Sync = append(c.Sync, SourceConfig{Name: s.Name, Type: s.Type, Path: s.Path, Interval: iv,
			MaxRemovedPercent: p})
	}
	return c, nil
}

func bound(key string, s safetyYAML, def int) (int, error) {
	if s.MaxRemovedPercent == nil {
		return def, nil
	}
	if p := *s.MaxRemovedPercent; p < 0 || p > 100 {
		return 0, fmt.Errorf("port49-inventory: %s must be between 0 and 100; got %d", key, p)
	}
	return *s.MaxRemovedPercent, nil
}

// Bounds is each configured source's bound, by name.
func (c Config) Bounds() map[string]int {
	out := map[string]int{}
	for _, s := range c.Sync {
		out[s.Name] = s.MaxRemovedPercent
	}
	return out
}
