// Package config loads port49d.yaml. Keys are snake_case; secrets come from the
// environment by name, never inline.
//
// Everything a running daemon needs from disk is read here, once: the key
// versions, the limits, and the device inventory with its admission table
// already built. A daemon that starts has a config that parsed, an inventory
// that resolved, and every shared secret present in the environment — an
// operator learns about a typo at start, not at 3am on the first packet from
// the device it broke.
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/daemon/limits"
	"github.com/rhwendt/port49/internal/keyring"
	"github.com/rhwendt/port49/internal/store"
)

type KeyVersion struct {
	Version   int    `yaml:"version"`
	SecretEnv string `yaml:"secret_env"`
}

type KeySet struct {
	Current KeyVersion   `yaml:"current"`
	Accept  []KeyVersion `yaml:"accept"`
	Retired []KeyVersion `yaml:"retired"` // diagnosis only: identifies, never admits
}

type AccountingConfig struct {
	// SpoolCapacity is reserved by the spool (it validates `< 1`); the spool is
	// an append-only durable file, so it does not bound a drain pass today.
	SpoolCapacity int    `yaml:"spool_capacity"`
	SpoolPath     string `yaml:"spool_path"`
}

type SeedToken struct {
	NAS      string `yaml:"nas"`
	Username string `yaml:"username"`
	Secret   string `yaml:"secret"`
	Kind     string `yaml:"kind"`
}

// LabConfig is the stand-in authorizer's configuration. It is required until
// the policy engine lands (plan 4): without it there is no authorizer at all,
// and port49 never falls back to permitting everything.
type LabConfig struct {
	SessionAttributes []string    `yaml:"session_attributes"`
	DenyPrefixes      []string    `yaml:"deny_prefixes"`
	SeedTokens        []SeedToken `yaml:"seed_tokens"`
}

// limitsYAML mirrors the limits block. The two reset windows are pointers so
// an absent key (take the default) is distinguishable from an explicit zero
// (which would mean "never reset" in the limiter, and is refused).
type limitsYAML struct {
	PerNASConnections    int            `yaml:"per_nas_connections"`
	IdleTimeout          time.Duration  `yaml:"idle_timeout"`
	MalformedBackoffBase time.Duration  `yaml:"malformed_backoff_base"`
	MalformedBackoffMax  time.Duration  `yaml:"malformed_backoff_max"`
	MalformedWindow      *time.Duration `yaml:"malformed_window"`
	AuthFailureDelayBase time.Duration  `yaml:"auth_failure_delay_base"`
	AuthFailureDelayMax  time.Duration  `yaml:"auth_failure_delay_max"`
	AuthFailureWindow    *time.Duration `yaml:"auth_failure_window"`
}

type fileConfig struct {
	Listen         string            `yaml:"listen"`
	MetricsListen  string            `yaml:"metrics_listen"`
	InventoryFile  string            `yaml:"inventory_file"`
	Keys           map[string]KeySet `yaml:"keys"`
	Limits         limitsYAML        `yaml:"limits"`
	ReceiptTTL     time.Duration     `yaml:"receipt_ttl"`
	ContextIdleTTL time.Duration     `yaml:"context_idle_ttl"`
	Accounting     AccountingConfig  `yaml:"accounting"`
	Lab            *LabConfig        `yaml:"lab"`
}

type Config struct {
	Listen         string
	MetricsListen  string
	InventoryFile  string
	Keys           map[string]KeySet
	Limits         limits.Config
	ReceiptTTL     time.Duration
	ContextIdleTTL time.Duration
	Accounting     AccountingConfig
	Lab            *LabConfig

	// Inventory and Admission are read and built once, here, so the daemon
	// never re-reads the file and the two can never disagree.
	Inventory admission.Inventory
	Admission *admission.Trie

	secrets map[string]string
}

const defaultWindow = 10 * time.Minute

func Load(path string) (Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var f fileConfig
	if err := yaml.Unmarshal(raw, &f); err != nil {
		return Config{}, fmt.Errorf("config: %s: %w", path, err)
	}

	malformedWindow, err := window("malformed_window", f.Limits.MalformedWindow)
	if err != nil {
		return Config{}, err
	}
	authFailureWindow, err := window("auth_failure_window", f.Limits.AuthFailureWindow)
	if err != nil {
		return Config{}, err
	}

	c := Config{
		Listen:         or(f.Listen, ":49"),
		MetricsListen:  or(f.MetricsListen, ":9049"),
		InventoryFile:  f.InventoryFile,
		Keys:           f.Keys,
		ReceiptTTL:     orD(f.ReceiptTTL, 30*time.Second),
		ContextIdleTTL: orD(f.ContextIdleTTL, 12*time.Hour),
		Accounting:     f.Accounting,
		Lab:            f.Lab,
		secrets:        map[string]string{},
		Limits: limits.Config{
			PerNASConnections:    orI(f.Limits.PerNASConnections, 32),
			IdleTimeout:          orD(f.Limits.IdleTimeout, 30*time.Second),
			MalformedBackoffBase: orD(f.Limits.MalformedBackoffBase, 100*time.Millisecond),
			MalformedBackoffMax:  orD(f.Limits.MalformedBackoffMax, 5*time.Second),
			MalformedWindow:      malformedWindow,
			AuthFailureDelayBase: orD(f.Limits.AuthFailureDelayBase, 500*time.Millisecond),
			AuthFailureDelayMax:  orD(f.Limits.AuthFailureDelayMax, 5*time.Second),
			AuthFailureWindow:    authFailureWindow,
		},
	}
	if c.Accounting.SpoolCapacity == 0 {
		c.Accounting.SpoolCapacity = 10000
	}
	if c.Accounting.SpoolPath == "" {
		c.Accounting.SpoolPath = "/var/lib/port49/acct.jsonl"
	}
	if c.InventoryFile == "" {
		return Config{}, fmt.Errorf("config: inventory_file is required")
	}
	if err := checkPositive(c); err != nil {
		return Config{}, err
	}
	if c.Lab == nil {
		return Config{}, fmt.Errorf("config: lab: block is required until the policy engine lands (plan 4)")
	}
	for i, t := range c.Lab.SeedTokens {
		switch t.Kind {
		case store.KindLogin, store.KindEnable:
		default:
			return Config{}, fmt.Errorf("config: lab.seed_tokens[%d]: kind %q must be %q or %q", i, t.Kind, store.KindLogin, store.KindEnable)
		}
		if t.NAS == "" || t.Username == "" || t.Secret == "" {
			return Config{}, fmt.Errorf("config: lab.seed_tokens[%d]: nas, username, and secret are all required", i)
		}
	}

	for ref, ks := range c.Keys {
		seen := map[int]bool{}
		for _, v := range allVersions(ks) {
			if v.Version < 1 {
				return Config{}, fmt.Errorf("config: key %s: every version number must be 1 or greater", ref)
			}
			if seen[v.Version] {
				return Config{}, fmt.Errorf("config: key %s: version %d appears twice", ref, v.Version)
			}
			seen[v.Version] = true
			if v.SecretEnv == "" {
				return Config{}, fmt.Errorf("config: key %s version %d: secret_env is required", ref, v.Version)
			}
			s, ok := os.LookupEnv(v.SecretEnv)
			if !ok || s == "" {
				return Config{}, fmt.Errorf("config: key %s version %d: environment variable %s is not set", ref, v.Version, v.SecretEnv)
			}
			c.secrets[v.SecretEnv] = s
		}
	}

	inv, err := admission.LoadFile(c.InventoryFile)
	if err != nil {
		return Config{}, err
	}
	for _, g := range inv.KeyGroups {
		if _, ok := c.Keys[g.KeyRef]; !ok {
			return Config{}, fmt.Errorf("config: key group references key_ref %q which is not in keys", g.KeyRef)
		}
	}
	for _, d := range inv.Devices {
		if d.KeyRef != "" {
			if _, ok := c.Keys[d.KeyRef]; !ok {
				return Config{}, fmt.Errorf("config: device %q pins key_ref %q which is not in keys", d.Name, d.KeyRef)
			}
		}
	}
	trie, err := admission.Build(inv)
	if err != nil {
		return Config{}, err
	}
	c.Inventory, c.Admission = inv, trie
	return c, nil
}

// Keyring resolves every key set to its secrets, ordered current, accept, retired.
func (c Config) Keyring() map[string]keyring.Set {
	out := make(map[string]keyring.Set, len(c.Keys))
	for ref, ks := range c.Keys {
		set := keyring.Set{Ref: ref}
		set.Versions = append(set.Versions, keyring.Version{Number: ks.Current.Version, Secret: []byte(c.secrets[ks.Current.SecretEnv])})
		for _, v := range ks.Accept {
			set.Versions = append(set.Versions, keyring.Version{Number: v.Version, Secret: []byte(c.secrets[v.SecretEnv])})
		}
		for _, v := range ks.Retired {
			set.Versions = append(set.Versions, keyring.Version{Number: v.Version, Secret: []byte(c.secrets[v.SecretEnv]), Retired: true})
		}
		out[ref] = set
	}
	return out
}

func allVersions(ks KeySet) []KeyVersion {
	out := make([]KeyVersion, 0, 1+len(ks.Accept)+len(ks.Retired))
	out = append(out, ks.Current)
	out = append(out, ks.Accept...)
	return append(out, ks.Retired...)
}

// window applies the 10m default for an absent key and refuses an explicit zero
// or negative one: the limiter reads a zero window as "never reset", so a
// source's strike count would only ever grow.
func window(name string, v *time.Duration) (time.Duration, error) {
	if v == nil {
		return defaultWindow, nil
	}
	if *v <= 0 {
		return 0, fmt.Errorf("config: limits.%s must be greater than zero (a zero window never resets a source's count); got %s", name, *v)
	}
	return *v, nil
}

// checkPositive refuses a negative duration or connection cap that the `or`
// defaults would otherwise pass straight through to the limiter.
func checkPositive(c Config) error {
	for _, f := range []struct {
		name string
		d    time.Duration
	}{
		{"limits.idle_timeout", c.Limits.IdleTimeout},
		{"limits.malformed_backoff_base", c.Limits.MalformedBackoffBase},
		{"limits.malformed_backoff_max", c.Limits.MalformedBackoffMax},
		{"limits.auth_failure_delay_base", c.Limits.AuthFailureDelayBase},
		{"limits.auth_failure_delay_max", c.Limits.AuthFailureDelayMax},
		{"receipt_ttl", c.ReceiptTTL},
		{"context_idle_ttl", c.ContextIdleTTL},
	} {
		if f.d <= 0 {
			return fmt.Errorf("config: %s must be greater than zero; got %s", f.name, f.d)
		}
	}
	if c.Limits.PerNASConnections < 1 {
		return fmt.Errorf("config: limits.per_nas_connections must be at least 1; got %d", c.Limits.PerNASConnections)
	}
	if c.Accounting.SpoolCapacity < 1 {
		return fmt.Errorf("config: accounting.spool_capacity must be at least 1; got %d", c.Accounting.SpoolCapacity)
	}
	return nil
}

func or(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

func orD(v, d time.Duration) time.Duration {
	if v == 0 {
		return d
	}
	return v
}

func orI(v, d int) int {
	if v == 0 {
		return d
	}
	return v
}
