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
	"bytes"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/daemon/limits"
	"github.com/rhwendt/port49/internal/keyring"
	"github.com/rhwendt/port49/internal/platform"
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
	SessionAttributes []string `yaml:"session_attributes"`
	// CommandAttributes are attached to a PERMITTED per-command authorization
	// reply, as SessionAttributes are to a session one. It is a separate list
	// because register entry L18 asks the same question of each reply
	// separately; see author.Lab.
	CommandAttributes []string    `yaml:"command_attributes"`
	DenyPrefixes      []string    `yaml:"deny_prefixes"`
	SeedTokens        []SeedToken `yaml:"seed_tokens"`
}

// PlatformConfig is an operator's override of one built-in platform adapter
// (spec §8). Plan 1 reads one field from an adapter, so it carries one;
// plan 5 builds the rest.
type PlatformConfig struct {
	// SessionServices replaces the built-in list of authorization `service`
	// values a session on this platform may arrive with. It is a list, and it
	// is settable, because on Junos the name is a device setting: `set system
	// tacplus-options service-name junos-exec-fw` renames it, so `junos-exec`
	// is a default and not a constant. Setting it replaces the built-in — a
	// fleet part-way through a rename lists both names.
	SessionServices []string `yaml:"session_services"`

	// EnableUsername selects what username an enable START is expected to
	// carry: `principal` (the default, and the only value config.Load
	// accepts) or `enab`, which is refused — see resolveEnableUsernames.
	EnableUsername string `yaml:"enable_username"`
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
	Listen        string            `yaml:"listen"`
	MetricsListen string            `yaml:"metrics_listen"`
	InventoryFile string            `yaml:"inventory_file"`
	Keys          map[string]KeySet `yaml:"keys"`
	Limits        limitsYAML        `yaml:"limits"`
	// ReceiptTTL is kept only so Load can refuse the key by name: it was
	// replaced by the two bounds below, and a daemon that starts on a stale
	// config is a daemon whose receipt window is not what the operator
	// believes (spec §13, decision 15).
	ReceiptTTL     time.Duration             `yaml:"receipt_ttl"`
	ReceiptIdleTTL time.Duration             `yaml:"receipt_idle_ttl"`
	ReceiptMaxAge  time.Duration             `yaml:"receipt_max_age"`
	ContextIdleTTL time.Duration             `yaml:"context_idle_ttl"`
	Accounting     AccountingConfig          `yaml:"accounting"`
	Platforms      map[string]PlatformConfig `yaml:"platforms"`
	Lab            *LabConfig                `yaml:"lab"`
}

type Config struct {
	Listen        string
	MetricsListen string
	InventoryFile string
	Keys          map[string]KeySet
	Limits        limits.Config
	// ReceiptIdleTTL slides a receipt forward on every presentation it
	// answers; ReceiptMaxAge caps it from the first redemption and never
	// moves. A presentation past either is FAIL on the wire and `token_spent`
	// in the log (spec §5.7; §13, decision 15).
	ReceiptIdleTTL time.Duration
	ReceiptMaxAge  time.Duration
	ContextIdleTTL time.Duration
	Accounting     AccountingConfig
	Lab            *LabConfig

	// SessionServices is the resolved authorization-`service` table: every
	// built-in platform, with any operator override already applied. It is
	// resolved here rather than at each authorization so the daemon never
	// consults two sources, and so a name the operator mistyped is a startup
	// error rather than a platform silently on its default (spec §5.2, §8).
	SessionServices map[string][]string

	// EnableUsernames is the resolved enable-username table: every built-in
	// platform mapped to platform.EnablePrincipal, the only value config.Load
	// accepts today (see resolveEnableUsernames).
	EnableUsernames map[string]string

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
	// KnownFields: this file is read once, at start, and every key in it
	// changes how the daemon answers devices. Silently ignoring an unknown one
	// turns `per_nas_conections: 4` into the default 32 and `retire:` into a
	// dropped key version — both invisible until a device is affected by them.
	var f fileConfig
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil && err != io.EOF {
		return Config{}, fmt.Errorf("config: %s: %w; check the key spelling against the port49d.yaml schema", path, err)
	}

	malformedWindow, err := window("malformed_window", f.Limits.MalformedWindow)
	if err != nil {
		return Config{}, err
	}
	authFailureWindow, err := window("auth_failure_window", f.Limits.AuthFailureWindow)
	if err != nil {
		return Config{}, err
	}

	if f.ReceiptTTL != 0 {
		return Config{}, fmt.Errorf("config: receipt_ttl was replaced by receipt_idle_ttl (default 15m) " +
			"and receipt_max_age (default 2h) when the receipt became a sliding window (spec §13, decision 15); " +
			"remove the key and set those")
	}

	c := Config{
		Listen:         or(f.Listen, ":49"),
		MetricsListen:  or(f.MetricsListen, ":9049"),
		InventoryFile:  f.InventoryFile,
		Keys:           f.Keys,
		ReceiptIdleTTL: orD(f.ReceiptIdleTTL, 15*time.Minute),
		ReceiptMaxAge:  orD(f.ReceiptMaxAge, 2*time.Hour),
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
			// 2s, not 5s: the ceiling has to stay under the reply timeout of the
			// devices being answered, or the FAIL it delays arrives after the
			// device has given up and is read as an unreachable server — which
			// falls through to the local password, so the brake undoes the
			// denial. The shortest timeout measured is about 3s (spec §15, L13;
			// tests/lab/results/L13-*.md). An operator who raises this above
			// their own shortest device timeout converts denials into
			// fall-through.
			AuthFailureDelayMax: orD(f.Limits.AuthFailureDelayMax, 2*time.Second),
			AuthFailureWindow:   authFailureWindow,
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
	if err := resolveSessionServices(&c, f.Platforms); err != nil {
		return Config{}, err
	}
	if err := resolveEnableUsernames(&c, f.Platforms); err != nil {
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
	// A device that matches no key group builds without error (admission.Build
	// simply omits it from the table) and then fails every packet at runtime as
	// an unresolved key. That is a configuration mistake, not a device it's fine
	// to leave unreachable, so it is refused here rather than discovered later.
	for _, d := range inv.Devices {
		resolved := false
		for _, a := range d.Addresses {
			if r, ok := trie.Lookup(a); ok && r.KeyRef != "" {
				resolved = true
				break
			}
		}
		if !resolved {
			return Config{}, fmt.Errorf("inventory: device %q matches no key group", d.Name)
		}
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

// resolveSessionServices builds c.SessionServices from the built-in table and
// whatever `platforms:` overrides. Three things are refused rather than
// accepted, and each is a configuration that would be invisible at runtime:
//
//   - a platform name port49 ships no adapter for. `platforms: {junos: ...}`
//     is a typo for `juniper_junos`, and the operator would see Junos denied
//     beside a file that plainly permits it.
//   - an explicitly empty list. It authorizes nothing, so every session on
//     that platform is denied `service_unsupported` — a whole vendor locked
//     out by a key that looks like it is configuring something. Omitting the
//     key is how you ask for the default.
//   - an empty service name, which would match a request carrying no
//     `service` at all.
func resolveSessionServices(c *Config, overrides map[string]PlatformConfig) error {
	c.SessionServices = platform.Defaults()
	names := make([]string, 0, len(overrides))
	for name := range overrides {
		names = append(names, name)
	}
	sort.Strings(names) // one bad key in a map: report the same one every run
	for _, name := range names {
		if !platform.Known(name) {
			return fmt.Errorf("config: platforms: %q is not a platform port49 ships an adapter for; known platforms are %s",
				name, strings.Join(platform.Names(), ", "))
		}
		svc := overrides[name].SessionServices
		if svc == nil {
			continue // the block names the platform and sets nothing
		}
		if len(svc) == 0 {
			return fmt.Errorf("config: platforms.%s.session_services is empty, which denies every session on that platform "+
				"service_unsupported; remove the key to take the default [%s]", name, strings.Join(platform.SessionServices(name), " "))
		}
		for i, s := range svc {
			if s == "" {
				return fmt.Errorf("config: platforms.%s.session_services[%d] is the empty string; list the `service` value the device sends", name, i)
			}
		}
		c.SessionServices[name] = append([]string(nil), svc...)
	}
	return nil
}

// resolveEnableUsernames applies any platforms.<name>.enable_username override
// to the built-in table, and refuses `enab`.
//
// The $enab{level}$ enable path is unbuilt on purpose: it would need a
// (nas, rem_addr) secondary index, and rem_addr is measured identical for two
// concurrent sessions behind one bastion, so that index would have to refuse
// rather than guess — and its refusal needs a reason code spec §5.7 does not
// carry. None of that is worth building for a username form no device in this
// lab has ever sent.
func resolveEnableUsernames(c *Config, overrides map[string]PlatformConfig) error {
	c.EnableUsernames = platform.EnableUsernames()
	names := make([]string, 0, len(overrides))
	for name := range overrides {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		v := overrides[name].EnableUsername
		if v == "" {
			continue
		}
		if !platform.KnownEnableUsername(v) {
			return fmt.Errorf("config: platforms.%s.enable_username is %q; it must be %q or %q",
				name, v, platform.EnablePrincipal, platform.EnableEnab)
		}
		if v == platform.EnableEnab {
			return fmt.Errorf("config: platforms.%s.enable_username: %q is refused: no platform in the lab has been "+
				"measured sending that username form, and port49 does not ship an unexercised enable path for it. "+
				"Every platform with an enable exchange sends the operator's own username "+
				"(tests/lab/results/L3-arista_eos.md, L3-cisco_iosxe.md). To enable it, add a "+
				"tests/lab/results/ note showing a device sending it and lift this refusal with the code that reads it",
				name, platform.EnableEnab)
		}
		c.EnableUsernames[name] = v
	}
	return nil
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
		{"receipt_idle_ttl", c.ReceiptIdleTTL},
		{"receipt_max_age", c.ReceiptMaxAge},
		{"context_idle_ttl", c.ContextIdleTTL},
	} {
		if f.d <= 0 {
			return fmt.Errorf("config: %s must be greater than zero; got %s", f.name, f.d)
		}
	}
	if c.ReceiptIdleTTL > c.ReceiptMaxAge {
		return fmt.Errorf("config: receipt_idle_ttl (%s) is longer than receipt_max_age (%s): "+
			"the window can never slide, so the idle bound does nothing", c.ReceiptIdleTTL, c.ReceiptMaxAge)
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
