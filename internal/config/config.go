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
	"github.com/rhwendt/port49/internal/store/crypt"
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

// SeedToken names one lab operator who gets a token pair at start, and nothing
// else: port49d mints the secret and writes it to LabConfig.SeedTokenFile, so a
// credential is never written down in a configuration file or re-emitted on a
// stream. `enable: true` asks for an enable token beside the login one.
//
// The yaml tags are not decoration — without them the decoder matches
// case-insensitively on the field name and would accept `NAS:` and `Username:`,
// against the snake_case rule and against what KnownFields(true) is for.
type SeedToken struct {
	NAS      string `yaml:"nas"`
	Username string `yaml:"username"`
	Enable   bool   `yaml:"enable"`
}

// LabConfig is the lab's measurement instrument (author.Lab): seeded tokens,
// and the fixed answers the register entries vary. It is optional since the
// policy engine landed (plan 4): without it a context with no blob is denied,
// and every context the broker mints has one. With it, only the seeded
// contexts get the lab's answers.
type LabConfig struct {
	SessionAttributes []string `yaml:"session_attributes"`
	// CommandAttributes are attached to a PERMITTED per-command authorization
	// reply, as SessionAttributes are to a session one. It is a separate list
	// because register entry L18 asks the same question of each reply
	// separately; see author.Lab.
	CommandAttributes []string `yaml:"command_attributes"`
	DenyPrefixes      []string `yaml:"deny_prefixes"`

	// SeedTokenFile is where port49d writes the pairs it mints for SeedTokens,
	// one JSON object per line, mode 0600. It is required when SeedTokens is
	// non-empty: the daemon mints the secret, so it is the daemon that must not
	// publish it, and a seed with nowhere to go is a daemon that either loses
	// the credential or prints it into the journal the decision log ships to.
	SeedTokenFile string      `yaml:"seed_token_file"`
	SeedTokens    []SeedToken `yaml:"seed_tokens"`
}

// SessionConfig is the set of clocks a context lives by (spec §5.6).
type SessionConfig struct {
	// StalenessCeiling denies a context whose `refreshed_at` is older than
	// this, `context_stale`. It defaults to 0, which disables the check, and
	// that default is a wiring fact rather than a taste: nothing moves
	// `refreshed_at` until the broker refreshes contexts (plans 3 and 7), so
	// `refreshed_at` is stamped once at login. Any finite ceiling before then
	// denies a steadily working operator "the broker is unreachable" at login
	// plus the ceiling, with no broker to reach. Whoever wires the broker sets
	// this key; set, it must be at least a minute.
	StalenessCeiling time.Duration `yaml:"staleness_ceiling"`

	// GraceWindow is how long past `session_expires` a context is kept for
	// diagnosis before plan 7's sweep reclaims it. Nothing reads it today.
	GraceWindow time.Duration `yaml:"grace_window"`

	// IndexTTL is how long the context indexes (principal, sid, cert) outlive
	// a write. They exist so revocation can reach a live context, so they are
	// given a TTL of their own rather than the context's.
	IndexTTL time.Duration `yaml:"index_ttl"`

	// MaxSessionAgeDefault is the `max_session_age` a mint uses when policy
	// names none; `session_expires = auth_time + max_session_age`.
	MaxSessionAgeDefault time.Duration `yaml:"max_session_age_default"`
}

// TokenConfig is the minter's bounds.
type TokenConfig struct {
	// CandidateCap is how many unspent tokens may stand for one
	// (device, username) at once. Past it the mint is refused with the count,
	// so a client stuck in a loop is told so rather than filling the store.
	CandidateCap int `yaml:"candidate_cap"`
}

// BrokerConfig is the vertical slice's broker (design §19 step 3), served by
// port49d on a second listener because the store is in-process (plan 3,
// Decided 1). Absent, port49d runs no broker, as before.
//
// The policy file is read once, at start, and the store is in memory: a
// policy edit needs a restart, and a restart ends every live login context
// and every unspent token — every operator logs in again (plan 3,
// Question 3). Live policy reload, which keeps every login, is plan 4b's (roadmap).
//
// The slice has no revocation lever. To cut someone off, remove their subject
// from the policy (or re-issue the CA) and restart; certificate revocation is
// plan 7.
//
// A relative path resolves against port49d's working directory, not the
// config file's, as inventory_file does.
type BrokerConfig struct {
	Listen      string `yaml:"listen"`
	TLSCertFile string `yaml:"tls_cert_file"`
	// TLSKeyFile is loaded through internal/keyfile, which refuses a symlink,
	// a file not owned by port49's user or root, any group or other mode bit,
	// and anything over 1 MiB. Keep the key in a directory only its owner can
	// write: the check covers the file, and a symlink in a parent directory is
	// followed.
	TLSKeyFile string `yaml:"tls_key_file"`
	// ClientCAFile is the one trust anchor client certificates are verified
	// against. It must hold exactly one certificate (broker.LoadTLS).
	ClientCAFile string `yaml:"client_ca_file"`
	PolicyFile   string `yaml:"policy_file"`
	// BatchMax caps the devices in one mint request; a larger sweep pages
	// (design §17). Default 100.
	BatchMax int `yaml:"batch_max"`
}

// encKeyYAML names one encryption-at-rest key: the id that travels with every
// record it seals, and the environment variable holding its 32 bytes. The
// secret is never inline, for the same reason no shared secret in this file is.
type encKeyYAML struct {
	ID        string `yaml:"id"`
	SecretEnv string `yaml:"secret_env"`
}

// encryptionYAML is the two-key rotation window of design §8: writes use
// `current`, reads accept `previous` as well. `previous` is optional and is
// read-only — retiring it is a config change, never code.
type encryptionYAML struct {
	Current  encKeyYAML `yaml:"current"`
	Previous encKeyYAML `yaml:"previous"`
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
	Encryption     encryptionYAML            `yaml:"encryption"`
	Session        SessionConfig             `yaml:"session"`
	Token          TokenConfig               `yaml:"token"`
	Broker         *BrokerConfig             `yaml:"broker"`
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
	Session        SessionConfig
	Token          TokenConfig
	// Broker is nil when no broker: block is configured, and Lab when no lab:
	// block is.
	Broker *BrokerConfig
	Lab    *LabConfig

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

	// encCurrent and encPrevious are the key references, not the keys: the
	// bytes live in secrets, which Load fills from the environment, so a
	// Config that is printed or logged carries no key material.
	encCurrent, encPrevious encKeyYAML
	hasPrevious             bool

	secrets map[string]string
}

const defaultWindow = 10 * time.Minute

func Load(path string) (Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	// Before the strict decode, because KnownFields(true) refuses `secret:` and
	// `kind:` under a seed with "field secret not found in type
	// config.SeedToken" — true, and no help at all to an operator whose lab
	// logins stopped working. staleSeedKeys names the replacement instead.
	if err := staleSeedKeys(raw); err != nil {
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
		// staleness_ceiling has no default: 0 means the check is off, which is
		// what SessionConfig.StalenessCeiling argues for.
		Session: SessionConfig{
			StalenessCeiling:     f.Session.StalenessCeiling,
			GraceWindow:          orD(f.Session.GraceWindow, 10*time.Minute),
			IndexTTL:             orD(f.Session.IndexTTL, 12*time.Hour),
			MaxSessionAgeDefault: orD(f.Session.MaxSessionAgeDefault, 12*time.Hour),
		},
		Token:       TokenConfig{CandidateCap: orI(f.Token.CandidateCap, 8)},
		encCurrent:  f.Encryption.Current,
		encPrevious: f.Encryption.Previous,
		hasPrevious: f.Encryption.Previous.SecretEnv != "",
		secrets:     map[string]string{},
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
	// No lab: block is a production daemon: Lab stays nil, the policy engine
	// answers every context the broker minted, and a context with no blob is
	// denied — there is no instrument to answer it.
	if c.Lab != nil {
		for i, t := range c.Lab.SeedTokens {
			if t.NAS == "" || t.Username == "" {
				return Config{}, fmt.Errorf("config: lab.seed_tokens[%d]: nas and username are both required", i)
			}
		}
		if len(c.Lab.SeedTokens) > 0 && c.Lab.SeedTokenFile == "" {
			return Config{}, fmt.Errorf("config: lab.seed_token_file is required when lab.seed_tokens is non-empty: " +
				"port49d mints each seed's secret at start and has to put it somewhere an operator can read " +
				"and nothing else can — a 0600 file, never a stream")
		}
	}

	if f.Broker != nil {
		b := *f.Broker
		for _, req := range []struct{ key, v string }{
			{"broker.listen", b.Listen}, {"broker.tls_cert_file", b.TLSCertFile}, {"broker.tls_key_file", b.TLSKeyFile},
			{"broker.client_ca_file", b.ClientCAFile}, {"broker.policy_file", b.PolicyFile},
		} {
			if req.v == "" {
				return Config{}, fmt.Errorf("config: %s is required when broker: is present; remove the block to run "+
					"port49d without a broker", req.key)
			}
		}
		b.BatchMax = orI(b.BatchMax, 100)
		if b.BatchMax < 1 || b.BatchMax > 1000 {
			return Config{}, fmt.Errorf("config: broker.batch_max must be between 1 and 1000; got %d", b.BatchMax)
		}
		c.Broker = &b
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

	// The encryption keys go into c.secrets alongside the shared secrets,
	// because that map is the one place a secret is held and EncryptionKeys
	// reads it. Without this the map is empty for those names, key32 is handed
	// "", and — were it to zero-pad rather than refuse — every token, receipt
	// and context in the store would be sealed under an all-zero AES-256 key,
	// with no error and no panic.
	if f.Encryption.Current.SecretEnv == "" {
		return Config{}, fmt.Errorf("config: encryption.current is required: it is the key every token, receipt " +
			"and context is sealed under at rest (design §8); name an id and the environment variable holding " +
			"its 32 bytes")
	}
	for _, k := range []struct {
		what string
		ref  encKeyYAML
	}{
		{"encryption.current", f.Encryption.Current}, {"encryption.previous", f.Encryption.Previous},
	} {
		if k.ref.SecretEnv == "" {
			// previous is optional; current's absence was refused above. But a
			// previous key that names an id and no variable is not "absent" to
			// the operator who wrote it — it reads as a rotation in progress
			// while every record still sealed under that id fails to open.
			if k.ref.ID != "" {
				return Config{}, fmt.Errorf("config: %s: id %q is named with no secret_env, so the key is not "+
					"loaded and every record sealed under it fails to open; give it a secret_env or remove the block",
					k.what, k.ref.ID)
			}
			continue
		}
		if k.ref.ID == "" {
			return Config{}, fmt.Errorf("config: %s: id is required: it is written into every record the key "+
				"seals and is its authenticated data, so a record cannot be opened without it", k.what)
		}
		// Unset and wrong-length are separate errors on purpose, and each names
		// the id as well as the variable. The length check below would absorb
		// an unset one — "" is not 32 bytes — and the operator would be told
		// their key is the wrong size when what happened is that the unit never
		// exported it. That is the difference between editing a secret and
		// editing a systemd file at 3am.
		s, ok := os.LookupEnv(k.ref.SecretEnv)
		if !ok || s == "" {
			return Config{}, fmt.Errorf("config: %s (id %q): environment variable %s is not set",
				k.what, k.ref.ID, k.ref.SecretEnv)
		}
		if len(s) != 32 {
			return Config{}, fmt.Errorf("config: %s (id %q): %s must be exactly 32 bytes for AES-256, got %d",
				k.what, k.ref.ID, k.ref.SecretEnv, len(s))
		}
		c.secrets[k.ref.SecretEnv] = s
	}
	// The id is what a sealed record is labelled with, so two keys under one id
	// is not a rotation: Open matches the label on Current every time, Previous
	// is never tried, and every record written before the secret changed is
	// unopenable — from a config that looks exactly like a correct rotation.
	if c.hasPrevious && f.Encryption.Previous.ID == f.Encryption.Current.ID {
		return Config{}, fmt.Errorf("config: encryption.previous.id is %q, the same as encryption.current.id: "+
			"the id labels every record the key sealed, so a rotation has to change it or the previous key is "+
			"never tried", f.Encryption.Current.ID)
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

// EncryptionKeys is the two-key window: writes use Current, reads try Current
// then Previous. Retiring Previous is a config change, never code (design §8).
func (c Config) EncryptionKeys() (crypt.Keys, error) {
	cur, err := key32(c.encCurrent.ID, c.secrets[c.encCurrent.SecretEnv])
	if err != nil {
		return crypt.Keys{}, err
	}
	keys := crypt.Keys{Current: cur}
	if c.hasPrevious {
		p, err := key32(c.encPrevious.ID, c.secrets[c.encPrevious.SecretEnv])
		if err != nil {
			return crypt.Keys{}, err
		}
		keys.Previous = &p
	}
	return keys, nil
}

// key32 returns an error rather than a short key silently zero-padded. Load
// already refuses anything but 32 bytes, so this is the backstop that makes the
// silent case impossible to reach by another route — and it is what the error
// return in EncryptionKeys's signature is for.
func key32(id, secret string) (crypt.Key, error) {
	if len(secret) != 32 {
		return crypt.Key{}, fmt.Errorf("config: encryption key %q: secret must be exactly 32 bytes, got %d", id, len(secret))
	}
	var k crypt.Key
	k.ID = id
	copy(k.Bytes[:], secret)
	return k, nil
}

// staleSeedKeys refuses a `secret:` or `kind:` under lab.seed_tokens and names
// the minter as what replaced it. Both are unknown fields now, so the strict
// decode would refuse them anyway — but its message says the key does not
// exist, not that port49d mints the secret itself and writes it to
// lab.seed_token_file, and an operator whose seeds silently stopped being used
// has nothing else to read. (The same discipline receipt_ttl gets, for the same
// reason.)
//
// A decode error here is ignored on purpose: the strict decode below reports a
// malformed file properly, naming the path.
func staleSeedKeys(raw []byte) error {
	var loose struct {
		Lab struct {
			SeedTokens []map[string]any `yaml:"seed_tokens"`
		} `yaml:"lab"`
	}
	if err := yaml.Unmarshal(raw, &loose); err != nil {
		return nil
	}
	for i, t := range loose.Lab.SeedTokens {
		for _, k := range []string{"secret", "kind"} {
			if _, ok := t[k]; !ok {
				continue
			}
			return fmt.Errorf("config: lab.seed_tokens[%d]: %q was removed: the pair is minted by port49d at "+
				"start and written to lab.seed_token_file, so a seed names who gets one and nothing else; "+
				"drop the key (an enable token is `enable: true`)", i, k)
		}
	}
	return nil
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
		{"session.grace_window", c.Session.GraceWindow},
		{"session.index_ttl", c.Session.IndexTTL},
		{"session.max_session_age_default", c.Session.MaxSessionAgeDefault},
	} {
		if f.d <= 0 {
			return fmt.Errorf("config: %s must be greater than zero; got %s", f.name, f.d)
		}
	}
	// staleness_ceiling is the one duration here whose zero is meaningful: it
	// is the default and it means the check is off. A positive one still has to
	// outlast a refresh interval — under a minute it denies everyone
	// `context_stale` about as fast as the broker can refresh them.
	if c.Session.StalenessCeiling < 0 {
		return fmt.Errorf("config: session.staleness_ceiling must not be negative; got %s (omit the key to disable the check)",
			c.Session.StalenessCeiling)
	}
	if c.Session.StalenessCeiling > 0 && c.Session.StalenessCeiling < time.Minute {
		return fmt.Errorf("config: session.staleness_ceiling is %s: set it to at least 1m, or omit it to disable "+
			"the staleness check; a ceiling shorter than a refresh interval denies every live context context_stale",
			c.Session.StalenessCeiling)
	}
	if c.Token.CandidateCap < 1 {
		return fmt.Errorf("config: token.candidate_cap must be at least 1; got %d", c.Token.CandidateCap)
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
