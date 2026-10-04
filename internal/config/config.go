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
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/daemon/limits"
	"github.com/rhwendt/port49/internal/fence"
	"github.com/rhwendt/port49/internal/keyring"
	"github.com/rhwendt/port49/internal/platform"
	"github.com/rhwendt/port49/internal/store/crypt"
	"github.com/rhwendt/port49/internal/yamlfault"
)

type KeyVersion struct {
	Version   int    `yaml:"version"`
	SecretEnv string `yaml:"secret_env"`
	// RetireAfter is the last day, UTC, the version admits (spec §10):
	// accept versions only. RetireAt is it parsed, the first instant the
	// version is refused — midnight after that day. Zero is none.
	RetireAfter string    `yaml:"retire_after"`
	RetireAt    time.Time `yaml:"-"`
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
	// FaultFile is the lab's fault switch (author.LabFault): a file naming the
	// fault in force, re-read on every request. Absent is no fault, and the
	// shipped lab config leaves it absent; a derivation adds it.
	FaultFile string `yaml:"fault_file"`

	// SeedTokenFile is where port49d writes the pairs it mints for SeedTokens,
	// one JSON object per line, mode 0600. It is required when SeedTokens is
	// non-empty: the daemon mints the secret, so it is the daemon that must not
	// publish it, and a seed with nowhere to go is a daemon that either loses
	// the credential or prints it into the journal the decision log ships to.
	SeedTokenFile string      `yaml:"seed_token_file"`
	SeedTokens    []SeedToken `yaml:"seed_tokens"`

	// DenyMessageLength pads the lab's deny server_msg to this many bytes
	// with a counting pattern, so the last digit a device prints says where
	// it cut (spec §15, L2's truncation length). 0 leaves it; otherwise
	// 16 to 4096.
	DenyMessageLength int `yaml:"deny_message_length"`
	// DenySession fails every session authorization of a seeded context with
	// the (padded) deny message: L2 on Junos, which never authorizes a
	// command (plan 7b; pre-flight I12).
	DenySession bool `yaml:"deny_session"`
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

	// GraceWindow is how long past `session_expires` a context is kept: the
	// authorizer denies through it and then deletes the context (plan 7b);
	// the broker's refresh resumes inside it.
	GraceWindow time.Duration `yaml:"grace_window"`

	// CeilingWarning is how long before session_expires a permitted reply
	// carries the warning in server_msg (spec §5.6; decision 33). Default
	// 30m, long enough to finish a change; 0s turns it off; at most 24h. It
	// is read through sessionYAML, so an explicit 0s is told from absent.
	CeilingWarning time.Duration `yaml:"-"`
	// CeilingWarningPlatforms are platforms the operator adds to the
	// warning's allow-list (platform.CeilingWarning), unmeasured by L34.
	// Each is a platform name's shape, unchecked against the set: an
	// operator may name a variant.
	CeilingWarningPlatforms []string `yaml:"ceiling_warning_platforms"`

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
// The policy file is watched: port49d reads it every policy_watch_interval,
// and on SIGHUP, and a file that loads is put in force and carried into every
// live login context with no logout; one that does not is refused and the
// policy in force keeps serving (plan 4b). The TLS files and the inventory are
// read once, at start: a change to either needs a restart, and the store is in
// memory, so a restart ends every live login context and every unspent token.
//
// To cut someone off, remove their grants from the policy: their live
// contexts are revoked at the next reload, with no restart, and the next
// command is denied on a platform that authorizes commands. On one that does
// not (Junos, spec §13 decision 21) the live shell keeps its access until
// logout: the refresh line counts those and the process log names each
// ctx_id, so close them on the device. To end a principal's or a
// certificate's sessions at once, use `port49 revoke` over `admin_socket`
// (plan 7a).
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
	// PolicyWatchInterval is how often port49d reads policy_file for a
	// change (plan 4b). A change is loaded once two reads in a row agree, and
	// what is loaded is the bytes they agreed on, so an edit is in force
	// within two intervals and a write in progress is not loaded part-way.
	// Default 5s; 1s to 5m. SIGHUP loads what is on disk at once. Write the
	// file atomically — a temporary file renamed over it: a writer stalled
	// part-way for two intervals, or a SIGHUP sent mid-write, loads what is
	// there. The file and its directory must be writable by port49d's user or
	// root alone, or it is refused (spec §5.1.3).
	PolicyWatchInterval time.Duration `yaml:"policy_watch_interval"`
	// RevocationsFile is where port49d keeps the revocations `port49 revoke`
	// puts in force (plan 7a), so a restart forgets none. Required. Its
	// directory must exist and be writable by port49d's user or root alone,
	// and the file's own name may not be a link. port49d never creates it: a
	// missing file, or one that does not load, refuses every start, and so
	// does a directory others can write (spec §13 decision 32, amended
	// 2026-10-02). `port49d init-revocations` creates it once per install, as
	// port49d's user, beside a marker (<file>.created); a start writes the
	// marker beside a file that loads with none. port49d writes the file, 0600
	// and atomically, after every revocation and lift.
	RevocationsFile string `yaml:"revocations_file"`
	// MaxConnsPerPrincipal caps one principal's held broker connections; a
	// new one closes the oldest of its certificate, else the principal's
	// oldest (spec §13 decision 32). Default 4; 1 to 64.
	MaxConnsPerPrincipal int `yaml:"max_conns_per_principal"`
	// MaxPendingConnsPerSource caps the broker connections one address holds
	// that are not bound to a principal; the next is reset. Default 16; 1 to
	// 256.
	MaxPendingConnsPerSource int `yaml:"max_pending_conns_per_source"`
	// CertificateStatus is required (plan 7b); see CertificateStatusConfig.
	CertificateStatus *CertificateStatusConfig `yaml:"certificate_status"`
	// StateDir is where port49-broker keeps the CRLs it verified,
	// crl-<name>.der; required under the broker's role, which has no
	// revocations file (plan 7e, Ruling 12).
	StateDir string `yaml:"state_dir"`
}

// Role is which process a configuration is for (plan 7e, Ruling 2):
// port49d's, the zero value, or port49-broker's.
type Role int

const (
	RoleDaemon Role = iota
	RoleBroker
)

// PolicyConfig is the policy file a process admits from, quarantines by and
// redacts with: broker.policy_file with a broker in the process, or policy:
// in a port49d.yaml with none (plan 7e).
type PolicyConfig struct {
	File          string
	WatchInterval time.Duration
}

// policyYAML is policy:, the policy a port49d with no broker admits from.
type policyYAML struct {
	File          string        `yaml:"file"`
	WatchInterval time.Duration `yaml:"watch_interval"`
}

// CertificateStatusConfig is broker.certificate_status (spec §5.1.4;
// decision 33): where the broker learns a client certificate's revocation.
// Required with a broker: Disabled is the explicit choice not to check.
//
// Each CRL is read from a file or fetched over http(s), and names the CA
// certificate that signs it (issuer_file): the trust anchor, or one the
// anchor signed, byte for byte the certificate in a client's chain. Each
// verified list is kept beside broker.revocations_file, or in
// broker.state_dir under port49-broker, as crl-<name>.der, so a restart
// keeps it. A status that cannot be established is refused (503,
// retried) under on_unavailable: refuse, the default, or admitted and said
// under allow.
type CertificateStatusConfig struct {
	Disabled        bool                   `yaml:"disabled"`
	CRLs            []CertificateStatusCRL `yaml:"crls"`
	OCSP            *CertificateStatusOCSP `yaml:"ocsp"`
	RefreshInterval time.Duration          `yaml:"refresh_interval"` // 1m to 24h; default 10m
	OnUnavailable   string                 `yaml:"on_unavailable"`   // refuse (default) or allow
}

// CertificateStatusCRL is one broker.certificate_status.crls entry: exactly
// one of File and URL.
type CertificateStatusCRL struct {
	Name       string `yaml:"name"`
	File       string `yaml:"file"`
	URL        string `yaml:"url"`
	IssuerFile string `yaml:"issuer_file"`
}

// CertificateStatusOCSP is broker.certificate_status.ocsp: a fixed
// responder, or each certificate's own (use_aia).
type CertificateStatusOCSP struct {
	Responder string        `yaml:"responder"`
	UseAIA    bool          `yaml:"use_aia"`
	Timeout   time.Duration `yaml:"timeout"` // 100ms to 10s; default 2s
	Hash      string        `yaml:"hash"`    // the CertID hash: sha256 (default) or sha1
}

// StoreConfig is `store:`, resolved (plan 7d; spec §13, decision 35): the
// backend and every packet's store deadline, and on etcd its client.
type StoreConfig struct {
	// Backend is memory (the default) or etcd. etcd requires admin_socket,
	// and in port49d.yaml policy: and no broker: block (plan 7e).
	Backend string
	// PacketDeadline bounds every TACACS+ packet's store work: default 2s,
	// 100ms to 2s (Junos times out a reply at about 3s; spec §15, L13), and
	// at least store.etcd.call_timeout.
	PacketDeadline time.Duration
	// Etcd is nil on memory.
	Etcd *EtcdConfig
}

// storeYAML mirrors the store block; checkStore resolves it.
type storeYAML struct {
	Backend        string        `yaml:"backend"`
	PacketDeadline time.Duration `yaml:"packet_deadline"`
	Etcd           *EtcdConfig   `yaml:"etcd"`
}

const (
	BackendMemory   = "memory"
	BackendEtcd     = "etcd"
	RolesEnforced   = "enforced"
	RolesUnenforced = "unenforced"
)

// EtcdConfig is store.etcd: where the keyspace is, and how port49d
// bounds every call to it (decision 35).
type EtcdConfig struct {
	// Endpoints are https only: port49d authenticates by client certificate.
	Endpoints []string `yaml:"endpoints"`
	CAFile    string   `yaml:"ca_file"`
	// Prefix is the keyspace: default /port49/, and it must start with /.
	Prefix string `yaml:"prefix"`
	// Daemon and Broker are each component's own identity, its CN etcd's
	// user. Each file names its own alone: port49d.yaml the daemon's, and
	// port49-broker.yaml the broker's (plan 7e, Ruling 1).
	Daemon EtcdIdentity  `yaml:"daemon"`
	Broker *EtcdIdentity `yaml:"broker"`
	// Roles is enforced (the default) or unenforced: whether port49d
	// refuses to start when the daemon's identity can do more than its role.
	Roles string `yaml:"roles"`
	// CallTimeout bounds each token and context call: default 500ms, 10ms to 5s.
	CallTimeout time.Duration `yaml:"call_timeout"`
	// BulkTimeout bounds each bulk scan: default 30s, 1s to 5m.
	BulkTimeout time.Duration `yaml:"bulk_timeout"`
	Breaker     EtcdBreaker   `yaml:"breaker"`
	MaxInFlight EtcdInFlight  `yaml:"max_in_flight"`
	// LeaseGrace is how long past a record's own expiry its lease reclaims
	// it: default 5m, 1m to 1h.
	LeaseGrace time.Duration `yaml:"lease_grace"`
	// HoldTTL is the keyspace hold's lease: default 15s, 10s to 60s. It is
	// also how long a pool's circuit stays open before the store is gone.
	HoldTTL time.Duration `yaml:"hold_ttl"`
	// SweepInterval is how often the index sweep runs: default 10m, 1m to 24h.
	SweepInterval time.Duration `yaml:"sweep_interval"`
	// StartTimeoutSet is the start_timeout key, a pointer so an absent key
	// (30s) is told from an explicit 0 (wait forever), as limitsYAML does
	// for its windows. StartTimeout is its resolved value: 0, or 5s to 10m.
	StartTimeoutSet *zeroDuration `yaml:"start_timeout"`
	StartTimeout    time.Duration `yaml:"-"`
}

// zeroDuration is a duration that may also be written as a bare 0, as
// the spec writes start_timeout's "wait forever" (decision 35): yaml.v3
// alone refuses an integer for a time.Duration. Any other bare number
// has no unit and is still refused.
type zeroDuration time.Duration

func (z *zeroDuration) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode && n.Value == "0" {
		*z = 0
		return nil
	}
	return n.Decode((*time.Duration)(z))
}

// EtcdIdentity is one component's client certificate and key. The key
// loads through internal/keyfile: owner-only, no symlink.
type EtcdIdentity struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

// EtcdBreaker is each pool's circuit: Failures consecutive failures
// (default 5, 1 to 100) open it for OpenFor (default 5s, 1s to 5m).
type EtcdBreaker struct {
	Failures int           `yaml:"failures"`
	OpenFor  time.Duration `yaml:"open_for"`
}

// EtcdInFlight is each pool's in-flight slots: default 64 token, 128
// context, 4 bulk, 1 to 4096 each. A call that gets none within its
// deadline is refused, never queued.
type EtcdInFlight struct {
	Token   int `yaml:"token"`
	Context int `yaml:"context"`
	Bulk    int `yaml:"bulk"`
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

	// EnableUsername moved to the policy file's `platforms:` block in plan 5,
	// where the offline tools see it as port49d does (plan 4 pre-flight N5).
	// It is declared only so config.Load can say where it went.
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

// sessionYAML mirrors the session block. ceiling_warning is a pointer so an
// absent key (take the 30m default) is told from an explicit 0s (off), as
// limitsYAML does for its windows.
type sessionYAML struct {
	SessionConfig  `yaml:",inline"`
	CeilingWarning *time.Duration `yaml:"ceiling_warning"`
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
	Session        sessionYAML               `yaml:"session"`
	Token          TokenConfig               `yaml:"token"`
	Broker         *BrokerConfig             `yaml:"broker"`
	Lab            *LabConfig                `yaml:"lab"`
	InventoryOpts  inventoryYAML             `yaml:"inventory"`
	AdminSocket    string                    `yaml:"admin_socket"`
	Store          storeYAML                 `yaml:"store"`
	Policy         *policyYAML               `yaml:"policy"`
	// KeyRefs is port49-broker.yaml's in place of keys: the names a policy
	// may assign, and never a secret (plan 7e, Ruling 2).
	KeyRefs []string `yaml:"key_refs"`
}

// inventoryYAML is how port49d bounds an inventory reload (spec §10). The
// pointer tells an absent key (the default) from an explicit 0, which refuses
// every removal.
type inventoryYAML struct {
	MaxRemovedPercent *int                    `yaml:"max_removed_percent"`
	Service           *InventoryServiceConfig `yaml:"service"`
}

// InventoryServiceConfig is where port49d takes its inventory from when the
// inventory service publishes it (spec §10), in place of inventory_file.
// port49d asks url every poll_interval for the bundle's version, over mutual
// TLS with its own certificate, and fetches a new document when it changes.
// Every document, from the service, from state_dir or from mirror_dir, is
// verified against verify_key_files (spec §13, decision 30) and applied
// against port49d's own broker.policy_file (decision 29).
type InventoryServiceConfig struct {
	URL         string `yaml:"url"`
	CAFile      string `yaml:"ca_file"`
	TLSCertFile string `yaml:"tls_cert_file"`
	TLSKeyFile  string `yaml:"tls_key_file"`
	// VerifyKeyFiles are the service's signing public keys: two while its key
	// rotates. SIGHUP re-reads the list.
	VerifyKeyFiles []string `yaml:"verify_key_files"`
	// PollInterval is how often port49d asks: default 30s, 5s to 10m.
	PollInterval time.Duration `yaml:"poll_interval"`
	// StateDir holds the last document port49d applied, bundle.json, which a
	// restart starts from with no service (spec §10, a MUST).
	StateDir string `yaml:"state_dir"`
	// MirrorDir is the shared copy the service writes, read at a cold start
	// when StateDir has none. Optional.
	MirrorDir string `yaml:"mirror_dir"`
}

type Config struct {
	// Role is which process the file was loaded for: Load's is RoleDaemon,
	// LoadBroker's RoleBroker.
	Role Role
	// Policy is the policy file in force: broker.policy_file with a broker
	// block, policy: with none, and nil with neither.
	Policy *PolicyConfig

	Listen        string
	MetricsListen string
	InventoryFile string
	// InventoryService is nil without an inventory.service block; with one,
	// InventoryFile is empty.
	InventoryService *InventoryServiceConfig
	Keys             map[string]KeySet
	Limits           limits.Config
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

	// AdminSocket is where port49d answers `port49 keys diagnose` (plan 6a
	// owner decision 2): a Unix socket, 0600, for port49d's user and root.
	// Empty, the default, is off, and no packet is held.
	AdminSocket string

	// Store is where tokens, receipts and contexts live: memory, the
	// default, or etcd (plan 7d).
	Store StoreConfig

	// MaxRemovedPercent refuses an inventory reload that takes more than this
	// share of the devices in force out of service — removed, or kept and
	// newly refused admission (spec §10, bounded change): default 10, 100
	// turns the bound off. An empty inventory is refused whatever it says.
	// It is read at start and re-read at every SIGHUP (InventoryBound), so a
	// deliberate large removal is: raise it, send SIGHUP, lower it again.
	MaxRemovedPercent int

	// SessionServices is the resolved authorization-`service` table: every
	// built-in platform, with any operator override already applied. It is
	// resolved here rather than at each authorization so the daemon never
	// consults two sources, and so a name the operator mistyped is a startup
	// error rather than a platform silently on its default (spec §5.2, §8).
	SessionServices map[string][]string

	// Notices are lines port49d prints at start about the file itself: a key
	// that still loads but has moved, and where it went.
	Notices []string

	// Inventory and Admission are read and built once, here, so the daemon
	// never re-reads the file and the two can never disagree. Admission is
	// nil with a policy: port49d admits from the policy in force
	// (policy.Policy.Admission).
	Inventory admission.Inventory
	Admission *admission.Trie

	// keyRefs is key_refs under the broker's role: the names alone.
	keyRefs []string

	// encCurrent and encPrevious are the key references, not the keys: the
	// bytes live in secrets, which Load fills from the environment, so a
	// Config that is printed or logged carries no key material.
	encCurrent, encPrevious encKeyYAML
	hasPrevious             bool

	secrets map[string]string
}

const defaultWindow = 10 * time.Minute

// defaultCeilingWarning and maxCeilingWarning bound session.ceiling_warning
// (spec §5.6; decision 33).
const (
	defaultCeilingWarning = 30 * time.Minute
	maxCeilingWarning     = 24 * time.Hour
)

// platformNameShape is how an inventory writes a platform, as the policy
// loader checks it (policy.platformNameShape).
var platformNameShape = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// DefaultMaxSessionAge is session.max_session_age_default where the file
// sets none (spec §5.6: "The default is 12h").
const DefaultMaxSessionAge = 12 * time.Hour

// MaxSessionAge reads session.max_session_age_default from a port49d.yaml's
// bytes, with Load's default and its refusal of a value that is not
// positive. It is what `port49 platform export --classes` renders a
// session-only platform's idle-timeout from (spec §13, decision 21). The file
// is decoded as strictly as Load decodes it, so the wrong file or a
// misspelled key is an error, never the default: a default read in place of
// the daemon's value is a timeout the device would be checked against and
// the daemon does not run with. It resolves no key and reads no secret or
// inventory, so a CI job holding no key can run it.
func MaxSessionAge(raw []byte) (time.Duration, error) {
	if err := staleSeedKeys(raw); err != nil {
		return 0, err
	}
	var f fileConfig
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil && err != io.EOF {
		return 0, fmt.Errorf("config: %w; check the key spelling against the port49d.yaml schema", decodeFault(err))
	}
	d := orD(f.Session.MaxSessionAgeDefault, DefaultMaxSessionAge)
	if d <= 0 {
		return 0, fmt.Errorf("config: session.max_session_age_default must be greater than zero; got %s", d)
	}
	return d, nil
}

// InventoryBound reads inventory.max_removed_percent from a port49d.yaml's
// bytes, with Load's default and range: what port49d re-reads at SIGHUP. It
// resolves no secret and decodes as strictly as Load, so a typo is an error,
// never the default.
func InventoryBound(raw []byte) (int, error) {
	var f fileConfig
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil && err != io.EOF {
		return 0, fmt.Errorf("config: %w; check the key spelling against the port49d.yaml schema", decodeFault(err))
	}
	return inventoryBound(f.InventoryOpts)
}

func inventoryBound(o inventoryYAML) (int, error) {
	if o.MaxRemovedPercent == nil {
		return 10, nil
	}
	if p := *o.MaxRemovedPercent; p < 0 || p > 100 {
		return 0, fmt.Errorf("config: inventory.max_removed_percent must be between 0 and 100; got %d", p)
	}
	return *o.MaxRemovedPercent, nil
}

// RevocationsFile reads broker.revocations_file from a port49d.yaml's bytes,
// for `port49d init-revocations` (spec §13 decision 32, amended): it resolves
// no secret, so the command runs where the daemon's environment is not, and
// decodes as strictly as Load, so a typo is an error, never "no path". It
// refuses the paths Load refuses (ownRevocationsFile), each read from the
// same bytes, so init never drops a file where admin_socket, the spool or
// the policy will be (pre-flight M10).
func RevocationsFile(raw []byte) (string, error) {
	var f fileConfig
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil && err != io.EOF {
		return "", fmt.Errorf("config: %w; check the key spelling against the port49d.yaml schema", decodeFault(err))
	}
	if f.Broker == nil || f.Broker.RevocationsFile == "" {
		return "", errors.New("config: no broker.revocations_file: init-revocations is for a port49d with a broker")
	}
	c := Config{InventoryFile: f.InventoryFile, InventoryService: f.InventoryOpts.Service, Accounting: f.Accounting,
		Lab: f.Lab, AdminSocket: f.AdminSocket}
	if c.Accounting.SpoolPath == "" {
		c.Accounting.SpoolPath = defaultSpoolPath
	}
	if err := ownRevocationsFile(c, *f.Broker); err != nil {
		return "", err
	}
	return f.Broker.RevocationsFile, nil
}

// defaultSpoolPath is accounting.spool_path when port49d.yaml names none.
const defaultSpoolPath = "/var/lib/port49/acct.jsonl"

// MaxConfigSize bounds a read of port49d.yaml, a file of a few kilobytes.
const MaxConfigSize = 1 << 20

// maxInventorySize bounds Load's read of the inventory file with no broker:
// a 10,000-device inventory is a few megabytes.
const maxInventorySize = 64 << 20

// ReadRegular reads path if it is a regular file of at most max bytes. It
// opens non-blocking and checks the opened file, so a named pipe or a device
// at the path is refused rather than blocking the read until something
// writes to it, and a path pointed at something large is not read whole
// (plan 6a Task 11a, Task 12 m3). It is not the policy file's owner and mode
// fence.
func ReadRegular(path string, max int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	raw, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > max {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, max)
	}
	return raw, nil
}

// Load reads port49d.yaml, under the daemon's role.
func Load(path string) (Config, error) { return load(path, RoleDaemon) }

// LoadBroker reads port49-broker.yaml: port49d.yaml's schema under the
// broker's role (plan 7e, Ruling 2). It names key_refs in place of keys:,
// broker.state_dir in place of the revocations file, and the broker's etcd
// identity alone, and refuses what is port49d's (brokerRefusals).
func LoadBroker(path string) (Config, error) { return load(path, RoleBroker) }

func load(path string, role Role) (Config, error) {
	raw, err := ReadRegular(path, MaxConfigSize)
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
		return Config{}, fmt.Errorf("config: %s: %w; check the key spelling against the port49d.yaml schema", path, decodeFault(err))
	}
	switch role {
	case RoleBroker:
		if err := brokerRefusals(f); err != nil {
			return Config{}, err
		}
	default:
		// Each is port49-broker.yaml's, and would be ignored here.
		if len(f.KeyRefs) > 0 {
			return Config{}, errors.New("config: key_refs is port49-broker.yaml's: port49d names its keys, with " +
				"their secrets, under keys:; remove it (plan 7e)")
		}
		if f.Broker != nil && f.Broker.StateDir != "" {
			return Config{}, errors.New("config: broker.state_dir is port49-broker.yaml's: the in-process broker " +
				"keeps its CRLs beside broker.revocations_file; remove it (plan 7e)")
		}
	}

	if f.ReceiptTTL != 0 {
		return Config{}, fmt.Errorf("config: receipt_ttl was replaced by receipt_idle_ttl (default 15m) " +
			"and receipt_max_age (default 2h) when the receipt became a sliding window (spec §13, decision 15); " +
			"remove the key and set those")
	}

	c := Config{
		Role:           role,
		MetricsListen:  or(f.MetricsListen, ":9049"),
		InventoryFile:  f.InventoryFile,
		Keys:           f.Keys,
		ContextIdleTTL: orD(f.ContextIdleTTL, 12*time.Hour),
		Lab:            f.Lab,
		AdminSocket:    f.AdminSocket,
		// staleness_ceiling has no default: 0 means the check is off, which is
		// what SessionConfig.StalenessCeiling argues for.
		Session: SessionConfig{
			StalenessCeiling:        f.Session.StalenessCeiling,
			GraceWindow:             orD(f.Session.GraceWindow, 10*time.Minute),
			IndexTTL:                orD(f.Session.IndexTTL, 12*time.Hour),
			MaxSessionAgeDefault:    orD(f.Session.MaxSessionAgeDefault, DefaultMaxSessionAge),
			CeilingWarning:          defaultCeilingWarning,
			CeilingWarningPlatforms: f.Session.CeilingWarningPlatforms,
		},
		Token:       TokenConfig{CandidateCap: orI(f.Token.CandidateCap, 8)},
		encCurrent:  f.Encryption.Current,
		encPrevious: f.Encryption.Previous,
		hasPrevious: f.Encryption.Previous.SecretEnv != "",
		secrets:     map[string]string{},
	}
	switch role {
	case RoleBroker:
		// The broker speaks no TACACS+: no listener, receipt or limit, and
		// metrics beside port49d's on one host.
		c.MetricsListen = or(f.MetricsListen, ":9050")
	default:
		if err := daemonDefaults(&c, f); err != nil {
			return Config{}, err
		}
	}
	// inventory.service is applied against the policy in force (decision
	// 29), whichever block names it.
	hasPolicy := f.Broker != nil || f.Policy != nil
	switch svc := f.InventoryOpts.Service; {
	case svc != nil && c.InventoryFile != "":
		return Config{}, fmt.Errorf("config: name inventory_file or inventory.service, not both: two inventory " +
			"sources would be the disagreement the bundle exists to prevent (spec §10)")
	case svc == nil && c.InventoryFile == "":
		return Config{}, fmt.Errorf("config: inventory_file or inventory.service is required")
	case svc != nil:
		if !hasPolicy {
			return Config{}, fmt.Errorf("config: inventory.service needs a policy (broker.policy_file or " +
				"policy.file): port49d applies the service's inventory against the policy it admits from (spec §13, " +
				"decision 29)")
		}
		if c.InventoryService, err = checkService(*svc); err != nil {
			return Config{}, err
		}
	}
	if c.MaxRemovedPercent, err = inventoryBound(f.InventoryOpts); err != nil {
		return Config{}, err
	}
	if f.Session.CeilingWarning != nil {
		c.Session.CeilingWarning = *f.Session.CeilingWarning
	}
	if c.Session.CeilingWarning < 0 || c.Session.CeilingWarning > maxCeilingWarning {
		return Config{}, fmt.Errorf("config: session.ceiling_warning is %s: set 0s to turn the warning off, or up to %s",
			c.Session.CeilingWarning, maxCeilingWarning)
	}
	for i, p := range c.Session.CeilingWarningPlatforms {
		if !platformNameShape.MatchString(p) {
			return Config{}, fmt.Errorf("config: session.ceiling_warning_platforms[%d] is %q: a platform name is lowercase "+
				"letters, digits and underscores, beginning with a letter", i, p)
		}
	}
	if err := checkPositive(c); err != nil {
		return Config{}, err
	}
	if role == RoleDaemon {
		if err := resolveSessionServices(&c, f.Platforms); err != nil {
			return Config{}, err
		}
		if err := moveEnableUsernames(&c, f.Platforms); err != nil {
			return Config{}, err
		}
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
		if n := c.Lab.DenyMessageLength; n != 0 && (n < 16 || n > 4096) {
			return Config{}, fmt.Errorf("config: lab.deny_message_length is %d: set 0 to leave the deny message "+
				"as it is, or 16 to 4096", n)
		}
		if len(c.Lab.SeedTokens) > 0 && c.Lab.SeedTokenFile == "" {
			return Config{}, fmt.Errorf("config: lab.seed_token_file is required when lab.seed_tokens is non-empty: " +
				"port49d mints each seed's secret at start and has to put it somewhere an operator can read " +
				"and nothing else can — a 0600 file, never a stream")
		}
	}

	if role == RoleBroker && f.Broker == nil {
		return Config{}, errors.New("config: broker: is required in port49-broker.yaml: its listener, TLS files, " +
			"policy_file and state_dir (plan 7e, Ruling 2)")
	}
	if f.Broker != nil {
		if c.Broker, err = checkBroker(c, *f.Broker, role); err != nil {
			return Config{}, err
		}
	}
	switch {
	case f.Policy != nil && f.Broker != nil:
		// Under the broker's role brokerRefusals has refused policy: already.
		return Config{}, errors.New("config: policy: beside a broker: block: the in-process broker's policy is " +
			"broker.policy_file; remove policy:")
	case f.Broker != nil:
		c.Policy = &PolicyConfig{File: c.Broker.PolicyFile, WatchInterval: c.Broker.PolicyWatchInterval}
	case f.Policy != nil:
		p := PolicyConfig{File: f.Policy.File, WatchInterval: orD(f.Policy.WatchInterval, 5*time.Second)}
		if p.File == "" {
			// On etcd policy: is required, so removing it is no fix there.
			fix := ""
			if or(f.Store.Backend, BackendMemory) == BackendMemory {
				fix = ", or remove the block to run port49d on inventory_file's key groups"
			}
			return Config{}, fmt.Errorf("config: policy.file is required when policy: is present: name the policy "+
				"file port49d admits from%s", fix)
		}
		if p.WatchInterval < time.Second || p.WatchInterval > 5*time.Minute {
			return Config{}, fmt.Errorf("config: policy.watch_interval must be between 1s and 5m; got %s",
				p.WatchInterval)
		}
		c.Policy = &p
	}
	if c.Store, err = checkStore(f.Store, role, f.Broker != nil, f.Policy != nil, f.AdminSocket != ""); err != nil {
		return Config{}, fmt.Errorf("config: %w", err)
	}
	if role == RoleDaemon && c.Store.Backend == BackendEtcd && c.Lab != nil && len(c.Lab.SeedTokens) > 0 {
		return Config{}, errors.New("config: lab.seed_tokens: lab seed tokens are minted by port49-broker on etcd; " +
			"move lab.seed_tokens and lab.seed_token_file into port49-broker.yaml (plan 7e)")
	}

	if role == RoleBroker {
		if c.keyRefs, err = checkKeyRefList(f.KeyRefs); err != nil {
			return Config{}, err
		}
	} else if err := resolveKeys(&c, raw); err != nil {
		return Config{}, err
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
		if k.ref.ID != "" && !KeyIDShape.MatchString(k.ref.ID) {
			// Not printed: whatever the operator wrote, a line must not carry
			// it. Checked first, so no later refusal in this loop echoes an
			// id outside the charset.
			return Config{}, fmt.Errorf("config: %s: id must be 1 to 64 of A-Z a-z 0-9 . _ -: it is written "+
				"into every record the key seals, and every line about a record that will not open names it", k.what)
		}
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
		if !envName.MatchString(k.ref.SecretEnv) {
			return Config{}, fmt.Errorf("config: %s: secret_env is not an environment variable name (letters, "+
				"digits and _): it names the variable holding the key, never the key", k.what)
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
			return Config{}, fmt.Errorf("config: %s (id %q): its secret_env names an environment variable that "+
				"is not set", k.what, k.ref.ID)
		}
		if len(s) != 32 {
			return Config{}, fmt.Errorf("config: %s (id %q): the variable its secret_env names must hold exactly "+
				"32 bytes for AES-256, got %d", k.what, k.ref.ID, len(s))
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

	if c.Policy != nil {
		// With a policy the inventory is live, and port49d reads it behind
		// the policy file's fence (fencedInventory, plan 6a C2), so it is not
		// read here at all: a plain read first would hang on a FIFO, or read
		// a link to a huge file whole, before the fence could refuse it. Key
		// groups are the policy's (spec §10), and port49d admits from the
		// policy loaded against that inventory, which refuses a device a group
		// cannot admit on its own, never the daemon (policy.Policy.Admission;
		// plan 6a Decided 5).
		return c, nil
	}
	rawInv, err := ReadRegular(c.InventoryFile, maxInventorySize)
	if err != nil {
		return Config{}, err
	}
	inv, err := admission.ParseFile(rawInv, c.InventoryFile)
	if err != nil {
		return Config{}, err
	}
	// Names and addresses are the inventory's own faults, and an inventory
	// that has one cannot be used at all: refused at start (spec §10).
	if err := admission.Validate(inv.Devices); err != nil {
		return Config{}, err
	}
	c.Inventory = inv
	// No broker: plan 1's mode, the lab's. The inventory's own key groups
	// are read once, here, and a device none admits refuses the start.
	for _, g := range inv.KeyGroups {
		if _, ok := c.Keys[g.KeyRef]; !ok {
			return Config{}, fmt.Errorf("config: key group references key_ref %q which is not in keys", g.KeyRef)
		}
	}
	for _, d := range inv.Devices {
		if d.KeyRef != "" && !admission.KeyRefShape.MatchString(d.KeyRef) {
			// Not printed: a pin that is not a name may be a secret.
			return Config{}, fmt.Errorf("config: device %q pins a key_ref that is not a valid key_ref name (%s)",
				d.Name, admission.KeyRefShapeRule)
		}
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
			// Admitted is Refused == "", never an index hit or a key_ref
			// alone (Task 3 review M3).
			if r, ok := trie.Lookup(a); ok && r.Refused == "" && r.KeyRef != "" {
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

// daemonDefaults fills what port49d alone has: the TACACS+ listener, the
// receipt bounds, the limits and the accounting spool.
func daemonDefaults(c *Config, f fileConfig) error {
	malformedWindow, err := window("malformed_window", f.Limits.MalformedWindow)
	if err != nil {
		return err
	}
	authFailureWindow, err := window("auth_failure_window", f.Limits.AuthFailureWindow)
	if err != nil {
		return err
	}
	c.Listen = or(f.Listen, ":49")
	c.ReceiptIdleTTL = orD(f.ReceiptIdleTTL, 15*time.Minute)
	c.ReceiptMaxAge = orD(f.ReceiptMaxAge, 2*time.Hour)
	c.Accounting = f.Accounting
	c.Limits = limits.Config{
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
	}
	if c.Accounting.SpoolCapacity == 0 {
		c.Accounting.SpoolCapacity = 10000
	}
	if c.Accounting.SpoolPath == "" {
		c.Accounting.SpoolPath = defaultSpoolPath
	}
	return nil
}

// resolveKeys checks keys: and reads each version's secret from the
// environment (port49d's role), and notes an accept version with no
// retire_after or one past it.
func resolveKeys(c *Config, raw []byte) error {
	var err error
	if c.Keys, err = checkKeySets(c.Keys, raw); err != nil {
		return err
	}
	for ref, ks := range c.Keys {
		for _, v := range allVersions(ks) {
			s, ok := os.LookupEnv(v.SecretEnv)
			if !ok || s == "" {
				return fmt.Errorf("config: key %s version %d: its secret_env names an environment variable "+
					"that is not set", ref, v.Version)
			}
			c.secrets[v.SecretEnv] = s
		}
	}
	now := time.Now()
	for _, ref := range sortedKeySets(c.Keys) {
		for _, v := range c.Keys[ref].Accept {
			switch {
			case v.RetireAt.IsZero():
				c.Notices = append(c.Notices, fmt.Sprintf("key %s version %d has no retire_after; an indefinitely "+
					"accepted version is what rotation exists to prevent (spec §10)", ref, v.Version))
			case !now.Before(v.RetireAt):
				c.Notices = append(c.Notices, fmt.Sprintf("key %s version %d: retire_after %s has passed, so it "+
					"identifies devices and admits none; move it to retired, or remove it", ref, v.Version, v.RetireAfter))
			}
		}
	}
	return nil
}

// checkBroker checks a broker: block and applies its defaults. Under the
// broker's role broker.state_dir takes the revocations file's place
// (Ruling 12): required, absolute, a directory that exists.
func checkBroker(c Config, b BrokerConfig, role Role) (*BrokerConfig, error) {
	required := []struct{ key, v string }{
		{"broker.listen", b.Listen}, {"broker.tls_cert_file", b.TLSCertFile}, {"broker.tls_key_file", b.TLSKeyFile},
		{"broker.client_ca_file", b.ClientCAFile}, {"broker.policy_file", b.PolicyFile},
	}
	fix := "is required when broker: is present; remove the block to run port49d without a broker"
	if role == RoleBroker {
		required = append(required, struct{ key, v string }{"broker.state_dir", b.StateDir})
		fix = "is required in port49-broker.yaml"
	} else {
		required = append(required, struct{ key, v string }{"broker.revocations_file", b.RevocationsFile})
	}
	for _, req := range required {
		if req.v == "" {
			return nil, fmt.Errorf("config: %s %s", req.key, fix)
		}
	}
	if role == RoleBroker {
		if !filepath.IsAbs(b.StateDir) {
			return nil, errors.New("config: broker.state_dir must be an absolute path")
		}
		fi, err := os.Stat(b.StateDir)
		if err != nil || !fi.IsDir() {
			return nil, fmt.Errorf("config: broker.state_dir %s must be a directory that exists: port49-broker keeps "+
				"its verified CRLs there; create it, owned by port49-broker's user, mode 0700", b.StateDir)
		}
		// Fenced as broker.revocations_file is (ownRevocationsFile): what
		// the broker keeps there is its own, so no other user may write the
		// directory. Group read, as a 0750 volume mount has, is no write.
		if fi.Mode().Perm()&0o022 != 0 {
			return nil, fmt.Errorf("config: broker.state_dir %s is writable by its group or others (mode %04o): "+
				"port49-broker's own state is kept there; chmod 0700 it", b.StateDir, fi.Mode().Perm())
		}
		// Nor inside, nor around, a directory the inventory service and
		// port49d rewrite.
		if svc := c.InventoryService; svc != nil {
			for _, d := range []struct{ key, dir string }{{"inventory.service.state_dir", svc.StateDir},
				{"inventory.service.mirror_dir", svc.MirrorDir}} {
				if d.dir != "" && (within(d.dir, b.StateDir) || within(b.StateDir, d.dir)) {
					return nil, fmt.Errorf("config: broker.state_dir is port49-broker's own state and may not be "+
						"inside %s, nor hold it: give each its own directory", d.key)
				}
			}
		}
	}
	b.BatchMax = orI(b.BatchMax, 100)
	if b.BatchMax < 1 || b.BatchMax > 1000 {
		return nil, fmt.Errorf("config: broker.batch_max must be between 1 and 1000; got %d", b.BatchMax)
	}
	b.PolicyWatchInterval = orD(b.PolicyWatchInterval, 5*time.Second)
	if b.PolicyWatchInterval < time.Second || b.PolicyWatchInterval > 5*time.Minute {
		return nil, fmt.Errorf("config: broker.policy_watch_interval must be between 1s and 5m; got %s",
			b.PolicyWatchInterval)
	}
	// orI maps 0 alone to the default, so a negative value reaches the
	// bound and is refused.
	b.MaxConnsPerPrincipal = orI(b.MaxConnsPerPrincipal, 4)
	if b.MaxConnsPerPrincipal < 1 || b.MaxConnsPerPrincipal > 64 {
		return nil, fmt.Errorf("config: broker.max_conns_per_principal must be between 1 and 64; got %d",
			b.MaxConnsPerPrincipal)
	}
	b.MaxPendingConnsPerSource = orI(b.MaxPendingConnsPerSource, 16)
	if b.MaxPendingConnsPerSource < 1 || b.MaxPendingConnsPerSource > 256 {
		return nil, fmt.Errorf("config: broker.max_pending_conns_per_source must be between 1 and 256; got %d",
			b.MaxPendingConnsPerSource)
	}
	if role == RoleDaemon {
		if err := ownRevocationsFile(c, b); err != nil {
			return nil, err
		}
	}
	if b.CertificateStatus == nil {
		return nil, fmt.Errorf("config: broker.certificate_status is required when broker: is present: " +
			"name the CRLs or OCSP responder that say whether a client certificate is revoked, or set " +
			"certificate_status: {disabled: true} to check none (spec §5.1.4)")
	}
	cs := *b.CertificateStatus
	if err := checkCertificateStatus(&cs, b); err != nil {
		return nil, err
	}
	b.CertificateStatus = &cs
	return &b, nil
}

// checkKeyRefList is key_refs, port49-broker.yaml's key names (plan 7e,
// Ruling 2): at least one, each a key_ref name (admission.KeyRefShape) and
// named once. One that is not a name is refused by its index and never
// printed, as checkKeyRefs refuses one under keys:. It returns them sorted.
func checkKeyRefList(refs []string) ([]string, error) {
	if len(refs) == 0 {
		return nil, errors.New("config: key_refs is required in port49-broker.yaml: the key_ref names a policy " +
			"may assign, as port49d.yaml's keys: names them, never their secrets (plan 7e)")
	}
	seen := map[string]bool{}
	for i, ref := range refs {
		if !admission.KeyRefShape.MatchString(ref) {
			return nil, fmt.Errorf("config: key_refs[%d] is not a valid key_ref name (%s): it names the key, never "+
				"holds it", i, admission.KeyRefShapeRule)
		}
		if seen[ref] {
			return nil, fmt.Errorf("config: key_refs[%d] %s is named twice; name each key once", i, ref)
		}
		seen[ref] = true
	}
	out := append([]string(nil), refs...)
	sort.Strings(out)
	return out, nil
}

// brokerRefusals refuses, by key, what a port49-broker.yaml must never name
// (plan 7e, Rulings 1, 2): the broker never speaks TACACS+, never holds a
// device key or the daemon's etcd identity, and on etcd keeps no
// revocations file.
func brokerRefusals(f fileConfig) error {
	lab := f.Lab
	if lab == nil {
		lab = &LabConfig{}
	}
	for _, c := range []struct {
		key string
		set bool
		why string
	}{
		{"listen", f.Listen != "", "port49-broker never speaks TACACS+; that is port49d's"},
		{"keys:", len(f.Keys) > 0, "device keys are port49d's alone; name the key references under key_refs"},
		{"accounting", f.Accounting != (AccountingConfig{}), "accounting is port49d's"},
		{"limits", f.Limits != (limitsYAML{}), "TACACS+ limits are port49d's"},
		{"receipt_idle_ttl", f.ReceiptIdleTTL != 0, "receipts are port49d's"},
		{"receipt_max_age", f.ReceiptMaxAge != 0, "receipts are port49d's"},
		{"platforms", len(f.Platforms) > 0, "session services are port49d's"},
		{"policy:", f.Policy != nil, "port49-broker's policy is broker.policy_file"},
		{"broker.revocations_file", f.Broker != nil && f.Broker.RevocationsFile != "",
			"on etcd the store keeps the marks (decision 36); remove it"},
		{"store.etcd.daemon", f.Store.Etcd != nil && (f.Store.Etcd.Daemon != EtcdIdentity{}),
			"the daemon's etcd identity is port49d's alone"},
		{"lab.fault_file", lab.FaultFile != "", "the lab's fault switch is port49d's"},
		{"lab.session_attributes", len(lab.SessionAttributes) > 0, "the lab's answers are port49d's"},
		{"lab.command_attributes", len(lab.CommandAttributes) > 0, "the lab's answers are port49d's"},
		{"lab.deny_prefixes", len(lab.DenyPrefixes) > 0, "the lab's answers are port49d's"},
		{"lab.deny_message_length", lab.DenyMessageLength != 0, "the lab's answers are port49d's"},
		{"lab.deny_session", lab.DenySession, "the lab's answers are port49d's"},
	} {
		if c.set {
			return fmt.Errorf("config: %s is not port49-broker.yaml's: %s (plan 7e)", c.key, c.why)
		}
	}
	return nil
}

// KeyRefs names every key_ref keys defines, or under the broker's role
// key_refs names, sorted and never nil: a device the policy assigns any
// other is refused admission (spec §10). Names only.
func (c Config) KeyRefs() []string {
	if c.Role == RoleBroker {
		return append(make([]string, 0, len(c.keyRefs)), c.keyRefs...)
	}
	out := make([]string, 0, len(c.Keys))
	for ref := range c.Keys {
		out = append(out, ref)
	}
	sort.Strings(out)
	return out
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
			set.Versions = append(set.Versions, keyring.Version{Number: v.Version, Secret: []byte(c.secrets[v.SecretEnv]),
				RetireAt: v.RetireAt})
		}
		for _, v := range ks.Retired {
			set.Versions = append(set.Versions, keyring.Version{Number: v.Version, Secret: []byte(c.secrets[v.SecretEnv]), Retired: true})
		}
		out[ref] = set
	}
	return out
}

// checkKeySets validates keys without reading a secret: every version
// numbered from 1 and once, a secret_env named, and retire_after a date on an
// accept version only. It returns the sets with RetireAt filled.
func checkKeySets(keys map[string]KeySet, raw []byte) (map[string]KeySet, error) {
	if err := checkKeyRefs(keys, raw); err != nil {
		return nil, err
	}
	out := make(map[string]KeySet, len(keys))
	for ref, ks := range keys {
		seen := map[int]bool{}
		for _, v := range allVersions(ks) {
			if v.Version < 1 {
				return nil, fmt.Errorf("config: key %s: every version number must be 1 or greater", ref)
			}
			if seen[v.Version] {
				return nil, fmt.Errorf("config: key %s: version %d appears twice", ref, v.Version)
			}
			seen[v.Version] = true
			if v.SecretEnv == "" {
				return nil, fmt.Errorf("config: key %s version %d: secret_env is required", ref, v.Version)
			}
			if !envName.MatchString(v.SecretEnv) {
				return nil, fmt.Errorf("config: key %s version %d: secret_env is not an environment variable name "+
					"(letters, digits and _): it names the variable holding the secret, never the secret", ref, v.Version)
			}
		}
		if ks.Current.RetireAfter != "" {
			return nil, fmt.Errorf("config: key %s: current version %d has retire_after; current is what devices "+
				"are provisioned with, so retire it by making another version current (spec §10)", ref, ks.Current.Version)
		}
		for _, v := range ks.Retired {
			if v.RetireAfter != "" {
				return nil, fmt.Errorf("config: key %s: retired version %d has retire_after; a retired version is "+
					"refused already", ref, v.Version)
			}
		}
		accept := make([]KeyVersion, len(ks.Accept))
		for i, v := range ks.Accept {
			if v.RetireAfter != "" {
				day, err := time.Parse("2006-01-02", v.RetireAfter)
				if err != nil {
					return nil, fmt.Errorf("config: key %s version %d: retire_after is not a date (YYYY-MM-DD)",
						ref, v.Version)
				}
				v.RetireAt = day.AddDate(0, 0, 1) // admits through the named day, UTC
			}
			accept[i] = v
		}
		ks.Accept = accept
		out[ref] = ks
	}
	return out, nil
}

// KeySets reads port49d.yaml's keys: block as Load does, without reading a
// secret: the names, versions and dates `port49 keys status` and `port49
// policy test --config` read, in CI or anywhere else no key is.
func KeySets(raw []byte) (map[string]KeySet, error) {
	var f fileConfig
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil && err != io.EOF {
		return nil, fmt.Errorf("config: %w; check the key spelling against the port49d.yaml schema", decodeFault(err))
	}
	return checkKeySets(f.Keys, raw)
}

// checkKeyRefs refuses a key under keys: that is not a key_ref name
// (admission.KeyRefShape), by its line in raw and never by the name: every
// report prints a key_ref, and one that is not a name is most likely a secret.
func checkKeyRefs(keys map[string]KeySet, raw []byte) error {
	var bad []string
	for ref := range keys {
		if !admission.KeyRefShape.MatchString(ref) {
			bad = append(bad, ref)
		}
	}
	if len(bad) == 0 {
		return nil
	}
	line := 0
	var doc yaml.Node
	if yaml.Unmarshal(raw, &doc) == nil && len(doc.Content) == 1 {
		top := doc.Content[0]
		for i := 0; i+1 < len(top.Content); i += 2 {
			if top.Content[i].Value != "keys" {
				continue
			}
			for j, keys := 0, top.Content[i+1]; j+1 < len(keys.Content); j += 2 {
				if !admission.KeyRefShape.MatchString(keys.Content[j].Value) && (line == 0 || keys.Content[j].Line < line) {
					line = keys.Content[j].Line
				}
			}
		}
	}
	where := "a key under keys:"
	if line > 0 {
		where = fmt.Sprintf("a key under keys: on line %d", line)
	}
	return fmt.Errorf("config: %s is not a valid key_ref name (%s): it names the key, never holds it",
		where, admission.KeyRefShapeRule)
}

// checkService is inventory.service checked as Load checks it. Every path is
// required to be absolute, and named by its key when it is not: port49d's
// working directory is not a place its trust roots should depend on. ca_file
// above all is required — without it RootCAs would be nil, which Go reads as
// the host's roots, and any public CA could vouch for the service.
func checkService(s InventoryServiceConfig) (*InventoryServiceConfig, error) {
	// What the client (internal/inventory) refuses, refused at load: no
	// user information, where a credential would sit, and no path, query or
	// fragment, where a token would be pasted. None is printed.
	if u, err := url.Parse(s.URL); err != nil || u.Scheme != "https" || u.Host == "" || u.Opaque != "" ||
		u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, fmt.Errorf("config: inventory.service.url must be https://host[:port], with no user " +
			"information, path, query or fragment")
	}
	for _, req := range []struct{ key, v string }{{"ca_file", s.CAFile}, {"tls_cert_file", s.TLSCertFile},
		{"tls_key_file", s.TLSKeyFile}, {"state_dir", s.StateDir}} {
		if req.v == "" {
			return nil, fmt.Errorf("config: inventory.service.%s is required", req.key)
		}
		if !filepath.IsAbs(req.v) {
			return nil, fmt.Errorf("config: inventory.service.%s must be an absolute path", req.key)
		}
	}
	if s.MirrorDir != "" && !filepath.IsAbs(s.MirrorDir) {
		return nil, fmt.Errorf("config: inventory.service.mirror_dir must be an absolute path")
	}
	// As the service refuses them (internal/inventory's config): the mirror is
	// a separate copy, and neither directory is a part of the other.
	if s.MirrorDir != "" && within(s.StateDir, s.MirrorDir) {
		return nil, fmt.Errorf("config: inventory.service.mirror_dir must be outside state_dir; the mirror is a " +
			"separate copy, not a part of the state")
	}
	if s.MirrorDir != "" && within(s.MirrorDir, s.StateDir) {
		return nil, fmt.Errorf("config: inventory.service.state_dir must be outside mirror_dir; the mirror is a " +
			"separate copy, and the state is not a part of it")
	}
	if len(s.VerifyKeyFiles) == 0 {
		return nil, fmt.Errorf("config: inventory.service.verify_key_files must name the service's signing public " +
			"key (port49 inventory keygen writes it)")
	}
	for i, f := range s.VerifyKeyFiles {
		if !filepath.IsAbs(f) {
			return nil, fmt.Errorf("config: inventory.service.verify_key_files[%d] must be an absolute path", i)
		}
	}
	if _, err := VerifyKeys(s.VerifyKeyFiles); err != nil {
		return nil, err
	}
	s.PollInterval = orD(s.PollInterval, 30*time.Second)
	if s.PollInterval < 5*time.Second || s.PollInterval > 10*time.Minute {
		return nil, fmt.Errorf("config: inventory.service.poll_interval must be between 5s and 10m; got %s",
			s.PollInterval)
	}
	return &s, nil
}

// ownRevocationsFile refuses a broker.revocations_file that is another path
// port49d reads or writes, compared as absolute paths (pre-flight M13):
// written over the policy or a key it would destroy it, and a file shared
// with another writer is not the record of revocations. Its marker
// (<file>.created), which init-revocations creates and a start writes beside
// a file that loads, is held to the same. Nor may it sit in the inventory
// service's state or mirror directory, whose files the service and port49d
// rewrite.
func ownRevocationsFile(c Config, b BrokerConfig) error {
	revAbs, err := filepath.Abs(b.RevocationsFile)
	if err != nil {
		return fmt.Errorf("config: broker.revocations_file: %w", err)
	}
	others := []struct{ key, path string }{
		{"broker.policy_file", b.PolicyFile}, {"broker.tls_cert_file", b.TLSCertFile},
		{"broker.tls_key_file", b.TLSKeyFile}, {"broker.client_ca_file", b.ClientCAFile},
		{"inventory_file", c.InventoryFile}, {"accounting.spool_path", c.Accounting.SpoolPath},
		{"admin_socket", c.AdminSocket},
	}
	if c.Lab != nil {
		others = append(others, struct{ key, path string }{"lab.seed_token_file", c.Lab.SeedTokenFile},
			struct{ key, path string }{"lab.fault_file", c.Lab.FaultFile})
	}
	if s := c.InventoryService; s != nil {
		others = append(others, struct{ key, path string }{"inventory.service.ca_file", s.CAFile},
			struct{ key, path string }{"inventory.service.tls_cert_file", s.TLSCertFile},
			struct{ key, path string }{"inventory.service.tls_key_file", s.TLSKeyFile})
		for i, f := range s.VerifyKeyFiles {
			others = append(others, struct{ key, path string }{fmt.Sprintf("inventory.service.verify_key_files[%d]", i), f})
		}
	}
	for _, o := range others {
		if o.path == "" {
			continue
		}
		oAbs, err := filepath.Abs(o.path)
		if err != nil {
			continue
		}
		switch oAbs {
		case revAbs:
			return fmt.Errorf("config: broker.revocations_file is port49d's own state and may not be %s", o.key)
		case revAbs + ".created":
			return fmt.Errorf("config: broker.revocations_file's marker (%s.created) is port49d's own state and "+
				"may not be %s", filepath.Base(revAbs), o.key)
		}
	}
	if s := c.InventoryService; s != nil {
		for _, d := range []struct{ key, dir string }{{"inventory.service.state_dir", s.StateDir},
			{"inventory.service.mirror_dir", s.MirrorDir}} {
			if d.dir != "" && within(d.dir, revAbs) {
				return fmt.Errorf("config: broker.revocations_file is port49d's own state and may not be inside %s",
					d.key)
			}
		}
	}
	return nil
}

// crlName is a CRL source's name: it names the kept list's file and the
// crl_next_update metric's label.
var crlName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// checkCertificateStatus checks broker.certificate_status and applies its
// defaults in place. A refusal names the key, and never repeats a URL,
// which may carry a credential.
func checkCertificateStatus(cs *CertificateStatusConfig, b BrokerConfig) error {
	const key = "broker.certificate_status"
	if cs.Disabled {
		// Every other key does nothing beside it, and one an operator reads
		// as meaningful (on_unavailable: allow, say) is refused, not ignored.
		var dead []string
		for _, k := range []struct {
			name string
			set  bool
		}{{"crls", cs.CRLs != nil}, {"ocsp", cs.OCSP != nil}, {"refresh_interval", cs.RefreshInterval != 0},
			{"on_unavailable", cs.OnUnavailable != ""}} {
			if k.set {
				dead = append(dead, key+"."+k.name)
			}
		}
		if len(dead) > 0 {
			return fmt.Errorf("config: %s.disabled is true beside %s, which then do nothing: remove them, or "+
				"disabled", key, strings.Join(dead, ", "))
		}
		return nil
	}
	if len(cs.CRLs) == 0 && cs.OCSP == nil {
		return fmt.Errorf("config: %s: name at least one crls entry or an ocsp block, or set disabled: true", key)
	}
	// The kept lists sit in broker.state_dir under the broker's role, and
	// beside broker.revocations_file under the daemon's (plan 7e, Ruling 12).
	stateDir := b.StateDir
	if stateDir == "" {
		revAbs, err := filepath.Abs(b.RevocationsFile)
		if err != nil {
			return fmt.Errorf("config: broker.revocations_file: %w", err)
		}
		stateDir = filepath.Dir(revAbs)
	}
	seen := map[string]bool{}
	for i, src := range cs.CRLs {
		at := fmt.Sprintf("%s.crls[%d]", key, i)
		switch {
		case !crlName.MatchString(src.Name):
			return fmt.Errorf("config: %s.name must match %s", at, crlName)
		case seen[src.Name]:
			return fmt.Errorf("config: %s.name %s names another source too; each is kept under its own name", at,
				src.Name)
		case (src.File == "") == (src.URL == ""):
			return fmt.Errorf("config: %s: set exactly one of file and url", at)
		case src.URL != "" && !httpURL(src.URL):
			return fmt.Errorf("config: %s.url must be an http or https URL with a host", at)
		case src.IssuerFile == "":
			return fmt.Errorf("config: %s.issuer_file is required: the CA certificate that signs the list", at)
		}
		seen[src.Name] = true
		// The kept list is port49d's own state, written beside the
		// revocations file: it may be no file an operator gave it.
		kept := filepath.Join(stateDir, "crl-"+src.Name+".der")
		marker := ""
		if b.RevocationsFile != "" {
			marker = b.RevocationsFile + ".created"
		}
		for _, o := range []struct{ key, path string }{
			{"broker.revocations_file", b.RevocationsFile}, {"broker.revocations_file's marker", marker},
			{"broker.policy_file", b.PolicyFile}, {"broker.tls_cert_file", b.TLSCertFile},
			{"broker.tls_key_file", b.TLSKeyFile}, {"broker.client_ca_file", b.ClientCAFile},
			{at + ".file", src.File}, {at + ".issuer_file", src.IssuerFile},
		} {
			if o.path == "" {
				continue
			}
			if oAbs, err := filepath.Abs(o.path); err == nil && oAbs == kept {
				return fmt.Errorf("config: %s.name %s: its kept list, %s, would be %s", at, src.Name, kept, o.key)
			}
		}
	}
	if cs.OCSP != nil {
		oc := *cs.OCSP
		o := &oc
		switch {
		case o.Responder == "" && !o.UseAIA:
			return fmt.Errorf("config: %s.ocsp: set responder, or use_aia: true to ask each certificate's own", key)
		case o.Responder != "" && !httpURL(o.Responder):
			return fmt.Errorf("config: %s.ocsp.responder must be an http or https URL with a host", key)
		}
		o.Timeout = orD(o.Timeout, 2*time.Second)
		if o.Timeout < 100*time.Millisecond || o.Timeout > 10*time.Second {
			return fmt.Errorf("config: %s.ocsp.timeout must be between 100ms and 10s; got %s", key, o.Timeout)
		}
		switch o.Hash {
		case "":
			o.Hash = "sha256"
		case "sha256", "sha1":
		default:
			return fmt.Errorf("config: %s.ocsp.hash must be sha256 or sha1 (the CertID hash alone); got %q", key,
				o.Hash)
		}
		cs.OCSP = o
	}
	cs.RefreshInterval = orD(cs.RefreshInterval, 10*time.Minute)
	if cs.RefreshInterval < time.Minute || cs.RefreshInterval > 24*time.Hour {
		return fmt.Errorf("config: %s.refresh_interval must be between 1m and 24h; got %s", key, cs.RefreshInterval)
	}
	switch cs.OnUnavailable {
	case "":
		cs.OnUnavailable = "refuse"
	case "refuse", "allow":
	default:
		return fmt.Errorf("config: %s.on_unavailable must be refuse or allow; got %q", key, cs.OnUnavailable)
	}
	return nil
}

// httpURL is whether s is an http or https URL with a host, the only kind a
// status source is fetched over.
func httpURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

// within reports whether dir is base or a directory under it.
func within(base, dir string) bool {
	rel, err := filepath.Rel(filepath.Clean(base), filepath.Clean(dir))
	return err == nil && (rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))))
}

// VerifyKeys reads each verify key file behind the write fence (pre-flight
// M3): a verify key is the trust root of the bundle's signature, so whoever
// could write it would have any inventory they sign accepted — from the
// mirror, the persisted copy and the API alike. One that does not read is
// named by its position and path.
func VerifyKeys(files []string) ([]ed25519.PublicKey, error) {
	keys, err := fence.ReadVerifyKeys("inventory.service.verify_key_files", files)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return keys, nil
}

// InventoryServiceOf is inventory.service from a port49d.yaml's bytes,
// decoded as strictly as Load and checked as Load checks it, or nil when the
// file has none: what SIGHUP re-reads verify_key_files from. It resolves no
// secret.
func InventoryServiceOf(raw []byte) (*InventoryServiceConfig, error) {
	var f fileConfig
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil && err != io.EOF {
		return nil, fmt.Errorf("config: %w; check the key spelling against the port49d.yaml schema", decodeFault(err))
	}
	if f.InventoryOpts.Service == nil {
		return nil, nil
	}
	return checkService(*f.InventoryOpts.Service)
}

// decodeFault is a port49d.yaml decode error as it is shown: each fault's
// line and a fixed category, and no text from the document (yamlfault).
func decodeFault(err error) error { return yamlfault.Of(err) }

// checkStoreShape resolves `store:` (plan 7d; spec §13, decision 35): the
// backend, the packet deadline, and on etcd every key's default and
// bound. It holds every check that is not a role's, and refuses what
// would run unsafely in any file:
//   - an endpoint that is not https;
//   - a file an identity names absent, or a certificate whose CN is root.
//
// Either identity may be named or absent: which a file must name is its
// role's (checkStore). A key file's mode, owner and symlink are refused
// where it is read, by internal/keyfile (Task 12).
func checkStoreShape(s storeYAML) (StoreConfig, error) {
	out := StoreConfig{Backend: or(s.Backend, BackendMemory), PacketDeadline: orD(s.PacketDeadline, 2*time.Second)}
	if out.PacketDeadline < 100*time.Millisecond || out.PacketDeadline > 2*time.Second {
		return StoreConfig{}, fmt.Errorf("store.packet_deadline %v: must be 100ms to 2s, so a device hears port49's "+
			"answer before its own TACACS+ timeout, which is about 3s on Junos (spec §15, L13)", out.PacketDeadline)
	}
	switch out.Backend {
	case BackendMemory:
		if s.Etcd != nil {
			return StoreConfig{}, errors.New("store.etcd is set but store.backend is memory: say store.backend: etcd, " +
				"or remove store.etcd")
		}
		return out, nil
	case BackendEtcd:
	default:
		return StoreConfig{}, fmt.Errorf("store.backend %q: must be memory or etcd", s.Backend)
	}
	if s.Etcd == nil {
		return StoreConfig{}, errors.New("store.backend is etcd and store.etcd is missing")
	}
	e := *s.Etcd
	if len(e.Endpoints) == 0 {
		return StoreConfig{}, errors.New("store.etcd.endpoints is empty")
	}
	// As checkService: no user information, where a credential would sit,
	// and no path, query or fragment, where a token would be pasted. None
	// is printed; the index names the endpoint.
	for i, ep := range e.Endpoints {
		u, err := url.Parse(ep)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.Opaque != "" || u.User != nil ||
			(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
			return StoreConfig{}, fmt.Errorf("store.etcd.endpoints[%d] must be https://host:port, with no user "+
				"information, path, query or fragment: port49d authenticates to etcd by client certificate "+
				"(decision 35)", i)
		}
	}
	e.Prefix = or(e.Prefix, "/port49/")
	if !strings.HasPrefix(e.Prefix, "/") {
		return StoreConfig{}, fmt.Errorf("store.etcd.prefix %q: must start with /", e.Prefix)
	}
	if !strings.HasSuffix(e.Prefix, "/") {
		e.Prefix += "/"
	}
	if err := readableFile("store.etcd.ca_file", e.CAFile); err != nil {
		return StoreConfig{}, err
	}
	var ids []struct {
		name string
		id   EtcdIdentity
	}
	if e.Daemon != (EtcdIdentity{}) {
		ids = append(ids, struct {
			name string
			id   EtcdIdentity
		}{"store.etcd.daemon", e.Daemon})
	}
	if e.Broker != nil {
		ids = append(ids, struct {
			name string
			id   EtcdIdentity
		}{"store.etcd.broker", *e.Broker})
	}
	for _, id := range ids {
		for _, f := range [][2]string{{".cert_file", id.id.CertFile}, {".key_file", id.id.KeyFile}} {
			if err := readableFile(id.name+f[0], f[1]); err != nil {
				return StoreConfig{}, err
			}
		}
		// etcd takes a client certificate's CN as its user, and root is
		// its administrator, past every role (Ruling T11-a).
		if certCN(id.id.CertFile) == "root" {
			return StoreConfig{}, fmt.Errorf("%s.cert_file: its CN is \"root\", etcd's administrator, which "+
				"bypasses every role: give the component a certificate of its own (decision 35)", id.name)
		}
	}
	switch e.Roles = or(e.Roles, RolesEnforced); e.Roles {
	case RolesEnforced, RolesUnenforced:
	default:
		return StoreConfig{}, fmt.Errorf("store.etcd.roles %q: must be enforced or unenforced", e.Roles)
	}
	for _, d := range []struct {
		name     string
		v        *time.Duration
		def      time.Duration
		min, max time.Duration
	}{
		{"store.etcd.call_timeout", &e.CallTimeout, 500 * time.Millisecond, 10 * time.Millisecond, 5 * time.Second},
		{"store.etcd.bulk_timeout", &e.BulkTimeout, 30 * time.Second, time.Second, 5 * time.Minute},
		{"store.etcd.breaker.open_for", &e.Breaker.OpenFor, 5 * time.Second, time.Second, 5 * time.Minute},
		{"store.etcd.lease_grace", &e.LeaseGrace, 5 * time.Minute, time.Minute, time.Hour},
		{"store.etcd.hold_ttl", &e.HoldTTL, 15 * time.Second, 10 * time.Second, time.Minute},
		{"store.etcd.sweep_interval", &e.SweepInterval, 10 * time.Minute, time.Minute, 24 * time.Hour},
	} {
		*d.v = orD(*d.v, d.def)
		if *d.v < d.min || *d.v > d.max {
			return StoreConfig{}, fmt.Errorf("%s %v: must be %v to %v", d.name, *d.v, d.min, d.max)
		}
	}
	// start_timeout: absent is 30s; 0 is wait forever (pre-flight I19).
	e.StartTimeout = 30 * time.Second
	if e.StartTimeoutSet != nil {
		e.StartTimeout = time.Duration(*e.StartTimeoutSet)
	}
	if e.StartTimeout != 0 && (e.StartTimeout < 5*time.Second || e.StartTimeout > 10*time.Minute) {
		return StoreConfig{}, fmt.Errorf("store.etcd.start_timeout %v: must be 0 (wait for as long as it takes), "+
			"or 5s to 10m", e.StartTimeout)
	}
	for _, n := range []struct {
		name          string
		v             *int
		def, min, max int
	}{
		{"store.etcd.breaker.failures", &e.Breaker.Failures, 5, 1, 100},
		{"store.etcd.max_in_flight.token", &e.MaxInFlight.Token, 64, 1, 4096},
		{"store.etcd.max_in_flight.context", &e.MaxInFlight.Context, 128, 1, 4096},
		{"store.etcd.max_in_flight.bulk", &e.MaxInFlight.Bulk, 4, 1, 4096},
	} {
		*n.v = orI(*n.v, n.def)
		if *n.v < n.min || *n.v > n.max {
			return StoreConfig{}, fmt.Errorf("%s %d: must be %d to %d", n.name, *n.v, n.min, n.max)
		}
	}
	if out.PacketDeadline < e.CallTimeout {
		return StoreConfig{}, fmt.Errorf("store.packet_deadline %v: must be at least store.etcd.call_timeout (%v)",
			out.PacketDeadline, e.CallTimeout)
	}
	out.Etcd = &e
	return out, nil
}

// checkStore is checkStoreShape and then the role's requirements (plan 7e,
// Rulings 1, 2): no host holds both etcd identities.
//   - port49d on etcd names its own identity alone, the policy it admits
//     from under policy:, and no broker: block;
//   - port49-broker names its own identity alone, and runs on etcd;
//   - either on etcd names admin_socket.
func checkStore(s storeYAML, role Role, hasBroker, hasPolicy, hasAdminSocket bool) (StoreConfig, error) {
	out, err := checkStoreShape(s)
	if err != nil {
		return StoreConfig{}, err
	}
	if out.Backend != BackendEtcd {
		if role == RoleBroker {
			return StoreConfig{}, errors.New("store.backend: port49-broker runs on etcd: with the memory store, run " +
				"the broker in port49d (a broker: block in port49d.yaml)")
		}
		return out, nil
	}
	e := out.Etcd
	switch role {
	case RoleBroker:
		if e.Broker == nil {
			return StoreConfig{}, errors.New("store.etcd.broker is missing: port49-broker authenticates to etcd as " +
				"itself (decision 35)")
		}
		if e.Daemon != (EtcdIdentity{}) {
			return StoreConfig{}, errors.New("store.etcd.daemon: the daemon's identity is port49d's alone; remove " +
				"it from port49-broker.yaml (plan 7e)")
		}
	default:
		if hasBroker {
			return StoreConfig{}, errors.New("store.backend: etcd runs the broker as its own process (plan 7e): " +
				"move the broker: block, with store.etcd.broker, into port49-broker.yaml and start port49-broker; " +
				"name the policy port49d admits from under policy: (file, watch_interval)")
		}
		if !hasPolicy {
			return StoreConfig{}, errors.New("store.backend etcd needs the policy port49d admits from: name it " +
				"under policy: (file, watch_interval) (plan 7e)")
		}
		if e.Broker != nil {
			return StoreConfig{}, errors.New("store.etcd.broker: the broker's identity is port49-broker's alone; " +
				"remove it from port49d.yaml (plan 7e)")
		}
		if e.Daemon == (EtcdIdentity{}) {
			return StoreConfig{}, errors.New("store.etcd.daemon is missing: port49d authenticates to etcd as " +
				"itself (decision 35)")
		}
	}
	if !hasAdminSocket {
		return StoreConfig{}, errors.New("store.backend etcd needs admin_socket: port49-broker's answers " +
			"'port49 revoke', the one way to lift a mark on etcd, and port49d's 'port49 keys diagnose' " +
			"(decision 35; plan 7e)")
	}
	return out, nil
}

// certCN is the subject CN of the first certificate in the PEM file at
// path, or "" when there is none or it does not parse: port49d's start
// names that (Task 12).
func certCN(path string) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	b, _ := pem.Decode(raw)
	if b == nil || b.Type != "CERTIFICATE" {
		return ""
	}
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return ""
	}
	return c.Subject.CommonName
}

// readableFile refuses a path that is empty, relative (port49d's working
// directory is not a place its trust roots should depend on, as
// checkService says), or not a regular file. A private key's mode and
// owner are keyfile's, at the read (Task 12).
func readableFile(name, path string) error {
	if path == "" {
		return fmt.Errorf("%s is missing", name)
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("%s must be an absolute path", name)
	}
	fi, err := os.Stat(path)
	if err != nil {
		var pe *fs.PathError
		if errors.As(err, &pe) {
			err = pe.Err // the path is printed once, below
		}
		return fmt.Errorf("%s %s: %w", name, path, err)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s %s: not a regular file", name, path)
	}
	return nil
}

// StoreBlocks is `store:` from either file's bytes, port49d.yaml's or
// port49-broker.yaml's, decoded as strictly as Load (the stale seed keys
// first, as Load refuses them) and checked for its shape alone
// (checkStoreShape): either identity may be named or absent (plan 7e,
// pre-flight I8). It is for `port49d store-roles`, which reads nothing
// else, and which reads a 7d port49d.yaml naming both identities that
// Load under the daemon's role refuses.
func StoreBlocks(raw []byte) (StoreConfig, error) {
	if err := staleSeedKeys(raw); err != nil {
		return StoreConfig{}, err
	}
	var f fileConfig
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil && err != io.EOF {
		return StoreConfig{}, fmt.Errorf("config: %w; check the key spelling against the port49d.yaml schema", decodeFault(err))
	}
	s, err := checkStoreShape(f.Store)
	if err != nil {
		return StoreConfig{}, fmt.Errorf("config: %w", err)
	}
	return s, nil
}

// envName is what an environment variable's name looks like. A secret_env
// that is not one is refused without being printed: it is most likely the
// secret, pasted where its variable's name goes.
var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// KeyIDShape is an encryption key id: what crypt seals into every record's
// header and what every line about a record that will not open names
// (crypt.LineKeyID prints anything else as "?"). Plan 7e, Ruling 15.
var KeyIDShape = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// sortedKeySets names keys' refs, sorted, so the start notices read the same
// every time.
func sortedKeySets(keys map[string]KeySet) []string {
	out := make([]string, 0, len(keys))
	for ref := range keys {
		out = append(out, ref)
	}
	sort.Strings(out)
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

// moveEnableUsernames handles platforms.<name>.enable_username, which is an
// adapter fact: since plan 5 adapters live in the policy file's `platforms:`
// block, where `port49 policy test` reads it as port49d does, and a key here
// would be one CI never sees (plan 4 pre-flight N5). `principal`, the default
// and the only value config.Load ever accepted, still loads with a notice, so
// the upgrade is not an outage; any other value is refused by name.
func moveEnableUsernames(c *Config, overrides map[string]PlatformConfig) error {
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
		moved := fmt.Sprintf("platforms.%s.enable_username moved to the policy file in plan 5: write it under "+
			"`platforms: {%s: {enable_username: ...}}` there, where `port49 policy test` reads it as port49d does",
			name, name)
		if v == platform.EnableEnab {
			// Told only to move it, the operator would learn on the second
			// try that the policy file refuses it too (task 8 review minor 1).
			return fmt.Errorf("config: %s; enab is refused there too until a tests/lab/results/ note shows a "+
				"device sending it (spec §7, L3), so delete the line", moved)
		}
		if v != platform.EnablePrincipal {
			return fmt.Errorf("config: %s", moved)
		}
		c.Notices = append(c.Notices, moved+"; principal is the default, so delete the line")
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
	if c.Role == RoleBroker {
		return nil // the rest is port49d's, which port49-broker.yaml refuses (brokerRefusals)
	}
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
