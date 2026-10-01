// Package inventory is port49-inventory (spec §10, "The inventory service"):
// its configuration, its sources, the syncer that bounds and publishes the
// signed bundle document, its state directory and mirror, and its mutual-TLS
// API; and the client port49d and the port49 tool read that API with.
package inventory

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/bundle"
	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/sot"
	"github.com/rhwendt/port49/internal/yamlfault"
)

// SourceConfig is one entry of sync: (spec §10, "Connectors and sync
// cadence"): a file source (plan 6b), or a netbox or nautobot source (plan
// 6c, decision 31).
type SourceConfig struct {
	Name, Type, Path string
	// Interval is how often this source is synced (spec §10), default the
	// top-level interval.
	Interval          time.Duration
	MaxRemovedPercent int
	// The netbox and nautobot sources': where and how the source is read,
	// and, when it takes webhooks, the secret its deliveries are signed
	// with. Token and WebhookSecret print as <redacted>.
	URL, CAFile, Profile, API string
	PageSize                  int
	Token, WebhookSecret      sot.Secret
	Mapping                   sot.Mapping
}

// Config is port49-inventory.yaml. Every path is read at start; nothing in
// it is a secret — the TLS and signing keys are files read through keyfile.
type Config struct {
	// Listen is the API, mutual TLS on every path; MetricsListen serves
	// /metrics, /healthz and /readyz in plain HTTP, and no fleet data.
	Listen, MetricsListen                 string
	TLSCertFile, TLSKeyFile, ClientCAFile string
	// WebhookListen is where NetBox's and Nautobot's deliveries arrive (plan
	// 6c, decision 31): TLS under the API's certificate, or under
	// WebhookTLSCertFile's, and no client certificate, since no product can
	// present one. Empty is no webhook.
	WebhookListen                         string
	WebhookTLSCertFile, WebhookTLSKeyFile string
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

// sourceYAML is one entry of sync:. The keys after safety are a netbox or
// nautobot source's (plan 6c).
type sourceYAML struct {
	Name             string            `yaml:"name"`
	Type             string            `yaml:"type"`
	Path             string            `yaml:"path"`
	Interval         time.Duration     `yaml:"interval"`
	Safety           safetyYAML        `yaml:"safety"`
	URL              string            `yaml:"url"`
	CAFile           string            `yaml:"ca_file"`
	TokenSecretEnv   string            `yaml:"token_secret_env"`
	WebhookSecretEnv string            `yaml:"webhook_secret_env"`
	Profile          string            `yaml:"profile"`
	API              string            `yaml:"api"`
	PageSize         int               `yaml:"page_size"`
	Filter           *filterYAML       `yaml:"filter"`
	Map              map[string]string `yaml:"map"`
	Addresses        *addressesYAML    `yaml:"addresses"`
	PlatformAliases  map[string]string `yaml:"platform_aliases"`
}

type filterYAML struct {
	Status       *stringList `yaml:"status"`
	Tags         []string    `yaml:"tags"`
	HasPrimaryIP bool        `yaml:"has_primary_ip"`
}

type addressesYAML struct {
	Primary       *bool    `yaml:"primary"`
	Interfaces    []string `yaml:"interfaces"`
	AllInterfaces bool     `yaml:"all_interfaces"`
}

// stringList is a string or a list of them: spec §10's example writes
// `status: active`.
type stringList []string

func (l *stringList) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		*l = []string{n.Value}
		return nil
	}
	var s []string
	if err := n.Decode(&s); err != nil {
		return err
	}
	*l = s
	return nil
}

type fileConfig struct {
	Listen             string        `yaml:"listen"`
	MetricsListen      string        `yaml:"metrics_listen"`
	WebhookListen      string        `yaml:"webhook_listen"`
	WebhookTLSCertFile string        `yaml:"webhook_tls_cert_file"`
	WebhookTLSKeyFile  string        `yaml:"webhook_tls_key_file"`
	TLSCertFile        string        `yaml:"tls_cert_file"`
	TLSKeyFile         string        `yaml:"tls_key_file"`
	ClientCAFile       string        `yaml:"client_ca_file"`
	Readers            []string      `yaml:"readers"`
	Syncers            []string      `yaml:"syncers"`
	SigningKeyFile     string        `yaml:"signing_key_file"`
	VerifyKeyFiles     []string      `yaml:"verify_key_files"`
	SyncTimeout        time.Duration `yaml:"sync_timeout"`
	PolicyFile         string        `yaml:"policy_file"`
	StateDir           string        `yaml:"state_dir"`
	MirrorDir          string        `yaml:"mirror_dir"`
	Interval           time.Duration `yaml:"interval"`
	Safety             safetyYAML    `yaml:"safety"`
	Sync               []sourceYAML  `yaml:"sync"`
}

// identityShape is a caller as CallerOf names one: `user:` and an email, or a
// URI with a scheme; printable ASCII, no space, no control character, so a
// matched identity is safe to print.
var identityShape = regexp.MustCompile(`^(user:[!-?A-~]+@[!-?A-~]+|` + uriIdentity + `)$`)

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
	// A second document after --- would be ignored silently: refused, in
	// fixed text, so none of it is echoed.
	if err := dec.Decode(new(yaml.Node)); err != io.EOF {
		return Config{}, fmt.Errorf("port49-inventory: %s: holds more than one YAML document; "+
			"port49-inventory.yaml is one YAML document", path)
	}
	c := Config{Listen: f.Listen, MetricsListen: f.MetricsListen, WebhookListen: f.WebhookListen,
		WebhookTLSCertFile: f.WebhookTLSCertFile, WebhookTLSKeyFile: f.WebhookTLSKeyFile, TLSCertFile: f.TLSCertFile, TLSKeyFile: f.TLSKeyFile,
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
	// Every path is absolute: a relative one resolves against the working
	// directory, which under systemd is /. The key is named, never the value.
	paths := []struct{ key, v string }{{"tls_cert_file", c.TLSCertFile}, {"tls_key_file", c.TLSKeyFile},
		{"client_ca_file", c.ClientCAFile}, {"signing_key_file", c.SigningKeyFile}, {"policy_file", c.PolicyFile},
		{"state_dir", c.StateDir}}
	if c.MirrorDir != "" {
		paths = append(paths, struct{ key, v string }{"mirror_dir", c.MirrorDir})
	}
	for _, p := range []struct{ key, v string }{{"webhook_tls_cert_file", c.WebhookTLSCertFile},
		{"webhook_tls_key_file", c.WebhookTLSKeyFile}} {
		if p.v != "" {
			paths = append(paths, p)
		}
	}
	for i, v := range c.VerifyKeyFiles {
		paths = append(paths, struct{ key, v string }{fmt.Sprintf("verify_key_files[%d]", i), v})
	}
	for _, p := range paths {
		if !filepath.IsAbs(p.v) {
			return Config{}, fmt.Errorf("port49-inventory: %s must be an absolute path", p.key)
		}
	}
	if c.MirrorDir != "" && within(c.StateDir, c.MirrorDir) {
		return Config{}, fmt.Errorf("port49-inventory: mirror_dir must be outside state_dir; the mirror is a " +
			"separate copy, not a part of the state")
	}
	if c.MirrorDir != "" && within(c.MirrorDir, c.StateDir) {
		return Config{}, fmt.Errorf("port49-inventory: state_dir must be outside mirror_dir; the mirror is a " +
			"separate copy, and the state is not a part of it")
	}
	for _, l := range []struct{ key, v string }{{"listen", c.Listen}, {"metrics_listen", c.MetricsListen}} {
		if _, port, err := net.SplitHostPort(l.v); err != nil || port == "" {
			return Config{}, fmt.Errorf("port49-inventory: %s must be host:port, such as 127.0.0.1:8443 or :8443", l.key)
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
			// CallerOf lower-cases a caller's email, and a match is exact:
			// an entry with a capital would match nobody, silently.
			if strings.HasPrefix(id, "user:") && id != strings.ToLower(id) {
				return Config{}, fmt.Errorf("port49-inventory: %s[%d] has an upper-case letter; write a user: "+
					"address in lower case, as a caller's certificate email is matched in lower case", l.key, i)
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
		var conn SourceConfig
		switch s.Type {
		case "file":
			if s.Path == "" {
				return Config{}, fmt.Errorf("port49-inventory: sync[%d] (%s): path is required for a file source", i, s.Name)
			}
			if !filepath.IsAbs(s.Path) {
				return Config{}, fmt.Errorf("port49-inventory: sync[%d].path must be an absolute path", i)
			}
			if s.URL != "" || s.CAFile != "" || s.TokenSecretEnv != "" || s.WebhookSecretEnv != "" || s.Profile != "" ||
				s.API != "" || s.PageSize != 0 || s.Filter != nil || s.Map != nil || s.Addresses != nil ||
				s.PlatformAliases != nil {
				return Config{}, fmt.Errorf("port49-inventory: sync[%d] (%s): url, ca_file, token_secret_env, "+
					"webhook_secret_env, profile, api, page_size, filter, map, addresses and platform_aliases are for "+
					"netbox and nautobot sources", i, s.Name)
			}
		case "netbox", "nautobot":
			if conn, err = sotSource(i, s); err != nil {
				return Config{}, err
			}
		default:
			return Config{}, fmt.Errorf("port49-inventory: sync[%d] (%s): type must be file, netbox or nautobot", i, s.Name)
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
		conn.Name, conn.Type, conn.Path, conn.Interval, conn.MaxRemovedPercent = s.Name, s.Type, s.Path, iv, p
		c.Sync = append(c.Sync, conn)
	}
	// Decision 31: a webhook secret needs a listener, and a listener a
	// source whose deliveries it can authenticate.
	for i, s := range c.Sync {
		if !s.WebhookSecret.Empty() && c.WebhookListen == "" {
			return Config{}, fmt.Errorf("port49-inventory: sync[%d] (%s): webhook_secret_env is set, and webhook_listen "+
				"is not: no listener would take its deliveries", i, s.Name)
		}
	}
	if c.WebhookListen != "" {
		if len(c.WebhookSources()) == 0 {
			return Config{}, fmt.Errorf("port49-inventory: webhook_listen is set, and no source has webhook_secret_env: " +
				"no delivery could be authenticated")
		}
		if _, port, err := net.SplitHostPort(c.WebhookListen); err != nil || port == "" {
			return Config{}, fmt.Errorf("port49-inventory: webhook_listen must be host:port, such as :8444")
		}
	}
	if (c.WebhookTLSCertFile == "") != (c.WebhookTLSKeyFile == "") {
		return Config{}, fmt.Errorf("port49-inventory: webhook_tls_cert_file and webhook_tls_key_file go together")
	}
	if c.WebhookTLSCertFile != "" && c.WebhookListen == "" {
		return Config{}, fmt.Errorf("port49-inventory: webhook_tls_cert_file is set, and webhook_listen is not")
	}
	return c, nil
}

// within reports whether dir is base or a directory under it.
func within(base, dir string) bool {
	rel, err := filepath.Rel(filepath.Clean(base), filepath.Clean(dir))
	return err == nil && (rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))))
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

var (
	envNameShape = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	attrShape    = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	statusShape  = regexp.MustCompile(`^[a-z0-9][a-z0-9 _-]{0,63}$`)
)

// secretFromEnv is the value of the environment variable name, named by key
// in port49-inventory.yaml. Its errors name key, never the variable or its
// value (plan 6a Task 15): the value is the secret, and a name is where one
// gets pasted. A value is min to max printable ASCII characters without a
// space, so it cannot split a header.
func secretFromEnv(key, name string, min, max int) (sot.Secret, error) {
	if name == "" {
		// Pre-flight M12: absent, not malformed.
		return sot.Secret{}, fmt.Errorf("port49-inventory: %s is required", key)
	}
	if !envNameShape.MatchString(name) {
		return sot.Secret{}, fmt.Errorf("port49-inventory: %s is not an environment variable name (letters, digits "+
			"and _)", key)
	}
	v, ok := os.LookupEnv(name)
	if !ok || v == "" {
		return sot.Secret{}, fmt.Errorf("port49-inventory: %s names an environment variable that is unset or empty",
			key)
	}
	if len(v) < min || len(v) > max || strings.IndexFunc(v, func(r rune) bool { return r < 0x21 || r > 0x7e }) >= 0 {
		return sot.Secret{}, fmt.Errorf("port49-inventory: %s names a variable whose value is not %d to %d printable "+
			"characters without a space", key, min, max)
	}
	return sot.NewSecret(v), nil
}

// sotSource is a netbox or nautobot entry's connection, secrets and mapping,
// with decision 31's defaults: api auto, page_size 500, filter status
// [active], addresses primary. An error names the key at fault; a value is
// quoted only once it has passed its shape.
func sotSource(i int, s sourceYAML) (SourceConfig, error) {
	at := fmt.Sprintf("port49-inventory: sync[%d] (%s): ", i, s.Name)
	fail := func(format string, args ...any) (SourceConfig, error) {
		return SourceConfig{}, fmt.Errorf(at+format, args...)
	}
	if s.Path != "" {
		return fail("path is for a file source; a %s source reads url", s.Type)
	}
	if s.URL == "" {
		return fail("url is required")
	}
	if err := sot.CheckURL(s.URL); err != nil {
		return fail("%s", err)
	}
	if s.CAFile == "" || !filepath.IsAbs(s.CAFile) {
		return fail("ca_file is required, an absolute path: the CA bundle that issues the source's certificate (the " +
			"host's own bundle file for a public one)")
	}
	c := SourceConfig{URL: s.URL, CAFile: s.CAFile, Profile: s.Profile, API: s.API, PageSize: s.PageSize}
	var err error
	if c.Token, err = secretFromEnv(fmt.Sprintf("sync[%d].token_secret_env", i), s.TokenSecretEnv, 1, 512); err != nil {
		return SourceConfig{}, err
	}
	if s.WebhookSecretEnv != "" {
		// 255 is the products' secret field (L27, L30).
		if c.WebhookSecret, err = secretFromEnv(fmt.Sprintf("sync[%d].webhook_secret_env", i), s.WebhookSecretEnv, 32,
			255); err != nil {
			return SourceConfig{}, err
		}
	}
	if c.Profile != "" && !sot.KnownProfile(s.Type, c.Profile) {
		return fail("profile must be one of %s", strings.Join(sot.ProfilesOf(s.Type), ", "))
	}
	switch c.API {
	case "":
		c.API = "auto"
	case "auto", "graphql", "rest":
	default:
		return fail("api must be auto, graphql or rest")
	}
	if c.PageSize == 0 {
		c.PageSize = 500
	}
	if c.PageSize < 1 || c.PageSize > 1000 {
		return fail("page_size must be between 1 and 1000")
	}
	m := sot.Mapping{Filter: sot.Filter{Status: []string{"active"}}, Addresses: sot.Addresses{Primary: true}}
	if f := s.Filter; f != nil {
		if f.Status != nil {
			// Empty would keep every status, decommissioned and planned
			// included: whoever wants that lists them.
			if len(*f.Status) == 0 {
				return fail("filter.status is empty; name the statuses kept")
			}
			m.Filter.Status = nil
			for j, st := range *f.Status {
				if st = strings.ToLower(st); !statusShape.MatchString(st) {
					return fail("filter.status[%d] is not a status name", j)
				}
				m.Filter.Status = append(m.Filter.Status, st)
			}
		}
		for j, tag := range f.Tags {
			if !bundle.TextOK(tag) || tag == "" {
				return fail("filter.tags[%d] is not a tag", j)
			}
		}
		m.Filter.Tags, m.Filter.HasPrimaryIP = f.Tags, f.HasPrimaryIP
	}
	if s.Map != nil {
		if _, ok := s.Map["platform"]; !ok {
			return fail("map must name platform: the path the device's platform is read from")
		}
		keys := make([]string, 0, len(s.Map))
		for k := range s.Map {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, attr := range keys {
			if !attrShape.MatchString(attr) || attr == "name" {
				return fail("map has a key that is not an attribute name (lowercase letters, digits and _, starting " +
					"with a letter; not name)")
			}
			if !sot.ValidPath(s.Map[attr]) {
				return fail("map.%s names no path a profile reads (site.slug, role.slug, platform.slug, "+
					"platform.network_driver, location.name, role.name, platform.name, status, custom_fields.<key>)", attr)
			}
		}
		m.Map = s.Map
	}
	if a := s.Addresses; a != nil {
		if a.Primary != nil {
			m.Addresses.Primary = *a.Primary
		}
		if a.AllInterfaces && len(a.Interfaces) > 0 {
			return fail("addresses names interfaces and all_interfaces: one or the other")
		}
		for j, n := range a.Interfaces {
			if n == "" || !bundle.TextOK(n) {
				return fail("addresses.interfaces[%d] is not an interface name", j)
			}
		}
		m.Addresses.Interfaces, m.Addresses.AllInterfaces = a.Interfaces, a.AllInterfaces
	}
	interfaces := len(m.Addresses.Interfaces) > 0 || m.Addresses.AllInterfaces
	if !m.Addresses.Primary && !interfaces {
		return fail("addresses gives no address: set primary: true, interfaces or all_interfaces")
	}
	if c.API == "rest" && interfaces {
		return fail("addresses names interfaces, which REST does not give in the device list (L27): use api: auto or graphql")
	}
	for slug, name := range s.PlatformAliases {
		if !bundle.NameOK(slug) || !sot.PlatformNameShape.MatchString(name) {
			return fail("platform_aliases has an entry that is not slug: platform_name (a platform name is lowercase " +
				"letters, digits and _, as the policy writes one)")
		}
		if m.Aliases == nil {
			m.Aliases = map[string]string{}
		}
		// Two keys alike in lower case would land on one alias, and map
		// order would pick which, start to start.
		if _, dup := m.Aliases[strings.ToLower(slug)]; dup {
			return fail("platform_aliases has two entries for one slug, compared in lower case")
		}
		m.Aliases[strings.ToLower(slug)] = name
	}
	c.Mapping = m
	return c, nil
}

// WebhookSources is every source that takes webhooks, by name, sorted.
func (c Config) WebhookSources() []string {
	var out []string
	for _, s := range c.Sync {
		if !s.WebhookSecret.Empty() {
			out = append(out, s.Name)
		}
	}
	sort.Strings(out)
	return out
}

// WebhookSecrets is each webhook source's secret, the HMAC key its
// deliveries are checked with. Never print or log the map: it is the
// secrets themselves, without Secret's redaction.
func (c Config) WebhookSecrets() map[string][]byte {
	out := map[string][]byte{}
	for _, s := range c.Sync {
		if !s.WebhookSecret.Empty() {
			out[s.Name] = []byte(s.WebhookSecret.Reveal())
		}
	}
	return out
}
