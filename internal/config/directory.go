package config

import (
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/rhwendt/port49/internal/directory"
	"github.com/rhwendt/port49/internal/oidc"
)

type serverYAML struct {
	URI      string `yaml:"uri"`
	Priority int    `yaml:"priority"`
	Site     string `yaml:"site"`
	StartTLS bool   `yaml:"start_tls"`
}

type bindYAML struct {
	Mechanism   string `yaml:"mechanism"`
	TLSCertFile string `yaml:"tls_cert_file"`
	TLSKeyFile  string `yaml:"tls_key_file"`
	KeytabFile  string `yaml:"keytab_file"`
	Principal   string `yaml:"principal"`
	KRB5Conf    string `yaml:"krb5_conf"`
	BindDN      string `yaml:"bind_dn"`
	PasswordEnv string `yaml:"password_env"`
}

type mappingYAML struct {
	Kind      string   `yaml:"kind"`
	Attribute string   `yaml:"attribute"`
	AllowWeak bool     `yaml:"allow_weak"`
	Issuers   []string `yaml:"issuers"`
}

type healthYAML struct {
	Interval time.Duration `yaml:"interval"`
	Timeout  time.Duration `yaml:"timeout"`
}

type breakerYAML struct {
	FailureThreshold int           `yaml:"failure_threshold"`
	ProbeInterval    time.Duration `yaml:"probe_interval"`
}

type failbackYAML struct {
	StabilityWindow *time.Duration `yaml:"stability_window"`
}

type prewarmYAML struct {
	Interval *time.Duration `yaml:"interval"`
	// MaxPrincipals bounds one pre-warm pass's principals. People and, under
	// a workload mapping, workloads (machine_group members and listed
	// spiffe:// identities) each take up to it, so one interval verifies up
	// to twice it (plan 8b; spec §13 decision 41 ruling 6).
	MaxPrincipals int `yaml:"max_principals"`
}

// directoryYAML is broker.directory (design §10; plan 7g).
type directoryYAML struct {
	Servers            []serverYAML   `yaml:"servers"`
	Site               string         `yaml:"site"`
	SiteEnv            string         `yaml:"site_env"`
	CAFile             string         `yaml:"ca_file"`
	Bind               bindYAML       `yaml:"bind"`
	BaseDN             string         `yaml:"base_dn"`
	GroupsBaseDN       string         `yaml:"groups_base_dn"`
	UserFilter         string         `yaml:"user_filter"`
	GroupFilter        string         `yaml:"group_filter"`
	PrincipalAttribute string         `yaml:"principal_attribute"`
	UsernameAttribute  string         `yaml:"username_attribute"`
	GroupNameAttribute string         `yaml:"group_name_attribute"`
	MemberAttribute    string         `yaml:"member_attribute"`
	CertificateMapping mappingYAML    `yaml:"certificate_mapping"`
	NestedGroups       string         `yaml:"nested_groups"`
	MaxDepth           int            `yaml:"max_depth"`
	QueryTimeout       time.Duration  `yaml:"query_timeout"`
	HealthCheck        *healthYAML    `yaml:"health_check"`
	CircuitBreaker     *breakerYAML   `yaml:"circuit_breaker"`
	Failback           *failbackYAML  `yaml:"failback"`
	Grace              *time.Duration `yaml:"grace"`
	Prewarm            *prewarmYAML   `yaml:"prewarm"`
}

// Defaults provisional on the owner's answer to OR-1 (plan 7g): each is one
// line to change.
const (
	defaultRefreshInterval = 5 * time.Minute
	defaultGrace           = 4 * time.Hour
	defaultStabilityWindow = 5 * time.Minute
)

// checkDirectory resolves broker.directory, refusing what Rulings 1, 6,
// 8 and 9 refuse. getenv is os.Getenv outside tests.
func checkDirectory(y directoryYAML, getenv func(string) string) (*directory.Config, error) {
	const p = "broker.directory."
	d := &directory.Config{CAFile: y.CAFile, BaseDN: y.BaseDN,
		GroupsBaseDN:       or(y.GroupsBaseDN, y.BaseDN),
		UserFilter:         or(y.UserFilter, "(objectClass=person)"),
		GroupFilter:        or(y.GroupFilter, "(|(objectClass=group)(objectClass=groupOfNames))"),
		PrincipalAttribute: or(y.PrincipalAttribute, "userPrincipalName"),
		UsernameAttribute:  or(y.UsernameAttribute, "sAMAccountName"),
		GroupNameAttribute: or(y.GroupNameAttribute, "cn"),
		MemberAttribute:    or(y.MemberAttribute, "member"),
		MaxDepth:           orI(y.MaxDepth, 16),
		QueryTimeout:       orD(y.QueryTimeout, 5*time.Second),
		HealthInterval:     30 * time.Second, HealthTimeout: 2 * time.Second,
		FailureThreshold: 3, ProbeInterval: time.Minute, StabilityWindow: defaultStabilityWindow,
		Grace: defaultGrace, PrewarmInterval: time.Hour, PrewarmMax: 10000}
	if len(y.Servers) == 0 {
		return nil, fmt.Errorf("config: %sservers: list at least one", p)
	}
	labels := map[string]int{}
	for i, s := range y.Servers {
		// Userinfo first: every other message here echoes the URI. Any "@"
		// is refused, so a URI that does not parse cannot carry one into a
		// message either.
		if strings.Contains(s.URI, "@") {
			return nil, fmt.Errorf("config: %sservers[%d].uri: credentials in the URI are refused; use "+
				"broker.directory.bind", p, i)
		}
		u, err := url.Parse(s.URI)
		switch {
		case err != nil || u.Host == "" || (u.Scheme != "ldaps" && u.Scheme != "ldap"):
			return nil, fmt.Errorf("config: %sservers[%d].uri %q: an ldaps:// or ldap:// URI with a host", p, i, s.URI)
		case u.Scheme == "ldap" && !s.StartTLS:
			return nil, fmt.Errorf("config: %sservers[%d].uri %s: plain LDAP is refused; use ldaps:// or set start_tls: true",
				p, i, s.URI)
		case u.Scheme == "ldaps" && s.StartTLS:
			return nil, fmt.Errorf("config: %sservers[%d]: start_tls is for ldap://; %s is TLS already", p, i, s.URI)
		}
		srv := directory.Server{URI: s.URI, Priority: s.Priority, Site: s.Site, StartTLS: s.StartTLS}
		if j, dup := labels[srv.Label()]; dup {
			return nil, fmt.Errorf("config: %sservers[%d].uri %s: the same host:port as servers[%d]; a server is named by it in the log and in metrics",
				p, i, s.URI, j)
		}
		labels[srv.Label()] = i
		d.Servers = append(d.Servers, srv)
	}
	switch {
	case y.Site != "":
		d.Site, d.SiteFrom = y.Site, "site"
	default:
		name := or(y.SiteEnv, "PORT49_SITE")
		if v := getenv(name); v != "" {
			d.Site, d.SiteFrom = v, name
		}
	}
	if y.CAFile == "" {
		return nil, fmt.Errorf("config: %sca_file is required: the directory's server certificates are verified", p)
	}
	if err := readableFile(p+"ca_file", y.CAFile); err != nil {
		return nil, err
	}
	if y.BaseDN == "" {
		return nil, fmt.Errorf("config: %sbase_dn is required", p)
	}
	for _, dn := range []struct{ key, v string }{{"base_dn", d.BaseDN}, {"groups_base_dn", d.GroupsBaseDN}} {
		if _, err := ldap.ParseDN(dn.v); err != nil {
			return nil, fmt.Errorf("config: %s%s %q: %v", p, dn.key, dn.v, err)
		}
	}
	b, err := checkBind(y.Bind, getenv)
	if err != nil {
		return nil, err
	}
	d.Bind = b
	// The site is logged as auth.directory.site: a password must never be
	// read from the variable it comes from.
	if b.PasswordEnv != "" && b.PasswordEnv == or(y.SiteEnv, "PORT49_SITE") {
		return nil, fmt.Errorf("config: %ssite_env %s is also bind.password_env: the site is logged, a password "+
			"never is; name different variables", p, b.PasswordEnv)
	}
	m, err := checkMapping(y.CertificateMapping)
	if err != nil {
		return nil, err
	}
	d.Mapping = m
	switch directory.Nested(y.NestedGroups) {
	case "in_chain", "recursive", "direct":
		d.Nested = directory.Nested(y.NestedGroups)
	case "":
		return nil, fmt.Errorf("config: %snested_groups is required: in_chain (Active Directory), recursive (port49 "+
			"walks member) or direct (the groups are flat); design §10", p)
	default:
		return nil, fmt.Errorf("config: %snested_groups %q: in_chain, recursive or direct", p, y.NestedGroups)
	}
	if d.MaxDepth < 1 || d.MaxDepth > 64 {
		return nil, fmt.Errorf("config: %smax_depth %d: must be 1 to 64", p, y.MaxDepth)
	}
	if d.QueryTimeout < time.Second || d.QueryTimeout > 30*time.Second {
		return nil, fmt.Errorf("config: %squery_timeout %s: must be 1s to 30s", p, d.QueryTimeout)
	}
	if h := y.HealthCheck; h != nil {
		d.HealthInterval, d.HealthTimeout = orD(h.Interval, d.HealthInterval), orD(h.Timeout, d.HealthTimeout)
	}
	if d.HealthInterval < 5*time.Second || d.HealthInterval > 5*time.Minute {
		return nil, fmt.Errorf("config: %shealth_check.interval %s: must be 5s to 5m", p, d.HealthInterval)
	}
	if d.HealthTimeout > d.HealthInterval {
		return nil, fmt.Errorf("config: %shealth_check.timeout %s: must be at most health_check.interval (%s)", p,
			d.HealthTimeout, d.HealthInterval)
	}
	if cb := y.CircuitBreaker; cb != nil {
		d.FailureThreshold, d.ProbeInterval = orI(cb.FailureThreshold, 3), orD(cb.ProbeInterval, time.Minute)
	}
	if d.FailureThreshold < 1 || d.FailureThreshold > 20 {
		return nil, fmt.Errorf("config: %scircuit_breaker.failure_threshold %d: must be 1 to 20", p, d.FailureThreshold)
	}
	if d.ProbeInterval < 5*time.Second || d.ProbeInterval > 10*time.Minute {
		return nil, fmt.Errorf("config: %scircuit_breaker.probe_interval %s: must be 5s to 10m", p, d.ProbeInterval)
	}
	if f := y.Failback; f != nil && f.StabilityWindow != nil {
		d.StabilityWindow = *f.StabilityWindow
	}
	if d.StabilityWindow < 0 || d.StabilityWindow > time.Hour {
		return nil, fmt.Errorf("config: %sfailback.stability_window %s: must be 0s to 1h", p, d.StabilityWindow)
	}
	if y.Grace != nil {
		d.Grace = *y.Grace
	}
	if d.Grace < 0 || d.Grace > 24*time.Hour {
		return nil, fmt.Errorf("config: %sgrace %s: must be 0s to 24h", p, d.Grace)
	}
	if pw := y.Prewarm; pw != nil {
		if pw.Interval != nil {
			d.PrewarmInterval = *pw.Interval
		}
		d.PrewarmMax = orI(pw.MaxPrincipals, d.PrewarmMax)
	}
	if d.PrewarmInterval != 0 && (d.PrewarmInterval < 5*time.Minute || d.PrewarmInterval > 24*time.Hour) {
		return nil, fmt.Errorf("config: %sprewarm.interval %s: must be 0s (off) or 5m to 24h", p, d.PrewarmInterval)
	}
	if d.PrewarmMax < 1 || d.PrewarmMax > 1_000_000 {
		return nil, fmt.Errorf("config: %sprewarm.max_principals %d: must be 1 to 1000000", p, d.PrewarmMax)
	}
	if err := checkSearchShape(d); err != nil {
		return nil, err
	}
	return d, nil
}

func checkBind(b bindYAML, getenv func(string) string) (directory.Bind, error) {
	const p = "broker.directory.bind."
	out := directory.Bind{Mechanism: directory.BindMechanism(b.Mechanism), TLSCertFile: b.TLSCertFile,
		TLSKeyFile: b.TLSKeyFile, KeytabFile: b.KeytabFile, Principal: b.Principal, KRB5Conf: b.KRB5Conf,
		BindDN: b.BindDN, PasswordEnv: b.PasswordEnv}
	switch b.Mechanism {
	case "external":
		if b.TLSCertFile == "" || b.TLSKeyFile == "" {
			return out, fmt.Errorf("config: %stls_cert_file and tls_key_file are required for external", p)
		}
		// A missing file stops the start, not the first bind at 3am.
		for _, f := range []struct{ key, path string }{{"tls_cert_file", b.TLSCertFile}, {"tls_key_file", b.TLSKeyFile}} {
			if err := readableFile(p+f.key, f.path); err != nil {
				return out, err
			}
		}
	case "gssapi":
		if b.KeytabFile == "" || b.Principal == "" || b.KRB5Conf == "" {
			return out, fmt.Errorf("config: %skeytab_file, principal and krb5_conf are required for gssapi", p)
		}
		for _, f := range []struct{ key, path string }{{"keytab_file", b.KeytabFile}, {"krb5_conf", b.KRB5Conf}} {
			if err := readableFile(p+f.key, f.path); err != nil {
				return out, err
			}
		}
	case "simple":
		if b.BindDN == "" || b.PasswordEnv == "" {
			return out, fmt.Errorf("config: %sbind_dn and password_env are required for simple", p)
		}
		if getenv(b.PasswordEnv) == "" {
			return out, fmt.Errorf("config: %spassword_env %s is not set", p, b.PasswordEnv)
		}
	case "":
		return out, fmt.Errorf("config: %smechanism is required: external, gssapi or simple", p)
	default:
		return out, fmt.Errorf("config: %smechanism %q: external, gssapi or simple", p, b.Mechanism)
	}
	return out, nil
}

func checkMapping(m mappingYAML) (directory.Mapping, error) {
	const p = "broker.directory.certificate_mapping."
	kind := directory.MappingKind(m.Kind)
	if kind == directory.MapSPIFFEID {
		return directory.Mapping{}, fmt.Errorf("config: %skind spiffe_id is a workload certificate's mapping: set it "+
			"under broker.identity.machines[].directory", p)
	}
	if !slices.Contains(directory.Kinds, kind) {
		names := make([]string, len(directory.Kinds))
		for i, k := range directory.Kinds {
			names[i] = string(k)
		}
		return directory.Mapping{}, fmt.Errorf("config: %skind %s: one of %s", p, or(m.Kind, `""`), strings.Join(names, ", "))
	}
	out := directory.Mapping{Kind: kind, Attribute: or(m.Attribute, kind.DefaultAttribute()), AllowWeak: m.AllowWeak}
	// A strong kind repointed at another attribute is as strong as that
	// attribute (pre-flight M-4): it takes the weak opt-in and its pin.
	repointed := kind.Strong() && m.Attribute != "" && m.Attribute != kind.DefaultAttribute()
	if repointed && !m.AllowWeak {
		return directory.Mapping{}, fmt.Errorf("config: %sattribute %s: repointing %s makes it as strong as %s; set "+
			"allow_weak: true and list the issuers it is pinned to (design §7)", p, m.Attribute, kind, m.Attribute)
	}
	for i, iss := range m.Issuers {
		if _, err := ldap.ParseDN(iss); err != nil || !strings.Contains(iss, "=") || !directory.ValidPin(iss) {
			return directory.Mapping{}, fmt.Errorf("config: %sissuers[%d] %q: not an RFC 4514 DN", p, i, iss)
		}
		out.Issuers = append(out.Issuers, iss)
	}
	if repointed && len(out.Issuers) == 0 {
		return directory.Mapping{}, fmt.Errorf("config: %sissuers: a repointed strong mapping is pinned to its "+
			"issuers; list at least one (design §7)", p)
	}
	if !kind.Strong() {
		if !m.AllowWeak {
			return directory.Mapping{}, fmt.Errorf("config: %skind %s is a weak mapping: set allow_weak: true and list "+
				"the issuers it is pinned to (design §7)", p, kind)
		}
		if len(out.Issuers) == 0 {
			return directory.Mapping{}, fmt.Errorf("config: %sissuers: a weak mapping is pinned to its issuers; list "+
				"at least one (design §7)", p)
		}
	}
	return out, nil
}

// refreshInterval resolves broker.refresh_interval (Ruling 12).
func refreshInterval(d time.Duration) (time.Duration, error) {
	d = orD(d, defaultRefreshInterval)
	if d < time.Minute || d > time.Hour {
		return 0, fmt.Errorf("config: broker.refresh_interval %s: must be 1m to 1h", d)
	}
	return d, nil
}

// checkWorkloadMapping resolves an x509 machine verifier's directory: (plan 8b;
// spec §13 decision 41 rulings 1 and 2): spiffe_id alone, attribute required,
// weak so allow_weak and issuers required, user_filter defaulting to
// broker.directory's.
func checkWorkloadMapping(d oidc.WorkloadDirectory, trustDomains []string, userFilter string) (*directory.WorkloadMapping, error) {
	const p = "broker.identity.machines[].directory."
	switch {
	case directory.MappingKind(d.Kind) != directory.MapSPIFFEID:
		return nil, fmt.Errorf("config: %skind %q: spiffe_id, the one kind a workload's mapping takes (spec §13 "+
			"decision 41)", p, d.Kind)
	case d.Attribute == "":
		return nil, fmt.Errorf("config: %sattribute is required: no schema has one for a SPIFFE ID; name the "+
			"attribute your directory administrators reserve for it", p)
	case !descriptor.MatchString(d.Attribute):
		return nil, fmt.Errorf("config: %sattribute %q: not an attribute descriptor", p, d.Attribute)
	case !d.AllowWeak:
		return nil, fmt.Errorf("config: %s: spiffe_id is a weak mapping: set allow_weak: true and list the issuers "+
			"it is pinned to (design §7)", strings.TrimSuffix(p, "."))
	case len(d.Issuers) == 0:
		return nil, fmt.Errorf("config: %sissuers: a weak mapping is pinned to its issuers; list at least one "+
			"(design §7)", p)
	}
	for i, iss := range d.Issuers {
		if _, err := ldap.ParseDN(iss); err != nil || !strings.Contains(iss, "=") || !directory.ValidPin(iss) {
			return nil, fmt.Errorf("config: %sissuers[%d] %q is not an RFC 4514 DN", p, i, iss)
		}
	}
	w := &directory.WorkloadMapping{Attribute: d.Attribute, Issuers: d.Issuers, UserFilter: or(d.UserFilter, userFilter),
		TrustDomains: trustDomains}
	if _, err := ldap.CompileFilter(w.UserFilter); err != nil {
		return nil, fmt.Errorf("config: %suser_filter %q: %v", p, w.UserFilter, err)
	}
	return w, nil
}

// descriptor is an LDAP attribute description: a name or a numeric OID
// (RFC 4512 §1.4). A value outside it would be pasted into a filter.
var descriptor = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9-]*|[0-9]+(\.[0-9]+)+)$`)

// checkSearchShape refuses, at load, a filter that does not compile and an
// attribute that is no descriptor: otherwise a typo is an "error" on every
// query and never a load error.
func checkSearchShape(d *directory.Config) error {
	const p = "broker.directory."
	for _, f := range []struct{ key, v string }{{"user_filter", d.UserFilter}, {"group_filter", d.GroupFilter}} {
		if _, err := ldap.CompileFilter(f.v); err != nil {
			return fmt.Errorf("config: %s%s %q: %v", p, f.key, f.v, err)
		}
	}
	for _, a := range []struct{ key, v string }{{"principal_attribute", d.PrincipalAttribute},
		{"username_attribute", d.UsernameAttribute}, {"group_name_attribute", d.GroupNameAttribute},
		{"member_attribute", d.MemberAttribute}, {"certificate_mapping.attribute", d.Mapping.Attribute}} {
		if !descriptor.MatchString(a.v) {
			return fmt.Errorf("config: %s%s %q: not an attribute descriptor", p, a.key, a.v)
		}
	}
	return nil
}
