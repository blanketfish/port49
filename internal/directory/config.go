package directory

import "time"

// Server is one directory server in the pool.
type Server struct {
	URI      string
	Priority int
	Site     string
	StartTLS bool
}

// BindMechanism is how the broker authenticates to the directory.
type BindMechanism string // "external" | "gssapi" | "simple"

// Bind is the broker's bind, by mechanism. A simple bind's password is
// named by PasswordEnv and never held here.
type Bind struct {
	Mechanism               BindMechanism
	TLSCertFile, TLSKeyFile string // external
	KeytabFile, Principal   string // gssapi
	KRB5Conf                string // gssapi
	BindDN, PasswordEnv     string // simple
}

// MappingKind is how a client certificate finds its directory entry.
type MappingKind string

const (
	MapIssuerSerial MappingKind = "issuer_serial"
	MapSID          MappingKind = "sid"
	MapSANUPN       MappingKind = "san_upn"
	MapSANEmail     MappingKind = "san_email"
	MapSubjectDN    MappingKind = "subject_dn"
	MapCN           MappingKind = "cn"
	// MapSPIFFEID is a workload certificate's mapping (plan 8b; spec §13
	// decision 41 ruling 2): never broker.directory.certificate_mapping's, so
	// it is not in Kinds.
	MapSPIFFEID MappingKind = "spiffe_id"
)

// Mapping is the resolved certificate_mapping.
type Mapping struct {
	Kind      MappingKind
	Attribute string // resolved: the kind's default when unset
	AllowWeak bool
	Issuers   []string // RFC 4514 issuer DNs a weak kind is pinned to
}

// WorkloadMapping is broker.identity.machines[].directory resolved (plan 8b;
// spec §13 decision 41): a workload certificate's entry, found by the SPIFFE
// ID its attribute holds. It is weak (decision 38 ruling 1), so it is always
// issuer-pinned.
type WorkloadMapping struct {
	Attribute    string   // the entry attribute holding the SPIFFE ID; no default
	Issuers      []string // RFC 4514 DNs the leaf's issuer must be one of
	UserFilter   string   // resolved: the block's, else broker.directory.user_filter
	TrustDomains []string // the verifier's spiffe_trust_domains: what pre-warm takes from an entry
}

// Nested is how nested group membership is resolved.
type Nested string // "in_chain" | "recursive" | "direct"

// Config is broker.directory resolved: the form every later task reads.
type Config struct {
	Servers                 []Server
	Site                    string // resolved: site, else os.Getenv(site_env), else ""
	SiteFrom                string // "site", "PORT49_SITE" (the env var), or "" for none
	CAFile                  string
	Bind                    Bind
	BaseDN, GroupsBaseDN    string
	UserFilter, GroupFilter string
	PrincipalAttribute      string
	UsernameAttribute       string
	GroupNameAttribute      string
	MemberAttribute         string
	Mapping                 Mapping
	// Workload is the workload certificate mapping, nil without one: then no
	// workload is ever sent to the directory (decision 40 ruling 5).
	Workload         *WorkloadMapping
	Nested           Nested
	MaxDepth         int
	QueryTimeout     time.Duration
	HealthInterval   time.Duration
	HealthTimeout    time.Duration
	FailureThreshold int
	ProbeInterval    time.Duration
	StabilityWindow  time.Duration
	Grace            time.Duration
	PrewarmInterval  time.Duration
	PrewarmMax       int
}

// Strong reports whether a kind binds a key-specific value (design §7):
// issuer and serial, or the SID extension. The others bind a name, and
// must be issuer-pinned.
func (k MappingKind) Strong() bool { return k == MapIssuerSerial || k == MapSID }

// DefaultAttribute is the entry attribute each kind looks up by default.
func (k MappingKind) DefaultAttribute() string {
	switch k {
	case MapIssuerSerial:
		return "altSecurityIdentities"
	case MapSID:
		return "objectSid"
	case MapSANUPN:
		return "userPrincipalName"
	case MapSANEmail:
		return "mail"
	case MapSubjectDN:
		return "distinguishedName"
	case MapCN:
		return "cn"
	}
	return ""
}

// Kinds is every MappingKind, in the order the refusal lists them.
var Kinds = []MappingKind{MapIssuerSerial, MapSID, MapSANUPN, MapSANEmail, MapSubjectDN, MapCN}
