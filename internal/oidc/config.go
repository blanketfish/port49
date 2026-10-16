package oidc

import (
	"slices"
	"strings"
	"time"
)

// Domain is a trust domain (spec §13 decision 16): the list a verifier is in.
type Domain string

const (
	Humans   Domain = "humans"
	Machines Domain = "machines"
)

// The claims a human verifier may take its principal from (Ruling 6).
const (
	ClaimPreferredUsername = "preferred_username"
	ClaimEmail             = "email"
	ClaimUPN               = "upn"
)

// MachineSessionClaims mark a person's authentication or a delegated grant:
// a token carrying one is never a machine's (Ruling 21).
var MachineSessionClaims = []string{"auth_time", "sid", "nonce", "scp", "amr", "act", "may_act"}

// MachineClient is one client a machine verifier accepts, and the sub its
// client-credentials tokens carry: the client's own identity at the
// provider (RFC 9068 §2.2), which no person's token carries (Ruling 21).
type MachineClient struct {
	ClientID string
	Sub      string
}

// VerifierConfig is one oidc verifier of broker.identity (Ruling 1). A
// human's is keyed by ClientID and gives principals in PrincipalDomains; a
// machine's is keyed by Audience and takes the Clients it lists.
type VerifierConfig struct {
	Domain         Domain
	Issuer         string
	ClientID       string
	Audience       string
	PrincipalClaim string
	// PrincipalDomains are the domains whose user: principals a human
	// verifier may give, lower-cased (Ruling 22).
	PrincipalDomains []string
	// Clients are a machine verifier's (Ruling 21).
	Clients []MachineClient
	// Scopes are what /v1/config tells a public client to ask for, openid
	// first (Ruling 16).
	Scopes     []string
	Algorithms []Alg
	// CAFile is the provider's TLS anchor; "" is the system roots.
	CAFile string
	// Kind is "" for an oidc verifier and KindK8s for a cluster's (plan 10;
	// spec §13 decision 49): a k8s verifier is a machine verifier keyed by
	// Issuer, named Cluster on the port49 side, its keys fetched from JWKS,
	// its principals in Namespaces.
	Kind       string
	Cluster    string
	JWKS       string
	Namespaces []string
}

// KindK8s is a Kubernetes cluster's verifier (decision 49 ruling 1).
const KindK8s = "k8s"

// ListsNamespace reports whether a k8s verifier may name ns's service
// accounts (decision 49 ruling 8).
func (v VerifierConfig) ListsNamespace(ns string) bool { return slices.Contains(v.Namespaces, ns) }

// Who is how the operator's lines name v: a k8s verifier by its cluster,
// the issuer beside it; any other by its issuer (decision 49 ruling 1).
func (v VerifierConfig) Who() string {
	if v.Kind == KindK8s {
		return "cluster " + v.Cluster + " (" + v.Issuer + ")"
	}
	return v.Issuer
}

// DomainOf is a user: principal's domain, after its last @; "" for any
// other principal.
func DomainOf(principal string) string {
	i := strings.LastIndexByte(principal, '@')
	if !strings.HasPrefix(principal, "user:") || i < 0 {
		return ""
	}
	return principal[i+1:]
}

// Owns reports whether principal is one this human verifier may give: a
// user: principal in its PrincipalDomains, exactly (Ruling 22).
func (v VerifierConfig) Owns(principal string) bool {
	d := DomainOf(principal)
	return d != "" && slices.Contains(v.PrincipalDomains, d)
}

// Client is the listed client named id, if a machine verifier lists it.
func (v VerifierConfig) Client(id string) (MachineClient, bool) {
	i := slices.IndexFunc(v.Clients, func(c MachineClient) bool { return c.ClientID == id })
	if i < 0 {
		return MachineClient{}, false
	}
	return v.Clients[i], true
}

// Timing is broker.identity's timing (OR-2).
type Timing struct {
	ClockSkew, MaxTokenAge, JWKSRefresh, JWKSMaxAge time.Duration
}

// DefaultTiming is OR-2's recommendation.
var DefaultTiming = Timing{ClockSkew: time.Minute, MaxTokenAge: 2 * time.Hour, JWKSRefresh: time.Hour,
	JWKSMaxAge: 24 * time.Hour}

// X509Machine is the workload certificate verifier (plan 8; spec §13
// decision 40): x509 under broker.identity.machines, its one trust anchor's
// file and the SPIFFE trust domains a certificate it verifies may name.
type X509Machine struct {
	AnchorFile   string
	TrustDomains []string
	// Directory is the verifier's directory: block as written (plan 8b; spec
	// §13 decision 41); nil without one. Config resolves it into
	// directory.Config.Workload once broker.directory is read.
	Directory *WorkloadDirectory
}

// WorkloadDirectory is broker.identity.machines[].directory as written.
type WorkloadDirectory struct {
	Kind, Attribute, UserFilter string
	AllowWeak                   bool
	Issuers                     []string
}

// Config is broker.identity resolved: the one x509 human anchor ("" for
// none), whether it came from broker.client_ca_file with no
// broker.identity (Shorthand), the oidc verifiers, and the timing.
type Config struct {
	X509AnchorFile string
	Shorthand      bool
	// X509Machine is the workload verifier, nil without one (plan 8).
	X509Machine *X509Machine
	OIDC        []VerifierConfig
	K8s         []VerifierConfig // the k8s verifiers, one per cluster (plan 10)
	Timing      Timing
	// Issuance is broker.identity.issuance (plan 9b; spec §13 decision 43
	// rulings 9 and 14): nil when the broker issues no certificate.
	Issuance *Issuance
	// PerLoginMFA is broker.identity.per_login_mfa (plan 9c; decision 45):
	// nil when none is configured.
	PerLoginMFA *PerLoginMFA
	// PasswordSignIn is the directory_password human verifier (plan 9e;
	// decision 47): nil when none is listed.
	PasswordSignIn *PasswordSignIn
}

// PerLoginMFA is broker.identity.per_login_mfa resolved: the roots file a
// hardware_key_touch attestation chains to ("" for none), and an idp_mfa's
// accepted amr values (empty: ["mfa"]) and the acr_values its sign-in sends.
type PerLoginMFA struct {
	AttestationRootsFile string
	AMR                  []string
	ACRValues            string
}

// PasswordSignIn is a type: directory_password human verifier resolved
// (plan 9e; spec §13 decision 47 ruling 18).
type PasswordSignIn struct {
	PrincipalDomains     []string
	Filter               string
	OpenUntil            time.Time     // zero: no rollout window
	NewEntriesFor        time.Duration // 0: off
	ReopenFor            time.Duration
	FailuresPerPrincipal int
	FailuresPerSource    int // 0: off
	Window               time.Duration
	TOTPLabel            string // "" is "port49 (<broker host>)", filled at start
}

const (
	DefaultNewEntriesFor        = 14 * 24 * time.Hour
	DefaultReopenFor            = 24 * time.Hour
	DefaultFailuresPerPrincipal = 5
	DefaultFailuresPerSource    = 50
	DefaultSignInWindow         = 15 * time.Minute
)

// Issuance is broker.identity.issuance resolved.
type Issuance struct {
	// CertificateLifetime is certificate_lifetime: 12h by default, 1h to 24h.
	CertificateLifetime time.Duration
}
