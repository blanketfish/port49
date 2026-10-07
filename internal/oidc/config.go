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

// Config is broker.identity resolved: the one x509 human anchor ("" for
// none), whether it came from broker.client_ca_file with no
// broker.identity (Shorthand), the oidc verifiers, and the timing.
type Config struct {
	X509AnchorFile string
	Shorthand      bool
	OIDC           []VerifierConfig
	Timing         Timing
}
