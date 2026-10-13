package config

import (
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/rhwendt/port49/internal/issuer"
	"github.com/rhwendt/port49/internal/oidc"
	"github.com/rhwendt/port49/internal/spiffe"
)

// workloadDirectoryYAML is an x509 machine verifier's directory: (plan 8b;
// spec §13 decision 41).
type workloadDirectoryYAML struct {
	Kind       string   `yaml:"kind"`
	Attribute  string   `yaml:"attribute"`
	AllowWeak  bool     `yaml:"allow_weak"`
	Issuers    []string `yaml:"issuers"`
	UserFilter string   `yaml:"user_filter"`
}

// identityVerifierYAML is one entry of broker.identity.humans or .machines
// (plan 7h, Ruling 1).
type identityVerifierYAML struct {
	Type               string                 `yaml:"type"`
	TrustAnchorFile    string                 `yaml:"trust_anchor_file"`
	SPIFFETrustDomains []string               `yaml:"spiffe_trust_domains"`
	Issuer             string                 `yaml:"issuer"`
	ClientID           string                 `yaml:"client_id"`
	Audience           string                 `yaml:"audience"`
	PrincipalClaim     string                 `yaml:"principal_claim"`
	PrincipalDomains   []string               `yaml:"principal_domains"`
	Clients            []machineClientYAML    `yaml:"clients"`
	Scopes             []string               `yaml:"scopes"`
	Algorithms         []string               `yaml:"algorithms"`
	CAFile             string                 `yaml:"ca_file"`
	Directory          *workloadDirectoryYAML `yaml:"directory"`
}

// machineClientYAML is one entry of a machine verifier's clients (Ruling
// 21): a client id, and the sub its client-credentials tokens carry.
type machineClientYAML struct {
	ClientID string `yaml:"client_id"`
	Sub      string `yaml:"sub"`
}

// identityYAML is broker.identity (spec §13 decisions 16 and 39).
type identityYAML struct {
	Humans              []identityVerifierYAML `yaml:"humans"`
	Machines            []identityVerifierYAML `yaml:"machines"`
	ClockSkew           *time.Duration         `yaml:"clock_skew"`
	MaxTokenAge         *time.Duration         `yaml:"max_token_age"`
	JWKSRefreshInterval *time.Duration         `yaml:"jwks_refresh_interval"`
	JWKSMaxAge          *time.Duration         `yaml:"jwks_max_age"`
	Issuance            *issuanceYAML          `yaml:"issuance"`
	PerLoginMFA         *perLoginMFAYAML       `yaml:"per_login_mfa"`
}

// perLoginMFAYAML is broker.identity.per_login_mfa (plan 9c; spec §13
// decision 45): what the broker verifies for a policy's per_login_mfa.
type perLoginMFAYAML struct {
	HardwareKeyTouch *struct {
		AttestationRootsFile string `yaml:"attestation_roots_file"`
	} `yaml:"hardware_key_touch"`
	IdPMFA *struct {
		AMR       []string `yaml:"amr"`
		ACRValues string   `yaml:"acr_values"`
	} `yaml:"idp_mfa"`
}

// checkPerLoginMFA resolves broker.identity.per_login_mfa. The roots file
// is read at start (port49d), not here.
func checkPerLoginMFA(y perLoginMFAYAML) (*oidc.PerLoginMFA, error) {
	out := &oidc.PerLoginMFA{}
	if t := y.HardwareKeyTouch; t != nil {
		if t.AttestationRootsFile == "" {
			return nil, errors.New("config: broker.identity.per_login_mfa.hardware_key_touch.attestation_roots_file " +
				"is required: the PEM roots a touch key's attestation chains to")
		}
		out.AttestationRootsFile = t.AttestationRootsFile
	}
	if m := y.IdPMFA; m != nil {
		for i, v := range m.AMR {
			if v == "" {
				return nil, fmt.Errorf("config: broker.identity.per_login_mfa.idp_mfa.amr[%d] is empty", i)
			}
		}
		out.AMR, out.ACRValues = m.AMR, m.ACRValues
	}
	return out, nil
}

// issuanceYAML is broker.identity.issuance (plan 9b; spec §13 decision 43).
// `issuance: {}` turns it on with its defaults.
type issuanceYAML struct {
	CertificateLifetime *time.Duration `yaml:"certificate_lifetime"`
}

// checkIdentity resolves broker.identity, or, with none, the shorthand:
// broker.client_ca_file as the one x509 human verifier.
func checkIdentity(y *identityYAML, clientCAFile string) (*oidc.Config, error) {
	if y == nil {
		if clientCAFile == "" {
			return nil, errors.New("config: broker.client_ca_file is required when broker: is present and " +
				"broker.identity is not; or list the verifiers under broker.identity")
		}
		return &oidc.Config{X509AnchorFile: clientCAFile, Shorthand: true, Timing: oidc.DefaultTiming}, nil
	}
	if clientCAFile != "" {
		return nil, errors.New("config: broker.client_ca_file: moved to broker.identity.humans[].trust_anchor_file; " +
			"set one or the other")
	}
	t, err := identityTiming(*y)
	if err != nil {
		return nil, err
	}
	out := &oidc.Config{Timing: t}
	for _, list := range []struct {
		domain oidc.Domain
		vs     []identityVerifierYAML
	}{{oidc.Humans, y.Humans}, {oidc.Machines, y.Machines}} {
		for i, v := range list.vs {
			at := fmt.Sprintf("broker.identity.%s[%d]", list.domain, i)
			switch {
			case v.Type == "x509" && list.domain == oidc.Machines:
				// The workload verifier (plan 8; decision 40 ruling 1).
				if out.X509Machine != nil {
					return nil, errors.New("config: broker.identity.machines: at most one x509 verifier (the broker " +
						"verifies a workload's chain against one anchor)")
				}
				if v.TrustAnchorFile == "" || v.Issuer != "" || v.ClientID != "" || v.Audience != "" ||
					v.PrincipalClaim != "" || v.PrincipalDomains != nil || v.Clients != nil || v.Scopes != nil ||
					v.Algorithms != nil || v.CAFile != "" {
					return nil, fmt.Errorf("config: %s: type x509 takes trust_anchor_file and spiffe_trust_domains alone", at)
				}
				tds, err := spiffeTrustDomains(at, v.SPIFFETrustDomains)
				if err != nil {
					return nil, err
				}
				out.X509Machine = &oidc.X509Machine{AnchorFile: v.TrustAnchorFile, TrustDomains: tds}
				if d := v.Directory; d != nil {
					out.X509Machine.Directory = &oidc.WorkloadDirectory{Kind: d.Kind, Attribute: d.Attribute,
						UserFilter: d.UserFilter, AllowWeak: d.AllowWeak, Issuers: d.Issuers}
				}
			case v.Type == "k8s":
				return nil, fmt.Errorf("config: %s: type k8s is plan 10's; remove it", at)
			case v.Type == "x509":
				if out.X509AnchorFile != "" {
					return nil, errors.New("config: broker.identity.humans: at most one x509 verifier (the broker " +
						"verifies a chain against one anchor)")
				}
				if v.TrustAnchorFile == "" || v.Issuer != "" || v.ClientID != "" || v.Audience != "" ||
					v.PrincipalClaim != "" || v.PrincipalDomains != nil || v.Clients != nil || v.Scopes != nil ||
					v.Algorithms != nil || v.CAFile != "" || v.SPIFFETrustDomains != nil || v.Directory != nil {
					return nil, fmt.Errorf("config: %s: type x509 takes trust_anchor_file alone", at)
				}
				out.X509AnchorFile = v.TrustAnchorFile
			case v.Type == "oidc":
				vc, err := checkOIDCVerifier(at, list.domain, v)
				if err != nil {
					return nil, err
				}
				out.OIDC = append(out.OIDC, vc)
			default:
				return nil, fmt.Errorf("config: %s.type %q: one of x509 or oidc (k8s is plan 10's)", at, v.Type)
			}
		}
	}
	if y.Issuance != nil {
		if out.Issuance, err = checkIssuance(*y.Issuance, out.OIDC, y.Humans); err != nil {
			return nil, err
		}
	}
	if y.PerLoginMFA != nil {
		if out.PerLoginMFA, err = checkPerLoginMFA(*y.PerLoginMFA); err != nil {
			return nil, err
		}
	}
	if out.X509AnchorFile == "" && out.X509Machine == nil && len(out.OIDC) == 0 {
		return nil, errors.New("config: broker.identity accepts no one: list at least one verifier under humans " +
			"or machines")
	}
	// One file under both lists would make a certificate it verifies a
	// person's and a workload's at once (decision 40 ruling 2); port49d
	// refuses the same certificate in two files, and one signing the other,
	// once it has read them (Task 8).
	if m := out.X509Machine; m != nil && out.X509AnchorFile != "" &&
		filepath.Clean(m.AnchorFile) == filepath.Clean(out.X509AnchorFile) {
		return nil, errors.New("config: broker.identity's humans and machines trust_anchor_file are one file: a " +
			"certificate it verifies would be a person's and a workload's at once; anchor each list at its own " +
			"issuing CA")
	}
	if err := distinctVerifiers(out.OIDC, *y); err != nil {
		return nil, err
	}
	return out, nil
}

// checkIssuance resolves broker.identity.issuance (plan 9b; spec §13
// decision 43 rulings 9 and 14): a certificate is issued over an OIDC
// sign-in, so a human oidc verifier must be listed, and each one's issuer URL
// must be one an issued certificate can carry (issuer.CarriesIssuer);
// certificate_lifetime is 12h by default, 1h to 24h.
func checkIssuance(y issuanceYAML, vs []oidc.VerifierConfig, humans []identityVerifierYAML) (*oidc.Issuance, error) {
	if !slices.ContainsFunc(vs, func(v oidc.VerifierConfig) bool { return v.Domain == oidc.Humans }) {
		return nil, errors.New("config: broker.identity.issuance: a certificate is issued over an OIDC sign-in, so " +
			"list a human oidc verifier under broker.identity.humans")
	}
	for i, h := range humans {
		if h.Type != "oidc" {
			continue
		}
		if err := issuer.CarriesIssuer(h.Issuer); err != nil {
			return nil, fmt.Errorf("config: broker.identity.humans[%d].issuer %q: with broker.identity.issuance set, "+
				"a certificate carries the issuer URL, and %v", i, h.Issuer, err)
		}
	}
	life := issuer.DefaultLifetime
	if y.CertificateLifetime != nil {
		life = *y.CertificateLifetime
	}
	if life < issuer.MinLifetime || life > issuer.MaxLifetime {
		return nil, fmt.Errorf("config: broker.identity.issuance.certificate_lifetime must be between %s and %s; got %s",
			issuer.MinLifetime, issuer.MaxLifetime, life)
	}
	return &oidc.Issuance{CertificateLifetime: life}, nil
}

func checkOIDCVerifier(at string, d oidc.Domain, v identityVerifierYAML) (oidc.VerifierConfig, error) {
	u, err := url.Parse(v.Issuer)
	if v.Issuer == "" || err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.Fragment != "" {
		return oidc.VerifierConfig{}, fmt.Errorf("config: %s.issuer must be an https URL with no userinfo, query or fragment "+
			"(OpenID Connect Discovery §2)", at)
	}
	if v.TrustAnchorFile != "" {
		return oidc.VerifierConfig{}, fmt.Errorf("config: %s.trust_anchor_file is x509's; an oidc verifier's "+
			"provider anchor is ca_file", at)
	}
	if v.SPIFFETrustDomains != nil {
		return oidc.VerifierConfig{}, fmt.Errorf("config: %s.spiffe_trust_domains is an x509 machine verifier's", at)
	}
	if v.Directory != nil {
		return oidc.VerifierConfig{}, fmt.Errorf("config: %s.directory is an x509 machine verifier's", at)
	}
	algs, err := oidc.ParseAlgs(v.Algorithms)
	if err != nil {
		return oidc.VerifierConfig{}, fmt.Errorf("config: %s.algorithms: %w", at, err)
	}
	if v.CAFile != "" {
		if err := readableFile(at+".ca_file", v.CAFile); err != nil {
			return oidc.VerifierConfig{}, fmt.Errorf("config: %w", err) // pre-flight M-11
		}
	}
	out := oidc.VerifierConfig{Domain: d, Issuer: v.Issuer, Algorithms: algs, CAFile: v.CAFile}
	switch d {
	case oidc.Humans:
		switch {
		case !printableKey(v.ClientID):
			return oidc.VerifierConfig{}, fmt.Errorf("config: %s.client_id is required: the public client's id, "+
				"which a person's ID token names in aud", at)
		case v.Audience != "":
			return oidc.VerifierConfig{}, fmt.Errorf("config: %s.audience is a machine verifier's; a human "+
				"verifier is keyed by client_id", at)
		case v.Clients != nil:
			return oidc.VerifierConfig{}, fmt.Errorf("config: %s.clients is a machine verifier's; a human verifier "+
				"names principal_domains", at)
		case v.PrincipalClaim == "":
			// No default (decision 39 ruling 23): OpenID Connect Core §5.7 says
			// preferred_username is not unique, and Keycloak's documented default is
			// a bare username (L46 measures it).
			return oidc.VerifierConfig{}, fmt.Errorf("config: %s.principal_claim is required: one of "+
				"preferred_username, email or upn, whichever only your provider's administrators can set", at)
		case !slices.Contains([]string{oidc.ClaimPreferredUsername, oidc.ClaimEmail, oidc.ClaimUPN}, v.PrincipalClaim):
			return oidc.VerifierConfig{}, fmt.Errorf("config: %s.principal_claim %q: one of preferred_username, "+
				"email or upn", at, v.PrincipalClaim)
		}
		domains, err := principalDomains(at, v.PrincipalDomains)
		if err != nil {
			return oidc.VerifierConfig{}, err
		}
		scopes := []string{"openid"}
		for _, s := range v.Scopes {
			if !printableKey(s) {
				return oidc.VerifierConfig{}, fmt.Errorf("config: %s.scopes: a scope is printable ASCII with no space", at)
			}
			if !slices.Contains(scopes, s) {
				scopes = append(scopes, s)
			}
		}
		out.ClientID, out.PrincipalClaim, out.PrincipalDomains, out.Scopes = v.ClientID, v.PrincipalClaim, domains, scopes
	case oidc.Machines:
		switch {
		case !printableKey(v.Audience):
			return oidc.VerifierConfig{}, fmt.Errorf("config: %s.audience is required: the API identifier a "+
				"client-credentials token names in aud", at)
		case v.ClientID != "", v.PrincipalClaim != "", v.PrincipalDomains != nil, v.Scopes != nil:
			return oidc.VerifierConfig{}, fmt.Errorf("config: %s.client_id, principal_claim, principal_domains and "+
				"scopes are a human verifier's; a machine's principal is app:<azp>, a client listed in clients", at)
		case len(v.Clients) == 0:
			return oidc.VerifierConfig{}, fmt.Errorf("config: %s.clients is required: each client_id that may be a "+
				"machine principal, with its sub at the provider (decision 39 ruling 21)", at)
		}
		for i, c := range v.Clients {
			ca := fmt.Sprintf("%s.clients[%d]", at, i)
			switch {
			case !printableKey(c.ClientID):
				return oidc.VerifierConfig{}, fmt.Errorf("config: %s.client_id is required", ca)
			case !printableKey(c.Sub):
				return oidc.VerifierConfig{}, fmt.Errorf("config: %s.sub is required: the client's own identity at "+
					"the provider (Keycloak: the service-account user's id; Entra ID: the service principal's object "+
					"id), which its client-credentials tokens carry as sub and no person's token does", ca)
			case slices.ContainsFunc(out.Clients, func(m oidc.MachineClient) bool { return m.ClientID == c.ClientID }):
				return oidc.VerifierConfig{}, fmt.Errorf("config: %s repeats client_id %s", ca, c.ClientID)
			}
			out.Clients = append(out.Clients, oidc.MachineClient{ClientID: c.ClientID, Sub: c.Sub})
		}
		out.Audience = v.Audience
	}
	return out, nil
}

// principalDomains is a human verifier's principal_domains, lower-cased
// and once each (decision 39 ruling 22): at least one, each a domain with
// a dot, no @ and no leading dot. A domain is matched exactly: no
// subdomain is implied.
func principalDomains(at string, ds []string) ([]string, error) {
	if len(ds) == 0 {
		return nil, fmt.Errorf("config: %s.principal_domains is required: the domains whose people this verifier "+
			"may name (user:<name>@<domain>), so no other provider can name them", at)
	}
	var out []string
	for _, d := range ds {
		l := strings.ToLower(d)
		if !printableKey(l) || strings.ContainsAny(l, "@/") || strings.HasPrefix(l, ".") || !strings.Contains(l, ".") {
			return nil, fmt.Errorf("config: %s.principal_domains: %q is not a domain (a name with a dot, no @)", at, d)
		}
		if !slices.Contains(out, l) {
			out = append(out, l)
		}
	}
	return out, nil
}

// spiffeTrustDomains is a workload verifier's spiffe_trust_domains, once
// each and in order (decision 40 ruling 1): at least one, each a SPIFFE trust
// domain as it is written, never folded to lower case.
func spiffeTrustDomains(at string, tds []string) ([]string, error) {
	if len(tds) == 0 {
		return nil, fmt.Errorf("config: %s.spiffe_trust_domains is required: the SPIFFE trust domains whose "+
			"workloads this anchor may name (spiffe://<trust domain>/<path>)", at)
	}
	var out []string
	for _, td := range tds {
		if err := spiffe.CheckTrustDomain(td); err != nil {
			return nil, fmt.Errorf("config: %s.spiffe_trust_domains: %q is not a SPIFFE trust domain (%v)", at, td, err)
		}
		if !slices.Contains(out, td) {
			out = append(out, td)
		}
	}
	return out, nil
}

// distinctVerifiers refuses a verifier listed twice, which includes two
// human verifiers of one issuer with one client_id (the logout acceptance
// of Task 6 names a verifier by issuer and client_id); two machine
// verifiers on different issuers that list one client_id, which would give
// one app:<azp> principal two issuers (decision 39 ruling 22); a human's
// client_id equal to a machine's audience at one issuer, since a token
// naming it would be both lists' and refused at every request (Ruling 2);
// two human verifiers at one issuer with different principal claims, which
// would give one sub two principals (Ruling 24); and two human verifiers
// at different issuers whose principal_domains overlap, which would let
// either issuer name the other's people (Ruling 22).
func distinctVerifiers(vs []oidc.VerifierConfig, y identityYAML) error {
	name := func(i int) string {
		if i < len(y.Humans) {
			return fmt.Sprintf("broker.identity.humans[%d]", i)
		}
		return fmt.Sprintf("broker.identity.machines[%d]", i-len(y.Humans))
	}
	// vs is in list order, humans first, and only the oidc entries; index
	// them back to their place in the file.
	var at []int
	for i, v := range y.Humans {
		if v.Type == "oidc" {
			at = append(at, i)
		}
	}
	for i, v := range y.Machines {
		if v.Type == "oidc" {
			at = append(at, len(y.Humans)+i)
		}
	}
	key := func(v oidc.VerifierConfig) string { return v.ClientID + v.Audience }
	for i := range vs {
		for j := range i {
			a, b := vs[j], vs[i]
			if a.Issuer != b.Issuer && issuerForm(a.Issuer) == issuerForm(b.Issuer) {
				return fmt.Errorf("config: %s.issuer and %s.issuer differ only by a trailing slash or by case in the "+
					"scheme or host: the provider's discovery document names one spelling, so the other would "+
					"never get keys; list each issuer once, spelled as the provider spells it", name(at[i]), name(at[j]))
			}
			humans := a.Domain == oidc.Humans && b.Domain == oidc.Humans
			if a.Issuer != b.Issuer {
				if a.Domain == oidc.Machines && b.Domain == oidc.Machines {
					for _, c := range b.Clients {
						if slices.ContainsFunc(a.Clients, func(x oidc.MachineClient) bool { return x.ClientID == c.ClientID }) {
							return fmt.Errorf("config: %s.clients: %s is also %s's, at another issuer: two issuers "+
								"would give one principal (decision 39 ruling 22)", name(at[i]), c.ClientID, name(at[j]))
						}
					}
				}
				if !humans {
					continue
				}
				for _, d := range b.PrincipalDomains {
					if slices.Contains(a.PrincipalDomains, d) {
						return fmt.Errorf("config: %s.principal_domains: %s is also %s's, at another issuer: two issuers "+
							"would give one principal (decision 39 ruling 22)", name(at[i]), d, name(at[j]))
					}
				}
				continue
			}
			switch {
			case a.Domain == b.Domain && key(a) == key(b):
				return fmt.Errorf("config: %s repeats %s", name(at[i]), name(at[j]))
			case a.Domain != b.Domain && key(a) == key(b):
				return fmt.Errorf("config: %s.audience %s is %s's client_id: a token naming it would be both "+
					"lists', and refused", name(at[i]), b.Audience, name(at[j]))
			case humans && a.PrincipalClaim != b.PrincipalClaim:
				return fmt.Errorf("config: %s.principal_claim %s differs from %s's (%s) at one issuer: one sub would "+
					"be two principals (decision 39 ruling 24)", name(at[i]), b.PrincipalClaim, name(at[j]), a.PrincipalClaim)
			}
		}
	}
	return nil
}

func identityTiming(y identityYAML) (oidc.Timing, error) {
	t := oidc.DefaultTiming
	for _, b := range []struct {
		key      string
		v        *time.Duration
		into     *time.Duration
		min, max time.Duration
	}{
		{"clock_skew", y.ClockSkew, &t.ClockSkew, 0, 5 * time.Minute},
		{"max_token_age", y.MaxTokenAge, &t.MaxTokenAge, 5 * time.Minute, 24 * time.Hour},
		{"jwks_refresh_interval", y.JWKSRefreshInterval, &t.JWKSRefresh, 5 * time.Minute, 24 * time.Hour},
		{"jwks_max_age", y.JWKSMaxAge, &t.JWKSMaxAge, 10 * time.Minute, 30 * 24 * time.Hour},
	} {
		if b.v == nil {
			continue
		}
		if *b.v < b.min || *b.v > b.max {
			return oidc.Timing{}, fmt.Errorf("config: broker.identity.%s must be between %s and %s; got %s", b.key,
				b.min, b.max, *b.v)
		}
		*b.into = *b.v
	}
	if t.JWKSMaxAge < 2*t.JWKSRefresh {
		return oidc.Timing{}, fmt.Errorf("config: broker.identity.jwks_max_age %s is under twice jwks_refresh_interval "+
			"(%s): one missed refresh would refuse every token", t.JWKSMaxAge, t.JWKSRefresh)
	}
	return t, nil
}

// printableKey is a non-empty value of printable ASCII with no space, up to
// 255 bytes: a client id, an audience, a scope.
func printableKey(s string) bool {
	return s != "" && len(s) <= 255 && strings.IndexFunc(s, func(r rune) bool { return r < 0x21 || r > 0x7e }) < 0
}

// identityIssuers is each OIDC issuer of b's identity, once.
func identityIssuers(b *BrokerConfig) []string {
	var out []string
	if b.Identity != nil {
		for _, v := range b.Identity.OIDC {
			if !slices.Contains(out, v.Issuer) {
				out = append(out, v.Issuer)
			}
		}
	}
	return out
}

// BrokerStateDir is where the broker keeps its own state: broker.state_dir
// on port49-broker, else the directory holding broker.revocations_file, as
// the kept CRLs are (plan 7b). port49d's brokerStateDir is this (Task 14).
func BrokerStateDir(b *BrokerConfig) string {
	if b.StateDir != "" {
		return b.StateDir
	}
	return filepath.Dir(b.RevocationsFile)
}

// issuerForm is an issuer with the spellings discovery treats as one
// removed: the scheme and host in lower case, no trailing slash. The path
// stays case-sensitive.
func issuerForm(iss string) string {
	u, err := url.Parse(iss)
	if err != nil {
		return iss
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host) + strings.TrimSuffix(u.EscapedPath(), "/")
}
