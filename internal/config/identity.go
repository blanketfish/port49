package config

import (
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/blanketfish/port49/internal/issuer"
	"github.com/blanketfish/port49/internal/k8sid"
	"github.com/blanketfish/port49/internal/oidc"
	"github.com/blanketfish/port49/internal/spiffe"
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
	Type               string              `yaml:"type"`
	TrustAnchorFile    string              `yaml:"trust_anchor_file"`
	SPIFFETrustDomains []string            `yaml:"spiffe_trust_domains"`
	Issuer             string              `yaml:"issuer"`
	ClientID           string              `yaml:"client_id"`
	Audience           string              `yaml:"audience"`
	PrincipalClaim     string              `yaml:"principal_claim"`
	PrincipalDomains   []string            `yaml:"principal_domains"`
	Clients            []machineClientYAML `yaml:"clients"`
	Scopes             []string            `yaml:"scopes"`
	Algorithms         []string            `yaml:"algorithms"`
	CAFile             string              `yaml:"ca_file"`
	// k8s's own keys (plan 10; decision 49).
	Cluster    string                 `yaml:"cluster"`
	JWKS       string                 `yaml:"jwks"`
	Namespaces []string               `yaml:"namespaces"`
	Directory  *workloadDirectoryYAML `yaml:"directory"`
	// directory_password's own keys (plan 9e; decision 47).
	SecondFactor string          `yaml:"second_factor"`
	Filter       string          `yaml:"filter"`
	Enrollment   *enrollmentYAML `yaml:"enrollment"`
	RateLimits   *rateLimitsYAML `yaml:"rate_limits"`
	TOTPLabel    string          `yaml:"totp_label"`
}

// k8sKeys reports whether v sets a key only a k8s verifier takes.
func (v identityVerifierYAML) k8sKeys() bool {
	return v.Cluster != "" || v.JWKS != "" || v.Namespaces != nil
}

// clusterName is a k8s verifier's cluster: a CRL source's name shape
// (config.go's crlName), since it is configuration's word for a cluster, not
// the cluster's own (decision 49 ruling 1).
var clusterName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// enrollmentYAML is a directory_password verifier's enrollment windows
// (decision 47 D2).
type enrollmentYAML struct {
	OpenUntil     string         `yaml:"open_until"`
	NewEntriesFor *time.Duration `yaml:"new_entries_for"`
	ReopenFor     *time.Duration `yaml:"reopen_for"`
}

// rateLimitsYAML is its attempt limits (decision 47 D5).
type rateLimitsYAML struct {
	FailuresPerPrincipal *int           `yaml:"failures_per_principal"`
	FailuresPerSource    *int           `yaml:"failures_per_source"`
	Window               *time.Duration `yaml:"window"`
}

// passwordKeys reports whether v sets a key only a directory_password
// verifier takes.
func (v identityVerifierYAML) passwordKeys() bool {
	return v.SecondFactor != "" || v.Filter != "" || v.Enrollment != nil || v.RateLimits != nil || v.TOTPLabel != ""
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
					v.Algorithms != nil || v.CAFile != "" || v.passwordKeys() || v.k8sKeys() {
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
			case v.Type == "k8s" && list.domain == oidc.Humans:
				return nil, fmt.Errorf("config: %s: k8s is a machine verifier: a cluster's service accounts are "+
					"workloads; list it under machines", at)
			case v.Type == "k8s":
				vc, err := checkK8sVerifier(at, v)
				if err != nil {
					return nil, err
				}
				out.K8s = append(out.K8s, vc)
			case v.Type == "x509":
				if out.X509AnchorFile != "" {
					return nil, errors.New("config: broker.identity.humans: at most one x509 verifier (the broker " +
						"verifies a chain against one anchor)")
				}
				if v.TrustAnchorFile == "" || v.Issuer != "" || v.ClientID != "" || v.Audience != "" ||
					v.PrincipalClaim != "" || v.PrincipalDomains != nil || v.Clients != nil || v.Scopes != nil ||
					v.Algorithms != nil || v.CAFile != "" || v.SPIFFETrustDomains != nil || v.Directory != nil ||
					v.passwordKeys() || v.k8sKeys() {
					return nil, fmt.Errorf("config: %s: type x509 takes trust_anchor_file alone", at)
				}
				out.X509AnchorFile = v.TrustAnchorFile
			case v.Type == "directory_password" && list.domain == oidc.Machines:
				return nil, fmt.Errorf("config: %s: directory_password is a human verifier; list it under humans", at)
			case v.Type == "directory_password":
				if out.PasswordSignIn != nil {
					return nil, errors.New("config: broker.identity.humans: at most one directory_password verifier " +
						"(one directory, one password sign-in)")
				}
				if v.TrustAnchorFile != "" || v.Issuer != "" || v.ClientID != "" || v.Audience != "" ||
					v.PrincipalClaim != "" || v.Clients != nil || v.Scopes != nil || v.Algorithms != nil ||
					v.CAFile != "" || v.SPIFFETrustDomains != nil || v.Directory != nil || v.k8sKeys() {
					return nil, fmt.Errorf("config: %s: type directory_password takes principal_domains, second_factor, "+
						"filter, enrollment, rate_limits and totp_label alone", at)
				}
				if out.PasswordSignIn, err = checkPasswordSignIn(at, v); err != nil {
					return nil, err
				}
			case v.Type == "oidc":
				vc, err := checkOIDCVerifier(at, list.domain, v)
				if err != nil {
					return nil, err
				}
				out.OIDC = append(out.OIDC, vc)
			default:
				return nil, fmt.Errorf("config: %s.type %q: one of x509, oidc, k8s or directory_password",
					at, v.Type)
			}
		}
	}
	if y.Issuance != nil {
		if out.Issuance, err = checkIssuance(*y.Issuance, out.OIDC, y.Humans, out.PasswordSignIn != nil); err != nil {
			return nil, err
		}
	}
	if out.PasswordSignIn != nil && out.Issuance == nil {
		return nil, errors.New("config: broker.identity.issuance: a directory_password sign-in ends in an issued " +
			"certificate, so set broker.identity.issuance (`issuance: {}` takes its defaults)")
	}
	if y.PerLoginMFA != nil {
		if out.PerLoginMFA, err = checkPerLoginMFA(*y.PerLoginMFA); err != nil {
			return nil, err
		}
	}
	if out.X509AnchorFile == "" && out.X509Machine == nil && len(out.OIDC) == 0 && len(out.K8s) == 0 &&
		out.PasswordSignIn == nil {
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
	if err := distinctClusters(out.K8s, out.OIDC, *y); err != nil {
		return nil, err
	}
	if p := out.PasswordSignIn; p != nil {
		pi := slices.IndexFunc(y.Humans, func(v identityVerifierYAML) bool { return v.Type == "directory_password" })
		for i, h := range y.Humans {
			if h.Type != "oidc" {
				continue
			}
			for _, d := range p.PrincipalDomains {
				if slices.ContainsFunc(h.PrincipalDomains, func(x string) bool { return strings.EqualFold(x, d) }) {
					return nil, fmt.Errorf("config: broker.identity.humans[%d].principal_domains: %s is also "+
						"broker.identity.humans[%d]'s: a password beside an identity provider is a downgrade an "+
						"attacker picks (decision 47 D8)", pi, d, i)
				}
			}
		}
	}
	return out, nil
}

// checkPasswordSignIn resolves a directory_password verifier (plan 9e;
// decision 47 ruling 18): totp the one second factor, the domains its
// people's principals are in, the enrollment windows and the attempt limits,
// each inside its bounds.
func checkPasswordSignIn(at string, v identityVerifierYAML) (*oidc.PasswordSignIn, error) {
	switch v.SecondFactor {
	case "totp":
	case "":
		return nil, fmt.Errorf("config: %s.second_factor is required: totp, the one second factor a password "+
			"sign-in takes (decision 47)", at)
	default:
		return nil, fmt.Errorf("config: %s.second_factor %q: totp is the one second factor (decision 47)", at,
			v.SecondFactor)
	}
	domains, err := principalDomains(at, v.PrincipalDomains)
	if err != nil {
		return nil, err
	}
	out := &oidc.PasswordSignIn{PrincipalDomains: domains, Filter: v.Filter,
		NewEntriesFor: oidc.DefaultNewEntriesFor, ReopenFor: oidc.DefaultReopenFor,
		FailuresPerPrincipal: oidc.DefaultFailuresPerPrincipal, FailuresPerSource: oidc.DefaultFailuresPerSource,
		Window: oidc.DefaultSignInWindow}
	if v.Filter != "" {
		if _, err := ldap.CompileFilter(v.Filter); err != nil {
			return nil, fmt.Errorf("config: %s.filter %q: %v", at, v.Filter, err)
		}
	}
	if e := v.Enrollment; e != nil {
		if e.OpenUntil != "" {
			t, err := time.Parse(time.RFC3339, e.OpenUntil)
			if err != nil {
				return nil, fmt.Errorf("config: %s.enrollment.open_until %q: an RFC 3339 time, such as "+
					"2026-12-01T00:00:00Z", at, e.OpenUntil)
			}
			out.OpenUntil = t
		}
		if e.NewEntriesFor != nil {
			out.NewEntriesFor = *e.NewEntriesFor
		}
		if e.ReopenFor != nil {
			out.ReopenFor = *e.ReopenFor
		}
	}
	if l := v.RateLimits; l != nil {
		if l.FailuresPerPrincipal != nil {
			out.FailuresPerPrincipal = *l.FailuresPerPrincipal
		}
		if l.FailuresPerSource != nil {
			out.FailuresPerSource = *l.FailuresPerSource
		}
		if l.Window != nil {
			out.Window = *l.Window
		}
	}
	for _, d := range []struct {
		key      string
		v        time.Duration
		min, max time.Duration
	}{
		{"enrollment.new_entries_for", out.NewEntriesFor, 0, 90 * 24 * time.Hour},
		{"enrollment.reopen_for", out.ReopenFor, time.Hour, 168 * time.Hour},
		{"rate_limits.window", out.Window, time.Minute, 24 * time.Hour},
	} {
		if d.v < d.min || d.v > d.max {
			return nil, fmt.Errorf("config: %s.%s must be between %s and %s; got %s", at, d.key, d.min, d.max, d.v)
		}
	}
	for _, n := range []struct {
		key      string
		v        int
		min, max int
	}{
		{"rate_limits.failures_per_principal", out.FailuresPerPrincipal, 1, 100},
		{"rate_limits.failures_per_source", out.FailuresPerSource, 0, 10000},
	} {
		if n.v < n.min || n.v > n.max {
			return nil, fmt.Errorf("config: %s.%s must be between %d and %d; got %d", at, n.key, n.min, n.max, n.v)
		}
	}
	if l := v.TOTPLabel; l != "" {
		if len(l) > 64 || strings.ContainsRune(l, ':') || strings.IndexFunc(l, func(r rune) bool { return r < 0x20 || r > 0x7e }) >= 0 {
			return nil, fmt.Errorf("config: %s.totp_label: printable ASCII with no colon, at most 64 bytes (it is the "+
				"issuer an authenticator app shows)", at)
		}
		out.TOTPLabel = l
	}
	return out, nil
}

// checkIssuance resolves broker.identity.issuance (plan 9b; spec §13
// decision 43 rulings 9 and 14): a certificate is issued over an OIDC
// sign-in, so a human oidc verifier must be listed, and each one's issuer URL
// must be one an issued certificate can carry (issuer.CarriesIssuer);
// certificate_lifetime is 12h by default, 1h to 24h.
func checkIssuance(y issuanceYAML, vs []oidc.VerifierConfig, humans []identityVerifierYAML, password bool) (*oidc.Issuance, error) {
	if !password && !slices.ContainsFunc(vs, func(v oidc.VerifierConfig) bool { return v.Domain == oidc.Humans }) {
		return nil, errors.New("config: broker.identity.issuance: a certificate is issued over a sign-in, an OIDC " +
			"one or a directory password: list a human oidc or directory_password verifier under " +
			"broker.identity.humans")
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
	if v.k8sKeys() {
		return oidc.VerifierConfig{}, fmt.Errorf("config: %s: jwks, namespaces and cluster are a k8s verifier's", at)
	}
	if v.passwordKeys() {
		return oidc.VerifierConfig{}, fmt.Errorf("config: %s: second_factor, filter, enrollment, rate_limits and "+
			"totp_label are a directory_password verifier's", at)
	}
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

// identityIssuers is each OIDC or k8s issuer of b's identity, once.
func identityIssuers(b *BrokerConfig) []string {
	var out []string
	if b.Identity != nil {
		for _, v := range append(slices.Clone(b.Identity.OIDC), b.Identity.K8s...) {
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

// checkK8sVerifier resolves a k8s verifier (plan 10; spec §13 decision 49
// rulings 1, 4 and 5). Its namespaces may be another cluster's too (ruling 4).
func checkK8sVerifier(at string, v identityVerifierYAML) (oidc.VerifierConfig, error) {
	if v.TrustAnchorFile != "" || v.SPIFFETrustDomains != nil || v.Directory != nil || v.ClientID != "" ||
		v.PrincipalClaim != "" || v.PrincipalDomains != nil || v.Clients != nil || v.Scopes != nil || v.passwordKeys() {
		return oidc.VerifierConfig{}, fmt.Errorf("config: %s: type k8s takes issuer, cluster, jwks, audience, namespaces, "+
			"ca_file and algorithms alone", at)
	}
	if !httpsURL(v.Issuer) {
		return oidc.VerifierConfig{}, fmt.Errorf("config: %s.issuer must be an https URL with no userinfo, query or "+
			"fragment: the cluster's --service-account-issuer, as its tokens carry it in iss", at)
	}
	switch {
	case v.Cluster == "":
		return oidc.VerifierConfig{}, fmt.Errorf("config: %s.cluster is required: this cluster's name in port49's "+
			"records and lines (us_east, say); nothing in the cluster changes", at)
	case !clusterName.MatchString(v.Cluster):
		return oidc.VerifierConfig{}, fmt.Errorf("config: %s.cluster must match %s", at, clusterName)
	case v.JWKS == "":
		return oidc.VerifierConfig{}, fmt.Errorf("config: %s.jwks is required: the URL the cluster's keys are read "+
			"from (the API server's https://<host>:<port>/openid/v1/jwks, or where your cluster publishes them)", at)
	case !httpsURL(v.JWKS):
		return oidc.VerifierConfig{}, fmt.Errorf("config: %s.jwks must be an https URL with no userinfo, query or fragment", at)
	case v.Audience == "":
		return oidc.VerifierConfig{}, fmt.Errorf("config: %s.audience is required: the audience your pods' projected "+
			"token volume asks for (port49 in the examples)", at)
	case !printableKey(v.Audience):
		return oidc.VerifierConfig{}, fmt.Errorf("config: %s.audience must be 1 to 255 printable ASCII characters with "+
			"no space: the audience your pods' projected token volume asks for", at)
	case len(v.Namespaces) == 0:
		return oidc.VerifierConfig{}, fmt.Errorf("config: %s.namespaces is required: the namespaces whose service "+
			"accounts this cluster may name, by name", at)
	}
	var nss []string
	for _, ns := range v.Namespaces {
		if err := k8sid.CheckNamespace(ns); err != nil {
			return oidc.VerifierConfig{}, fmt.Errorf("config: %s.namespaces: %q: %v", at, ns, err)
		}
		if !slices.Contains(nss, ns) {
			nss = append(nss, ns)
		}
	}
	algs, err := oidc.ParseAlgs(v.Algorithms)
	if err != nil {
		return oidc.VerifierConfig{}, fmt.Errorf("config: %s.algorithms: %w", at, err)
	}
	if v.CAFile != "" {
		if err := readableFile(at+".ca_file", v.CAFile); err != nil {
			return oidc.VerifierConfig{}, fmt.Errorf("config: %w", err)
		}
	}
	return oidc.VerifierConfig{Domain: oidc.Machines, Kind: oidc.KindK8s, Issuer: v.Issuer, Cluster: v.Cluster,
		JWKS: v.JWKS, Audience: v.Audience, Namespaces: nss, Algorithms: algs, CAFile: v.CAFile}, nil
}

// httpsURL is an https URL with a host and no userinfo, query or fragment.
func httpsURL(s string) bool {
	u, err := url.Parse(s)
	return s != "" && err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.Opaque == "" &&
		u.RawQuery == "" && !u.ForceQuery && u.Fragment == ""
}

// distinctClusters is decision 49 rulings 1 and 3: one issuer per cluster,
// never an oidc verifier's issuer, and one name per cluster. Two verifiers on
// one jwks are one cluster under two issuers (a migration), and share its
// name. Namespaces are not compared: several clusters may vouch for one
// (ruling 4), which the start says.
func distinctClusters(ks, os []oidc.VerifierConfig, y identityYAML) error {
	at := func(i int) string {
		n := -1
		for j, v := range y.Machines {
			if v.Type == "k8s" {
				if n++; n == i {
					return fmt.Sprintf("broker.identity.machines[%d]", j)
				}
			}
		}
		return "broker.identity.machines[?]"
	}
	// oidcAt is where the oidc verifier of issuer iss is listed.
	oidcAt := func(iss string) string {
		for j, v := range y.Humans {
			if v.Type == "oidc" && issuerForm(v.Issuer) == issuerForm(iss) {
				return fmt.Sprintf("broker.identity.humans[%d]", j)
			}
		}
		for j, v := range y.Machines {
			if v.Type == "oidc" && issuerForm(v.Issuer) == issuerForm(iss) {
				return fmt.Sprintf("broker.identity.machines[%d]", j)
			}
		}
		return "an oidc verifier"
	}
	for i, b := range ks {
		for _, o := range os {
			if issuerForm(o.Issuer) == issuerForm(b.Issuer) {
				return fmt.Errorf("config: %s.issuer %s is also %s's, a k8s verifier's: one issuer is one cluster's "+
					"or one provider's (decision 49 ruling 3)", oidcAt(o.Issuer), o.Issuer, at(i))
			}
		}
		for j := range i {
			a := ks[j]
			switch {
			case a.Issuer == b.Issuer:
				return fmt.Errorf("config: %s.issuer %s is also %s's: each cluster needs its own "+
					"--service-account-issuer (kubeadm's default is the same on every cluster) (decision 49 ruling 3)",
					at(i), b.Issuer, at(j))
			case issuerForm(a.Issuer) == issuerForm(b.Issuer):
				return fmt.Errorf("config: %s.issuer and %s.issuer differ only by a trailing slash or by case in the "+
					"scheme or host; list each issuer once, spelled as the cluster spells it", at(i), at(j))
			case a.Cluster == b.Cluster && a.JWKS != b.JWKS:
				return fmt.Errorf("config: %s.cluster %s is also %s's: each cluster's name is its own (decision 49 "+
					"ruling 1); two verifiers share one only on the same jwks, one cluster under two issuers",
					at(i), b.Cluster, at(j))
			case a.Cluster != b.Cluster && a.JWKS == b.JWKS:
				return fmt.Errorf("config: %s and %s read one jwks, so they are one cluster under two issuers: give "+
					"them one cluster name, not %s and %s", at(j), at(i), a.Cluster, b.Cluster)
			}
		}
	}
	return nil
}
