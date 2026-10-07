package api

// Identity is GET /v1/identity: what the broker resolves the caller to
// (design §17). Groups is empty until the directory (plan 7g). Grants are
// the subject's unexpired at the request, by scope: never a device list,
// since the API does not enumerate the fleet.
type Identity struct {
	Principal   string `json:"principal"`
	Method      string `json:"method"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Subject     string `json:"subject,omitempty"`
	// Subjects, Username, GroupDNs, VerifiedAt and Source are what the
	// directory contributed (plan 7g): every matched subject when several
	// match, the directory's username, the group DNs it gave, and when and
	// from where ("fresh" or "grace") the membership was verified.
	Subjects   []string        `json:"subjects,omitempty"`
	Username   string          `json:"username,omitempty"`
	GroupDNs   []string        `json:"group_dns,omitempty"`
	VerifiedAt string          `json:"verified_at,omitempty"`
	Source     string          `json:"source,omitempty"`
	Groups     []string        `json:"groups"`
	Grants     []IdentityGrant `json:"grants"`
	API        []string        `json:"api"`
	AuthTime   string          `json:"auth_time"`
	// ConnectionEndsAt is auth_time plus max_session_age: when this
	// connection must authenticate again. A device's own session ceiling
	// may end a session sooner (pre-flight M16).
	ConnectionEndsAt string `json:"connection_ends_at,omitempty"`
	// OIDC is the verified token's identity when the caller presented one
	// (plan 7h).
	OIDC *IdentityOIDC `json:"oidc,omitempty"`
}

// IdentityOIDC is what GET /v1/identity says of an OIDC caller's token.
type IdentityOIDC struct {
	Issuer string   `json:"issuer"`
	Sub    string   `json:"sub"`
	Sid    string   `json:"sid,omitempty"`
	AMR    []string `json:"amr,omitempty"`
	ACR    string   `json:"acr,omitempty"`
}

// IdentityGrant is one grant row as the policy declares it.
type IdentityGrant struct {
	Scope        string   `json:"scope"`
	Roles        []string `json:"roles"`
	MaxPrivilege string   `json:"max_privilege,omitempty"`
	Expires      string   `json:"expires,omitempty"`
}
