package api

// Identity is GET /v1/identity: what the broker resolves the caller to
// (design §17). Groups is empty until the directory (plan 7g). Grants are
// the subject's unexpired at the request, by scope: never a device list,
// since the API does not enumerate the fleet.
type Identity struct {
	Principal   string          `json:"principal"`
	Method      string          `json:"method"`
	Fingerprint string          `json:"fingerprint,omitempty"`
	Subject     string          `json:"subject,omitempty"`
	Groups      []string        `json:"groups"`
	Grants      []IdentityGrant `json:"grants"`
	API         []string        `json:"api"`
	AuthTime    string          `json:"auth_time"`
	// ConnectionEndsAt is auth_time plus max_session_age: when this
	// connection must authenticate again. A device's own session ceiling
	// may end a session sooner (pre-flight M16).
	ConnectionEndsAt string `json:"connection_ends_at,omitempty"`
}

// IdentityGrant is one grant row as the policy declares it.
type IdentityGrant struct {
	Scope        string   `json:"scope"`
	Roles        []string `json:"roles"`
	MaxPrivilege string   `json:"max_privilege,omitempty"`
	Expires      string   `json:"expires,omitempty"`
}
