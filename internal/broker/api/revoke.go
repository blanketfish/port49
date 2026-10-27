package api

import "time"

// RevokeSlotWait bounds how long POST /v1/tokens/revoke waits for the
// broker's revocation slot, behind another revocation or lift, before it
// answers 503 revocation_busy. Once it holds the slot, the run is bounded by
// the broker's RevokeTimeout. A client sizes its wait from both, so it is
// never the side that gives up on a revocation that goes on to finish.
const RevokeSlotWait = 10 * time.Second

// RevokeRequest is POST /v1/tokens/revoke (design §17; spec §5.1.4). Exactly
// one form: Mine (alone, or with Device and Username for the caller's own
// on one key); Principal; or Device and Username (whoever holds the key,
// under revoke_others). Sid, with Issuer when more than one human OIDC
// verifier is configured, ends one OIDC session under revoke_others (plan
// 7h). A token is never sent: the broker finds what to revoke itself.
type RevokeRequest struct {
	Mine      bool   `json:"mine,omitempty"`
	Principal string `json:"principal,omitempty"`
	Device    string `json:"device,omitempty"`
	Username  string `json:"username,omitempty"`
	Sid       string `json:"sid,omitempty"`
	Issuer    string `json:"issuer,omitempty"`
	// CertIssuer and CertSerial, together, revoke one certificate (a
	// standing mark) under revoke_others and a touch (plan 12b).
	CertIssuer string `json:"cert_issuer,omitempty"`
	CertSerial string `json:"cert_serial,omitempty"`
}

// SessionRef names a live session by device and device-facing username.
type SessionRef struct {
	Device   string `json:"device"`
	Username string `json:"username"`
}

// RevokeResponse says what a revocation reached. By is principal (a
// standing mark), self or key (neither leaves one). Subject is the policy
// subject the revoked principal, or the key's owner, resolves to, so a
// misspelt colleague is seen at once; empty for self, or when no subject
// names the principal. Saved is a standing mark's alone: whether
// broker.revocations_file was written. Incomplete is set when a step did
// not finish; running the same request again repeats every step. Text is
// what port49 revoke prints.
type RevokeResponse struct {
	By          string       `json:"by"`
	Principal   string       `json:"principal,omitempty"`
	Subject     string       `json:"subject,omitempty"`
	Subjects    []string     `json:"subjects,omitempty"`
	Device      string       `json:"device,omitempty"`
	Username    string       `json:"username,omitempty"`
	Standing    bool         `json:"standing"`
	At          string       `json:"at"`
	Contexts    int          `json:"contexts"`
	TokenKeys   int          `json:"token_keys"`
	Connections int          `json:"connections"`
	Unreached   []SessionRef `json:"unreached"`
	Saved       *bool        `json:"saved,omitempty"`
	Incomplete  string       `json:"incomplete,omitempty"`
	Text        string       `json:"text"`
}
