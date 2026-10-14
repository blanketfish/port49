package api

// SignInRequest is POST /v1/sign-in's body (plan 9e; spec §13 decision 47):
// a person's directory name, password and TOTP code, and the key's PKCS #10
// request as POST /v1/certificate takes it. Code is empty for a person with
// no second factor, who is enrolled instead.
type SignInRequest struct {
	Name     string `json:"name"`
	Password string `json:"password"`
	Code     string `json:"code,omitempty"`
	CSR      string `json:"csr"`
}

// Enrollment is the 202 answer to a sign-in that starts an enrollment: the
// otpauth URI the person's authenticator reads, the handle that confirms it,
// and when the enrollment ends.
type Enrollment struct {
	Handle    string `json:"handle"`
	URI       string `json:"otpauth_uri"`
	ConfirmBy string `json:"confirm_by"`
}

// EnrollResponse is POST /v1/sign-in's 202 body.
type EnrollResponse struct {
	Enroll Enrollment `json:"enroll"`
}

// ConfirmRequest is POST /v1/sign-in/confirm's body: the handle, the
// authenticator's first code, and the key's request.
type ConfirmRequest struct {
	Handle string `json:"handle"`
	Code   string `json:"code"`
	CSR    string `json:"csr"`
}

// SignInConfig is /v1/config's word that the broker signs a person in by
// directory password, and what second factor it asks.
type SignInConfig struct {
	SecondFactor string `json:"second_factor"`
}
