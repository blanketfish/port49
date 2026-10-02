package api

// ExplainRequest is POST /v1/explain (design §17): one hypothetical
// decision on Device, about the caller or, under explain_others,
// Principal. An empty Command is the session.
type ExplainRequest struct {
	Device    string `json:"device"`
	Command   string `json:"command,omitempty"`
	Principal string `json:"principal,omitempty"`
}

// ExplainResponse is its answer: the verdict and reason the broker and the
// daemon would give (spec §5.7), or MintError where the broker would mint
// no token; and Text, as port49 explain renders it, redacted and with no
// session attributes, a session's included. Platform is
// empty where the answer is no_grants_matched, so no answer says which
// devices exist.
type ExplainResponse struct {
	Principal string `json:"principal"`
	Subject   string `json:"subject,omitempty"`
	Device    string `json:"device"`
	Platform  string `json:"platform,omitempty"`
	Verdict   string `json:"verdict,omitempty"`
	Reason    string `json:"reason,omitempty"`
	MintError string `json:"mint_error,omitempty"`
	Text      string `json:"text"`
}
