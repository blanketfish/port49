package agent

import (
	"errors"
	"io"
	"net/http"

	"github.com/rhwendt/port49/internal/brokercrl"
)

// codeBrokerRefused is the socket code for a connection the broker CRL check
// refused (a BrokerRefusedError): not the broker failing and not a session
// that is over, so a caller must neither retry it nor say the broker is
// unreachable.
const codeBrokerRefused = "broker_refused"

// codeBrokerUnavailable is the socket code for a broker the agent could not
// reach or that answered 503 (a BrokerUnavailableError): an outage a caller may
// try again, not a broker that answered and refused (that stays broker_error).
const codeBrokerUnavailable = "broker_unavailable"

// codeStoreUnavailable is the socket code for a 503 the broker gave as
// store_unavailable (a StoreUnavailableError); the socket's Retry-After is the
// broker's.
const codeStoreUnavailable = "store_unavailable"

// codeNoAttestation is the socket code for a token that shows none of the
// attestations a touch proof needs (mfatouch.ErrNoAttestation): sent before
// the key blinked, so the command may prove another way.
const codeNoAttestation = "no_attestation"

// decodeRefresh reads POST /refresh's body. It is optional (an older client
// sends none) but strict: a field it does not know is refused by name, so a
// misspelled challenge is never dropped in silence and its proof left unspent.
func decodeRefresh(body io.Reader) (RefreshRequest, error) {
	var req RefreshRequest
	if err := decodeOne(body, &req); err != nil && !errors.Is(err, io.EOF) {
		return RefreshRequest{}, err
	}
	return req, nil
}

// refusedCert is a revoked broker certificate as the socket carries it, so
// the client can rebuild a *brokercrl.RevokedError for errors.As.
type refusedCert struct {
	Subject string `json:"subject"`
	Serial  string `json:"serial"`
	List    string `json:"list"`
}

// refusalBody is an error body of the agent's socket: the API's, and for
// broker_refused what the check found.
type refusalBody struct {
	Error     string       `json:"error"`
	Detail    string       `json:"detail,omitempty"`
	Revoked   *refusedCert `json:"revoked,omitempty"`
	Unchecked *string      `json:"unchecked,omitempty"`
}

// refusalOf is err as a broker_refused body, and whether it is one. The detail
// is the check's own words, without the agent's prefix, which the rebuilt
// BrokerRefusedError adds again.
func refusalOf(err error) (refusalBody, bool) {
	var no *BrokerRefusedError
	if !errors.As(err, &no) {
		return refusalBody{}, false
	}
	b := refusalBody{Error: codeBrokerRefused, Detail: no.Err.Error()}
	var revoked *brokercrl.RevokedError
	var unchecked *brokercrl.UncheckedError
	switch {
	case errors.As(no.Err, &revoked):
		b.Revoked = &refusedCert{Subject: revoked.Subject, Serial: revoked.Serial, List: revoked.List}
	case errors.As(no.Err, &unchecked):
		b.Unchecked = &unchecked.Detail
	}
	return b, true
}

// writeRefusal answers 502 broker_refused when err is a refused connection,
// and says whether it did.
func writeRefusal(w http.ResponseWriter, err error) bool {
	b, ok := refusalOf(err)
	if ok {
		writeJSON(w, http.StatusBadGateway, b)
	}
	return ok
}

// refused rebuilds the *BrokerRefusedError a broker_refused body stands for,
// nil for any other body.
func (b refusalBody) refused() error {
	if b.Error != codeBrokerRefused {
		return nil
	}
	var inner error = errors.New(b.Detail)
	switch {
	case b.Revoked != nil:
		inner = &brokercrl.RevokedError{Subject: b.Revoked.Subject, Serial: b.Revoked.Serial, List: b.Revoked.List}
	case b.Unchecked != nil:
		inner = &brokercrl.UncheckedError{Detail: *b.Unchecked}
	}
	return &BrokerRefusedError{Err: inner}
}
