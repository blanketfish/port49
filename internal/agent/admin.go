package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"strings"
	"sync/atomic"
	"time"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/hwkey"
	"github.com/rhwendt/port49/internal/mfatouch"
	"github.com/rhwendt/port49/internal/normal"
	"github.com/rhwendt/port49/internal/printsafe"
)

// Admin calls (spec §5.1.6; plan 12b task 3d): `port49 revoke` and `port49
// directory` hand the agent the request, and the agent makes it: it asks,
// takes the broker's challenge, shows the person what the touch is for, signs
// over the held connection, and sends the proved retry on that connection or
// not at all.

// adminBodyMax bounds the body of every admin call but an import.
const adminBodyMax = 4 << 10

// adminReplyMax bounds the answer read from the broker.
const adminReplyMax = 8 << 20

// adminRequestMax bounds POST /admin's body: an import's export, base64 in the
// JSON, and a little over.
const adminRequestMax = api.MaxImportBytes/3*4 + 4096

// adminTimeout bounds an admin call whole: the broker's longest wait on a
// revocation, the touch, and an import's body read, so the agent is the side
// that gives up, and says why.
var adminTimeout = revokeWait + api.ImportReadTimeout + time.Minute

// adminStreamType marks a POST /admin answer that carries the prompt before
// the result: one JSON event per line.
const adminStreamType = "application/x-ndjson"

// ErrTouchBusy is a second admin call asked while one waits on the key: a
// touch proves presence, and two waiting at once could not be told apart by
// the person at the key.
var ErrTouchBusy = errors.New("agent: another touch is waiting on your key; touch it or let it time out, then " +
	"run this again")

// ErrChallengeMismatch is a challenge whose operation or target is not the
// request the agent is sending. Nothing was shown and nothing was signed. The
// broker's words are not repeated: they are the broker's, not the person's
// request.
var ErrChallengeMismatch = errors.New("agent: the broker asked for a touch for a different request than the one " +
	"sent, so nothing was signed; run it again, and look at the broker if it does it again")

// AdminRefusedError is a call the agent does not make: a path outside its
// allowlist, or a body that is not the request its path takes.
type AdminRefusedError struct{ Detail string }

func (e *AdminRefusedError) Error() string { return "agent: " + e.Detail }

// TouchUnusableError is a touch key that is not configured or cannot be used.
// Nothing was sent, so no refused proof is recorded for a key that could not
// have touched.
type TouchUnusableError struct{ Detail string }

func (e *TouchUnusableError) Error() string { return "agent: " + e.Detail }

// UnansweredAdminError is a proved admin call that was written and never
// answered: the broker may have run it.
type UnansweredAdminError struct{ Err error }

func (e *UnansweredAdminError) Error() string {
	return fmt.Sprintf("agent: the broker did not answer the admin call (%v); it may have run", e.Err)
}
func (e *UnansweredAdminError) Unwrap() error { return e.Err }

// AdminRequest is POST /admin on the agent's socket: one request to the
// broker's API. Path is the request URI, path and query, as the broker sees
// it, since the proof is bound to it.
type AdminRequest struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	Body   []byte `json:"body,omitempty"`
}

// AdminResponse is the broker's answer to a proved call, as it is: the status
// and the body, for the command to read.
type AdminResponse struct {
	Status int    `json:"status"`
	Body   []byte `json:"body,omitempty"`
}

// adminCall is what a request is, derived from the request alone: the
// operation and target a challenge must name, or no operation for a call that
// takes no touch.
type adminCall struct{ op, target string }

const (
	pathRevoke     = "/v1/tokens/revoke"
	pathLift       = "/v1/revocations/lift"
	pathList       = "/v1/revocations"
	pathForget     = "/v1/directory/forget"
	pathReset      = "/v1/directory/reset-second-factor"
	pathUnlock     = "/v1/directory/unlock"
	pathImport     = "/v1/directory/import"
	pathImportBase = pathImport + "?replace="
)

func adminRefused(format string, args ...any) error {
	return &AdminRefusedError{Detail: fmt.Sprintf(format, args...)}
}

// decodeStrict decodes body as one JSON object into v, refusing an unknown
// field or anything after it, as the broker does.
func decodeStrict(body []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing data")
	}
	return nil
}

// classifyAdmin is the agent's allowlist: the routes of spec §5.1.6, and the
// operation and target each is shown as. It derives them from the request
// alone, with the broker's own spelling (package normal), so a challenge can
// be held to them. Anything else is refused, whatever the caller sends.
func classifyAdmin(req AdminRequest) (adminCall, error) {
	if req.Method == http.MethodGet && req.Path == pathList {
		if len(req.Body) != 0 {
			return adminCall{}, adminRefused("the revocation list takes no body")
		}
		return adminCall{}, nil
	}
	if req.Method != http.MethodPost {
		return adminCall{}, adminRefused("%s %s is not an admin call the agent makes", printsafe.Line(req.Method, 20),
			printsafe.Line(req.Path, 100))
	}
	limit := adminBodyMax
	if req.Path == pathImport || strings.HasPrefix(req.Path, pathImportBase) {
		limit = api.MaxImportBytes
	}
	if len(req.Body) > limit {
		return adminCall{}, adminRefused("the body is over %d bytes", limit)
	}
	bad := func(what string, err error) (adminCall, error) {
		return adminCall{}, adminRefused("%s: %s", what, strings.TrimPrefix(err.Error(), "broker: "))
	}
	switch req.Path {
	case pathRevoke:
		return classifyRevoke(req.Body)
	case pathLift:
		var l api.LiftRequest
		if err := decodeStrict(req.Body, &l); err != nil {
			return bad("not a lift", err)
		}
		switch {
		case l.Principal != "" && l.CertIssuer == "" && l.CertSerial == "":
			p, err := normal.Principal(l.Principal)
			if err != nil {
				return bad("a lift of a principal", err)
			}
			return adminCall{"lift", p}, nil
		case l.Principal == "" && l.CertIssuer != "" && l.CertSerial != "":
			t, err := certTarget(l.CertIssuer, l.CertSerial)
			if err != nil {
				return bad("a lift of a certificate", err)
			}
			return adminCall{"lift", t}, nil
		}
		return adminCall{}, adminRefused("a lift names a principal, or a certificate's cert_issuer and cert_serial")
	case pathForget:
		var p api.PrincipalRequest
		if err := decodeStrict(req.Body, &p); err != nil {
			return bad("not a forget", err)
		}
		n, err := normal.Principal(p.Principal)
		if err != nil {
			return bad("a forget", err)
		}
		return adminCall{"forget_principal", n}, nil
	case pathReset:
		var r api.ResetSecondFactorRequest
		if err := decodeStrict(req.Body, &r); err != nil {
			return bad("not a reset", err)
		}
		switch {
		case r.All && r.Principal == "":
			return adminCall{"reset_second_factor_all", "all"}, nil
		case !r.All && r.Principal != "":
			n, err := normal.User(r.Principal)
			if err != nil {
				return bad("a reset", err)
			}
			return adminCall{"reset_second_factor", n}, nil
		}
		return adminCall{}, adminRefused("a reset names a principal, or all")
	case pathUnlock:
		var p api.PrincipalRequest
		if err := decodeStrict(req.Body, &p); err != nil {
			return bad("not an unlock", err)
		}
		n, err := normal.User(p.Principal)
		if err != nil {
			return bad("an unlock", err)
		}
		return adminCall{"unlock_sign_in", n}, nil
	case pathImport, pathImportBase + "false", pathImportBase + "true":
		if len(bytes.TrimSpace(req.Body)) == 0 {
			return adminCall{}, adminRefused("an import carries the sealed export as its body")
		}
		mode := "merge"
		if req.Path == pathImportBase+"true" {
			mode = "replace"
		}
		sum := sha256.Sum256(req.Body)
		return adminCall{"import_enrollments", mode + " " + hex.EncodeToString(sum[:])[:12]}, nil
	}
	return adminCall{}, adminRefused("%s %s is not an admin call the agent makes", req.Method, printsafe.Line(req.Path, 100))
}

// certTarget is a certificate's target as the broker shows it: its issuer,
// then serial, then the serial as the broker compares it.
func certTarget(issuer, serial string) (string, error) {
	if err := normal.Issuer(issuer); err != nil {
		return "", err
	}
	s, err := normal.Serial(serial)
	if err != nil {
		return "", err
	}
	return issuer + " serial " + s, nil
}

// classifyRevoke is POST /v1/tokens/revoke's admin forms. A revocation of
// one's own sessions (mine) is not one: it goes through POST /revoke.
func classifyRevoke(body []byte) (adminCall, error) {
	var r api.RevokeRequest
	if err := decodeStrict(body, &r); err != nil {
		return adminCall{}, adminRefused("not a revocation: %v", err)
	}
	if r.Mine {
		return adminCall{}, adminRefused("a revocation of your own sessions is not an admin call: it goes through " +
			"the agent's POST /revoke")
	}
	forms := 0
	for _, set := range []bool{r.Principal != "", r.CertIssuer != "" || r.CertSerial != "",
		r.Device != "" || r.Username != "", r.Sid != ""} {
		if set {
			forms++
		}
	}
	if forms != 1 {
		return adminCall{}, adminRefused("a revocation names one of a principal, a certificate, a device and username, " +
			"or a sid")
	}
	switch {
	case r.Principal != "":
		n, err := normal.Principal(r.Principal)
		if err != nil {
			return adminCall{}, adminRefused("a revocation of a principal: %s", strings.TrimPrefix(err.Error(), "broker: "))
		}
		return adminCall{"revoke_principal", n}, nil
	case r.CertIssuer != "" || r.CertSerial != "":
		if r.CertIssuer == "" || r.CertSerial == "" {
			return adminCall{}, adminRefused("a certificate is named by its issuer and its serial, both")
		}
		t, err := certTarget(r.CertIssuer, r.CertSerial)
		if err != nil {
			return adminCall{}, adminRefused("a revocation of a certificate: %v", err)
		}
		return adminCall{"revoke_certificate", t}, nil
	case r.Device != "" || r.Username != "":
		if r.Device == "" || r.Username == "" {
			return adminCall{}, adminRefused("a key is named by its device and username, both")
		}
		return adminCall{"revoke_key", r.Device + "/" + r.Username}, nil
	}
	if r.Issuer == "" {
		return adminCall{}, adminRefused("a sid is named with its issuer")
	}
	return adminCall{"revoke_sid", r.Sid + " at " + r.Issuer}, nil
}

// Admin makes one admin call; AdminPrompt with the prompt written to the log.
func (a *Agent) Admin(ctx context.Context, req AdminRequest) (AdminResponse, error) {
	return a.AdminPrompt(ctx, req, func(line string) { fmt.Fprintf(a.log, "port49 agent: %s\n", line) })
}

// AdminPrompt makes one admin call (spec §5.1.6). It derives the operation and
// target from the request itself and sends the request; an answer that is not
// a challenge is returned as it is. A challenge must name that operation and
// target, or nothing is shown and nothing signed. Then it calls prompt with
// what the touch is for, built from the request and never from the broker's
// words, signs over the held connection's exporter value (the wire released
// for the touch, as decision 45 ruling 14 does), and sends the same request
// with the proof on that connection or not at all (ErrConnectionChanged).
//
// A key that is not configured or cannot be used is refused before anything is
// sent. One touch waits at a time (ErrTouchBusy).
func (a *Agent) AdminPrompt(ctx context.Context, req AdminRequest, prompt func(string)) (AdminResponse, error) {
	call, err := classifyAdmin(req)
	if err != nil {
		return AdminResponse{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, adminTimeout)
	defer cancel()
	select {
	case <-a.done:
		return AdminResponse{}, ErrSessionOver
	default:
	}
	if ends := a.SessionEndsAt(); ends.IsZero() || !a.now().Before(ends) {
		return AdminResponse{}, ErrSessionOver
	}
	if call.op == "" {
		reply, _, err := a.adminAsk(ctx, req, nil)
		return reply.response(), err
	}
	switch {
	case a.touch != nil:
	case a.touchUnusable != "":
		return AdminResponse{}, &TouchUnusableError{"touch_key is configured and cannot be used: " + a.touchUnusable}
	default:
		return AdminResponse{}, &TouchUnusableError{"no touch_key is configured; add touch_key to your config and run " +
			"`port49 login` again"}
	}
	switch a.touch.State() {
	case hwkey.Absent:
		return AdminResponse{}, a.absentOrLocked(&KeyError{Err: hwkey.ErrKeyAbsent}, true)
	case hwkey.Locked:
		return AdminResponse{}, a.absentOrLocked(&KeyError{Err: hwkey.ErrLocked}, true)
	}
	if !a.touching.CompareAndSwap(false, true) {
		return AdminResponse{}, ErrTouchBusy
	}
	defer a.touching.Store(false)

	reply, ekm, err := a.adminAsk(ctx, req, nil)
	if err != nil {
		return AdminResponse{}, err
	}
	if reply.status != http.StatusUnauthorized {
		return reply.response(), nil
	}
	var need struct {
		Error string              `json:"error"`
		Admin *api.AdminChallenge `json:"admin"`
	}
	if json.Unmarshal(reply.body, &need) != nil || need.Error != "admin_touch_required" || need.Admin == nil {
		return reply.response(), nil // a refusal that is not a challenge: the command reads it
	}
	ch := need.Admin
	if ch.Operation != call.op || ch.Target != call.target {
		return AdminResponse{}, ErrChallengeMismatch
	}
	challenge, err := mfatouch.Challenge(ch.Challenge)
	if err != nil {
		return AdminResponse{}, fmt.Errorf("agent: %w", err)
	}
	// The attestations are read before the touch: a token that shows none is
	// said before the key blinks for nothing.
	chain, err := a.touchChain()
	if err != nil {
		return AdminResponse{}, err
	}
	if prompt != nil {
		prompt(fmt.Sprintf("touch your key to %s %s", call.op, printsafe.Line(call.target, 300)))
	}
	sig, err := mfatouch.SignAdmin(a.touch, challenge, api.AdminRequestSHA256(req.Method, req.Path, req.Body), ekm)
	if err != nil {
		if keyFault(err) != nil {
			return AdminResponse{}, a.absentOrLocked(&KeyError{Err: err}, true)
		}
		return AdminResponse{}, fmt.Errorf("agent: signing the admin proof: %w", err)
	}
	header, err := mfatouch.AdminHeader(ch.Challenge, sig, chain)
	if err != nil {
		return AdminResponse{}, err
	}
	reply, _, err = a.adminAsk(ctx, req, &adminProof{header: header, ekm: ekm})
	if err != nil {
		return AdminResponse{}, err
	}
	return reply.response(), nil
}

// adminProof is a signed retry: the header and the exporter value it covers.
type adminProof struct {
	header string
	ekm    []byte
}

// adminReply is the broker's answer to one admin request.
type adminReply struct {
	status int
	body   []byte
}

func (r adminReply) response() AdminResponse { return AdminResponse{Status: r.status, Body: r.body} }

// adminAsk sends req on the held connection and reads the answer; with proof
// it is the retry, posted only on the connection the proof was made over. It
// returns the exporter value of the connection the request travelled on. A
// refusal that ends the session ends it here, as every call's does.
func (a *Agent) adminAsk(ctx context.Context, req AdminRequest, proof *adminProof) (adminReply, []byte, error) {
	if err := a.takeWire(ctx, false, "asked", "that command"); err != nil {
		return adminReply{}, nil, err
	}
	defer a.giveWire(false)
	var sent atomic.Bool
	var ekm []byte
	trace := &httptrace.ClientTrace{
		WroteHeaders: func() { sent.Store(true) },
		GotConn: func(i httptrace.GotConnInfo) {
			if wc, ok := i.Conn.(*watchedConn); ok {
				if cs, has := wc.tlsState(); has {
					ekm, _ = mfatouch.AdminExporter(cs)
				}
			}
		},
	}
	var body io.Reader = http.NoBody
	if len(req.Body) > 0 {
		body = bytes.NewReader(req.Body)
	}
	hreq, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), req.Method, a.broker+req.Path, body)
	if err != nil {
		return adminReply{}, nil, err
	}
	if len(req.Body) > 0 {
		hreq.Header.Set("Content-Type", "application/octet-stream")
		if req.Path != pathImport && !strings.HasPrefix(req.Path, pathImportBase) {
			hreq.Header.Set("Content-Type", "application/json")
		}
	}
	var resp *http.Response
	if proof == nil {
		resp, err = a.doOn(a.adminClient, hreq)
	} else {
		hreq.Header.Set(api.AdminProofHeader, proof.header)
		resp, err = mfatouch.PostRequest(ctx, func(r *http.Request) (*http.Response, error) {
			return a.doOn(a.adminClient, r)
		}, hreq, req.Body, proof.ekm, func(c net.Conn) (tls.ConnectionState, bool) {
			wc, ok := c.(*watchedConn)
			if !ok {
				return tls.ConnectionState{}, false
			}
			return wc.tlsState()
		})
	}
	if err != nil {
		if errors.Is(err, mfatouch.ErrConnectionChanged) {
			return adminReply{}, nil, ErrConnectionChanged
		}
		a.client.CloseIdleConnections()
		if over := a.refusedReconnect(err); over != nil {
			return adminReply{}, nil, over
		}
		var no *BrokerRefusedError
		if errors.As(err, &no) {
			return adminReply{}, nil, no
		}
		if proof != nil && sent.Load() {
			return adminReply{}, nil, &UnansweredAdminError{Err: err}
		}
		var hup *hangUpError
		if errors.As(err, &hup) {
			return adminReply{}, nil, hup
		}
		return adminReply{}, nil, &BrokerUnavailableError{fmt.Errorf("agent: the broker at %s is unreachable: %w",
			a.broker, err)}
	}
	defer drain(resp.Body)
	raw, err := io.ReadAll(io.LimitReader(resp.Body, adminReplyMax))
	if err != nil {
		if proof != nil {
			return adminReply{}, nil, &UnansweredAdminError{Err: err}
		}
		return adminReply{}, nil, fmt.Errorf("agent: the broker's answer: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		var e api.Error
		if json.Unmarshal(raw, &e) == nil {
			if over := sessionOver(resp.StatusCode, e); over != nil {
				a.end(over)
				return adminReply{}, nil, over
			}
		}
		if err := redirected(resp); err != nil {
			return adminReply{}, nil, err
		}
	}
	return adminReply{status: resp.StatusCode, body: raw}, ekm, nil
}

// adminEvent is one line of a streamed POST /admin answer: the prompt, then
// the response or the error.
type adminEvent struct {
	Prompt   string         `json:"prompt,omitempty"`
	Response *AdminResponse `json:"response,omitempty"`
	Error    *adminFailure  `json:"error,omitempty"`
}

// adminFailure is the error answer the socket would have given, carried in a
// stream whose status line is already sent.
type adminFailure struct {
	Status     int             `json:"status"`
	RetryAfter string          `json:"retry_after,omitempty"`
	Body       json.RawMessage `json:"body"`
}

// captured is a ResponseWriter that keeps what answer wrote.
type captured struct {
	h    http.Header
	code int
	buf  bytes.Buffer
}

func (c *captured) Header() http.Header         { return c.h }
func (c *captured) Write(p []byte) (int, error) { return c.buf.Write(p) }
func (c *captured) WriteHeader(code int)        { c.code = code }

// adminHandler is POST /admin. The prompt is sent the moment the agent has
// built it, before the touch is waited on, so the command can show it: the
// answer is then a stream (adminStreamType). A call that never reaches a
// touch is answered as every other socket call is.
func (a *Agent) adminHandler(w http.ResponseWriter, r *http.Request) {
	var req AdminRequest
	dec := json.NewDecoder(io.LimitReader(r.Body, adminRequestMax))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, api.Error{Error: "bad_request", Detail: "not an admin request"})
		return
	}
	flusher, _ := w.(http.Flusher)
	enc := json.NewEncoder(w)
	streaming := false
	out, err := a.AdminPrompt(r.Context(), req, func(line string) {
		if !streaming {
			w.Header().Set("Content-Type", adminStreamType)
			w.WriteHeader(http.StatusOK)
			streaming = true
		}
		_ = enc.Encode(adminEvent{Prompt: line})
		if flusher != nil {
			flusher.Flush()
		}
	})
	if !streaming {
		answer(w, out, err)
		return
	}
	if err == nil {
		_ = enc.Encode(adminEvent{Response: &out})
		return
	}
	c := &captured{h: http.Header{}, code: http.StatusOK}
	answer(c, nil, err)
	_ = enc.Encode(adminEvent{Error: &adminFailure{Status: c.code, RetryAfter: c.h.Get("Retry-After"),
		Body: bytes.TrimSpace(c.buf.Bytes())}})
}
