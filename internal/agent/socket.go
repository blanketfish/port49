package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/blanketfish/port49/internal/broker/api"
	"github.com/blanketfish/port49/internal/hwkey"
	"github.com/blanketfish/port49/internal/mfatouch"
)

// ErrNoAgent is a socket nothing answers on. The answer is `port49 login`.
var ErrNoAgent = errors.New("agent: no agent is listening")

// getuid is os.Getuid, swapped in tests: seen as another uid, a directory the
// test created is a squatter's, which is how the owner check is tested
// without a second account.
var getuid = os.Getuid

// SocketPath is where the agent listens by default:
// $XDG_RUNTIME_DIR/port49/agent.sock, or /tmp/port49-<uid>/agent.sock on a
// host without one.
func SocketPath() string {
	// PORT49_TEST_AGENT_SOCKET is the tests' only way to point a command at
	// an agent of its own: no flag names a socket, and nothing but a test sets
	// this.
	if p := os.Getenv("PORT49_TEST_AGENT_SOCKET"); p != "" {
		return p
	}
	if d := os.Getenv("XDG_RUNTIME_DIR"); d != "" {
		return filepath.Join(d, "port49", "agent.sock")
	}
	return filepath.Join(os.TempDir(), fmt.Sprintf("port49-%d", os.Getuid()), "agent.sock")
}

// PrivateDir makes dir at mode 0700, or accepts an existing one only if it is
// a real directory (not a symlink), at exactly that mode, owned by this user.
// The directory is the socket's whole access control — whoever can reach the
// socket can mint as this operator, and whoever owns the directory can swap
// the socket for their own — so anything else is refused rather than
// narrowed. On the /tmp fallback anyone can create /tmp/port49-<uid> first
// (pre-flight F4).
func PrivateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return checkPrivateDir(dir)
}

// checkPrivateDir is PrivateDir's check without the MkdirAll. The client runs
// it too, before it dials: a socket in a directory someone else owns is
// someone else's, and asking it for a token tells it which device the
// operator is about to log in to.
func checkPrivateDir(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("agent: %s is a symlink; the socket's directory must be a real directory you own, "+
			"at mode 0700; remove the link and create the directory with mode 0700, or set XDG_RUNTIME_DIR to a "+
			"directory you own", dir)
	}
	if !fi.IsDir() || fi.Mode().Perm() != 0o700 {
		return fmt.Errorf("agent: %s must be a directory at mode 0700, and it is %v; its mode is the socket's "+
			"access control; run chmod 700 %s, or set XDG_RUNTIME_DIR to a directory you own", dir, fi.Mode().Perm(), dir)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); !ok || int(st.Uid) != getuid() {
		return fmt.Errorf("agent: %s is not owned by you (uid %d); whoever owns it can replace the socket, "+
			"so it is refused - remove it, or set XDG_RUNTIME_DIR to a directory you own", dir, getuid())
	}
	return nil
}

// maxSocketPath is the longest path a Unix socket address holds on Linux:
// sun_path is 108 bytes, one of them the terminating NUL.
const maxSocketPath = 107

// Listen opens the agent's socket at path, refusing to start beside a live
// agent and clearing a stale socket a dead one left.
func Listen(path string) (net.Listener, error) {
	if len(path) > maxSocketPath {
		return nil, fmt.Errorf("agent: the socket path %s is %d bytes, too long for a Unix socket (at most %d); "+
			"set XDG_RUNTIME_DIR to a shorter directory", path, len(path), maxSocketPath)
	}
	if err := PrivateDir(filepath.Dir(path)); err != nil {
		return nil, err
	}
	if c, err := net.Dial("unix", path); err == nil {
		c.Close()
		return nil, fmt.Errorf("agent: an agent is already listening at %s", path)
	}
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

// Client is `port49 token`'s side of the socket.
type Client struct {
	socket string
	http   *http.Client
}

// socketTimeout bounds a call to the agent: past its longest wait on the
// broker (revokeWait), so the agent is always the side that gives up, and
// says why.
const socketTimeout = revokeWait + 10*time.Second

// NewClient talks to the agent at socket.
func NewClient(socket string) *Client {
	return &Client{socket: socket, http: &http.Client{Timeout: socketTimeout, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		}}}}
}

// checkDir refuses a socket whose directory is not private before anything
// dials it. A directory that is not there is no agent.
func (c *Client) checkDir() error {
	dir := filepath.Dir(c.socket)
	if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%w at %s: %v", ErrNoAgent, c.socket, err)
	}
	if err := checkPrivateDir(dir); err != nil {
		return err
	}
	return c.checkSocket()
}

// checkSocket refuses a path that is there and is not a socket, or is a socket another user owns,
// before anything dials it: the agent answers whoever connects, and what a client sends it names
// the device the operator is about to log in to. PORT49_TEST_AGENT_SOCKET names any path, so this
// is what keeps it from naming someone else's. A path that is not there is no agent.
func (c *Client) checkSocket() error {
	fi, err := os.Lstat(c.socket)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil
	case err != nil:
		return err
	case fi.Mode().Type() != os.ModeSocket:
		return fmt.Errorf("agent: %s is not a socket; the agent's socket is refused rather than dialled", c.socket)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); !ok || int(st.Uid) != getuid() {
		return fmt.Errorf("agent: the socket %s is not owned by you (uid %d); it is refused rather than dialled, "+
			"since whoever owns it can read what you ask the agent for", c.socket, getuid())
	}
	return nil
}

// Token asks the agent to mint one device.
func (c *Client) Token(ctx context.Context, r TokenRequest) (api.MintItem, error) {
	body, err := json.Marshal(r)
	if err != nil {
		return api.MintItem{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://agent/token", bytes.NewReader(body))
	if err != nil {
		return api.MintItem{}, err
	}
	if err := c.checkDir(); err != nil {
		return api.MintItem{}, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return api.MintItem{}, fmt.Errorf("%w at %s: %v", ErrNoAgent, c.socket, err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		var item api.MintItem
		if err := json.NewDecoder(resp.Body).Decode(&item); err != nil {
			return api.MintItem{}, err
		}
		if item.Error != "" {
			return item, &ItemError{Device: item.Device, Code: item.Error, Detail: item.Detail}
		}
		return item, nil
	case http.StatusPreconditionRequired:
		var need api.PerLoginMFA
		if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&need); err != nil || need.Challenge == "" {
			return api.MintItem{}, errors.New("agent: the agent's requirement is malformed")
		}
		return api.MintItem{Device: r.Device}, &MFARequiredError{Requirement: need}
	case http.StatusGone:
		// Detail is the agent's ErrSessionOver with why the session ended
		// after it, or, for a revocation, the broker's detail alone; the
		// caller still matches either with errors.Is.
		var e api.Error
		_ = json.NewDecoder(resp.Body).Decode(&e)
		if e.Error == "credential_revoked" {
			return api.MintItem{}, &RevokedError{Detail: e.Detail}
		}
		return api.MintItem{}, fmt.Errorf("%w%s", ErrSessionOver, strings.TrimPrefix(e.Detail, ErrSessionOver.Error()))
	case http.StatusServiceUnavailable:
		var e api.Error
		_ = json.NewDecoder(resp.Body).Decode(&e)
		if e.Error == "revocation_running" {
			return api.MintItem{}, &RevocationRunningError{Detail: e.Detail}
		}
		if e.Error == codeBrokerUnavailable {
			return api.MintItem{}, &BrokerUnavailableError{errors.New(e.Detail)}
		}
		if e.Error == codeStoreUnavailable {
			return api.MintItem{}, &StoreUnavailableError{Err: &BrokerUnavailableError{errors.New(e.Detail)},
				RetryAfter: retryAfterHeader(resp.Header)}
		}
		return api.MintItem{}, fmt.Errorf("agent: %s: %s", e.Error, e.Detail)
	default:
		var e refusalBody
		_ = json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&e)
		if refused := e.refused(); refused != nil {
			return api.MintItem{}, refused
		}
		if ke := keyErrorFromCode(e.Error, e.Detail); ke != nil {
			return api.MintItem{}, ke
		}
		return api.MintItem{}, fmt.Errorf("agent: %s: %s", e.Error, e.Detail)
	}
}

// Refresh asks the agent to refresh the session it holds and answers what
// the broker extended. challenge, when not empty, names the proof that covers
// the contexts a per-login requirement left.
func (c *Client) Refresh(ctx context.Context, challenge string) (api.RefreshResponse, error) {
	var rd io.Reader = http.NoBody
	if challenge != "" {
		body, err := json.Marshal(RefreshRequest{PerLoginMFAChallenge: challenge})
		if err != nil {
			return api.RefreshResponse{}, err
		}
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://agent/refresh", rd)
	if err != nil {
		return api.RefreshResponse{}, err
	}
	if err := c.checkDir(); err != nil {
		return api.RefreshResponse{}, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return api.RefreshResponse{}, fmt.Errorf("%w at %s: %v", ErrNoAgent, c.socket, err)
	}
	defer resp.Body.Close()
	var e refusalBody
	switch resp.StatusCode {
	case http.StatusOK:
		var out api.RefreshResponse
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			return api.RefreshResponse{}, err
		}
		return out, nil
	case http.StatusGone:
		// As Token's: a revocation is rebuilt without the text that says to
		// log in.
		_ = json.NewDecoder(resp.Body).Decode(&e)
		if e.Error == "credential_revoked" {
			return api.RefreshResponse{}, &RevokedError{Detail: e.Detail}
		}
		return api.RefreshResponse{}, fmt.Errorf("%w%s", ErrSessionOver, strings.TrimPrefix(e.Detail, ErrSessionOver.Error()))
	case http.StatusServiceUnavailable:
		_ = json.NewDecoder(resp.Body).Decode(&e)
		if e.Error == "revocation_running" {
			return api.RefreshResponse{}, &RevocationRunningError{Detail: e.Detail}
		}
		return api.RefreshResponse{}, fmt.Errorf("agent: %s: %s", e.Error, e.Detail)
	default:
		// refresh_failed's detail is the agent's own error, already saying
		// what the broker answered.
		_ = json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&e)
		if refused := e.refused(); refused != nil {
			return api.RefreshResponse{}, refused
		}
		if ke := keyErrorFromCode(e.Error, e.Detail); ke != nil {
			return api.RefreshResponse{}, ke
		}
		if e.Error == "refresh_failed" {
			return api.RefreshResponse{}, errors.New(e.Detail)
		}
		return api.RefreshResponse{}, fmt.Errorf("agent: %s: %s", e.Error, e.Detail)
	}
}

// ErrAgentTooOld is a call the running agent has no route for: it was
// started by a port49 older than this one, and lives until max_session_age
// (pre-flight I9).
var ErrAgentTooOld = errors.New("agent: your agent (started before this port49) does not carry this command; " +
	"run `port49 login` again")

// roundTrip asks the agent one API call: a 200 decodes into out; a 410 is
// the session's end (a revocation's own error, or ErrSessionOver); a 404
// with no API code is the agent's own mux, which predates the route
// (ErrAgentTooOld); the agent's 502 broker_error is its own error, said as
// it is; any other answer carries the broker's status and code, a 503
// revocation_busy among them, and is an *APIError.
func (c *Client) roundTrip(ctx context.Context, method, path string, in, out any) error {
	var rd io.Reader = http.NoBody
	if in != nil {
		body, err := json.Marshal(in)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://agent"+path, rd)
	if err != nil {
		return err
	}
	if err := c.checkDir(); err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%w at %s: %w", ErrNoAgent, c.socket, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return &badAnswerError{err}
		}
		return nil
	}
	return c.answerError(resp)
}

// answerError is the error a non-200 answer from the agent means: the
// switch of roundTrip's comment.
func (c *Client) answerError(resp *http.Response) error {
	var e refusalBody
	_ = json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&e)
	switch {
	case e.refused() != nil:
		return e.refused()
	case e.Error == codeNoAttestation:
		return fmt.Errorf("agent: %w", mfatouch.ErrNoAttestation)
	case resp.StatusCode == http.StatusGone && e.Error == "credential_revoked":
		return &RevokedError{Detail: e.Detail}
	case resp.StatusCode == http.StatusGone:
		return fmt.Errorf("%w%s", ErrSessionOver, strings.TrimPrefix(e.Detail, ErrSessionOver.Error()))
	case resp.StatusCode == http.StatusNotFound && e.Error == "":
		return ErrAgentTooOld
	case resp.StatusCode == http.StatusBadGateway && e.Error == "broker_error":
		return &BrokerFaultError{errors.New(e.Detail)}
	case resp.StatusCode == http.StatusConflict && e.Error == "connection_changed":
		return ErrConnectionChanged
	case keyErrorFromCode(e.Error, e.Detail) != nil:
		return keyErrorFromCode(e.Error, e.Detail)
	case resp.StatusCode == http.StatusServiceUnavailable && e.Error == "revocation_running":
		return &RevocationRunningError{Detail: e.Detail}
	case resp.StatusCode == http.StatusServiceUnavailable && e.Error == codeBrokerUnavailable:
		return &BrokerUnavailableError{errors.New(e.Detail)}
	case resp.StatusCode == http.StatusServiceUnavailable && e.Error == codeStoreUnavailable:
		return &StoreUnavailableError{Err: &BrokerUnavailableError{errors.New(e.Detail)}, RetryAfter: retryAfterHeader(resp.Header)}
	case resp.StatusCode == http.StatusBadRequest && e.Error == codeAdminRefused:
		return &AdminRefusedError{Detail: e.Detail}
	case resp.StatusCode == http.StatusConflict && e.Error == codeTouchUnusable:
		return &TouchUnusableError{Detail: e.Detail}
	case resp.StatusCode == http.StatusConflict && e.Error == codeTouchBusy:
		return ErrTouchBusy
	case e.Error == codeChallengeMismatch:
		return ErrChallengeMismatch
	case e.Error == codeAdminUnanswered:
		return &UnansweredAdminError{Err: errors.New(e.Detail)}
	case e.Error != "":
		return &APIError{Status: resp.StatusCode, Code: e.Error, Detail: e.Detail, RetryAfter: retryAfterHeader(resp.Header)}
	}
	return fmt.Errorf("agent: the agent at %s answered %s", c.socket, resp.Status)
}

// ProveTouch asks the agent to prove challenge with its touch key: the key
// blinks and the person touches it. A touch not made, a locked key or a key
// that is gone is a *KeyError; a connection that changed meanwhile is
// ErrConnectionChanged; the broker's refusal is an *APIError.
func (c *Client) ProveTouch(ctx context.Context, challenge string) error {
	var out struct{}
	return c.roundTrip(ctx, http.MethodPost, "/mfa/touch", TouchRequest{Challenge: challenge}, &out)
}

// Identity asks the agent what the broker resolves its principal to.
func (c *Client) Identity(ctx context.Context) (api.Identity, error) {
	var out api.Identity
	return out, c.roundTrip(ctx, http.MethodGet, "/identity", nil, &out)
}

// Explain asks the agent for the broker's explanation.
func (c *Client) Explain(ctx context.Context, req api.ExplainRequest) (api.ExplainResponse, error) {
	var out api.ExplainResponse
	return out, c.roundTrip(ctx, http.MethodPost, "/explain", req, &out)
}

// Revoke asks the agent to send a revocation under its principal's rights.
// One the agent took and never answered is an *UnansweredRevokeError, not
// ErrNoAgent: it may have reached the broker.
func (c *Client) Revoke(ctx context.Context, req api.RevokeRequest) (api.RevokeResponse, error) {
	var out api.RevokeResponse
	var sent atomic.Bool
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{WroteHeaders: func() { sent.Store(true) }})
	unanswered := func(err error) error {
		return &UnansweredRevokeError{Who: "your agent at " + c.socket, Principal: req.Principal != "", Err: err}
	}
	err := c.roundTrip(ctx, http.MethodPost, "/revoke", req, &out)
	var bad *badAnswerError
	switch {
	case errors.Is(err, ErrNoAgent) && sent.Load():
		var cause error = err
		if ue := (*url.Error)(nil); errors.As(err, &ue) {
			cause = ue.Err
		}
		return out, unanswered(cause)
	case errors.As(err, &bad):
		// An agent that died mid-write: it may have reached the broker.
		return api.RevokeResponse{}, unanswered(fmt.Errorf("its 200 did not decode: %w", bad.err))
	case err == nil && out.By == "":
		return api.RevokeResponse{}, unanswered(errors.New("its 200 named no revocation"))
	}
	return out, err
}

// badAnswerError is a 200 from the agent whose body did not decode. Its text
// is the decode error's, as it always was; Revoke tells it apart.
type badAnswerError struct{ err error }

func (e *badAnswerError) Error() string { return e.err.Error() }
func (e *badAnswerError) Unwrap() error { return e.err }

// Unlock gives the agent's key its PIN: POST /unlock {"pin": "…"}. The body
// is built in a []byte, zeroed after the write, and pin is zeroed too. A PIN
// the token refused is a *hwkey.PINError with the token's tries-left flags.
func (c *Client) Unlock(ctx context.Context, pin []byte) error {
	defer clear(pin)
	body := make([]byte, 0, len(pin)+16)
	defer func() { clear(body) }()
	body = append(body, `{"pin":"`...)
	for _, b := range pin {
		switch {
		case b == '"' || b == '\\':
			body = append(body, '\\', b)
		case b < 0x20:
			return errors.New("agent: a PIN holds no control characters")
		default:
			body = append(body, b)
		}
	}
	body = append(body, `"}`...)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://agent/unlock", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if err := c.checkDir(); err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%w at %s: %v", ErrNoAgent, c.socket, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	var e UnlockRefusal
	_ = json.NewDecoder(io.LimitReader(resp.Body, 4<<10)).Decode(&e)
	switch {
	case resp.StatusCode == http.StatusNotFound && e.Error == "":
		return ErrAgentTooOld
	case resp.StatusCode == http.StatusUnauthorized && e.Error == "pin_blocked":
		return &hwkey.PINError{Blocked: true}
	case resp.StatusCode == http.StatusUnauthorized && e.Error == "pin_refused":
		return &hwkey.PINError{Low: e.Low, Final: e.Final}
	case resp.StatusCode == http.StatusConflict && e.Error == "key_absent":
		return hwkey.ErrKeyAbsent
	case e.Error != "":
		return fmt.Errorf("agent: %s: %s", e.Error, e.Detail)
	}
	return fmt.Errorf("agent: the agent at %s answered %s", c.socket, resp.Status)
}

// Status asks the agent whose session it holds.
func (c *Client) Status(ctx context.Context) (Status, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://agent/status", nil)
	if err != nil {
		return Status{}, err
	}
	if err := c.checkDir(); err != nil {
		return Status{}, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return Status{}, fmt.Errorf("%w at %s: %v", ErrNoAgent, c.socket, err)
	}
	defer resp.Body.Close()
	var s Status
	if err := json.NewDecoder(resp.Body).Decode(&s); err != nil {
		return Status{}, err
	}
	return s, nil
}

// Admin asks the agent to make one admin call (spec §5.1.6) and returns the
// broker's answer. prompt is called with what the touch is for, as the agent
// built it from the request, once the broker has asked and before the key is
// waited on; it is never called for a call that needs no touch or that the
// agent refuses. One the agent took and never answered, after the proof was
// on its way, is an *UnansweredAdminError, not ErrNoAgent: it may have run.
func (c *Client) Admin(ctx context.Context, req AdminRequest, prompt func(string)) (AdminResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return AdminResponse{}, err
	}
	var sent atomic.Bool
	// The agent gives up first, past adminTimeout, and says why; the client's
	// own Timeout is sized for a mint.
	ctx, cancel := context.WithTimeout(ctx, adminTimeout+10*time.Second)
	defer cancel()
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{WroteHeaders: func() { sent.Store(true) }})
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://agent/admin", bytes.NewReader(body))
	if err != nil {
		return AdminResponse{}, err
	}
	if err := c.checkDir(); err != nil {
		return AdminResponse{}, err
	}
	resp, err := (&http.Client{Transport: c.http.Transport}).Do(hreq)
	if err != nil {
		if sent.Load() {
			var cause error = err
			if ue := (*url.Error)(nil); errors.As(err, &ue) {
				cause = ue.Err
			}
			return AdminResponse{}, &UnansweredAdminError{Err: fmt.Errorf("your agent at %s: %w", c.socket, cause)}
		}
		return AdminResponse{}, fmt.Errorf("%w at %s: %w", ErrNoAgent, c.socket, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return AdminResponse{}, c.answerError(resp)
	}
	if resp.Header.Get("Content-Type") != adminStreamType {
		var out AdminResponse
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			return AdminResponse{}, &UnansweredAdminError{Err: fmt.Errorf("your agent's answer did not decode: %w", err)}
		}
		return out, nil
	}
	dec := json.NewDecoder(resp.Body)
	for {
		var ev adminEvent
		if err := dec.Decode(&ev); err != nil {
			return AdminResponse{}, &UnansweredAdminError{Err: fmt.Errorf("your agent at %s stopped answering: %w",
				c.socket, err)}
		}
		switch {
		case ev.Prompt != "":
			if prompt != nil {
				prompt(ev.Prompt)
			}
		case ev.Response != nil:
			return *ev.Response, nil
		case ev.Error != nil:
			h := http.Header{}
			if ev.Error.RetryAfter != "" {
				h.Set("Retry-After", ev.Error.RetryAfter)
			}
			return AdminResponse{}, c.answerError(&http.Response{StatusCode: ev.Error.Status, Header: h,
				Body: io.NopCloser(bytes.NewReader(ev.Error.Body))})
		}
	}
}
