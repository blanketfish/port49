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
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/rhwendt/port49/internal/broker/api"
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
			"at mode 0700", dir)
	}
	if !fi.IsDir() || fi.Mode().Perm() != 0o700 {
		return fmt.Errorf("agent: %s must be a directory at mode 0700, and it is %v; its mode is the socket's "+
			"access control", dir, fi.Mode().Perm())
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); !ok || int(st.Uid) != getuid() {
		return fmt.Errorf("agent: %s is not owned by you (uid %d); whoever owns it can replace the socket, "+
			"so it is refused - remove it or pass --socket", dir, getuid())
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
			"pass a shorter --socket", path, len(path), maxSocketPath)
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

// NewClient talks to the agent at socket.
func NewClient(socket string) *Client {
	return &Client{socket: socket, http: &http.Client{Timeout: 90 * time.Second, Transport: &http.Transport{
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
	return checkPrivateDir(dir)
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
	default:
		var e api.Error
		_ = json.NewDecoder(resp.Body).Decode(&e)
		return api.MintItem{}, fmt.Errorf("agent: %s: %s", e.Error, e.Detail)
	}
}

// Refresh asks the agent to refresh the session it holds and answers what
// the broker extended.
func (c *Client) Refresh(ctx context.Context) (api.RefreshResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://agent/refresh", http.NoBody)
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
	var e api.Error
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
	default:
		// refresh_failed's detail is the agent's own error, already saying
		// what the broker answered.
		_ = json.NewDecoder(resp.Body).Decode(&e)
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
		return fmt.Errorf("%w at %s: %v", ErrNoAgent, c.socket, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	var e api.Error
	_ = json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&e)
	switch {
	case resp.StatusCode == http.StatusGone && e.Error == "credential_revoked":
		return &RevokedError{Detail: e.Detail}
	case resp.StatusCode == http.StatusGone:
		return fmt.Errorf("%w%s", ErrSessionOver, strings.TrimPrefix(e.Detail, ErrSessionOver.Error()))
	case resp.StatusCode == http.StatusNotFound && e.Error == "":
		return ErrAgentTooOld
	case resp.StatusCode == http.StatusBadGateway && e.Error == "broker_error":
		return errors.New(e.Detail)
	case e.Error != "":
		return &APIError{Status: resp.StatusCode, Code: e.Error, Detail: e.Detail}
	}
	return fmt.Errorf("agent: the agent at %s answered %s", c.socket, resp.Status)
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
func (c *Client) Revoke(ctx context.Context, req api.RevokeRequest) (api.RevokeResponse, error) {
	var out api.RevokeResponse
	return out, c.roundTrip(ctx, http.MethodPost, "/revoke", req, &out)
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
