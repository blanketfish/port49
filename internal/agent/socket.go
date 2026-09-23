package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	if st, ok := fi.Sys().(*syscall.Stat_t); !ok || int(st.Uid) != os.Getuid() {
		return fmt.Errorf("agent: %s is not owned by you (uid %d); whoever owns it can replace the socket, "+
			"so it is refused - remove it or pass --socket", dir, os.Getuid())
	}
	return nil
}

// Listen opens the agent's socket at path, refusing to start beside a live
// agent and clearing a stale socket a dead one left.
func Listen(path string) (net.Listener, error) {
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
		// after it; the caller still matches it with errors.Is.
		var e api.Error
		_ = json.NewDecoder(resp.Body).Decode(&e)
		return api.MintItem{}, fmt.Errorf("%w%s", ErrSessionOver, strings.TrimPrefix(e.Detail, ErrSessionOver.Error()))
	default:
		var e api.Error
		_ = json.NewDecoder(resp.Body).Decode(&e)
		return api.MintItem{}, fmt.Errorf("agent: %s: %s", e.Error, e.Detail)
	}
}

// Status asks the agent whose session it holds.
func (c *Client) Status(ctx context.Context) (Status, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://agent/status", nil)
	if err != nil {
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
