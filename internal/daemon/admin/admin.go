// Package admin is port49d's local admin socket (plan 6a owner decision 2):
// a Unix socket, mode 0600, that answers only port49d's own uid and root,
// and serves one read-only operation, keys_diagnose (spec §10). It is off
// unless admin_socket is set. No answer carries a key, a held body, a token
// or a credential: a diagnosis names key versions and nothing else.
package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/rhwendt/port49/internal/keyring"
)

// Request is one line a client sends.
type Request struct {
	Op     string `json:"op"`
	Device string `json:"device"`
}

// Response is the one line port49d answers.
type Response struct {
	Error   string           `json:"error,omitempty"`
	Text    string           `json:"text,omitempty"`
	Finding *keyring.Finding `json:"finding,omitempty"`
}

// Server answers the socket.
type Server struct {
	Held     *keyring.Held
	Keys     map[string]keyring.Set
	Assigned func(device string) string
	Now      func() time.Time
}

const maxRequest = 4096

// Listen opens the socket at path, mode 0600. A stale socket at path — one
// whose dial is refused, so nothing listens on it — is removed. Any other
// socket is refused and left alone: one another process answers on, a second
// port49d sharing the path, and one this uid cannot dial at all, such as
// another uid's port49d's 0600 socket, whose dial fails with EACCES. So is
// anything at path that is not a socket: a symlink is never followed, and no
// mode is ever set through the path.
func Listen(path string) (net.Listener, error) {
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("%s exists and is not a socket; port49d will not remove it", path)
		}
		c, err := net.DialTimeout("unix", path, time.Second)
		if err == nil {
			c.Close()
			return nil, fmt.Errorf("another process answers on %s; give each port49d its own admin_socket", path)
		}
		if !stale(err) {
			return nil, fmt.Errorf("%s is a socket port49d cannot tell is stale (%v); port49d will not remove it",
				path, errors.Unwrap(err))
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return listenPrivate(path)
}

// stale reports whether a dial error says nothing listens on the socket:
// ECONNREFUSED alone. Anything else, a permission refused or a listener too
// busy to accept, may be a live port49d's socket.
func stale(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED)
}

// Serve answers until ctx ends.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go s.handle(c)
	}
}

// handle answers one connection. The peer is checked on every connection,
// before a byte of the request is read.
func (s *Server) handle(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	enc := json.NewEncoder(c)
	if err := peerAllowed(c); err != nil {
		_ = enc.Encode(Response{Error: "refused: " + err.Error()})
		return
	}
	var req Request
	if err := json.NewDecoder(io.LimitReader(c, maxRequest)).Decode(&req); err != nil {
		_ = enc.Encode(Response{Error: "a request is one JSON object"})
		return
	}
	_ = enc.Encode(s.answer(req))
}

func (s *Server) answer(req Request) Response {
	if req.Op != "keys_diagnose" {
		return Response{Error: "unknown op; the one op is keys_diagnose"}
	}
	assigned := ""
	if s.Assigned != nil {
		assigned = s.Assigned(req.Device)
	}
	now := s.Now()
	f, ok := keyring.Diagnose(s.Held, s.Keys, req.Device, assigned, now)
	if !ok {
		return Response{Error: fmt.Sprintf("port49d holds no unvalidated packet from %q since it started", req.Device)}
	}
	return Response{Text: f.Text(now), Finding: &f}
}

// uidAllowed is the rule peerAllowed applies: port49d's own uid, and root.
func uidAllowed(uid, own uint32) error {
	if uid != 0 && uid != own {
		return fmt.Errorf("uid %d is neither port49d's (%d) nor root", uid, own)
	}
	return nil
}
