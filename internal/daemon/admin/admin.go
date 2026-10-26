// Package admin is port49d's local admin socket (plan 6a owner decision 2):
// a Unix socket, mode 0600, that answers only port49d's own uid and root,
// and serves keys_diagnose (spec §10), which is read-only, and revoke and
// revocations (plan 7a), which put a revocation in force or lift it: the
// same people can already rewrite the policy file and cut anyone's access.
// directory_forget (plan 7g) deletes a principal's directory membership and
// its pin. second_factor_reset, sign_in_unlock, enrollments_init,
// enrollments_export and enrollments_import (plan 9e) are the operator's side
// of the directory-password sign-in; an import's body, up to 64 MiB, follows
// its request line on the connection.
// It is off unless admin_socket is set. No answer carries a key, a held
// body, a token or a credential: a diagnosis names key versions and nothing
// else, and a revocation names what it revoked and what it reached.
package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"slices"
	"syscall"
	"time"

	"github.com/rhwendt/port49/internal/config"

	"github.com/rhwendt/port49/internal/keyring"
	"github.com/rhwendt/port49/internal/printsafe"
)

// Request is one line a client sends.
type Request struct {
	Op     string `json:"op"`
	Device string `json:"device"`
	// Principal, CertIssuer and CertSerial name what op "revoke" revokes,
	// or with Lift lifts (plan 7a): a principal, or a certificate, not both.
	Principal  string `json:"principal,omitempty"`
	CertIssuer string `json:"cert_issuer,omitempty"`
	CertSerial string `json:"cert_serial,omitempty"`
	Lift       bool   `json:"lift,omitempty"`
	// All makes second_factor_reset the reopening of every entry with no
	// active second factor (plan 9e, D7); Replace lets enrollments_import
	// overwrite a store holding a second factor enrolled or reset after the
	// export (D13).
	All     bool `json:"all,omitempty"`
	Replace bool `json:"replace,omitempty"`
	// body is what follows an enrollments_import request line on the
	// connection, set by handle: never decoded from the request.
	body io.Reader
}

// RevokeOp is one `port49 revoke`, with the uid that asked (SO_PEERCRED),
// which the revoke record names as its origin.
type RevokeOp struct {
	Principal, Issuer, Serial string
	Lift                      bool
	UID                       uint32
}

// OpTimeout bounds a revoke's or lift's wait for its turn behind another,
// and a list. A revocation under way is bounded by Broker.RevokeTimeout,
// which port49d sets to this, so the connection's deadline covers both.
const OpTimeout = 60 * time.Second

// PersistTimeout bounds the revocations_file write a revocation or lift
// waits on; port49d's persister gives up on the file at it.
const PersistTimeout = 5 * time.Second

// answerMargin is the time the connection is given past an op's bounds to
// write its answer.
const answerMargin = 10 * time.Second

// RevokeWait is how long port49d holds a revoke's or lift's connection open
// at the default OpTimeout: its wait for its turn, its run (Broker.
// RevokeTimeout, which port49d sets to OpTimeout), and the answer. The
// revocations_file save runs inside the run's bound; PersistTimeout is
// headroom for it. A client waits longer, so it is never the side that
// gives up first on a revocation that goes on to finish.
const RevokeWait = 2*OpTimeout + PersistTimeout + answerMargin

// ListWait is RevokeWait for a list, which takes no turn.
const ListWait = OpTimeout + answerMargin

// StatusOpTimeout bounds a store_status: its reads run at once, each store's
// Ping beside its member count, which is a member list and then a status
// read, so it takes about two call_timeouts, and call_timeout is at most
// config.MaxCallTimeout.
const StatusOpTimeout = 2 * config.MaxCallTimeout

// StatusWait is how long a store_status's connection is held open, and how
// long `port49 store status` waits: the op's bound and the answer.
const StatusWait = StatusOpTimeout + answerMargin

// Response is the one line port49d answers.
type Response struct {
	Error   string           `json:"error,omitempty"`
	Text    string           `json:"text,omitempty"`
	Finding *keyring.Finding `json:"finding,omitempty"`
	// Partial is a revocation or lift in force that did not finish or was
	// not saved; `port49 revoke` exits 3 on it (plan 7a).
	Partial bool `json:"partial,omitempty"`
	// Degraded is a store_status in which a store did not answer; `port49
	// store status` exits 3 on it (plan 11a, R21).
	Degraded bool `json:"degraded,omitempty"`
	// Sealed is enrollments_export's body, sealed whole under the broker's
	// key (plan 9e, D13); base64 in JSON. At most maxImport bytes.
	Sealed []byte `json:"sealed,omitempty"`
}

// Server answers the socket.
type Server struct {
	// StoreStatus answers `port49 store status` (plan 11a, R21): each
	// store's line as this process sees it, and whether one did not answer.
	// Nil when the process reports no stores.
	StoreStatus func(ctx context.Context) (text string, degraded bool, err error)
	Held        *keyring.Held
	Keys        func() map[string]keyring.Set
	Assigned    func(device string) string
	Now         func() time.Time
	// Revoke and Revocations answer `port49 revoke` (plan 7a). Nil when
	// port49d runs no broker; the ops are then refused, saying so.
	Revoke      func(ctx context.Context, op RevokeOp) (text string, partial bool, err error)
	Revocations func(ctx context.Context) (string, error)
	// RevokeElsewhere names where revocation is answered when this process
	// runs no broker (plan 7e, Ruling 13): port49d on etcd, beside
	// port49-broker. Empty keeps the memory store's line.
	RevokeElsewhere string
	// Forget answers `port49 directory forget` (plan 7g, Ruling 3's
	// escape): it deletes a principal's directory membership, pin
	// included. Nil when this process runs no broker.
	Forget func(ctx context.Context, principal string, uid uint32) (string, error)
	// SecondFactorReset, SignInUnlock, EnrollmentsInit, EnrollmentsExport and
	// EnrollmentsImport answer `port49 directory reset-second-factor`,
	// `unlock`, `init-enrollments`, `export` and `import` (plan 9e). Nil when
	// this process runs no broker, or the broker has no directory_password
	// verifier: the ops are then refused, saying so.
	SecondFactorReset func(ctx context.Context, principal string, all bool, uid uint32) (string, error)
	SignInUnlock      func(ctx context.Context, principal string, uid uint32) (string, error)
	EnrollmentsInit   func(ctx context.Context, uid uint32) (string, error)
	EnrollmentsExport func(ctx context.Context, uid uint32) ([]byte, error)
	EnrollmentsImport func(ctx context.Context, sealed []byte, replace bool, uid uint32) (string, error)
	// DiagnoseElsewhere names where keys diagnose is answered when this
	// process holds no device packets (Held nil): port49-broker, beside
	// port49d (plan 7e, Ruling 13; pre-flight M16).
	DiagnoseElsewhere string
	// Proc names this process in a failed op's line and answer:
	// "port49d" when empty, "port49-broker" on the broker (Task 15a review
	// M-6).
	Proc string
	// OpTimeout bounds revoke and revocations; zero is the package's
	// OpTimeout. Tests shorten it.
	OpTimeout time.Duration
	// ownUID is the uid answered besides root; nil is port49d's own. A test
	// moves it so its own uid reads as another's without needing root. It
	// is the Server's, never a package variable, so a test that moves it
	// cannot race another test's handler still reading it.
	ownUID func() uint32
}

const maxRequest = 4096

// maxImport bounds what follows an enrollments_import request line, and what
// an enrollments_export answers: an enrollment store of a fleet's people
// (plan 9e, pre-flight I14). Every other op stays within maxRequest.
const maxImport = 64 << 20

// signInOps are the ops of plan 9e's operator side.
var signInOps = []string{"second_factor_reset", "sign_in_unlock", "enrollments_init", "enrollments_export",
	"enrollments_import"}

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
//
// A revoke or revocations runs under a ctx that ends at the op's deadline
// or when the caller hangs up, whichever is first: a caller that gave up
// leaves nothing waiting on its behalf behind a hung revocation. The broker
// honours that end only while it waits its turn; a revocation under way
// finishes, under its own bound of the same length (Broker.RevokeTimeout),
// so the connection is given both (RevokeWait). The caller's end is seen as
// a read that fails, so a client keeps its write side open until it has the
// answer (no half-close).
func (s *Server) handle(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	enc := json.NewEncoder(c)
	own := ownUID
	if s.ownUID != nil {
		own = s.ownUID
	}
	uid, err := peerAllowed(c, own())
	if err != nil {
		_ = enc.Encode(Response{Error: "refused: " + err.Error()})
		return
	}
	// A misspelt key is refused, never dropped: "lifted" read as nothing
	// would turn a lift into a revocation.
	var req Request
	dec := json.NewDecoder(io.LimitReader(c, maxRequest))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		_ = enc.Encode(Response{Error: "a request is one JSON object with known keys"})
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	isImport := req.Op == "enrollments_import"
	if isImport {
		// The sealed body follows the request line, to the client's half-close.
		// The decoder has read ahead of the line: what it holds is the body's
		// start, after the one newline the encoder ends the line with (answer
		// drops it). No hang-up watch: it would read the body. An import runs to
		// its end, bounded by the op's timeout.
		_ = c.SetDeadline(time.Now().Add(s.connTimeout(req.Op)))
		req.body = io.MultiReader(dec.Buffered(), c)
	}
	if req.Op == "revoke" || req.Op == "revocations" || req.Op == "directory_forget" ||
		req.Op == "store_status" || slices.Contains(signInOps, req.Op) && !isImport {
		_ = c.SetDeadline(time.Now().Add(s.connTimeout(req.Op)))
		go func() {
			defer cancel()
			var b [64]byte
			for {
				if _, err := c.Read(b[:]); err != nil {
					return
				}
			}
		}()
	}
	_ = enc.Encode(s.answer(ctx, req, uid))
}

// connTimeout is how long a revoke's, revocations' or directory_forget's
// connection is held open: RevokeWait for a revoke, ListWait otherwise, at
// the Server's OpTimeout.
func (s *Server) connTimeout(op string) time.Duration {
	if op == "store_status" {
		return StatusWait
	}
	if op != "revoke" {
		return s.opTimeout() + answerMargin
	}
	return 2*s.opTimeout() + PersistTimeout + answerMargin
}

func (s *Server) opTimeout() time.Duration {
	if s.OpTimeout > 0 {
		return s.OpTimeout
	}
	return OpTimeout
}

func (s *Server) answer(ctx context.Context, req Request, uid uint32) (resp Response) {
	// The admin socket's goroutines share the process with TACACS+: a
	// panic behind an op is an answer, never the end of port49d (M12).
	defer func() {
		if r := recover(); r != nil {
			proc := s.Proc
			if proc == "" {
				proc = "port49d"
			}
			log.Printf("%s: admin socket: op %q failed: %v", proc, printsafe.Line(req.Op, 40), r)
			resp = Response{Error: "internal error; " + proc + "'s log says what"}
		}
	}()
	switch req.Op {
	case "keys_diagnose":
		if s.Held == nil && s.DiagnoseElsewhere != "" {
			return Response{Error: "port49-broker holds no device packets; keys diagnose is " + s.DiagnoseElsewhere}
		}
		assigned := ""
		if s.Assigned != nil {
			assigned = s.Assigned(req.Device)
		}
		now := s.Now()
		f, ok := keyring.Diagnose(s.Held, s.Keys(), req.Device, assigned, now)
		if !ok {
			return Response{Error: fmt.Sprintf("port49d holds no unvalidated packet from %q since it started", req.Device)}
		}
		return Response{Text: f.Text(now), Finding: &f}
	case "revoke", "revocations":
		if s.Revoke == nil || s.Revocations == nil {
			if s.RevokeElsewhere != "" {
				return Response{Error: "port49d runs no broker; revocation is " + s.RevokeElsewhere +
					": run port49 revoke --socket <that path>"}
			}
			return Response{Error: "port49d runs no broker (no broker: block in port49d.yaml), so there is nothing to revoke"}
		}
		ctx, cancel := context.WithTimeout(ctx, s.opTimeout())
		defer cancel()
		var text string
		var partial bool
		var err error
		if req.Op == "revocations" {
			text, err = s.Revocations(ctx)
		} else {
			text, partial, err = s.Revoke(ctx, RevokeOp{Principal: req.Principal, Issuer: req.CertIssuer,
				Serial: req.CertSerial, Lift: req.Lift, UID: uid})
		}
		if err != nil {
			return Response{Error: err.Error()}
		}
		return Response{Text: text, Partial: partial}
	case "directory_forget":
		if s.Forget == nil {
			if s.RevokeElsewhere != "" {
				return Response{Error: "port49d runs no broker; directory forget is " + s.RevokeElsewhere +
					": run port49 directory forget --socket <that path>"}
			}
			return Response{Error: "this process runs no broker, so it holds no directory membership"}
		}
		if req.Principal == "" {
			return Response{Error: "directory_forget names a principal"}
		}
		ctx, cancel := context.WithTimeout(ctx, s.opTimeout())
		defer cancel()
		text, err := s.Forget(ctx, req.Principal, uid)
		if err != nil {
			return Response{Error: err.Error()}
		}
		return Response{Text: text}
	case "store_status":
		if s.StoreStatus == nil {
			return Response{Error: "this process reports no stores"}
		}
		ctx, cancel := context.WithTimeout(ctx, StatusOpTimeout)
		defer cancel()
		text, degraded, err := s.StoreStatus(ctx)
		if err != nil {
			return Response{Error: err.Error()}
		}
		return Response{Text: text, Degraded: degraded}
	case "second_factor_reset", "sign_in_unlock", "enrollments_init", "enrollments_export", "enrollments_import":
		return s.signInOp(ctx, req, uid)
	}
	return Response{Error: "unknown op; the ops are keys_diagnose, revoke, revocations, directory_forget, " +
		"store_status, second_factor_reset, sign_in_unlock, enrollments_init, enrollments_export and enrollments_import"}
}

// signInCommand is the `port49 directory` subcommand that sends op.
var signInCommand = map[string]string{"second_factor_reset": "reset-second-factor", "sign_in_unlock": "unlock",
	"enrollments_init": "init-enrollments", "enrollments_export": "export", "enrollments_import": "import"}

// signInOp answers plan 9e's operator ops. A process with no broker, or one
// with no directory_password verifier, leaves the op's func nil and says where
// the ops run.
func (s *Server) signInOp(ctx context.Context, req Request, uid uint32) Response {
	var ran bool
	switch req.Op {
	case "second_factor_reset":
		ran = s.SecondFactorReset != nil
	case "sign_in_unlock":
		ran = s.SignInUnlock != nil
	case "enrollments_init":
		ran = s.EnrollmentsInit != nil
	case "enrollments_export":
		ran = s.EnrollmentsExport != nil
	case "enrollments_import":
		ran = s.EnrollmentsImport != nil
	}
	if !ran {
		cmd := "port49 directory " + signInCommand[req.Op]
		if s.RevokeElsewhere != "" {
			return Response{Error: "port49d runs no broker; " + cmd + " is " + s.RevokeElsewhere + ": run " + cmd +
				" --socket <that path>"}
		}
		return Response{Error: "this process runs no broker with a directory_password verifier, so it holds no second " +
			"factors (" + cmd + " is answered by the process that does)"}
	}
	switch {
	case req.Op == "second_factor_reset" && req.All && req.Principal != "":
		return Response{Error: "second_factor_reset names a principal or all, not both"}
	case req.Op == "second_factor_reset" && !req.All && req.Principal == "":
		return Response{Error: "second_factor_reset names a principal, or all"}
	case req.Op == "sign_in_unlock" && req.Principal == "":
		return Response{Error: "sign_in_unlock names a principal"}
	}
	ctx, cancel := context.WithTimeout(ctx, s.opTimeout())
	defer cancel()
	var text string
	var err error
	switch req.Op {
	case "second_factor_reset":
		text, err = s.SecondFactorReset(ctx, req.Principal, req.All, uid)
	case "sign_in_unlock":
		text, err = s.SignInUnlock(ctx, req.Principal, uid)
	case "enrollments_init":
		text, err = s.EnrollmentsInit(ctx, uid)
	case "enrollments_export":
		var sealed []byte
		if sealed, err = s.EnrollmentsExport(ctx, uid); err == nil {
			if len(sealed) > maxImport {
				return Response{Error: fmt.Sprintf("the export is over %d MiB, more than the admin socket carries; "+
					"copy the enrollment store from its backend instead", maxImport>>20)}
			}
			return Response{Text: fmt.Sprintf("exported %d bytes", len(sealed)), Sealed: sealed}
		}
	case "enrollments_import":
		// Never echoed or logged, whatever it holds.
		if req.body == nil {
			req.body = bytes.NewReader(nil)
		}
		// The request line's newline leads the body: it is not counted.
		body, rerr := io.ReadAll(io.LimitReader(req.body, maxImport+2))
		body = bytes.TrimPrefix(body, []byte("\n"))
		switch {
		case rerr != nil:
			return Response{Error: "the export did not arrive whole: send it after the request line and half-close"}
		case len(body) > maxImport:
			return Response{Error: fmt.Sprintf("the export is over %d MiB, more than the admin socket takes", maxImport>>20)}
		case len(bytes.TrimSpace(body)) == 0:
			return Response{Error: "enrollments_import carries the export after its request line: none arrived"}
		}
		text, err = s.EnrollmentsImport(ctx, body, req.Replace, uid)
	}
	if err != nil {
		return Response{Error: err.Error()}
	}
	return Response{Text: text}
}

// uidAllowed is the rule peerAllowed applies: port49d's own uid, and root.
func uidAllowed(uid, own uint32) error {
	if uid != 0 && uid != own {
		return fmt.Errorf("uid %d is neither port49d's (%d) nor root", uid, own)
	}
	return nil
}
