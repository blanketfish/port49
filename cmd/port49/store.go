package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/rhwendt/port49/internal/daemon/admin"
)

// storeStatusWait is how long the command waits for the answer.
var storeStatusWait = admin.StatusWait

// storeCmd is `port49 store` (plan 11a): status asks a process's admin
// socket what each of its stores is.
func storeCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "status" {
		return storeStatusCmd(args[1:], stdout, stderr)
	}
	fmt.Fprint(stderr, usage)
	return 2
}

// storeStatusCmd is `port49 store status` (spec §12; decision 51 R21):
// exit 0 when every store answers, 3 when one does not, 1 when the socket
// does not answer.
func storeStatusCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("port49 store status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	socket := fs.String("socket", "/run/port49/port49d.sock", "the admin_socket of port49d or port49-broker")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	resp, err := askAdmin(*socket, admin.Request{Op: "store_status"}, storeStatusWait)
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		fmt.Fprintf(stderr, "port49 store status: %s did not answer within %v (is the process wedged?)\n",
			*socket, storeStatusWait)
		return 1
	}
	if err != nil {
		fmt.Fprintln(stderr, "port49 store status:", err)
		return 1
	}
	if resp.Error != "" {
		fmt.Fprintln(stderr, "port49 store status:", resp.Error)
		return 1
	}
	fmt.Fprintln(stdout, resp.Text)
	if resp.Degraded {
		return 3
	}
	return 0
}

// unansweredError is askAdmin's failure after the request was written: the
// op may have run.
type unansweredError struct{ err error }

func (e *unansweredError) Error() string { return e.err.Error() }
func (e *unansweredError) Unwrap() error { return e.err }

// askAdmin sends req to port49d's admin socket and returns its one answer,
// waiting at most wait. The socket answers port49d's user and root alone.
// The write side stays open until the answer is read: port49d takes a
// half-close for a hang-up and abandons the op. A failure once the request
// is written is an *unansweredError.
func askAdmin(socket string, req admin.Request, wait time.Duration) (admin.Response, error) {
	c, err := net.DialTimeout("unix", socket, 5*time.Second)
	if err != nil {
		return admin.Response{}, fmt.Errorf("%v (is admin_socket set in port49d.yaml, and are you port49d's user "+
			"or root?)", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(wait))
	if err := json.NewEncoder(c).Encode(req); err != nil {
		return admin.Response{}, err
	}
	var resp admin.Response
	if err := json.NewDecoder(c).Decode(&resp); err != nil {
		return admin.Response{}, &unansweredError{err}
	}
	return resp, nil
}
