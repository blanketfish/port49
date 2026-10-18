package main

import (
	"flag"
	"fmt"
	"io"

	"github.com/rhwendt/port49/internal/daemon/admin"
)

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
	resp, err := askAdmin(*socket, admin.Request{Op: "store_status"}, admin.StatusWait)
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
