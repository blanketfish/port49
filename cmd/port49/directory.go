package main

import (
	"flag"
	"fmt"
	"io"

	"github.com/rhwendt/port49/internal/daemon/admin"
)

// directoryCmd is `port49 directory forget` (plan 7g, Ruling 3's escape):
// it asks the broker, over its admin socket, to forget a principal's
// directory membership and the entry the principal is pinned to, so its
// next verification pins the entry the directory gives it then. It is for
// an entry deleted and re-created: confirm the new entry is the same
// person first.
func directoryCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "forget" {
		fmt.Fprint(stderr, usage)
		return 2
	}
	fs := flag.NewFlagSet("port49 directory forget", flag.ContinueOnError)
	fs.SetOutput(stderr)
	socket := fs.String("socket", "/run/port49/port49d.sock", "the admin_socket of the process running the broker")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	resp, err := askAdmin(*socket, admin.Request{Op: "directory_forget", Principal: fs.Arg(0)}, listWait)
	if err != nil {
		fmt.Fprintln(stderr, "port49 directory forget:", err, "(a forget that was not answered may have run: "+
			"the broker's log names each, event directory_forget; running it again is safe)")
		return 1
	}
	if resp.Error != "" {
		fmt.Fprintln(stderr, "port49 directory forget:", resp.Error)
		return 1
	}
	fmt.Fprintln(stdout, resp.Text)
	return 0
}
