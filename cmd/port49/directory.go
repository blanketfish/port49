package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/rhwendt/port49/internal/daemon/admin"
)

// importLimit is the most `port49 directory import` reads and the admin
// socket takes (admin's maxImport).
const importLimit = 64 << 20

// directoryStdin is where import reads the export from; tests move it.
var directoryStdin io.Reader = os.Stdin

// directoryCmd is `port49 directory`: forget (plan 7g, Ruling 3's escape),
// and the operator's side of the directory-password sign-in (plan 9e):
// reset-second-factor, unlock, init-enrollments, export and import. Each asks
// the broker, over its admin socket.
//
// forget asks it to forget a principal's directory membership and the entry
// the principal is pinned to, so its next verification pins the entry the
// directory gives it then. It is for an entry deleted and re-created: confirm
// the new entry is the same person first.
func directoryCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	name := "port49 directory " + args[0]
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	socket := fs.String("socket", "/run/port49/port49d.sock", "the admin_socket of the process running the broker")
	var all, replace *bool
	switch args[0] {
	case "forget", "unlock", "init-enrollments", "export":
	case "reset-second-factor":
		all = fs.Bool("all", false, "reopen enrollment for every entry with no active second factor, and replace a lost store")
	case "import":
		replace = fs.Bool("replace", false, "replace a store holding a second factor enrolled or reset after the export")
	default:
		fmt.Fprint(stderr, usage)
		return 2
	}
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	want := 0 // the positional arguments
	switch args[0] {
	case "forget", "unlock":
		want = 1
	case "reset-second-factor":
		want = 1
		if *all {
			want = 0
		}
	}
	if fs.NArg() != want {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "forget":
		return directoryAsk(name, *socket, admin.Request{Op: "directory_forget", Principal: fs.Arg(0)},
			"forget", stdout, stderr)
	case "reset-second-factor":
		return directoryAsk(name, *socket, admin.Request{Op: "second_factor_reset", Principal: fs.Arg(0), All: *all},
			"reset", stdout, stderr)
	case "unlock":
		return directoryAsk(name, *socket, admin.Request{Op: "sign_in_unlock", Principal: fs.Arg(0)}, "unlock", stdout, stderr)
	case "init-enrollments":
		return directoryAsk(name, *socket, admin.Request{Op: "enrollments_init"}, "init", stdout, stderr)
	case "export":
		return directoryExport(name, *socket, stdout, stderr)
	}
	return directoryImport(name, *socket, *replace, stdout, stderr)
}

// directoryAsk sends req and prints the broker's answer. A failure after the
// request was written may have run: the broker's log names each op.
func directoryAsk(name, socket string, req admin.Request, what string, stdout, stderr io.Writer) int {
	resp, err := askAdmin(socket, req, listWait)
	if code := directoryFailed(name, what, resp, err, stderr); code != 0 {
		return code
	}
	fmt.Fprintln(stdout, resp.Text)
	return 0
}

// directoryFailed is the exit code of an answer that is not a success, 0
// when it is one, after saying why on stderr.
func directoryFailed(name, what string, resp admin.Response, err error, stderr io.Writer) int {
	switch {
	case err != nil:
		fmt.Fprintln(stderr, name+":", err, "(a "+what+" that was not answered may have run: the broker's log names "+
			"each; running it again is safe)")
		return 1
	case resp.Error != "":
		fmt.Fprintln(stderr, name+":", resp.Error)
		return 1
	}
	return 0
}

// directoryExport writes the sealed export to stdout, raw, and refuses a
// terminal: it is a file to keep, not text to read. What it holds is sealed
// under the broker's key, and nothing but the file's size is said.
func directoryExport(name, socket string, stdout, stderr io.Writer) int {
	if f, ok := stdout.(*os.File); ok && isTerminal(f) {
		fmt.Fprintln(stderr, name+": the export is a sealed file, not text: redirect it to a file "+
			"(port49 directory export > enrollments.export)")
		return 1
	}
	resp, err := askAdmin(socket, admin.Request{Op: "enrollments_export"}, listWait)
	if code := directoryFailed(name, "export", resp, err, stderr); code != 0 {
		return code
	}
	if len(resp.Sealed) == 0 {
		fmt.Fprintln(stderr, name+": the broker answered an empty export")
		return 1
	}
	if _, err := stdout.Write(resp.Sealed); err != nil {
		fmt.Fprintln(stderr, name+": writing the export:", err)
		return 1
	}
	fmt.Fprintf(stderr, "%s: exported %d bytes, sealed under the broker's encryption key; keep it as you keep that key\n",
		name, len(resp.Sealed))
	return 0
}

// directoryImport sends stdin, an export, to the broker.
func directoryImport(name, socket string, replace bool, stdout, stderr io.Writer) int {
	body, err := io.ReadAll(io.LimitReader(directoryStdin, importLimit+1))
	switch {
	case err != nil:
		fmt.Fprintln(stderr, name+": reading the export from standard input:", err)
		return 1
	case len(body) > importLimit:
		fmt.Fprintf(stderr, "%s: the export on standard input is over %d MiB; it is not an export port49 wrote\n",
			name, importLimit>>20)
		return 1
	case len(body) == 0:
		fmt.Fprintln(stderr, name+": no export on standard input: port49 directory import < enrollments.export")
		return 1
	}
	resp, err := askAdminBody(socket, admin.Request{Op: "enrollments_import", Replace: replace}, body, listWait)
	if code := directoryFailed(name, "import", resp, err, stderr); code != 0 {
		return code
	}
	fmt.Fprintln(stdout, resp.Text)
	return 0
}

// askAdminBody is askAdmin for an op whose body follows its request line: the
// body, then a half-close that ends it. The socket answers a refusal without
// reading all of a body it will not take, so a write that fails is not the
// answer: the answer is read first and only its absence is the write's error.
func askAdminBody(socket string, req admin.Request, body []byte, wait time.Duration) (admin.Response, error) {
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
	_, werr := c.Write(body)
	if uc, ok := c.(*net.UnixConn); ok && werr == nil {
		werr = uc.CloseWrite()
	}
	var resp admin.Response
	if err := json.NewDecoder(c).Decode(&resp); err != nil {
		if werr != nil {
			return admin.Response{}, fmt.Errorf("sending the export: %w", werr)
		}
		return admin.Response{}, &unansweredError{err}
	}
	return resp, nil
}
