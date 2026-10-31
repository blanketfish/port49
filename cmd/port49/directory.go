package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/rhwendt/port49/internal/agent"
	"github.com/rhwendt/port49/internal/broker/api"
)

// directoryStdin is where import reads the export from; tests move it.
var directoryStdin io.Reader = os.Stdin

// directoryCmd is `port49 directory`: forget (plan 7g, Ruling 3's escape), and
// the operator's side of the directory-password sign-in (plan 9e):
// reset-second-factor, unlock and import. Each asks the broker through your
// agent, under your api: rights and a press of your security key (spec
// §5.1.6). init-enrollments and export are on the broker host, not here.
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
	var all, replace *bool
	switch args[0] {
	case "forget", "unlock":
	case "reset-second-factor":
		all = fs.Bool("all", false, "reopen enrollment for every entry with no active second factor, and replace a lost store")
	case "import":
		replace = fs.Bool("replace", false, "replace a store holding a second factor enrolled or reset after the export")
	case "init-enrollments", "export":
		fmt.Fprintf(stderr, "%s: this runs on the broker host, where the store and its key are: run `port49-broker %s-"+
			"enrollments`%s there\n", name, map[string]string{"init-enrollments": "init", "export": "export"}[args[0]],
			map[string]string{"init-enrollments": "", "export": " > FILE"}[args[0]])
		return 2
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
		return directoryJSON(name, "/v1/directory/forget", api.PrincipalRequest{Principal: fs.Arg(0)}, "forget", stdout, stderr)
	case "reset-second-factor":
		return directoryJSON(name, "/v1/directory/reset-second-factor",
			api.ResetSecondFactorRequest{Principal: fs.Arg(0), All: *all}, "reset", stdout, stderr)
	case "unlock":
		return directoryJSON(name, "/v1/directory/unlock", api.PrincipalRequest{Principal: fs.Arg(0)}, "unlock", stdout, stderr)
	}
	return directoryImport(name, *replace, stdout, stderr)
}

// directoryJSON makes one directory call whose body is a small JSON object.
// A call that was sent and not answered may have run: running it again is safe.
func directoryJSON(name, path string, in any, what string, stdout, stderr io.Writer) int {
	body, err := json.Marshal(in)
	if err != nil {
		fmt.Fprintln(stderr, name+":", err)
		return 1
	}
	resp, code := adminCall(name, agent.AdminRequest{Method: http.MethodPost, Path: path, Body: body},
		"the "+what+" may have run: running it again is safe", stderr)
	if code != 0 {
		return code
	}
	return printAdminResult(name, resp, stdout, stderr)
}

// directoryImport sends stdin, an export, to the broker.
func directoryImport(name string, replace bool, stdout, stderr io.Writer) int {
	body, err := io.ReadAll(io.LimitReader(directoryStdin, api.MaxImportBytes+1))
	switch {
	case err != nil:
		fmt.Fprintln(stderr, name+": reading the export from standard input:", err)
		return 1
	case len(body) > api.MaxImportBytes:
		fmt.Fprintf(stderr, "%s: the export on standard input is over %d MiB; it is not an export port49 wrote: check "+
			"the file\n", name, api.MaxImportBytes>>20)
		return 1
	case len(body) == 0:
		fmt.Fprintln(stderr, name+": no export on standard input: port49 directory import < enrollments.export")
		return 1
	}
	path := "/v1/directory/import?replace=false"
	if replace {
		path = "/v1/directory/import?replace=true"
	}
	resp, code := adminCall(name, agent.AdminRequest{Method: http.MethodPost, Path: path, Body: body},
		"the import may have run: running it again is safe", stderr)
	if code != 0 {
		return code
	}
	return printAdminResult(name, resp, stdout, stderr)
}
