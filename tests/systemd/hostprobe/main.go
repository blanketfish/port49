// Command hostprobe is what lab entry L84's host cells run inside a transient systemd unit with
// LoadCredential=: port49d's own fence.ReadSecret on $CREDENTIALS_DIRECTORY/<name>, within that
// directory as livekeys.go passes file_dir, and a description of the directory and file. It prints
// owners, modes, the presence of an ACL and a refusal's category, never the file's bytes.
//
//	hostprobe read NAME      read NAME and describe it
//	hostprobe has NAME...    print each NAME as present or absent in the directory
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/blanketfish/port49/internal/fence"
	"github.com/blanketfish/port49/tests/systemd/sdtest"
)

func main() {
	dir := os.Getenv("CREDENTIALS_DIRECTORY")
	if len(os.Args) < 3 || dir == "" {
		fmt.Println("INVALID: usage: hostprobe read NAME | has NAME...; CREDENTIALS_DIRECTORY must be set")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "read":
		fmt.Println(strings.Join(sdtest.Report(dir, os.Args[2], fence.ReadSecret), "\n"))
	case "has":
		for _, n := range os.Args[2:] {
			state := "absent"
			if _, err := os.Stat(filepath.Join(dir, n)); err == nil {
				state = "present"
			}
			fmt.Printf("%s: %s\n", n, state)
		}
	default:
		fmt.Println("INVALID: unknown command", os.Args[1])
		os.Exit(2)
	}
}
