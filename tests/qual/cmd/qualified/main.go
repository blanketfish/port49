// Command qualified prints docs/qualified-platforms.md: the table of what the
// lab measured, generated from the committed profiles, goldens and notes.
//
//	go run ./tests/qual/cmd/qualified > docs/qualified-platforms.md
package main

import (
	"fmt"
	"os"
)

func main() {
	out, err := Build(".")
	if err != nil {
		fmt.Fprintln(os.Stderr, "qualified:", err)
		os.Exit(1)
	}
	fmt.Print(out)
}
