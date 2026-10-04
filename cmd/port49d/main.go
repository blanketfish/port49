// Command port49d is the TACACS+ daemon (internal/port49d).
package main

import (
	"os"

	"github.com/rhwendt/port49/internal/port49d"
)

func main() { os.Exit(port49d.Main(os.Args[1:])) }
