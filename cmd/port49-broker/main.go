// Command port49-broker is port49's broker, its own process on etcd (plan
// 7e; internal/port49d).
package main

import (
	"os"

	"github.com/rhwendt/port49/internal/port49d"
)

func main() { os.Exit(port49d.BrokerMain(os.Args[1:])) }
