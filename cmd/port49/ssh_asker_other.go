//go:build !linux && !darwin

package main

import (
	"errors"
	"net"
)

// askerParent is an error on an OS that has no way to read the asker's
// parent, so there `port49 ssh` ends before it sends a token rather than send
// one unchecked.
func askerParent(net.Conn) (int, error) {
	return 0, errors.New("this OS has no way to read the asker's parent")
}
