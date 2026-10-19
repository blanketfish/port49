//go:build !linux

package main

import (
	"errors"
	"os"
)

func holdLock(string, string) (*os.File, error) {
	return nil, errors.New("lab-regress runs on the Linux lab host only")
}
