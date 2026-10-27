//go:build !linux

package fence

import "errors"

// Read refuses on every system but Linux: the check that nobody else could
// have written the file is made on descriptors (openat, O_PATH) used on Linux
// alone, and a file that cannot be checked is not read. port49 builds here so
// the rest of it can be worked on.
func Read(_ string, _ int64, what string) ([]byte, error) {
	return nil, errors.New("port49 reads " + what + " on Linux only: the check of who could have written it is Linux's")
}

// ReadNoLink refuses off Linux, as Read does.
func ReadNoLink(path string, max int64, what string) ([]byte, error) { return Read(path, max, what) }

// ReadSigned refuses off Linux, as Read does: O_NOFOLLOW is not everywhere.
func ReadSigned(path string, max int64, what string) ([]byte, error) { return Read(path, max, what) }

// ReadSecret refuses off Linux, as Read does.
func ReadSecret(path, _ string, max int64) ([]byte, error) { return Read(path, max, "secret file") }

// CheckDir refuses off Linux, as Read does.
func CheckDir(_ string, what string) error {
	return errors.New("port49 keeps " + what + " on Linux only: the check of who could write it is Linux's")
}
