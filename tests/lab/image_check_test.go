//go:build lab

package lab

import (
	"errors"
	"strings"
	"testing"
)

// A shell that cannot reach the docker daemon is not a missing image: saying
// "image … is not present" sends the operator off to rebuild an image that is
// there. It is a failed run that says what is wrong (final wave, lab
// harness). No docker is run here.
func TestAnImageCheckSaysWhenDockerIsDenied(t *testing.T) {
	failed := errors.New("exit status 1")
	for _, c := range []struct {
		name       string
		out        string
		err        error
		absent     string
		deniedWord string
	}{
		{"present", "[{...}]", nil, "", ""},
		{"absent", "Error: No such image: ceos:4.33.1F\n", failed, "image ceos:4.33.1F is not present", ""},
		{"denied", "permission denied while trying to connect to the Docker daemon socket at " +
			"unix:///var/run/docker.sock: Get \"http://%2Fvar%2Frun%2Fdocker.sock/v1.47/images/ceos:4.33.1F/json\": " +
			"dial unix /var/run/docker.sock: connect: permission denied\n", failed, "", "docker group"},
	} {
		absent, err := imageAbsent("ceos:4.33.1F", []byte(c.out), c.err)
		if absent != c.absent {
			t.Errorf("%s: absent %q, want %q", c.name, absent, c.absent)
		}
		if (err != nil) != (c.deniedWord != "") || (err != nil && !strings.Contains(err.Error(), c.deniedWord)) {
			t.Errorf("%s: error %v, want one naming %q", c.name, err, c.deniedWord)
		}
	}
}
