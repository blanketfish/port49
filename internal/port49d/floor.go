package port49d

import (
	"errors"
	"fmt"
	"io"
	"strings"

	etcdstore "github.com/rhwendt/port49/internal/store/etcd"
)

// endpointVersions asks the members their versions; a variable so a test can
// stand an old member in.
var endpointVersions = (*etcdstore.Store).EndpointVersions

// checkFloor judges the versions a start read (decision 53 ruling 9): a member
// below the floor is a store fault, every member at or above it is said in
// one line, and one that did not answer is said and left unchecked until
// the next start, never waited for. What a member answered is its own text:
// a version is printed only once it parses, and an error from the probe is
// said by kind, never quoted.
func checkFloor(vs []etcdstore.EndpointVersion, what string, out io.Writer, proc string) error {
	var ok []string
	for _, v := range vs {
		switch {
		case v.Err != nil:
			why := "did not answer"
			if errors.Is(v.Err, etcdstore.ErrRefused) {
				why = "refused this identity's request"
			}
			fmt.Fprintf(out, "%s: %s: etcd at %s %s for its version; it is unchecked against the floor (%s) until "+
				"the next start\n", proc, what, v.Endpoint, why, etcdstore.VersionFloor)
		case !etcdstore.ReadableVersion(v.Version):
			return fmt.Errorf("%s: etcd at %s did not report a version port49 can read, so it cannot be held to the "+
				"floor it needs (%s): the feed fence rests on a guarantee older releases do not make; check the "+
				"member's version", what, v.Endpoint, etcdstore.VersionFloor)
		case etcdstore.BelowFloor(v.Version):
			note := ""
			if strings.Contains(v.Version, "-") {
				note = " (a pre-release is older than its release, and may lack the fix)"
			}
			return fmt.Errorf("%s: etcd at %s is version %s, below the floor port49 needs (%s)%s: the feed fence "+
				"rests on a guarantee older releases do not make; upgrade the member", what, v.Endpoint, v.Version,
				etcdstore.VersionFloor, note)
		default:
			ok = append(ok, v.Endpoint+" "+v.Version)
		}
	}
	if len(ok) > 0 {
		fmt.Fprintf(out, "%s: %s: etcd %s, at or above the floor (%s)\n", proc, what, strings.Join(ok, ", "),
			etcdstore.VersionFloor)
	}
	return nil
}
