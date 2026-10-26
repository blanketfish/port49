package etcd

import (
	"context"
	"regexp"
	"strconv"
	"sync"
	"time"
)

// VersionFloor is the etcd release port49 requires (design §13; decision 53
// ruling 9): the feed fence rests on etcd never sending an event it has not
// delivered, which 3.4.24, 3.5.8 and every 3.6 guarantee.
const VersionFloor = "3.4.24, 3.5.8 or 3.6"

// versionShape is a release as Status answers it: major.minor.patch, and a
// pre-release suffix of the characters semver allows. Nothing else is a
// version port49 reads, or prints.
var versionShape = regexp.MustCompile(`^([0-9]{1,6})\.([0-9]{1,6})\.([0-9]{1,6})(?:-[0-9A-Za-z.-]{1,32})?$`)

// ReadableVersion reports whether version parses as one: a refusal prints a
// member's version only when it does, since what a member answers is its own
// text.
func ReadableVersion(version string) bool { return versionShape.MatchString(version) }

// BelowFloor reports whether version, as Status answers it, is older than the
// floor. One that does not parse is below it.
func BelowFloor(version string) bool {
	m := versionShape.FindStringSubmatch(version)
	if m == nil {
		return true
	}
	var n [3]int
	for i := range n {
		n[i], _ = strconv.Atoi(m[i+1])
	}
	switch {
	case n[0] != 3:
		return n[0] < 3
	case n[1] >= 6:
		return false
	case n[1] == 5:
		return n[2] < 8
	case n[1] == 4:
		return n[2] < 24
	}
	return true
}

// EndpointVersion is one endpoint's answer: its version, or why it gave none.
type EndpointVersion struct {
	Endpoint, Version string
	Err               error
}

// EndpointVersions asks every endpoint's Status at once, each bounded by per,
// so a dark member costs one per and holds nothing else (decision 53 ruling 9).
func (s *Store) EndpointVersions(ctx context.Context, endpoints []string, per time.Duration) []EndpointVersion {
	out := make([]EndpointVersion, len(endpoints))
	var wg sync.WaitGroup
	for i, ep := range endpoints {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, cancel := context.WithTimeout(ctx, per)
			defer cancel()
			out[i].Endpoint = ep
			resp, err := s.ctx.Status(c, ep)
			if err != nil {
				out[i].Err = unavailable(err)
				return
			}
			out[i].Version = resp.Version
		}()
	}
	wg.Wait()
	return out
}
