package etcd

import (
	"context"
	"testing"
	"time"
)

func TestBelowFloor(t *testing.T) {
	for v, below := range map[string]bool{
		"3.4.23": true, "3.4.24": false, "3.4.30": false, "3.5.7": true, "3.5.8": false, "3.5.21": false,
		"3.6.0": false, "3.6.15": false, "3.7.0": false, "4.0.0": false, "3.3.25": true, "2.3.8": true,
		"": true, "garbage": true, "3.5": true,
	} {
		if BelowFloor(v) != below {
			t.Errorf("%q: %v", v, !below)
		}
	}
}

// Semver orders 3.5.8-rc.0 below 3.5.8, and a release candidate may not carry
// the fix the floor exists for: a pre-release of a floor release is below the
// floor, and one of a later release (3.5.9-rc.0, 3.6.1-rc.0, 3.7.0-alpha.0) is
// not. Security wins over leniency.
func TestAPreReleaseOfAFloorReleaseIsBelowTheFloor(t *testing.T) {
	for v, below := range map[string]bool{
		"3.5.8-rc.0": true, "3.4.24-rc.1": true, "3.6.0-rc.0": true, "3.6.0-alpha.0": true,
		"3.5.9-rc.0": false, "3.4.25-rc.0": false, "3.6.1-rc.0": false, "3.7.0-alpha.0": false, "4.0.0-rc.1": false,
		"3.5.7-rc.9": true, "3.4.23-rc.1": true, "3.5.8": false, "3.4.24": false, "3.6.0": false,
	} {
		if BelowFloor(v) != below {
			t.Errorf("%q: below the floor is %v, want %v", v, !below, below)
		}
	}
}

// Only a version that parses is ever printed: what a member answers is its
// own text, and a refusal that quotes it quotes whatever it chose to say.
func TestOnlyAVersionThatParsesIsReadable(t *testing.T) {
	for v, ok := range map[string]bool{
		"3.6.15": true, "3.6.0-alpha.0": true, "3.4.24": true, "": false, "garbage": false, "3.5": false,
		"3.5.x": false, "3.5.8\nforged line": false, "-1.2.3": false, "3.6.15+meta": false,
		"3.6.15-\x1b[31m": false, "999999999999999999999.1.1": false,
	} {
		if ReadableVersion(v) != ok {
			t.Errorf("%q: %v", v, !ok)
		}
	}
}

// Each endpoint is asked its version, and the embedded server answers its own.
// The asking identity holds only the daemon's role: Status needs no key, and
// a floor that came back "did not answer" under port49's roles would go
// unchecked in every production start.
func TestEndpointVersionsAsksEachEndpoint(t *testing.T) {
	const prefix = "/port49/"
	srv := provisioned(t, prefix)
	for _, cn := range []string{"port49-daemon", "port49-broker"} {
		s := openAs(t, srv, cn, prefix)
		vs := s.EndpointVersions(context.Background(), []string{srv.Endpoint, "https://127.0.0.1:1"}, time.Second)
		if len(vs) != 2 || vs[0].Err != nil || !ReadableVersion(vs[0].Version) || BelowFloor(vs[0].Version) ||
			vs[0].Endpoint != srv.Endpoint || vs[1].Err == nil || vs[1].Version != "" {
			t.Fatalf("%s: %+v", cn, vs)
		}
	}
}
