package qual

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/rhwendt/port49/internal/devicemock"
	"github.com/rhwendt/port49/internal/platform"
)

// singleConnectDrift holds platform.TLSServerSingleConnect's table and the
// profiles' measured facts to each other, both ways (spec §13 decision 50
// ruling 20; design Task 7 RI4):
//
//   - every table platform has at least one profile that measured
//     tls_server_single_connect_honored, and none that measured _ignored;
//   - every profile that measured either fact is of a table platform.
//
// A profile with neither fact makes no claim: it is never read as "not
// honored". A firmware that ignores the offer fails here, before a release
// ships the table entry for it.
func singleConnectDrift(table []string, profiles []*devicemock.Profile) []string {
	var out []string
	for _, name := range table {
		honored := false
		for _, p := range profiles {
			if p.Platform != name {
				continue
			}
			honored = honored || p.HasFact(devicemock.FactTLSServerSingleConnectHonored)
			if p.HasFact(devicemock.FactTLSServerSingleConnectIgnored) {
				out = append(out, name+" "+p.Firmware+": port49 offers it single-connect, and its profile measured the offer ignored")
			}
		}
		if !honored {
			out = append(out, name+": port49 offers it single-connect, and no profile measured the offer honored")
		}
	}
	for _, p := range profiles {
		if (p.HasFact(devicemock.FactTLSServerSingleConnectHonored) || p.HasFact(devicemock.FactTLSServerSingleConnectIgnored)) &&
			!slices.Contains(table, p.Platform) {
			out = append(out, p.Platform+" "+p.Firmware+": its profile measured an offer port49's table does not make")
		}
	}
	return out
}

func driftProfile(platformName, firmware string, facts ...string) *devicemock.Profile {
	p := &devicemock.Profile{Platform: platformName, Firmware: firmware}
	for _, f := range facts {
		p.DeviceFacts = append(p.DeviceFacts, devicemock.DeviceFact{ID: f, Status: "measured"})
	}
	return p
}

func TestSingleConnectDriftFixtures(t *testing.T) {
	honored, ignored := devicemock.FactTLSServerSingleConnectHonored, devicemock.FactTLSServerSingleConnectIgnored
	table := []string{"cisco_nxos"}
	for name, c := range map[string]struct {
		profiles []*devicemock.Profile
		fail     bool
	}{
		"honored only": {[]*devicemock.Profile{driftProfile("cisco_nxos", "10.6", honored)}, false},
		"honored, and an older firmware with no claim": {[]*devicemock.Profile{
			driftProfile("cisco_nxos", "10.6", honored), driftProfile("cisco_nxos", "10.4")}, false},
		"ignored on a table platform": {[]*devicemock.Profile{
			driftProfile("cisco_nxos", "10.6", honored), driftProfile("cisco_nxos", "10.7", ignored)}, true},
		"honored on a non-table platform": {[]*devicemock.Profile{
			driftProfile("cisco_nxos", "10.6", honored), driftProfile("arista_eos", "4.36", honored)}, true},
		"absent everywhere for a non-table platform": {[]*devicemock.Profile{
			driftProfile("cisco_nxos", "10.6", honored), driftProfile("arista_eos", "4.36")}, false},
		"a table platform no profile measured": {[]*devicemock.Profile{driftProfile("cisco_nxos", "10.4")}, true},
	} {
		if got := singleConnectDrift(table, c.profiles); (len(got) > 0) != c.fail {
			t.Errorf("%s: drift %q, want a failure %v", name, got, c.fail)
		}
	}
}

// The committed profiles against the built-in table. It goes green when
// genprofile regenerates the NX-OS 10.6 profile from the L80 re-measure's
// qual run, never by a hand edit.
func TestSingleConnectTableMatchesTheProfiles(t *testing.T) {
	paths, err := filepath.Glob("profiles/*/*.yaml")
	if err != nil || len(paths) == 0 {
		t.Fatalf("profiles: %v %d", err, len(paths))
	}
	var profiles []*devicemock.Profile
	for _, path := range paths {
		p, err := devicemock.Load(path, filepath.Join("..", ".."))
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		profiles = append(profiles, p)
	}
	if drift := singleConnectDrift(platform.TLSServerSingleConnectPlatforms(), profiles); len(drift) > 0 {
		t.Fatalf("platform.TLSServerSingleConnect and the profiles disagree:\n%s", strings.Join(drift, "\n"))
	}
}
