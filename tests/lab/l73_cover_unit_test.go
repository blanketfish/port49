package lab

import (
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/rhwendt/port49/tests/lab/labcreds"
)

// The keywords a device's lines type are derived from the lines, not listed:
// a typed keyword that no ask covers at its own level escapes the probe, and
// the cell then meets a refused line half way through instead of an INVALID
// run at the probe.
//
// A token is a keyword when it is lower-case words joined by hyphens (or
// ipv4); an address, number, quoted string, key or lab name is a value and
// stands as "·" in a level. The tokens before the first level any ask covers
// are the path into the stanza (L71's own question, in Junos "set system
// tacplus-server <ip>") and are not checked. Also not checked, on purpose:
// request and exec lines (enrolment, certificate loads), delete and no lines
// (they undo what is set), exit, the path into a mode (the "aaa group server
// tacacs+ <group>" line itself), and Junos delete lines. The words typed
// inside the AAA server group are checked, against the asks that enter it. A host-line option (key, port,
// ...) may stand anywhere on its line, so it is checked at the level it
// stands in and the line goes on from that level.
var (
	l73KeywordRE = regexp.MustCompile(`^([a-z]+(-[a-z]+)*|ipv4)$`)
	l73HostOpts  = []string{"key", "port", "single-connection", "ssl-profile", "secret", "routing-instance"}
)

func l73IsValue(tok string) bool {
	if !l73KeywordRE.MatchString(tok) {
		return true
	}
	// the lab names that read as words, and the shared secret
	return slices.Contains([]string{l73XEVRF, labcreds.Key}, tok)
}

// l73LevelKey is a level's text with its values as "·". It names no value.
func l73LevelKey(toks []string) string {
	var b strings.Builder
	for _, t := range toks {
		if l73IsValue(t) {
			t = "·"
		}
		b.WriteString(t + " ")
	}
	return b.String()
}

// l73UncoveredWords returns "word at level" for each keyword in lines that no
// ask covers at its level. Values are never named.
func l73UncoveredWords(lines []string, asks []l73Ask) []string {
	asked := map[string][]string{}
	for _, a := range asks {
		k := l73LevelKey(strings.Fields(a.Ask))
		asked[k] = append(append(asked[k], a.Need...), a.Want...)
	}
	var bad []string
	for _, ln := range lines {
		var level []string
		inStanza, optValues := false, false
		for _, tok := range strings.Fields(ln) {
			if l73IsValue(tok) {
				if !optValues { // an option's values do not open a level
					level = append(level, tok)
				}
				continue
			}
			optValues = false
			if _, ok := asked[l73LevelKey(level)]; ok {
				inStanza = true
			}
			if !inStanza {
				level = append(level, tok)
				continue
			}
			if !slices.Contains(asked[l73LevelKey(level)], tok) {
				bad = append(bad, tok+" at "+l73LevelKey(level))
			}
			if slices.Contains(l73HostOpts, tok) {
				// the option and its values end here; the line resumes at this level
				optValues = true
				continue
			}
			level = append(level, tok)
		}
		if !inStanza {
			bad = append(bad, "line reaches no asked level: "+l73LevelKey(strings.Fields(ln)))
		}
	}
	slices.Sort(bad)
	return slices.Compact(bad)
}

// l73TypedValuesAreNotKeywords: the lab names and the shared secret are values.
func TestL73ValuesAreNotKeywords(t *testing.T) {
	for _, v := range []string{l73Instance, l73TrustGroup, l73RootProfile, l73InterProfile, l73CertID, l73XEServer,
		l73XESecond, l73XEStart, l73Group, l73XEVRF, l73XESource, l73CiscoKey, l73EOSProfile, labcreds.Key, `"` + labcreds.Key + `"`,
		"192.0.2.71", "300", "l73probe"} {
		if !l73IsValue(v) {
			t.Errorf("%q is read as a keyword", maskKey(v))
		}
	}
	for _, k := range []string{"tls", "single-connection", "ipv4", "ca-profile", "client-trustpoint"} {
		if l73IsValue(k) {
			t.Errorf("%q is read as a value", k)
		}
	}
}

func l73TypedDevices() []l73DeviceTLS {
	return []l73DeviceTLS{
		{Server: l73Server, Port: l73TLSPort, SingleConnection: true, Secret: true,
			Second: l73SecondServer, SecondTLS: true, SecondPort: l73TLSPort},
		{Server: l73Server, Second: l73SecondServer, SecondPort: 49},
	}
}

func TestL73JunosAsksCoverEveryTypedKeyword(t *testing.T) {
	var lines []string
	for _, d := range l73TypedDevices() {
		lines = append(lines, l73JunosLines(d)...)
	}
	lines = append(lines, l73JunosRestore()...)
	lines = append(lines, l73PKILines()...)
	lines = append(lines, l73TrustGroupLines()...)
	var set []string
	for _, ln := range lines {
		if strings.HasPrefix(ln, "set ") { // delete lines undo what these set
			set = append(set, ln)
		}
	}
	if len(set) < 20 {
		t.Fatalf("only %d set lines derived", len(set))
	}
	if bad := l73UncoveredWords(set, l73JunosAsks); len(bad) != 0 {
		t.Errorf("typed and never asked about at that level: %q", bad)
	}
}

func TestL73CiscoAsksCoverEveryTypedKeyword(t *testing.T) {
	groupIn := "aaa group server tacacs+ " + l73Group
	has := map[string]bool{l73HasNXOSSecure: true, l73HasTrustpointServer: true, l73HasNXOSServerTrust: true}
	for _, tc := range []struct{ platform, family string }{
		{"cisco_iosxe", "iosxe"}, {"cisco_nxos", "nxos"}, {"arista_ceos", "eos"},
	} {
		var typed, group []string
		for _, d := range l73TypedDevices() {
			object, inGroup := false, false
			for _, ln := range l73CiscoLines(tc.family, nil, d, has) {
				switch {
				case strings.HasPrefix(ln, groupIn):
					inGroup = true
				case ln == "exit" && inGroup:
					inGroup = false
				case inGroup:
					if !strings.HasPrefix(ln, "no ") {
						group = append(group, ln)
					}
				case tc.family == "iosxe":
					// Only inside a `tacacs server` object, where L71 asked; the
					// aaa group lines are IOS's own and not RFC 9887.
					if strings.HasPrefix(ln, "tacacs server ") {
						object = true
					} else if ln == "exit" {
						object = false
					} else if object {
						typed = append(typed, ln)
					}
				case strings.HasPrefix(ln, "tacacs-server "):
					typed = append(typed, ln)
				}
			}
		}
		if len(group) == 0 {
			t.Fatalf("%s: no AAA group lines derived", tc.family)
		}
		var objAsks, groupAsks []l73Ask
		for _, a := range l73Dialects[tc.platform].Asks {
			if slices.Contains(a.In, groupIn) {
				groupAsks = append(groupAsks, a)
			} else {
				objAsks = append(objAsks, a)
			}
		}
		if bad := l73UncoveredWords(group, groupAsks); len(bad) != 0 {
			t.Errorf("%s: typed in the AAA group and never asked about at that level: %q", tc.family, bad)
		}
		if len(typed) < 3 {
			t.Fatalf("%s: only %d lines derived", tc.family, len(typed))
		}
		if bad := l73UncoveredWords(typed, objAsks); len(bad) != 0 {
			t.Errorf("%s: typed and never asked about at that level: %q", tc.family, bad)
		}
	}
}

// A line whose path reaches no asked level is reported, not skipped: nothing
// about it would be probed.
func TestL73UncoveredWordsReportsALineThatReachesNoAskedLevel(t *testing.T) {
	asks := []l73Ask{{Ask: "set system tacplus-server 192.0.2.71 ", Need: []string{"port"}}}
	bad := l73UncoveredWords([]string{"set system authentication-order tacplus", "set system tacplus-server 10.0.0.1 port 300"}, asks)
	if len(bad) != 1 || !strings.Contains(bad[0], "authentication-order") {
		t.Fatalf("%q", bad)
	}
}
