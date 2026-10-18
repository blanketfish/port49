package lab

import (
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/tests/lab/labcreds"
)

// Each dialect's first ask is L71's own question, entered and left the way
// L71 enters and leaves it, so the addendum answers L71's question and not
// a neighbour of it.
func TestL73DialectsAskL71sQuestionFirst(t *testing.T) {
	for name, d := range l73Dialects {
		p, ok := l71Probes[d.Probe]
		if !ok {
			t.Errorf("%s: probe %q is not in l71Probes", name, d.Probe)
			continue
		}
		if len(d.Asks) == 0 || !slices.Contains(p.ask, d.Asks[0].Ask) {
			t.Errorf("%s: first ask %+v is not L71's question", name, d.Asks)
		}
		// L71's client words are each looked for by some ask, so the verdict
		// that the image has a client and the keywords typed agree.
		for _, y := range p.yes {
			if !slices.ContainsFunc(d.Asks, func(a l73Ask) bool { return slices.Contains(a.Need, y) || slices.Contains(a.Want, y) }) {
				t.Errorf("%s: L71's client word %q is asked by no ask", name, y)
			}
		}
		if !slices.Equal(d.Enter, p.enter) || !slices.Equal(d.Cleanup, p.cleanup) || d.CfgMark == "" {
			t.Errorf("%s: enter %q cleanup %q, L71's %q %q", name, d.Enter, d.Cleanup, p.enter, p.cleanup)
		}
		if !d.HelpOnly && (d.VersionCmd == "" || d.VersionHas == "" || d.LogCmd == "" || len(d.ShowCmds) == 0 ||
			d.Enrol == "" || d.Fallback == "" || d.Revocation == "") {
			t.Errorf("%s: a measured dialect with an empty field: %+v", name, d)
		}
		for _, a := range d.Asks {
			if a.Only != "" && !slices.ContainsFunc(d.Asks, func(b l73Ask) bool {
				return slices.ContainsFunc(append(slices.Clone(b.Need), b.Want...), func(w string) bool { return b.listed(w) == a.Only })
			}) {
				t.Errorf("%s: %q is asked only after %q, which no ask looks for", name, a.Ask, a.Only)
			}
		}
	}
}

func TestL73IOSXELines(t *testing.T) {
	got := l73CiscoLines("iosxe", nil, l73DeviceTLS{Server: "172.100.100.1"}, nil)
	want := []string{
		"tacacs server l73-tls", "address ipv4 172.100.100.1", "tls trustpoint client l73-dev",
		"tls ip vrf forwarding clab-mgmt", "tls ip tacacs source-interface GigabitEthernet1", "exit",
		"aaa group server tacacs+ port49", "no server name port49-host", "server name l73-tls", "exit",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("got\n%s", maskKey(strings.Join(got, "\n")))
	}
	prev := l73DeviceTLS{Server: "172.100.100.1"}
	got = l73CiscoLines("iosxe", &prev, l73DeviceTLS{Server: "172.100.100.1", Port: 300, SingleConnection: true,
		Second: "172.100.100.2"}, map[string]bool{l73HasTrustpointServer: true})
	for _, line := range []string{"no tacacs server l73-tls", "tls port 300", "single-connection",
		"tls trustpoint server l73-root", "tacacs server l73-second", "key 0 " + labcreds.Key, "server name l73-second"} {
		if !slices.Contains(got, line) {
			t.Errorf("missing %q", maskKey(line))
		}
	}
	// The undo comes first, whole, before anything of the new cell.
	if i, j := slices.Index(got, "no tacacs server l73-tls"), slices.Index(got, "tls port 300"); i < 0 || j < i {
		t.Errorf("undo at %d, new lines at %d", i, j)
	}
}

func TestL73NXOSLines(t *testing.T) {
	got := l73CiscoLines("nxos", nil, l73DeviceTLS{Server: "172.100.100.1", Port: 300}, map[string]bool{l73HasNXOSSecure: true})
	want := []string{
		"aaa group server tacacs+ port49", "no server 172.100.100.1", "exit", "no tacacs-server host 172.100.100.1",
		"tacacs-server secure tls",
		"tacacs-server host 172.100.100.1 port 300", "tacacs-server host 172.100.100.1 tls client-trustpoint l73-dev",
		"aaa group server tacacs+ port49", "server 172.100.100.1", "exit",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("got\n%s", maskKey(strings.Join(got, "\n")))
	}
	got = l73CiscoLines("nxos", nil, l73DeviceTLS{Server: "172.100.100.1", Second: "172.100.100.2"}, nil)
	for _, ln := range got {
		if strings.Contains(ln, "ssl-profile") && ln != "tacacs-server tls ssl-profile l73-tls" {
			t.Errorf("ssl-profile typed on %q: the image's host line takes none", ln)
		}
	}
	if !slices.Contains(l73CiscoRestoreAll("eos", nil), "no tacacs-server tls ssl-profile") {
		t.Error("the undo leaves the global ssl-profile")
	}
	// A TLS host carries no key: the image lists none after `tls`.
	if ln := l73EOSHost("172.100.100.1", true, 0, false, true); strings.Contains(ln, "key") {
		t.Errorf("%q", ln)
	}
	if slices.Contains(got, "tacacs-server secure tls") || !slices.Contains(got, "tacacs-server host 172.100.100.2 key 0 "+labcreds.Key) ||
		slices.Contains(got, "tacacs-server host 172.100.100.2 tls client-trustpoint l73-dev") {
		t.Fatalf("%q", maskKey(strings.Join(got, "\n")))
	}
}

func TestL73EOSLines(t *testing.T) {
	got := l73CiscoLines("eos", nil, l73DeviceTLS{Server: "172.100.100.1"}, nil)
	want := []string{
		"aaa group server tacacs+ port49", "no server 172.100.100.1", "exit",
		"no tacacs-server host 172.100.100.1 tls", "no tacacs-server host 172.100.100.1",
		"no tacacs-server host 172.100.100.2 tls", "no tacacs-server host 172.100.100.2",
		"tacacs-server tls ssl-profile l73-tls", "tacacs-server host 172.100.100.1 tls",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("got\n%s", maskKey(strings.Join(got, "\n")))
	}
	got = l73CiscoLines("eos", nil, l73DeviceTLS{Server: "172.100.100.1", Port: 300, SingleConnection: true,
		Second: "172.100.100.2"}, map[string]bool{l73HasNXOSSecure: true})
	for _, line := range []string{"tacacs-server host 172.100.100.1 tls single-connection port 300",
		"tacacs-server host 172.100.100.2 key 0 " + labcreds.Key} {
		if !slices.Contains(got, line) {
			t.Errorf("missing %q", maskKey(line))
		}
	}
	if slices.Contains(got, "tacacs-server secure tls") || slices.Contains(l73CiscoRestoreAll("eos", map[string]bool{l73HasNXOSSecure: true}), "no tacacs-server secure tls") {
		t.Fatal("an NX-OS keyword typed on EOS")
	}
	_, csr, load, profile := l73EOSEnrol("leaf1")
	if !strings.Contains(csr, "common-name leaf1") || len(load) != 3 || profile[0] != "management security" ||
		!slices.Contains(profile, "ssl profile l73-tls") || !slices.Contains(profile, "chain certificate l73-inter.crt") {
		t.Fatalf("%q %q %q", csr, load, profile) // public names only
	}
}

// The undo ends in the startup config's own lines, read from the files, so
// a renamed server or group in a startup config fails here and not on the
// device.
func TestL73CiscoUndoIsTheStartupConfig(t *testing.T) {
	for _, tc := range []struct{ family, file string }{
		{"iosxe", "configs/iosxe-startup.cfg"}, {"nxos", "configs/nxos-startup.cfg"}, {"eos", "configs/eos-startup.cfg"},
	} {
		b, err := os.ReadFile(tc.file)
		if err != nil {
			t.Fatal(err)
		}
		startup := map[string]bool{}
		for _, ln := range strings.Split(string(b), "\n") {
			startup[strings.TrimSpace(ln)] = true
		}
		has := map[string]bool{l73HasNXOSSecure: true}
		undo := l73CiscoRestoreAll(tc.family, has)
		for _, ln := range undo {
			if strings.HasPrefix(ln, "no ") || ln == "exit" {
				continue
			}
			if !startup[ln] {
				t.Errorf("%s: the undo types %q, which %s does not hold", tc.family, maskKey(ln), tc.file)
			}
		}
		apply := l73CiscoLines(tc.family, nil, l73DeviceTLS{Server: l73Server, Second: l73SecondServer, SecondTLS: true}, has)
		for _, ln := range apply {
			if strings.HasPrefix(ln, "tacacs server ") && !slices.Contains(undo, "no "+ln) {
				t.Errorf("%s: %q is never removed", tc.family, maskKey(ln))
			}
			if strings.HasPrefix(ln, "tacacs-server host ") && !slices.Contains(undo, "no "+strings.Join(strings.Fields(ln)[:3], " ")) {
				t.Errorf("%s: %q is never removed", tc.family, maskKey(ln))
			}
			if ln == "tacacs-server secure tls" && !slices.Contains(undo, "no tacacs-server secure tls") {
				t.Errorf("%s: secure tls is never removed", tc.family)
			}
		}
	}
}

func TestL73NextAnswer(t *testing.T) {
	steps := []l73Step{{"serial number", "no"}, {"IP address", "no"}}
	used := []bool{false, false}
	if _, ok := l73NextAnswer("% Start certificate enrollment ..\r\n", steps, used, "xe1("); ok {
		t.Fatal("an answer before any question")
	}
	tail := "% Include an IP address in the subject name? [no]: and the serial number in the subject name? "
	if n, ok := l73NextAnswer(tail, steps, used, "xe1("); !ok || n != 1 {
		t.Fatalf("%d %v: the earliest question is the IP address one", n, ok)
	}
	used[1] = true
	if n, ok := l73NextAnswer(tail, steps, used, "xe1("); !ok || n != 0 {
		t.Fatalf("%d %v: an answered question chosen again", n, ok)
	}
	if n, ok := l73NextAnswer("done\r\nxe1(config)#", steps, used, "xe1("); !ok || n != -1 {
		t.Fatalf("%d %v: the prompt not read as the end", n, ok)
	}
	if n, ok := l73NextAnswer("xe1(config)# serial number", steps, []bool{false, false}, "xe1("); !ok || n != -1 {
		t.Fatalf("%d %v: a question after the prompt chosen over it", n, ok)
	}
}

func TestL73Expand(t *testing.T) {
	got := l73Expand("{ROOT}{INTER}quit", map[string]string{"ROOT": "R\n", "INTER": "I\n"})
	if got != "R\nI\nquit" {
		t.Fatalf("%q", got)
	}
}

// No reply names a placeholder l73Expand does not fill, and no reply is a
// secret: the dialogues type public certificates, names and yes or no.
func TestL73DialogsUseKnownPlaceholders(t *testing.T) {
	ph := regexp.MustCompile(`\{[A-Z]+\}`)
	for _, family := range []string{"iosxe", "nxos"} {
		prep, enroll, load := l73CiscoEnrol(family, "xe1")
		for _, d := range append(append(prep, enroll), load) {
			for _, s := range d.Steps {
				for _, m := range ph.FindAllString(s.Reply, -1) {
					if !slices.Contains([]string{"{ROOT}", "{INTER}", "{LEAF}", "{NODE}", "{ADDR}"}, m) {
						t.Errorf("%s %q: unknown placeholder %s", family, d.Cmd, m)
					}
				}
				if strings.Contains(s.Reply, labcreds.Key) || strings.Contains(s.Reply, "breakglass") {
					t.Errorf("%s %q: a reply carries a secret", family, d.Cmd)
				}
			}
		}
		if enroll.Done == "" {
			t.Errorf("%s: the enrolment has no Done marker", family)
		}
	}
}

func TestL73Refusal(t *testing.T) {
	if got := l73Refusal("tls port 300\r\n          ^\r\n% Invalid input detected at '^' marker.\r\n"); got != "% Invalid input detected at '^' marker." {
		t.Fatalf("%q", got)
	}
	if got := l73Refusal("xe1(config-server-tacacs)#"); got != "" {
		t.Fatalf("%q", got)
	}
}

// maskKey keeps the lab's shared secret out of a failure message.
func maskKey(s string) string { return strings.ReplaceAll(s, labcreds.Key, "<key>") }

// What a help lists is recorded by ask and word. Two asks that both look for
// "server" (IOS XE's AAA group and its `tls trustpoint` flag) must not answer
// for each other, or the harness types a flag the image never offered.
func TestL73ListedIsKeyedByLevelAndWord(t *testing.T) {
	var group, trust l73Ask
	for _, a := range l73IOSXEAsks {
		switch a.Ask {
		case "":
			if len(a.In) > 0 {
				group = a
			}
		case "tls trustpoint ":
			trust = a
		}
	}
	listed := map[string]bool{}
	l73RecordListed(listed, group, nil, nil) // the group help lists server
	l73RecordListed(listed, trust, nil, nil) // the trustpoint help does not
	if !listed[group.listed("server")] || listed[trust.listed("server")] {
		t.Fatalf("listed: %v", listed)
	}
	if listed[l73HasTrustpointServer] {
		t.Fatal("the group's server answered for the trustpoint flag")
	}
	// A Want word is recorded when listed, and a Need word as listed or missed.
	l73RecordListed(listed, trust, nil, []string{"server"})
	if !listed[l73HasTrustpointServer] {
		t.Fatal("a listed trustpoint server was not recorded")
	}
	// And the other way: listed at the trustpoint, missed by the group.
	other := map[string]bool{}
	l73RecordListed(other, trust, nil, []string{"server"})
	l73RecordListed(other, group, []string{"server"}, nil)
	if other[group.listed("server")] || !other[l73HasTrustpointServer] {
		t.Fatalf("a word listed at one level and missed at another: %v", other)
	}
}

// After a part-way In/Out failure the CLI may be in the object, the group or
// the top of configuration. The recovery leaves configuration with the
// dialect's own last cleanup line, then enters again exactly as the probe did,
// so the cleanup that follows runs from the mode it assumes.
func TestL73RecoverLinesReturnToTheProbeMode(t *testing.T) {
	for _, tc := range []struct {
		platform string
		want     []string
	}{
		{"cisco_iosxe", []string{"end", "configure terminal", "tacacs server l71probe"}},
		{"cisco_nxos", []string{"end", "configure terminal"}},
		{"arista_ceos", []string{"end", "configure"}},
		{"juniper_vjunos-router", nil}, // no ask leaves the Enter mode
	} {
		d := l73Dialects[tc.platform]
		got := l73RecoverLines(d)
		if !slices.Equal(got, tc.want) {
			t.Errorf("%s: %q, want %q", tc.platform, got, tc.want)
		}
		if got != nil && !slices.Equal(got[1:], d.Enter) {
			t.Errorf("%s: recovery does not end in the probe's Enter lines", tc.platform)
		}
	}
}

func TestL73HelpWordsAreTheListedKeywords(t *testing.T) {
	help := "tacacs-server host 192.0.2.71 tls ?\r\n  ssl-profile  Name of the SSL profile\r\n  vrf          VRF\r\n  <cr>\r\n" +
		"    continued description line\r\n  ssl-profile  again\r\nleaf1(config)#"
	if got := l73HelpWords(help); !slices.Equal(got, []string{"ssl-profile", "vrf"}) {
		t.Fatalf("%q", got)
	}
	var many strings.Builder
	for i := 0; i < 20; i++ {
		many.WriteString("  w" + strconv.Itoa(i) + "  x\r\n")
	}
	if got := l73HelpWords(many.String()); len(got) != l73DiagWords {
		t.Fatalf("%d words, want %d", len(got), l73DiagWords)
	}
}

// The EOS help diagnostic asks at the image's own `tls` keyword, one level
// of keywords below it, and the SSL profile submode, which it leaves by
// undoing what it entered. It types no TLS client line.
func TestL73EOSDiagAsks(t *testing.T) {
	d := l73EOSDialect
	if d.DiagDeep != 2 || len(d.DiagAsks) != 1 || d.DiagAsks[0] != "tacacs-server host 192.0.2.71 tls " ||
		len(d.DiagOpAsks) != 3 || d.DiagOpAsks[0] != "show management security ssl profile " || d.DiagOpAsks[2] != "copy " ||
		!slices.Equal(d.DiagFilterAsks, []string{"tacacs-server "}) || !slices.Contains(d.DiagFilter, "ssl") ||
		!slices.Contains(d.DiagSubAsks, "trust certificate ") {
		t.Fatal(d.DiagAsks, d.DiagOpAsks, d.DiagDeep)
	}
	if !slices.Equal(d.DiagSubIn, []string{"management security", "ssl profile l73x"}) ||
		!slices.Contains(d.DiagSubOut, "no ssl profile l73x") {
		t.Fatal(d.DiagSubIn, d.DiagSubOut)
	}
	for _, a := range slices.Concat(d.DiagAsks, d.DiagOpAsks, d.DiagFilterAsks, d.DiagSubAsks[1:]) {
		if !strings.HasSuffix(a, " ") || strings.Contains(a, "?") {
			t.Errorf("%q", a)
		}
	}
	if slices.Contains(d.Asks[0].Need, "ssl-profile") || !slices.Contains(d.Asks[0].Need, "tls") {
		t.Errorf("the host ask requires %v", d.Asks[0].Need)
	}
}

func TestL73HelpWordsHoldingNarrowsToTheFilter(t *testing.T) {
	help := "  host    a\r\n  ssl-profile  b\r\n  tls  c\r\n  key  d\r\n  timeout  e\r\n"
	if got := l73HelpWordsHolding(help, []string{"ssl", "tls"}); !slices.Equal(got, []string{"ssl-profile", "tls"}) {
		t.Fatalf("%q", got)
	}
	if got := l73HelpWordsHolding(help, nil); len(got) != 5 {
		t.Fatalf("%q", got)
	}
}

// The EOS asks confirm every word the run types before it types anything:
// the host line's tls, the global ssl-profile, and the profile submode's
// key, chain and trust arguments.
func TestL73EOSAsksConfirmWhatIsTyped(t *testing.T) {
	need := map[string][]string{}
	for _, a := range l73EOSDialect.Asks {
		need[a.Ask] = a.Need
		if a.Ask != "" && strings.HasPrefix(a.Ask, "tacacs-server") == false && !slices.Equal(a.In, l73EOSProbeIn) && !slices.Equal(a.In, []string{"aaa group server tacacs+ " + l73Group}) {
			t.Errorf("%q is asked outside the scratch profile", a.Ask)
		}
	}
	for ask, w := range map[string]string{
		"tacacs-server host 192.0.2.71 ": "tls", "tacacs-server tls ": "ssl-profile", "tacacs-server ": "tls",
		"certificate " + l73CertID + ".crt ": "key", "chain certificate ": "WORD", "trust certificate ": "WORD",
	} {
		if !slices.Contains(need[ask], w) {
			t.Errorf("no ask at %q needs %q", ask, w)
		}
	}
	if !slices.Contains(l73EOSProbeOut, "no ssl profile l73x") {
		t.Error("the scratch profile is left behind")
	}
}

func TestL73EOSMissing(t *testing.T) {
	d := l73DeviceTLS{Server: "172.100.100.1", Port: 300, SingleConnection: true, Second: "172.100.100.2"}
	shown := "tacacs-server host 172.100.100.1 port 300 single-connection tls\r\n" +
		"tacacs-server host 172.100.100.2 key 7 0123456789abcdef\r\n" +
		"tacacs-server tls ssl-profile l73-tls\r\n"
	if got := l73EOSMissing(shown, d); len(got) != 0 {
		t.Fatalf("%q", got)
	}
	got := l73EOSMissing("tacacs-server host 172.100.100.1 port 300 single-connection\r\n", d)
	want := []string{l73EOSGlobalTLS, "tacacs-server host 172.100.100.1 tls single-connection port 300", "tacacs-server host 172.100.100.2"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %q want %q", got, want)
	}
	for _, g := range got {
		if strings.Contains(g, labcreds.Key) || strings.Contains(g, " key ") {
			t.Errorf("a key reached the message: %q", g)
		}
	}
}

// The EOS INVALID evidence is the device's own TACACS+ view, and the group
// member's help is recorded as a Want, never a Need.
func TestL73EOSInvalidEvidenceAndMemberAsk(t *testing.T) {
	d := l73EOSDialect
	if !slices.Equal(d.InvalidCmds, []string{"show tacacs", "show running-config section tacacs", "show aaa"}) {
		t.Fatal(d.InvalidCmds)
	}
	i := slices.IndexFunc(d.Asks, func(a l73Ask) bool { return a.Ask == "server "+l73Server+" " })
	if i < 0 {
		t.Fatal("no group-member ask")
	}
	a := d.Asks[i]
	if !slices.Equal(a.Need, []string{"port"}) || !slices.Equal(a.In, []string{"aaa group server tacacs+ " + l73Group}) ||
		!slices.Equal(a.Out, []string{"exit"}) {
		t.Fatalf("%+v", a)
	}
	if got := l71MaskExchange("tacacs-server host 172.100.100.1 key 7 0123456789abcdef tls"); strings.Contains(got, "0123456789abcdef") {
		t.Fatal(got)
	}
}

const l73ShowTacacsA = "show tacacs\r\nTACACS+ server            : 172.100.100.1/300 TLS\r\nSSL profile               : l73-tls\r\n" +
	"          Connection opens:          0\r\n\r\nTACACS+ server-group: port49\r\n     0: 172.100.100.1/49\r\n\r\nleaf1#"

func TestL73EOSHostPortIsReadFromShowTacacs(t *testing.T) {
	if got := l73EOSHostPort(l73ShowTacacsA, "172.100.100.1"); got != 300 {
		t.Fatalf("got %d", got)
	}
	if got := l73EOSHostPort(l73ShowTacacsA, "172.100.100.2"); got != 0 {
		t.Fatalf("got %d", got)
	}
	d := l73DeviceTLS{Server: "172.100.100.1"}
	if p, _, err := l73EOSMemberPorts(l73ShowTacacsA, d); err != nil || p != 300 {
		t.Fatal(p, err)
	}
	// A configured port wins; a host `show tacacs` does not list is an error, never a guess.
	if p, _, err := l73EOSMemberPorts("", l73DeviceTLS{Server: "172.100.100.1", Port: 6049}); err != nil || p != 6049 {
		t.Fatal(p, err)
	}
	if _, _, err := l73EOSMemberPorts("", d); err == nil {
		t.Fatal("no error for an unlisted host")
	}
	if _, _, err := l73EOSMemberPorts(l73ShowTacacsA, l73DeviceTLS{Server: "172.100.100.1", Second: "172.100.100.2"}); err == nil {
		t.Fatal("no error for an unlisted second host")
	}
}

func TestL73EOSMembersNameThePort(t *testing.T) {
	d := l73DeviceTLS{Server: "172.100.100.1", Second: "172.100.100.2"}
	want := []string{"aaa group server tacacs+ port49", "server 172.100.100.1 tls port 300", "server 172.100.100.2 port 49", "exit"}
	if got := l73EOSMembers(d, 300, 49); !slices.Equal(got, want) {
		t.Fatalf("%q", got)
	}
	// The undo names the port the member was typed with.
	d.MemberPort, d.SecondMemberPort = 300, 49
	got := l73CiscoUndo("eos", d, nil)
	if !slices.Contains(got, "no server 172.100.100.1 tls port 300") || !slices.Contains(got, "no server 172.100.100.2 port 49") {
		t.Fatalf("%q", got)
	}
	if got := l73CiscoUndo("eos", l73DeviceTLS{Server: "172.100.100.1"}, nil); !slices.Contains(got, "no server 172.100.100.1") {
		t.Fatalf("%q", got)
	}
}

// The attempt 4 and 5 state: a TLS host on 300 and a member on 49 is caught.
func TestL73EOSGroupMissingCatchesThePortMismatch(t *testing.T) {
	d := l73DeviceTLS{Server: "172.100.100.1"}
	got := l73EOSGroupMissing(l73ShowTacacsA, d, 300, 0)
	if len(got) != 1 || !strings.Contains(got[0], "member 172.100.100.1/300 TLS") {
		t.Fatalf("%q", got)
	}
	fixed := strings.Replace(l73ShowTacacsA, "0: 172.100.100.1/49", "0: 172.100.100.1/300 TLS", 1)
	if got := l73EOSGroupMissing(fixed, d, 300, 0); len(got) != 0 {
		t.Fatalf("%q", got)
	}
	// The host itself must be listed on the port typed for it.
	if got := l73EOSGroupMissing(fixed, d, 6049, 0); len(got) != 2 {
		t.Fatalf("%q", got)
	}
}

// A plain member under a TLS host is the attempt 6 state: the port agrees,
// the transport does not.
func TestL73EOSGroupMissingCatchesAPlainMemberUnderATLSHost(t *testing.T) {
	d := l73DeviceTLS{Server: "172.100.100.1"}
	plain := strings.Replace(l73ShowTacacsA, "0: 172.100.100.1/49", "0: 172.100.100.1/300", 1)
	got := l73EOSGroupMissing(plain, d, 300, 0)
	if len(got) != 1 || !strings.Contains(got[0], "member 172.100.100.1/300 TLS") {
		t.Fatalf("%q", got)
	}
	// A plain second host is listed, and matched, without a tag.
	two := plain + "\r\nTACACS+ server            : 172.100.100.2/49\r\nTACACS+ server-group: port49\r\n     0: 172.100.100.1/300 TLS\r\n     1: 172.100.100.2/49\r\n"
	if got := l73EOSGroupMissing(two, l73DeviceTLS{Server: "172.100.100.1", Second: "172.100.100.2"}, 300, 49); len(got) != 0 {
		t.Fatalf("%q", got)
	}
}

func TestL73EOSMemberTakesTLSBeforePort(t *testing.T) {
	if got := l73EOSMember("172.100.100.1", true, 300); got != "server 172.100.100.1 tls port 300" {
		t.Fatal(got)
	}
	if got := l73EOSMember("172.100.100.2", false, 49); got != "server 172.100.100.2 port 49" {
		t.Fatal(got)
	}
	var tlsAsk bool
	for _, a := range l73EOSDialect.Asks {
		if a.Ask == "server "+l73Server+" tls " && slices.Contains(a.Need, "port") {
			tlsAsk = true
		}
	}
	if !tlsAsk {
		t.Fatal("no ask confirms port after the member's tls")
	}
}

// Cell i's TLS second host must not outlive its cell: the apply and the undo
// name both addresses, in both forms, and the read-back refuses a host the
// cell did not type.
func TestL73EOSRemovesBothHostsAndRefusesAStaleOne(t *testing.T) {
	for _, want := range []string{"no tacacs-server host 172.100.100.2 tls", "no tacacs-server host 172.100.100.2"} {
		if !slices.Contains(l73EOSApply(l73DeviceTLS{Server: "172.100.100.1"}), want) {
			t.Errorf("a one-server apply leaves %q", want)
		}
		if !slices.Contains(l73CiscoUndo("eos", l73DeviceTLS{Server: "172.100.100.1", Second: "172.100.100.2", SecondTLS: true}, nil), want) {
			t.Errorf("the undo leaves %q", want)
		}
	}
	shown := l73ShowTacacsA + "\r\nTACACS+ server            : 172.100.100.2/300 TLS\r\n"
	fixed := strings.Replace(shown, "0: 172.100.100.1/49", "0: 172.100.100.1/300 TLS", 1)
	got := l73EOSGroupMissing(fixed, l73DeviceTLS{Server: "172.100.100.1"}, 300, 0)
	if len(got) != 1 || !strings.Contains(got[0], "stale host 172.100.100.2") {
		t.Fatalf("%q", got)
	}
}

func TestL73DropSeedMintsKeepsEveryOtherRecord(t *testing.T) {
	recs := []map[string]any{
		{"event": "mint", "auth": map[string]any{"method": "lab"}, "token_sha256": []any{"x"}},
		{"event": "mint", "auth": map[string]any{"method": "oidc"}},
		{"event": "redeem", "auth": map[string]any{"method": "lab"}},
		{"event": "mint"},
		{"event": "mint", "auth": map[string]any{"method": "lab"}},
	}
	got, n := l73DropSeedMints(recs)
	if n != 2 || len(got) != 3 || got[0]["event"] != "mint" || got[1]["event"] != "redeem" {
		t.Fatalf("%d dropped, %v", n, got)
	}
}

// Cell d reads the device's refusal off the capture: a fatal alert the device
// sent (EOS sends it in the clear after a TLS 1.3 ServerHello).
func TestL73DeviceAlertIsTheDevicesFatalAlert(t *testing.T) {
	conns := []l73Conn{{Alerts: []l73Alert{{Level: 2, Description: 40, FromDevice: false}, {Level: 1, Description: 90, FromDevice: true}}},
		{Alerts: []l73Alert{{Level: 2, Description: 42, FromDevice: true}}}}
	if a, ok := l73DeviceAlert(conns); !ok || a.Description != 42 {
		t.Fatalf("%v %v", a, ok)
	}
	if _, ok := l73DeviceAlert(conns[:1]); ok {
		t.Fatal("a server alert or a warning counted")
	}
}

// A connection opened before the window (the readiness probe's) reads
// "-1.06s", not "+-1.06s", and says why.
func TestL73DescribeSignsAndTagsEarlyConnections(t *testing.T) {
	from := time.Unix(1000, 0)
	got := l73Describe([]l73Conn{{Server: "172.100.100.1:300", SYNAt: from.Add(-1060 * time.Millisecond), Answer: "syn-ack"},
		{Server: "172.100.100.1:300", SYNAt: from.Add(30 * time.Millisecond), Answer: "syn-ack"}}, from)
	if strings.Contains(got, "+-") || !strings.Contains(got, "-1.06s to") || !strings.Contains(got, "+0.03s to") ||
		!strings.Contains(got, "readiness probe") {
		t.Fatal(got)
	}
}

// Cell j2 moves the plain listener to 172.100.100.2:49; the start gate dials
// that address, not the standing .1:49 nothing listens on then.
func TestL73HealthAddrFollowsTheMovedListener(t *testing.T) {
	if got := l73HealthAddr("172.100.100.1:49", ""); got != "172.100.100.1:49" {
		t.Fatal(got)
	}
	if got := l73HealthAddr("172.100.100.1:49", "172.100.100.2:49"); got != "172.100.100.2:49" {
		t.Fatal(got)
	}
}

func TestL73HasAddressMatchesWholeAddresses(t *testing.T) {
	shown := "7: br-x    inet 172.100.100.1/24 brd 172.100.100.255 scope global br-x\n"
	if l73HasAddress(shown, "172.100.100.2") || !l73HasAddress(shown, "172.100.100.1") || l73HasAddress(shown, "172.100.100.") {
		t.Fatal("matched a prefix or missed the address")
	}
	if !l73HasAddress(shown+"7: br-x    inet 172.100.100.2/24 scope global secondary br-x\n", "172.100.100.2") {
		t.Fatal("missed the second address")
	}
}

// Cell i's rows assume 172.100.100.2 stayed on the bridge (an RST from it);
// with it gone the device's second server times out, and the row says so.
func TestL73IRowGateDegradesToNotMeasured(t *testing.T) {
	obs, docs := "rows", "yes: ruling 7"
	gone := "7: br-x    inet 172.100.100.1/24 scope global br-x\n"
	here := gone + "7: br-x    inet 172.100.100.2/24 scope global secondary br-x\n"
	if o, d := l73IRowGate(here, obs, docs); o != obs || d != docs {
		t.Fatalf("a present address changed the row: %q %q", o, d)
	}
	o, d := l73IRowGate(gone, obs, docs)
	if !strings.HasPrefix(o, "not measured: 172.100.100.2 left the bridge during the cell") || !strings.Contains(o, "172.100.100.1/24") ||
		!strings.HasPrefix(d, "n/a: not measured") || strings.Contains(d, "yes") || strings.Contains(o, "**no**") {
		t.Fatalf("%q %q", o, d)
	}
}
