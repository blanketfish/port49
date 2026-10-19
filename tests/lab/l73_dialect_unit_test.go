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
	// 17.18.02 drops `address ipv4` on a second server object that would share
	// port49-host's address, so port49-host goes, object and all, first.
	want := []string{
		"aaa group server tacacs+ port49", "no server name port49-host", "exit", "no tacacs server port49-host",
		"tacacs server l73-tls", "address ipv4 172.100.100.1", "do show running-config | section tacacs",
		"tls trustpoint client l73-dev", "tls ip vrf forwarding clab-mgmt", "tls ip tacacs source-interface GigabitEthernet1", "exit",
		"aaa group server tacacs+ port49", "server name l73-tls", "exit",
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
	// It frees the address before port49-host takes it back.
	if i, j := slices.Index(got, "no tacacs server l73-tls"), slices.Index(got, "address ipv4 172.100.100.1"); i < 0 || j < i {
		t.Errorf("the address is taken back at %d, before l73-tls is removed at %d", j, i)
	}
}

// The undo gives port49-host back exactly as the startup config holds it
// (lines 61-65 of configs/iosxe-startup.cfg), and the group its member.
func TestL73IOSXEUndoRestoresPort49HostAsTheStartupConfigHoldsIt(t *testing.T) {
	b, err := os.ReadFile("configs/iosxe-startup.cfg")
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	for _, ln := range strings.Split(string(b), "\n") {
		switch {
		case ln == "tacacs server port49-host":
			want = []string{ln}
		case want != nil && strings.HasPrefix(ln, " "):
			want = append(want, strings.TrimSpace(ln))
		case want != nil:
			goto done
		}
	}
done:
	undo := l73CiscoRestoreAll("iosxe", nil)
	i := slices.Index(undo, "tacacs server port49-host")
	if i < 0 || len(want) < 4 || !slices.Equal(undo[i:i+len(want)], want) {
		t.Fatalf("undo %v\nwants the startup config's block %v", maskKey(strings.Join(undo, " | ")), maskKey(strings.Join(want, " | ")))
	}
	if undo[i+len(want)] != "exit" || !slices.Contains(undo[i:], "server name port49-host") {
		t.Errorf("the block is not closed and re-added to the group: %v", undo[i:])
	}
}

// What the image printed for the TLS server object when it dropped the
// address (attempt 3, 17.18.02): no `% ` with a space, a Warning on exit.
const l73IOSXEDroppedAddress = `xe1(config)#tacacs server l73-tls
xe1(config-server-tacacs)#address ipv4 172.100.100.1
xe1(config-server-tacacs)#tls trustpoint client l73-dev
xe1(config-server-tacacs)#tls ip vrf forwarding clab-mgmt
%Invalid IP version 0 for the server address
xe1(config-server-tacacs)#exit
Warning: Address not yet configured.
xe1(config)#`

func TestL73RefusalSeesTheUnspacedMarksAndIOSXEsAddressWarning(t *testing.T) {
	if got := l73Refusal(l73IOSXEDroppedAddress); got != "%Invalid IP version 0 for the server address" {
		t.Errorf("%q", got)
	}
	for _, m := range []string{"%Invalid input", "%Incomplete command", "%Unrecognized command", "%Ambiguous command", "%Error opening x"} {
		if got := l73Refusal("xe1(config)#x\r\n" + m + "\r\n"); got != m {
			t.Errorf("%q: got %q", m, got)
		}
	}
	// The Warning is IOS XE's alone: with the marks of any other dialect, or none,
	// it refuses nothing.
	warn := "xe1(config-server-tacacs)#exit\nWarning: Address not yet configured.\nxe1(config)#"
	for _, fam := range []string{"", "nxos", "eos", "xr", "junos"} {
		if got := l73Refusal(warn, l73ExtraMarks(fam)...); got != "" {
			t.Errorf("%s: the Warning refused: %q", fam, got)
		}
	}
	if got := l73Refusal(warn, l73ExtraMarks("iosxe")...); got != "Warning: Address not yet configured." {
		t.Errorf("iosxe: %q", got)
	}
	// Other Warnings stay what they were.
	if got := l73Refusal("Warning: a thing\n", l73ExtraMarks("iosxe")...); got != "" {
		t.Errorf("%q", got)
	}
}

func TestL73IOSXERestoredReadsPort49HostBackWithItsAddress(t *testing.T) {
	ok := "tacacs server port49-host\n address ipv4 172.100.100.1\n key 0 <key>\n timeout 5\n"
	if !l73IOSXERestored(ok) {
		t.Error("the startup block was refused")
	}
	for _, bad := range []string{"", "tacacs server port49-host\n key 0 <key>\n", "tacacs server l73-tls\n address ipv4 172.100.100.1\n",
		"tacacs server port49-host\n address ipv4 172.100.100.2\n"} {
		if l73IOSXERestored(bad) {
			t.Errorf("accepted %q", bad)
		}
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
			t.Errorf("ssl-profile typed on %q: the image's host line takes none", maskKey(ln))
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

// The IOL-XE image has no `tacacs server <name>` object (the 2026-10-18 probe
// listed `tacacs-server` and no `tacacs`), so its help is asked in the legacy
// form, as XRd's is: the host ask first (L71's own verdict), the keyword list,
// and the `tls` level only when the host help listed `tls`.
func TestL73IOLAsksTheLegacyFormAndGatesTheTLSLevel(t *testing.T) {
	d := l73Dialects["cisco_iol-xe"]
	pr := l71Probes["cisco_iol-xe"]
	host := "tacacs-server host 192.0.2.71 "
	if len(d.Asks) != 4 || d.Asks[0].Ask != host || d.Asks[1].Ask != "tacacs-server " || !d.Asks[1].Evidence ||
		d.Asks[2].Ask != "" || !d.Asks[2].Evidence || !slices.Equal(d.Asks[2].Keep, []string{"aaa", "tacacs"}) || d.Asks[3].Ask != host+"tls " {
		t.Fatalf("asks: %+v", d.Asks)
	}
	if !slices.Equal(d.Enter, []string{"configure terminal"}) || !slices.Equal(d.Enter, pr.enter) || !slices.Equal(pr.ask, []string{host}) ||
		slices.Contains(d.Enter, "tacacs server l71probe") || slices.Contains(pr.enter, "tacacs server l71probe") {
		t.Fatalf("enter %v, probe %v %v", d.Enter, pr.enter, pr.ask)
	}
	// Ask 1's Want words are a control: other words in the help are no failure.
	if _, _, err := l73HelpVerdict("  timeout  t\n  zzz  z\n", d.Asks[1]); err != nil {
		t.Fatalf("a help with other words failed: %v", err)
	}
	third := d.Asks[3]
	listed := map[string]bool{}
	_, _, _ = l73HelpVerdict("  key  k\n  port  p\n", d.Asks[0])
	miss, have, _ := l73HelpVerdict("  key  k\n  port  p\n  timeout  t\n", d.Asks[0])
	l73RecordListed(listed, d.Asks[0], miss, have)
	if third.Only == "" || listed[third.Only] {
		t.Fatalf("the tls level would be asked with no tls listed: only %q listed %v", third.Only, listed)
	}
	miss, have, _ = l73HelpVerdict("  key  k\n  port  p\n  tls  Use TLS\n", d.Asks[0])
	l73RecordListed(listed, d.Asks[0], miss, have)
	if !listed[third.Only] {
		t.Fatalf("the tls level is skipped though tls was listed: %q %v", third.Only, listed)
	}
}

const l73IOLHostHelp = "tacacs-server host 192.0.2.71 ?\n  <cr>  <cr>\n\niol1(config)#tacacs-server host 192.0.2.71 \b\b\b                  \b\b\b"

// IOL-XE 17.18.02's `tacacs-server host <addr> ?` printed `<cr>` and nothing
// else (the 2026-10-18 probe). That is an answer, not a screen to refuse.
func TestL73CROnlyHelpIsAValidNegative(t *testing.T) {
	if !l73CROnly(l73IOLHostHelp) {
		t.Fatal("the IOL host help was not read as <cr> only")
	}
	for name, help := range map[string]string{
		"a list":    "tacacs-server host 192.0.2.71 ?\n  key  k\n  <cr>  <cr>\n\niol1(config)#",
		"an error":  "tacacs-server host 192.0.2.71 ?\n% Invalid input detected at '^' marker.\n\niol1(config)#",
		"nothing":   "tacacs-server host 192.0.2.71 ?\n\niol1(config)#",
		"tls in cr": "tacacs-server host 192.0.2.71 ?\n  <cr>  <cr>\n  tls  Use TLS\n\niol1(config)#",
	} {
		if l73CROnly(help) {
			t.Errorf("%s was read as <cr> only", name)
		}
	}
	pr := l71Probes["cisco_iol-xe"]
	if line, err := l71Read(l73IOLHostHelp, pr); err != nil || line != "" {
		t.Fatalf("L71's reading of the <cr>-only help: %q %v", line, err)
	}
	a := l73Dialects["cisco_iol-xe"].Asks[0]
	if miss, _, err := l73HelpVerdict(l73IOLHostHelp, a); err != nil || !slices.Contains(miss, "tls") {
		t.Fatalf("the verdict on the <cr>-only help: miss %v err %v", miss, err)
	}
}

func TestL73KeepLinesKeepsOnlyTheNamedWords(t *testing.T) {
	help := "?\n  aaa  Authentication, Authorization and Accounting.\n  access-list  Add an access list entry\n  tacacs-server  Modify TACACS query parameters\n  tftp-server  x\n\niol1(config)#"
	got := l73KeepLines(help, []string{"tacacs", "aaa"})
	if len(got) != 2 || !strings.HasPrefix(got[0], "aaa ") || !strings.HasPrefix(got[1], "tacacs-server ") {
		t.Fatalf("%q", got)
	}
}

// The finding says what was seen: no "does not support TLS", and the
// `tacacs` object is named absent only when the listing shows no such word.
func TestL73CRFindingStatesExactlyWhatWasSeen(t *testing.T) {
	got := l73CRFinding("IOL-XE 17.18.02", "tacacs-server host <addr>", []string{"aaa  Authentication", "tacacs-server  Modify TACACS query parameters"})
	for _, want := range []string{"IOL-XE 17.18.02 offers no RFC 9887 client in its configuration help", "`tacacs-server`", "no `tacacs` object", "lists `<cr>` only"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %q", want, got)
		}
	}
	if strings.Contains(got, "support") {
		t.Errorf("claims more than was seen: %q", got)
	}
	with := l73CRFinding("IOL-XE 17.18.02", "tacacs-server host <addr>", []string{"tacacs  Configure TACACS+ server"})
	if strings.Contains(with, "no `tacacs` object") {
		t.Errorf("a listed tacacs object was called absent: %q", with)
	}
	if none := l73CRFinding("IOL-XE 17.18.02", "tacacs-server host <addr>", nil); strings.Contains(none, "no `tacacs` object") {
		t.Errorf("an unasked listing was read as absence: %q", none)
	}
}

func TestL73HelpBodyIsTheListWithoutEchoOrPrompt(t *testing.T) {
	got := l73HelpBody(l73IOLHostHelp)
	if len(got) != 1 || strings.TrimSpace(got[0]) != "<cr>  <cr>" {
		t.Fatalf("%q", got)
	}
}

// A help-only row starts no port49d, so it mints no seed token; its probe
// exchange is still checked against the lab's published key and password. A
// measured row with no token is still refused.
func TestL73SecretsForAHelpOnlyRowNeedNoSeedToken(t *testing.T) {
	got, err := l73SecretsFor(true, []string{"pem-body"}, nil)
	// Names only: the list holds the lab key and the break-glass password.
	var missing []string
	for name, v := range map[string]string{"pem": "pem-body", "lab key": labcreds.Key, "break-glass password": labcreds.BreakglassPassword} {
		if !slices.Contains(got, v) {
			missing = append(missing, name)
		}
	}
	if err != nil || len(missing) > 0 {
		t.Fatalf("help-only: missing %v, %d entries, err %v", missing, len(got), err)
	}
	if _, err := l73SecretsFor(false, nil, nil); err == nil {
		t.Fatal("a measured row with no minted token was accepted")
	}
}

// A container's log goes to the INVALID directory only through the screens'
// scrub: the lab key, a PEM body and a typed secret never reach the file.
func TestL73LogScreenScrubsAContainerLog(t *testing.T) {
	in := "boot ok\ntacacs-server host 10.0.0.1 key 0 " + labcreds.Key + "\n" +
		"-----BEGIN PRIVATE KEY-----\nQUJDREVGR0hJSktMTU5PUFFSU1RVVldY\n-----END PRIVATE KEY-----\n" +
		"password " + labcreds.BreakglassPassword + "\nsshd: listening on 22\n"
	got := l73LogScreen(in)
	for _, bad := range []string{labcreds.Key, "QUJDREVG", labcreds.BreakglassPassword} {
		if strings.Contains(got, bad) {
			t.Errorf("the log screen still holds a secret (%d bytes of it)", len(bad))
		}
	}
	if !strings.Contains(got, "boot ok") || !strings.Contains(got, "sshd: listening on 22") {
		t.Errorf("the log screen lost the log: %q", got)
	}
}

// The L71 claim mentions the `tacacs server l71probe` object only for a probe
// that creates it; IOL-XE 17.18.02 has no such object and its probe enters
// none.
func TestL71ClaimNamesTheProbeObjectOnlyWhereItIsCreated(t *testing.T) {
	const obj = "tacacs server l71probe"
	for name, pr := range l71Probes {
		creates := slices.Contains(pr.enter, obj)
		if got := strings.Contains(l71ClaimFor(name), obj); got != creates {
			t.Errorf("%s: claim names the object %v, probe creates it %v", name, got, creates)
		}
		if !strings.Contains(l71ClaimFor(name), "policy engine spec §15 L71") {
			t.Errorf("%s: the claim lost its citation", name)
		}
	}
	if !slices.Contains(l71Probes["cisco_iosxe"].enter, obj) {
		t.Fatal("the IOS XE probe no longer creates the object: the test checks nothing")
	}
}

// NX-OS 10.6.2.F's terminal enrolment refuses an ECC key ("no rsa key-pair is
// associated with the trustpoint configuration", attempt 19): the device key
// is an RSA-2048 one, and the image's own help is asked about both words
// before either is typed.
func TestL73NXOSEnrolMakesAnRSAKeyAndAsksItsHelp(t *testing.T) {
	prep, _, _ := l73CiscoEnrol("nxos", "nx1")
	var cmds []string
	for _, d := range prep {
		cmds = append(cmds, d.Cmd)
	}
	j := strings.Join(cmds, "\n")
	for _, want := range []string{"crypto key generate rsa label " + l73CiscoKey + " exportable modulus 2048", "rsakeypair " + l73CiscoKey} {
		if !strings.Contains(j, want) {
			t.Errorf("prep lacks %q:\n%s", want, j)
		}
	}
	if strings.Contains(j, "ecc") {
		t.Errorf("prep still makes an ECC key:\n%s", j)
	}
	need := map[string][]string{}
	for _, a := range l73NXOSAsks {
		key := a.Ask
		if len(a.In) > 0 {
			key = strings.Join(a.In, ";") + "|" + a.Ask
		}
		need[key] = a.Need
	}
	if got := need["crypto ca trustpoint "+l73CertID+"|"]; !slices.Contains(got, "rsakeypair") {
		t.Errorf("no ask for the trustpoint's help needing rsakeypair: %v", need)
	}
	got := need["crypto key generate rsa "]
	for _, w := range []string{"label", "modulus", "exportable"} {
		if !slices.Contains(got, w) {
			t.Errorf("the key-generation ask lacks Need %q: %v", w, got)
		}
	}
}

// NX-OS's `crypto ca import ... certificate` asks "input (cut & paste)
// certificate in PEM format:" (attempt 20) and ends the paste at the
// certificate's own END CERTIFICATE line: a following "END OF INPUT" is read
// as a command and refused (attempt 21). So the dialogue waits for the words
// the image printed and sends the certificate alone.
func TestL73NXOSImportWaitsForTheImagesOwnPrompt(t *testing.T) {
	_, _, load := l73CiscoEnrol("nxos", "nx1")
	if len(load.Steps) != 1 || load.Steps[0].Prompt != "certificate in PEM format:" || load.Steps[0].Reply != "{LEAF}" {
		t.Fatalf("%+v", load.Steps)
	}
}

// NX-OS 10.6.2.F answers port49d's server flight 5.00 s late on every
// connection, which the default handshake_timeout (10s) covers, so no
// platform widens it. A failed control login there reads the device's own
// view, and none of those commands can print a private key.
func TestL73NXOSRunsAtTheDefaultHandshakeAndReadsTheDevice(t *testing.T) {
	d := l73Dialects["cisco_nxos"]
	for name, o := range l73Dialects {
		if o.HandshakeTimeout != 0 {
			t.Errorf("%s sets the handshake timeout to %s; the default is what runs", name, o.HandshakeTimeout)
		}
	}
	want := []string{"show logging last 50", "show crypto ca certificates l73-dev", "show crypto key mypubkey rsa", "show running-config tacacs+"}
	if !slices.Equal(d.InvalidCmds, want) {
		t.Fatalf("%q", d.InvalidCmds)
	}
	for _, c := range d.InvalidCmds {
		if strings.Contains(c, "export") || strings.Contains(c, "private") || strings.Contains(c, "keypair") {
			t.Errorf("%q could print private key material", c)
		}
	}
}

// NX-OS 10.6.2.F delays every RFC 9887 connection 5.00 s, and a token login is
// five connections, so its SSH dial gets 90s; no other platform changes.
func TestL73NXOSLoginDialIsWidened(t *testing.T) {
	if got := l73Dialects["cisco_nxos"].LoginDial; got != 90*time.Second {
		t.Errorf("nxos login dial %s", got)
	}
	for name, d := range l73Dialects {
		if name != "cisco_nxos" && d.LoginDial != 0 {
			t.Errorf("%s widens the login dial to %s", name, d.LoginDial)
		}
	}
}

// A failed IOS XE control login reads the TACACS+ configuration and server
// state; every command is a show, and none can print a key.
func TestL73IOSXEReadsTheDeviceOnAFailedLogin(t *testing.T) {
	want := []string{"show running-config | section tacacs", "show tacacs", "show aaa servers",
		"show ip route vrf clab-mgmt 172.100.100.1", "show logging | include TACACS|TLS|PKI|SSL|CRYPTO"}
	if got := l73Dialects["cisco_iosxe"].InvalidCmds; !slices.Equal(got, want) {
		t.Fatalf("%q", got)
	}
	for _, c := range want {
		if !strings.HasPrefix(c, "show ") {
			t.Errorf("%q is not a show command", c)
		}
	}
}

// XRd's sshd resets a session over its rate limit; the run records the image's
// help for the option and configures nothing.
func TestL73XRdAsksTheSSHRateLimitHelpAndConfiguresNothing(t *testing.T) {
	d := l73Dialects["cisco_xrd"]
	var asks []string
	for _, a := range d.Asks {
		asks = append(asks, a.Ask)
		if len(a.In) > 0 {
			t.Errorf("the ask %q enters a mode: %q", a.Ask, a.In)
		}
	}
	if !slices.Contains(asks, "ssh server ") || !slices.Contains(asks, "ssh server rate-limit ") {
		t.Fatalf("%q", asks)
	}
	for _, a := range d.Asks {
		if (a.Ask == "ssh server " || a.Ask == "ssh server rate-limit ") && !a.Evidence {
			t.Errorf("%q must be recorded as evidence, not graded", a.Ask)
		}
	}
	if !d.HelpOnly {
		t.Error("the XRd row is help only")
	}
}

// The `do show` typed right after the address line is kept, as the image
// printed it, for the note; the rest of the configure screen is not.
func TestL73DoShowScreensKeepsWhatTheImagePrintedAfterEachDoShow(t *testing.T) {
	screen := "xe1(config)#tacacs server l73-tls\r\n" +
		"xe1(config-server-tacacs)#address ipv4 172.100.100.1\r\n" +
		"xe1(config-server-tacacs)#do show running-config | section tacacs\r\n" +
		"tacacs server l73-tls\r\n address ipv4 172.100.100.1\r\n key 0 <key>\r\n" +
		"xe1(config-server-tacacs)#tls port 300\r\n"
	got := l73DoShowScreens(screen)
	want := []string{"tacacs server l73-tls\n address ipv4 172.100.100.1\n key 0 <key>"}
	if !slices.Equal(got, want) {
		t.Fatalf("%q", got)
	}
	if got := l73DoShowScreens("xe1(config)#exit\r\n"); len(got) != 0 {
		t.Fatalf("%q", got)
	}
}

func TestL73RetryReachesOnTheFirstThirdAndTimesOut(t *testing.T) {
	var now time.Time
	clock := func() time.Time { return now }
	var slept []time.Duration
	sleep := func(d time.Duration) { slept = append(slept, d); now = now.Add(d) }
	// The first attempt reaches: no wait.
	n, err := l73Retry(func(int) (bool, int) { return true, 0 }, sleep, clock, 10*time.Second, 5*time.Minute)
	if err != nil || n != 1 || len(slept) != 0 {
		t.Fatalf("first: %d %v %v", n, err, slept)
	}
	// The third reaches, after two waits of 10s.
	n, err = l73Retry(func(n int) (bool, int) { return n == 3, 0 }, sleep, clock, 10*time.Second, 5*time.Minute)
	if err != nil || n != 3 || len(slept) != 2 || slept[0] != 10*time.Second {
		t.Fatalf("third: %d %v %v", n, err, slept)
	}
	// Never: INVALID at the bound.
	slept = nil
	n, err = l73Retry(func(int) (bool, int) { return false, 0 }, sleep, clock, 10*time.Second, 5*time.Minute)
	if err == nil || !strings.Contains(err.Error(), "opened no connection") || n < 30 || n > 32 {
		t.Fatalf("timeout: %d %v", n, err)
	}
	// With no bound (a dialect that does not retry) one unreached attempt ends it.
	n, err = l73Retry(func(int) (bool, int) { return false, 0 }, sleep, clock, 10*time.Second, 0)
	if err == nil || n != 1 {
		t.Fatalf("no retry: %d %v", n, err)
	}
	// An unreached attempt that port49d recorded is a leak, not a retry.
	n, err = l73Retry(func(int) (bool, int) { return false, 2 }, sleep, clock, 10*time.Second, 5*time.Minute)
	if err == nil || !strings.Contains(err.Error(), "leaked") || n != 1 {
		t.Fatalf("leak: %d %v", n, err)
	}
}

func TestL73IOSXERetriesUnreachedLogins(t *testing.T) {
	if !l73Dialects["cisco_iosxe"].RetryUnreached {
		t.Error("IOS XE does not retry an unreached login")
	}
	for name, d := range l73Dialects {
		if d.Family != "iosxe" && d.RetryUnreached {
			t.Errorf("%s retries", name)
		}
	}
}
