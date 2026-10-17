package lab

import (
	"slices"
	"strconv"
	"strings"

	"github.com/rhwendt/port49/tests/lab/labcreds"
)

// l73Dialect is how TestL73 asks one platform's CLI about its RFC 9887
// client, points the client at port49 and puts it back, and reads it.
type l73Dialect struct {
	Family     string // junos, iosxe, nxos, eos, xr: which line builders apply
	Vendor     string // the note's name for the OS
	Probe      string // the l71Probes entry whose question the first ask is
	Enter      []string
	Cleanup    []string
	CfgMark    string // what every configuration prompt contains
	Asks       []l73Ask
	HelpOnly   bool
	VersionCmd string // run after each token login
	VersionHas string // what its output holds on the image under test
	Attrs      string // port49d's session_attributes here; "" keeps the lab file's
	Enrol      string // cell e's "configured" wording
	Fallback   string // the startup config's login method list (cell i)
	Revocation string // the run facts' sentence on device-side revocation
	LogCmd     string
	ShowCmds   []string
}

var l73JunosDialect = l73Dialect{
	Family: "junos", Vendor: "Junos", Probe: "juniper_vjunos-router",
	Enter: []string{"configure"}, Cleanup: []string{"rollback 0", "exit configuration-mode"}, CfgMark: "# ",
	Asks: l73JunosAsks, VersionCmd: "show version | match Junos:", VersionHas: "26.2R1", Attrs: "[]",
	Enrol: "the documented offline enrolment (`request security pki generate-key-pair`, " +
		"`generate-certificate-request`, the lab CA's answer loaded back from a file)",
	Fallback:   "`authentication-order [ tacplus password ]` (configs/vjunos-startup.conf)",
	Revocation: "`revocation-check disable` on its CA profiles",
	LogCmd:     `show log messages | match "tacplus|TACPLUS|tls|TLS|certif|pki" | last 40`,
	ShowCmds: []string{"show configuration system tacplus-server | display set",
		"show configuration system accounting | display set", "show configuration security pki | display set",
		"show security pki local-certificate certificate-id " + l73CertID + " detail"},
}

// IOS XE's help is asked inside a probe server object, as L71 asked it.
var l73IOSXEAsks = []l73Ask{
	{Ask: "", Control: []string{"address", "key", "port", "timeout"}, Need: []string{"tls", "address", "single-connection", "key", "port"}},
	{Ask: "address ", Control: []string{"ipv4"}, Need: []string{"ipv4"}},
	{Ask: "tls ", Control: []string{"port", "trustpoint", "idle-timeout", "connection-timeout"}, Need: []string{"port", "trustpoint", "ip"}},
	{Ask: "tls trustpoint ", Control: []string{"client", "server"}, Need: []string{"client"}, Want: []string{"server"}},
	{Ask: "tls ip ", Control: []string{"vrf", "tacacs"}, Need: []string{"vrf", "tacacs"}},
	{Ask: "tls ip vrf ", Control: []string{"forwarding"}, Need: []string{"forwarding"}},
	{Ask: "tls ip tacacs ", Control: []string{"source-interface"}, Need: []string{"source-interface"}},
	// The AAA server group the cell's servers join: IOS XE leaves the probe
	// object, enters the startup config's group and comes back.
	{Ask: "", Control: []string{"server"}, Need: []string{"server"},
		In: []string{"exit", "aaa group server tacacs+ " + l73Group}, Out: []string{"exit", "tacacs server l71probe"}},
	{Ask: "server ", Control: []string{"name"}, Need: []string{"name"},
		In: []string{"exit", "aaa group server tacacs+ " + l73Group}, Out: []string{"exit", "tacacs server l71probe"}},
}

var l73IOSXEDialect = l73Dialect{
	Family: "iosxe", Vendor: "IOS XE", Probe: "cisco_iosxe",
	Enter: []string{"configure terminal", "tacacs server l71probe"}, Cleanup: []string{"exit", "no tacacs server l71probe", "end"},
	CfgMark: "(config", Asks: l73IOSXEAsks,
	VersionCmd: "show version | include Cisco IOS XE Software", VersionHas: "17.18", Attrs: `["priv-lvl=15"]`,
	Enrol: "terminal enrolment as Cisco doc 225097 shows it (`crypto key generate ec keysize 256`, `crypto pki enroll`, " +
		"the request read off the screen, the lab CA's answer pasted at `crypto pki import`)",
	Fallback:   "`aaa authentication login default group port49 local` (configs/iosxe-startup.cfg)",
	Revocation: "`revocation-check none` on both trustpoints",
	LogCmd:     "show logging | include TACACS|TLS|PKI|SSL|CRYPTO",
	ShowCmds: []string{"show running-config | section tacacs", "show running-config | section crypto pki trustpoint",
		"show crypto pki certificates " + l73CertID, "show tacacs"},
}

var l73NXOSAsks = []l73Ask{
	{Ask: "tacacs-server host 192.0.2.71 ", Control: []string{"key", "port", "timeout"}, Need: []string{"tls", "port", "single-connection", "key"}},
	{Ask: "tacacs-server ", Control: []string{"host", "key", "timeout"}, Need: []string{"host"}, Want: []string{"secure"}},
	{Ask: "tacacs-server secure ", Control: []string{"tls"}, Need: []string{"tls"}, Only: l73HasNXOSSecure},
	{Ask: "tacacs-server host 192.0.2.71 tls ", Control: []string{"client-trustpoint", "server-trustpoint"},
		Need: []string{"client-trustpoint"}, Want: []string{"server-trustpoint"}},
	{Ask: "", Control: []string{"server"}, Need: []string{"server"}, In: []string{"aaa group server tacacs+ " + l73Group}, Out: []string{"exit"}},
}

// EOS: the client keyword is ssl-profile (L71 looked for it and for tls);
// the profile itself is a submode the help cannot be asked about.
var l73EOSDialect = l73Dialect{
	Family: "eos", Vendor: "EOS", Probe: "arista_ceos",
	Enter: []string{"configure"}, Cleanup: []string{"end"}, CfgMark: "(config",
	Asks: []l73Ask{{Ask: "tacacs-server host 192.0.2.71 ", Control: []string{"key", "port", "timeout"},
		Need: []string{"ssl-profile", "port", "single-connection", "key"}, Want: []string{"tls"}},
		{Ask: "", Control: []string{"server"}, Need: []string{"server"}, In: []string{"aaa group server tacacs+ " + l73Group}, Out: []string{"exit"}}},
	VersionCmd: "show version | include Software image version", VersionHas: "4.36.3M",
	Enrol: "EOS's documented enrolment (`security pki key generate`, `security pki certificate generate signing-request`, " +
		"the request read off the screen, the lab CA's answer copied to `certificate:`; the SSL profile names the " +
		"intermediate as its `chain certificate`)",
	Fallback:   "`aaa authentication login default group port49 local` (configs/eos-startup.cfg)",
	Revocation: "no CRL in its SSL profile",
	LogCmd:     "show logging | include TACACS|TLS|SSL|AAA",
	ShowCmds: []string{"show running-config section tacacs", "show running-config section management security",
		"show management security ssl profile " + l73EOSProfile, "show tacacs"},
}

var l73Dialects = map[string]l73Dialect{
	"juniper_vjunos-router": l73JunosDialect,
	"arista_ceos":           l73EOSDialect,
	"juniper_vjunos-switch": l73JunosDialect,
	"cisco_iosxe":           l73IOSXEDialect,
	"cisco_nxos": {
		Family: "nxos", Vendor: "NX-OS", Probe: "cisco_nxos",
		Enter: []string{"configure terminal"}, Cleanup: []string{"end"}, CfgMark: "(config", Asks: l73NXOSAsks,
		VersionCmd: "show version | include NXOS:", VersionHas: "10.6(2)",
		Enrol: "terminal enrolment as Cisco doc 224882 shows it (`crypto key generate ecc`, `crypto ca enroll`, " +
			"the request read off the screen, the lab CA's answer pasted at `crypto ca import`)",
		Fallback:   "`aaa authentication login default group port49 local` (configs/nxos-startup.cfg)",
		Revocation: "`revocation-check none` on both trustpoints",
		LogCmd:     `show logging logfile | egrep "TACACS|tacacs|TLS|tls|PKI|pki" | last 40`,
		ShowCmds: []string{"show running-config tacacs+", "show crypto ca trustpoints",
			"show crypto ca certificates " + l73CertID, "show tacacs-server"},
	},
	"cisco_iol-xe": {Family: "iosxe", Vendor: "IOS XE (IOL)", Probe: "cisco_iol-xe", HelpOnly: true,
		Enter: l73IOSXEDialect.Enter, Cleanup: l73IOSXEDialect.Cleanup, CfgMark: "(config", Asks: l73IOSXEAsks},
	"cisco_xrd": {Family: "xr", Vendor: "IOS XR (XRd)", Probe: "cisco_xrd", HelpOnly: true,
		Enter: []string{"configure"}, Cleanup: []string{"abort"}, CfgMark: "(config",
		Asks: []l73Ask{{Ask: "tacacs-server host 192.0.2.71 ", Control: []string{"key", "port", "timeout"}, Need: []string{"tls"}}}},
}

// The names the Cisco lines use. l73XEStart and l73Group are the startup
// configs' (TestL73CiscoUndoIsTheStartupConfig reads them from the files).
const (
	l73XEServer = "l73-tls"
	l73XESecond = "l73-second"
	l73XEStart  = "port49-host"
	l73Group    = "port49"
	l73XEVRF    = "clab-mgmt"
	l73XESource = "GigabitEthernet1"
	l73CiscoKey = "l73-key"
)

// l73RecoverLines is what to type when an ask's In or Out failed part way and
// the CLI's mode is unknown: leave configuration with the dialect's own last
// cleanup line (the first line is typed expecting the exec prompt), then
// enter as the probe did, so the cleanup runs from the mode it assumes. Nil
// when no ask leaves the Enter mode.
func l73RecoverLines(d l73Dialect) []string {
	if len(d.Cleanup) == 0 || !slices.ContainsFunc(d.Asks, func(a l73Ask) bool { return len(a.In) > 0 || len(a.Out) > 0 }) {
		return nil
	}
	return append([]string{d.Cleanup[len(d.Cleanup)-1]}, d.Enter...)
}

// The keys of the Want words the Cisco lines read from has (l73RecordListed).
var (
	l73HasTrustpointServer = l73Ask{Ask: "tls trustpoint "}.listed("server")
	l73HasNXOSSecure       = l73Ask{Ask: "tacacs-server "}.listed("secure")
	l73HasNXOSServerTrust  = l73Ask{Ask: "tacacs-server host 192.0.2.71 tls "}.listed("server-trustpoint")
)

// l73CiscoLines is what one Cisco cell types: the previous cell's undo (prev
// nil: the startup config is in place), then this cell's lines. IOS XE and
// NX-OS have no commit to roll back, so each cell starts from the startup
// config's servers. has is the Want words the image's help listed.
func l73CiscoLines(family string, prev *l73DeviceTLS, d l73DeviceTLS, has map[string]bool) []string {
	var out []string
	if prev != nil {
		out = l73CiscoUndo(family, *prev, has)
	}
	switch family {
	case "iosxe":
		return append(out, l73IOSXEApply(d, has)...)
	case "nxos":
		return append(out, l73NXOSApply(d, has)...)
	case "eos":
		return append(out, l73EOSApply(d)...)
	}
	return nil
}

// l73CiscoUndo takes d's servers away and puts the startup config's back.
func l73CiscoUndo(family string, d l73DeviceTLS, has map[string]bool) []string {
	switch family {
	case "iosxe":
		out := []string{"aaa group server tacacs+ " + l73Group, "no server name " + l73XEServer}
		if d.Second != "" {
			out = append(out, "no server name "+l73XESecond)
		}
		out = append(out, "server name "+l73XEStart, "exit", "no tacacs server "+l73XEServer)
		if d.Second != "" {
			out = append(out, "no tacacs server "+l73XESecond)
		}
		return out
	case "nxos", "eos":
		out := []string{"aaa group server tacacs+ " + l73Group, "no server " + d.Server}
		if d.Second != "" {
			out = append(out, "no server "+d.Second)
		}
		out = append(out, "exit", "no tacacs-server host "+d.Server)
		if d.Second != "" {
			out = append(out, "no tacacs-server host "+d.Second)
		}
		if family == "nxos" && has[l73HasNXOSSecure] {
			out = append(out, "no tacacs-server secure tls")
		}
		return append(out, "tacacs-server host "+l73Server+" key 0 "+labcreds.Key,
			"aaa group server tacacs+ "+l73Group, "server "+l73Server, "exit")
	}
	return nil
}

// l73CiscoRestoreAll is the cleanup's undo: every server L73 can configure.
// It is typed leniently (Task 7a), because the cell that failed may have
// applied only some of its lines.
func l73CiscoRestoreAll(family string, has map[string]bool) []string {
	return l73CiscoUndo(family, l73DeviceTLS{Server: l73Server, Second: l73SecondServer}, has)
}

func l73IOSXEServer(name, addr string, tls bool, port int, single, secret, serverTrust bool) []string {
	out := []string{"tacacs server " + name, "address ipv4 " + addr}
	switch {
	case tls:
		if port != 0 {
			out = append(out, "tls port "+strconv.Itoa(port))
		}
		out = append(out, "tls trustpoint client "+l73CertID)
		if serverTrust {
			out = append(out, "tls trustpoint server "+l73RootProfile)
		}
		out = append(out, "tls ip vrf forwarding "+l73XEVRF, "tls ip tacacs source-interface "+l73XESource)
	case port != 0:
		out = append(out, "port "+strconv.Itoa(port))
	}
	if single {
		out = append(out, "single-connection")
	}
	if secret {
		out = append(out, "key 0 "+labcreds.Key)
	}
	return append(out, "exit")
}

func l73IOSXEApply(d l73DeviceTLS, has map[string]bool) []string {
	out := l73IOSXEServer(l73XEServer, d.Server, true, d.Port, d.SingleConnection, d.Secret, has[l73HasTrustpointServer])
	if d.Second != "" {
		out = append(out, l73IOSXEServer(l73XESecond, d.Second, d.SecondTLS, d.SecondPort, false,
			d.Secret || !d.SecondTLS, has[l73HasTrustpointServer])...)
	}
	out = append(out, "aaa group server tacacs+ "+l73Group, "no server name "+l73XEStart, "server name "+l73XEServer)
	if d.Second != "" {
		out = append(out, "server name "+l73XESecond)
	}
	return append(out, "exit")
}

func l73NXOSHost(addr string, tls bool, port int, single, secret bool, has map[string]bool) []string {
	h := "tacacs-server host " + addr
	first := h
	if secret {
		first += " key 0 " + labcreds.Key
	}
	if port != 0 {
		first += " port " + strconv.Itoa(port)
	}
	if single {
		first += " single-connection"
	}
	out := []string{first}
	if tls {
		out = append(out, h+" tls client-trustpoint "+l73CertID)
		if has[l73HasNXOSServerTrust] {
			out = append(out, h+" tls server-trustpoint "+l73RootProfile)
		}
	}
	return out
}

// l73NXOSApply starts from the startup config: the plain host leaves the
// group and is removed before the TLS host takes its address.
func l73NXOSApply(d l73DeviceTLS, has map[string]bool) []string {
	out := []string{"aaa group server tacacs+ " + l73Group, "no server " + l73Server, "exit", "no tacacs-server host " + l73Server}
	if has[l73HasNXOSSecure] {
		out = append(out, "tacacs-server secure tls")
	}
	out = append(out, l73NXOSHost(d.Server, true, d.Port, d.SingleConnection, d.Secret, has)...)
	if d.Second != "" {
		out = append(out, l73NXOSHost(d.Second, d.SecondTLS, d.SecondPort, false, d.Secret || !d.SecondTLS, has)...)
	}
	out = append(out, "aaa group server tacacs+ "+l73Group, "server "+d.Server)
	if d.Second != "" {
		out = append(out, "server "+d.Second)
	}
	return append(out, "exit")
}

// l73EOSProfile is the SSL profile the EOS host line names.
const l73EOSProfile = "l73-tls"

func l73EOSHost(addr string, tls bool, port int, single, secret bool) string {
	line := "tacacs-server host " + addr
	if single {
		line += " single-connection"
	}
	if port != 0 {
		line += " port " + strconv.Itoa(port)
	}
	if tls {
		line += " ssl-profile " + l73EOSProfile
	}
	if secret {
		line += " key 0 " + labcreds.Key
	}
	return line
}

// l73EOSApply starts from the startup config, as l73NXOSApply does.
func l73EOSApply(d l73DeviceTLS) []string {
	out := []string{"aaa group server tacacs+ " + l73Group, "no server " + l73Server, "exit", "no tacacs-server host " + l73Server,
		l73EOSHost(d.Server, true, d.Port, d.SingleConnection, d.Secret)}
	if d.Second != "" {
		out = append(out, l73EOSHost(d.Second, d.SecondTLS, d.SecondPort, false, d.Secret || !d.SecondTLS))
	}
	out = append(out, "aaa group server tacacs+ "+l73Group, "server "+d.Server)
	if d.Second != "" {
		out = append(out, "server "+d.Second)
	}
	return append(out, "exit")
}

// l73EOSEnrol is EOS's enrolment: two exec commands that make the key on
// the device and print the request, the exec copies that move the scp'd
// public certificates from flash: into certificate:, and the SSL profile's
// configuration lines.
func l73EOSEnrol(node string) (keyGen, csr string, load, profile []string) {
	keyGen = "security pki key generate rsa 2048 " + l73CertID + ".key"
	csr = "security pki certificate generate signing-request key " + l73CertID + ".key parameters common-name " + node
	for _, f := range []string{"l73-root.crt", "l73-inter.crt", l73CertID + ".crt"} {
		load = append(load, "copy flash:"+f+" certificate:"+f)
	}
	profile = []string{"management security", "ssl profile " + l73EOSProfile,
		"certificate " + l73CertID + ".crt key " + l73CertID + ".key",
		"chain certificate l73-inter.crt", "trust certificate l73-root.crt", "exit", "exit"}
	return keyGen, csr, load, profile
}

// l73Step is one question a command may ask, and its answer. A reply may
// name {ROOT}, {INTER}, {LEAF} (PEM, ending in a newline), {NODE} and {ADDR}.
type l73Step struct{ Prompt, Reply string }

// l73Dialog is one configuration line and the questions it may ask, each
// answered at most once, in whatever order the device asks them. Done, when
// set, must appear before the configuration prompt returns, or the line did
// not do what it was typed for.
type l73Dialog struct {
	Cmd   string
	Steps []l73Step
	Done  string
}

func l73Lines(lines ...string) []l73Dialog {
	out := make([]l73Dialog, len(lines))
	for i, ln := range lines {
		out[i] = l73Dialog{Cmd: ln}
	}
	return out
}

// l73CiscoEnrol is the documents' terminal enrolment: a key pair made on
// the device, two trustpoints (the lab root, and the device's own, whose CA
// is the lab intermediate), a request read off the screen, the lab CA's
// answer pasted back. Only public certificates are typed.
func l73CiscoEnrol(family, node string) (prep []l73Dialog, enroll, load l73Dialog) {
	switch family {
	case "iosxe":
		paste := func(pem string) []l73Step {
			return []l73Step{{"on a line by itself", pem + "quit"}, {"accept this certificate", "yes"}}
		}
		prep = []l73Dialog{{Cmd: "crypto key generate ec keysize 256 label " + l73CiscoKey, Steps: []l73Step{{"replace them", "yes"}}}}
		prep = append(prep, l73Lines("crypto pki trustpoint "+l73RootProfile, "enrollment terminal", "revocation-check none", "exit",
			"crypto pki trustpoint "+l73CertID, "enrollment terminal pem", "subject-name CN="+node, "serial-number none",
			"ip-address none", "revocation-check none", "eckeypair "+l73CiscoKey, "chain-validation continue "+l73RootProfile,
			"exit")...)
		prep = append(prep,
			l73Dialog{Cmd: "crypto pki authenticate " + l73RootProfile, Steps: paste("{ROOT}"), Done: "successfully imported"},
			l73Dialog{Cmd: "crypto pki authenticate " + l73CertID, Steps: paste("{INTER}"), Done: "successfully imported"})
		enroll = l73Dialog{Cmd: "crypto pki enroll " + l73CertID, Steps: []l73Step{
			{"serial number in the subject name", "no"}, {"IP address in the subject name", "no"},
			{"Display Certificate Request to terminal", "yes"}, {"Redisplay enrollment request", "no"}},
			Done: "END CERTIFICATE REQUEST"}
		load = l73Dialog{Cmd: "crypto pki import " + l73CertID + " certificate",
			Steps: []l73Step{{"on a line by itself", "{LEAF}quit"}}, Done: "successfully imported"}
	case "nxos":
		prep = l73Lines("crypto key generate ecc label "+l73CiscoKey+" exportable modulus 256",
			"crypto ca trustpoint "+l73RootProfile, "revocation-check none", "exit",
			"crypto ca trustpoint "+l73CertID, "ecckeypair "+l73CiscoKey, "revocation-check none", "exit")
		prep = append(prep,
			l73Dialog{Cmd: "crypto ca authenticate " + l73RootProfile,
				Steps: []l73Step{{"END OF INPUT", "{ROOT}END OF INPUT"}, {"accept this certificate", "yes"}}},
			l73Dialog{Cmd: "crypto ca authenticate " + l73CertID,
				Steps: []l73Step{{"END OF INPUT", "{INTER}{ROOT}END OF INPUT"}, {"accept this certificate", "yes"}}})
		enroll = l73Dialog{Cmd: "crypto ca enroll " + l73CertID, Steps: []l73Step{
			{"Password:", ""}, {"serial number in the subject name", "no"}, {"IP address in the subject name", "yes"},
			{"ip address:", "{ADDR}"}, {"Alternate Subject Name ?", "yes"}, {"Enter Alternate Subject Name", "{NODE}"}},
			Done: "END CERTIFICATE REQUEST"}
		load = l73Dialog{Cmd: "crypto ca import " + l73CertID + " certificate",
			Steps: []l73Step{{"END OF INPUT", "{LEAF}END OF INPUT"}}}
	}
	return prep, enroll, load
}

// l73NextAnswer is what the device waits for in tail: the unanswered step
// whose prompt appears first (its index), or the configuration prompt (-1)
// when that appears before any of them. ok is false while neither has.
func l73NextAnswer(tail string, steps []l73Step, used []bool, prompt string) (step int, ok bool) {
	best, at := -1, strings.Index(tail, prompt)
	for n, s := range steps {
		if used[n] {
			continue
		}
		if i := strings.Index(tail, s.Prompt); i >= 0 && (at < 0 || i < at) {
			best, at = n, i
		}
	}
	return best, at >= 0
}

func l73Expand(reply string, vals map[string]string) string {
	for _, k := range []string{"ROOT", "INTER", "LEAF", "NODE", "ADDR"} {
		reply = strings.ReplaceAll(reply, "{"+k+"}", vals[k])
	}
	return reply
}

// l73RefusalMarks are how IOS XE's and NX-OS's parsers, and command
// authorization, refuse a line (iosxeConfigure and nxosConfigure check the
// same).
var l73RefusalMarks = []string{"% Invalid", "% Incomplete", "% Unrecognized", "% Ambiguous", "% Error",
	"authorization failed", "Invalid command", "ERROR:"}

// l73Refusal is the first line of out that refuses what was typed; "" when
// none does.
func l73Refusal(out string) string {
	for _, ln := range strings.Split(strings.ReplaceAll(out, "\r", ""), "\n") {
		for _, m := range l73RefusalMarks {
			if strings.Contains(ln, m) {
				return strings.TrimSpace(ln)
			}
		}
	}
	return ""
}
