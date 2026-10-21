package lab

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

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
	// HandshakeTimeout is the daemon's tls_listener.handshake_timeout on this
	// platform; 0 keeps the default.
	HandshakeTimeout time.Duration
	// LoginDial is the SSH dial deadline of a token login here; 0 is 45s.
	LoginDial time.Duration
	// RetryUnreached repeats a measured login whose capture holds no connection
	// to port49d, every 10s for at most 5 minutes, on the cell's own daemon:
	// IOS XE marks a server Dead after a reset or a decline and answers logins
	// locally, without a packet, until its dead time runs out.
	RetryUnreached bool
	// EarlyCapture starts cell h's capture before its configuration: the device
	// opens its single connection when the commit lands (XR), so a capture
	// started after it holds no SYN.
	EarlyCapture   bool
	InvalidCmds    []string // read into PORT49_L73_INVALID_DIR when the control login fails
	RefusalCmds    []string // read into the INVALID dir when configuring the TLS client is refused
	DiagOpAsks     []string // DiagAsks' operational-mode counterpart
	DiagAsks       []string // help asked at a value position by PORT49_L73_DIAG=help, which then ends INVALID
	DiagDeep       int      // levels below each DiagAsks answer asked too: every keyword the help lists, at most l73DiagWords of them
	DiagFilter     []string // DiagFilterAsks are followed only into the keywords that hold one of these
	DiagFilterAsks []string // DiagAsks' counterpart whose deeper levels DiagFilter narrows
	DiagSubIn      []string // lines that enter a submode whose help DiagSubAsks asks, after DiagAsks
	DiagSubAsks    []string // asks made inside that submode ("" is the submode's own help)
	DiagSubOut     []string // lines that leave it and undo what DiagSubIn made
}

var l73JunosDialect = l73Dialect{
	Family: "junos", Vendor: "Junos", Probe: "juniper_vjunos-router",
	Enter: []string{"configure"}, Cleanup: []string{"rollback 0", "exit configuration-mode"}, CfgMark: "# ",
	Asks: l73JunosAsks, VersionCmd: "show version | match Junos:", VersionHas: "26.2R1", Attrs: "[]",
	Enrol: "the documented offline enrolment (`request security pki generate-key-pair`, " +
		"`generate-certificate-request`, the lab CA's answer loaded back from a file), beside which this row's request and issued leaf are the root-shell path's: `openssl req` on the device, client.key and client.crt in its client folder",
	Fallback:    "`authentication-order [ tacplus password ]` (configs/vjunos-startup.conf)",
	Revocation:  "`revocation-check disable` on its CA profiles",
	LogCmd:      `show log messages | match "tacplus|TACPLUS|tls|TLS|certif|pki" | last 40`,
	RefusalCmds: []string{"show security pki ca-certificate", "show configuration security pki | display set"},
	DiagOpAsks:  []string{"request security pki ", "request system ", "show security pki ", "request security pki ca-certificate "},
	DiagAsks:    []string{"set security pki trusted-ca-group " + l73TrustGroup + " "},
	InvalidCmds: []string{`show log messages | match "tacplus|tls|ssl|pki" | last 60`,
		"show security pki local-certificate detail",
		"show configuration system tacplus-server | display set",
		"show configuration system accounting | display set"},
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
	Family: "iosxe", Vendor: "IOS XE", Probe: "cisco_iosxe", RetryUnreached: true,
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
	// A failed control login reads the device's own view: the TACACS+ configuration (keys masked
	// by the screen scrub), the server state, and the route configs/iosxe-startup.cfg says to check.
	InvalidCmds: []string{"show running-config | section tacacs", "show tacacs", "show aaa servers",
		"show ip route vrf clab-mgmt 172.100.100.1", "show logging | include TACACS|TLS|PKI|SSL|CRYPTO"},
}

var l73NXOSAsks = []l73Ask{
	{Ask: "tacacs-server host 192.0.2.71 ", Control: []string{"key", "port", "timeout"}, Need: []string{"tls", "port", "single-connection", "key"}},
	{Ask: "tacacs-server ", Control: []string{"host", "key", "timeout"}, Need: []string{"host"}, Want: []string{"secure"}},
	{Ask: "tacacs-server secure ", Control: []string{"tls"}, Need: []string{"tls"}, Only: l73HasNXOSSecure},
	{Ask: "tacacs-server host 192.0.2.71 tls ", Control: []string{"client-trustpoint", "server-trustpoint"},
		Need: []string{"client-trustpoint"}, Want: []string{"server-trustpoint"}},
	{Ask: "", Control: []string{"server"}, Need: []string{"server"}, In: []string{"aaa group server tacacs+ " + l73Group}, Out: []string{"exit"}},
	// The enrolment's key words, asked before they are typed. The image's
	// terminal enrolment refuses an ECC key (attempt 19), so the device key is RSA.
	{Ask: "crypto key generate rsa ", Control: []string{"label", "modulus", "exportable"}, Need: []string{"label", "modulus", "exportable"}},
	{Ask: "", Control: []string{"revocation-check", "rsakeypair"}, Need: []string{"rsakeypair"},
		In: []string{"crypto ca trustpoint " + l73CertID}, Out: []string{"exit"}},
}

// The scratch SSL profile the EOS asks enter, and how they leave it.
var (
	l73EOSProbeIn  = []string{"management security", "ssl profile l73x"}
	l73EOSProbeOut = []string{"exit", "no ssl profile l73x", "exit"}
)

// EOS 4.36.3M (Task 14 attempts 1 to 3, the image's own help): the host line
// takes a bare `tls`, after which only port, single-connection, timeout and
// vrf are offered (no key); the SSL profile is global, `tacacs-server tls
// ssl-profile <name>`. The profile is a submode, so its asks enter a scratch
// profile and leave by deleting it. The asks run before anything is typed:
// a word the image does not list makes the run INVALID.
var l73EOSDialect = l73Dialect{
	Family: "eos", Vendor: "EOS", Probe: "arista_ceos",
	Enter: []string{"configure"}, Cleanup: []string{"end"}, CfgMark: "(config",
	Asks: []l73Ask{{Ask: "tacacs-server host 192.0.2.71 ", Control: []string{"key", "port", "timeout"},
		Need: []string{"tls", "port", "single-connection", "key"}},
		{Ask: "tacacs-server host 192.0.2.71 tls ", Control: []string{"port", "timeout", "vrf"}, Need: []string{"port", "single-connection"}},
		{Ask: "tacacs-server ", Control: []string{"host", "key", "timeout"}, Need: []string{"host", "tls"}},
		{Ask: "tacacs-server tls ", Control: []string{"ssl-profile"}, Need: []string{"ssl-profile"}},
		{Ask: "certificate " + l73CertID + ".crt ", Control: []string{"key"}, Need: []string{"key"}, In: l73EOSProbeIn, Out: l73EOSProbeOut},
		{Ask: "chain certificate ", Control: []string{"WORD"}, Need: []string{"WORD"}, In: l73EOSProbeIn, Out: l73EOSProbeOut},
		{Ask: "trust certificate ", Control: []string{"WORD"}, Need: []string{"WORD"}, In: l73EOSProbeIn, Out: l73EOSProbeOut},
		{Ask: "", Control: []string{"server"}, Need: []string{"server"}, In: []string{"aaa group server tacacs+ " + l73Group}, Out: []string{"exit"}},
		// The group member names the host's port (Task 14 attempt 5: a member with no port is :49).
		{Ask: "server " + l73Server + " ", Control: []string{"<cr>", "port", "tls", "vrf"}, Need: []string{"port"}, Want: []string{"tls", "vrf"},
			In: []string{"aaa group server tacacs+ " + l73Group}, Out: []string{"exit"}},
		// The member's own tls flag (Task 14 attempt 6: a plain member under a TLS host never connects).
		{Ask: "server " + l73Server + " tls ", Control: []string{"<cr>", "port", "vrf"}, Need: []string{"port"}, Want: []string{"vrf"},
			In: []string{"aaa group server tacacs+ " + l73Group}, Out: []string{"exit"}}},
	VersionCmd: "show version | include Software image version", VersionHas: "4.36.3M",
	Enrol: "EOS's documented enrolment (`security pki key generate`, `security pki certificate generate signing-request`, " +
		"the request read off the screen, the lab CA's answer copied to `certificate:`; the SSL profile names the " +
		"intermediate as its `chain certificate`)",
	Fallback:   "`aaa authentication login default group port49 local` (configs/eos-startup.cfg)",
	Revocation: "no CRL in its SSL profile",
	LogCmd:     "show logging | include TACACS|TLS|SSL|AAA",
	// Read when the device never reaches port49 or the control login fails; keys are masked by the scrub.
	InvalidCmds:    []string{"show tacacs", "show running-config section tacacs", "show aaa"},
	DiagOpAsks:     []string{"show management security ssl profile ", "show management security ssl certificate ", "copy "},
	DiagFilterAsks: []string{"tacacs-server "},
	DiagFilter:     []string{"ssl", "profile", "tls"},
	DiagAsks:       []string{"tacacs-server host 192.0.2.71 tls "},
	DiagDeep:       2,
	DiagSubIn:      []string{"management security", "ssl profile l73x"},
	DiagSubAsks:    []string{"", "certificate ", "trust ", "trust certificate ", "tls ", "chain ", "peer "},
	DiagSubOut:     []string{"exit", "no ssl profile l73x", "exit"},
	ShowCmds: []string{"show running-config section tacacs", "show running-config section management security",
		"show management security ssl profile " + l73EOSProfile, "show tacacs"},
}

// l73XRDialect is XRd 26.1.1's, filled from the image's own help (Task 16): no
// line is typed that its help has not listed. What the help showed that the
// other families' did not: after `tacacs-server host A` the options come in
// the order port, key, single-connection, timeout, tls; `key` and
// `single-connection` end the line (only <cr> follows) and so does
// `tls trustpoint <name>`, so each is its own line for the same host; the
// trustpoint has `rsakeypair` and no EC key word, so the device key is RSA;
// the AAA group's member is one address, `server A`, with no port; `commit`
// ends every change. The ssh server asks are evidence only: XRd's sshd resets a
// session over its rate limit, and the harness never configures it.
var l73XRDialect = l73Dialect{
	Family: "xr", Vendor: "IOS XR (XRd)", Probe: "cisco_xrd", RetryUnreached: true, EarlyCapture: true,
	Enter: []string{"configure"}, Cleanup: []string{"abort"}, CfgMark: "(config",
	Asks: []l73Ask{
		{Ask: "tacacs-server host 192.0.2.71 ", Control: []string{"key", "port", "timeout"},
			Need: []string{"tls", "port", "single-connection", "key"}},
		{Ask: "tacacs-server host 192.0.2.71 tls ", Control: []string{"apply-group", "trustpoint"},
			Need: []string{"trustpoint"}, Want: []string{"server-name-indicator"}},
		{Ask: "tacacs-server host 192.0.2.71 tls trustpoint " + l73CertID + " ", Control: []string{"<cr>"}, Need: []string{"<cr>"}},
		{Ask: "no tacacs-server host 192.0.2.71 ", Control: []string{"key", "port", "tls"}, Need: []string{"port", "tls"}},
		{Ask: "aaa group server tacacs+ " + l73Group + " ", Control: []string{"server"}, Need: []string{"server"}},
		{Ask: "crypto ca trustpoint " + l73CertID + " ", Control: []string{"enrollment", "rsakeypair"},
			Need: []string{"enrollment", "rsakeypair", "subject-name", "crl", "serial-number", "ip-address"}},
		{Ask: "domain ", Control: []string{"name", "lookup"}, Need: []string{"name"}},
		{Ask: "do crypto key generate ", Control: []string{"rsa", "ecdsa"}, Need: []string{"rsa"}},
		{Ask: "do crypto ca import " + l73CertID + " ", Control: []string{"certificate"}, Need: []string{"certificate"}},
		{Ask: "ssh server ", Control: []string{"v2", "rate-limit"}, Evidence: true},
		{Ask: "ssh server rate-limit ", Control: []string{"<"}, Evidence: true}},
	VersionCmd: "show version | include Version", VersionHas: "26.1.1",
	Enrol: "XR's terminal enrolment (`crypto key generate rsa`, `crypto ca authenticate`, `crypto ca enroll`, the request " +
		"read off the screen, the lab CA's answer pasted at `crypto ca import ... certificate`; the trustpoint names the key by `rsakeypair`)",
	Fallback:   "`aaa authentication login default group port49 local` (configs/xrd-startup.cfg)",
	Revocation: "`crl optional` on both trustpoints",
	LogCmd:     "show logging | include TACACS",
	InvalidCmds: []string{"show running-config tacacs-server", "show tacacs details", "show tacacs server-groups",
		"show running-config aaa", "show logging | include TACACS"},
	ShowCmds: []string{"show running-config tacacs-server", "show running-config aaa", "show crypto ca certificates " + l73CertID,
		"show tacacs details"},
	// PORT49_L73_DIAG=help (the run ends INVALID): the enrolment's and the
	// apply lines' help, then the AAA group's own.
	DiagOpAsks: []string{"configure ", "crypto key generate rsa ", "crypto ca enroll " + l73CertID + " ", "show logging | ",
		"show running-config tacacs-server ", "show tacacs details | "},
	DiagAsks: []string{"commit ", "tacacs-server host 172.100.100.1 port 3049 tls trustpoint " + l73CertID + " ",
		"no tacacs-server host 172.100.100.1 port 3049 "},
	DiagSubIn:   []string{"crypto ca trustpoint " + l73CertID},
	DiagSubAsks: []string{"", "enrollment ", "crl "},
	DiagSubOut:  []string{"exit"},
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
		Enrol: "terminal enrolment as Cisco doc 224882 shows it, with an RSA-2048 key (`crypto key generate rsa label ... exportable modulus 2048`, `rsakeypair`, " +
			"`crypto ca enroll`, the request read off the screen, the lab CA's answer pasted at `crypto ca import`). RSA, not the ECC key doc 224882 makes: this " +
			"image's own refusal of the ECC key at `crypto ca enroll` was \"no rsa key-pair is associated with the trustpoint configuration\". The two key " +
			"commands are documented in Cisco's Nexus 3600 Switch NX-OS Security Configuration Guide, Release 10.6(x), \"Configuring PKI\" " +
			"(https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus3600/106x/configuration/security/cisco-nexus-3600-switch-nx-os-security-configuration-guide-106x/m_configuring_pki_9x.html; " +
			"the Nexus 9000 10.6(x) page was not found at the guessed address, so this is the nearest), and the run asks the image's own help for both before typing",
		Fallback:   "`aaa authentication login default group port49 local` (configs/nxos-startup.cfg)",
		Revocation: "`revocation-check none` on both trustpoints",
		LogCmd:     `show logging logfile | egrep "TACACS|tacacs|TLS|tls|PKI|pki" | last 40`,
		// A token login is five TACACS+ steps (redeem, authorize session, account,
		// authorize command, account), each on its own connection that this image
		// delays 5.00 s: about 25 s, so 45 s is too little margin.
		LoginDial: 90 * time.Second,
		InvalidCmds: []string{"show logging last 50", "show crypto ca certificates " + l73CertID, "show crypto key mypubkey rsa",
			"show running-config tacacs+"},
		ShowCmds: []string{"show running-config tacacs+", "show crypto ca trustpoints",
			"show crypto ca certificates " + l73CertID, "show tacacs-server"},
	},
	// IOL-XE 17.18.02 has no `tacacs server <name>` object (its config-mode help
	// lists `tacacs-server` and no `tacacs`), so its help is asked in the legacy
	// form, as XRd's is. The host ask comes first: it is L71's own verdict. The
	// `tls` level is asked only if that help listed `tls`; the keyword list's
	// words are a control, and whatever it lists is recorded.
	"cisco_iol-xe": {Family: "iosxe", Vendor: "IOS XE (IOL)", Probe: "cisco_iol-xe", HelpOnly: true,
		Enter: []string{"configure terminal"}, Cleanup: []string{"end"}, CfgMark: "(config", Asks: []l73Ask{
			{Ask: l73IOLHost, Control: []string{"key", "port", "timeout", "<cr>"}, Need: []string{"tls"}},
			{Ask: "tacacs-server ", Control: []string{"host", "key", "timeout", "<cr>"}, Evidence: true},
			{Ask: "", Control: []string{"aaa"}, Evidence: true, Keep: []string{"aaa", "tacacs"}},
			{Ask: l73IOLHost + "tls ", Control: []string{"port", "vrf", "single-connection", "timeout", "key"}, Need: []string{"port"},
				Only: l73Ask{Ask: l73IOLHost}.listed("tls")},
		}},
	"cisco_xrd": l73XRDialect,
}

// l73IOLHost is the IOL-XE host ask: the legacy `tacacs-server host`, with an
// address from the documentation range (nothing is configured by asking).
const l73IOLHost = "tacacs-server host 192.0.2.71 "

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
	case "xr":
		return append(out, l73XRApply(d)...)
	}
	return nil
}

// l73CiscoUndo takes d's servers away and puts the startup config's back.
func l73CiscoUndo(family string, d l73DeviceTLS, has map[string]bool) []string {
	switch family {
	case "xr":
		return l73XRUndo(d)
	case "iosxe":
		// The L73 objects go first: 17.18.02 keeps one server object per address,
		// so port49-host cannot take 172.100.100.1 back while l73-tls holds it.
		out := []string{"aaa group server tacacs+ " + l73Group, "no server name " + l73XEServer}
		if d.Second != "" {
			out = append(out, "no server name "+l73XESecond)
		}
		out = append(out, "exit", "no tacacs server "+l73XEServer)
		if d.Second != "" {
			out = append(out, "no tacacs server "+l73XESecond)
		}
		// configs/iosxe-startup.cfg's port49-host block, as it holds it.
		return append(out, "tacacs server "+l73XEStart, "address ipv4 "+l73Server, "key 0 "+labcreds.Key, "timeout 5", "exit",
			"aaa group server tacacs+ "+l73Group, "server name "+l73XEStart, "exit")
	case "nxos", "eos":
		out := []string{"aaa group server tacacs+ " + l73Group, l73NoMember(family, d.Server, d.MemberPort, true)}
		if d.Second != "" {
			out = append(out, l73NoMember(family, d.Second, d.SecondMemberPort, d.SecondTLS))
		}
		if family == "eos" {
			out = append(out, "exit")
			out = append(out, l73EOSNoHosts(d.Server, d.Second)...)
		} else {
			out = append(out, "exit", "no tacacs-server host "+d.Server)
			if d.Second != "" {
				out = append(out, "no tacacs-server host "+d.Second)
			}
		}
		if family == "nxos" && has[l73HasNXOSSecure] {
			out = append(out, "no tacacs-server secure tls")
		}
		if family == "eos" {
			out = append(out, "no tacacs-server tls ssl-profile")
		}
		return append(out, "tacacs-server host "+l73Server+" key 0 "+labcreds.Key,
			"aaa group server tacacs+ "+l73Group, "server "+l73Server, "exit")
	}
	return nil
}

// l73NoMember removes a group member; on EOS one typed with a port is named by it.
func l73NoMember(family, addr string, port int, tls bool) string {
	if family == "eos" && port != 0 {
		if tls {
			addr += " tls"
		}
		return "no server " + addr + " port " + strconv.Itoa(port)
	}
	return "no server " + addr
}

// l73CiscoRestoreAll is the cleanup's undo: every server L73 can configure.
// It is typed leniently (Task 7a), because the cell that failed may have
// applied only some of its lines.
func l73CiscoRestoreAll(family string, has map[string]bool) []string {
	return l73CiscoUndo(family, l73DeviceTLS{Server: l73Server, Second: l73SecondServer}, has)
}

func l73IOSXEServer(name, addr string, tls bool, port int, single, secret, serverTrust bool) []string {
	// The `do show` reads back what the image kept of the address line, before
	// the lines that fail when it dropped it.
	out := []string{"tacacs server " + name, "address ipv4 " + addr, "do show running-config | section tacacs"}
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
	// port49-host leaves the group and goes, object and all, before the TLS server
	// takes its address: 17.18.02 drops `address ipv4` on a second object that
	// would share one (attempt 3: the tls lines then print %Invalid IP version 0).
	out := []string{"aaa group server tacacs+ " + l73Group, "no server name " + l73XEStart, "exit", "no tacacs server " + l73XEStart}
	out = append(out, l73IOSXEServer(l73XEServer, d.Server, true, d.Port, d.SingleConnection, d.Secret, has[l73HasTrustpointServer])...)
	if d.Second != "" {
		out = append(out, l73IOSXEServer(l73XESecond, d.Second, d.SecondTLS, d.SecondPort, false,
			d.Secret || !d.SecondTLS, has[l73HasTrustpointServer])...)
	}
	out = append(out, "aaa group server tacacs+ "+l73Group, "server name "+l73XEServer)
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

// l73EOSHost is one host line. A TLS host takes `tls` right after the
// address and then only the options the image lists after it (no key, so a
// TLS host carries none); a plain host keeps the order the first help lists.
func l73EOSHost(addr string, tls bool, port int, single, secret bool) string {
	line := "tacacs-server host " + addr
	if tls {
		line += " tls"
	}
	if single {
		line += " single-connection"
	}
	if port != 0 {
		line += " port " + strconv.Itoa(port)
	}
	if secret && !tls {
		line += " key 0 " + labcreds.Key
	}
	return line
}

// l73EOSGlobalTLS is the global line that names the SSL profile.
const l73EOSGlobalTLS = "tacacs-server tls ssl-profile " + l73EOSProfile

// l73EOSNoHosts removes the hosts at the addresses, each as the TLS host it
// may be and as the plain host it may be: the negation of the typed form
// (`no tacacs-server host <addr> tls`), because a cell's TLS host left behind
// (172.100.100.2 after cell i) made cell j2 measure a stale entry.
func l73EOSNoHosts(addrs ...string) []string {
	var out []string
	for _, a := range addrs {
		if a != "" {
			out = append(out, "no tacacs-server host "+a+" tls", "no tacacs-server host "+a)
		}
	}
	return out
}

// l73EOSApply is the host lines: the startup config's member and host go,
// the global profile and d's hosts come. The group members come after,
// once the hosts' ports are known (l73EOSMembers).
func l73EOSApply(d l73DeviceTLS) []string {
	out := []string{"aaa group server tacacs+ " + l73Group, "no server " + l73Server, "exit"}
	out = append(out, l73EOSNoHosts(l73Server, l73SecondServer)...)
	out = append(out, l73EOSGlobalTLS, l73EOSHost(d.Server, true, d.Port, d.SingleConnection, d.Secret))
	if d.Second != "" {
		out = append(out, l73EOSHost(d.Second, d.SecondTLS, d.SecondPort, false, d.Secret || !d.SecondTLS))
	}
	return out
}

// l73EOSMember is one group member: `server <addr> [tls] port <P>`, the tls
// flag matching the host's, the order the image's help gives (port follows tls).
func l73EOSMember(addr string, tls bool, port int) string {
	line := "server " + addr
	if tls {
		line += " tls"
	}
	return line + " port " + strconv.Itoa(port)
}

// l73EOSMembers is the AAA group's members, each naming its host's port and
// transport: a bare member is port 49, plain TCP, and matches a TLS host on
// 300 to nothing.
func l73EOSMembers(d l73DeviceTLS, port, second int) []string {
	out := []string{"aaa group server tacacs+ " + l73Group, l73EOSMember(d.Server, true, port)}
	if d.Second != "" {
		out = append(out, l73EOSMember(d.Second, d.SecondTLS, second))
	}
	return append(out, "exit")
}

var l73ShowTacacsHost = regexp.MustCompile(`(?m)^TACACS\+ server\s*:\s*(\S+?)/(\d+)( TLS)?`)
var l73ShowTacacsMember = regexp.MustCompile(`(?m)^\s+\d+:\s*(\S+?)/(\d+)( TLS)?`)

// l73EOSHostPort is the port `show tacacs` lists for addr's host, 0 when it
// lists none.
func l73EOSHostPort(shown, addr string) int {
	for _, m := range l73ShowTacacsHost.FindAllStringSubmatch(strings.ReplaceAll(shown, "\r", ""), -1) {
		if m[1] == addr {
			n, _ := strconv.Atoi(m[2])
			return n
		}
	}
	return 0
}

// l73EOSMemberPorts resolves the ports the members are typed with: the
// configured port, else what `show tacacs` listed (never assumed).
func l73EOSMemberPorts(shown string, d l73DeviceTLS) (port, second int, err error) {
	pick := func(addr string, set int) (int, error) {
		if set != 0 {
			return set, nil
		}
		if p := l73EOSHostPort(shown, addr); p != 0 {
			return p, nil
		}
		return 0, fmt.Errorf("`show tacacs` lists no port for the host %s", addr)
	}
	if port, err = pick(d.Server, d.Port); err != nil || d.Second == "" {
		return port, 0, err
	}
	second, err = pick(d.Second, d.SecondPort)
	return port, second, err
}

// l73EOSGroupMissing is what `show tacacs` lacks of d's servers: each host
// listed on its port with its transport tag (TLS or none), and the
// server-group holding a member with the same port and the same tag.
func l73EOSGroupMissing(shown string, d l73DeviceTLS, port, second int) []string {
	shown = strings.ReplaceAll(shown, "\r", "")
	var missing []string
	members := map[string]bool{}
	if i := strings.Index(shown, "server-group: "+l73Group); i >= 0 {
		for _, m := range l73ShowTacacsMember.FindAllStringSubmatch(shown[i:], -1) {
			members[m[1]+"/"+m[2]+m[3]] = true
		}
	}
	type srv struct {
		addr string
		port int
		tls  bool
	}
	want := []srv{{d.Server, port, true}}
	if d.Second != "" {
		want = append(want, srv{d.Second, second, d.SecondTLS})
	}
	listed := map[string]bool{}
	for _, m := range l73ShowTacacsHost.FindAllStringSubmatch(shown, -1) {
		listed[m[1]] = true
	}
	for addr := range listed {
		if addr != d.Server && addr != d.Second {
			missing = append(missing, "no stale host "+addr+" (left from an earlier cell)")
		}
	}
	for _, w := range want {
		tag := ""
		if w.tls {
			tag = " TLS"
		}
		name := w.addr + "/" + strconv.Itoa(w.port) + tag
		hostOK := false
		for _, m := range l73ShowTacacsHost.FindAllStringSubmatch(shown, -1) {
			if m[1] == w.addr && m[2] == strconv.Itoa(w.port) && m[3] == tag {
				hostOK = true
			}
		}
		if !hostOK {
			missing = append(missing, "host "+name)
		}
		if !members[name] {
			missing = append(missing, "server-group "+l73Group+" member "+name)
		}
	}
	return missing
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
		prep = l73Lines("crypto key generate rsa label "+l73CiscoKey+" exportable modulus 2048",
			"crypto ca trustpoint "+l73RootProfile, "revocation-check none", "exit",
			"crypto ca trustpoint "+l73CertID, "rsakeypair "+l73CiscoKey, "revocation-check none", "exit")
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
			Steps: []l73Step{{"certificate in PEM format:", "{LEAF}"}}}
	case "xr":
		return l73XREnrol(node)
	}
	return prep, enroll, load
}

// l73XRHost is one RFC 9887 or plain server on XR. Every option past `port`
// ends the line it is on (the image's help offers only <cr> after `key`,
// `single-connection` and `tls trustpoint <name>`), so each is a line of its
// own for the same host, which the device merges.
func l73XRHost(addr string, tls bool, port int, single, secret bool) []string {
	h := "tacacs-server host " + addr
	if port != 0 {
		h += " port " + strconv.Itoa(port)
	}
	var out []string
	if tls {
		out = append(out, h+" tls trustpoint "+l73CertID)
	}
	if secret {
		out = append(out, h+" key 0 "+labcreds.Key)
	}
	if single {
		out = append(out, h+" single-connection")
	}
	return out
}

// l73XRNoHost removes a host: by address, and by address and port when the
// run gave it one (the help of `no tacacs-server host A` lists `port`).
func l73XRNoHost(addr string, port int) []string {
	out := []string{"no tacacs-server host " + addr}
	if port != 0 {
		out = append(out, "no tacacs-server host "+addr+" port "+strconv.Itoa(port))
	}
	return out
}

// l73XRApply replaces the startup config's plain server with the RFC 9887 one
// and puts it in the AAA group. The group's member goes in its own commit:
// XR refuses to delete a server "still referenced in one of the server groups
// and is the only server with the given IP address" when the same commit takes
// the member out and puts it back (Task 16 run 4, a TLS host on port 300 in
// place of the plain one on 49). The list ends in `commit`: XR applies nothing
// before it.
func l73XRApply(d l73DeviceTLS) []string {
	out := []string{"aaa group server tacacs+ " + l73Group, "no server " + l73Server, "exit", "commit"}
	out = append(out, l73XRNoHost(l73Server, 0)...)
	out = append(out, l73XRHost(d.Server, true, d.Port, d.SingleConnection, d.Secret)...)
	if d.Second != "" {
		out = append(out, l73XRHost(d.Second, d.SecondTLS, d.SecondPort, false, d.Secret || !d.SecondTLS)...)
	}
	out = append(out, "aaa group server tacacs+ "+l73Group, "server "+d.Server)
	if d.Second != "" {
		out = append(out, "server "+d.Second)
	}
	return append(out, "exit", "commit")
}

// l73XRUndo takes the run's servers away and types the startup config's own
// lines back (configs/xrd-startup.cfg), the members out in a commit of their
// own as in l73XRApply.
func l73XRUndo(d l73DeviceTLS) []string {
	out := []string{"aaa group server tacacs+ " + l73Group, "no server " + d.Server}
	if d.Second != "" {
		out = append(out, "no server "+d.Second)
	}
	out = append(out, "exit", "commit")
	out = append(out, l73XRNoHost(d.Server, d.Port)...)
	if d.Second != "" {
		out = append(out, l73XRNoHost(d.Second, d.SecondPort)...)
	}
	return append(out, "tacacs-server host "+l73Server+" key 0 "+labcreds.Key,
		"aaa group server tacacs+ "+l73Group, "server "+l73Server, "exit", "commit")
}

// l73XREnrol is XR's terminal enrolment: two trustpoints (the lab root, and
// the device's own, whose CA is the lab intermediate), an RSA key (the
// trustpoint's only key word is `rsakeypair`), a request read off the screen,
// the lab CA's answer pasted back. The exec commands are typed with `do`.
// Only public certificates are typed.
func l73XREnrol(node string) (prep []l73Dialog, enroll, load l73Dialog) {
	paste := func(pem string) []l73Step {
		return []l73Step{{"on a line by itself", pem + "quit"}, {"accept this certificate", "yes"}}
	}
	prep = l73Lines("crypto ca trustpoint "+l73RootProfile, "enrollment terminal", "crl optional", "exit",
		"crypto ca trustpoint "+l73CertID, "enrollment terminal", "rsakeypair "+l73CiscoKey, "subject-name CN="+node,
		"serial-number none", "ip-address none", "crl optional", "exit", "commit")
	prep = append(prep,
		l73Dialog{Cmd: "do crypto key generate rsa " + l73CiscoKey, Steps: []l73Step{{"replace them", "yes"}, {"modulus", ""}}},
		l73Dialog{Cmd: "do crypto ca authenticate " + l73RootProfile, Steps: paste("{ROOT}")},
		l73Dialog{Cmd: "do crypto ca authenticate " + l73CertID, Steps: paste("{INTER}")})
	enroll = l73Dialog{Cmd: "do crypto ca enroll " + l73CertID, Steps: []l73Step{{"Password:", ""}, {"Re-enter Password:", ""},
		{"Display Certificate Request to terminal", "yes"}, {"Redisplay enrollment request", "no"}},
		Done: "END CERTIFICATE REQUEST"}
	load = l73Dialog{Cmd: "do crypto ca import " + l73CertID + " certificate", Steps: []l73Step{{"on a line by itself", "{LEAF}quit"}}}
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
// IOS XE 17.18.02 prints some refusals with no space after the %
// ("%Invalid IP version 0 for the server address").
var l73RefusalMarks = []string{"% Invalid", "% Incomplete", "% Unrecognized", "% Ambiguous", "% Error",
	"%Invalid", "%Incomplete", "%Unrecognized", "%Ambiguous", "%Error",
	"authorization failed", "Invalid command", "ERROR:"}

// l73ExtraMarks are the refusals of one dialect alone. IOS XE 17.18.02 says
// "Warning: Address not yet configured." on leaving a server object whose
// `address ipv4` it silently dropped; a Warning is no refusal anywhere else.
func l73ExtraMarks(family string) []string {
	switch family {
	case "iosxe":
		return []string{"Warning: Address not yet configured"}
	case "xr":
		// A failed commit reverts the whole change and leaves the session in
		// configuration mode with it pending (Task 16 run 4).
		return []string{"Failed to commit"}
	}
	return nil
}

// The waits between sessions of the loops that log in to a device again: XRd's
// sshd resets a session past 60 a minute (L71-cisco_xrd.md), so no loop here
// goes faster than one a second.
const (
	l73ReadyEvery     = 10 * time.Second // ready(): break-glass logins until the device is seen connecting
	l73UnreachedEvery = 10 * time.Second // untilReached(): the measured login again while the capture holds no connection
)

// l73Retry runs attempt until it reaches a server, waiting `every` between
// attempts for at most max by now's clock. An unreached attempt that port49d
// recorded (stray records) is a leaked measurement, not a retry. max 0 is one
// attempt.
func l73Retry(attempt func(n int) (reached bool, stray int), sleep func(time.Duration), now func() time.Time,
	every, max time.Duration) (attempts int, err error) {
	start := now()
	for {
		attempts++
		reached, stray := attempt(attempts)
		switch {
		case reached:
			return attempts, nil
		case stray > 0:
			return attempts, fmt.Errorf("attempt %d reached no server yet port49d recorded %d record(s): the measurement leaked", attempts, stray)
		case now().Sub(start) >= max:
			return attempts, fmt.Errorf("the device opened no connection to %s in %d attempt(s) over %s", l73Server, attempts,
				now().Sub(start).Round(time.Second))
		}
		sleep(every)
	}
}

// l73DoShowScreens are the answers, in order, to each `do show running-config
// | section tacacs` in a configure screen: the lines after the echo, up to
// the next configuration prompt.
func l73DoShowScreens(screen string) []string {
	var out []string
	var cur []string
	in := false
	for _, ln := range strings.Split(strings.ReplaceAll(screen, "\r", ""), "\n") {
		if strings.Contains(ln, "(config") && strings.Contains(ln, ")#") {
			if in {
				out = append(out, strings.Join(cur, "\n"))
			}
			cur, in = nil, strings.Contains(ln, "#do show running-config | section tacacs")
			continue
		}
		if in {
			cur = append(cur, ln)
		}
	}
	if in {
		out = append(out, strings.Join(cur, "\n"))
	}
	return out
}

// l73IOSXERestored is whether show (`show running-config | section tacacs`)
// holds port49-host again with its address, as the startup config does.
func l73IOSXERestored(show string) bool {
	in := false
	for _, ln := range strings.Split(strings.ReplaceAll(show, "\r", ""), "\n") {
		switch {
		case strings.TrimSpace(ln) == "tacacs server "+l73XEStart && !strings.HasPrefix(ln, " "):
			in = true
		case !strings.HasPrefix(ln, " "):
			in = false
		case in && strings.TrimSpace(ln) == "address ipv4 "+l73Server:
			return true
		}
	}
	return false
}

// l73Refusal is the first line of out that refuses what was typed (by the
// common marks or by extra, a dialect's); "" when none does.
func l73Refusal(out string, extra ...string) string {
	for _, ln := range strings.Split(strings.ReplaceAll(out, "\r", ""), "\n") {
		for _, m := range append(extra[:len(extra):len(extra)], l73RefusalMarks...) {
			if strings.Contains(ln, m) {
				return strings.TrimSpace(ln)
			}
		}
	}
	return ""
}

// l73DiagWords bounds how many keywords one help answer is followed into.
const l73DiagWords = 8

var l73HelpKeyword = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

// l73HelpWords are the keywords a help answer lists: the first word of each
// line indented by two spaces, as EOS prints them. "<cr>", rules and
// repeats are left out, and only plain keyword characters are kept, so what
// is typed next is never something the device did not offer as a word.
func l73HelpWords(help string) []string { return l73HelpWordsHolding(help, nil) }

// l73HelpWordsHolding is l73HelpWords narrowed to the keywords holding one
// of subs (all of them when subs is empty).
func l73HelpWordsHolding(help string, subs []string) []string {
	var out []string
	for _, ln := range strings.Split(strings.ReplaceAll(help, "\r", ""), "\n") {
		if !strings.HasPrefix(ln, "  ") || strings.HasPrefix(ln, "   ") {
			continue
		}
		f := strings.Fields(ln)
		if len(f) == 0 || !l73HelpKeyword.MatchString(f[0]) || slices.Contains(out, f[0]) || !l73HoldsAny(f[0], subs) {
			continue
		}
		if out = append(out, f[0]); len(out) == l73DiagWords {
			break
		}
	}
	return out
}

func l73HoldsAny(w string, subs []string) bool {
	for _, s := range subs {
		if strings.Contains(w, s) {
			return true
		}
	}
	return len(subs) == 0
}

// l73EOSMissing is the typed lines of d's TACACS+ configuration that
// `show running-config section tacacs` does not show: the global
// ssl-profile line, and for each server a host line holding the words typed
// for it (the running config may order them differently). Key words are
// never compared and never named.
func l73EOSMissing(shown string, d l73DeviceTLS) []string {
	var missing []string
	have := map[string]bool{}
	var hosts [][]string
	for _, ln := range strings.Split(strings.ReplaceAll(shown, "\r", ""), "\n") {
		ln = strings.TrimSpace(ln)
		have[ln] = true
		if f := strings.Fields(ln); len(f) > 2 && f[0] == "tacacs-server" && f[1] == "host" {
			hosts = append(hosts, f)
		}
	}
	if !have[l73EOSGlobalTLS] {
		missing = append(missing, l73EOSGlobalTLS)
	}
	type host struct {
		addr string
		line string
	}
	var typed []host
	typed = append(typed, host{d.Server, l73EOSHost(d.Server, true, d.Port, d.SingleConnection, false)})
	if d.Second != "" {
		typed = append(typed, host{d.Second, l73EOSHost(d.Second, d.SecondTLS, d.SecondPort, false, false)})
	}
	for _, h := range typed {
		ok := false
		for _, f := range hosts {
			if f[2] == h.addr && l73HasWords(f, strings.Fields(h.line)[3:]) {
				ok = true
			}
		}
		if !ok {
			missing = append(missing, h.line)
		}
	}
	return missing
}

func l73HasWords(have, want []string) bool {
	for _, w := range want {
		if !slices.Contains(have, w) {
			return false
		}
	}
	return true
}

// l73VersionAuths counts the permitted authorize_command records whose command
// is `show version`: what a note cites to say the device sent command
// authorization over a TLS connection.
func l73VersionAuths(recs []map[string]any) int {
	n := 0
	for _, r := range recs {
		if r["event"] != "authorize_command" || r["verdict"] != "permit" {
			continue
		}
		req, _ := r["request"].(map[string]any)
		vec, _ := req["vector"].([]any)
		if len(vec) >= 2 && vec[0] == "show" && vec[1] == "version" {
			n++
		}
	}
	return n
}
