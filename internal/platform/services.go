package platform

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// rpcServicesOff is whether a projected Junos device must run no management
// service but the CLI's (plan 5b Task 14, branch M). It is true: on both
// images a wire deny-commands did not bind a native NETCONF RPC, and the
// fail-closed reply refused the session before hello
// (tests/lab/results/L12-netconf-juniper_*.md), so a
// service that runs RPCs under the same TACACS+ login and reply would walk
// around every deny port49 sends: `<get-configuration>` past `deny show
// configuration **`.
//
// Whether it is sufficient is unmeasured (L26c, open). With `netconf ssh`
// still configured, a projected CLI session opened NETCONF itself by typing
// `xml-mode netconf need-trailer` and ran a native RPC its deny did not name,
// within its bits (`view` without view-configuration got an empty
// `<configuration>`); `op url` was accepted; the fail-closed reply's
// `deny-commands .*` refused both (tests/lab/results/L26c-juniper_*.md).
// Whether a wire deny binds an RPC reached that way is unmeasured, so port49
// assumes a native RPC may reach whatever the bits reach (option C) and the
// projection fails closed on any composition whose safety beneath a
// permitted bit rests on a deny (internal/projection, FailRefusedShape naming
// RPC reach); this check closes only the services around the CLI. The
// NETCONF subsystem on port 22 was refused with `netconf ssh` deleted (L26c).
//
// Under a set whose adapter carries rpc_entry_denies (set 1.2.0) the reply's
// `junoscript` deny closes NETCONF, port 830 and the CLI's `xml-mode` for the
// session that carries it (tests/lab/results/L26c-junoscript-juniper_*.md),
// so the check there passes NETCONF and is a shorter allowlist: the services
// entryServices names, and the rpcPastEntryDeny words failing wherever they
// appear (decision 44 ruling 6).
var rpcServicesOff = true

// RPCServicesChecked reports whether `port49 devices check-config` reads a
// device of d's management services (CheckServices): against cliServices
// under a set that sends no entry deny, against entryServices and
// rpcPastEntryDeny under one that does.
func RPCServicesChecked(d Dialect) bool {
	return rpcServicesOff && d.CommandProjection == ProjectionJunosRegex
}

// cliServices are the only services under `system services` a checked
// device may enable, the CLI's own transports, each with the only statements
// it may carry under it. Anything else under `system services`, a name this
// list does not know included, fails (plan 5b pre-flight C1: an allowlist,
// not a denylist). Whether a CLI session over one reaches RPCs regardless is
// rpcServicesOff's lab question. Only the word after the service is read:
// display set prints one statement a line, so any word after it is that
// statement's value.
var cliServices = map[string][]string{"ssh": sshOptions, "telnet": telnetOptions}

// sshOptions are the only statements under `system services ssh` a checked
// device may carry: the transport's own options — its algorithms, limits,
// port, login and forwarding refusals — none of which opens a channel but
// the CLI's. `sftp-server` opens a file-access subsystem no measured deny
// binds, `tcp-forwarding` a channel to any port, and a statement this list
// does not know, `authorized-keys-command` included, fails (plan 5b Task
// 13a ruling). scp rides the CLI's ssh and cannot be switched off apart
// from it; whether a deny binds it is a Task 19 lab row.
var sshOptions = []string{"ciphers", "client-alive-count-max", "client-alive-interval", "connection-limit",
	"fingerprint-hash", "hostkey-algorithm", "key-exchange", "log-key-changes", "macs",
	"max-pre-authentication-packets", "max-sessions-per-connection", "no-challenge-response", "no-passwords",
	"no-public-keys", "no-tcp-forwarding", "port", "protocol-version", "rate-limit", "rekey", "root-login"}

// telnetOptions are the only statements under `system services telnet` a
// checked device may carry: its limits and authentication order.
var telnetOptions = []string{"authentication-order", "connection-limit", "rate-limit"}

// rpcAnywhere are service names that run RPCs wherever in the hierarchy they
// appear: the REST API, J-Web, and JET/gRPC/gNMI.
var rpcAnywhere = []string{"rest", "web-management", "extension-service"}

// ConfigCapture is the one form check-config reads a projected Junos device's
// configuration in: set form, each configuration group's statements expanded
// under the levels they land on. Either pipe order expands the same, and
// neither prints a `set groups` or a `set apply-groups` line
// (tests/lab/results/L57-juniper_*.md), so a capture holding one was taken
// without `display inheritance` and is refused (groupSign; decision 44 ruling
// 7). The earlier `| except "^set groups "` tail removed nothing from it.
const ConfigCapture = `show configuration | display set | display inheritance`

// notInheritedWhy is why a capture with a group line is refused, after the
// line's number. It quotes nothing of the line.
const notInheritedWhy = "applies or defines a configuration group, which a capture taken with `display " +
	"inheritance` never prints: this capture was taken without it, so what a group adds where it lands was not " +
	"expanded and cannot be checked. If it was taken with it, the device keeps a group application switched off " +
	"or locked, which reads the same: remove that application, then capture again (a one-word value spelled " +
	"apply-groups, which display set prints bare, is read the same way: rename it)"

// groupSign reports whether a statement shows its capture was taken without
// `display inheritance`: a `set groups` line, a logical system's or tenant's
// included, or `apply-groups` as a keyword anywhere in it, at the top, under
// `system` or on a class. The inherited capture printed neither on either
// image (L57); that it strips a class-level `apply-groups` as it strips the
// top-level ones is *provisional on L57*. `apply-groups-except` survives
// inheritance and is no sign. A line statementWords cannot split is read on
// whitespace with its quotes taken off, so a stray quote hides no group.
func groupSign(line string) bool {
	words, ok := statementWords(line)
	if !ok {
		words = nil
		for _, f := range strings.Fields(line) {
			words = append(words, word{text: strings.Trim(f, `"`)})
		}
	}
	if len(words) < 2 {
		return false
	}
	if slices.ContainsFunc(words[1:], func(w word) bool { return w.keyword("apply-groups") }) {
		return true
	}
	path := words[1:]
	for len(path) > 2 && (path[0].keyword("logical-systems") || path[0].keyword("tenants")) {
		path = path[2:]
	}
	return words[0].keyword("set") && path[0].keyword("groups")
}

// NetconfForbidden reports whether check-config fails a device of d for
// serving NETCONF: a checked device whose set sends no entry deny (set
// 1.1.0). Under set 1.2.0 the reply's `junoscript` deny closes NETCONF for
// the subject it is sent to, and the device keeps it for the rest (decision
// 44 rulings 1 and 6).
func NetconfForbidden(d Dialect) bool { return RPCServicesChecked(d) && len(d.RPCEntryDenies) == 0 }

// rpcPastEntryDeny are the services that run RPCs and that no lab cell
// measured set 1.2.0's entry deny closing, each a finding wherever its word
// appears: REST (the lab's tunnel reached it in no cell, the control's
// included, so G2 kept it; tests/lab/results/L26c-scripts-juniper_*.md),
// J-Web and JET/gRPC/gNMI (no cell measures them), the XML API and
// outbound-ssh (decision 44 ruling 6, *provisional on L26c*).
var rpcPastEntryDeny = []string{"rest", "web-management", "extension-service", "xnm-ssh", "xnm-ssl",
	"xnm-clear-text", "outbound-ssh"}

// entryServices are the only services under `system services` a checked
// device may enable under a set whose adapter carries rpc_entry_denies (set
// 1.2.0), each with any statement beneath it. It is an allowlist, as
// cliServices is under set 1.1.0: a service no one listed fails, an RPC
// service no one thought of included (decision 44 ruling 6; plan 9b1
// controller ruling 6, on `service-deployment`, which speaks the JUNOScript
// XML API and passed a denylist). `netconf` is closed per subject by the
// reply's `junoscript` deny (tests/lab/results/L26c-junoscript-juniper_*.md),
// and `ssh` and `telnet` are the CLI's own transports; the lab's devices run
// `netconf ssh` and `ssh root-login allow` and nothing else there
// (tests/lab/configs/vjunos-startup.conf; testdata/l57-*.set). The rest are
// statements of Junos's `[edit system services]` hierarchy (Juniper's CLI
// reference, "services (System Services)",
// https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/system-services.html,
// read 2026-10-12) that serve no management session: database-replication
// copies the configuration database between Routing Engines; dhcp and
// dhcp-local-server serve addresses; dns is a DNS proxy and dynamic-dns a
// client updating one; finger answers who is logged in; ftp serves files
// to a user who logs in; static-subscribers, subscriber-management and
// subscriber-management-helper run broadband subscriber sessions. Whether a
// `show configuration` deny holds against a file read of /config through
// ftp, or ssh's sftp-server, is unmeasured (L26c, open). The hierarchy's
// others stay off it: tftp-server serves files with no login, and
// service-deployment, outbound-https, grpc-tunnel, webapi, flow-tap-dtcp,
// jeb, http, netproxy, reverse, resource-monitor, bbe-stats-service and
// extensible-subscriber-services either run a management session or were
// not read closely enough to say they do not.
var entryServices = []string{"netconf", "ssh", "telnet", "database-replication", "dhcp", "dhcp-local-server", "dns",
	"dynamic-dns", "finger", "ftp", "static-subscribers", "subscriber-management", "subscriber-management-helper"}

const unlistedSays = "a service under `system services` that set 1.2.0's check does not list: only `netconf`, `ssh`, " +
	"`telnet` and the services it names as serving no management session may be on, so a service no one listed " +
	"fails rather than passes (decision 44 ruling 6). Disable it, or, if it serves no management session, report " +
	"it to port49 to be listed with its source"

const entrySays = "a management service that runs RPCs is enabled, and no lab cell measured the reply's " +
	"`junoscript` deny closing it (decision 44 ruling 6; tests/lab/results/L26c-scripts-juniper_*.md): a session " +
	"may reach RPCs through it past every deny port49 sends. Disable it, or pin a set that does not project Junos"

// CheckServices reads a device's configuration, as ConfigCapture prints it,
// where RPCServicesChecked(d), a statement under a logical system or tenant
// included. Under a set whose d sends no entry deny (set 1.1.0) every
// statement that enables a management service but the CLI's is a finding,
// since a deny does not bind the RPCs it serves. Under one that does (set
// 1.2.0) the `junoscript` deny closes NETCONF for the session that carries
// it, so a statement under `system services` is a finding where its service
// is not on entryServices, and the services no lab cell measured the deny
// closing are findings wherever their word appears (rpcPastEntryDeny;
// decision 44 ruling 6). It
// is an error where the input is not in that form, since then a service could
// be missed: a line that is not a set, deactivate or protect statement, a
// terminal's prompt or a ## line; a `set groups` line, or `apply-groups` as a
// word at any level, which the inherited capture never prints, so a group's
// services were not expanded where they land (groupSign; decision 44 ruling
// 7); a line it cannot split into words; or a capture without the top-level
// `set version` line a whole display set prints, since a capture of a subtree
// leaves every service outside it unread. An error names the line by number
// and quotes nothing from it. A capture cut off before its end cannot be told
// from a whole one in set form, since display set closes with no last line. A
// deactivate or protect enables nothing, and a service under one is still a
// finding, since an activate turns it on. Where d is not checked it reads
// nothing.
func CheckServices(d Dialect, config []byte) ([]ConfigFinding, error) {
	if !RPCServicesChecked(d) {
		return nil, nil
	}
	var findings []ConfigFinding
	var formErr error
	version := false
	refuse := func(n int, why string) {
		formErr = fmt.Errorf("line %d %s: capture the configuration with `%s`", n, why, ConfigCapture)
	}
	err := eachLine(config, func(n int, line string) {
		if formErr != nil {
			return
		}
		if !plainLine(line) {
			refuse(n, "holds a character no set statement carries: a line or word separator other than a space "+
				"or tab, a control or invisible formatting character, or invalid UTF-8")
			return
		}
		trimmed := strings.Trim(line, " \t")
		if trimmed == "" || strings.HasPrefix(trimmed, "##") || prompt.MatchString(trimmed) {
			return
		}
		words, ok := statementWords(trimmed)
		if !ok {
			refuse(n, "is not a statement the check can split into words: an unclosed quote, or a quote that "+
				"opens or closes inside a word")
			return
		}
		switch {
		case words[0].value || words[0].text != "set" && words[0].text != "deactivate" && words[0].text != "protect":
			refuse(n, "is not a set, deactivate or protect statement")
			return
		case groupSign(trimmed):
			refuse(n, notInheritedWhy)
			return
		case words[0].text != "set":
			return // an inactive or protected statement enables nothing
		}
		if len(words) == 3 && words[1].keyword("version") && !words[2].value {
			version = true
		}
		path := words[1:]
		for len(path) > 2 && (path[0].keyword("logical-systems") || path[0].keyword("tenants")) {
			path = path[2:]
		}
		entry := !NetconfForbidden(d)
		offList := false
		if len(path) >= 3 && path[0].keyword("system") && path[1].keyword("services") {
			if entry {
				offList = path[2].value || !slices.Contains(entryServices, path[2].text)
			} else {
				options, ok := cliServices[path[2].text]
				offList = path[2].value || !ok || len(path) >= 4 && (path[3].value || !slices.Contains(options, path[3].text))
			}
		}
		anywhere, says := rpcAnywhere, servicesSays
		if entry {
			anywhere, says = rpcPastEntryDeny, entrySays
		}
		rpcWord := slices.ContainsFunc(words, func(w word) bool { return slices.ContainsFunc(anywhere, w.keyword) })
		if entry && offList && !rpcWord {
			says = unlistedSays
		}
		if offList || rpcWord {
			findings = append(findings, ConfigFinding{Line: n, Text: joinWords(trimmed), Says: says})
		}
	})
	if err != nil {
		return nil, err
	}
	if formErr != nil {
		return nil, formErr
	}
	if !version {
		return nil, errors.New("the configuration has no top-level set version line, which a whole display set " +
			"prints: a capture of part of it leaves every service outside that part unread: capture it with `" +
			ConfigCapture + "`")
	}
	return findings, nil
}

// word is one word of a set statement: its text, unquoted, and whether it is
// a value — a quoted string that holds whitespace or nothing, such as a
// description — which is never a keyword.
type word struct {
	text  string
	value bool
}

// keyword reports whether w is the keyword k, in any case: Junos prints a
// keyword bare and lower-case, and a hand-edited capture that quotes or
// capitalizes one still names it.
func (w word) keyword(k string) bool { return !w.value && strings.EqualFold(w.text, k) }

// plainLine reports whether line holds only what a line of display set
// does: valid UTF-8 whose only whitespace and control characters are spaces
// and tabs, and no invisible formatting character. A vertical tab, a form
// feed, NEL or a Unicode line or paragraph separator would end one statement
// and start another within one line eachLine reads, and a zero-width
// character would hide a keyword inside a word (task 13a review I2).
func plainLine(line string) bool {
	if !utf8.ValidString(line) {
		return false
	}
	for _, r := range line {
		if r != ' ' && r != '\t' && (unicode.IsSpace(r) || unicode.IsControl(r) || unicode.In(r, unicode.Cf,
			unicode.Zl, unicode.Zp)) {
			return false
		}
	}
	return true
}

// separator reports whether r separates the words of a plainLine.
func separator(r rune) bool { return r == ' ' || r == '\t' }

// statementWords splits a plainLine into words, a quoted string, its
// \-escapes read, one word. It reports false where the line cannot be split
// with certainty — an unclosed quote, or a quote that opens or closes inside
// a word — since a keyword could then hide in a word the check misreads.
func statementWords(line string) ([]word, bool) {
	var words []word
	for i := 0; i < len(line); {
		r, size := utf8.DecodeRuneInString(line[i:])
		switch {
		case separator(r):
			i += size
		case r == '"':
			var b strings.Builder
			j := i + 1
			for ; j < len(line) && line[j] != '"'; j++ {
				if line[j] == '\\' {
					j++
					if j == len(line) {
						return nil, false
					}
				}
				b.WriteByte(line[j])
			}
			if j == len(line) {
				return nil, false
			}
			j++
			if next, _ := utf8.DecodeRuneInString(line[j:]); j < len(line) && !separator(next) {
				return nil, false
			}
			text := b.String()
			words = append(words, word{text: text, value: text == "" || strings.IndexFunc(text, separator) >= 0})
			i = j
		default:
			j := i
			for j < len(line) {
				r, size := utf8.DecodeRuneInString(line[j:])
				if separator(r) {
					break
				}
				if r == '"' {
					return nil, false
				}
				j += size
			}
			words = append(words, word{text: line[i:j]})
			i = j
		}
	}
	return words, len(words) > 0
}

// joinWords is line with each run of whitespace read as one space, as a
// finding quotes it.
func joinWords(line string) string { return strings.Join(strings.Fields(line), " ") }

const servicesSays = "a management service other than the CLI's is enabled, and a port49 deny does not bind the RPCs " +
	"it serves (tests/lab/results/L12-netconf-juniper_*.md): a session walks around every deny port49 sends. On a " +
	"projected Junos device only `system services ssh` and `telnet` may be on: disable this one, or pin a set that " +
	"does not project Junos"
