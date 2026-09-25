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
// service but the CLI's: true only where tests/lab/results/L12-netconf-juniper_*.md
// found a wire deny-commands, or the fail-closed reply, not binding a NETCONF
// RPC on either image (plan 5b Task 14, branch M). A service that runs RPCs
// under the same TACACS+ login and reply would then walk around every deny
// port49 sends: `<get-configuration>` past `deny show configuration **`.
var rpcServicesOff = false

// RPCServicesChecked reports whether `port49 devices check-config` holds a
// device of d to the management-service allowlist (CheckServices).
func RPCServicesChecked(d Dialect) bool {
	return rpcServicesOff && d.CommandProjection == ProjectionJunosRegex
}

// cliServices are the only services under `system services` a checked
// device may enable: the CLI's own transports. `ssh` serves NETCONF only
// through `system services netconf ssh`, which is not on the list. Anything
// else under `system services`, a name this list does not know included,
// fails (plan 5b pre-flight C1: an allowlist, not a denylist).
var cliServices = []string{"ssh", "telnet"}

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

// rpcAnywhere are service names that run RPCs wherever in the hierarchy they
// appear: the REST API, J-Web, and JET/gRPC/gNMI.
var rpcAnywhere = []string{"rest", "web-management", "extension-service"}

// ServicesCapture is the one form CheckServices reads: set form, groups'
// statements expanded where they apply, and the group definitions left out,
// so no statement is hidden behind a group the check cannot resolve.
const ServicesCapture = `show configuration | display set | display inheritance | except "^set groups "`

// CheckServices reads a device's configuration, as ServicesCapture prints
// it, where RPCServicesChecked(d): every statement that enables a management
// service but the CLI's is a finding, one under a logical system or tenant
// included. It is an error where the input is not in that form — a line
// that is not a set, deactivate or protect statement, a terminal's prompt or
// a ## line, a `set groups` or apply-groups statement whose group the check
// cannot resolve, or a line it cannot split into words — since then a
// service could be missed; the error names the line by number and quotes
// nothing from it. A deactivate or protect enables nothing, and a service
// under one is still a finding, since an activate turns it on. Where d is
// not checked it reads nothing.
func CheckServices(d Dialect, config []byte) ([]ConfigFinding, error) {
	if !RPCServicesChecked(d) {
		return nil, nil
	}
	var findings []ConfigFinding
	var formErr error
	statements := 0
	refuse := func(n int, why string) {
		formErr = fmt.Errorf("line %d %s: capture the configuration with `%s`", n, why, ServicesCapture)
	}
	err := eachLine(config, func(n int, line string) {
		if formErr != nil {
			return
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "##") || prompt.MatchString(trimmed) {
			return
		}
		words, ok := statementWords(trimmed)
		if !ok {
			refuse(n, "is not a statement the check can split into words: an unclosed quote, or a character "+
				"no set statement carries")
			return
		}
		switch {
		case words[0].value || words[0].text != "set" && words[0].text != "deactivate" && words[0].text != "protect":
			refuse(n, "is not a set, deactivate or protect statement")
			return
		case words[0].text != "set":
			return // an inactive or protected statement enables nothing
		}
		statements++
		path := words[1:]
		for len(path) > 2 && !path[0].value && (path[0].text == "logical-systems" || path[0].text == "tenants") {
			path = path[2:]
		}
		if len(path) > 0 && path[0].keyword("groups") {
			refuse(n, "holds a group definition, whose statements the check cannot resolve")
			return
		}
		if slices.ContainsFunc(words, func(w word) bool { return w.keyword("apply-groups") }) {
			refuse(n, "applies a group, and the check cannot tell whether that group's statements were "+
				"expanded where it applies")
			return
		}
		underServices := len(path) >= 3 && path[0].keyword("system") && path[1].keyword("services")
		underSSH := underServices && len(path) >= 4 && path[2].keyword("ssh")
		if underServices && (path[2].value || !slices.Contains(cliServices, path[2].text)) ||
			underSSH && (path[3].value || !slices.Contains(sshOptions, path[3].text)) ||
			slices.ContainsFunc(words, func(w word) bool {
				return slices.ContainsFunc(rpcAnywhere, w.keyword)
			}) {
			findings = append(findings, ConfigFinding{Line: n, Text: joinWords(trimmed), Says: servicesSays})
		}
	})
	if err != nil {
		return nil, err
	}
	if formErr != nil {
		return nil, formErr
	}
	if statements == 0 {
		return nil, errors.New("the configuration holds no set statement: capture it with `" + ServicesCapture + "`")
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

// statementWords splits a line of set form into words, a quoted string, its
// \-escapes read, one word. It reports false where the line cannot be split
// with certainty — invalid UTF-8, a control or invisible formatting
// character, an unclosed quote, or a quote that opens or closes inside a
// word — since a keyword could then hide in a word the check misreads.
func statementWords(line string) ([]word, bool) {
	if !utf8.ValidString(line) {
		return nil, false
	}
	for _, r := range line {
		if !unicode.IsSpace(r) && (unicode.IsControl(r) || unicode.Is(unicode.Cf, r)) {
			return nil, false
		}
	}
	var words []word
	for i := 0; i < len(line); {
		r, size := utf8.DecodeRuneInString(line[i:])
		switch {
		case unicode.IsSpace(r):
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
			if next, _ := utf8.DecodeRuneInString(line[j:]); j < len(line) && !unicode.IsSpace(next) {
				return nil, false
			}
			text := b.String()
			words = append(words, word{text: text, value: text == "" || strings.IndexFunc(text, unicode.IsSpace) >= 0})
			i = j
		default:
			j := i
			for j < len(line) {
				r, size := utf8.DecodeRuneInString(line[j:])
				if unicode.IsSpace(r) {
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
