package lab

import (
	"fmt"
	"regexp"
	"strings"
)

// L76 measures Nokia SR Linux against port49 over plain TACACS+ (spec §15).
// The node is opt-in (optInPlatforms): only PORT49_LAB_PLATFORMS=srlinux
// deploys it.
const (
	l76Sel          = "srlinux"
	l76PlatformName = "nokia_srlinux"
	l76Node         = "srl1"
	l76Addr         = "172.100.100.71"
	l76Image        = "ghcr.io/nokia/srlinux:26.7.2-519"
	l76Version      = "SR Linux 26.7.2-519"
	l76Topo         = "topologies/srlinux.clab.yml"
	l76Config       = "configs/srlinux-startup.cli"
	// l76Container is containerlab's name for the node: clab-<topology>-<node>.
	l76Container = "clab-port49-srlinux-srl1"
	// l76AAALog is the AAA manager's log (SA#configuring-local-accounting).
	l76AAALog = "/var/log/srlinux/debug/sr_aaa_mgr.log"
	// l76WrongKeyEnv holds cell (e)'s random wrong key, for port49d only.
	l76WrongKeyEnv = "PORT49_L76_WRONG_KEY"
	// l76KeyAnchor is port49d-lab.yaml's standing key block (l28Anchor's text;
	// l28's is lab-tagged, so it is repeated here and tested against the file).
	l76KeyAnchor = "  lab_key:\n    current: {version: 1, secret_env: PORT49_LAB_KEY}\n"
	// l76LocalNameRule is srl_nokia-aaa.yang's must on server-group name.
	l76LocalNameRule = "Server group name must be 'local' if and only if local server type is 'local'"
	// l76AdminDefault is SR Linux's documented default admin password
	// (SA#configuring-authentication-local-users; CLAB#credentials). It is
	// public, and it is in the leak gate only so no transcript carries it.
	l76AdminDefault = "NokiaSrl1!"
)

type l76Cell struct{ id, claim string }

// l76Cells are spec §15 L76's cells, word for word (TestL76CellsAreTheRegistersCells).
var l76Cells = []l76Cell{
	{"a", "a user that exists only in port49 logs in over SSH; the session table names it, the port49 group and the priv-lvl; the authentication type on the wire"},
	{"b", "the authorization requests the login sends with priv-lvl-authorization true: services and attributes; whether any per-command request follows; what the device does with priv-lvl=15 and the optional shell:roles"},
	{"c", "the accounting records a CLI command sends: start and stop, their attributes; whether a session start or stop is sent"},
	{"d", "a wrong password: port49's refusal, the time to the device's refusal, and whether a port49 deny falls through to local"},
	{"e", "a wrong shared secret: port49's no_known_key_matches, and whether the break-glass account still logs in through local, and how fast"},
	{"f", "port49 stopped: the break-glass login through local and its time; a port49 user refused; whether a CLI command still runs with accounting unreachable, and its time"},
	{"g", "port49 restarted: the time until the device asks port49 again; the empty connections a quiet minute holds (health checks) and whether port49 logs them"},
	{"h", "priv-lvl=1 in the reply: the roles the session gets (p49-read only) and the session table's priv-lvl"},
	{"i", "priv-lvl-authorization false (the default): whether any authorization request is sent, and the roles the session gets"},
	{"j", "service-request nokia-srl-authorization-role true: the services the device asks for, port49's answers, and whether the login survives them"},
}

// l76Claim is the note's Claim: the row's lead and every cell.
func l76Claim() string {
	parts := make([]string, len(l76Cells))
	for i, c := range l76Cells {
		parts[i] = "(" + c.id + ") " + c.claim
	}
	return "Nokia SR Linux against port49 over TACACS+ on port 49, server group `port49` then `local`, " +
		"accounting to `port49`: " + strings.Join(parts, "; ") + "."
}

// l76LeafList reads `name [ a b ]` or the same over several lines, as
// `info` prints it.
func l76LeafList(text, name string) []string {
	re := regexp.MustCompile(`(?:^|[\s{])` + regexp.QuoteMeta(name) + `\s+\[([^\]]*)\]`)
	m := re.FindStringSubmatch(text)
	if m == nil {
		return nil
	}
	return strings.Fields(m[1])
}

var (
	// l76Hashed is a crypt-style hash or SR Linux's reversible key form
	// ($aes1$ for secret-key; $y$, $ar2$, $6$ for passwords).
	l76Hashed = regexp.MustCompile(`\$(?:aes1|ar2|y|[15689])\$\S*`)
	// l76Keyed is a secret-key or password statement and its value.
	l76Keyed = regexp.MustCompile(`(\b(?:secret-key|password)[ \t]+)(\S+)`)
	// l76Long is the lab rule's sed mask: 24 or more base64-ish characters.
	l76Long = regexp.MustCompile(`[A-Za-z0-9_+/=.-]{24,}`)
	// l76Word is a long run the mask leaves alone: a lowercase keyword joined
	// by hyphens or underscores, such as nokia-srl-authorization-role-netconf
	// or aaa_accounting_event_type.
	l76Word = regexp.MustCompile(`^[a-z]+(?:[-_][a-z]+)*$`)
	// l76SSHKey is an OpenSSH public key with its comment. containerlab
	// writes the runner's own public keys into admin-user and linuxadmin-user
	// `ssh-key` (its srl template), and the comment is user@host or an email.
	l76SSHKey = regexp.MustCompile(`(?:ssh-(?:rsa|ed25519|dss)|ecdsa-sha2-nistp\d+|sk-[a-z0-9-]+@openssh\.com)[ \t]+[A-Za-z0-9+/=]+[^"\]\n]*`)
	// l76DropLine is the lab rule's grep -v -i.
	l76DropLine = regexp.MustCompile(`(?i)password|token|secret|eyJ`)
)

// l76MaskConfig is device configuration made fit for a note: every SSH
// public key (with its user@host comment) and every hash masked, every
// secret-key and password value masked, the statements kept.
func l76MaskConfig(s string) string {
	s = l76SSHKey.ReplaceAllString(s, "<ssh public key masked>")
	s = l76Hashed.ReplaceAllString(s, "<masked>")
	s = l76Keyed.ReplaceAllStringFunc(s, func(m string) string {
		sm := l76Keyed.FindStringSubmatch(m)
		if sm[2] == "{" || sm[2] == "<masked>" {
			return m
		}
		return sm[1] + "<masked>"
	})
	return l76MaskLong(s)
}

// l76MaskLong masks every long base64-ish run that is not a keyword.
func l76MaskLong(s string) string {
	return l76Long.ReplaceAllStringFunc(s, func(m string) string {
		if l76Word.MatchString(m) {
			return m
		}
		return "<LONG>"
	})
}

// l76FilterLog is the lab rule's shell filter as code, for any device text
// that is not configuration: lines naming a password, token, secret or JWT
// are dropped, then hashes and long runs are masked.
func l76FilterLog(s string) string {
	var keep []string
	for _, ln := range strings.Split(s, "\n") {
		if !l76DropLine.MatchString(ln) {
			keep = append(keep, ln)
		}
	}
	s = l76SSHKey.ReplaceAllString(strings.Join(keep, "\n"), "<ssh public key masked>")
	return l76MaskLong(l76Hashed.ReplaceAllString(s, "<masked>"))
}

// l76Grep keeps the lines of text that contain any key, ignoring case.
func l76Grep(text string, keys []string) string {
	var keep []string
	for _, ln := range strings.Split(strings.TrimRight(text, "\n"), "\n") {
		low := strings.ToLower(ln)
		for _, k := range keys {
			if strings.Contains(low, strings.ToLower(k)) {
				keep = append(keep, ln)
				break
			}
		}
	}
	return strings.Join(keep, "\n")
}

// l76Leaks names what text must not hold: any of secrets (by index, never by
// value), any hash, any JWT.
func l76Leaks(text string, secrets []string) []string {
	var out []string
	for i, s := range secrets {
		if s != "" && strings.Contains(text, s) {
			out = append(out, fmt.Sprintf("secret #%d", i))
		}
	}
	if l76Hashed.MatchString(text) {
		out = append(out, "a hash")
	}
	if strings.Contains(text, "eyJ") {
		out = append(out, "a JWT")
	}
	if l76SSHKey.MatchString(text) {
		out = append(out, "an SSH public key")
	}
	return out
}
