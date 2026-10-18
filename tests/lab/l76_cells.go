package lab

import (
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
