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
	// The run ends at whitespace, a quote or a closing bracket, so a quoted
	// value keeps its delimiters. bcrypt ($2a$ $2b$ $2y$), scrypt ($7$) and
	// argon2 are included.
	l76Hashed = regexp.MustCompile(`\$(?:aes1|ar2|y|argon2(?:id|i|d)|scrypt|2[aby]|[156789])\$[^\s"'}\]]*`)
	// l76Keyed is a secret-key, password or authentication-key statement and
	// its value, after a space, "=" or ":". The value is a quoted string
	// (spaces and escaped quotes allowed, never across a line), a quote that
	// never closes (taken to the end of the line), or a bare run that stops
	// at a quote, so a JSON string's closing quote survives.
	l76Keyed = regexp.MustCompile(`(\b(?:secret-key|password|authentication-key)(?:[ \t]*[=:][ \t]*|[ \t]+))("(?:[^"\\\n]|\\[^\n])*"|"[^\n]*|[^\s"]+)`)
	// l76QuotedValue is a quoted value that closes on its own line.
	l76QuotedValue = regexp.MustCompile(`^"(?:[^"\\\n]|\\[^\n])*"$`)
	// l76LineWrap is a device's line wrap inside one value: a line break with
	// the indentation around it. A space inside a line is not one.
	l76LineWrap = regexp.MustCompile(`\s*\n\s*`)
	// l76JSONKeyed is the same statements in JSON output: the key, then a
	// string value that may hold spaces and escaped quotes.
	l76JSONKeyed = regexp.MustCompile(`("(?:secret-key|password|authentication-key)"[ \t]*:[ \t]*")(?:[^"\\]|\\.)*(")`)
	// l76Long is the lab rule's sed mask: 24 or more base64-ish characters.
	l76Long = regexp.MustCompile(`[A-Za-z0-9_+/=.-]{24,}`)
	// l76Word is a long run the mask leaves alone: a lowercase keyword joined
	// by hyphens or underscores, such as nokia-srl-authorization-role-netconf
	// or aaa_accounting_event_type.
	l76Word = regexp.MustCompile(`^[a-z]+(?:[-_][a-z]+)*$`)
	// l76SSHKey is an OpenSSH public key with its comment. containerlab
	// writes the runner's own public keys into admin-user and linuxadmin-user
	// `ssh-key` (its srl template), and the comment is user@host or an email.
	// Certificate types (-cert-v01@openssh.com) carry the same comment.
	l76SSHKey = regexp.MustCompile(`(?:(?:sk-)?(?:ssh-(?:rsa|ed25519|dss)|ecdsa-sha2-nistp\d+)(?:-cert-v01@openssh\.com)?|sk-[a-z0-9-]+@openssh\.com)[ \t]+[A-Za-z0-9+/=]+[^"\]\n]*`)
	// l76DropLine is the lab rule's grep -v -i.
	l76DropLine = regexp.MustCompile(`(?i)password|token|secret|eyJ`)
)

// l76MaskConfig is device configuration made fit for a note: every SSH
// public key (with its user@host comment) and every hash masked, every
// secret-key and password value masked, the statements kept.
func l76MaskConfig(s string) string {
	s = l76SSHKey.ReplaceAllString(s, "<ssh public key masked>")
	s = l76Hashed.ReplaceAllString(s, "<masked>")
	s = l76JSONKeyed.ReplaceAllString(s, "${1}<masked>${2}")
	return l76MaskLong(l76MaskKeyed(s))
}

// l76MaskKeyed masks the value of every secret-key, password and
// authentication-key statement, keeping a quoted value's quotes.
func l76MaskKeyed(s string) string {
	return l76Keyed.ReplaceAllStringFunc(s, func(m string) string {
		sm := l76Keyed.FindStringSubmatch(m)
		switch sm[2] {
		case "{", "<masked>", `"<masked>"`:
			return m
		}
		if l76QuotedValue.MatchString(sm[2]) {
			return sm[1] + `"<masked>"`
		}
		return sm[1] + "<masked>"
	})
}

// l76IsKeyword is a hyphen- or underscore-joined run of lowercase words, each
// at most 16 letters and the whole at most 64 characters. A lowercase secret
// longer than that, or one without separators, is masked; a passphrase of
// short words is indistinguishable from a keyword, so l76Leaks covers the
// known ones by value.
func l76IsKeyword(m string) bool {
	if len(m) > 64 || !l76Word.MatchString(m) {
		return false
	}
	for _, w := range strings.FieldsFunc(m, func(r rune) bool { return r == '-' || r == '_' }) {
		if len(w) > 16 {
			return false
		}
	}
	return true
}

// l76MaskLong masks every long base64-ish run that is not a keyword.
func l76MaskLong(s string) string {
	return l76Long.ReplaceAllStringFunc(s, func(m string) string {
		if l76IsKeyword(m) {
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
	s = l76JSONKeyed.ReplaceAllString(l76Hashed.ReplaceAllString(s, "<masked>"), "${1}<masked>${2}")
	return l76MaskLong(l76MaskKeyed(s))
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
	folded := strings.ToLower(text)
	squeezed := l76Squeeze(folded)
	for i, s := range secrets {
		if s == "" {
			continue
		}
		// Exact, then folded to lower case (a device may upper-case a value)
		// with line wraps removed (a device may wrap a long one).
		q := l76Squeeze(strings.ToLower(s))
		if strings.Contains(text, s) || (q != "" && strings.Contains(squeezed, q)) {
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

// l76Squeeze removes each line break with the indentation around it, which
// rejoins a value the device wrapped. Spaces inside a line stay.
func l76Squeeze(s string) string {
	return l76LineWrap.ReplaceAllString(s, "")
}

// l76Session is one row of `show system aaa authentication session`
// (SA#display-user-session-information). Current is the row's trailing
// `*` on the user name.
type l76Session struct {
	ID, User, Service, Method, PrivLvl, TTY string
	Current                                 bool
}

// l76Sessions reads the rows of the session table whose first cell is a
// number. Header rows, borders and a wrapped login-time line are skipped.
func l76Sessions(out string) []l76Session {
	var rows []l76Session
	for _, ln := range strings.Split(out, "\n") {
		cells := strings.Split(strings.TrimSpace(ln), "|")
		if len(cells) < 8 {
			continue
		}
		c := make([]string, len(cells))
		for i := range cells {
			c[i] = strings.TrimSpace(cells[i])
		}
		id := c[1]
		if id == "" || strings.Trim(id, "0123456789") != "" {
			continue
		}
		user, cur := strings.CutSuffix(c[2], "*")
		rows = append(rows, l76Session{ID: id, User: user, Service: c[3], Method: c[4], PrivLvl: c[5], TTY: c[6], Current: cur})
	}
	return rows
}

// l76SessionHead opens one entry of YANG `list session` (srl_nokia-aaa.yang
// 487) as `info from state system aaa authentication session` prints it.
var l76SessionHead = regexp.MustCompile(`^\s*session\s+\S+\s*\{\s*$`)

// l76BraceDelta is a line's opening braces less its closing ones, outside
// double-quoted values: a brace in a quoted value is not block structure.
// A quote does not span lines.
func l76BraceDelta(ln string) int {
	d, inQuote := 0, false
	for i := 0; i < len(ln); i++ {
		switch c := ln[i]; {
		case inQuote && c == '\\':
			i++
		case c == '"':
			inQuote = !inQuote
		case inQuote:
		case c == '{':
			d++
		case c == '}':
			d--
		}
	}
	return d
}

// l76UserBlocks is the `session <id> { ... }` blocks of a session-state
// read whose `username` leaf is exactly user. A block that never closes is
// not read.
func l76UserBlocks(text, user string) []string {
	var blocks []string
	lines := strings.Split(text, "\n")
	for i := 0; i < len(lines); i++ {
		if !l76SessionHead.MatchString(lines[i]) {
			continue
		}
		depth, j := 0, i
		for ; j < len(lines); j++ {
			depth += l76BraceDelta(lines[j])
			if depth == 0 {
				break
			}
		}
		if j == len(lines) {
			break
		}
		block := lines[i : j+1]
		for _, ln := range block {
			if f := strings.Fields(ln); len(f) == 2 && f[0] == "username" && f[1] == user {
				blocks = append(blocks, strings.Join(block, "\n"))
				break
			}
		}
		i = j
	}
	return blocks
}

// l76UserSessions is l76UserBlocks joined, or "".
func l76UserSessions(text, user string) string {
	return strings.Join(l76UserBlocks(text, user), "\n")
}

// l76RolesIn is the lab's roles (p49-read, p49-admin) that user's sessions
// hold (YANG `leaf-list role`, srl_nokia-aaa.yang 550), sorted. Only whole
// tokens of the `role [ ... ]` leaf-list in the user's own blocks count:
// another user's session, a longer role name or another leaf never does
// (pre-flight I2).
func l76RolesIn(text, user string) []string {
	held := map[string]bool{}
	for _, b := range l76UserBlocks(text, user) {
		for _, r := range l76LeafList(b, "role") {
			held[r] = true
		}
	}
	var out []string
	for _, r := range []string{"p49-admin", "p49-read"} {
		if held[r] {
			out = append(out, r)
		}
	}
	return out
}

// l76RolesOf is what a note says of user's roles: the list, or that the
// state read held no session block for user.
func l76RolesOf(text, user string) string {
	if l76UserSessions(text, user) == "" {
		return "(no session block for `" + user + "` in the state read)"
	}
	return fmt.Sprintf("%v", l76RolesIn(text, user))
}

// The device reads (CM#configuration-datastores; the YANG rows of the cite
// table for the state paths). Each is run as the container's root with
// sr_cli -d, or in a token login.
const (
	l76ReadRunning      = "info from running system aaa"
	l76ReadGroup        = "info from state system aaa server-group port49"
	l76ReadSessions     = "show system aaa authentication session"
	l76ReadSessionState = "info from state system aaa authentication session"
	l76ReadVersion      = "info from state system information version"
)

// l76Commands are what every token login runs: the session table
// (SA#display-user-session-information), the session state with its roles,
// and the version.
var l76Commands = []string{l76ReadSessions, l76ReadSessionState, l76ReadVersion}

// The mid-run changes of cells (i) and (j), one flat `set /` line each
// (CLAB#cli's flat form). The live test uses only these constants.
const (
	l76PrivLvlAuthzOff = "set / system aaa server-group port49 tacacs priv-lvl-authorization false"
	l76PrivLvlAuthzOn  = "set / system aaa server-group port49 tacacs priv-lvl-authorization true"
	l76RoleServiceOn   = "set / system aaa server-group port49 tacacs service-request nokia-srl-authorization-role true"
	l76RoleServiceOff  = "set / system aaa server-group port49 tacacs service-request nokia-srl-authorization-role false"
)

var l76SetLines = []string{l76PrivLvlAuthzOff, l76PrivLvlAuthzOn, l76RoleServiceOn, l76RoleServiceOff}

// l76ModelRead is how the schema check reads a YANG model from the image: a
// container file read, not SR Linux CLI syntax.
const l76ModelRead = `cat "$(find /opt/srlinux/models -name <model> | head -1)"`

// l76RootForms are the sr_cli forms and file reads the harness runs as the
// container's root.
var l76RootForms = []string{
	"sr_cli -d <command>",
	"sr_cli --help",
	"sr_cli -d --candidate-mode --commit-at-end -- <line>",
	"enter candidate",
	"commit now",
	"tail -n 400 " + l76AAALog,
	l76ModelRead,
}

// The pages every SR Linux statement is checked against (the plan's cite
// table): Nokia's 26.7 guide chapters, and containerlab's srl kind page.
const (
	l76SAURL   = "https://documentation.nokia.com/srlinux/26-7/books/config-basics/secur-access.html"
	l76CMURL   = "https://documentation.nokia.com/srlinux/26-7/books/config-basics/configuration-management.html"
	l76CLABURL = "https://containerlab.dev/manual/kinds/srl/"
)

type l76Source struct{ what, cite string }

// l76Sources is one row per command, statement or default the run relies
// on, with its cite. A cite is one or more parts joined by "; ", each one
// SA#<anchor>, CM#<anchor>, CLAB#<anchor>, YANG <file>[:<line>] or HELP,
// with an optional note in parentheses that holds no "; ".
var l76Sources = []l76Source{
	{l76ReadSessions, "SA#display-user-session-information"},
	{l76ReadSessionState, "CM#configuration-datastores; YANG srl_nokia-aaa.yang:487 (list session); " +
		"YANG srl_nokia-aaa.yang:550 (leaf-list role)"},
	{l76ReadVersion, "CM#configuration-datastores; YANG srl_nokia-system-info.yang:108 (leaf version)"},
	{l76ReadRunning, "CM#configuration-datastores"},
	{l76ReadGroup, "CM#configuration-datastores; SA#configuring-aaa-server-group"},
	{l76PrivLvlAuthzOff, "CLAB#cli (flat form); SA#configuring-tacacsx-authorization"},
	{l76PrivLvlAuthzOn, "CLAB#cli (flat form); SA#configuring-tacacsx-authorization"},
	{l76RoleServiceOn, "CLAB#cli (flat form); SA#configuring-tacacs-authorization-with-vsas"},
	{l76RoleServiceOff, "CLAB#cli (flat form); SA#configuring-tacacs-authorization-with-vsas"},
	{"sr_cli -d <command>", "HELP (-d/--dumb-terminal, with a positional command run as one line)"},
	{"sr_cli --help", "HELP"},
	{l76ModelRead, "YANG srl_nokia-aaa.yang; YANG srl_nokia-aaa-types.yang (the image's own models)"},
	{"sr_cli -d --candidate-mode --commit-at-end -- <line>", "HELP (example: sr_cli --candidate-mode --commit-at-end -- <command>)"},
	{"enter candidate", "CM#configuration-modes"},
	{"commit now", "CM#commit-configuration-in-candidate-mode"},
	{"tail -n 400 " + l76AAALog, "SA#configuring-local-accounting"},
	{"authentication-method [ port49 local ]", "SA#configuring-authentication-local-users"},
	{"user breakglass { password ...; role [ p49-admin ] }", "SA#configuring-authentication-local-users; SA#assign-roles-to-users"},
	{"authorization { role <n> { tacacs { priv-lvl <n> } } }", "SA#configuring-tacacsx-authorization"},
	{"accounting { accounting-method [ port49 ]; event command { record start-stop } }",
		"SA#configuring-account; YANG srl_nokia-aaa-types.yang:77 (identity command, base aaa_accounting_event_type)"},
	{"server-group local { type local }", "SA#configuring-authentication-local-users; YANG srl_nokia-aaa.yang:134 (the name must be local)"},
	{"server-group port49 { type tacacs; tacacs { priv-lvl-authorization true } }",
		"SA#configuring-aaa-server-group; SA#configuring-tacacsx-authorization"},
	{"server 172.100.100.1 { network-instance mgmt; tacacs { port 49; secret-key ... } }",
		"SA#configuring-aaa-server-group; YANG srl_nokia-aaa-tacacs.yang (port, default 49)"},
	{"configuration { role <n> { rule / { action read|write } } }", "SA#configuring-role"},
	{"exit-on-reject: default false", "YANG srl_nokia-aaa.yang:1165"},
	{"priv-lvl-authorization false: authorization skipped, full admin", "YANG srl_nokia-aaa.yang:254"},
	{"the TACACS+ health check: a TCP open and close every 30 s", "SA#aaa-server-group-configuration"},
	{"ssh-server rate-limit: default 20 unauthenticated sessions", "YANG srl_nokia-ssh.yang:479"},
}

// l76CiteKnown says whether every part of cite is one of the cite kinds.
func l76CiteKnown(cite string) bool {
	if cite == "" {
		return false
	}
	for _, part := range strings.Split(cite, "; ") {
		if !(strings.HasPrefix(part, "SA#") || strings.HasPrefix(part, "CM#") || strings.HasPrefix(part, "CLAB#") ||
			strings.HasPrefix(part, "YANG ") || part == "HELP" || strings.HasPrefix(part, "HELP (")) {
			return false
		}
	}
	return true
}

// l76CiteURL is where one cite part is read: its page and anchor, the
// image's models, or the image's sr_cli --help.
func l76CiteURL(part string) string {
	anchor := func(p string) string {
		a, _, _ := strings.Cut(p, " ")
		return a
	}
	switch {
	case strings.HasPrefix(part, "SA#"):
		return l76SAURL + "#" + anchor(strings.TrimPrefix(part, "SA#"))
	case strings.HasPrefix(part, "CM#"):
		return l76CMURL + "#" + anchor(strings.TrimPrefix(part, "CM#"))
	case strings.HasPrefix(part, "CLAB#"):
		return l76CLABURL + "#" + anchor(strings.TrimPrefix(part, "CLAB#"))
	case strings.HasPrefix(part, "YANG "):
		return "/opt/srlinux/models in " + l76Image
	default:
		return "sr_cli --help in " + l76Image
	}
}

// l76SourcesSection is the note's Sources: one line per l76Sources row,
// each cite part followed by where it is read.
func l76SourcesSection() string {
	var b strings.Builder
	for _, s := range l76Sources {
		var parts []string
		for _, p := range strings.Split(s.cite, "; ") {
			parts = append(parts, p+" <"+l76CiteURL(p)+">")
		}
		fmt.Fprintf(&b, "- `%s`: %s\n", s.what, strings.Join(parts, "; "))
	}
	return strings.TrimRight(b.String(), "\n")
}

// l76IdentityBase is the base of YANG identity name, without its prefix.
func l76IdentityBase(yang, name string) string {
	re := regexp.MustCompile(`identity\s+` + regexp.QuoteMeta(name) + `\s*\{[^}]*?\bbase\s+(?:[\w-]+:)?([\w-]+)\s*;`)
	m := re.FindStringSubmatch(yang)
	if m == nil {
		return ""
	}
	return m[1]
}

// l76SchemaFindings is what the image's AAA models say where Nokia's guide
// says otherwise or nothing. aaa is srl_nokia-aaa.yang, types is
// srl_nokia-aaa-types.yang.
func l76SchemaFindings(aaa, types string) []string {
	var out []string
	if l76IdentityBase(types, "command") == "aaa_accounting_event_type" &&
		l76IdentityBase(types, "commands") == "aaa_authorization_event_type" {
		out = append(out, "The accounting event is `event command` (base aaa_accounting_event_type); "+
			"the guide's `event commands` is an authorization event type.")
	}
	if strings.Contains(aaa, l76LocalNameRule) {
		out = append(out, "A local server group must be named `local`; the guide's `LOCAL-GROUP` is refused.")
	}
	if strings.Contains(aaa, "grouping aaa-authorization-methods-config") &&
		!strings.Contains(aaa, "uses aaa-authorization-methods-config") &&
		!strings.Contains(aaa, "uses aaa-authorization-events-top") {
		out = append(out, "The SR Linux native schema has no TACACS+ authorization method: "+
			"`aaa-authorization-methods-config` and `aaa-authorization-events-top` are defined in "+
			"srl_nokia-aaa.yang and never used, so there is no per-command authorization "+
			"(OpenConfig's openconfig-aaa.yang does use them; OpenConfig mode is not measured).")
	}
	if strings.Contains(aaa, "authorization is skipped for TACACS+ users granting full admin access") {
		out = append(out, "`priv-lvl-authorization` false (the default) skips authorization and grants full admin.")
	}
	return out
}

// l76SchemaExcerpt is the lines of yang holding any key, trimmed and masked.
func l76SchemaExcerpt(yang string, keys []string) string {
	var keep []string
	for _, ln := range strings.Split(yang, "\n") {
		for _, k := range keys {
			if strings.Contains(ln, k) {
				keep = append(keep, strings.TrimSpace(ln))
				break
			}
		}
	}
	return l76MaskConfig(strings.Join(keep, "\n"))
}

// l76At walks a decoded decision record. The harness's str/sub/strs are
// lab-tagged; these are their untagged twins for code `make test` covers.
func l76At(m map[string]any, path ...string) any {
	var v any = m
	for _, k := range path {
		mm, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = mm[k]
	}
	return v
}

func l76Str(m map[string]any, path ...string) string {
	s, _ := l76At(m, path...).(string)
	return s
}

func l76Strs(m map[string]any, path ...string) []string {
	a, _ := l76At(m, path...).([]any)
	var out []string
	for _, v := range a {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// l76Of is the records whose session names user.
func l76Of(recs []map[string]any, user string) []map[string]any {
	var out []map[string]any
	for _, r := range recs {
		if l76Str(r, "session", "username") == user {
			out = append(out, r)
		}
	}
	return out
}

func l76Count(recs []map[string]any, event string) int {
	n := 0
	for _, r := range recs {
		if l76Str(r, "event") == event {
			n++
		}
	}
	return n
}

// l76Diagnoses counts the unvalidated records' diagnoses.
func l76Diagnoses(recs []map[string]any) map[string]int {
	out := map[string]int{}
	for _, r := range recs {
		if d := l76Str(r, "unvalidated", "diagnosis"); d != "" {
			out[d]++
		}
	}
	return out
}

// l76Services counts the authorization requests' service values.
func l76Services(recs []map[string]any) map[string]int {
	out := map[string]int{}
	for _, r := range recs {
		if e := l76Str(r, "event"); e == "authorize_session" || e == "authorize_command" {
			out[l76Str(r, "request", "service")]++
		}
	}
	return out
}

// l76Render is one line per record: what a note shows of the decision log.
// It holds no credential: records carry only credential_sha256, and this
// does not print it.
func l76Render(recs []map[string]any) string {
	var b strings.Builder
	for _, r := range recs {
		ev := l76Str(r, "event")
		switch {
		case ev == "account":
			fmt.Fprintf(&b, "account flags=%s user=%s record=%v\n", l76Str(r, "flags"),
				l76Str(r, "session", "username"), l76Strs(r, "record", "raw"))
		case l76At(r, "unvalidated") != nil:
			fmt.Fprintf(&b, "%s diagnosis=%s\n", ev, l76Str(r, "unvalidated", "diagnosis"))
		case ev == "authorize_session" || ev == "authorize_command":
			fmt.Fprintf(&b, "%s %s/%s user=%s service=%s request=%v reply=%v\n", ev, l76Str(r, "verdict"),
				l76Str(r, "reason"), l76Str(r, "session", "username"), l76Str(r, "request", "service"),
				l76Strs(r, "request", "raw"), l76Strs(r, "reply", "attributes"))
		default:
			fmt.Fprintf(&b, "%s %s/%s method=%s user=%s\n", ev, l76Str(r, "verdict"), l76Str(r, "reason"),
				l76Str(r, "auth", "method"), l76Str(r, "session", "username"))
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

// l76WrongKeyConfig is cfg with its one standing key block pointed at
// l76WrongKeyEnv: port49d then validates no packet the device sends.
func l76WrongKeyConfig(cfg string) (string, error) {
	if n := strings.Count(cfg, l76KeyAnchor); n != 1 {
		return "", fmt.Errorf("the lab config holds the standing lab_key block %d times, want once", n)
	}
	return strings.Replace(cfg, l76KeyAnchor,
		"  lab_key:\n    current: {version: 1, secret_env: "+l76WrongKeyEnv+"}\n", 1), nil
}

// l76Observation is the note's Observation: the schema check, then each
// cell under its claim, in register order, then extra (the live test's
// retries line and Evidence pointer), then the Sources every command
// and statement cites (pre-flight I3). extra must start with "\n" and end
// with a newline, as the cells' text does.
func l76Observation(out map[string]string, schema, extra string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "### Schema and configuration\n\n%s\n", schema)
	for _, c := range l76Cells {
		fmt.Fprintf(&b, "\n### (%s) %s\n\n%s\n", c.id, c.claim, out[c.id])
	}
	b.WriteString(extra)
	fmt.Fprintf(&b, "\n### Sources\n\n%s\n", l76SourcesSection())
	return b.String()
}

// l76SafeInvalid is an INVALID message as it may be printed: msg itself when
// l76Leaks finds nothing in it, else a fixed message that names what leaked
// by index or shape, never by value.
func l76SafeInvalid(msg string, secrets []string) string {
	if leaks := l76Leaks(msg, secrets); len(leaks) > 0 {
		return fmt.Sprintf("(message withheld: it held %s)", strings.Join(leaks, ", "))
	}
	return msg
}

// l76InvalidText is an INVALID message as it is printed: the long and keyed
// values masked, then the l76SafeInvalid gate. It does not run l76FilterLog:
// that drops every line naming a password or token, which would blank the
// message's own wording ("logged in with a wrong password"). Every caller
// filters or masks the device text it passes in.
func l76InvalidText(msg string, secrets []string) string {
	return l76SafeInvalid(l76MaskLong(l76MaskKeyed(msg)), secrets)
}

// l76ReturnsFromInvalid says whether invalid logs and returns instead of
// ending the run: only a deferred restore (restoring) after the run has
// already failed. Anything else must stop the run.
func l76ReturnsFromInvalid(restoring, failed bool) bool {
	return restoring && failed
}

// l76RunSection is the note's "Run" section, which l76Observation puts
// between the cells and the Sources: the dials retried after a failure before
// authentication, and the Evidence pointer. dir is the evidence directory's
// name under tests/lab/evidence/.
func l76RunSection(retries []string, dir string) string {
	list := " none"
	if len(retries) > 0 {
		list = "\n\n- " + strings.Join(retries, "\n- ")
	}
	return "\n### Run\n\nDials retried after a failure before authentication (one retry each, 5 s later):" + list +
		"\n\nEvidence: `tests/lab/evidence/" + dir + "/` (device outputs, masked config, AAA log " +
		"lines, the redacted decision log).\n"
}
