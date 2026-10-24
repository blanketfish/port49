package lab

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"

	"github.com/rhwendt/port49/tests/lab/labcreds"
)

// Device debug capture for EOS, IOS XR, Junos, IOS XE and NX-OS (post-11b fix
// PR, task 8; spec §13 decision 50 ruling 20). Debug output can carry the
// request, the reply and the credential, so nothing from the device is kept as
// it is. deviceDebugFilter.Keep scrubs the text in-process, before anything
// reaches disk, in this order:
//
//  1. Keep by facility. A line is kept only if it carries the platform's
//     TACACS/AAA facility (ddProfile.facility). Everything else is dropped.
//  2. Drop payload and hex-dump lines. A line that says payload, or has a hex
//     layout (ddHexView: a run of eight or more hex digits, or four or more
//     groups of one, two or four hex digits in a row, separated by blanks or
//     colons, a clock aside; ddHexMessage: a message of nothing but hex groups;
//     nxosDebugHexRun), is dropped whole: it is the packet body. A line whose
//     separator-stripped copy holds the hex of a known secret is dropped too,
//     because a spaced form cannot be redacted in place.
//  3. Mask every run of 24 or more token characters as <LONG> (and again after
//     step 5, so a redaction cannot split a run and unmask the rest).
//  4. Redact the run's known secrets: the TACACS+ key, the lab passwords, the
//     tokens and TOTP codes the run handled. Every value is replaced by
//     <redacted> in its literal, hex, base64 (standard and URL, padded and not,
//     at the three alignments) and Cisco type 7 forms (all 16 salts), matched
//     without regard to case, longest first.
//  5. Redact reversible encodings and crypt hashes by shape: Junos $9$, crypt
//     $1$ $5$ $6$ $8$, and `key|key-string|password|secret` followed by a type
//     7 value or a 0, 6, 8 or 9 encoding, quoted or not. The shape is judged
//     without knowing the secret, so an encoding of a secret nobody told us
//     about is still redacted.
//  6. Fail closed. The kept text is checked once more for every secret in every
//     form, and every line for the hex of one with its separators stripped. If
//     any survives, the whole capture is discarded: Keep returns
//     errDeviceDebugLeak, which names no device text, and the cell is graded
//     unmeasured.
//
// Limits, stated: a fragment of a secret of under 24 characters can survive a
// line wrap or an overlap of two secrets (the redaction matches whole values);
// the capture sets a wide terminal where the CLI has one. The facilities are
// coarse words (Junos `tacplus` also appears in an echoed `set ... tacplus-server`
// command, IOS XE `TAC` anywhere in a line), which is safe only while the harness
// types nothing but known secrets.
//
// Nothing the device prints is decoded: type 7 and $9$ values are redacted, never
// read. Only our own known secrets are encoded, to know what to look for. The
// collector (captureDeviceDebug) filters in-process, so the raw output never
// reaches disk.

var (
	errUnknownDebugPlatform = errors.New("device debug: unknown platform")
	// errDeviceDebugLeak is the fail-closed error. It names no device text.
	errDeviceDebugLeak = errors.New("device debug: a known secret survived the scrub; the whole capture was discarded and the cell is unmeasured")
)

// deviceDebugFilter is the capture filter for one platform ("eos", "iosxr",
// "junos", "iosxe", "nxos") in one lab. Secrets, if set, is called at each
// Keep for the values the run has handled so far (tokens and codes are minted
// during a cell).
type deviceDebugFilter struct {
	Platform string
	Secrets  func() []string
	// Drops, if set, counts the lines Keep drops, by reason. Numbers only.
	Drops *ddDropCounts
	// Tags, if set, counts the syslog process tag of each line Keep reads before
	// the facility rule (ddTagCounts). Numbers only.
	Tags *ddTagCounts
}

// ddDropCounts is how many lines Keep dropped, by the rule that dropped them.
type ddDropCounts struct {
	Facility, Payload, HexView, HexMessage, Marker, StrippedSecret int
}

// String is the counts as `name=n` words, for the summary and the note.
func (d ddDropCounts) String() string {
	return fmt.Sprintf("facility=%d body_word=%d hex_view=%d hex_message=%d evidence_marker=%d known_value_hex=%d",
		d.Facility, d.Payload, d.HexView, d.HexMessage, d.Marker, d.StrippedSecret)
}

// ddProfile is one platform's facility and counters. The counters read kept
// lines, which are whole scrubbed lines, so they are coarse and unanchored.
type ddProfile struct {
	// facility selects the lines to keep: those it matches.
	facility *regexp.Regexp
	// What the counters read in a kept line.
	open, authen, author, acct, single, dead, fallback *regexp.Regexp
	// closed matches a close; its one group, if it has one, is the reason the
	// device states.
	closed *regexp.Regexp
	// failed matches a failed open (cEOS prints connFails after connOpens);
	// request matches a request of unknown kind (cEOS messagesSent), counted
	// apart from the three kinds. Both may be nil.
	failed, request *regexp.Regexp
	// noClose is a platform whose debug has no close line (Junos): its summary
	// says the close is unknown instead of counting none.
	noClose bool
	// authenAlt, authorAlt and acctAlt count a request kind only when no line of
	// the text matches the kind's primary regexp (see deviceDebugSummarize).
	authenAlt, authorAlt, acctAlt *regexp.Regexp
}

// ddNever matches nothing.
var ddNever = regexp.MustCompile(`\z\A`)

// ddSep is the punctuation between two words of a device's debug line.
const ddSep = `[\W_]+`

var deviceDebugProfiles = map[string]*ddProfile{
	"iosxe": {
		facility: regexp.MustCompile(`(?i)\b(?:TPLUS|TAC)\b`),
		open:     regexp.MustCompile(`(?i)\bopening tcp/ip to\b|tacacs secure connection established with peer`),
		closed:   regexp.MustCompile(`(?i)closing tcp/ip \S+ connection to \S+(?: \((idle timeout|remote reset|timeout|error|closed by server)\))?|tacacs secure connection closed with peer`),
		// A request is counted once: from the `send KIND/` lines when the text has
		// any of that kind, else from the processing or request-created lines. A
		// device that prints both for one request would otherwise count it twice.
		authen:    regexp.MustCompile(`(?i)send AUTHEN/`),
		author:    regexp.MustCompile(`(?i)send AUTHOR/`),
		acct:      regexp.MustCompile(`(?i)send ACCT/`),
		authenAlt: regexp.MustCompile(`(?i)TPLUS` + ddSep + `processing authentication\b`),
		authorAlt: regexp.MustCompile(`(?i)TPLUS` + ddSep + `authorization request created`),
		acctAlt:   regexp.MustCompile(`(?i)TPLUS` + ddSep + `accounting request created`),
		single:    regexp.MustCompile(`(?i)using single connection`),
		dead:      regexp.MustCompile(`(?i)server \S+ (?:marked|is) dead`),
		fallback:  regexp.MustCompile(`(?i)method=(?:local|none)`),
	},
	"eos": {
		facility: regexp.MustCompile(`\b(?:Aaa|Tacacs|TacPlus)\b`),
		// TacacsLib prints counter lines: connOpens is a connection (a refused one
		// too, followed by connFails), messagesSent a request, connCloses a close.
		open:    regexp.MustCompile(`(?i)\b(?:connecting|connected) to\b|created socket|\bcounter connOpens\b`),
		closed:  regexp.MustCompile(`(?i)connection to \S+ (closed(?: by peer| by server| idle timeout)?|reset|timed out)|\btacacs\b\W+close\b|\bcounter connCloses\b`),
		failed:  regexp.MustCompile(`(?i)\bcounter connFails\b`),
		request: regexp.MustCompile(`(?i)\bcounter messagesSent\b`),
		// The tac_send_* result lines (returned, failed) are never requests: a
		// failed one never went out, and one printed after connCloses would open a
		// connection that is not there. messagesSent is the request.
		authen:   regexp.MustCompile(`(?i)sending authentication request`),
		author:   regexp.MustCompile(`(?i)sending authorization request`),
		acct:     regexp.MustCompile(`(?i)sending accounting request`),
		single:   regexp.MustCompile(`(?i)single connect(?:ion)? (?:flag set|negotiated)`),
		dead:     regexp.MustCompile(`(?i)marked dead|is not responding`),
		fallback: regexp.MustCompile(`(?i)falling back to`),
	},
	"iosxr": {
		// The close line has no process name (step 4 sample `_ connection closed _
		// A port _`), so the facility also takes that one shape: straight after the
		// clock and zone, no process slot, a number, an address, `port`. Another
		// daemon's "connection closed ... port" line (sshd, netconf) is not kept.
		facility: regexp.MustCompile(`(?i)\btacacsd\b|\d{2}\.\d{1,9}(?: [A-Z]{2,5})?: connection closed \d+ (?:\d{1,3}\.){3}\d{1,3} port \d+`),
		open:     regexp.MustCompile(`(?i)opening connection to|socket connected`),
		closed:   regexp.MustCompile(`(?i)closing connection to \S+ port \S+(?: \((idle timeout|remote reset|timeout|error|closed by server)\))?|\bconnection closed\b|\bclosing the socket\b`),
		// One request prints three lines (the selected server, the Encrypted line and
		// the Packet line); only the last has "(session N) to server" and counts.
		authen:   regexp.MustCompile(`(?i)^.*\bPacket AUTHEN/\w+ \(session \d+\) to server\b`),
		author:   regexp.MustCompile(`(?i)^.*\bPacket AUTHOR/\w+ \(session \d+\) to server\b`),
		acct:     regexp.MustCompile(`(?i)^.*\bPacket ACCT/\w+ \(session \d+\) to server\b`),
		single:   regexp.MustCompile(`(?i)single connection (?:flag set|negotiated)`),
		dead:     regexp.MustCompile(`(?i)marked dead|is not responding`),
		fallback: regexp.MustCompile(`(?i)falling back to`),
	},
	"junos": {
		facility: regexp.MustCompile(`(?i)\b(?:tacplus|authd|tacacs)\b`),
		// Only the auditd accounting line is measured (step 4d). No connection or
		// authentication line has been kept: the login path's syslog tag is not
		// known yet (see ddTagCounts), so they are unmeasured, not guessed, and the
		// close stays unknown. The reservation-file "opened" lines of authd are not
		// connections and are not counted.
		open:     ddNever,
		closed:   ddNever,
		noClose:  true,
		authen:   ddNever,
		author:   ddNever,
		acct:     regexp.MustCompile(`(?i)successfully sent tacacs\+ accounting-request message`),
		single:   regexp.MustCompile(`(?i)single-connect (?:flag set|negotiated)`),
		dead:     regexp.MustCompile(`(?i)marked dead`),
		fallback: regexp.MustCompile(`(?i)falling back to`),
	},
	"nxos": {
		facility: regexp.MustCompile(`(?i)\b(?:tacacsd|aaad)\b`),
		open:     regexp.MustCompile(`(?i)nxos_ssl_open success`),
		closed:   regexp.MustCompile(`(?i)freeing ssl_ctx for sock_fd`),
		authen:   regexp.MustCompile(`(?i)aaa type: *1\b`),
		author:   regexp.MustCompile(`(?i)aaa type: *2\b`),
		acct:     regexp.MustCompile(`(?i)aaa type: *3\b`),
		single:   ddNever,
		dead:     regexp.MustCompile(`(?i)mark server\(.*\) dead|aaa_mark_server_dead \d`),
		fallback: regexp.MustCompile(`(?i)fall back method`),
	},
}

var (
	ddPayload = regexp.MustCompile(`(?i)payload`)
	// ddShapeRedact are the reversible encodings and hashes redacted by shape,
	// unconditionally, each with its replacement. The Junos $9$ and the crypt
	// $1$ $5$ $6$ $8$ forms go whole; a `key|password|secret` word keeps its
	// word (and its type) and loses its value.
	ddShapeRedact = []struct {
		re   *regexp.Regexp
		repl string
	}{
		// The Junos $9$ alphabet includes `-`, so the value runs to a space or quote.
		{regexp.MustCompile(`\$[15689]\$[^\s"']+`), ddRedacted},
		// The reversible and clear types of a key, password or secret: any
		// whitespace, the quoted NX-OS form or a bare word, the whole value.
		{regexp.MustCompile(`(?i)\b(key(?:-string)?|password|secret)\s+(7|[0689])\s+("[^"]*"|\S+)`), "${1} ${2} " + ddRedacted},
	}
	ddClock = regexp.MustCompile(`\d\d:\d\d:\d\d(?:\.\d{1,9})?`)

	// The hex-dump views. ddHexChain is four or more groups of one, two or four
	// hex digits in a row, separated by blanks or colons; ddHexRun a contiguous
	// run of eight or more; ddHexOnly a message that is nothing but hex groups.
	// A clock is replaced by T first, so `09:39:03` is not a dump, and a dotted
	// address never is one (the dot is no separator).
	ddHexTok   = `(?:[0-9A-Fa-f]{4}|[0-9A-Fa-f]{1,2})`
	ddHexChain = regexp.MustCompile(`(?:^|[ \t:,-])(?:` + ddHexTok + `[ \t:,-]+){3,}` + ddHexTok + `(?:[ \t:,-]|$)`)
	ddHexRun   = regexp.MustCompile(`[0-9A-Fa-f]{8,}`)
	ddHexOnly  = regexp.MustCompile(`^(?:[0-9A-Fa-f]{1,8}(?:[ \t:.,-]+|$)){2,}$`)
	ddIndex    = regexp.MustCompile(`^\s*(?:\[\d+\]|\(\w+\))?[\s:+]*`)
	// ddSepStrip removes what can sit between the bytes of a spelled-out hex
	// string: every 0x or \x and all punctuation and blanks.
	ddSepStrip = regexp.MustCompile(`(?i)\\x|0x|[^0-9a-z]`)
	// ddBytePrefix is the 0x or \x in front of a byte, C and Python style.
	ddBytePrefix = regexp.MustCompile(`(?i)\\x|\b0x`)
	// ddMarker is what an evidence file must not hold, so the line goes rather
	// than the whole run turning INVALID at the gate.
	ddMarker = regexp.MustCompile(`(?i:_sha256)|BEGIN `)
)

// ddHexView is whether line, a clock aside, has a hex-dump layout: a run of
// eight or more hex digits, or four or more hex groups in a row.
func ddHexView(line string) bool {
	v := ddBytePrefix.ReplaceAllString(ddClock.ReplaceAllString(line, "T"), " ")
	return ddHexRun.MatchString(v) || ddHexChain.MatchString(v)
}

// ddHexMessage is whether the message after the facility (first match of p) is
// nothing but hex groups.
func ddHexMessage(p *ddProfile, line string, whole bool) bool {
	loc := p.facility.FindStringIndex(line)
	rest := line
	switch {
	case loc != nil:
		rest = line[loc[1]:]
	case !whole:
		return false
	}
	rest = rest[len(ddIndex.FindString(rest)):]
	rest = ddBytePrefix.ReplaceAllString(ddClock.ReplaceAllString(rest, "T"), " ")
	return ddHexOnly.MatchString(strings.TrimSpace(rest))
}

const ddRedacted = "<redacted>"

// ddXlat is the Cisco type 7 translation table.
const ddXlat = "dsfd;kfoA,.iyewrkldJKDHSUBsgvca69834ncxv9873254k;fg87"

// ddType7 is s as Cisco type 7 encodes it with salt (0 to 15): the two-digit
// salt, then each byte xor the table, in hex. Only our own known secrets are
// encoded, to know what to look for; no value the device prints is decoded.
func ddType7(s string, salt int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%02d", salt)
	for i := 0; i < len(s); i++ {
		fmt.Fprintf(&b, "%02X", s[i]^ddXlat[(salt+i)%len(ddXlat)])
	}
	return b.String()
}

// ddSecretForms are the strings that must not survive in the kept text, one per
// form of each secret, lowercase and longest first. Besides the literal, hex,
// base64 (both alphabets, padded or not) and type 7 forms, the base64 of a
// secret at the three alignments it can have in a longer encoded string is
// covered by the stable inner part of each: the encoding of the secret alone
// (a partial last character cut), and of the secret behind one and two zero
// bytes (the characters that mix in the neighbour's bits cut).
func ddSecretForms(secrets []string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		if s = strings.ToLower(s); s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	addInner := func(s string) {
		if len(s) >= 4 {
			add(s)
		}
	}
	encs := []*base64.Encoding{base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.RawURLEncoding}
	for _, s := range secrets {
		if s == "" {
			continue
		}
		b := []byte(s)
		add(s)
		add(hex.EncodeToString(b))
		for _, enc := range encs {
			add(enc.EncodeToString(b))
		}
		for _, enc := range encs[:2] {
			for off := 0; off < 3; off++ {
				e := strings.TrimRight(enc.EncodeToString(append(make([]byte, off), b...)), "=")
				head := [3]int{0, 2, 3}[off]
				if head >= len(e) {
					continue
				}
				e = e[head:]
				if (off+len(b))%3 != 0 && len(e) > 0 {
					e = e[:len(e)-1] // the last character mixes in the next byte
				}
				addInner(e)
			}
		}
		for salt := 0; salt < 16; salt++ {
			add(ddType7(s, salt))
		}
	}
	slices.SortFunc(out, func(a, b string) int { return len(b) - len(a) })
	return out
}

// ddHexForms are the lowercase hex of each secret of three bytes or more, for
// the check on a line with its separators stripped.
func ddHexForms(secrets []string) []string {
	var out []string
	for _, s := range secrets {
		if len(s) >= 3 {
			out = append(out, strings.ToLower(hex.EncodeToString([]byte(s))))
		}
	}
	return out
}

// ddRedactSecrets compiles forms once into a function that replaces every one
// of them in a line with <redacted>, leftmost and longest. It is a variable so
// the fail-closed test can break it.
var ddRedactSecrets = func(forms []string) func(string) string {
	if len(forms) == 0 {
		return func(s string) string { return s }
	}
	quoted := make([]string, len(forms))
	for i, f := range forms {
		quoted[i] = regexp.QuoteMeta(f)
	}
	re := regexp.MustCompile(`(?i)` + strings.Join(quoted, "|"))
	re.Longest()
	return func(s string) string { return re.ReplaceAllLiteralString(s, ddRedacted) }
}

// ddStrippedHex is whether line, its separators removed, holds the hex of a
// known secret: a secret spelled in spaced, coloured or oddly grouped hex.
func ddStrippedHex(line string, hexForms []string) bool {
	if len(hexForms) == 0 {
		return false
	}
	low := strings.ToLower(ddSepStrip.ReplaceAllString(line, ""))
	for _, f := range hexForms {
		if strings.Contains(low, f) {
			return true
		}
	}
	return false
}

// ddLeaks reports whether any form of any secret is in text, or the hex of one in
// a line of it with its separators stripped. The markers Keep writes are replaced
// by a separator first, so a secret that happens to spell part of one cannot
// fail a clean capture, and two pieces on either side of a marker cannot join
// into a form.
func ddLeaks(text string, forms, hexForms []string) bool {
	low := strings.NewReplacer("<redacted>", "\x00", "<long>", "\x00").Replace(strings.ToLower(text))
	for _, f := range forms {
		if strings.Contains(low, f) {
			return true
		}
	}
	// A letter outside the hex digits stands for a marker here, so two pieces on
	// either side of one cannot join in the stripped view.
	for _, ln := range strings.Split(strings.ReplaceAll(low, "\x00", "g"), "\n") {
		if ddStrippedHex(ln, hexForms) {
			return true
		}
	}
	return false
}

// drop is the rule of steps 1 and 2 that drops line, or "" if none does.
func (f deviceDebugFilter) drop(p *ddProfile, line string) string {
	return f.dropFrom(p, line, false)
}

// dropFrom is drop for a line of a source file whose every line is a line of the
// AAA daemon's own trace (whole): the facility rule is skipped for it.
func (f deviceDebugFilter) dropFrom(p *ddProfile, line string, whole bool) string {
	switch {
	case !whole && !p.facility.MatchString(line):
		return "facility"
	case ddPayload.MatchString(line) || nxosDebugHexRun.MatchString(line):
		return "payload"
	case ddMarker.MatchString(line):
		return "marker"
	case ddHexView(line):
		return "hex_view"
	case ddHexMessage(p, line, whole):
		return "hex_message"
	}
	return ""
}

// keeps is whether line passes the facility, payload and hex-dump rules (steps 1
// and 2).
func (f deviceDebugFilter) keeps(p *ddProfile, line string) bool {
	return f.drop(p, line) == ""
}

func (d *ddDropCounts) count(reason string) {
	if d == nil {
		return
	}
	switch reason {
	case "facility":
		d.Facility++
	case "payload":
		d.Payload++
	case "marker":
		d.Marker++
	case "hex_view":
		d.HexView++
	case "hex_message":
		d.HexMessage++
	case "known_value_hex":
		d.StrippedSecret++
	}
}

// Keep is text (the device's debug output, as `show logging` or `show log`
// prints it) cut to the lines the rules above keep and scrubbed, one per line.
// It returns errDeviceDebugLeak, and nothing else, when a known secret
// survives the scrub.
func (f deviceDebugFilter) Keep(text string) (deviceDebugKept, error) {
	return f.KeepSource(text, false)
}

// KeepSource is Keep for text that comes from one source file. whole says that
// the file is the AAA daemon's own trace (Junos's authd traceoptions file): its
// lines are kept past the facility rule, which they need not carry. The file is
// the whole authd trace, not TACACS+ alone (local, RADIUS and LDAP
// authentication too), so what protects it is the scrub: every other rule
// applies to every line, and the fail-closed check runs on all of it.
func (f deviceDebugFilter) KeepSource(text string, whole bool) (deviceDebugKept, error) {
	p := deviceDebugProfiles[f.Platform]
	if p == nil {
		return "", nil
	}
	var secrets []string
	if f.Secrets != nil {
		secrets = f.Secrets()
	}
	forms, hexForms := ddSecretForms(secrets), ddHexForms(secrets)
	redact := ddRedactSecrets(forms)
	var out []string
	for _, ln := range strings.Split(nxosDebugANSI.ReplaceAllString(text, ""), "\n") {
		ln = strings.TrimSpace(ln)
		// A secret spelled in separated hex cannot be redacted in place: the line goes.
		if ln == "" {
			continue
		}
		if f.Tags != nil {
			f.Tags.add(ln, forms, hexForms)
		}
		if r := f.dropFrom(p, ln, whole); r != "" {
			f.Drops.count(r)
			continue
		}
		if ddStrippedHex(ln, hexForms) {
			f.Drops.count("known_value_hex")
			continue
		}
		// Long runs are masked before the redaction too, so a redaction cannot
		// split a run and leave the rest of it unmasked.
		ln = nxosDebugLong.ReplaceAllString(ln, "<LONG>")
		ln = redact(ln)
		for _, s := range ddShapeRedact {
			ln = s.re.ReplaceAllString(ln, s.repl)
		}
		out = append(out, nxosDebugLong.ReplaceAllString(ln, "<LONG>"))
	}
	kept := strings.Join(out, "\n")
	if ddLeaks(kept, forms, hexForms) {
		return "", errDeviceDebugLeak
	}
	return deviceDebugKept(kept), nil
}

// deviceDebugKept is text Keep has filtered. The counters take only this type,
// so a raw capture cannot reach them without an explicit conversion.
type deviceDebugKept string

// deviceDebugConn is one connection the kept debug shows: when it opened
// and closed (the device's own time; "" for none), the reason it states for
// the close, and the requests sent on it. Requests before any open belong to
// a connection opened earlier (reuse), shown with Opened "".
type deviceDebugConn struct {
	Opened, Closed string
	Reason         string
	Authen, Author int
	Acct           int
	Requests       int // requests of unknown kind (cEOS messagesSent)
	// Placed is whether a kept open line started this connection. A request
	// with no open in force sits in an unplaced bucket (Opened "") that gathers
	// every request between two kept opens: it is not a connection.
	Placed bool
}

// Total is the connection's requests of every kind.
func (c deviceDebugConn) Total() int { return c.Authen + c.Author + c.Acct + c.Requests }

// deviceDebugSummary answers the single-connect and pipelining question from
// kept text only.
type deviceDebugSummary struct {
	Conns                []deviceDebugConn
	Opened, Closed       int
	Failed               int  // failed opens (cEOS connFails)
	CloseUnknown         bool // the platform's debug has no close line: Closed says nothing
	SingleConnect        int  // lines showing single-connect negotiated or its flag
	ServerDead, Fallback int  // server-dead and fallback lines
	Unplaced             int  // requests not placed on a connection (no kept open)
}

// Placed is the connections that a kept open started: how many, their requests,
// and how many carried more than one. Only these can answer the pipelining
// question.
func (s deviceDebugSummary) Placed() (conns, requests, multi int) {
	for _, c := range s.Conns {
		if !c.Placed {
			continue
		}
		conns++
		requests += c.Total()
		if c.Total() > 1 {
			multi++
		}
	}
	return
}

// ddKeptMsg splits a kept line into the device's clock (its first time of day,
// "" if it shows none) and the line, which is what the counters read.
func ddKeptMsg(ln string) (at, msg string) {
	return ddClock.FindString(ln), ln
}

// deviceDebugSummarize reads the counters out of kept, which Keep has already
// filtered, in order: a request belongs to the connection open at that line.
func deviceDebugSummarize(platform string, kept deviceDebugKept) deviceDebugSummary {
	var s deviceDebugSummary
	p := deviceDebugProfiles[platform]
	if p == nil {
		return s
	}
	s.CloseUnknown = p.noClose
	if kept == "" {
		return s
	}
	// A kind with an alternative family is counted from the primary lines when
	// the text has any, else from the alternative, so one request counts once.
	useAlt := func(primary, alt *regexp.Regexp) bool {
		return alt != nil && !primary.MatchString(string(kept))
	}
	altAuthen, altAuthor, altAcct := useAlt(p.authen, p.authenAlt), useAlt(p.author, p.authorAlt), useAlt(p.acct, p.acctAlt)
	cur := -1 // the index in s.Conns of the connection requests go to
	ensure := func() {
		if cur < 0 {
			s.Conns = append(s.Conns, deviceDebugConn{})
			cur = len(s.Conns) - 1
		}
	}
	for _, ln := range strings.Split(string(kept), "\n") {
		at, msg := ddKeptMsg(ln)
		switch {
		case p.open.MatchString(msg):
			s.Opened++
			s.Conns = append(s.Conns, deviceDebugConn{Opened: at, Placed: true})
			cur = len(s.Conns) - 1
		case p.closed.MatchString(msg):
			s.Closed++
			ensure()
			s.Conns[cur].Closed = at
			if m := p.closed.FindStringSubmatch(msg); len(m) > 1 {
				s.Conns[cur].Reason = m[1]
			}
			cur = -1
		case p.request != nil && p.request.MatchString(msg):
			ensure()
			s.Conns[cur].Requests++
		case p.authen.MatchString(msg) || altAuthen && p.authenAlt.MatchString(msg):
			ensure()
			s.Conns[cur].Authen++
		case p.author.MatchString(msg) || altAuthor && p.authorAlt.MatchString(msg):
			ensure()
			s.Conns[cur].Author++
		case p.acct.MatchString(msg) || altAcct && p.acctAlt.MatchString(msg):
			ensure()
			s.Conns[cur].Acct++
		}
		if p.failed != nil && p.failed.MatchString(msg) {
			s.Failed++
		}
		if p.single.MatchString(msg) {
			s.SingleConnect++
		}
		if p.dead.MatchString(msg) {
			s.ServerDead++
		}
		if p.fallback.MatchString(msg) {
			s.Fallback++
		}
	}
	for _, c := range s.Conns {
		if !c.Placed {
			s.Unplaced += c.Total()
		}
	}
	return s
}

// deviceDebugCommands is how one platform's debug is turned on, collected and
// turned off. Enable and Disable are run in order, Collect's output is the
// debug text. The syntax is from vendor documentation and the lab notes,
// not yet confirmed on the image: the lab run confirms it (task 8 report).
type deviceDebugCommands struct {
	Enable, Disable, Collect []string
	// Whole names the Collect commands whose output is a daemon's own trace file
	// (Junos's authd traceoptions): every line of it is kept past the facility
	// rule.
	Whole []string
}

// ddJunosFlagHelp lists the traceoptions flags this release has.
const ddJunosFlagHelp = "set system processes general-authentication-service traceoptions flag ?"

var deviceDebugCmds = map[string]deviceDebugCommands{
	"eos": {
		Enable:  []string{"terminal length 0", "terminal width 511", "clear agent Aaa logs", "configure", "trace Aaa setting *", "end"},
		Disable: []string{"configure", "no trace Aaa setting *", "end"},
		Collect: []string{"show agent Aaa logs"},
	},
	"iosxr": {
		Enable:  []string{"terminal length 0", "terminal width 512", "clear logging", "y", "debug tacacs", "debug aaa"},
		Disable: []string{"undebug all"},
		Collect: []string{"show logging"},
	},
	"iosxe": {
		Enable: []string{"terminal length 0", "terminal width 511", "clear logging", "", "debug tacacs", "debug aaa authentication",
			"debug aaa authorization", "debug aaa accounting"},
		Disable: []string{"undebug all"},
		Collect: []string{"show logging"},
	},
	"junos": {
		// authd (general-authentication-service) is the process whose trace this
		// reads (Juniper's TACACS+ troubleshooting points at it). `level` is not
		// valid under its traceoptions, so only file and flag all are set. The flag help is read once in configure mode
		// (`?` shows the words and nothing is committed by it) to learn whether
		// this release has a TACACS or login flag. The syslog file stays for
		// auditd's accounting line and the process tags.
		Enable: []string{"set cli screen-width 300", "clear log tacacs-traceoptions", "clear log p49-auth.log", "configure",
			ddJunosFlagHelp,
			"set system processes general-authentication-service traceoptions file tacacs-traceoptions",
			"set system processes general-authentication-service traceoptions flag all",
			"set system syslog file p49-auth.log any any",
			"commit and-quit"},
		Disable: []string{"configure", "delete system processes general-authentication-service traceoptions",
			"delete system syslog file p49-auth.log", "commit and-quit",
			"clear log tacacs-traceoptions", "clear log p49-auth.log"},
		Collect: []string{"show log tacacs-traceoptions", "show log p49-auth.log"},
		Whole:   []string{"show log tacacs-traceoptions"},
	},
}

// captureDeviceDebug turns the platform's debug on, runs during (the cell
// under measurement), collects the debug text and turns debug off again. The
// debug is collected and debug turned off even when during or a step fails: it
// is wanted most when a cell goes wrong. run sends one line to the device and
// returns its output. The collected text is filtered here, in-process: the raw
// text is never returned, so a caller cannot write it to disk. A known secret
// that survives the scrub discards the whole capture (errDeviceDebugLeak). An
// error from run can hold the device's output (a prompt timeout prints the whole
// tail), so each is replaced by ddWrap's text; during's error is the caller's
// own and is returned first, unchanged.
func captureDeviceDebug(f deviceDebugFilter, run func(cmd string) (string, error), during func() error) (deviceDebugKept, error) {
	cmds, ok := deviceDebugCmds[f.Platform]
	if !ok {
		return "", errUnknownDebugPlatform
	}
	for _, c := range cmds.Enable {
		if _, err := run(c); err != nil {
			disableDeviceDebug(cmds, run)
			return "", ddWrap(c, err)
		}
	}
	cellErr := during()
	var kept []string
	var collectErr, leakErr error
	for _, c := range cmds.Collect {
		raw, err := run(c)
		// A partial capture is kept, filtered like the rest.
		k, kerr := f.KeepSource(ddWithoutEcho(raw, c, slices.Contains(cmds.Whole, c)), slices.Contains(cmds.Whole, c))
		if kerr != nil {
			leakErr = kerr
		} else if k != "" {
			kept = append(kept, string(k))
		}
		if err != nil && collectErr == nil {
			collectErr = ddWrap(c, err)
		}
	}
	disableErr := disableDeviceDebug(cmds, run)
	err := cellErr
	if err == nil {
		err = leakErr
	}
	if err == nil {
		err = collectErr
	}
	if err == nil {
		err = disableErr
	}
	if leakErr != nil {
		return "", err
	}
	return deviceDebugKept(strings.Join(kept, "\n")), err
}

// ddWrap replaces err with the command it came from and its kind, and the size
// of what was withheld (the device's output can be in it, as in l71Wrap).
func ddWrap(cmd string, err error) error {
	kind := "error"
	if errors.Is(err, os.ErrDeadlineExceeded) || strings.Contains(err.Error(), "appeared") {
		kind = "timeout"
	}
	return fmt.Errorf("device debug %q: %s (%d bytes of device output withheld from this message)", cmd, kind, len(err.Error()))
}

func disableDeviceDebug(cmds deviceDebugCommands, run func(string) (string, error)) error {
	var first error
	for _, c := range cmds.Disable {
		if _, err := run(c); err != nil && first == nil {
			first = ddWrap(c, err)
		}
	}
	return first
}

// ddKnownSecrets is every secret list a debug cell redacts, joined, always with
// the lab TACACS+ key (never only through a device env).
func ddKnownSecrets(parts ...[]string) []string {
	all := []string{labcreds.Key}
	for _, p := range parts {
		all = append(all, p...)
	}
	return all
}

// ddTagRe captures the syslog process tag: `Oct 23 15:31:11 host tag[pid]: `.
var ddTagRe = regexp.MustCompile(`^\S+\s+\S+\s+\S+\s+\S+\s+([a-z][a-z0-9_-]{1,23})(\[[0-9]+\])?:`)

// ddMaxTags is how many distinct tags ddTagCounts reports; the rest count as other.
const ddMaxTags = 30

// ddTagCounts counts lines per syslog process tag, to learn which process
// writes the login path. It holds only counts: a tag that is not a short
// lower-case word of at most 24 characters, that holds a known secret in any
// form or looks like hex counts as other, and no text is kept. A line that does not
// match counts as other.
type ddTagCounts struct {
	tags  map[string]int
	other int
}

func (t *ddTagCounts) add(line string, forms, hexForms []string) {
	m := ddTagRe.FindStringSubmatch(line)
	if m == nil {
		t.other++
		return
	}
	tag := m[1]
	if ddLeaks(tag, forms, hexForms) || ddHexView(tag) {
		t.other++
		return
	}
	if t.tags == nil {
		t.tags = map[string]int{}
	}
	t.tags[tag]++
}

// String is `tag=n ... other=n`, the most frequent tags first, at most ddMaxTags
// of them; the rest are in other.
func (t *ddTagCounts) String() string {
	names := make([]string, 0, len(t.tags))
	for n := range t.tags {
		names = append(names, n)
	}
	slices.SortFunc(names, func(a, b string) int {
		if t.tags[a] != t.tags[b] {
			return t.tags[b] - t.tags[a]
		}
		return strings.Compare(a, b)
	})
	other := t.other
	if len(names) > ddMaxTags {
		for _, n := range names[ddMaxTags:] {
			other += t.tags[n]
		}
		names = names[:ddMaxTags]
	}
	var parts []string
	for _, n := range names {
		parts = append(parts, fmt.Sprintf("%s=%d", n, t.tags[n]))
	}
	return strings.Join(append(parts, fmt.Sprintf("other=%d", other)), " ")
}

// ddWithoutEcho, for a whole-file collection, removes what the CLI adds around
// the file: the echoed command, the prompt lines and the pager prompt. Other
// sources go through the facility rule, which drops those anyway.
func ddWithoutEcho(raw, cmd string, whole bool) string {
	if !whole {
		return raw
	}
	var out []string
	for _, ln := range strings.Split(raw, "\n") {
		t := strings.TrimSpace(ln)
		if strings.Contains(t, cmd) || ddCLIPrompt.MatchString(t) || strings.HasPrefix(t, "---(more") {
			continue
		}
		out = append(out, ln)
	}
	return strings.Join(out, "\n")
}

// ddCLIPrompt is a Junos operational or configuration prompt, `user@host> `.
var ddCLIPrompt = regexp.MustCompile(`^\S+@\S+[>#%]\s*$`)

// ddFlagWord is what a traceoptions flag name looks like. Only such a word is
// ever written from the CLI's flag help.
var ddFlagWord = regexp.MustCompile(`^[a-z][a-z0-9-]{1,30}$`)

// ddFlagWords reads the flag names out of the CLI's `?` help for flag: the first
// word of each line under "Possible completions:" that matches ddFlagWord, once
// each, sorted, at most 100. Nothing else of the help is kept.
func ddFlagWords(help string) []string {
	var words []string
	in := false
	for _, ln := range strings.Split(help, "\n") {
		t := strings.TrimSpace(ln)
		if strings.HasPrefix(t, "Possible completions:") {
			in = true
			continue
		}
		if !in {
			continue
		}
		if f := strings.Fields(t); len(f) > 0 && ddFlagWord.MatchString(f[0]) && !slices.Contains(words, f[0]) {
			words = append(words, f[0])
		}
	}
	slices.Sort(words)
	if len(words) > 100 {
		words = words[:100]
	}
	return words
}
