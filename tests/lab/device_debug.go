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
)

// Device debug capture for EOS, IOS XR, Junos, IOS XE and NX-OS (post-11b fix
// PR, task 8; spec §13 decision 50 ruling 20). Debug output can carry the
// request, the reply and the credential, so nothing from the device is kept as
// it is. deviceDebugFilter.Keep scrubs the text in-process, before anything
// reaches disk, in this order:
//
//  1. Keep by facility. A line is kept only if it carries the platform's
//     TACACS/AAA facility (ddProfile.facility). Everything else is dropped.
//  2. Drop payload lines. A line that says payload, or holds a hex-dump run
//     (nxosDebugHexRun: eight or more spaced hex bytes, or sixteen contiguous
//     hex digits), is dropped whole: it is the packet body.
//  3. Redact the run's known secrets: the TACACS+ key, the lab passwords, the
//     tokens and TOTP codes the run handled. Every value is replaced by
//     <redacted> in its literal, hex, base64 (standard and URL, padded and not)
//     and Cisco type 7 forms (all 16 salts), matched without regard to case.
//  4. Redact reversible encodings and crypt hashes by shape: Junos $9$, crypt
//     $1$ $5$ $6$ $8$, and `key|password|secret` followed by a type 7 value or
//     a 0, 6, 8 or 9 encoding. The shape is judged without knowing the secret,
//     so an encoding of a secret nobody told us about is still redacted.
//  5. Mask every run of 24 or more token characters as <LONG>.
//  6. Fail closed. The kept text is checked once more for every secret in every
//     form. If any survives, the whole capture is discarded: Keep returns
//     errDeviceDebugLeak, which names no device text, and the cell is graded
//     unmeasured.
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
		open:     regexp.MustCompile(`(?i)\b(?:connecting|connected) to\b|created socket`),
		closed:   regexp.MustCompile(`(?i)connection to \S+ (closed(?: by peer| by server| idle timeout)?|reset|timed out)|\btacacs\b\W+close\b`),
		authen:   regexp.MustCompile(`(?i)sending authentication request|tac` + ddSep + `send` + ddSep + `authen\b`),
		author:   regexp.MustCompile(`(?i)sending authorization request|tac` + ddSep + `send` + ddSep + `author\b`),
		acct:     regexp.MustCompile(`(?i)sending accounting request|tac` + ddSep + `send` + ddSep + `acct\b`),
		single:   regexp.MustCompile(`(?i)single connect(?:ion)? (?:flag set|negotiated)`),
		dead:     regexp.MustCompile(`(?i)marked dead|is not responding`),
		fallback: regexp.MustCompile(`(?i)falling back to`),
	},
	"iosxr": {
		// The close line has no process name (step 4 sample `_ connection closed _
		// A port _`), so the facility also takes it.
		facility: regexp.MustCompile(`(?i)\btacacsd\b|\bconnection closed\b.*\bport\b`),
		open:     regexp.MustCompile(`(?i)opening connection to|socket connected`),
		closed:   regexp.MustCompile(`(?i)closing connection to \S+ port \S+(?: \((idle timeout|remote reset|timeout|error|closed by server)\))?|\bconnection closed\b`),
		authen:   regexp.MustCompile(`(?i)sending authentication request|\bpacket\b.*\bstart\b.*\blogin\b`),
		author:   regexp.MustCompile(`(?i)sending authorization request|\bpacket\b.*\bauthor\b.*\bstart\b`),
		acct:     regexp.MustCompile(`(?i)sending accounting request|\bpacket\b.*\brequest\b.*\bstart\b`),
		single:   regexp.MustCompile(`(?i)single connection (?:flag set|negotiated)`),
		dead:     regexp.MustCompile(`(?i)marked dead|is not responding`),
		fallback: regexp.MustCompile(`(?i)falling back to`),
	},
	"junos": {
		facility: regexp.MustCompile(`(?i)\b(?:tacplus|authd|tacacs)\b`),
		open:     regexp.MustCompile(`(?i)connecting to server|\bopened\b`),
		closed:   ddNever,
		noClose:  true,
		authen:   regexp.MustCompile(`(?i)sending authentication request|sent tacacs` + ddSep + `authentication request message`),
		author:   regexp.MustCompile(`(?i)sending authorization request|sent tacacs` + ddSep + `authorization request message`),
		acct:     regexp.MustCompile(`(?i)sending accounting request|sent tacacs` + ddSep + `accounting request message`),
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
		dead:     regexp.MustCompile(`(?i)mark server\(.*\) dead`),
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
		{regexp.MustCompile(`\$[15689]\$[A-Za-z0-9./$=]+`), ddRedacted},
		{regexp.MustCompile(`(?i)\b(key|password|secret) 7 [0-9]{2}[0-9A-Fa-f]+`), "${1} 7 " + ddRedacted},
		{regexp.MustCompile(`(?i)\b(key|password|secret) ([0689]) \S+`), "${1} ${2} " + ddRedacted},
	}
	ddClock = regexp.MustCompile(`\d\d:\d\d:\d\d(?:\.\d{1,9})?`)
)

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
// form of each secret, lowercase and longest first (so a longer form is matched
// before a prefix of it).
func ddSecretForms(secrets []string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		if s = strings.ToLower(s); s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, s := range secrets {
		if s == "" {
			continue
		}
		b := []byte(s)
		add(s)
		add(hex.EncodeToString(b))
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.RawURLEncoding} {
			add(enc.EncodeToString(b))
		}
		for salt := 0; salt < 16; salt++ {
			add(ddType7(s, salt))
		}
	}
	slices.SortFunc(out, func(a, b string) int { return len(b) - len(a) })
	return out
}

// ddRedactSecrets replaces every form of every secret in text with <redacted>.
// It is a variable so the fail-closed test can break it.
var ddRedactSecrets = func(text string, forms []string) string {
	if len(forms) == 0 {
		return text
	}
	quoted := make([]string, len(forms))
	for i, f := range forms {
		quoted[i] = regexp.QuoteMeta(f)
	}
	return regexp.MustCompile(`(?i)`+strings.Join(quoted, "|")).ReplaceAllLiteralString(text, ddRedacted)
}

// ddLeaks reports whether any form of any secret is in text. The markers Keep
// writes are replaced by a separator first, so a secret that happens to spell
// part of one cannot fail a clean capture, and two pieces on either side of a
// marker cannot join into a form.
func ddLeaks(text string, forms []string) bool {
	low := strings.NewReplacer("<redacted>", "\x00", "<long>", "\x00").Replace(strings.ToLower(text))
	for _, f := range forms {
		if strings.Contains(low, f) {
			return true
		}
	}
	return false
}

// keeps is whether line passes the facility and payload rules (steps 1 and 2).
func (f deviceDebugFilter) keeps(p *ddProfile, line string) bool {
	return p.facility.MatchString(line) && !ddPayload.MatchString(line) && !nxosDebugHexRun.MatchString(line)
}

// Keep is text (the device's debug output, as `show logging` or `show log`
// prints it) cut to the lines the rules above keep and scrubbed, one per line.
// It returns errDeviceDebugLeak, and nothing else, when a known secret
// survives the scrub.
func (f deviceDebugFilter) Keep(text string) (deviceDebugKept, error) {
	p := deviceDebugProfiles[f.Platform]
	if p == nil {
		return "", nil
	}
	var secrets []string
	if f.Secrets != nil {
		secrets = f.Secrets()
	}
	forms := ddSecretForms(secrets)
	var out []string
	for _, ln := range strings.Split(nxosDebugANSI.ReplaceAllString(text, ""), "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || !f.keeps(p, ln) {
			continue
		}
		ln = ddRedactSecrets(ln, forms)
		for _, s := range ddShapeRedact {
			ln = s.re.ReplaceAllString(ln, s.repl)
		}
		out = append(out, nxosDebugLong.ReplaceAllString(ln, "<LONG>"))
	}
	kept := strings.Join(out, "\n")
	if ddLeaks(kept, forms) {
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
}

// deviceDebugSummary answers the single-connect and pipelining question from
// kept text only.
type deviceDebugSummary struct {
	Conns                []deviceDebugConn
	Opened, Closed       int
	CloseUnknown         bool // the platform's debug has no close line: Closed says nothing
	SingleConnect        int  // lines showing single-connect negotiated or its flag
	ServerDead, Fallback int  // server-dead and fallback lines
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
			s.Conns = append(s.Conns, deviceDebugConn{Opened: at})
			cur = len(s.Conns) - 1
		case p.closed.MatchString(msg):
			s.Closed++
			ensure()
			s.Conns[cur].Closed = at
			if m := p.closed.FindStringSubmatch(msg); len(m) > 1 {
				s.Conns[cur].Reason = m[1]
			}
			cur = -1
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
	return s
}

// deviceDebugCommands is how one platform's debug is turned on, collected and
// turned off. Enable and Disable are run in order, Collect's output is the
// debug text. The syntax is from vendor documentation and the lab notes,
// not yet confirmed on the image: the lab run confirms it (task 8 report).
type deviceDebugCommands struct {
	Enable, Disable, Collect []string
}

var deviceDebugCmds = map[string]deviceDebugCommands{
	"eos": {
		Enable:  []string{"terminal length 0", "clear agent Aaa logs", "configure", "trace Aaa setting *", "end"},
		Disable: []string{"configure", "no trace Aaa setting *", "end"},
		Collect: []string{"show agent Aaa logs"},
	},
	"iosxr": {
		Enable:  []string{"terminal length 0", "clear logging", "y", "debug tacacs", "debug aaa"},
		Disable: []string{"undebug all"},
		Collect: []string{"show logging"},
	},
	"iosxe": {
		Enable: []string{"terminal length 0", "clear logging", "", "debug tacacs", "debug aaa authentication",
			"debug aaa authorization", "debug aaa accounting"},
		Disable: []string{"undebug all"},
		Collect: []string{"show logging"},
	},
	"junos": {
		Enable: []string{"clear log p49-tacplus.log", "clear log p49-auth.log", "configure",
			"set system processes general-authentication-service traceoptions file p49-tacplus.log",
			"set system processes general-authentication-service traceoptions flag all",
			"set system syslog file p49-auth.log any any",
			"commit and-quit"},
		Disable: []string{"configure", "delete system processes general-authentication-service traceoptions",
			"delete system syslog file p49-auth.log", "commit and-quit",
			"clear log p49-tacplus.log", "clear log p49-auth.log"},
		Collect: []string{"show log p49-tacplus.log", "show log p49-auth.log"},
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
		k, kerr := f.Keep(raw)
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
