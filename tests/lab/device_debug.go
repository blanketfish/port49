package lab

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"strings"

	"github.com/rhwendt/port49/tests/lab/labcreds"
)

// Device debug capture for EOS, IOS XR, Junos and IOS XE (post-11b fix PR,
// task 8; spec §13 decision 50 ruling 20). The same filter as NX-OS
// (nxos_debug.go), per platform: debug output can carry the request, the
// reply and the credential, so nothing from the device is kept as it is.
// deviceDebugFilter.Keep filters each line before anything reaches disk:
//
//  1. Drop the line if it holds a secret word or a hex run (the NX-OS rules,
//     nxosDebugSecret and nxosDebugHexRun). Payload lines are the packet body.
//  2. Drop the line if it holds a run of 24 or more token characters
//     (nxosDebugLong: a token or base64). NX-OS masks such a run; here the
//     line is dropped, as the task brief says.
//  3. Keep the line only if one anchored shape of the platform's profile
//     admits it. A shape admits a count, a status word, a verb or an address,
//     never a free-text field, so a debug line of a shape nobody listed is
//     lost rather than kept. An unknown platform keeps nothing.
//  4. Every value field is allow-listed: an address only if it is one of the
//     lab's (Addrs), a server group only from Groups, a method list only from
//     deviceDebugLists, a fallback method only none or local, a username only
//     from the lab's (deviceDebugUser), and an opaque id (a session, handle or
//     tty name) is always <masked>. A number is kept only in a named position
//     and within bounds: a port 1-65535, a version or small counter of three
//     digits at most; a session or request id is written <n>. An attribute line keeps its key only for
//     service, cmd, cmd-arg and priv-lvl, with the NX-OS word lists
//     (nxosDebugServices, nxosDebugWords, priv-lvl 0-15); any other value is
//     <masked>, any other key drops the line.
//
// The line shapes are plausible wording, not measured: the lab run confirms
// them, and a wrong guess costs masked or missing lines, never a leak. No body
// byte is decoded and no line is kept unfiltered. The collector
// (captureDeviceDebug) filters in-process, so the raw output never reaches
// disk.

var errUnknownDebugPlatform = errors.New("device debug: unknown platform")

// deviceDebugLists are the method-list names kept: NX-OS's own (the
// `req <kind>:<list>` form), and `default`, the only list the other lab
// configs carry (`aaa authentication login default group port49 local`).
var deviceDebugLists = append([]string{"default"}, nxosDebugLists...)

// deviceDebugUsers are the usernames kept: the lab's break-glass account and
// the alice01..alice99 token users.
var deviceDebugUser = regexp.MustCompile(`^(` + regexp.QuoteMeta(labcreds.BreakglassUser) + `|alice[0-9]{2})$`)

// deviceDebugFilter is the capture filter for one platform ("eos", "iosxr",
// "junos", "iosxe") in one lab: the addresses and server group names a kept
// line may name. Anything else in those fields is <masked>.
type deviceDebugFilter struct {
	Platform string
	Addrs    []netip.Addr // port49's listen address and the device's management address
	Groups   []string     // the lab's TACACS+ server group names
}

// Placeholders in a shape: each becomes one capturing group, judged by kind.
const (
	ddIP     = "\x01" // an address, kept only if a lab address
	ddGroup  = "\x02" // a server group name
	ddList   = "\x03" // a method list name
	ddMethod = "\x04" // a fallback method: none or local
	ddUser   = "\x05" // a username
	ddOpaque = "\x06" // a session id, handle or tty name: always masked
	ddID     = "\x07" // a session or request id: kept as <n>
)

// ddProfile is one platform's line format and shapes.
type ddProfile struct {
	line   *regexp.Regexp // splits a line into t (time), p (process, optional), m (message)
	av     *regexp.Regexp // an attribute line: the fixed prefix, key and value
	shapes []string
	// What the counters read in a kept message.
	open, authen, author, acct, single, dead, fallback *regexp.Regexp
	// closed matches a close; its one group is the reason the device states.
	closed *regexp.Regexp
}

const (
	// ddSmall is a version or small counter (three digits at most); ddPort is
	// a port, 1 to 65535. A session or request id is kept as <n> (ddID).
	ddSmall  = `\d{1,3}`
	ddPort   = `(?:6553[0-5]|655[0-2]\d|65[0-4]\d\d|6[0-4]\d{3}|[1-5]\d{4}|[1-9]\d{0,3})`
	ddStatus = `(PASS|FAIL|FAILURE|ERROR|GETUSER|GETPASS|GETDATA|RESTART|FOLLOW|PASS_ADD|PASS_REPL|SUCCESS)`
	ddKind   = `(authentication|authorization|accounting)`
)

var deviceDebugProfiles = map[string]*ddProfile{
	"iosxe": {
		line: regexp.MustCompile(`^[*.]?(?:[A-Z][a-z]{2} +\d+(?: \d{4})? )?(?P<t>\d\d:\d\d:\d\d\.\d+)(?: [A-Z]{2,5})?: (?P<m>.*)$`),
		av:   regexp.MustCompile(`^(TAC\+: +)(priv-lvl|service|cmd-arg|cmd)=(.*)$`),
		shapes: []string{
			`TPLUS: Queuing AAA (Authentication|Authorization|Accounting) request ` + ddID + ` for processing`,
			`TPLUS: processing (authentication|authorization|accounting) (start )?request id ` + ddID,
			`TPLUS: Authentication start packet created for ` + ddID + `\(` + ddUser + `\)`,
			`TPLUS: (Using|Choosing next) server ` + ddIP,
			`TPLUS\(` + ddOpaque + `\)/` + ddSmall + `/` + ddOpaque + `/` + ddOpaque + `: Started ` + ddSmall + ` sec timeout`,
			`TPLUS\(` + ddOpaque + `\) login timer (started ` + ddSmall + ` sec timeout|stopped)`,
			`TAC\+: Opening TCP/IP to ` + ddIP + `/` + ddPort + ` timeout=` + ddSmall,
			`TAC\+: Opened TCP/IP handle ` + ddOpaque + ` to ` + ddIP + `/` + ddPort,
			`TAC\+: Closing TCP/IP ` + ddOpaque + ` connection to ` + ddIP + `/` + ddPort + `( \((idle timeout|remote reset|timeout|error|closed by server)\))?`,
			`TAC\+: Using single connection to ` + ddIP,
			`TAC\+: Server ` + ddIP + ` (marked|is) (DEAD|ALIVE)`,
			`TAC\+: Using default tacacs server-group "` + ddGroup + `"`,
			`TAC\+: send (AUTHEN|AUTHOR|ACCT)/(START|CONT|REQ|REQUEST) packet`,
			`TAC\+: ver=` + ddSmall + ` id=` + ddID + ` received (AUTHEN|AUTHOR|ACCT) status = ` + ddStatus,
			`TAC\+: \(` + ddID + `\): received (authen|author|acct) response status = ` + ddStatus,
			`AAA/AUTHEN/LOGIN \(` + ddOpaque + `\): Pick method list '` + ddList + `'`,
			`AAA/AUTHEN/LOGIN \(` + ddOpaque + `\): Status = ` + ddStatus,
			`AAA/AUTHEN/LOGIN \(` + ddOpaque + `\): Method=(LOCAL|NONE)`,
			`AAA/AUTHEN/LOGIN \(` + ddOpaque + `\): Method=` + ddGroup + ` \(tacacs\+\)`,
			`AAA/AUTHOR/(EXEC|CMD) \(` + ddOpaque + `\): (Method=` + ddGroup + ` \(tacacs\+\)|Post authorization status = ` + ddStatus + `)`,
			`AAA/ACCT/(EXEC|CMD|NET)/(START|STOP|WATCHDOG) User ` + ddUser + `, Port ` + ddOpaque,
		},
		open:     regexp.MustCompile(`TAC\+: Opening TCP/IP to`),
		closed:   regexp.MustCompile(`TAC\+: Closing TCP/IP \S+ connection to \S+(?: \((idle timeout|remote reset|timeout|error|closed by server)\))?$`),
		authen:   regexp.MustCompile(`send AUTHEN/`),
		author:   regexp.MustCompile(`send AUTHOR/`),
		acct:     regexp.MustCompile(`send ACCT/`),
		single:   regexp.MustCompile(`Using single connection`),
		dead:     regexp.MustCompile(`Server \S+ (marked|is) DEAD`),
		fallback: regexp.MustCompile(`Method=(LOCAL|NONE)`),
	},
	"eos": {
		line: regexp.MustCompile(`^(?:[A-Z][a-z]{2} +\d+ |\d{4}-\d\d-\d\dT)?(?P<t>\d\d:\d\d:\d\d(?:\.\d+)?)(?:[+-]\d\d:\d\d|Z)? (?:\S+ )?(?P<p>Aaa|Tacacs|TacPlus)(?:\[\d+\])?: (?P<m>.*)$`),
		av:   regexp.MustCompile(`^()(priv-lvl|service|cmd-arg|cmd)=(.*)$`),
		shapes: []string{
			`(Connecting|Connected) to (TACACS\+ )?server ` + ddIP + `( port |:)` + ddPort,
			`Connection to ` + ddIP + `:` + ddPort + ` (closed|closed by peer|closed by server|closed idle timeout|reset|timed out)`,
			`Sending ` + ddKind + ` request ` + ddID + ` to ` + ddIP + `(:` + ddPort + `)?`,
			`Received ` + ddKind + ` reply ` + ddID + ` status ` + ddStatus,
			`Single connect (flag set|negotiated|not supported)`,
			`Server ` + ddIP + ` (marked dead|marked alive|is not responding)`,
			`Falling back to ` + ddMethod + ` for ` + ddKind,
			`Using server group ` + ddGroup,
			`User ` + ddUser + ` authenticating via method list ` + ddList,
		},
		open:     regexp.MustCompile(`^(Connecting|Connected) to`),
		closed:   regexp.MustCompile(`^Connection to \S+ (closed(?: by peer| by server| idle timeout)?|reset|timed out)$`),
		authen:   regexp.MustCompile(`^Sending authentication request`),
		author:   regexp.MustCompile(`^Sending authorization request`),
		acct:     regexp.MustCompile(`^Sending accounting request`),
		single:   regexp.MustCompile(`^Single connect (flag set|negotiated)`),
		dead:     regexp.MustCompile(`marked dead|is not responding`),
		fallback: regexp.MustCompile(`^Falling back to`),
	},
	"iosxr": {
		line: regexp.MustCompile(`^(?:RP/\d+/\S+:)?(?:[A-Z][a-z]{2} +\d+ )?(?P<t>\d\d:\d\d:\d\d\.\d+)(?: [A-Z]{2,5})?: (?P<p>tacacsd|aaad|tac_plus)(?:\[\d+\])?: (?P<m>.*)$`),
		av:   regexp.MustCompile(`^()(priv-lvl|service|cmd-arg|cmd)=(.*)$`),
		shapes: []string{
			`(Opening|Opened) connection to ` + ddIP + ` port ` + ddPort,
			`Closing connection to ` + ddIP + ` port ` + ddPort + `( \((idle timeout|remote reset|timeout|error|closed by server)\))?`,
			`Sending ` + ddKind + ` request ` + ddID + ` to ` + ddIP,
			`Received ` + ddKind + ` reply ` + ddID + ` status ` + ddStatus,
			`Single connection (flag set|negotiated|not supported)`,
			`Server ` + ddIP + ` (marked dead|marked alive|is not responding)`,
			`Falling back to ` + ddMethod + ` for ` + ddKind,
			`Using server group ` + ddGroup,
			`User ` + ddUser + ` authenticating via method list ` + ddList,
		},
		open:     regexp.MustCompile(`^Opening connection to`),
		closed:   regexp.MustCompile(`^Closing connection to \S+ port \S+(?: \((idle timeout|remote reset|timeout|error|closed by server)\))?$`),
		authen:   regexp.MustCompile(`^Sending authentication request`),
		author:   regexp.MustCompile(`^Sending authorization request`),
		acct:     regexp.MustCompile(`^Sending accounting request`),
		single:   regexp.MustCompile(`^Single connection (flag set|negotiated)`),
		dead:     regexp.MustCompile(`marked dead|is not responding`),
		fallback: regexp.MustCompile(`^Falling back to`),
	},
	"junos": {
		line: regexp.MustCompile(`^(?:[A-Z][a-z]{2} +\d+ )?(?P<t>\d\d:\d\d:\d\d(?:\.\d+)?) (?:\S+ )?(?P<p>mgd|sshd|login|tacplus|authd)(?:\[\d+\])?: (?P<m>.*)$`),
		av:   regexp.MustCompile(`^()(priv-lvl|service|cmd-arg|cmd)=(.*)$`),
		shapes: []string{
			`(connecting|connected) to server ` + ddIP + ` port ` + ddPort,
			`connection to ` + ddIP + ` (closed|closed by server|closed idle timeout|reset|timed out)`,
			`sending ` + ddKind + ` request ` + ddID + ` to ` + ddIP,
			`received ` + ddKind + ` reply ` + ddID + ` status ` + ddStatus,
			`single-connect (flag set|negotiated|not offered)`,
			`server ` + ddIP + ` (marked dead|marked alive|timed out)`,
			`falling back to ` + ddMethod,
			`using server group ` + ddGroup,
			`user ` + ddUser + ` authenticating via method list ` + ddList,
		},
		open:     regexp.MustCompile(`^connecting to server`),
		closed:   regexp.MustCompile(`^connection to \S+ (closed(?: by server| idle timeout)?|reset|timed out)$`),
		authen:   regexp.MustCompile(`^sending authentication request`),
		author:   regexp.MustCompile(`^sending authorization request`),
		acct:     regexp.MustCompile(`^sending accounting request`),
		single:   regexp.MustCompile(`^single-connect (flag set|negotiated)`),
		dead:     regexp.MustCompile(`marked dead`),
		fallback: regexp.MustCompile(`^falling back to`),
	},
}

// ddCompiled are a platform's shapes with their value kinds, compiled once.
type ddCompiled struct {
	re    *regexp.Regexp
	kinds []byte // per capturing group: 'i' address, 'g' group, 'l' method list, 'm' fallback method, 'u' user, 'x' opaque, 'n' id
}

var ddShapes = func() map[string][]ddCompiled {
	out := map[string][]ddCompiled{}
	repl := strings.NewReplacer(ddIP, `([0-9A-Za-z.:]{2,39})`, ddGroup, `([A-Za-z0-9_-]{0,32})`,
		ddList, `([A-Za-z0-9_:-]{1,40})`, ddMethod, `([a-z]+)`, ddUser, `([A-Za-z0-9_.-]{1,32})`,
		ddOpaque, `([0-9A-Za-z_.:-]{1,23})`, ddID, `(-?\d{1,12})`)
	for name, p := range deviceDebugProfiles {
		for _, s := range p.shapes {
			var kinds []byte
			for _, c := range s {
				switch string(c) {
				case ddIP:
					kinds = append(kinds, 'i')
				case ddGroup:
					kinds = append(kinds, 'g')
				case ddList:
					kinds = append(kinds, 'l')
				case ddMethod:
					kinds = append(kinds, 'm')
				case ddUser:
					kinds = append(kinds, 'u')
				case ddOpaque:
					kinds = append(kinds, 'x')
				case ddID:
					kinds = append(kinds, 'n')
				}
			}
			re := repl.Replace(nxosNonCapturing(s))
			out[name] = append(out[name], ddCompiled{re: regexp.MustCompile(`^` + re + `$`), kinds: kinds})
		}
	}
	return out
}()

// Keep is text (the device's debug output, as `show logging` or `show log`
// prints it) cut to the lines the rules above keep, one per line, in the form
// `time [process:] message`.
func (f deviceDebugFilter) Keep(text string) deviceDebugKept {
	p := deviceDebugProfiles[f.Platform]
	if p == nil {
		return ""
	}
	var out []string
	for _, ln := range strings.Split(nxosDebugANSI.ReplaceAllString(text, ""), "\n") {
		m := p.line.FindStringSubmatch(ln)
		if m == nil || nxosDebugSecret.MatchString(ln) || nxosDebugHexRun.MatchString(ln) {
			continue
		}
		msg := strings.TrimSpace(m[p.line.SubexpIndex("m")])
		// A run of 24 or more token characters is a token or base64: the
		// line is dropped, not masked.
		if nxosDebugLong.MatchString(msg) {
			continue
		}
		// An attribute line is judged by key before the mask, which would
		// otherwise swallow `key=` with its value.
		var ok bool
		if av := p.av.FindStringSubmatch(msg); av != nil {
			msg, ok = ddAV(av)
		} else {
			msg, ok = f.admitted(f.Platform, msg)
		}
		if !ok {
			continue
		}
		prefix := m[p.line.SubexpIndex("t")]
		if i := p.line.SubexpIndex("p"); i > 0 && m[i] != "" {
			prefix += " " + m[i] + ":"
		}
		out = append(out, prefix+" "+msg)
	}
	return deviceDebugKept(strings.Join(out, "\n"))
}

// deviceDebugKept is text Keep has filtered. The counters take only this type,
// so a raw capture cannot reach them without an explicit conversion.
type deviceDebugKept string

// ddAV is an attribute message as kept: priv-lvl keeps 0-15, service a listed
// service, cmd and cmd-arg a listed word, and any other value is <masked>. The
// av pattern admits only those four keys; any other key reaches the shapes,
// which have none for it, so the line is dropped.
func ddAV(av []string) (string, bool) {
	prefix, key, val := av[1], av[2], av[3]
	var ok bool
	switch key {
	case "priv-lvl":
		ok = nxosDebugPrivLvl.MatchString(val)
	case "service":
		ok = slices.Contains(nxosDebugServices, val)
	case "cmd", "cmd-arg":
		ok = slices.Contains(nxosDebugWords, val)
	}
	if !ok {
		val = "<masked>"
	}
	return prefix + key + "=" + val, true
}

// admitted is msg as kept, its value fields judged, or false when no shape of
// the platform admits it.
func (f deviceDebugFilter) admitted(platform, msg string) (string, bool) {
	for _, sh := range ddShapes[platform] {
		idx := sh.re.FindStringSubmatchIndex(msg)
		if idx == nil {
			continue
		}
		// Replace from the last field back, so earlier offsets stay right.
		for g := len(sh.kinds) - 1; g >= 0; g-- {
			a, b := idx[2*g+2], idx[2*g+3]
			if a < 0 {
				continue
			}
			if sh.kinds[g] == 'n' {
				msg = msg[:a] + "<n>" + msg[b:]
				continue
			}
			if f.allowed(sh.kinds[g], msg[a:b]) {
				continue
			}
			msg = msg[:a] + "<masked>" + msg[b:]
		}
		return msg, true
	}
	return "", false
}

// allowed reports whether v, a field of kind, is one of the lab's values.
func (f deviceDebugFilter) allowed(kind byte, v string) bool {
	switch kind {
	case 'i':
		a, err := netip.ParseAddr(v)
		return err == nil && slices.ContainsFunc(f.Addrs, func(x netip.Addr) bool { return x.Unmap() == a.Unmap() })
	case 'g':
		return v == "" || slices.Contains(f.Groups, v)
	case 'l':
		return slices.Contains(deviceDebugLists, v)
	case 'm':
		return slices.Contains(nxosDebugMethods, v)
	case 'u':
		return deviceDebugUser.MatchString(v)
	}
	return false // 'x': an opaque id is never kept
}

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
	SingleConnect        int // lines showing single-connect negotiated or its flag
	ServerDead, Fallback int // server-dead and fallback lines
}

// deviceDebugSummarize reads the counters out of kept, which Keep has already
// filtered, in order: a request belongs to the connection open at that line.
func deviceDebugSummarize(platform string, kept deviceDebugKept) deviceDebugSummary {
	var s deviceDebugSummary
	p := deviceDebugProfiles[platform]
	if p == nil || kept == "" {
		return s
	}
	cur := -1 // the index in s.Conns of the connection requests go to
	ensure := func() {
		if cur < 0 {
			s.Conns = append(s.Conns, deviceDebugConn{})
			cur = len(s.Conns) - 1
		}
	}
	for _, ln := range strings.Split(string(kept), "\n") {
		at, msg, _ := strings.Cut(ln, " ")
		// Cut the process name off a `time proc: message` line.
		if proc, rest, ok := strings.Cut(msg, ": "); ok && !strings.Contains(proc, " ") && p.line.SubexpIndex("p") > 0 {
			msg = rest
		}
		switch {
		case p.open.MatchString(msg):
			s.Opened++
			s.Conns = append(s.Conns, deviceDebugConn{Opened: at})
			cur = len(s.Conns) - 1
		case p.closed.MatchString(msg):
			s.Closed++
			ensure()
			s.Conns[cur].Closed = at
			if m := p.closed.FindStringSubmatch(msg); m != nil {
				s.Conns[cur].Reason = m[1]
			}
			cur = -1
		case p.authen.MatchString(msg):
			ensure()
			s.Conns[cur].Authen++
		case p.author.MatchString(msg):
			ensure()
			s.Conns[cur].Author++
		case p.acct.MatchString(msg):
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
		Enable: []string{"clear log p49-tacplus.log", "configure",
			"set system processes general-authentication-service traceoptions file p49-tacplus.log",
			"set system processes general-authentication-service traceoptions flag all", "commit and-quit"},
		Disable: []string{"configure", "delete system processes general-authentication-service traceoptions", "commit and-quit",
			"clear log p49-tacplus.log"},
		Collect: []string{"show log p49-tacplus.log"},
	},
}

// captureDeviceDebug turns the platform's debug on, runs during (the cell
// under measurement), collects the debug text and turns debug off again. The
// debug is collected and debug turned off even when during or a step fails: it
// is wanted most when a cell goes wrong. run sends one line to the device and
// returns its output. The collected text is filtered here, in-process: the raw
// text is never returned, so a caller cannot write it to disk. An error from
// run can hold the device's output (a prompt timeout prints the whole tail),
// so each is replaced by ddWrap's text; during's error is the caller's own and
// is returned first, unchanged.
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
	var collectErr error
	for _, c := range cmds.Collect {
		raw, err := run(c)
		// A partial capture is kept, filtered like the rest.
		if k := string(f.Keep(raw)); k != "" {
			kept = append(kept, k)
		}
		if err != nil && collectErr == nil {
			collectErr = ddWrap(c, err)
		}
	}
	disableErr := disableDeviceDebug(cmds, run)
	err := cellErr
	if err == nil {
		err = collectErr
	}
	if err == nil {
		err = disableErr
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
