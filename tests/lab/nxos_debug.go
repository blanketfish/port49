package lab

import (
	"net/netip"
	"regexp"
	"strings"
)

// NX-OS debug capture (L80; spec §13 decision 50 ruling 20). `debug
// tacacs+ all` and `debug aaa` write the request, the reply and the
// credential into the device's debug logfile, so nothing from that file is
// kept as it is. nxosDebugKeep filters each line before anything reaches
// disk, in this order:
//
//  1. Drop the line if it holds a secret word (nxosDebugSecret: payload
//     lines are the packet body) or a hex run (nxosDebugHexRun: eight or
//     more space-separated bytes, or sixteen contiguous hex digits). The
//     line is dropped, never masked.
//  2. Mask every run of 24 or more token characters as <LONG>.
//  3. Keep the line only if one anchored pattern of nxosDebugAllow admits
//     it. A pattern admits a count, an address, a status or a request kind,
//     never a free-text field, so a new debug line that carries a body is
//     lost rather than kept.
//  4. An avstr= line keeps its key only for service, cmd, cmd-arg and
//     priv-lvl; a cmd or cmd-arg value only when it is one word of
//     nxosDebugWords, and a service or priv-lvl value only when it is one
//     word of at most 16 characters; any other value is written <masked>.
//     An address field is kept only if it parses as an address. A typed secret
//     (`username x password s`) arrives as cmd-arg=password, then
//     cmd-arg=s, and the secret-word rule catches only the first.
//
// No body byte is decoded, and no line is kept unfiltered.

// The L80 sequences (design Task 7, lab step 2). A sequence that types a new
// word adds it to nxosDebugWords in the same commit
// (TestNXOSDebugSequencesUseOnlyListedWords), so the harness never depends
// on the lab typing only safe commands.
var (
	// nxosSeqS1 and nxosSeqS3 are the A/B's s1 and s3.
	nxosSeqS1 = []string{"terminal length 0", "show version", "show users", "show clock", "show users"}
	nxosSeqS3 = []string{"terminal length 0", "configure terminal", "hostname nx1", "end", "show users"}
	// nxosSeqE1 is arm E's sequence 1, which the concurrent-sessions cell
	// runs in each CLI session, followed by `show users`.
	nxosSeqE1 = []string{"terminal length 0", "show clock", "terminal length 0", "show clock", "show version",
		"configure terminal", "hostname nx1", "hostname nx1", "end", "show clock", "show users"}
	// nxosSeqSpacing is the A/B's sp step: `terminal length 0`, a gap, then
	// `show users`. The idle-boundary cell runs it with its own gaps.
	nxosSeqSpacing = []string{"terminal length 0", "show users"}
)

// nxosDebugWords are the only cmd and cmd-arg values kept: the sequences'
// own words, and <cr>.
var nxosDebugWords = []string{"show", "users", "version", "clock", "terminal", "length", "0", "configure",
	"hostname", "nx1", "end", "<cr>"}

var (
	// nxosDebugLine is `HH:MM:SS.ffffff process: message`, the shape of a
	// logfile line once its date prefix is cut.
	nxosDebugLine = regexp.MustCompile(`(\d\d:\d\d:\d\d\.\d+) (tacacsd|aaad): (.*)$`)
	// nxosDebugSecret drops a line outright: a credential word, a JWT
	// prefix, or any payload line (`in tac payload(hex): ...`), whose hex is
	// the packet body. The extra words cost nothing: no pattern below
	// admits them.
	nxosDebugSecret = regexp.MustCompile(`(?i)password|token|secret|eyJ|payload|passwd|challenge|nonce|signature`)
	// nxosDebugHexRun is eight or more space-separated hex bytes (NX-OS
	// prints them without a leading zero), or sixteen or more contiguous
	// hex digits.
	nxosDebugHexRun = regexp.MustCompile(`(?i)(^|\s)([0-9a-f]{1,2}\s+){7}[0-9a-f]{1,2}(\s|$)|[0-9a-f]{16,}`)
	nxosDebugLong   = regexp.MustCompile(`[A-Za-z0-9_+/=.-]{24,}`)
	nxosDebugANSI   = regexp.MustCompile(`\x1b\[[0-9;?]*[A-Za-z]|\r`)
	// nxosDebugAvstr is an attribute line; its key and value are judged by
	// nxosDebugAV.
	nxosDebugAvstr = regexp.MustCompile(`^avstr=([A-Za-z0-9_-]+)=(.*)$`)
	// nxosDebugWord is a service or priv-lvl value kept as it is: one short
	// word. Anything longer is <masked>, whatever its key.
	nxosDebugWord = regexp.MustCompile(`^[A-Za-z0-9_-]{1,16}$`)
)

// nxosDebugAllow are the anchored shapes a kept line may have, after the
// drop and mask rules. ip is an address, and the only capturing group: each
// one must parse as an address (netip.ParseAddr), so colon-separated hex of
// any other kind is dropped. n is a count; fn a function name the mask may
// have cut to <LONG>.
var nxosDebugAllow = func() []*regexp.Regexp {
	const ip, n, fn = "\x01", `-?\d+`, `(<LONG>: )?`
	shapes := []string{
		// Request construction: the type and counts, never the user.
		`construct_tac_req(\(` + n + `\))?:? ?(aaa session id: ` + n + `, )?aaa type: ` + n +
			`(, user_len=` + n + `)?(, av_count_net=` + n + `)?(, av_count_host=` + n + `)?`,
		`construct_tac_req: (entering|exiting) for aaa session id: ` + n,
		// Socket writes and reads.
		`nxos_ssl_write: ?sending ` + n + ` bytes to ` + ip + ` port ` + n + ` on socket ` + n,
		fn + `before calling nxos_ssl_write\(\) total length ` + n,
		fn + `nxos_ssl_read\(\) for server ` + ip + ` on socket ` + n,
		fn + `nxos_ssl_read\(\) for server ` + ip + ` group [A-Za-z0-9_-]* aaa session id: ` + n + ` recv_bytes_left ` + n,
		fn + `nxos_ssl_read\(\) failed for socket ` + n + `\.?`,
		// Named counters only, at most four: a run of word=decimal fields
		// could spell anything.
		`non_blocking_(read|write)(\(` + n + `\))?:?( (socket|sock|sock_fd|fd|len|length|bytes|rc|ret|errno)[ =:]*-?\d{1,10},?){0,4}`,
		`before nxos_ssl_open +hostname ` + ip + ` server ` + ip + ` on port ` + n + ` vrf ` + n,
		`after nxos_ssl_open rc ` + n,
		`nxos_ssl_(open success|open failed|retry_open)`,
		// Connections, and their reuse.
		`connect_tac_server(\(` + n + `\))?: connection is Active/connect succeeded +! socket\(` + n + `\)`,
		`connect_tac_server(\(` + n + `\))?:Entering for aaa session id: ` + n,
		`connect_tac_server: exiting for aaa session id: ` + n,
		`connect_tac_server:` + n + ` current server servername ` + ip + ` ` + n + ` port ` + n + ` ssl_enable ` + n,
		`connect_tac_server:` + n + ` tplus_sm->ssl_enable ` + n,
		`connect_tac_server: tplus_do_ssl_connect failed, switching server for aaa session id\(` + n + `\) rtvalue\(` + n + `\)`,
		`clean_up_sock_sm_node: (socket ` + n + ` is_ssl_socket ` + n + `|freeing ssl_ctx for sock_fd ` + n + `|return Successfully)`,
		// The server marked dead.
		`clean_up_sock_sm_node(\(` + n + `\))?: mark server\(` + ip + `\) dead`,
		`aaa_mark_server_dead ` + n,
		`aaa_mark_server_dead : +Idle time is ` + n + `\. Server will not be monitored`,
		// What fell back, and to what.
		`Fall back method [a-z]+ (succeeded|failed)`,
		`Sending request to (TACACS|LOCAL) service`,
		`protocol TACACS failed with server group [A-Za-z0-9_-]+`,
		`LOCAL method not supported for (Authorization|Authentication|Accounting) req [a-z_]+:[A-Za-z0-9_-]+`,
		`(TACACS|LOCAL|group [A-Za-z0-9_-]+) method (not supported|failed|succeeded) for (Authorization|Authentication|Accounting) req [a-z_]+:[A-Za-z0-9_-]+`,
		// The fixed-shape response lines: a request kind and a status.
		`(aaad: )?response for (accounting|authorization|authentication) request of (old|new) library will be sent as (SUCCESS|FAILURE|ERROR)`,
		`(aaad: )?response status[ :=]+(SUCCESS|FAIL|FAILURE|ERROR|PASS_ADD|PASS_REPL|PASS)`,
	}
	out := make([]*regexp.Regexp, len(shapes))
	for i, s := range shapes {
		out[i] = regexp.MustCompile(`^` + strings.ReplaceAll(nxosNonCapturing(s), ip, `([0-9A-Fa-f.:]{2,39})`) + `$`)
	}
	return out
}()

// nxosNonCapturing makes every group of s non-capturing, so the only
// capturing groups are the addresses put in after it.
func nxosNonCapturing(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		b.WriteByte(s[i])
		if s[i] == '(' && (i == 0 || s[i-1] != '\\') && (i+1 >= len(s) || s[i+1] != '?') {
			b.WriteString("?:")
		}
	}
	return b.String()
}

// nxosDebugAV is an avstr= message as kept, or false to drop it: service
// and priv-lvl keep a one-word value, cmd and cmd-arg keep a listed word,
// and any other value is <masked>. Any other key drops the line.
func nxosDebugAV(msg string) (string, bool) {
	m := nxosDebugAvstr.FindStringSubmatch(msg)
	if m == nil {
		return "", false
	}
	key, val := m[1], m[2]
	switch key {
	case "service", "priv-lvl":
		if !nxosDebugWord.MatchString(val) {
			val = "<masked>"
		}
	case "cmd", "cmd-arg":
		ok := false
		for _, w := range nxosDebugWords {
			ok = ok || val == w
		}
		if !ok {
			val = "<masked>"
		}
	default:
		return "", false
	}
	return "avstr=" + key + "=" + val, true
}

// nxosDebugKeep is text (the contents of `show debug logfile`) cut to the
// lines the rules above keep, one per line, in the form `time process:
// message`.
func nxosDebugKeep(text string) string {
	var out []string
	for _, ln := range strings.Split(nxosDebugANSI.ReplaceAllString(text, ""), "\n") {
		m := nxosDebugLine.FindStringSubmatch(ln)
		if m == nil || nxosDebugSecret.MatchString(ln) || nxosDebugHexRun.MatchString(ln) {
			continue
		}
		// An avstr= line is judged by key before the mask, which would
		// otherwise swallow `avstr=key=` with its value; a long value is
		// masked all the same, since no listed word is long.
		msg := strings.TrimSpace(m[3])
		if strings.HasPrefix(msg, "avstr=") {
			var ok bool
			if msg, ok = nxosDebugAV(msg); !ok {
				continue
			}
		} else if msg = nxosDebugLong.ReplaceAllString(msg, "<LONG>"); !nxosDebugAdmitted(msg) {
			continue
		}
		out = append(out, m[1]+" "+m[2]+": "+msg)
	}
	return strings.Join(out, "\n")
}

func nxosDebugAdmitted(msg string) bool {
	for _, re := range nxosDebugAllow {
		m := re.FindStringSubmatch(msg)
		if m == nil {
			continue
		}
		for _, addr := range m[1:] {
			if _, err := netip.ParseAddr(addr); err != nil {
				return false
			}
		}
		return true
	}
	return false
}

// nxosDebugCounts is the number of kept lines containing each marker, over
// text already passed through nxosDebugKeep.
func nxosDebugCounts(kept string) map[string]int {
	counts := map[string]int{}
	for _, ln := range strings.Split(kept, "\n") {
		for name, re := range nxosDebugMarkers {
			if re.MatchString(ln) {
				counts[name]++
			}
		}
	}
	return counts
}

// nxosDebugMarkers are the L80 measures, plus the request types by number
// and the TLS socket calls.
var nxosDebugMarkers = map[string]*regexp.Regexp{
	"ssl_read_failed":     regexp.MustCompile(`nxos_ssl_read\(\) failed`),
	"mark_server_dead":    regexp.MustCompile(`mark server\(.*\) dead`),
	"fall_back_none":      regexp.MustCompile(`Fall back method none`),
	"tacacs_group_failed": regexp.MustCompile(`protocol TACACS failed with server group`),
	"connection_active":   regexp.MustCompile(`connection is Active`),
	"request_authen":      regexp.MustCompile(`aaa type: *1\b`),
	"request_author":      regexp.MustCompile(`aaa type: *2\b`),
	"request_acct":        regexp.MustCompile(`aaa type: *3\b`),
	"ssl_open_success":    regexp.MustCompile(`nxos_ssl_open success`),
}

// nxosFallback is one `Fall back method` line with what preceded it in the
// kept debug: the request it belongs to (from the last `aaa type` line, its
// allowed avstr= lines included) through the fallback, so each can be
// attributed (lab step 2: what was authorized, and whether it ran on the
// fallback).
type nxosFallback struct {
	At      string   // the device's own time
	Line    string   // the fallback line
	Before  string   // the line just before it
	Context []string // from the request's aaa type line through Before
}

// nxosFallbacks reads every fallback out of kept, which nxosDebugKeep has
// already filtered.
func nxosFallbacks(kept string) []nxosFallback {
	lines := strings.Split(kept, "\n")
	var out []nxosFallback
	start := -1
	for i, ln := range lines {
		if strings.Contains(ln, "aaa type:") {
			start = i
		}
		if !strings.Contains(ln, "Fall back method") {
			continue
		}
		f := nxosFallback{Line: ln}
		if at, _, ok := strings.Cut(ln, " "); ok {
			f.At = at
		}
		if i > 0 {
			f.Before = lines[i-1]
		}
		from := start
		if from < 0 || from >= i {
			from = max(0, i-1)
		}
		f.Context = append([]string(nil), lines[from:i]...)
		out = append(out, f)
	}
	return out
}
