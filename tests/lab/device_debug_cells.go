package lab

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

// The device-debug arm (task 8): the TLS cells of a re-vet run with the
// platform's own TACACS+ debug on, to count whether the device pipelines a
// second request on one connection before reading the reply. Everything the
// arm writes passes deviceDebugFilter.Keep first; the raw collect text lives
// in captureDeviceDebug and in ddArmSample only.

// ddArmPlatform is the deviceDebugProfiles key for an l73Dialect family.
func ddArmPlatform(family string) (string, bool) {
	switch family {
	case "eos":
		return "eos", true
	case "xr":
		return "iosxr", true
	case "iosxe":
		return "iosxe", true
	case "junos":
		return "junos", true
	}
	return "", false
}

// ddArmWait is the prompts that end command cmd, and whether the session is in
// configuration mode after it. Junos moves between its operational prompt and
// its configuration prompt (a commit leaves configuration mode); IOS XE and IOS
// XR ask to confirm `clear logging`.
func ddArmWait(platform, cmd string, cfgMode bool, prompt string) (wait []string, cfgAfter bool) {
	switch {
	case platform == "junos" && cmd == "configure":
		return []string{"# "}, true
	case platform == "junos" && cmd == "commit and-quit":
		return []string{"> "}, false
	case platform == "junos" && cfgMode:
		return []string{"# "}, true
	case platform == "junos":
		return []string{"> "}, false
	case platform == "eos" && cmd == "configure":
		return []string{")#"}, true
	case platform == "eos" && cmd == "end":
		return []string{prompt}, false
	case platform == "eos" && cfgMode:
		return []string{")#"}, true
	case cmd == "clear logging":
		return []string{prompt, "[confirm]"}, false
	}
	return []string{prompt}, false
}

// ddArmMasterName is the name of a TestQualify run's master capture. An armed
// run (device debug on) must never write the QUAL-<firmware> master that a
// committed re-vet's evidence is audited against, so it writes a QUAL-DEBUG one.
func ddArmMasterName(slug string, armed bool) string {
	if armed {
		return "QUAL-DEBUG-" + slug
	}
	return "QUAL-" + slug
}

// ddArmLineCount is the number of lines in kept.
func ddArmLineCount(kept deviceDebugKept) int {
	if kept == "" {
		return 0
	}
	return strings.Count(string(kept), "\n") + 1
}

// ddArmSummary is the cell's summary text: counts and connection facts from
// the kept lines, and the header-only TLS connection lines the caller made.
// rawLines is how many lines the device returned, so a filter that keeps
// nothing is visible as such.
func ddArmSummary(platform, cell string, kept deviceDebugKept, rawLines int, tlsConns []string) string {
	s := deviceDebugSummarize(platform, kept)
	var b strings.Builder
	fmt.Fprintf(&b, "device debug arm, platform %s, cell %s\n", platform, cell)
	fmt.Fprintf(&b, "device returned %d log lines in all; the filter kept %d of the cell's\n", rawLines, ddArmLineCount(kept))
	fmt.Fprintf(&b, "tls connections (header-only capture): %d\n", len(tlsConns))
	for _, l := range tlsConns {
		b.WriteString("  " + l + "\n")
	}
	// A platform whose debug has no close line says so: a count of 0 would read
	// as "none closed".
	closedAll := fmt.Sprint(s.Closed)
	if s.CloseUnknown {
		closedAll = "unknown"
	}
	fmt.Fprintf(&b, "debug connections opened=%d closed=%s single_connect_lines=%d server_dead_lines=%d fallback_lines=%d\n",
		s.Opened, closedAll, s.SingleConnect, s.ServerDead, s.Fallback)
	if s.Failed > 0 {
		fmt.Fprintf(&b, "debug connections failed_opens=%d\n", s.Failed)
	}
	for i, c := range s.Conns {
		open, closed := c.Opened, c.Closed
		if open == "" {
			open = "before"
		}
		if closed == "" {
			closed = "open"
		}
		if s.CloseUnknown {
			closed = "unknown"
		}
		fmt.Fprintf(&b, "  debug conn %d: opened=%s closed=%s reason=%q authen=%d author=%d acct=%d\n",
			i+1, open, closed, c.Reason, c.Authen, c.Author, c.Acct)
	}
	if s.CloseUnknown {
		b.WriteString("note: this platform's two debug files are joined in order, not merged by time, so a request is " +
			"attributed to the last connection opened in the trace, not necessarily the one it was sent on\n")
	}
	pipel := 0
	for _, c := range s.Conns {
		if n := c.Total(); n > 1 {
			pipel++
		}
	}
	fmt.Fprintf(&b, "connections that carried more than one request: %d of %d (a count of requests per connection, not of "+
		"writes without a read between them: the kept lines do not order those)\n", pipel, len(s.Conns))
	return b.String()
}

var (
	ddArmDrop = regexp.MustCompile(`(?i)password|passwd|pass|pwd|key|token|secret|eyJ|payload|challenge|response|nonce|signature|cred|hash|md5|sha`)
	// ddArmHot marks the lines a sample lists first: the ones about the exchange.
	ddArmHot = regexp.MustCompile(`(?i)tac|server|connect|session|request|reply|socket|ssl|tls|author|account|single`)
	// ddArmAddr finds the spans that may be an IPv4 or IPv6 address; netip
	// decides.
	ddArmAddr = regexp.MustCompile(`[0-9A-Fa-f:.]*[0-9A-Fa-f:][0-9A-Fa-f:.]*`)
)

// ddArmWords is the closed vocabulary of a sample: protocol and verb words,
// written here and never derived from device output. Each is lowercase ASCII
// letters, three or more, and not made only of hex digits (a hex byte pair or
// word must never be kept); TestDeviceDebugArmVocabularyIsClosed enforces it.
const ddArmWords = `tac tacacs tplus connect connected connection socket server opened open closed close secure message
	type request reply send sent receive received queued queuing processed processing created start started timeout
	tls ssl tcp session author authorization authentication accounting group list method status error failed fail
	established peer port host address bind bound immediate new not the and for are has was with from using
	previously default handle name addr timer expired unavailable available detected thread sleeping seconds debug
	auth login packet create destroy free alloc state transaction transactions cmd arg service shell exec
	tacacsd tacplus authd invalid syntax`

var ddArmVocab = map[string]bool{}

func init() {
	for _, w := range strings.Fields(ddArmWords) {
		ddArmVocab[w] = true
	}
}

// ddArmSample is a shape sample of raw device text, for the case where the
// filter keeps nothing and the line shapes must be learned. Its output alphabet
// is closed. A line holding a secret word (ddArmDrop) is dropped. In the others
// the output is tokens joined by single spaces, each one of: a word of the fixed
// vocabulary ddArmVocab, matched case-insensitively as a whole ASCII alphanumeric
// run and written lowercase; A, for an IPv4 or IPv6 address; or _, for every
// other maximal span of the input (an unknown word, a number, punctuation, a
// non-ASCII character or a raw byte, with the spaces between them). No character
// of any value is ever copied: the output is only [a-z], A, _ and space. "TAC+:
// Opened TCP/IP handle 0x1F to 10.149.0.2/49" becomes "tac _ opened tcp _ handle
// _ to A _". Lines about the exchange come first and a repeated line is listed
// once. At most max lines come back, cut to 160 characters on a token boundary.
// Hot or cold is decided on the output, not the raw line.
func ddArmSample(raw string, max int) []string {
	var hot, cold []string
	seen := map[string]bool{}
	for _, ln := range strings.Split(raw, "\n") {
		if ddArmDrop.MatchString(ln) {
			continue
		}
		out := ddArmTokens(ln)
		if out == "" {
			continue
		}
		if len(out) > 160 {
			// Cut on a token boundary: a partial last token is dropped.
			if out[160] == ' ' {
				out = out[:160]
			} else if i := strings.LastIndexByte(out[:160], ' '); i >= 0 {
				out = out[:i]
			} else {
				out = out[:160]
			}
		}
		if seen[out] {
			continue
		}
		seen[out] = true
		if ddArmHot.MatchString(out) {
			hot = append(hot, out)
		} else {
			cold = append(cold, out)
		}
	}
	res := append(hot, cold...)
	if len(res) > max {
		res = res[:max]
	}
	return res
}

// ddArmTokens turns one line into the closed alphabet (see ddArmSample).
func ddArmTokens(ln string) string {
	var out []string
	other := false
	emit := func(tok string) {
		if other {
			out = append(out, "_")
			other = false
		}
		out = append(out, tok)
	}
	isAlnum := func(c byte) bool {
		return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
	}
	// text scans a stretch holding no address: alphanumeric runs and the gaps.
	text := func(t string) {
		for i := 0; i < len(t); {
			j := i
			if isAlnum(t[i]) {
				for j < len(t) && isAlnum(t[j]) {
					j++
				}
				if w := strings.ToLower(t[i:j]); ddArmVocab[w] {
					emit(w)
				} else {
					other = true
				}
			} else {
				for j < len(t) && !isAlnum(t[j]) {
					j++
				}
				if strings.Trim(t[i:j], " \t") != "" {
					other = true
				}
			}
			i = j
		}
	}
	at := 0
	for _, m := range ddArmAddr.FindAllStringIndex(ln, -1) {
		s, e := m[0], m[1]
		if s > 0 && isAlnum(ln[s-1]) || e < len(ln) && isAlnum(ln[e]) {
			continue
		}
		if _, err := netip.ParseAddr(ln[s:e]); err != nil {
			continue
		}
		text(ln[at:s])
		emit("A")
		at = e
	}
	text(ln[at:])
	if other {
		out = append(out, "_")
	}
	return strings.Join(out, " ")
}

// ddArmCountLines is the number of device log lines in a command's output: the
// echoed command and the prompt lines are not the device's log.
func ddArmCountLines(out, cmd string, prompts ...string) int {
	n := 0
	for _, ln := range strings.Split(strings.ReplaceAll(out, "\r", ""), "\n") {
		t := strings.TrimSpace(ln)
		if t == "" || t == cmd {
			continue
		}
		prompt := false
		for _, p := range prompts {
			prompt = prompt || (p != "" && strings.HasSuffix(t, strings.TrimSpace(p)))
		}
		if !prompt {
			n++
		}
	}
	return n
}

// ddArmIsCollect is whether cmd is one of the platform's collect commands,
// whose output is the debug text (sampled), not an enable or disable answer.
func ddArmIsCollect(platform, cmd string) bool {
	for _, c := range deviceDebugCmds[platform].Collect {
		if c == cmd {
			return true
		}
	}
	return false
}
