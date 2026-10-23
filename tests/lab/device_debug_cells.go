package lab

import (
	"fmt"
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
	case cmd == "clear logging":
		return []string{prompt, "[confirm]"}, false
	}
	return []string{prompt}, false
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
	fmt.Fprintf(&b, "debug connections opened=%d closed=%d single_connect_lines=%d server_dead_lines=%d fallback_lines=%d\n",
		s.Opened, s.Closed, s.SingleConnect, s.ServerDead, s.Fallback)
	for i, c := range s.Conns {
		open, closed := c.Opened, c.Closed
		if open == "" {
			open = "before"
		}
		if closed == "" {
			closed = "open"
		}
		fmt.Fprintf(&b, "  debug conn %d: opened=%s closed=%s reason=%q authen=%d author=%d acct=%d\n",
			i+1, open, closed, c.Reason, c.Authen, c.Author, c.Acct)
	}
	pipel := 0
	for _, c := range s.Conns {
		if n := c.Authen + c.Author + c.Acct; n > 1 {
			pipel++
		}
	}
	fmt.Fprintf(&b, "connections that carried more than one request: %d of %d (a count of requests per connection, not of "+
		"writes without a read between them: the kept lines do not order those)\n", pipel, len(s.Conns))
	return b.String()
}

var (
	ddArmDrop = regexp.MustCompile(`(?i)password|passwd|pass|pwd|key|token|secret|eyJ|payload|challenge|response|nonce|signature|cred|hash|md5|sha`)
	ddArmLong = regexp.MustCompile(`[A-Za-z0-9_+/=.-]{24,}`)
	// ddArmHot marks the lines a sample lists first: the ones about the exchange.
	ddArmHot    = regexp.MustCompile(`(?i)tac|server|connect|session|request|reply|socket|ssl|tls|author|account|single`)
	ddArmHexish = regexp.MustCompile(`[0-9A-Fa-f]{8,}`)
	ddArmDigits = regexp.MustCompile(`[0-9]+`)
	ddArmWord   = regexp.MustCompile(`[A-Za-z][A-Za-z_-]*`)
)

// ddArmSample is a shape sample of raw device text, for the case where the
// filter keeps nothing and the line shapes must be learned: lines with a
// secret word are dropped, long and hex runs and every number are masked, and
// every word outside the shapes' own vocabulary (anything not a lowercase
// word of at most 12 letters) is masked. Lines about the exchange come first, repeated shapes once. At most max lines come back. It is
// the only function that sees the raw text beside captureDeviceDebug, and
// it returns shapes, never values.
func ddArmSample(raw string, max int) []string {
	var hot, cold []string
	seen := map[string]bool{}
	for _, ln := range strings.Split(strings.ReplaceAll(raw, "\r", ""), "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || ddArmDrop.MatchString(ln) {
			continue
		}
		interesting := ddArmHot.MatchString(ln)
		ln = ddArmLong.ReplaceAllString(ln, "\x01")
		ln = ddArmHexish.ReplaceAllString(ln, "\x02")
		ln = ddArmDigits.ReplaceAllString(ln, "\x03")
		ln = ddArmWord.ReplaceAllStringFunc(ln, func(w string) string {
			if len(w) > 12 || w != strings.ToLower(w) {
				return "W"
			}
			return w
		})
		ln = strings.NewReplacer("\x01", "<LONG>", "\x02", "<HEX>", "\x03", "N").Replace(ln)
		if len(ln) > 160 {
			ln = ln[:160]
		}
		if seen[ln] {
			continue
		}
		seen[ln] = true
		if interesting {
			hot = append(hot, ln)
		} else {
			cold = append(cold, ln)
		}
	}
	out := append(hot, cold...)
	if len(out) > max {
		out = out[:max]
	}
	return out
}
