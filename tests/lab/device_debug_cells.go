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
	// ddArmHot marks the lines a sample lists first: the ones about the exchange.
	ddArmHot   = regexp.MustCompile(`(?i)tac|server|connect|session|request|reply|socket|ssl|tls|author|account|single`)
	ddArmIP4   = regexp.MustCompile(`[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]+)?`)
	ddArmAlnum = regexp.MustCompile(`[A-Za-z0-9]+`)
)

// ddArmVocab is the closed list of protocol and verb words a sample may keep.
// It is written here and never derived from device output; a run that is not
// exactly one of these (ignoring case) is not kept.
var ddArmVocab = map[string]bool{}

func init() {
	for _, w := range strings.Fields(`tac tacacs tplus connect connected connection socket server opened open closed close
		secure message type request reply send sent receive received queued processed processing created start started
		queuing timeout tls ssl session author authorization authentication accounting aaa group list method status error failed
		fail ok up down established peer port host address bind bound immediate new no not is are the to from for on in
		of and with by set get has was using previously default handle name addr id fd vrf timer expired unavailable
		available detected thread sleeping seconds sec debug auth login packet create destroy free alloc state
		transaction transactions tty cmd arg service shell exec`) {
		ddArmVocab[w] = true
	}
}

// ddArmClass is what one alphanumeric run becomes in a sample: itself if it is
// exactly a vocabulary word, otherwise a class token with no value character in
// it: N for digits only, w for letters only, x for letters and digits mixed.
func ddArmClass(run string) string {
	if ddArmVocab[strings.ToLower(run)] {
		return run
	}
	letters, digits := false, false
	for _, r := range run {
		if r >= '0' && r <= '9' {
			digits = true
		} else {
			letters = true
		}
	}
	switch {
	case letters && digits:
		return "x"
	case letters:
		return "w"
	}
	return "N"
}

// ddArmSample is a shape sample of raw device text, for the case where the
// filter keeps nothing and the line shapes must be learned. A line with a
// secret word is dropped. In the others an IPv4 address becomes A, and every
// alphanumeric run becomes a class token (ddArmClass) unless the whole run is
// a word of the fixed vocabulary ddArmVocab, so no letter or digit of any
// value (user, host, group, secret, hex byte) survives; punctuation stays.
// Lines about the exchange come first and a repeated shape is listed once. At
// most max lines come back, cut to 160 characters.
func ddArmSample(raw string, max int) []string {
	var hot, cold []string
	seen := map[string]bool{}
	for _, ln := range strings.Split(strings.ReplaceAll(raw, "\r", ""), "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || ddArmDrop.MatchString(ln) {
			continue
		}
		interesting := ddArmHot.MatchString(ln)
		ln = ddArmIP4.ReplaceAllString(ln, "\x01")
		ln = ddArmAlnum.ReplaceAllStringFunc(ln, ddArmClass)
		ln = strings.ReplaceAll(ln, "\x01", "A")
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
