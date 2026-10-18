package lab

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/rhwendt/port49/tests/lab/labcreds"
)

var optionWord = regexp.MustCompile(`^[a-z][a-z0-9-]{0,23}$`)

// l71Probe is how one platform's CLI is asked whether it has an RFC 9887
// client: lines typed to reach the right mode, the help request typed
// without a newline (so nothing is configured by it), and the words that
// mean "yes" in the help it prints. cleanup leaves nothing configured, and
// runs on every path: IOS-XE's `tacacs server l71probe` creates its server
// object as it is entered (IOS has no commit), and cleanup's
// `no tacacs server l71probe` removes it.
//
// control is what makes an absence a finding. The probe measures that a
// word is missing from the help, so it must first know the help was the
// real thing: a help that lacks every control word (an option the client
// has always had) is a timeout, a wrong mode or an error, and the run is
// INVALID rather than a negative. snapshot is a command whose output is
// compared before and after, to show the probe left the TACACS+
// configuration as it found it; its output is never written to a note.
// cfgMark is a substring of every prompt in configuration mode on that
// platform; opMark is the operational prompt, or "" for the CLI's own
// idle prompt.
type l71Probe struct {
	enter    []string
	ask      []string // each typed, then "?" with no newline, then Ctrl-U
	yes      []string
	control  []string
	cleanup  []string
	snapshot string
	cfgMark  string
	opMark   string
}

var l71Probes = map[string]l71Probe{
	"arista_eos": {enter: []string{"configure"}, ask: []string{"tacacs-server host 192.0.2.71 "},
		yes: []string{"ssl-profile", "tls"}, control: []string{"key", "port", "timeout"}, cleanup: []string{"end"},
		snapshot: "show running-config | include tacacs", cfgMark: "(config"},
	"cisco_iosxe": {enter: []string{"configure terminal", "tacacs server l71probe"}, ask: []string{""},
		yes: []string{"tls"}, control: []string{"address", "key", "port", "timeout"},
		cleanup:  []string{"exit", "no tacacs server l71probe", "end"},
		snapshot: "show running-config | include tacacs", cfgMark: "(config"},
	"cisco_nxos": {enter: []string{"configure terminal"}, ask: []string{"tacacs-server host 192.0.2.71 ", "tacacs-server "},
		yes: []string{"tls", "secure"}, control: []string{"key", "port", "timeout"}, cleanup: []string{"end"},
		snapshot: "show running-config | include tacacs", cfgMark: "(config"},
	"juniper_vjunos-router": {enter: []string{"configure"}, ask: []string{"set system tacplus-server 192.0.2.71 "},
		yes: []string{"tls"}, control: []string{"secret", "port", "timeout"},
		cleanup:  []string{"rollback 0", "exit configuration-mode"},
		snapshot: "show configuration system tacplus-server | display set", cfgMark: "# ", opMark: "> "},
	"juniper_vsrx": {enter: []string{"configure"}, ask: []string{"set system tacplus-server 192.0.2.71 "},
		yes: []string{"tls"}, control: []string{"secret", "port", "timeout"},
		cleanup:  []string{"rollback 0", "exit configuration-mode"},
		snapshot: "show configuration system tacplus-server | display set", cfgMark: "# ", opMark: "> "},
	// cEOS runs EOS's parser: vEOS's question, asked of the cEOS 4.36.3M row
	// (TestL73, ceos436).
	"arista_ceos": {enter: []string{"configure"}, ask: []string{"tacacs-server host 192.0.2.71 "},
		yes: []string{"ssl-profile", "tls"}, control: []string{"key", "port", "timeout"}, cleanup: []string{"end"},
		snapshot: "show running-config | include tacacs", cfgMark: "(config"},
	// IOL-XE runs IOS XE's parser: the C8000V question, asked of the L71
	// help cell's IOL row (TestL73, iolxe1718).
	"cisco_iol-xe": {enter: []string{"configure terminal"}, ask: []string{"tacacs-server host 192.0.2.71 "},
		yes: []string{"tls"}, control: []string{"key", "port", "timeout"},
		cleanup:  []string{"end"},
		snapshot: "show running-config | include tacacs", cfgMark: "(config"},
	// XR: `abort` leaves configuration mode with nothing committed.
	"cisco_xrd": {enter: []string{"configure"}, ask: []string{"tacacs-server host 192.0.2.71 "},
		yes: []string{"tls"}, control: []string{"key", "port", "timeout"}, cleanup: []string{"abort"},
		snapshot: "show running-config tacacs-server", cfgMark: "(config"},
}

// l71Says reports whether help, a CLI's answer to "?", lists one of yes as
// an option word: the first token of a help line, after a Junos `+` or `>` marker, exactly.
func l71Says(help string, yes []string) (string, bool) {
	for _, line := range strings.Split(help, "\n") {
		f := strings.Fields(line)
		if len(f) > 1 && (f[0] == "+" || f[0] == ">") {
			f = f[1:] // Junos marks inherited (+) and container (>) options
		}
		if len(f) == 0 {
			continue
		}
		for _, y := range yes {
			if f[0] == y {
				return strings.TrimSpace(line), true
			}
		}
	}
	return "", false
}

// l71Read is the verdict on one help text. It returns the help line that
// offers a client, or "" when the help is a real option list that has none.
// A help that lists none of the probe's control words is an error: it is
// not evidence of anything, and the caller must fail the run without
// writing a note.
func l71Read(help string, p l71Probe) (string, error) {
	if _, ok := l71Says(help, p.control); !ok {
		return "", fmt.Errorf("INVALID: the help lists none of the control options %v, so it is not an option list "+
			"(a timeout, the wrong mode or an error), and its lacking %v proves nothing; its line-leading words were: %s",
			p.control, p.yes, l71Words(help))
	}
	line, _ := l71Says(help, p.yes)
	return line, nil
}

// l71Wrap is an error for a failed CLI step. The error from sendExpect or
// expectFrom carries what the device said, and on a configuration command
// that can be a key hash or a secret, so it is replaced by a fixed text and
// the size of what was withheld; the test log never holds device output.
func l71Wrap(what string, err error) error {
	return fmt.Errorf("%s: failed (%d bytes of device output withheld from this message)", what, len(err.Error()))
}

// l71Words is the first token of each non-empty line of help, at most 30:
// enough to see what kind of text a CLI printed, never a value.
func l71Words(help string) string {
	var w []string
	for _, line := range strings.Split(help, "\n") {
		if f := strings.Fields(line); len(f) > 0 && len(w) < 30 && optionWord.MatchString(f[0]) {
			w = append(w, f[0])
		}
	}
	return strings.Join(w, " ")
}

// l71CleanupFor is the cleanup lines to type after entered of probe.enter
// were sent. Nothing was entered, nothing to undo. A partial enter has put
// the session in configuration mode only, so only the last cleanup line
// (the one that leaves it) runs: the earlier ones undo a later enter line,
// and `exit` typed at privileged exec would end the session.
func l71CleanupFor(p l71Probe, entered int) []string {
	switch {
	case entered <= 0:
		return nil
	case entered < len(p.enter):
		return p.cleanup[len(p.cleanup)-1:]
	}
	return p.cleanup
}

// l71LineEmpty reports whether the last line of out, as a terminal would
// show it, is a bare prompt: it ends in `#` or `>` once trailing spaces are
// dropped, and nothing typed follows. Backspaces, carriage returns and the
// erase (K and J), cursor-left and cursor-right escapes are applied, so a line a device erased
// with Ctrl-U reads as empty and one it kept reads as not.
func l71LineEmpty(out string) bool {
	if i := strings.LastIndex(out, "\n"); i >= 0 {
		out = out[i+1:]
	}
	var line []byte
	cur := 0
	for i := 0; i < len(out); i++ {
		switch ch := out[i]; {
		case ch == '\r':
			cur = 0
		case ch == '\b':
			if cur > 0 {
				cur--
			}
		case ch == 0x1b && i+1 < len(out) && out[i+1] == '[':
			j := i + 2
			for j < len(out) && (out[j] >= '0' && out[j] <= '9' || out[j] == ';') {
				j++
			}
			if j < len(out) {
				n := 0
				fmt.Sscanf(out[i+2:j], "%d", &n)
				switch out[j] {
				case 'K', 'J':
					if cur < len(line) {
						line = line[:cur]
					}
				case 'D':
					if n == 0 {
						n = 1
					}
					cur = max(cur-n, 0)
				case 'C':
					if n == 0 {
						n = 1
					}
					cur = min(cur+n, len(line))
				}
			}
			i = j
		case ch >= 0x20 && ch < 0x7f:
			if cur < len(line) {
				line[cur] = ch
			} else {
				line = append(line, ch)
			}
			cur++
		}
	}
	t := strings.TrimRight(string(line), " ")
	return strings.HasSuffix(t, "#") || strings.HasSuffix(t, ">")
}

// l71Secret is what l71MaskExchange hides in a probe exchange beyond what
// labcreds.RedactNote finds: a hashed or plain key, secret or password a
// device's help or echo might show.
var l71Secret = regexp.MustCompile(`\$[0-9]\$\S+|key [0-9] \S+|secret \S+|password \S+`)

// l71MaskExchange is a probe exchange fit to commit: credentials masked, and
// control bytes shown as `cat -v` shows them (a newline stays a newline), so
// the file reads the way the terminal's redraw can be checked.
func l71MaskExchange(s string) string {
	s = labcreds.RedactNote(s)
	s = l71Secret.ReplaceAllString(s, "<MASKED>")
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\n' || r == '\t':
			b.WriteRune(r)
		case r < 0x20:
			b.WriteString("^" + string(r+0x40))
		case r == 0x7f:
			b.WriteString("^?")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
