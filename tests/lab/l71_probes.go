package lab

import (
	"fmt"
	"regexp"
	"strings"
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
}

// l71Says reports whether help, a CLI's answer to "?", lists one of yes as
// an option word: the first token of an indented help line, exactly.
func l71Says(help string, yes []string) (string, bool) {
	for _, line := range strings.Split(help, "\n") {
		f := strings.Fields(line)
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
