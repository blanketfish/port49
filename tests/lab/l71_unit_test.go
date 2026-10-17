package lab

import (
	"errors"
	"strings"
	"testing"
)

func TestL71ProbesEveryPlatform(t *testing.T) {
	for _, p := range []string{"arista_eos", "cisco_iosxe", "cisco_nxos", "juniper_vjunos-router", "juniper_vsrx"} {
		pr, ok := l71Probes[p]
		if !ok || len(pr.ask) == 0 || len(pr.yes) == 0 || len(pr.cleanup) == 0 ||
			len(pr.control) == 0 || pr.snapshot == "" || pr.cfgMark == "" {
			t.Errorf("%s: %+v", p, pr)
		}
	}
}

func TestL71SaysReadsOptionWordsOnly(t *testing.T) {
	help := "  key             Set key\n  port            TCP port\n  single-connection  Use one connection\n"
	if _, ok := l71Says(help, []string{"tls"}); ok {
		t.Fatal("no tls option, yet yes")
	}
	if line, ok := l71Says(help+"  tls             TLS settings\n", []string{"tls"}); !ok || line != "tls             TLS settings" {
		t.Fatalf("%q %v", line, ok)
	}
	if _, ok := l71Says("% Invalid input: tls is not a command\n", []string{"tls"}); ok {
		t.Fatal("an error line mentioning tls read as an option")
	}
}

func TestL71ReadNeedsAControlBeforeItCallsAnAbsence(t *testing.T) {
	p := l71Probes["arista_eos"]
	real := "  key   Set key\n  port  TCP port\n"
	if line, err := l71Read(real, p); err != nil || line != "" {
		t.Fatalf("a real help without tls: %q, %v", line, err)
	}
	if line, err := l71Read(real+"  ssl-profile  SSL profile\n", p); err != nil || !strings.HasPrefix(line, "ssl-profile") {
		t.Fatalf("a real help with ssl-profile: %q, %v", line, err)
	}
	for name, help := range map[string]string{
		"empty":         "",
		"echo only":     "tacacs-server host 192.0.2.71 ?",
		"invalid input": "% Invalid input\n",
		"wrong mode":    "  show   Show running system information\n",
	} {
		if _, err := l71Read(help, p); err == nil || !strings.Contains(err.Error(), "INVALID") {
			t.Errorf("%s: read as a verdict, err %v", name, err)
		}
	}
}

func TestL71ErrorsCarryNoDeviceOutput(t *testing.T) {
	leak := errors.New("none of [\"#\"] appeared; what it said was:\n key 7 0822455D0A16\n secret \"$9$abc\"")
	got := l71Wrap("cleanup \"end\"", leak).Error()
	for _, bad := range []string{"0822455D0A16", "$9$abc", "key 7", "secret"} {
		if strings.Contains(got, bad) {
			t.Errorf("wrapped error holds %q: %s", bad, got)
		}
	}
	_, err := l71Read("foo 7 0822455D0A16\nbar \"$9$abc\"\n0822455D0A16\n$9$abc\n", l71Probes["juniper_vsrx"])
	if err == nil {
		t.Fatal("no control option, yet a verdict")
	}
	for _, bad := range []string{"0822455D0A16", "$9$abc"} {
		if strings.Contains(err.Error(), bad) {
			t.Errorf("INVALID error holds %q: %v", bad, err)
		}
	}
}

func TestL71CleanupForRunsOnlyWhatEnterNeeds(t *testing.T) {
	xe := l71Probes["cisco_iosxe"]
	if got := l71CleanupFor(xe, 0); len(got) != 0 {
		t.Errorf("nothing entered: %v", got)
	}
	if got := l71CleanupFor(xe, 1); len(got) != 1 || got[0] != "end" {
		t.Errorf("only configure terminal sent: %v", got)
	}
	if got := l71CleanupFor(xe, 2); len(got) != 3 || got[1] != "no tacacs server l71probe" {
		t.Errorf("fully entered: %v", got)
	}
	if got := l71CleanupFor(l71Probes["juniper_vsrx"], 1); len(got) != 2 {
		t.Errorf("junos fully entered: %v", got)
	}
}

func TestL71LineEmptyReadsTheTerminalNotTheBytes(t *testing.T) {
	typed := "tacacs-server "
	for name, c := range map[string]struct {
		out  string
		want bool
	}{
		"bare prompt":         {"help\r\nnx1(config)#", true},
		"junos prompt":        {"help\r\nuser@h# ", true},
		"erased by backspace": {"nx1(config)#" + typed + strings.Repeat("\b \b", len(typed)), true},
		"erased by cr and K":  {"user@h# set system \r\x1b[Kuser@h# ", true},
		"erased by cursor":    {"nx1(config)#" + typed + "\x1b[" + "14D\x1b[K", true},
		"typed text kept":     {"nx1(config)#" + typed, false},
		"ctrl-u ignored":      {"help\r\nnx1(config)#" + typed + "\a", false},
		"half erased":         {"nx1(config)#" + typed + strings.Repeat("\b \b", 3), false},
	} {
		if got := l71LineEmpty(c.out); got != c.want {
			t.Errorf("%s: %v, want %v", name, got, c.want)
		}
	}
}

func TestL71MaskExchange(t *testing.T) {
	in := "nx1(config)#tacacs-server host 192.0.2.71 ?\r\n" +
		"  key 7 fakeKeyHashABC\r\n  key 0 fakeplainkey\r\n  secret fakesecret1\r\n  password fakepass1\r\n" +
		"  $9$fakeJunosHash12 and $6$fakesalt$fakehash\r\n" +
		"\x1b[K\b \bnx1(config)#"
	got := l71MaskExchange(in)
	for _, leak := range []string{"fakeKeyHashABC", "fakeplainkey", "fakesecret1", "fakepass1", "fakeJunosHash12", "fakehash"} {
		if strings.Contains(got, leak) {
			t.Errorf("%q survived the mask:\n%s", leak, got)
		}
	}
	if !strings.Contains(got, "<MASKED>") || !strings.Contains(got, "host 192.0.2.71 ?") {
		t.Errorf("mask over- or under-reached:\n%s", got)
	}
	// Control bytes are shown, as cat -v shows them, and a newline stays one.
	if !strings.Contains(got, "^[[K^H ^H") || !strings.Contains(got, "^M\n") {
		t.Errorf("control bytes not rendered:\n%s", got)
	}
	if strings.ContainsAny(got, "\x1b\b\r") {
		t.Errorf("raw control bytes survived:\n%s", got)
	}
}
