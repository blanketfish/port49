package lab

import (
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
