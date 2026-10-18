//go:build lab

package lab

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestL73InvalidScreenDropsPEM(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PORT49_L73_INVALID_DIR", dir)
	e := &l73Env{l: &lab{p: platform{name: "x"}}}
	e.invalidScreen("device-2", "Issuer: CN=L73\n-----BEGIN CERTIFICATE-----\nZZZZ\n-----END CERTIFICATE-----\n")
	b, err := os.ReadFile(filepath.Join(dir, "l73-invalid-x-device-2.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "ZZZZ") || !strings.Contains(string(b), "Issuer: CN=L73") {
		t.Fatal(string(b))
	}
}

func TestL73InvalidScreenMasksTheTacplusSecret(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PORT49_L73_INVALID_DIR", dir)
	e := &l73Env{l: &lab{p: platform{name: "x"}}}
	e.invalidScreen("device-3", "set system tacplus-server 172.100.100.1 port 300\n"+
		"set system tacplus-server 172.100.100.1 secret \"$9$abcdefgh1234\"\n"+
		"set system tacplus-server 172.100.100.1 authentication-key \"$9$zzzzyyyy5678\"\n")
	b, err := os.ReadFile(filepath.Join(dir, "l73-invalid-x-device-3.txt"))
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	if strings.Contains(got, "$9$") || strings.Contains(got, "abcdefgh") || strings.Contains(got, "zzzzyyyy") ||
		!strings.Contains(got, "tacplus-server 172.100.100.1 port 300") {
		t.Fatal(got)
	}
}

func TestJunosLineRefusal(t *testing.T) {
	ln := "set system tacplus-server 1.2.3.4 tls trusted-ca-group g"
	for name, c := range map[string]struct {
		ln, out string
		want    bool
	}{
		"clean set":                         {ln, ln + "\r\nbreakglass@srx1# ", false},
		"clean set as the image answers it": {ln, ln + " \r\n\r\n[edit]\r\nbreakglass@srx1#  " + ln + " \r\n\r\n[edit]\r\nbreakglass@srx1# ", false},
		"error then edit":                   {ln, ln + "\r\nerror: bad\r\n\r\n[edit]\r\nbreakglass@srx1# ", true},
		"syntax error then edit":            {ln, ln + "\r\n  ^\r\nsyntax error.\r\n\r\n[edit]\r\nbreakglass@srx1# ", true},
		"other words then edit":             {ln, ln + "\r\nwarning: odd\r\n\r\n[edit]\r\nbreakglass@srx1# ", true},
		"clean set at a level":              {ln, ln + "\r\n\r\n[edit system]\r\nbreakglass@srx1# ", false},
		"syntax error":                      {ln, ln + "\r\n                  ^\r\nsyntax error.\r\nbreakglass@srx1# ", true},
		"unknown command":                   {ln, ln + "\r\nunknown command.\r\nbreakglass@srx1# ", true},
		"error colon":                       {ln, ln + "\r\nerror: bad\r\nbreakglass@srx1# ", true},
		"missing argument":                  {ln, ln + "\r\nmissing argument.\r\nbreakglass@srx1# ", true},
		"set warning":                       {ln, ln + "\r\nwarning: something odd\r\nbreakglass@srx1# ", true},
		"delete not found":                  {"delete system tacplus-server", "delete system tacplus-server\r\nwarning: statement not found\r\nbreakglass@srx1# ", false},
		"delete real error":                 {"delete system tacplus-server", "delete system tacplus-server\r\nerror: bad\r\nbreakglass@srx1# ", true},
	} {
		if got := junosLineRefusal(c.ln, c.out) != ""; got != c.want {
			t.Errorf("%s: refusal %v want %v", name, got, c.want)
		}
	}
}

func TestL73ScrubLogMasksTheTacplusSecret(t *testing.T) {
	got := l73ScrubLog("set system tacplus-server 172.100.100.1 port 300\n" +
		"set system tacplus-server 172.100.100.1 secret \"$9$abcdefgh1234\"\n" +
		"set system tacplus-server 172.100.100.1 authentication-key \"$9$zzzzyyyy5678\"\n")
	if strings.Contains(got, "$9$") || strings.Contains(got, "secret") || strings.Contains(got, "abcdefgh") || strings.Contains(got, "zzzzyyyy") || !strings.Contains(got, "port 300") {
		t.Fatal(got)
	}
}

func TestL73InvalidScreenKeepsAPlainFilePath(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PORT49_L73_INVALID_DIR", dir)
	e := &l73Env{l: &lab{p: platform{name: "x"}}}
	e.invalidScreen("configure", "File path '/var/db/certs/common/local/l73-trust' doesn't exists.\r\n")
	b, err := os.ReadFile(filepath.Join(dir, "l73-invalid-x-configure.txt"))
	if err != nil || !strings.Contains(string(b), "'/var/db/certs/common/local/l73-trust'") {
		t.Fatal(err, string(b))
	}
}
